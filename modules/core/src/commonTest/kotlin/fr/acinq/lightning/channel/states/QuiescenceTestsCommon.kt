package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Lightning
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.htlcTimeoutTxs
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import kotlin.test.*

class QuiescenceTestsCommon : LightningTestSuite() {

    @Test
    fun `send stfu after pending local changes have been added`() {
        // we have an unsigned htlc in our local changes
        val (alice, bob) = reachNormal()
        val (nodes1, _, _) = TestsHelper.addHtlc(50_000_000.msat, alice, bob)
        val (alice1, bob1) = nodes1
        val (alice2, actionsAlice2) = alice1.process(createSpliceCommand(alice1))
        assertIs<LNChannel<Normal>>(alice2)
        assertNull(actionsAlice2.findOutgoingMessageOpt<Stfu>())
        val (_, _, stfu) = crossSignForStfu(alice2, bob1)
        assertTrue(stfu.initiator)
    }

    @Test
    fun `recv stfu when there are pending local changes`() {
        val (alice, bob) = reachNormal()
        val (alice1, actionsAlice1) = alice.process(createSpliceCommand(alice))
        val stfuAlice = actionsAlice1.findOutgoingMessage<Stfu>()
        assertTrue(stfuAlice.initiator)
        // we're holding the stfu from alice so that bob can add a pending local change
        val (nodes2, _, _) = TestsHelper.addHtlc(50_000_000.msat, bob, alice1)
        val (bob2, alice2) = nodes2
        // bob will not reply to alice's stfu until bob has no pending local commitment changes
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(stfuAlice))
        assertTrue(actionsBob3.isEmpty())
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.Commitment.Sign)
        val commitSigBob = actionsBob4.findOutgoingMessage<CommitSig>()
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(commitSigBob))
        val revAlice = actionsAlice3.findOutgoingMessage<RevokeAndAck>()
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.Commitment.Sign)
        val commitSigAlice = actionsAlice4.findOutgoingMessage<CommitSig>()
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(revAlice))
        assertNull(actionsBob5.findOutgoingMessageOpt<Stfu>())
        val (bob6, actionsBob6) = bob5.process(ChannelCommand.MessageReceived(commitSigAlice))
        val revBob = actionsBob6.findOutgoingMessage<RevokeAndAck>()
        val stfuBob = actionsBob6.findOutgoingMessage<Stfu>()
        assertFalse(stfuBob.initiator)
        val (alice5, _) = alice4.process(ChannelCommand.MessageReceived(revBob))
        val (_, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(stfuBob))
        // when both nodes are quiescent, alice can start the splice
        val spliceInit = actionsAlice6.findOutgoingMessage<SpliceInit>()
        val (_, actionsBob7) = bob6.process(ChannelCommand.MessageReceived(spliceInit))
        actionsBob7.findOutgoingMessage<SpliceAck>()
    }

    @Test
    fun `recv forbidden non-settlement commands while initiator is awaiting stfu from remote`() {
        val (alice, _) = reachNormal()
        val (alice1, actionsAlice1) = alice.process(createSpliceCommand(alice))
        actionsAlice1.findOutgoingMessage<Stfu>()
        // Alice should reject commands that change the commitment once it became quiescent.
        val cmds = listOf(
            ChannelCommand.Htlc.Add(1_000_000.msat, Lightning.randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(alice.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket, UUID.randomUUID()),
            ChannelCommand.Commitment.UpdateFee(FeeratePerKw(100.sat)),
            ChannelCommand.Close.MutualClose(null, TestConstants.feeratePerKw),
        )
        cmds.forEach {
            alice1.process(it).second.findCommandError<ForbiddenDuringSplice>()
        }
    }

    @Test
    fun `recv forbidden non-settlement commands while quiescent`() {
        val (alice, bob) = reachNormal()
        val (alice1, bob1, _) = exchangeStfu(createSpliceCommand(alice), alice, bob)
        // both should reject commands that change the commitment while quiescent
        val cmds = listOf(
            ChannelCommand.Htlc.Add(1_000_000.msat, Lightning.randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(alice.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket, UUID.randomUUID()),
            ChannelCommand.Commitment.UpdateFee(FeeratePerKw(100.sat)),
            ChannelCommand.Close.MutualClose(null, TestConstants.feeratePerKw)
        )
        cmds.forEach {
            alice1.process(it).second.findCommandError<ForbiddenDuringSplice>()
        }
        cmds.forEach {
            bob1.process(it).second.findCommandError<ForbiddenDuringSplice>()
        }
    }

    @Test
    fun `recv settlement command while initiator is awaiting stfu from remote`() {
        val (alice, bob) = reachNormal()
        val (nodes1, preimage, htlc) = TestsHelper.addHtlc(50_000_000.msat, bob, alice)
        val (bob1, alice1) = nodes1
        val (alice2, actionsAlice2) = alice1.process(createSpliceCommand(alice1))
        assertIs<LNChannel<Normal>>(alice2)
        val stfuAlice = actionsAlice2.findOutgoingMessage<Stfu>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(stfuAlice))
        assertIs<LNChannel<Normal>>(bob2)
        assertTrue(actionsBob2.isEmpty())
        val (_, alice3, stfuBob) = crossSignForStfu(bob2, alice2)
        listOf(
            ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, preimage),
            ChannelCommand.Htlc.Settlement.Fail(htlc.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(TemporaryNodeFailure))
        ).forEach { cmd ->
            // Alice simply ignores the settlement command.
            val (alice4, actionsAlice4) = alice3.process(cmd)
            assertTrue(actionsAlice4.isEmpty())
            // But she replays the HTLC once splicing is complete.
            val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(stfuBob))
            actionsAlice5.findOutgoingMessage<SpliceInit>()
            val (alice6, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(TxAbort(alice.channelId, null)))
            assertIs<Normal>(alice6.state)
            assertEquals(2, actionsAlice6.size)
            assertEquals(htlc, actionsAlice6.find<ChannelAction.ProcessIncomingHtlc>().add)
            actionsAlice6.findOutgoingMessage<TxAbort>()
            // She can now process the command.
            val (alice7, actionsAlice7) = alice6.process(cmd)
            assertIs<Normal>(alice7.state)
            assertEquals(htlc.id, actionsAlice7.findOutgoingMessage<HtlcSettlementMessage>().id)
        }
    }

    @Test
    fun `recv settlement commands while initiator is awaiting stfu from remote and channel disconnects`() {
        val (alice, bob) = reachNormal()
        val (nodes1, preimage, htlc) = TestsHelper.addHtlc(50_000_000.msat, bob, alice)
        val (bob1, alice1) = nodes1
        val (alice2, actionsAlice2) = alice1.process(createSpliceCommand(alice1))
        assertIs<LNChannel<Normal>>(alice2)
        val stfuAlice = actionsAlice2.findOutgoingMessage<Stfu>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(stfuAlice))
        assertIs<LNChannel<Normal>>(bob2)
        assertTrue(actionsBob2.isEmpty())
        val (bob3, alice3, _) = crossSignForStfu(bob2, alice2)
        listOf(
            ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, preimage),
            ChannelCommand.Htlc.Settlement.Fail(htlc.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(TemporaryNodeFailure))
        ).forEach { cmd ->
            // Alice simply ignores the settlement command.
            val (alice4, actionsAlice4) = alice3.process(cmd)
            assertTrue(actionsAlice4.isEmpty())
            // Alice and Bob disconnect and reconnect, which aborts the quiescence negotiation.
            val (aliceOffline, bobOffline) = disconnect(alice4, bob3)
            val (alice5, _, actionsAlice5, _) = reconnect(aliceOffline, bobOffline)
            assertIs<Normal>(alice5.state)
            assertEquals(1, actionsAlice5.size)
            assertEquals(htlc, actionsAlice5.find<ChannelAction.ProcessIncomingHtlc>().add)
            // She can now process the command.
            val (alice6, actionsAlice6) = alice5.process(cmd)
            assertIs<Normal>(alice6.state)
            assertEquals(htlc.id, actionsAlice6.findOutgoingMessage<HtlcSettlementMessage>().id)
        }
    }

    @Test
    fun `recv settlement commands while quiescent`() {
        val (alice, bob) = reachNormal()
        // Alice initiates quiescence with an outgoing HTLC to Bob.
        val (nodes1, preimageBob, htlcBob) = TestsHelper.addHtlc(50_000_000.msat, alice, bob)
        val (alice1, bob1) = nodes1
        val (alice2, actionsAlice2) = alice1.process(createSpliceCommand(alice1))
        assertIs<LNChannel<Normal>>(alice2)
        assertTrue(actionsAlice2.isEmpty())
        val (alice3, bob3, stfuAlice) = crossSignForStfu(alice2, bob1)
        // Bob sends an outgoing HTLC to Alice before going quiescent.
        val (nodes4, preimageAlice, htlcAlice) = TestsHelper.addHtlc(40_000_000.msat, bob3, alice3)
        val (bob4, alice4) = nodes4
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(stfuAlice))
        assertIs<LNChannel<Normal>>(bob5)
        assertTrue(actionsBob5.isEmpty())
        val (bob6, alice6, stfuBob) = crossSignForStfu(bob5, alice4)
        val (alice7, actionsAlice7) = alice6.process(ChannelCommand.MessageReceived(stfuBob))
        val spliceInit = actionsAlice7.findOutgoingMessage<SpliceInit>()
        val (bob7, actionsBob7) = bob6.process(ChannelCommand.MessageReceived(spliceInit))
        actionsBob7.findOutgoingMessage<SpliceAck>()
        // Alice receives settlement commands.
        run {
            listOf(
                ChannelCommand.Htlc.Settlement.Fulfill(htlcAlice.id, preimageAlice),
                ChannelCommand.Htlc.Settlement.Fail(htlcAlice.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(TemporaryNodeFailure))
            ).forEach { cmd ->
                // Alice simply ignores the settlement command.
                val (alice8, actionsAlice8) = alice7.process(cmd)
                assertTrue(actionsAlice8.isEmpty())
                // But she replays the HTLC once splicing is complete.
                val (alice9, actionsAlice9) = alice8.process(ChannelCommand.MessageReceived(TxAbort(alice.channelId, null)))
                assertIs<Normal>(alice9.state)
                assertEquals(htlcAlice, actionsAlice9.find<ChannelAction.ProcessIncomingHtlc>().add)
                // She can now process the command.
                val (alice10, actionsAlice10) = alice9.process(cmd)
                assertIs<Normal>(alice10.state)
                assertEquals(htlcAlice.id, actionsAlice10.findOutgoingMessage<HtlcSettlementMessage>().id)
            }
        }
        // Bob receives settlement commands.
        run {
            listOf(
                ChannelCommand.Htlc.Settlement.Fulfill(htlcBob.id, preimageBob),
                ChannelCommand.Htlc.Settlement.Fail(htlcBob.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(TemporaryNodeFailure))
            ).forEach { cmd ->
                // Bob simply ignores the settlement command.
                val (bob8, actionsBob8) = bob7.process(cmd)
                assertTrue(actionsBob8.isEmpty())
                // But he replays the HTLC once splicing is complete.
                val (bob9, actionsBob9) = bob8.process(ChannelCommand.MessageReceived(TxAbort(bob.channelId, null)))
                assertIs<Normal>(bob9.state)
                assertEquals(htlcBob, actionsBob9.find<ChannelAction.ProcessIncomingHtlc>().add)
                // He can now process the command.
                val (bob10, actionsBob10) = bob9.process(cmd)
                assertIs<Normal>(bob10.state)
                assertEquals(htlcBob.id, actionsBob10.findOutgoingMessage<HtlcSettlementMessage>().id)
            }
        }
    }

    @Test
    fun `recv settlement commands while quiescent and channel disconnects`() {
        val (alice, bob) = reachNormal()
        // Alice initiates quiescence with an outgoing HTLC to Bob.
        val (nodes1, preimageBob, htlcBob) = TestsHelper.addHtlc(50_000_000.msat, alice, bob)
        val (alice1, bob1) = nodes1
        val (alice2, actionsAlice2) = alice1.process(createSpliceCommand(alice1))
        assertIs<LNChannel<Normal>>(alice2)
        assertTrue(actionsAlice2.isEmpty())
        val (alice3, bob3, stfuAlice) = crossSignForStfu(alice2, bob1)
        // Bob sends an outgoing HTLC to Alice before going quiescent.
        val (nodes4, preimageAlice, htlcAlice) = TestsHelper.addHtlc(40_000_000.msat, bob3, alice3)
        val (bob4, alice4) = nodes4
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(stfuAlice))
        assertIs<LNChannel<Normal>>(bob5)
        assertTrue(actionsBob5.isEmpty())
        val (bob6, alice6, stfuBob) = crossSignForStfu(bob5, alice4)
        val (alice7, actionsAlice7) = alice6.process(ChannelCommand.MessageReceived(stfuBob))
        val spliceInit = actionsAlice7.findOutgoingMessage<SpliceInit>()
        val (bob7, actionsBob7) = bob6.process(ChannelCommand.MessageReceived(spliceInit))
        actionsBob7.findOutgoingMessage<SpliceAck>()
        // Alice receives settlement commands.
        run {
            listOf(
                ChannelCommand.Htlc.Settlement.Fulfill(htlcAlice.id, preimageAlice),
                ChannelCommand.Htlc.Settlement.Fail(htlcAlice.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(TemporaryNodeFailure))
            ).forEach { cmd ->
                // Alice simply ignores the settlement command.
                val (alice8, actionsAlice8) = alice7.process(cmd)
                assertTrue(actionsAlice8.isEmpty())
                // Alice and Bob disconnect and reconnect, which aborts the quiescence negotiation.
                val (aliceOffline, bobOffline) = disconnect(alice8, bob7)
                val (alice9, _, actionsAlice9, _) = reconnect(aliceOffline, bobOffline)
                assertIs<Normal>(alice9.state)
                assertEquals(1, actionsAlice9.size)
                assertEquals(htlcAlice, actionsAlice9.find<ChannelAction.ProcessIncomingHtlc>().add)
                // She can now process the command.
                val (alice10, actionsAlice10) = alice9.process(cmd)
                assertIs<Normal>(alice10.state)
                assertEquals(htlcAlice.id, actionsAlice10.findOutgoingMessage<HtlcSettlementMessage>().id)
            }
        }
        // Bob receives settlement commands.
        run {
            listOf(
                ChannelCommand.Htlc.Settlement.Fulfill(htlcBob.id, preimageBob),
                ChannelCommand.Htlc.Settlement.Fail(htlcBob.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(TemporaryNodeFailure))
            ).forEach { cmd ->
                // Bob simply ignores the settlement command.
                val (bob8, actionsBob8) = bob7.process(cmd)
                assertTrue(actionsBob8.isEmpty())
                // Alice and Bob disconnect and reconnect, which aborts the quiescence negotiation.
                val (aliceOffline, bobOffline) = disconnect(alice7, bob8)
                val (_, bob9, _, actionsBob9) = reconnect(aliceOffline, bobOffline)
                assertIs<Normal>(bob9.state)
                assertEquals(htlcBob, actionsBob9.find<ChannelAction.ProcessIncomingHtlc>().add)
                // He can now process the command.
                val (bob10, actionsBob10) = bob9.process(cmd)
                assertIs<Normal>(bob10.state)
                assertEquals(htlcBob.id, actionsBob10.findOutgoingMessage<HtlcSettlementMessage>().id)
            }
        }
    }

    @Test
    fun `recv second stfu while non-initiator is waiting for local commitment to be signed`() {
        val (alice, bob) = reachNormal()
        val (alice1, actionsAlice1) = alice.process(createSpliceCommand(alice))
        val stfu = actionsAlice1.findOutgoingMessage<Stfu>()
        val (nodes2, _, _) = TestsHelper.addHtlc(50_000_000.msat, bob, alice1)
        val (bob2, _) = nodes2
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(stfu))
        assertTrue(actionsBob3.isEmpty())
        // second stfu to bob is ignored
        val (_, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(stfu))
        assertTrue(actionsBob4.isEmpty())
    }

    @Test
    fun `recv Shutdown message before initiator receives stfu from remote`() {
        val (alice, bob) = reachNormal()
        // Alice initiates quiescence.
        val (alice1, actionsAlice1) = alice.process(createSpliceCommand(alice))
        val stfuAlice = actionsAlice1.findOutgoingMessage<Stfu>()
        // But Bob is concurrently initiating a mutual close, which should "win".
        val (bob1, actionsBob1) = bob.process(ChannelCommand.Close.MutualClose(null, TestConstants.feeratePerKw))
        val shutdownBob = actionsBob1.hasOutgoingMessage<Shutdown>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(stfuAlice))
        assertNull(actionsBob2.findOutgoingMessageOpt<Stfu>())
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(shutdownBob))
        assertIs<Negotiating>(alice2.state)
        val shutdownAlice = actionsAlice2.findOutgoingMessage<Shutdown>()
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(shutdownAlice))
        assertIs<Negotiating>(bob3.state)
        actionsBob3.findOutgoingMessage<ClosingComplete>()
        actionsBob3.has<ChannelAction.Storage.StoreState>()
    }

    @Test
    fun `recv forbidden settlement messages while quiescent`() {
        val (alice, bob) = reachNormal()
        val (nodes1, preimage, htlc) = TestsHelper.addHtlc(50_000_000.msat, bob, alice)
        val (bob1, alice1) = nodes1
        val (bob2, alice2) = TestsHelper.crossSign(bob1, alice1)
        val (alice3, bob3, _) = exchangeStfu(createSpliceCommand(alice2), alice2, bob2)
        listOf(
            UpdateFulfillHtlc(bob3.channelId, htlc.id, preimage),
            UpdateFailHtlc(bob3.channelId, htlc.id, Lightning.randomBytes32()),
            UpdateFee(bob3.channelId, FeeratePerKw(500.sat)),
            UpdateAddHtlc(Lightning.randomBytes32(), htlc.id + 1, 50000000.msat, Lightning.randomBytes32(), CltvExpiry(alice.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket),
            Shutdown(alice.channelId, alice.commitments.params.localParams.defaultFinalScriptPubKey),
        ).forEach {
            // both parties will respond to a forbidden msg while quiescent with a warning (and disconnect)
            val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(it))
            assertEquals(alice3, alice4)
            actionsAlice4.findOutgoingMessage<Warning>()
            actionsAlice4.has<ChannelAction.Disconnect>()
            val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(it))
            assertEquals(bob3, bob4)
            actionsBob4.findOutgoingMessage<Warning>()
            actionsBob4.has<ChannelAction.Disconnect>()
        }
    }

    @Test
    fun `recv stfu from splice initiator that is not quiescent`() {
        val (alice, bob) = reachNormal()
        val (nodes1, _, _) = TestsHelper.addHtlc(50_000_000.msat, alice, bob)
        val (alice1, bob1) = nodes1
        val (nodes2, _, _) = TestsHelper.addHtlc(40_000_000.msat, bob1, alice1)
        val (bob2, alice2) = nodes2
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(Stfu(alice.channelId, initiator = true)))
        assertEquals(bob2, bob3)
        actionsBob3.findOutgoingMessage<Warning>()
        actionsBob3.find<ChannelAction.Disconnect>()
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(Stfu(alice.channelId, initiator = true)))
        assertEquals(alice2, alice3)
        actionsAlice3.findOutgoingMessage<Warning>()
        actionsAlice3.find<ChannelAction.Disconnect>()
    }

    @Test
    fun `recv stfu from splice non-initiator that is not quiescent`() {
        val (alice, bob) = reachNormal()
        val (nodes1, _, _) = TestsHelper.addHtlc(50_000_000.msat, bob, alice)
        val (_, alice1) = nodes1
        val (alice2, actionsAlice2) = alice1.process(createSpliceCommand(alice1))
        assertIs<Normal>(alice2.state)
        actionsAlice2.findOutgoingMessage<Stfu>()
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(Stfu(bob.channelId, initiator = false)))
        assertIs<Normal>(alice3.state)
        assertEquals(alice2.state.copy(spliceStatus = SpliceStatus.None), alice3.state)
        actionsAlice3.findOutgoingMessage<Warning>()
        actionsAlice3.find<ChannelAction.Disconnect>()
    }

    @Test
    fun `initiate quiescence concurrently with no pending changes`() = runSuspendTest {
        val (alice, bob) = reachNormal()
        val cmdAlice = createSpliceCommand(alice)
        val cmdBob = createSpliceCommand(bob)
        val (alice1, actionsAlice1) = alice.process(cmdAlice)
        val stfuAlice = actionsAlice1.findOutgoingMessage<Stfu>()
        assertTrue(stfuAlice.initiator)
        val (bob1, actionsBob1) = bob.process(cmdBob)
        val stfuBob = actionsBob1.findOutgoingMessage<Stfu>()
        assertTrue(stfuBob.initiator)
        // Alice is the channel initiator, so she has precedence and remains the splice initiator.
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(stfuBob))
        val spliceInit = actionsAlice2.findOutgoingMessage<SpliceInit>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(stfuAlice))
        assertTrue(actionsBob2.isEmpty())
        val (_, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(spliceInit))
        val spliceAck = actionsBob3.findOutgoingMessage<SpliceAck>()
        val (_, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(spliceAck))
        actionsAlice3.hasOutgoingMessage<TxAddInput>()
        withTimeout(100) {
            assertIs<ChannelFundingResponse.Failure.ConcurrentRemoteSplice>(cmdBob.replyTo.await())
        }
    }

    @Test
    fun `initiate quiescence concurrently with pending changes on one side`() = runSuspendTest {
        val (alice, bob) = reachNormal()
        val (nodes1, _, _) = TestsHelper.addHtlc(50_000_000.msat, alice, bob)
        val (alice1, bob1) = nodes1
        val cmdAlice = createSpliceCommand(alice1)
        val cmdBob = createSpliceCommand(bob1)
        val (alice2, actionsAlice2) = alice1.process(cmdAlice)
        assertTrue(actionsAlice2.isEmpty()) // alice isn't quiescent yet
        val (bob2, actionsBob2) = bob1.process(cmdBob)
        val stfuBob = actionsBob2.findOutgoingMessage<Stfu>()
        assertTrue(stfuBob.initiator)
        val (alice3, _) = alice2.process(ChannelCommand.MessageReceived(stfuBob))
        assertIs<LNChannel<Normal>>(alice3)
        assertIs<LNChannel<Normal>>(bob2)
        val (alice4, bob3, stfuAlice) = crossSignForStfu(alice3, bob2)
        assertFalse(stfuAlice.initiator)
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(stfuAlice))
        val spliceInit = actionsBob4.findOutgoingMessage<SpliceInit>()
        val (_, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(spliceInit))
        val spliceAck = actionsAlice5.findOutgoingMessage<SpliceAck>()
        val (_, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(spliceAck))
        actionsBob5.hasOutgoingMessage<TxAddInput>()
        withTimeout(100) {
            assertIs<ChannelFundingResponse.Failure.ConcurrentRemoteSplice>(cmdAlice.replyTo.await())
        }
    }

    @Test
    fun `outgoing htlc timeout during quiescence negotiation`() {
        val (alice, bob) = reachNormal()
        val (nodes1, _, add) = TestsHelper.addHtlc(50_000_000.msat, alice, bob)
        val (alice1, bob1) = nodes1
        val (alice2, bob2) = TestsHelper.crossSign(alice1, bob1)
        val (alice3, _, _) = exchangeStfu(createSpliceCommand(alice2), alice2, bob2)
        // The outgoing HTLC from Alice has timed out: she should force-close to avoid an on-chain race.
        val (alice4, actionsAlice4) = run {
            val tmp = alice3.copy(ctx = alice3.ctx.copy(currentBlockHeight = add.cltvExpiry.toLong().toInt()))
            tmp.process(ChannelCommand.Commitment.CheckHtlcTimeout)
        }
        assertIs<Closing>(alice4.state)
        val lcp = alice4.state.localCommitPublished
        assertNotNull(lcp)
        assertEquals(1, lcp.htlcTxs.size)
        val htlcTimeoutTxs = lcp.htlcTimeoutTxs()
        assertEquals(1, htlcTimeoutTxs.size)
        actionsAlice4.hasPublishTx(lcp.commitTx)
        actionsAlice4.hasPublishTx(lcp.htlcTimeoutTxs().first().tx)
    }

    @Test
    fun `incoming htlc timeout during quiescence negotiation`() {
        val (alice, bob) = reachNormal()
        val (nodes1, preimage, add) = TestsHelper.addHtlc(50_000_000.msat, bob, alice)
        val (bob1, alice1) = nodes1
        val (bob2, alice2) = TestsHelper.crossSign(bob1, alice1)
        val (alice3, _, _) = exchangeStfu(createSpliceCommand(alice2), alice2, bob2)
        listOf(
            ChannelCommand.Htlc.Settlement.Fail(add.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(TemporaryNodeFailure)),
            ChannelCommand.Htlc.Settlement.Fulfill(add.id, preimage)
        ).forEach { cmd ->
            // Alice simply ignores the settlement command during quiescence.
            val (alice4, actionsAlice4) = alice3.process(cmd)
            assertTrue(actionsAlice4.isEmpty())
            // The incoming HTLC to Alice has timed out: it is Bob's responsibility to force-close.
            // If Bob doesn't force-close, Alice will fulfill or fail the HTLC when they reconnect.
            val (alice5, actionsAlice5) = run {
                val tmp = alice4.copy(ctx = alice4.ctx.copy(currentBlockHeight = add.cltvExpiry.toLong().toInt()))
                tmp.process(ChannelCommand.Commitment.CheckHtlcTimeout)
            }
            assertTrue(actionsAlice5.isEmpty())
            // Alice replays the HTLC once splicing is complete.
            val (alice6, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(TxAbort(alice5.channelId, "deadbeef")))
            assertIs<Normal>(alice6.state)
            assertEquals(add, actionsAlice6.find<ChannelAction.ProcessIncomingHtlc>().add)
            // She can now process the command.
            val (alice7, actionsAlice7) = alice6.process(cmd)
            assertIs<Normal>(alice7.state)
            assertEquals(add.id, actionsAlice7.findOutgoingMessage<HtlcSettlementMessage>().id)
        }
    }

    @Test
    fun `receive SpliceInit when channel is not quiescent`() {
        val (alice, bob) = reachNormal()
        val (_, _, spliceInit) = exchangeStfu(createSpliceCommand(alice), alice, bob)
        // If we send splice_init to Bob's before reaching quiescence, he simply rejects it.
        val (bob2, actionsBob2) = bob.process(ChannelCommand.MessageReceived(spliceInit))
        assertEquals(bob.state.copy(spliceStatus = SpliceStatus.Aborted), bob2.state)
        actionsBob2.hasOutgoingMessage<TxAbort>()
    }

    companion object {
        private fun createWalletWithFunds(keyManager: KeyManager, utxos: List<Satoshi>): List<WalletState.Utxo> {
            return utxos.mapIndexed { index, amount ->
                val script = keyManager.swapInOnChainWallet.getSwapInProtocol(index).pubkeyScript
                val txIn = listOf(TxIn(OutPoint(TxId(Lightning.randomBytes32()), 2), 0))
                val txOut = listOf(TxOut(amount, script), TxOut(150.sat, Script.pay2wpkh(Lightning.randomKey().publicKey())))
                val parentTx = Transaction(2, txIn, txOut, 0)
                WalletState.Utxo(parentTx.txid, 0, 42, parentTx, WalletState.AddressMeta.Derived(index))
            }
        }

        fun createSpliceCommand(sender: LNChannel<Normal>, spliceIn: List<Satoshi> = listOf(500_000.sat), spliceOut: Satoshi? = 100_000.sat): ChannelCommand.Commitment.Splice.Request {
            return ChannelCommand.Commitment.Splice.Request(
                replyTo = CompletableDeferred(),
                spliceIn = ChannelCommand.Commitment.Splice.Request.SpliceIn(createWalletWithFunds(sender.staticParams.nodeParams.keyManager, spliceIn)),
                spliceOut = spliceOut?.let { ChannelCommand.Commitment.Splice.Request.SpliceOut(it, Script.write(Script.pay2wpkh(Lightning.randomKey().publicKey())).byteVector()) },
                feerate = FeeratePerKw(253.sat),
                requestRemoteFunding = null,
                currentFeeCredit = 0.msat,
                origins = listOf(),
            )
        }

        /** Use this function when both nodes are already quiescent and want to exchange stfu. */
        fun exchangeStfu(cmd: ChannelCommand.Commitment.Splice.Request, sender: LNChannel<Normal>, receiver: LNChannel<Normal>): Triple<LNChannel<Normal>, LNChannel<Normal>, SpliceInit> {
            val (sender1, sActions1) = sender.process(cmd)
            val stfu1 = sActions1.findOutgoingMessage<Stfu>()
            assertTrue(stfu1.initiator)
            val (receiver1, rActions1) = receiver.process(ChannelCommand.MessageReceived(stfu1))
            val stfu2 = rActions1.findOutgoingMessage<Stfu>()
            assertFalse(stfu2.initiator)
            val (sender2, sActions2) = sender1.process(ChannelCommand.MessageReceived(stfu2))
            val spliceInit = sActions2.findOutgoingMessage<SpliceInit>()
            assertIs<LNChannel<Normal>>(sender2)
            assertIs<LNChannel<Normal>>(receiver1)
            return Triple(sender2, receiver1, spliceInit)
        }

        /** Use this function when the sender has pending changes that need to be cross-signed before sending stfu. */
        fun crossSignForStfu(sender: LNChannel<Normal>, receiver: LNChannel<Normal>): Triple<LNChannel<Normal>, LNChannel<Normal>, Stfu> {
            val (sender2, sActions2) = sender.process(ChannelCommand.Commitment.Sign)
            val sCommitSig = sActions2.findOutgoingMessage<CommitSig>()
            val (receiver2, rActions2) = receiver.process(ChannelCommand.MessageReceived(sCommitSig))
            val rRev = rActions2.findOutgoingMessage<RevokeAndAck>()
            val (receiver3, rActions3) = receiver2.process(ChannelCommand.Commitment.Sign)
            val rCommitSig = rActions3.findOutgoingMessage<CommitSig>()
            val (sender3, sActions3) = sender2.process(ChannelCommand.MessageReceived(rRev))
            assertNull(sActions3.findOutgoingMessageOpt<Stfu>())
            val (sender4, sActions4) = sender3.process(ChannelCommand.MessageReceived(rCommitSig))
            val sRev = sActions4.findOutgoingMessage<RevokeAndAck>()
            val stfu = sActions4.findOutgoingMessage<Stfu>()
            val (receiver4, _) = receiver3.process(ChannelCommand.MessageReceived(sRev))
            assertIs<LNChannel<Normal>>(sender4)
            assertIs<LNChannel<Normal>>(receiver4)
            return Triple(sender4, receiver4, stfu)
        }

        fun disconnect(alice: LNChannel<ChannelState>, bob: LNChannel<ChannelState>): Pair<LNChannel<Offline>, LNChannel<Offline>> {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.Disconnected)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.Disconnected)
            assertIs<Offline>(alice1.state)
            assertTrue(actionsAlice1.isEmpty())
            assertIs<Offline>(bob1.state)
            assertTrue(actionsBob1.isEmpty())
            assertIs<LNChannel<Offline>>(alice1)
            assertIs<LNChannel<Offline>>(bob1)
            return Pair(alice1, bob1)
        }

        data class PostReconnectionState(val alice: LNChannel<Normal>, val bob: LNChannel<Normal>, val actionsAlice: List<ChannelAction>, val actionsBob: List<ChannelAction>)

        fun reconnect(alice: LNChannel<Offline>, bob: LNChannel<Offline>): PostReconnectionState {
            val aliceInit = Init(alice.commitments.params.localParams.features)
            val bobInit = Init(bob.commitments.params.localParams.features)
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.Connected(aliceInit, bobInit))
            assertIs<LNChannel<Syncing>>(alice1)
            val channelReestablishA = actionsAlice1.findOutgoingMessage<ChannelReestablish>()
            val (bob1, _) = bob.process(ChannelCommand.Connected(bobInit, aliceInit))
            assertIs<LNChannel<Syncing>>(bob1)
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(channelReestablishA))
            val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(channelReestablishB))
            assertIs<LNChannel<Normal>>(alice2)
            assertIs<LNChannel<Normal>>(bob2)
            return PostReconnectionState(alice2, bob2, actionsAlice2, actionsBob2)
        }
    }

}
