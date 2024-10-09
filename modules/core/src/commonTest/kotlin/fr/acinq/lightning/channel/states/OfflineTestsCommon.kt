package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.htlcSuccessTxs
import fr.acinq.lightning.channel.TestsHelper.htlcTimeoutTxs
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.*
import kotlin.test.*

class OfflineTestsCommon : LightningTestSuite() {

    @Test
    fun `handle disconnect - connect events in WaitForChannelReady -- zeroconf`() {
        val (alice, aliceCommitSig, bob, _) = WaitForFundingSignedTestsCommon.init(
            ChannelType.SupportedChannelType.AnchorOutputsZeroReserve,
            zeroConf = true,
            bobUsePeerStorage = false,
        )
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(aliceCommitSig))
        assertIs<WaitForChannelReady>(bob1.state)
        assertIs<LNChannel<WaitForChannelReady>>(bob1)
        actionsBob1.hasOutgoingMessage<TxSignatures>()
        actionsBob1.hasOutgoingMessage<ChannelReady>()
        val (alice1, bob2) = disconnect(alice, bob1)

        val aliceInit = Init(alice.state.channelParams.localParams.features.initFeatures())
        val bobInit = Init(bob.state.channelParams.localParams.features.initFeatures())

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Connected(aliceInit, bobInit))
        assertIs<Syncing>(alice2.state)
        val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.Connected(bobInit, aliceInit))
        assertIs<Syncing>(bob3.state)
        actionsBob3.findOutgoingMessage<ChannelReestablish>()

        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(channelReestablishA))
        assertIs<WaitForChannelReady>(bob4.state)
        actionsBob4.hasOutgoingMessage<CommitSig>()
        actionsBob4.hasOutgoingMessage<TxSignatures>()
        actionsBob4.hasOutgoingMessage<ChannelReady>()
    }

    @Test
    fun `handle disconnect - connect events -- no messages sent yet`() {
        val (alice, bob) = TestsHelper.reachNormal(bobUsePeerStorage = false)
        val (alice1, bob1) = disconnect(alice, bob)

        val localInit = Init(alice.commitments.params.localParams.features.initFeatures())
        val remoteInit = Init(bob.commitments.params.localParams.features.initFeatures())

        val (alice2, actions) = alice1.process(ChannelCommand.Connected(localInit, remoteInit))
        assertIs<Syncing>(alice2.state)
        val channelReestablishA = actions.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actions1) = bob1.process(ChannelCommand.Connected(remoteInit, localInit))
        assertIs<Syncing>(bob2.state)
        val channelReestablishB = actions1.findOutgoingMessage<ChannelReestablish>()

        val bobCommitments = bob.commitments
        val aliceCommitments = alice.commitments
        val bobCurrentPerCommitmentPoint = bobCommitments.params.localParams.channelKeys(bob.ctx.keyManager).commitmentPoint(bobCommitments.localCommitIndex)
        val aliceCurrentPerCommitmentPoint = aliceCommitments.params.localParams.channelKeys(alice.ctx.keyManager).commitmentPoint(aliceCommitments.localCommitIndex)

        // alice didn't receive any update or sig
        assertEquals(
            ChannelReestablish(alice.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), aliceCurrentPerCommitmentPoint),
            channelReestablishA.copy(tlvStream = TlvStream.empty())
        )
        assertEquals(
            ChannelReestablish(bob.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), bobCurrentPerCommitmentPoint),
            channelReestablishB
        )

        val (alice3, actions2) = alice2.process(ChannelCommand.MessageReceived(channelReestablishB))
        assertEquals(alice, alice3)
        assertEquals(1, actions2.size)
        actions2.hasOutgoingMessage<ChannelReady>()

        val (bob3, actions3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishA))
        assertEquals(bob, bob3)
        assertEquals(1, actions3.size)
        actions3.hasOutgoingMessage<ChannelReady>()
    }

    @Test
    fun `re-send update and sig after first commitment`() {
        val (alice0, bob0) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobUsePeerStorage = false)
            val cmdAdd = ChannelCommand.Htlc.Add(1_000_000.msat, ByteVector32.Zeroes, CltvExpiryDelta(144).toCltvExpiry(alice0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket, UUID.randomUUID())
            val (alice1, actions1) = alice0.process(cmdAdd)
            val add = actions1.hasOutgoingMessage<UpdateAddHtlc>()
            val (alice2, actions2) = alice1.process(ChannelCommand.Commitment.Sign)
            assertIs<LNChannel<Normal>>(alice2)
            actions2.hasOutgoingMessage<CommitSig>()
            val (bob1, _) = bob0.process(ChannelCommand.MessageReceived(add))
            assertIs<LNChannel<Normal>>(bob1)
            // bob doesn't receive the sig
            Pair(alice2, bob1)
        }

        val (alice1, bob1) = disconnect(alice0, bob0)
        val localInit = Init(alice0.commitments.params.localParams.features)
        val remoteInit = Init(bob0.commitments.params.localParams.features)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Connected(localInit, remoteInit))
        assertIs<Syncing>(alice2.state)
        val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.Connected(remoteInit, localInit))
        assertIs<Syncing>(bob2.state)
        val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()

        val bobCommitments = bob0.commitments
        val aliceCommitments = alice0.commitments
        val bobCurrentPerCommitmentPoint = bobCommitments.params.localParams.channelKeys(bob0.ctx.keyManager).commitmentPoint(bobCommitments.localCommitIndex)
        val aliceCurrentPerCommitmentPoint = aliceCommitments.params.localParams.channelKeys(alice0.ctx.keyManager).commitmentPoint(aliceCommitments.localCommitIndex)

        // alice didn't receive any update or sig
        assertEquals(channelReestablishA, ChannelReestablish(alice0.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), aliceCurrentPerCommitmentPoint))
        // bob did not receive alice's sig
        assertEquals(channelReestablishB, ChannelReestablish(bob0.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), bobCurrentPerCommitmentPoint))

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishB))
        // alice sends ChannelReady again
        actionsAlice3.hasOutgoingMessage<ChannelReady>()
        // alice re-sends the update and the sig
        val add = actionsAlice3.hasOutgoingMessage<UpdateAddHtlc>()
        val sig = actionsAlice3.hasOutgoingMessage<CommitSig>()

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishA))
        actionsBob3.hasOutgoingMessage<ChannelReady>() // bob sends ChannelReady again
        assertNull(actionsBob3.findOutgoingMessageOpt<RevokeAndAck>()) // bob didn't receive the sig, so he cannot send a rev

        val (bob4, _) = bob3.process(ChannelCommand.MessageReceived(add))
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(sig))
        // bob sends back a revocation and a sig
        val revB = actionsBob5.hasOutgoingMessage<RevokeAndAck>()
        actionsBob5.hasCommand<ChannelCommand.Commitment.Sign>()
        val (bob6, actionsBob6) = bob5.process(ChannelCommand.Commitment.Sign)
        val sigB = actionsBob6.hasOutgoingMessage<CommitSig>()

        val (alice4, _) = alice3.process(ChannelCommand.MessageReceived(revB))
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(sigB))
        assertIs<Normal>(alice5.state)
        val revA = actionsAlice5.hasOutgoingMessage<RevokeAndAck>()

        val (bob7, _) = bob6.process(ChannelCommand.MessageReceived(revA))
        assertIs<Normal>(bob7.state)

        assertEquals(1, alice5.commitments.changes.localNextHtlcId)
        assertEquals(1, bob7.commitments.changes.remoteNextHtlcId)
    }

    @Test
    fun `re-send lost revocation`() {
        val (alice0, bob0) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobUsePeerStorage = false)
            val cmdAdd = ChannelCommand.Htlc.Add(1_000_000.msat, ByteVector32.Zeroes, CltvExpiryDelta(144).toCltvExpiry(alice0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket, UUID.randomUUID())
            val (alice1, actionsAlice1) = alice0.process(cmdAdd)
            val add = actionsAlice1.hasOutgoingMessage<UpdateAddHtlc>()
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
            assertIs<LNChannel<Normal>>(alice2)
            val sig = actionsAlice2.hasOutgoingMessage<CommitSig>()
            val (bob1, _) = bob0.process(ChannelCommand.MessageReceived(add))
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(sig))
            actionsBob2.hasOutgoingMessage<RevokeAndAck>()
            actionsBob2.hasCommand<ChannelCommand.Commitment.Sign>()
            val (bob3, actionsBob3) = bob2.process(ChannelCommand.Commitment.Sign)
            assertIs<LNChannel<Normal>>(bob3)
            actionsBob3.hasOutgoingMessage<CommitSig>()
            // bob received the sig, but alice didn't receive the revocation
            Pair(alice2, bob3)
        }

        val (alice1, bob1) = disconnect(alice0, bob0)
        val localInit = Init(alice0.commitments.params.localParams.features)
        val remoteInit = Init(bob0.commitments.params.localParams.features)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Connected(localInit, remoteInit))
        assertIs<Syncing>(alice2.state)
        val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.Connected(remoteInit, localInit))
        assertIs<Syncing>(bob2.state)
        val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()

        val bobCommitments = bob0.commitments
        val aliceCommitments = alice0.commitments
        val bobCurrentPerCommitmentPoint = bobCommitments.params.localParams.channelKeys(bob0.ctx.keyManager).commitmentPoint(bobCommitments.localCommitIndex)
        val aliceCurrentPerCommitmentPoint = aliceCommitments.params.localParams.channelKeys(alice0.ctx.keyManager).commitmentPoint(aliceCommitments.localCommitIndex)

        // alice didn't receive any update or sig
        assertEquals(channelReestablishA, ChannelReestablish(alice0.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), aliceCurrentPerCommitmentPoint))
        // bob did receive alice's sig
        assertEquals(channelReestablishB, ChannelReestablish(bob0.channelId, 2, 0, PrivateKey(ByteVector32.Zeroes), bobCurrentPerCommitmentPoint))

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishB))
        // alice does not re-send messages bob already received
        assertNull(actionsAlice3.findOutgoingMessageOpt<ChannelReady>())
        assertNull(actionsAlice3.findOutgoingMessageOpt<UpdateAddHtlc>())
        assertNull(actionsAlice3.findOutgoingMessageOpt<CommitSig>())

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishA))
        val revB = actionsBob3.hasOutgoingMessage<RevokeAndAck>() // bob re-sends his revocation
        val sigB = actionsBob3.hasOutgoingMessage<CommitSig>() // bob re-sends his signature

        val (alice4, _) = alice3.process(ChannelCommand.MessageReceived(revB))
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(sigB))
        assertIs<Normal>(alice5.state)
        val revA = actionsAlice5.hasOutgoingMessage<RevokeAndAck>()

        val (bob4, _) = bob3.process(ChannelCommand.MessageReceived(revA))
        assertIs<Normal>(bob4.state)

        assertEquals(1, alice5.commitments.changes.localNextHtlcId)
        assertEquals(1, bob4.commitments.changes.remoteNextHtlcId)
    }

    @Test
    fun `resume htlc settlement`() {
        val (alice0, bob0, revB) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobUsePeerStorage = false)
            val (nodes1, r1, htlc1) = TestsHelper.addHtlc(15_000_000.msat, bob0, alice0)
            val (bob1, alice1) = TestsHelper.crossSign(nodes1.first, nodes1.second)
            val (bob2, alice2) = TestsHelper.fulfillHtlc(htlc1.id, r1, bob1, alice1)
            val (alice3, bob3) = TestsHelper.crossSign(alice2, bob2)
            val (nodes2, r2, htlc2) = TestsHelper.addHtlc(25_000_000.msat, bob3, alice3)
            val (bob4, alice4) = TestsHelper.crossSign(nodes2.first, nodes2.second)
            val (bob5, alice5) = TestsHelper.fulfillHtlc(htlc2.id, r2, bob4, alice4)
            val (alice6, actionsAlice) = alice5.process(ChannelCommand.Commitment.Sign)
            val commitSig = actionsAlice.findOutgoingMessage<CommitSig>()
            val (bob6, actionsBob) = bob5.process(ChannelCommand.MessageReceived(commitSig))
            val revokeAndAck = actionsBob.findOutgoingMessage<RevokeAndAck>()
            assertIs<LNChannel<Normal>>(alice6)
            assertIs<LNChannel<Normal>>(bob6)
            Triple(alice6, bob6, revokeAndAck)
        }

        val (alice1, bob1) = disconnect(alice0, bob0)
        val initA = Init(alice0.commitments.params.localParams.features)
        val initB = Init(bob0.commitments.params.localParams.features)
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Connected(initA, initB))
        assertIs<Syncing>(alice2.state)
        val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.Connected(initB, initA))
        assertIs<Syncing>(bob2.state)
        val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()
        assertEquals(channelReestablishA.nextLocalCommitmentNumber, 4)
        assertEquals(channelReestablishA.nextRemoteRevocationNumber, 3)
        assertEquals(channelReestablishB.nextLocalCommitmentNumber, 5)
        assertEquals(channelReestablishB.nextRemoteRevocationNumber, 3)

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishB))
        // alice does not re-send messages bob already received
        assertTrue(actionsAlice3.filterIsInstance<ChannelAction.Message.Send>().isEmpty())

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishA))
        assertEquals(1, actionsBob3.filterIsInstance<ChannelAction.Message.Send>().size)
        assertEquals(revB, actionsBob3.findOutgoingMessage())
        actionsBob3.hasCommand<ChannelCommand.Commitment.Sign>()
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.Commitment.Sign)
        val sigB = actionsBob4.findOutgoingMessage<CommitSig>()

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(revB))
        assertTrue(actionsAlice4.filterIsInstance<ChannelAction.Message.Send>().isEmpty())
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(sigB))
        val revA = actionsAlice5.findOutgoingMessage<RevokeAndAck>()

        val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(revA))
        assertTrue(actionsBob5.filterIsInstance<ChannelAction.Message.Send>().isEmpty())

        assertIs<Normal>(alice5.state)
        assertIs<Normal>(bob5.state)
        assertEquals(4, alice5.commitments.localCommitIndex)
        assertEquals(4, bob5.commitments.localCommitIndex)
    }

    @Test
    fun `discover that we have a revoked commitment`() {
        val (alice, aliceOld, bob) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobUsePeerStorage = false)
            val (nodes1, r1, htlc1) = TestsHelper.addHtlc(250_000_000.msat, alice0, bob0)
            val (alice1, bob1) = TestsHelper.crossSign(nodes1.first, nodes1.second)
            val (nodes2, r2, htlc2) = TestsHelper.addHtlc(100_000_000.msat, alice1, bob1)
            val (alice2, bob2) = TestsHelper.crossSign(nodes2.first, nodes2.second)
            val (nodes3, r3, htlc3) = TestsHelper.addHtlc(10_000.msat, alice2, bob2)
            val (alice3, bob3) = TestsHelper.crossSign(nodes3.first, nodes3.second)
            assertIs<LNChannel<Normal>>(alice3)
            // alice will lose the following updates
            val (alice4, bob4) = TestsHelper.fulfillHtlc(htlc1.id, r1, alice3, bob3)
            val (bob5, alice5) = TestsHelper.crossSign(bob4, alice4)
            val (alice6, bob6) = TestsHelper.fulfillHtlc(htlc2.id, r2, alice5, bob5)
            val (bob7, alice7) = TestsHelper.crossSign(bob6, alice6)
            val (alice8, bob8) = TestsHelper.fulfillHtlc(htlc3.id, r3, alice7, bob7)
            val (bob9, alice9) = TestsHelper.crossSign(bob8, alice8)
            assertIs<LNChannel<Normal>>(alice9)
            assertIs<LNChannel<Normal>>(bob9)
            Triple(alice9, alice3, bob9)
        }

        val (aliceTmp1, bob1) = disconnect(alice, bob)
        // we manually replace alice's state with an older one
        val alice1 = aliceTmp1.copy(state = Offline(aliceOld.state))

        val localInit = Init(alice.commitments.params.localParams.features)
        val remoteInit = Init(bob.commitments.params.localParams.features)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Connected(localInit, remoteInit))
        assertIs<Syncing>(alice2.state)
        val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.Connected(remoteInit, localInit))
        assertIs<Syncing>(bob2.state)
        val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()

        // alice realizes she has an old state...
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishB))
        // ...and asks bob to publish its current commitment
        val errorA = actionsAlice3.findOutgoingMessage<Error>()
        assertEquals(errorA.toAscii(), PleasePublishYourCommitment(aliceOld.channelId).message)
        assertIs<WaitForRemotePublishFutureCommitment>(alice3.state)

        // bob detects that alice has an outdated commitment and stands by
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishA))
        assertIs<Syncing>(bob3.state)
        assertTrue { actionsBob3.isEmpty() }

        // bob receives the error from alice and publishes his local commitment tx
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(errorA))
        assertIs<Closing>(bob4.state)
        assertNotNull(bob4.state.localCommitPublished)
        val bobCommitTx = bob4.state.localCommitPublished!!.commitTx
        actionsBob4.hasPublishTx(bobCommitTx)

        // alice is able to claim her main output
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.WatchReceived(WatchEventSpent(aliceOld.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertIs<Closing>(alice4.state)
        assertNotNull(alice4.state.futureRemoteCommitPublished)
        assertEquals(bobCommitTx, alice4.state.futureRemoteCommitPublished!!.commitTx)
        assertNotNull(alice4.state.futureRemoteCommitPublished!!.claimMainOutputTx)
        assertTrue(alice4.state.futureRemoteCommitPublished!!.claimHtlcTxs.isEmpty())
        actionsAlice4.hasPublishTx(alice4.state.futureRemoteCommitPublished!!.claimMainOutputTx!!.tx)
        Transaction.correctlySpends(alice4.state.futureRemoteCommitPublished!!.claimMainOutputTx!!.tx, bobCommitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `counterparty lies about having a more recent commitment and publishes current commitment`() {
        val (alice0, bob0) = TestsHelper.reachNormal(bobUsePeerStorage = false)
        // The current state contains a pending htlc.
        val (alice1, bob1) = run {
            val (aliceTmp, bobTmp) = TestsHelper.addHtlc(250_000_000.msat, alice0, bob0).first
            TestsHelper.crossSign(aliceTmp, bobTmp)
        }
        val bobCommitTx = bob1.commitments.latest.localCommit.publishableTxs.commitTx.tx

        // We simulate a disconnection followed by a reconnection.
        val (alice2, bob2) = disconnect(alice1, bob1)
        val localInit = Init(alice0.commitments.params.localParams.features)
        val remoteInit = Init(bob0.commitments.params.localParams.features)
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.Connected(localInit, remoteInit))
        assertIs<LNChannel<Syncing>>(alice3)
        actionsAlice3.findOutgoingMessage<ChannelReestablish>()
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.Connected(remoteInit, localInit))
        assertIs<LNChannel<Syncing>>(bob3)
        val invalidReestablish = actionsBob3.findOutgoingMessage<ChannelReestablish>().copy(nextRemoteRevocationNumber = 42)

        // Alice then asks Bob to publish his commitment to find out if Bob is lying.
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(invalidReestablish))
        assertIs<LNChannel<WaitForRemotePublishFutureCommitment>>(alice4)
        assertEquals(alice4.state.remoteChannelReestablish, invalidReestablish)
        assertEquals(actionsAlice4.size, 2)
        val error = actionsAlice4.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), PleasePublishYourCommitment(alice0.channelId).message)
        actionsAlice4.has<ChannelAction.Storage.StoreState>()

        // Bob publishes the latest commitment.
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.WatchReceived(WatchEventSpent(alice0.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        // Alice is able to claim her main output and the htlc (once it times out).
        assertIs<LNChannel<Closing>>(alice5)
        assertEquals(actionsAlice5.size, 7)
        val remoteCommitPublished = alice5.state.remoteCommitPublished
        assertNotNull(remoteCommitPublished)
        assertEquals(remoteCommitPublished.claimHtlcTxs.size, 1)
        val claimMainTx = remoteCommitPublished.claimMainOutputTx!!.tx
        val claimHtlcTx = remoteCommitPublished.claimHtlcTxs.values.first()!!.tx
        listOf(claimMainTx, claimHtlcTx).forEach { Transaction.correctlySpends(it, listOf(bobCommitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }
        actionsAlice5.hasPublishTx(claimMainTx)
        actionsAlice5.hasPublishTx(claimHtlcTx)
        assertEquals(actionsAlice5.findWatches<WatchConfirmed>().map { it.txId }.toSet(), setOf(bobCommitTx.txid, claimMainTx.txid))
        val watchHtlcOutputSpent = actionsAlice5.findWatch<WatchSpent>()
        assertEquals(watchHtlcOutputSpent.event, BITCOIN_OUTPUT_SPENT)
        assertEquals(watchHtlcOutputSpent.txId, remoteCommitPublished.claimHtlcTxs.keys.first().txid)
        assertEquals(watchHtlcOutputSpent.outputIndex, remoteCommitPublished.claimHtlcTxs.keys.first().index.toInt())
        actionsAlice5.has<ChannelAction.Storage.StoreState>()
        actionsAlice5.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
    }

    @Test
    fun `counterparty lies about having a more recent commitment and publishes revoked commitment`() {
        val (alice0, bob0) = TestsHelper.reachNormal(bobUsePeerStorage = false)
        // We sign a new commitment to make sure the first one is revoked.
        val bobRevokedCommitTx = bob0.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice1, bob1) = run {
            val (aliceTmp, bobTmp) = TestsHelper.addHtlc(250_000_000.msat, alice0, bob0).first
            TestsHelper.crossSign(aliceTmp, bobTmp)
        }

        // We simulate a disconnection followed by a reconnection.
        val (alice2, bob2) = disconnect(alice1, bob1)
        val localInit = Init(alice0.commitments.params.localParams.features)
        val remoteInit = Init(bob0.commitments.params.localParams.features)
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.Connected(localInit, remoteInit))
        assertIs<LNChannel<Syncing>>(alice3)
        actionsAlice3.findOutgoingMessage<ChannelReestablish>()
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.Connected(remoteInit, localInit))
        assertIs<LNChannel<Syncing>>(bob3)
        val invalidReestablish = actionsBob3.findOutgoingMessage<ChannelReestablish>().copy(nextLocalCommitmentNumber = 42)

        // Alice then asks Bob to publish his commitment to find out if Bob is lying.
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(invalidReestablish))
        assertIs<LNChannel<WaitForRemotePublishFutureCommitment>>(alice4)
        assertEquals(alice4.state.remoteChannelReestablish, invalidReestablish)
        assertEquals(actionsAlice4.size, 2)
        val error = actionsAlice4.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), PleasePublishYourCommitment(alice0.channelId).message)
        actionsAlice4.has<ChannelAction.Storage.StoreState>()

        // Bob publishes the revoked commitment.
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.WatchReceived(WatchEventSpent(alice0.channelId, BITCOIN_FUNDING_SPENT, bobRevokedCommitTx)))
        // Alice is able to claim all outputs.
        assertIs<LNChannel<Closing>>(alice5)
        assertEquals(actionsAlice5.size, 9)
        val revokedCommitPublished = alice5.state.revokedCommitPublished.firstOrNull()
        assertNotNull(revokedCommitPublished)
        val claimMainTx = revokedCommitPublished.claimMainOutputTx!!.tx
        val claimMainPenaltyTx = revokedCommitPublished.mainPenaltyTx!!.tx
        listOf(claimMainTx, claimMainPenaltyTx).forEach { Transaction.correctlySpends(it, listOf(bobRevokedCommitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }
        actionsAlice5.hasPublishTx(claimMainTx)
        actionsAlice5.hasPublishTx(claimMainPenaltyTx)
        assertEquals(actionsAlice5.find<ChannelAction.Storage.GetHtlcInfos>().revokedCommitTxId, bobRevokedCommitTx.txid)
        assertEquals(actionsAlice5.findWatches<WatchConfirmed>().map { it.txId }.toSet(), setOf(bobRevokedCommitTx.txid, claimMainTx.txid))
        val watchSpent = actionsAlice5.findWatch<WatchSpent>()
        assertEquals(watchSpent.event, BITCOIN_OUTPUT_SPENT)
        assertEquals(watchSpent.txId, bobRevokedCommitTx.txid)
        assertEquals(watchSpent.outputIndex, claimMainPenaltyTx.txIn.first().outPoint.index.toInt())
        actionsAlice5.has<ChannelAction.Storage.StoreState>()
        actionsAlice5.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
        actionsAlice5.hasOutgoingMessage<Error>()
    }

    @Test
    fun `reprocess pending incoming htlcs after disconnection or wallet restart`() {
        val (alice, bob, htlcs) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobUsePeerStorage = false)
            val (aliceId, bobId) = Pair(alice0.staticParams.nodeParams.nodeId, bob0.staticParams.nodeParams.nodeId)
            val currentBlockHeight = alice0.currentBlockHeight.toLong()
            // We add some htlcs Alice ---> Bob
            val (alice1, bob1, htlc1) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(75_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice0, bob0)
            val (alice2, bob2, htlc2) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(50_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice1, bob1)
            val (alice3, bob3, htlc3) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(65_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice2, bob2)
            // And htlcs Bob ---> Alice
            val (bob4, alice4, htlc4) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(45_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob3, alice3)
            val (bob5, alice5, htlc5) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(55_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob4, alice4)
            val (alice6, bob6) = TestsHelper.crossSign(alice5, bob5)
            // And some htlcs aren't signed yet: they will be dropped when disconnecting, and may be retransmitted later.
            val (bob7, alice7, _) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(50_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob6, alice6)
            val (alice8, bob8, _) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(70_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice7, bob7)
            assertIs<LNChannel<Normal>>(alice8)
            assertIs<LNChannel<Normal>>(bob8)
            Triple(alice8, bob8, listOf(htlc1, htlc2, htlc3, htlc4, htlc5))
        }

        // Bob's wallet disconnects, but doesn't restart.
        val (bob1, _) = bob.process(ChannelCommand.Disconnected)
        assertIs<Offline>(bob1.state)

        // Alice's wallet restarts.
        val initState = LNChannel(alice.ctx, WaitForInit)
        val (alice1, actions1) = initState.process(ChannelCommand.Init.Restore(alice.state))
        assertEquals(1, actions1.size)
        actions1.hasWatch<WatchSpent>()
        assertIs<Offline>(alice1.state)

        val localInit = Init(alice.commitments.params.localParams.features)
        val remoteInit = Init(bob.commitments.params.localParams.features)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Connected(localInit, remoteInit))
        assertIs<Syncing>(alice2.state)
        assertTrue(actionsAlice2.filterIsInstance<ChannelAction.ProcessIncomingHtlc>().isEmpty())
        val channelReestablishAlice = actionsAlice2.hasOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.Connected(localInit, remoteInit))
        assertTrue(actionsBob2.filterIsInstance<ChannelAction.ProcessIncomingHtlc>().isEmpty())
        val channelReestablishBob = actionsBob2.hasOutgoingMessage<ChannelReestablish>()

        // Alice reprocesses the htlcs received from Bob.
        val (_, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(2, actionsAlice3.size)
        val expectedHtlcsAlice = htlcs.drop(3).take(2).map { ChannelAction.ProcessIncomingHtlc(it) }
        assertEquals(expectedHtlcsAlice, actionsAlice3.filterIsInstance<ChannelAction.ProcessIncomingHtlc>())

        // Bob reprocesses the htlcs received from Alice.
        val (_, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(3, actionsBob3.size)
        val expectedHtlcsBob = htlcs.take(3).map { ChannelAction.ProcessIncomingHtlc(it) }
        assertEquals(expectedHtlcsBob, actionsBob3.filterIsInstance<ChannelAction.ProcessIncomingHtlc>())
    }

    @Test
    fun `reprocess pending incoming htlcs after disconnection or wallet restart -- htlc settlement signed by us`() {
        val (alice, bob, htlcs) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobUsePeerStorage = false)
            val (aliceId, bobId) = Pair(alice0.staticParams.nodeParams.nodeId, bob0.staticParams.nodeParams.nodeId)
            val currentBlockHeight = alice0.currentBlockHeight.toLong()
            val preimage = randomBytes32()
            // Alice sends some htlcs to Bob.
            val (alice1, bob1, htlc1) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(75_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice0, bob0)
            val (alice2, bob2, htlc2) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(50_000.msat, bobId, currentBlockHeight, preimage).second, alice1, bob1)
            val (alice3, bob3, htlc3) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(65_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice2, bob2)
            // Bob sends some htlcs to Alice.
            val (bob4, alice4, htlc4) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(45_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob3, alice3)
            val (bob5, alice5, htlc5) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(55_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob4, alice4)
            val (alice6, bob6) = TestsHelper.crossSign(alice5, bob5)
            // Bob settles the first two htlcs and sends his signature, but Alice doesn't receive these messages.
            val (bob7, _) = bob6.process(ChannelCommand.Htlc.Settlement.Fail(htlc1.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(PaymentTimeout), commit = false))
            val (bob8, _) = bob7.process(ChannelCommand.Htlc.Settlement.Fulfill(htlc2.id, preimage, commit = false))
            val (bob9, _) = bob8.process(ChannelCommand.Commitment.Sign)
            assertIs<LNChannel<Normal>>(alice6)
            assertIs<LNChannel<Normal>>(bob9)
            Triple(alice6, bob9, listOf(htlc1, htlc2, htlc3, htlc4, htlc5))
        }

        // Alice and Bob are disconnected.
        val (alice1, bob1) = disconnect(alice, bob)
        val aliceInit = Init(alice.commitments.params.localParams.features)
        val bobInit = Init(bob.commitments.params.localParams.features)

        val (alice2, actionsAlice) = alice1.process(ChannelCommand.Connected(aliceInit, bobInit))
        val (bob2, _) = bob1.process(ChannelCommand.Connected(bobInit, aliceInit))
        assertIs<Syncing>(alice2.state)
        assertIs<Syncing>(bob2.state)
        val channelReestablishAlice = actionsAlice.hasOutgoingMessage<ChannelReestablish>()

        // Bob resends htlc settlement messages to Alice and reprocesses unsettled htlcs.
        val (_, actionsBob) = bob2.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(4, actionsBob.size)
        val fail = actionsBob.hasOutgoingMessage<UpdateFailHtlc>()
        assertEquals(fail.id, htlcs[0].id)
        val fulfill = actionsBob.hasOutgoingMessage<UpdateFulfillHtlc>()
        assertEquals(fulfill.id, htlcs[1].id)
        actionsBob.hasOutgoingMessage<CommitSig>()
        assertEquals(listOf(ChannelAction.ProcessIncomingHtlc(htlcs[2])), actionsBob.filterIsInstance<ChannelAction.ProcessIncomingHtlc>())
    }

    @Test
    fun `republish unconfirmed funding tx after restart`() {
        val (alice, bob, fundingTx) = WaitForFundingConfirmedTestsCommon.init(ChannelType.SupportedChannelType.AnchorOutputs)
        // Alice restarts:
        val (alice1, actionsAlice1) = LNChannel(alice.ctx, WaitForInit).process(ChannelCommand.Init.Restore(alice.state))
        assertEquals(alice1.state, Offline(alice.state))
        assertEquals(actionsAlice1.size, 2)
        actionsAlice1.hasPublishTx(fundingTx)
        assertEquals(actionsAlice1.findWatch<WatchConfirmed>().txId, fundingTx.txid)
        // Bob restarts:
        val (bob1, actionsBob1) = LNChannel(bob.ctx, WaitForInit).process(ChannelCommand.Init.Restore(bob.state))
        assertEquals(bob1.state, Offline(bob.state))
        assertEquals(actionsBob1.size, 2)
        actionsBob1.hasPublishTx(fundingTx)
        assertEquals(actionsBob1.findWatch<WatchConfirmed>().txId, fundingTx.txid)
    }

    @Test
    fun `republish unconfirmed funding tx with previous funding txs after restart`() {
        val (alice, bob, previousFundingTx, walletAlice) = WaitForFundingConfirmedTestsCommon.init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, bob1, fundingTx) = WaitForFundingConfirmedTestsCommon.rbf(alice, bob, walletAlice)
        assertEquals(alice1.commitments.active.size, 2)
        assertNotEquals(previousFundingTx.txid, fundingTx.txid)
        // Alice restarts:
        val (alice2, actionsAlice2) = LNChannel(alice1.ctx, WaitForInit).process(ChannelCommand.Init.Restore(alice1.state))
        assertEquals(alice2.state, Offline(alice1.state))
        assertEquals(actionsAlice2.size, 4)
        actionsAlice2.hasPublishTx(previousFundingTx)
        actionsAlice2.hasPublishTx(fundingTx)
        assertEquals(actionsAlice2.findWatches<WatchConfirmed>().map { it.txId }.toSet(), setOf(previousFundingTx.txid, fundingTx.txid))
        // Bob restarts:
        val (bob2, actionsBob2) = LNChannel(bob1.ctx, WaitForInit).process(ChannelCommand.Init.Restore(bob1.state))
        assertEquals(bob2.state, Offline(bob1.state))
        assertEquals(actionsBob2.size, 4)
        actionsBob2.hasPublishTx(previousFundingTx)
        actionsBob2.hasPublishTx(fundingTx)
        assertEquals(actionsBob2.findWatches<WatchConfirmed>().map { it.txId }.toSet(), setOf(previousFundingTx.txid, fundingTx.txid))
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK`() {
        val (alice, bob, _) = WaitForFundingConfirmedTestsCommon.init(ChannelType.SupportedChannelType.AnchorOutputs)
        val fundingTx = alice.state.latestFundingTx.sharedTx.tx.buildUnsignedTx()
        val (alice1, bob1) = disconnect(alice, bob)
        // outer state is Offline, we check the inner states
        assertIs<WaitForFundingConfirmed>(alice1.state.state)
        assertIs<WaitForFundingConfirmed>(bob1.state.state)
        val (_, _) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
            .also { (state, actions) ->
                assertIs<Offline>(state.state)
                assertEquals(2, actions.size)
                assertIs<WaitForChannelReady>(state.state.state)
                actions.hasWatchFundingSpent(fundingTx.txid)
                actions.has<ChannelAction.Storage.StoreState>()
            }
        val (_, _) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
            .also { (state, actions) ->
                assertIs<Offline>(state.state)
                assertEquals(2, actions.size)
                assertIs<WaitForChannelReady>(state.state.state)
                actions.hasWatchFundingSpent(fundingTx.txid)
                actions.has<ChannelAction.Storage.StoreState>()
            }
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- previous funding tx`() {
        val (alice, bob, previousFundingTx, walletAlice) = WaitForFundingConfirmedTestsCommon.init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, bob1) = WaitForFundingConfirmedTestsCommon.rbf(alice, bob, walletAlice)
        val (alice2, bob2) = disconnect(alice1, bob1)
        assertIs<WaitForFundingConfirmed>(alice2.state.state)
        assertIs<WaitForFundingConfirmed>(bob2.state.state)
        val (_, _) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, previousFundingTx)))
            .also { (state, actions) ->
                assertIs<Offline>(state.state)
                assertIs<WaitForChannelReady>(state.state.state)
                assertEquals(1, state.commitments.active.size)
                assertEquals(previousFundingTx.txid, state.commitments.latest.fundingTxId)
                assertIs<LocalFundingStatus.ConfirmedFundingTx>(state.commitments.latest.localFundingStatus)
                assertEquals(2, actions.size)
                actions.hasWatchFundingSpent(previousFundingTx.txid)
                actions.has<ChannelAction.Storage.StoreState>()
            }
        val (_, _) = bob2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, previousFundingTx)))
            .also { (state, actions) ->
                assertIs<Offline>(state.state)
                assertIs<WaitForChannelReady>(state.state.state)
                assertEquals(1, state.commitments.active.size)
                assertEquals(previousFundingTx.txid, state.commitments.latest.fundingTxId)
                assertIs<LocalFundingStatus.ConfirmedFundingTx>(state.commitments.latest.localFundingStatus)
                assertEquals(2, actions.size)
                actions.hasWatchFundingSpent(previousFundingTx.txid)
                actions.has<ChannelAction.Storage.StoreState>()
            }
    }

    @Test
    fun `recv CheckHtlcTimeout -- no htlc timed out`() {
        val (alice0, bob0) = TestsHelper.reachNormal()
        val (nodes, _, _) = TestsHelper.addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = TestsHelper.crossSign(nodes.first, nodes.second)
        val (alice2, _) = alice1.process(ChannelCommand.Disconnected)
        assertIs<Offline>(alice2.state)

        val (alice3, actions3) = alice2.process(ChannelCommand.Commitment.CheckHtlcTimeout)
        assertIs<Offline>(alice3.state)
        assertEquals(alice2.state.state, alice3.state.state)
        assertTrue(actions3.isEmpty())
    }

    @Test
    fun `recv NewBlock -- an htlc timed out`() {
        val (alice0, bob0) = TestsHelper.reachNormal()
        val (nodes, _, htlc) = TestsHelper.addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = TestsHelper.crossSign(nodes.first, nodes.second)
        val (alice2, _) = alice1.process(ChannelCommand.Disconnected)
        assertIs<Offline>(alice2.state)

        // alice restarted after the htlc timed out
        val alice3 = alice2.copy(
            ctx = alice2.ctx.copy(currentBlockHeight = htlc.cltvExpiry.toLong().toInt()),
            state = alice2.state.state
        )
        val (alice4, actions) = alice3.process(ChannelCommand.Commitment.CheckHtlcTimeout)
        assertIs<Closing>(alice4.state)
        assertNotNull(alice4.state.localCommitPublished)
        actions.hasOutgoingMessage<Error>()
        actions.has<ChannelAction.Storage.StoreState>()
        val lcp = alice4.state.localCommitPublished!!
        actions.hasPublishTx(lcp.commitTx)
        assertEquals(1, lcp.htlcTimeoutTxs().size)
        assertEquals(1, lcp.claimHtlcDelayedTxs.size)
        assertEquals(4, actions.findPublishTxs().size) // commit tx + main output + htlc-timeout + claim-htlc-delayed
        assertEquals(3, actions.findWatches<WatchConfirmed>().size) // commit tx + main output + claim-htlc-delayed
        assertEquals(1, actions.findWatches<WatchSpent>().size) // htlc-timeout
    }

    @Test
    fun `recv CheckHtlcTimeout -- fulfilled signed htlc ignored by peer`() {
        val (alice0, bob0) = TestsHelper.reachNormal()
        val (nodes, preimage, htlc) = TestsHelper.addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = TestsHelper.crossSign(nodes.first, nodes.second)
        val (bob2, actions2) = bob1.process(ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, preimage))
        actions2.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob3, _) = bob2.process(ChannelCommand.Disconnected)
        assertIs<Offline>(bob3.state)

        // bob restarts when the fulfilled htlc is close to timing out: alice hasn't signed, so bob closes the channel
        val (bob4, actions4) = run {
            val tmp = bob3.copy(ctx = bob3.ctx.copy(currentBlockHeight = htlc.cltvExpiry.toLong().toInt()))
            tmp.process(ChannelCommand.Commitment.CheckHtlcTimeout)
        }
        assertIs<Closing>(bob4.state)
        assertNotNull(bob4.state.localCommitPublished)
        actions4.has<ChannelAction.Storage.StoreState>()

        val lcp = bob4.state.localCommitPublished!!
        assertNotNull(lcp.claimMainDelayedOutputTx)
        assertEquals(1, lcp.htlcSuccessTxs().size)
        Transaction.correctlySpends(lcp.htlcSuccessTxs().first().tx, lcp.commitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        assertEquals(1, lcp.claimHtlcDelayedTxs.size)
        Transaction.correctlySpends(lcp.claimHtlcDelayedTxs.first().tx, lcp.htlcSuccessTxs().first().tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        val txs = setOf(lcp.commitTx, lcp.claimMainDelayedOutputTx!!.tx, lcp.htlcSuccessTxs().first().tx, lcp.claimHtlcDelayedTxs.first().tx)
        assertEquals(txs, actions4.findPublishTxs().toSet())
        val watchConfirmed = listOf(lcp.commitTx, lcp.claimMainDelayedOutputTx!!.tx, lcp.claimHtlcDelayedTxs.first().tx).map { it.txid }.toSet()
        assertEquals(watchConfirmed, actions4.findWatches<WatchConfirmed>().map { it.txId }.toSet())
        val watchSpent = setOf(lcp.htlcSuccessTxs().first().input.outPoint)
        assertEquals(watchSpent, actions4.findWatches<WatchSpent>().map { OutPoint(lcp.commitTx, it.outputIndex.toLong()) }.toSet())
    }

    @Test
    fun `recv ChannelCommand_Close_ForceClose`() {
        val (alice, _) = TestsHelper.reachNormal()
        val (alice1, _) = alice.process(ChannelCommand.Disconnected)
        assertIs<Offline>(alice1.state)
        val commitTx = alice1.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice2, actions2) = alice1.process(ChannelCommand.Close.ForceClose)
        assertIs<Closing>(alice2.state)
        assertTrue(actions2.contains(ChannelAction.Storage.StoreState(alice2.state)))
        actions2.hasPublishTx(commitTx)
        actions2.hasWatchConfirmed(commitTx.txid)
        actions2.hasOutgoingMessage<Error>()
        assertEquals(1, actions2.filterIsInstance<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>().size)
    }

    @Test
    fun `forget unsigned channel`() {
        val (alice, bob, fundingTxId) = run {
            val (alice, bob, inputAlice) = WaitForFundingCreatedTestsCommon.init()
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(inputAlice))
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<TxAddInput>()))
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<TxAddOutput>()))
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
            actionsAlice2.hasOutgoingMessage<TxComplete>()
            actionsAlice2.hasOutgoingMessage<CommitSig>()
            assertIs<WaitForFundingCreated>(bob2.state)
            assertIs<WaitForFundingSigned>(alice2.state)
            Triple(alice2, bob2, alice2.state.signingSession.fundingTx.txId)
        }

        // Bob has not received Alice's tx_complete, so he's not storing the channel.
        val (bob1, _) = bob.process(ChannelCommand.Disconnected)
        assertIs<Aborted>(bob1.state)

        // On reconnection, Alice tries to resume the signing session.
        val (alice1, _) = alice.process(ChannelCommand.Disconnected)
        assertIs<Offline>(alice1.state)
        val (alice2, _) = LNChannel(alice1.ctx, WaitForInit).process(ChannelCommand.Init.Restore(alice1.state.state))
        assertIs<Offline>(alice2.state)
        val aliceInit = Init((alice.state as WaitForFundingSigned).channelParams.localParams.features.initFeatures())
        val bobInit = Init((bob.state as WaitForFundingCreated).localParams.features.initFeatures())
        val (alice3, actions3) = alice2.process(ChannelCommand.Connected(aliceInit, bobInit))
        assertIs<Syncing>(alice3.state)
        assertEquals(alice.state, alice3.state.state)
        assertEquals(actions3.size, 1)
        assertEquals(actions3.hasOutgoingMessage<ChannelReestablish>().nextFundingTxId, fundingTxId)
        // When receiving Bob's error, Alice forgets the channel.
        val (alice4, actions4) = alice3.process(ChannelCommand.MessageReceived(Error(alice.channelId, "unknown channel")))
        assertIs<Aborted>(alice4.state)
        assertEquals(1, actions4.size)
        actions4.find<ChannelAction.Storage.RemoveChannel>().also { assertEquals(alice.channelId, it.data.channelId) }
    }

    @Test
    fun `forget unsigned rbf attempt`() {
        val (alice, bob, rbfFundingTxId) = run {
            val (alice, bob, _, wallet) = WaitForFundingConfirmedTestsCommon.init()
            val command = WaitForFundingConfirmedTestsCommon.createRbfCommand(alice, wallet)
            val (alice1, actionsAlice1) = alice.process(command)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<TxInitRbf>()))
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<TxAckRbf>()))
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxAddInput>()))
            val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxAddInput>()))
            val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice3.findOutgoingMessage<TxAddInput>()))
            val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(actionsBob3.findOutgoingMessage<TxComplete>()))
            val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(actionsAlice4.findOutgoingMessage<TxAddOutput>()))
            val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(actionsBob4.findOutgoingMessage<TxComplete>()))
            actionsAlice5.hasOutgoingMessage<TxComplete>()
            actionsAlice5.hasOutgoingMessage<CommitSig>()
            actionsAlice5.has<ChannelAction.Storage.StoreState>()
            assertIs<WaitForFundingConfirmed>(bob4.state)
            assertIs<RbfStatus.InProgress>(bob4.state.rbfStatus)
            assertIs<WaitForFundingConfirmed>(alice5.state)
            assertIs<RbfStatus.WaitingForSigs>(alice5.state.rbfStatus)
            Triple(alice5, bob4, (alice5.state.rbfStatus as RbfStatus.WaitingForSigs).session.fundingTx.txId)
        }

        val aliceInit = Init(alice.commitments.params.localParams.features)
        val bobInit = Init(bob.commitments.params.localParams.features)

        // Bob has not received Alice's tx_complete, so he's not storing the RBF attempt.
        val (bob1, _) = bob.process(ChannelCommand.Disconnected)
        assertIs<Offline>(bob1.state)
        assertIs<WaitForFundingConfirmed>(bob1.state.state)
        assertEquals((bob1.state.state as WaitForFundingConfirmed).rbfStatus, RbfStatus.None)

        // Alice has sent commit_sig, so she's storing the RBF attempt.
        val (alice1, _) = alice.process(ChannelCommand.Disconnected)
        assertIs<Offline>(alice1.state)
        assertIs<WaitForFundingConfirmed>(alice1.state.state)
        assertIs<RbfStatus.WaitingForSigs>((alice1.state.state as WaitForFundingConfirmed).rbfStatus)

        // On reconnection, Alice tries to resume the RBF signing session: Bob reacts by aborting it.
        val (alice2, _) = LNChannel(alice1.ctx, WaitForInit).process(ChannelCommand.Init.Restore(alice1.state.state))
        val (bob2, _) = LNChannel(bob1.ctx, WaitForInit).process(ChannelCommand.Init.Restore(bob1.state.state))
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.Connected(aliceInit, bobInit))
        assertIs<Syncing>(alice3.state)
        val channelReestablishAlice = actionsAlice3.hasOutgoingMessage<ChannelReestablish>()
        assertEquals(channelReestablishAlice.nextFundingTxId, rbfFundingTxId)
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.Connected(bobInit, aliceInit))
        assertIs<Syncing>(bob3.state)
        assertTrue(actionsBob3.isEmpty())
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertIs<WaitForFundingConfirmed>(bob4.state)
        val channelReestablishBob = actionsBob4.hasOutgoingMessage<ChannelReestablish>()
        assertNull(channelReestablishBob.nextFundingTxId)
        val txAbortBob = actionsBob4.hasOutgoingMessage<TxAbort>()
        assertEquals(bob4.state.rbfStatus, RbfStatus.RbfAborted)
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertIs<WaitForFundingConfirmed>(alice4.state)
        assertIs<RbfStatus.WaitingForSigs>(alice4.state.rbfStatus)
        assertTrue(actionsAlice4.isEmpty())
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(txAbortBob))
        assertIs<WaitForFundingConfirmed>(alice5.state)
        assertEquals(alice5.state.rbfStatus, RbfStatus.None)
        assertEquals(alice5.state.commitments.active.size, 1)
        actionsAlice5.hasOutgoingMessage<TxAbort>()
    }

    @Test
    fun `restore closing channel`() {
        val bob = run {
            val (alice, bob) = TestsHelper.reachNormal()
            // alice publishes her commitment tx
            val (bob1, _) = bob.process(ChannelCommand.WatchReceived(WatchEventSpent(bob.channelId, BITCOIN_FUNDING_SPENT, alice.commitments.latest.localCommit.publishableTxs.commitTx.tx)))
            assertIs<LNChannel<Closing>>(bob1)
            assertNull(bob1.state.closingTypeAlreadyKnown())
            bob1
        }

        val state = LNChannel(bob.ctx, WaitForInit)
        val (state1, actions) = state.process(ChannelCommand.Init.Restore(bob.state))
        assertIs<Closing>(state1.state)
        assertEquals(4, actions.size)
        val watchSpent = actions.hasWatch<WatchSpent>()
        assertEquals(bob.commitments.latest.commitInput.outPoint.txid, watchSpent.txId)
        val remoteCommitPublished = bob.state.remoteCommitPublished
        assertNotNull(remoteCommitPublished)
        val claimMainOutputTx = remoteCommitPublished.claimMainOutputTx
        assertNotNull(claimMainOutputTx)
        actions.hasPublishTx(claimMainOutputTx.tx)
        val watches = actions.findWatches<WatchConfirmed>()
        assertEquals(2, watches.size)
        assertNotNull(watches.first { it.txId == remoteCommitPublished.commitTx.txid })
        assertNotNull(watches.first { it.txId == claimMainOutputTx.tx.txid })
    }

    companion object {
        fun disconnect(alice: LNChannel<PersistedChannelState>, bob: LNChannel<PersistedChannelState>): Pair<LNChannel<Offline>, LNChannel<Offline>> {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.Disconnected)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.Disconnected)
            assertIs<LNChannel<Offline>>(alice1)
            assertTrue(actionsAlice1.isEmpty())
            assertIs<LNChannel<Offline>>(bob1)
            assertTrue(actionsBob1.isEmpty())
            return Pair(alice1, bob1)
        }
    }

}
