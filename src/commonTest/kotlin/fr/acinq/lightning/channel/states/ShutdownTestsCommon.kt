package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.Feature
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.Features
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_SPENT
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.blockchain.WatchSpent
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.addHtlc
import fr.acinq.lightning.channel.TestsHelper.claimHtlcSuccessTxs
import fr.acinq.lightning.channel.TestsHelper.claimHtlcTimeoutTxs
import fr.acinq.lightning.channel.TestsHelper.crossSign
import fr.acinq.lightning.channel.TestsHelper.fulfillHtlc
import fr.acinq.lightning.channel.TestsHelper.makeCmdAdd
import fr.acinq.lightning.channel.TestsHelper.processEx
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.channel.TestsHelper.signAndRevack
import fr.acinq.lightning.serialization.Serialization
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.Either
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.*
import kotlin.test.*

class ShutdownTestsCommon : LightningTestSuite() {

    @Test
    fun `recv CMD_ADD_HTLC`() {
        val (_, bob) = init()
        val add = CMD_ADD_HTLC(500000000.msat, r1, cltvExpiry = CltvExpiry(300000), TestConstants.emptyOnionPacket, UUID.randomUUID())
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(add))
        assertTrue(bob1 is ShuttingDown)
        assertTrue(actions1.any { it is ChannelAction.ProcessCmdRes.AddFailed && it.error == ChannelUnavailable(bob.channelId) })
        assertEquals(bob1.commitments.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.Wumbo)))
    }

    @Test
    fun `recv CMD_ADD_HTLC (zero-reserve)`() {
        val (_, bob) = init(bobFeatures = TestConstants.Bob.nodeParams.features.add(Feature.ZeroReserveChannels to FeatureSupport.Optional))
        val add = CMD_ADD_HTLC(500000000.msat, r1, cltvExpiry = CltvExpiry(300000), TestConstants.emptyOnionPacket, UUID.randomUUID())
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(add))
        assertTrue(bob1 is ShuttingDown)
        assertTrue(actions1.any { it is ChannelAction.ProcessCmdRes.AddFailed && it.error == ChannelUnavailable(bob.channelId) })
        assertEquals(bob1.commitments.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.Wumbo, Feature.ZeroReserveChannels)))
    }

    @Test
    fun `recv CMD_FULFILL_HTLC`() {
        val (_, bob) = init()
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(0, r1)))
        val fulfill = actions1.findOutgoingMessage<UpdateFulfillHtlc>()
        assertTrue { bob1 is ShuttingDown && bob1.commitments.localChanges.proposed.contains(fulfill) }
    }

    @Test
    fun `recv CMD_FULFILL_HTLC (unknown htlc id)`() {
        val (_, bob) = init()
        val cmd = CMD_FULFILL_HTLC(42, randomBytes32())
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(cmd))
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, UnknownHtlcId(bob.channelId, 42))))
        assertEquals(bob1, bob)
    }

    @Test
    fun `recv CMD_FULFILL_HTLC (invalid preimage)`() {
        val (_, bob) = init()
        val cmd = CMD_FULFILL_HTLC(0, randomBytes32())
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(cmd))
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, InvalidHtlcPreimage(bob.channelId, 0))))
        assertEquals(bob1, bob)
    }

    @Test
    fun `recv UpdateFulfillHtlc`() {
        val (alice, bob) = init()
        val (_, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(0, r1)))
        val fulfill = actions1.findOutgoingMessage<UpdateFulfillHtlc>()
        val (alice1, _) = alice.processEx(ChannelEvent.MessageReceived(fulfill))
        assertTrue { alice1 is ShuttingDown && alice1.commitments.remoteChanges.proposed.contains(fulfill) }
    }

    @Test
    fun `recv UpdateFulfillHtlc (unknown htlc id)`() {
        val (alice, _) = init()
        val (alice1, actions) = alice.processEx(ChannelEvent.MessageReceived(UpdateFulfillHtlc(alice.channelId, 42, r1)))
        actions.hasOutgoingMessage<Error>()
        // Alice should publish: commit tx + main delayed tx + 2 * htlc timeout txs + 2 * htlc delayed txs
        assertEquals(6, actions.findTxs().size)
        assertTrue(alice1 is Closing)
    }

    @Test
    fun `recv UpdateFulfillHtlc (invalid preimage)`() {
        val (alice, _) = init()
        val (alice1, actions) = alice.processEx(ChannelEvent.MessageReceived(UpdateFulfillHtlc(alice.channelId, 0, randomBytes32())))
        actions.hasOutgoingMessage<Error>()
        // Alice should publish: commit tx + main delayed tx + 2 * htlc timeout txs + 2 * htlc delayed txs
        assertEquals(6, actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().size)
        assertTrue(alice1 is Closing)
    }

    @Test
    fun `recv CMD_FAIL_HTLC`() {
        val (_, bob) = init()
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FAIL_HTLC(0, CMD_FAIL_HTLC.Reason.Failure(PermanentChannelFailure))))
        val fail = actions1.findOutgoingMessage<UpdateFailHtlc>()
        assertTrue { bob1 is ShuttingDown && bob1.commitments.localChanges.proposed.contains(fail) }
    }

    @Test
    fun `recv CMD_FAIL_HTLC (unknown htlc id)`() {
        val (_, bob) = init()
        val cmdFail = CMD_FAIL_HTLC(42, CMD_FAIL_HTLC.Reason.Failure(PermanentChannelFailure))
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(cmdFail))
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmdFail, UnknownHtlcId(bob.channelId, 42))))
        assertEquals(bob, bob1)
    }

    @Test
    fun `recv CMD_FAIL_MALFORMED_HTLC`() {
        val (_, bob) = init()
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FAIL_MALFORMED_HTLC(1, ByteVector32(Crypto.sha256(ByteVector.empty)), FailureMessage.BADONION)))
        val fail = actions1.findOutgoingMessage<UpdateFailMalformedHtlc>()
        assertTrue { bob1 is ShuttingDown && bob1.commitments.localChanges.proposed.contains(fail) }
    }

    @Test
    fun `recv CMD_FAIL_MALFORMED_HTLC (unknown htlc id)`() {
        val (_, bob) = init()
        val cmdFail = CMD_FAIL_MALFORMED_HTLC(42, ByteVector32(Crypto.sha256(ByteVector.empty)), FailureMessage.BADONION)
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(cmdFail))
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmdFail, UnknownHtlcId(bob.channelId, 42))))
        assertEquals(bob, bob1)
    }

    @Test
    fun `recv CMD_FAIL_MALFORMED_HTLC (invalid failure_code)`() {
        val (_, bob) = init()
        val cmdFail = CMD_FAIL_MALFORMED_HTLC(42, randomBytes32(), 42)
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(cmdFail))
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmdFail, InvalidFailureCode(bob.channelId))))
        assertEquals(bob, bob1)
    }

    @Test
    fun `recv UpdateFailHtlc`() {
        val (alice, bob) = init()
        val (_, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FAIL_HTLC(0, CMD_FAIL_HTLC.Reason.Failure(PermanentChannelFailure))))
        val fail = actions1.findOutgoingMessage<UpdateFailHtlc>()
        val (alice1, _) = alice.processEx(ChannelEvent.MessageReceived(fail))
        assertTrue { alice1 is ShuttingDown && alice1.commitments.remoteChanges.proposed.contains(fail) }
    }

    @Test
    fun `recv UpdateFailHtlc (unknown htlc id)`() {
        val (alice, _) = init()
        val commitTx = alice.commitments.localCommit.publishableTxs.commitTx.tx
        val (alice1, actions1) = alice.processEx(ChannelEvent.MessageReceived(UpdateFailHtlc(alice.channelId, 42, ByteVector.empty)))
        assertTrue(alice1 is Closing)
        assertTrue(actions1.contains(ChannelAction.Storage.StoreState(alice1)))
        assertTrue(actions1.contains(ChannelAction.Blockchain.PublishTx(commitTx)))
        assertTrue(actions1.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions1.findWatches<WatchSpent>().isNotEmpty())
        val error = actions1.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice.channelId, 42).message)
    }

    @Test
    fun `recv UpdateFailMalformedHtlc`() {
        val (alice, bob) = init()
        val (_, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FAIL_MALFORMED_HTLC(1, ByteVector32(Crypto.sha256(ByteVector.empty)), FailureMessage.BADONION)))
        val fail = actions1.findOutgoingMessage<UpdateFailMalformedHtlc>()
        val (alice1, _) = alice.processEx(ChannelEvent.MessageReceived(fail))
        assertTrue { alice1 is ShuttingDown && alice1.commitments.remoteChanges.proposed.contains(fail) }
    }

    @Test
    fun `recv UpdateFailMalformedHtlc (invalid failure_code)`() {
        val (alice, _) = init()
        val fail = UpdateFailMalformedHtlc(ByteVector32.Zeroes, 1, ByteVector.empty.sha256(), 42)
        val (alice1, actions) = alice.processEx(ChannelEvent.MessageReceived(fail))
        assertTrue(alice1 is Closing)
        assertTrue(actions.contains(ChannelAction.Storage.StoreState(alice1)))
        assertTrue(actions.contains(ChannelAction.Blockchain.PublishTx(alice.commitments.localCommit.publishableTxs.commitTx.tx)))
        assertEquals(6, actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().size) // commit tx + main delayed + htlc-timeout + htlc delayed
        assertEquals(6, actions.filterIsInstance<ChannelAction.Blockchain.SendWatch>().size)
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InvalidFailureCode(alice.channelId).message)
    }

    @Test
    fun `recv CMD_SIGN`() {
        val (alice, bob) = init()
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(0, r1)))
        val fulfill = actions1.findOutgoingMessage<UpdateFulfillHtlc>()
        val (alice1, _) = alice.processEx(ChannelEvent.MessageReceived(fulfill))
        val (_, alice2) = signAndRevack(bob1, alice1)
        val (alice3, actions3) = alice2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(alice3 is ShuttingDown)
        assertTrue(alice3.commitments.remoteNextCommitInfo.isLeft)
        actions3.hasOutgoingMessage<CommitSig>()
        actions3.has<ChannelAction.Storage.StoreState>()
        // we still have 1 HTLC in the commit tx
        val htlcInfos = actions3.find<ChannelAction.Storage.StoreHtlcInfos>()
        assertEquals(htlcInfos.htlcs.size, 1)
        assertEquals(htlcInfos.htlcs.first().paymentHash, r2.sha256())
    }

    @Test
    fun `recv CMD_SIGN (no changes)`() {
        val (_, bob) = init()
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertEquals(bob, bob1)
        assertTrue { actions1.isEmpty() }
    }

    @Test
    fun `recv CMD_SIGN (while waiting for RevokeAndAck)`() {
        val (_, bob) = init()
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(0, r1)))
        actions1.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob2, actions2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(bob2 is ShuttingDown)
        actions2.hasOutgoingMessage<CommitSig>()
        assertNotNull(bob2.commitments.remoteNextCommitInfo.left)
        val waitForRevocation = bob2.commitments.remoteNextCommitInfo.left!!
        assertFalse(waitForRevocation.reSignAsap)
        val (bob3, actions3) = bob2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(bob3 is ShuttingDown)
        assertTrue(actions3.isEmpty())
        assertEquals(Either.Left(waitForRevocation), bob3.commitments.remoteNextCommitInfo)
    }

    @Test
    fun `recv CommitSig`() {
        val (alice0, bob0) = init()
        val (bob1, actionsBob1) = bob0.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(0, r1)))
        val fulfill = actionsBob1.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (_, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val sig = actionsBob2.hasOutgoingMessage<CommitSig>()
        val (alice1, _) = alice0.processEx(ChannelEvent.MessageReceived(fulfill))
        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.MessageReceived(sig))
        assertTrue(alice2 is ShuttingDown)
        actionsAlice2.hasOutgoingMessage<RevokeAndAck>()
    }

    @Test
    fun `recv CommitSig (no changes)`() {
        val (alice0, bob0) = init()
        val (bob1, actionsBob1) = bob0.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(0, r1)))
        val fulfill = actionsBob1.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (_, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val sig = actionsBob2.hasOutgoingMessage<CommitSig>()
        val (alice1, _) = alice0.processEx(ChannelEvent.MessageReceived(fulfill))
        val (alice2, _) = alice1.processEx(ChannelEvent.MessageReceived(sig))
        assertTrue(alice2 is ShuttingDown)
        // alice receives another commit signature
        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(sig))
        assertTrue(alice3 is Closing)
        actionsAlice3.hasOutgoingMessage<Error>()
        assertNotNull(alice3.localCommitPublished)
        actionsAlice3.hasTx(alice2.commitments.localCommit.publishableTxs.commitTx.tx)
    }

    @Test
    fun `recv CommitSig (invalid signature)`() {
        val (alice0, bob0) = init()
        val (bob1, actionsBob1) = bob0.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(0, r1)))
        val fulfill = actionsBob1.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (_, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val sig = actionsBob2.hasOutgoingMessage<CommitSig>()
        val (alice1, _) = alice0.processEx(ChannelEvent.MessageReceived(fulfill))
        assertTrue(alice1 is ShuttingDown)
        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.MessageReceived(sig.copy(signature = ByteVector64.Zeroes)))
        assertTrue(alice2 is Closing)
        actionsAlice2.hasOutgoingMessage<Error>()
        assertNotNull(alice2.localCommitPublished)
        actionsAlice2.hasTx(alice1.commitments.localCommit.publishableTxs.commitTx.tx)
    }

    @Test
    fun `recv RevokeAndAck (with remaining htlcs on both sides)`() {
        val (alice0, bob0) = init()
        val (alice1, bob1) = fulfillHtlc(1, r2, alice0, bob0)
        val (bob2, alice2) = crossSign(bob1, alice1)
        assertTrue(alice2 is ShuttingDown)
        assertTrue(bob2 is ShuttingDown)
        assertEquals(1, alice2.commitments.localCommit.spec.htlcs.size)
        assertEquals(1, alice2.commitments.remoteCommit.spec.htlcs.size)
        assertEquals(1, bob2.commitments.localCommit.spec.htlcs.size)
        assertEquals(1, bob2.commitments.remoteCommit.spec.htlcs.size)
    }

    @Test
    fun `recv RevokeAndAck (with remaining htlcs on one side)`() {
        val (alice0, bob0) = init()
        val (alice1, bob1) = fulfillHtlc(0, r1, alice0, bob0)
        val (alice2, bob2) = fulfillHtlc(1, r2, alice1, bob1)
        val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val sig = actionsBob3.hasOutgoingMessage<CommitSig>()
        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(sig))
        assertTrue(alice3 is ShuttingDown)
        val revack = actionsAlice3.hasOutgoingMessage<RevokeAndAck>()
        val (bob4, _) = bob3.processEx(ChannelEvent.MessageReceived(revack))
        assertTrue(bob4 is ShuttingDown)
        assertEquals(2, bob4.commitments.localCommit.spec.htlcs.size)
        assertTrue(bob4.commitments.remoteCommit.spec.htlcs.isEmpty())
        assertEquals(2, alice3.commitments.remoteCommit.spec.htlcs.size)
        assertTrue(alice3.commitments.localCommit.spec.htlcs.isEmpty())

    }

    @Test
    fun `recv RevokeAndAck (no more htlcs on either side)`() {
        val (alice0, bob0) = init()
        val (alice1, bob1) = fulfillHtlc(0, r1, alice0, bob0)
        val (alice2, bob2) = fulfillHtlc(1, r2, alice1, bob1)
        val (bob3, alice3) = crossSign(bob2, alice2)
        assertTrue(alice3 is Negotiating)
        assertTrue(bob3 is Negotiating)
    }

    @Test
    fun `recv RevokeAndAck (invalid preimage)`() {
        val (alice0, bob0) = init()
        val (bob1, actionsBob1) = bob0.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(0, r1)))
        val fulfill = actionsBob1.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(bob2 is ShuttingDown)
        val sig = actionsBob2.hasOutgoingMessage<CommitSig>()
        val (alice1, _) = alice0.processEx(ChannelEvent.MessageReceived(fulfill))
        val (_, actionsAlice2) = alice1.processEx(ChannelEvent.MessageReceived(sig))
        val revack = actionsAlice2.hasOutgoingMessage<RevokeAndAck>()
        val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.MessageReceived(revack.copy(perCommitmentSecret = randomKey())))
        assertTrue(bob3 is Closing)
        assertNotNull(bob3.localCommitPublished)
        actionsBob3.hasTx(bob2.commitments.localCommit.publishableTxs.commitTx.tx)
        actionsBob3.hasOutgoingMessage<Error>()
    }

    @Test
    fun `recv RevokeAndAck (unexpectedly)`() {
        val (alice0, _) = init()
        val (alice1, actions1) = alice0.processEx(ChannelEvent.MessageReceived(RevokeAndAck(alice0.channelId, randomKey(), randomKey().publicKey())))
        assertTrue(alice1 is Closing)
        assertNotNull(alice1.localCommitPublished)
        actions1.hasTx(alice0.commitments.localCommit.publishableTxs.commitTx.tx)
        actions1.hasOutgoingMessage<Error>()
    }

    @Test
    fun `recv Shutdown with encrypted channel data`() {
        val (_, bob0) = reachNormal()
        assertTrue(bob0.commitments.localParams.features.hasFeature(Feature.ChannelBackupClient))
        assertFalse(bob0.commitments.channelFeatures.hasFeature(Feature.ChannelBackupClient)) // this isn't a permanent channel feature
        val (bob1, actions1) = bob0.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(bob1 is Normal)
        val blob = Serialization.encrypt(bob1.staticParams.nodeParams.nodePrivateKey.value, bob1)
        val shutdown = actions1.findOutgoingMessage<Shutdown>()
        assertEquals(blob, shutdown.channelData)
    }

    @Test
    fun `recv NewBlock (no htlc timed out)`() {
        val (alice, _) = init()

        run {
            val (alice1, actions1) = alice.processEx(ChannelEvent.NewBlock(alice.currentBlockHeight + 1, alice.currentTip.second))
            assertEquals(alice.copy(currentTip = alice1.currentTip), alice1)
            assertTrue(actions1.isEmpty())
        }

        run {
            val (alice1, actions1) = alice.processEx(ChannelEvent.CheckHtlcTimeout)
            assertEquals(alice, alice1)
            assertTrue(actions1.isEmpty())
        }
    }

    @Test
    fun `recv NewBlock (an htlc timed out)`() {
        val (alice, _) = init()
        val commitTx = alice.commitments.localCommit.publishableTxs.commitTx.tx
        val htlcExpiry = alice.commitments.localCommit.spec.htlcs.map { it.add.cltvExpiry }.first()
        val (alice1, actions1) = run {
            val (tmp, _) = alice.processEx(ChannelEvent.NewBlock(htlcExpiry.toLong().toInt(), alice.currentTip.second))
            tmp.processEx(ChannelEvent.CheckHtlcTimeout)
        }
        assertTrue(alice1 is Closing)
        assertNotNull(alice1.localCommitPublished)
        actions1.hasTx(commitTx)
        actions1.hasOutgoingMessage<Error>()
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (their commit)`() {
        val (alice, bob) = init()
        // bob publishes his current commit tx, which contains two pending htlcs alice->bob
        val bobCommitTx = bob.commitments.localCommit.publishableTxs.commitTx.tx
        assertEquals(6, bobCommitTx.txOut.size) // 2 main outputs + 2 anchors + 2 pending htlcs
        val (_, remoteCommitPublished) = TestsHelper.remoteClose(bobCommitTx, alice)
        assertNotNull(remoteCommitPublished.claimMainOutputTx)
        assertEquals(2, remoteCommitPublished.claimHtlcTxs.size)
        assertTrue(remoteCommitPublished.claimHtlcSuccessTxs().isEmpty())
        assertEquals(2, remoteCommitPublished.claimHtlcTimeoutTxs().size)
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (their next commit)`() {
        val (alice, bob) = run {
            val (alice0, bob0) = reachNormal()
            val (nodes1, _, _) = addHtlc(25_000_000.msat, alice0, bob0)
            val (alice1, bob1) = nodes1
            val (alice2, bob2) = crossSign(alice1, bob1)
            val (nodes3, _, _) = addHtlc(35_000_000.msat, alice2, bob2)
            val (alice3, bob3) = nodes3
            // alice signs the next commitment, but bob doesn't
            val (alice4, actionsAlice) = alice3.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
            val commitSig = actionsAlice.hasOutgoingMessage<CommitSig>()
            val (bob4, actionsBob) = bob3.processEx(ChannelEvent.MessageReceived(commitSig))
            actionsBob.hasOutgoingMessage<RevokeAndAck>() // not forwarded to Alice (malicious Bob)
            shutdown(alice4, bob4)
        }

        val bobCommitTx = bob.commitments.localCommit.publishableTxs.commitTx.tx
        assertEquals(6, bobCommitTx.txOut.size) // 2 main outputs + 2 anchors + 2 pending htlc
        val (alice1, aliceActions1) = alice.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertTrue(alice1 is Closing)
        assertNotNull(alice1.nextRemoteCommitPublished)
        aliceActions1.has<ChannelAction.Storage.StoreState>()
        val rcp = alice1.nextRemoteCommitPublished!!
        assertNotNull(rcp.claimMainOutputTx)
        assertEquals(2, rcp.claimHtlcTxs.size)
        assertTrue(rcp.claimHtlcSuccessTxs().isEmpty())
        assertEquals(2, rcp.claimHtlcTimeoutTxs().size)
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (revoked tx)`() {
        val (alice, _, revokedTx) = run {
            val (alice0, bob0) = reachNormal()
            val (nodes1, _, _) = addHtlc(25_000_000.msat, alice0, bob0)
            val (alice1, bob1) = nodes1
            val (alice2, bob2) = crossSign(alice1, bob1)
            val (nodes3, _, _) = addHtlc(35_000_000.msat, alice2, bob2)
            val (alice3, bob3) = nodes3
            val (alice4, bob4) = crossSign(alice3, bob3)
            val (alice5, bob5) = shutdown(alice4, bob4)
            Triple(alice5, bob5, (bob2 as Normal).commitments.localCommit.publishableTxs.commitTx.tx)
        }

        assertEquals(5, revokedTx.txOut.size) // 2 main outputs + 2 anchors + 1 pending htlc
        val (alice1, aliceActions1) = alice.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, revokedTx)))
        assertTrue(alice1 is Closing)
        assertEquals(1, alice1.revokedCommitPublished.size)
        aliceActions1.hasOutgoingMessage<Error>()
        aliceActions1.has<ChannelAction.Storage.StoreState>()
        aliceActions1.has<ChannelAction.Storage.GetHtlcInfos>()
        val rvk = alice1.revokedCommitPublished.first()
        assertNotNull(rvk.claimMainOutputTx)
        assertNotNull(rvk.mainPenaltyTx)
    }

    @Test
    fun `recv Disconnected`() {
        val (alice, _) = init()
        val (alice1, _) = alice.processEx(ChannelEvent.Disconnected)
        assertTrue { alice1 is Offline }
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (alice, _) = init()
        val (alice1, actions) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertEquals(alice1, alice)
        assertEquals(actions, listOf(ChannelAction.ProcessCmdRes.NotExecuted(CMD_CLOSE(null), ClosingAlreadyInProgress(alice.channelId))))
    }

    private fun testLocalForceClose(alice: ChannelState, actions: List<ChannelAction>) {
        assertTrue(alice is Closing)
        val aliceCommitTx = alice.commitments.localCommit.publishableTxs.commitTx
        val lcp = alice.localCommitPublished
        assertNotNull(lcp)
        assertEquals(lcp.commitTx, aliceCommitTx.tx)

        val txs = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }
        assertEquals(6, txs.size)
        // alice has sent 2 htlcs so we expect 6 transactions:
        // - alice's current commit tx
        // - 1 tx to claim the main delayed output
        // - 2 txs for each htlc
        // - 2 txs for each delayed output of the claimed htlc
        assertEquals(aliceCommitTx.tx, txs[0])
        assertEquals(aliceCommitTx.tx.txOut.size, 6) // 2 anchor outputs + 2 main output + 2 pending htlcs
        // the main delayed output spends the commitment transaction
        Transaction.correctlySpends(txs[1], aliceCommitTx.tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // 2nd stage transactions spend the commitment transaction
        Transaction.correctlySpends(txs[2], aliceCommitTx.tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        Transaction.correctlySpends(txs[3], aliceCommitTx.tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // 3rd stage transactions spend their respective HTLC-Success/HTLC-Timeout transactions
        Transaction.correctlySpends(txs[4], txs[2], ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        Transaction.correctlySpends(txs[5], txs[3], ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        val expectedWatchConfirmed = listOf(
            txs[0].txid, // commit tx
            txs[1].txid, // main delayed
            txs[4].txid, // htlc-delayed
            txs[5].txid, // htlc-delayed
        )
        assertEquals(actions.findWatches<WatchConfirmed>().map { it.txId }, expectedWatchConfirmed)
        assertEquals(lcp.htlcTxs.keys, actions.findWatches<WatchSpent>().map { OutPoint(aliceCommitTx.tx, it.outputIndex.toLong()) }.toSet())
    }

    @Test
    fun `recv CMD_FORCECLOSE`() {
        val (alice, _) = init()
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_FORCECLOSE))
        testLocalForceClose(alice1, actions1)
    }

    @Test
    fun `recv Error`() {
        val (alice, _) = init()
        val (alice1, actions1) = alice.processEx(ChannelEvent.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        testLocalForceClose(alice1, actions1)
    }

    companion object {
        val r1 = randomBytes32()
        val r2 = randomBytes32()

        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            currentBlockHeight: Int = TestConstants.defaultBlockHeight,
            aliceFeatures: Features = TestConstants.Alice.nodeParams.features,
            bobFeatures: Features = TestConstants.Bob.nodeParams.features,
        ): Pair<ShuttingDown, ShuttingDown> {
            val (alice, bob) = reachNormal(channelType, aliceFeatures, bobFeatures, currentBlockHeight)
            val (_, cmdAdd1) = makeCmdAdd(300_000_000.msat, bob.staticParams.nodeParams.nodeId, currentBlockHeight.toLong(), r1)
            val (alice1, actions) = alice.processEx(ChannelEvent.ExecuteCommand(cmdAdd1))
            val htlc1 = actions.findOutgoingMessage<UpdateAddHtlc>()
            val (bob1, _) = bob.processEx(ChannelEvent.MessageReceived(htlc1))

            val (_, cmdAdd2) = makeCmdAdd(200_000_000.msat, bob.staticParams.nodeParams.nodeId, currentBlockHeight.toLong(), r2)
            val (alice2, actions3) = alice1.processEx(ChannelEvent.ExecuteCommand(cmdAdd2))
            val htlc2 = actions3.findOutgoingMessage<UpdateAddHtlc>()
            val (bob2, _) = bob1.processEx(ChannelEvent.MessageReceived(htlc2))

            // Alice signs
            val (alice3, bob3) = signAndRevack(alice2, bob2)
            // Bob signs back
            val (bob4, alice4) = signAndRevack(bob3, alice3)
            // Alice initiates a closing
            return shutdown(alice4, bob4)
        }

        fun shutdown(alice: ChannelState, bob: ChannelState): Pair<ShuttingDown, ShuttingDown> {
            // Alice initiates a closing
            val (alice1, actionsAlice) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
            val shutdown = actionsAlice.findOutgoingMessage<Shutdown>()
            val (bob1, actionsBob) = bob.processEx(ChannelEvent.MessageReceived(shutdown))
            val shutdown1 = actionsBob.findOutgoingMessage<Shutdown>()
            val (alice2, _) = alice1.processEx(ChannelEvent.MessageReceived(shutdown1))
            assertTrue(alice2 is ShuttingDown)
            assertTrue(bob1 is ShuttingDown)
            if (alice2.commitments.channelFeatures.hasFeature(Feature.ChannelBackupClient)) assertFalse(shutdown.channelData.isEmpty())
            if (bob1.commitments.channelFeatures.hasFeature(Feature.ChannelBackupClient)) assertFalse(shutdown1.channelData.isEmpty())
            return Pair(alice2, bob1)
        }
    }

}
