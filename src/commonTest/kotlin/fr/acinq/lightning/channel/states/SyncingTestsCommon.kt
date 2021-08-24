package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.Transaction
import fr.acinq.lightning.Feature
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_SPENT
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.processEx
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.ChannelReestablish
import fr.acinq.lightning.wire.Error
import fr.acinq.lightning.wire.Init
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SyncingTestsCommon : LightningTestSuite() {

    @Test
    fun `detect that a remote commit tx was published`() {
        val (alice, bob, _) = run {
            val (alice, bob) = init()
            disconnect(alice, bob)
        }
        val aliceCommitTx = alice.state.commitments.localCommit.publishableTxs.commitTx.tx
        val (bob1, actions) = bob.processEx(ChannelEvent.WatchReceived(WatchEventSpent(bob.state.channelId, BITCOIN_FUNDING_SPENT, aliceCommitTx)))
        assertTrue(bob1 is Closing)
        // we published a tx to claim our main output
        val claimTx = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }.first()
        Transaction.correctlySpends(claimTx, alice.state.commitments.localCommit.publishableTxs.commitTx.tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        val watches = actions.findWatches<WatchConfirmed>()
        assertEquals(watches.map { it.txId }.toSet(), setOf(aliceCommitTx.txid, claimTx.txid))
    }

    @Test
    fun `detect that a revoked commit tx was published`() {
        val (_, bob, revokedTx) = run {
            val (alice, bob) = init()
            val (nodes, _, _) = TestsHelper.addHtlc(10_000_000.msat, payer = alice, payee = bob)
            val (alice1, bob1) = nodes
            val (alice2, bob2) = TestsHelper.crossSign(alice1, bob1)
            alice2 as Normal
            bob2 as Normal
            val (alice3, bob3, _) = disconnect(alice2, bob2)
            Triple(alice3, bob3, alice.commitments.localCommit.publishableTxs.commitTx.tx)
        }
        val (bob1, actions) = bob.processEx(ChannelEvent.WatchReceived(WatchEventSpent(bob.state.channelId, BITCOIN_FUNDING_SPENT, revokedTx)))
        assertTrue(bob1 is Closing)
        val claimTxs = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }
        assertEquals(claimTxs.size, 2)
        claimTxs.forEach { Transaction.correctlySpends(it, revokedTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }
        val watches = actions.findWatches<WatchConfirmed>()
        // we watch the revoked tx and our "claim main output tx"
        assertEquals(watches.map { it.txId }.toSet(), setOf(revokedTx.txid, bob1.revokedCommitPublished.first().claimMainOutputTx!!.tx.txid))
    }

    @Test
    fun `recv CMD_FORCECLOSE`() {
        val (alice, _, _) = run {
            val (alice, bob) = init()
            disconnect(alice, bob)
        }
        val (alice1, actions1) = alice.process(ChannelEvent.ExecuteCommand(CMD_FORCECLOSE))
        assertTrue(alice1 is Closing)
        actions1.hasOutgoingMessage<Error>()
    }

    companion object {
        fun init(): Pair<Normal, Normal> {
            // NB: we disable channel backups to ensure Bob sends his channel_reestablish on reconnection.
            return reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
        }

        fun disconnect(alice: Normal, bob: Normal): Triple<Syncing, Syncing, Pair<ChannelReestablish, ChannelReestablish>> {
            val (alice1, _) = alice.processEx(ChannelEvent.Disconnected)
            val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
            assertTrue(alice1 is Offline)
            assertTrue(bob1 is Offline)

            val aliceInit = Init(ByteVector(alice1.state.commitments.localParams.features.toByteArray()))
            val bobInit = Init(ByteVector(bob1.state.commitments.localParams.features.toByteArray()))

            val (alice2, actions) = alice1.processEx(ChannelEvent.Connected(aliceInit, bobInit))
            assertTrue(alice2 is Syncing)
            val channelReestablishA = actions.findOutgoingMessage<ChannelReestablish>()
            val (bob2, actions1) = bob1.processEx(ChannelEvent.Connected(bobInit, aliceInit))
            assertTrue(bob2 is Syncing)
            val channelReestablishB = actions1.findOutgoingMessage<ChannelReestablish>()
            return Triple(alice2, bob2, Pair(channelReestablishA, channelReestablishB))
        }
    }

}