package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.makeCmdAdd
import fr.acinq.lightning.channel.TestsHelper.mutualClose
import fr.acinq.lightning.channel.TestsHelper.processEx
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.wire.ClosingSigned
import fr.acinq.lightning.wire.Error
import fr.acinq.lightning.wire.Shutdown
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NegotiatingTestsCommon : LightningTestSuite() {

    @Test
    fun `correctly sign and detect closing tx`() {
        // we're fundee here, not funder !!
        val (bob, alice) = reachNormal()
        val priv = randomKey()

        // Alice initiates a mutual close with a custom final script
        val finalScript = Script.write(Script.pay2pkh(priv.publicKey())).toByteVector()
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(finalScript)))
        val shutdownA = actions1.findOutgoingMessage<Shutdown>()

        // Bob replies with Shutdown + ClosingSigned
        val (bob1, actions2) = bob.processEx(ChannelEvent.MessageReceived(shutdownA))
        val shutdownB = actions2.findOutgoingMessage<Shutdown>()
        val closingSignedB = actions2.findOutgoingMessage<ClosingSigned>()

        // Alice agrees with Bob's closing fee, publishes her closing tx and replies with her own ClosingSigned
        val (alice2, _) = alice1.processEx(ChannelEvent.MessageReceived(shutdownB))
        val (alice3, actions4) = alice2.processEx(ChannelEvent.MessageReceived(closingSignedB))
        assertTrue(alice3 is Closing)
        val closingTxA = actions4.filterIsInstance<ChannelAction.Blockchain.PublishTx>().first().tx
        val closingSignedA = actions4.findOutgoingMessage<ClosingSigned>()
        val watch = actions4.findWatch<WatchConfirmed>()
        assertEquals(watch.txId, closingTxA.txid)

        val fundingTx = Transaction(
            version = 2,
            txIn = listOf(TxIn(OutPoint(ByteVector32.Zeroes, 0), TxIn.SEQUENCE_FINAL)),
            txOut = listOf(bob.commitments.commitInput.txOut),
            lockTime = 0
        )
        assertEquals(fundingTx.txid, closingTxA.txIn[0].outPoint.txid)
        // check that our closing tx is correctly signed
        Transaction.correctlySpends(closingTxA, fundingTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // Bob published his closing tx (which should be the same as Alice's !!!)
        val (bob2, actions5) = bob1.processEx(ChannelEvent.MessageReceived(closingSignedA))
        assertTrue(bob2 is Closing)
        val closingTxB = actions5.filterIsInstance<ChannelAction.Blockchain.PublishTx>().first().tx
        assertEquals(closingTxA, closingTxB)

        // Alice sees Bob's closing tx (which should be the same as the one she published)
        val (alice4, _) = alice3.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice3.channelId, BITCOIN_FUNDING_SPENT, closingTxB)))
        assertTrue(alice4 is Closing)

        val (alice5, _) = alice4.processEx(ChannelEvent.WatchReceived(WatchEventConfirmed(alice3.channelId, BITCOIN_TX_CONFIRMED(closingTxA), 144, 0, closingTxA)))
        assertTrue(alice5 is Closed)
    }

    @Test
    fun `recv CMD_ADD_HTLC`() {
        val (alice, _, _) = init()
        val (_, add) = makeCmdAdd(500_000.msat, alice.staticParams.remoteNodeId, TestConstants.defaultBlockHeight.toLong())
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(add))
        assertTrue(alice1 is Negotiating)
        assertEquals(1, actions1.size)
        actions1.hasCommandError<ChannelUnavailable>()
    }

    @Test
    fun `recv ClosingSigned (theirCloseFee != ourCloseFee)`() {
        val (alice, bob, aliceCloseSig) = init()
        val (_, actions) = bob.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
        // Bob answers with a counter proposition
        val bobCloseSig = actions.findOutgoingMessage<ClosingSigned>()
        assertTrue { aliceCloseSig.feeSatoshis > bobCloseSig.feeSatoshis }
        val (alice1, actions1) = alice.processEx(ChannelEvent.MessageReceived(bobCloseSig))
        val aliceCloseSig1 = actions1.findOutgoingMessage<ClosingSigned>()
        // BOLT 2: If the receiver [doesn't agree with the fee] it SHOULD propose a value strictly between the received fee-satoshis and its previously-sent fee-satoshis
        assertTrue { aliceCloseSig1.feeSatoshis < aliceCloseSig.feeSatoshis && aliceCloseSig1.feeSatoshis > bobCloseSig.feeSatoshis }
        assertEquals((alice1 as Negotiating).closingTxProposed.last().map { it.localClosingSigned }, alice.closingTxProposed.last().map { it.localClosingSigned } + listOf(aliceCloseSig1))
    }

    @Test
    fun `recv ClosingSigned (theirCloseFee == ourCloseFee)`() {
        val (alice, bob, aliceCloseSig) = init()
        assertTrue { converge(alice, bob, aliceCloseSig) != null }
    }

    @Test
    fun `recv ClosingSigned (theirCloseFee == ourCloseFee, different fee parameters)`() {
        val (alice, bob, aliceCloseSig) = init(tweakFees = true)
        assertTrue { converge(alice, bob, aliceCloseSig) != null }
    }

    @Test
    fun `recv ClosingSigned (nothing at stake)`() {
        val (alice, bob, aliceCloseSig) = init(pushMsat = 0.msat)
        // Bob has nothing at stake
        val (bob1, actions) = bob.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
        assertTrue(bob1 is Closing)
        val mutualCloseTxBob = actions.findTxs().first()
        val bobCloseSig = actions.findOutgoingMessage<ClosingSigned>()
        assertEquals(aliceCloseSig.feeSatoshis, bobCloseSig.feeSatoshis)
        val (alice1, actions1) = alice.processEx(ChannelEvent.MessageReceived(bobCloseSig))
        assertTrue(alice1 is Closing)
        val mutualCloseTxAlice = actions1.findTxs().first()
        assertEquals(mutualCloseTxAlice, mutualCloseTxBob)
        assertEquals(actions.findWatches<WatchConfirmed>().map { it.event }, listOf(BITCOIN_TX_CONFIRMED(mutualCloseTxBob)))
        assertEquals(actions1.findWatches<WatchConfirmed>().map { it.event }, listOf(BITCOIN_TX_CONFIRMED(mutualCloseTxBob)))
        assertEquals(bob1.mutualClosePublished.map { it.tx }, listOf(mutualCloseTxBob))
        assertEquals(alice1.mutualClosePublished.map { it.tx }, listOf(mutualCloseTxBob))
    }

    @Test
    fun `recv ClosingSigned (invalid signature)`() {
        val (_, bob, aliceCloseSig) = init()
        val (bob1, actions) = bob.processEx(ChannelEvent.MessageReceived(aliceCloseSig.copy(feeSatoshis = 99000.sat)))
        assertTrue(bob1 is Closing)
        actions.hasOutgoingMessage<Error>()
        actions.hasWatch<WatchConfirmed>()
        actions.findTxs().contains(bob.commitments.localCommit.publishableTxs.commitTx.tx)
    }

    @Test
    fun `recv ClosingSigned with encrypted channel data`() {
        val (alice, bob, aliceCloseSig) = init()
        assertTrue(alice.commitments.localParams.features.hasFeature(Feature.ChannelBackupProvider))
        assertTrue(bob.commitments.localParams.features.hasFeature(Feature.ChannelBackupClient))
        assertTrue(aliceCloseSig.channelData.isEmpty())
        val (_, actions1) = bob.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
        val bobCloseSig = actions1.hasOutgoingMessage<ClosingSigned>()
        assertFalse(bobCloseSig.channelData.isEmpty())
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (an older mutual close)`() {
        val (alice, bob, aliceCloseSig) = init()
        val (bob1, actions) = bob.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
        assertTrue(bob1 is Negotiating)
        val bobCloseSig = actions.findOutgoingMessage<ClosingSigned>()
        val (alice1, actions1) = alice.processEx(ChannelEvent.MessageReceived(bobCloseSig))
        val aliceCloseSig1 = actions1.findOutgoingMessage<ClosingSigned>()
        assertTrue(bobCloseSig.feeSatoshis != aliceCloseSig1.feeSatoshis)
        // at this point alice and bob have not yet converged on closing fees, but bob decides to publish a mutual close with one of the previous sigs
        val bobClosingTx = Helpers.Closing.checkClosingSignature(
            bob1.keyManager,
            bob1.commitments,
            bob1.localShutdown.scriptPubKey.toByteArray(),
            bob1.remoteShutdown.scriptPubKey.toByteArray(),
            aliceCloseSig1.feeSatoshis,
            aliceCloseSig1.signature
        ).right!!
        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, bobClosingTx.tx)))
        assertTrue(alice2 is Closing)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsAlice2.hasTx(bobClosingTx.tx)
        assertEquals(actionsAlice2.hasWatch<WatchConfirmed>().txId, bobClosingTx.tx.txid)
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (alice, _, _) = init()
        val (alice1, actions) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertEquals(alice1, alice)
        assertEquals(actions, listOf(ChannelAction.ProcessCmdRes.NotExecuted(CMD_CLOSE(null), ClosingAlreadyInProgress(alice.channelId))))
    }

    @Test
    fun `recv Error`() {
        val (alice, _, _) = init()
        val (alice1, actions) = alice.processEx(ChannelEvent.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertTrue(alice1 is Closing)
        assertTrue(actions.findTxs().contains(alice.commitments.localCommit.publishableTxs.commitTx.tx))
        assertTrue(actions.findWatches<WatchConfirmed>().map { it.event }.contains(BITCOIN_TX_CONFIRMED(alice.commitments.localCommit.publishableTxs.commitTx.tx)))
    }

    companion object {
        fun init(channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs, tweakFees: Boolean = false, pushMsat: MilliSatoshi = TestConstants.pushMsat): Triple<Negotiating, Negotiating, ClosingSigned> {
            val (alice, bob) = reachNormal(channelType = channelType, pushMsat = pushMsat)
            return mutualClose(alice, bob, tweakFees)
        }

        tailrec fun converge(a: ChannelState, b: ChannelState, aliceCloseSig: ClosingSigned?): Pair<Closing, Closing>? {
            return when {
                a !is ChannelStateWithCommitments || b !is ChannelStateWithCommitments -> null
                a is Closing && b is Closing -> Pair(a, b)
                aliceCloseSig != null -> {
                    val (b1, actions) = b.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
                    val bobCloseSig = actions.findOutgoingMessageOpt<ClosingSigned>()
                    if (bobCloseSig != null) {
                        val (a1, actions2) = a.processEx(ChannelEvent.MessageReceived(bobCloseSig))
                        return converge(a1, b1, actions2.findOutgoingMessageOpt<ClosingSigned>())
                    }
                    val bobClosingTx = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }.firstOrNull()
                    if (bobClosingTx != null && bobClosingTx.txIn[0].outPoint == a.commitments.localCommit.publishableTxs.commitTx.input.outPoint && a !is Closing) {
                        // Bob just spent the funding tx
                        val (a1, actions2) = a.processEx(ChannelEvent.WatchReceived(WatchEventSpent(a.channelId, BITCOIN_FUNDING_SPENT, bobClosingTx)))
                        return converge(a1, b1, actions2.findOutgoingMessageOpt<ClosingSigned>())
                    }
                    converge(a, b1, null)
                }
                else -> null
            }
        }
    }

}
