package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Lightning.randomBytes64
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.addHtlc
import fr.acinq.lightning.channel.TestsHelper.crossSign
import fr.acinq.lightning.channel.TestsHelper.fulfillHtlc
import fr.acinq.lightning.channel.TestsHelper.makeCmdAdd
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.db.ChannelClosingType
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.wire.*
import kotlin.test.*

class NegotiatingTestsCommon : LightningTestSuite() {

    @Test
    fun `recv ChannelCommand_Htlc_Add`() {
        val (alice, _, _) = init()
        val (_, add) = makeCmdAdd(500_000.msat, alice.staticParams.remoteNodeId, TestConstants.defaultBlockHeight.toLong())
        val (alice1, actions1) = alice.process(add)
        assertIs<LNChannel<Negotiating>>(alice1)
        assertEquals(1, actions1.size)
        actions1.hasCommandError<ChannelUnavailable>()
    }

    @Test
    fun `recv ClosingComplete -- both outputs`() {
        val (alice, bob, closingCompleteAlice, closingCompleteBob) = init()

        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(closingCompleteBob))
        assertEquals(4, actionsAlice1.size)
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        val closingTxBob = actionsAlice1.findPublishTxs().first()
        actionsAlice1.hasWatchConfirmed(closingTxBob.txid)
        val closingSigAlice = actionsAlice1.findOutgoingMessage<ClosingSig>()

        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingCompleteAlice))
        assertEquals(4, actionsBob1.size)
        actionsBob1.has<ChannelAction.Storage.StoreState>()
        val closingTxAlice = actionsBob1.findPublishTxs().first()
        actionsBob1.hasWatchConfirmed(closingTxAlice.txid)
        val closingSigBob = actionsBob1.findOutgoingMessage<ClosingSig>()

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(closingSigBob))
        assertIs<Negotiating>(alice2.state)
        assertEquals(3, actionsAlice2.size)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        assertTrue(actionsAlice2.findPublishTxs().contains(closingTxAlice))
        actionsAlice2.hasWatchConfirmed(closingTxAlice.txid)

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(closingSigAlice))
        assertIs<Negotiating>(bob2.state)
        assertEquals(3, actionsBob2.size)
        actionsBob2.has<ChannelAction.Storage.StoreState>()
        assertTrue(actionsBob2.findPublishTxs().contains(closingTxBob))
        actionsBob2.hasWatchConfirmed(closingTxBob.txid)
    }

    @Test
    fun `recv ClosingComplete -- both outputs -- external address`() {
        val closingScript = Script.write(Script.pay2wpkh(randomKey().publicKey())).toByteVector()
        val (alice, bob, closingComplete, _) = init(aliceClosingScript = closingScript)

        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete))
        assertIs<Negotiating>(bob1.state)
        val closingTx = actionsBob1.findPublishTxs().first()
        assertTrue(closingTx.txOut.any { it.publicKeyScript == closingScript })
        val closingSig = actionsBob1.findOutgoingMessage<ClosingSig>()

        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(closingSig))
        assertIs<Negotiating>(alice1.state)
        assertTrue(actionsAlice1.findPublishTxs().contains(closingTx))
    }

    @Test
    fun `recv ClosingComplete -- single output`() {
        val (alice, bob) = reachNormal(bobFundingAmount = 0.sat)
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.Close.MutualClose(null, TestConstants.feeratePerKw))
        val shutdownAlice = actionsAlice1.findOutgoingMessage<Shutdown>()
        val (bob1, actionsBob1) = bob.process(ChannelCommand.Close.MutualClose(null, TestConstants.feeratePerKw))
        val shutdownBob = actionsBob1.findOutgoingMessage<Shutdown>()

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(shutdownAlice))
        assertNull(actionsBob2.findOutgoingMessageOpt<ClosingComplete>()) // Bob cannot pay mutual close fees.
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(shutdownBob))
        val closingCompleteAlice = actionsAlice2.findOutgoingMessage<ClosingComplete>()
        assertNull(closingCompleteAlice.closerAndCloseeOutputsSig)
        assertNotNull(closingCompleteAlice.closerOutputOnlySig)

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(closingCompleteAlice))
        assertIs<Negotiating>(bob3.state)
        val closingTxAlice = actionsBob3.findPublishTxs().first()
        assertEquals(1, closingTxAlice.txOut.size)
        val closingSigBob = actionsBob3.findOutgoingMessage<ClosingSig>()
        assertNotNull(closingSigBob.closerOutputOnlySig)

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(closingSigBob))
        assertIs<Negotiating>(alice3.state)
        assertTrue(actionsAlice3.findPublishTxs().contains(closingTxAlice))
        actionsAlice3.hasWatchConfirmed(closingTxAlice.txid)
    }

    @Test
    fun `recv ClosingComplete -- with concurrent script updates`() {
        val (alice, bob, closingCompleteAlice1, closingCompleteBob1) = init()

        // Alice sends closing_sig in response to Bob's first closing_complete.
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(closingCompleteBob1))
        assertEquals(4, actionsAlice1.size)
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        val closingTx1 = actionsAlice1.findPublishTxs().first()
        actionsAlice1.hasWatchConfirmed(closingTx1.txid)
        val closingSigAlice1 = actionsAlice1.hasOutgoingMessage<ClosingSig>()

        // Bob updates his closing script before receiving Alice's closing_complete and closing_sig.
        val closingScript = Script.write(Script.pay2wpkh(randomKey().publicKey())).byteVector()
        val (bob1, actionsBob1) = bob.process(ChannelCommand.Close.MutualClose(closingScript, TestConstants.feeratePerKw * 1.5))
        assertEquals(2, actionsBob1.size)
        actionsBob1.has<ChannelAction.Storage.StoreState>()
        val closingCompleteBob2 = actionsBob1.findOutgoingMessage<ClosingComplete>()
        assertEquals(closingScript, closingCompleteBob2.closerScriptPubKey)
        assertEquals(closingCompleteAlice1.closerScriptPubKey, closingCompleteBob2.closeeScriptPubKey)

        // Bob ignores Alice's obsolete closing_complete.
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(closingCompleteAlice1))
        actionsBob2.hasOutgoingMessage<Warning>()
        // Bob ignores Alice's obsolete closing_sig.
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(closingSigAlice1))
        actionsBob3.hasOutgoingMessage<Warning>()

        // Alice handles Bob's updated closing_complete.
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(closingCompleteBob2))
        assertIs<Negotiating>(alice2.state)
        assertEquals(4, actionsAlice2.size)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        val closingTx2 = actionsAlice2.findPublishTxs().first()
        assertTrue(closingTx2.txOut.any { it.publicKeyScript == closingScript })
        actionsAlice2.hasWatchConfirmed(closingTx2.txid)
        val closingSigAlice2 = actionsAlice2.findOutgoingMessage<ClosingSig>()

        // Bob receives Alice's closing_sig for his updated closing_complete.
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(closingSigAlice2))
        assertIs<Negotiating>(bob4.state)
        assertEquals(3, actionsBob4.size)
        actionsBob4.has<ChannelAction.Storage.StoreState>()
        assertEquals(closingTx2, actionsBob4.findPublishTxs().first())
        actionsBob4.hasWatchConfirmed(closingTx2.txid)
    }

    @Test
    fun `recv ClosingComplete -- missing closee output`() {
        val (_, bob, closingComplete, _) = init()

        // Bob expects to receive a signature for a closing transaction containing his output, so he ignores Alice's
        // closing_complete instead of sending back his closing_sig.
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete.copy(tlvStream = TlvStream(ClosingCompleteTlv.CloserOutputOnly(closingComplete.closerOutputOnlySig!!)))))
        assertIs<Negotiating>(bob1.state)
        assertEquals(1, actionsBob1.size)
        actionsBob1.hasOutgoingMessage<Warning>()

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(closingComplete))
        assertIs<Negotiating>(bob2.state)
        val closingTxAlice = actionsBob2.findPublishTxs().first()
        assertTrue(closingTxAlice.txOut.size == 2)
        actionsBob2.findOutgoingMessage<ClosingSig>()
    }

    @Test
    fun `recv ClosingSig -- missing signature`() {
        val (alice, bob, closingComplete, _) = init()

        val (_, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete))
        val closingSig = actionsBob1.findOutgoingMessage<ClosingSig>()

        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(closingSig.copy(tlvStream = TlvStream.empty())))
        assertIs<Negotiating>(alice1.state)
        assertEquals(1, actionsAlice1.size)
        actionsAlice1.hasOutgoingMessage<Warning>()
    }

    @Test
    fun `recv ClosingSig -- invalid signature`() {
        val (alice, bob, closingComplete, _) = init()

        val (_, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete))
        val closingSig = actionsBob1.findOutgoingMessage<ClosingSig>()

        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(closingSig.copy(tlvStream = TlvStream(ClosingSigTlv.CloserAndCloseeOutputs(randomBytes64())))))
        assertIs<Negotiating>(alice1.state)
        actionsAlice1.hasOutgoingMessage<Warning>()
    }

    @Test
    fun `recv ClosingComplete and ClosingSig with encrypted channel data`() {
        val (alice, bob, closingCompleteAlice, closingCompleteBob) = init()
        assertTrue(alice.commitments.params.localParams.features.hasFeature(Feature.ChannelBackupProvider))
        assertTrue(bob.commitments.params.localParams.features.hasFeature(Feature.ChannelBackupClient))
        assertTrue(closingCompleteAlice.channelData.isEmpty())
        assertFalse(closingCompleteBob.channelData.isEmpty())
        val (_, actions1) = bob.process(ChannelCommand.MessageReceived(closingCompleteAlice))
        val closingSigBob = actions1.hasOutgoingMessage<ClosingSig>()
        assertFalse(closingSigBob.channelData.isEmpty())
    }

    @Test
    fun `recv BITCOIN_TX_CONFIRMED -- signed mutual close`() {
        val (alice, bob, closingComplete, _) = init()

        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete))
        val closingTx = actionsBob1.findPublishTxs().first()
        val closingSig = actionsBob1.findOutgoingMessage<ClosingSig>()

        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(closingSig))
        assertTrue(actionsAlice1.findPublishTxs().contains(closingTx))
        actionsAlice1.hasWatchConfirmed(closingTx.txid)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_TX_CONFIRMED(closingTx), 0, 0, closingTx)))
        assertIs<Closed>(alice2.state)
        assertEquals(3, actionsAlice2.size)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsAlice2.find<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>().also {
            assertEquals(closingTx.txid, it.txId)
            assertEquals(ChannelClosingType.Mutual, it.closingType)
            assertTrue(it.miningFees > 0.sat)
            assertEquals(850_000.sat, it.amount + it.miningFees)
        }
        actionsAlice2.find<ChannelAction.Storage.SetLocked>().also { assertEquals(closingTx.txid, it.txId) }

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_TX_CONFIRMED(closingTx), 0, 0, closingTx)))
        assertIs<Closed>(bob2.state)
        assertEquals(3, actionsBob2.size)
        actionsBob2.has<ChannelAction.Storage.StoreState>()
        actionsBob2.find<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>().also {
            assertEquals(closingTx.txid, it.txId)
            assertEquals(ChannelClosingType.Mutual, it.closingType)
            assertEquals(150_000.sat, it.amount)
        }
        actionsBob2.find<ChannelAction.Storage.SetLocked>().also { assertEquals(closingTx.txid, it.txId) }
    }

    @Test
    fun `recv BITCOIN_TX_CONFIRMED -- proposed mutual close`() {
        val (alice, bob, closingComplete, _) = init()

        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete))
        val closingTx = actionsBob1.findPublishTxs().first()
        actionsBob1.findOutgoingMessage<ClosingSig>()

        val (alice1, actionsAlice1) = alice.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_TX_CONFIRMED(closingTx), 0, 0, closingTx)))
        assertIs<Closed>(alice1.state)
        assertEquals(3, actionsAlice1.size)
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        actionsAlice1.find<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>().also {
            assertEquals(closingTx.txid, it.txId)
            assertEquals(ChannelClosingType.Mutual, it.closingType)
            assertTrue(it.miningFees > 0.sat)
            assertEquals(850_000.sat, it.amount + it.miningFees)
        }
        actionsAlice1.find<ChannelAction.Storage.SetLocked>().also { assertEquals(closingTx.txid, it.txId) }

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_TX_CONFIRMED(closingTx), 0, 0, closingTx)))
        assertIs<Closed>(bob2.state)
        assertEquals(3, actionsBob2.size)
        actionsBob2.has<ChannelAction.Storage.StoreState>()
        actionsBob2.find<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>().also {
            assertEquals(closingTx.txid, it.txId)
            assertEquals(ChannelClosingType.Mutual, it.closingType)
            assertEquals(150_000.sat, it.amount)
        }
        actionsBob2.find<ChannelAction.Storage.SetLocked>().also { assertEquals(closingTx.txid, it.txId) }
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- proposed mutual close`() {
        val (alice, bob, closingComplete, _) = init()
        val (_, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete))
        val closingTx = actionsBob1.findPublishTxs().first()
        actionsBob1.findOutgoingMessage<ClosingSig>()

        val (alice1, actionsAlice1) = alice.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, closingTx)))
        assertIs<Negotiating>(alice1.state)
        assertEquals(3, actionsAlice1.size)
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        actionsAlice1.hasPublishTx(closingTx)
        actionsAlice1.hasWatchConfirmed(closingTx.txid)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_TX_CONFIRMED(closingTx), 0, 0, closingTx)))
        assertIs<Closed>(alice2.state)
        assertEquals(3, actionsAlice2.size)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsAlice2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
        actionsAlice2.find<ChannelAction.Storage.SetLocked>().also { assertEquals(closingTx.txid, it.txId) }
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- proposed mutual close -- offline`() {
        val (alice, bob, closingComplete, _) = init()
        val (_, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete))
        val closingTx = actionsBob1.findPublishTxs().first()
        actionsBob1.findOutgoingMessage<ClosingSig>()

        val (aliceOffline, actionsAliceOffline) = alice.process(ChannelCommand.Disconnected)
        assertIs<Offline>(aliceOffline.state)
        assertTrue(actionsAliceOffline.isEmpty())

        val (alice1, actionsAlice1) = aliceOffline.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, closingTx)))
        assertIs<Offline>(alice1.state)
        assertEquals(3, actionsAlice1.size)
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        actionsAlice1.hasPublishTx(closingTx)
        actionsAlice1.hasWatchConfirmed(closingTx.txid)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_TX_CONFIRMED(closingTx), 0, 0, closingTx)))
        assertIs<Closed>(alice2.state)
        assertEquals(3, actionsAlice2.size)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsAlice2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
        actionsAlice2.find<ChannelAction.Storage.SetLocked>().also { assertEquals(closingTx.txid, it.txId) }
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- proposed mutual close -- syncing`() {
        val (alice, bob, closingComplete, _) = init()
        val (_, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete))
        val closingTx = actionsBob1.findPublishTxs().first()
        actionsBob1.findOutgoingMessage<ClosingSig>()

        val (aliceOffline, actionsAliceOffline) = alice.process(ChannelCommand.Disconnected)
        assertIs<Offline>(aliceOffline.state)
        assertTrue(actionsAliceOffline.isEmpty())

        val (aliceSyncing, actionsAliceSyncing) = aliceOffline.process(ChannelCommand.Connected(Init(alice.staticParams.nodeParams.features), Init(bob.staticParams.nodeParams.features)))
        assertIs<Syncing>(aliceSyncing.state)
        actionsAliceSyncing.hasOutgoingMessage<ChannelReestablish>()

        val (alice1, actionsAlice1) = aliceSyncing.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, closingTx)))
        assertIs<Syncing>(alice1.state)
        assertEquals(3, actionsAlice1.size)
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        actionsAlice1.hasPublishTx(closingTx)
        actionsAlice1.hasWatchConfirmed(closingTx.txid)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_TX_CONFIRMED(closingTx), 0, 0, closingTx)))
        assertIs<Closed>(alice2.state)
        assertEquals(3, actionsAlice2.size)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsAlice2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
        actionsAlice2.find<ChannelAction.Storage.SetLocked>().also { assertEquals(closingTx.txid, it.txId) }
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- their commit`() {
        val (alice, bob, closingComplete, _) = init()
        val (alice1, bob1) = signClosingTxAlice(alice, bob, closingComplete)

        val bobCommitTx = bob1.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice2, actions2) = alice1.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertIs<LNChannel<Closing>>(alice2)
        assertEquals(5, actions2.size)
        assertNotNull(alice2.state.remoteCommitPublished)
        assertTrue(alice2.state.mutualClosePublished.isNotEmpty())
        actions2.has<ChannelAction.Storage.StoreState>()
        val claimMain = actions2.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.ClaimRemoteDelayedOutputTx)
        actions2.hasWatchConfirmed(bobCommitTx.txid)
        actions2.hasWatchConfirmed(claimMain.txid)
        actions2.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- revoked tx`() {
        val (alice, bob, revokedCommit) = run {
            val (alice0, bob0) = reachNormal()
            val revokedCommit = bob0.commitments.latest.localCommit.publishableTxs.commitTx.tx
            val (nodes1, r, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
            val (alice2, bob2) = crossSign(nodes1.first, nodes1.second)
            val (alice3, bob3) = fulfillHtlc(htlc.id, r, alice2, bob2)
            val (bob4, alice4) = crossSign(bob3, alice3)
            Triple(alice4, bob4, revokedCommit)
        }

        val (alice1, actionsAlice1) = alice.process(ChannelCommand.Close.MutualClose(null, TestConstants.feeratePerKw))
        val shutdownAlice = actionsAlice1.findOutgoingMessage<Shutdown>()
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(shutdownAlice))
        assertIs<LNChannel<Negotiating>>(bob1)
        val shutdownBob = actionsBob1.findOutgoingMessage<Shutdown>()
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(shutdownBob))
        assertIs<LNChannel<Negotiating>>(alice2)
        val closingComplete = actionsAlice2.findOutgoingMessage<ClosingComplete>()
        val (alice3, _) = signClosingTxAlice(alice2, bob1, closingComplete)

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, revokedCommit)))
        assertIs<LNChannel<Closing>>(alice4)
        assertTrue(alice4.state.revokedCommitPublished.isNotEmpty())
        assertTrue(alice4.state.mutualClosePublished.isNotEmpty())
        actionsAlice4.has<ChannelAction.Storage.StoreState>()
        val claimMain = actionsAlice4.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.ClaimRemoteDelayedOutputTx)
        actionsAlice4.hasPublishTx(ChannelAction.Blockchain.PublishTx.Type.MainPenaltyTx)
        actionsAlice4.hasWatchConfirmed(revokedCommit.txid)
        actionsAlice4.hasWatchConfirmed(claimMain.txid)
        actionsAlice4.has<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>()
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose to bump feerate`() {
        val (alice, _, closingComplete, _) = init()
        val (alice1, actions1) = alice.process(ChannelCommand.Close.MutualClose(null, TestConstants.feeratePerKw * 1.25))
        assertIs<Negotiating>(alice1.state)
        val closingComplete1 = actions1.hasOutgoingMessage<ClosingComplete>()
        assertTrue(closingComplete.fees < closingComplete1.fees)
        assertEquals(closingComplete.closerScriptPubKey, closingComplete1.closerScriptPubKey)
        assertEquals(closingComplete.closeeScriptPubKey, closingComplete1.closeeScriptPubKey)
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose with feerate too low`() {
        val (alice, _) = init()
        val (alice1, actions1) = alice.process(ChannelCommand.Close.MutualClose(null, FeeratePerKw(2500.sat)))
        assertEquals(alice1, alice)
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(ChannelCommand.Close.MutualClose(null, FeeratePerKw(2500.sat)), InvalidRbfFeerate(alice.channelId, FeeratePerKw(2500.sat), FeeratePerKw(6000.sat)))))
    }

    @Test
    fun `recv Error`() {
        val (alice, _) = init()
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertIs<LNChannel<Closing>>(alice1)
        actions1.hasPublishTx(alice.commitments.latest.localCommit.publishableTxs.commitTx.tx)
        assertTrue(actions1.findWatches<WatchConfirmed>().map { it.event }.contains(BITCOIN_TX_CONFIRMED(alice.commitments.latest.localCommit.publishableTxs.commitTx.tx)))
    }

    companion object {
        data class Fixture(val alice: LNChannel<Negotiating>, val bob: LNChannel<Negotiating>, val closingCompleteAlice: ClosingComplete, val closingCompleteBob: ClosingComplete)

        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            aliceFundingAmount: Satoshi = TestConstants.aliceFundingAmount,
            bobFundingAmount: Satoshi = TestConstants.bobFundingAmount,
            aliceClosingFeerate: FeeratePerKw = TestConstants.feeratePerKw,
            bobClosingFeerate: FeeratePerKw = TestConstants.feeratePerKw,
            aliceClosingScript: ByteVector? = null,
            bobClosingScript: ByteVector? = null,
        ): Fixture {
            val (alice, bob) = reachNormal(channelType = channelType, aliceFundingAmount = aliceFundingAmount, bobFundingAmount = bobFundingAmount)
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.Close.MutualClose(aliceClosingScript, aliceClosingFeerate))
            val shutdownAlice = actionsAlice1.findOutgoingMessage<Shutdown>()
            assertNull(actionsAlice1.findOutgoingMessageOpt<ClosingComplete>())

            val (bob1, actionsBob1) = bob.process(ChannelCommand.Close.MutualClose(bobClosingScript, bobClosingFeerate))
            val shutdownBob = actionsBob1.findOutgoingMessage<Shutdown>()
            assertNull(actionsBob1.findOutgoingMessageOpt<ClosingComplete>())

            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(shutdownAlice))
            assertIs<LNChannel<Negotiating>>(bob2)
            val closingCompleteBob = actionsBob2.findOutgoingMessage<ClosingComplete>()

            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(shutdownBob))
            assertIs<LNChannel<Negotiating>>(alice2)
            val closingCompleteAlice = actionsAlice2.findOutgoingMessage<ClosingComplete>()
            assertEquals(closingCompleteAlice.closerScriptPubKey, closingCompleteBob.closeeScriptPubKey)
            assertEquals(closingCompleteAlice.closeeScriptPubKey, closingCompleteBob.closerScriptPubKey)

            return Fixture(alice2, bob2, closingCompleteAlice, closingCompleteBob)
        }

        fun signClosingTxAlice(alice: LNChannel<Negotiating>, bob: LNChannel<Negotiating>, closingComplete: ClosingComplete): Pair<LNChannel<Negotiating>, LNChannel<Negotiating>> {
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(closingComplete))
            assertIs<LNChannel<Negotiating>>(bob1)
            val closingTx = actionsBob1.findPublishTxs().first()
            val closingSig = actionsBob1.findOutgoingMessage<ClosingSig>()
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(closingSig))
            assertIs<LNChannel<Negotiating>>(alice1)
            assertTrue(actionsAlice1.findPublishTxs().contains(closingTx))
            return Pair(alice1, bob1)
        }
    }

}
