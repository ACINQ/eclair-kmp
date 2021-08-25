package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.makeCmdAdd
import fr.acinq.lightning.channel.TestsHelper.mutualCloseAlice
import fr.acinq.lightning.channel.TestsHelper.mutualCloseBob
import fr.acinq.lightning.channel.TestsHelper.processEx
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.wire.*
import kotlin.test.*

class NegotiatingTestsCommon : LightningTestSuite() {

    @Test
    fun `recv CMD_ADD_HTLC`() {
        val (alice, _, _) = init()
        val (_, add) = makeCmdAdd(500_000.msat, alice.staticParams.remoteNodeId, TestConstants.defaultBlockHeight.toLong())
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(add))
        assertTrue(alice1 is Negotiating)
        assertEquals(1, actions1.size)
        actions1.hasCommandError<ChannelUnavailable>()
    }

    private fun testClosingSignedDifferentFees(alice: Normal, bob: Normal, bobInitiates: Boolean = false) {
        // alice and bob see different on-chain feerates
        val alice1 = alice.updateFeerate(FeeratePerKw(5_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(7_500.sat))
        val (alice2, bob2, aliceCloseSig1) = if (bobInitiates) mutualCloseBob(alice1, bob1) else mutualCloseAlice(alice1, bob1)

        // alice is funder so she initiates the negotiation
        assertEquals(aliceCloseSig1.feeSatoshis, 3370.sat) // matches a feerate of 5000 sat/kw
        val aliceFeeRange = aliceCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>()
        assertNotNull(aliceFeeRange)
        assertTrue(aliceFeeRange.min < aliceCloseSig1.feeSatoshis)
        assertTrue(aliceCloseSig1.feeSatoshis < aliceFeeRange.max)
        assertEquals(alice2.closingTxProposed.size, 1)
        assertEquals(alice2.closingTxProposed.last().size, 1)
        assertNull(alice2.bestUnpublishedClosingTx)

        // bob answers with a counter proposition in alice's fee range
        val (bob3, bobActions3) = bob2.processEx(ChannelEvent.MessageReceived(aliceCloseSig1))
        assertTrue(bob3 is Negotiating)
        val bobCloseSig1 = bobActions3.findOutgoingMessage<ClosingSigned>()
        assertTrue(aliceFeeRange.min < bobCloseSig1.feeSatoshis)
        assertTrue(bobCloseSig1.feeSatoshis < aliceFeeRange.max)
        assertNotNull(bobCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>())
        assertTrue(aliceCloseSig1.feeSatoshis < bobCloseSig1.feeSatoshis)
        assertNotNull(bob3.bestUnpublishedClosingTx)

        // alice accepts this proposition
        val (alice3, aliceActions3) = alice2.processEx(ChannelEvent.MessageReceived(bobCloseSig1))
        assertTrue(alice3 is Closing)
        val mutualCloseTx = aliceActions3.findTxs().first()
        assertEquals(aliceActions3.findWatch<WatchConfirmed>().txId, mutualCloseTx.txid)
        assertEquals(mutualCloseTx.txOut.size, 2) // NB: anchors are removed from the closing tx
        val aliceCloseSig2 = aliceActions3.findOutgoingMessage<ClosingSigned>()
        assertEquals(aliceCloseSig2.feeSatoshis, bobCloseSig1.feeSatoshis)
        val (bob4, bobActions4) = bob3.processEx(ChannelEvent.MessageReceived(aliceCloseSig2))
        assertTrue(bob4 is Closing)
        bobActions4.hasTx(mutualCloseTx)
        assertEquals(bobActions4.findWatch<WatchConfirmed>().txId, mutualCloseTx.txid)
        assertEquals(alice3.mutualClosePublished.map { it.tx }, listOf(mutualCloseTx))
        assertEquals(bob4.mutualClosePublished.map { it.tx }, listOf(mutualCloseTx))
    }

    @Test
    fun `recv ClosingSigned (theirCloseFee != ourCloseFee)`() {
        val (alice, bob) = reachNormal()
        testClosingSignedDifferentFees(alice, bob)
    }

    @Test
    fun `recv ClosingSigned (theirCloseFee != ourCloseFee, bob starts closing)`() {
        val (alice, bob) = reachNormal()
        testClosingSignedDifferentFees(alice, bob, bobInitiates = true)
    }

    @Test
    fun `recv ClosingSigned (theirMinCloseFee greater than ourCloseFee)`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(10_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(2_500.sat))

        val (_, bob2, aliceCloseSig) = mutualCloseAlice(alice1, bob1)
        val (bob3, actions) = bob2.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
        assertTrue(bob3 is Closing)
        val bobCloseSig = actions.findOutgoingMessage<ClosingSigned>()
        assertEquals(bobCloseSig.feeSatoshis, aliceCloseSig.feeSatoshis)
    }

    @Test
    fun `recv ClosingSigned (theirMaxCloseFee smaller than ourCloseFee)`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(5_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(20_000.sat))

        val (_, bob2, aliceCloseSig) = mutualCloseAlice(alice1, bob1)
        val (_, actions) = bob2.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
        val bobCloseSig = actions.findOutgoingMessage<ClosingSigned>()
        assertEquals(bobCloseSig.feeSatoshis, aliceCloseSig.tlvStream.get<ClosingSignedTlv.FeeRange>()!!.max)
    }

    private fun testClosingSignedSameFees(alice: Normal, bob: Normal, bobInitiates: Boolean = false) {
        val alice1 = alice.updateFeerate(FeeratePerKw(5_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(5_000.sat))
        val (alice2, bob2, aliceCloseSig1) = if (bobInitiates) mutualCloseBob(alice1, bob1) else mutualCloseAlice(alice1, bob1)

        // alice is funder so she initiates the negotiation
        assertEquals(aliceCloseSig1.feeSatoshis, 3370.sat) // matches a feerate of 5000 sat/kw
        val aliceFeeRange = aliceCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>()
        assertNotNull(aliceFeeRange)

        // bob agrees with that proposal
        val (bob3, bobActions3) = bob2.processEx(ChannelEvent.MessageReceived(aliceCloseSig1))
        assertTrue(bob3 is Closing)
        val bobCloseSig1 = bobActions3.findOutgoingMessage<ClosingSigned>()
        assertNotNull(bobCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>())
        assertEquals(aliceCloseSig1.feeSatoshis, bobCloseSig1.feeSatoshis)
        val mutualCloseTx = bobActions3.findTxs().first()
        assertEquals(mutualCloseTx.txOut.size, 2) // NB: anchors are removed from the closing tx

        val (alice3, aliceActions3) = alice2.processEx(ChannelEvent.MessageReceived(bobCloseSig1))
        assertTrue(alice3 is Closing)
        aliceActions3.hasTx(mutualCloseTx)
    }

    @Test
    fun `recv ClosingSigned (theirCloseFee == ourCloseFee)`() {
        val (alice, bob) = reachNormal()
        testClosingSignedSameFees(alice, bob)
    }

    @Test
    fun `recv ClosingSigned (theirCloseFee == ourCloseFee, bob starts closing)`() {
        val (alice, bob) = reachNormal()
        testClosingSignedSameFees(alice, bob, bobInitiates = true)
    }

    @Test
    fun `override on-chain fee estimator (funder)`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(10_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))

        // alice initiates the negotiation with a very low feerate
        val (alice2, bob2, aliceCloseSig) = mutualCloseAlice(alice1, bob1, feerates = ClosingFeerates(FeeratePerKw(2_500.sat), FeeratePerKw(2_000.sat), FeeratePerKw(3_000.sat)))
        assertEquals(aliceCloseSig.feeSatoshis, 1685.sat)
        assertEquals(aliceCloseSig.tlvStream.get<ClosingSignedTlv.FeeRange>(), ClosingSignedTlv.FeeRange(1348.sat, 2022.sat))

        // bob chooses alice's highest fee
        val (bob3, bobActions3) = bob2.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
        val bobCloseSig = bobActions3.findOutgoingMessage<ClosingSigned>()
        assertEquals(bobCloseSig.feeSatoshis, 2022.sat)

        // alice accepts this proposition
        val (alice3, aliceActions3) = alice2.process(ChannelEvent.MessageReceived(bobCloseSig))
        assertTrue(alice3 is Closing)
        val mutualCloseTx = aliceActions3.findTxs().first()
        val aliceCloseSig2 = aliceActions3.findOutgoingMessage<ClosingSigned>()
        assertEquals(aliceCloseSig2.feeSatoshis, 2022.sat)

        val (bob4, bobActions4) = bob3.processEx(ChannelEvent.MessageReceived(aliceCloseSig2))
        assertTrue(bob4 is Closing)
        bobActions4.hasTx(mutualCloseTx)
    }

    @Test
    fun `override on-chain fee estimator (fundee)`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(10_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))

        // alice is funder, so bob's override will simply be ignored
        val (alice2, bob2, aliceCloseSig) = mutualCloseBob(alice1, bob1, feerates = ClosingFeerates(FeeratePerKw(2_500.sat), FeeratePerKw(2_000.sat), FeeratePerKw(3_000.sat)))
        assertEquals(aliceCloseSig.feeSatoshis, 6740.sat) // matches a feerate of 10 000 sat/kw

        // bob directly agrees because their fee estimator matches
        val (bob3, bobActions3) = bob2.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
        assertTrue(bob3 is Closing)
        val mutualCloseTx = bobActions3.findTxs().first()
        val bobCloseSig = bobActions3.findOutgoingMessage<ClosingSigned>()
        assertEquals(bobCloseSig.feeSatoshis, aliceCloseSig.feeSatoshis)

        // alice accepts this proposition
        val (alice3, aliceActions3) = alice2.process(ChannelEvent.MessageReceived(bobCloseSig))
        assertTrue(alice3 is Closing)
        aliceActions3.hasTx(mutualCloseTx)
    }

    @Test
    fun `recv ClosingSigned (nothing at stake)`() {
        val (alice, bob) = reachNormal(pushMsat = 0.msat)
        val alice1 = alice.updateFeerate(FeeratePerKw(5_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))

        // Bob has nothing at stake
        val (_, bob2, aliceCloseSig) = mutualCloseBob(alice1, bob1)
        val (bob3, bobActions3) = bob2.processEx(ChannelEvent.MessageReceived(aliceCloseSig))
        assertTrue(bob3 is Closing)
        val mutualCloseTx = bobActions3.findTxs().first()
        assertEquals(bob3.mutualClosePublished.map { it.tx }, listOf(mutualCloseTx))
        assertEquals(bobActions3.findWatches<WatchConfirmed>().map { it.event }, listOf(BITCOIN_TX_CONFIRMED(mutualCloseTx)))
    }

    @Test
    fun `recv ClosingSigned (other side ignores our fee range, funder)`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(1_000.sat))
        val (alice2, bob2, aliceCloseSig1) = mutualCloseAlice(alice1, bob)
        val aliceFeeRange = aliceCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>()
        assertNotNull(aliceFeeRange)
        assertEquals(aliceCloseSig1.feeSatoshis, 674.sat)
        assertEquals(aliceFeeRange.max, 1348.sat)
        assertEquals(alice2.closingTxProposed.last().size, 1)
        assertNull(alice2.bestUnpublishedClosingTx)

        // bob makes a proposal outside our fee range
        val (_, bobCloseSig1) = makeLegacyClosingSigned(alice2, bob2, 2_500.sat)
        val (alice3, actions3) = alice2.processEx(ChannelEvent.MessageReceived(bobCloseSig1))
        assertTrue(alice3 is Negotiating)
        val aliceCloseSig2 = actions3.findOutgoingMessage<ClosingSigned>()
        assertTrue(aliceCloseSig1.feeSatoshis < aliceCloseSig2.feeSatoshis)
        assertTrue(aliceCloseSig2.feeSatoshis < 1600.sat)
        assertEquals(alice3.closingTxProposed.last().size, 2)
        assertNotNull(alice3.bestUnpublishedClosingTx)

        val (_, bobCloseSig2) = makeLegacyClosingSigned(alice2, bob2, 2_000.sat)
        val (alice4, actions4) = alice3.processEx(ChannelEvent.MessageReceived(bobCloseSig2))
        assertTrue(alice4 is Negotiating)
        val aliceCloseSig3 = actions4.findOutgoingMessage<ClosingSigned>()
        assertTrue(aliceCloseSig2.feeSatoshis < aliceCloseSig3.feeSatoshis)
        assertTrue(aliceCloseSig3.feeSatoshis < 1800.sat)
        assertEquals(alice4.closingTxProposed.last().size, 3)
        assertNotNull(alice4.bestUnpublishedClosingTx)

        val (_, bobCloseSig3) = makeLegacyClosingSigned(alice2, bob2, 1_800.sat)
        val (alice5, actions5) = alice4.processEx(ChannelEvent.MessageReceived(bobCloseSig3))
        assertTrue(alice5 is Negotiating)
        val aliceCloseSig4 = actions5.findOutgoingMessage<ClosingSigned>()
        assertTrue(aliceCloseSig3.feeSatoshis < aliceCloseSig4.feeSatoshis)
        assertTrue(aliceCloseSig4.feeSatoshis < 1800.sat)
        assertEquals(alice5.closingTxProposed.last().size, 4)
        assertNotNull(alice5.bestUnpublishedClosingTx)

        val (_, bobCloseSig4) = makeLegacyClosingSigned(alice2, bob2, aliceCloseSig4.feeSatoshis)
        val (alice6, actions6) = alice5.processEx(ChannelEvent.MessageReceived(bobCloseSig4))
        assertTrue(alice6 is Closing)
        val mutualCloseTx = actions6.findTxs().first()
        assertEquals(alice6.mutualClosePublished.size, 1)
        assertEquals(mutualCloseTx, alice6.mutualClosePublished.first().tx)
    }

    @Test
    fun `recv ClosingSigned (other side ignores our fee range, fundee)`() {
        val (alice, bob) = reachNormal()
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))
        val (alice2, bob2, _) = mutualCloseBob(alice, bob1)

        // alice starts with a very low proposal
        val (aliceCloseSig1, _) = makeLegacyClosingSigned(alice2, bob2, 500.sat)
        val (bob3, actions3) = bob2.processEx(ChannelEvent.MessageReceived(aliceCloseSig1))
        assertTrue(bob3 is Negotiating)
        val bobCloseSig1 = actions3.findOutgoingMessage<ClosingSigned>()
        assertTrue(3000.sat < bobCloseSig1.feeSatoshis)
        assertEquals(bob3.closingTxProposed.last().size, 1)
        assertNotNull(bob3.bestUnpublishedClosingTx)

        val (aliceCloseSig2, _) = makeLegacyClosingSigned(alice2, bob2, 750.sat)
        val (bob4, actions4) = bob3.processEx(ChannelEvent.MessageReceived(aliceCloseSig2))
        assertTrue(bob4 is Negotiating)
        val bobCloseSig2 = actions4.findOutgoingMessage<ClosingSigned>()
        assertTrue(2000.sat < bobCloseSig2.feeSatoshis)
        assertEquals(bob4.closingTxProposed.last().size, 2)
        assertNotNull(bob4.bestUnpublishedClosingTx)

        val (aliceCloseSig3, _) = makeLegacyClosingSigned(alice2, bob2, 1000.sat)
        val (bob5, actions5) = bob4.processEx(ChannelEvent.MessageReceived(aliceCloseSig3))
        assertTrue(bob5 is Negotiating)
        val bobCloseSig3 = actions5.findOutgoingMessage<ClosingSigned>()
        assertTrue(1500.sat < bobCloseSig3.feeSatoshis)
        assertEquals(bob5.closingTxProposed.last().size, 3)
        assertNotNull(bob5.bestUnpublishedClosingTx)

        val (aliceCloseSig4, _) = makeLegacyClosingSigned(alice2, bob2, 1300.sat)
        val (bob6, actions6) = bob5.processEx(ChannelEvent.MessageReceived(aliceCloseSig4))
        assertTrue(bob6 is Negotiating)
        val bobCloseSig4 = actions6.findOutgoingMessage<ClosingSigned>()
        assertTrue(1300.sat < bobCloseSig4.feeSatoshis)
        assertEquals(bob6.closingTxProposed.last().size, 4)
        assertNotNull(bob6.bestUnpublishedClosingTx)

        val (aliceCloseSig5, _) = makeLegacyClosingSigned(alice2, bob2, bobCloseSig4.feeSatoshis)
        val (bob7, actions7) = bob6.processEx(ChannelEvent.MessageReceived(aliceCloseSig5))
        assertTrue(bob7 is Closing)
        val mutualCloseTx = actions7.findTxs().first()
        assertEquals(bob7.mutualClosePublished.size, 1)
        assertEquals(mutualCloseTx, bob7.mutualClosePublished.first().tx)
    }

    @Test
    fun `recv ClosingSigned (other side ignores our fee range, max iterations reached)`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(1_000.sat))
        val (alice2, bob2, aliceCloseSig1) = mutualCloseAlice(alice1, bob)
        var mutableAlice = alice2 as ChannelStateWithCommitments
        var aliceCloseSig = aliceCloseSig1

        for (i in 1..Channel.MAX_NEGOTIATION_ITERATIONS) {
            val feeRange = aliceCloseSig.tlvStream.get<ClosingSignedTlv.FeeRange>()
            assertNotNull(feeRange)
            val bobNextFee = (aliceCloseSig.feeSatoshis + 500.sat).max(feeRange.max + 1.sat)
            val (_, bobClosing) = makeLegacyClosingSigned(alice2, bob2, bobNextFee)
            val (aliceNew, actions) = mutableAlice.processEx(ChannelEvent.MessageReceived(bobClosing))
            aliceCloseSig = actions.findOutgoingMessage<ClosingSigned>()
            mutableAlice = aliceNew as ChannelStateWithCommitments
        }

        assertTrue(mutableAlice is Closing)
        assertEquals(mutableAlice.mutualClosePublished.size, 1)
    }

    @Test
    fun `recv ClosingSigned (invalid signature)`() {
        val (_, bob, aliceCloseSig) = init()
        val (bob1, actions) = bob.processEx(ChannelEvent.MessageReceived(aliceCloseSig.copy(feeSatoshis = 99_000.sat)))
        assertTrue(bob1 is Closing)
        actions.hasOutgoingMessage<Error>()
        actions.hasWatch<WatchConfirmed>()
        actions.findTxs().contains(bob.commitments.localCommit.publishableTxs.commitTx.tx)
    }

    @Test
    fun `recv ClosingSigned with encrypted channel data`() {
        val (_, _, aliceCloseSig) = init(ChannelVersion.STANDARD or ChannelVersion.ZERO_RESERVE)
        assertFalse(aliceCloseSig.channelData.isEmpty())
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (counterparty's mutual close)`() {
        // NB: we're fundee here, not funder
        val (bob, alice) = reachNormal()
        val priv = randomKey()

        // Alice initiates a mutual close with a custom final script
        val finalScript = Script.write(Script.pay2pkh(priv.publicKey())).toByteVector()
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(finalScript, null)))
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

        // Bob published his closing tx (which should be the same as Alice's)
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
    fun `recv BITCOIN_FUNDING_SPENT (an older mutual close)`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(1_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))
        val (alice2, bob2, aliceCloseSig1) = mutualCloseAlice(alice1, bob1)

        val (bob3, bobActions3) = bob2.processEx(ChannelEvent.MessageReceived(aliceCloseSig1))
        assertTrue(bob3 is Negotiating)
        bobActions3.findOutgoingMessage<ClosingSigned>()
        val firstMutualCloseTx = bob3.bestUnpublishedClosingTx
        assertNotNull(firstMutualCloseTx)

        val (_, bobCloseSig1) = makeLegacyClosingSigned(alice2, bob2, 3_000.sat)
        assertNotEquals(bobCloseSig1.feeSatoshis, aliceCloseSig1.feeSatoshis)
        val (alice3, aliceActions3) = alice2.processEx(ChannelEvent.MessageReceived(bobCloseSig1))
        assertTrue(alice3 is Negotiating)
        val aliceCloseSig2 = aliceActions3.findOutgoingMessage<ClosingSigned>()
        assertNotEquals(aliceCloseSig2.feeSatoshis, bobCloseSig1.feeSatoshis)
        val latestMutualCloseTx = alice3.bestUnpublishedClosingTx
        assertNotNull(latestMutualCloseTx)
        assertNotEquals(firstMutualCloseTx.tx.txid, latestMutualCloseTx.tx.txid)

        // at this point bob will receive a new signature, but he decides instead to publish the first mutual close
        val (alice4, aliceActions4) = alice3.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice3.channelId, BITCOIN_FUNDING_SPENT, firstMutualCloseTx.tx)))
        assertTrue(alice4 is Closing)
        aliceActions4.has<ChannelAction.Storage.StoreState>()
        aliceActions4.hasTx(firstMutualCloseTx.tx)
        assertEquals(aliceActions4.hasWatch<WatchConfirmed>().txId, firstMutualCloseTx.tx.txid)
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (alice, _, _) = init()
        val (alice1, actions) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null, null)))
        assertEquals(alice1, alice)
        assertEquals(actions, listOf(ChannelAction.ProcessCmdRes.NotExecuted(CMD_CLOSE(null, null), ClosingAlreadyInProgress(alice.channelId))))
    }

    @Test
    fun `recv Error`() {
        val (alice, _, _) = init()
        val (alice1, actions) = alice.processEx(ChannelEvent.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertTrue(alice1 is Closing)
        actions.hasTx(alice.commitments.localCommit.publishableTxs.commitTx.tx)
        assertTrue(actions.findWatches<WatchConfirmed>().map { it.event }.contains(BITCOIN_TX_CONFIRMED(alice.commitments.localCommit.publishableTxs.commitTx.tx)))
    }

    companion object {
        fun init(channelVersion: ChannelVersion = ChannelVersion.STANDARD, pushMsat: MilliSatoshi = TestConstants.pushMsat): Triple<Negotiating, Negotiating, ClosingSigned> {
            val (alice, bob) = reachNormal(channelVersion = channelVersion, pushMsat = pushMsat)
            return mutualCloseAlice(alice, bob)
        }

        private fun makeLegacyClosingSigned(alice: Negotiating, bob: Negotiating, closingFee: Satoshi): Pair<ClosingSigned, ClosingSigned> {
            val aliceScript = alice.localShutdown.scriptPubKey.toByteArray()
            val bobScript = bob.localShutdown.scriptPubKey.toByteArray()
            val (_, aliceClosingSigned) = Helpers.Closing.makeClosingTx(alice.keyManager, alice.commitments, aliceScript, bobScript, ClosingFees(closingFee, closingFee, closingFee))
            val (_, bobClosingSigned) = Helpers.Closing.makeClosingTx(bob.keyManager, bob.commitments, bobScript, aliceScript, ClosingFees(closingFee, closingFee, closingFee))
            return Pair(aliceClosingSigned.copy(tlvStream = TlvStream.empty()), bobClosingSigned.copy(tlvStream = TlvStream.empty()))
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
