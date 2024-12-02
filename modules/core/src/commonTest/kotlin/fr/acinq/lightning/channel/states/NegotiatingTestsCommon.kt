package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.makeCmdAdd
import fr.acinq.lightning.channel.TestsHelper.mutualCloseAlice
import fr.acinq.lightning.channel.TestsHelper.mutualCloseBob
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
    fun `recv ChannelCommand_Htlc_Add`() {
        val (alice, _, _) = init()
        val (_, add) = makeCmdAdd(500_000.msat, alice.staticParams.remoteNodeId, TestConstants.defaultBlockHeight.toLong())
        val (alice1, actions1) = alice.process(add)
        assertIs<LNChannel<Negotiating>>(alice1)
        assertEquals(1, actions1.size)
        actions1.hasCommandError<ChannelUnavailable>()
    }

    private fun testClosingSignedDifferentFees(alice: LNChannel<Normal>, bob: LNChannel<Normal>, bobInitiates: Boolean = false) {
        // alice and bob see different on-chain feerates
        val alice1 = alice.updateFeerate(FeeratePerKw(5_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(7_500.sat))
        val (alice2, bob2, aliceCloseSig1) = if (bobInitiates) mutualCloseBob(alice1, bob1) else mutualCloseAlice(alice1, bob1)

        // alice is initiator so she initiates the negotiation
        assertEquals(aliceCloseSig1.feeSatoshis, 3370.sat) // matches a feerate of 5000 sat/kw
        val aliceFeeRange = aliceCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>()
        assertNotNull(aliceFeeRange)
        assertTrue(aliceFeeRange.min < aliceCloseSig1.feeSatoshis)
        assertTrue(aliceCloseSig1.feeSatoshis < aliceFeeRange.max)
        assertEquals(alice2.state.closingTxProposed.size, 1)
        assertEquals(alice2.state.closingTxProposed.last().size, 1)
        assertNull(alice2.state.bestUnpublishedClosingTx)

        // bob answers with a counter proposition in alice's fee range
        val (bob3, bobActions3) = bob2.process(ChannelCommand.MessageReceived(aliceCloseSig1))
        assertIs<LNChannel<Negotiating>>(bob3)
        val bobCloseSig1 = bobActions3.findOutgoingMessage<ClosingSigned>()
        assertTrue(aliceFeeRange.min < bobCloseSig1.feeSatoshis)
        assertTrue(bobCloseSig1.feeSatoshis < aliceFeeRange.max)
        assertNotNull(bobCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>())
        assertTrue(aliceCloseSig1.feeSatoshis < bobCloseSig1.feeSatoshis)
        assertNotNull(bob3.state.bestUnpublishedClosingTx)

        // alice accepts this proposition
        val (alice3, aliceActions3) = alice2.process(ChannelCommand.MessageReceived(bobCloseSig1))
        assertIs<LNChannel<Closing>>(alice3)
        val mutualCloseTx = aliceActions3.findPublishTxs().first()
        assertEquals(aliceActions3.findWatch<WatchConfirmed>().txId, mutualCloseTx.txid)
        assertEquals(mutualCloseTx.txOut.size, 2) // NB: anchors are removed from the closing tx
        val aliceCloseSig2 = aliceActions3.findOutgoingMessage<ClosingSigned>()
        assertEquals(aliceCloseSig2.feeSatoshis, bobCloseSig1.feeSatoshis)
        val (bob4, bobActions4) = bob3.process(ChannelCommand.MessageReceived(aliceCloseSig2))
        assertIs<LNChannel<Closing>>(bob4)
        bobActions4.hasPublishTx(mutualCloseTx)
        assertEquals(bobActions4.findWatch<WatchConfirmed>().txId, mutualCloseTx.txid)
        assertEquals(alice3.state.mutualClosePublished.map { it.tx }, listOf(mutualCloseTx))
        assertEquals(bob4.state.mutualClosePublished.map { it.tx }, listOf(mutualCloseTx))
    }

    @Test
    fun `recv ClosingSigned -- theirCloseFee != ourCloseFee`() {
        val (alice, bob) = reachNormal()
        testClosingSignedDifferentFees(alice, bob)
    }

    @Test
    fun `recv ClosingSigned -- theirCloseFee != ourCloseFee + bob starts closing`() {
        val (alice, bob) = reachNormal()
        testClosingSignedDifferentFees(alice, bob, bobInitiates = true)
    }

    @Test
    fun `recv ClosingSigned -- theirMinCloseFee greater than ourCloseFee`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(10_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(2_500.sat))

        val (_, bob2, aliceCloseSig) = mutualCloseAlice(alice1, bob1)
        val (bob3, actions) = bob2.process(ChannelCommand.MessageReceived(aliceCloseSig))
        assertIs<LNChannel<Closing>>(bob3)
        val bobCloseSig = actions.findOutgoingMessage<ClosingSigned>()
        assertEquals(bobCloseSig.feeSatoshis, aliceCloseSig.feeSatoshis)
    }

    @Test
    fun `recv ClosingSigned -- theirMaxCloseFee smaller than ourCloseFee`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(5_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(20_000.sat))

        val (_, bob2, aliceCloseSig) = mutualCloseAlice(alice1, bob1)
        val (_, actions) = bob2.process(ChannelCommand.MessageReceived(aliceCloseSig))
        val bobCloseSig = actions.findOutgoingMessage<ClosingSigned>()
        assertEquals(bobCloseSig.feeSatoshis, aliceCloseSig.tlvStream.get<ClosingSignedTlv.FeeRange>()!!.max)
    }

    private fun testClosingSignedSameFees(alice: LNChannel<Normal>, bob: LNChannel<Normal>, bobInitiates: Boolean = false) {
        val alice1 = alice.updateFeerate(FeeratePerKw(5_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(5_000.sat))
        val (alice2, bob2, aliceCloseSig1) = if (bobInitiates) mutualCloseBob(alice1, bob1) else mutualCloseAlice(alice1, bob1)

        // alice is initiator so she initiates the negotiation
        assertEquals(aliceCloseSig1.feeSatoshis, 3370.sat) // matches a feerate of 5000 sat/kw
        val aliceFeeRange = aliceCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>()
        assertNotNull(aliceFeeRange)

        // bob agrees with that proposal
        val (bob3, bobActions3) = bob2.process(ChannelCommand.MessageReceived(aliceCloseSig1))
        assertIs<LNChannel<Closing>>(bob3)
        val bobCloseSig1 = bobActions3.findOutgoingMessage<ClosingSigned>()
        assertNotNull(bobCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>())
        assertEquals(aliceCloseSig1.feeSatoshis, bobCloseSig1.feeSatoshis)
        val mutualCloseTx = bobActions3.findPublishTxs().first()
        assertEquals(mutualCloseTx.txOut.size, 2) // NB: anchors are removed from the closing tx

        val (alice3, aliceActions3) = alice2.process(ChannelCommand.MessageReceived(bobCloseSig1))
        assertIs<LNChannel<Closing>>(alice3)
        aliceActions3.hasPublishTx(mutualCloseTx)
    }

    @Test
    fun `recv ClosingSigned -- theirCloseFee == ourCloseFee`() {
        val (alice, bob) = reachNormal()
        testClosingSignedSameFees(alice, bob)
    }

    @Test
    fun `recv ClosingSigned -- theirCloseFee == ourCloseFee + bob starts closing`() {
        val (alice, bob) = reachNormal()
        testClosingSignedSameFees(alice, bob, bobInitiates = true)
    }

    @Test
    fun `recv ClosingSigned -- theirCloseFee == ourCloseFee -- non-initiator pays commit fees`() {
        val (alice, bob) = reachNormal(channelType = ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, aliceFundingAmount = 200_000.sat, requestRemoteFunding = TestConstants.bobFundingAmount)
        assertFalse(alice.commitments.params.localParams.paysCommitTxFees)
        assertTrue(bob.commitments.params.localParams.paysCommitTxFees)
        // Alice sends all of her balance to Bob.
        val (nodes1, r, htlc) = TestsHelper.addHtlc(alice.commitments.availableBalanceForSend(), alice, bob)
        val (alice1, bob1) = TestsHelper.crossSign(nodes1.first, nodes1.second)
        val (alice2, bob2) = TestsHelper.fulfillHtlc(htlc.id, r, alice1, bob1)
        val (bob3, alice3) = TestsHelper.crossSign(bob2, alice2)
        assertEquals(0.msat, alice3.commitments.latest.localCommit.spec.toLocal)
        // Alice and Bob agree on the current feerate.
        val alice4 = alice3.updateFeerate(FeeratePerKw(3_000.sat))
        val bob4 = bob3.updateFeerate(FeeratePerKw(3_000.sat))
        // Bob initiates the mutual close.
        val (bob5, actionsBob5) = bob4.process(ChannelCommand.Close.MutualClose(null, null))
        assertIs<LNChannel<ShuttingDown>>(bob5)
        val shutdownBob = actionsBob5.findOutgoingMessage<Shutdown>()
        assertNull(actionsBob5.findOutgoingMessageOpt<ClosingSigned>())
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(shutdownBob))
        assertIs<LNChannel<Negotiating>>(alice5)
        val shutdownAlice = actionsAlice5.findOutgoingMessage<Shutdown>()
        assertNull(actionsAlice5.findOutgoingMessageOpt<ClosingSigned>())
        val (bob6, actionsBob6) = bob5.process(ChannelCommand.MessageReceived(shutdownAlice))
        assertIs<LNChannel<Negotiating>>(bob6)
        val closingSignedBob = actionsBob6.findOutgoingMessage<ClosingSigned>()
        val (alice6, actionsAlice6) = alice5.process(ChannelCommand.MessageReceived(closingSignedBob))
        assertIs<Closing>(alice6.state)
        val closingSignedAlice = actionsAlice6.findOutgoingMessage<ClosingSigned>()
        val mutualCloseTx = actionsAlice6.findPublishTxs().first()
        assertEquals(1, mutualCloseTx.txOut.size)
        val (bob7, actionsBob7) = bob6.process(ChannelCommand.MessageReceived(closingSignedAlice))
        assertIs<Closing>(bob7.state)
        actionsBob7.hasPublishTx(mutualCloseTx)
    }

    @Test
    fun `override on-chain fee estimator -- initiator`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(10_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))

        // alice initiates the negotiation with a very low feerate
        val (alice2, bob2, aliceCloseSig) = mutualCloseAlice(alice1, bob1, feerates = ClosingFeerates(FeeratePerKw(2_500.sat), FeeratePerKw(2_000.sat), FeeratePerKw(3_000.sat)))
        assertEquals(aliceCloseSig.feeSatoshis, 1685.sat)
        assertEquals(aliceCloseSig.tlvStream.get(), ClosingSignedTlv.FeeRange(1348.sat, 2022.sat))

        // bob chooses alice's highest fee
        val (bob3, bobActions3) = bob2.process(ChannelCommand.MessageReceived(aliceCloseSig))
        val bobCloseSig = bobActions3.findOutgoingMessage<ClosingSigned>()
        assertEquals(bobCloseSig.feeSatoshis, 2022.sat)

        // alice accepts this proposition
        val (alice3, aliceActions3) = alice2.process(ChannelCommand.MessageReceived(bobCloseSig))
        assertIs<LNChannel<Closing>>(alice3)
        val mutualCloseTx = aliceActions3.findPublishTxs().first()
        val aliceCloseSig2 = aliceActions3.findOutgoingMessage<ClosingSigned>()
        assertEquals(aliceCloseSig2.feeSatoshis, 2022.sat)

        val (bob4, bobActions4) = bob3.process(ChannelCommand.MessageReceived(aliceCloseSig2))
        assertIs<LNChannel<Closing>>(bob4)
        bobActions4.hasPublishTx(mutualCloseTx)
    }

    @Test
    fun `override on-chain fee estimator -- non-initiator`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(10_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))

        // alice is initiator, so bob's override will simply be ignored
        val (alice2, bob2, aliceCloseSig) = mutualCloseBob(alice1, bob1, feerates = ClosingFeerates(FeeratePerKw(2_500.sat), FeeratePerKw(2_000.sat), FeeratePerKw(3_000.sat)))
        assertEquals(aliceCloseSig.feeSatoshis, 6740.sat) // matches a feerate of 10 000 sat/kw

        // bob directly agrees because their fee estimator matches
        val (bob3, bobActions3) = bob2.process(ChannelCommand.MessageReceived(aliceCloseSig))
        assertIs<LNChannel<Closing>>(bob3)
        val mutualCloseTx = bobActions3.findPublishTxs().first()
        val bobCloseSig = bobActions3.findOutgoingMessage<ClosingSigned>()
        assertEquals(bobCloseSig.feeSatoshis, aliceCloseSig.feeSatoshis)

        // alice accepts this proposition
        val (alice3, aliceActions3) = alice2.process(ChannelCommand.MessageReceived(bobCloseSig))
        assertIs<LNChannel<Closing>>(alice3)
        aliceActions3.hasPublishTx(mutualCloseTx)
    }

    @Test
    fun `recv ClosingSigned -- nothing at stake`() {
        val (alice, bob) = reachNormal(bobFundingAmount = 0.sat)
        val alice1 = alice.updateFeerate(FeeratePerKw(5_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))

        // Bob has nothing at stake
        val (_, bob2, aliceCloseSig) = mutualCloseBob(alice1, bob1)
        val (bob3, bobActions3) = bob2.process(ChannelCommand.MessageReceived(aliceCloseSig))
        assertIs<LNChannel<Closing>>(bob3)
        val mutualCloseTx = bobActions3.findPublishTxs().first()
        assertEquals(bob3.state.mutualClosePublished.map { it.tx }, listOf(mutualCloseTx))
        assertEquals(bobActions3.findWatches<WatchConfirmed>().map { it.event }, listOf(BITCOIN_TX_CONFIRMED(mutualCloseTx)))
    }

    @Test
    fun `recv ClosingSigned -- other side ignores our fee range + initiator`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(1_000.sat))
        val (alice2, bob2, aliceCloseSig1) = mutualCloseAlice(alice1, bob)
        val aliceFeeRange = aliceCloseSig1.tlvStream.get<ClosingSignedTlv.FeeRange>()
        assertNotNull(aliceFeeRange)
        assertEquals(aliceCloseSig1.feeSatoshis, 674.sat)
        assertEquals(aliceFeeRange.max, 1348.sat)
        assertEquals(alice2.state.closingTxProposed.last().size, 1)
        assertNull(alice2.state.bestUnpublishedClosingTx)

        // bob makes a proposal outside our fee range
        val (_, bobCloseSig1) = makeLegacyClosingSigned(alice2, bob2, 2_500.sat)
        val (alice3, actions3) = alice2.process(ChannelCommand.MessageReceived(bobCloseSig1))
        assertIs<LNChannel<Negotiating>>(alice3)
        val aliceCloseSig2 = actions3.findOutgoingMessage<ClosingSigned>()
        assertTrue(aliceCloseSig1.feeSatoshis < aliceCloseSig2.feeSatoshis)
        assertTrue(aliceCloseSig2.feeSatoshis < 1600.sat)
        assertEquals(alice3.state.closingTxProposed.last().size, 2)
        assertNotNull(alice3.state.bestUnpublishedClosingTx)

        val (_, bobCloseSig2) = makeLegacyClosingSigned(alice2, bob2, 2_000.sat)
        val (alice4, actions4) = alice3.process(ChannelCommand.MessageReceived(bobCloseSig2))
        assertIs<LNChannel<Negotiating>>(alice4)
        val aliceCloseSig3 = actions4.findOutgoingMessage<ClosingSigned>()
        assertTrue(aliceCloseSig2.feeSatoshis < aliceCloseSig3.feeSatoshis)
        assertTrue(aliceCloseSig3.feeSatoshis < 1800.sat)
        assertEquals(alice4.state.closingTxProposed.last().size, 3)
        assertNotNull(alice4.state.bestUnpublishedClosingTx)

        val (_, bobCloseSig3) = makeLegacyClosingSigned(alice2, bob2, 1_800.sat)
        val (alice5, actions5) = alice4.process(ChannelCommand.MessageReceived(bobCloseSig3))
        assertIs<LNChannel<Negotiating>>(alice5)
        val aliceCloseSig4 = actions5.findOutgoingMessage<ClosingSigned>()
        assertTrue(aliceCloseSig3.feeSatoshis < aliceCloseSig4.feeSatoshis)
        assertTrue(aliceCloseSig4.feeSatoshis < 1800.sat)
        assertEquals(alice5.state.closingTxProposed.last().size, 4)
        assertNotNull(alice5.state.bestUnpublishedClosingTx)

        val (_, bobCloseSig4) = makeLegacyClosingSigned(alice2, bob2, aliceCloseSig4.feeSatoshis)
        val (alice6, actions6) = alice5.process(ChannelCommand.MessageReceived(bobCloseSig4))
        assertIs<LNChannel<Closing>>(alice6)
        val mutualCloseTx = actions6.findPublishTxs().first()
        assertEquals(alice6.state.mutualClosePublished.size, 1)
        assertEquals(mutualCloseTx, alice6.state.mutualClosePublished.first().tx)
    }

    @Test
    fun `recv ClosingSigned -- other side ignores our fee range + non-initiator`() {
        val (alice, bob) = reachNormal()
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))
        val (alice2, bob2, _) = mutualCloseBob(alice, bob1)

        // alice starts with a very low proposal
        val (aliceCloseSig1, _) = makeLegacyClosingSigned(alice2, bob2, 500.sat)
        val (bob3, actions3) = bob2.process(ChannelCommand.MessageReceived(aliceCloseSig1))
        assertIs<LNChannel<Negotiating>>(bob3)
        val bobCloseSig1 = actions3.findOutgoingMessage<ClosingSigned>()
        assertTrue(3000.sat < bobCloseSig1.feeSatoshis)
        assertEquals(bob3.state.closingTxProposed.last().size, 1)
        assertNotNull(bob3.state.bestUnpublishedClosingTx)

        val (aliceCloseSig2, _) = makeLegacyClosingSigned(alice2, bob2, 750.sat)
        val (bob4, actions4) = bob3.process(ChannelCommand.MessageReceived(aliceCloseSig2))
        assertIs<LNChannel<Negotiating>>(bob4)
        val bobCloseSig2 = actions4.findOutgoingMessage<ClosingSigned>()
        assertTrue(2000.sat < bobCloseSig2.feeSatoshis)
        assertEquals(bob4.state.closingTxProposed.last().size, 2)
        assertNotNull(bob4.state.bestUnpublishedClosingTx)

        val (aliceCloseSig3, _) = makeLegacyClosingSigned(alice2, bob2, 1000.sat)
        val (bob5, actions5) = bob4.process(ChannelCommand.MessageReceived(aliceCloseSig3))
        assertIs<LNChannel<Negotiating>>(bob5)
        val bobCloseSig3 = actions5.findOutgoingMessage<ClosingSigned>()
        assertTrue(1500.sat < bobCloseSig3.feeSatoshis)
        assertEquals(bob5.state.closingTxProposed.last().size, 3)
        assertNotNull(bob5.state.bestUnpublishedClosingTx)

        val (aliceCloseSig4, _) = makeLegacyClosingSigned(alice2, bob2, 1300.sat)
        val (bob6, actions6) = bob5.process(ChannelCommand.MessageReceived(aliceCloseSig4))
        assertIs<LNChannel<Negotiating>>(bob6)
        val bobCloseSig4 = actions6.findOutgoingMessage<ClosingSigned>()
        assertTrue(1300.sat < bobCloseSig4.feeSatoshis)
        assertEquals(bob6.state.closingTxProposed.last().size, 4)
        assertNotNull(bob6.state.bestUnpublishedClosingTx)

        val (aliceCloseSig5, _) = makeLegacyClosingSigned(alice2, bob2, bobCloseSig4.feeSatoshis)
        val (bob7, actions7) = bob6.process(ChannelCommand.MessageReceived(aliceCloseSig5))
        assertIs<LNChannel<Closing>>(bob7)
        val mutualCloseTx = actions7.findPublishTxs().first()
        assertEquals(bob7.state.mutualClosePublished.size, 1)
        assertEquals(mutualCloseTx, bob7.state.mutualClosePublished.first().tx)
    }

    @Test
    fun `recv ClosingSigned -- other side ignores our fee range + max iterations reached`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(1_000.sat))
        val (alice2, bob2, aliceCloseSig1) = mutualCloseAlice(alice1, bob)
        assertIs<LNChannel<ChannelStateWithCommitments>>(alice2)
        var mutableAlice: LNChannel<ChannelStateWithCommitments> = alice2
        var aliceCloseSig = aliceCloseSig1

        for (i in 1..Channel.MAX_NEGOTIATION_ITERATIONS) {
            val feeRange = aliceCloseSig.tlvStream.get<ClosingSignedTlv.FeeRange>()
            assertNotNull(feeRange)
            val bobNextFee = (aliceCloseSig.feeSatoshis + 500.sat).max(feeRange.max + 1.sat)
            val (_, bobClosing) = makeLegacyClosingSigned(alice2, bob2, bobNextFee)
            val (aliceNew, actions) = mutableAlice.process(ChannelCommand.MessageReceived(bobClosing))
            aliceCloseSig = actions.findOutgoingMessage()
            assertIs<LNChannel<ChannelStateWithCommitments>>(aliceNew)
            mutableAlice = aliceNew
        }

        assertIs<LNChannel<Closing>>(mutableAlice)
        assertEquals(mutableAlice.state.mutualClosePublished.size, 1)
    }

    @Test
    fun `recv ClosingSigned -- invalid signature`() {
        val (_, bob, aliceCloseSig) = init()
        val (bob1, actions) = bob.process(ChannelCommand.MessageReceived(aliceCloseSig.copy(feeSatoshis = 99_000.sat)))
        assertIs<LNChannel<Closing>>(bob1)
        actions.hasOutgoingMessage<Error>()
        actions.hasWatch<WatchConfirmed>()
        actions.findPublishTxs().contains(bob.commitments.latest.localCommit.publishableTxs.commitTx.tx)
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- counterparty's mutual close`() {
        // NB: we're not the initiator here
        val (bob, alice, fundingTx) = reachNormal()
        val priv = randomKey()

        // Alice initiates a mutual close with a custom final script
        val finalScript = Script.write(Script.pay2pkh(priv.publicKey())).toByteVector()
        val (alice1, actions1) = alice.process(ChannelCommand.Close.MutualClose(finalScript, null))
        val shutdownA = actions1.findOutgoingMessage<Shutdown>()

        // Bob replies with Shutdown + ClosingSigned
        val (bob1, actions2) = bob.process(ChannelCommand.MessageReceived(shutdownA))
        val shutdownB = actions2.findOutgoingMessage<Shutdown>()
        val closingSignedB = actions2.findOutgoingMessage<ClosingSigned>()

        // Alice agrees with Bob's closing fee, publishes her closing tx and replies with her own ClosingSigned
        val (alice2, _) = alice1.process(ChannelCommand.MessageReceived(shutdownB))
        val (alice3, actions4) = alice2.process(ChannelCommand.MessageReceived(closingSignedB))
        assertIs<LNChannel<Closing>>(alice3)
        val closingTxA = actions4.filterIsInstance<ChannelAction.Blockchain.PublishTx>().first().tx
        val closingSignedA = actions4.findOutgoingMessage<ClosingSigned>()
        val watch = actions4.findWatch<WatchConfirmed>()
        assertEquals(watch.txId, closingTxA.txid)

        assertEquals(fundingTx.txid, closingTxA.txIn[0].outPoint.txid)
        // check that our closing tx is correctly signed
        Transaction.correctlySpends(closingTxA, fundingTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // Bob published his closing tx (which should be the same as Alice's)
        val (bob2, actions5) = bob1.process(ChannelCommand.MessageReceived(closingSignedA))
        assertIs<LNChannel<Closing>>(bob2)
        val closingTxB = actions5.filterIsInstance<ChannelAction.Blockchain.PublishTx>().first().tx
        assertEquals(closingTxA, closingTxB)

        // Alice sees Bob's closing tx (which should be the same as the one she published)
        val (alice4, _) = alice3.process(ChannelCommand.WatchReceived(WatchEventSpent(alice3.channelId, BITCOIN_FUNDING_SPENT, closingTxB)))
        assertIs<LNChannel<Closing>>(alice4)

        val (alice5, _) = alice4.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice3.channelId, BITCOIN_TX_CONFIRMED(closingTxA), 144, 0, closingTxA)))
        assertIs<LNChannel<Closed>>(alice5)
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- an older mutual close`() {
        val (alice, bob) = reachNormal()
        val alice1 = alice.updateFeerate(FeeratePerKw(1_000.sat))
        val bob1 = bob.updateFeerate(FeeratePerKw(10_000.sat))
        val (alice2, bob2, aliceCloseSig1) = mutualCloseAlice(alice1, bob1)

        val (bob3, bobActions3) = bob2.process(ChannelCommand.MessageReceived(aliceCloseSig1))
        assertIs<LNChannel<Negotiating>>(bob3)
        bobActions3.findOutgoingMessage<ClosingSigned>()
        val firstMutualCloseTx = bob3.state.bestUnpublishedClosingTx
        assertNotNull(firstMutualCloseTx)

        val (_, bobCloseSig1) = makeLegacyClosingSigned(alice2, bob2, 3_000.sat)
        assertNotEquals(bobCloseSig1.feeSatoshis, aliceCloseSig1.feeSatoshis)
        val (alice3, aliceActions3) = alice2.process(ChannelCommand.MessageReceived(bobCloseSig1))
        assertIs<LNChannel<Negotiating>>(alice3)
        val aliceCloseSig2 = aliceActions3.findOutgoingMessage<ClosingSigned>()
        assertNotEquals(aliceCloseSig2.feeSatoshis, bobCloseSig1.feeSatoshis)
        val latestMutualCloseTx = alice3.state.bestUnpublishedClosingTx
        assertNotNull(latestMutualCloseTx)
        assertNotEquals(firstMutualCloseTx.tx.txid, latestMutualCloseTx.tx.txid)

        // at this point bob will receive a new signature, but he decides instead to publish the first mutual close
        val (alice4, aliceActions4) = alice3.process(ChannelCommand.WatchReceived(WatchEventSpent(alice3.channelId, BITCOIN_FUNDING_SPENT, firstMutualCloseTx.tx)))
        assertIs<LNChannel<Closing>>(alice4)
        aliceActions4.has<ChannelAction.Storage.StoreState>()
        aliceActions4.hasPublishTx(firstMutualCloseTx.tx)
        assertEquals(aliceActions4.hasWatch<WatchConfirmed>().txId, firstMutualCloseTx.tx.txid)
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose`() {
        val (alice, _, _) = init()
        val (alice1, actions) = alice.process(ChannelCommand.Close.MutualClose(null, null))
        assertEquals(alice1, alice)
        assertEquals(actions, listOf(ChannelAction.ProcessCmdRes.NotExecuted(ChannelCommand.Close.MutualClose(null, null), ClosingAlreadyInProgress(alice.channelId))))
    }

    @Test
    fun `recv Error`() {
        val (alice, _, _) = init()
        val (alice1, actions) = alice.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertIs<LNChannel<Closing>>(alice1)
        actions.hasPublishTx(alice.commitments.latest.localCommit.publishableTxs.commitTx.tx)
        assertTrue(actions.findWatches<WatchConfirmed>().map { it.event }.contains(BITCOIN_TX_CONFIRMED(alice.commitments.latest.localCommit.publishableTxs.commitTx.tx)))
    }

    companion object {
        fun init(channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs): Triple<LNChannel<Negotiating>, LNChannel<Negotiating>, ClosingSigned> {
            val (alice, bob) = reachNormal(channelType = channelType)
            return mutualCloseAlice(alice, bob)
        }

        private fun makeLegacyClosingSigned(alice: LNChannel<Negotiating>, bob: LNChannel<Negotiating>, closingFee: Satoshi): Pair<ClosingSigned, ClosingSigned> {
            val aliceScript = alice.state.localShutdown.scriptPubKey.toByteArray()
            val bobScript = bob.state.localShutdown.scriptPubKey.toByteArray()
            val aliceKeys = alice.ctx.keyManager.channelKeys(alice.commitments.params.localParams.fundingKeyPath)
            val bobKeys = bob.ctx.keyManager.channelKeys(bob.commitments.params.localParams.fundingKeyPath)
            val (_, aliceClosingSigned) = Helpers.Closing.makeClosingTx(aliceKeys, alice.commitments.latest, aliceScript, bobScript, ClosingFees(closingFee, closingFee, closingFee))
            val (_, bobClosingSigned) = Helpers.Closing.makeClosingTx(bobKeys, bob.commitments.latest, bobScript, aliceScript, ClosingFees(closingFee, closingFee, closingFee))
            return Pair(aliceClosingSigned.copy(tlvStream = TlvStream.empty()), bobClosingSigned.copy(tlvStream = TlvStream.empty()))
        }

        tailrec fun converge(a: LNChannel<ChannelState>, b: LNChannel<ChannelState>, aliceCloseSig: ClosingSigned?): Pair<LNChannel<Closing>, LNChannel<Closing>>? {
            return when {
                a.state !is ChannelStateWithCommitments || b.state !is ChannelStateWithCommitments -> null
                a.state is Closing && b.state is Closing -> Pair(LNChannel(a.ctx, a.state), LNChannel(b.ctx, b.state))
                aliceCloseSig != null -> {
                    val (b1, actions) = b.process(ChannelCommand.MessageReceived(aliceCloseSig))
                    val bobCloseSig = actions.findOutgoingMessageOpt<ClosingSigned>()
                    if (bobCloseSig != null) {
                        val (a1, actions2) = a.process(ChannelCommand.MessageReceived(bobCloseSig))
                        return converge(a1, b1, actions2.findOutgoingMessageOpt())
                    }
                    val bobClosingTx = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }.firstOrNull()
                    if (bobClosingTx != null && bobClosingTx.txIn[0].outPoint == a.commitments.latest.localCommit.publishableTxs.commitTx.input.outPoint && a.state !is Closing) {
                        // Bob just spent the funding tx
                        val (a1, actions2) = a.process(ChannelCommand.WatchReceived(WatchEventSpent(a.channelId, BITCOIN_FUNDING_SPENT, bobClosingTx)))
                        actions2.find<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>().also { assertEquals(bobClosingTx.txid, it.txId) }
                        return converge(a1, b1, actions2.findOutgoingMessageOpt())
                    }
                    converge(a, b1, null)
                }
                else -> null
            }
        }
    }

}
