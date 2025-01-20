package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Features
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_SPENT
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.Helpers.Closing.timedOutHtlcs
import fr.acinq.lightning.channel.TestsHelper.claimHtlcSuccessTxs
import fr.acinq.lightning.channel.TestsHelper.claimHtlcTimeoutTxs
import fr.acinq.lightning.channel.TestsHelper.htlcSuccessTxs
import fr.acinq.lightning.channel.TestsHelper.htlcTimeoutTxs
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.channel.states.Closing
import fr.acinq.lightning.crypto.ShaChain
import fr.acinq.lightning.logging.LoggingContext
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.testLoggerFactory
import fr.acinq.lightning.transactions.CommitmentSpec
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.IncorrectOrUnknownPaymentDetails
import fr.acinq.lightning.wire.TxSignatures
import fr.acinq.lightning.wire.UpdateAddHtlc
import kotlin.test.*

class CommitmentsTestsCommon : LightningTestSuite(), LoggingContext {

    override val logger: MDCLogger = MDCLogger(testLoggerFactory.newLogger(this::class))

    @Test
    fun `reach normal state`() {
        reachNormal()
    }

    @Test
    fun `correct values for availableForSend - availableForReceive -- success case`() {
        val (alice, bob) = reachNormal(aliceFundingAmount = 800_000.sat, bobFundingAmount = 200_000.sat)

        val aliceKeys = alice.ctx.keyManager.channelKeys(alice.commitments.params.localParams.fundingKeyPath)
        val bobKeys = bob.ctx.keyManager.channelKeys(bob.commitments.params.localParams.fundingKeyPath)

        val a = 774_660_000.msat // initial balance alice
        val b = 190_000_000.msat // initial balance bob
        val p = 42_000_000.msat // a->b payment
        val htlcOutputFee = (2 * 860_000).msat // fee due to the additional htlc output; we count it twice because we keep a reserve for a x2 feerate increase

        val ac0 = alice.state.commitments
        val bc0 = bob.state.commitments

        assertTrue(ac0.availableBalanceForSend() > p) // alice can afford the payment
        assertEquals(ac0.availableBalanceForSend(), a)
        assertEquals(ac0.availableBalanceForReceive(), b)
        assertEquals(bc0.availableBalanceForSend(), b)
        assertEquals(bc0.availableBalanceForReceive(), a)

        val currentBlockHeight = 144L
        val (payment_preimage, cmdAdd) = TestsHelper.makeCmdAdd(p, bob.staticParams.nodeParams.nodeId, currentBlockHeight)
        val (ac1, add) = ac0.sendAdd(cmdAdd, UUID.randomUUID(), currentBlockHeight).right!!
        assertEquals(ac1.availableBalanceForSend(), a - p - htlcOutputFee) // as soon as htlc is sent, alice sees its balance decrease (more than the payment amount because of the commitment fees)
        assertEquals(ac1.availableBalanceForReceive(), b)

        val bc1 = bc0.receiveAdd(add).right!!
        assertEquals(bc1.availableBalanceForSend(), b)
        assertEquals(bc1.availableBalanceForReceive(), a - p - htlcOutputFee)

        val (ac2, commit1) = ac1.sendCommit(aliceKeys, logger).right!!
        assertEquals(ac2.availableBalanceForSend(), a - p - htlcOutputFee)
        assertEquals(ac2.availableBalanceForReceive(), b)

        val (bc2, revocation1) = bc1.receiveCommit(commit1, bobKeys, logger).right!!
        assertEquals(bc2.availableBalanceForSend(), b)
        assertEquals(bc2.availableBalanceForReceive(), a - p - htlcOutputFee)

        val ac3 = ac2.receiveRevocation(revocation1).right!!.first
        assertEquals(ac3.availableBalanceForSend(), a - p - htlcOutputFee)
        assertEquals(ac3.availableBalanceForReceive(), b)

        val (bc3, commit2) = bc2.sendCommit(bobKeys, logger).right!!
        assertEquals(bc3.availableBalanceForSend(), b)
        assertEquals(bc3.availableBalanceForReceive(), a - p - htlcOutputFee)

        val (ac4, revocation2) = ac3.receiveCommit(commit2, aliceKeys, logger).right!!
        assertEquals(ac4.availableBalanceForSend(), a - p - htlcOutputFee)
        assertEquals(ac4.availableBalanceForReceive(), b)

        val bc4 = bc3.receiveRevocation(revocation2).right!!.first
        assertEquals(bc4.availableBalanceForSend(), b)
        assertEquals(bc4.availableBalanceForReceive(), a - p - htlcOutputFee)

        val cmdFulfill = ChannelCommand.Htlc.Settlement.Fulfill(0, payment_preimage)
        val (bc5, fulfill) = bc4.sendFulfill(cmdFulfill).right!!
        assertEquals(bc5.availableBalanceForSend(), b + p) // as soon as we have the fulfill, the balance increases
        assertEquals(bc5.availableBalanceForReceive(), a - p - htlcOutputFee)

        val ac5 = ac4.receiveFulfill(fulfill).right!!.first
        assertEquals(ac5.availableBalanceForSend(), a - p - htlcOutputFee)
        assertEquals(ac5.availableBalanceForReceive(), b + p)

        val (bc6, commit3) = bc5.sendCommit(bobKeys, logger).right!!
        assertEquals(bc6.availableBalanceForSend(), b + p)
        assertEquals(bc6.availableBalanceForReceive(), a - p - htlcOutputFee)

        val (ac6, revocation3) = ac5.receiveCommit(commit3, aliceKeys, logger).right!!
        assertEquals(ac6.availableBalanceForSend(), a - p)
        assertEquals(ac6.availableBalanceForReceive(), b + p)

        val bc7 = bc6.receiveRevocation(revocation3).right!!.first
        assertEquals(bc7.availableBalanceForSend(), b + p)
        assertEquals(bc7.availableBalanceForReceive(), a - p)

        val (ac7, commit4) = ac6.sendCommit(aliceKeys, logger).right!!
        assertEquals(ac7.availableBalanceForSend(), a - p)
        assertEquals(ac7.availableBalanceForReceive(), b + p)

        val (bc8, revocation4) = bc7.receiveCommit(commit4, bobKeys, logger).right!!
        assertEquals(bc8.availableBalanceForSend(), b + p)
        assertEquals(bc8.availableBalanceForReceive(), a - p)

        val ac8 = ac7.receiveRevocation(revocation4).right!!.first
        assertEquals(ac8.availableBalanceForSend(), a - p)
        assertEquals(ac8.availableBalanceForReceive(), b + p)
    }

    @Test
    fun `correct values for availableForSend - availableForReceive -- failure case`() {
        val (alice, bob) = reachNormal(aliceFundingAmount = 800_000.sat, bobFundingAmount = 200_000.sat)

        val aliceKeys = alice.ctx.keyManager.channelKeys(alice.commitments.params.localParams.fundingKeyPath)
        val bobKeys = bob.ctx.keyManager.channelKeys(bob.commitments.params.localParams.fundingKeyPath)

        val a = 774_660_000.msat // initial balance alice
        val b = 190_000_000.msat // initial balance bob
        val p = 42_000_000.msat // a->b payment
        val htlcOutputFee = (2 * 860_000).msat // fee due to the additional htlc output; we count it twice because we keep a reserve for a x2 feerate increase

        val ac0 = alice.state.commitments
        val bc0 = bob.state.commitments

        assertTrue(ac0.availableBalanceForSend() > p) // alice can afford the payment
        assertEquals(ac0.availableBalanceForSend(), a)
        assertEquals(ac0.availableBalanceForReceive(), b)
        assertEquals(bc0.availableBalanceForSend(), b)
        assertEquals(bc0.availableBalanceForReceive(), a)

        val currentBlockHeight = 144L
        val (_, cmdAdd) = TestsHelper.makeCmdAdd(p, bob.staticParams.nodeParams.nodeId, currentBlockHeight)
        val (ac1, add) = ac0.sendAdd(cmdAdd, UUID.randomUUID(), currentBlockHeight).right!!
        assertEquals(ac1.availableBalanceForSend(), a - p - htlcOutputFee) // as soon as htlc is sent, alice sees its balance decrease (more than the payment amount because of the commitment fees)
        assertEquals(ac1.availableBalanceForReceive(), b)

        val bc1 = bc0.receiveAdd(add).right!!
        assertEquals(bc1.availableBalanceForSend(), b)
        assertEquals(bc1.availableBalanceForReceive(), a - p - htlcOutputFee)

        val (ac2, commit1) = ac1.sendCommit(aliceKeys, logger).right!!
        assertEquals(ac2.availableBalanceForSend(), a - p - htlcOutputFee)
        assertEquals(ac2.availableBalanceForReceive(), b)

        val (bc2, revocation1) = bc1.receiveCommit(commit1, bobKeys, logger).right!!
        assertEquals(bc2.availableBalanceForSend(), b)
        assertEquals(bc2.availableBalanceForReceive(), a - p - htlcOutputFee)

        val ac3 = ac2.receiveRevocation(revocation1).right!!.first
        assertEquals(ac3.availableBalanceForSend(), a - p - htlcOutputFee)
        assertEquals(ac3.availableBalanceForReceive(), b)

        val (bc3, commit2) = bc2.sendCommit(bobKeys, logger).right!!
        assertEquals(bc3.availableBalanceForSend(), b)
        assertEquals(bc3.availableBalanceForReceive(), a - p - htlcOutputFee)

        val (ac4, revocation2) = ac3.receiveCommit(commit2, aliceKeys, logger).right!!
        assertEquals(ac4.availableBalanceForSend(), a - p - htlcOutputFee)
        assertEquals(ac4.availableBalanceForReceive(), b)

        val bc4 = bc3.receiveRevocation(revocation2).right!!.first
        assertEquals(bc4.availableBalanceForSend(), b)
        assertEquals(bc4.availableBalanceForReceive(), a - p - htlcOutputFee)

        val cmdFail = ChannelCommand.Htlc.Settlement.Fail(0, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(p, 42)))
        val (bc5, fail) = bc4.sendFail(cmdFail, bob.staticParams.nodeParams.nodePrivateKey).right!!
        assertEquals(bc5.availableBalanceForSend(), b)
        assertEquals(bc5.availableBalanceForReceive(), a - p - htlcOutputFee)

        val ac5 = ac4.receiveFail(fail).right!!.first
        assertEquals(ac5.availableBalanceForSend(), a - p - htlcOutputFee)
        assertEquals(ac5.availableBalanceForReceive(), b)

        val (bc6, commit3) = bc5.sendCommit(bobKeys, logger).right!!
        assertEquals(bc6.availableBalanceForSend(), b)
        assertEquals(bc6.availableBalanceForReceive(), a - p - htlcOutputFee)

        val (ac6, revocation3) = ac5.receiveCommit(commit3, aliceKeys, logger).right!!
        assertEquals(ac6.availableBalanceForSend(), a)
        assertEquals(ac6.availableBalanceForReceive(), b)

        val bc7 = bc6.receiveRevocation(revocation3).right!!.first
        assertEquals(bc7.availableBalanceForSend(), b)
        assertEquals(bc7.availableBalanceForReceive(), a)

        val (ac7, commit4) = ac6.sendCommit(aliceKeys, logger).right!!
        assertEquals(ac7.availableBalanceForSend(), a)
        assertEquals(ac7.availableBalanceForReceive(), b)

        val (bc8, revocation4) = bc7.receiveCommit(commit4, bobKeys, logger).right!!
        assertEquals(bc8.availableBalanceForSend(), b)
        assertEquals(bc8.availableBalanceForReceive(), a)

        val ac8 = ac7.receiveRevocation(revocation4).right!!.first
        assertEquals(ac8.availableBalanceForSend(), a)
        assertEquals(ac8.availableBalanceForReceive(), b)
    }

    @Test
    fun `correct values for availableForSend - availableForReceive -- multiple htlcs`() {
        val (alice, bob) = reachNormal(aliceFundingAmount = 800_000.sat, bobFundingAmount = 200_000.sat)

        val aliceKeys = alice.ctx.keyManager.channelKeys(alice.commitments.params.localParams.fundingKeyPath)
        val bobKeys = bob.ctx.keyManager.channelKeys(bob.commitments.params.localParams.fundingKeyPath)

        val a = 774_660_000.msat // initial balance alice
        val b = 190_000_000.msat // initial balance bob
        val p1 = 18_000_000.msat // a->b payment
        val p2 = 20_000_000.msat // a->b payment
        val p3 = 40_000_000.msat // b->a payment
        val ac0 = alice.state.commitments
        val bc0 = bob.state.commitments
        val htlcOutputFee = (2 * 860_000).msat // fee due to the additional htlc output; we count it twice because we keep a reserve for a x2 feerate increase

        assertTrue(ac0.availableBalanceForSend() > p1 + p2) // alice can afford the payment
        assertTrue(bc0.availableBalanceForSend() > p3) // alice can afford the payment
        assertEquals(ac0.availableBalanceForSend(), a)
        assertEquals(ac0.availableBalanceForReceive(), b)
        assertEquals(bc0.availableBalanceForSend(), b)
        assertEquals(bc0.availableBalanceForReceive(), a)

        val currentBlockHeight = 144L

        val (payment_preimage1, cmdAdd1) = TestsHelper.makeCmdAdd(p1, bob.staticParams.nodeParams.nodeId, currentBlockHeight)
        val (ac1, add1) = ac0.sendAdd(cmdAdd1, UUID.randomUUID(), currentBlockHeight).right!!
        assertEquals(ac1.availableBalanceForSend(), a - p1 - htlcOutputFee) // as soon as htlc is sent, alice sees its balance decrease (more than the payment amount because of the commitment fees)
        assertEquals(ac1.availableBalanceForReceive(), b)

        val (_, cmdAdd2) = TestsHelper.makeCmdAdd(p2, bob.staticParams.nodeParams.nodeId, currentBlockHeight)
        val (ac2, add2) = ac1.sendAdd(cmdAdd2, UUID.randomUUID(), currentBlockHeight).right!!
        assertEquals(ac2.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee) // as soon as htlc is sent, alice sees its balance decrease (more than the payment amount because of the commitment fees)
        assertEquals(ac2.availableBalanceForReceive(), b)

        val (payment_preimage3, cmdAdd3) = TestsHelper.makeCmdAdd(p3, alice.staticParams.nodeParams.nodeId, currentBlockHeight)
        val (bc1, add3) = bc0.sendAdd(cmdAdd3, UUID.randomUUID(), currentBlockHeight).right!!
        assertEquals(bc1.availableBalanceForSend(), b - p3) // as soon as htlc is sent, alice sees its balance decrease (more than the payment amount because of the commitment fees)
        assertEquals(bc1.availableBalanceForReceive(), a)

        val bc2 = bc1.receiveAdd(add1).right!!
        assertEquals(bc2.availableBalanceForSend(), b - p3)
        assertEquals(bc2.availableBalanceForReceive(), a - p1 - htlcOutputFee)

        val bc3 = bc2.receiveAdd(add2).right!!
        assertEquals(bc3.availableBalanceForSend(), b - p3)
        assertEquals(bc3.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee)

        val ac3 = ac2.receiveAdd(add3).right!!
        assertEquals(ac3.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee)
        assertEquals(ac3.availableBalanceForReceive(), b - p3)

        val (ac4, commit1) = ac3.sendCommit(aliceKeys, logger).right!!
        assertEquals(ac4.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee)
        assertEquals(ac4.availableBalanceForReceive(), b - p3)

        val (bc4, revocation1) = bc3.receiveCommit(commit1, bobKeys, logger).right!!
        assertEquals(bc4.availableBalanceForSend(), b - p3)
        assertEquals(bc4.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee)

        val ac5 = ac4.receiveRevocation(revocation1).right!!.first
        assertEquals(ac5.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee)
        assertEquals(ac5.availableBalanceForReceive(), b - p3)

        val (bc5, commit2) = bc4.sendCommit(bobKeys, logger).right!!
        assertEquals(bc5.availableBalanceForSend(), b - p3)
        assertEquals(bc5.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee)

        val (ac6, revocation2) = ac5.receiveCommit(commit2, aliceKeys, logger).right!!
        assertEquals(ac6.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee - htlcOutputFee) // alice has acknowledged b's hltc so it needs to pay the fee for it
        assertEquals(ac6.availableBalanceForReceive(), b - p3)

        val bc6 = bc5.receiveRevocation(revocation2).right!!.first
        assertEquals(bc6.availableBalanceForSend(), b - p3)
        assertEquals(bc6.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee - htlcOutputFee)

        val (ac7, commit3) = ac6.sendCommit(aliceKeys, logger).right!!
        assertEquals(ac7.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee - htlcOutputFee)
        assertEquals(ac7.availableBalanceForReceive(), b - p3)

        val (bc7, revocation3) = bc6.receiveCommit(commit3, bobKeys, logger).right!!
        assertEquals(bc7.availableBalanceForSend(), b - p3)
        assertEquals(bc7.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee - htlcOutputFee)

        val ac8 = ac7.receiveRevocation(revocation3).right!!.first
        assertEquals(ac8.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee - htlcOutputFee)
        assertEquals(ac8.availableBalanceForReceive(), b - p3)

        val cmdFulfill1 = ChannelCommand.Htlc.Settlement.Fulfill(0, payment_preimage1)
        val (bc8, fulfill1) = bc7.sendFulfill(cmdFulfill1).right!!
        assertEquals(bc8.availableBalanceForSend(), b + p1 - p3) // as soon as we have the fulfill, the balance increases
        assertEquals(bc8.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee - htlcOutputFee)

        val cmdFail2 = ChannelCommand.Htlc.Settlement.Fail(1, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(IncorrectOrUnknownPaymentDetails(p2, 42)))
        val (bc9, fail2) = bc8.sendFail(cmdFail2, bob.staticParams.nodeParams.nodePrivateKey).right!!
        assertEquals(bc9.availableBalanceForSend(), b + p1 - p3)
        assertEquals(bc9.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee - htlcOutputFee) // a's balance won't return to previous before she acknowledges the fail

        val cmdFulfill3 = ChannelCommand.Htlc.Settlement.Fulfill(0, payment_preimage3)
        val (ac9, fulfill3) = ac8.sendFulfill(cmdFulfill3).right!!
        assertEquals(ac9.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee + p3)
        assertEquals(ac9.availableBalanceForReceive(), b - p3)

        val ac10 = ac9.receiveFulfill(fulfill1).right!!.first
        assertEquals(ac10.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee + p3)
        assertEquals(ac10.availableBalanceForReceive(), b + p1 - p3)

        val ac11 = ac10.receiveFail(fail2).right!!.first
        assertEquals(ac11.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee + p3)
        assertEquals(ac11.availableBalanceForReceive(), b + p1 - p3)

        val bc10 = bc9.receiveFulfill(fulfill3).right!!.first
        assertEquals(bc10.availableBalanceForSend(), b + p1 - p3)
        assertEquals(bc10.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee + p3) // the fee for p3 disappears

        val (ac12, commit4) = ac11.sendCommit(aliceKeys, logger).right!!
        assertEquals(ac12.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee + p3)
        assertEquals(ac12.availableBalanceForReceive(), b + p1 - p3)

        val (bc11, revocation4) = bc10.receiveCommit(commit4, bobKeys, logger).right!!
        assertEquals(bc11.availableBalanceForSend(), b + p1 - p3)
        assertEquals(bc11.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee + p3)

        val ac13 = ac12.receiveRevocation(revocation4).right!!.first
        assertEquals(ac13.availableBalanceForSend(), a - p1 - htlcOutputFee - p2 - htlcOutputFee + p3)
        assertEquals(ac13.availableBalanceForReceive(), b + p1 - p3)

        val (bc12, commit5) = bc11.sendCommit(bobKeys, logger).right!!
        assertEquals(bc12.availableBalanceForSend(), b + p1 - p3)
        assertEquals(bc12.availableBalanceForReceive(), a - p1 - htlcOutputFee - p2 - htlcOutputFee + p3)

        val (ac14, revocation5) = ac13.receiveCommit(commit5, aliceKeys, logger).right!!
        assertEquals(ac14.availableBalanceForSend(), a - p1 + p3)
        assertEquals(ac14.availableBalanceForReceive(), b + p1 - p3)

        val bc13 = bc12.receiveRevocation(revocation5).right!!.first
        assertEquals(bc13.availableBalanceForSend(), b + p1 - p3)
        assertEquals(bc13.availableBalanceForReceive(), a - p1 + p3)

        val (ac15, commit6) = ac14.sendCommit(aliceKeys, logger).right!!
        assertEquals(ac15.availableBalanceForSend(), a - p1 + p3)
        assertEquals(ac15.availableBalanceForReceive(), b + p1 - p3)

        val (bc14, revocation6) = bc13.receiveCommit(commit6, bobKeys, logger).right!!
        assertEquals(bc14.availableBalanceForSend(), b + p1 - p3)
        assertEquals(bc14.availableBalanceForReceive(), a - p1 + p3)

        val ac16 = ac15.receiveRevocation(revocation6).right!!.first
        assertEquals(ac16.availableBalanceForSend(), a - p1 + p3)
        assertEquals(ac16.availableBalanceForReceive(), b + p1 - p3)
    }

    // See https://github.com/lightningnetwork/lightning-rfc/issues/728
    @Test
    fun `initiator keeps additional reserve to avoid channel being stuck`() {
        val isInitiator = true
        val currentBlockHeight = 144L
        val c = makeCommitments(100000000.msat, 50000000.msat, FeeratePerKw(2500.sat), 546.sat, isInitiator)
        val (_, cmdAdd) = TestsHelper.makeCmdAdd(c.availableBalanceForSend(), randomKey().publicKey(), currentBlockHeight)
        val (c1, _) = c.sendAdd(cmdAdd, UUID.randomUUID(), currentBlockHeight).right!!
        assertEquals(c1.availableBalanceForSend(), 0.msat)

        // We should be able to handle a fee increase.
        val (c2, _) = c1.sendFee(ChannelCommand.Commitment.UpdateFee(FeeratePerKw(3000.sat))).right!!

        // Now we shouldn't be able to send until we receive enough to handle the updated commit tx fee (even trimmed HTLCs shouldn't be sent).
        val (_, cmdAdd1) = TestsHelper.makeCmdAdd(100.msat, randomKey().publicKey(), currentBlockHeight)
        val e = c2.sendAdd(cmdAdd1, UUID.randomUUID(), currentBlockHeight).left
        assertIs<InsufficientFunds>(e)
    }

    @Test
    fun `can send availableForSend`() {
        val currentBlockHeight = 144L
        listOf(true, false).forEach {
            val c = makeCommitments(702000000.msat, 52000000.msat, FeeratePerKw(2679.sat), 546.sat, it)
            val (_, cmdAdd) = TestsHelper.makeCmdAdd(c.availableBalanceForSend(), randomKey().publicKey(), currentBlockHeight)
            val result = c.sendAdd(cmdAdd, UUID.randomUUID(), currentBlockHeight)
            assertTrue(result.isRight)
        }
    }

    @Test
    fun `can receive availableForReceive`() {
        val currentBlockHeight = 144L
        listOf(true, false).forEach {
            val c = makeCommitments(31000000.msat, 702000000.msat, FeeratePerKw(2679.sat), 546.sat, it)
            val add = UpdateAddHtlc(
                randomBytes32(), c.changes.remoteNextHtlcId, c.availableBalanceForReceive(), randomBytes32(), CltvExpiry(currentBlockHeight), TestConstants.emptyOnionPacket
            )
            val result = c.receiveAdd(add)
            assertTrue(result.isRight)
        }
    }

    @Test
    fun `find timed out htlcs`() {
        val (alice, bob, timedOutHtlcs) = run {
            val (alice0, bob0) = reachNormal()
            // We have two identical HTLCs (MPP):
            val (nodes1, _, htlcAlice1a) = TestsHelper.addHtlc(50_000_000.msat, payer = alice0, payee = bob0)
            val (alice1, bob1) = nodes1
            val cmdAddAlice = ChannelCommand.Htlc.Add(htlcAlice1a.amountMsat, htlcAlice1a.paymentHash, htlcAlice1a.cltvExpiry, htlcAlice1a.onionRoutingPacket, UUID.randomUUID())
            val (alice2, bob2, htlcAlice1b) = TestsHelper.addHtlc(cmdAddAlice, alice1, bob1)
            val (nodes3, preimageAlice2, htlcAlice2) = TestsHelper.addHtlc(60_000_000.msat, payer = alice2, payee = bob2)
            val (alice3, bob3) = nodes3
            val (alice4, bob4) = TestsHelper.crossSign(alice3, bob3)
            // We have two identical HTLCs (MPP):
            val (nodes5, _, htlcBob1a) = TestsHelper.addHtlc(15_000_000.msat, payer = bob4, payee = alice4)
            val (bob5, alice5) = nodes5
            val cmdAddBob = ChannelCommand.Htlc.Add(htlcBob1a.amountMsat, htlcBob1a.paymentHash, htlcBob1a.cltvExpiry, htlcBob1a.onionRoutingPacket, UUID.randomUUID())
            val (bob6, alice6, htlcBob1b) = TestsHelper.addHtlc(cmdAddBob, bob5, alice5)
            val (nodes7, preimageBob2, htlcBob2) = TestsHelper.addHtlc(20_000_000.msat, payer = bob6, payee = alice6)
            val (bob7, alice7) = nodes7
            val (bob8, alice8) = TestsHelper.crossSign(bob7, alice7)
            // Alice and Bob both know the preimage for only one of the two HTLCs they received.
            val (alice9, _) = alice8.process(ChannelCommand.Htlc.Settlement.Fulfill(htlcBob2.id, preimageBob2))
            val (bob9, _) = bob8.process(ChannelCommand.Htlc.Settlement.Fulfill(htlcAlice2.id, preimageAlice2))
            // Alice publishes her commitment.
            val (aliceClosing, _) = alice9.process(ChannelCommand.Close.ForceClose)
            assertIs<LNChannel<Closing>>(aliceClosing)
            val lcp = aliceClosing.state.localCommitPublished
            assertNotNull(lcp)
            val (bobClosing, _) = bob9.process(ChannelCommand.WatchReceived(WatchEventSpent(alice0.state.channelId, BITCOIN_FUNDING_SPENT, lcp.commitTx)))
            assertIs<LNChannel<Closing>>(bobClosing)
            val rcp = bobClosing.state.remoteCommitPublished
            assertNotNull(rcp)
            Triple(aliceClosing, bobClosing, listOf(htlcAlice1a, htlcAlice1b, htlcAlice2, htlcBob1a, htlcBob1b, htlcBob2))
        }

        val lcp = alice.state.localCommitPublished!!
        val localCommit = alice.state.commitments.latest.localCommit
        val rcp = bob.state.remoteCommitPublished!!
        val remoteCommit = bob.state.commitments.latest.remoteCommit
        val dustLimit = TestConstants.Alice.nodeParams.dustLimit
        val htlcTimeoutTxs = lcp.htlcTimeoutTxs()
        val htlcSuccessTxs = lcp.htlcSuccessTxs()
        val claimHtlcTimeoutTxs = rcp.claimHtlcTimeoutTxs()
        val claimHtlcSuccessTxs = rcp.claimHtlcSuccessTxs()

        val aliceTimedOutHtlcs = htlcTimeoutTxs.map { htlcTimeout ->
            val htlcs = timedOutHtlcs(localCommit, lcp, dustLimit, htlcTimeout.tx)
            assertEquals(1, htlcs.size)
            htlcs.first()
        }
        assertEquals(timedOutHtlcs.take(3).toSet(), aliceTimedOutHtlcs.toSet())

        val bobTimedOutHtlcs = claimHtlcTimeoutTxs.map { claimHtlcTimeout ->
            val htlcs = timedOutHtlcs(remoteCommit, rcp, dustLimit, claimHtlcTimeout.tx)
            assertEquals(1, htlcs.size)
            htlcs.first()
        }
        assertEquals(timedOutHtlcs.drop(3).toSet(), bobTimedOutHtlcs.toSet())

        htlcSuccessTxs.forEach { htlcSuccess -> assertTrue(timedOutHtlcs(localCommit, lcp, dustLimit, htlcSuccess.tx).isEmpty()) }
        htlcSuccessTxs.forEach { htlcSuccess -> assertTrue(timedOutHtlcs(remoteCommit, rcp, dustLimit, htlcSuccess.tx).isEmpty()) }
        claimHtlcSuccessTxs.forEach { claimHtlcSuccess -> assertTrue(timedOutHtlcs(localCommit, lcp, dustLimit, claimHtlcSuccess.tx).isEmpty()) }
        claimHtlcSuccessTxs.forEach { claimHtlcSuccess -> assertTrue(timedOutHtlcs(remoteCommit, rcp, dustLimit, claimHtlcSuccess.tx).isEmpty()) }
        htlcTimeoutTxs.forEach { htlcTimeout -> assertTrue(timedOutHtlcs(remoteCommit, rcp, dustLimit, htlcTimeout.tx).isEmpty()) }
        claimHtlcTimeoutTxs.forEach { claimHtlcTimeout -> assertTrue(timedOutHtlcs(localCommit, lcp, dustLimit, claimHtlcTimeout.tx).isEmpty()) }
    }

    companion object {
        fun makeCommitments(toLocal: MilliSatoshi, toRemote: MilliSatoshi, feeRatePerKw: FeeratePerKw = FeeratePerKw(0.sat), dustLimit: Satoshi = 0.sat, isInitiator: Boolean = true): Commitments {
            val localParams = LocalParams(
                randomKey().publicKey(), KeyPath("42"), dustLimit, Long.MAX_VALUE, 1.msat, CltvExpiryDelta(144), 50, isInitiator, isInitiator, ByteVector.empty, Features.empty
            )
            val remoteParams = RemoteParams(
                randomKey().publicKey(), dustLimit, Long.MAX_VALUE, 1.msat, CltvExpiryDelta(144), 50,
                randomKey().publicKey(), randomKey().publicKey(), randomKey().publicKey(), randomKey().publicKey(),
                Features.empty
            )
            val fundingAmount = (toLocal + toRemote).truncateToSatoshi()
            val dummyFundingScript = Scripts.multiSig2of2(randomKey().publicKey(), randomKey().publicKey())
            val dummyFundingTx = Transaction(2, listOf(TxIn(OutPoint(TxId(randomBytes32()), 1), 0)), listOf(TxOut(fundingAmount, Script.pay2wsh(dummyFundingScript))), 0)
            val commitmentInput = Transactions.InputInfo.SegwitInput(OutPoint(dummyFundingTx, 0), dummyFundingTx.txOut[0], dummyFundingScript)
            val localCommitTx = Transactions.TransactionWithInputInfo.CommitTx(commitmentInput, Transaction(2, listOf(), listOf(), 0))
            return Commitments(
                ChannelParams(
                    channelId = randomBytes32(),
                    channelConfig = ChannelConfig.standard,
                    channelFeatures = ChannelFeatures(ChannelType.SupportedChannelType.AnchorOutputs.features),
                    localParams = localParams,
                    remoteParams = remoteParams,
                    channelFlags = ChannelFlags(announceChannel = false, nonInitiatorPaysCommitFees = false),
                ),
                CommitmentChanges(
                    LocalChanges(listOf(), listOf(), listOf()),
                    RemoteChanges(listOf(), listOf(), listOf()),
                    localNextHtlcId = 1,
                    remoteNextHtlcId = 1,
                ),
                active = listOf(
                    Commitment(
                        fundingTxIndex = 0,
                        remoteFundingPubkey = randomKey().publicKey(),
                        LocalFundingStatus.ConfirmedFundingTx(dummyFundingTx, 500.sat, TxSignatures(randomBytes32(), TxId(randomBytes32()), listOf())),
                        RemoteFundingStatus.Locked,
                        LocalCommit(0, CommitmentSpec(setOf(), feeRatePerKw, toLocal, toRemote), PublishableTxs(localCommitTx, listOf())),
                        RemoteCommit(0, CommitmentSpec(setOf(), feeRatePerKw, toRemote, toLocal), TxId(randomBytes32()), randomKey().publicKey()),
                        nextRemoteCommit = null,
                    )
                ),
                inactive = emptyList(),
                payments = mapOf(),
                remoteNextCommitInfo = Either.Right(randomKey().publicKey()),
                remotePerCommitmentSecrets = ShaChain.init,
            )
        }
    }
}