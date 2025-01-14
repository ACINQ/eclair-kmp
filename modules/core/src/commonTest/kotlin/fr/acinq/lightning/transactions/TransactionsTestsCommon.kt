package fr.acinq.lightning.transactions

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.Crypto.ripemd160
import fr.acinq.bitcoin.Crypto.sha256
import fr.acinq.bitcoin.Script.pay2wpkh
import fr.acinq.bitcoin.Script.pay2wsh
import fr.acinq.bitcoin.Script.write
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.bitcoin.crypto.musig2.Musig2
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.Commitments
import fr.acinq.lightning.channel.Helpers.Funding
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.transactions.CommitmentOutput.OutHtlc
import fr.acinq.lightning.transactions.Scripts.htlcOffered
import fr.acinq.lightning.transactions.Scripts.htlcReceived
import fr.acinq.lightning.transactions.Scripts.toLocalDelayed
import fr.acinq.lightning.transactions.Transactions.PlaceHolderSig
import fr.acinq.lightning.transactions.Transactions.TxGenerationSkipped.AmountBelowDustLimit
import fr.acinq.lightning.transactions.Transactions.TxGenerationSkipped.OutputNotFound
import fr.acinq.lightning.transactions.Transactions.TxResult.Skipped
import fr.acinq.lightning.transactions.Transactions.TxResult.Success
import fr.acinq.lightning.transactions.Transactions.addSigs
import fr.acinq.lightning.transactions.Transactions.checkSig
import fr.acinq.lightning.transactions.Transactions.checkSpendable
import fr.acinq.lightning.transactions.Transactions.claimHtlcDelayedWeight
import fr.acinq.lightning.transactions.Transactions.claimHtlcSuccessWeight
import fr.acinq.lightning.transactions.Transactions.claimHtlcTimeoutWeight
import fr.acinq.lightning.transactions.Transactions.commitTxFee
import fr.acinq.lightning.transactions.Transactions.decodeTxNumber
import fr.acinq.lightning.transactions.Transactions.encodeTxNumber
import fr.acinq.lightning.transactions.Transactions.getCommitTxNumber
import fr.acinq.lightning.transactions.Transactions.htlcPenaltyWeight
import fr.acinq.lightning.transactions.Transactions.mainPenaltyWeight
import fr.acinq.lightning.transactions.Transactions.makeClaimDelayedOutputPenaltyTxs
import fr.acinq.lightning.transactions.Transactions.makeClaimHtlcSuccessTx
import fr.acinq.lightning.transactions.Transactions.makeClaimHtlcTimeoutTx
import fr.acinq.lightning.transactions.Transactions.makeClaimLocalDelayedOutputTx
import fr.acinq.lightning.transactions.Transactions.makeClaimRemoteDelayedOutputTx
import fr.acinq.lightning.transactions.Transactions.makeClosingTxs
import fr.acinq.lightning.transactions.Transactions.makeCommitTx
import fr.acinq.lightning.transactions.Transactions.makeCommitTxOutputs
import fr.acinq.lightning.transactions.Transactions.makeHtlcPenaltyTx
import fr.acinq.lightning.transactions.Transactions.makeHtlcTxs
import fr.acinq.lightning.transactions.Transactions.makeMainPenaltyTx
import fr.acinq.lightning.transactions.Transactions.sign
import fr.acinq.lightning.transactions.Transactions.swapInputWeight
import fr.acinq.lightning.transactions.Transactions.swapInputWeightLegacy
import fr.acinq.lightning.transactions.Transactions.weight2fee
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.UpdateAddHtlc
import kotlin.random.Random
import kotlin.test.*

class TransactionsTestsCommon : LightningTestSuite() {

    private val localFundingPriv = PrivateKey(randomBytes32())
    private val remoteFundingPriv = PrivateKey(randomBytes32())
    private val localRevocationPriv = PrivateKey(randomBytes32())
    private val localPaymentPriv = PrivateKey(randomBytes32())
    private val localDelayedPaymentPriv = PrivateKey(randomBytes32())
    private val remotePaymentPriv = PrivateKey(randomBytes32())
    private val localHtlcPriv = PrivateKey(randomBytes32())
    private val remoteHtlcPriv = PrivateKey(randomBytes32())
    private val commitInput = Funding.makeFundingInputInfo(TxId(randomBytes32()), 0, 1.btc, localFundingPriv.publicKey(), remoteFundingPriv.publicKey())
    private val toLocalDelay = CltvExpiryDelta(144)
    private val localDustLimit = 546.sat
    private val feerate = FeeratePerKw(22_000.sat)

    @Test
    fun `encode and decode sequence and lockTime -- one example`() {
        val txNumber = 0x11F71FB268DL

        val (sequence, lockTime) = encodeTxNumber(txNumber)
        assertEquals(0x80011F71L, sequence)
        assertEquals(0x20FB268DL, lockTime)

        val txNumber1 = decodeTxNumber(sequence, lockTime)
        assertEquals(txNumber, txNumber1)
    }

    @Test
    fun `reconstruct txNumber from sequence and lockTime`() {
        repeat(1_000) {
            val txNumber = Random.nextLong() and 0xffffffffffffL
            val (sequence, lockTime) = encodeTxNumber(txNumber)
            val txNumber1 = decodeTxNumber(sequence, lockTime)
            assertEquals(txNumber, txNumber1)
        }
    }

    @Test
    fun `compute fees`() {
        // see BOLT #3 specs
        val htlcs = setOf(
            OutgoingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, 5000000.msat, ByteVector32.Zeroes, CltvExpiry(552), TestConstants.emptyOnionPacket)),
            OutgoingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, 1000000.msat, ByteVector32.Zeroes, CltvExpiry(553), TestConstants.emptyOnionPacket)),
            IncomingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, 7000000.msat, ByteVector32.Zeroes, CltvExpiry(550), TestConstants.emptyOnionPacket)),
            IncomingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, 800000.msat, ByteVector32.Zeroes, CltvExpiry(551), TestConstants.emptyOnionPacket))
        )
        val spec = CommitmentSpec(htlcs, feerate = FeeratePerKw(5_000.sat), toLocal = 0.msat, toRemote = 0.msat)
        val fee = commitTxFee(546.sat, spec)
        assertEquals(8000.sat, fee)
    }

    @Test
    fun `check pre-computed transaction weights`() {
        val finalPubKeyScript = write(pay2wpkh(PrivateKey(randomBytes32()).publicKey()))
        val localDustLimit = 546.sat
        val toLocalDelay = CltvExpiryDelta(144)
        val feeratePerKw = FeeratePerKw.MinimumFeeratePerKw
        val blockHeight = 400_000

        run {
            // ClaimHtlcDelayedTx
            // first we create a fake htlcSuccessOrTimeoutTx tx, containing only the output that will be spent by the ClaimDelayedOutputTx
            val pubKeyScript = write(pay2wsh(toLocalDelayed(localRevocationPriv.publicKey(), toLocalDelay, localPaymentPriv.publicKey())))
            val htlcSuccessOrTimeoutTx = Transaction(version = 0, txIn = listOf(TxIn(OutPoint(TxId(ByteVector32.Zeroes), 0), TxIn.SEQUENCE_FINAL)), txOut = listOf(TxOut(20000.sat, pubKeyScript)), lockTime = 0)
            val claimHtlcDelayedTx = makeClaimLocalDelayedOutputTx(htlcSuccessOrTimeoutTx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localPaymentPriv.publicKey(), finalPubKeyScript, feeratePerKw)
            assertTrue(claimHtlcDelayedTx is Success, "is $claimHtlcDelayedTx")
            // we use dummy signatures to compute the weight
            val weight = Transaction.weight(addSigs(claimHtlcDelayedTx.result, PlaceHolderSig).tx)
            assertEquals(claimHtlcDelayedWeight, weight)
            assertTrue(claimHtlcDelayedTx.result.fee >= claimHtlcDelayedTx.result.minRelayFee)
        }
        run {
            // MainPenaltyTx
            // first we create a fake commitTx tx, containing only the output that will be spent by the MainPenaltyTx
            val pubKeyScript = write(pay2wsh(toLocalDelayed(localRevocationPriv.publicKey(), toLocalDelay, localPaymentPriv.publicKey())))
            val commitTx = Transaction(version = 0, txIn = listOf(TxIn(OutPoint(TxId(ByteVector32.Zeroes), 0), TxIn.SEQUENCE_FINAL)), txOut = listOf(TxOut(20000.sat, pubKeyScript)), lockTime = 0)
            val mainPenaltyTx = makeMainPenaltyTx(commitTx, localDustLimit, localRevocationPriv.publicKey(), finalPubKeyScript, toLocalDelay, localPaymentPriv.publicKey(), feeratePerKw)
            assertTrue(mainPenaltyTx is Success, "is $mainPenaltyTx")
            // we use dummy signatures to compute the weight
            val weight = Transaction.weight(addSigs(mainPenaltyTx.result, PlaceHolderSig).tx)
            assertEquals(mainPenaltyWeight, weight)
            assertTrue(mainPenaltyTx.result.fee >= mainPenaltyTx.result.minRelayFee)
        }
        run {
            // HtlcPenaltyTx
            // first we create a fake commitTx tx, containing only the output that will be spent by the ClaimHtlcSuccessTx
            val paymentPreimage = randomBytes32()
            val htlc = UpdateAddHtlc(ByteVector32.Zeroes, 0, (20000 * 1000).msat, ByteVector32(sha256(paymentPreimage)), CltvExpiryDelta(144).toCltvExpiry(blockHeight.toLong()), TestConstants.emptyOnionPacket)
            val redeemScript = htlcReceived(localHtlcPriv.publicKey(), remoteHtlcPriv.publicKey(), localRevocationPriv.publicKey(), ripemd160(htlc.paymentHash), htlc.cltvExpiry)
            val pubKeyScript = write(pay2wsh(redeemScript))
            val commitTx = Transaction(version = 0, txIn = listOf(TxIn(OutPoint(TxId(ByteVector32.Zeroes), 0), TxIn.SEQUENCE_FINAL)), txOut = listOf(TxOut(htlc.amountMsat.truncateToSatoshi(), pubKeyScript)), lockTime = 0)
            val htlcPenaltyTx = makeHtlcPenaltyTx(commitTx, 0, write(redeemScript), localDustLimit, finalPubKeyScript, feeratePerKw)
            assertTrue(htlcPenaltyTx is Success, "is $htlcPenaltyTx")
            // we use dummy signatures to compute the weight
            val weight = Transaction.weight(addSigs(htlcPenaltyTx.result, PlaceHolderSig, localRevocationPriv.publicKey()).tx)
            assertEquals(htlcPenaltyWeight, weight)
            assertTrue(htlcPenaltyTx.result.fee >= htlcPenaltyTx.result.minRelayFee)
        }
        run {
            // ClaimHtlcSuccessTx
            // first we create a fake commitTx tx, containing only the output that will be spent by the ClaimHtlcSuccessTx
            val paymentPreimage = randomBytes32()
            val htlc = UpdateAddHtlc(ByteVector32.Zeroes, 0, (20000 * 1000).msat, ByteVector32(sha256(paymentPreimage)), CltvExpiryDelta(144).toCltvExpiry(blockHeight.toLong()), TestConstants.emptyOnionPacket)
            val spec = CommitmentSpec(setOf(OutgoingHtlc(htlc)), feeratePerKw, toLocal = 0.msat, toRemote = 0.msat)
            val outputs =
                makeCommitTxOutputs(
                    localFundingPriv.publicKey(),
                    remoteFundingPriv.publicKey(),
                    true,
                    localDustLimit,
                    localRevocationPriv.publicKey(),
                    toLocalDelay,
                    localDelayedPaymentPriv.publicKey(),
                    remotePaymentPriv.publicKey(),
                    localHtlcPriv.publicKey(),
                    remoteHtlcPriv.publicKey(),
                    spec
                )
            val commitTx = Transaction(version = 0, txIn = listOf(TxIn(OutPoint(TxId(ByteVector32.Zeroes), 0), TxIn.SEQUENCE_FINAL)), txOut = outputs.map { it.output }, lockTime = 0)
            val claimHtlcSuccessTx =
                makeClaimHtlcSuccessTx(commitTx, outputs, localDustLimit, remoteHtlcPriv.publicKey(), localHtlcPriv.publicKey(), localRevocationPriv.publicKey(), finalPubKeyScript, htlc, feeratePerKw)
            assertTrue(claimHtlcSuccessTx is Success, "is $claimHtlcSuccessTx")
            // we use dummy signatures to compute the weight
            val weight = Transaction.weight(addSigs(claimHtlcSuccessTx.result, PlaceHolderSig, paymentPreimage).tx)
            assertEquals(claimHtlcSuccessWeight, weight)
            assertTrue(claimHtlcSuccessTx.result.fee >= claimHtlcSuccessTx.result.minRelayFee)
        }
        run {
            // ClaimHtlcTimeoutTx
            // first we create a fake commitTx tx, containing only the output that will be spent by the ClaimHtlcTimeoutTx
            val paymentPreimage = randomBytes32()
            val htlc = UpdateAddHtlc(ByteVector32.Zeroes, 0, (20000 * 1000).msat, ByteVector32(sha256(paymentPreimage)), toLocalDelay.toCltvExpiry(blockHeight.toLong()), TestConstants.emptyOnionPacket)
            val spec = CommitmentSpec(setOf(IncomingHtlc(htlc)), feeratePerKw, toLocal = 0.msat, toRemote = 0.msat)
            val outputs =
                makeCommitTxOutputs(
                    localFundingPriv.publicKey(),
                    remoteFundingPriv.publicKey(),
                    true,
                    localDustLimit,
                    localRevocationPriv.publicKey(),
                    toLocalDelay,
                    localDelayedPaymentPriv.publicKey(),
                    remotePaymentPriv.publicKey(),
                    localHtlcPriv.publicKey(),
                    remoteHtlcPriv.publicKey(),
                    spec
                )
            val commitTx = Transaction(version = 0, txIn = listOf(TxIn(OutPoint(TxId(ByteVector32.Zeroes), 0), TxIn.SEQUENCE_FINAL)), txOut = outputs.map { it.output }, lockTime = 0)
            val claimHtlcTimeoutTx =
                makeClaimHtlcTimeoutTx(commitTx, outputs, localDustLimit, remoteHtlcPriv.publicKey(), localHtlcPriv.publicKey(), localRevocationPriv.publicKey(), finalPubKeyScript, htlc, feeratePerKw)
            assertTrue(claimHtlcTimeoutTx is Success, "is $claimHtlcTimeoutTx")
            // we use dummy signatures to compute the weight
            val weight = Transaction.weight(addSigs(claimHtlcTimeoutTx.result, PlaceHolderSig).tx)
            assertEquals(claimHtlcTimeoutWeight, weight)
            assertTrue(claimHtlcTimeoutTx.result.fee >= claimHtlcTimeoutTx.result.minRelayFee)
        }
    }

    @Test
    fun `generate valid commitment and htlc transactions`() {
        val finalPubKeyScript = write(pay2wpkh(PrivateKey(ByteVector32("01".repeat(32))).publicKey()))
        val commitInput = Funding.makeFundingInputInfo(TxId(ByteVector32("02".repeat(32))), 0, 1.btc, localFundingPriv.publicKey(), remoteFundingPriv.publicKey())

        // htlc1 and htlc2 are regular IN/OUT htlcs
        val paymentPreimage1 = ByteVector32("03".repeat(32))
        val htlc1 = UpdateAddHtlc(ByteVector32.Zeroes, 0, 100.mbtc.toMilliSatoshi(), ByteVector32(sha256(paymentPreimage1)), CltvExpiry(300), TestConstants.emptyOnionPacket)
        val paymentPreimage2 = ByteVector32("04".repeat(32))
        val htlc2 = UpdateAddHtlc(ByteVector32.Zeroes, 1, 200.mbtc.toMilliSatoshi(), ByteVector32(sha256(paymentPreimage2)), CltvExpiry(300), TestConstants.emptyOnionPacket)
        // htlc3 and htlc4 are dust htlcs IN/OUT htlcs, with an amount large enough to be included in the commit tx, but too small to be claimed at 2nd stage
        val paymentPreimage3 = ByteVector32("05".repeat(32))
        val htlc3 = UpdateAddHtlc(
            ByteVector32.Zeroes,
            2,
            (localDustLimit + weight2fee(feerate, Commitments.HTLC_TIMEOUT_WEIGHT)).toMilliSatoshi(),
            ByteVector32(sha256(paymentPreimage3)),
            CltvExpiry(300),
            TestConstants.emptyOnionPacket
        )
        val paymentPreimage4 = ByteVector32("06".repeat(32))
        val htlc4 = UpdateAddHtlc(
            ByteVector32.Zeroes,
            3,
            (localDustLimit + weight2fee(feerate, Commitments.HTLC_SUCCESS_WEIGHT)).toMilliSatoshi(),
            ByteVector32(sha256(paymentPreimage4)),
            CltvExpiry(300),
            TestConstants.emptyOnionPacket
        )
        val spec = CommitmentSpec(
            htlcs = setOf(
                OutgoingHtlc(htlc1),
                IncomingHtlc(htlc2),
                OutgoingHtlc(htlc3),
                IncomingHtlc(htlc4)
            ),
            feerate = feerate,
            toLocal = 400.mbtc.toMilliSatoshi(),
            toRemote = 300.mbtc.toMilliSatoshi()
        )

        val outputs = makeCommitTxOutputs(
            localFundingPriv.publicKey(),
            remoteFundingPriv.publicKey(),
            true,
            localDustLimit,
            localRevocationPriv.publicKey(),
            toLocalDelay,
            localDelayedPaymentPriv.publicKey(),
            remotePaymentPriv.publicKey(),
            localHtlcPriv.publicKey(),
            remoteHtlcPriv.publicKey(),
            spec
        )

        val commitTxNumber = 0x404142434445L
        val commitTx = run {
            val txInfo = makeCommitTx(commitInput, commitTxNumber, localPaymentPriv.publicKey(), remotePaymentPriv.publicKey(), true, outputs)
            val localSig = sign(txInfo, localPaymentPriv)
            val remoteSig = sign(txInfo, remotePaymentPriv)
            addSigs(txInfo, localFundingPriv.publicKey(), remoteFundingPriv.publicKey(), localSig, remoteSig)
        }

        run {
            assertEquals(commitTxNumber, getCommitTxNumber(commitTx.tx, true, localPaymentPriv.publicKey(), remotePaymentPriv.publicKey()))
            val hash = sha256(localPaymentPriv.publicKey().value + remotePaymentPriv.publicKey().value)
            val num = Pack.int64BE(hash.takeLast(8).toByteArray()) and 0xffffffffffffL
            val check = ((commitTx.tx.txIn.first().sequence and 0xffffffL) shl 24) or (commitTx.tx.lockTime and 0xffffffL)
            assertEquals(commitTxNumber, check xor num)
        }
        val htlcTxs = makeHtlcTxs(commitTx.tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), spec.feerate, outputs)
        assertEquals(4, htlcTxs.size)
        val htlcSuccessTxs = htlcTxs.filterIsInstance<Transactions.TransactionWithInputInfo.HtlcTx.HtlcSuccessTx>()
        assertEquals(2, htlcSuccessTxs.size) // htlc2 and htlc4
        assertEquals(setOf(1L, 3L), htlcSuccessTxs.map { it.htlcId }.toSet())
        val htlcTimeoutTxs = htlcTxs.filterIsInstance<Transactions.TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx>()
        assertEquals(2, htlcTimeoutTxs.size) // htlc1 and htlc3
        assertEquals(setOf(0L, 2L), htlcTimeoutTxs.map { it.htlcId }.toSet())

        run {
            // either party spends local->remote htlc output with htlc timeout tx
            for (htlcTimeoutTx in htlcTimeoutTxs) {
                val localSig = sign(htlcTimeoutTx, localHtlcPriv)
                val remoteSig = sign(htlcTimeoutTx, remoteHtlcPriv, SigHash.SIGHASH_SINGLE or SigHash.SIGHASH_ANYONECANPAY)
                val signed = addSigs(htlcTimeoutTx, localSig, remoteSig)
                val csResult = checkSpendable(signed)
                assertTrue(csResult.isSuccess, "is $csResult")
            }
        }
        run {
            // local spends delayed output of htlc1 timeout tx
            val claimHtlcDelayed = makeClaimLocalDelayedOutputTx(htlcTimeoutTxs[1].tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), finalPubKeyScript, feerate)
            assertTrue(claimHtlcDelayed is Success, "is $claimHtlcDelayed")
            val localSig = sign(claimHtlcDelayed.result, localDelayedPaymentPriv)
            val signedTx = addSigs(claimHtlcDelayed.result, localSig)
            assertTrue(checkSpendable(signedTx).isSuccess)
            // local can't claim delayed output of htlc3 timeout tx because it is below the dust limit
            val claimHtlcDelayed1 = makeClaimLocalDelayedOutputTx(htlcTimeoutTxs[0].tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localPaymentPriv.publicKey(), finalPubKeyScript, feerate)
            assertEquals(Skipped(OutputNotFound), claimHtlcDelayed1)
        }
        run {
            // remote spends local->remote htlc1/htlc3 output directly in case of success
            for ((htlc, paymentPreimage) in listOf(htlc1 to paymentPreimage1, htlc3 to paymentPreimage3)) {
                val claimHtlcSuccessTx =
                    makeClaimHtlcSuccessTx(commitTx.tx, outputs, localDustLimit, remoteHtlcPriv.publicKey(), localHtlcPriv.publicKey(), localRevocationPriv.publicKey(), finalPubKeyScript, htlc, feerate)
                assertTrue(claimHtlcSuccessTx is Success, "is $claimHtlcSuccessTx")
                val localSig = sign(claimHtlcSuccessTx.result, remoteHtlcPriv)
                val signed = addSigs(claimHtlcSuccessTx.result, localSig, paymentPreimage)
                val csResult = checkSpendable(signed)
                assertTrue(csResult.isSuccess, "is $csResult")
            }
        }
        run {
            // local spends remote->local htlc2/htlc4 output with htlc success tx using payment preimage
            for ((htlcSuccessTx, paymentPreimage) in listOf(htlcSuccessTxs[1] to paymentPreimage2, htlcSuccessTxs[0] to paymentPreimage4)) {
                val localSig = sign(htlcSuccessTx, localHtlcPriv)
                val remoteSig = sign(htlcSuccessTx, remoteHtlcPriv, SigHash.SIGHASH_SINGLE or SigHash.SIGHASH_ANYONECANPAY)
                val signedTx = addSigs(htlcSuccessTx, localSig, remoteSig, paymentPreimage)
                val csResult = checkSpendable(signedTx)
                assertTrue(csResult.isSuccess, "is $csResult")
                // check remote sig
                assertTrue(checkSig(htlcSuccessTx, remoteSig, remoteHtlcPriv.publicKey(), SigHash.SIGHASH_SINGLE or SigHash.SIGHASH_ANYONECANPAY))
            }
        }
        run {
            // local spends delayed output of htlc2 success tx
            val claimHtlcDelayed = makeClaimLocalDelayedOutputTx(htlcSuccessTxs[1].tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), finalPubKeyScript, feerate)
            assertTrue(claimHtlcDelayed is Success, "is $claimHtlcDelayed")
            val localSig = sign(claimHtlcDelayed.result, localDelayedPaymentPriv)
            val signedTx = addSigs(claimHtlcDelayed.result, localSig)
            val csResult = checkSpendable(signedTx)
            assertTrue(csResult.isSuccess, "is $csResult")
            // local can't claim delayed output of htlc4 timeout tx because it is below the dust limit
            val claimHtlcDelayed1 = makeClaimLocalDelayedOutputTx(htlcSuccessTxs[0].tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), finalPubKeyScript, feerate)
            assertEquals(Skipped(AmountBelowDustLimit), claimHtlcDelayed1)
        }
        run {
            // remote spends main output
            val claimP2WPKHOutputTx = makeClaimRemoteDelayedOutputTx(commitTx.tx, localDustLimit, remotePaymentPriv.publicKey(), finalPubKeyScript.toByteVector(), feerate)
            assertTrue(claimP2WPKHOutputTx is Success, "is $claimP2WPKHOutputTx")
            val localSig = sign(claimP2WPKHOutputTx.result, remotePaymentPriv)
            val signedTx = addSigs(claimP2WPKHOutputTx.result, localSig)
            val csResult = checkSpendable(signedTx)
            assertTrue(csResult.isSuccess, "is $csResult")
        }
        run {
            // remote spends htlc1's htlc-timeout tx with revocation key
            val claimHtlcDelayedPenaltyTxs = makeClaimDelayedOutputPenaltyTxs(htlcTimeoutTxs[1].tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), finalPubKeyScript, feerate)
            assertEquals(1, claimHtlcDelayedPenaltyTxs.size)
            val claimHtlcDelayedPenaltyTx = claimHtlcDelayedPenaltyTxs.first()
            assertTrue(claimHtlcDelayedPenaltyTx is Success, "is $claimHtlcDelayedPenaltyTx")
            val sig = sign(claimHtlcDelayedPenaltyTx.result, localRevocationPriv)
            val signed = addSigs(claimHtlcDelayedPenaltyTx.result, sig)
            val csResult = checkSpendable(signed)
            assertTrue(csResult.isSuccess, "is $csResult")
            // remote can't claim revoked output of htlc3's htlc-timeout tx because it is below the dust limit
            val claimHtlcDelayedPenaltyTxsSkipped = makeClaimDelayedOutputPenaltyTxs(htlcTimeoutTxs[0].tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), finalPubKeyScript, feerate)
            assertEquals(listOf(Skipped(AmountBelowDustLimit)), claimHtlcDelayedPenaltyTxsSkipped)
        }
        run {
            // remote spends remote->local htlc output directly in case of timeout
            val claimHtlcTimeoutTx =
                makeClaimHtlcTimeoutTx(commitTx.tx, outputs, localDustLimit, remoteHtlcPriv.publicKey(), localHtlcPriv.publicKey(), localRevocationPriv.publicKey(), finalPubKeyScript, htlc2, feerate)
            assertTrue(claimHtlcTimeoutTx is Success, "is $claimHtlcTimeoutTx")
            val remoteSig = sign(claimHtlcTimeoutTx.result, remoteHtlcPriv)
            val signed = addSigs(claimHtlcTimeoutTx.result, remoteSig)
            val csResult = checkSpendable(signed)
            assertTrue(csResult.isSuccess, "is $csResult")
        }
        run {
            // remote spends htlc2's htlc-success tx with revocation key
            val claimHtlcDelayedPenaltyTxs = makeClaimDelayedOutputPenaltyTxs(htlcSuccessTxs[1].tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), finalPubKeyScript, feerate)
            assertEquals(1, claimHtlcDelayedPenaltyTxs.size)
            val claimHtlcDelayedPenaltyTx = claimHtlcDelayedPenaltyTxs.first()
            assertTrue(claimHtlcDelayedPenaltyTx is Success, "is $claimHtlcDelayedPenaltyTx")
            val sig = sign(claimHtlcDelayedPenaltyTx.result, localRevocationPriv)
            val signed = addSigs(claimHtlcDelayedPenaltyTx.result, sig)
            val csResult = checkSpendable(signed)
            assertTrue(csResult.isSuccess, "is $csResult")
            // remote can't claim revoked output of htlc4's htlc-success tx because it is below the dust limit
            val claimHtlcDelayedPenaltyTxsSkipped = makeClaimDelayedOutputPenaltyTxs(htlcSuccessTxs[0].tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), finalPubKeyScript, feerate)
            assertEquals(listOf(Skipped(AmountBelowDustLimit)), claimHtlcDelayedPenaltyTxsSkipped)
        }
        run {
            // remote spends all htlc txs aggregated in a single tx
            val txIn = htlcTimeoutTxs.flatMap { it.tx.txIn } + htlcSuccessTxs.flatMap { it.tx.txIn }
            val txOut = htlcTimeoutTxs.flatMap { it.tx.txOut } + htlcSuccessTxs.flatMap { it.tx.txOut }
            val aggregatedHtlcTx = Transaction(2, txIn, txOut, 0)
            val claimHtlcDelayedPenaltyTxs = makeClaimDelayedOutputPenaltyTxs(aggregatedHtlcTx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), finalPubKeyScript, feerate)
            assertEquals(4, claimHtlcDelayedPenaltyTxs.size)
            val skipped = claimHtlcDelayedPenaltyTxs.filterIsInstance<Skipped<AmountBelowDustLimit>>()
            assertEquals(2, skipped.size)
            val claimed = claimHtlcDelayedPenaltyTxs.filterIsInstance<Success<Transactions.TransactionWithInputInfo.ClaimHtlcDelayedOutputPenaltyTx>>()
            assertEquals(2, claimed.size)
            assertEquals(2, claimed.map { it.result.input.outPoint }.toSet().size)
        }
        run {
            // remote spends offered HTLC output with revocation key
            val script = write(htlcOffered(localHtlcPriv.publicKey(), remoteHtlcPriv.publicKey(), localRevocationPriv.publicKey(), ripemd160(htlc1.paymentHash)))
            val htlcOutputIndex = outputs.indexOfFirst {
                val outHtlc = (it.commitmentOutput as? OutHtlc)?.outgoingHtlc?.add
                outHtlc != null && outHtlc.id == htlc1.id
            }
            val htlcPenaltyTx = makeHtlcPenaltyTx(commitTx.tx, htlcOutputIndex, script, localDustLimit, finalPubKeyScript, feerate)
            assertTrue(htlcPenaltyTx is Success, "is $htlcPenaltyTx")
            val sig = sign(htlcPenaltyTx.result, localRevocationPriv)
            val signed = addSigs(htlcPenaltyTx.result, sig, localRevocationPriv.publicKey())
            val csResult = checkSpendable(signed)
            assertTrue(csResult.isSuccess, "is $csResult")
        }
        run {
            // remote spends received HTLC output with revocation key
            val script = write(htlcReceived(localHtlcPriv.publicKey(), remoteHtlcPriv.publicKey(), localRevocationPriv.publicKey(), ripemd160(htlc2.paymentHash), htlc2.cltvExpiry))
            val htlcOutputIndex = outputs.indexOfFirst {
                val inHtlc = (it.commitmentOutput as? CommitmentOutput.InHtlc)?.incomingHtlc?.add
                inHtlc != null && inHtlc.id == htlc2.id
            }
            val htlcPenaltyTx = makeHtlcPenaltyTx(commitTx.tx, htlcOutputIndex, script, localDustLimit, finalPubKeyScript, feerate)
            assertTrue(htlcPenaltyTx is Success, "is $htlcPenaltyTx")
            val sig = sign(htlcPenaltyTx.result, localRevocationPriv)
            val signed = addSigs(htlcPenaltyTx.result, sig, localRevocationPriv.publicKey())
            val csResult = checkSpendable(signed)
            assertTrue(csResult.isSuccess, "is $csResult")
        }
    }

    @Test
    fun `spend 2-of-2 legacy swap-in`() {
        val userWallet = TestConstants.Alice.keyManager.swapInOnChainWallet
        val swapInTx = Transaction(
            version = 2,
            txIn = listOf(TxIn(OutPoint(TxId(randomBytes32()), 2), 0)),
            txOut = listOf(TxOut(100_000.sat, userWallet.legacySwapInProtocol.pubkeyScript)),
            lockTime = 0
        )
        // The transaction can be spent if the user and the server produce a signature.
        run {
            val fundingTx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), 0)),
                txOut = listOf(TxOut(90_000.sat, pay2wpkh(randomKey().publicKey()))),
                lockTime = 0
            )
            val userSig = userWallet.signSwapInputUserLegacy(fundingTx, 0, swapInTx.txOut)
            val serverKey = TestConstants.Bob.keyManager.swapInOnChainWallet.localServerPrivateKey(TestConstants.Alice.nodeParams.nodeId)
            val serverSig = userWallet.legacySwapInProtocol.signSwapInputServer(fundingTx, 0, swapInTx.txOut.first(), serverKey)
            val witness = userWallet.legacySwapInProtocol.witness(userSig, serverSig)
            val signedTx = fundingTx.updateWitness(0, witness)
            Transaction.correctlySpends(signedTx, listOf(swapInTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }
        // Or it can be spent with only the user's signature, after a delay.
        run {
            val fundingTx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), userWallet.refundDelay.toLong())),
                txOut = listOf(TxOut(90_000.sat, pay2wpkh(randomKey().publicKey()))),
                lockTime = 0
            )
            val userSig = userWallet.signSwapInputUserLegacy(fundingTx, 0, swapInTx.txOut)
            val witness = userWallet.legacySwapInProtocol.witnessRefund(userSig)
            val signedTx = fundingTx.updateWitness(0, witness)
            Transaction.correctlySpends(signedTx, listOf(swapInTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }
    }

    @Test
    fun `spend 2-of-2 swap-in taproot-musig2 version`() {
        val userPrivateKey = PrivateKey(ByteArray(32) { 1 })
        val serverPrivateKey = PrivateKey(ByteArray(32) { 2 })
        val refundDelay = 25920

        val mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ")
        val seed = MnemonicCode.toSeed(mnemonics, "")
        val masterPrivateKey = DeterministicWallet.derivePrivateKey(DeterministicWallet.generate(seed), "/51'/0'/0'").copy(path = KeyPath.empty)
        val userRefundPrivateKey = DeterministicWallet.derivePrivateKey(masterPrivateKey, "0").privateKey
        val swapInProtocol = SwapInProtocol(userPrivateKey.publicKey(), serverPrivateKey.publicKey(), userRefundPrivateKey.publicKey(), refundDelay)

        val swapInTx = Transaction(
            version = 2,
            txIn = listOf(),
            txOut = listOf(TxOut(Satoshi(10000), swapInProtocol.pubkeyScript)),
            lockTime = 0
        )

        // The transaction can be spent if the user and the server produce a signature.
        run {
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), sequence = TxIn.SEQUENCE_FINAL)),
                txOut = listOf(TxOut(Satoshi(10000), pay2wpkh(PrivateKey(randomBytes32()).publicKey()))),
                lockTime = 0
            )
            // The first step of a musig2 signing session is to exchange nonces.
            // If participants are disconnected before the end of the signing session, they must start again with fresh nonces.
            val userNonce = Musig2.generateNonce(randomBytes32(), userPrivateKey, listOf(userPrivateKey.publicKey(), serverPrivateKey.publicKey()))
            val serverNonce = Musig2.generateNonce(randomBytes32(), serverPrivateKey, listOf(serverPrivateKey.publicKey(), userPrivateKey.publicKey()))

            // Once they have each other's public nonce, they can produce partial signatures.
            val userSig = swapInProtocol.signSwapInputUser(tx, 0, swapInTx.txOut, userPrivateKey, userNonce.first, userNonce.second, serverNonce.second).right!!
            val serverSig = swapInProtocol.signSwapInputServer(tx, 0, swapInTx.txOut, serverPrivateKey, serverNonce.first, userNonce.second, serverNonce.second).right!!

            // Once they have each other's partial signature, they can aggregate them into a valid signature.
            val witness = swapInProtocol.witness(tx, 0, swapInTx.txOut, userNonce.second, serverNonce.second, userSig, serverSig).right
            assertNotNull(witness)
            val signedTx = tx.updateWitness(0, witness)
            Transaction.correctlySpends(signedTx, swapInTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }

        // Or it can be spent with only the user's signature, after a delay.
        run {
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), sequence = refundDelay.toLong())),
                txOut = listOf(TxOut(Satoshi(10000), pay2wpkh(PrivateKey(randomBytes32()).publicKey()))),
                lockTime = 0
            )
            val sig = swapInProtocol.signSwapInputRefund(tx, 0, swapInTx.txOut, userRefundPrivateKey)
            val signedTx = tx.updateWitness(0, swapInProtocol.witnessRefund(sig))
            Transaction.correctlySpends(signedTx, swapInTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }
    }

    @Test
    fun `swap-in input weight`() {
        val pubkey = randomKey().publicKey()
        // DER-encoded ECDSA signatures usually take up to 72 bytes.
        val sig = ByteVector64.fromValidHex("90b658d172a51f1b3f1a2becd30942397f5df97da8cd2c026854607e955ad815ccfd87d366e348acc32aaf15ff45263aebbb7ecc913a0e5999133f447aee828c")
        val tx = Transaction(2, listOf(TxIn(OutPoint(TxId(ByteVector32.Zeroes), 2), 0)), listOf(TxOut(50_000.sat, pay2wpkh(pubkey))), 0)
        val swapInProtocol = SwapInProtocolLegacy(pubkey, pubkey, 144)
        val witness = swapInProtocol.witness(sig, sig)
        val swapInput = TxIn(OutPoint(TxId(ByteVector32.Zeroes), 3), ByteVector.empty, 0, witness)
        val txWithAdditionalInput = tx.copy(txIn = tx.txIn + listOf(swapInput))
        val inputWeight = txWithAdditionalInput.weight() - tx.weight()
        assertEquals(inputWeight, swapInputWeightLegacy)
    }

    @Test
    fun `swap-in input weight -- musig2 version`() {
        val pubkey = randomKey().publicKey()
        val sig = ByteVector64.fromValidHex("90b658d172a51f1b3f1a2becd30942397f5df97da8cd2c026854607e955ad815ccfd87d366e348acc32aaf15ff45263aebbb7ecc913a0e5999133f447aee828c")
        val tx = Transaction(2, listOf(TxIn(OutPoint(TxId(ByteVector32.Zeroes), 2), 0)), listOf(TxOut(50_000.sat, pay2wpkh(pubkey))), 0)
        val witness = Script.witnessKeyPathPay2tr(sig)
        val swapInput = TxIn(OutPoint(TxId(ByteVector32.Zeroes), 3), ByteVector.empty, 0, witness)
        val txWithAdditionalInput = tx.copy(txIn = tx.txIn + listOf(swapInput))
        val inputWeight = txWithAdditionalInput.weight() - tx.weight()
        assertEquals(inputWeight, swapInputWeight)
    }

    @Test
    fun `sort the htlc outputs using BIP69 and cltv expiry`() {
        val localFundingPriv = PrivateKey.fromHex("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
        val remoteFundingPriv = PrivateKey.fromHex("a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2")
        val localRevocationPriv = PrivateKey.fromHex("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3")
        val localPaymentPriv = PrivateKey.fromHex("a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4")
        val localDelayedPaymentPriv = PrivateKey.fromHex("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5")
        val remotePaymentPriv = PrivateKey.fromHex("a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6")
        val localHtlcPriv = PrivateKey.fromHex("a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7")
        val remoteHtlcPriv = PrivateKey.fromHex("a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8")
        val commitInput = Funding.makeFundingInputInfo(TxId("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"), 0, 1.btc, localFundingPriv.publicKey(), remoteFundingPriv.publicKey())

        // htlc1 and htlc2 are two regular incoming HTLCs with different amounts.
        // htlc2 and htlc3 have the same amounts and should be sorted according to their scriptPubKey
        // htlc4 is identical to htlc3 and htlc5 has same payment_hash/amount but different CLTV
        val paymentPreimage1 = ByteVector32.fromValidHex("1111111111111111111111111111111111111111111111111111111111111111")
        val paymentPreimage2 = ByteVector32.fromValidHex("2222222222222222222222222222222222222222222222222222222222222222")
        val paymentPreimage3 = ByteVector32.fromValidHex("3333333333333333333333333333333333333333333333333333333333333333")
        val htlc1 = UpdateAddHtlc(randomBytes32(), 1, 100.mbtc.toMilliSatoshi(), paymentPreimage1.sha256(), CltvExpiry(300), TestConstants.emptyOnionPacket)
        val htlc2 = UpdateAddHtlc(randomBytes32(), 2, 200.mbtc.toMilliSatoshi(), paymentPreimage2.sha256(), CltvExpiry(300), TestConstants.emptyOnionPacket)
        val htlc3 = UpdateAddHtlc(randomBytes32(), 3, 200.mbtc.toMilliSatoshi(), paymentPreimage3.sha256(), CltvExpiry(300), TestConstants.emptyOnionPacket)
        val htlc4 = UpdateAddHtlc(randomBytes32(), 4, 200.mbtc.toMilliSatoshi(), paymentPreimage3.sha256(), CltvExpiry(300), TestConstants.emptyOnionPacket)
        val htlc5 = UpdateAddHtlc(randomBytes32(), 5, 200.mbtc.toMilliSatoshi(), paymentPreimage3.sha256(), CltvExpiry(301), TestConstants.emptyOnionPacket)

        val spec = CommitmentSpec(
            htlcs = setOf(
                OutgoingHtlc(htlc1),
                OutgoingHtlc(htlc2),
                OutgoingHtlc(htlc3),
                OutgoingHtlc(htlc4),
                OutgoingHtlc(htlc5)
            ),
            feerate = feerate,
            toLocal = 400.mbtc.toMilliSatoshi(),
            toRemote = 300.mbtc.toMilliSatoshi()
        )

        val commitTxNumber = 0x404142434446L
        val (commitTx, outputs, htlcTxs) = run {
            val outputs =
                makeCommitTxOutputs(
                    localFundingPriv.publicKey(),
                    remoteFundingPriv.publicKey(),
                    true,
                    localDustLimit,
                    localRevocationPriv.publicKey(),
                    toLocalDelay,
                    localDelayedPaymentPriv.publicKey(),
                    remotePaymentPriv.publicKey(),
                    localHtlcPriv.publicKey(),
                    remoteHtlcPriv.publicKey(),
                    spec
                )
            val txInfo = makeCommitTx(commitInput, commitTxNumber, localPaymentPriv.publicKey(), remotePaymentPriv.publicKey(), true, outputs)
            val localSig = sign(txInfo, localPaymentPriv)
            val remoteSig = sign(txInfo, remotePaymentPriv)
            val commitTx = addSigs(txInfo, localFundingPriv.publicKey(), remoteFundingPriv.publicKey(), localSig, remoteSig)
            val htlcTxs = makeHtlcTxs(commitTx.tx, localDustLimit, localRevocationPriv.publicKey(), toLocalDelay, localDelayedPaymentPriv.publicKey(), feerate, outputs)
            Triple(commitTx, outputs, htlcTxs)
        }

        // htlc1 comes before htlc2 because of the smaller amount (BIP69)
        // htlc3, htlc4 and htlc5 have the same pubKeyScript but htlc5 comes after because it has a higher CLTV
        // htlc2 and htlc3/4/5 have the same amount but htlc2 comes last because its pubKeyScript is lexicographically greater than htlc3/4/5
        val (htlcOut1, htlcOut2, htlcOut3, htlcOut4, htlcOut5) = commitTx.tx.txOut.drop(2)
        assertEquals(10_000_000.sat, htlcOut1.amount)
        for (htlcOut in listOf(htlcOut2, htlcOut3, htlcOut4, htlcOut5)) {
            assertEquals(20_000_000.sat, htlcOut.amount)
        }

        // htlc3 and htlc4 are completely identical, their relative order can't be enforced.
        assertEquals(5, htlcTxs.size)
        htlcTxs.forEach { tx -> assertTrue(tx is Transactions.TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx) }
        val htlcIds = htlcTxs.map { it.htlcId }
        assertTrue(htlcIds == listOf(1L, 3L, 4L, 5L, 2L) || htlcIds == listOf(1L, 4L, 3L, 5L, 2L))

        assertTrue(htlcOut4.publicKeyScript.toHex() < htlcOut5.publicKeyScript.toHex())
        assertEquals(htlcOut1.publicKeyScript, outputs.find { it.commitmentOutput == OutHtlc(OutgoingHtlc(htlc1)) }?.output?.publicKeyScript)
        assertEquals(htlcOut5.publicKeyScript, outputs.find { it.commitmentOutput == OutHtlc(OutgoingHtlc(htlc2)) }?.output?.publicKeyScript)
        assertEquals(htlcOut3.publicKeyScript, outputs.find { it.commitmentOutput == OutHtlc(OutgoingHtlc(htlc3)) }?.output?.publicKeyScript)
        assertEquals(htlcOut4.publicKeyScript, outputs.find { it.commitmentOutput == OutHtlc(OutgoingHtlc(htlc4)) }?.output?.publicKeyScript)
        assertEquals(htlcOut2.publicKeyScript, outputs.find { it.commitmentOutput == OutHtlc(OutgoingHtlc(htlc5)) }?.output?.publicKeyScript)
    }

    @Test
    fun `find our output in closing tx`() {
        val localPubKeyScript = write(pay2wpkh(PrivateKey(randomBytes32()).publicKey())).byteVector()
        val remotePubKeyScript = write(pay2wpkh(PrivateKey(randomBytes32()).publicKey())).byteVector()

        run {
            // Different amounts, both outputs untrimmed, local is closer:
            val spec = CommitmentSpec(setOf(), feerate, 150_000_000.msat, 250_000_000.msat)
            val closingTxs = makeClosingTxs(commitInput, spec, Transactions.ClosingTxFee.PaidByUs(5_000.sat), 0, localPubKeyScript, remotePubKeyScript)
            assertNotNull(closingTxs.localAndRemote)
            assertNotNull(closingTxs.localOnly)
            assertNull(closingTxs.remoteOnly)
            val localAndRemote = closingTxs.localAndRemote?.toLocalOutput!!
            assertEquals(localPubKeyScript, localAndRemote.publicKeyScript)
            assertEquals(145_000.sat, localAndRemote.amount)
            val localOnly = closingTxs.localOnly?.toLocalOutput!!
            assertEquals(localPubKeyScript, localOnly.publicKeyScript)
            assertEquals(145_000.sat, localOnly.amount)
        }
        run {
            // Same amounts, both outputs untrimmed, remote is closer:
            val spec = CommitmentSpec(setOf(), feerate, 150_000_000.msat, 250_000_000.msat)
            val closingTxs = makeClosingTxs(commitInput, spec, Transactions.ClosingTxFee.PaidByThem(5_000.sat), 0, localPubKeyScript, remotePubKeyScript)
            assertNotNull(closingTxs.localAndRemote)
            assertNotNull(closingTxs.localOnly)
            assertNull(closingTxs.remoteOnly)
            val localAndRemote = closingTxs.localAndRemote?.toLocalOutput!!
            assertEquals(localPubKeyScript, localAndRemote.publicKeyScript)
            assertEquals(150_000.sat, localAndRemote.amount)
            val localOnly = closingTxs.localOnly?.toLocalOutput!!
            assertEquals(localPubKeyScript, localOnly.publicKeyScript)
            assertEquals(150_000.sat, localOnly.amount)
        }
        run {
            // Their output is trimmed:
            val spec = CommitmentSpec(setOf(), feerate, 150_000_000.msat, 1_000_000.msat)
            val closingTxs = makeClosingTxs(commitInput, spec, Transactions.ClosingTxFee.PaidByThem(800.sat), 0, localPubKeyScript, remotePubKeyScript)
            assertEquals(1, closingTxs.all.size)
            assertNotNull(closingTxs.localOnly)
            assertEquals(1, closingTxs.localOnly!!.tx.txOut.size)
            val toLocal = closingTxs.localOnly?.toLocalOutput!!
            assertEquals(localPubKeyScript, toLocal.publicKeyScript)
            assertEquals(150_000.sat, toLocal.amount)
        }
        run {
            // Our output is trimmed:
            val spec = CommitmentSpec(setOf(), feerate, 1_000_000.msat, 150_000_000.msat)
            val closingTxs = makeClosingTxs(commitInput, spec, Transactions.ClosingTxFee.PaidByUs(800.sat), 0, localPubKeyScript, remotePubKeyScript)
            assertEquals(1, closingTxs.all.size)
            assertNotNull(closingTxs.remoteOnly)
            assertNull(closingTxs.remoteOnly?.toLocalOutput)
        }
        run {
            // Both outputs are trimmed:
            val spec = CommitmentSpec(setOf(), feerate, 50_000.msat, 10_000.msat)
            val closingTxs = makeClosingTxs(commitInput, spec, Transactions.ClosingTxFee.PaidByUs(10.sat), 0, localPubKeyScript, remotePubKeyScript)
            assertNull(closingTxs.localAndRemote)
            assertNull(closingTxs.localOnly)
            assertNull(closingTxs.remoteOnly)
        }
    }

}
