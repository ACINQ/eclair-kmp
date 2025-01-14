/*
 * Copyright 2019 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.lightning.transactions

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.bitcoin.utils.Try
import fr.acinq.bitcoin.utils.runTrying
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.Commitments
import fr.acinq.lightning.io.*
import fr.acinq.lightning.transactions.CommitmentOutput.InHtlc
import fr.acinq.lightning.transactions.CommitmentOutput.OutHtlc
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.UpdateAddHtlc
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable

/** Type alias for a collection of commitment output links */
typealias TransactionsCommitmentOutputs = List<Transactions.CommitmentOutputLink<CommitmentOutput>>

/**
 * Created by PM on 15/12/2016.
 */
object Transactions {

    const val MAX_STANDARD_TX_WEIGHT = 400_000

    @Serializable
    data class InputInfo constructor(
        @Contextual val outPoint: OutPoint,
        @Contextual val txOut: TxOut,
        @Contextual val redeemScript: ByteVector
    ) {
        constructor(outPoint: OutPoint, txOut: TxOut, redeemScript: List<ScriptElt>) : this(outPoint, txOut, ByteVector(Script.write(redeemScript)))
    }

    @Serializable
    sealed class TransactionWithInputInfo {
        abstract val input: InputInfo
        abstract val tx: Transaction
        val fee: Satoshi get() = input.txOut.amount - tx.txOut.map { it.amount }.sum()
        val minRelayFee: Satoshi
            get() {
                val vsize = (tx.weight() + 3) / 4
                return (FeeratePerKw.MinimumRelayFeeRate * vsize / 1000).sat
            }

        @Serializable
        data class SpliceTx(override val input: InputInfo, @Contextual override val tx: Transaction) : TransactionWithInputInfo()

        @Serializable
        data class CommitTx(override val input: InputInfo, @Contextual override val tx: Transaction) : TransactionWithInputInfo()

        @Serializable
        sealed class HtlcTx : TransactionWithInputInfo() {
            abstract val htlcId: Long

            @Serializable
            data class HtlcSuccessTx(
                override val input: InputInfo,
                @Contextual override val tx: Transaction,
                @Contextual val paymentHash: ByteVector32,
                override val htlcId: Long
            ) : HtlcTx()

            @Serializable
            data class HtlcTimeoutTx(override val input: InputInfo, @Contextual override val tx: Transaction, override val htlcId: Long) : HtlcTx()
        }

        @Serializable
        sealed class ClaimHtlcTx : TransactionWithInputInfo() {
            abstract val htlcId: Long

            @Serializable
            data class ClaimHtlcSuccessTx(override val input: InputInfo, @Contextual override val tx: Transaction, override val htlcId: Long) : ClaimHtlcTx()

            @Serializable
            data class ClaimHtlcTimeoutTx(override val input: InputInfo, @Contextual override val tx: Transaction, override val htlcId: Long) : ClaimHtlcTx()
        }

        @Serializable
        sealed class ClaimAnchorOutputTx : TransactionWithInputInfo() {
            @Serializable
            data class ClaimLocalAnchorOutputTx(override val input: InputInfo, @Contextual override val tx: Transaction) : ClaimAnchorOutputTx()

            @Serializable
            data class ClaimRemoteAnchorOutputTx(override val input: InputInfo, @Contextual override val tx: Transaction) : ClaimAnchorOutputTx()
        }

        @Serializable
        data class ClaimLocalDelayedOutputTx(override val input: InputInfo, @Contextual override val tx: Transaction) : TransactionWithInputInfo()

        @Serializable
        sealed class ClaimRemoteCommitMainOutputTx : TransactionWithInputInfo() {
            // TODO: once we deprecate v2/v3 serialization, we can remove the class nesting.
            @Serializable
            data class ClaimRemoteDelayedOutputTx(override val input: InputInfo, @Contextual override val tx: Transaction) : ClaimRemoteCommitMainOutputTx()
        }

        @Serializable
        data class MainPenaltyTx(override val input: InputInfo, @Contextual override val tx: Transaction) : TransactionWithInputInfo()

        @Serializable
        data class HtlcPenaltyTx(override val input: InputInfo, @Contextual override val tx: Transaction) : TransactionWithInputInfo()

        @Serializable
        data class ClaimHtlcDelayedOutputPenaltyTx(override val input: InputInfo, @Contextual override val tx: Transaction) : TransactionWithInputInfo()

        @Serializable
        data class ClosingTx(override val input: InputInfo, @Contextual override val tx: Transaction, val toLocalIndex: Int?) : TransactionWithInputInfo() {
            val toLocalOutput: TxOut? get() = toLocalIndex?.let { tx.txOut[it] }
        }
    }

    sealed class TxGenerationSkipped {
        object OutputNotFound : TxGenerationSkipped() {
            override fun toString() = "output not found (probably trimmed)"
        }

        object AmountBelowDustLimit : TxGenerationSkipped() {
            override fun toString() = "amount is below dust limit"
        }
    }

    sealed class ClosingTxFee {
        data class PaidByUs(val fee: Satoshi) : ClosingTxFee()
        data class PaidByThem(val fee: Satoshi) : ClosingTxFee()
    }

    @Serializable
    data class ClosingTxs(val localAndRemote: TransactionWithInputInfo.ClosingTx?, val localOnly: TransactionWithInputInfo.ClosingTx?, val remoteOnly: TransactionWithInputInfo.ClosingTx?) {
        val preferred: TransactionWithInputInfo.ClosingTx? = localAndRemote ?: localOnly ?: remoteOnly
        val all: List<TransactionWithInputInfo.ClosingTx> = listOfNotNull(localAndRemote, localOnly, remoteOnly)

        override fun toString(): String = "localAndRemote=${localAndRemote?.tx?.toString()}, localOnly=${localOnly?.tx?.toString()}, remoteOnly=${remoteOnly?.tx?.toString()}"
    }

    /**
     * When *local* *current* [[CommitTx]] is published:
     *   - [[ClaimDelayedOutputTx]] spends to-local output of [[CommitTx]] after a delay
     *   - [[HtlcSuccessTx]] spends htlc-received outputs of [[CommitTx]] for which we have the preimage
     *     - [[ClaimDelayedOutputTx]] spends [[HtlcSuccessTx]] after a delay
     *   - [[HtlcTimeoutTx]] spends htlc-sent outputs of [[CommitTx]] after a timeout
     *     - [[ClaimDelayedOutputTx]] spends [[HtlcTimeoutTx]] after a delay
     *
     * When *remote* *current* [[CommitTx]] is published:
     *   - [[ClaimP2WPKHOutputTx]] spends to-local output of [[CommitTx]]
     *   - [[ClaimHtlcSuccessTx]] spends htlc-received outputs of [[CommitTx]] for which we have the preimage
     *   - [[ClaimHtlcTimeoutTx]] spends htlc-sent outputs of [[CommitTx]] after a timeout
     *
     * When *remote* *revoked* [[CommitTx]] is published:
     *   - [[ClaimP2WPKHOutputTx]] spends to-local output of [[CommitTx]]
     *   - [[MainPenaltyTx]] spends remote main output using the per-commitment secret
     *   - [[HtlcSuccessTx]] spends htlc-sent outputs of [[CommitTx]] for which they have the preimage (published by remote)
     *     - [[ClaimDelayedOutputPenaltyTx]] spends [[HtlcSuccessTx]] using the revocation secret (published by local)
     *   - [[HtlcTimeoutTx]] spends htlc-received outputs of [[CommitTx]] after a timeout (published by remote)
     *     - [[ClaimDelayedOutputPenaltyTx]] spends [[HtlcTimeoutTx]] using the revocation secret (published by local)
     *   - [[HtlcPenaltyTx]] spends competes with [[HtlcSuccessTx]] and [[HtlcTimeoutTx]] for the same outputs (published by local)
     */
    // legacy swap-in. witness is 2 signatures (73 bytes) + redeem script (77 bytes)
    const val swapInputWeightLegacy = 392
    // musig2 swap-in. witness is a single Schnorr signature (64 bytes)
    const val swapInputWeight = 233

    // The following values are specific to lightning and used to estimate fees.
    const val claimP2WPKHOutputWeight = 438
    const val claimAnchorOutputWeight = 321
    const val claimHtlcDelayedWeight = 483
    const val claimHtlcSuccessWeight = 574
    const val claimHtlcTimeoutWeight = 548
    const val mainPenaltyWeight = 484
    const val htlcPenaltyWeight = 581 // based on spending an HTLC-Success output (would be 571 with HTLC-Timeout)

    private fun weight2feeMsat(feerate: FeeratePerKw, weight: Int): MilliSatoshi = (feerate.toLong() * weight).msat

    fun weight2fee(feerate: FeeratePerKw, weight: Int): Satoshi = weight2feeMsat(feerate, weight).truncateToSatoshi()

    /**
     * @param fee tx fee
     * @param weight tx weight
     * @return the fee rate (in Satoshi/Kw) for this tx
     */
    fun fee2rate(fee: Satoshi, weight: Int): FeeratePerKw = FeeratePerKw((fee * 1000L) / weight.toLong())

    /** As defined in https://github.com/lightning/bolts/blob/master/03-transactions.md#dust-limits */
    fun dustLimit(scriptPubKey: ByteVector): Satoshi {
        return runTrying {
            val script = Script.parse(scriptPubKey)
            when {
                Script.isPay2pkh(script) -> 546.sat
                Script.isPay2sh(script) -> 540.sat
                Script.isPay2wpkh(script) -> 294.sat
                Script.isPay2wsh(script) -> 330.sat
                Script.isNativeWitnessScript(script) -> 354.sat
                script[0] == OP_RETURN -> 0.sat // OP_RETURN is never dust
                else -> 546.sat
            }
        }.getOrElse { 546.sat }
    }

    /** When an output is using OP_RETURN, we usually want to make sure its amount is 0, otherwise bitcoin nodes won't accept it. */
    fun isOpReturn(scriptPubKey: ByteVector): Boolean {
        return runTrying {
            val script = Script.parse(scriptPubKey)
            script[0] == OP_RETURN
        }.getOrElse { false }
    }

    /** Offered HTLCs below this amount will be trimmed. */
    fun offeredHtlcTrimThreshold(dustLimit: Satoshi, spec: CommitmentSpec): Satoshi = dustLimit + weight2fee(spec.feerate, Commitments.HTLC_TIMEOUT_WEIGHT)

    fun trimOfferedHtlcs(dustLimit: Satoshi, spec: CommitmentSpec): List<OutgoingHtlc> {
        val threshold = offeredHtlcTrimThreshold(dustLimit, spec)
        return spec.htlcs
            .filterIsInstance<OutgoingHtlc>()
            .filter { it.add.amountMsat >= threshold }
    }

    /** Received HTLCs below this amount will be trimmed. */
    fun receivedHtlcTrimThreshold(dustLimit: Satoshi, spec: CommitmentSpec): Satoshi = dustLimit + weight2fee(spec.feerate, Commitments.HTLC_SUCCESS_WEIGHT)

    fun trimReceivedHtlcs(dustLimit: Satoshi, spec: CommitmentSpec): List<IncomingHtlc> {
        val threshold = receivedHtlcTrimThreshold(dustLimit, spec)
        return spec.htlcs
            .filterIsInstance<IncomingHtlc>()
            .filter { it.add.amountMsat >= threshold }
    }

    /** Fee for an un-trimmed HTLC. */
    fun htlcOutputFee(feerate: FeeratePerKw): MilliSatoshi = weight2feeMsat(feerate, Commitments.HTLC_OUTPUT_WEIGHT)

    /**
     * While fees are generally computed in Satoshis (since this is the smallest on-chain unit), it may be useful in some
     * cases to calculate it in MilliSatoshi to avoid rounding issues.
     * If you are adding multiple fees together for example, you should always add them in MilliSatoshi and then round
     * down to Satoshi.
     */
    fun commitTxFeeMsat(dustLimit: Satoshi, spec: CommitmentSpec): MilliSatoshi {
        val trimmedOfferedHtlcs = trimOfferedHtlcs(dustLimit, spec)
        val trimmedReceivedHtlcs = trimReceivedHtlcs(dustLimit, spec)
        val weight = Commitments.COMMIT_WEIGHT + Commitments.HTLC_OUTPUT_WEIGHT * (trimmedOfferedHtlcs.size + trimmedReceivedHtlcs.size)
        return weight2feeMsat(spec.feerate, weight) + (Commitments.ANCHOR_AMOUNT * 2).toMilliSatoshi()
    }

    fun commitTxFee(dustLimit: Satoshi, spec: CommitmentSpec): Satoshi = commitTxFeeMsat(dustLimit, spec).truncateToSatoshi()

    /**
     * @param commitTxNumber commit tx number
     * @param isInitiator true if we are the channel initiator
     * @param localPaymentBasePoint local payment base point
     * @param remotePaymentBasePoint remote payment base point
     * @return the obscured tx number as defined in BOLT #3 (a 48 bits integer)
     */
    fun obscuredCommitTxNumber(commitTxNumber: Long, isInitiator: Boolean, localPaymentBasePoint: PublicKey, remotePaymentBasePoint: PublicKey): Long {
        // from BOLT 3: SHA256(payment-basepoint from open_channel || payment-basepoint from accept_channel)
        val h = if (isInitiator) {
            Crypto.sha256(localPaymentBasePoint.value + remotePaymentBasePoint.value)
        } else {
            Crypto.sha256(remotePaymentBasePoint.value + localPaymentBasePoint.value)
        }
        val blind = Pack.int64LE(h.takeLast(6).reversed().toByteArray() + ByteArray(4) { 0 })
        return commitTxNumber xor blind
    }

    /**
     * @param commitTx commit tx
     * @param isInitiator true if we are the channel initiator
     * @param localPaymentBasePoint local payment base point
     * @param remotePaymentBasePoint remote payment base point
     * @return the actual commit tx number that was blinded and stored in locktime and sequence fields
     */
    fun getCommitTxNumber(commitTx: Transaction, isInitiator: Boolean, localPaymentBasePoint: PublicKey, remotePaymentBasePoint: PublicKey): Long {
        val blind = obscuredCommitTxNumber(0, isInitiator, localPaymentBasePoint, remotePaymentBasePoint)
        val obscured = decodeTxNumber(commitTx.txIn.first().sequence, commitTx.lockTime)
        return obscured xor blind
    }

    /**
     * This is a trick to split and encode a 48-bit txnumber into the sequence and locktime fields of a tx
     *
     * @param txnumber commitment number
     * @return (sequence, locktime)
     */
    fun encodeTxNumber(txnumber: Long): Pair<Long, Long> {
        require(txnumber <= 0xffffffffffffL) { "txnumber must be lesser than 48 bits long" }
        return Pair(0x80000000L or (txnumber shr 24), (txnumber and 0xffffffL) or 0x20000000)
    }

    fun decodeTxNumber(sequence: Long, locktime: Long): Long = ((sequence and 0xffffffL) shl 24) + (locktime and 0xffffffL)

    /**
     * Represent a link between a commitment spec item (to-local, to-remote, htlc) and the actual output in the commit tx
     *
     * @param output           transaction output
     * @param redeemScript     redeem script that matches this output (most of them are p2wsh)
     * @param commitmentOutput commitment spec item this output is built from
     */
    data class CommitmentOutputLink<T : CommitmentOutput>(val output: TxOut, val redeemScript: List<ScriptElt>, val commitmentOutput: T) : Comparable<CommitmentOutputLink<T>> {
        /**
         * We sort HTLC outputs according to BIP69 + CLTV as tie-breaker for offered HTLC, we do this only for the outgoing
         * HTLC because we must agree with the remote on the order of HTLC-Timeout transactions even for identical HTLC outputs.
         * See https://github.com/lightningnetwork/lightning-rfc/issues/448#issuecomment-432074187.
         */
        override fun compareTo(other: CommitmentOutputLink<T>): Int {
            val htlcA = (this.commitmentOutput as? OutHtlc)?.outgoingHtlc?.add
            val htlcB = (other.commitmentOutput as? OutHtlc)?.outgoingHtlc?.add
            return when {
                htlcA != null && htlcB != null && htlcA.paymentHash == htlcB.paymentHash && htlcA.amountMsat == htlcB.amountMsat -> htlcA.cltvExpiry.compareTo(htlcB.cltvExpiry)
                else -> LexicographicalOrdering.compare(this.output, other.output)
            }
        }
    }

    fun makeCommitTxOutputs(
        localFundingPubkey: PublicKey,
        remoteFundingPubkey: PublicKey,
        localPaysCommitTxFees: Boolean,
        localDustLimit: Satoshi,
        localRevocationPubkey: PublicKey,
        toLocalDelay: CltvExpiryDelta,
        localDelayedPaymentPubkey: PublicKey,
        remotePaymentPubkey: PublicKey,
        localHtlcPubkey: PublicKey,
        remoteHtlcPubkey: PublicKey,
        spec: CommitmentSpec
    ): TransactionsCommitmentOutputs {
        val commitFee = commitTxFee(localDustLimit, spec)

        val (toLocalAmount: Satoshi, toRemoteAmount: Satoshi) = if (localPaysCommitTxFees) {
            Pair(spec.toLocal.truncateToSatoshi() - commitFee, spec.toRemote.truncateToSatoshi())
        } else {
            Pair(spec.toLocal.truncateToSatoshi(), spec.toRemote.truncateToSatoshi() - commitFee)
        } // NB: we don't care if values are < 0, they will be trimmed if they are < dust limit anyway

        val outputs = ArrayList<CommitmentOutputLink<CommitmentOutput>>()

        if (toLocalAmount >= localDustLimit) outputs.add(
            CommitmentOutputLink(
                TxOut(toLocalAmount, Script.pay2wsh(Scripts.toLocalDelayed(localRevocationPubkey, toLocalDelay, localDelayedPaymentPubkey))),
                Scripts.toLocalDelayed(localRevocationPubkey, toLocalDelay, localDelayedPaymentPubkey),
                CommitmentOutput.ToLocal
            )
        )

        if (toRemoteAmount >= localDustLimit) {
            outputs.add(
                CommitmentOutputLink(
                    TxOut(toRemoteAmount, Script.pay2wsh(Scripts.toRemoteDelayed(remotePaymentPubkey))),
                    Scripts.toRemoteDelayed(remotePaymentPubkey),
                    CommitmentOutput.ToRemote
                )
            )
        }

        val untrimmedHtlcs = trimOfferedHtlcs(localDustLimit, spec).isNotEmpty() || trimReceivedHtlcs(localDustLimit, spec).isNotEmpty()
        if (untrimmedHtlcs || toLocalAmount >= localDustLimit)
            outputs.add(
                CommitmentOutputLink(
                    TxOut(Commitments.ANCHOR_AMOUNT, Script.pay2wsh(Scripts.toAnchor(localFundingPubkey))),
                    Scripts.toAnchor(localFundingPubkey),
                    CommitmentOutput.ToLocalAnchor(localFundingPubkey)
                )
            )
        if (untrimmedHtlcs || toRemoteAmount >= localDustLimit)
            outputs.add(
                CommitmentOutputLink(
                    TxOut(Commitments.ANCHOR_AMOUNT, Script.pay2wsh(Scripts.toAnchor(remoteFundingPubkey))),
                    Scripts.toAnchor(remoteFundingPubkey),
                    CommitmentOutput.ToLocalAnchor(remoteFundingPubkey)
                )
            )

        trimOfferedHtlcs(localDustLimit, spec).forEach { htlc ->
            val redeemScript = Scripts.htlcOffered(localHtlcPubkey, remoteHtlcPubkey, localRevocationPubkey, Crypto.ripemd160(htlc.add.paymentHash.toByteArray()))
            outputs.add(CommitmentOutputLink(TxOut(htlc.add.amountMsat.truncateToSatoshi(), Script.pay2wsh(redeemScript)), redeemScript, OutHtlc(htlc)))
        }

        trimReceivedHtlcs(localDustLimit, spec).forEach { htlc ->
            val redeemScript = Scripts.htlcReceived(localHtlcPubkey, remoteHtlcPubkey, localRevocationPubkey, Crypto.ripemd160(htlc.add.paymentHash.toByteArray()), htlc.add.cltvExpiry)
            outputs.add(CommitmentOutputLink(TxOut(htlc.add.amountMsat.truncateToSatoshi(), Script.pay2wsh(redeemScript)), redeemScript, InHtlc(htlc)))
        }

        return outputs.apply { sort() }
    }

    fun makeCommitTx(
        commitTxInput: InputInfo,
        commitTxNumber: Long,
        localPaymentBasePoint: PublicKey,
        remotePaymentBasePoint: PublicKey,
        localIsChannelOpener: Boolean,
        outputs: TransactionsCommitmentOutputs
    ): TransactionWithInputInfo.CommitTx {
        val txNumber = obscuredCommitTxNumber(commitTxNumber, localIsChannelOpener, localPaymentBasePoint, remotePaymentBasePoint)
        val (sequence, locktime) = encodeTxNumber(txNumber)

        val tx = Transaction(
            version = 2,
            txIn = listOf(TxIn(commitTxInput.outPoint, ByteVector.empty, sequence = sequence)),
            txOut = outputs.map { it.output },
            lockTime = locktime
        )

        return TransactionWithInputInfo.CommitTx(commitTxInput, tx)
    }

    sealed class TxResult<T> {
        data class Skipped<T>(val why: TxGenerationSkipped) : TxResult<T>()
        data class Success<T>(val result: T) : TxResult<T>()
    }

    private fun makeHtlcTimeoutTx(
        commitTx: Transaction,
        output: CommitmentOutputLink<OutHtlc>,
        outputIndex: Int,
        localDustLimit: Satoshi,
        localRevocationPubkey: PublicKey,
        toLocalDelay: CltvExpiryDelta,
        localDelayedPaymentPubkey: PublicKey,
        feerate: FeeratePerKw
    ): TxResult<TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx> {
        val fee = weight2fee(feerate, Commitments.HTLC_TIMEOUT_WEIGHT)
        val redeemScript = output.redeemScript
        val htlc = output.commitmentOutput.outgoingHtlc.add
        val amount = htlc.amountMsat.truncateToSatoshi() - fee
        return if (amount < localDustLimit) {
            TxResult.Skipped(TxGenerationSkipped.AmountBelowDustLimit)
        } else {
            val input = InputInfo(OutPoint(commitTx, outputIndex.toLong()), commitTx.txOut[outputIndex], ByteVector(Script.write(redeemScript)))
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(input.outPoint, ByteVector.empty, 1L)),
                txOut = listOf(TxOut(amount, Script.pay2wsh(Scripts.toLocalDelayed(localRevocationPubkey, toLocalDelay, localDelayedPaymentPubkey)))),
                lockTime = htlc.cltvExpiry.toLong()
            )
            TxResult.Success(TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx(input, tx, htlc.id))
        }
    }

    private fun makeHtlcSuccessTx(
        commitTx: Transaction,
        output: CommitmentOutputLink<InHtlc>,
        outputIndex: Int,
        localDustLimit: Satoshi,
        localRevocationPubkey: PublicKey,
        toLocalDelay: CltvExpiryDelta,
        localDelayedPaymentPubkey: PublicKey,
        feerate: FeeratePerKw
    ): TxResult<TransactionWithInputInfo.HtlcTx.HtlcSuccessTx> {
        val fee = weight2fee(feerate, Commitments.HTLC_SUCCESS_WEIGHT)
        val redeemScript = output.redeemScript
        val htlc = output.commitmentOutput.incomingHtlc.add
        val amount = htlc.amountMsat.truncateToSatoshi() - fee
        return if (amount < localDustLimit) {
            TxResult.Skipped(TxGenerationSkipped.AmountBelowDustLimit)
        } else {
            val input = InputInfo(OutPoint(commitTx, outputIndex.toLong()), commitTx.txOut[outputIndex], ByteVector(Script.write(redeemScript)))
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(input.outPoint, ByteVector.empty, 1L)),
                txOut = listOf(TxOut(amount, Script.pay2wsh(Scripts.toLocalDelayed(localRevocationPubkey, toLocalDelay, localDelayedPaymentPubkey)))),
                lockTime = 0
            )
            TxResult.Success(TransactionWithInputInfo.HtlcTx.HtlcSuccessTx(input, tx, htlc.paymentHash, htlc.id))
        }
    }

    fun makeHtlcTxs(
        commitTx: Transaction,
        localDustLimit: Satoshi,
        localRevocationPubkey: PublicKey,
        toLocalDelay: CltvExpiryDelta,
        localDelayedPaymentPubkey: PublicKey,
        feerate: FeeratePerKw,
        outputs: TransactionsCommitmentOutputs
    ): List<TransactionWithInputInfo.HtlcTx> {
        val htlcTimeoutTxs = outputs
            .mapIndexedNotNull map@{ outputIndex, link ->
                val outHtlc = link.commitmentOutput as? OutHtlc ?: return@map null
                val co = CommitmentOutputLink(link.output, link.redeemScript, outHtlc)
                makeHtlcTimeoutTx(commitTx, co, outputIndex, localDustLimit, localRevocationPubkey, toLocalDelay, localDelayedPaymentPubkey, feerate)
            }
            .mapNotNull { (it as? TxResult.Success)?.result }

        val htlcSuccessTxs = outputs
            .mapIndexedNotNull map@{ outputIndex, link ->
                val inHtlc = link.commitmentOutput as? InHtlc ?: return@map null
                val co = CommitmentOutputLink(link.output, link.redeemScript, inHtlc)
                makeHtlcSuccessTx(commitTx, co, outputIndex, localDustLimit, localRevocationPubkey, toLocalDelay, localDelayedPaymentPubkey, feerate)
            }
            .mapNotNull { (it as? TxResult.Success)?.result }

        return (htlcTimeoutTxs + htlcSuccessTxs).sortedBy { it.input.outPoint.index }
    }

    fun makeClaimHtlcSuccessTx(
        commitTx: Transaction,
        outputs: TransactionsCommitmentOutputs,
        localDustLimit: Satoshi,
        localHtlcPubkey: PublicKey,
        remoteHtlcPubkey: PublicKey,
        remoteRevocationPubkey: PublicKey,
        localFinalScriptPubKey: ByteArray,
        htlc: UpdateAddHtlc,
        feerate: FeeratePerKw
    ): TxResult<TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcSuccessTx> {
        val redeemScript = Scripts.htlcOffered(remoteHtlcPubkey, localHtlcPubkey, remoteRevocationPubkey, Crypto.ripemd160(htlc.paymentHash))
        return outputs.withIndex()
            .firstOrNull { (it.value.commitmentOutput as? OutHtlc)?.outgoingHtlc?.add?.id == htlc.id }
            ?.let { (outputIndex, _) ->
                val input = InputInfo(OutPoint(commitTx, outputIndex.toLong()), commitTx.txOut[outputIndex], ByteVector(Script.write(redeemScript)))
                val tx = Transaction(
                    version = 2,
                    txIn = listOf(TxIn(input.outPoint, ByteVector.empty, 1L)),
                    txOut = listOf(TxOut(0.sat, localFinalScriptPubKey)),
                    lockTime = htlc.cltvExpiry.toLong()
                )
                val weight = addSigs(TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcSuccessTx(input, tx, htlc.id), PlaceHolderSig, ByteVector32.Zeroes).tx.weight()
                val fee = weight2fee(feerate, weight)
                val amount = input.txOut.amount - fee
                if (amount < localDustLimit) {
                    TxResult.Skipped(TxGenerationSkipped.AmountBelowDustLimit)
                } else {
                    val tx1 = tx.copy(txOut = listOf(tx.txOut.first().copy(amount = amount)))
                    TxResult.Success(TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcSuccessTx(input, tx1, htlc.id))
                }
            }
            ?: TxResult.Skipped(TxGenerationSkipped.OutputNotFound)
    }

    fun makeClaimHtlcTimeoutTx(
        commitTx: Transaction,
        outputs: TransactionsCommitmentOutputs,
        localDustLimit: Satoshi,
        localHtlcPubkey: PublicKey,
        remoteHtlcPubkey: PublicKey,
        remoteRevocationPubkey: PublicKey,
        localFinalScriptPubKey: ByteArray,
        htlc: UpdateAddHtlc,
        feerate: FeeratePerKw
    ): TxResult<TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx> {
        val redeemScript = Scripts.htlcReceived(remoteHtlcPubkey, localHtlcPubkey, remoteRevocationPubkey, Crypto.ripemd160(htlc.paymentHash), htlc.cltvExpiry)
        return outputs.withIndex()
            .firstOrNull { (it.value.commitmentOutput as? InHtlc)?.incomingHtlc?.add?.id == htlc.id }
            ?.let { (outputIndex, _) ->
                val input = InputInfo(OutPoint(commitTx, outputIndex.toLong()), commitTx.txOut[outputIndex], ByteVector(Script.write(redeemScript)))
                // unsigned tx
                val tx = Transaction(
                    version = 2,
                    txIn = listOf(TxIn(input.outPoint, ByteVector.empty, 1L)),
                    txOut = listOf(TxOut(0.sat, localFinalScriptPubKey)),
                    lockTime = htlc.cltvExpiry.toLong()
                )
                val weight = addSigs(TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx(input, tx, htlc.id), PlaceHolderSig).tx.weight()
                val fee = weight2fee(feerate, weight)
                val amount = input.txOut.amount - fee
                if (amount < localDustLimit) {
                    TxResult.Skipped(TxGenerationSkipped.AmountBelowDustLimit)
                } else {
                    val tx1 = tx.copy(txOut = listOf(tx.txOut.first().copy(amount = amount)))
                    TxResult.Success(TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx(input, tx1, htlc.id))
                }
            }
            ?: TxResult.Skipped(TxGenerationSkipped.OutputNotFound)
    }

    fun makeClaimRemoteDelayedOutputTx(
        commitTx: Transaction, localDustLimit: Satoshi,
        localPaymentPubkey: PublicKey,
        localFinalScriptPubKey: ByteVector,
        feerate: FeeratePerKw
    ): TxResult<TransactionWithInputInfo.ClaimRemoteCommitMainOutputTx.ClaimRemoteDelayedOutputTx> {
        val redeemScript = Scripts.toRemoteDelayed(localPaymentPubkey)
        val pubkeyScript = Script.write(Script.pay2wsh(redeemScript))

        return when (val pubkeyScriptIndex = findPubKeyScriptIndex(commitTx, pubkeyScript)) {
            is TxResult.Skipped -> TxResult.Skipped(pubkeyScriptIndex.why)
            is TxResult.Success -> {
                val outputIndex = pubkeyScriptIndex.result
                val input = InputInfo(OutPoint(commitTx, outputIndex.toLong()), commitTx.txOut[outputIndex], ByteVector(Script.write(redeemScript)))
                // unsigned transaction
                val tx = Transaction(
                    version = 2,
                    txIn = listOf(TxIn(input.outPoint, ByteVector.empty, 1)),
                    txOut = listOf(TxOut(0.sat, localFinalScriptPubKey)),
                    lockTime = 0
                )
                // compute weight with a dummy 73 bytes signature (the largest you can get)
                val weight = addSigs(TransactionWithInputInfo.ClaimRemoteCommitMainOutputTx.ClaimRemoteDelayedOutputTx(input, tx), PlaceHolderSig).tx.weight()
                val fee = weight2fee(feerate, weight)
                val amount = input.txOut.amount - fee
                if (amount < localDustLimit) {
                    TxResult.Skipped(TxGenerationSkipped.AmountBelowDustLimit)
                } else {
                    val tx1 = tx.copy(txOut = listOf(tx.txOut.first().copy(amount = amount)))
                    TxResult.Success(TransactionWithInputInfo.ClaimRemoteCommitMainOutputTx.ClaimRemoteDelayedOutputTx(input, tx1))
                }
            }
        }
    }

    fun makeClaimLocalDelayedOutputTx(
        delayedOutputTx: Transaction,
        localDustLimit: Satoshi,
        localRevocationPubkey: PublicKey,
        toLocalDelay: CltvExpiryDelta,
        localDelayedPaymentPubkey: PublicKey,
        localFinalScriptPubKey: ByteArray,
        feerate: FeeratePerKw
    ): TxResult<TransactionWithInputInfo.ClaimLocalDelayedOutputTx> {
        val redeemScript = Scripts.toLocalDelayed(localRevocationPubkey, toLocalDelay, localDelayedPaymentPubkey)
        val pubkeyScript = Script.write(Script.pay2wsh(redeemScript))
        return when (val pubkeyScriptIndex = findPubKeyScriptIndex(delayedOutputTx, pubkeyScript)) {
            is TxResult.Skipped -> TxResult.Skipped(pubkeyScriptIndex.why)
            is TxResult.Success -> {
                val outputIndex = pubkeyScriptIndex.result
                val input = InputInfo(OutPoint(delayedOutputTx, outputIndex.toLong()), delayedOutputTx.txOut[outputIndex], ByteVector(Script.write(redeemScript)))
                // unsigned transaction
                val tx = Transaction(
                    version = 2,
                    txIn = listOf(TxIn(input.outPoint, ByteVector.empty, toLocalDelay.toLong())),
                    txOut = listOf(TxOut(0.sat, localFinalScriptPubKey)),
                    lockTime = 0
                )
                // compute weight with a dummy 73 bytes signature (the largest you can get)
                val weight = addSigs(TransactionWithInputInfo.ClaimLocalDelayedOutputTx(input, tx), PlaceHolderSig).tx.weight()
                val fee = weight2fee(feerate, weight)
                val amount = input.txOut.amount - fee
                if (amount < localDustLimit) {
                    TxResult.Skipped(TxGenerationSkipped.AmountBelowDustLimit)
                } else {
                    val tx1 = tx.copy(txOut = listOf(tx.txOut.first().copy(amount = amount)))
                    TxResult.Success(TransactionWithInputInfo.ClaimLocalDelayedOutputTx(input, tx1))
                }
            }
        }
    }

    fun makeClaimDelayedOutputPenaltyTxs(
        delayedOutputTx: Transaction,
        localDustLimit: Satoshi,
        localRevocationPubkey: PublicKey,
        toLocalDelay: CltvExpiryDelta,
        localDelayedPaymentPubkey: PublicKey,
        localFinalScriptPubKey: ByteArray,
        feerate: FeeratePerKw
    ): List<TxResult<TransactionWithInputInfo.ClaimHtlcDelayedOutputPenaltyTx>> {
        val redeemScript = Scripts.toLocalDelayed(localRevocationPubkey, toLocalDelay, localDelayedPaymentPubkey)
        val pubkeyScript = Script.write(Script.pay2wsh(redeemScript))
        return when (val pubkeyScriptIndexes = findPubKeyScriptIndexes(delayedOutputTx, pubkeyScript)) {
            is TxResult.Skipped -> listOf(TxResult.Skipped(pubkeyScriptIndexes.why))
            is TxResult.Success -> pubkeyScriptIndexes.result.map { outputIndex ->
                val input = InputInfo(OutPoint(delayedOutputTx, outputIndex.toLong()), delayedOutputTx.txOut[outputIndex], ByteVector(Script.write(redeemScript)))
                // unsigned transaction
                val tx = Transaction(
                    version = 2,
                    txIn = listOf(TxIn(input.outPoint, ByteVector.empty, 0xffffffffL)),
                    txOut = listOf(TxOut(0.sat, localFinalScriptPubKey)),
                    lockTime = 0
                )
                // compute weight with a dummy 73 bytes signature (the largest you can get)
                val weight = addSigs(TransactionWithInputInfo.ClaimHtlcDelayedOutputPenaltyTx(input, tx), PlaceHolderSig).tx.weight()
                val fee = weight2fee(feerate, weight)
                val amount = input.txOut.amount - fee
                if (amount < localDustLimit) {
                    TxResult.Skipped(TxGenerationSkipped.AmountBelowDustLimit)
                } else {
                    val tx1 = tx.copy(txOut = listOf(tx.txOut.first().copy(amount = amount)))
                    TxResult.Success(TransactionWithInputInfo.ClaimHtlcDelayedOutputPenaltyTx(input, tx1))
                }
            }
        }
    }

    fun makeMainPenaltyTx(
        commitTx: Transaction,
        localDustLimit: Satoshi,
        remoteRevocationPubkey: PublicKey,
        localFinalScriptPubKey: ByteArray,
        toRemoteDelay: CltvExpiryDelta,
        remoteDelayedPaymentPubkey: PublicKey,
        feerate: FeeratePerKw
    ): TxResult<TransactionWithInputInfo.MainPenaltyTx> {
        val redeemScript = Scripts.toLocalDelayed(remoteRevocationPubkey, toRemoteDelay, remoteDelayedPaymentPubkey)
        val pubkeyScript = Script.write(Script.pay2wsh(redeemScript))
        return when (val pubkeyScriptIndex = findPubKeyScriptIndex(commitTx, pubkeyScript)) {
            is TxResult.Skipped -> TxResult.Skipped(pubkeyScriptIndex.why)
            is TxResult.Success -> {
                val outputIndex = pubkeyScriptIndex.result
                val input = InputInfo(OutPoint(commitTx, outputIndex.toLong()), commitTx.txOut[outputIndex], ByteVector(Script.write(redeemScript)))
                // unsigned transaction
                val tx = Transaction(
                    version = 2,
                    txIn = listOf(TxIn(input.outPoint, ByteVector.empty, 0xffffffffL)),
                    txOut = listOf(TxOut(0.sat, localFinalScriptPubKey)),
                    lockTime = 0
                )
                // compute weight with a dummy 73 bytes signature (the largest you can get)
                val weight = addSigs(TransactionWithInputInfo.MainPenaltyTx(input, tx), PlaceHolderSig).tx.weight()
                val fee = weight2fee(feerate, weight)
                val amount = input.txOut.amount - fee
                if (amount < localDustLimit) {
                    TxResult.Skipped(TxGenerationSkipped.AmountBelowDustLimit)
                } else {
                    val tx1 = tx.copy(txOut = listOf(tx.txOut.first().copy(amount = amount)))
                    TxResult.Success(TransactionWithInputInfo.MainPenaltyTx(input, tx1))
                }
            }
        }
    }

    /**
     * We already have the redeemScript, no need to build it
     */
    fun makeHtlcPenaltyTx(
        commitTx: Transaction,
        htlcOutputIndex: Int,
        redeemScript: ByteArray,
        localDustLimit: Satoshi,
        localFinalScriptPubKey: ByteArray,
        feerate: FeeratePerKw
    ): TxResult<TransactionWithInputInfo.HtlcPenaltyTx> {
        val input = InputInfo(OutPoint(commitTx, htlcOutputIndex.toLong()), commitTx.txOut[htlcOutputIndex], ByteVector(redeemScript))
        // unsigned transaction
        val tx = Transaction(
            version = 2,
            txIn = listOf(TxIn(input.outPoint, ByteVector.empty, 0xffffffffL)),
            txOut = listOf(TxOut(0.sat, localFinalScriptPubKey)),
            lockTime = 0
        )
        // compute weight with a dummy 73 bytes signature (the largest you can get)
        val weight = addSigs(TransactionWithInputInfo.MainPenaltyTx(input, tx), PlaceHolderSig).tx.weight()
        val fee = weight2fee(feerate, weight)
        val amount = input.txOut.amount - fee
        return if (amount < localDustLimit) {
            TxResult.Skipped(TxGenerationSkipped.AmountBelowDustLimit)
        } else {
            val tx1 = tx.copy(txOut = listOf(tx.txOut.first().copy(amount = amount)))
            TxResult.Success(TransactionWithInputInfo.HtlcPenaltyTx(input, tx1))
        }
    }

    fun makeClosingTxs(input: InputInfo, spec: CommitmentSpec, fee: ClosingTxFee, lockTime: Long, localScriptPubKey: ByteVector, remoteScriptPubKey: ByteVector): ClosingTxs {
        require(spec.htlcs.isEmpty()) { "there shouldn't be any pending htlcs" }

        val txNoOutput = Transaction(2, listOf(TxIn(input.outPoint, listOf(), sequence = 0xFFFFFFFDL)), listOf(), lockTime)

        // We compute the remaining balance for each side after paying the closing fees.
        // This lets us decide whether outputs can be included in the closing transaction or not.
        val (toLocalAmount, toRemoteAmount) = when (fee) {
            is ClosingTxFee.PaidByUs -> Pair(spec.toLocal.truncateToSatoshi() - fee.fee, spec.toRemote.truncateToSatoshi())
            is ClosingTxFee.PaidByThem -> Pair(spec.toLocal.truncateToSatoshi(), spec.toRemote.truncateToSatoshi() - fee.fee)
        }
        val toLocalOutput = when {
            toLocalAmount >= dustLimit(localScriptPubKey) -> TxOut(if (isOpReturn(localScriptPubKey)) 0.sat else toLocalAmount, localScriptPubKey)
            else -> null
        }
        val toRemoteOutput = when {
            toRemoteAmount >= dustLimit(remoteScriptPubKey) -> TxOut(if (isOpReturn(remoteScriptPubKey)) 0.sat else toRemoteAmount, remoteScriptPubKey)
            else -> null
        }
        // We may create multiple closing transactions based on which outputs may be included.
        return when {
            toLocalOutput != null && toRemoteOutput != null -> {
                val txLocalAndRemote = LexicographicalOrdering.sort(txNoOutput.copy(txOut = listOf(toLocalOutput, toRemoteOutput)))
                val toLocalIndex = when (val i = findPubKeyScriptIndex(txLocalAndRemote, localScriptPubKey.toByteArray())) {
                    is TxResult.Skipped -> null
                    is TxResult.Success -> i.result
                }
                ClosingTxs(
                    localAndRemote = TransactionWithInputInfo.ClosingTx(input, txLocalAndRemote, toLocalIndex),
                    // We also provide a version of the transaction without the remote output, which they may want to omit if not economical to spend.
                    localOnly = TransactionWithInputInfo.ClosingTx(input, txNoOutput.copy(txOut = listOf(toLocalOutput)), 0),
                    remoteOnly = null
                )
            }
            toLocalOutput != null -> ClosingTxs(
                localAndRemote = null,
                localOnly = TransactionWithInputInfo.ClosingTx(input, txNoOutput.copy(txOut = listOf(toLocalOutput)), 0),
                remoteOnly = null,
            )
            toRemoteOutput != null -> ClosingTxs(
                localAndRemote = null,
                localOnly = null,
                remoteOnly = TransactionWithInputInfo.ClosingTx(input, txNoOutput.copy(txOut = listOf(toRemoteOutput)), null)
            )
            else -> ClosingTxs(localAndRemote = null, localOnly = null, remoteOnly = null)
        }
    }

    private fun findPubKeyScriptIndex(tx: Transaction, pubkeyScript: ByteArray): TxResult<Int> {
        val outputIndex = tx.txOut.indexOfFirst { txOut -> txOut.publicKeyScript.contentEquals(pubkeyScript) }
        return if (outputIndex >= 0) {
            TxResult.Success(outputIndex)
        } else {
            TxResult.Skipped(TxGenerationSkipped.OutputNotFound)
        }
    }

    private fun findPubKeyScriptIndexes(tx: Transaction, pubkeyScript: ByteArray): TxResult<List<Int>> {
        val outputIndexes = tx.txOut.withIndex().filter { it.value.publicKeyScript.contentEquals(pubkeyScript) }.map { it.index }
        return if (outputIndexes.isNotEmpty()) {
            TxResult.Success(outputIndexes)
        } else {
            TxResult.Skipped(TxGenerationSkipped.OutputNotFound)
        }
    }

    /**
     * Default public key used for fee estimation
     */
    val PlaceHolderPubKey = PrivateKey(ByteVector32.One).publicKey()

    /**
     * This default sig takes 72B when encoded in DER (incl. 1B for the trailing sig hash), it is used for fee estimation
     * It is 72 bytes because our signatures are normalized (low-s) and will take up 72 bytes at most in DER format
     */
    val PlaceHolderSig = ByteVector64(ByteArray(64) { 0xaa.toByte() })
        .also { check(Scripts.der(it, SigHash.SIGHASH_ALL).size() == 72) { "Should be 72 bytes but is ${Scripts.der(it, SigHash.SIGHASH_ALL).size()} bytes" } }

    fun sign(tx: Transaction, inputIndex: Int, redeemScript: ByteArray, amount: Satoshi, key: PrivateKey, sigHash: Int = SigHash.SIGHASH_ALL): ByteVector64 {
        val sigDER = tx.signInput(inputIndex, redeemScript, sigHash, amount, SigVersion.SIGVERSION_WITNESS_V0, key)
        return Crypto.der2compact(sigDER)
    }

    fun sign(txInfo: TransactionWithInputInfo, key: PrivateKey, sigHash: Int = SigHash.SIGHASH_ALL): ByteVector64 {
        val inputIndex = txInfo.tx.txIn.indexOfFirst { it.outPoint == txInfo.input.outPoint }
        require(inputIndex >= 0) { "transaction doesn't spend the input to sign" }
        return sign(txInfo.tx, inputIndex, txInfo.input.redeemScript.toByteArray(), txInfo.input.txOut.amount, key, sigHash)
    }

    fun addSigs(
        commitTx: TransactionWithInputInfo.CommitTx,
        localFundingPubkey: PublicKey,
        remoteFundingPubkey: PublicKey,
        localSig: ByteVector64,
        remoteSig: ByteVector64
    ): TransactionWithInputInfo.CommitTx {
        val witness = Scripts.witness2of2(localSig, remoteSig, localFundingPubkey, remoteFundingPubkey)
        return commitTx.copy(tx = commitTx.tx.updateWitness(0, witness))
    }

    fun addSigs(mainPenaltyTx: TransactionWithInputInfo.MainPenaltyTx, revocationSig: ByteVector64): TransactionWithInputInfo.MainPenaltyTx {
        val witness = Scripts.witnessToLocalDelayedWithRevocationSig(revocationSig, mainPenaltyTx.input.redeemScript)
        return mainPenaltyTx.copy(tx = mainPenaltyTx.tx.updateWitness(0, witness))
    }

    fun addSigs(htlcPenaltyTx: TransactionWithInputInfo.HtlcPenaltyTx, revocationSig: ByteVector64, revocationPubkey: PublicKey): TransactionWithInputInfo.HtlcPenaltyTx {
        val witness = Scripts.witnessHtlcWithRevocationSig(revocationSig, revocationPubkey, htlcPenaltyTx.input.redeemScript)
        return htlcPenaltyTx.copy(tx = htlcPenaltyTx.tx.updateWitness(0, witness))
    }

    fun addSigs(htlcSuccessTx: TransactionWithInputInfo.HtlcTx.HtlcSuccessTx, localSig: ByteVector64, remoteSig: ByteVector64, paymentPreimage: ByteVector32): TransactionWithInputInfo.HtlcTx.HtlcSuccessTx {
        val witness = Scripts.witnessHtlcSuccess(localSig, remoteSig, paymentPreimage, htlcSuccessTx.input.redeemScript)
        return htlcSuccessTx.copy(tx = htlcSuccessTx.tx.updateWitness(0, witness))
    }

    fun addSigs(htlcTimeoutTx: TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx, localSig: ByteVector64, remoteSig: ByteVector64): TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx {
        val witness = Scripts.witnessHtlcTimeout(localSig, remoteSig, htlcTimeoutTx.input.redeemScript)
        return htlcTimeoutTx.copy(tx = htlcTimeoutTx.tx.updateWitness(0, witness))
    }

    fun addSigs(claimHtlcSuccessTx: TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcSuccessTx, localSig: ByteVector64, paymentPreimage: ByteVector32): TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcSuccessTx {
        val witness = Scripts.witnessClaimHtlcSuccessFromCommitTx(localSig, paymentPreimage, claimHtlcSuccessTx.input.redeemScript)
        return claimHtlcSuccessTx.copy(tx = claimHtlcSuccessTx.tx.updateWitness(0, witness))
    }

    fun addSigs(claimHtlcTimeoutTx: TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx, localSig: ByteVector64): TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx {
        val witness = Scripts.witnessClaimHtlcTimeoutFromCommitTx(localSig, claimHtlcTimeoutTx.input.redeemScript)
        return claimHtlcTimeoutTx.copy(tx = claimHtlcTimeoutTx.tx.updateWitness(0, witness))
    }

    fun addSigs(claimRemoteDelayed: TransactionWithInputInfo.ClaimRemoteCommitMainOutputTx.ClaimRemoteDelayedOutputTx, localSig: ByteVector64): TransactionWithInputInfo.ClaimRemoteCommitMainOutputTx.ClaimRemoteDelayedOutputTx {
        val witness = Scripts.witnessToRemoteDelayedAfterDelay(localSig, claimRemoteDelayed.input.redeemScript)
        return claimRemoteDelayed.copy(tx = claimRemoteDelayed.tx.updateWitness(0, witness))
    }

    fun addSigs(claimLocalDelayed: TransactionWithInputInfo.ClaimLocalDelayedOutputTx, localSig: ByteVector64): TransactionWithInputInfo.ClaimLocalDelayedOutputTx {
        val witness = Scripts.witnessToLocalDelayedAfterDelay(localSig, claimLocalDelayed.input.redeemScript)
        return claimLocalDelayed.copy(tx = claimLocalDelayed.tx.updateWitness(0, witness))
    }

    fun addSigs(claimHtlcDelayedPenalty: TransactionWithInputInfo.ClaimHtlcDelayedOutputPenaltyTx, revocationSig: ByteVector64): TransactionWithInputInfo.ClaimHtlcDelayedOutputPenaltyTx {
        val witness = Scripts.witnessToLocalDelayedWithRevocationSig(revocationSig, claimHtlcDelayedPenalty.input.redeemScript)
        return claimHtlcDelayedPenalty.copy(tx = claimHtlcDelayedPenalty.tx.updateWitness(0, witness))
    }

    fun addSigs(closingTx: TransactionWithInputInfo.ClosingTx, localFundingPubkey: PublicKey, remoteFundingPubkey: PublicKey, localSig: ByteVector64, remoteSig: ByteVector64): TransactionWithInputInfo.ClosingTx {
        val witness = Scripts.witness2of2(localSig, remoteSig, localFundingPubkey, remoteFundingPubkey)
        return closingTx.copy(tx = closingTx.tx.updateWitness(0, witness))
    }

    fun checkSpendable(txinfo: TransactionWithInputInfo): Try<Unit> = runTrying {
        txinfo.tx.correctlySpends(mapOf(txinfo.tx.txIn.first().outPoint to txinfo.input.txOut), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    fun checkSig(txinfo: TransactionWithInputInfo, sig: ByteVector64, pubKey: PublicKey, sigHash: Int = SigHash.SIGHASH_ALL): Boolean {
        val data = txinfo.tx.hashForSigning(0, txinfo.input.redeemScript.toByteArray(), sigHash, txinfo.input.txOut.amount, SigVersion.SIGVERSION_WITNESS_V0)
        return Crypto.verifySignature(data, sig, pubKey)
    }
}
