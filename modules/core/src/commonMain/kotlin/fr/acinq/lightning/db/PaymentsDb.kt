package fr.acinq.lightning.db

import fr.acinq.bitcoin.*
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.channel.ChannelManagementFees
import fr.acinq.lightning.payment.*
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.LiquidityAds

interface PaymentsDb : IncomingPaymentsDb, OutgoingPaymentsDb {
    /**
     * On-chain-related payments are not instant, but needs to be displayed as soon as possible to the user
     * for UX purposes. They affect the balance differently whether they are incoming or outgoing.
     *
     * For example, if a user initiates a swap-in, they will expect to see an incoming payment immediately in
     * their payment history, even if the amount isn't included in the balance and the funds are not spendable right
     * away. Conversely, after a swap-out, the balance is immediately decreased even if the transaction is not confirmed.
     *
     * Note that this is all related to transaction confirmations on the blockchain, but involves a bit more than
     * that, because both sides of the channel need to agree, and they may also agree to not require any confirmation.
     *
     * Incoming payments (channel creation or splice-in) are considered confirmed when the corresponding funds are added
     * to the balance and can be spent. Before that, they should appear as "pending" to the user.
     *
     * Outgoing payments (splice-out or channel close) are considered confirmed when the corresponding funding transaction
     * is confirmed on the blockchain. Before that, they should appear as "final" to the user, but with some indication that
     * the transaction is not yet confirmed. In the case of a force-close, the outgoing payment will only be considered confirmed
     * when the channel is closed, meaning that all related transactions have been confirmed.
     */
    suspend fun setLocked(txId: TxId)
}

interface IncomingPaymentsDb {

    /** Add a new expected incoming payment (not yet received). */
    suspend fun addIncomingPayment(incomingPayment: IncomingPayment)

    /** Get information about an incoming payment (paid or not) for the given payment hash, if any. */
    suspend fun getLightningIncomingPayment(paymentHash: ByteVector32): LightningIncomingPayment?

    /**
     * Mark an incoming payment as received (paid).
     * Note that this function assumes that there is a matching payment request in the DB, otherwise it will be a no-op.
     *
     * This method is additive:
     * - parts list is appended to the existing list in database.
     * - receivedAt must be updated in database.
     *
     * @param parts Is a list containing the payment parts holding the incoming amount.
     */
    suspend fun receiveLightningPayment(paymentHash: ByteVector32, parts: List<LightningIncomingPayment.Part>)

    /** List expired unpaid normal payments created within specified time range (with the most recent payments first). */
    suspend fun listLightningExpiredPayments(fromCreatedAt: Long = 0, toCreatedAt: Long = currentTimestampMillis()): List<LightningIncomingPayment>

    /** Remove a pending incoming payment.*/
    suspend fun removeLightningIncomingPayment(paymentHash: ByteVector32): Boolean
}

interface OutgoingPaymentsDb {
    /** Add a new pending outgoing payment (not yet settled). */
    suspend fun addOutgoingPayment(outgoingPayment: OutgoingPayment)

    /** Add new partial payments to a pending outgoing payment. */
    suspend fun addLightningOutgoingPaymentParts(parentId: UUID, parts: List<LightningOutgoingPayment.Part>)

    /** Get information about an outgoing payment (settled or not). */
    suspend fun getLightningOutgoingPayment(id: UUID): LightningOutgoingPayment?

    /** Get information about an outgoing payment from the id of one of its parts. */
    suspend fun getLightningOutgoingPaymentFromPartId(partId: UUID): LightningOutgoingPayment?

    /** Mark a lightning outgoing payment as completed. */
    suspend fun completeLightningOutgoingPayment(id: UUID, status: LightningOutgoingPayment.Status.Completed)

    /** Mark a lightning outgoing payment part as completed. */
    suspend fun completeLightningOutgoingPaymentPart(parentId: UUID, partId: UUID, status: LightningOutgoingPayment.Part.Status.Completed)

    /** Get information about a liquidity purchase (for which the funding transaction has been signed). */
    suspend fun getInboundLiquidityPurchase(fundingTxId: TxId): InboundLiquidityOutgoingPayment?

    /** List all the outgoing payment attempts that tried to pay the given payment hash. */
    suspend fun listLightningOutgoingPayments(paymentHash: ByteVector32): List<LightningOutgoingPayment>
}

/** A payment made to or from the wallet. */
sealed class WalletPayment {
    abstract val id: UUID

    /** Absolute time in milliseconds since UNIX epoch when the payment was created. */
    abstract val createdAt: Long

    /**
     * Absolute time in milliseconds since UNIX epoch when the payment was completed.
     * A completed payment is not necessarily successful. For example a Lightning
     * outgoing payment will be considered completed after all payment attempts
     * have been exhausted.
     */
    abstract val completedAt: Long?

    /** Absolute time in milliseconds since UNIX epoch when the payment succeeded. */
    abstract val succeededAt: Long?

    /** Fees applied to complete this payment. */
    abstract val fees: MilliSatoshi

    /**
     * The actual amount that has been sent or received:
     * - for outgoing payments, the fee is included. This is what left the wallet;
     * - for incoming payments, this is the amount AFTER the fees are applied. This is what went into the wallet.
     */
    abstract val amount: MilliSatoshi
}

sealed class IncomingPayment : WalletPayment() {
    /** Amount received for this part after applying the fees. This is the final amount we can use. */
    abstract val amountReceived: MilliSatoshi
    override val amount: MilliSatoshi get() = amountReceived
    /** A completed incoming payment is always successful. */
    override val succeededAt: Long? get() = completedAt
}

/**
 * An incoming payment received by this node.
 * At first it is in a pending state, then will become either a success (if we receive a matching payment) or a failure (if the payment request expires).
 *
 * @param paymentPreimage payment preimage, which acts as a proof-of-payment for the payer.
 */
sealed class LightningIncomingPayment(val paymentPreimage: ByteVector32) : IncomingPayment() {

    val paymentHash: ByteVector32 = Crypto.sha256(paymentPreimage).toByteVector32()

    override val id: UUID = UUID.fromBytes(paymentHash.toByteArray().copyOf(16))

    /** Funds received for this payment, empty if no funds have been received yet. */
    abstract val parts: List<Part>

    /** This timestamp will be defined when the received amount is usable for spending. */
    override val completedAt: Long? get() = parts.maxByOrNull { it.receivedAt }?.receivedAt

    /** Total fees paid to receive this payment. */
    override val fees: MilliSatoshi get() = parts.map { it.fees }.sum()

    /** Total amount actually received for this payment after applying the fees. If someone sent you 500 and the fee was 10, this amount will be 490. */
    override val amountReceived: MilliSatoshi get() = parts.map { it.amountReceived }.sum()

    sealed class Part {
        /** Amount received for this part after applying the fees. This is the final amount we can use. */
        abstract val amountReceived: MilliSatoshi

        /** Fees applied to receive this part.*/
        abstract val fees: MilliSatoshi

        abstract val receivedAt: Long

        /** Payment was received via existing lightning channels. */
        data class Htlc(override val amountReceived: MilliSatoshi, val channelId: ByteVector32, val htlcId: Long, val fundingFee: LiquidityAds.FundingFee?, override val receivedAt: Long = currentTimestampMillis()) : Part() {
            // If there is no funding fee, the fees are paid by the sender for lightning payments.
            override val fees: MilliSatoshi = fundingFee?.amount ?: 0.msat
        }

        /**
         * Payment was added to our fee credit for future on-chain operations (see [fr.acinq.lightning.Feature.FundingFeeCredit]).
         * We didn't really receive this amount yet, but we trust our peer to use it for future on-chain operations.
         */
        data class FeeCredit(override val amountReceived: MilliSatoshi, override val receivedAt: Long = currentTimestampMillis()) : Part() {
            // Adding to the fee credit doesn't cost any fees.
            override val fees: MilliSatoshi = 0.msat
        }
    }

    /** A payment expires if it is a [Bolt11IncomingPayment] and its invoice has expired. */
    fun isExpired(): Boolean = this is Bolt11IncomingPayment && this.paymentRequest.isExpired()

    /** Helper method to facilitate updating child classes */
    fun addReceivedParts(parts: List<Part>): LightningIncomingPayment {
        return when (this) {
            is Bolt11IncomingPayment -> copy(parts = this.parts + parts)
            is Bolt12IncomingPayment -> copy(parts = this.parts + parts)
        }
    }
}

/** A normal, Bolt11 invoice-based lightning payment. */
data class Bolt11IncomingPayment(
    private val preimage: ByteVector32,
    val paymentRequest: Bolt11Invoice,
    override val parts: List<Part> = emptyList(),
    override val createdAt: Long = currentTimestampMillis()
) : LightningIncomingPayment(preimage)

/** A payment for a Bolt 12 offer: note that we only keep a few fields from the corresponding Bolt 12 invoice. */
data class Bolt12IncomingPayment(
    private val preimage: ByteVector32,
    val metadata: OfferPaymentMetadata,
    override val parts: List<Part> = emptyList(),
    override val createdAt: Long = currentTimestampMillis()
) : LightningIncomingPayment(preimage)

/** Trustless swap-in (dual-funding or splice-in) */
sealed class OnChainIncomingPayment : IncomingPayment() {
    abstract override val id: UUID
    /** Fees paid to Lightning Service Provider for this on-chain transaction. */
    abstract val serviceFee: MilliSatoshi
    /** Feed paid to bitcoin miners for processing the on-chain operation. */
    abstract val miningFee: Satoshi
    override val fees: MilliSatoshi get() = serviceFee + miningFee.toMilliSatoshi()
    abstract val channelId: ByteVector32
    abstract val txId: TxId
    abstract val localInputs: Set<OutPoint>
    abstract val confirmedAt: Long?
    abstract val lockedAt: Long?
    /**
     * This timestamp will be defined when the received amount is usable for spending. The
     * associated transaction doesn't necessarily need to be confirmed (if zero-conf is
     * used), but both sides have to agree that the funds are usable, a.k.a. "locked".
     */
    override val completedAt: Long? get() = lockedAt

    /** Helper method to facilitate updating child classes */
    fun setLocked(lockedAt: Long): OnChainIncomingPayment =
        when (this) {
            is NewChannelIncomingPayment -> copy(lockedAt = lockedAt)
            is SpliceInIncomingPayment -> copy(lockedAt = lockedAt)
        }

    /** Helper method to facilitate updating child classes */
    fun setConfirmed(confirmedAt: Long): OnChainIncomingPayment =
        when (this) {
            is NewChannelIncomingPayment -> copy(confirmedAt = confirmedAt)
            is SpliceInIncomingPayment -> copy(confirmedAt = confirmedAt)
        }
}

/**
 * Payment was received via a new channel opened to us.
 *
 * @param amountReceived Our side of the balance of this channel when it's created. This is the amount received after the creation fees are applied.
 */
data class NewChannelIncomingPayment(
    override val id: UUID,
    override val amountReceived: MilliSatoshi,
    override val serviceFee: MilliSatoshi,
    override val miningFee: Satoshi,
    override val channelId: ByteVector32,
    override val txId: TxId,
    override val localInputs: Set<OutPoint>,
    override val createdAt: Long,
    override val confirmedAt: Long?,
    override val lockedAt: Long?
) : OnChainIncomingPayment()

/** Payment was received by splicing on-chain local funds into an existing channel. */
data class SpliceInIncomingPayment(
    override val id: UUID,
    override val amountReceived: MilliSatoshi,
    override val miningFee: Satoshi,
    override val channelId: ByteVector32,
    override val txId: TxId,
    override val localInputs: Set<OutPoint>,
    override val createdAt: Long,
    override val confirmedAt: Long?,
    override val lockedAt: Long?
) : OnChainIncomingPayment() {
    override val serviceFee: MilliSatoshi = 0.msat
}

@Deprecated("Legacy trusted swap-in, kept for backwards-compatibility with existing databases.")
data class LegacySwapInIncomingPayment(
    override val id: UUID,
    override val amountReceived: MilliSatoshi,
    override val fees: MilliSatoshi,
    val address: String?,
    override val createdAt: Long,
    override val completedAt: Long?
) : IncomingPayment()

@Deprecated("Legacy pay-to-open/pay-to-splice, kept for backwards-compatibility with existing databases. Those payments can be a mix of lightning parts and on-chain parts, and either Bolt11 or Bolt12.")
data class LegacyPayToOpenIncomingPayment(
    val paymentPreimage: ByteVector32,
    val origin: Origin,
    val parts: List<Part>,
    override val createdAt: Long,
    override val completedAt: Long?
) : IncomingPayment() {
    val paymentHash: ByteVector32 = Crypto.sha256(paymentPreimage).toByteVector32()
    override val id: UUID = UUID.fromBytes(paymentHash.toByteArray().copyOf(16))
    override val amountReceived: MilliSatoshi = parts.map { it.amountReceived }.sum()
    override val fees: MilliSatoshi = parts.filterIsInstance<Part.OnChain>().map { it.serviceFee + it.miningFee.toMilliSatoshi() }.sum()
    sealed class Origin {
        data class Invoice(val paymentRequest: Bolt11Invoice) : Origin()
        data class Offer(val metadata: OfferPaymentMetadata) : Origin()
    }
    sealed class Part {
        abstract val amountReceived: MilliSatoshi
        data class Lightning(override val amountReceived: MilliSatoshi, val channelId: ByteVector32, val htlcId: Long) : Part()
        data class OnChain(override val amountReceived: MilliSatoshi, val serviceFee: MilliSatoshi, val miningFee: Satoshi, val channelId: ByteVector32, val txId: TxId, val confirmedAt: Long?, val lockedAt: Long?) : Part()
    }
}

sealed class OutgoingPayment : WalletPayment()

/**
 * An outgoing payment sent by this node.
 * The payment may be split in multiple parts, which may fail, be retried, and then either succeed or fail.
 *
 * @param id internal payment identifier.
 * @param recipientAmount total amount that will be received by the final recipient.
 *          Note that, depending on the type of the payment, it may or may not contain the fees. See the `amount` and `fees` fields for details.
 * @param recipient final recipient nodeId.
 * @param details details that depend on the payment type (normal payments, swaps, etc).
 * @param parts list of partial child payments that have actually been sent.
 * @param status current status of the payment.
 */
@Suppress("DEPRECATION")
data class LightningOutgoingPayment(
    override val id: UUID,
    val recipientAmount: MilliSatoshi,
    val recipient: PublicKey,
    val details: Details,
    val parts: List<Part> = listOf(),
    val status: Status = Status.Pending,
    override val createdAt: Long = currentTimestampMillis()
) : OutgoingPayment() {

    val paymentHash: ByteVector32 = details.paymentHash

    @Suppress("MemberVisibilityCanBePrivate")
    val routingFee = parts.filter { it.status is Part.Status.Succeeded }.map { it.amount }.sum() - recipientAmount

    override val completedAt: Long? = (status as? Status.Completed)?.completedAt

    override val succeededAt: Long? = (status as? Status.Succeeded)?.completedAt

    /** This is the total fees that have been paid to make the payment work. It includes the LN routing fees, the fee for the swap-out service, the mining fees for closing a channel. */
    override val fees: MilliSatoshi = when (status) {
        is Status.Pending -> 0.msat
        is Status.Failed -> 0.msat
        is Status.Succeeded -> {
            if (details is Details.SwapOut) {
                // The swap-out service takes a fee to cover the miner fee. It's the difference between what we paid the service (recipientAmount) and what goes to the address.
                // We also include the routing fee, in case the swap-service is NOT the trampoline node.
                details.swapOutFee.toMilliSatoshi() + routingFee
            } else {
                routingFee
            }
        }
    }

    /** Amount that actually left the wallet. It does include the fees. */
    override val amount: MilliSatoshi = when (details) {
        // For a swap-out, recipientAmount is the amount paid to the swap service. It contains the swap-out fee, but not the routing fee.
        is Details.SwapOut -> recipientAmount + routingFee
        else -> recipientAmount + fees
    }

    sealed class Details {
        abstract val paymentRequest: PaymentRequest
        abstract val paymentHash: ByteVector32

        /** A normal lightning payment. */
        data class Normal(override val paymentRequest: Bolt11Invoice) : Details() {
            override val paymentHash: ByteVector32 = paymentRequest.paymentHash
        }

        /** A blinded lightning payment. */
        data class Blinded(override val paymentRequest: Bolt12Invoice, val payerKey: PrivateKey) : Details() {
            override val paymentHash: ByteVector32 = paymentRequest.paymentHash
        }

        /**
         * Backward compatibility code for legacy trusted swap-out.
         * Swap-out payments send a lightning payment to a swap server, which will send an on-chain transaction to a given address.
         * The swap-out fee is taken by the swap server to cover the miner fee.
         */
        @Deprecated("Legacy trusted swap-out, kept for backwards-compatibility with existing databases.")
        data class SwapOut(val address: String, override val paymentRequest: PaymentRequest, val swapOutFee: Satoshi) : Details() {
            override val paymentHash: ByteVector32 = paymentRequest.paymentHash
        }
    }

    sealed class Status {
        data object Pending : Status()
        sealed class Completed : Status() {
            abstract val completedAt: Long
        }

        data class Succeeded(val preimage: ByteVector32, override val completedAt: Long = currentTimestampMillis()) : Completed()
        data class Failed(val reason: FinalFailure, override val completedAt: Long = currentTimestampMillis()) : Completed()
    }

    /**
     * A child payment sent by this node (partial payment of the total amount). This payment has a status and can fail.
     *
     * @param id internal payment identifier.
     * @param amount amount sent, including fees.
     * @param route payment route used.
     * @param status current status of the payment.
     * @param createdAt absolute time in milliseconds since UNIX epoch when the payment was created.
     */
    data class Part(
        val id: UUID,
        val amount: MilliSatoshi,
        val route: List<HopDesc>,
        val status: Status,
        val createdAt: Long = currentTimestampMillis()
    ) {
        data class HopDesc(val nodeId: PublicKey, val nextNodeId: PublicKey, val shortChannelId: ShortChannelId? = null) {
            override fun toString(): String = when (shortChannelId) {
                null -> "$nodeId->$nextNodeId"
                else -> "$nodeId->$shortChannelId->$nextNodeId"
            }
        }

        sealed class Status {
            data object Pending : Status()
            sealed class Completed : Status() {
                abstract val completedAt: Long
            }

            data class Succeeded(val preimage: ByteVector32, override val completedAt: Long = currentTimestampMillis()) : Completed()
            data class Failed(val failure: Failure, override val completedAt: Long = currentTimestampMillis()) : Completed() {

                /**
                 * User-friendly payment part failure reason, whenever possible.
                 * Applications should define their own localized message for each of these failure cases.
                 */
                sealed class Failure {
                    // @formatter:off
                    /** The payment is too small: try sending a larger amount. */
                    data object PaymentAmountTooSmall : Failure() { override fun toString(): String = "the payment amount is too small" }
                    /** The user has sufficient balance, but the payment is too big: try sending a smaller amount. */
                    data object PaymentAmountTooBig : Failure() { override fun toString(): String = "the payment amount is too large" }
                    /** The user doesn't have sufficient balance: try sending a smaller amount. */
                    data object NotEnoughFunds : Failure() { override fun toString(): String = "not enough funds" }
                    /** The payment must be retried with more fees to reach the recipient. */
                    data object NotEnoughFees : Failure() { override fun toString(): String = "routing fees are insufficient" }
                    /** The payment expiry specified by the recipient is too far away in the future. */
                    data object PaymentExpiryTooBig : Failure() { override fun toString(): String = "the payment expiry is too far in the future" }
                    /** There are too many pending payments: wait for them to settle and retry. */
                    data object TooManyPendingPayments : Failure() { override fun toString(): String = "too many pending payments" }
                    /** Payments are temporarily paused while a channel is splicing: the payment can be retried after the splice. */
                    data object ChannelIsSplicing : Failure() { override fun toString(): String = "a splicing operation is in progress" }
                    /** The channel is closing: another channel should be created to send the payment. */
                    data object ChannelIsClosing : Failure() { override fun toString(): String = "channel closing is in progress" }
                    /** Remote failure from an intermediate node in the payment route. */
                    sealed class RouteFailure : Failure()
                    /** A remote node had a temporary failure: the payment may succeed if retried. */
                    data object TemporaryRemoteFailure : RouteFailure() { override fun toString(): String = "a node in the route had a temporary failure" }
                    /** The payment amount could not be relayed to the recipient, most likely because they don't have enough inbound liquidity. */
                    data object RecipientLiquidityIssue : RouteFailure() { override fun toString(): String = "liquidity issue at the recipient node" }
                    /** The payment recipient is offline and could not accept the payment. */
                    data object RecipientIsOffline : RouteFailure() { override fun toString(): String = "recipient node is offline or unreachable" }
                    /** The payment recipient received the payment but rejected it. */
                    data object RecipientRejectedPayment : Failure() { override fun toString(): String = "recipient node rejected the payment" }
                    /** This is an error that cannot be easily interpreted: we don't know what exactly went wrong and cannot correctly inform the user. */
                    data class Uninterpretable(val message: String) : Failure() { override fun toString(): String = message }
                    // @formatter:on
                }
            }
        }
    }
}

sealed class OnChainOutgoingPayment : OutgoingPayment() {
    abstract override val id: UUID
    abstract val miningFees: Satoshi
    abstract val channelId: ByteVector32
    abstract val txId: TxId
    abstract override val createdAt: Long
    abstract val confirmedAt: Long?
    abstract val lockedAt: Long?
    override val completedAt: Long? get() = lockedAt
    override val succeededAt: Long? get() = lockedAt

    /** Helper method to facilitate updating child classes */
    fun setLocked(lockedAt: Long): OnChainOutgoingPayment =
        when (this) {
            is SpliceOutgoingPayment -> copy(lockedAt = lockedAt)
            is SpliceCpfpOutgoingPayment -> copy(lockedAt = lockedAt)
            is InboundLiquidityOutgoingPayment -> copy(lockedAt = lockedAt)
            is ChannelCloseOutgoingPayment -> copy(lockedAt = lockedAt)
        }

    /** Helper method to facilitate updating child classes */
    fun setConfirmed(confirmedAt: Long): OnChainOutgoingPayment =
        when (this) {
            is SpliceOutgoingPayment -> copy(confirmedAt = confirmedAt)
            is SpliceCpfpOutgoingPayment -> copy(confirmedAt = confirmedAt)
            is InboundLiquidityOutgoingPayment -> copy(confirmedAt = confirmedAt)
            is ChannelCloseOutgoingPayment -> copy(confirmedAt = confirmedAt)
        }
}

data class SpliceOutgoingPayment(
    override val id: UUID,
    val recipientAmount: Satoshi,
    val address: String,
    override val miningFees: Satoshi,
    override val channelId: ByteVector32,
    override val txId: TxId,
    override val createdAt: Long,
    override val confirmedAt: Long?,
    override val lockedAt: Long?,
) : OnChainOutgoingPayment() {
    override val amount: MilliSatoshi = (recipientAmount + miningFees).toMilliSatoshi()
    override val fees: MilliSatoshi = miningFees.toMilliSatoshi()
}

data class SpliceCpfpOutgoingPayment(
    override val id: UUID,
    override val miningFees: Satoshi,
    override val channelId: ByteVector32,
    override val txId: TxId,
    override val createdAt: Long,
    override val confirmedAt: Long?,
    override val lockedAt: Long?,
) : OnChainOutgoingPayment() {
    override val amount: MilliSatoshi = miningFees.toMilliSatoshi()
    override val fees: MilliSatoshi = miningFees.toMilliSatoshi()
}

data class InboundLiquidityOutgoingPayment(
    override val id: UUID,
    override val channelId: ByteVector32,
    override val txId: TxId,
    val localMiningFees: Satoshi,
    val purchase: LiquidityAds.Purchase,
    override val createdAt: Long,
    override val confirmedAt: Long?,
    override val lockedAt: Long?,
) : OnChainOutgoingPayment() {
    override val miningFees: Satoshi = localMiningFees + purchase.fees.miningFee
    val serviceFees: Satoshi = purchase.fees.serviceFee
    override val fees: MilliSatoshi = (localMiningFees + purchase.fees.total).toMilliSatoshi()
    override val amount: MilliSatoshi = fees
    val fundingFee: LiquidityAds.FundingFee = LiquidityAds.FundingFee(purchase.fees.total.toMilliSatoshi(), txId)
    /**
     * Even in the "from future htlc" case the mining fee corresponding to the previous channel output
     * will be paid immediately from the channel balance, except if there is no channel.
     *
     * In the "from future htlc case", this inbound liquidity purchase is going to be followed by one or several [IncomingPayment.ReceivedWith.LightningPayment]
     * with a non-null [LiquidityAds.FundingFee] where [LiquidityAds.FundingFee.fundingTxId] matches this [InboundLiquidityOutgoingPayment.txId].
     * The sum of [LiquidityAds.FundingFee.amount] will match [InboundLiquidityOutgoingPayment.feePaidFromFutureHtlc].
     */
    val feePaidFromChannelBalance = when (purchase.paymentDetails.paymentType) {
        is LiquidityAds.PaymentType.FromChannelBalance -> ChannelManagementFees(miningFee = miningFees, serviceFee = purchase.fees.serviceFee)
        is LiquidityAds.PaymentType.FromChannelBalanceForFutureHtlc -> ChannelManagementFees(miningFee = miningFees, serviceFee = purchase.fees.serviceFee)
        is LiquidityAds.PaymentType.FromFutureHtlc -> ChannelManagementFees(miningFee = miningFees - purchase.fees.miningFee, serviceFee = 0.sat)
        is LiquidityAds.PaymentType.FromFutureHtlcWithPreimage -> ChannelManagementFees(miningFee = miningFees - purchase.fees.miningFee, serviceFee = 0.sat)
        is LiquidityAds.PaymentType.Unknown -> TODO()
    }
    val feePaidFromFutureHtlc = when (purchase.paymentDetails.paymentType) {
        is LiquidityAds.PaymentType.FromChannelBalance -> ChannelManagementFees(miningFee = 0.sat, serviceFee = 0.sat)
        is LiquidityAds.PaymentType.FromChannelBalanceForFutureHtlc -> ChannelManagementFees(miningFee = 0.sat, serviceFee = 0.sat)
        is LiquidityAds.PaymentType.FromFutureHtlc -> ChannelManagementFees(miningFee = purchase.fees.miningFee, serviceFee = purchase.fees.serviceFee)
        is LiquidityAds.PaymentType.FromFutureHtlcWithPreimage -> ChannelManagementFees(miningFee = purchase.fees.miningFee, serviceFee = purchase.fees.serviceFee)
        is LiquidityAds.PaymentType.Unknown -> TODO()
    }
    val feeCreditUsed = when (purchase) {
        is LiquidityAds.Purchase.WithFeeCredit -> purchase.feeCreditUsed
        else -> 0.msat
    }
}

data class ChannelCloseOutgoingPayment(
    override val id: UUID,
    val recipientAmount: Satoshi,
    val address: String,
    // The closingAddress may have been supplied by the user during a mutual close initiated by the user.
    // But in all other cases, the funds are sent to the default Phoenix address derived from the wallet seed.
    // So `isSentToDefaultAddress` means this default Phoenix address was used,
    // and is used by the UI to explain the situation to the user.
    val isSentToDefaultAddress: Boolean,
    override val miningFees: Satoshi,
    override val channelId: ByteVector32,
    override val txId: TxId,
    override val createdAt: Long,
    override val confirmedAt: Long?,
    override val lockedAt: Long?,
    val closingType: ChannelClosingType
) : OnChainOutgoingPayment() {
    enum class ChannelClosingType {
        Mutual, Local, Remote, Revoked, Other;
    }
    override val amount: MilliSatoshi = (recipientAmount + miningFees).toMilliSatoshi()
    override val fees: MilliSatoshi = miningFees.toMilliSatoshi()
}