package fr.acinq.lightning.payment

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.crypto.sphinx.Sphinx
import fr.acinq.lightning.db.*
import fr.acinq.lightning.io.AddLiquidityForIncomingPayment
import fr.acinq.lightning.io.PeerCommand
import fr.acinq.lightning.io.SendOnTheFlyFundingMessage
import fr.acinq.lightning.io.WrappedChannelCommand
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.logging.mdc
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import kotlin.time.Duration

sealed class PaymentPart {
    abstract val amount: MilliSatoshi
    abstract val totalAmount: MilliSatoshi
    abstract val paymentHash: ByteVector32
    abstract val finalPayload: PaymentOnion.FinalPayload
    abstract val onionPacket: OnionRoutingPacket
}

data class HtlcPart(val htlc: UpdateAddHtlc, override val finalPayload: PaymentOnion.FinalPayload) : PaymentPart() {
    override val amount: MilliSatoshi = htlc.amountMsat
    override val totalAmount: MilliSatoshi = finalPayload.totalAmount
    override val paymentHash: ByteVector32 = htlc.paymentHash
    override val onionPacket: OnionRoutingPacket = htlc.onionRoutingPacket
    override fun toString(): String = "htlc(channelId=${htlc.channelId},id=${htlc.id})"
}

data class WillAddHtlcPart(val htlc: WillAddHtlc, override val finalPayload: PaymentOnion.FinalPayload) : PaymentPart() {
    override val amount: MilliSatoshi = htlc.amount
    override val totalAmount: MilliSatoshi = finalPayload.totalAmount
    override val paymentHash: ByteVector32 = htlc.paymentHash
    override val onionPacket: OnionRoutingPacket = htlc.finalPacket
    override fun toString(): String = "future-htlc(id=${htlc.id},amount=${htlc.amount})"
}

class IncomingPaymentHandler(val nodeParams: NodeParams, val db: PaymentsDb) {

    sealed class ProcessAddResult {
        abstract val actions: List<PeerCommand>

        data class Accepted(override val actions: List<PeerCommand>, val incomingPayment: LightningIncomingPayment, val parts: List<LightningIncomingPayment.Part>) : ProcessAddResult() {
            val amount = parts.map { it.amountReceived }.sum()
        }
        data class Rejected(override val actions: List<PeerCommand>, val incomingPayment: LightningIncomingPayment?) : ProcessAddResult()
        data class Pending(val incomingPayment: LightningIncomingPayment, val pendingPayment: PendingPayment, override val actions: List<PeerCommand> = listOf()) : ProcessAddResult()
    }

    /**
     * We support receiving multipart payments, where an incoming payment will be split across multiple partial payments.
     * When we receive the first part, we need to start a timer: if we don't receive the rest of the payment before that
     * timer expires, we should fail the pending parts to avoid locking up liquidity and allow the sender to retry.
     *
     * @param parts partial payments received.
     * @param totalAmount total amount that should be received.
     * @param startedAtSeconds time at which we received the first partial payment (in seconds).
     */
    data class PendingPayment(val parts: Set<PaymentPart>, val totalAmount: MilliSatoshi, val startedAtSeconds: Long) {
        constructor(firstPart: PaymentPart) : this(setOf(firstPart), firstPart.totalAmount, currentTimestampSeconds())

        val amountReceived: MilliSatoshi = parts.map { it.amount }.sum()
        val fundingFee: MilliSatoshi = parts.filterIsInstance<HtlcPart>().map { it.htlc.fundingFee?.amount ?: 0.msat }.sum()

        fun add(part: PaymentPart): PendingPayment = copy(parts = parts + part)
    }

    private val logger = MDCLogger(nodeParams.loggerFactory.newLogger(this::class))
    private val pending = mutableMapOf<ByteVector32, PendingPayment>()
    private val privateKey = nodeParams.nodePrivateKey

    suspend fun createInvoice(
        paymentPreimage: ByteVector32,
        amount: MilliSatoshi?,
        description: Either<String, ByteVector32>,
        extraHops: List<List<Bolt11Invoice.TaggedField.ExtraHop>>,
        expiry: Duration? = null,
        timestampSeconds: Long = currentTimestampSeconds()
    ): Bolt11Invoice {
        val paymentHash = Crypto.sha256(paymentPreimage).toByteVector32()
        logger.debug(mapOf("paymentHash" to paymentHash)) { "using routing hints $extraHops" }
        val pr = Bolt11Invoice.create(
            nodeParams.chain,
            amount,
            paymentHash,
            nodeParams.nodePrivateKey,
            description,
            nodeParams.minFinalCltvExpiryDelta,
            nodeParams.features.invoiceFeatures(),
            randomBytes32(),
            // We always include a payment metadata in our invoices, which lets us test whether senders support it
            ByteVector("2a"),
            expiry?.inWholeSeconds,
            extraHops,
            timestampSeconds
        )
        logger.info(mapOf("paymentHash" to paymentHash)) { "generated payment request ${pr.write()}" }
        val incomingPayment = Bolt11IncomingPayment(paymentPreimage, pr)
        db.addIncomingPayment(incomingPayment)
        return pr
    }

    /** Process an incoming htlc. Before calling this, the htlc must be committed and ack-ed by both peers. */
    suspend fun process(htlc: UpdateAddHtlc, remoteFeatures: Features, currentBlockHeight: Int, currentFeerate: FeeratePerKw, remoteFundingRates: LiquidityAds.WillFundRates?, currentFeeCredit: MilliSatoshi = 0.msat): ProcessAddResult {
        return process(Either.Right(htlc), remoteFeatures, currentBlockHeight, currentFeerate, remoteFundingRates, currentFeeCredit)
    }

    /** Process an incoming on-the-fly funding request. */
    suspend fun process(htlc: WillAddHtlc, remoteFeatures: Features, currentBlockHeight: Int, currentFeerate: FeeratePerKw, remoteFundingRates: LiquidityAds.WillFundRates?, currentFeeCredit: MilliSatoshi = 0.msat): ProcessAddResult {
        return process(Either.Left(htlc), remoteFeatures, currentBlockHeight, currentFeerate, remoteFundingRates, currentFeeCredit)
    }

    private suspend fun process(
        htlc: Either<WillAddHtlc, UpdateAddHtlc>,
        remoteFeatures: Features,
        currentBlockHeight: Int,
        currentFeerate: FeeratePerKw,
        remoteFundingRates: LiquidityAds.WillFundRates?,
        currentFeeCredit: MilliSatoshi
    ): ProcessAddResult {
        // There are several checks we could perform *before* decrypting the onion.
        // But we need to carefully handle which error message is returned to prevent information leakage, so we always peel the onion first.
        return when (val res = toPaymentPart(privateKey, htlc)) {
            is Either.Left -> res.value
            is Either.Right -> processPaymentPart(res.value, remoteFeatures, currentBlockHeight, currentFeerate, remoteFundingRates, currentFeeCredit)
        }
    }

    /** Main payment processing, that handles payment parts. */
    private suspend fun processPaymentPart(
        paymentPart: PaymentPart,
        remoteFeatures: Features,
        currentBlockHeight: Int,
        currentFeerate: FeeratePerKw,
        remoteFundingRates: LiquidityAds.WillFundRates?,
        currentFeeCredit: MilliSatoshi
    ): ProcessAddResult {
        val logger = MDCLogger(logger.logger, staticMdc = paymentPart.mdc() + ("feeCredit" to currentFeeCredit))
        when (paymentPart) {
            is HtlcPart -> logger.info { "processing htlc part expiry=${paymentPart.htlc.cltvExpiry}" }
            is WillAddHtlcPart -> logger.info { "processing on-the-fly funding part amount=${paymentPart.amount} expiry=${paymentPart.htlc.expiry}" }
        }
        return when (val validationResult = validatePaymentPart(paymentPart, currentBlockHeight)) {
            is Either.Left -> validationResult.value
            is Either.Right -> {
                val incomingPayment = validationResult.value
                val receivedParts = incomingPayment.parts
                if (receivedParts.isNotEmpty()) {
                    return when (paymentPart) {
                        is HtlcPart -> {
                            // The invoice for this payment hash has already been paid. Two possible scenarios:
                            //
                            // 1) The htlc is a local replay emitted by a channel, but it has already been set as paid in the database.
                            //    This can happen when the wallet is stopped before the commands to fulfill htlcs have reached the channel. When the wallet restarts,
                            //    the channel will ask the handler to reprocess the htlc. So the htlc must be fulfilled again but the
                            //    payments database does not need to be updated.
                            //
                            // 2) This is a new htlc. This can happen when a sender pays an already paid invoice. In that case the
                            //    htlc can be safely rejected.
                            val htlcsMapInDb = receivedParts.filterIsInstance<LightningIncomingPayment.Part.Htlc>().map { it.channelId to it.htlcId }
                            if (htlcsMapInDb.contains(paymentPart.htlc.channelId to paymentPart.htlc.id)) {
                                logger.info { "accepting local replay of htlc=${paymentPart.htlc.id} on channel=${paymentPart.htlc.channelId}" }
                                val action = WrappedChannelCommand(paymentPart.htlc.channelId, ChannelCommand.Htlc.Settlement.Fulfill(paymentPart.htlc.id, incomingPayment.paymentPreimage, true))
                                ProcessAddResult.Accepted(listOf(action), incomingPayment, receivedParts)
                            } else {
                                logger.info { "rejecting htlc part for an invoice that has already been paid" }
                                val action = actionForFailureMessage(IncorrectOrUnknownPaymentDetails(paymentPart.totalAmount, currentBlockHeight.toLong()), paymentPart.htlc)
                                ProcessAddResult.Rejected(listOf(action), incomingPayment)
                            }
                        }
                        is WillAddHtlcPart -> {
                            logger.info { "rejecting on-the-fly funding part for an invoice that has already been paid" }
                            val action = actionForWillAddHtlcFailure(privateKey, IncorrectOrUnknownPaymentDetails(paymentPart.totalAmount, currentBlockHeight.toLong()), paymentPart.htlc)
                            ProcessAddResult.Rejected(listOf(action), incomingPayment)
                        }
                    }
                } else {
                    val payment = pending[paymentPart.paymentHash]?.add(paymentPart) ?: PendingPayment(paymentPart)
                    return when {
                        paymentPart.totalAmount != payment.totalAmount -> {
                            // Bolt 04:
                            // - SHOULD fail the entire HTLC set if `total_msat` is not the same for all HTLCs in the set.
                            logger.warning { "invalid total_amount_msat: ${paymentPart.totalAmount}, expected ${payment.totalAmount}" }
                            val failure = IncorrectOrUnknownPaymentDetails(payment.totalAmount, currentBlockHeight.toLong())
                            rejectPayment(payment, incomingPayment, failure)
                        }
                        payment.amountReceived + payment.fundingFee < payment.totalAmount -> {
                            // Still waiting for more payments.
                            pending[paymentPart.paymentHash] = payment
                            ProcessAddResult.Pending(incomingPayment, payment)
                        }
                        else -> {
                            val htlcParts = payment.parts.filterIsInstance<HtlcPart>()
                            val willAddHtlcParts = payment.parts.filterIsInstance<WillAddHtlcPart>()
                            when {
                                payment.parts.size > nodeParams.maxAcceptedHtlcs -> {
                                    logger.warning { "rejecting on-the-fly funding: too many parts (${payment.parts.size} > ${nodeParams.maxAcceptedHtlcs}" }
                                    nodeParams._nodeEvents.emit(LiquidityEvents.Rejected(payment.amountReceived, 0.msat, LiquidityEvents.Source.OffChainPayment, LiquidityEvents.Rejected.Reason.TooManyParts(payment.parts.size)))
                                    rejectPayment(payment, incomingPayment, TemporaryNodeFailure)
                                }
                                willAddHtlcParts.isNotEmpty() -> when (val result = validateOnTheFlyFundingRate(willAddHtlcParts.map { it.amount }.sum(), remoteFeatures, currentFeeCredit, currentFeerate, remoteFundingRates)) {
                                    is Either.Left -> {
                                        logger.warning { "rejecting on-the-fly funding: reason=${result.value.reason}" }
                                        nodeParams._nodeEvents.emit(result.value)
                                        rejectPayment(payment, incomingPayment, TemporaryNodeFailure)
                                    }
                                    is Either.Right -> {
                                        val (requestedAmount, fundingRate) = result.value
                                        val addToFeeCredit = run {
                                            val featureOk = Features.canUseFeature(nodeParams.features, remoteFeatures, Feature.FundingFeeCredit)
                                            // We may need to use a higher feerate than the current value depending on whether this is a new channel or not,
                                            // and whether we have enough balance. We keep adding to our fee credit until we reach the worst case scenario
                                            // in terms of fees we need to pay, otherwise we may not have enough to actually pay the liquidity fees.
                                            val maxFeerate = currentFeerate * AddLiquidityForIncomingPayment.SpliceWithNoBalanceFeerateRatio
                                            val maxLiquidityFees = fundingRate.fees(maxFeerate, requestedAmount, requestedAmount, isChannelCreation = true).total.toMilliSatoshi()
                                            val maxFeeCredit = when (val policy = nodeParams.liquidityPolicy.value) {
                                                LiquidityPolicy.Disable -> 0.msat
                                                is LiquidityPolicy.Auto -> policy.maxAllowedFeeCredit
                                            }
                                            val nextFeeCredit = willAddHtlcParts.map { it.amount }.sum() + currentFeeCredit
                                            val cannotCoverLiquidityFees = nextFeeCredit <= maxLiquidityFees
                                            val isBelowMaxFeeCredit = nextFeeCredit <= maxFeeCredit
                                            val assessment = featureOk && cannotCoverLiquidityFees && isBelowMaxFeeCredit
                                            logger.info { "fee credit assessment: result=$assessment featureOk=$featureOk cannotCoverLiquidityFees=$cannotCoverLiquidityFees isBelowMaxFeeCredit=$isBelowMaxFeeCredit (nextFeeCredit=$nextFeeCredit, maxLiquidityFees=$maxLiquidityFees, maxFeeCredit=$maxFeeCredit)" }
                                            assessment
                                        }
                                        when {
                                            addToFeeCredit -> {
                                                logger.info { "adding on-the-fly funding to fee credit (amount=${willAddHtlcParts.map { it.amount }.sum()})" }
                                                val parts = buildList {
                                                    htlcParts.forEach { add(LightningIncomingPayment.Part.Htlc(it.amount, it.htlc.channelId, it.htlc.id, it.htlc.fundingFee)) }
                                                    willAddHtlcParts.forEach { add(LightningIncomingPayment.Part.FeeCredit(it.amount)) }
                                                }
                                                val actions = buildList {
                                                    // We send a single add_fee_credit for the will_add_htlc set.
                                                    add(SendOnTheFlyFundingMessage(AddFeeCredit(nodeParams.chainHash, incomingPayment.paymentPreimage)))
                                                    htlcParts.forEach { add(WrappedChannelCommand(it.htlc.channelId, ChannelCommand.Htlc.Settlement.Fulfill(it.htlc.id, incomingPayment.paymentPreimage, true))) }
                                                }
                                                acceptPayment(incomingPayment, parts, actions)
                                            }
                                            else -> {
                                                // We're not adding to our fee credit, so we need to check our liquidity policy.
                                                // Even if we have enough fee credit to pay the fees, we may want to wait for a lower feerate.
                                                val fees = fundingRate.fees(currentFeerate, requestedAmount, requestedAmount, isChannelCreation = true)
                                                    .let { ChannelManagementFees(miningFee = it.miningFee, serviceFee = it.serviceFee) }
                                                when (val rejected = nodeParams.liquidityPolicy.value.maybeReject(requestedAmount.toMilliSatoshi(), fees, LiquidityEvents.Source.OffChainPayment, logger)) {
                                                    is LiquidityEvents.Rejected -> {
                                                        nodeParams._nodeEvents.emit(rejected)
                                                        rejectPayment(payment, incomingPayment, TemporaryNodeFailure)
                                                    }
                                                    else -> {
                                                        val actions = listOf(AddLiquidityForIncomingPayment(payment.amountReceived, requestedAmount, fundingRate, incomingPayment.paymentPreimage, willAddHtlcParts.map { it.htlc }))
                                                        val paymentOnlyHtlcs = payment.copy(
                                                            // We need to splice before receiving the remaining HTLC parts.
                                                            // We extend the duration of the MPP timeout to give more time for funding to complete.
                                                            startedAtSeconds = payment.startedAtSeconds + 30,
                                                            // We keep the currently added HTLCs, and should receive the remaining HTLCs after the open/splice.
                                                            parts = htlcParts.toSet()
                                                        )
                                                        when {
                                                            paymentOnlyHtlcs.parts.isNotEmpty() -> pending[paymentPart.paymentHash] = paymentOnlyHtlcs
                                                            else -> pending.remove(paymentPart.paymentHash)
                                                        }
                                                        ProcessAddResult.Pending(incomingPayment, paymentOnlyHtlcs, actions)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                else -> when (val fundingFee = validateFundingFee(htlcParts)) {
                                    is Either.Left -> {
                                        logger.warning { "rejecting htlcs with invalid on-the-fly funding fee: ${fundingFee.value.message}" }
                                        val failure = IncorrectOrUnknownPaymentDetails(paymentPart.totalAmount, currentBlockHeight.toLong())
                                        rejectPayment(payment, incomingPayment, failure)
                                    }
                                    is Either.Right -> {
                                        val parts = htlcParts.map { part -> LightningIncomingPayment.Part.Htlc(part.amount, part.htlc.channelId, part.htlc.id, part.htlc.fundingFee) }
                                        val actions = htlcParts.map { part ->
                                            val cmd = ChannelCommand.Htlc.Settlement.Fulfill(part.htlc.id, incomingPayment.paymentPreimage, true)
                                            WrappedChannelCommand(part.htlc.channelId, cmd)
                                        }
                                        acceptPayment(incomingPayment, parts, actions)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private suspend fun acceptPayment(incomingPayment: LightningIncomingPayment, parts: List<LightningIncomingPayment.Part>, actions: List<PeerCommand>): ProcessAddResult.Accepted {
        pending.remove(incomingPayment.paymentHash)
        if (incomingPayment is Bolt12IncomingPayment) {
            // We didn't store the Bolt 12 invoice in our DB when receiving the invoice_request (to protect against DoS).
            // We need to create the DB entry now otherwise the payment won't be recorded.
            db.addIncomingPayment(incomingPayment)
        }
        db.receiveLightningPayment(incomingPayment.paymentHash, parts)
        val incomingPayment1 = incomingPayment.addReceivedParts(parts)
        nodeParams._nodeEvents.emit(PaymentEvents.PaymentReceived(incomingPayment1))
        return ProcessAddResult.Accepted(actions, incomingPayment1, parts)
    }

    private fun rejectPayment(payment: PendingPayment, incomingPayment: LightningIncomingPayment, failure: FailureMessage): ProcessAddResult.Rejected {
        pending.remove(incomingPayment.paymentHash)
        val actions = payment.parts.map { part ->
            when (part) {
                is HtlcPart -> actionForFailureMessage(failure, part.htlc)
                is WillAddHtlcPart -> actionForWillAddHtlcFailure(nodeParams.nodePrivateKey, failure, part.htlc)
            }
        }
        return ProcessAddResult.Rejected(actions, incomingPayment)
    }

    private fun validateOnTheFlyFundingRate(
        willAddHtlcAmount: MilliSatoshi,
        remoteFeatures: Features,
        currentFeeCredit: MilliSatoshi,
        currentFeerate: FeeratePerKw,
        remoteFundingRates: LiquidityAds.WillFundRates?
    ): Either<LiquidityEvents.Rejected, Pair<Satoshi, LiquidityAds.FundingRate>> {
        return when (val liquidityPolicy = nodeParams.liquidityPolicy.value) {
            is LiquidityPolicy.Disable -> Either.Left(LiquidityEvents.Rejected(willAddHtlcAmount, 0.msat, LiquidityEvents.Source.OffChainPayment, LiquidityEvents.Rejected.Reason.PolicySetToDisabled))
            is LiquidityPolicy.Auto -> {
                // Whenever we receive on-the-fly funding, we take this opportunity to purchase inbound liquidity, if configured.
                // This reduces the frequency of on-chain funding and thus the overall on-chain fees paid.
                val additionalInboundLiquidity = liquidityPolicy.inboundLiquidityTarget ?: 0.sat
                // We must round up to the nearest satoshi value instead of rounding down.
                val requestedAmount = (willAddHtlcAmount + 999.msat).truncateToSatoshi() + additionalInboundLiquidity
                when (val fundingRate = remoteFundingRates?.findRate(requestedAmount)) {
                    null -> Either.Left(LiquidityEvents.Rejected(requestedAmount.toMilliSatoshi(), 0.msat, LiquidityEvents.Source.OffChainPayment, LiquidityEvents.Rejected.Reason.NoMatchingFundingRate))
                    else -> {
                        // We don't know at that point if we'll need a channel or if we already have one.
                        // We must use the worst case fees that applies to channel creation.
                        val fees = fundingRate.fees(currentFeerate, requestedAmount, requestedAmount, isChannelCreation = true)
                            .let { ChannelManagementFees(miningFee = it.miningFee, serviceFee = it.serviceFee) }
                        val canAddToFeeCredit = Features.canUseFeature(nodeParams.features, remoteFeatures, Feature.FundingFeeCredit) && (willAddHtlcAmount + currentFeeCredit) <= liquidityPolicy.maxAllowedFeeCredit
                        logger.info { "on-the-fly assessment: amount=$requestedAmount feerate=$currentFeerate fees=$fees" }
                        val rejected = when {
                            // We never reject if we can add payments to our fee credit until making an on-chain operation becomes acceptable.
                            canAddToFeeCredit -> null
                            // We only initiate on-the-fly funding if the missing amount is greater than the fees paid.
                            // Otherwise our peer may not be able to claim the funding fees from the relayed HTLCs.
                            (willAddHtlcAmount + currentFeeCredit) < fees.total * 2 -> LiquidityEvents.Rejected(
                                requestedAmount.toMilliSatoshi(),
                                fees.total.toMilliSatoshi(),
                                LiquidityEvents.Source.OffChainPayment,
                                LiquidityEvents.Rejected.Reason.MissingOffChainAmountTooLow(willAddHtlcAmount, currentFeeCredit)
                            )
                            else -> liquidityPolicy.maybeReject(requestedAmount.toMilliSatoshi(), fees, LiquidityEvents.Source.OffChainPayment, logger)
                        }
                        when (rejected) {
                            null -> Either.Right(Pair(requestedAmount, fundingRate))
                            else -> Either.Left(rejected)
                        }
                    }
                }
            }
        }
    }

    private suspend fun validateFundingFee(parts: List<HtlcPart>): Either<ChannelException, LiquidityAds.FundingFee?> {
        return when (val fundingTxId = parts.map { it.htlc.fundingFee?.fundingTxId }.firstOrNull()) {
            is TxId -> {
                val channelId = parts.first().htlc.channelId
                val paymentHash = parts.first().htlc.paymentHash
                val fundingFee = parts.map { it.htlc.fundingFee?.amount ?: 0.msat }.sum()
                when (val purchase = db.getInboundLiquidityPurchase(fundingTxId)?.purchase) {
                    null -> Either.Left(UnexpectedLiquidityAdsFundingFee(channelId, fundingTxId))
                    else -> {
                        val fundingFeeOk = when (val details = purchase.paymentDetails) {
                            is LiquidityAds.PaymentDetails.FromFutureHtlc -> details.paymentHashes.contains(paymentHash) && fundingFee <= purchase.fees.total.toMilliSatoshi()
                            is LiquidityAds.PaymentDetails.FromFutureHtlcWithPreimage -> details.preimages.any { Crypto.sha256(it).byteVector32() == paymentHash } && fundingFee <= purchase.fees.total.toMilliSatoshi()
                            // Fees have already been paid from our channel balance.
                            is LiquidityAds.PaymentDetails.FromChannelBalanceForFutureHtlc -> details.paymentHashes.contains(paymentHash) && fundingFee == 0.msat
                            is LiquidityAds.PaymentDetails.FromChannelBalance -> false
                        }
                        when {
                            fundingFeeOk -> Either.Right(LiquidityAds.FundingFee(fundingFee, fundingTxId))
                            else -> Either.Left(InvalidLiquidityAdsFundingFee(channelId, fundingTxId, paymentHash, purchase.fees.total, fundingFee))
                        }
                    }
                }
            }
            else -> Either.Right(null)
        }
    }

    private suspend fun validatePaymentPart(paymentPart: PaymentPart, currentBlockHeight: Int): Either<ProcessAddResult.Rejected, LightningIncomingPayment> {
        val logger = MDCLogger(logger.logger, staticMdc = paymentPart.mdc())
        when (val finalPayload = paymentPart.finalPayload) {
            is PaymentOnion.FinalPayload.Standard -> {
                val incomingPayment = db.getLightningIncomingPayment(paymentPart.paymentHash)
                return when {
                    incomingPayment == null -> {
                        logger.warning { "payment for which we don't have a preimage" }
                        Either.Left(rejectPaymentPart(privateKey, paymentPart, null, currentBlockHeight))
                    }
                    // Payments are rejected for expired invoices UNLESS invoice has already been paid
                    // We must accept payments for already paid invoices, because it could be the channel replaying HTLCs that we already fulfilled
                    incomingPayment.isExpired() && incomingPayment.parts.isEmpty() -> {
                        logger.warning { "the invoice is expired" }
                        Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                    }
                    incomingPayment !is Bolt11IncomingPayment -> {
                        logger.warning { "unsupported payment type: ${incomingPayment::class}" }
                        Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                    }
                    incomingPayment.paymentRequest.paymentSecret != finalPayload.paymentSecret -> {
                        // BOLT 04:
                        // - if the payment_secret doesn't match the expected value for that payment_hash,
                        //   or the payment_secret is required and is not present:
                        //   - MUST fail the HTLC.
                        //   - MUST return an incorrect_or_unknown_payment_details error.
                        //
                        //   Related: https://github.com/lightningnetwork/lightning-rfc/pull/671
                        //
                        // NB: We always include a paymentSecret, and mark the feature as mandatory.
                        logger.warning { "payment with invalid paymentSecret (${finalPayload.paymentSecret})" }
                        Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                    }
                    incomingPayment.paymentRequest.amount != null && paymentPart.totalAmount < incomingPayment.paymentRequest.amount -> {
                        // BOLT 04:
                        // - if the amount paid is less than the amount expected:
                        //   - MUST fail the HTLC.
                        //   - MUST return an incorrect_or_unknown_payment_details error.
                        logger.warning { "invalid amount (underpayment): ${paymentPart.totalAmount}, expected: ${incomingPayment.paymentRequest.amount}" }
                        Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                    }
                    incomingPayment.paymentRequest.amount != null && paymentPart.totalAmount > incomingPayment.paymentRequest.amount * 2 -> {
                        // BOLT 04:
                        // - if the amount paid is more than twice the amount expected:
                        //   - SHOULD fail the HTLC.
                        //   - SHOULD return an incorrect_or_unknown_payment_details error.
                        //
                        //   Note: this allows the origin node to reduce information leakage by altering
                        //   the amount while not allowing for accidental gross overpayment.
                        logger.warning { "invalid amount (overpayment): ${paymentPart.totalAmount}, expected: ${incomingPayment.paymentRequest.amount}" }
                        Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                    }
                    paymentPart is HtlcPart && paymentPart.htlc.cltvExpiry < minFinalCltvExpiry(nodeParams, paymentPart, incomingPayment, currentBlockHeight) -> {
                        logger.warning { "payment with expiry too small: ${paymentPart.htlc.cltvExpiry}, min is ${minFinalCltvExpiry(nodeParams, paymentPart, incomingPayment, currentBlockHeight)}" }
                        Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                    }
                    else -> Either.Right(incomingPayment)
                }
            }
            is PaymentOnion.FinalPayload.Blinded -> {
                // We encrypted the payment metadata for ourselves in the blinded path we included in the invoice.
                return when (val metadata = OfferPaymentMetadata.fromPathId(nodeParams.nodePrivateKey, finalPayload.pathId, paymentPart.paymentHash)) {
                    null -> {
                        logger.warning { "invalid path_id: ${finalPayload.pathId.toHex()}" }
                        Either.Left(rejectPaymentPart(privateKey, paymentPart, null, currentBlockHeight))
                    }
                    else -> {
                        val incomingPayment = db.getLightningIncomingPayment(paymentPart.paymentHash) ?: Bolt12IncomingPayment(metadata.preimage, metadata)
                        when {
                            incomingPayment !is Bolt12IncomingPayment -> {
                                logger.warning { "unsupported payment type: ${incomingPayment::class}" }
                                Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                            }
                            paymentPart.paymentHash != metadata.paymentHash -> {
                                logger.warning { "payment for which we don't have a preimage" }
                                Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                            }
                            paymentPart.totalAmount < metadata.amount -> {
                                logger.warning { "invalid amount (underpayment): ${paymentPart.totalAmount}, expected: ${metadata.amount}" }
                                Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                            }
                            paymentPart is HtlcPart && paymentPart.htlc.cltvExpiry < minFinalCltvExpiry(nodeParams, paymentPart, incomingPayment, currentBlockHeight) -> {
                                logger.warning { "payment with expiry too small: ${paymentPart.htlc.cltvExpiry}, min is ${minFinalCltvExpiry(nodeParams, paymentPart, incomingPayment, currentBlockHeight)}" }
                                Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                            }
                            metadata.createdAtMillis + nodeParams.bolt12InvoiceExpiry.inWholeMilliseconds < currentTimestampMillis() && incomingPayment.parts.isEmpty() -> {
                                logger.warning { "the invoice is expired" }
                                Either.Left(rejectPaymentPart(privateKey, paymentPart, incomingPayment, currentBlockHeight))
                            }
                            else -> Either.Right(incomingPayment)
                        }
                    }
                }
            }
        }
    }

    fun checkPaymentsTimeout(currentTimestampSeconds: Long): List<PeerCommand> {
        val actions = mutableListOf<PeerCommand>()
        val keysToRemove = mutableSetOf<ByteVector32>()

        // BOLT 04:
        // - MUST fail all HTLCs in the HTLC set after some reasonable timeout.
        //   - SHOULD wait for at least 60 seconds after the initial HTLC.
        //   - SHOULD use mpp_timeout for the failure message.
        pending.forEach { (paymentHash, payment) ->
            val isExpired = currentTimestampSeconds > (payment.startedAtSeconds + nodeParams.mppAggregationWindow.inWholeSeconds)
            if (isExpired) {
                keysToRemove += paymentHash
                payment.parts.forEach { part ->
                    when (part) {
                        is HtlcPart -> actions += actionForFailureMessage(PaymentTimeout, part.htlc)
                        is WillAddHtlcPart -> actions += actionForWillAddHtlcFailure(privateKey, PaymentTimeout, part.htlc)
                    }
                }
            }
        }

        pending.minusAssign(keysToRemove)
        return actions
    }

    /**
     * Purge all expired unpaid normal payments with creation times in the given time range.
     *
     * @param fromCreatedAt from absolute time in milliseconds since UNIX epoch when the payment request was generated.
     * @param toCreatedAt to absolute time in milliseconds since UNIX epoch when the payment request was generated.
     * @return number of invoices purged
     */
    suspend fun purgeExpiredPayments(fromCreatedAt: Long = 0, toCreatedAt: Long = currentTimestampMillis()): Int {
        return db.listLightningExpiredPayments(fromCreatedAt, toCreatedAt).count {
            logger.info { "purging unpaid expired payment for paymentHash=${it.paymentHash} from DB" }
            db.removeLightningIncomingPayment(it.paymentHash)
        }
    }

    /**
     * If we are disconnected, we must forget pending payment parts.
     * On-the-fly funding proposals will be forgotten by our peer, so we need to do the same.
     * Offered HTLCs that haven't been resolved will be re-processed when we reconnect.
     */
    fun purgePendingPayments() {
        pending.forEach { (paymentHash, pending) -> logger.info { "purging pending incoming payments for paymentHash=$paymentHash: ${pending.parts.joinToString(", ") { it.toString() }}" } }
        pending.clear()
    }

    companion object {
        /** Convert an incoming htlc to a payment part abstraction. Payment parts are then summed together to reach the full payment amount. */
        private fun toPaymentPart(privateKey: PrivateKey, htlc: Either<WillAddHtlc, UpdateAddHtlc>): Either<ProcessAddResult.Rejected, PaymentPart> {
            return when (val decrypted = IncomingPaymentPacket.decrypt(htlc, privateKey)) {
                is Either.Left -> {
                    val action = when (htlc) {
                        is Either.Left -> actionForWillAddHtlcFailure(privateKey, decrypted.value, htlc.value)
                        is Either.Right -> actionForFailureMessage(decrypted.value, htlc.value)
                    }
                    Either.Left(ProcessAddResult.Rejected(listOf(action), null))
                }
                is Either.Right -> when (htlc) {
                    is Either.Left -> Either.Right(WillAddHtlcPart(htlc.value, decrypted.value))
                    is Either.Right -> Either.Right(HtlcPart(htlc.value, decrypted.value))
                }
            }
        }

        private fun rejectPaymentPart(privateKey: PrivateKey, paymentPart: PaymentPart, incomingPayment: LightningIncomingPayment?, currentBlockHeight: Int): ProcessAddResult.Rejected {
            val failureMsg = when (paymentPart.finalPayload) {
                is PaymentOnion.FinalPayload.Blinded -> InvalidOnionBlinding(Sphinx.hash(paymentPart.onionPacket))
                is PaymentOnion.FinalPayload.Standard -> IncorrectOrUnknownPaymentDetails(paymentPart.totalAmount, currentBlockHeight.toLong())
            }
            val rejectedAction = when (paymentPart) {
                is HtlcPart -> actionForFailureMessage(failureMsg, paymentPart.htlc)
                is WillAddHtlcPart -> actionForWillAddHtlcFailure(privateKey, failureMsg, paymentPart.htlc)
            }
            return ProcessAddResult.Rejected(listOf(rejectedAction), incomingPayment)
        }

        private fun actionForFailureMessage(msg: FailureMessage, htlc: UpdateAddHtlc, commit: Boolean = true): WrappedChannelCommand {
            val cmd: ChannelCommand.Htlc.Settlement = when (msg) {
                is BadOnion -> ChannelCommand.Htlc.Settlement.FailMalformed(htlc.id, msg.onionHash, msg.code, commit)
                else -> ChannelCommand.Htlc.Settlement.Fail(htlc.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(msg), commit)
            }
            return WrappedChannelCommand(htlc.channelId, cmd)
        }

        private fun actionForWillAddHtlcFailure(privateKey: PrivateKey, failure: FailureMessage, htlc: WillAddHtlc): SendOnTheFlyFundingMessage {
            val msg = OutgoingPaymentPacket.buildWillAddHtlcFailure(privateKey, htlc, failure)
            return SendOnTheFlyFundingMessage(msg)
        }

        private fun minFinalCltvExpiry(nodeParams: NodeParams, paymentPart: PaymentPart, incomingPayment: LightningIncomingPayment, currentBlockHeight: Int): CltvExpiry {
            val minFinalExpiryDelta = when (incomingPayment) {
                is Bolt11IncomingPayment -> incomingPayment.paymentRequest.minFinalExpiryDelta ?: Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA
                is Bolt12IncomingPayment -> nodeParams.minFinalCltvExpiryDelta
            }
            return when {
                paymentPart is HtlcPart && paymentPart.htlc.usesOnTheFlyFunding -> {
                    // This HTLC is using on-the-fly funding, so it may have been forwarded with a delay
                    // because an on-chain transaction was required.
                    // If the expiry is now below our min_final_expiry_delta, we sill want to accept this
                    // HTLC if we can do so safely, because we need to pay funding fees by fulfilling it.
                    // As long as we have time to publish a force-close, it is safe to accept the HTLC.
                    val overrideFinalExpiryDelta = minFinalExpiryDelta.min(nodeParams.fulfillSafetyBeforeTimeoutBlocks * 2)
                    overrideFinalExpiryDelta.toCltvExpiry(currentBlockHeight.toLong())
                }
                else -> minFinalExpiryDelta.toCltvExpiry(currentBlockHeight.toLong())
            }
        }
    }

}