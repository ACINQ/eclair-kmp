package fr.acinq.lightning.payment

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.Try
import fr.acinq.lightning.*
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.states.*
import fr.acinq.lightning.crypto.sphinx.FailurePacket
import fr.acinq.lightning.crypto.sphinx.PacketAndSecrets
import fr.acinq.lightning.crypto.sphinx.SharedSecrets
import fr.acinq.lightning.db.HopDesc
import fr.acinq.lightning.db.LightningOutgoingPayment
import fr.acinq.lightning.db.OutgoingPaymentsDb
import fr.acinq.lightning.io.PayInvoice
import fr.acinq.lightning.io.WrappedChannelCommand
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.logging.error
import fr.acinq.lightning.logging.mdc
import fr.acinq.lightning.router.NodeHop
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.FailureMessage
import fr.acinq.lightning.wire.TrampolineExpiryTooSoon
import fr.acinq.lightning.wire.TrampolineFeeInsufficient
import fr.acinq.lightning.wire.UnknownNextPeer

class OutgoingPaymentHandler(val nodeParams: NodeParams, val walletParams: WalletParams, val db: OutgoingPaymentsDb) {

    interface SendPaymentResult
    interface ProcessFailureResult
    interface ProcessFulfillResult

    /** A payment attempt has been made: we provide information about the fees we're paying, which may increase as we re-try our payment. */
    data class Progress(val request: PayInvoice, val fees: MilliSatoshi, val actions: List<WrappedChannelCommand>) : SendPaymentResult, ProcessFailureResult

    /** The payment could not be sent. */
    data class Failure(val request: PayInvoice, val failure: OutgoingPaymentFailure) : SendPaymentResult, ProcessFailureResult

    /** The payment was successfully made. */
    data class Success(val request: PayInvoice, val payment: LightningOutgoingPayment, val preimage: ByteVector32) : ProcessFailureResult, ProcessFulfillResult

    private val logger = nodeParams.loggerFactory.newLogger(this::class)
    // Each outgoing HTLC will have its own ID, because its status will be recorded in the payments DB.
    // Since we automatically retry on failure, we may have multiple child attempts for each payment.
    private val childToPaymentId = mutableMapOf<UUID, UUID>()
    private val pending = mutableMapOf<UUID, PaymentAttempt>()

    /**
     * While a payment is in progress, we wait for the outgoing HTLC to settle.
     * When we receive a failure, we may retry with a different fee or expiry.
     *
     * @param request payment request containing the total amount to send.
     * @param attemptNumber number of failed previous payment attempts.
     * @param pending pending outgoing payment.
     * @param sharedSecrets payment onion shared secrets, used to decrypt failures.
     * @param failures previous payment failures.
     */
    data class PaymentAttempt(
        val request: PayInvoice,
        val attemptNumber: Int,
        val pending: LightningOutgoingPayment.Part,
        val sharedSecrets: SharedSecrets,
        val failures: List<Either<ChannelException, FailureMessage>>
    ) {
        val fees: MilliSatoshi = pending.amount - request.amount
    }

    // NB: this function should only be used in tests.
    fun getPendingPayment(paymentId: UUID): PaymentAttempt? = pending[paymentId]

    private fun getPaymentAttempt(childId: UUID): PaymentAttempt? = childToPaymentId[childId]?.let { pending[it] }

    private suspend fun sendPaymentInternal(request: PayInvoice, failures: List<Either<ChannelException, FailureMessage>>, channels: Map<ByteVector32, ChannelState>, currentBlockHeight: Int, logger: MDCLogger): Either<Failure, Progress> {
        val attemptNumber = failures.size
        val trampolineFees = (request.trampolineFeesOverride ?: walletParams.trampolineFees)[attemptNumber]
        logger.info { "trying payment with fee_base=${trampolineFees.feeBase}, fee_proportional=${trampolineFees.feeProportional}" }
        val trampolineAmount = request.amount + trampolineFees.calculateFees(request.amount)
        return when (val result = selectChannel(trampolineAmount, channels)) {
            is Either.Left -> {
                logger.warning { "payment failed: ${result.value}" }
                if (attemptNumber == 0) {
                    db.addOutgoingPayment(LightningOutgoingPayment(request.paymentId, request.amount, request.recipient, request.paymentDetails))
                }
                db.completeOutgoingPaymentOffchain(request.paymentId, result.value)
                removeFromState(request.paymentId)
                Either.Left(Failure(request, OutgoingPaymentFailure(result.value, failures)))
            }
            is Either.Right -> {
                val hop = NodeHop(walletParams.trampolineNode.id, request.recipient, trampolineFees.cltvExpiryDelta, trampolineFees.calculateFees(request.amount))
                val (childPayment, sharedSecrets, cmd) = createOutgoingPayment(request, result.value, hop, currentBlockHeight)
                if (attemptNumber == 0) {
                    db.addOutgoingPayment(LightningOutgoingPayment(request.paymentId, request.amount, request.recipient, request.paymentDetails, listOf(childPayment), LightningOutgoingPayment.Status.Pending))
                } else {
                    db.addOutgoingLightningParts(request.paymentId, listOf(childPayment))
                }
                val payment = PaymentAttempt(request, attemptNumber, childPayment, sharedSecrets, failures)
                pending[request.paymentId] = payment
                Either.Right(Progress(request, payment.fees, listOf(cmd)))
            }
        }
    }

    suspend fun sendPayment(request: PayInvoice, channels: Map<ByteVector32, ChannelState>, currentBlockHeight: Int): SendPaymentResult {
        val logger = MDCLogger(logger, staticMdc = request.mdc())
        logger.info { "sending ${request.amount} to ${request.recipient}" }
        if (request.amount <= 0.msat) {
            logger.warning { "payment amount must be positive (${request.amount})" }
            return Failure(request, FinalFailure.InvalidPaymentAmount.toPaymentFailure())
        }
        if (!nodeParams.features.areSupported(request.paymentDetails.paymentRequest.features.invoiceFeatures())) {
            logger.warning { "invoice contains mandatory features that we don't support" }
            return Failure(request, FinalFailure.FeaturesNotSupported.toPaymentFailure())
        }
        if (pending.containsKey(request.paymentId)) {
            logger.error { "contract violation: caller is recycling uuid's" }
            return Failure(request, FinalFailure.InvalidPaymentId.toPaymentFailure())
        }
        if (db.listLightningOutgoingPayments(request.paymentHash).find { it.status is LightningOutgoingPayment.Status.Completed.Succeeded } != null) {
            logger.error { "invoice has already been paid" }
            return Failure(request, FinalFailure.AlreadyPaid.toPaymentFailure())
        }
        return sendPaymentInternal(request, listOf(), channels, currentBlockHeight, logger).fold({ it }, { it })
    }

    /**
     * This may happen if we hit channel limits (e.g. max-accepted-htlcs).
     * This is a temporary failure that we cannot automatically resolve: we must wait for the channel to be usable again.
     */
    suspend fun processAddFailed(channelId: ByteVector32, event: ChannelAction.ProcessCmdRes.AddFailed): Failure? {
        val payment = getPaymentAttempt(event.cmd.paymentId) ?: return processPostRestartFailure(event.cmd.paymentId, Either.Left(event.error))
        val logger = MDCLogger(logger, staticMdc = mapOf("channelId" to channelId, "childPaymentId" to event.cmd.paymentId) + payment.request.mdc())

        if (payment.pending.id != event.cmd.paymentId) {
            logger.warning { "ignoring HTLC that does not match pending payment part (${event.cmd.paymentId} != ${payment.pending.id})" }
            return null
        }

        logger.info { "could not send HTLC: ${event.error.message}" }
        db.completeOutgoingLightningPart(event.cmd.paymentId, OutgoingPaymentFailure.convertFailure(Either.Left(event.error)))
        db.completeOutgoingPaymentOffchain(payment.request.paymentId, FinalFailure.NoAvailableChannels)
        removeFromState(payment.request.paymentId)
        return Failure(payment.request, OutgoingPaymentFailure(FinalFailure.NoAvailableChannels, payment.failures + Either.Left(event.error)))
    }

    suspend fun processAddSettledFailed(channelId: ByteVector32, event: ChannelAction.ProcessCmdRes.AddSettledFail, channels: Map<ByteVector32, ChannelState>, currentBlockHeight: Int): ProcessFailureResult? {
        val payment = getPaymentAttempt(event.paymentId) ?: return processPostRestartFailure(event.paymentId, Either.Left(CannotDecryptFailure(channelId, "restarted")))
        val logger = MDCLogger(logger, staticMdc = mapOf("channelId" to channelId, "childPaymentId" to event.paymentId) + payment.request.mdc())

        if (payment.pending.id != event.paymentId) {
            logger.warning { "ignoring HTLC that does not match latest payment part (${event.paymentId} != ${payment.pending.id})" }
            // This case may happen when we receive AddSettledFailed again for the previous attempt.
            // This can happen if we disconnect and re-process the update_fail_htlc message on reconnection.
            return null
        }

        val failure = when (event.result) {
            is ChannelAction.HtlcResult.Fail.RemoteFail -> when (val decrypted = FailurePacket.decrypt(event.result.fail.reason.toByteArray(), payment.sharedSecrets)) {
                is Try.Failure -> {
                    logger.warning { "could not decrypt failure packet: ${decrypted.error.message}" }
                    Either.Left(CannotDecryptFailure(channelId, decrypted.error.message ?: "unknown"))
                }
                is Try.Success -> {
                    logger.debug { "HTLC failed: ${decrypted.result.failureMessage.message}" }
                    Either.Right(decrypted.result.failureMessage)
                }
            }
            is ChannelAction.HtlcResult.Fail.RemoteFailMalformed -> {
                logger.warning { "our peer couldn't decrypt our payment onion (failureCode=${event.result.fail.failureCode})" }
                Either.Left(CannotDecryptFailure(channelId, "malformed onion"))
            }
            is ChannelAction.HtlcResult.Fail.OnChainFail -> {
                logger.warning { "channel closed while our HTLC was pending: ${event.result.cause.message}" }
                Either.Left(event.result.cause)
            }
            is ChannelAction.HtlcResult.Fail.Disconnected -> {
                logger.warning { "we got disconnected before signing outgoing HTLC" }
                Either.Left(CannotSignDisconnected(channelId))
            }
        }

        // We update the status in our DB.
        db.completeOutgoingLightningPart(event.paymentId, OutgoingPaymentFailure.convertFailure(failure))

        val trampolineFees = payment.request.trampolineFeesOverride ?: walletParams.trampolineFees
        val finalError = when {
            trampolineFees.size <= payment.attemptNumber + 1 -> FinalFailure.RetryExhausted
            failure == Either.Right(UnknownNextPeer) -> FinalFailure.RecipientUnreachable
            failure != Either.Right(TrampolineExpiryTooSoon) && failure != Either.Right(TrampolineFeeInsufficient) -> FinalFailure.UnknownError // non-retriable error
            else -> null
        }
        return if (finalError != null) {
            db.completeOutgoingPaymentOffchain(payment.request.paymentId, finalError)
            removeFromState(payment.request.paymentId)
            Failure(payment.request, OutgoingPaymentFailure(finalError, payment.failures + failure))
        } else {
            // The trampoline node is asking us to retry the payment with more fees or a larger expiry delta.
            sendPaymentInternal(payment.request, payment.failures + failure, channels, currentBlockHeight, logger).fold({ it }, { it })
        }
    }

    private suspend fun processPostRestartFailure(partId: UUID, failure: Either<ChannelException, FailureMessage>): Failure? {
        return when (val payment = db.getLightningOutgoingPaymentFromPartId(partId)) {
            null -> {
                logger.error { "paymentId=$partId doesn't match any known payment attempt" }
                null
            }
            else -> {
                val logger = MDCLogger(logger, staticMdc = mapOf("childPaymentId" to partId) + payment.mdc())
                logger.debug { "could not send HTLC (wallet restart): ${failure.fold({ it.message }, { it.message })}" }
                val status = LightningOutgoingPayment.Part.Status.Failed(OutgoingPaymentFailure.convertFailure(failure))
                db.completeOutgoingLightningPart(partId, status.failure)
                logger.warning { "payment failed: ${FinalFailure.WalletRestarted}" }
                val request = PayInvoice(payment.id, payment.recipientAmount, payment.details)
                db.completeOutgoingPaymentOffchain(payment.id, FinalFailure.WalletRestarted)
                removeFromState(payment.id)
                val failures = payment.parts.map { it.status }.filterIsInstance<LightningOutgoingPayment.Part.Status.Failed>() + status
                Failure(request, OutgoingPaymentFailure(FinalFailure.WalletRestarted, failures))
            }
        }
    }

    suspend fun processAddSettledFulfilled(event: ChannelAction.ProcessCmdRes.AddSettledFulfill): Success? {
        val preimage = event.result.paymentPreimage
        val payment = getPaymentAttempt(event.paymentId) ?: return processPostRestartFulfill(event.paymentId, preimage)
        val logger = MDCLogger(logger, staticMdc = mapOf("childPaymentId" to event.paymentId) + payment.request.mdc())

        if (payment.pending.id != event.paymentId) {
            logger.error { "fulfilled HTLC that does not match latest payment part, this should never happen (${event.paymentId} != ${payment.pending.id})" }
            return null
        }

        logger.info { "payment successfully sent (fees=${payment.fees})" }
        db.completeOutgoingLightningPart(event.paymentId, preimage)
        db.completeOutgoingPaymentOffchain(payment.request.paymentId, preimage)
        removeFromState(payment.request.paymentId)
        val status = LightningOutgoingPayment.Status.Completed.Succeeded.OffChain(preimage)
        val part = payment.pending.copy(status = LightningOutgoingPayment.Part.Status.Succeeded(preimage))
        val result = LightningOutgoingPayment(payment.request.paymentId, payment.request.amount, payment.request.recipient, payment.request.paymentDetails, listOf(part), status)
        return Success(payment.request, result, preimage)
    }

    private suspend fun processPostRestartFulfill(partId: UUID, preimage: ByteVector32): Success? {
        return when (val payment = db.getLightningOutgoingPaymentFromPartId(partId)) {
            null -> {
                logger.error { "paymentId=$partId doesn't match any known payment attempt" }
                null
            }
            else -> {
                val logger = MDCLogger(logger, staticMdc = mapOf("childPaymentId" to partId) + payment.mdc())
                db.completeOutgoingLightningPart(partId, preimage)
                logger.info { "payment successfully sent (wallet restart)" }
                val request = PayInvoice(payment.id, payment.recipientAmount, payment.details)
                db.completeOutgoingPaymentOffchain(payment.id, preimage)
                removeFromState(payment.id)
                // NB: we reload the payment to ensure all parts status are updated
                // this payment cannot be null
                val succeeded = db.getLightningOutgoingPayment(payment.id)!!
                Success(request, succeeded, preimage)
            }
        }
    }

    private fun removeFromState(paymentId: UUID) {
        val children = childToPaymentId.filterValues { it == paymentId }.keys
        children.forEach { childToPaymentId.remove(it) }
        pending.remove(paymentId)
    }

    /**
     * We assume that we have at most one channel with our trampoline node.
     * We return it if it's ready and has enough balance for the payment, otherwise we return a failure.
     */
    private fun selectChannel(toSend: MilliSatoshi, channels: Map<ByteVector32, ChannelState>): Either<FinalFailure, Normal> {
        return when (val available = channels.values.firstOrNull { it is Normal }) {
            is Normal -> when {
                toSend < available.channelUpdate.htlcMinimumMsat -> Either.Left(FinalFailure.InvalidPaymentAmount)
                available.commitments.availableBalanceForSend() < toSend -> Either.Left(FinalFailure.InsufficientBalance)
                else -> Either.Right(available)
            }
            else -> {
                val failure = when {
                    channels.values.any { it is Syncing || it is Offline } -> FinalFailure.ChannelNotConnected
                    channels.values.any { it is WaitForOpenChannel || it is WaitForAcceptChannel || it is WaitForFundingCreated || it is WaitForFundingSigned || it is WaitForFundingConfirmed || it is WaitForChannelReady } -> FinalFailure.ChannelOpening
                    channels.values.any { it is ShuttingDown || it is Negotiating || it is Closing || it is Closed || it is WaitForRemotePublishFutureCommitment } -> FinalFailure.ChannelClosing
                    else -> FinalFailure.NoAvailableChannels
                }
                Either.Left(failure)
            }
        }
    }

    private fun createOutgoingPayment(request: PayInvoice, channel: Normal, hop: NodeHop, currentBlockHeight: Int): Triple<LightningOutgoingPayment.Part, SharedSecrets, WrappedChannelCommand> {
        val logger = MDCLogger(logger, staticMdc = request.mdc())
        val childId = UUID.randomUUID()
        childToPaymentId[childId] = request.paymentId
        val (amount, expiry, onion) = createPaymentOnion(request, hop, currentBlockHeight)
        val outgoingPayment = LightningOutgoingPayment.Part(
            id = childId,
            amount = amount,
            route = listOf(HopDesc(nodeParams.nodeId, hop.nodeId, channel.shortChannelId), HopDesc(hop.nodeId, hop.nextNodeId)),
            status = LightningOutgoingPayment.Part.Status.Pending
        )
        logger.info { "sending $amount to channel ${channel.shortChannelId}" }
        val add = ChannelCommand.Htlc.Add(amount, request.paymentHash, expiry, onion.packet, paymentId = childId, commit = true)
        return Triple(outgoingPayment, onion.sharedSecrets, WrappedChannelCommand(channel.channelId, add))
    }

    private fun createPaymentOnion(request: PayInvoice, hop: NodeHop, currentBlockHeight: Int): Triple<MilliSatoshi, CltvExpiry, PacketAndSecrets> {
        return when (val paymentRequest = request.paymentDetails.paymentRequest) {
            is Bolt11Invoice -> {
                val minFinalExpiryDelta = paymentRequest.minFinalExpiryDelta ?: Channel.MIN_CLTV_EXPIRY_DELTA
                val expiry = nodeParams.paymentRecipientExpiryParams.computeFinalExpiry(currentBlockHeight, minFinalExpiryDelta)
                val invoiceFeatures = paymentRequest.features
                if (request.recipient == walletParams.trampolineNode.id) {
                    // We are directly paying our trampoline node.
                    OutgoingPaymentPacket.buildPacketToTrampolinePeer(paymentRequest, request.amount, expiry)
                } else if (invoiceFeatures.hasFeature(Feature.ExperimentalTrampolinePayment)) {
                    OutgoingPaymentPacket.buildPacketToTrampolineRecipient(paymentRequest, request.amount, expiry, hop)
                } else {
                    OutgoingPaymentPacket.buildPacketToLegacyRecipient(paymentRequest, request.amount, expiry, hop)
                }
            }
            is Bolt12Invoice -> {
                // The recipient already included a final cltv-expiry-delta in their invoice blinded paths.
                val minFinalExpiryDelta = CltvExpiryDelta(0)
                val expiry = nodeParams.paymentRecipientExpiryParams.computeFinalExpiry(currentBlockHeight, minFinalExpiryDelta)
                OutgoingPaymentPacket.buildPacketToBlindedRecipient(paymentRequest, request.amount, expiry, hop)
            }
        }
    }

}
