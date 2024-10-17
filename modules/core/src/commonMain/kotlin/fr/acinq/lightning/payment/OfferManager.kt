package fr.acinq.lightning.payment

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.utils.Either.Left
import fr.acinq.bitcoin.utils.Either.Right
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.crypto.RouteBlinding
import fr.acinq.lightning.io.OfferInvoiceReceived
import fr.acinq.lightning.io.OfferNotPaid
import fr.acinq.lightning.io.PayOffer
import fr.acinq.lightning.io.PeerEvent
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.message.OnionMessages
import fr.acinq.lightning.message.OnionMessages.Destination
import fr.acinq.lightning.message.OnionMessages.IntermediateNode
import fr.acinq.lightning.message.OnionMessages.buildMessage
import fr.acinq.lightning.utils.currentTimestampMillis
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.wire.*
import kotlinx.coroutines.flow.MutableSharedFlow

sealed class OnionMessageAction {
    /** Send an outgoing onion message (invoice or invoice_request). */
    data class SendMessage(val message: OnionMessage) : OnionMessageAction()
    /** We received a valid invoice for an offer we're trying to pay: we should now pay that invoice. */
    data class PayInvoice(val payOffer: PayOffer, val invoice: Bolt12Invoice) : OnionMessageAction()
}

private data class PendingInvoiceRequest(val payOffer: PayOffer, val request: OfferTypes.InvoiceRequest)

/** Failures occurring when fetching an invoice to pay an offer */
sealed class Bolt12InvoiceRequestFailure {
    // @formatter:off
    data class NoResponse(val request: OfferTypes.InvoiceRequest) : Bolt12InvoiceRequestFailure() { override fun toString(): String = "no response to the invoice request" }
    data class MalformedResponse(val request: OfferTypes.InvoiceRequest, val failure: Bolt12Invoice.Companion.Bolt12ParsingResult.Failure.Malformed) : Bolt12InvoiceRequestFailure() { override fun toString(): String = "recipient returned an invalid response to the invoice request" }
    data class ErrorFromRecipient(val request: OfferTypes.InvoiceRequest, val failure: Bolt12Invoice.Companion.Bolt12ParsingResult.Failure.RecipientError) : Bolt12InvoiceRequestFailure() { override fun toString(): String = "recipient responded to the invoice request with an error" }
    data class InvoiceMismatch(val request: OfferTypes.InvoiceRequest, val reason: String) : Bolt12InvoiceRequestFailure() { override fun toString(): String = "recipient returned an invoice that does not match the request" }
    // @formatter:on
}

class OfferManager(val nodeParams: NodeParams, val walletParams: WalletParams, val eventsFlow: MutableSharedFlow<PeerEvent>, private val logger: MDCLogger) {
    val remoteNodeId: PublicKey = walletParams.trampolineNode.id
    private val pendingInvoiceRequests: HashMap<ByteVector32, PendingInvoiceRequest> = HashMap()
    private val localOffers: HashMap<ByteVector32, OfferTypes.Offer> = HashMap()

    init {
        registerOffer(nodeParams.defaultOffer(walletParams.trampolineNode.id).offer, null)
    }

    fun registerOffer(offer: OfferTypes.Offer, pathId: ByteVector32?) {
        localOffers[pathId ?: ByteVector32.Zeroes] = offer
    }

    /**
     * @return invoice requests that must be sent and the corresponding path_id that must be used in case of a timeout.
     */
    fun requestInvoice(payOffer: PayOffer): Triple<ByteVector32, List<OnionMessage>, OfferTypes.InvoiceRequest> {
        // If we're providing our contact secret, it means we're willing to reveal our identity to the recipient.
        // We include our own offer to allow them to add us to their contacts list and pay us back.
        val contactTlvs = setOfNotNull(
            payOffer.contactSecret?.let { OfferTypes.InvoiceRequestContactSecret(it) },
            payOffer.contactSecret?.let { localOffers[ByteVector32.Zeroes] }?.let { OfferTypes.InvoiceRequestPayerOffer(it) },
        )
        val request = OfferTypes.InvoiceRequest(payOffer.offer, payOffer.amount, 1, nodeParams.features.bolt12Features(), payOffer.payerKey, payOffer.payerNote, nodeParams.chainHash, contactTlvs)
        val replyPathId = randomBytes32()
        pendingInvoiceRequests[replyPathId] = PendingInvoiceRequest(payOffer, request)
        // We add dummy hops to the reply path: this way the receiver only learns that we're at most 3 hops away from our peer.
        val replyPathHops = listOf(IntermediateNode(EncodedNodeId.WithPublicKey.Plain(remoteNodeId)), IntermediateNode(EncodedNodeId.WithPublicKey.Wallet(nodeParams.nodeId)), IntermediateNode(EncodedNodeId.WithPublicKey.Wallet(nodeParams.nodeId)))
        val lastHop = Destination.Recipient(EncodedNodeId.WithPublicKey.Wallet(nodeParams.nodeId), replyPathId)
        val replyPath = OnionMessages.buildRoute(randomKey(), replyPathHops, lastHop)
        val messageContent = TlvStream(OnionMessagePayloadTlv.ReplyPath(replyPath), OnionMessagePayloadTlv.InvoiceRequest(request.records))
        val invoiceRequests = payOffer.offer.contactInfos.mapNotNull { contactInfo ->
            val destination = Destination(contactInfo)
            buildMessage(randomKey(), randomKey(), intermediateNodes(destination), destination, messageContent).right
        }
        return Triple(replyPathId, invoiceRequests, request)
    }

    suspend fun checkInvoiceRequestTimeout(pathId: ByteVector32, payOffer: PayOffer) {
        if (pendingInvoiceRequests.containsKey(pathId)) {
            val request = pendingInvoiceRequests[pathId]!!.request
            logger.warning { "paymentId:${payOffer.paymentId} pathId=$pathId invoice request timed out" }
            eventsFlow.emit(OfferNotPaid(payOffer, Bolt12InvoiceRequestFailure.NoResponse(request)))
            pendingInvoiceRequests.remove(pathId)
        }
    }

    suspend fun receiveMessage(msg: OnionMessage, remoteChannelUpdates: List<ChannelUpdate>, currentBlockHeight: Int): OnionMessageAction? {
        return OnionMessages.decryptMessage(nodeParams.nodePrivateKey, msg, logger)?.let { decrypted ->
            when {
                pendingInvoiceRequests.containsKey(decrypted.pathId) -> receiveInvoiceResponse(decrypted)
                localOffers.containsKey(decrypted.pathId) -> receiveInvoiceRequest(decrypted, remoteChannelUpdates, currentBlockHeight)
                else -> {
                    logger.warning { "pathId:${decrypted.pathId} ignoring onion message (could be a duplicate invoice response)" }
                    null
                }
            }
        }
    }

    private suspend fun receiveInvoiceResponse(decrypted: OnionMessages.DecryptedMessage): OnionMessageAction.PayInvoice? {
        val (payOffer, request) = pendingInvoiceRequests[decrypted.pathId]!!
        pendingInvoiceRequests.remove(decrypted.pathId)
        return when (val res = Bolt12Invoice.extract(decrypted.content.records)) {
            is Bolt12Invoice.Companion.Bolt12ParsingResult.Failure.Malformed -> {
                logger.warning { "paymentId:${payOffer.paymentId} pathId=${decrypted.pathId} malformed response: invalid_tlv=${res.invalidTlvPayload}" }
                eventsFlow.emit(OfferNotPaid(payOffer, Bolt12InvoiceRequestFailure.MalformedResponse(request, res)))
                null
            }
            is Bolt12Invoice.Companion.Bolt12ParsingResult.Failure.RecipientError -> {
                logger.warning { "paymentId:${payOffer.paymentId} pathId=${decrypted.pathId} response did not contain an invoice: invoice_error=${res.invoiceError.error}" }
                eventsFlow.emit(OfferNotPaid(payOffer, Bolt12InvoiceRequestFailure.ErrorFromRecipient(request, res)))
                null
            }
            is Bolt12Invoice.Companion.Bolt12ParsingResult.Success -> {
                when (val reason = res.invoice.validateFor(request)) {
                    is Left -> {
                        logger.warning { "paymentId:${payOffer.paymentId} pathId=${decrypted.pathId} invoice does not match request: ${reason.value}" }
                        eventsFlow.emit(OfferNotPaid(payOffer, Bolt12InvoiceRequestFailure.InvoiceMismatch(request, reason.value)))
                        null
                    }
                    is Right -> {
                        logger.info { "paymentId:${payOffer.paymentId} pathId=${decrypted.pathId} received valid invoice: ${res.invoice}" }
                        eventsFlow.emit(OfferInvoiceReceived(payOffer, res.invoice))
                        OnionMessageAction.PayInvoice(payOffer, res.invoice)
                    }
                }
            }
        }
    }

    private fun receiveInvoiceRequest(decrypted: OnionMessages.DecryptedMessage, remoteChannelUpdates: List<ChannelUpdate>, currentBlockHeight: Int): OnionMessageAction.SendMessage? {
        val offer = localOffers[decrypted.pathId]!!
        val request = decrypted.content.records.get<OnionMessagePayloadTlv.InvoiceRequest>()?.let { OfferTypes.InvoiceRequest.validate(it.tlvs).right }
        // We must use the most restrictive minimum HTLC value between local and remote.
        val minHtlc = (listOf(nodeParams.htlcMinimum) + remoteChannelUpdates.map { it.htlcMinimumMsat }).max()
        return when {
            request == null -> {
                logger.warning { "offerId:${offer.offerId} pathId:${decrypted.pathId} ignoring onion message: missing or invalid invoice request" }
                null
            }
            decrypted.content.replyPath == null -> {
                logger.warning { "offerId:${offer.offerId} pathId:${decrypted.pathId} ignoring invoice request: no reply path ($request)" }
                null
            }
            request.offer != offer -> {
                logger.warning { "offerId:${offer.offerId} pathId:${decrypted.pathId} ignoring invoice request: wrong offer (expected=$offer actual=${request.offer})" }
                sendInvoiceError("ignoring invoice request for wrong offer", decrypted.content.replyPath)
            }
            !request.isValid() -> {
                logger.warning { "offerId:${offer.offerId} pathId:${decrypted.pathId} ignoring invalid invoice request ($request)" }
                sendInvoiceError("ignoring invalid invoice request", decrypted.content.replyPath)
            }
            request.requestedAmount()?.let { it < minHtlc } ?: false -> {
                logger.warning { "offerId:${offer.offerId} pathId:${decrypted.pathId} amount too low (amount=${request.requestedAmount()} minHtlc=$minHtlc)" }
                sendInvoiceError("amount too low, minimum amount = $minHtlc", decrypted.content.replyPath)
            }
            else -> {
                val amount = request.requestedAmount()!!
                val preimage = randomBytes32()
                val truncatedPayerNote = request.payerNote?.let {
                    if (it.length <= 64) {
                        it
                    } else {
                        it.take(63) + "…"
                    }
                }
                // We mustn't use too much space in the path_id, otherwise the sender won't be able to include it in its payment onion.
                // If the payer_address is provided, we don't include the payer_offer: we can retrieve it from the DNS.
                // Otherwise, we want to include the payer_offer, but we must skip it if it's too large.
                val payerOfferSize = request.payerOffer?.let { OfferTypes.Offer.tlvSerializer.write(it.records).size }
                val payerOffer = when {
                    request.payerAddress != null -> null
                    payerOfferSize != null && payerOfferSize > 300 -> null
                    else -> request.payerOffer
                }
                val pathId = OfferPaymentMetadata.V2(
                    ByteVector32(decrypted.pathId),
                    amount,
                    preimage,
                    request.payerId,
                    truncatedPayerNote,
                    request.quantity,
                    request.contactSecret,
                    payerOffer,
                    request.payerAddress,
                    currentTimestampMillis()
                ).toPathId(nodeParams.nodePrivateKey)
                val recipientPayload = RouteBlindingEncryptedData(TlvStream(RouteBlindingEncryptedDataTlv.PathId(pathId))).write().toByteVector()
                val cltvExpiryDelta = remoteChannelUpdates.maxOfOrNull { it.cltvExpiryDelta } ?: walletParams.invoiceDefaultRoutingFees.cltvExpiryDelta
                val paymentInfo = OfferTypes.PaymentInfo(
                    feeBase = remoteChannelUpdates.maxOfOrNull { it.feeBaseMsat } ?: walletParams.invoiceDefaultRoutingFees.feeBase,
                    feeProportionalMillionths = remoteChannelUpdates.maxOfOrNull { it.feeProportionalMillionths } ?: walletParams.invoiceDefaultRoutingFees.feeProportional,
                    // We include our min_final_cltv_expiry_delta in the path, but we *don't* include it in the payment_relay field
                    // for our trampoline node (below). This ensures that we will receive payments with at least this final expiry delta.
                    // This ensures that even when payers haven't received the latest block(s) or don't include a safety margin in the
                    // expiry they use, we can still safely receive their payment.
                    cltvExpiryDelta = cltvExpiryDelta + nodeParams.minFinalCltvExpiryDelta,
                    minHtlc = minHtlc,
                    // Payments are allowed to overpay at most two times the invoice amount.
                    maxHtlc = amount * 2,
                    allowedFeatures = Features.empty
                )
                // Once the invoice expires, the blinded path shouldn't be usable anymore.
                // We assume 10 minutes between each block to convert the invoice expiry to a cltv_expiry_delta.
                // When paying the invoice, payers may add any number of blocks to the current block height to protect recipient privacy.
                // We assume that they won't add more than 720 blocks, which is reasonable because adding a large delta increases the risk
                // that intermediate nodes reject the payment because they don't want their funds potentially locked for a long duration.
                val pathExpiry = (paymentInfo.cltvExpiryDelta + CltvExpiryDelta(720) + (nodeParams.bolt12InvoiceExpiry.inWholeMinutes.toInt() / 10)).toCltvExpiry(currentBlockHeight.toLong())
                val remoteNodePayload = RouteBlindingEncryptedData(
                    TlvStream(
                        RouteBlindingEncryptedDataTlv.OutgoingNodeId(EncodedNodeId.WithPublicKey.Wallet(nodeParams.nodeId)),
                        RouteBlindingEncryptedDataTlv.PaymentRelay(cltvExpiryDelta, paymentInfo.feeProportionalMillionths, paymentInfo.feeBase),
                        RouteBlindingEncryptedDataTlv.PaymentConstraints(pathExpiry, paymentInfo.minHtlc)
                    )
                ).write().toByteVector()
                val blindedRoute = RouteBlinding.create(randomKey(), listOf(remoteNodeId, nodeParams.nodeId), listOf(remoteNodePayload, recipientPayload)).route
                val path = Bolt12Invoice.Companion.PaymentBlindedContactInfo(OfferTypes.ContactInfo.BlindedPath(blindedRoute), paymentInfo)
                val invoice = Bolt12Invoice(request, preimage, decrypted.blindedPrivateKey, nodeParams.bolt12InvoiceExpiry.inWholeSeconds, nodeParams.features.bolt12Features(), listOf(path))
                val destination = Destination.BlindedPath(decrypted.content.replyPath)
                when (val invoiceMessage = buildMessage(randomKey(), randomKey(), intermediateNodes(destination), destination, TlvStream(OnionMessagePayloadTlv.Invoice(invoice.records)))) {
                    is Left -> {
                        logger.warning { "offerId:${offer.offerId} pathId:${decrypted.pathId} ignoring invoice request, could not build onion message: ${invoiceMessage.value}" }
                        sendInvoiceError("failed to build onion message", decrypted.content.replyPath)
                    }
                    is Right -> {
                        logger.info { "sending BOLT 12 invoice with amount=${invoice.amount}, paymentHash=${invoice.paymentHash}, payerId=${invoice.invoiceRequest.payerId} to introduction node ${destination.route.firstNodeId}" }
                        OnionMessageAction.SendMessage(invoiceMessage.value)
                    }
                }
            }
        }
    }

    private fun sendInvoiceError(message: String, replyPath: RouteBlinding.BlindedRoute): OnionMessageAction.SendMessage? {
        val error = TlvStream<OnionMessagePayloadTlv>(OnionMessagePayloadTlv.InvoiceError(TlvStream(OfferTypes.Error(message))))
        val destination = Destination.BlindedPath(replyPath)
        return buildMessage(randomKey(), randomKey(), intermediateNodes(destination), destination, error)
            .right
            ?.let { OnionMessageAction.SendMessage(it) }
    }

    /** If our trampoline node is the introduction node, we don't need an intermediate encryption step. */
    private fun intermediateNodes(destination: Destination): List<IntermediateNode> {
        val needIntermediateHop = when (destination) {
            is Destination.BlindedPath -> when (val introduction = destination.route.firstNodeId) {
                is EncodedNodeId.WithPublicKey.Plain -> introduction.publicKey != remoteNodeId
                is EncodedNodeId.WithPublicKey.Wallet -> true
                is EncodedNodeId.ShortChannelIdDir -> true // we don't have access to the graph data and rely on our peer to resolve the scid
            }
            is Destination.Recipient -> destination.nodeId.publicKey != remoteNodeId
        }
        return if (needIntermediateHop) listOf(IntermediateNode(EncodedNodeId.WithPublicKey.Plain(remoteNodeId))) else listOf()
    }
}
