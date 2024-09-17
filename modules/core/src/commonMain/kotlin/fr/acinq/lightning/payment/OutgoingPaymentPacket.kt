package fr.acinq.lightning.payment

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.flatMap
import fr.acinq.lightning.*
import fr.acinq.lightning.channel.ChannelCommand
import fr.acinq.lightning.crypto.sphinx.FailurePacket
import fr.acinq.lightning.crypto.sphinx.Sphinx
import fr.acinq.lightning.router.NodeHop
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.wire.*

/**
 * Our outgoing payments always use trampoline: there are thus two layers of onion encryption.
 *
 * @param packet payment packet that should be included in [UpdateAddHtlc].
 * @param outerSharedSecrets shared secrets for the outer payment onion.
 * @param innerSharedSecrets shared secrets for the inner trampoline onion.
 */
data class OutgoingPacket(val packet: OnionRoutingPacket, val outerSharedSecrets: List<Sphinx.SharedSecret>, val innerSharedSecrets: List<Sphinx.SharedSecret>)

object OutgoingPaymentPacket {

    /**
     * Build an encrypted onion packet from onion payloads and node public keys.
     */
    fun buildOnion(nodes: List<PublicKey>, payloads: List<PaymentOnion.PerHopPayload>, associatedData: ByteVector32, payloadLength: Int? = null): Sphinx.PacketAndSecrets {
        val sessionKey = Lightning.randomKey()
        return buildOnion(sessionKey, nodes, payloads, associatedData, payloadLength)
    }

    fun buildOnion(sessionKey: PrivateKey, nodes: List<PublicKey>, payloads: List<PaymentOnion.PerHopPayload>, associatedData: ByteVector32, payloadLength: Int? = null): Sphinx.PacketAndSecrets {
        require(nodes.size == payloads.size)
        val payloadsBin = payloads.map { it.write() }
        val totalPayloadLength = payloadLength ?: payloadsBin.sumOf { it.size + Sphinx.MacLength }
        return Sphinx.create(sessionKey, nodes, payloadsBin, associatedData, totalPayloadLength)
    }

    /**
     * Build an encrypted payment onion packet when the final recipient supports trampoline.
     * The trampoline node will receive instructions on how much to relay to the final recipient.
     *
     * @param invoice a Bolt 11 invoice that contains the trampoline feature bit.
     * @param amount amount that should be received by the final recipient.
     * @param expiry cltv expiry that should be received by the final recipient.
     * @param hop the trampoline hop from the trampoline node to the recipient.
     */
    fun buildPacketToTrampolineRecipient(invoice: Bolt11Invoice, amount: MilliSatoshi, expiry: CltvExpiry, hop: NodeHop): Triple<MilliSatoshi, CltvExpiry, OutgoingPacket> {
        require(invoice.features.hasFeature(Feature.TrampolinePayment)) { "invoice must support trampoline" }
        val trampolineOnion = run {
            val finalPayload = PaymentOnion.FinalPayload.Standard.createSinglePartPayload(amount, expiry, invoice.paymentSecret, invoice.paymentMetadata)
            val trampolinePayload = PaymentOnion.NodeRelayPayload.create(amount, expiry, hop.nextNodeId)
            buildOnion(listOf(hop.nodeId, hop.nextNodeId), listOf(trampolinePayload, finalPayload), invoice.paymentHash)
        }
        val trampolineAmount = amount + hop.fee(amount)
        val trampolineExpiry = expiry + hop.cltvExpiryDelta
        // We generate a random secret to avoid leaking the invoice secret to the trampoline node.
        val trampolinePaymentSecret = Lightning.randomBytes32()
        val payload = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(trampolineAmount, trampolineAmount, trampolineExpiry, trampolinePaymentSecret, trampolineOnion.packet)
        val paymentOnion = buildOnion(listOf(hop.nodeId), listOf(payload), invoice.paymentHash, OnionRoutingPacket.PaymentPacketLength)
        return Triple(trampolineAmount, trampolineExpiry, OutgoingPacket(paymentOnion.packet, paymentOnion.sharedSecrets, trampolineOnion.sharedSecrets))
    }

    /**
     * Build an encrypted payment onion packet when the final recipient supports trampoline.
     * We use each hop in the blinded path as a trampoline hop, which doesn't reveal anything to our trampoline node.
     * From their point of view, they will be relaying a trampoline payment to another trampoline node.
     * They won't even know that a blinded path is being used.
     */
    fun buildPacketToTrampolineRecipient(paymentHash: ByteVector32, amount: MilliSatoshi, expiry: CltvExpiry, path: Bolt12Invoice.Companion.PaymentBlindedContactInfo, hop: NodeHop): Triple<MilliSatoshi, CltvExpiry, OutgoingPacket> {
        require(path.route.route.firstNodeId is EncodedNodeId.WithPublicKey) { "blinded path must provide the introduction node_id" }
        val (trampolineAmount, trampolineExpiry, trampolineOnion) = run {
            val blindedAmount = amount + path.paymentInfo.fee(amount)
            val blindedExpiry = expiry + path.paymentInfo.cltvExpiryDelta
            val blindedNodes = listOf(path.route.route.firstNodeId.publicKey) + path.route.route.blindedNodeIds.drop(1)
            val blindedPayloads = when {
                blindedNodes.size == 1 -> {
                    val finalPayload = PaymentOnion.FinalPayload.Blinded.create(amount, expiry, path.route.route.encryptedPayloads.last(), path.route.route.firstPathKey)
                    listOf(finalPayload)
                }
                else -> {
                    val finalPayload = PaymentOnion.FinalPayload.Blinded.create(amount, expiry, path.route.route.encryptedPayloads.last(), pathKey = null)
                    val intermediatePayloads = path.route.route.encryptedPayloads.drop(1).dropLast(1).map { PaymentOnion.BlindedChannelRelayPayload.create(it, pathKey = null) }
                    val introductionPayload = PaymentOnion.BlindedChannelRelayPayload.create(path.route.route.encryptedPayloads.first(), path.route.route.firstPathKey)
                    listOf(introductionPayload) + intermediatePayloads + listOf(finalPayload)
                }
            }
            val trampolinePayload = PaymentOnion.NodeRelayPayload.create(blindedAmount, blindedExpiry, blindedNodes.first())
            val trampolineOnion = buildOnion(listOf(hop.nodeId) + blindedNodes, listOf(trampolinePayload) + blindedPayloads, paymentHash)
            val trampolineAmount = blindedAmount + hop.fee(blindedAmount)
            val trampolineExpiry = blindedExpiry + hop.cltvExpiryDelta
            Triple(trampolineAmount, trampolineExpiry, trampolineOnion)
        }
        val trampolinePaymentSecret = Lightning.randomBytes32()
        val payload = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(trampolineAmount, trampolineAmount, trampolineExpiry, trampolinePaymentSecret, trampolineOnion.packet)
        val paymentOnion = buildOnion(listOf(hop.nodeId), listOf(payload), paymentHash, OnionRoutingPacket.PaymentPacketLength)
        return Triple(trampolineAmount, trampolineExpiry, OutgoingPacket(paymentOnion.packet, paymentOnion.sharedSecrets, trampolineOnion.sharedSecrets))
    }

    /**
     * Build an encrypted payment onion packet when the final recipient is our trampoline node.
     *
     * @param invoice a Bolt 11 invoice that contains the trampoline feature bit.
     * @param amount amount that should be received by the final recipient.
     * @param expiry cltv expiry that should be received by the final recipient.
     */
    fun buildPacketToTrampolinePeer(invoice: Bolt11Invoice, amount: MilliSatoshi, expiry: CltvExpiry): Triple<MilliSatoshi, CltvExpiry, OutgoingPacket> {
        require(invoice.features.hasFeature(Feature.TrampolinePayment)) { "invoice must support trampoline" }
        val trampolineOnion = run {
            val finalPayload = PaymentOnion.FinalPayload.Standard.createSinglePartPayload(amount, expiry, invoice.paymentSecret, invoice.paymentMetadata)
            buildOnion(listOf(invoice.nodeId), listOf(finalPayload), invoice.paymentHash)
        }
        val payload = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(amount, amount, expiry, invoice.paymentSecret, trampolineOnion.packet)
        val paymentOnion = buildOnion(listOf(invoice.nodeId), listOf(payload), invoice.paymentHash, OnionRoutingPacket.PaymentPacketLength)
        return Triple(amount, expiry, OutgoingPacket(paymentOnion.packet, paymentOnion.sharedSecrets, trampolineOnion.sharedSecrets))
    }

    /**
     * Build an encrypted trampoline onion packet when the final recipient doesn't support trampoline.
     * The trampoline node will receive instructions to convert to a legacy payment.
     * This reveals to the trampoline node who the recipient is and details from the invoice.
     * This must be deprecated once recipients support either trampoline or blinded paths.
     *
     * @param invoice a Bolt11 invoice (features and routing hints will be provided to the trampoline node).
     * @param amount amount that should be received by the final recipient.
     * @param expiry cltv expiry that should be received by the final recipient.
     * @param hop the trampoline hop from the trampoline node to the recipient.
     */
    fun buildPacketToLegacyRecipient(invoice: Bolt11Invoice, amount: MilliSatoshi, expiry: CltvExpiry, hop: NodeHop): Triple<MilliSatoshi, CltvExpiry, OutgoingPacket> {
        val trampolineOnion = run {
            var routingInfo = invoice.routingInfo
            var trampolinePayload = PaymentOnion.RelayToNonTrampolinePayload.create(amount, amount, expiry, hop.nextNodeId, invoice, routingInfo)
            var trampolineOnion = buildOnion(listOf(hop.nodeId), listOf(trampolinePayload), invoice.paymentHash)
            // Ensure that this onion can fit inside the outer 1300 bytes onion. The outer onion fields need ~150 bytes and we add some safety margin.
            while (trampolineOnion.packet.payload.size() > 1000) {
                routingInfo = routingInfo.dropLast(1)
                trampolinePayload = PaymentOnion.RelayToNonTrampolinePayload.create(amount, amount, expiry, hop.nextNodeId, invoice, routingInfo)
                trampolineOnion = buildOnion(listOf(hop.nodeId), listOf(trampolinePayload), invoice.paymentHash)
            }
            trampolineOnion
        }
        val trampolineAmount = amount + hop.fee(amount)
        val trampolineExpiry = expiry + hop.cltvExpiryDelta
        val payload = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(trampolineAmount, trampolineAmount, trampolineExpiry, invoice.paymentSecret, trampolineOnion.packet)
        val paymentOnion = buildOnion(listOf(hop.nodeId), listOf(payload), invoice.paymentHash, OnionRoutingPacket.PaymentPacketLength)
        return Triple(trampolineAmount, trampolineExpiry, OutgoingPacket(paymentOnion.packet, paymentOnion.sharedSecrets, trampolineOnion.sharedSecrets))
    }

    /**
     * Build an encrypted trampoline onion packet when the final recipient is using a blinded path.
     * The trampoline node will receive data from the invoice to allow them to pay the blinded path.
     * The data revealed to the trampoline node doesn't leak anything about the recipient's identity.
     * We only need a single trampoline node, who will find routes to the blinded paths.
     *
     * @param invoice a Bolt12 invoice (blinded path data will be provided to the trampoline node).
     * @param amount amount that should be received by the final recipient.
     * @param expiry cltv expiry that should be received by the final recipient.
     * @param hop the trampoline hop from the trampoline node to the recipient.
     */
    fun buildPacketToBlindedRecipient(invoice: Bolt12Invoice, amount: MilliSatoshi, expiry: CltvExpiry, hop: NodeHop): Triple<MilliSatoshi, CltvExpiry, OutgoingPacket> {
        val trampolineOnion = run {
            var blindedPaths = invoice.blindedPaths
            var trampolinePayload = PaymentOnion.RelayToBlindedPayload.create(amount, expiry, invoice.features, blindedPaths)
            var trampolineOnion = buildOnion(listOf(hop.nodeId), listOf(trampolinePayload), invoice.paymentHash)
            // Ensure that this onion can fit inside the outer 1300 bytes onion. The outer onion fields need ~150 bytes and we add some safety margin.
            while (trampolineOnion.packet.payload.size() > 1000) {
                blindedPaths = blindedPaths.dropLast(1)
                trampolinePayload = PaymentOnion.RelayToBlindedPayload.create(amount, expiry, invoice.features, blindedPaths)
                trampolineOnion = buildOnion(listOf(hop.nodeId), listOf(trampolinePayload), invoice.paymentHash)
            }
            trampolineOnion
        }
        val trampolineAmount = amount + hop.fee(amount)
        val trampolineExpiry = expiry + hop.cltvExpiryDelta
        // We generate a random secret to avoid leaking the invoice secret to the trampoline node.
        val trampolinePaymentSecret = Lightning.randomBytes32()
        val payload = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(trampolineAmount, trampolineAmount, trampolineExpiry, trampolinePaymentSecret, trampolineOnion.packet)
        val paymentOnion = buildOnion(listOf(hop.nodeId), listOf(payload), invoice.paymentHash, OnionRoutingPacket.PaymentPacketLength)
        return Triple(trampolineAmount, trampolineExpiry, OutgoingPacket(paymentOnion.packet, paymentOnion.sharedSecrets, trampolineOnion.sharedSecrets))
    }

    fun buildHtlcFailure(nodeSecret: PrivateKey, paymentHash: ByteVector32, onion: OnionRoutingPacket, reason: ChannelCommand.Htlc.Settlement.Fail.Reason): Either<FailureMessage, ByteVector> {
        return extractSharedSecrets(nodeSecret, paymentHash, onion).map {
            val (outerSecret, innerSecret) = it
            when (innerSecret) {
                null -> when (reason) {
                    is ChannelCommand.Htlc.Settlement.Fail.Reason.Bytes -> FailurePacket.wrap(reason.bytes.toByteArray(), outerSecret).toByteVector()
                    is ChannelCommand.Htlc.Settlement.Fail.Reason.Failure -> FailurePacket.create(outerSecret, reason.message).toByteVector()
                }
                else -> {
                    // We encrypt with the trampoline onion secret first.
                    val innerReason = when (reason) {
                        is ChannelCommand.Htlc.Settlement.Fail.Reason.Bytes -> FailurePacket.wrap(reason.bytes.toByteArray(), innerSecret)
                        is ChannelCommand.Htlc.Settlement.Fail.Reason.Failure -> FailurePacket.create(innerSecret, reason.message)
                    }
                    // And wrap it with the outer payment onion secret.
                    FailurePacket.wrap(innerReason, outerSecret).toByteVector()
                }
            }
        }
    }

    /** Extract the onion shared secret and if available the trampoline onion shared secret. */
    private fun extractSharedSecrets(nodeSecret: PrivateKey, paymentHash: ByteVector32, onion: OnionRoutingPacket): Either<FailureMessage, Pair<ByteVector32, ByteVector32?>> {
        // We decrypt the payment onion to obtain its shared secret.
        return Sphinx.peel(nodeSecret, paymentHash, onion).flatMap { outer ->
            // If it contains a trampoline onion, we decrypt it as well to obtain its shared secret.
            when (val trampolineOnion = PaymentOnion.PerHopPayload.read(outer.payload.toByteArray()).map { it.get<OnionPaymentPayloadTlv.TrampolineOnion>() }.right) {
                null -> Either.Right(Pair(outer.sharedSecret, null))
                else -> Sphinx.peel(nodeSecret, paymentHash, trampolineOnion.packet).map { Pair(outer.sharedSecret, it.sharedSecret) }
            }
        }
    }

    fun buildWillAddHtlcFailure(nodeSecret: PrivateKey, willAddHtlc: WillAddHtlc, failure: FailureMessage): OnTheFlyFundingMessage {
        val reason = ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(failure)
        return when (val f = buildHtlcFailure(nodeSecret, willAddHtlc.paymentHash, willAddHtlc.finalPacket, reason)) {
            is Either.Right -> WillFailHtlc(willAddHtlc.id, willAddHtlc.paymentHash, f.value)
            is Either.Left -> WillFailMalformedHtlc(willAddHtlc.id, willAddHtlc.paymentHash, Sphinx.hash(willAddHtlc.finalPacket), f.value.code)
        }
    }

}