package fr.acinq.lightning.payment

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.flatMap
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.crypto.RouteBlinding
import fr.acinq.lightning.crypto.sphinx.Sphinx
import fr.acinq.lightning.crypto.sphinx.Sphinx.hash
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.*

object IncomingPaymentPacket {

    /** Decrypt the onion packet of a received htlc. */
    fun decrypt(add: UpdateAddHtlc, privateKey: PrivateKey): Either<FailureMessage, PaymentOnion.FinalPayload> = decrypt(Either.Right(add), privateKey)

    /** Decrypt the onion packet of a received on-the-fly funding request. */
    fun decrypt(add: WillAddHtlc, privateKey: PrivateKey): Either<FailureMessage, PaymentOnion.FinalPayload> = decrypt(Either.Left(add), privateKey)

    /**
     * Decrypt the onion packet of a received htlc. We expect to be the final recipient, and we validate that the HTLC
     * fields match the onion fields (this prevents intermediate nodes from sending an invalid amount or expiry).
     *
     * @param add incoming htlc.
     * @param privateKey this node's private key.
     * @return either:
     *  - a decrypted and valid onion final payload
     *  - or a Bolt4 failure message that can be returned to the sender if the HTLC is invalid
     */
    fun decrypt(add: Either<WillAddHtlc, UpdateAddHtlc>, privateKey: PrivateKey): Either<FailureMessage, PaymentOnion.FinalPayload> {
        // The previous node may forward a smaller amount than expected to cover liquidity fees.
        // But the amount used for validation should take this funding fee into account.
        // We will verify later in the IncomingPaymentHandler whether the funding fee is valid or not.
        val htlcAmount = add.fold({ it.amount }, { it.amountMsat + (it.fundingFee?.amount ?: 0.msat) })
        val htlcExpiry = add.fold({ it.expiry }, { it.cltvExpiry })
        val paymentHash = add.fold({ it.paymentHash }, { it.paymentHash })
        val pathKey = add.fold({ it.pathKey }, { it.pathKey })
        val onion = add.fold({ it.finalPacket }, { it.onionRoutingPacket })
        return decryptOnion(paymentHash, onion, privateKey, pathKey).flatMap { outer ->
            when (outer) {
                is PaymentOnion.FinalPayload.Standard ->
                    when (val trampolineOnion = outer.records.get<OnionPaymentPayloadTlv.TrampolineOnion>()) {
                        null -> validate(htlcAmount, htlcExpiry, outer)
                        else -> {
                            when (val inner = decryptOnion(paymentHash, trampolineOnion.packet, privateKey, outer.records.get<OnionPaymentPayloadTlv.PathKey>()?.publicKey)) {
                                is Either.Left -> Either.Left(inner.value)
                                is Either.Right -> when (val innerPayload = inner.value) {
                                    is PaymentOnion.FinalPayload.Standard -> validate(htlcAmount, htlcExpiry, outer, innerPayload)
                                    is PaymentOnion.FinalPayload.Blinded -> validate(htlcAmount, htlcExpiry, trampolineOnion.packet, innerPayload)
                                }
                            }
                        }
                    }
                is PaymentOnion.FinalPayload.Blinded -> validate(htlcAmount, htlcExpiry, onion, outer)
            }
        }
    }

    private fun decryptOnion(paymentHash: ByteVector32, packet: OnionRoutingPacket, privateKey: PrivateKey, pathKey: PublicKey?): Either<FailureMessage, PaymentOnion.FinalPayload> {
        val onionDecryptionKey = pathKey?.let { RouteBlinding.derivePrivateKey(privateKey, it) } ?: privateKey
        return Sphinx.peel(onionDecryptionKey, paymentHash, packet).flatMap { decrypted ->
            when {
                !decrypted.isLastPacket -> Either.Left(UnknownNextPeer)
                else -> PaymentOnion.PerHopPayload.read(decrypted.payload.toByteArray()).flatMap { tlvs ->
                    when (val encryptedRecipientData = tlvs.get<OnionPaymentPayloadTlv.EncryptedRecipientData>()?.data) {
                        null -> when {
                            pathKey != null -> Either.Left(InvalidOnionBlinding(hash(packet)))
                            else -> PaymentOnion.FinalPayload.Standard.read(decrypted.payload)
                        }
                        else -> when {
                            // We're never the introduction node of a blinded path, since we don't have public channels.
                            tlvs.get<OnionPaymentPayloadTlv.PathKey>() != null -> Either.Left(InvalidOnionBlinding(hash(packet)))
                            // We must receive the path key to be able to decrypt the blinded path data.
                            pathKey == null -> Either.Left(InvalidOnionBlinding(hash(packet)))
                            else -> when (val payload = decryptRecipientData(privateKey, pathKey, encryptedRecipientData, tlvs)) {
                                is Either.Left -> Either.Left(InvalidOnionBlinding(hash(packet)))
                                is Either.Right -> Either.Right(payload.value)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun decryptRecipientData(privateKey: PrivateKey, pathKey: PublicKey, data: ByteVector, tlvs: TlvStream<OnionPaymentPayloadTlv>): Either<InvalidTlvPayload, PaymentOnion.FinalPayload.Blinded> {
        return RouteBlinding.decryptPayload(privateKey, pathKey, data)
            .flatMap { (decryptedRecipientData, _) -> RouteBlindingEncryptedData.read(decryptedRecipientData.toByteArray()) }
            .flatMap { blindedTlvs -> PaymentOnion.FinalPayload.Blinded.validate(tlvs, blindedTlvs) }
    }

    private fun validate(htlcAmount: MilliSatoshi, htlcExpiry: CltvExpiry, payload: PaymentOnion.FinalPayload.Standard): Either<FailureMessage, PaymentOnion.FinalPayload> {
        return when {
            htlcAmount < payload.amount -> Either.Left(FinalIncorrectHtlcAmount(htlcAmount))
            htlcExpiry < payload.expiry -> Either.Left(FinalIncorrectCltvExpiry(htlcExpiry))
            else -> Either.Right(payload)
        }
    }

    private fun validate(htlcAmount: MilliSatoshi, htlcExpiry: CltvExpiry, onion: OnionRoutingPacket, payload: PaymentOnion.FinalPayload.Blinded): Either<FailureMessage, PaymentOnion.FinalPayload> {
        return when {
            payload.recipientData.paymentConstraints?.let { htlcAmount < it.minAmount } == true -> Either.Left(InvalidOnionBlinding(hash(onion)))
            payload.recipientData.paymentConstraints?.let { it.maxCltvExpiry < htlcExpiry } == true -> Either.Left(InvalidOnionBlinding(hash(onion)))
            // We currently don't set the allowed_features field in our invoices.
            !Features.areCompatible(Features.empty, payload.recipientData.allowedFeatures) -> Either.Left(InvalidOnionBlinding(hash(onion)))
            htlcAmount < payload.amount -> Either.Left(InvalidOnionBlinding(hash(onion)))
            htlcExpiry < payload.expiry -> Either.Left(InvalidOnionBlinding(hash(onion)))
            else -> Either.Right(payload)
        }
    }

    private fun validate(htlcAmount: MilliSatoshi, htlcExpiry: CltvExpiry, outerPayload: PaymentOnion.FinalPayload.Standard, innerPayload: PaymentOnion.FinalPayload.Standard): Either<FailureMessage, PaymentOnion.FinalPayload> {
        return when {
            htlcAmount < outerPayload.amount -> Either.Left(FinalIncorrectHtlcAmount(htlcAmount))
            htlcExpiry < outerPayload.expiry -> Either.Left(FinalIncorrectCltvExpiry(htlcExpiry))
            // previous trampoline didn't forward the right expiry
            outerPayload.expiry != innerPayload.expiry -> Either.Left(FinalIncorrectCltvExpiry(htlcExpiry))
            // previous trampoline didn't forward the right amount
            outerPayload.totalAmount != innerPayload.amount -> Either.Left(FinalIncorrectHtlcAmount(outerPayload.totalAmount))
            else -> {
                // We merge contents from the outer and inner payloads.
                // We must use the inner payload's total amount and payment secret because the payment may be split between multiple trampoline payments (#reckless).
                Either.Right(PaymentOnion.FinalPayload.Standard.createMultiPartPayload(outerPayload.amount, innerPayload.totalAmount, outerPayload.expiry, innerPayload.paymentSecret, innerPayload.paymentMetadata))
            }
        }
    }

}