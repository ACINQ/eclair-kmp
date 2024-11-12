package fr.acinq.lightning.wire

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.Either.Left
import fr.acinq.bitcoin.utils.Either.Right
import fr.acinq.bitcoin.utils.Try
import fr.acinq.bitcoin.utils.runTrying
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.crypto.RouteBlinding
import fr.acinq.lightning.message.OnionMessages

/**
 * Lightning Bolt 12 offers
 * see https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
 */
object OfferTypes {
    /** Data provided to reach the issuer of an offer or invoice. */
    sealed class ContactInfo {
        abstract val nodeId: PublicKey

        /** If the offer or invoice issuer doesn't want to hide their identity, they can directly share their public nodeId. */
        data class RecipientNodeId(override val nodeId: PublicKey) : ContactInfo()

        /** If the offer or invoice issuer wants to hide their identity, they instead provide blinded paths. */
        data class BlindedPath(val route: RouteBlinding.BlindedRoute) : ContactInfo() {
            override val nodeId: PublicKey = route.blindedNodeIds.last()
        }
    }

    fun writePath(path: ContactInfo.BlindedPath, out: Output) {
        LightningCodecs.writeEncodedNodeId(path.route.introductionNodeId, out)
        LightningCodecs.writeBytes(path.route.blindingKey.value, out)
        LightningCodecs.writeByte(path.route.blindedNodes.size, out)
        for (node in path.route.blindedNodes) {
            LightningCodecs.writeBytes(node.blindedPublicKey.value, out)
            LightningCodecs.writeU16(node.encryptedPayload.size(), out)
            LightningCodecs.writeBytes(node.encryptedPayload, out)
        }
    }

    fun readPath(input: Input): ContactInfo.BlindedPath {
        val introductionNodeId = LightningCodecs.encodedNodeId(input)
        val blindingKey = PublicKey(LightningCodecs.bytes(input, 33))
        val blindedNodes = ArrayList<RouteBlinding.BlindedNode>()
        val numBlindedNodes = LightningCodecs.byte(input)
        for (i in 1..numBlindedNodes) {
            val blindedKey = PublicKey(LightningCodecs.bytes(input, 33))
            val payload = ByteVector(LightningCodecs.bytes(input, LightningCodecs.u16(input)))
            blindedNodes.add(RouteBlinding.BlindedNode(blindedKey, payload))
        }
        return ContactInfo.BlindedPath(RouteBlinding.BlindedRoute(introductionNodeId, blindingKey, blindedNodes))
    }

    sealed class Bolt12Tlv : Tlv

    sealed class InvoiceTlv : Bolt12Tlv()

    sealed class InvoiceRequestTlv : InvoiceTlv()

    sealed class OfferTlv : InvoiceRequestTlv()

    sealed class InvoiceErrorTlv : Bolt12Tlv()

    /**
     * Chains for which the offer is valid. If empty, bitcoin mainnet is implied.
     */
    data class OfferChains(val chains: List<BlockHash>) : OfferTlv() {
        override val tag: Long get() = OfferChains.tag

        override fun write(out: Output) {
            for (chain in chains) {
                LightningCodecs.writeBytes(chain.value, out)
            }
        }

        companion object : TlvValueReader<OfferChains> {
            const val tag: Long = 2
            override fun read(input: Input): OfferChains {
                val chains = ArrayList<BlockHash>()
                while (input.availableBytes > 0) {
                    chains.add(BlockHash(LightningCodecs.bytes(input, 32)))
                }
                return OfferChains(chains)
            }
        }
    }

    /**
     * Data from the offer creator to themselves, for instance a signature that authenticates the offer so that they don't need to store the offer.
     */
    data class OfferMetadata(val data: ByteVector) : OfferTlv() {
        override val tag: Long get() = OfferMetadata.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(data, out)
        }

        companion object : TlvValueReader<OfferMetadata> {
            const val tag: Long = 4
            override fun read(input: Input): OfferMetadata {
                return OfferMetadata(ByteVector(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * Three-letter code of the currency the offer is denominated in. If empty, bitcoin is implied.
     */
    data class OfferCurrency(val iso4217: String) : OfferTlv() {
        override val tag: Long get() = OfferCurrency.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(iso4217.encodeToByteArray(), out)
        }

        companion object : TlvValueReader<OfferCurrency> {
            const val tag: Long = 6
            override fun read(input: Input): OfferCurrency {
                return OfferCurrency(LightningCodecs.bytes(input, input.availableBytes).decodeToString())
            }
        }
    }

    /**
     * Amount to pay per item. As we only support bitcoin, the amount is in msat.
     */
    data class OfferAmount(val amount: MilliSatoshi) : OfferTlv() {
        override val tag: Long get() = OfferAmount.tag

        override fun write(out: Output) {
            LightningCodecs.writeTU64(amount.toLong(), out)
        }

        companion object : TlvValueReader<OfferAmount> {
            const val tag: Long = 8
            override fun read(input: Input): OfferAmount {
                return OfferAmount(MilliSatoshi(LightningCodecs.tu64(input)))
            }
        }
    }

    /**
     * Description of the purpose of the payment.
     */
    data class OfferDescription(val description: String) : OfferTlv() {
        override val tag: Long get() = OfferDescription.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(description.encodeToByteArray(), out)
        }

        companion object : TlvValueReader<OfferDescription> {
            const val tag: Long = 10
            override fun read(input: Input): OfferDescription {
                return OfferDescription(LightningCodecs.bytes(input, input.availableBytes).decodeToString())
            }
        }
    }

    /**
     * Features supported to pay the offer.
     */
    data class OfferFeatures(val features: Features) : OfferTlv() {
        override val tag: Long get() = OfferFeatures.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(features.toByteArray(), out)
        }

        companion object : TlvValueReader<OfferFeatures> {
            const val tag: Long = 12
            override fun read(input: Input): OfferFeatures {
                return OfferFeatures(Features(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * Time after which the offer is no longer valid.
     */
    data class OfferAbsoluteExpiry(val absoluteExpirySeconds: Long) : OfferTlv() {
        override val tag: Long get() = OfferAbsoluteExpiry.tag

        override fun write(out: Output) {
            LightningCodecs.writeTU64(absoluteExpirySeconds, out)
        }

        companion object : TlvValueReader<OfferAbsoluteExpiry> {
            const val tag: Long = 14
            override fun read(input: Input): OfferAbsoluteExpiry {
                return OfferAbsoluteExpiry(LightningCodecs.tu64(input))
            }
        }
    }

    /**
     * Paths that can be used to retrieve an invoice.
     */
    data class OfferPaths(val paths: List<ContactInfo.BlindedPath>) : OfferTlv() {
        override val tag: Long get() = OfferPaths.tag

        override fun write(out: Output) {
            for (path in paths) {
                writePath(path, out)
            }
        }

        companion object : TlvValueReader<OfferPaths> {
            const val tag: Long = 16
            override fun read(input: Input): OfferPaths {
                val paths = ArrayList<ContactInfo.BlindedPath>()
                while (input.availableBytes > 0) {
                    val path = readPath(input)
                    paths.add(path)
                }
                return OfferPaths(paths)
            }
        }
    }

    /**
     * Name of the offer creator.
     */
    data class OfferIssuer(val issuer: String) : OfferTlv() {
        override val tag: Long get() = OfferIssuer.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(issuer.encodeToByteArray(), out)
        }

        companion object : TlvValueReader<OfferIssuer> {
            const val tag: Long = 18
            override fun read(input: Input): OfferIssuer {
                return OfferIssuer(LightningCodecs.bytes(input, input.availableBytes).decodeToString())
            }
        }
    }

    /**
     * If present, the item described in the offer can be purchased multiple times with a single payment.
     * If max = 0, there is no limit on the quantity that can be purchased in a single payment.
     * If max > 1, it corresponds to the maximum number of items that be purchased in a single payment.
     */
    data class OfferQuantityMax(val max: Long) : OfferTlv() {
        override val tag: Long get() = OfferQuantityMax.tag

        override fun write(out: Output) {
            LightningCodecs.writeTU64(max, out)
        }

        companion object : TlvValueReader<OfferQuantityMax> {
            const val tag: Long = 20
            override fun read(input: Input): OfferQuantityMax {
                return OfferQuantityMax(LightningCodecs.tu64(input))
            }
        }
    }

    /**
     * Public key of the offer issuer.
     * If `OfferPaths` is present, they must be used to retrieve an invoice even if this public key corresponds to a node id in the public network.
     * If `OfferPaths` is not present, this public key must correspond to a node id in the public network that needs to be contacted to retrieve an invoice.
     */
    data class OfferIssuerId(val publicKey: PublicKey) : OfferTlv() {
        override val tag: Long get() = OfferIssuerId.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(publicKey.value, out)
        }

        companion object : TlvValueReader<OfferIssuerId> {
            const val tag: Long = 22
            override fun read(input: Input): OfferIssuerId {
                return OfferIssuerId(PublicKey(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * Random data to provide enough entropy so that some fields of the invoice request / invoice can be revealed without revealing the others.
     */
    data class InvoiceRequestMetadata(val data: ByteVector) : InvoiceRequestTlv() {
        override val tag: Long get() = InvoiceRequestMetadata.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(data, out)
        }

        companion object : TlvValueReader<InvoiceRequestMetadata> {
            const val tag: Long = 0
            override fun read(input: Input): InvoiceRequestMetadata {
                return InvoiceRequestMetadata(ByteVector(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * If `OfferChains` is present, this specifies which chain is going to be used to pay.
     */
    data class InvoiceRequestChain(val hash: BlockHash) : InvoiceRequestTlv() {
        override val tag: Long get() = InvoiceRequestChain.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(hash.value, out)
        }

        companion object : TlvValueReader<InvoiceRequestChain> {
            const val tag: Long = 80
            override fun read(input: Input): InvoiceRequestChain {
                return InvoiceRequestChain(BlockHash(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * Amount that the sender is going to send.
     */
    data class InvoiceRequestAmount(val amount: MilliSatoshi) : InvoiceRequestTlv() {
        override val tag: Long get() = InvoiceRequestAmount.tag

        override fun write(out: Output) {
            LightningCodecs.writeTU64(amount.toLong(), out)
        }

        companion object : TlvValueReader<InvoiceRequestAmount> {
            const val tag: Long = 82
            override fun read(input: Input): InvoiceRequestAmount {
                return InvoiceRequestAmount(MilliSatoshi(LightningCodecs.tu64(input)))
            }
        }
    }

    /**
     * Features supported by the sender to pay the offer.
     */
    data class InvoiceRequestFeatures(val features: Features) : InvoiceRequestTlv() {
        override val tag: Long get() = InvoiceRequestFeatures.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(features.toByteArray(), out)
        }

        companion object : TlvValueReader<InvoiceRequestFeatures> {
            const val tag: Long = 84
            override fun read(input: Input): InvoiceRequestFeatures {
                return InvoiceRequestFeatures(Features(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * Number of items to purchase. Only use if the offer supports purchasing multiple items at once.
     */
    data class InvoiceRequestQuantity(val quantity: Long) : InvoiceRequestTlv() {
        override val tag: Long get() = InvoiceRequestQuantity.tag

        override fun write(out: Output) {
            LightningCodecs.writeTU64(quantity, out)
        }

        companion object : TlvValueReader<InvoiceRequestQuantity> {
            const val tag: Long = 86
            override fun read(input: Input): InvoiceRequestQuantity {
                return InvoiceRequestQuantity(LightningCodecs.tu64(input))
            }
        }
    }

    /**
     * A public key for which the sender knows the corresponding private key.
     * This can be used to prove that you are the sender.
     */
    data class InvoiceRequestPayerId(val publicKey: PublicKey) : InvoiceRequestTlv() {
        override val tag: Long get() = InvoiceRequestPayerId.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(publicKey.value, out)
        }

        companion object : TlvValueReader<InvoiceRequestPayerId> {
            const val tag: Long = 88
            override fun read(input: Input): InvoiceRequestPayerId {
                return InvoiceRequestPayerId(PublicKey(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * A message from the sender.
     */
    data class InvoiceRequestPayerNote(val note: String) : InvoiceRequestTlv() {
        override val tag: Long get() = InvoiceRequestPayerNote.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(note.encodeToByteArray(), out)
        }

        companion object : TlvValueReader<InvoiceRequestPayerNote> {
            const val tag: Long = 89
            override fun read(input: Input): InvoiceRequestPayerNote {
                return InvoiceRequestPayerNote(LightningCodecs.bytes(input, input.availableBytes).decodeToString())
            }
        }
    }

    /**
     * Payment paths to send the payment to.
     */
    data class InvoicePaths(val paths: List<ContactInfo.BlindedPath>) : InvoiceTlv() {
        override val tag: Long get() = InvoicePaths.tag

        override fun write(out: Output) {
            for (path in paths) {
                writePath(path, out)
            }
        }

        companion object : TlvValueReader<InvoicePaths> {
            const val tag: Long = 160
            override fun read(input: Input): InvoicePaths {
                val paths = ArrayList<ContactInfo.BlindedPath>()
                while (input.availableBytes > 0) {
                    val path = readPath(input)
                    paths.add(path)
                }
                return InvoicePaths(paths)
            }
        }
    }

    data class PaymentInfo(
        val feeBase: MilliSatoshi,
        val feeProportionalMillionths: Long,
        val cltvExpiryDelta: CltvExpiryDelta,
        val minHtlc: MilliSatoshi,
        val maxHtlc: MilliSatoshi,
        val allowedFeatures: Features
    ) {
        fun fee(amount: MilliSatoshi): MilliSatoshi {
            return feeBase + amount * feeProportionalMillionths / 1_000_000L
        }
    }

    fun writePaymentInfo(paymentInfo: PaymentInfo, out: Output) {
        LightningCodecs.writeU32(paymentInfo.feeBase.msat.toInt(), out)
        LightningCodecs.writeU32(paymentInfo.feeProportionalMillionths.toInt(), out)
        LightningCodecs.writeU16(paymentInfo.cltvExpiryDelta.toInt(), out)
        LightningCodecs.writeU64(paymentInfo.minHtlc.msat, out)
        LightningCodecs.writeU64(paymentInfo.maxHtlc.msat, out)
        val featuresArray = paymentInfo.allowedFeatures.toByteArray()
        LightningCodecs.writeU16(featuresArray.size, out)
        LightningCodecs.writeBytes(featuresArray, out)
    }

    fun readPaymentInfo(input: Input): PaymentInfo {
        val feeBase = MilliSatoshi(LightningCodecs.u32(input).toLong())
        val feeProportionalMillionths = LightningCodecs.u32(input)
        val cltvExpiryDelta = CltvExpiryDelta(LightningCodecs.u16(input))
        val minHtlc = MilliSatoshi(LightningCodecs.u64(input))
        val maxHtlc = MilliSatoshi(LightningCodecs.u64(input))
        val allowedFeatures = Features(LightningCodecs.bytes(input, LightningCodecs.u16(input)))
        return PaymentInfo(feeBase, feeProportionalMillionths.toLong(), cltvExpiryDelta, minHtlc, maxHtlc, allowedFeatures)
    }

    /**
     * Costs and parameters of the paths in `InvoicePaths`.
     */
    data class InvoiceBlindedPay(val paymentInfos: List<PaymentInfo>) : InvoiceTlv() {
        override val tag: Long get() = InvoiceBlindedPay.tag

        override fun write(out: Output) {
            for (paymentInfo in paymentInfos) {
                writePaymentInfo(paymentInfo, out)
            }
        }

        companion object : TlvValueReader<InvoiceBlindedPay> {
            const val tag: Long = 162
            override fun read(input: Input): InvoiceBlindedPay {
                val paymentInfos = ArrayList<PaymentInfo>()
                while (input.availableBytes > 0) {
                    paymentInfos.add(readPaymentInfo(input))
                }
                return InvoiceBlindedPay(paymentInfos)
            }
        }
    }

    /**
     * Time at which the invoice was created.
     */
    data class InvoiceCreatedAt(val timestampSeconds: Long) : InvoiceTlv() {
        override val tag: Long get() = InvoiceCreatedAt.tag

        override fun write(out: Output) {
            LightningCodecs.writeTU64(timestampSeconds, out)
        }

        companion object : TlvValueReader<InvoiceCreatedAt> {
            const val tag: Long = 164
            override fun read(input: Input): InvoiceCreatedAt {
                return InvoiceCreatedAt(LightningCodecs.tu64(input))
            }
        }
    }

    /**
     * Duration after which the invoice can no longer be paid.
     */
    data class InvoiceRelativeExpiry(val seconds: Long) : InvoiceTlv() {
        override val tag: Long get() = InvoiceRelativeExpiry.tag

        override fun write(out: Output) {
            LightningCodecs.writeTU64(seconds, out)
        }

        companion object : TlvValueReader<InvoiceRelativeExpiry> {
            const val tag: Long = 166
            override fun read(input: Input): InvoiceRelativeExpiry {
                return InvoiceRelativeExpiry(LightningCodecs.tu64(input))
            }
        }
    }

    /**
     * Hash whose preimage will be released in exchange for the payment.
     */
    data class InvoicePaymentHash(val hash: ByteVector32) : InvoiceTlv() {
        override val tag: Long get() = InvoicePaymentHash.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(hash, out)
        }

        companion object : TlvValueReader<InvoicePaymentHash> {
            const val tag: Long = 168
            override fun read(input: Input): InvoicePaymentHash {
                return InvoicePaymentHash(ByteVector32(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * Amount to pay. Must be the same as `InvoiceRequestAmount` if it was present.
     */
    data class InvoiceAmount(val amount: MilliSatoshi) : InvoiceTlv() {
        override val tag: Long get() = InvoiceAmount.tag

        override fun write(out: Output) {
            LightningCodecs.writeTU64(amount.toLong(), out)
        }

        companion object : TlvValueReader<InvoiceAmount> {
            const val tag: Long = 170
            override fun read(input: Input): InvoiceAmount {
                return InvoiceAmount(MilliSatoshi(LightningCodecs.tu64(input)))
            }
        }
    }

    data class FallbackAddress(val version: Int, val value: ByteVector)

    /**
     * Onchain addresses to use to pay the invoice in case the lightning payment fails.
     */
    data class InvoiceFallbacks(val addresses: List<FallbackAddress>) : InvoiceTlv() {
        override val tag: Long get() = InvoiceFallbacks.tag

        override fun write(out: Output) {
            for (address in addresses) {
                LightningCodecs.writeByte(address.version, out)
                LightningCodecs.writeU16(address.value.size(), out)
                LightningCodecs.writeBytes(address.value, out)
            }
        }

        companion object : TlvValueReader<InvoiceFallbacks> {
            const val tag: Long = 172
            override fun read(input: Input): InvoiceFallbacks {
                val addresses = ArrayList<FallbackAddress>()
                while (input.availableBytes > 0) {
                    val version = LightningCodecs.byte(input)
                    val value = ByteVector(LightningCodecs.bytes(input, LightningCodecs.u16(input)))
                    addresses.add(FallbackAddress(version, value))
                }
                return InvoiceFallbacks(addresses)
            }
        }
    }

    /**
     * Features supported to pay the invoice.
     */
    data class InvoiceFeatures(val features: Features) : InvoiceTlv() {
        override val tag: Long get() = InvoiceFeatures.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(features.toByteArray(), out)
        }

        companion object : TlvValueReader<InvoiceFeatures> {
            const val tag: Long = 174
            override fun read(input: Input): InvoiceFeatures {
                return InvoiceFeatures(Features(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * Public key of the invoice recipient.
     */
    data class InvoiceNodeId(val nodeId: PublicKey) : InvoiceTlv() {
        override val tag: Long get() = InvoiceNodeId.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(nodeId.value, out)
        }

        companion object : TlvValueReader<InvoiceNodeId> {
            const val tag: Long = 176
            override fun read(input: Input): InvoiceNodeId {
                return InvoiceNodeId(PublicKey(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    /**
     * Signature from the sender when used in an invoice request.
     * Signature from the recipient when used in an invoice.
     */
    data class Signature(val signature: ByteVector64) : InvoiceRequestTlv() {
        override val tag: Long get() = Signature.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(signature, out)
        }

        companion object : TlvValueReader<Signature> {
            const val tag: Long = 240
            override fun read(input: Input): Signature {
                return Signature(ByteVector64(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    private fun isOfferTlv(tlv: GenericTlv): Boolean {
        // Offer TLVs are in the range [1, 79] or [1000000000, 1999999999].
        return tlv.tag in 1..79 || tlv.tag in 1000000000..1999999999
    }

    private fun isInvoiceRequestTlv(tlv: GenericTlv): Boolean {
        // Invoice request TLVs are in the range [0, 159] or [1000000000, 2999999999].
        return tlv.tag in 0..159 || tlv.tag in 1000000000..2999999999
    }

    fun filterOfferFields(tlvs: TlvStream<InvoiceRequestTlv>): TlvStream<OfferTlv> {
        return TlvStream(
            tlvs.records.filterIsInstance<OfferTlv>().toSet(),
            tlvs.unknown.filter { isOfferTlv(it) }.toSet()
        )
    }

    fun filterInvoiceRequestFields(tlvs: TlvStream<InvoiceTlv>): TlvStream<InvoiceRequestTlv> {
        return TlvStream(
            tlvs.records.filterIsInstance<InvoiceRequestTlv>().toSet(),
            tlvs.unknown.filter { isInvoiceRequestTlv(it) }.toSet()
        )
    }

    data class ErroneousField(val fieldTag: Long) : InvoiceErrorTlv() {
        override val tag: Long get() = ErroneousField.tag

        override fun write(out: Output) {
            LightningCodecs.writeTU64(fieldTag, out)
        }

        companion object : TlvValueReader<ErroneousField> {
            const val tag: Long = 1
            override fun read(input: Input): ErroneousField {
                return ErroneousField(LightningCodecs.tu64(input))
            }
        }
    }

    data class SuggestedValue(val value: ByteVector) : InvoiceErrorTlv() {
        override val tag: Long get() = SuggestedValue.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(value, out)
        }

        companion object : TlvValueReader<SuggestedValue> {
            const val tag: Long = 3
            override fun read(input: Input): SuggestedValue {
                return SuggestedValue(ByteVector(LightningCodecs.bytes(input, input.availableBytes)))
            }
        }
    }

    data class Error(val message: String) : InvoiceErrorTlv() {
        override val tag: Long get() = Error.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(message.encodeToByteArray(), out)
        }

        companion object : TlvValueReader<Error> {
            const val tag: Long = 5
            override fun read(input: Input): Error {
                return Error(LightningCodecs.bytes(input, input.availableBytes).decodeToString())
            }
        }
    }

    data class Offer(val records: TlvStream<OfferTlv>) {
        val chains: List<BlockHash> = records.get<OfferChains>()?.chains ?: listOf(Block.LivenetGenesisBlock.hash)
        val metadata: ByteVector? = records.get<OfferMetadata>()?.data
        val currency: String? = records.get<OfferCurrency>()?.iso4217
        val amount: MilliSatoshi? = if (currency == null) {
            records.get<OfferAmount>()?.amount
        } else {
            null // TODO: add exchange rates
        }
        val description: String? = records.get<OfferDescription>()?.description
        val features: Features = records.get<OfferFeatures>()?.features ?: Features.empty
        val expirySeconds: Long? = records.get<OfferAbsoluteExpiry>()?.absoluteExpirySeconds
        val paths: List<ContactInfo.BlindedPath>? = records.get<OfferPaths>()?.paths
        val issuer: String? = records.get<OfferIssuer>()?.issuer
        val quantityMax: Long? = records.get<OfferQuantityMax>()?.max?.let { if (it == 0L) Long.MAX_VALUE else it }
        val issuerId: PublicKey? = records.get<OfferIssuerId>()?.publicKey
        // A valid offer must contain a blinded path or an issuerId (and may contain both).
        // When both are provided, the blinded paths should be tried first.
        val contactInfos: List<ContactInfo> = paths ?: listOf(ContactInfo.RecipientNodeId(issuerId!!))

        fun encode(): String {
            val data = tlvSerializer.write(records)
            return Bech32.encodeBytes(hrp, data, Bech32.Encoding.Beck32WithoutChecksum)
        }

        override fun toString(): String = encode()

        val offerId: ByteVector32 = rootHash(records)

        companion object {
            val hrp = "lno"

            /**
             * Create an offer without using a blinded path to hide our nodeId.
             *
             * @param amount amount if it can be determined at offer creation time.
             * @param description description of the offer (may be null if [amount] is also null).
             * @param nodeId the nodeId to use for this offer.
             * @param features invoice features.
             * @param chain chain on which the offer is valid.
             */
            internal fun createNonBlindedOffer(
                amount: MilliSatoshi?,
                description: String?,
                nodeId: PublicKey,
                features: Features,
                chain: BlockHash,
                additionalTlvs: Set<OfferTlv> = setOf(),
                customTlvs: Set<GenericTlv> = setOf()
            ): Offer {
                if (description == null) require(amount == null) { "an offer description must be provided if the amount isn't null" }
                val tlvs: Set<OfferTlv> = setOfNotNull(
                    if (chain != Block.LivenetGenesisBlock.hash) OfferChains(listOf(chain)) else null,
                    amount?.let { OfferAmount(it) },
                    description?.let { OfferDescription(it) },
                    features.bolt12Features().let { if (it != Features.empty) OfferFeatures(it) else null },
                    OfferIssuerId(nodeId)
                )
                return Offer(TlvStream(tlvs + additionalTlvs, customTlvs))
            }

            /**
             * Create an offer using a single-hop blinded path going through our trampoline node.
             *
             * @param amount amount if it can be determined at offer creation time.
             * @param description description of the offer (may be null if [amount] is also null).
             * @param nodeParams our node parameters.
             * @param trampolineNodeId our trampoline node.
             * @param features features that should be advertised in the offer.
             * @param blindingSecret session key used for the blinded path included in the offer.
             * @param pathId path id for this offer's blinded path.
             */
            fun createBlindedOffer(
                amount: MilliSatoshi?,
                description: String?,
                nodeParams: NodeParams,
                trampolineNodeId: PublicKey,
                features: Features,
                blindingSecret: PrivateKey,
                pathId: ByteVector32?,
                additionalTlvs: Set<OfferTlv> = setOf(),
                customTlvs: Set<GenericTlv> = setOf()
            ): Pair<Offer, PrivateKey> {
                if (description == null) require(amount == null) { "an offer description must be provided if the amount isn't null" }
                val blindedRouteDetails = OnionMessages.buildRouteToRecipient(blindingSecret, listOf(OnionMessages.IntermediateNode(EncodedNodeId.WithPublicKey.Plain(trampolineNodeId))), OnionMessages.Destination.Recipient(EncodedNodeId.WithPublicKey.Wallet(nodeParams.nodeId), pathId))
                val tlvs: Set<OfferTlv> = setOfNotNull(
                    if (nodeParams.chainHash != Block.LivenetGenesisBlock.hash) OfferChains(listOf(nodeParams.chainHash)) else null,
                    amount?.let { OfferAmount(it) },
                    description?.let { OfferDescription(it) },
                    features.bolt12Features().let { if (it != Features.empty) OfferFeatures(it) else null },
                    // Note that we don't include an offer_node_id since we're using a blinded path.
                    OfferPaths(listOf(ContactInfo.BlindedPath(blindedRouteDetails.route))),
                )
                return Pair(Offer(TlvStream(tlvs + additionalTlvs, customTlvs)), blindedRouteDetails.blindedPrivateKey(nodeParams.nodePrivateKey))
            }

            fun validate(records: TlvStream<OfferTlv>): Either<InvalidTlvPayload, Offer> {
                if (records.get<OfferDescription>() == null && records.get<OfferAmount>() != null) return Left(MissingRequiredTlv(10))
                if (records.get<OfferIssuerId>() == null && records.get<OfferPaths>() == null) return Left(MissingRequiredTlv(22))
                if (records.unknown.any { !isOfferTlv(it) }) return Left(ForbiddenTlv(records.unknown.find { !isOfferTlv(it) }!!.tag))
                return Right(Offer(records))
            }

            val tlvSerializer = TlvStreamSerializer(
                false, @Suppress("UNCHECKED_CAST") mapOf(
                    OfferChains.tag to OfferChains as TlvValueReader<OfferTlv>,
                    OfferMetadata.tag to OfferMetadata as TlvValueReader<OfferTlv>,
                    OfferCurrency.tag to OfferCurrency as TlvValueReader<OfferTlv>,
                    OfferAmount.tag to OfferAmount as TlvValueReader<OfferTlv>,
                    OfferDescription.tag to OfferDescription as TlvValueReader<OfferTlv>,
                    OfferFeatures.tag to OfferFeatures as TlvValueReader<OfferTlv>,
                    OfferAbsoluteExpiry.tag to OfferAbsoluteExpiry as TlvValueReader<OfferTlv>,
                    OfferPaths.tag to OfferPaths as TlvValueReader<OfferTlv>,
                    OfferIssuer.tag to OfferIssuer as TlvValueReader<OfferTlv>,
                    OfferQuantityMax.tag to OfferQuantityMax as TlvValueReader<OfferTlv>,
                    OfferIssuerId.tag to OfferIssuerId as TlvValueReader<OfferTlv>,
                )
            )

            fun decode(s: String): Try<Offer> = runTrying {
                val (prefix, encoded, encoding) = Bech32.decodeBytes(s.lowercase(), true)
                require(prefix == hrp)
                require(encoding == Bech32.Encoding.Beck32WithoutChecksum)
                val tlvs = tlvSerializer.read(encoded)
                when (val offer = validate(tlvs)) {
                    is Left -> throw IllegalArgumentException(offer.value.toString())
                    is Right -> offer.value
                }
            }
        }
    }

    data class InvoiceRequest(val records: TlvStream<InvoiceRequestTlv>) {
        val offer: Offer = Offer.validate(filterOfferFields(records)).right!!

        val metadata: ByteVector = records.get<InvoiceRequestMetadata>()!!.data
        val chain: BlockHash = records.get<InvoiceRequestChain>()?.hash ?: Block.LivenetGenesisBlock.hash
        val amount: MilliSatoshi? = records.get<InvoiceRequestAmount>()?.amount
        val features: Features = records.get<InvoiceRequestFeatures>()?.features ?: Features.empty
        val quantity_opt: Long? = records.get<InvoiceRequestQuantity>()?.quantity
        val quantity: Long = quantity_opt ?: 1
        val payerId: PublicKey = records.get<InvoiceRequestPayerId>()!!.publicKey
        val payerNote: String? = records.get<InvoiceRequestPayerNote>()?.note
        private val signature: ByteVector64 = records.get<Signature>()!!.signature

        fun isValid(): Boolean =
            (offer.amount == null || amount == null || offer.amount * quantity <= amount) &&
                    (offer.amount != null || amount != null) &&
                    offer.chains.contains(chain) &&
                    ((offer.quantityMax == null && quantity_opt == null) || (offer.quantityMax != null && quantity_opt != null && quantity <= offer.quantityMax)) &&
                    Features.areCompatible(offer.features, features) &&
                    checkSignature()

        fun requestedAmount(): MilliSatoshi? = amount ?: offer.amount?.let { it * quantity }

        fun checkSignature(): Boolean =
            verifySchnorr(
                signatureTag,
                rootHash(removeSignature(records)),
                signature,
                payerId
            )

        fun encode(): String {
            val data = tlvSerializer.write(records)
            return Bech32.encodeBytes(hrp, data, Bech32.Encoding.Beck32WithoutChecksum)
        }

        override fun toString(): String = encode()

        fun unsigned(): TlvStream<InvoiceRequestTlv> = removeSignature(records)

        companion object {
            val hrp = "lnr"
            val signatureTag: ByteVector =
                ByteVector(("lightning" + "invoice_request" + "signature").encodeToByteArray())

            /**
             * Create a request to fetch an invoice for a given offer.
             *
             * @param offer    Bolt 12 offer.
             * @param amount   amount that we want to pay.
             * @param quantity quantity of items we're buying.
             * @param features invoice features.
             * @param payerKey private key identifying the payer: this lets us prove we're the ones who paid the invoice.
             * @param chain    chain we want to use to pay this offer.
             */
            operator fun invoke(
                offer: Offer,
                amount: MilliSatoshi,
                quantity: Long,
                features: Features,
                payerKey: PrivateKey,
                payerNote: String?,
                chain: BlockHash,
                additionalTlvs: Set<InvoiceRequestTlv> = setOf(),
                customTlvs: Set<GenericTlv> = setOf()
            ): InvoiceRequest {
                require(offer.chains.contains(chain))
                require(quantity == 1L || offer.quantityMax != null)
                val tlvs: Set<InvoiceRequestTlv> = offer.records.records + setOfNotNull(
                    InvoiceRequestMetadata(randomBytes32()),
                    InvoiceRequestChain(chain),
                    InvoiceRequestAmount(amount),
                    if (offer.quantityMax != null) InvoiceRequestQuantity(quantity) else null,
                    if (features != Features.empty) InvoiceRequestFeatures(features) else null,
                    InvoiceRequestPayerId(payerKey.publicKey()),
                    payerNote?.let { InvoiceRequestPayerNote(it) },
                ) + additionalTlvs
                val signature = signSchnorr(
                    signatureTag,
                    rootHash(TlvStream(tlvs, offer.records.unknown + customTlvs)),
                    payerKey
                )
                return InvoiceRequest(TlvStream(tlvs + Signature(signature), offer.records.unknown + customTlvs))
            }

            fun validate(records: TlvStream<InvoiceRequestTlv>): Either<InvalidTlvPayload, InvoiceRequest> {
                when (val offer = Offer.validate(filterOfferFields(records))) {
                    is Left -> return Left(offer.value)
                    is Right -> {}
                }
                if (records.get<InvoiceRequestMetadata>() == null) return Left(MissingRequiredTlv(0L))
                if (records.get<InvoiceRequestPayerId>() == null) return Left(MissingRequiredTlv(88))
                if (records.get<Signature>() == null) return Left(MissingRequiredTlv(240))
                if (records.unknown.any { !isInvoiceRequestTlv(it) }) return Left(ForbiddenTlv(records.unknown.find { !isInvoiceRequestTlv(it) }!!.tag))
                return Right(InvoiceRequest(records))
            }

            val tlvSerializer = TlvStreamSerializer(
                false, @Suppress("UNCHECKED_CAST") mapOf(
                    InvoiceRequestMetadata.tag to InvoiceRequestMetadata as TlvValueReader<InvoiceRequestTlv>,
                    // Offer part that must be copy-pasted from above
                    OfferChains.tag to OfferChains as TlvValueReader<InvoiceRequestTlv>,
                    OfferMetadata.tag to OfferMetadata as TlvValueReader<InvoiceRequestTlv>,
                    OfferCurrency.tag to OfferCurrency as TlvValueReader<InvoiceRequestTlv>,
                    OfferAmount.tag to OfferAmount as TlvValueReader<InvoiceRequestTlv>,
                    OfferDescription.tag to OfferDescription as TlvValueReader<InvoiceRequestTlv>,
                    OfferFeatures.tag to OfferFeatures as TlvValueReader<InvoiceRequestTlv>,
                    OfferAbsoluteExpiry.tag to OfferAbsoluteExpiry as TlvValueReader<InvoiceRequestTlv>,
                    OfferPaths.tag to OfferPaths as TlvValueReader<InvoiceRequestTlv>,
                    OfferIssuer.tag to OfferIssuer as TlvValueReader<InvoiceRequestTlv>,
                    OfferQuantityMax.tag to OfferQuantityMax as TlvValueReader<InvoiceRequestTlv>,
                    OfferIssuerId.tag to OfferIssuerId as TlvValueReader<InvoiceRequestTlv>,
                    // Invoice request part
                    InvoiceRequestChain.tag to InvoiceRequestChain as TlvValueReader<InvoiceRequestTlv>,
                    InvoiceRequestAmount.tag to InvoiceRequestAmount as TlvValueReader<InvoiceRequestTlv>,
                    InvoiceRequestFeatures.tag to InvoiceRequestFeatures as TlvValueReader<InvoiceRequestTlv>,
                    InvoiceRequestQuantity.tag to InvoiceRequestQuantity as TlvValueReader<InvoiceRequestTlv>,
                    InvoiceRequestPayerId.tag to InvoiceRequestPayerId as TlvValueReader<InvoiceRequestTlv>,
                    InvoiceRequestPayerNote.tag to InvoiceRequestPayerNote as TlvValueReader<InvoiceRequestTlv>,
                    Signature.tag to Signature as TlvValueReader<InvoiceRequestTlv>,
                )
            )

            fun decode(s: String): Try<InvoiceRequest> = runTrying {
                val (prefix, encoded, encoding) = Bech32.decodeBytes(s.lowercase(), true)
                require(prefix == hrp)
                require(encoding == Bech32.Encoding.Beck32WithoutChecksum)
                val tlvs = tlvSerializer.read(encoded)
                when (val invoiceRequest = validate(tlvs)) {
                    is Left -> throw IllegalArgumentException(invoiceRequest.value.toString())
                    is Right -> invoiceRequest.value
                }
            }
        }
    }

    object Invoice {
        val tlvSerializer = TlvStreamSerializer(
            false, @Suppress("UNCHECKED_CAST") mapOf(
                // Invoice request part that must be copy-pasted from above
                InvoiceRequestMetadata.tag to InvoiceRequestMetadata as TlvValueReader<InvoiceTlv>,
                OfferChains.tag to OfferChains as TlvValueReader<InvoiceTlv>,
                OfferMetadata.tag to OfferMetadata as TlvValueReader<InvoiceTlv>,
                OfferCurrency.tag to OfferCurrency as TlvValueReader<InvoiceTlv>,
                OfferAmount.tag to OfferAmount as TlvValueReader<InvoiceTlv>,
                OfferDescription.tag to OfferDescription as TlvValueReader<InvoiceTlv>,
                OfferFeatures.tag to OfferFeatures as TlvValueReader<InvoiceTlv>,
                OfferAbsoluteExpiry.tag to OfferAbsoluteExpiry as TlvValueReader<InvoiceTlv>,
                OfferPaths.tag to OfferPaths as TlvValueReader<InvoiceTlv>,
                OfferIssuer.tag to OfferIssuer as TlvValueReader<InvoiceTlv>,
                OfferQuantityMax.tag to OfferQuantityMax as TlvValueReader<InvoiceTlv>,
                OfferIssuerId.tag to OfferIssuerId as TlvValueReader<InvoiceTlv>,
                InvoiceRequestChain.tag to InvoiceRequestChain as TlvValueReader<InvoiceTlv>,
                InvoiceRequestAmount.tag to InvoiceRequestAmount as TlvValueReader<InvoiceTlv>,
                InvoiceRequestFeatures.tag to InvoiceRequestFeatures as TlvValueReader<InvoiceTlv>,
                InvoiceRequestQuantity.tag to InvoiceRequestQuantity as TlvValueReader<InvoiceTlv>,
                InvoiceRequestPayerId.tag to InvoiceRequestPayerId as TlvValueReader<InvoiceTlv>,
                InvoiceRequestPayerNote.tag to InvoiceRequestPayerNote as TlvValueReader<InvoiceTlv>,
                // Invoice part
                InvoicePaths.tag to InvoicePaths as TlvValueReader<InvoiceTlv>,
                InvoiceBlindedPay.tag to InvoiceBlindedPay as TlvValueReader<InvoiceTlv>,
                InvoiceCreatedAt.tag to InvoiceCreatedAt as TlvValueReader<InvoiceTlv>,
                InvoiceRelativeExpiry.tag to InvoiceRelativeExpiry as TlvValueReader<InvoiceTlv>,
                InvoicePaymentHash.tag to InvoicePaymentHash as TlvValueReader<InvoiceTlv>,
                InvoiceAmount.tag to InvoiceAmount as TlvValueReader<InvoiceTlv>,
                InvoiceFallbacks.tag to InvoiceFallbacks as TlvValueReader<InvoiceTlv>,
                InvoiceFeatures.tag to InvoiceFeatures as TlvValueReader<InvoiceTlv>,
                InvoiceNodeId.tag to InvoiceNodeId as TlvValueReader<InvoiceTlv>,
                Signature.tag to Signature as TlvValueReader<InvoiceTlv>,
            )
        )
    }

    data class InvoiceError(val records: TlvStream<InvoiceErrorTlv>) {
        val error = records.get<Error>()!!.message

        companion object {
            fun validate(records: TlvStream<InvoiceErrorTlv>): Either<InvalidTlvPayload, InvoiceError> {
                if (records.get<Error>() == null) return Left(MissingRequiredTlv(5))
                return Right(InvoiceError(records))
            }
        }
    }

    fun <T : Tlv> rootHash(tlvStream: TlvStream<T>): ByteVector32 {
        val encodedTlvs = (tlvStream.records + tlvStream.unknown).sortedBy { it.tag }.map { tlv ->
            val out = ByteArrayOutput()
            LightningCodecs.writeBigSize(tlv.tag, out)
            val tag = out.toByteArray()
            val data = tlv.write()
            LightningCodecs.writeBigSize(data.size.toLong(), out)
            LightningCodecs.writeBytes(data, out)
            Pair(tag, out.toByteArray())
        }
        val nonceKey = "LnNonce".encodeToByteArray() + encodedTlvs[0].second

        fun previousPowerOfTwo(n: Int): Int {
            var p = 1
            while (p < n) {
                p = p shl 1
            }
            return p shr 1
        }

        fun merkleTree(i: Int, j: Int): ByteArray {
            val (a, b) = if (j - i == 1) {
                val (tag, fullTlv) = encodedTlvs[i]
                Pair(hash("LnLeaf".encodeToByteArray(), fullTlv), hash(nonceKey, tag))
            } else {
                val k = i + previousPowerOfTwo(j - i)
                Pair(merkleTree(i, k), merkleTree(k, j))
            }
            return if (LexicographicalOrdering.isLessThan(a, b)) {
                hash("LnBranch".encodeToByteArray(), a + b)
            } else {
                hash("LnBranch".encodeToByteArray(), b + a)
            }
        }

        return ByteVector32(merkleTree(0, encodedTlvs.size))
    }

    private fun hash(tag: ByteArray, msg: ByteArray): ByteArray {
        val tagHash = Crypto.sha256(tag)
        return Crypto.sha256(tagHash + tagHash + msg)
    }

    fun signSchnorr(tag: ByteVector, msg: ByteVector32, key: PrivateKey): ByteVector64 {
        val h = ByteVector32(hash(tag.toByteArray(), msg.toByteArray()))
        // NB: we don't add auxiliary random data to keep signatures deterministic.
        return Crypto.signSchnorr(h, key, Crypto.SchnorrTweak.NoTweak)
    }

    fun verifySchnorr(tag: ByteVector, msg: ByteVector32, signature: ByteVector64, publicKey: PublicKey): Boolean {
        val h = ByteVector32(hash(tag.toByteArray(), msg.toByteArray()))
        return Crypto.verifySignatureSchnorr(h, signature, XonlyPublicKey(publicKey))
    }

    /** We often need to remove the signature field to compute the merkle root. */
    fun <T : Bolt12Tlv> removeSignature(records: TlvStream<T>): TlvStream<T> =
        TlvStream(records.records.filter { it !is Signature }.toSet(), records.unknown)

}
