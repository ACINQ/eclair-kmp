package fr.acinq.lightning.wire

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.flatMap
import fr.acinq.lightning.*
import fr.acinq.lightning.payment.Bolt11Invoice
import fr.acinq.lightning.payment.Bolt12Invoice
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.toByteVector

sealed class OnionPaymentPayloadTlv : Tlv {
    /** Amount to forward to the next node. */
    data class AmountToForward(val amount: MilliSatoshi) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = AmountToForward.tag
        override fun write(out: Output) = LightningCodecs.writeTU64(amount.toLong(), out)

        companion object : TlvValueReader<AmountToForward> {
            const val tag: Long = 2
            override fun read(input: Input): AmountToForward = AmountToForward(MilliSatoshi(LightningCodecs.tu64(input)))
        }
    }

    /** CLTV value to use for the HTLC offered to the next node. */
    data class OutgoingCltv(val cltv: CltvExpiry) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = OutgoingCltv.tag
        override fun write(out: Output) = LightningCodecs.writeTU32(cltv.toLong().toInt(), out)

        companion object : TlvValueReader<OutgoingCltv> {
            const val tag: Long = 4
            override fun read(input: Input): OutgoingCltv = OutgoingCltv(CltvExpiry(LightningCodecs.tu32(input).toLong()))
        }
    }

    /** Id of the channel to use to forward a payment to the next node. */
    data class OutgoingChannelId(val shortChannelId: ShortChannelId) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = OutgoingChannelId.tag
        override fun write(out: Output) = LightningCodecs.writeU64(shortChannelId.toLong(), out)

        companion object : TlvValueReader<OutgoingChannelId> {
            const val tag: Long = 6
            override fun read(input: Input): OutgoingChannelId = OutgoingChannelId(ShortChannelId(LightningCodecs.u64(input)))
        }
    }

    /**
     * Bolt 11 payment details (only included for the last node).
     *
     * @param secret payment secret specified in the Bolt 11 invoice.
     * @param totalAmount total amount in multi-part payments. When missing, assumed to be equal to AmountToForward.
     */
    data class PaymentData(val secret: ByteVector32, val totalAmount: MilliSatoshi) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = PaymentData.tag
        override fun write(out: Output) {
            LightningCodecs.writeBytes(secret, out)
            LightningCodecs.writeTU64(totalAmount.toLong(), out)
        }

        companion object : TlvValueReader<PaymentData> {
            const val tag: Long = 8
            override fun read(input: Input): PaymentData = PaymentData(ByteVector32(LightningCodecs.bytes(input, 32)), MilliSatoshi(LightningCodecs.tu64(input)))
        }
    }

    /**
     * Route blinding lets the recipient provide some encrypted data for each intermediate node in the blinded part of
     * the route. This data cannot be decrypted or modified by the sender and usually contains information to locate the
     * next node without revealing it to the sender.
     */
    data class EncryptedRecipientData(val data: ByteVector) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = EncryptedRecipientData.tag
        override fun write(out: Output) {
            LightningCodecs.writeBytes(data, out)
        }

        companion object : TlvValueReader<EncryptedRecipientData> {
            const val tag: Long = 10
            override fun read(input: Input): EncryptedRecipientData = EncryptedRecipientData(LightningCodecs.bytes(input, input.availableBytes).toByteVector())
        }
    }

    /** Path key for the introduction node of a blinded route. */
    data class PathKey(val publicKey: PublicKey) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = PathKey.tag
        override fun write(out: Output) {
            LightningCodecs.writeBytes(publicKey.value, out)
        }

        companion object : TlvValueReader<PathKey> {
            const val tag: Long = 12
            override fun read(input: Input): PathKey = PathKey(PublicKey(LightningCodecs.bytes(input, 33)))
        }
    }

    /** Id of the next node. */
    data class OutgoingNodeId(val nodeId: PublicKey) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = OutgoingNodeId.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(nodeId.value, out)

        companion object : TlvValueReader<OutgoingNodeId> {
            const val tag: Long = 14
            override fun read(input: Input): OutgoingNodeId = OutgoingNodeId(PublicKey(LightningCodecs.bytes(input, 33)))
        }
    }

    /**
     * When payment metadata is included in a Bolt 9 invoice, we should send it as-is to the recipient.
     * This lets recipients generate invoices without having to store anything on their side until the invoice is paid.
     */
    data class PaymentMetadata(val data: ByteVector) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = PaymentMetadata.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(data, out)

        companion object : TlvValueReader<PaymentMetadata> {
            const val tag: Long = 16
            override fun read(input: Input): PaymentMetadata = PaymentMetadata(ByteVector(LightningCodecs.bytes(input, input.availableBytes)))
        }
    }

    /** Total amount in blinded multi-part payments. */
    data class TotalAmount(val totalAmount: MilliSatoshi) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = TotalAmount.tag
        override fun write(out: Output) {
            LightningCodecs.writeTU64(totalAmount.toLong(), out)
        }

        companion object : TlvValueReader<TotalAmount> {
            const val tag: Long = 18
            override fun read(input: Input): TotalAmount = TotalAmount(MilliSatoshi(LightningCodecs.tu64(input)))
        }
    }

    /** An encrypted trampoline onion packet. */
    data class TrampolineOnion(val packet: OnionRoutingPacket) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = TrampolineOnion.tag
        override fun write(out: Output) = OnionRoutingPacketSerializer(packet.payload.size()).write(packet, out)

        companion object : TlvValueReader<TrampolineOnion> {
            const val tag: Long = 20
            override fun read(input: Input): TrampolineOnion {
                val payloadLength = input.availableBytes - 66 // 1 byte version + 33 bytes public key + 32 bytes HMAC
                return TrampolineOnion(OnionRoutingPacketSerializer(payloadLength).read(input))
            }
        }
    }

    /**
     * Invoice feature bits. Only included for intermediate trampoline nodes when they should convert to a legacy payment
     * because the final recipient doesn't support trampoline.
     */
    data class InvoiceFeatures(val features: ByteVector) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = InvoiceFeatures.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(features, out)

        companion object : TlvValueReader<InvoiceFeatures> {
            const val tag: Long = 66097
            override fun read(input: Input): InvoiceFeatures = InvoiceFeatures(ByteVector(LightningCodecs.bytes(input, input.availableBytes)))
        }
    }

    /**
     * Invoice routing hints. Only included for intermediate trampoline nodes when they should convert to a legacy payment
     * because the final recipient doesn't support trampoline.
     */
    data class InvoiceRoutingInfo(val extraHops: List<List<Bolt11Invoice.TaggedField.ExtraHop>>) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = InvoiceRoutingInfo.tag
        override fun write(out: Output) {
            for (routeHint in extraHops) {
                LightningCodecs.writeByte(routeHint.size, out)
                routeHint.map {
                    LightningCodecs.writeBytes(it.nodeId.value, out)
                    LightningCodecs.writeU64(it.shortChannelId.toLong(), out)
                    LightningCodecs.writeU32(it.feeBase.toLong().toInt(), out)
                    LightningCodecs.writeU32(it.feeProportionalMillionths.toInt(), out)
                    LightningCodecs.writeU16(it.cltvExpiryDelta.toInt(), out)
                }
            }
        }

        companion object : TlvValueReader<InvoiceRoutingInfo> {
            const val tag: Long = 66099
            override fun read(input: Input): InvoiceRoutingInfo {
                val extraHops = mutableListOf<List<Bolt11Invoice.TaggedField.ExtraHop>>()
                while (input.availableBytes > 0) {
                    val hopCount = LightningCodecs.byte(input)
                    val extraHop = (0 until hopCount).map {
                        Bolt11Invoice.TaggedField.ExtraHop(
                            PublicKey(LightningCodecs.bytes(input, 33)),
                            ShortChannelId(LightningCodecs.u64(input)),
                            MilliSatoshi(LightningCodecs.u32(input).toLong()),
                            LightningCodecs.u32(input).toLong(),
                            CltvExpiryDelta(LightningCodecs.u16(input))
                        )
                    }
                    extraHops.add(extraHop)
                }
                return InvoiceRoutingInfo(extraHops)
            }
        }
    }

    /** Blinded paths to relay the payment to */
    data class OutgoingBlindedPaths(val paths: List<Bolt12Invoice.Companion.PaymentBlindedContactInfo>) : OnionPaymentPayloadTlv() {
        override val tag: Long get() = OutgoingBlindedPaths.tag
        override fun write(out: Output) {
            for (path in paths) {
                OfferTypes.writePath(path.route, out)
                OfferTypes.writePaymentInfo(path.paymentInfo, out)
            }
        }

        companion object : TlvValueReader<OutgoingBlindedPaths> {
            const val tag: Long = 66102
            override fun read(input: Input): OutgoingBlindedPaths {
                val paths = ArrayList<Bolt12Invoice.Companion.PaymentBlindedContactInfo>()
                while (input.availableBytes > 0) {
                    val route = OfferTypes.readPath(input)
                    val payInfo = OfferTypes.readPaymentInfo(input)
                    paths.add(Bolt12Invoice.Companion.PaymentBlindedContactInfo(route, payInfo))
                }
                return OutgoingBlindedPaths(paths)
            }
        }
    }

}

object PaymentOnion {

    sealed class PerHopPayload {

        abstract fun write(out: Output)

        fun write(): ByteArray {
            val out = ByteArrayOutput()
            write(out)
            return out.toByteArray()
        }

        companion object {
            val tlvSerializer = TlvStreamSerializer(
                true, @Suppress("UNCHECKED_CAST") mapOf(
                    OnionPaymentPayloadTlv.AmountToForward.tag to OnionPaymentPayloadTlv.AmountToForward.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.OutgoingCltv.tag to OnionPaymentPayloadTlv.OutgoingCltv.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.OutgoingChannelId.tag to OnionPaymentPayloadTlv.OutgoingChannelId.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.OutgoingNodeId.tag to OnionPaymentPayloadTlv.OutgoingNodeId.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.PaymentData.tag to OnionPaymentPayloadTlv.PaymentData.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.EncryptedRecipientData.tag to OnionPaymentPayloadTlv.EncryptedRecipientData.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.PathKey.tag to OnionPaymentPayloadTlv.PathKey.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.PaymentMetadata.tag to OnionPaymentPayloadTlv.PaymentMetadata.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.TotalAmount.tag to OnionPaymentPayloadTlv.TotalAmount.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.TrampolineOnion.tag to OnionPaymentPayloadTlv.TrampolineOnion.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.InvoiceFeatures.tag to OnionPaymentPayloadTlv.InvoiceFeatures.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.InvoiceRoutingInfo.tag to OnionPaymentPayloadTlv.InvoiceRoutingInfo.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                    OnionPaymentPayloadTlv.OutgoingBlindedPaths.tag to OnionPaymentPayloadTlv.OutgoingBlindedPaths.Companion as TlvValueReader<OnionPaymentPayloadTlv>,
                )
            )

            fun read(input: Input): Either<InvalidOnionPayload, TlvStream<OnionPaymentPayloadTlv>> = try {
                Either.Right(tlvSerializer.read(input))
            } catch (_: Throwable) {
                // We should change TlvStream.read to return an Either<InvalidTlvPayload, TlvStream<T>>, which allows returning a more accurate error here.
                Either.Left(InvalidOnionPayload(0, 0))
            }

            fun read(bytes: ByteArray): Either<InvalidOnionPayload, TlvStream<OnionPaymentPayloadTlv>> = read(ByteArrayInput(bytes))
        }
    }

    interface PerHopPayloadReader<T : PerHopPayload> {
        fun read(input: Input): Either<InvalidOnionPayload, T>
        fun read(bytes: ByteArray): Either<InvalidOnionPayload, T> = read(ByteArrayInput(bytes))
        fun read(bytes: ByteVector): Either<InvalidOnionPayload, T> = read(bytes.toByteArray())
    }

    sealed class FinalPayload : PerHopPayload() {
        abstract val amount: MilliSatoshi
        abstract val totalAmount: MilliSatoshi
        abstract val expiry: CltvExpiry

        data class Standard(val records: TlvStream<OnionPaymentPayloadTlv>) : FinalPayload() {
            override val amount = records.get<OnionPaymentPayloadTlv.AmountToForward>()!!.amount
            override val expiry = records.get<OnionPaymentPayloadTlv.OutgoingCltv>()!!.cltv
            val paymentSecret = records.get<OnionPaymentPayloadTlv.PaymentData>()!!.secret
            override val totalAmount = run {
                val total = records.get<OnionPaymentPayloadTlv.PaymentData>()!!.totalAmount
                if (total > 0.msat) total else amount
            }
            val paymentMetadata = records.get<OnionPaymentPayloadTlv.PaymentMetadata>()?.data

            override fun write(out: Output) = tlvSerializer.write(records, out)

            companion object : PerHopPayloadReader<Standard> {
                override fun read(input: Input): Either<InvalidOnionPayload, Standard> {
                    return PerHopPayload.read(input).flatMap { tlvs ->
                        when {
                            tlvs.get<OnionPaymentPayloadTlv.AmountToForward>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.AmountToForward.tag, 0))
                            tlvs.get<OnionPaymentPayloadTlv.OutgoingCltv>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.OutgoingCltv.tag, 0))
                            tlvs.get<OnionPaymentPayloadTlv.PaymentData>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.PaymentData.tag, 0))
                            tlvs.get<OnionPaymentPayloadTlv.EncryptedRecipientData>() != null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.EncryptedRecipientData.tag, 0))
                            else -> Either.Right(Standard(tlvs))
                        }
                    }
                }

                /** Create a single-part payment (total amount sent at once). */
                fun createSinglePartPayload(
                    amount: MilliSatoshi,
                    expiry: CltvExpiry,
                    paymentSecret: ByteVector32,
                    paymentMetadata: ByteVector?,
                    userCustomTlvs: Set<GenericTlv> = setOf()
                ): Standard {
                    val tlvs = buildSet {
                        add(OnionPaymentPayloadTlv.AmountToForward(amount))
                        add(OnionPaymentPayloadTlv.OutgoingCltv(expiry))
                        add(OnionPaymentPayloadTlv.PaymentData(paymentSecret, amount))
                        paymentMetadata?.let { add(OnionPaymentPayloadTlv.PaymentMetadata(it)) }
                    }
                    return Standard(TlvStream(tlvs, userCustomTlvs))
                }

                /** Create a partial payment (total amount split between multiple payments). */
                fun createMultiPartPayload(
                    amount: MilliSatoshi,
                    totalAmount: MilliSatoshi,
                    expiry: CltvExpiry,
                    paymentSecret: ByteVector32,
                    paymentMetadata: ByteVector?,
                    additionalTlvs: Set<OnionPaymentPayloadTlv> = setOf(),
                    userCustomTlvs: Set<GenericTlv> = setOf()
                ): Standard {
                    val tlvs = buildSet {
                        add(OnionPaymentPayloadTlv.AmountToForward(amount))
                        add(OnionPaymentPayloadTlv.OutgoingCltv(expiry))
                        add(OnionPaymentPayloadTlv.PaymentData(paymentSecret, totalAmount))
                        paymentMetadata?.let { add(OnionPaymentPayloadTlv.PaymentMetadata(it)) }
                        addAll(additionalTlvs)
                    }
                    return Standard(TlvStream(tlvs, userCustomTlvs))
                }

                /** Create a trampoline outer payload. */
                fun createTrampolinePayload(
                    amount: MilliSatoshi,
                    totalAmount: MilliSatoshi,
                    expiry: CltvExpiry,
                    paymentSecret: ByteVector32,
                    trampolinePacket: OnionRoutingPacket
                ): Standard {
                    val tlvs = TlvStream(
                        OnionPaymentPayloadTlv.AmountToForward(amount),
                        OnionPaymentPayloadTlv.OutgoingCltv(expiry),
                        OnionPaymentPayloadTlv.PaymentData(paymentSecret, totalAmount),
                        OnionPaymentPayloadTlv.TrampolineOnion(trampolinePacket)
                    )
                    return Standard(tlvs)
                }
            }
        }

        data class Blinded(val records: TlvStream<OnionPaymentPayloadTlv>, val recipientData: RouteBlindingEncryptedData) : FinalPayload() {
            override val amount = records.get<OnionPaymentPayloadTlv.AmountToForward>()!!.amount
            override val totalAmount = records.get<OnionPaymentPayloadTlv.TotalAmount>()!!.totalAmount
            override val expiry = records.get<OnionPaymentPayloadTlv.OutgoingCltv>()!!.cltv
            val pathId = recipientData.pathId!!

            override fun write(out: Output) = tlvSerializer.write(records, out)

            companion object {
                fun validate(records: TlvStream<OnionPaymentPayloadTlv>, blindedRecords: RouteBlindingEncryptedData): Either<InvalidTlvPayload, Blinded> {
                    // Bolt 4: MUST return an error if the payload contains other tlv fields than `encrypted_recipient_data`, `current_path_key`, `amt_to_forward`, `outgoing_cltv_value` and `total_amount_msat`.
                    val allowed = setOf(
                        OnionPaymentPayloadTlv.AmountToForward.tag,
                        OnionPaymentPayloadTlv.OutgoingCltv.tag,
                        OnionPaymentPayloadTlv.EncryptedRecipientData.tag,
                        OnionPaymentPayloadTlv.PathKey.tag,
                        OnionPaymentPayloadTlv.TotalAmount.tag,
                    )
                    return when {
                        records.get<OnionPaymentPayloadTlv.AmountToForward>() == null -> Either.Left(MissingRequiredTlv(OnionPaymentPayloadTlv.AmountToForward.tag))
                        records.get<OnionPaymentPayloadTlv.OutgoingCltv>() == null -> Either.Left(MissingRequiredTlv(OnionPaymentPayloadTlv.OutgoingCltv.tag))
                        records.get<OnionPaymentPayloadTlv.EncryptedRecipientData>() == null -> Either.Left(MissingRequiredTlv(OnionPaymentPayloadTlv.EncryptedRecipientData.tag))
                        records.get<OnionPaymentPayloadTlv.TotalAmount>() == null -> Either.Left(MissingRequiredTlv(OnionPaymentPayloadTlv.TotalAmount.tag))
                        records.records.any { !allowed.contains(it.tag) } -> Either.Left(ForbiddenTlv(records.records.first { !allowed.contains(it.tag) }.tag))
                        records.unknown.isNotEmpty() -> Either.Left(ForbiddenTlv(records.unknown.first().tag))
                        blindedRecords.pathId == null -> Either.Left(MissingRequiredTlv(RouteBlindingEncryptedDataTlv.PathId.tag))
                        else -> Either.Right(Blinded(records, blindedRecords))
                    }
                }
            }
        }
    }

    data class ChannelRelayPayload(val records: TlvStream<OnionPaymentPayloadTlv>) : PerHopPayload() {
        val amountToForward = records.get<OnionPaymentPayloadTlv.AmountToForward>()!!.amount
        val outgoingCltv = records.get<OnionPaymentPayloadTlv.OutgoingCltv>()!!.cltv
        val outgoingChannelId = records.get<OnionPaymentPayloadTlv.OutgoingChannelId>()!!.shortChannelId

        override fun write(out: Output) = tlvSerializer.write(records, out)

        companion object : PerHopPayloadReader<ChannelRelayPayload> {
            override fun read(input: Input): Either<InvalidOnionPayload, ChannelRelayPayload> {
                return PerHopPayload.read(input).flatMap { tlvs ->
                    when {
                        tlvs.get<OnionPaymentPayloadTlv.AmountToForward>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.AmountToForward.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.OutgoingCltv>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.OutgoingCltv.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.OutgoingChannelId>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.OutgoingChannelId.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.EncryptedRecipientData>() != null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.EncryptedRecipientData.tag, 0))
                        else -> Either.Right(ChannelRelayPayload(tlvs))
                    }
                }
            }

            fun create(outgoingChannelId: ShortChannelId, amountToForward: MilliSatoshi, outgoingCltv: CltvExpiry): ChannelRelayPayload =
                ChannelRelayPayload(TlvStream(OnionPaymentPayloadTlv.AmountToForward(amountToForward), OnionPaymentPayloadTlv.OutgoingCltv(outgoingCltv), OnionPaymentPayloadTlv.OutgoingChannelId(outgoingChannelId)))
        }
    }

    data class NodeRelayPayload(val records: TlvStream<OnionPaymentPayloadTlv>) : PerHopPayload() {
        val amountToForward = records.get<OnionPaymentPayloadTlv.AmountToForward>()!!.amount
        val outgoingCltv = records.get<OnionPaymentPayloadTlv.OutgoingCltv>()!!.cltv
        val outgoingNodeId = records.get<OnionPaymentPayloadTlv.OutgoingNodeId>()!!.nodeId
        val totalAmount = run {
            val paymentData = records.get<OnionPaymentPayloadTlv.PaymentData>()
            when {
                paymentData == null -> amountToForward
                paymentData.totalAmount == MilliSatoshi(0) -> amountToForward
                else -> paymentData.totalAmount
            }
        }

        override fun write(out: Output) = tlvSerializer.write(records, out)

        companion object : PerHopPayloadReader<NodeRelayPayload> {
            override fun read(input: Input): Either<InvalidOnionPayload, NodeRelayPayload> {
                return PerHopPayload.read(input).flatMap { tlvs ->
                    when {
                        tlvs.get<OnionPaymentPayloadTlv.AmountToForward>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.AmountToForward.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.OutgoingCltv>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.OutgoingCltv.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.OutgoingNodeId>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.OutgoingNodeId.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.EncryptedRecipientData>() != null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.EncryptedRecipientData.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.PathKey>() != null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.PathKey.tag, 0))
                        else -> Either.Right(NodeRelayPayload(tlvs))
                    }
                }
            }

            fun create(amount: MilliSatoshi, expiry: CltvExpiry, nextNodeId: PublicKey) =
                NodeRelayPayload(TlvStream(OnionPaymentPayloadTlv.AmountToForward(amount), OnionPaymentPayloadTlv.OutgoingCltv(expiry), OnionPaymentPayloadTlv.OutgoingNodeId(nextNodeId)))
        }
    }

    /**
     * Create a trampoline payload to tell our trampoline node to relay to a Bolt 11 recipient that doesn't support trampoline.
     * This reveals to our trampoline node who the recipient is and details from the invoice.
     * This must be deprecated once recipients support either trampoline or blinded paths.
     */
    data class RelayToNonTrampolinePayload(val records: TlvStream<OnionPaymentPayloadTlv>) : PerHopPayload() {
        val amountToForward = records.get<OnionPaymentPayloadTlv.AmountToForward>()!!.amount
        val outgoingCltv = records.get<OnionPaymentPayloadTlv.OutgoingCltv>()!!.cltv
        val outgoingNodeId = records.get<OnionPaymentPayloadTlv.OutgoingNodeId>()!!.nodeId
        val paymentSecret = records.get<OnionPaymentPayloadTlv.PaymentData>()!!.secret
        val paymentMetadata = records.get<OnionPaymentPayloadTlv.PaymentMetadata>()?.data
        val invoiceFeatures = records.get<OnionPaymentPayloadTlv.InvoiceFeatures>()!!.features
        val invoiceRoutingInfo = records.get<OnionPaymentPayloadTlv.InvoiceRoutingInfo>()!!.extraHops

        override fun write(out: Output) = tlvSerializer.write(records, out)

        companion object : PerHopPayloadReader<RelayToNonTrampolinePayload> {
            override fun read(input: Input): Either<InvalidOnionPayload, RelayToNonTrampolinePayload> {
                return PerHopPayload.read(input).flatMap { tlvs ->
                    when {
                        tlvs.get<OnionPaymentPayloadTlv.AmountToForward>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.AmountToForward.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.OutgoingCltv>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.OutgoingCltv.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.OutgoingNodeId>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.OutgoingNodeId.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.PaymentData>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.PaymentData.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.InvoiceFeatures>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.InvoiceFeatures.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.InvoiceRoutingInfo>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.InvoiceRoutingInfo.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.EncryptedRecipientData>() != null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.EncryptedRecipientData.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.PathKey>() != null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.PathKey.tag, 0))
                        else -> Either.Right(RelayToNonTrampolinePayload(tlvs))
                    }
                }
            }

            fun create(amount: MilliSatoshi, totalAmount: MilliSatoshi, expiry: CltvExpiry, targetNodeId: PublicKey, invoice: Bolt11Invoice, routingInfo: List<Bolt11Invoice.TaggedField.RoutingInfo>): RelayToNonTrampolinePayload =
                RelayToNonTrampolinePayload(
                    TlvStream(
                        buildSet {
                            add(OnionPaymentPayloadTlv.AmountToForward(amount))
                            add(OnionPaymentPayloadTlv.OutgoingCltv(expiry))
                            add(OnionPaymentPayloadTlv.OutgoingNodeId(targetNodeId))
                            add(OnionPaymentPayloadTlv.PaymentData(invoice.paymentSecret, totalAmount))
                            invoice.paymentMetadata?.let { add(OnionPaymentPayloadTlv.PaymentMetadata(it)) }
                            add(OnionPaymentPayloadTlv.InvoiceFeatures(invoice.features.toByteArray().toByteVector()))
                            add(OnionPaymentPayloadTlv.InvoiceRoutingInfo(routingInfo.map { it.hints }))
                        }
                    )
                )
        }
    }

    data class RelayToBlindedPayload(val records: TlvStream<OnionPaymentPayloadTlv>) : PerHopPayload() {
        val amountToForward = records.get<OnionPaymentPayloadTlv.AmountToForward>()!!.amount
        val outgoingCltv = records.get<OnionPaymentPayloadTlv.OutgoingCltv>()!!.cltv
        val outgoingBlindedPaths = records.get<OnionPaymentPayloadTlv.OutgoingBlindedPaths>()!!.paths
        val invoiceFeatures = records.get<OnionPaymentPayloadTlv.InvoiceFeatures>()!!.features

        override fun write(out: Output) = tlvSerializer.write(records, out)

        companion object : PerHopPayloadReader<RelayToBlindedPayload> {
            override fun read(input: Input): Either<InvalidOnionPayload, RelayToBlindedPayload> {
                return PerHopPayload.read(input).flatMap { tlvs ->
                    when {
                        tlvs.get<OnionPaymentPayloadTlv.AmountToForward>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.AmountToForward.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.OutgoingCltv>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.OutgoingCltv.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.InvoiceFeatures>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.InvoiceFeatures.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.OutgoingBlindedPaths>() == null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.OutgoingBlindedPaths.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.EncryptedRecipientData>() != null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.EncryptedRecipientData.tag, 0))
                        tlvs.get<OnionPaymentPayloadTlv.PathKey>() != null -> Either.Left(InvalidOnionPayload(OnionPaymentPayloadTlv.PathKey.tag, 0))
                        else -> Either.Right(RelayToBlindedPayload(tlvs))
                    }
                }
            }

            fun create(amount: MilliSatoshi, expiry: CltvExpiry, features: Features, blindedPaths: List<Bolt12Invoice.Companion.PaymentBlindedContactInfo>): RelayToBlindedPayload =
                RelayToBlindedPayload(
                    TlvStream(
                        setOf(
                            OnionPaymentPayloadTlv.AmountToForward(amount),
                            OnionPaymentPayloadTlv.OutgoingCltv(expiry),
                            OnionPaymentPayloadTlv.OutgoingBlindedPaths(blindedPaths),
                            OnionPaymentPayloadTlv.InvoiceFeatures(features.toByteArray().toByteVector())
                        )
                    )
                )
        }
    }

}
