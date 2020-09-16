package fr.acinq.eclair.wire

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.eclair.CltvExpiry
import fr.acinq.eclair.MilliSatoshi
import fr.acinq.eclair.ShortChannelId
import fr.acinq.eclair.io.ByteVector32KSerializer
import fr.acinq.eclair.io.ByteVectorKSerializer
import fr.acinq.eclair.io.PublicKeyKSerializer
import fr.acinq.eclair.payment.PaymentRequest
import fr.acinq.eclair.utils.toByteVector
import fr.acinq.eclair.utils.toByteVector32
import kotlinx.serialization.Serializable

@Serializable
data class OnionRoutingPacket(
    val version: Int,
    @Serializable(with = ByteVectorKSerializer::class) val publicKey: ByteVector,
    @Serializable(with = ByteVectorKSerializer::class) val payload: ByteVector,
    @Serializable(with = ByteVector32KSerializer::class) val hmac: ByteVector32
) {
    companion object {
        const val PaymentPacketLength = 1300
        const val TrampolinePacketLength = 400
    }
}

/**
 * @param payloadLength length of the onion-encrypted payload.
 */
@OptIn(ExperimentalUnsignedTypes::class)
class OnionRoutingPacketSerializer(private val payloadLength: Int) : LightningSerializer<OnionRoutingPacket>() {
    override val tag: Long get() = TODO("Not used")

    override fun read(input: Input): OnionRoutingPacket {
        return OnionRoutingPacket(
            byte(input),
            bytes(input, 33).toByteVector(),
            bytes(input, payloadLength).toByteVector(),
            bytes(input, 32).toByteVector32()
        )
    }

    override fun write(message: OnionRoutingPacket, out: Output) {
        writeByte(message.version, out)
        writeBytes(message.publicKey, out)
        writeBytes(message.payload, out)
        writeBytes(message.hmac, out)
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
sealed class OnionTlv : Tlv {
    /** Amount to forward to the next node. */
    @Serializable
    data class AmountToForward(val amount: MilliSatoshi) : OnionTlv() {
        override val tag: Long get() = 2L
    }

    /** CLTV value to use for the HTLC offered to the next node. */
    @Serializable
    data class OutgoingCltv(val cltv: CltvExpiry) : OnionTlv() {
        override val tag: Long get() = 4L
    }

    /** Id of the channel to use to forward a payment to the next node. */
    @Serializable
    data class OutgoingChannelId(val shortChannelId: ShortChannelId) : OnionTlv() {
        override val tag: Long get() = 6L
    }

    /**
     * Bolt 11 payment details (only included for the last node).
     *
     * @param secret      payment secret specified in the Bolt 11 invoice.
     * @param totalAmount total amount in multi-part payments. When missing, assumed to be equal to AmountToForward.
     */
    @Serializable
    data class PaymentData(@Serializable(with = ByteVector32KSerializer::class) val secret: ByteVector32, val totalAmount: MilliSatoshi) : OnionTlv() {
        override val tag: Long get() = 8L
    }

    /**
     * Invoice feature bits. Only included for intermediate trampoline nodes when they should convert to a legacy payment
     * because the final recipient doesn't support trampoline.
     */
    @Serializable
    data class InvoiceFeatures(@Serializable(with = ByteVectorKSerializer::class) val features: ByteVector) : OnionTlv() {
        override val tag: Long get() = 66097L
    }

    /** Id of the next node. */
    @Serializable
    data class OutgoingNodeId(@Serializable(with = PublicKeyKSerializer::class) val nodeId: PublicKey) : OnionTlv() {
        override val tag: Long get() = 66098L
    }

    /**
     * Invoice routing hints. Only included for intermediate trampoline nodes when they should convert to a legacy payment
     * because the final recipient doesn't support trampoline.
     */
    @Serializable
    data class InvoiceRoutingInfo(val extraHops: List<List<PaymentRequest.TaggedField.ExtraHop>>) : OnionTlv() {
        override val tag: Long get() = 66099L
    }

    /** An encrypted trampoline onion packet. */
    @Serializable
    data class TrampolineOnion(val packet: OnionRoutingPacket) : OnionTlv() {
        override val tag: Long get() = 66100L
    }
}

sealed class PerHopPayload

sealed class FinalPayload : PerHopPayload(), LightningSerializable<FinalPayload> {
    abstract val amount: MilliSatoshi
    abstract val expiry: CltvExpiry
    abstract val paymentSecret: ByteVector32?
    abstract val totalAmount: MilliSatoshi

    override fun serializer(): LightningSerializer<FinalPayload> = FinalPayload

    companion object : LightningSerializer<FinalPayload>() {
        override val tag: Long get() = TODO("Not used")

        override fun read(input: Input): FinalPayload {
            // TODO: handle other types of payloads
            return FinalLegacyPayload.read(input)
        }

        override fun write(message: FinalPayload, out: Output) {
            when (message) {
                is FinalLegacyPayload -> FinalLegacyPayload.write(message, out)
                is FinalTlvPayload -> TODO("implement")
            }
        }

        fun createSinglePartPayload(amount: MilliSatoshi, expiry: CltvExpiry, paymentSecret: ByteVector32? = null, userCustomTlvs: List<GenericTlv> = listOf()): FinalPayload {
            return when {
                paymentSecret == null && userCustomTlvs.isNotEmpty() -> FinalTlvPayload(TlvStream(listOf(OnionTlv.AmountToForward(amount), OnionTlv.OutgoingCltv(expiry)), userCustomTlvs))
                paymentSecret == null -> FinalLegacyPayload(amount, expiry)
                else -> FinalTlvPayload(TlvStream(listOf(OnionTlv.AmountToForward(amount), OnionTlv.OutgoingCltv(expiry), OnionTlv.PaymentData(paymentSecret, amount)), userCustomTlvs))
            }
        }

        fun createMultiPartPayload(amount: MilliSatoshi, totalAmount: MilliSatoshi, expiry: CltvExpiry, paymentSecret: ByteVector32, additionalTlvs: List<OnionTlv> = listOf(), userCustomTlvs: List<GenericTlv> = listOf()): FinalPayload =
            FinalTlvPayload(TlvStream(listOf(OnionTlv.AmountToForward(amount), OnionTlv.OutgoingCltv(expiry), OnionTlv.PaymentData(paymentSecret, totalAmount)) + additionalTlvs, userCustomTlvs))
    }
}

data class FinalLegacyPayload(override val amount: MilliSatoshi, override val expiry: CltvExpiry) : FinalPayload() {
    override val paymentSecret: ByteVector32? = null
    override val totalAmount = amount

    companion object : LightningSerializer<FinalLegacyPayload>() {
        override val tag: Long get() = TODO("Not used")

        override fun read(input: Input): FinalLegacyPayload {
            val realm = byte(input)
            require(realm == 0) { "invalid realm: $realm" }
            bytes(input, 8)
            val amount = MilliSatoshi(u64(input))
            val expiry = CltvExpiry(u32(input).toLong())
            bytes(input, 12)
            return FinalLegacyPayload(amount, expiry)
        }

        override fun write(message: FinalLegacyPayload, out: Output) {
            writeByte(0, out) // realm is always 0
            writeBytes(ByteArray(8), out)
            writeU64(message.amount.toLong(), out)
            writeU32(message.expiry.toLong().toInt(), out)
            writeBytes(ByteArray(12), out)
        }
    }
}

data class RelayLegacyPayload(val outgoingChannelId: ShortChannelId, val amountToForward: MilliSatoshi, val outgoingCltv: CltvExpiry) : PerHopPayload(), LightningSerializable<RelayLegacyPayload> {
    override fun serializer(): LightningSerializer<RelayLegacyPayload> = RelayLegacyPayload

    companion object : LightningSerializer<RelayLegacyPayload>() {
        override val tag: Long get() = TODO("Not used")

        override fun read(input: Input): RelayLegacyPayload {
            val realm = byte(input)
            require(realm == 0) { "invalid realm " }
            val shortChannelId = ShortChannelId(u64(input))
            val amount = MilliSatoshi(u64(input))
            val expiry = CltvExpiry(u32(input).toLong())
            bytes(input, 12)
            return RelayLegacyPayload(shortChannelId, amount, expiry)
        }

        override fun write(message: RelayLegacyPayload, out: Output) {
            writeByte(0, out) // realm is always 0
            writeU64(message.outgoingChannelId.toLong(), out)
            writeU64(message.amountToForward.toLong(), out)
            writeU32(message.outgoingCltv.toLong().toInt(), out)
            writeBytes(ByteArray(12), out)
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class FinalTlvPayload(val records: TlvStream<OnionTlv>) : FinalPayload() {
    override val amount = records.get<OnionTlv.AmountToForward>()!!.amount
    override val expiry = records.get<OnionTlv.OutgoingCltv>()!!.cltv
    override val paymentSecret = records.get<OnionTlv.PaymentData>()?.secret
    override val totalAmount = records.get<OnionTlv.PaymentData>()?.totalAmount ?: amount
}

data class NodeRelayPayload(val records: TlvStream<OnionTlv>) : PerHopPayload() {
    val amountToForward = records.get<OnionTlv.AmountToForward>()!!.amount
    val outgoingCltv = records.get<OnionTlv.OutgoingCltv>()!!.cltv
    val outgoingNodeId = records.get<OnionTlv.OutgoingNodeId>()!!.nodeId
    val totalAmount = run {
        val paymentData = records.get<OnionTlv.PaymentData>()
        when {
            paymentData == null -> amountToForward
            paymentData.totalAmount == MilliSatoshi(0) -> amountToForward
            else -> paymentData.totalAmount
        }
    }
    val paymentSecret = records.get<OnionTlv.PaymentData>()?.secret
    val invoiceFeatures = records.get<OnionTlv.InvoiceFeatures>()?.features
    val invoiceRoutingInfo = records.get<OnionTlv.InvoiceRoutingInfo>()?.extraHops

    companion object {
        fun create(amount: MilliSatoshi, expiry: CltvExpiry, nextNodeId: PublicKey) = NodeRelayPayload(TlvStream(listOf(OnionTlv.AmountToForward(amount), OnionTlv.OutgoingCltv(expiry), OnionTlv.OutgoingNodeId(nextNodeId))))
    }
}
