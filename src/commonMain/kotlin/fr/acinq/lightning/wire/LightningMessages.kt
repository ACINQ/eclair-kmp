package fr.acinq.lightning.wire

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.lightning.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.ChannelVersion
import fr.acinq.lightning.router.Announcements
import fr.acinq.lightning.utils.*
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlin.math.max
import kotlin.math.min
import kotlin.native.concurrent.ThreadLocal

interface LightningMessage {

    /**
     * Once decrypted, lightning messages start with a 2-byte type that uniquely identifies the kind of message received.
     * See https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#lightning-message-format.
     */
    val type: Long

    fun write(out: Output)

    fun write(): ByteArray {
        val out = ByteArrayOutput()
        write(out)
        return out.toByteArray()
    }

    @ThreadLocal
    companion object {
        val logger by lightningLogger<LightningMessage>()

        /**
         * @param input a single, complete message (typically received over the transport layer).
         * There is a very strong assumption that framing has been taken care of and that there are no missing or extra bytes.
         * Whatever we don't read will simply be ignored, as per the BOLTs.
         */
        fun decode(input: ByteArray): LightningMessage? {
            val stream = ByteArrayInput(input)
            val code = LightningCodecs.u16(stream)
            return when (code.toLong()) {
                Init.type -> Init.read(stream)
                ChannelReestablish.type -> ChannelReestablish.read(stream)
                Warning.type -> Warning.read(stream)
                Error.type -> Error.read(stream)
                Ping.type -> Ping.read(stream)
                Pong.type -> Pong.read(stream)
                OpenChannel.type -> OpenChannel.read(stream)
                AcceptChannel.type -> AcceptChannel.read(stream)
                FundingCreated.type -> FundingCreated.read(stream)
                FundingSigned.type -> FundingSigned.read(stream)
                FundingLocked.type -> FundingLocked.read(stream)
                CommitSig.type -> CommitSig.read(stream)
                RevokeAndAck.type -> RevokeAndAck.read(stream)
                UpdateAddHtlc.type -> UpdateAddHtlc.read(stream)
                UpdateFailHtlc.type -> UpdateFailHtlc.read(stream)
                UpdateFailMalformedHtlc.type -> UpdateFailMalformedHtlc.read(stream)
                UpdateFulfillHtlc.type -> UpdateFulfillHtlc.read(stream)
                UpdateFee.type -> UpdateFee.read(stream)
                AnnouncementSignatures.type -> AnnouncementSignatures.read(stream)
                ChannelAnnouncement.type -> ChannelAnnouncement.read(stream)
                ChannelUpdate.type -> ChannelUpdate.read(stream)
                Shutdown.type -> Shutdown.read(stream)
                ClosingSigned.type -> ClosingSigned.read(stream)
                PayToOpenRequest.type -> PayToOpenRequest.read(stream)
                PayToOpenResponse.type -> PayToOpenResponse.read(stream)
                FCMToken.type -> FCMToken.read(stream)
                UnsetFCMToken.type -> UnsetFCMToken
                SwapInRequest.type -> SwapInRequest.read(stream)
                SwapInResponse.type -> SwapInResponse.read(stream)
                SwapInPending.type -> SwapInPending.read(stream)
                SwapInConfirmed.type -> SwapInConfirmed.read(stream)
                else -> {
                    logger.warning { "cannot decode ${Hex.encode(input)}" }
                    null
                }
            }
        }

        fun encode(input: LightningMessage, out: Output) {
            LightningCodecs.writeU16(input.type.toInt(), out)
            input.write(out)
        }

        fun encode(input: LightningMessage): ByteArray {
            val out = ByteArrayOutput()
            encode(input, out)
            return out.toByteArray()
        }
    }
}

interface LightningMessageReader<T : LightningMessage> {
    fun read(input: Input): T
    fun read(bytes: ByteArray): T = read(ByteArrayInput(bytes))
    fun read(hex: String): T = read(Hex.decode(hex))
}

interface HtlcMessage : LightningMessage
interface SetupMessage : LightningMessage
interface RoutingMessage : LightningMessage
interface AnnouncementMessage : RoutingMessage
interface HasTimestamp : LightningMessage {
    val timestampSeconds: Long
}

interface UpdateMessage : LightningMessage

interface HtlcSettlementMessage : UpdateMessage {
    val id: Long
}

interface HasTemporaryChannelId : LightningMessage {
    val temporaryChannelId: ByteVector32
}

interface HasChannelId : LightningMessage {
    val channelId: ByteVector32
}

interface HasChainHash : LightningMessage {
    val chainHash: ByteVector32
}

@Serializable
data class EncryptedChannelData(@Contextual val data: ByteVector) {
    /** We don't want to log the encrypted channel backups, they take a lot of space. We only keep the first bytes to help correlate mobile/server backups. */
    override fun toString(): String {
        val bytes = data.take(min(data.size(), 10))
        return if (bytes.isEmpty()) "" else "$bytes (truncated)"
    }

    fun isEmpty(): Boolean = data.isEmpty()

    companion object {
        val empty: EncryptedChannelData = EncryptedChannelData(ByteVector.empty)
    }
}

interface HasEncryptedChannelData : LightningMessage {
    val channelData: EncryptedChannelData
    fun withChannelData(data: ByteVector): HasEncryptedChannelData = withChannelData(EncryptedChannelData(data))
    fun withChannelData(ecd: EncryptedChannelData): HasEncryptedChannelData = if (ecd.isEmpty()) this else withNonEmptyChannelData(ecd)
    fun withNonEmptyChannelData(ecd: EncryptedChannelData): HasEncryptedChannelData
}

interface ChannelMessage

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class Init(@Contextual val features: ByteVector, val tlvs: TlvStream<InitTlv> = TlvStream.empty()) : SetupMessage {
    @Transient
    val networks = tlvs.get<InitTlv.Networks>()?.chainHashes ?: listOf()

    override val type: Long get() = Init.type

    override fun write(out: Output) {
        LightningCodecs.writeU16(0, out)
        LightningCodecs.writeU16(features.size(), out)
        LightningCodecs.writeBytes(features, out)
        val tlvReaders = HashMap<Long, TlvValueReader<InitTlv>>()
        @Suppress("UNCHECKED_CAST")
        tlvReaders[InitTlv.Networks.tag] = InitTlv.Networks.Companion as TlvValueReader<InitTlv>
        val serializer = TlvStreamSerializer(false, tlvReaders)
        serializer.write(tlvs, out)
    }

    companion object : LightningMessageReader<Init> {
        const val type: Long = 16

        override fun read(input: Input): Init {
            val gflen = LightningCodecs.u16(input)
            val globalFeatures = LightningCodecs.bytes(input, gflen)
            val lflen = LightningCodecs.u16(input)
            val localFeatures = LightningCodecs.bytes(input, lflen)
            val len = max(gflen, lflen)
            // merge features together
            val features = ByteVector(globalFeatures.leftPaddedCopyOf(len).or(localFeatures.leftPaddedCopyOf(len)))
            val tlvReaders = HashMap<Long, TlvValueReader<InitTlv>>()
            @Suppress("UNCHECKED_CAST")
            tlvReaders[InitTlv.Networks.tag] = InitTlv.Networks.Companion as TlvValueReader<InitTlv>
            val serializer = TlvStreamSerializer(false, tlvReaders)
            val tlvs = serializer.read(input)
            return Init(features, tlvs)
        }
    }
}

data class Warning(override val channelId: ByteVector32, val data: ByteVector) : SetupMessage, HasChannelId {
    constructor(channelId: ByteVector32, message: String?) : this(channelId, ByteVector(message?.encodeToByteArray() ?: ByteArray(0)))
    constructor(message: String?) : this(ByteVector32.Zeroes, message)

    fun toAscii(): String = data.toByteArray().decodeToString()

    override val type: Long get() = Warning.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU16(data.size(), out)
        LightningCodecs.writeBytes(data, out)
    }

    companion object : LightningMessageReader<Warning> {
        const val type: Long = 1

        override fun read(input: Input): Warning {
            return Warning(
                LightningCodecs.bytes(input, 32).toByteVector32(),
                LightningCodecs.bytes(input, LightningCodecs.u16(input)).toByteVector()
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class Error(override val channelId: ByteVector32, val data: ByteVector) : SetupMessage, HasChannelId {
    constructor(channelId: ByteVector32, message: String?) : this(channelId, ByteVector(message?.encodeToByteArray() ?: ByteArray(0)))

    fun toAscii(): String = data.toByteArray().decodeToString()

    override val type: Long get() = Error.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU16(data.size(), out)
        LightningCodecs.writeBytes(data, out)
    }

    companion object : LightningMessageReader<Error> {
        const val type: Long = 17

        override fun read(input: Input): Error {
            return Error(
                LightningCodecs.bytes(input, 32).toByteVector32(),
                LightningCodecs.bytes(input, LightningCodecs.u16(input)).toByteVector()
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class Ping(val pongLength: Int, val data: ByteVector) : SetupMessage {
    override val type: Long get() = Ping.type

    override fun write(out: Output) {
        LightningCodecs.writeU16(pongLength, out)
        LightningCodecs.writeU16(data.size(), out)
        LightningCodecs.writeBytes(data, out)
    }

    companion object : LightningMessageReader<Ping> {
        const val type: Long = 18

        override fun read(input: Input): Ping {
            return Ping(LightningCodecs.u16(input), LightningCodecs.bytes(input, LightningCodecs.u16(input)).toByteVector())
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class Pong(val data: ByteVector) : SetupMessage {
    override val type: Long get() = Pong.type

    override fun write(out: Output) {
        LightningCodecs.writeU16(data.size(), out)
        LightningCodecs.writeBytes(data, out)
    }

    companion object : LightningMessageReader<Pong> {
        const val type: Long = 19

        override fun read(input: Input): Pong {
            return Pong(LightningCodecs.bytes(input, LightningCodecs.u16(input)).toByteVector())
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class OpenChannel(
    @Contextual override val chainHash: ByteVector32,
    @Contextual override val temporaryChannelId: ByteVector32,
    @Contextual val fundingSatoshis: Satoshi,
    val pushMsat: MilliSatoshi,
    @Contextual val dustLimitSatoshis: Satoshi,
    val maxHtlcValueInFlightMsat: Long, // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
    @Contextual val channelReserveSatoshis: Satoshi,
    val htlcMinimumMsat: MilliSatoshi,
    val feeratePerKw: FeeratePerKw,
    val toSelfDelay: CltvExpiryDelta,
    val maxAcceptedHtlcs: Int,
    @Contextual val fundingPubkey: PublicKey,
    @Contextual val revocationBasepoint: PublicKey,
    @Contextual val paymentBasepoint: PublicKey,
    @Contextual val delayedPaymentBasepoint: PublicKey,
    @Contextual val htlcBasepoint: PublicKey,
    @Contextual val firstPerCommitmentPoint: PublicKey,
    val channelFlags: Byte,
    val tlvStream: TlvStream<ChannelTlv> = TlvStream.empty()
) : ChannelMessage, HasTemporaryChannelId, HasChainHash {
    val channelVersion: ChannelVersion? get() = tlvStream.get<ChannelTlv.ChannelVersionTlv>()?.channelVersion

    override val type: Long get() = OpenChannel.type

    override fun write(out: Output) {
        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            ChannelTlv.UpfrontShutdownScript.tag to ChannelTlv.UpfrontShutdownScript.Companion as TlvValueReader<ChannelTlv>,
            ChannelTlv.ChannelVersionTlv.tag to ChannelTlv.ChannelVersionTlv.Companion as TlvValueReader<ChannelTlv>,
            ChannelTlv.ChannelOriginTlv.tag to ChannelTlv.ChannelOriginTlv.Companion as TlvValueReader<ChannelTlv>
        )
        LightningCodecs.writeBytes(chainHash, out)
        LightningCodecs.writeBytes(temporaryChannelId, out)
        LightningCodecs.writeU64(fundingSatoshis.toLong(), out)
        LightningCodecs.writeU64(pushMsat.toLong(), out)
        LightningCodecs.writeU64(dustLimitSatoshis.toLong(), out)
        LightningCodecs.writeU64(maxHtlcValueInFlightMsat, out)
        LightningCodecs.writeU64(channelReserveSatoshis.toLong(), out)
        LightningCodecs.writeU64(htlcMinimumMsat.toLong(), out)
        LightningCodecs.writeU32(feeratePerKw.toLong().toInt(), out)
        LightningCodecs.writeU16(toSelfDelay.toInt(), out)
        LightningCodecs.writeU16(maxAcceptedHtlcs, out)
        LightningCodecs.writeBytes(fundingPubkey.value, out)
        LightningCodecs.writeBytes(revocationBasepoint.value, out)
        LightningCodecs.writeBytes(paymentBasepoint.value, out)
        LightningCodecs.writeBytes(delayedPaymentBasepoint.value, out)
        LightningCodecs.writeBytes(htlcBasepoint.value, out)
        LightningCodecs.writeBytes(firstPerCommitmentPoint.value, out)
        LightningCodecs.writeByte(channelFlags.toInt(), out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<OpenChannel> {
        const val type: Long = 32

        override fun read(input: Input): OpenChannel {
            @Suppress("UNCHECKED_CAST")
            val readers = mapOf(
                ChannelTlv.UpfrontShutdownScript.tag to ChannelTlv.UpfrontShutdownScript.Companion as TlvValueReader<ChannelTlv>,
                ChannelTlv.ChannelVersionTlv.tag to ChannelTlv.ChannelVersionTlv.Companion as TlvValueReader<ChannelTlv>,
                ChannelTlv.ChannelOriginTlv.tag to ChannelTlv.ChannelOriginTlv.Companion as TlvValueReader<ChannelTlv>
            )
            return OpenChannel(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                ByteVector32(LightningCodecs.bytes(input, 32)),
                Satoshi(LightningCodecs.u64(input)),
                MilliSatoshi(LightningCodecs.u64(input)),
                Satoshi(LightningCodecs.u64(input)),
                LightningCodecs.u64(input), // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
                Satoshi(LightningCodecs.u64(input)),
                MilliSatoshi(LightningCodecs.u64(input)),
                FeeratePerKw(LightningCodecs.u32(input).toLong().sat),
                CltvExpiryDelta(LightningCodecs.u16(input)),
                LightningCodecs.u16(input),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                LightningCodecs.byte(input).toByte(),
                TlvStreamSerializer(false, readers).read(input)
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class AcceptChannel(
    @Contextual override val temporaryChannelId: ByteVector32,
    @Contextual val dustLimitSatoshis: Satoshi,
    val maxHtlcValueInFlightMsat: Long, // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
    @Contextual val channelReserveSatoshis: Satoshi,
    val htlcMinimumMsat: MilliSatoshi,
    val minimumDepth: Long,
    val toSelfDelay: CltvExpiryDelta,
    val maxAcceptedHtlcs: Int,
    @Contextual val fundingPubkey: PublicKey,
    @Contextual val revocationBasepoint: PublicKey,
    @Contextual val paymentBasepoint: PublicKey,
    @Contextual val delayedPaymentBasepoint: PublicKey,
    @Contextual val htlcBasepoint: PublicKey,
    @Contextual val firstPerCommitmentPoint: PublicKey,
    val tlvStream: TlvStream<ChannelTlv> = TlvStream.empty()
) : ChannelMessage, HasTemporaryChannelId {
    override val type: Long get() = AcceptChannel.type

    override fun write(out: Output) {
        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            ChannelTlv.UpfrontShutdownScript.tag to ChannelTlv.UpfrontShutdownScript.Companion as TlvValueReader<ChannelTlv>,
            ChannelTlv.ChannelVersionTlv.tag to ChannelTlv.ChannelVersionTlv.Companion as TlvValueReader<ChannelTlv>
        )
        LightningCodecs.writeBytes(temporaryChannelId, out)
        LightningCodecs.writeU64(dustLimitSatoshis.toLong(), out)
        LightningCodecs.writeU64(maxHtlcValueInFlightMsat, out)
        LightningCodecs.writeU64(channelReserveSatoshis.toLong(), out)
        LightningCodecs.writeU64(htlcMinimumMsat.toLong(), out)
        LightningCodecs.writeU32(minimumDepth.toInt(), out)
        LightningCodecs.writeU16(toSelfDelay.toInt(), out)
        LightningCodecs.writeU16(maxAcceptedHtlcs, out)
        LightningCodecs.writeBytes(fundingPubkey.value, out)
        LightningCodecs.writeBytes(revocationBasepoint.value, out)
        LightningCodecs.writeBytes(paymentBasepoint.value, out)
        LightningCodecs.writeBytes(delayedPaymentBasepoint.value, out)
        LightningCodecs.writeBytes(htlcBasepoint.value, out)
        LightningCodecs.writeBytes(firstPerCommitmentPoint.value, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<AcceptChannel> {
        const val type: Long = 33

        override fun read(input: Input): AcceptChannel {
            @Suppress("UNCHECKED_CAST")
            val readers = mapOf(
                ChannelTlv.UpfrontShutdownScript.tag to ChannelTlv.UpfrontShutdownScript.Companion as TlvValueReader<ChannelTlv>,
                ChannelTlv.ChannelVersionTlv.tag to ChannelTlv.ChannelVersionTlv.Companion as TlvValueReader<ChannelTlv>
            )
            return AcceptChannel(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                Satoshi(LightningCodecs.u64(input)),
                LightningCodecs.u64(input), // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi,
                Satoshi(LightningCodecs.u64(input)),
                MilliSatoshi(LightningCodecs.u64(input)),
                LightningCodecs.u32(input).toLong(),
                CltvExpiryDelta(LightningCodecs.u16(input)),
                LightningCodecs.u16(input),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                TlvStreamSerializer(false, readers).read(input)
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class FundingCreated(
    @Contextual override val temporaryChannelId: ByteVector32,
    @Contextual val fundingTxid: ByteVector32,
    val fundingOutputIndex: Int,
    @Contextual val signature: ByteVector64
) : ChannelMessage, HasTemporaryChannelId {
    override val type: Long get() = FundingCreated.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(temporaryChannelId, out)
        LightningCodecs.writeBytes(fundingTxid, out)
        LightningCodecs.writeU16(fundingOutputIndex, out)
        LightningCodecs.writeBytes(signature, out)
    }

    companion object : LightningMessageReader<FundingCreated> {
        const val type: Long = 34

        override fun read(input: Input): FundingCreated {
            return FundingCreated(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                ByteVector32(LightningCodecs.bytes(input, 32)),
                LightningCodecs.u16(input),
                ByteVector64(LightningCodecs.bytes(input, 64))
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class FundingSigned(
    @Contextual override val channelId: ByteVector32,
    @Contextual val signature: ByteVector64,
    val tlvStream: TlvStream<FundingSignedTlv> = TlvStream.empty()
) : ChannelMessage, HasChannelId, HasEncryptedChannelData {
    override val type: Long get() = FundingSigned.type

    override val channelData: EncryptedChannelData get() = tlvStream.get<FundingSignedTlv.ChannelData>()?.ecb ?: EncryptedChannelData.empty
    override fun withNonEmptyChannelData(ecd: EncryptedChannelData): FundingSigned = copy(tlvStream = tlvStream.addOrUpdate(FundingSignedTlv.ChannelData(ecd)))

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeBytes(signature, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<FundingSigned> {
        const val type: Long = 35

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(FundingSignedTlv.ChannelData.tag to FundingSignedTlv.ChannelData.Companion as TlvValueReader<FundingSignedTlv>)

        override fun read(input: Input): FundingSigned {
            return FundingSigned(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                ByteVector64(LightningCodecs.bytes(input, 64)),
                TlvStreamSerializer(false, readers).read(input)
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class FundingLocked(
    @Contextual override val channelId: ByteVector32,
    @Contextual val nextPerCommitmentPoint: PublicKey
) : ChannelMessage, HasChannelId {
    override val type: Long get() = FundingLocked.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeBytes(nextPerCommitmentPoint.value, out)
    }

    companion object : LightningMessageReader<FundingLocked> {
        const val type: Long = 36

        override fun read(input: Input): FundingLocked {
            return FundingLocked(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                PublicKey(LightningCodecs.bytes(input, 33))
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class UpdateAddHtlc(
    @Contextual override val channelId: ByteVector32,
    val id: Long,
    val amountMsat: MilliSatoshi,
    @Contextual val paymentHash: ByteVector32,
    val cltvExpiry: CltvExpiry,
    val onionRoutingPacket: OnionRoutingPacket
) : HtlcMessage, UpdateMessage, HasChannelId {
    override val type: Long get() = UpdateAddHtlc.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU64(id, out)
        LightningCodecs.writeU64(amountMsat.toLong(), out)
        LightningCodecs.writeBytes(paymentHash, out)
        LightningCodecs.writeU32(cltvExpiry.toLong().toInt(), out)
        OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).write(onionRoutingPacket, out)
    }

    companion object : LightningMessageReader<UpdateAddHtlc> {
        const val type: Long = 128

        override fun read(input: Input): UpdateAddHtlc {
            val channelId = ByteVector32(LightningCodecs.bytes(input, 32))
            val id = LightningCodecs.u64(input)
            val amount = MilliSatoshi(LightningCodecs.u64(input))
            val paymentHash = ByteVector32(LightningCodecs.bytes(input, 32))
            val expiry = CltvExpiry(LightningCodecs.u32(input).toLong())
            val onion = OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).read(input)
            return UpdateAddHtlc(channelId, id, amount, paymentHash, expiry, onion)
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class UpdateFulfillHtlc(
    @Contextual override val channelId: ByteVector32,
    override val id: Long,
    @Contextual val paymentPreimage: ByteVector32
) : HtlcMessage, HtlcSettlementMessage, HasChannelId {
    override val type: Long get() = UpdateFulfillHtlc.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU64(id, out)
        LightningCodecs.writeBytes(paymentPreimage, out)
    }

    companion object : LightningMessageReader<UpdateFulfillHtlc> {
        const val type: Long = 130

        override fun read(input: Input): UpdateFulfillHtlc {
            return UpdateFulfillHtlc(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                LightningCodecs.u64(input),
                ByteVector32(LightningCodecs.bytes(input, 32))
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class UpdateFailHtlc(
    @Contextual override val channelId: ByteVector32,
    override val id: Long,
    @Contextual val reason: ByteVector
) : HtlcMessage, HtlcSettlementMessage, HasChannelId {
    override val type: Long get() = UpdateFailHtlc.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU64(id, out)
        LightningCodecs.writeU16(reason.size(), out)
        LightningCodecs.writeBytes(reason, out)
    }

    companion object : LightningMessageReader<UpdateFailHtlc> {
        const val type: Long = 131

        override fun read(input: Input): UpdateFailHtlc {
            return UpdateFailHtlc(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                LightningCodecs.u64(input),
                ByteVector(LightningCodecs.bytes(input, LightningCodecs.u16(input)))
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class UpdateFailMalformedHtlc(
    @Contextual override val channelId: ByteVector32,
    override val id: Long,
    @Contextual val onionHash: ByteVector32,
    val failureCode: Int
) : HtlcMessage, HtlcSettlementMessage, HasChannelId {
    override val type: Long get() = UpdateFailMalformedHtlc.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU64(id, out)
        LightningCodecs.writeBytes(onionHash, out)
        LightningCodecs.writeU16(failureCode, out)
    }

    companion object : LightningMessageReader<UpdateFailMalformedHtlc> {
        const val type: Long = 135

        override fun read(input: Input): UpdateFailMalformedHtlc {
            return UpdateFailMalformedHtlc(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                LightningCodecs.u64(input),
                ByteVector32(LightningCodecs.bytes(input, 32)),
                LightningCodecs.u16(input)
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class CommitSig(
    @Contextual override val channelId: ByteVector32,
    @Contextual val signature: ByteVector64,
    val htlcSignatures: List<@Contextual ByteVector64>,
    val tlvStream: TlvStream<CommitSigTlv> = TlvStream.empty()
) : HtlcMessage, HasChannelId, HasEncryptedChannelData {
    override val type: Long get() = CommitSig.type

    override val channelData: EncryptedChannelData get() = tlvStream.get<CommitSigTlv.ChannelData>()?.ecb ?: EncryptedChannelData.empty
    override fun withNonEmptyChannelData(ecd: EncryptedChannelData): CommitSig = copy(tlvStream = tlvStream.addOrUpdate(CommitSigTlv.ChannelData(ecd)))

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeBytes(signature, out)
        LightningCodecs.writeU16(htlcSignatures.size, out)
        htlcSignatures.forEach { LightningCodecs.writeBytes(it, out) }
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<CommitSig> {
        const val type: Long = 132

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(CommitSigTlv.ChannelData.tag to CommitSigTlv.ChannelData.Companion as TlvValueReader<CommitSigTlv>)

        override fun read(input: Input): CommitSig {
            val channelId = ByteVector32(LightningCodecs.bytes(input, 32))
            val sig = ByteVector64(LightningCodecs.bytes(input, 64))
            val numHtlcs = LightningCodecs.u16(input)
            val htlcSigs = ArrayList<ByteVector64>(numHtlcs)
            for (i in 1..numHtlcs) {
                htlcSigs += ByteVector64(LightningCodecs.bytes(input, 64))
            }
            return CommitSig(channelId, sig, htlcSigs.toList(), TlvStreamSerializer(false, readers).read(input))
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class RevokeAndAck(
    override val channelId: ByteVector32,
    val perCommitmentSecret: PrivateKey,
    val nextPerCommitmentPoint: PublicKey,
    val tlvStream: TlvStream<RevokeAndAckTlv> = TlvStream.empty()
) : HtlcMessage, HasChannelId, HasEncryptedChannelData {
    override val type: Long get() = RevokeAndAck.type

    override val channelData: EncryptedChannelData get() = tlvStream.get<RevokeAndAckTlv.ChannelData>()?.ecb ?: EncryptedChannelData.empty
    override fun withNonEmptyChannelData(ecd: EncryptedChannelData): RevokeAndAck = copy(tlvStream = tlvStream.addOrUpdate(RevokeAndAckTlv.ChannelData(ecd)))

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeBytes(perCommitmentSecret.value, out)
        LightningCodecs.writeBytes(nextPerCommitmentPoint.value, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<RevokeAndAck> {
        const val type: Long = 133

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(RevokeAndAckTlv.ChannelData.tag to RevokeAndAckTlv.ChannelData.Companion as TlvValueReader<RevokeAndAckTlv>)

        override fun read(input: Input): RevokeAndAck {
            return RevokeAndAck(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                PrivateKey(LightningCodecs.bytes(input, 32)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                TlvStreamSerializer(false, readers).read(input)
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class UpdateFee(
    @Contextual override val channelId: ByteVector32,
    val feeratePerKw: FeeratePerKw
) : ChannelMessage, UpdateMessage, HasChannelId {
    override val type: Long get() = UpdateFee.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU32(feeratePerKw.feerate.toLong().toInt(), out)
    }

    companion object : LightningMessageReader<UpdateFee> {
        const val type: Long = 134

        override fun read(input: Input): UpdateFee {
            return UpdateFee(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                FeeratePerKw(LightningCodecs.u32(input).toLong().sat)
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class ChannelReestablish(
    @Contextual override val channelId: ByteVector32,
    val nextLocalCommitmentNumber: Long,
    val nextRemoteRevocationNumber: Long,
    @Contextual val yourLastCommitmentSecret: PrivateKey,
    @Contextual val myCurrentPerCommitmentPoint: PublicKey,
    val tlvStream: TlvStream<ChannelReestablishTlv> = TlvStream.empty()
) : HasChannelId, HasEncryptedChannelData {
    override val type: Long get() = ChannelReestablish.type

    override val channelData: EncryptedChannelData get() = tlvStream.get<ChannelReestablishTlv.ChannelData>()?.ecb ?: EncryptedChannelData.empty
    override fun withNonEmptyChannelData(ecd: EncryptedChannelData): ChannelReestablish = copy(tlvStream = tlvStream.addOrUpdate(ChannelReestablishTlv.ChannelData(ecd)))

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU64(nextLocalCommitmentNumber, out)
        LightningCodecs.writeU64(nextRemoteRevocationNumber, out)
        LightningCodecs.writeBytes(yourLastCommitmentSecret.value, out)
        LightningCodecs.writeBytes(myCurrentPerCommitmentPoint.value, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<ChannelReestablish> {
        const val type: Long = 136

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(ChannelReestablishTlv.ChannelData.tag to ChannelReestablishTlv.ChannelData.Companion as TlvValueReader<ChannelReestablishTlv>)

        override fun read(input: Input): ChannelReestablish {
            return ChannelReestablish(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                LightningCodecs.u64(input),
                LightningCodecs.u64(input),
                PrivateKey(LightningCodecs.bytes(input, 32)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                TlvStreamSerializer(false, readers).read(input)
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class AnnouncementSignatures(
    override val channelId: ByteVector32,
    val shortChannelId: ShortChannelId,
    val nodeSignature: ByteVector64,
    val bitcoinSignature: ByteVector64
) : RoutingMessage, HasChannelId {
    override val type: Long get() = AnnouncementSignatures.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU64(shortChannelId.toLong(), out)
        LightningCodecs.writeBytes(nodeSignature, out)
        LightningCodecs.writeBytes(bitcoinSignature, out)
    }

    companion object : LightningMessageReader<AnnouncementSignatures> {
        const val type: Long = 259

        override fun read(input: Input): AnnouncementSignatures {
            return AnnouncementSignatures(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                ShortChannelId(LightningCodecs.u64(input)),
                ByteVector64(LightningCodecs.bytes(input, 64)),
                ByteVector64(LightningCodecs.bytes(input, 64))
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class ChannelAnnouncement(
    @Contextual val nodeSignature1: ByteVector64,
    @Contextual val nodeSignature2: ByteVector64,
    @Contextual val bitcoinSignature1: ByteVector64,
    @Contextual val bitcoinSignature2: ByteVector64,
    val features: Features,
    @Contextual override val chainHash: ByteVector32,
    val shortChannelId: ShortChannelId,
    @Contextual val nodeId1: PublicKey,
    @Contextual val nodeId2: PublicKey,
    @Contextual val bitcoinKey1: PublicKey,
    @Contextual val bitcoinKey2: PublicKey,
    @Contextual val unknownFields: ByteVector = ByteVector.empty
) : AnnouncementMessage, HasChainHash {
    override val type: Long get() = ChannelAnnouncement.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(nodeSignature1, out)
        LightningCodecs.writeBytes(nodeSignature2, out)
        LightningCodecs.writeBytes(bitcoinSignature1, out)
        LightningCodecs.writeBytes(bitcoinSignature2, out)
        val featureBytes = features.toByteArray()
        LightningCodecs.writeU16(featureBytes.size, out)
        LightningCodecs.writeBytes(featureBytes, out)
        LightningCodecs.writeBytes(chainHash, out)
        LightningCodecs.writeU64(shortChannelId.toLong(), out)
        LightningCodecs.writeBytes(nodeId1.value, out)
        LightningCodecs.writeBytes(nodeId2.value, out)
        LightningCodecs.writeBytes(bitcoinKey1.value, out)
        LightningCodecs.writeBytes(bitcoinKey2.value, out)
        LightningCodecs.writeBytes(unknownFields, out)
    }

    companion object : LightningMessageReader<ChannelAnnouncement> {
        const val type: Long = 256

        override fun read(input: Input): ChannelAnnouncement {
            val nodeSignature1 = LightningCodecs.bytes(input, 64).toByteVector64()
            val nodeSignature2 = LightningCodecs.bytes(input, 64).toByteVector64()
            val bitcoinSignature1 = LightningCodecs.bytes(input, 64).toByteVector64()
            val bitcoinSignature2 = LightningCodecs.bytes(input, 64).toByteVector64()
            val featureBytes = LightningCodecs.bytes(input, LightningCodecs.u16(input))
            val chainHash = LightningCodecs.bytes(input, 32).toByteVector32()
            val shortChannelId = ShortChannelId(LightningCodecs.u64(input))
            val nodeId1 = PublicKey(LightningCodecs.bytes(input, 33))
            val nodeId2 = PublicKey(LightningCodecs.bytes(input, 33))
            val bitcoinKey1 = PublicKey(LightningCodecs.bytes(input, 33))
            val bitcoinKey2 = PublicKey(LightningCodecs.bytes(input, 33))
            val unknownBytes = if (input.availableBytes > 0) LightningCodecs.bytes(input, input.availableBytes).toByteVector() else ByteVector.empty
            return ChannelAnnouncement(
                nodeSignature1,
                nodeSignature2,
                bitcoinSignature1,
                bitcoinSignature2,
                Features(featureBytes),
                chainHash,
                shortChannelId,
                nodeId1,
                nodeId2,
                bitcoinKey1,
                bitcoinKey2,
                unknownBytes
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class ChannelUpdate(
    @Contextual val signature: ByteVector64,
    @Contextual override val chainHash: ByteVector32,
    val shortChannelId: ShortChannelId,
    override val timestampSeconds: Long,
    val messageFlags: Byte,
    val channelFlags: Byte,
    val cltvExpiryDelta: CltvExpiryDelta,
    val htlcMinimumMsat: MilliSatoshi,
    val feeBaseMsat: MilliSatoshi,
    val feeProportionalMillionths: Long,
    val htlcMaximumMsat: MilliSatoshi?,
    @Contextual val unknownFields: ByteVector = ByteVector.empty
) : AnnouncementMessage, HasTimestamp, HasChainHash {
    init {
        require(((messageFlags.toInt() and 1) != 0) == (htlcMaximumMsat != null)) { "htlcMaximumMsat is not consistent with messageFlags" }
    }

    override val type: Long get() = ChannelUpdate.type

    /** BOLT 7: The creating node [...] MUST set the direction bit of flags to 0 if the creating node is node-id-1 in that message, otherwise 1. */
    fun isNode1(): Boolean = (channelFlags.toInt() and 1) == 0

    /** BOLT 7: A node MAY create and send a channel_update with the disable bit set to signal the temporary unavailability of a channel */
    fun isEnabled(): Boolean = (channelFlags.toInt() and 2) == 0

    fun isRemote(localNodeId: PublicKey, remoteNodeId: PublicKey): Boolean = isNode1() != Announcements.isNode1(localNodeId, remoteNodeId)

    override fun write(out: Output) {
        LightningCodecs.writeBytes(signature, out)
        LightningCodecs.writeBytes(chainHash, out)
        LightningCodecs.writeU64(shortChannelId.toLong(), out)
        LightningCodecs.writeU32(timestampSeconds.toInt(), out)
        LightningCodecs.writeByte(messageFlags.toInt(), out)
        LightningCodecs.writeByte(channelFlags.toInt(), out)
        LightningCodecs.writeU16(cltvExpiryDelta.toInt(), out)
        LightningCodecs.writeU64(htlcMinimumMsat.toLong(), out)
        LightningCodecs.writeU32(feeBaseMsat.toLong().toInt(), out)
        LightningCodecs.writeU32(feeProportionalMillionths.toInt(), out)
        if (htlcMaximumMsat != null) {
            LightningCodecs.writeU64(htlcMaximumMsat.toLong(), out)
        }
        LightningCodecs.writeBytes(unknownFields, out)
    }

    companion object : LightningMessageReader<ChannelUpdate> {
        const val type: Long = 258

        override fun read(input: Input): ChannelUpdate {
            val signature = ByteVector64(LightningCodecs.bytes(input, 64))
            val chainHash = ByteVector32(LightningCodecs.bytes(input, 32))
            val shortChannelId = ShortChannelId(LightningCodecs.u64(input))
            val timestampSeconds = LightningCodecs.u32(input).toLong()
            val messageFlags = LightningCodecs.byte(input).toByte()
            val channelFlags = LightningCodecs.byte(input).toByte()
            val cltvExpiryDelta = CltvExpiryDelta(LightningCodecs.u16(input))
            val htlcMinimumMsat = MilliSatoshi(LightningCodecs.u64(input))
            val feeBaseMsat = MilliSatoshi(LightningCodecs.u32(input).toLong())
            val feeProportionalMillionths = LightningCodecs.u32(input).toLong()
            val htlcMaximumMsat = if ((messageFlags.toInt() and 1) != 0) MilliSatoshi(LightningCodecs.u64(input)) else null
            val unknownBytes = if (input.availableBytes > 0) LightningCodecs.bytes(input, input.availableBytes).toByteVector() else ByteVector.empty
            return ChannelUpdate(
                signature,
                chainHash,
                shortChannelId,
                timestampSeconds,
                messageFlags,
                channelFlags,
                cltvExpiryDelta,
                htlcMinimumMsat,
                feeBaseMsat,
                feeProportionalMillionths,
                htlcMaximumMsat,
                unknownBytes
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class Shutdown(
    @Contextual override val channelId: ByteVector32,
    @Contextual val scriptPubKey: ByteVector,
    val tlvStream: TlvStream<ShutdownTlv> = TlvStream.empty()
) : ChannelMessage, HasChannelId, HasEncryptedChannelData {
    override val type: Long get() = Shutdown.type

    override val channelData: EncryptedChannelData get() = tlvStream.get<ShutdownTlv.ChannelData>()?.ecb ?: EncryptedChannelData.empty
    override fun withNonEmptyChannelData(ecd: EncryptedChannelData): Shutdown = copy(tlvStream = tlvStream.addOrUpdate(ShutdownTlv.ChannelData(ecd)))

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU16(scriptPubKey.size(), out)
        LightningCodecs.writeBytes(scriptPubKey, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<Shutdown> {
        const val type: Long = 38

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(ShutdownTlv.ChannelData.tag to ShutdownTlv.ChannelData.Companion as TlvValueReader<ShutdownTlv>)

        override fun read(input: Input): Shutdown {
            return Shutdown(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                ByteVector(LightningCodecs.bytes(input, LightningCodecs.u16(input))),
                TlvStreamSerializer(false, readers).read(input)
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class ClosingSigned(
    @Contextual override val channelId: ByteVector32,
    @Contextual val feeSatoshis: Satoshi,
    @Contextual val signature: ByteVector64,
    val tlvStream: TlvStream<ClosingSignedTlv> = TlvStream.empty()
) : ChannelMessage, HasChannelId, HasEncryptedChannelData {
    override val type: Long get() = ClosingSigned.type

    override val channelData: EncryptedChannelData get() = tlvStream.get<ClosingSignedTlv.ChannelData>()?.ecb ?: EncryptedChannelData.empty
    override fun withNonEmptyChannelData(ecd: EncryptedChannelData): ClosingSigned = copy(tlvStream = tlvStream.addOrUpdate(ClosingSignedTlv.ChannelData(ecd)))

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU64(feeSatoshis.toLong(), out)
        LightningCodecs.writeBytes(signature, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<ClosingSigned> {
        const val type: Long = 39

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            ClosingSignedTlv.FeeRange.tag to ClosingSignedTlv.FeeRange.Companion as TlvValueReader<ClosingSignedTlv>,
            ClosingSignedTlv.ChannelData.tag to ClosingSignedTlv.ChannelData.Companion as TlvValueReader<ClosingSignedTlv>
        )

        override fun read(input: Input): ClosingSigned {
            return ClosingSigned(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                Satoshi(LightningCodecs.u64(input)),
                ByteVector64(LightningCodecs.bytes(input, 64)),
                TlvStreamSerializer(false, readers).read(input)
            )
        }
    }
}

/**
 * When we don't have enough incoming liquidity to receive a payment, our peer may open a channel to us on-the-fly to carry that payment.
 * This message contains details that allow us to recalculate the fee that our peer will take in exchange for the new channel.
 * This allows us to combine multiple requests for the same payment and figure out the final fee that will be applied.
 *
 * @param chainHash chain we're on.
 * @param fundingSatoshis total capacity of the channel our peer will open to us (some of the funds may be on their side).
 * @param amountMsat payment amount covered by this new channel: we will receive push_msat = amountMsat - fees.
 * @param payToOpenMinAmountMsat minimum amount for a pay-to-open to be attempted, this should be compared to the total amount in the case of an MPP payment.
 * @param payToOpenFeeSatoshis fees that will be deducted from the amount pushed to us (this fee covers the on-chain fees our peer will pay to open the channel).
 * @param paymentHash payment hash.
 * @param expireAt after the proposal expires, our peer will fail the payment and won't open a channel to us.
 * @param finalPacket onion packet that we would have received if there had been a channel to forward the payment to.
 */
@OptIn(ExperimentalUnsignedTypes::class)
data class PayToOpenRequest(
    override val chainHash: ByteVector32,
    val fundingSatoshis: Satoshi,
    val amountMsat: MilliSatoshi,
    val payToOpenMinAmountMsat: MilliSatoshi,
    val payToOpenFeeSatoshis: Satoshi,
    val paymentHash: ByteVector32,
    val expireAt: Long,
    val finalPacket: OnionRoutingPacket
) : LightningMessage, HasChainHash {
    override val type: Long get() = PayToOpenRequest.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash, out)
        LightningCodecs.writeU64(fundingSatoshis.toLong(), out)
        LightningCodecs.writeU64(amountMsat.toLong(), out)
        LightningCodecs.writeU64(payToOpenMinAmountMsat.toLong(), out)
        LightningCodecs.writeU64(payToOpenFeeSatoshis.toLong(), out)
        LightningCodecs.writeBytes(paymentHash, out)
        LightningCodecs.writeU32(expireAt.toInt(), out)
        LightningCodecs.writeU16(finalPacket.payload.size(), out)
        OnionRoutingPacketSerializer(finalPacket.payload.size()).write(finalPacket, out)
    }

    companion object : LightningMessageReader<PayToOpenRequest> {
        const val type: Long = 35021

        override fun read(input: Input): PayToOpenRequest {
            return PayToOpenRequest(
                chainHash = ByteVector32(LightningCodecs.bytes(input, 32)),
                fundingSatoshis = Satoshi(LightningCodecs.u64(input)),
                amountMsat = MilliSatoshi(LightningCodecs.u64(input)),
                payToOpenMinAmountMsat = MilliSatoshi(LightningCodecs.u64(input)),
                payToOpenFeeSatoshis = Satoshi(LightningCodecs.u64(input)),
                paymentHash = ByteVector32(LightningCodecs.bytes(input, 32)),
                expireAt = LightningCodecs.u32(input).toLong(),
                finalPacket = OnionRoutingPacketSerializer(LightningCodecs.u16(input)).read(input)
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class PayToOpenResponse(override val chainHash: ByteVector32, val paymentHash: ByteVector32, val result: Result) : LightningMessage, HasChainHash {
    override val type: Long get() = PayToOpenResponse.type

    sealed class Result {
        // @formatter:off
        data class Success(val paymentPreimage: ByteVector32) : Result()
        /** reason is an onion-encrypted failure message, like those in UpdateFailHtlc */
        data class Failure(val reason: ByteVector?) : Result()
        // @formatter:on
    }

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash, out)
        LightningCodecs.writeBytes(paymentHash, out)
        when (result) {
            is Result.Success -> LightningCodecs.writeBytes(result.paymentPreimage, out)
            is Result.Failure -> {
                LightningCodecs.writeBytes(ByteVector32.Zeroes, out) // this is for backward compatibility
                result.reason?.let {
                    LightningCodecs.writeU16(it.size(), out)
                    LightningCodecs.writeBytes(it, out)
                }
            }
        }
    }

    companion object : LightningMessageReader<PayToOpenResponse> {
        const val type: Long = 35003

        override fun read(input: Input): PayToOpenResponse {
            val chainHash = LightningCodecs.bytes(input, 32).toByteVector32()
            val paymentHash = LightningCodecs.bytes(input, 32).toByteVector32()
            return when (val preimage = LightningCodecs.bytes(input, 32).toByteVector32()) {
                ByteVector32.Zeroes -> {
                    val failure = if (input.availableBytes > 0) LightningCodecs.bytes(input, LightningCodecs.u16(input)).toByteVector() else null
                    PayToOpenResponse(chainHash, paymentHash, Result.Failure(failure))
                }
                else -> PayToOpenResponse(chainHash, paymentHash, Result.Success(preimage))
            }
        }
    }
}

@Serializable
data class FCMToken(@Contextual val token: ByteVector) : LightningMessage {
    constructor(token: String) : this(ByteVector(token.encodeToByteArray()))

    override val type: Long get() = FCMToken.type

    override fun write(out: Output) {
        LightningCodecs.writeU16(token.size(), out)
        LightningCodecs.writeBytes(token, out)
    }

    fun toAscii(): String = token.toByteArray().decodeToString()

    companion object : LightningMessageReader<FCMToken> {
        const val type: Long = 35017

        override fun read(input: Input): FCMToken {
            return FCMToken(LightningCodecs.bytes(input, LightningCodecs.u16(input)).toByteVector())
        }
    }
}

@Serializable
object UnsetFCMToken : LightningMessage {
    override val type: Long get() = 35019
    override fun write(out: Output) {}
}

@OptIn(ExperimentalUnsignedTypes::class)
data class SwapInRequest(
    override val chainHash: ByteVector32
) : LightningMessage, HasChainHash {
    override val type: Long get() = SwapInRequest.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash, out)
    }

    companion object : LightningMessageReader<SwapInRequest> {
        const val type: Long = 35007

        override fun read(input: Input): SwapInRequest {
            return SwapInRequest(LightningCodecs.bytes(input, 32).toByteVector32())
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class SwapInResponse(
    override val chainHash: ByteVector32,
    val bitcoinAddress: String
) : LightningMessage, HasChainHash {
    override val type: Long get() = SwapInResponse.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash, out)
        val addressBytes = bitcoinAddress.encodeToByteArray()
        LightningCodecs.writeU16(addressBytes.size, out)
        LightningCodecs.writeBytes(addressBytes, out)
    }

    companion object : LightningMessageReader<SwapInResponse> {
        const val type: Long = 35009

        override fun read(input: Input): SwapInResponse {
            return SwapInResponse(
                chainHash = ByteVector32(LightningCodecs.bytes(input, 32)),
                bitcoinAddress = LightningCodecs.bytes(input, LightningCodecs.u16(input)).decodeToString()
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class SwapInPending(
    val bitcoinAddress: String,
    val amount: Satoshi
) : LightningMessage {
    override val type: Long get() = SwapInPending.type

    override fun write(out: Output) {
        val addressBytes = bitcoinAddress.encodeToByteArray()
        LightningCodecs.writeU16(addressBytes.size, out)
        LightningCodecs.writeBytes(addressBytes, out)
        LightningCodecs.writeU64(amount.toLong(), out)
    }

    companion object : LightningMessageReader<SwapInPending> {
        const val type: Long = 35005

        override fun read(input: Input): SwapInPending {
            return SwapInPending(
                bitcoinAddress = LightningCodecs.bytes(input, LightningCodecs.u16(input)).decodeToString(),
                amount = Satoshi(LightningCodecs.u64(input))
            )
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
data class SwapInConfirmed(
    val bitcoinAddress: String,
    val amount: MilliSatoshi
) : LightningMessage {
    override val type: Long get() = SwapInConfirmed.type

    override fun write(out: Output) {
        val addressBytes = bitcoinAddress.encodeToByteArray()
        LightningCodecs.writeU16(addressBytes.size, out)
        LightningCodecs.writeBytes(addressBytes, out)
        LightningCodecs.writeU64(amount.toLong(), out)
    }

    companion object : LightningMessageReader<SwapInConfirmed> {
        const val type: Long = 35015

        override fun read(input: Input): SwapInConfirmed {
            return SwapInConfirmed(
                bitcoinAddress = LightningCodecs.bytes(input, LightningCodecs.u16(input)).decodeToString(),
                amount = MilliSatoshi(LightningCodecs.u64(input))
            )
        }
    }
}
