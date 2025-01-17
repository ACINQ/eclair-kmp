package fr.acinq.lightning.wire

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.lightning.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.ChannelFlags
import fr.acinq.lightning.channel.ChannelType
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.router.Announcements
import fr.acinq.lightning.utils.*
import fr.acinq.secp256k1.Hex
import io.ktor.utils.io.charsets.*
import io.ktor.utils.io.core.*
import kotlin.math.max
import kotlin.math.min

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

    companion object {

        /**
         * @param input a single, complete message (typically received over the transport layer).
         * There is a very strong assumption that framing has been taken care of and that there are no missing or extra bytes.
         * Whatever we don't read will simply be ignored, as per the BOLTs.
         */
        fun decode(input: ByteArray): LightningMessage {
            val stream = ByteArrayInput(input)
            val code = LightningCodecs.u16(stream)
            return when (code.toLong()) {
                Init.type -> Init.read(stream)
                ChannelReestablish.type -> ChannelReestablish.read(stream)
                Warning.type -> Warning.read(stream)
                Error.type -> Error.read(stream)
                Ping.type -> Ping.read(stream)
                Pong.type -> Pong.read(stream)
                OpenDualFundedChannel.type -> OpenDualFundedChannel.read(stream)
                AcceptDualFundedChannel.type -> AcceptDualFundedChannel.read(stream)
                FundingCreated.type -> FundingCreated.read(stream)
                FundingSigned.type -> FundingSigned.read(stream)
                ChannelReady.type -> ChannelReady.read(stream)
                TxAddInput.type -> TxAddInput.read(stream)
                TxAddOutput.type -> TxAddOutput.read(stream)
                TxRemoveInput.type -> TxRemoveInput.read(stream)
                TxRemoveOutput.type -> TxRemoveOutput.read(stream)
                TxComplete.type -> TxComplete.read(stream)
                TxSignatures.type -> TxSignatures.read(stream)
                TxInitRbf.type -> TxInitRbf.read(stream)
                TxAckRbf.type -> TxAckRbf.read(stream)
                TxAbort.type -> TxAbort.read(stream)
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
                OnionMessage.type -> OnionMessage.read(stream)
                WillAddHtlc.type -> WillAddHtlc.read(stream)
                WillFailHtlc.type -> WillFailHtlc.read(stream)
                WillFailMalformedHtlc.type -> WillFailMalformedHtlc.read(stream)
                CancelOnTheFlyFunding.type -> CancelOnTheFlyFunding.read(stream)
                AddFeeCredit.type -> AddFeeCredit.read(stream)
                CurrentFeeCredit.type -> CurrentFeeCredit.read(stream)
                FCMToken.type -> FCMToken.read(stream)
                UnsetFCMToken.type -> UnsetFCMToken
                DNSAddressRequest.type -> DNSAddressRequest.read(stream)
                DNSAddressResponse.type -> DNSAddressResponse.read(stream)
                PhoenixAndroidLegacyInfo.type -> PhoenixAndroidLegacyInfo.read(stream)
                RecommendedFeerates.type -> RecommendedFeerates.read(stream)
                Stfu.type -> Stfu.read(stream)
                SpliceInit.type -> SpliceInit.read(stream)
                SpliceAck.type -> SpliceAck.read(stream)
                SpliceLocked.type -> SpliceLocked.read(stream)
                else -> UnknownMessage(code.toLong())
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

interface UpdateMessage : LightningMessage, ForbiddenMessageDuringSplice

interface HtlcSettlementMessage : UpdateMessage {
    val id: Long
}

sealed class InteractiveTxMessage : LightningMessage
sealed class InteractiveTxConstructionMessage : InteractiveTxMessage()

interface HasTemporaryChannelId : LightningMessage {
    val temporaryChannelId: ByteVector32
}

interface HasChannelId : LightningMessage {
    val channelId: ByteVector32
}

interface HasSerialId : LightningMessage {
    val serialId: Long
}

interface HasChainHash : LightningMessage {
    val chainHash: BlockHash
}

interface ForbiddenMessageDuringSplice : LightningMessage

data class EncryptedChannelData(val data: ByteVector) {
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

interface HasEncryptedChannelData : HasChannelId {
    val channelData: EncryptedChannelData
    fun withNonEmptyChannelData(ecd: EncryptedChannelData): HasEncryptedChannelData
    fun withChannelData(data: ByteVector, logger: MDCLogger? = null): HasEncryptedChannelData = withChannelData(EncryptedChannelData(data), logger)
    fun withChannelData(ecd: EncryptedChannelData, logger: MDCLogger? = null): HasEncryptedChannelData {
        // The maximum size for lightning messages is 65535 bytes, so we only include a channel backup when we have enough space available.
        // Our peer needs to be able to send the backup back in their channel_reestablish message, and we don't know the size of that message.
        // We use an upper bound of 60000 bytes, hoping that it will be enough to make it work in all cases.
        val sizeWithoutBackup = write().size
        return when {
            ecd.isEmpty() -> this
            ecd.data.size() + sizeWithoutBackup <= 60_000 -> withNonEmptyChannelData(ecd)
            else -> {
                logger?.warning { "c:${this.channelId} could not include encrypted backup in ${this::class.simpleName}: too large (${ecd.data.size()} bytes)" }
                this
            }
        }
    }
}

interface ChannelMessage

interface OnTheFlyFundingMessage : LightningMessage

data class Init(val features: Features, val tlvs: TlvStream<InitTlv> = TlvStream.empty()) : SetupMessage {
    val networks = tlvs.get<InitTlv.Networks>()?.chainHashes ?: listOf()
    val liquidityRates = tlvs.get<InitTlv.OptionWillFund>()?.rates

    constructor(features: Features, chainHashs: List<ByteVector32>, liquidityRates: LiquidityAds.WillFundRates?) : this(
        features,
        TlvStream(
            setOfNotNull(
                if (chainHashs.isNotEmpty()) InitTlv.Networks(chainHashs) else null,
                liquidityRates?.let { InitTlv.OptionWillFund(it) },
            )
        )
    )

    override val type: Long get() = Init.type

    override fun write(out: Output) {
        LightningCodecs.writeU16(0, out)
        features.toByteArray().let {
            LightningCodecs.writeU16(it.size, out)
            LightningCodecs.writeBytes(it, out)
        }
        TlvStreamSerializer(false, readers).write(tlvs, out)
    }

    companion object : LightningMessageReader<Init> {
        const val type: Long = 16

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            InitTlv.Networks.tag to InitTlv.Networks.Companion as TlvValueReader<InitTlv>,
            InitTlv.OptionWillFund.tag to InitTlv.OptionWillFund.Companion as TlvValueReader<InitTlv>,
            InitTlv.PhoenixAndroidLegacyNodeId.tag to InitTlv.PhoenixAndroidLegacyNodeId.Companion as TlvValueReader<InitTlv>,
        )

        override fun read(input: Input): Init {
            val gflen = LightningCodecs.u16(input)
            val globalFeatures = LightningCodecs.bytes(input, gflen)
            val lflen = LightningCodecs.u16(input)
            val localFeatures = LightningCodecs.bytes(input, lflen)
            val len = max(gflen, lflen)
            // merge features together
            val features = Features(ByteVector(globalFeatures.leftPaddedCopyOf(len).or(localFeatures.leftPaddedCopyOf(len))))
            val tlvs = TlvStreamSerializer(false, readers).read(input)
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

data class TxAddInput(
    override val channelId: ByteVector32,
    override val serialId: Long,
    val previousTx: Transaction?,
    val previousTxOutput: Long,
    val sequence: UInt,
    val tlvs: TlvStream<TxAddInputTlv> = TlvStream.empty()
) : InteractiveTxConstructionMessage(), HasChannelId, HasSerialId {
    constructor(channelId: ByteVector32, serialId: Long, sharedInput: OutPoint, sequence: UInt) : this(
        channelId,
        serialId,
        null,
        sharedInput.index,
        sequence,
        TlvStream(TxAddInputTlv.SharedInputTxId(sharedInput.txid))
    )

    override val type: Long get() = TxAddInput.type
    val sharedInput: OutPoint? = tlvs.get<TxAddInputTlv.SharedInputTxId>()?.let { OutPoint(it.txId, previousTxOutput) }
    val swapInParamsLegacy = tlvs.get<TxAddInputTlv.SwapInParamsLegacy>()
    val swapInParams = tlvs.get<TxAddInputTlv.SwapInParams>()

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId.toByteArray(), out)
        LightningCodecs.writeU64(serialId, out)
        when (previousTx) {
            null -> LightningCodecs.writeU16(0, out)
            else -> {
                val encodedTx = Transaction.write(previousTx)
                LightningCodecs.writeU16(encodedTx.size, out)
                LightningCodecs.writeBytes(encodedTx, out)
            }
        }
        LightningCodecs.writeU32(previousTxOutput.toInt(), out)
        LightningCodecs.writeU32(sequence.toInt(), out)
        TlvStreamSerializer(false, readers).write(tlvs, out)
    }

    companion object : LightningMessageReader<TxAddInput> {
        const val type: Long = 66

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            TxAddInputTlv.SharedInputTxId.tag to TxAddInputTlv.SharedInputTxId.Companion as TlvValueReader<TxAddInputTlv>,
            TxAddInputTlv.SwapInParamsLegacy.tag to TxAddInputTlv.SwapInParamsLegacy.Companion as TlvValueReader<TxAddInputTlv>,
            TxAddInputTlv.SwapInParams.tag to TxAddInputTlv.SwapInParams.Companion as TlvValueReader<TxAddInputTlv>,
        )

        override fun read(input: Input): TxAddInput = TxAddInput(
            LightningCodecs.bytes(input, 32).byteVector32(),
            LightningCodecs.u64(input),
            when (val txSize = LightningCodecs.u16(input)) {
                0 -> null
                else -> Transaction.read(LightningCodecs.bytes(input, txSize))
            },
            LightningCodecs.u32(input).toLong(),
            LightningCodecs.u32(input).toUInt(),
            TlvStreamSerializer(false, readers).read(input)
        )
    }
}

data class TxAddOutput(
    override val channelId: ByteVector32,
    override val serialId: Long,
    val amount: Satoshi,
    val pubkeyScript: ByteVector,
    val tlvs: TlvStream<TxAddOutputTlv> = TlvStream.empty()
) : InteractiveTxConstructionMessage(), HasChannelId, HasSerialId {
    override val type: Long get() = TxAddOutput.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId.toByteArray(), out)
        LightningCodecs.writeU64(serialId, out)
        LightningCodecs.writeU64(amount.toLong(), out)
        LightningCodecs.writeU16(pubkeyScript.size(), out)
        LightningCodecs.writeBytes(pubkeyScript, out)
    }

    companion object : LightningMessageReader<TxAddOutput> {
        const val type: Long = 67

        override fun read(input: Input): TxAddOutput = TxAddOutput(
            LightningCodecs.bytes(input, 32).byteVector32(),
            LightningCodecs.u64(input),
            LightningCodecs.u64(input).sat,
            LightningCodecs.bytes(input, LightningCodecs.u16(input)).byteVector(),
        )
    }
}

data class TxRemoveInput(
    override val channelId: ByteVector32,
    override val serialId: Long,
    val tlvs: TlvStream<TxRemoveInputTlv> = TlvStream.empty()
) : InteractiveTxConstructionMessage(), HasChannelId, HasSerialId {
    override val type: Long get() = TxRemoveInput.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId.toByteArray(), out)
        LightningCodecs.writeU64(serialId, out)
    }

    companion object : LightningMessageReader<TxRemoveInput> {
        const val type: Long = 68

        override fun read(input: Input): TxRemoveInput = TxRemoveInput(
            LightningCodecs.bytes(input, 32).byteVector32(),
            LightningCodecs.u64(input),
        )
    }
}

data class TxRemoveOutput(
    override val channelId: ByteVector32,
    override val serialId: Long,
    val tlvs: TlvStream<TxRemoveOutputTlv> = TlvStream.empty()
) : InteractiveTxConstructionMessage(), HasChannelId, HasSerialId {
    override val type: Long get() = TxRemoveOutput.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId.toByteArray(), out)
        LightningCodecs.writeU64(serialId, out)
    }

    companion object : LightningMessageReader<TxRemoveOutput> {
        const val type: Long = 69

        override fun read(input: Input): TxRemoveOutput = TxRemoveOutput(
            LightningCodecs.bytes(input, 32).byteVector32(),
            LightningCodecs.u64(input),
        )
    }
}

data class TxComplete(
    override val channelId: ByteVector32,
    val tlvs: TlvStream<TxCompleteTlv> = TlvStream.empty()
) : InteractiveTxConstructionMessage(), HasChannelId {
    override val type: Long get() = TxComplete.type

    val publicNonces: List<IndividualNonce> = tlvs.get<TxCompleteTlv.Nonces>()?.nonces ?: listOf()

    constructor(channelId: ByteVector32, publicNonces: List<IndividualNonce>) : this(channelId, TlvStream(TxCompleteTlv.Nonces(publicNonces)))

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId.toByteArray(), out)
        TlvStreamSerializer(false, readers).write(tlvs, out)
    }

    companion object : LightningMessageReader<TxComplete> {
        const val type: Long = 70

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(TxCompleteTlv.Nonces.tag to TxCompleteTlv.Nonces.Companion as TlvValueReader<TxCompleteTlv>)

        override fun read(input: Input): TxComplete = TxComplete(LightningCodecs.bytes(input, 32).byteVector32(), TlvStreamSerializer(false, readers).read(input))
    }
}

data class TxSignatures(
    override val channelId: ByteVector32,
    val txId: TxId,
    val witnesses: List<ScriptWitness>,
    val tlvs: TlvStream<TxSignaturesTlv> = TlvStream.empty()
) : InteractiveTxMessage(), HasChannelId, HasEncryptedChannelData {
    constructor(
        channelId: ByteVector32,
        tx: Transaction,
        witnesses: List<ScriptWitness>,
        previousFundingSig: ByteVector64?,
        swapInUserSigs: List<ByteVector64>,
        swapInServerSigs: List<ByteVector64>,
        swapInUserPartialSigs: List<TxSignaturesTlv.PartialSignature>,
        swapInServerPartialSigs: List<TxSignaturesTlv.PartialSignature>
    ) : this(
        channelId,
        tx.txid,
        witnesses,
        TlvStream(
            setOfNotNull(
                previousFundingSig?.let { TxSignaturesTlv.PreviousFundingTxSig(it) },
                if (swapInUserSigs.isNotEmpty()) TxSignaturesTlv.SwapInUserSigs(swapInUserSigs) else null,
                if (swapInServerSigs.isNotEmpty()) TxSignaturesTlv.SwapInServerSigs(swapInServerSigs) else null,
                if (swapInUserPartialSigs.isNotEmpty()) TxSignaturesTlv.SwapInUserPartialSigs(swapInUserPartialSigs) else null,
                if (swapInServerPartialSigs.isNotEmpty()) TxSignaturesTlv.SwapInServerPartialSigs(swapInServerPartialSigs) else null,
            )
        ),
    )

    override val type: Long get() = TxSignatures.type

    val previousFundingTxSig: ByteVector64? = tlvs.get<TxSignaturesTlv.PreviousFundingTxSig>()?.sig
    val swapInUserSigs: List<ByteVector64> = tlvs.get<TxSignaturesTlv.SwapInUserSigs>()?.sigs ?: listOf()
    val swapInServerSigs: List<ByteVector64> = tlvs.get<TxSignaturesTlv.SwapInServerSigs>()?.sigs ?: listOf()
    val swapInUserPartialSigs: List<TxSignaturesTlv.PartialSignature> = tlvs.get<TxSignaturesTlv.SwapInUserPartialSigs>()?.psigs ?: listOf()
    val swapInServerPartialSigs: List<TxSignaturesTlv.PartialSignature> = tlvs.get<TxSignaturesTlv.SwapInServerPartialSigs>()?.psigs ?: listOf()

    override val channelData: EncryptedChannelData get() = tlvs.get<TxSignaturesTlv.ChannelData>()?.ecb ?: EncryptedChannelData.empty
    override fun withNonEmptyChannelData(ecd: EncryptedChannelData): TxSignatures = copy(tlvs = tlvs.addOrUpdate(TxSignaturesTlv.ChannelData(ecd)))

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId.toByteArray(), out)
        // Note that we encode the tx_hash instead of the tx_id to be consistent with other lightning messages.
        LightningCodecs.writeTxHash(TxHash(txId), out)
        LightningCodecs.writeU16(witnesses.size, out)
        witnesses.forEach { witness ->
            val witnessData = ScriptWitness.write(witness)
            LightningCodecs.writeU16(witnessData.size, out)
            LightningCodecs.writeBytes(witnessData, out)
        }
        TlvStreamSerializer(false, readers).write(tlvs, out)
    }

    companion object : LightningMessageReader<TxSignatures> {
        const val type: Long = 71

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            TxSignaturesTlv.PreviousFundingTxSig.tag to TxSignaturesTlv.PreviousFundingTxSig.Companion as TlvValueReader<TxSignaturesTlv>,
            TxSignaturesTlv.SwapInUserSigs.tag to TxSignaturesTlv.SwapInUserSigs.Companion as TlvValueReader<TxSignaturesTlv>,
            TxSignaturesTlv.SwapInServerSigs.tag to TxSignaturesTlv.SwapInServerSigs.Companion as TlvValueReader<TxSignaturesTlv>,
            TxSignaturesTlv.SwapInUserPartialSigs.tag to TxSignaturesTlv.SwapInUserPartialSigs.Companion as TlvValueReader<TxSignaturesTlv>,
            TxSignaturesTlv.SwapInServerPartialSigs.tag to TxSignaturesTlv.SwapInServerPartialSigs.Companion as TlvValueReader<TxSignaturesTlv>,
            TxSignaturesTlv.ChannelData.tag to TxSignaturesTlv.ChannelData.Companion as TlvValueReader<TxSignaturesTlv>,
        )

        override fun read(input: Input): TxSignatures {
            val channelId = LightningCodecs.bytes(input, 32).byteVector32()
            val txHash = LightningCodecs.txHash(input)
            val witnessCount = LightningCodecs.u16(input)
            val witnesses = (1..witnessCount).map {
                val witnessSize = LightningCodecs.u16(input)
                ScriptWitness.read(LightningCodecs.bytes(input, witnessSize))
            }
            return TxSignatures(channelId, TxId(txHash), witnesses, TlvStreamSerializer(false, readers).read(input))
        }
    }
}

data class TxInitRbf(
    override val channelId: ByteVector32,
    val lockTime: Long,
    val feerate: FeeratePerKw,
    val tlvs: TlvStream<TxInitRbfTlv> = TlvStream.empty()
) : InteractiveTxMessage(), HasChannelId {
    constructor(channelId: ByteVector32, lockTime: Long, feerate: FeeratePerKw, fundingContribution: Satoshi) : this(channelId, lockTime, feerate, TlvStream(TxInitRbfTlv.SharedOutputContributionTlv(fundingContribution)))

    val fundingContribution = tlvs.get<TxInitRbfTlv.SharedOutputContributionTlv>()?.amount ?: 0.sat
    val requireConfirmedInputs: Boolean = tlvs.get<TxInitRbfTlv.RequireConfirmedInputsTlv>()?.let { true } ?: false

    override val type: Long get() = TxInitRbf.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId.toByteArray(), out)
        LightningCodecs.writeU32(lockTime.toInt(), out)
        LightningCodecs.writeU32(feerate.toLong().toInt(), out)
        TlvStreamSerializer(false, readers).write(tlvs, out)
    }

    companion object : LightningMessageReader<TxInitRbf> {
        const val type: Long = 72

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            TxInitRbfTlv.SharedOutputContributionTlv.tag to TxInitRbfTlv.SharedOutputContributionTlv.Companion as TlvValueReader<TxInitRbfTlv>,
            TxInitRbfTlv.RequireConfirmedInputsTlv.tag to TxInitRbfTlv.RequireConfirmedInputsTlv as TlvValueReader<TxInitRbfTlv>,
        )

        override fun read(input: Input): TxInitRbf = TxInitRbf(
            LightningCodecs.bytes(input, 32).byteVector32(),
            LightningCodecs.u32(input).toLong(),
            FeeratePerKw(LightningCodecs.u32(input).toLong().sat),
            TlvStreamSerializer(false, readers).read(input),
        )
    }
}

data class TxAckRbf(
    override val channelId: ByteVector32,
    val tlvs: TlvStream<TxAckRbfTlv> = TlvStream.empty()
) : InteractiveTxMessage(), HasChannelId {
    constructor(channelId: ByteVector32, fundingContribution: Satoshi) : this(channelId, TlvStream(TxAckRbfTlv.SharedOutputContributionTlv(fundingContribution)))

    val fundingContribution = tlvs.get<TxAckRbfTlv.SharedOutputContributionTlv>()?.amount ?: 0.sat
    val requireConfirmedInputs: Boolean = tlvs.get<TxAckRbfTlv.RequireConfirmedInputsTlv>()?.let { true } ?: false

    override val type: Long get() = TxAckRbf.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId.toByteArray(), out)
        TlvStreamSerializer(false, readers).write(tlvs, out)
    }

    companion object : LightningMessageReader<TxAckRbf> {
        const val type: Long = 73

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            TxAckRbfTlv.SharedOutputContributionTlv.tag to TxAckRbfTlv.SharedOutputContributionTlv.Companion as TlvValueReader<TxAckRbfTlv>,
            TxAckRbfTlv.RequireConfirmedInputsTlv.tag to TxAckRbfTlv.RequireConfirmedInputsTlv as TlvValueReader<TxAckRbfTlv>,
        )

        override fun read(input: Input): TxAckRbf = TxAckRbf(
            LightningCodecs.bytes(input, 32).byteVector32(),
            TlvStreamSerializer(false, readers).read(input),
        )
    }
}

data class TxAbort(
    override val channelId: ByteVector32,
    val data: ByteVector,
    val tlvs: TlvStream<TxAbortTlv> = TlvStream.empty()
) : InteractiveTxMessage(), HasChannelId {
    constructor(channelId: ByteVector32, message: String?) : this(channelId, ByteVector(message?.encodeToByteArray() ?: ByteArray(0)))

    fun toAscii(): String = data.toByteArray().decodeToString()

    override val type: Long get() = TxAbort.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU16(data.size(), out)
        LightningCodecs.writeBytes(data, out)
    }

    companion object : LightningMessageReader<TxAbort> {
        const val type: Long = 74

        override fun read(input: Input): TxAbort = TxAbort(
            LightningCodecs.bytes(input, 32).byteVector32(),
            LightningCodecs.bytes(input, LightningCodecs.u16(input)).byteVector(),
        )
    }
}

data class OpenDualFundedChannel(
    override val chainHash: BlockHash,
    override val temporaryChannelId: ByteVector32,
    val fundingFeerate: FeeratePerKw,
    val commitmentFeerate: FeeratePerKw,
    val fundingAmount: Satoshi,
    val dustLimit: Satoshi,
    val maxHtlcValueInFlightMsat: Long, // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
    val htlcMinimum: MilliSatoshi,
    val toSelfDelay: CltvExpiryDelta,
    val maxAcceptedHtlcs: Int,
    val lockTime: Long,
    val fundingPubkey: PublicKey,
    val revocationBasepoint: PublicKey,
    val paymentBasepoint: PublicKey,
    val delayedPaymentBasepoint: PublicKey,
    val htlcBasepoint: PublicKey,
    val firstPerCommitmentPoint: PublicKey,
    val secondPerCommitmentPoint: PublicKey,
    val channelFlags: ChannelFlags,
    val tlvStream: TlvStream<ChannelTlv> = TlvStream.empty()
) : ChannelMessage, HasTemporaryChannelId, HasChainHash {
    val channelType: ChannelType? get() = tlvStream.get<ChannelTlv.ChannelTypeTlv>()?.channelType
    val requestFunding: LiquidityAds.RequestFunding? get() = tlvStream.get<ChannelTlv.RequestFundingTlv>()?.request

    override val type: Long get() = OpenDualFundedChannel.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash.value, out)
        LightningCodecs.writeBytes(temporaryChannelId, out)
        LightningCodecs.writeU32(fundingFeerate.toLong().toInt(), out)
        LightningCodecs.writeU32(commitmentFeerate.toLong().toInt(), out)
        LightningCodecs.writeU64(fundingAmount.toLong(), out)
        LightningCodecs.writeU64(dustLimit.toLong(), out)
        LightningCodecs.writeU64(maxHtlcValueInFlightMsat, out)
        LightningCodecs.writeU64(htlcMinimum.toLong(), out)
        LightningCodecs.writeU16(toSelfDelay.toInt(), out)
        LightningCodecs.writeU16(maxAcceptedHtlcs, out)
        LightningCodecs.writeU32(lockTime.toInt(), out)
        LightningCodecs.writeBytes(fundingPubkey.value, out)
        LightningCodecs.writeBytes(revocationBasepoint.value, out)
        LightningCodecs.writeBytes(paymentBasepoint.value, out)
        LightningCodecs.writeBytes(delayedPaymentBasepoint.value, out)
        LightningCodecs.writeBytes(htlcBasepoint.value, out)
        LightningCodecs.writeBytes(firstPerCommitmentPoint.value, out)
        LightningCodecs.writeBytes(secondPerCommitmentPoint.value, out)
        val announceChannelFlag = if (channelFlags.announceChannel) 1 else 0
        val commitFeesFlag = if (channelFlags.nonInitiatorPaysCommitFees) 2 else 0
        LightningCodecs.writeByte(announceChannelFlag + commitFeesFlag, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<OpenDualFundedChannel> {
        const val type: Long = 64

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            ChannelTlv.UpfrontShutdownScriptTlv.tag to ChannelTlv.UpfrontShutdownScriptTlv.Companion as TlvValueReader<ChannelTlv>,
            ChannelTlv.ChannelTypeTlv.tag to ChannelTlv.ChannelTypeTlv.Companion as TlvValueReader<ChannelTlv>,
            ChannelTlv.RequireConfirmedInputsTlv.tag to ChannelTlv.RequireConfirmedInputsTlv as TlvValueReader<ChannelTlv>,
            ChannelTlv.RequestFundingTlv.tag to ChannelTlv.RequestFundingTlv as TlvValueReader<ChannelTlv>,
        )

        override fun read(input: Input): OpenDualFundedChannel {
            val chainHash = BlockHash(LightningCodecs.bytes(input, 32))
            val temporaryChannelId = ByteVector32(LightningCodecs.bytes(input, 32))
            val fundingFeerate = FeeratePerKw(LightningCodecs.u32(input).toLong().sat)
            val commitmentFeerate = FeeratePerKw(LightningCodecs.u32(input).toLong().sat)
            val fundingAmount = Satoshi(LightningCodecs.u64(input))
            val dustLimit = Satoshi(LightningCodecs.u64(input))
            val maxHtlcValueInFlightMsat = LightningCodecs.u64(input) // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
            val htlcMinimum = MilliSatoshi(LightningCodecs.u64(input))
            val toSelfDelay = CltvExpiryDelta(LightningCodecs.u16(input))
            val maxAcceptedHtlcs = LightningCodecs.u16(input)
            val lockTime = LightningCodecs.u32(input).toLong()
            val fundingPubkey = PublicKey(LightningCodecs.bytes(input, 33))
            val revocationBasepoint = PublicKey(LightningCodecs.bytes(input, 33))
            val paymentBasepoint = PublicKey(LightningCodecs.bytes(input, 33))
            val delayedPaymentBasepoint = PublicKey(LightningCodecs.bytes(input, 33))
            val htlcBasepoint = PublicKey(LightningCodecs.bytes(input, 33))
            val firstPerCommitmentPoint = PublicKey(LightningCodecs.bytes(input, 33))
            val secondPerCommitmentPoint = PublicKey(LightningCodecs.bytes(input, 33))
            val encodedChannelFlags = LightningCodecs.byte(input).toByte()
            val channelFlags = ChannelFlags(announceChannel = encodedChannelFlags.toInt().and(1) != 0, nonInitiatorPaysCommitFees = encodedChannelFlags.toInt().and(2) != 0)
            val tlvs = TlvStreamSerializer(false, readers).read(input)
            return OpenDualFundedChannel(
                chainHash = chainHash,
                temporaryChannelId = temporaryChannelId,
                fundingFeerate = fundingFeerate,
                commitmentFeerate = commitmentFeerate,
                fundingAmount = fundingAmount,
                dustLimit = dustLimit,
                maxHtlcValueInFlightMsat = maxHtlcValueInFlightMsat,
                htlcMinimum = htlcMinimum,
                toSelfDelay = toSelfDelay,
                maxAcceptedHtlcs = maxAcceptedHtlcs,
                lockTime = lockTime,
                fundingPubkey = fundingPubkey,
                revocationBasepoint = revocationBasepoint,
                paymentBasepoint = paymentBasepoint,
                delayedPaymentBasepoint = delayedPaymentBasepoint,
                htlcBasepoint = htlcBasepoint,
                firstPerCommitmentPoint = firstPerCommitmentPoint,
                secondPerCommitmentPoint = secondPerCommitmentPoint,
                channelFlags = channelFlags,
                tlvStream = tlvs
            )
        }
    }
}

data class AcceptDualFundedChannel(
    override val temporaryChannelId: ByteVector32,
    val fundingAmount: Satoshi,
    val dustLimit: Satoshi,
    val maxHtlcValueInFlightMsat: Long, // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
    val htlcMinimum: MilliSatoshi,
    val minimumDepth: Long,
    val toSelfDelay: CltvExpiryDelta,
    val maxAcceptedHtlcs: Int,
    val fundingPubkey: PublicKey,
    val revocationBasepoint: PublicKey,
    val paymentBasepoint: PublicKey,
    val delayedPaymentBasepoint: PublicKey,
    val htlcBasepoint: PublicKey,
    val firstPerCommitmentPoint: PublicKey,
    val secondPerCommitmentPoint: PublicKey,
    val tlvStream: TlvStream<ChannelTlv> = TlvStream.empty()
) : ChannelMessage, HasTemporaryChannelId {
    val channelType: ChannelType? get() = tlvStream.get<ChannelTlv.ChannelTypeTlv>()?.channelType
    val willFund: LiquidityAds.WillFund? get() = tlvStream.get<ChannelTlv.ProvideFundingTlv>()?.willFund
    val feeCreditUsed: MilliSatoshi = tlvStream.get<ChannelTlv.FeeCreditUsedTlv>()?.amount ?: 0.msat

    override val type: Long get() = AcceptDualFundedChannel.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(temporaryChannelId, out)
        LightningCodecs.writeU64(fundingAmount.toLong(), out)
        LightningCodecs.writeU64(dustLimit.toLong(), out)
        LightningCodecs.writeU64(maxHtlcValueInFlightMsat, out)
        LightningCodecs.writeU64(htlcMinimum.toLong(), out)
        LightningCodecs.writeU32(minimumDepth.toInt(), out)
        LightningCodecs.writeU16(toSelfDelay.toInt(), out)
        LightningCodecs.writeU16(maxAcceptedHtlcs, out)
        LightningCodecs.writeBytes(fundingPubkey.value, out)
        LightningCodecs.writeBytes(revocationBasepoint.value, out)
        LightningCodecs.writeBytes(paymentBasepoint.value, out)
        LightningCodecs.writeBytes(delayedPaymentBasepoint.value, out)
        LightningCodecs.writeBytes(htlcBasepoint.value, out)
        LightningCodecs.writeBytes(firstPerCommitmentPoint.value, out)
        LightningCodecs.writeBytes(secondPerCommitmentPoint.value, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<AcceptDualFundedChannel> {
        const val type: Long = 65

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(
            ChannelTlv.UpfrontShutdownScriptTlv.tag to ChannelTlv.UpfrontShutdownScriptTlv.Companion as TlvValueReader<ChannelTlv>,
            ChannelTlv.ChannelTypeTlv.tag to ChannelTlv.ChannelTypeTlv.Companion as TlvValueReader<ChannelTlv>,
            ChannelTlv.RequireConfirmedInputsTlv.tag to ChannelTlv.RequireConfirmedInputsTlv as TlvValueReader<ChannelTlv>,
            ChannelTlv.ProvideFundingTlv.tag to ChannelTlv.ProvideFundingTlv as TlvValueReader<ChannelTlv>,
            ChannelTlv.FeeCreditUsedTlv.tag to ChannelTlv.FeeCreditUsedTlv as TlvValueReader<ChannelTlv>,
        )

        override fun read(input: Input): AcceptDualFundedChannel = AcceptDualFundedChannel(
            ByteVector32(LightningCodecs.bytes(input, 32)),
            Satoshi(LightningCodecs.u64(input)),
            Satoshi(LightningCodecs.u64(input)),
            LightningCodecs.u64(input), // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi,
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
            PublicKey(LightningCodecs.bytes(input, 33)),
            TlvStreamSerializer(false, readers).read(input)
        )
    }
}

data class FundingCreated(
    override val temporaryChannelId: ByteVector32,
    val fundingTxHash: ByteVector32,
    val fundingOutputIndex: Int,
    val signature: ByteVector64
) : ChannelMessage, HasTemporaryChannelId {
    override val type: Long get() = FundingCreated.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(temporaryChannelId, out)
        LightningCodecs.writeBytes(fundingTxHash, out)
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

data class FundingSigned(
    override val channelId: ByteVector32,
    val signature: ByteVector64,
) : ChannelMessage, HasChannelId {
    override val type: Long get() = FundingSigned.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeBytes(signature, out)
    }

    companion object : LightningMessageReader<FundingSigned> {
        const val type: Long = 35

        override fun read(input: Input): FundingSigned {
            return FundingSigned(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                ByteVector64(LightningCodecs.bytes(input, 64)),
            )
        }
    }
}

data class ChannelReady(
    override val channelId: ByteVector32,
    val nextPerCommitmentPoint: PublicKey,
    val tlvStream: TlvStream<ChannelReadyTlv> = TlvStream.empty()
) : ChannelMessage, HasChannelId {
    override val type: Long get() = ChannelReady.type
    val alias: ShortChannelId? = tlvStream.get<ChannelReadyTlv.ShortChannelIdTlv>()?.alias

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeBytes(nextPerCommitmentPoint.value, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<ChannelReady> {
        const val type: Long = 36

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(ChannelReadyTlv.ShortChannelIdTlv.tag to ChannelReadyTlv.ShortChannelIdTlv.Companion as TlvValueReader<ChannelReadyTlv>)

        override fun read(input: Input) = ChannelReady(
            ByteVector32(LightningCodecs.bytes(input, 32)),
            PublicKey(LightningCodecs.bytes(input, 33)),
            TlvStreamSerializer(false, readers).read(input)
        )
    }
}

data class Stfu(
    override val channelId: ByteVector32,
    val initiator: Boolean
) : SetupMessage, HasChannelId {
    override val type: Long get() = Stfu.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeByte(if (initiator) 1 else 0, out)
    }

    companion object : LightningMessageReader<Stfu> {
        const val type: Long = 2

        override fun read(input: Input): Stfu {
            return Stfu(
                ByteVector32(LightningCodecs.bytes(input, 32)),
                LightningCodecs.byte(input) == 1
            )
        }
    }
}

data class SpliceInit(
    override val channelId: ByteVector32,
    val fundingContribution: Satoshi,
    val feerate: FeeratePerKw,
    val lockTime: Long,
    val fundingPubkey: PublicKey,
    val tlvStream: TlvStream<ChannelTlv> = TlvStream.empty()
) : ChannelMessage, HasChannelId {
    override val type: Long get() = SpliceInit.type
    val requireConfirmedInputs: Boolean = tlvStream.get<ChannelTlv.RequireConfirmedInputsTlv>()?.let { true } ?: false
    val requestFunding: LiquidityAds.RequestFunding? = tlvStream.get<ChannelTlv.RequestFundingTlv>()?.request

    constructor(channelId: ByteVector32, fundingContribution: Satoshi, feerate: FeeratePerKw, lockTime: Long, fundingPubkey: PublicKey, requestFunding: LiquidityAds.RequestFunding?) : this(
        channelId,
        fundingContribution,
        feerate,
        lockTime,
        fundingPubkey,
        TlvStream(
            setOfNotNull(
                requestFunding?.let { ChannelTlv.RequestFundingTlv(it) },
            )
        )
    )

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeInt64(fundingContribution.toLong(), out)
        LightningCodecs.writeU32(feerate.toLong().toInt(), out)
        LightningCodecs.writeU32(lockTime.toInt(), out)
        LightningCodecs.writeBytes(fundingPubkey.value, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<SpliceInit> {
        const val type: Long = 37000

        @Suppress("UNCHECKED_CAST")
        private val readers = mapOf(
            ChannelTlv.RequireConfirmedInputsTlv.tag to ChannelTlv.RequireConfirmedInputsTlv as TlvValueReader<ChannelTlv>,
            ChannelTlv.RequestFundingTlv.tag to ChannelTlv.RequestFundingTlv as TlvValueReader<ChannelTlv>,
        )

        override fun read(input: Input): SpliceInit = SpliceInit(
            channelId = ByteVector32(LightningCodecs.bytes(input, 32)),
            fundingContribution = Satoshi(LightningCodecs.int64(input)),
            feerate = FeeratePerKw(LightningCodecs.u32(input).toLong().sat),
            lockTime = LightningCodecs.u32(input).toLong(),
            fundingPubkey = PublicKey(LightningCodecs.bytes(input, 33)),
            tlvStream = TlvStreamSerializer(false, readers).read(input)
        )
    }
}

data class SpliceAck(
    override val channelId: ByteVector32,
    val fundingContribution: Satoshi,
    val fundingPubkey: PublicKey,
    val tlvStream: TlvStream<ChannelTlv> = TlvStream.empty()
) : ChannelMessage, HasChannelId {
    override val type: Long get() = SpliceAck.type
    val requireConfirmedInputs: Boolean = tlvStream.get<ChannelTlv.RequireConfirmedInputsTlv>()?.let { true } ?: false
    val willFund: LiquidityAds.WillFund? = tlvStream.get<ChannelTlv.ProvideFundingTlv>()?.willFund
    val feeCreditUsed: MilliSatoshi = tlvStream.get<ChannelTlv.FeeCreditUsedTlv>()?.amount ?: 0.msat

    constructor(channelId: ByteVector32, fundingContribution: Satoshi, fundingPubkey: PublicKey, willFund: LiquidityAds.WillFund?) : this(
        channelId,
        fundingContribution,
        fundingPubkey,
        TlvStream(
            setOfNotNull(
                willFund?.let { ChannelTlv.ProvideFundingTlv(it) }
            ))
    )

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeInt64(fundingContribution.toLong(), out)
        LightningCodecs.writeBytes(fundingPubkey.value, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<SpliceAck> {
        const val type: Long = 37002

        @Suppress("UNCHECKED_CAST")
        private val readers = mapOf(
            ChannelTlv.RequireConfirmedInputsTlv.tag to ChannelTlv.RequireConfirmedInputsTlv as TlvValueReader<ChannelTlv>,
            ChannelTlv.ProvideFundingTlv.tag to ChannelTlv.ProvideFundingTlv as TlvValueReader<ChannelTlv>,
            ChannelTlv.FeeCreditUsedTlv.tag to ChannelTlv.FeeCreditUsedTlv.Companion as TlvValueReader<ChannelTlv>,
        )

        override fun read(input: Input): SpliceAck = SpliceAck(
            channelId = ByteVector32(LightningCodecs.bytes(input, 32)),
            fundingContribution = Satoshi(LightningCodecs.int64(input)),
            fundingPubkey = PublicKey(LightningCodecs.bytes(input, 33)),
            tlvStream = TlvStreamSerializer(false, readers).read(input)
        )
    }
}

data class SpliceLocked(
    override val channelId: ByteVector32,
    val fundingTxId: TxId,
    val tlvStream: TlvStream<ChannelTlv> = TlvStream.empty()
) : ChannelMessage, HasChannelId {
    override val type: Long get() = SpliceLocked.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeTxHash(TxHash(fundingTxId), out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<SpliceLocked> {
        const val type: Long = 37004

        private val readers = emptyMap<Long, TlvValueReader<ChannelTlv>>()

        override fun read(input: Input): SpliceLocked = SpliceLocked(
            channelId = ByteVector32(LightningCodecs.bytes(input, 32)),
            fundingTxId = TxId(LightningCodecs.txHash(input)),
            tlvStream = TlvStreamSerializer(false, readers).read(input)
        )
    }
}

data class UpdateAddHtlc(
    override val channelId: ByteVector32,
    val id: Long,
    val amountMsat: MilliSatoshi,
    val paymentHash: ByteVector32,
    val cltvExpiry: CltvExpiry,
    val onionRoutingPacket: OnionRoutingPacket,
    val tlvStream: TlvStream<UpdateAddHtlcTlv> = TlvStream.empty()
) : HtlcMessage, UpdateMessage, HasChannelId, ForbiddenMessageDuringSplice {
    override val type: Long get() = UpdateAddHtlc.type

    val pathKey: PublicKey? = tlvStream.get<UpdateAddHtlcTlv.PathKey>()?.publicKey
    val fundingFee: LiquidityAds.FundingFee? = tlvStream.get<UpdateAddHtlcTlv.FundingFeeTlv>()?.fee
    val usesOnTheFlyFunding: Boolean = fundingFee != null

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU64(id, out)
        LightningCodecs.writeU64(amountMsat.toLong(), out)
        LightningCodecs.writeBytes(paymentHash, out)
        LightningCodecs.writeU32(cltvExpiry.toLong().toInt(), out)
        OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).write(onionRoutingPacket, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<UpdateAddHtlc> {
        const val type: Long = 128

        @Suppress("UNCHECKED_CAST")
        private val readers = mapOf(
            UpdateAddHtlcTlv.PathKey.tag to UpdateAddHtlcTlv.PathKey as TlvValueReader<UpdateAddHtlcTlv>,
            UpdateAddHtlcTlv.FundingFeeTlv.tag to UpdateAddHtlcTlv.FundingFeeTlv as TlvValueReader<UpdateAddHtlcTlv>,
        )

        override fun read(input: Input): UpdateAddHtlc {
            val channelId = ByteVector32(LightningCodecs.bytes(input, 32))
            val id = LightningCodecs.u64(input)
            val amount = MilliSatoshi(LightningCodecs.u64(input))
            val paymentHash = ByteVector32(LightningCodecs.bytes(input, 32))
            val expiry = CltvExpiry(LightningCodecs.u32(input).toLong())
            val onion = OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).read(input)
            val tlvStream = TlvStreamSerializer(false, readers).read(input)
            return UpdateAddHtlc(channelId, id, amount, paymentHash, expiry, onion, tlvStream)
        }

        operator fun invoke(
            channelId: ByteVector32,
            id: Long,
            amountMsat: MilliSatoshi,
            paymentHash: ByteVector32,
            cltvExpiry: CltvExpiry,
            onionRoutingPacket: OnionRoutingPacket,
            pathKey: PublicKey?,
            fundingFee: LiquidityAds.FundingFee?
        ): UpdateAddHtlc {
            val tlvs = setOfNotNull(
                pathKey?.let { UpdateAddHtlcTlv.PathKey(it) },
                fundingFee?.let { UpdateAddHtlcTlv.FundingFeeTlv(it) }
            )
            return UpdateAddHtlc(channelId, id, amountMsat, paymentHash, cltvExpiry, onionRoutingPacket, TlvStream(tlvs))
        }
    }
}

data class UpdateFulfillHtlc(
    override val channelId: ByteVector32,
    override val id: Long,
    val paymentPreimage: ByteVector32
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

data class UpdateFailHtlc(
    override val channelId: ByteVector32,
    override val id: Long,
    val reason: ByteVector
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

data class UpdateFailMalformedHtlc(
    override val channelId: ByteVector32,
    override val id: Long,
    val onionHash: ByteVector32,
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

data class CommitSig(
    override val channelId: ByteVector32,
    val signature: ByteVector64,
    val htlcSignatures: List<ByteVector64>,
    val tlvStream: TlvStream<CommitSigTlv> = TlvStream.empty()
) : HtlcMessage, HasChannelId, HasEncryptedChannelData {
    override val type: Long get() = CommitSig.type

    override val channelData: EncryptedChannelData get() = tlvStream.get<CommitSigTlv.ChannelData>()?.ecb ?: EncryptedChannelData.empty
    override fun withNonEmptyChannelData(ecd: EncryptedChannelData): CommitSig = copy(tlvStream = tlvStream.addOrUpdate(CommitSigTlv.ChannelData(ecd)))

    val alternativeFeerateSigs: List<CommitSigTlv.AlternativeFeerateSig> = tlvStream.get<CommitSigTlv.AlternativeFeerateSigs>()?.sigs ?: listOf()
    val batchSize: Int = tlvStream.get<CommitSigTlv.Batch>()?.size ?: 1

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
        val readers = mapOf(
            CommitSigTlv.ChannelData.tag to CommitSigTlv.ChannelData.Companion as TlvValueReader<CommitSigTlv>,
            CommitSigTlv.AlternativeFeerateSigs.tag to CommitSigTlv.AlternativeFeerateSigs.Companion as TlvValueReader<CommitSigTlv>,
            CommitSigTlv.Batch.tag to CommitSigTlv.Batch.Companion as TlvValueReader<CommitSigTlv>,
        )

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

data class UpdateFee(
    override val channelId: ByteVector32,
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

data class ChannelReestablish(
    override val channelId: ByteVector32,
    val nextLocalCommitmentNumber: Long,
    val nextRemoteRevocationNumber: Long,
    val yourLastCommitmentSecret: PrivateKey,
    val myCurrentPerCommitmentPoint: PublicKey,
    val tlvStream: TlvStream<ChannelReestablishTlv> = TlvStream.empty()
) : HasChannelId, HasEncryptedChannelData {
    override val type: Long get() = ChannelReestablish.type

    val nextFundingTxId: TxId? = tlvStream.get<ChannelReestablishTlv.NextFunding>()?.txId
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
        val readers = mapOf(
            ChannelReestablishTlv.ChannelData.tag to ChannelReestablishTlv.ChannelData.Companion as TlvValueReader<ChannelReestablishTlv>,
            ChannelReestablishTlv.NextFunding.tag to ChannelReestablishTlv.NextFunding.Companion as TlvValueReader<ChannelReestablishTlv>,
        )

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

data class ChannelAnnouncement(
    val nodeSignature1: ByteVector64,
    val nodeSignature2: ByteVector64,
    val bitcoinSignature1: ByteVector64,
    val bitcoinSignature2: ByteVector64,
    val features: Features,
    override val chainHash: BlockHash,
    val shortChannelId: ShortChannelId,
    val nodeId1: PublicKey,
    val nodeId2: PublicKey,
    val bitcoinKey1: PublicKey,
    val bitcoinKey2: PublicKey,
    val unknownFields: ByteVector = ByteVector.empty
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
        LightningCodecs.writeBytes(chainHash.value, out)
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
            val chainHash = BlockHash(LightningCodecs.bytes(input, 32))
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

data class ChannelUpdate(
    val signature: ByteVector64,
    override val chainHash: BlockHash,
    val shortChannelId: ShortChannelId,
    override val timestampSeconds: Long,
    val messageFlags: Byte,
    val channelFlags: Byte,
    val cltvExpiryDelta: CltvExpiryDelta,
    val htlcMinimumMsat: MilliSatoshi,
    val feeBaseMsat: MilliSatoshi,
    val feeProportionalMillionths: Long,
    val htlcMaximumMsat: MilliSatoshi?,
    val unknownFields: ByteVector = ByteVector.empty
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
        LightningCodecs.writeBytes(chainHash.value, out)
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
            val chainHash = BlockHash(LightningCodecs.bytes(input, 32))
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

data class Shutdown(
    override val channelId: ByteVector32,
    val scriptPubKey: ByteVector,
    val tlvStream: TlvStream<ShutdownTlv> = TlvStream.empty()
) : ChannelMessage, HasChannelId, HasEncryptedChannelData, ForbiddenMessageDuringSplice {
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

data class ClosingSigned(
    override val channelId: ByteVector32,
    val feeSatoshis: Satoshi,
    val signature: ByteVector64,
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

data class OnionMessage(
    val pathKey: PublicKey,
    val onionRoutingPacket: OnionRoutingPacket
) : LightningMessage {
    override val type: Long get() = OnionMessage.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(pathKey.value, out)
        LightningCodecs.writeU16(onionRoutingPacket.payload.size() + 66, out)
        OnionRoutingPacketSerializer(onionRoutingPacket.payload.size()).write(onionRoutingPacket, out)
    }

    override fun toString(): String =
        "OnionMessage(pathKey=$pathKey, onionRoutingPacket=OnionRoutingPacket(version=${onionRoutingPacket.version}, publicKey=${onionRoutingPacket.publicKey.toHex()}, payload=<${onionRoutingPacket.payload.size()} bytes>, hmac=${onionRoutingPacket.hmac.toHex()}))"

    companion object : LightningMessageReader<OnionMessage> {
        const val type: Long = 513

        override fun read(input: Input): OnionMessage {
            val pathKey = PublicKey(LightningCodecs.bytes(input, 33))
            val onion = OnionRoutingPacketSerializer(LightningCodecs.u16(input) - 66).read(input)
            return OnionMessage(pathKey, onion)
        }
    }
}

/**
 * This message is sent when an HTLC couldn't be relayed to our node because we don't have enough inbound liquidity.
 * This allows us to treat it as an incoming payment, and request on-the-fly liquidity accordingly if we wish to receive that payment.
 * If we accept the payment, we will send an [OpenDualFundedChannel] or [SpliceInit] message containing [ChannelTlv.RequestFundingTlv].
 * Our peer will then provide the requested funding liquidity and will relay the corresponding HTLC(s) afterwards.
 */
data class WillAddHtlc(
    override val chainHash: BlockHash,
    val id: ByteVector32,
    val amount: MilliSatoshi,
    val paymentHash: ByteVector32,
    val expiry: CltvExpiry,
    val finalPacket: OnionRoutingPacket,
    val tlvStream: TlvStream<WillAddHtlcTlv> = TlvStream.empty()
) : OnTheFlyFundingMessage, HasChainHash {
    override val type: Long get() = WillAddHtlc.type

    val pathKey: PublicKey? = tlvStream.get<WillAddHtlcTlv.PathKey>()?.publicKey

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash.value, out)
        LightningCodecs.writeBytes(id, out)
        LightningCodecs.writeU64(amount.toLong(), out)
        LightningCodecs.writeBytes(paymentHash, out)
        LightningCodecs.writeU32(expiry.toLong().toInt(), out)
        OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).write(finalPacket, out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<WillAddHtlc> {
        const val type: Long = 41041

        @Suppress("UNCHECKED_CAST")
        private val readers = mapOf(
            WillAddHtlcTlv.PathKey.tag to WillAddHtlcTlv.PathKey as TlvValueReader<WillAddHtlcTlv>,
        )

        override fun read(input: Input): WillAddHtlc = WillAddHtlc(
            chainHash = BlockHash(LightningCodecs.bytes(input, 32)),
            id = LightningCodecs.bytes(input, 32).byteVector32(),
            amount = LightningCodecs.u64(input).msat,
            paymentHash = LightningCodecs.bytes(input, 32).byteVector32(),
            expiry = CltvExpiry(LightningCodecs.u32(input).toLong()),
            finalPacket = OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).read(input),
            tlvStream = TlvStreamSerializer(false, readers).read(input)
        )

        operator fun invoke(
            chainHash: BlockHash,
            id: ByteVector32,
            amount: MilliSatoshi,
            paymentHash: ByteVector32,
            cltvExpiry: CltvExpiry,
            onionRoutingPacket: OnionRoutingPacket,
            pathKey: PublicKey?
        ): WillAddHtlc {
            val tlvStream = TlvStream(setOfNotNull<WillAddHtlcTlv>(pathKey?.let { WillAddHtlcTlv.PathKey(it) }))
            return WillAddHtlc(chainHash, id, amount, paymentHash, cltvExpiry, onionRoutingPacket, tlvStream)
        }
    }
}

data class WillFailHtlc(val id: ByteVector32, val paymentHash: ByteVector32, val reason: ByteVector) : OnTheFlyFundingMessage {
    override val type: Long get() = WillFailHtlc.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(id, out)
        LightningCodecs.writeBytes(paymentHash, out)
        LightningCodecs.writeU16(reason.size(), out)
        LightningCodecs.writeBytes(reason, out)
    }

    companion object : LightningMessageReader<WillFailHtlc> {
        const val type: Long = 41042

        override fun read(input: Input): WillFailHtlc = WillFailHtlc(
            id = LightningCodecs.bytes(input, 32).byteVector32(),
            paymentHash = LightningCodecs.bytes(input, 32).byteVector32(),
            reason = LightningCodecs.bytes(input, LightningCodecs.u16(input)).byteVector()
        )
    }
}

data class WillFailMalformedHtlc(val id: ByteVector32, val paymentHash: ByteVector32, val onionHash: ByteVector32, val failureCode: Int) : OnTheFlyFundingMessage {
    override val type: Long get() = WillFailMalformedHtlc.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(id, out)
        LightningCodecs.writeBytes(paymentHash, out)
        LightningCodecs.writeBytes(onionHash, out)
        LightningCodecs.writeU16(failureCode, out)
    }

    companion object : LightningMessageReader<WillFailMalformedHtlc> {
        const val type: Long = 41043

        override fun read(input: Input): WillFailMalformedHtlc = WillFailMalformedHtlc(
            id = LightningCodecs.bytes(input, 32).byteVector32(),
            paymentHash = LightningCodecs.bytes(input, 32).byteVector32(),
            onionHash = LightningCodecs.bytes(input, 32).byteVector32(),
            failureCode = LightningCodecs.u16(input),
        )
    }
}

/**
 * This message is sent in response to an [OpenDualFundedChannel] or [SpliceInit] message containing an invalid [LiquidityAds.RequestFunds].
 * The receiver must consider the funding attempt failed when receiving this message.
 */
data class CancelOnTheFlyFunding(override val channelId: ByteVector32, val paymentHashes: List<ByteVector32>, val reason: ByteVector) : OnTheFlyFundingMessage, HasChannelId {
    constructor(channelId: ByteVector32, paymentHashes: List<ByteVector32>, message: String?) : this(channelId, paymentHashes, ByteVector(message?.encodeToByteArray() ?: ByteArray(0)))

    override val type: Long get() = CancelOnTheFlyFunding.type

    fun toAscii(): String = reason.toByteArray().decodeToString()

    override fun write(out: Output) {
        LightningCodecs.writeBytes(channelId, out)
        LightningCodecs.writeU16(paymentHashes.size, out)
        paymentHashes.forEach { LightningCodecs.writeBytes(it, out) }
        LightningCodecs.writeU16(reason.size(), out)
        LightningCodecs.writeBytes(reason, out)
    }

    companion object : LightningMessageReader<CancelOnTheFlyFunding> {
        const val type: Long = 41044

        override fun read(input: Input): CancelOnTheFlyFunding = CancelOnTheFlyFunding(
            channelId = LightningCodecs.bytes(input, 32).byteVector32(),
            paymentHashes = (0 until LightningCodecs.u16(input)).map { LightningCodecs.bytes(input, 32).byteVector32() },
            reason = LightningCodecs.bytes(input, LightningCodecs.u16(input)).byteVector()
        )
    }
}

/**
 * This message is used to reveal the preimage of a small payment for which it isn't economical to perform an on-chain
 * transaction. The amount of the payment will be added to our fee credit, which can be used when a future on-chain
 * transaction is needed. This message requires the [Feature.FundingFeeCredit] feature.
 */
data class AddFeeCredit(override val chainHash: BlockHash, val preimage: ByteVector32) : HasChainHash, OnTheFlyFundingMessage {
    override val type: Long = AddFeeCredit.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash.value, out)
        LightningCodecs.writeBytes(preimage, out)
    }

    companion object : LightningMessageReader<AddFeeCredit> {
        const val type: Long = 41045

        override fun read(input: Input): AddFeeCredit = AddFeeCredit(
            chainHash = BlockHash(LightningCodecs.bytes(input, 32)),
            preimage = LightningCodecs.bytes(input, 32).byteVector32()
        )
    }
}

/** This message contains our current fee credit: our peer is the source of truth for that value. */
data class CurrentFeeCredit(override val chainHash: BlockHash, val amount: MilliSatoshi) : HasChainHash, OnTheFlyFundingMessage {
    override val type: Long = CurrentFeeCredit.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash.value, out)
        LightningCodecs.writeU64(amount.toLong(), out)
    }

    companion object : LightningMessageReader<CurrentFeeCredit> {
        const val type: Long = 41046

        override fun read(input: Input): CurrentFeeCredit = CurrentFeeCredit(
            chainHash = BlockHash(LightningCodecs.bytes(input, 32)),
            amount = LightningCodecs.u64(input).msat,
        )
    }
}

data class FCMToken(val token: ByteVector) : LightningMessage {
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

object UnsetFCMToken : LightningMessage {
    override val type: Long get() = 35019
    override fun write(out: Output) {}
}

data class PhoenixAndroidLegacyInfo(
    val hasChannels: Boolean
) : LightningMessage {
    override val type: Long get() = PhoenixAndroidLegacyInfo.type

    override fun write(out: Output) {
        LightningCodecs.writeByte(if (hasChannels) 0xff else 0, out)
    }

    companion object : LightningMessageReader<PhoenixAndroidLegacyInfo> {
        const val type: Long = 35023

        override fun read(input: Input): PhoenixAndroidLegacyInfo {
            return PhoenixAndroidLegacyInfo(LightningCodecs.byte(input) != 0)
        }
    }
}

/**
 * A message to request a BIP-353's compliant DNS address from our peer. The peer may not respond, e.g. if there are no channels.
 *
 * @param languageSubtag IETF BCP 47 language tag (en, fr, de, es, ...) to indicate preference for the words that make up the address
 */
data class DNSAddressRequest(override val chainHash: BlockHash, val offer: OfferTypes.Offer, val languageSubtag: String) : LightningMessage, HasChainHash {

    override val type: Long get() = DNSAddressRequest.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash.value, out)
        val serializedOffer = OfferTypes.Offer.tlvSerializer.write(offer.records)
        LightningCodecs.writeU16(serializedOffer.size, out)
        LightningCodecs.writeBytes(serializedOffer, out)
        LightningCodecs.writeU16(languageSubtag.length, out)
        LightningCodecs.writeBytes(languageSubtag.toByteArray(charset = Charsets.UTF_8), out)
    }

    companion object : LightningMessageReader<DNSAddressRequest> {
        const val type: Long = 35025

        override fun read(input: Input): DNSAddressRequest {
            return DNSAddressRequest(
                chainHash = BlockHash(LightningCodecs.bytes(input, 32)),
                offer = OfferTypes.Offer(OfferTypes.Offer.tlvSerializer.read(LightningCodecs.bytes(input, LightningCodecs.u16(input)))),
                languageSubtag = LightningCodecs.bytes(input, LightningCodecs.u16(input)).decodeToString()
            )
        }
    }
}

data class DNSAddressResponse(override val chainHash: BlockHash, val address: String) : LightningMessage, HasChainHash {

    override val type: Long get() = DNSAddressResponse.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash.value, out)
        LightningCodecs.writeU16(address.length, out)
        LightningCodecs.writeBytes(address.toByteArray(charset = Charsets.UTF_8), out)
    }

    companion object : LightningMessageReader<DNSAddressResponse> {
        const val type: Long = 35027

        override fun read(input: Input): DNSAddressResponse {
            return DNSAddressResponse(
                chainHash = BlockHash(LightningCodecs.bytes(input, 32)),
                address = LightningCodecs.bytes(input, LightningCodecs.u16(input)).decodeToString()
            )
        }
    }
}

data class RecommendedFeerates(
    override val chainHash: BlockHash,
    val fundingFeerate: FeeratePerKw,
    val commitmentFeerate: FeeratePerKw,
    val tlvStream: TlvStream<RecommendedFeeratesTlv> = TlvStream.empty(),
) : LightningMessage, HasChainHash {
    override val type: Long get() = RecommendedFeerates.type

    override fun write(out: Output) {
        LightningCodecs.writeBytes(chainHash.value, out)
        LightningCodecs.writeU32(fundingFeerate.toLong().toInt(), out)
        LightningCodecs.writeU32(commitmentFeerate.toLong().toInt(), out)
        TlvStreamSerializer(false, readers).write(tlvStream, out)
    }

    companion object : LightningMessageReader<RecommendedFeerates> {
        const val type: Long = 39409

        @Suppress("UNCHECKED_CAST")
        private val readers = mapOf(
            RecommendedFeeratesTlv.FundingFeerateRange.tag to RecommendedFeeratesTlv.FundingFeerateRange as TlvValueReader<RecommendedFeeratesTlv>,
            RecommendedFeeratesTlv.CommitmentFeerateRange.tag to RecommendedFeeratesTlv.CommitmentFeerateRange as TlvValueReader<RecommendedFeeratesTlv>,
        )

        override fun read(input: Input): RecommendedFeerates = RecommendedFeerates(
            chainHash = BlockHash(LightningCodecs.bytes(input, 32)),
            fundingFeerate = FeeratePerKw(LightningCodecs.u32(input).sat),
            commitmentFeerate = FeeratePerKw(LightningCodecs.u32(input).sat),
            tlvStream = TlvStreamSerializer(false, readers).read(input)
        )
    }
}

data class UnknownMessage(override val type: Long) : LightningMessage {
    override fun write(out: Output) = TODO("Serialization of unknown messages is not implemented")
}