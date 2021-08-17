package fr.acinq.lightning.serialization.v2

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.readNBytes
import fr.acinq.lightning.NodeParams
import fr.acinq.lightning.crypto.ChaCha20Poly1305
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.wire.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

object Serialization {
    private val versionMagic = 2

    /**
     * Versioned serialized data.
     *
     * @README DO NOT change the structure of this class !!
     *
     * If a new serialization format is added, just change the `version` field and update serialize()/deserialize() methods
     * @param version version of the serialization algorithm
     * @param data serialized data
     */
    @Serializable
    private data class SerializedData(val version: Int, @Serializable(with = ByteVectorKSerializer::class) val data: ByteVector)

    private val updateSerializersModule = SerializersModule {
        polymorphic(UpdateMessage::class) {
            subclass(UpdateAddHtlc.serializer())
            subclass(UpdateFailHtlc.serializer())
            subclass(UpdateFailMalformedHtlc.serializer())
            subclass(UpdateFee.serializer())
            subclass(UpdateFulfillHtlc.serializer())
        }
    }

    private val tlvSerializersModule = SerializersModule {
        polymorphic(Tlv::class) {
            subclass(ChannelTlv.UpfrontShutdownScript.serializer())
            subclass(ChannelTlv.ChannelVersionTlv.serializer())
            subclass(ChannelTlv.ChannelOriginTlv.serializer())
            subclass(InitTlv.Networks.serializer())
            subclass(OnionTlv.AmountToForward.serializer())
            subclass(OnionTlv.OutgoingCltv.serializer())
            subclass(OnionTlv.OutgoingChannelId.serializer())
            subclass(OnionTlv.PaymentData.serializer())
            subclass(OnionTlv.InvoiceFeatures.serializer())
            subclass(OnionTlv.OutgoingNodeId.serializer())
            subclass(OnionTlv.InvoiceRoutingInfo.serializer())
            subclass(OnionTlv.TrampolineOnion.serializer())
            subclass(GenericTlv.serializer())
        }
    }

    private val serializersModule = SerializersModule {
        polymorphic(ChannelStateWithCommitments::class) {
            subclass(Normal::class)
            subclass(WaitForFundingConfirmed::class)
            subclass(WaitForFundingLocked::class)
            subclass(WaitForRemotePublishFutureCommitment::class)
            subclass(ShuttingDown::class)
            subclass(Negotiating::class)
            subclass(Closing::class)
            subclass(Closed::class)
            subclass(ErrorInformationLeak::class)
        }
    }

    private val serializationModules = SerializersModule {
        include(tlvSerializersModule)
        include(updateSerializersModule)
        include(SerializersModule {
            contextual(ByteVector64KSerializer)
            contextual(ByteVector32KSerializer)
            contextual(ByteVectorKSerializer)
            contextual(SatoshiKSerializer)
            contextual(PrivateKeyKSerializer)
            contextual(PublicKeyKSerializer)
            contextual(OutPointKSerializer)
            contextual(TxInKSerializer)
            contextual(TxOutKSerializer)
            contextual(TransactionKSerializer)
            contextual(BlockHeaderKSerializer)
        })
    }

    // used by the "test node" JSON API
    val lightningSerializersModule = SerializersModule {
        include(serializersModule)
        include(serializationModules)
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun serialize(state: ChannelStateWithCommitments): ByteArray {
        val output = ByteArrayOutput()
        val encoder = DataOutputEncoder(output)
        encoder.encodeSerializableValue(ChannelStateWithCommitments.serializer(), state)
        val bytes = output.toByteArray()
        val versioned = SerializedData(version = versionMagic, data = bytes.toByteVector())
        val output1 = ByteArrayOutput()
        val encoder1 = DataOutputEncoder(output1)
        encoder1.encodeSerializableValue(SerializedData.serializer(), versioned)
        return output1.toByteArray()
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun serialize(state: fr.acinq.lightning.channel.ChannelStateWithCommitments): ByteArray {
        return serialize(ChannelStateWithCommitments.import(state))
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun deserialize(bin: ByteArray, nodeParams: NodeParams): fr.acinq.lightning.channel.ChannelStateWithCommitments {
        val input = ByteArrayInput(bin)
        val decoder = DataInputDecoder(input)
        val versioned = decoder.decodeSerializableValue(SerializedData.serializer())
        return when (versioned.version) {
            versionMagic -> {
                val input1 = ByteArrayInput(versioned.data.toByteArray())
                val decoder1 = DataInputDecoder(input1)
                decoder1.decodeSerializableValue(ChannelStateWithCommitments.serializer()).export(nodeParams)
            }
            else -> error("unknown serialization version ${versioned.version}")
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    private fun deserialize(bin: ByteVector, nodeParams: NodeParams): fr.acinq.lightning.channel.ChannelStateWithCommitments = deserialize(bin.toByteArray(), nodeParams)

    @OptIn(ExperimentalSerializationApi::class)
    fun encrypt(key: ByteVector32, state: ChannelStateWithCommitments): EncryptedChannelData {
        val bin = serialize(state)
        // NB: there is a chance of collision here, due to how the nonce is calculated. Probability of collision is once every 2.2E19 times.
        // See https://en.wikipedia.org/wiki/Birthday_attack
        val nonce = Crypto.sha256(bin).take(12).toByteArray()
        val (ciphertext, tag) = ChaCha20Poly1305.encrypt(key.toByteArray(), nonce, bin, ByteArray(0))
        return EncryptedChannelData((ciphertext + nonce + tag).toByteVector())
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun encrypt(key: ByteVector32, state: fr.acinq.lightning.channel.ChannelStateWithCommitments): EncryptedChannelData {
        val bin = serialize(state)
        // NB: there is a chance of collision here, due to how the nonce is calculated. Probability of collision is once every 2.2E19 times.
        // See https://en.wikipedia.org/wiki/Birthday_attack
        val nonce = Crypto.sha256(bin).take(12).toByteArray()
        val (ciphertext, tag) = ChaCha20Poly1305.encrypt(key.toByteArray(), nonce, bin, ByteArray(0))
        return EncryptedChannelData((ciphertext + nonce + tag).toByteVector())
    }

    fun encrypt(key: PrivateKey, state: fr.acinq.lightning.channel.ChannelStateWithCommitments): EncryptedChannelData = encrypt(key.value, state)

    @OptIn(ExperimentalSerializationApi::class)
    fun decrypt(key: ByteVector32, data: ByteArray, nodeParams: NodeParams): fr.acinq.lightning.channel.ChannelStateWithCommitments {
        // nonce is 12B, tag is 16B
        val ciphertext = data.dropLast(12 + 16)
        val nonce = data.takeLast(12 + 16).take(12)
        val tag = data.takeLast(16)
        val plaintext = ChaCha20Poly1305.decrypt(key.toByteArray(), nonce.toByteArray(), ciphertext.toByteArray(), ByteArray(0), tag.toByteArray())
        return deserialize(plaintext, nodeParams)
    }

    fun decrypt(key: PrivateKey, data: ByteArray, nodeParams: NodeParams): fr.acinq.lightning.channel.ChannelStateWithCommitments = decrypt(key.value, data, nodeParams)
    fun decrypt(key: PrivateKey, backup: EncryptedChannelData, nodeParams: NodeParams): fr.acinq.lightning.channel.ChannelStateWithCommitments = decrypt(key, backup.data.toByteArray(), nodeParams)

    @OptIn(ExperimentalSerializationApi::class)
    class DataOutputEncoder(val output: ByteArrayOutput) : AbstractEncoder() {
        override val serializersModule: SerializersModule = serializationModules
        override fun encodeBoolean(value: Boolean) = output.write(if (value) 1 else 0)
        override fun encodeByte(value: Byte) = output.write(value.toInt())
        override fun encodeShort(value: Short) = output.write(Pack.writeInt16BE(value))
        override fun encodeInt(value: Int) = output.write(Pack.writeInt32BE(value))
        override fun encodeLong(value: Long) = output.write(Pack.writeInt64BE(value))
        override fun encodeFloat(value: Float) {
            TODO()
        }

        override fun encodeDouble(value: Double) {
            TODO()
        }

        override fun encodeChar(value: Char) = output.write(value.toInt())
        override fun encodeString(value: String) {
            val bytes = value.encodeToByteArray()
            encodeInt(bytes.size)
            output.write(bytes)
        }

        override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) = output.write(index)
        override fun beginCollection(descriptor: SerialDescriptor, collectionSize: Int): CompositeEncoder {
            encodeInt(collectionSize)
            return this
        }

        override fun encodeNull() = encodeBoolean(false)
        override fun encodeNotNullMark() = encodeBoolean(true)
    }

    @OptIn(ExperimentalSerializationApi::class)
    @ExperimentalSerializationApi
    class DataInputDecoder(val input: ByteArrayInput, var elementsCount: Int = 0) : AbstractDecoder() {
        private var elementIndex = 0
        override val serializersModule: SerializersModule = serializationModules
        override fun decodeBoolean(): Boolean = input.read() != 0
        override fun decodeByte(): Byte = input.read().toByte()
        override fun decodeShort(): Short = Pack.int16BE(input.readNBytes(2)!!)
        override fun decodeInt(): Int = Pack.int32BE(input.readNBytes(4)!!)
        override fun decodeLong(): Long = Pack.int64BE(input.readNBytes(8)!!)
        override fun decodeFloat(): Float = TODO()
        override fun decodeDouble(): Double = TODO()
        override fun decodeChar(): Char = input.read().toChar()
        override fun decodeString(): String {
            val len = decodeInt()
            require(len <= input.availableBytes)
            val decoded = input.readNBytes(len)!!.decodeToString()
            return decoded
        }

        override fun decodeEnum(enumDescriptor: SerialDescriptor): Int = input.read()
        override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
            if (elementIndex == elementsCount) return CompositeDecoder.DECODE_DONE
            return elementIndex++
        }

        override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder = DataInputDecoder(input, descriptor.elementsCount)
        override fun decodeSequentially(): Boolean = true
        override fun decodeCollectionSize(descriptor: SerialDescriptor): Int = decodeInt().also {
            require(it <= input.availableBytes)
            elementsCount = it
        }

        override fun decodeNotNullMark(): Boolean = decodeBoolean()
    }
}