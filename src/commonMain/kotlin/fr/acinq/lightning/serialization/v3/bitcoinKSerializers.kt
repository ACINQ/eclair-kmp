package fr.acinq.lightning.serialization.v3

import fr.acinq.bitcoin.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object ByteVectorKSerializer : KSerializer<ByteVector> {
    @Serializable
    private data class ByteVectorSurrogate(val value: ByteArray)

    override val descriptor: SerialDescriptor = ByteVectorSurrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: ByteVector) {
        val surrogate = ByteVectorSurrogate(value.toByteArray())
        return encoder.encodeSerializableValue(ByteVectorSurrogate.serializer(), surrogate)
    }

    override fun deserialize(decoder: Decoder): ByteVector {
        val surrogate = decoder.decodeSerializableValue(ByteVectorSurrogate.serializer())
        return ByteVector(surrogate.value)
    }
}

object ByteVector32KSerializer : KSerializer<ByteVector32> {
    @Serializable
    private data class ByteVector32Surrogate(val value: ByteArray) {
        init {
            require(value.size == 32)
        }
    }

    override val descriptor: SerialDescriptor = ByteVector32Surrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: ByteVector32) {
        val surrogate = ByteVector32Surrogate(value.toByteArray())
        return encoder.encodeSerializableValue(ByteVector32Surrogate.serializer(), surrogate)
    }

    override fun deserialize(decoder: Decoder): ByteVector32 {
        val surrogate = decoder.decodeSerializableValue(ByteVector32Surrogate.serializer())
        return ByteVector32(surrogate.value)
    }
}

object ByteVector64KSerializer : KSerializer<ByteVector64> {
    @Serializable
    private data class ByteVector64Surrogate(val value: ByteArray)

    override val descriptor: SerialDescriptor = ByteVector64Surrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: ByteVector64) {
        val surrogate = ByteVector64Surrogate(value.toByteArray())
        return encoder.encodeSerializableValue(ByteVector64Surrogate.serializer(), surrogate)
    }

    override fun deserialize(decoder: Decoder): ByteVector64 {
        val surrogate = decoder.decodeSerializableValue(ByteVector64Surrogate.serializer())
        return ByteVector64(surrogate.value)
    }
}

object PrivateKeyKSerializer : KSerializer<PrivateKey> {

    override fun deserialize(decoder: Decoder): PrivateKey {
        return PrivateKey(ByteVector32KSerializer.deserialize(decoder))
    }

    override val descriptor: SerialDescriptor get() = ByteVector32KSerializer.descriptor

    override fun serialize(encoder: Encoder, value: PrivateKey) {
        ByteVector32KSerializer.serialize(encoder, value.value)
    }
}

object PublicKeyKSerializer : KSerializer<PublicKey> {

    override fun deserialize(decoder: Decoder): PublicKey {
        return PublicKey(ByteVectorKSerializer.deserialize(decoder))
    }

    override val descriptor: SerialDescriptor get() = ByteVectorKSerializer.descriptor

    override fun serialize(encoder: Encoder, value: PublicKey) {
        ByteVectorKSerializer.serialize(encoder, value.value)
    }
}

object SatoshiKSerializer : KSerializer<Satoshi> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Satoshi", PrimitiveKind.LONG)

    override fun serialize(encoder: Encoder, value: Satoshi) {
        encoder.encodeLong(value.toLong())
    }

    override fun deserialize(decoder: Decoder): Satoshi {
        return Satoshi(decoder.decodeLong())
    }
}

abstract class AbstractBtcSerializableKSerializer<T : BtcSerializable<T>>(val name: String, val btcSerializer: BtcSerializer<T>) : KSerializer<T> {
    @Serializable
    data class Surrogate(val name: String, val bytes: ByteArray)

    override val descriptor: SerialDescriptor = Surrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: T) {
        val surrogate = Surrogate(name, btcSerializer.write(value))
        return encoder.encodeSerializableValue(Surrogate.serializer(), surrogate)
    }

    override fun deserialize(decoder: Decoder): T {
        val surrogate = decoder.decodeSerializableValue(Surrogate.serializer())
        return btcSerializer.read(surrogate.bytes)
    }
}

object BlockHeaderKSerializer : AbstractBtcSerializableKSerializer<BlockHeader>("BlockHeader", BlockHeader)

object OutPointKSerializer : AbstractBtcSerializableKSerializer<OutPoint>("OutPoint", OutPoint)

object ScriptWitnessKSerializer : AbstractBtcSerializableKSerializer<ScriptWitness>("ScriptWitness", ScriptWitness)

object TxInKSerializer : AbstractBtcSerializableKSerializer<TxIn>("TxIn", TxIn)

object TxOutKSerializer : AbstractBtcSerializableKSerializer<TxOut>("TxOut", TxOut)

object TransactionKSerializer : AbstractBtcSerializableKSerializer<Transaction>("Transaction", Transaction)

object ExtendedPrivateKeyKSerializer : KSerializer<DeterministicWallet.ExtendedPrivateKey> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ExtendedPublicKey") {
        element("secretkeybytes", ByteVector32KSerializer.descriptor)
        element("chaincode", ByteVector32KSerializer.descriptor)
        element<Int>("depth")
        element("path", KeyPathKSerializer.descriptor)
        element<Long>("parent")
    }

    override fun serialize(encoder: Encoder, value: DeterministicWallet.ExtendedPrivateKey) {
        val compositeEncoder = encoder.beginStructure(ExtendedPublicKeyKSerializer.descriptor)
        compositeEncoder.encodeSerializableElement(ExtendedPublicKeyKSerializer.descriptor, 0, ByteVector32KSerializer, value.secretkeybytes)
        compositeEncoder.encodeSerializableElement(ExtendedPublicKeyKSerializer.descriptor, 1, ByteVector32KSerializer, value.chaincode)
        compositeEncoder.encodeIntElement(ExtendedPublicKeyKSerializer.descriptor, 2, value.depth)
        compositeEncoder.encodeSerializableElement(ExtendedPublicKeyKSerializer.descriptor, 3, KeyPathKSerializer, value.path)
        compositeEncoder.encodeLongElement(ExtendedPublicKeyKSerializer.descriptor, 4, value.parent)
        compositeEncoder.endStructure(ExtendedPublicKeyKSerializer.descriptor)
    }

    override fun deserialize(decoder: Decoder): DeterministicWallet.ExtendedPrivateKey {
        var secretkeybytes: ByteVector32? = null
        var chaincode: ByteVector32? = null
        var depth: Int? = null
        var path: KeyPath? = null
        var parent: Long? = null

        val compositeDecoder = decoder.beginStructure(ExtendedPublicKeyKSerializer.descriptor)
        loop@ while (true) {
            when (compositeDecoder.decodeElementIndex(ExtendedPublicKeyKSerializer.descriptor)) {
                CompositeDecoder.DECODE_DONE -> break@loop
                0 -> secretkeybytes = compositeDecoder.decodeSerializableElement(ExtendedPublicKeyKSerializer.descriptor, 0, ByteVector32KSerializer)
                1 -> chaincode = compositeDecoder.decodeSerializableElement(ExtendedPublicKeyKSerializer.descriptor, 1, ByteVector32KSerializer)
                2 -> depth = compositeDecoder.decodeIntElement(ExtendedPublicKeyKSerializer.descriptor, 2)
                3 -> path = compositeDecoder.decodeSerializableElement(ExtendedPublicKeyKSerializer.descriptor, 3, KeyPathKSerializer)
                4 -> parent = compositeDecoder.decodeLongElement(ExtendedPublicKeyKSerializer.descriptor, 4)
            }
        }
        compositeDecoder.endStructure(ExtendedPublicKeyKSerializer.descriptor)

        return DeterministicWallet.ExtendedPrivateKey(secretkeybytes!!, chaincode!!, depth!!, path!!, parent!!)
    }

}

object ExtendedPublicKeyKSerializer : KSerializer<DeterministicWallet.ExtendedPublicKey> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ExtendedPublicKey") {
        element("publickeybytes", ByteVectorKSerializer.descriptor)
        element("chaincode", ByteVector32KSerializer.descriptor)
        element<Int>("depth")
        element("path", KeyPathKSerializer.descriptor)
        element<Long>("parent")
    }

    override fun serialize(encoder: Encoder, value: DeterministicWallet.ExtendedPublicKey) {
        val compositeEncoder = encoder.beginStructure(descriptor)
        compositeEncoder.encodeSerializableElement(descriptor, 0, ByteVectorKSerializer, value.publickeybytes)
        compositeEncoder.encodeSerializableElement(descriptor, 1, ByteVector32KSerializer, value.chaincode)
        compositeEncoder.encodeIntElement(descriptor, 2, value.depth)
        compositeEncoder.encodeSerializableElement(descriptor, 3, KeyPathKSerializer, value.path)
        compositeEncoder.encodeLongElement(descriptor, 4, value.parent)
        compositeEncoder.endStructure(descriptor)
    }

    override fun deserialize(decoder: Decoder): DeterministicWallet.ExtendedPublicKey {
        var publickeybytes: ByteVector? = null
        var chaincode: ByteVector32? = null
        var depth: Int? = null
        var path: KeyPath? = null
        var parent: Long? = null

        val compositeDecoder = decoder.beginStructure(descriptor)
        loop@ while (true) {
            when (compositeDecoder.decodeElementIndex(descriptor)) {
                CompositeDecoder.DECODE_DONE -> break@loop
                0 -> publickeybytes = compositeDecoder.decodeSerializableElement(descriptor, 0, ByteVectorKSerializer)
                1 -> chaincode = compositeDecoder.decodeSerializableElement(descriptor, 1, ByteVector32KSerializer)
                2 -> depth = compositeDecoder.decodeIntElement(descriptor, 2)
                3 -> path = compositeDecoder.decodeSerializableElement(descriptor, 3, KeyPathKSerializer)
                4 -> parent = compositeDecoder.decodeLongElement(descriptor, 4)
            }
        }
        compositeDecoder.endStructure(descriptor)

        return DeterministicWallet.ExtendedPublicKey(publickeybytes!!, chaincode!!, depth!!, path!!, parent!!)
    }

}

object KeyPathKSerializer : KSerializer<KeyPath> {
    private val listSerializer = ListSerializer(Long.serializer())

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("KeyPath") {
        element("path", listSerializer.descriptor)
    }

    override fun serialize(encoder: Encoder, value: KeyPath) {
        val compositeEncoder = encoder.beginStructure(ExtendedPublicKeyKSerializer.descriptor)
        compositeEncoder.encodeSerializableElement(descriptor, 0, listSerializer, value.path)
        compositeEncoder.endStructure(descriptor)
    }

    override fun deserialize(decoder: Decoder): KeyPath {
        val compositeDecoder = decoder.beginStructure(ExtendedPublicKeyKSerializer.descriptor)
        require(compositeDecoder.decodeElementIndex(descriptor) == 0)
        val path = compositeDecoder.decodeSerializableElement(descriptor, 0, listSerializer)
        compositeDecoder.endStructure(descriptor)
        return KeyPath(path)
    }
}
