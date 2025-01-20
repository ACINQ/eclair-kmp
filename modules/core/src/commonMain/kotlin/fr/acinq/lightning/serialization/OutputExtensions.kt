package fr.acinq.lightning.serialization

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.io.Output
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.wire.LightningCodecs
import fr.acinq.lightning.wire.LightningMessage

object OutputExtensions {

    fun Output.writeNumber(o: Number): Unit = LightningCodecs.writeBigSize(o.toLong(), this)

    fun Output.writeBoolean(o: Boolean): Unit = if (o) write(1) else write(0)

    fun Output.writeString(o: String): Unit = writeDelimited(o.encodeToByteArray())

    fun Output.writeByteVector32(o: ByteVector32) = write(o.toByteArray())

    fun Output.writeByteVector64(o: ByteVector64) = write(o.toByteArray())

    fun Output.writePublicKey(o: PublicKey) = write(o.value.toByteArray())

    fun Output.writePrivateKey(o: PrivateKey) = write(o.value.toByteArray())

    fun Output.writeTxId(o: TxId) = write(o.value.toByteArray())

    fun Output.writePublicNonce(o: IndividualNonce) = write(o.toByteArray())

    fun Output.writeUuid(o: UUID) = o.run {
        // NB: copied from kotlin source code (https://github.com/JetBrains/kotlin/blob/v2.1.0/libraries/stdlib/src/kotlin/uuid/Uuid.kt) in order to be forward compatible
        fun Long.toByteArray(dst: ByteArray, dstOffset: Int) {
            for (index in 0 until 8) {
                val shift = 8 * (7 - index)
                dst[dstOffset + index] = (this ushr shift).toByte()
            }
        }
        val bytes = ByteArray(16)
        mostSignificantBits.toByteArray(bytes, 0)
        leastSignificantBits.toByteArray(bytes, 8)
        write(bytes)
    }

    fun Output.writeDelimited(o: ByteArray) {
        writeNumber(o.size)
        write(o)
    }

    fun <T : BtcSerializable<T>> Output.writeBtcObject(o: T): Unit = writeDelimited(o.serializer().write(o))

    fun Output.writeLightningMessage(o: LightningMessage) = writeDelimited(LightningMessage.encode(o))

    fun <T> Output.writeCollection(o: Collection<T>, writeElem: (T) -> Unit) {
        writeNumber(o.size)
        o.forEach { writeElem(it) }
    }

    fun <L, R> Output.writeEither(o: Either<L, R>, writeLeft: (L) -> Unit, writeRight: (R) -> Unit) = when (o) {
        is Either.Left -> {
            write(0); writeLeft(o.value)
        }
        is Either.Right -> {
            write(1); writeRight(o.value)
        }
    }

    fun <T : Any> Output.writeNullable(o: T?, writeNotNull: (T) -> Unit) = when (o) {
        is T -> {
            write(1); writeNotNull(o)
        }
        else -> write(0)
    }
}