package fr.acinq.lightning.serialization

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.wire.LightningCodecs
import fr.acinq.lightning.wire.LightningMessage

object InputExtensions {

    fun Input.readNumber(): Long = LightningCodecs.bigSize(this)

    fun Input.readBoolean(): Boolean = read() == 1

    fun Input.readString(): String = readDelimitedByteArray().decodeToString()

    fun Input.readByteVector32(): ByteVector32 = ByteVector32(ByteArray(32).also { read(it, 0, it.size) })

    fun Input.readByteVector64(): ByteVector64 = ByteVector64(ByteArray(64).also { read(it, 0, it.size) })

    fun Input.readPublicKey() = PublicKey(ByteArray(33).also { read(it, 0, it.size) })

    fun Input.readPrivateKey() = PrivateKey(ByteArray(32).also { read(it, 0, it.size) })

    fun Input.readTxId(): TxId = TxId(readByteVector32())

    fun Input.readPublicNonce() = IndividualNonce(ByteArray(66).also { read(it, 0, it.size) })

    fun Input.readUuid(): UUID = UUID.fromBytes(ByteArray(16).also { read(it, 0, it.size) })

    fun Input.readDelimitedByteArray(): ByteArray {
        val size = readNumber().toInt()
        return ByteArray(size).also { read(it, 0, size) }
    }

    fun Input.readLightningMessage() = LightningMessage.decode(readDelimitedByteArray())

    fun <T> Input.readCollection(readElem: () -> T): Collection<T> {
        val size = readNumber()
        return buildList {
            repeat(size.toInt()) {
                add(readElem())
            }
        }
    }

    fun <L, R> Input.readEither(readLeft: () -> L, readRight: () -> R): Either<L, R> = when (read()) {
        0 -> Either.Left(readLeft())
        else -> Either.Right(readRight())
    }

    fun <T : Any> Input.readNullable(readNotNull: () -> T): T? = when (read()) {
        1 -> readNotNull()
        else -> null
    }
}