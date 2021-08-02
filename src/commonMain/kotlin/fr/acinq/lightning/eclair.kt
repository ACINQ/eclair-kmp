package fr.acinq.lightning

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.KeyPath
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.lightning.crypto.WeakRandom
import fr.acinq.lightning.utils.secure
import fr.acinq.lightning.utils.xor
import kotlin.experimental.xor
import kotlin.random.Random

object Lightning {

    private val secureRandom = Random.secure()

    fun randomBytes(length: Int): ByteArray {
        val buffer = ByteArray(length)
        secureRandom.nextBytes(buffer)
        val weakBuffer = ByteArray(length)
        WeakRandom.nextBytes(weakBuffer)
        return buffer.xor(weakBuffer)
    }

    fun randomBytes32(): ByteVector32 = ByteVector32(randomBytes(32))
    fun randomBytes64(): ByteVector64 = ByteVector64(randomBytes(64))
    fun randomKey(): PrivateKey = PrivateKey(randomBytes32())

    fun randomKeyPath(length: Int): KeyPath {
        val path = mutableListOf<Long>()
        repeat(length) { path.add(randomLong()) }
        return KeyPath(path)
    }

    fun randomLong(): Long {
        return secureRandom.nextLong().xor(WeakRandom.nextLong())
    }

    fun toLongId(fundingTxHash: ByteVector32, fundingOutputIndex: Int): ByteVector32 {
        require(fundingOutputIndex < 65536) { "fundingOutputIndex must not be greater than FFFF" }
        val x1 = fundingTxHash[30] xor (fundingOutputIndex.shr(8)).toByte()
        val x2 = fundingTxHash[31] xor fundingOutputIndex.toByte()
        return ByteVector32(fundingTxHash.take(30).concat(x1).concat(x2))
    }

    /**
     * @param baseFee fixed fee
     * @param proportionalFee proportional fee (millionths)
     * @param paymentAmount payment amount in millisatoshi
     * @return the fee that a node should be paid to forward an HTLC of 'paymentAmount' millisatoshis
     */
    fun nodeFee(baseFee: MilliSatoshi, proportionalFee: Long, paymentAmount: MilliSatoshi): MilliSatoshi = baseFee + (paymentAmount * proportionalFee) / 1_000_000

}
