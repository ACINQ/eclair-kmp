package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.BitField
import kotlin.math.log2
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotSame
import kotlin.test.assertTrue

class WeakRandomTestsCommon : LightningTestSuite() {

    @Test
    fun `random long generation`() {
        val randomNumbers = (1..1000).map { WeakRandom.nextLong() }
        assertEquals(1000, randomNumbers.toSet().size)
        val entropy = randomNumbers.sumOf { entropyScore(it) } / 1000
        assertTrue(entropy >= 0.98)
    }

    @Test
    fun `random bytes generation (small length)`() {
        val b1 = ByteArray(32)
        WeakRandom.nextBytes(b1)
        val b2 = ByteArray(32)
        WeakRandom.nextBytes(b2)
        val b3 = ByteArray(32)
        WeakRandom.nextBytes(b3)
        assertNotSame(b1, b2)
        assertNotSame(b1, b3)
        assertNotSame(b2, b3)
    }

    @Test
    fun `random bytes generation (same length)`() {
        var randomBytes = ByteArray(0)
        for (i in 1..1000) {
            val buffer = ByteArray(64)
            WeakRandom.nextBytes(buffer)
            randomBytes += buffer
        }
        val entropy = entropyScore(randomBytes)
        assertTrue(entropy >= 0.99)
    }

    @Test
    fun `random bytes generation (variable length)`() {
        var randomBytes = ByteArray(0)
        for (i in 10..500) {
            val buffer = ByteArray(i)
            WeakRandom.nextBytes(buffer)
            randomBytes += buffer
        }
        val entropy = entropyScore(randomBytes)
        assertTrue(entropy >= 0.99)
    }

    companion object {
        // See https://en.wikipedia.org/wiki/Binary_entropy_function
        private fun entropyScore(bits: BitField): Double {
            val p = bits.asLeftSequence().fold(0) { acc, bit -> if (bit) acc + 1 else acc }.toDouble() / bits.bitCount
            return (-p) * log2(p) - (1 - p) * log2(1 - p)
        }

        fun entropyScore(l: Long): Double {
            return entropyScore(BitField.from(Pack.writeInt64BE(l)))
        }

        fun entropyScore(bytes: ByteArray): Double {
            return entropyScore(BitField.from(bytes))
        }
    }

}