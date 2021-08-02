package fr.acinq.lightning.crypto.noise

import swift.phoenix_crypto.*
import fr.acinq.lightning.utils.toByteArray
import fr.acinq.lightning.utils.toNSData
import fr.acinq.lightning.crypto.ChaCha20Poly1305
import kotlinx.cinterop.autoreleasepool

actual object Chacha20Poly1305CipherFunctions : CipherFunctions {
    override fun name() = "ChaChaPoly"

    // as specified in BOLT #8
    fun nonce(n: Long): ByteArray = ByteArray(4) + ChaCha20Poly1305.write64(n)

    // Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte unsigned integer nonce n which must be unique.
    override fun encrypt(k: ByteArray, n: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        autoreleasepool {
            val ciphertextAndMac = NativeChaChaPoly.encryptWithKey(
                key = k.toNSData(),
                nonce = nonce(n).toNSData(),
                authenticatedData = ad.toNSData(),
                plaintext = plaintext.toNSData()
            )
            return ciphertextAndMac.toByteArray()
        }
    }

    // Decrypts ciphertext using a cipher key k of 32 bytes, an 8-byte unsigned integer nonce n, and associated data ad.
    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    override fun decrypt(k: ByteArray, n: Long, ad: ByteArray, ciphertextAndMac: ByteArray): ByteArray {
        autoreleasepool {
            val plaintext = NativeChaChaPoly.decryptWithKey(
                key = k.toNSData(),
                nonce = nonce(n).toNSData(),
                authenticatedData = ad.toNSData(),
                ciphertextAndTag = ciphertextAndMac.toNSData()
            )
            return plaintext.toByteArray()
        }
    }
}
