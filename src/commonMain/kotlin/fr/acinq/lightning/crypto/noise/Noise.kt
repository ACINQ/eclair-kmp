package fr.acinq.lightning.crypto.noise

import fr.acinq.lightning.Lightning.randomBytes

interface DHFunctions {
    fun name(): String
    fun generateKeyPair(priv: ByteArray): Pair<ByteArray, ByteArray>
    fun dh(keyPair: Pair<ByteArray, ByteArray>, publicKey: ByteArray): ByteArray
    fun dhLen(): Int
    fun pubKeyLen(): Int
}

/**
 * Cipher functions
 */
interface CipherFunctions {
    fun name(): String

    // Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte unsigned integer nonce n which must be unique
    // for the key k. Returns the ciphertext. Encryption must be done with an "AEAD" encryption mode with the associated
    // data ad (using the terminology from [1]) and returns a ciphertext that is the same size as the plaintext
    // plus 16 bytes for authentication data. The entire ciphertext must be indistinguishable from random if the key is secret.
    fun encrypt(k: ByteArray, n: Long, ad: ByteArray, plaintext: ByteArray): ByteArray

    // Decrypts ciphertext using a cipher key k of 32 bytes, an 8-byte unsigned integer nonce n, and associated data ad.
    // Returns the plaintext, unless authentication fails, in which case an error is signaled to the caller.
    fun decrypt(k: ByteArray, n: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray
}

/**
 * Hash functions
 */
interface HashFunctions {
    fun name(): String

    // Hashes some arbitrary-length data with a collision-resistant cryptographic hash function and returns an output of HASHLEN bytes.
    fun hash(data: ByteArray): ByteArray

    // A constant specifying the size in bytes of the hash output. Must be 32 or 64.
    fun hashLen(): Int

    // A constant specifying the size in bytes that the hash function uses internally to divide its input for iterative processing. This is needed to use the hash function with HMAC (BLOCKLEN is B in [2]).
    fun blockLen(): Int

    // Applies HMAC from [2] using the HASH() function. This function is only called as part of HKDF(), below.
    fun hmacHash(key: ByteArray, data: ByteArray): ByteArray

    // Takes a chaining_key byte sequence of length HASHLEN, and an input_key_material byte sequence with length either zero bytes, 32 bytes, or DHLEN bytes. Returns two byte sequences of length HASHLEN, as follows:
    // Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
    // Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
    // Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
    // Returns the pair (output1, output2).
    fun hkdf(chainingKey: ByteArray, inputMaterial: ByteArray): Pair<ByteArray, ByteArray> {
        val tempkey = hmacHash(chainingKey, inputMaterial)
        val output1 = hmacHash(tempkey, byteArrayOf(0x01))
        val output2 = hmacHash(tempkey, output1 + byteArrayOf(0x02))

        return Pair(output1, output2)
    }
}

/**
 * Cipher state
 */
interface CipherState {
    fun cipher(): CipherFunctions

    fun initializeKey(key: ByteArray): CipherState =
        apply(key, cipher())

    fun hasKey(): Boolean

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): Pair<CipherState, ByteArray>

    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): Pair<CipherState, ByteArray>

    companion object {
        fun apply(k: ByteArray, cipher: CipherFunctions): CipherState = when (k.size) {
            0 -> UninitializedCipherState(cipher)
            32 -> InitializedCipherState(k, 0, cipher)
            else -> throw RuntimeException("invalid key size")
        }

        fun apply(cipher: CipherFunctions): CipherState =
            UninitializedCipherState(cipher)
    }
}

/**
 * Uninitialized cipher state. Encrypt and decrypt do nothing (ciphertext = plaintext)
 *
 * @param cipher cipher functions
 */
data class UninitializedCipherState(val cipher: CipherFunctions) :
    CipherState {
    override fun cipher(): CipherFunctions = cipher

    override fun hasKey() = false

    override fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): Pair<CipherState, ByteArray> = Pair(this, plaintext)

    override fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): Pair<CipherState, ByteArray> = Pair(this, ciphertext)
}

/**
 * Initialized cipher state
 *
 * @param k      key
 * @param n      nonce
 * @param cipher cipher functions
 */
data class InitializedCipherState(val k: ByteArray, val n: Long, val cipher: CipherFunctions) :
    CipherState {
    init {
        require(k.size == 32) { "key size must be 32 bytes" }
    }

    override fun cipher(): CipherFunctions = cipher

    override fun hasKey() = true

    override fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): Pair<CipherState, ByteArray> {
        return Pair(this.copy(n = this.n + 1), cipher.encrypt(k, n, ad, plaintext))
    }

    override fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): Pair<CipherState, ByteArray> {
        return Pair(this.copy(n = this.n + 1), cipher.decrypt(k, n, ad, ciphertext))
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        //if (javaClass != other?.javaClass) return false

        other as InitializedCipherState

        if (!k.contentEquals(other.k)) return false
        if (n != other.n) return false
        if (cipher != other.cipher) return false

        return true
    }

    override fun hashCode(): Int {
        var result = k.contentHashCode()
        result = 31 * result + n.hashCode()
        result = 31 * result + cipher.hashCode()
        return result
    }
}

/**
 *
 * @param cipherState   cipher state
 * @param ck            chaining key
 * @param h             hash
 * @param hashFunctions hash functions
 */
data class SymmetricState(val cipherState: CipherState, val ck: ByteArray, val h: ByteArray, val hashFunctions: HashFunctions) {
    fun mixKey(inputKeyMaterial: ByteArray): SymmetricState {
        val (ck1, tempk) = hashFunctions.hkdf(ck, inputKeyMaterial)
        val tempk1 = when (hashFunctions.hashLen()) {
            32 -> tempk
            64 -> tempk.take(32).toByteArray()
            else -> throw RuntimeException("invalid key size, must be 32 or 64 bytes")
        }
        return this.copy(cipherState = cipherState.initializeKey(tempk1), ck = ck1)
    }

    fun mixHash(data: ByteArray): SymmetricState {
        return this.copy(h = hashFunctions.hash(h + data))
    }

    fun encryptAndHash(plaintext: ByteArray): Pair<SymmetricState, ByteArray> {
        val (cipherstate1, ciphertext) = cipherState.encryptWithAd(h, plaintext)
        return Pair(this.copy(cipherState = cipherstate1).mixHash(ciphertext), ciphertext)
    }

    fun decryptAndHash(ciphertext: ByteArray): Pair<SymmetricState, ByteArray> {
        val (cipherstate1, plaintext) = cipherState.decryptWithAd(h, ciphertext)
        return Pair(this.copy(cipherState = cipherstate1).mixHash(ciphertext), plaintext)
    }

    fun split(): Triple<CipherState, CipherState, ByteArray> {
        val (tempk1, tempk2) = hashFunctions.hkdf(ck, ByteArray(0))
        return Triple(cipherState.initializeKey(tempk1.take(32).toByteArray()), cipherState.initializeKey(tempk2.take(32).toByteArray()), ck)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        //if (javaClass != other?.javaClass) return false

        other as SymmetricState

        if (cipherState != other.cipherState) return false
        if (!ck.contentEquals(other.ck)) return false
        if (!h.contentEquals(other.h)) return false
        if (hashFunctions != other.hashFunctions) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cipherState.hashCode()
        result = 31 * result + ck.contentHashCode()
        result = 31 * result + h.contentHashCode()
        result = 31 * result + hashFunctions.hashCode()
        return result
    }

    companion object {
        fun apply(protocolName: ByteArray, cipherFunctions: CipherFunctions, hashFunctions: HashFunctions): SymmetricState {
            val h = if (protocolName.size <= hashFunctions.hashLen())
                protocolName + ByteArray(hashFunctions.hashLen() - protocolName.size)
            else hashFunctions.hash(protocolName)

            return SymmetricState(
                CipherState.apply(
                    cipherFunctions
                ), ck = h, h = h, hashFunctions = hashFunctions
            )
        }
    }
}

enum class MessagePattern {
    S, E, EE, ES, SE, SS
}

data class HandshakePattern(val name: String, val initiatorPreMessages: List<MessagePattern>, val responderPreMessages: List<MessagePattern>, val messages: List<List<MessagePattern>>) {
    init {
        require(
            isValidInitiator(
                initiatorPreMessages
            )
        ) { "invalid initiator messages" }
        require(
            isValidInitiator(
                responderPreMessages
            )
        ) { "invalid responder messages" }
    }

    companion object {
        val validInitiatorPatterns: Set<List<MessagePattern>> = setOf(
            listOf<MessagePattern>(), listOf(
                MessagePattern.E
            ), listOf(MessagePattern.S), listOf(
                MessagePattern.E,
                MessagePattern.S
            )
        )

        fun isValidInitiator(initiator: List<MessagePattern>): Boolean = validInitiatorPatterns.contains(initiator)
    }
}

/**
 * standard handshake patterns
 */

val handshakePatternNN = HandshakePattern(
    "NN",
    initiatorPreMessages = listOf<MessagePattern>(),
    responderPreMessages = listOf<MessagePattern>(),
    messages = listOf(
        listOf(MessagePattern.E),
        listOf(
            MessagePattern.E,
            MessagePattern.EE
        )
    )
)

val handshakePatternXK = HandshakePattern(
    "XK",
    initiatorPreMessages = listOf<MessagePattern>(),
    responderPreMessages = listOf(MessagePattern.S),
    messages = listOf(
        listOf(
            MessagePattern.E,
            MessagePattern.ES
        ),
        listOf(
            MessagePattern.E,
            MessagePattern.EE
        ),
        listOf(
            MessagePattern.S,
            MessagePattern.SE
        )
    )
)

interface ByteStream {
    fun nextBytes(length: Int): ByteArray
}

object RandomBytes : ByteStream {
    override fun nextBytes(length: Int) = randomBytes(length)
}


sealed class HandshakeState {
    @ExperimentalStdlibApi
    companion object {
        private fun makeSymmetricState(handshakePattern: HandshakePattern, prologue: ByteArray, dh: DHFunctions, cipher: CipherFunctions, hash: HashFunctions): SymmetricState {
            val name = "Noise_${handshakePattern.name}_${dh.name()}_${cipher.name()}_${hash.name()}"
            val symmetricState = SymmetricState.apply(
                name.encodeToByteArray(),
                cipher,
                hash
            )
            return symmetricState.mixHash(prologue)
        }

        fun initializeWriter(
            handshakePattern: HandshakePattern,
            prologue: ByteArray,
            s: Pair<ByteArray, ByteArray>,
            e: Pair<ByteArray, ByteArray>,
            rs: ByteArray,
            re: ByteArray,
            dh: DHFunctions,
            cipher: CipherFunctions,
            hash: HashFunctions,
            byteStream: ByteStream = RandomBytes
        ): HandshakeStateWriter {
            val symmetricState =
                makeSymmetricState(
                    handshakePattern,
                    prologue,
                    dh,
                    cipher,
                    hash
                )
            val symmetricState1 = handshakePattern.initiatorPreMessages.fold(symmetricState, { state, pattern ->
                when (pattern) {
                    MessagePattern.E -> state.mixHash(e.first)
                    MessagePattern.S -> state.mixHash(s.first)
                    else -> throw RuntimeException("invalid pre-message")
                }
            })
            val symmetricState2 = handshakePattern.responderPreMessages.fold(symmetricState1, { state, pattern ->
                when (pattern) {
                    MessagePattern.E -> state.mixHash(re)
                    MessagePattern.S -> state.mixHash(rs)
                    else -> throw RuntimeException("invalid pre-message")
                }
            })
            return HandshakeStateWriter(
                handshakePattern.messages,
                symmetricState2,
                s,
                e,
                rs,
                re,
                dh,
                byteStream
            )
        }

        fun initializeReader(
            handshakePattern: HandshakePattern,
            prologue: ByteArray,
            s: Pair<ByteArray, ByteArray>,
            e: Pair<ByteArray, ByteArray>,
            rs: ByteArray,
            re: ByteArray,
            dh: DHFunctions,
            cipher: CipherFunctions,
            hash: HashFunctions,
            byteStream: ByteStream = RandomBytes
        ): HandshakeStateReader {
            val symmetricState =
                makeSymmetricState(
                    handshakePattern,
                    prologue,
                    dh,
                    cipher,
                    hash
                )
            val symmetricState1 = handshakePattern.initiatorPreMessages.fold(symmetricState, { state, pattern ->
                when (pattern) {
                    MessagePattern.E -> state.mixHash(re)
                    MessagePattern.S -> state.mixHash(rs)
                    else -> throw RuntimeException("invalid pre-message")
                }
            })
            val symmetricState2 = handshakePattern.responderPreMessages.fold(symmetricState1, { state, pattern ->
                when (pattern) {
                    MessagePattern.E -> state.mixHash(e.first)
                    MessagePattern.S -> state.mixHash(s.first)
                    else -> throw RuntimeException("invalid pre-message")
                }
            })
            return HandshakeStateReader(
                handshakePattern.messages,
                symmetricState2,
                s,
                e,
                rs,
                re,
                dh,
                byteStream
            )
        }

    }
}

data class HandshakeStateWriter(
    val messages: List<List<MessagePattern>>,
    val state: SymmetricState,
    val s: Pair<ByteArray, ByteArray>,
    val e: Pair<ByteArray, ByteArray>,
    val rs: ByteArray,
    val re: ByteArray,
    val dh: DHFunctions,
    val byteStream: ByteStream
) : HandshakeState() {

    fun toReader(): HandshakeStateReader =
        HandshakeStateReader(
            messages,
            state,
            s,
            e,
            rs,
            re,
            dh,
            byteStream
        )

    /**
     *
     * @param payload input message (can be empty)
     * @return a (reader, output, Option[(cipherstate, cipherstate)] tuple.
     *         The output will be sent to the other side, and we will read its answer using the returned reader instance
     *         When the handshake is over (i.e. there are no more handshake patterns to process) the last item will
     *         contain 2 cipherstates than can be used to encrypt/decrypt further communication
     */
    fun write(payload: ByteArray): Triple<HandshakeStateReader, ByteArray, Triple<CipherState, CipherState, ByteArray>?> {
        val (writer1, buffer1) = messages.first().fold(Pair(this, ByteArray(0)), { (writer, buffer), pattern ->
            when (pattern) {
                MessagePattern.E -> {
                    val e1 = dh.generateKeyPair(byteStream.nextBytes(dh.dhLen()))
                    val state1 = writer.state.mixHash(e1.first)
                    Pair(writer.copy(state = state1, e = e1), buffer + e1.first)
                }
                MessagePattern.S -> {
                    val (state1, ciphertext) = writer.state.encryptAndHash(s.first)
                    Pair(writer.copy(state = state1), buffer + ciphertext)
                }
                MessagePattern.EE -> {
                    val state1 = writer.state.mixKey(dh.dh(writer.e, writer.re))
                    Pair(writer.copy(state = state1), buffer)
                }
                MessagePattern.SS -> {
                    val state1 = writer.state.mixKey(dh.dh(writer.s, writer.rs))
                    Pair(writer.copy(state = state1), buffer)
                }
                MessagePattern.ES -> {
                    val state1 = writer.state.mixKey(dh.dh(writer.e, writer.rs))
                    Pair(writer.copy(state = state1), buffer)
                }
                MessagePattern.SE -> {
                    val state1 = writer.state.mixKey(dh.dh(writer.s, writer.re))
                    Pair(writer.copy(state = state1), buffer)
                }
            }
        })

        val (state1, ciphertext) = writer1.state.encryptAndHash(payload)
        val buffer2 = buffer1 + ciphertext
        val writer2 = writer1.copy(messages = messages.drop(1), state = state1)

        return Triple(writer2.toReader(), buffer2, if (messages.drop(1).isEmpty()) writer2.state.split() else null)
    }

    companion object {
        fun apply(messages: List<List<MessagePattern>>, state: SymmetricState, s: Pair<ByteArray, ByteArray>, e: Pair<ByteArray, ByteArray>, rs: ByteArray, re: ByteArray, dh: DHFunctions): HandshakeStateWriter =
            HandshakeStateWriter(
                messages,
                state,
                s,
                e,
                rs,
                re,
                dh,
                RandomBytes
            )
    }
}


data class HandshakeStateReader(
    val messages: List<List<MessagePattern>>,
    val state: SymmetricState,
    val s: Pair<ByteArray, ByteArray>,
    val e: Pair<ByteArray, ByteArray>,
    val rs: ByteArray,
    val re: ByteArray,
    val dh: DHFunctions,
    val byteStream: ByteStream
) : HandshakeState() {
    fun toWriter(): HandshakeStateWriter =
        HandshakeStateWriter(
            messages,
            state,
            s,
            e,
            rs,
            re,
            dh,
            byteStream
        )

    /** *
     *
     * @param message input message
     * @return a (writer, payload, Option[(cipherstate, cipherstate)] tuple.
     *         The payload contains the original payload used by the sender and a writer that will be used to create the
     *         next message. When the handshake is over (i.e. there are no more handshake patterns to process) the last item will
     *         contain 2 cipherstates than can be used to encrypt/decrypt further communication
     */
    fun read(message: ByteArray): Triple<HandshakeStateWriter, ByteArray, Triple<CipherState, CipherState, ByteArray>?> {
        val (reader1, buffer1) = messages.first().fold(Pair(this, message), { (reader, buffer), pattern ->
            when (pattern) {
                MessagePattern.E -> {
                    val (re1, buffer1) = buffer.splitAt(dh.pubKeyLen())
                    val state1 = reader.state.mixHash(re1)
                    Pair(reader.copy(state = state1, re = re1), buffer1)
                }
                MessagePattern.S -> {
                    val len = if (reader.state.cipherState.hasKey()) dh.pubKeyLen() + 16 else dh.pubKeyLen()
                    val (temp, buffer1) = buffer.splitAt(len)
                    val (state1, rs1) = reader.state.decryptAndHash(temp)
                    Pair(reader.copy(state = state1, rs = rs1), buffer1)
                }
                MessagePattern.EE -> {
                    val state1 = reader.state.mixKey(dh.dh(reader.e, reader.re))
                    Pair(reader.copy(state = state1), buffer)
                }
                MessagePattern.SS -> {
                    val state1 = reader.state.mixKey(dh.dh(reader.s, reader.rs))
                    Pair(reader.copy(state = state1), buffer)
                }
                MessagePattern.ES -> {
                    val ss = dh.dh(reader.s, reader.re)
                    val state1 = reader.state.mixKey(ss)
                    Pair(reader.copy(state = state1), buffer)
                }
                MessagePattern.SE -> {
                    val state1 = reader.state.mixKey(dh.dh(reader.e, reader.rs))
                    Pair(reader.copy(state = state1), buffer)
                }
            }
        })

        val (state1, payload) = reader1.state.decryptAndHash(buffer1)
        val reader2 = reader1.copy(messages = messages.drop(1), state = state1)
        return Triple(reader2.toWriter(), payload, if (messages.drop(1).isEmpty()) reader2.state.split() else null)
    }

    companion object {
        private fun ByteArray.splitAt(n: Int): Pair<ByteArray, ByteArray> = Pair(this.take(n).toByteArray(), this.drop(n).toByteArray())
        fun apply(messages: List<List<MessagePattern>>, state: SymmetricState, s: Pair<ByteArray, ByteArray>, e: Pair<ByteArray, ByteArray>, rs: ByteArray, re: ByteArray, dh: DHFunctions): HandshakeStateReader =
            HandshakeStateReader(
                messages,
                state,
                s,
                e,
                rs,
                re,
                dh,
                RandomBytes
            )
    }
}
