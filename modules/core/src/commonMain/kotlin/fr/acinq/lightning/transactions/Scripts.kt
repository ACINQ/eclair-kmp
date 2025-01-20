package fr.acinq.lightning.transactions

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.ScriptEltMapping.code2elt
import fr.acinq.bitcoin.crypto.musig2.Musig2
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.transactions.Transactions.NUMS_POINT
import fr.acinq.lightning.utils.sat

/**
 * Created by PM on 02/12/2016.
 */
object Scripts {

    fun der(sig: ByteVector64, sigHash: Int): ByteVector = Crypto.compact2der(sig).concat(sigHash.toByte())

    fun multiSig2of2(pubkey1: PublicKey, pubkey2: PublicKey): List<ScriptElt> =
        if (LexicographicalOrdering.isLessThan(pubkey1.value, pubkey2.value)) {
            Script.createMultiSigMofN(2, listOf(pubkey1, pubkey2))
        } else {
            Script.createMultiSigMofN(2, listOf(pubkey2, pubkey1))
        }

    /**
     * @return a script witness that matches the msig 2-of-2 pubkey script for pubkey1 and pubkey2
     */
    fun witness2of2(sig1: ByteVector64, sig2: ByteVector64, pubkey1: PublicKey, pubkey2: PublicKey): ScriptWitness =
        if (LexicographicalOrdering.isLessThan(pubkey1.value, pubkey2.value)) {
            ScriptWitness(listOf(ByteVector.empty, der(sig1, SigHash.SIGHASH_ALL), der(sig2, SigHash.SIGHASH_ALL), ByteVector(Script.write(multiSig2of2(pubkey1, pubkey2)))))
        } else {
            ScriptWitness(listOf(ByteVector.empty, der(sig2, SigHash.SIGHASH_ALL), der(sig1, SigHash.SIGHASH_ALL), ByteVector(Script.write(multiSig2of2(pubkey1, pubkey2)))))
        }

    fun sort(pubkeys: List<PublicKey>): List<PublicKey> = pubkeys.sortedWith { a, b -> LexicographicalOrdering.compare(a, b) }

    fun musig2Aggregate(pubkey1: PublicKey, pubkey2: PublicKey): XonlyPublicKey = Musig2.aggregateKeys(sort(listOf(pubkey1, pubkey2)))

    fun musig2FundingScript(pubkey1: PublicKey, pubkey2: PublicKey): List<ScriptElt> = Script.pay2tr(musig2Aggregate(pubkey1, pubkey2), null as ByteVector32?)

    /**
     * minimal encoding of a number into a script element:
     * - OP_0 to OP_16 if 0 <= n <= 16
     * - OP_PUSHDATA(encodeNumber(n)) otherwise
     *
     * @param n input number
     * @return a script element that represents n
     */
    fun encodeNumber(n: Long): ScriptElt = when (n) {
        0L -> OP_0
        -1L -> OP_1NEGATE
        in 1..16 -> code2elt.getValue(OP_1.code + n.toInt() - 1)
        else -> OP_PUSHDATA(Script.encodeNumber(n))
    }

    fun applyFees(amount_us: Satoshi, amount_them: Satoshi, fee: Satoshi): Pair<Satoshi, Satoshi> =
        when {
            amount_us >= fee / 2 && amount_them >= fee / 2 -> Pair((amount_us - fee) / 2, (amount_them - fee) / 2)
            amount_us < fee / 2 -> Pair(0.sat, (amount_them - fee + amount_us).max(0.sat))
            amount_them < fee / 2 -> Pair((amount_us - fee + amount_them).max(0.sat), 0.sat)
            else -> error("impossible")
        }

    /**
     * This function interprets the locktime for the given transaction, and returns the block height before which this tx cannot be published.
     * By convention in bitcoin, depending of the value of locktime it might be a number of blocks or a number of seconds since epoch.
     * This function does not support the case when the locktime is a number of seconds that is not way in the past.
     * NB: We use this property in lightning to store data in this field.
     *
     * @return the block height before which this tx cannot be published.
     */
    fun cltvTimeout(tx: Transaction): Long =
        if (tx.lockTime <= Script.LOCKTIME_THRESHOLD) {
            // locktime is a number of blocks
            tx.lockTime
        } else {
            // locktime is a unix epoch timestamp
            require(tx.lockTime <= 0x20FFFFFF) { "locktime should be lesser than 0x20FFFFFF" }
            // since locktime is very well in the past (0x20FFFFFF is in 1987), it is equivalent to no locktime at all
            0
        }

    /**
     * @return the number of confirmations of the tx parent before which it can be published
     */
    fun csvTimeout(tx: Transaction): Long {
        fun sequenceToBlockHeight(sequence: Long) =
            if ((sequence and TxIn.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0L) 0L
            else {
                require((sequence and TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG) == 0L) { "CSV timeout must use block heights, not block times" }
                sequence and TxIn.SEQUENCE_LOCKTIME_MASK
            }

        return if (tx.version < 2) 0L else tx.txIn.map { it.sequence }.map { sequenceToBlockHeight(it) }.maxOrNull()!!
    }

    fun toAnchor(fundingPubkey: PublicKey): List<ScriptElt> =
        // @formatter:off
        listOf(
            OP_PUSHDATA(fundingPubkey),
            OP_CHECKSIG,
            OP_IFDUP,
            OP_NOTIF,
                OP_16, OP_CHECKSEQUENCEVERIFY,
            OP_ENDIF
        )
        // @formatter:on

    fun toLocalDelayed(revocationPubkey: PublicKey, toSelfDelay: CltvExpiryDelta, localDelayedPaymentPubkey: PublicKey): List<ScriptElt> =
        // @formatter:off
        listOf(
            OP_IF,
                OP_PUSHDATA(revocationPubkey),
            OP_ELSE,
                encodeNumber(toSelfDelay.toLong()), OP_CHECKSEQUENCEVERIFY, OP_DROP,
                OP_PUSHDATA(localDelayedPaymentPubkey),
            OP_ENDIF,
            OP_CHECKSIG
        )
        // @formatter:on

    fun toRemoteDelayed(pub: PublicKey): List<ScriptElt> = listOf(OP_PUSHDATA(pub), OP_CHECKSIGVERIFY, OP_1, OP_CHECKSEQUENCEVERIFY)

    /**
     * This witness script spends a [[toLocalDelayed]] output using a local sig after a delay
     */
    fun witnessToRemoteDelayedAfterDelay(localSig: ByteVector64, toRemoteDelayedScript: ByteVector) =
        ScriptWitness(listOf(der(localSig, SigHash.SIGHASH_ALL), toRemoteDelayedScript))

    /**
     * This witness script spends a [[toLocalDelayed]] output using a local sig after a delay
     */
    fun witnessToLocalDelayedAfterDelay(localSig: ByteVector64, toLocalDelayedScript: ByteVector) =
        ScriptWitness(listOf(der(localSig, SigHash.SIGHASH_ALL), ByteVector.empty, toLocalDelayedScript))

    /**
     * This witness script spends (steals) a [[toLocalDelayed]] output using a revocation key as a punishment
     * for having published a revoked transaction
     */
    fun witnessToLocalDelayedWithRevocationSig(revocationSig: ByteVector64, toLocalScript: ByteVector) =
        ScriptWitness(listOf(der(revocationSig, SigHash.SIGHASH_ALL), ByteVector(byteArrayOf(1)), toLocalScript))

    fun htlcOffered(localHtlcPubkey: PublicKey, remoteHtlcPubkey: PublicKey, revocationPubKey: PublicKey, paymentHash: ByteArray): List<ScriptElt> = listOf(
        // @formatter:off
        // To you with revocation key
        OP_DUP, OP_HASH160, OP_PUSHDATA(revocationPubKey.hash160()), OP_EQUAL,
        OP_IF,
            OP_CHECKSIG,
        OP_ELSE,
            OP_PUSHDATA(remoteHtlcPubkey), OP_SWAP, OP_SIZE, encodeNumber(32), OP_EQUAL,
            OP_NOTIF,
                // To me via HTLC-timeout transaction (timelocked).
                OP_DROP, OP_2, OP_SWAP, OP_PUSHDATA(localHtlcPubkey), OP_2, OP_CHECKMULTISIG,
            OP_ELSE,
                OP_HASH160, OP_PUSHDATA(paymentHash), OP_EQUALVERIFY,
                OP_CHECKSIG,
            OP_ENDIF,
            OP_1, OP_CHECKSEQUENCEVERIFY, OP_DROP,
        OP_ENDIF
        // @formatter:on
    )

    /**
     * This is the witness script of the 2nd-stage HTLC Success transaction (consumes htlcOffered script from commit tx)
     * local signature is created with SIGHASH_ALL flag
     * remote signature is created with SIGHASH_SINGLE || SIGHASH_ANYONECANPAY
     */
    fun witnessHtlcSuccess(localSig: ByteVector64, remoteSig: ByteVector64, paymentPreimage: ByteVector32, htlcOfferedScript: ByteVector) =
        ScriptWitness(listOf(ByteVector.empty, der(remoteSig, SigHash.SIGHASH_SINGLE or SigHash.SIGHASH_ANYONECANPAY), der(localSig, SigHash.SIGHASH_ALL), paymentPreimage, htlcOfferedScript))

    /** Extract the payment preimage from a 2nd-stage HTLC Success transaction's witness script */
    fun extractPreimageFromHtlcSuccess(): (ScriptWitness) -> ByteVector32? = f@{
        if (it.stack.size < 5 || !it.stack[0].isEmpty()) return@f null
        val paymentPreimage = it.stack[3]
        if (paymentPreimage.size() != 32) return@f null
        ByteVector32(paymentPreimage)
    }

    /**
     * If remote publishes its commit tx where there was a remote->local htlc, then local uses this script to
     * claim its funds using a payment preimage (consumes htlcOffered script from commit tx)
     */
    fun witnessClaimHtlcSuccessFromCommitTx(localSig: ByteVector64, paymentPreimage: ByteVector32, htlcOffered: ByteVector) =
        ScriptWitness(listOf(der(localSig, SigHash.SIGHASH_ALL), paymentPreimage, htlcOffered))

    /** Extract the payment preimage from from a fulfilled offered htlc. */
    fun extractPreimageFromClaimHtlcSuccess(): (ScriptWitness) -> ByteVector32? = f@{
        if (it.stack.size < 3) return@f null
        val paymentPreimage = it.stack[1]
        if (paymentPreimage.size() != 32) return@f null
        ByteVector32(paymentPreimage)
    }

    fun htlcReceived(localHtlcPubkey: PublicKey, remoteHtlcPubkey: PublicKey, revocationPubKey: PublicKey, paymentHash: ByteArray, lockTime: CltvExpiry) = listOf(
        // @formatter:off
        // To you with revocation key
        OP_DUP, OP_HASH160, OP_PUSHDATA(revocationPubKey.hash160()), OP_EQUAL,
        OP_IF,
            OP_CHECKSIG,
        OP_ELSE,
            OP_PUSHDATA(remoteHtlcPubkey), OP_SWAP, OP_SIZE, encodeNumber(32), OP_EQUAL,
            OP_IF,
                // To me via HTLC-success transaction.
                OP_HASH160, OP_PUSHDATA(paymentHash), OP_EQUALVERIFY,
                OP_2, OP_SWAP, OP_PUSHDATA(localHtlcPubkey), OP_2, OP_CHECKMULTISIG,
            OP_ELSE,
                // To you after timeout.
                OP_DROP, encodeNumber(lockTime.toLong()), OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                OP_CHECKSIG,
            OP_ENDIF,
            OP_1, OP_CHECKSEQUENCEVERIFY, OP_DROP,
        OP_ENDIF
        // @formatter:on
    )

    /**
     * This is the witness script of the 2nd-stage HTLC Timeout transaction (consumes htlcOffered script from commit tx)
     * local signature is created with SIGHASH_ALL
     * remote signature is created with SIGHASH_SINGLE || SIGHASH_ANYONECANPAY
     */
    fun witnessHtlcTimeout(localSig: ByteVector64, remoteSig: ByteVector64, htlcOfferedScript: ByteVector) =
        ScriptWitness(listOf(ByteVector.empty, der(remoteSig, SigHash.SIGHASH_SINGLE or SigHash.SIGHASH_ANYONECANPAY), der(localSig, SigHash.SIGHASH_ALL), ByteVector.empty, htlcOfferedScript))

    /** Extract the payment hash from a 2nd-stage HTLC Timeout transaction's witness script */
    fun extractPaymentHashFromHtlcTimeout(): (ScriptWitness) -> ByteVector? = f@{
        if (it.stack.size < 5 || !it.stack[0].isEmpty() || !it.stack[3].isEmpty()) return@f null
        val htlcOfferedScript = it.stack[4]
        htlcOfferedScript.slice(109, 109 + 20)
    }

    /**
     * If remote publishes its commit tx where there was a local->remote htlc, then local uses this script to
     * claim its funds after timeout (consumes htlcReceived script from commit tx)
     */
    fun witnessClaimHtlcTimeoutFromCommitTx(localSig: ByteVector64, htlcReceivedScript: ByteVector) =
        ScriptWitness(listOf(der(localSig, SigHash.SIGHASH_ALL), ByteVector.empty, htlcReceivedScript))

    /** Extract the payment hash from a timed-out received htlc. */
    fun extractPaymentHashFromClaimHtlcTimeout(): (ScriptWitness) -> ByteVector? = f@{
        if (it.stack.size < 3 || !it.stack[1].isEmpty()) return@f null
        val htlcReceivedScript = it.stack[2]
        htlcReceivedScript.slice(69, 69 + 20)
    }

    /**
     * This witness script spends (steals) a [[htlcOffered]] or [[htlcReceived]] output using a revocation key as a punishment
     * for having published a revoked transaction
     */
    fun witnessHtlcWithRevocationSig(revocationSig: ByteVector64, revocationPubkey: PublicKey, htlcScript: ByteVector) =
        ScriptWitness(listOf(der(revocationSig, SigHash.SIGHASH_ALL), revocationPubkey.value, htlcScript))

    /**
     * Specific scripts for taproot channels
     */
    object Taproot {
        val anchorScript: List<ScriptElt> = listOf(OP_16, OP_CHECKSEQUENCEVERIFY)

        val anchorScriptTree = ScriptTree.Leaf(anchorScript)

        fun toRevokeScript(revocationPubkey: PublicKey, localDelayedPaymentPubkey: PublicKey) =
            listOf(OP_PUSHDATA(localDelayedPaymentPubkey.xOnly()), OP_DROP, OP_PUSHDATA(revocationPubkey.xOnly()), OP_CHECKSIG)

        fun toDelayScript(localDelayedPaymentPubkey: PublicKey, toLocalDelay: CltvExpiryDelta) =
            listOf(OP_PUSHDATA(localDelayedPaymentPubkey.xOnly()), OP_CHECKSIG, encodeNumber(toLocalDelay.toLong()), OP_CHECKSEQUENCEVERIFY, OP_DROP)

        /**
         * Taproot channels to-local key, used for the delayed to-local output
         *
         * @param revocationPubkey          revocation key
         * @param toSelfDelay               self CsV delay
         * @param localDelayedPaymentPubkey local delayed payment key
         * @return an (XonlyPubkey, Parity) pair
         */
        fun toLocalKey(revocationPubkey: PublicKey, toSelfDelay: CltvExpiryDelta, localDelayedPaymentPubkey: PublicKey): Pair<XonlyPublicKey, Boolean> {
            val revokeScript = toRevokeScript(revocationPubkey, localDelayedPaymentPubkey)
            val delayScript = toDelayScript(localDelayedPaymentPubkey, toSelfDelay)
            val scriptTree = ScriptTree.Branch(
                ScriptTree.Leaf(delayScript),
                ScriptTree.Leaf(revokeScript),
            )
            return XonlyPublicKey(NUMS_POINT).outputKey(Crypto.TaprootTweak.ScriptTweak(scriptTree))
        }

        /**
         *
         * @param revocationPubkey          revocation key
         * @param toSelfDelay               to-self CSV delay
         * @param localDelayedPaymentPubkey local delayed payment key
         * @return a script tree with two leaves (to self with delay, and to revocation key)
         */
        fun toLocalScriptTree(revocationPubkey: PublicKey, toSelfDelay: CltvExpiryDelta, localDelayedPaymentPubkey: PublicKey): ScriptTree.Branch {
            return ScriptTree.Branch(
                ScriptTree.Leaf(toDelayScript(localDelayedPaymentPubkey, toSelfDelay)),
                ScriptTree.Leaf(toRevokeScript(revocationPubkey, localDelayedPaymentPubkey)),
            )
        }

        fun toRemoteScript(remotePaymentPubkey: PublicKey) = listOf(OP_PUSHDATA(remotePaymentPubkey.xOnly()), OP_CHECKSIG, OP_1, OP_CHECKSEQUENCEVERIFY, OP_DROP)

        /**
         * taproot channel to-remote key, used for the to-remote output
         *
         * @param remotePaymentPubkey remote key
         * @return a (XonlyPubkey, Parity) pair
         */
        fun toRemoteKey(remotePaymentPubkey: PublicKey): Pair<XonlyPublicKey, Boolean> {
            val remoteScript = toRemoteScript(remotePaymentPubkey)
            val scriptTree = ScriptTree.Leaf(remoteScript)
            return XonlyPublicKey(NUMS_POINT).outputKey(scriptTree)
        }

        /**
         *
         * @param remotePaymentPubkey remote key
         * @return a script tree with a single leaf (to remote key, with a 1-block CSV delay)
         */
        fun toRemoteScriptTree(remotePaymentPubkey: PublicKey) = ScriptTree.Leaf(toRemoteScript(remotePaymentPubkey))

        fun offeredHtlcTimeoutScript(localHtlcPubkey: PublicKey, remoteHtlcPubkey: PublicKey) = listOf(OP_PUSHDATA(localHtlcPubkey.xOnly()), OP_CHECKSIGVERIFY, OP_PUSHDATA(remoteHtlcPubkey.xOnly()), OP_CHECKSIG)

        fun offeredHtlcSuccessScript(remoteHtlcPubkey: PublicKey, paymentHash: ByteVector32) = listOf(
            // @formatter:off
            OP_SIZE, encodeNumber(32), OP_EQUALVERIFY,
            OP_HASH160, OP_PUSHDATA(Crypto.ripemd160(paymentHash)), OP_EQUALVERIFY,
            OP_PUSHDATA(remoteHtlcPubkey.xOnly()), OP_CHECKSIG,
            OP_1, OP_CHECKSEQUENCEVERIFY, OP_DROP
            // @formatter:on
        )

        fun offeredHtlcTree(localHtlcPubkey: PublicKey, remoteHtlcPubkey: PublicKey, paymentHash: ByteVector32) =
            ScriptTree.Branch(
                ScriptTree.Leaf(offeredHtlcTimeoutScript(localHtlcPubkey, remoteHtlcPubkey)),
                ScriptTree.Leaf(offeredHtlcSuccessScript(remoteHtlcPubkey, paymentHash))
            )

        fun receivedHtlcTimeoutScript(remoteHtlcPubkey: PublicKey, lockTime: CltvExpiry) = listOf(
            // @formatter:off
            OP_PUSHDATA(remoteHtlcPubkey.xOnly()), OP_CHECKSIG,
            OP_1, OP_CHECKSEQUENCEVERIFY, OP_DROP,
            encodeNumber(lockTime.toLong()), OP_CHECKLOCKTIMEVERIFY, OP_DROP
            // @formatter:on
        )

        fun receivedHtlcSuccessScript(localHtlcPubkey: PublicKey, remoteHtlcPubkey: PublicKey, paymentHash: ByteVector32) = listOf(
            // @formatter:off
            OP_SIZE, encodeNumber(32), OP_EQUALVERIFY,
            OP_HASH160, OP_PUSHDATA(Crypto.ripemd160(paymentHash)), OP_EQUALVERIFY,
            OP_PUSHDATA(localHtlcPubkey.xOnly()), OP_CHECKSIGVERIFY,
            OP_PUSHDATA(remoteHtlcPubkey.xOnly()), OP_CHECKSIG
            // @formatter:on
        )

        fun receivedHtlcTree(localHtlcPubkey: PublicKey, remoteHtlcPubkey: PublicKey, paymentHash: ByteVector32, lockTime: CltvExpiry): ScriptTree.Branch {
            return ScriptTree.Branch(
                ScriptTree.Leaf(receivedHtlcTimeoutScript(remoteHtlcPubkey, lockTime)),
                ScriptTree.Leaf(receivedHtlcSuccessScript(localHtlcPubkey, remoteHtlcPubkey, paymentHash)),
            )
        }
    }
}