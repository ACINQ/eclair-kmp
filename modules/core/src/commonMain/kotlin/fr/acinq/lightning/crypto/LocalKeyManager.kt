package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.DeterministicWallet.hardened
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.lightning.Lightning.secureRandom
import fr.acinq.lightning.crypto.LocalKeyManager.Companion.channelKeyPath

/**
 * An implementation of [KeyManager] that supports deterministic derivation for [KeyManager.ChannelKeys] based
 * on the initial funding pubkey.
 *
 * Specifically, for channel keys there are two paths:
 *   - `fundingKeyPath`: chosen at random using [newFundingKeyPath]
 *   - `channelKeyPath`: computed from `fundingKeyPath` using [channelKeyPath]
 *
 * The resulting paths looks like so on mainnet:
 * ```
 *  node key:
 *       50' / 0'
 *
 *  funding keys:
 *       50' / 1' / <fundingKeyPath> / <0' or 1'> / <index>'
 *
 *  others channel basepoint keys (payment, revocation, htlc, etc.):
 *       50' / 1' / <channelKeyPath> / <1'-5'>
 *
 *  bip-84 on-chain keys:
 *       84' / 0' / <account>' / <0' or 1'> / <index>
 * ```
 *
 * @param seed seed from which the channel keys will be derived
 * @param remoteSwapInExtendedPublicKey xpub belonging to our swap-in server, that must be used in our swap address
 */
data class LocalKeyManager(val seed: ByteVector, val chain: Chain, val remoteSwapInExtendedPublicKey: String) : KeyManager {

    private val master = DeterministicWallet.generate(seed)

    override val nodeKeys: KeyManager.NodeKeys = KeyManager.NodeKeys(
        nodeKey = master.derivePrivateKey(nodeKeyBasePath(chain)),
    )

    override val finalOnChainWallet: KeyManager.Bip84OnChainKeys = KeyManager.Bip84OnChainKeys(chain, master, account = 0)
    override val swapInOnChainWallet: KeyManager.SwapInOnChainKeys = run {
        val (prefix, xpub) = DeterministicWallet.ExtendedPublicKey.decode(remoteSwapInExtendedPublicKey)
        val expectedPrefix = when (chain) {
            Chain.Mainnet -> DeterministicWallet.xpub
            else -> DeterministicWallet.tpub
        }
        require(prefix == expectedPrefix) { "unexpected swap-in xpub prefix $prefix (expected $expectedPrefix)" }
        val remoteSwapInPublicKey = xpub.derivePublicKey(KeyManager.SwapInOnChainKeys.perUserPath(nodeKeys.nodeKey.publicKey)).publicKey
        KeyManager.SwapInOnChainKeys(chain, master, remoteSwapInPublicKey)
    }

    private val channelKeyBasePath: KeyPath = channelKeyBasePath(chain)

    /**
     * This method offers direct access to the master key derivation. It should only be used for some advanced usage
     * like (LNURL-auth, data encryption).
     */
    fun derivePrivateKey(keyPath: KeyPath): DeterministicWallet.ExtendedPrivateKey = master.derivePrivateKey(keyPath)

    fun privateKey(keyPath: KeyPath): PrivateKey = master.derivePrivateKey(keyPath).privateKey

    override fun newFundingKeyPath(isInitiator: Boolean): KeyPath {
        val last = hardened(if (isInitiator) 1 else 0)
        fun next() = secureRandom.nextInt().toLong() and 0xFFFFFFFF
        return KeyPath.empty / next() / next() / next() / next() / next() / next() / next() / next() / last
    }

    override fun channelKeys(fundingKeyPath: KeyPath): KeyManager.ChannelKeys {
        // We use a different funding key for each splice, with a derivation based on the fundingTxIndex.
        val fundingKey: (Long) -> PrivateKey = { index -> master.derivePrivateKey(channelKeyBasePath / fundingKeyPath / hardened(index)).privateKey }
        // We use the initial funding pubkey to compute the channel key path, and we use the recovery process even
        // in the normal case, which guarantees it works all the time.
        val initialFundingPubkey = fundingKey(0).publicKey()
        val recoveredChannelKeys = recoverChannelKeys(initialFundingPubkey)
        return KeyManager.ChannelKeys(
            fundingKeyPath,
            fundingKey = fundingKey,
            paymentKey = recoveredChannelKeys.paymentKey,
            delayedPaymentKey = recoveredChannelKeys.delayedPaymentKey,
            htlcKey = recoveredChannelKeys.htlcKey,
            revocationKey = recoveredChannelKeys.revocationKey,
            shaSeed = recoveredChannelKeys.shaSeed
        )
    }

    /**
     * Generate channel-specific keys and secrets (note that we cannot re-compute the channel's funding private key)
     * @params fundingPubKey funding public key
     * @return channel keys and secrets
     */
    fun recoverChannelKeys(fundingPubKey: PublicKey): RecoveredChannelKeys {
        val channelKeyPrefix = channelKeyBasePath / channelKeyPath(fundingPubKey)
        return RecoveredChannelKeys(
            fundingPubKey,
            paymentKey = privateKey(channelKeyPrefix / hardened(2)),
            delayedPaymentKey = privateKey(channelKeyPrefix / hardened(3)),
            htlcKey = privateKey(channelKeyPrefix / hardened(4)),
            revocationKey = privateKey(channelKeyPrefix / hardened(1)),
            shaSeed = privateKey(channelKeyPrefix / hardened(5)).value.concat(1).sha256()
        )
    }

    /**
     * Channel keys recovered from the channel's funding public key (note that we cannot recover the funding private key).
     * These keys can be used to spend our outputs from a commit tx that has been published to the blockchain, without any other information than
     * the node's seed ("backup less backup")
     */
    data class RecoveredChannelKeys(
        val fundingPubKey: PublicKey,
        val paymentKey: PrivateKey,
        val delayedPaymentKey: PrivateKey,
        val htlcKey: PrivateKey,
        val revocationKey: PrivateKey,
        val shaSeed: ByteVector32
    ) {
        val htlcBasepoint: PublicKey = htlcKey.publicKey()
        val paymentBasepoint: PublicKey = paymentKey.publicKey()
        val delayedPaymentBasepoint: PublicKey = delayedPaymentKey.publicKey()
        val revocationBasepoint: PublicKey = revocationKey.publicKey()
    }

    override fun toString(): String = "LocalKeyManager(seed=<redacted>,chain=$chain)"

    /**
     * WARNING: If you change the paths below, keys will change (including your node id) even if the seed remains the same!!!
     * Note that the node path and the above channel path are on different branches so even if the
     * node key is compromised there is no way to retrieve the wallet keys
     */
    companion object {

        /**
         * Create a BIP32 path from a public key. This path will be used to derive channel keys.
         * Having channel keys derived from the funding public keys makes it very easy to retrieve your funds when you've lost your data:
         * - connect to your peer and use DLP to get them to publish their remote commit tx
         * - retrieve the commit tx from the bitcoin network, extract your funding pubkey from its witness data
         * - recompute your channel keys and spend your output
         *
         * @param fundingPubKey funding public key
         * @return a BIP32 path
         */
        fun channelKeyPath(fundingPubKey: PublicKey): KeyPath {
            val buffer = fundingPubKey.value.sha256().toByteArray()
            val path = (0 until 8).map { i -> Pack.int32BE(buffer, 4 * i).toUInt().toLong() }
            return KeyPath(path)
        }

        fun channelKeyBasePath(chain: Chain) = when (chain) {
            Chain.Testnet4, Chain.Testnet3, Chain.Regtest, Chain.Signet -> KeyPath.empty / hardened(48) / hardened(1)
            Chain.Mainnet -> KeyPath.empty / hardened(50) / hardened(1)
        }

        fun nodeKeyBasePath(chain: Chain) = when (chain) {
            Chain.Testnet4, Chain.Testnet3, Chain.Regtest, Chain.Signet -> KeyPath.empty / hardened(48) / hardened(0)
            Chain.Mainnet -> KeyPath.empty / hardened(50) / hardened(0)
        }
    }
}

infix operator fun KeyPath.div(index: Long): KeyPath = this.append(index)

infix operator fun KeyPath.div(other: KeyPath): KeyPath = this.append(other)
