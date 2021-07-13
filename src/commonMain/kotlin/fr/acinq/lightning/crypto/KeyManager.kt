package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.Crypto.sha256
import fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo

interface KeyManager {
    val nodeKey: DeterministicWallet.ExtendedPrivateKey

    val nodeId: PublicKey

    fun closingPubkeyScript(fundingPubKey: PublicKey): Pair<PublicKey, ByteArray>

    fun fundingPublicKey(keyPath: KeyPath): ExtendedPublicKey

    fun revocationPoint(channelKeyPath: KeyPath): ExtendedPublicKey

    fun paymentPoint(channelKeyPath: KeyPath): ExtendedPublicKey

    fun delayedPaymentPoint(channelKeyPath: KeyPath): ExtendedPublicKey

    fun htlcPoint(channelKeyPath: KeyPath): ExtendedPublicKey

    fun commitmentSecret(channelKeyPath: KeyPath, index: Long): PrivateKey

    fun commitmentPoint(channelKeyPath: KeyPath, index: Long): PublicKey

    fun commitmentSecret(shaSeed: ByteVector32, index: Long): PrivateKey

    fun commitmentPoint(shaSeed: ByteVector32, index: Long): PublicKey

    fun channelKeyPath(fundingKeyPath: KeyPath, channelConfig: ChannelConfig): KeyPath = when {
        // deterministic mode: use the funding pubkey to compute the channel key path
        channelConfig.hasOption(ChannelConfigOption.FundingPubKeyBasedChannelKeyPath) -> channelKeyPath(fundingPublicKey(fundingKeyPath))
        // legacy mode:  we reuse the funding key path as our channel key path
        else -> fundingKeyPath
    }

    fun channelKeyPath(localParams: LocalParams, channelConfig: ChannelConfig): KeyPath = channelKeyPath(localParams.channelKeys.fundingKeyPath, channelConfig)

    /**
     *
     * @param isFunder true if we're funding this channel
     * @return a partial key path for a new funding public key. This key path will be extended:
     *         - with a specific "chain" prefix
     *         - with a specific "funding pubkey" suffix
     */
    fun newFundingKeyPath(isFunder: Boolean): KeyPath

    /**
     * generate channel-specific keys and secrets
     * @params fundingKeyPath funding public key BIP32 path
     * @return channel keys and secrets
     */
    fun channelKeys(fundingKeyPath: KeyPath): ChannelKeys

    /**
     * generate channel-specific keys and secrets (note that we cannot re-compute the channel's funding private key)
     * @params fundingPubKey funding public key
     * @return channel keys and secrets
     */
    fun recoverChannelKeys(fundingPubKey: PublicKey): RecoveredChannelKeys

    /**
     *
     * @param tx        input transaction
     * @param privateKey private key
     * @return a signature generated with the input private key
     */
    fun sign(tx: TransactionWithInputInfo, privateKey: PrivateKey): ByteVector64

    /**
     * This method is used to spend funds send to htlc keys/delayed keys
     *
     * @param tx          input transaction
     * @param privateKey  private key
     * @param remotePoint remote point
     * @return a signature generated with a private key generated from the input private key and the remote point.
     */
    fun sign(tx: TransactionWithInputInfo, privateKey: PrivateKey, remotePoint: PublicKey, sigHash: Int): ByteVector64

    /**
     * Ths method is used to spend revoked transactions, with the corresponding revocation key
     *
     * @param tx           input transaction
     * @param privateKey   private key
     * @param remoteSecret remote secret
     * @return a signature generated with a private key generated from the input private key and the remote secret.
     */
    fun sign(tx: TransactionWithInputInfo, privateKey: PrivateKey, remoteSecret: PrivateKey): ByteVector64

    companion object {
        /**
         * Create a BIP32 path from a public key. This path will be used to derive channel keys.
         * Having channel keys derived from the funding public keys makes it very easy to retrieve your funds when've you've lost your data:
         * - connect to your peer and use DLP to get them to publish their remote commit tx
         * - retrieve the commit tx from the bitcoin network, extract your funding pubkey from its witness data
         * - recompute your channel keys and spend your output
         *
         * @param fundingPubKey funding public key
         * @return a BIP32 path
         */
        @OptIn(ExperimentalUnsignedTypes::class)
        fun channelKeyPath(fundingPubKey: PublicKey): KeyPath {
            val buffer = sha256(fundingPubKey.value)

            val path = sequence {
                var i = 0
                while (true) {
                    yield(Pack.int32BE(buffer, i).toUInt().toLong())
                    i += 4
                }
            }
            return KeyPath(path.take(8).toList())
        }

        fun channelKeyPath(fundingPubKey: ExtendedPublicKey): KeyPath = channelKeyPath(fundingPubKey.publicKey)
    }
}
