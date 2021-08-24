package fr.acinq.lightning.channel

import fr.acinq.bitcoin.ByteVector
import fr.acinq.lightning.utils.BitField
import kotlinx.serialization.Serializable

/**
 * Internal configuration option impacting the channel's structure or behavior.
 * This must be set when creating the channel and cannot be changed afterwards.
 */
@Serializable
sealed class ChannelConfigOption {

    abstract val name: String
    abstract val supportBit: Int

    /**
     * If set, the channel's BIP32 key path will be deterministically derived from the funding public key.
     * It makes it very easy to retrieve funds when channel data has been lost:
     *  - connect to your peer and use option_data_loss_protect to get them to publish their remote commit tx
     *  - retrieve the commit tx from the bitcoin network, extract your funding pubkey from its witness data
     *  - recompute your channel keys and spend your output
     */
    @Serializable
    object FundingPubKeyBasedChannelKeyPath : ChannelConfigOption() {
        override val name: String get() = "funding_pubkey_based_channel_keypath"
        override val supportBit: Int get() = 0
    }

}

@Serializable
data class ChannelConfig(val options: Set<ChannelConfigOption>) {

    fun hasOption(option: ChannelConfigOption): Boolean = options.contains(option)

    fun toByteArray(): ByteArray {
        val bits = options.map { it.supportBit }.toHashSet()
        if (bits.isEmpty()) return ByteArray(0)

        val buf = BitField.forAtMost(bits.maxOrNull()!! + 1)
        bits.forEach { buf.setRight(it) }
        return buf.bytes
    }

    companion object {
        val standard = ChannelConfig(setOf(ChannelConfigOption.FundingPubKeyBasedChannelKeyPath))

        private val allOptions = setOf<ChannelConfigOption>(
            ChannelConfigOption.FundingPubKeyBasedChannelKeyPath
        )

        operator fun invoke(vararg options: ChannelConfigOption): ChannelConfig = ChannelConfig(setOf(*options))

        operator fun invoke(bytes: ByteVector): ChannelConfig = invoke(bytes.toByteArray())

        operator fun invoke(bytes: ByteArray): ChannelConfig = invoke(BitField.from(bytes))

        operator fun invoke(bits: BitField): ChannelConfig {
            val options = bits.asRightSequence()
                .withIndex()
                .filter { it.value }
                .map { (idx, _) -> allOptions.find { it.supportBit == idx } }
                .filterNotNull()
                .toSet()
            return ChannelConfig(options)
        }

    }
}