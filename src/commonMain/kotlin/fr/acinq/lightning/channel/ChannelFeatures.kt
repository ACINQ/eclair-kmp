package fr.acinq.lightning.channel

import fr.acinq.lightning.Feature
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.Features
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.Serializable

/**
 * Subset of Bolt 9 features used to configure a channel and applicable over the lifetime of that channel.
 * Even if one of these features is later disabled at the connection level, it will still apply to the channel until the
 * channel is upgraded or closed.
 */
@Serializable
data class ChannelFeatures(val activated: Set<Feature>) {

    val channelType: ChannelType.SupportedChannelType = when {
        activated.contains(Feature.AnchorOutputs) -> ChannelType.SupportedChannelType.AnchorOutputs
        activated.contains(Feature.StaticRemoteKey) -> ChannelType.SupportedChannelType.StaticRemoteKey
        else -> ChannelType.SupportedChannelType.Standard
    }

    fun hasFeature(feature: Feature): Boolean = activated.contains(feature)

    override fun toString(): String = activated.joinToString(",")

}

/** A channel type is a specific set of feature bits that represent persistent channel features as defined in Bolt 2. */
@Serializable
sealed class ChannelType {

    abstract val name: String
    abstract val features: Set<Feature>

    override fun toString(): String = name

    @Serializable
    sealed class SupportedChannelType : ChannelType() {

        fun toFeatures(): Features = Features(features.associateWith { FeatureSupport.Mandatory })

        @Serializable
        object Standard : SupportedChannelType() {
            override val name: String get() = "standard"
            override val features: Set<Feature> get() = setOf()
        }

        @Serializable
        object StaticRemoteKey : SupportedChannelType() {
            override val name: String get() = "static_remotekey"
            override val features: Set<Feature> get() = setOf(Feature.StaticRemoteKey)
        }

        @Serializable
        object AnchorOutputs : SupportedChannelType() {
            override val name: String get() = "anchor_outputs"
            override val features: Set<Feature> get() = setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs)
        }
    }

    @Serializable
    data class UnsupportedChannelType(val featureBits: Features) : ChannelType() {
        override val name: String get() = "0x${Hex.encode(featureBits.toByteArray())}"
        override val features: Set<Feature> get() = featureBits.activated.keys
    }

    companion object {

        // NB: Bolt 2: features must exactly match in order to identify a channel type.
        fun fromFeatures(features: Features): ChannelType = when (features) {
            Features(Feature.StaticRemoteKey to FeatureSupport.Mandatory, Feature.AnchorOutputs to FeatureSupport.Mandatory) -> SupportedChannelType.AnchorOutputs
            Features(Feature.StaticRemoteKey to FeatureSupport.Mandatory) -> SupportedChannelType.StaticRemoteKey
            Features.empty -> SupportedChannelType.Standard
            else -> UnsupportedChannelType(features)
        }

    }

}