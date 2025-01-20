package fr.acinq.lightning

import fr.acinq.bitcoin.ByteVector
import fr.acinq.lightning.utils.BitField
import fr.acinq.lightning.utils.leftPaddedCopyOf
import fr.acinq.lightning.utils.or
import kotlinx.serialization.Serializable

/** Feature scope as defined in Bolt 9. */
enum class FeatureScope { Init, Node, Invoice, Bolt12 }

enum class FeatureSupport {
    Mandatory {
        override fun toString() = "mandatory"
    },
    Optional {
        override fun toString() = "optional"
    }
}

@Serializable
sealed class Feature {

    abstract val rfcName: String
    abstract val mandatory: Int
    abstract val scopes: Set<FeatureScope>
    val optional: Int get() = mandatory + 1

    fun supportBit(support: FeatureSupport): Int = when (support) {
        FeatureSupport.Mandatory -> mandatory
        FeatureSupport.Optional -> optional
    }

    override fun toString() = rfcName

    @Serializable
    object OptionDataLossProtect : Feature() {
        override val rfcName get() = "option_data_loss_protect"
        override val mandatory get() = 0
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object InitialRoutingSync : Feature() {
        override val rfcName get() = "initial_routing_sync"

        // reserved but not used as per lightningnetwork/lightning-rfc/pull/178
        override val mandatory get() = 2
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init)
    }

    @Serializable
    object ChannelRangeQueries : Feature() {
        override val rfcName get() = "gossip_queries"
        override val mandatory get() = 6
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object VariableLengthOnion : Feature() {
        override val rfcName get() = "var_onion_optin"
        override val mandatory get() = 8
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node, FeatureScope.Invoice)
    }

    @Serializable
    object ChannelRangeQueriesExtended : Feature() {
        override val rfcName get() = "gossip_queries_ex"
        override val mandatory get() = 10
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object StaticRemoteKey : Feature() {
        override val rfcName get() = "option_static_remotekey"
        override val mandatory get() = 12
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object PaymentSecret : Feature() {
        override val rfcName get() = "payment_secret"
        override val mandatory get() = 14
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node, FeatureScope.Invoice)
    }

    @Serializable
    object BasicMultiPartPayment : Feature() {
        override val rfcName get() = "basic_mpp"
        override val mandatory get() = 16
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node, FeatureScope.Invoice, FeatureScope.Bolt12)
    }

    @Serializable
    object Wumbo : Feature() {
        override val rfcName get() = "option_support_large_channel"
        override val mandatory get() = 18
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object AnchorOutputs : Feature() {
        override val rfcName get() = "option_anchor_outputs"
        override val mandatory get() = 20
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object RouteBlinding : Feature() {
        override val rfcName get() = "option_route_blinding"
        override val mandatory get() = 24
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object ShutdownAnySegwit : Feature() {
        override val rfcName get() = "option_shutdown_anysegwit"
        override val mandatory get() = 26
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object DualFunding : Feature() {
        override val rfcName get() = "option_dual_fund"
        override val mandatory get() = 28
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object Quiescence : Feature() {
        override val rfcName get() = "option_quiescence"
        override val mandatory get() = 34
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object ChannelType : Feature() {
        override val rfcName get() = "option_channel_type"
        override val mandatory get() = 44
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object PaymentMetadata : Feature() {
        override val rfcName get() = "option_payment_metadata"
        override val mandatory get() = 48
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Invoice)
    }

    // The following features have not been standardised, hence the high feature bits to avoid conflicts.

    // We historically used the following feature bit in our invoices.
    // However, the spec assigned the same feature bit to `option_scid_alias` (https://github.com/lightning/bolts/pull/910).
    // We're moving this feature bit to 148, but we have to keep supporting it until enough wallet users have migrated, then we can remove it.
    // We cannot rename that object otherwise we will not be able to read old serialized data.
    @Serializable
    object TrampolinePayment : Feature() {
        override val rfcName get() = "trampoline_payment_backwards_compat"
        override val mandatory get() = 50
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node, FeatureScope.Invoice)
    }

    /** This feature bit should be activated when a node accepts having their channel reserve set to 0. */
    @Serializable
    object ZeroReserveChannels : Feature() {
        override val rfcName get() = "zero_reserve_channels"
        override val mandatory get() = 128
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    /** DEPRECATED: this feature bit should not be used, it is only kept for serialization backwards-compatibility. */
    @Serializable
    object ZeroConfChannels : Feature() {
        override val rfcName get() = "zero_conf_channels"
        override val mandatory get() = 130
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    /** This feature bit should be activated when a mobile node supports waking up via push notifications. */
    @Serializable
    object WakeUpNotificationClient : Feature() {
        override val rfcName get() = "wake_up_notification_client"
        override val mandatory get() = 132
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init)
    }

    /** This feature bit should be activated when a node supports waking up their peers via push notifications. */
    @Serializable
    object WakeUpNotificationProvider : Feature() {
        override val rfcName get() = "wake_up_notification_provider"
        override val mandatory get() = 134
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    /** DEPRECATED: this feature bit was used for the legacy pay-to-open protocol. */
    @Serializable
    object PayToOpenClient : Feature() {
        override val rfcName get() = "pay_to_open_client"
        override val mandatory get() = 136
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init)
    }

    /** DEPRECATED: this feature bit was used for the legacy pay-to-open protocol. */
    @Serializable
    object PayToOpenProvider : Feature() {
        override val rfcName get() = "pay_to_open_provider"
        override val mandatory get() = 138
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    /** DEPRECATED: this feature bit should not be used, it is only kept for serialization backwards-compatibility. */
    @Serializable
    object TrustedSwapInClient : Feature() {
        override val rfcName get() = "trusted_swap_in_client"
        override val mandatory get() = 140
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init)
    }

    /** DEPRECATED: this feature bit should not be used, it is only kept for serialization backwards-compatibility. */
    @Serializable
    object TrustedSwapInProvider : Feature() {
        override val rfcName get() = "trusted_swap_in_provider"
        override val mandatory get() = 142
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    /** This feature bit should be activated when a node wants to send channel backups to their peers. */
    @Serializable
    object ChannelBackupClient : Feature() {
        override val rfcName get() = "channel_backup_client"
        override val mandatory get() = 144
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init)
    }

    /** This feature bit should be activated when a node stores channel backups for their peers. */
    @Serializable
    object ChannelBackupProvider : Feature() {
        override val rfcName get() = "channel_backup_provider"
        override val mandatory get() = 146
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    // The version of trampoline enabled by this feature bit does not match the latest spec PR: once the spec is accepted,
    // we will introduce a new version of trampoline that will work in parallel to this one, until we can safely deprecate it.
    @Serializable
    object ExperimentalTrampolinePayment : Feature() {
        override val rfcName get() = "trampoline_payment_experimental"
        override val mandatory get() = 148
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node, FeatureScope.Invoice)
    }

    @Serializable
    object ExperimentalSplice : Feature() {
        override val rfcName get() = "splice_experimental"
        override val mandatory get() = 154
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init)
    }

    @Serializable
    object OnTheFlyFunding : Feature() {
        override val rfcName get() = "on_the_fly_funding"
        override val mandatory get() = 560
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object FundingFeeCredit : Feature() {
        override val rfcName get() = "funding_fee_credit"
        override val mandatory get() = 562
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }

    @Serializable
    object SimpleTaprootStaging : Feature() {
        override val rfcName get() = "option_simple_taproot_staging"
        override val mandatory get() = 182 // README: this is not the feature bit defined in the bolt proposal (180) because we don't support zero-fee anchor outputs
        override val scopes: Set<FeatureScope> get() = setOf(FeatureScope.Init, FeatureScope.Node)
    }
}

@Serializable
data class UnknownFeature(val bitIndex: Int)

@Serializable
data class Features(val activated: Map<Feature, FeatureSupport>, val unknown: Set<UnknownFeature> = emptySet()) {

    fun hasFeature(feature: Feature, support: FeatureSupport? = null): Boolean = when (support) {
        null -> activated.containsKey(feature)
        else -> activated[feature] == support
    }

    fun initFeatures(): Features = Features(activated.filter { it.key.scopes.contains(FeatureScope.Init) }, unknown)

    fun nodeAnnouncementFeatures(): Features = Features(activated.filter { it.key.scopes.contains(FeatureScope.Node) }, unknown)

    fun invoiceFeatures(): Features = Features(activated.filter { it.key.scopes.contains(FeatureScope.Invoice) }, unknown)

    fun bolt12Features(): Features = Features(activated.filter { it.key.scopes.contains(FeatureScope.Bolt12) }, unknown)

    /** NB: this method is not reflexive, see [[Features.areCompatible]] if you want symmetric validation. */
    fun areSupported(remoteFeatures: Features): Boolean {
        // we allow unknown odd features (it's ok to be odd)
        val unknownFeaturesOk = remoteFeatures.unknown.all { it.bitIndex % 2 == 1 }
        // we verify that we activated every mandatory feature they require
        val knownFeaturesOk = remoteFeatures.activated.all { (feature, support) ->
            when (support) {
                FeatureSupport.Optional -> true
                FeatureSupport.Mandatory -> hasFeature(feature)
            }
        }
        return unknownFeaturesOk && knownFeaturesOk
    }

    fun toByteArray(): ByteArray {
        val activatedFeatureBytes = activated.map { (feature, support) -> feature.supportBit(support) }.toHashSet().indicesToByteArray()
        val unknownFeatureBytes = unknown.map { it.bitIndex }.toHashSet().indicesToByteArray()
        val maxSize = activatedFeatureBytes.size.coerceAtLeast(unknownFeatureBytes.size)
        return activatedFeatureBytes.leftPaddedCopyOf(maxSize) or unknownFeatureBytes.leftPaddedCopyOf(maxSize)
    }

    private fun Set<Int>.indicesToByteArray(): ByteArray {
        if (isEmpty()) return ByteArray(0)
        val buf = BitField.forAtMost(maxOrNull()!! + 1)
        forEach { buf.setRight(it) }
        return buf.bytes
    }

    companion object {
        val empty = Features(mapOf())

        private val knownFeatures: Set<Feature> = setOf(
            Feature.OptionDataLossProtect,
            Feature.InitialRoutingSync,
            Feature.ChannelRangeQueries,
            Feature.VariableLengthOnion,
            Feature.ChannelRangeQueriesExtended,
            Feature.StaticRemoteKey,
            Feature.PaymentSecret,
            Feature.BasicMultiPartPayment,
            Feature.Wumbo,
            Feature.AnchorOutputs,
            Feature.RouteBlinding,
            Feature.ShutdownAnySegwit,
            Feature.DualFunding,
            Feature.Quiescence,
            Feature.ChannelType,
            Feature.PaymentMetadata,
            Feature.TrampolinePayment,
            Feature.ExperimentalTrampolinePayment,
            Feature.ZeroReserveChannels,
            Feature.ZeroConfChannels,
            Feature.WakeUpNotificationClient,
            Feature.WakeUpNotificationProvider,
            Feature.PayToOpenClient,
            Feature.PayToOpenProvider,
            Feature.TrustedSwapInClient,
            Feature.TrustedSwapInProvider,
            Feature.ChannelBackupClient,
            Feature.ChannelBackupProvider,
            Feature.ExperimentalSplice,
            Feature.OnTheFlyFunding,
            Feature.FundingFeeCredit,
            Feature.SimpleTaprootStaging
        )

        operator fun invoke(bytes: ByteVector): Features = invoke(bytes.toByteArray())

        operator fun invoke(bytes: ByteArray): Features = invoke(BitField.from(bytes))

        operator fun invoke(bits: BitField): Features {
            val all = bits.asRightSequence().withIndex()
                .filter { it.value }
                .map { (idx, _) ->
                    knownFeatures.find { it.optional == idx }?.let { Pair(it, FeatureSupport.Optional) }
                        ?: knownFeatures.find { it.mandatory == idx }?.let { Pair(it, FeatureSupport.Mandatory) }
                        ?: UnknownFeature(idx)
                }
                .toList()

            return Features(
                activated = all.filterIsInstance<Pair<Feature, FeatureSupport>>().toMap(),
                unknown = all.filterIsInstance<UnknownFeature>().toSet()
            )
        }

        operator fun invoke(vararg pairs: Pair<Feature, FeatureSupport>): Features = Features(mapOf(*pairs))

        // Features may depend on other features, as specified in Bolt 9.
        private val featuresDependency: Map<Feature, List<Feature>> = mapOf(
            Feature.ChannelRangeQueriesExtended to listOf(Feature.ChannelRangeQueries),
            Feature.PaymentSecret to listOf(Feature.VariableLengthOnion),
            Feature.BasicMultiPartPayment to listOf(Feature.PaymentSecret),
            Feature.AnchorOutputs to listOf(Feature.StaticRemoteKey),
            Feature.TrampolinePayment to listOf(Feature.PaymentSecret),
            Feature.ExperimentalTrampolinePayment to listOf(Feature.PaymentSecret),
            Feature.OnTheFlyFunding to listOf(Feature.ExperimentalSplice),
            Feature.FundingFeeCredit to listOf(Feature.OnTheFlyFunding),
            Feature.SimpleTaprootStaging to listOf(Feature.StaticRemoteKey)
        )

        class FeatureException(message: String) : IllegalArgumentException(message)

        fun validateFeatureGraph(features: Features): FeatureException? {
            featuresDependency.forEach { (feature, dependencies) ->
                if (features.hasFeature(feature)) {
                    val missing = dependencies.filter { !features.hasFeature(it) }
                    if (missing.isNotEmpty()) {
                        return FeatureException("$feature is set but is missing a dependency (${missing.joinToString(" and ")})")
                    }
                }
            }
            return null
        }

        fun areCompatible(ours: Features, theirs: Features): Boolean = ours.areSupported(theirs) && theirs.areSupported(ours)

        /** returns true if both have at least optional support */
        fun canUseFeature(localFeatures: Features, remoteFeatures: Features, feature: Feature): Boolean =
            localFeatures.hasFeature(feature) && remoteFeatures.hasFeature(feature)
    }
}
