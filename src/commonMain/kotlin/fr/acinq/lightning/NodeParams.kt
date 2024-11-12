package fr.acinq.lightning

import co.touchlab.kermit.Logger
import fr.acinq.bitcoin.*
import fr.acinq.lightning.Lightning.nodeFee
import fr.acinq.lightning.blockchain.fee.FeerateTolerance
import fr.acinq.lightning.blockchain.fee.OnChainFeeConf
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.logging.LoggerFactory
import fr.acinq.lightning.payment.LiquidityPolicy
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toMilliSatoshi
import fr.acinq.lightning.wire.OfferTypes
import io.ktor.utils.io.charsets.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

data class NodeUri(val id: PublicKey, val host: String, val port: Int)

/**
 * When we send a trampoline payment, we start with a low fee.
 * If that fails, we increase the fee(s) and retry (up to a point).
 * This class encapsulates the fees and expiry to use at a particular attempt.
 */
data class TrampolineFees(val feeBase: Satoshi, val feeProportional: Long, val cltvExpiryDelta: CltvExpiryDelta) {
    fun calculateFees(recipientAmount: MilliSatoshi): MilliSatoshi = nodeFee(feeBase.toMilliSatoshi(), feeProportional, recipientAmount)
}

/**
 * When we create an invoice, we need to add a routing hint since we only have private channels.
 * This routing hint contains routing fees that should be paid by the sender, set by our peer.
 * When we have a channel, we'll take them from our peer's channel update, but when we don't have any channel we'll use these default values.
 */
data class InvoiceDefaultRoutingFees(val feeBase: MilliSatoshi, val feeProportional: Long, val cltvExpiryDelta: CltvExpiryDelta)

/**
 * These parameters must match the parameters used by the wallet provider.
 *
 * @param minConfirmations number of confirmations needed on swap-in transactions, before importing those funds into a channel.
 * @param maxConfirmations maximum number of confirmations for swap-in transactions: funds need to be imported into a channel before reaching that threshold.
 * @param refundDelay number of confirmations for swap-in transactions after which funds can be unilaterally refunded back to the user.
 */
data class SwapInParams(val minConfirmations: Int, val maxConfirmations: Int, val refundDelay: Int)

object DefaultSwapInParams {
    /** When doing a swap-in, the funds must be confirmed before we can use them in a 0-conf splice. */
    const val MinConfirmations = 3

    /**
     * When doing a swap-in, the corresponding splice must be triggered before we get too close to the refund delay.
     * Users would otherwise be able to steal funds if the splice transaction doesn't confirm before the refund delay.
     */
    const val MaxConfirmations = 144 * 30 * 4 // ~4 months

    /** When doing a swap-in, the user's funds are locked in a 2-of-2: they can claim them unilaterally after that delay. */
    const val RefundDelay = 144 * 30 * 6 // ~6 months
}

/**
 * @param trampolineNode address of the trampoline node used for outgoing payments.
 * @param trampolineFees ordered list of trampoline fees to try when making an outgoing payment.
 * @param invoiceDefaultRoutingFees default routing fees set in invoices when we don't have any channel.
 * @param swapInParams parameters for swap-in transactions.
 */
data class WalletParams(
    val trampolineNode: NodeUri,
    val trampolineFees: List<TrampolineFees>,
    val invoiceDefaultRoutingFees: InvoiceDefaultRoutingFees,
    val swapInParams: SwapInParams,
)

/**
 * When sending a payment, if the expiry used for the last node is very close to the current block height,
 * it lets intermediate nodes figure out their position in the route. To protect against this, a random
 * number of blocks between min and max will be added to the current block height, before the `minFinalExpiryDelta`
 * requested by the recipient, which makes it look like there are more hops after the final node.
 *
 * The overall cltv expiry delta for an outgoing trampoline payment will thus be:
 * `cltvExpiryDelta` =  `random(min, max)` + `minFinalExpiryDelta` + `TrampolineFees.cltvExpiryDelta`
 */
data class RecipientCltvExpiryParams(val min: CltvExpiryDelta, val max: CltvExpiryDelta) {
    fun computeFinalExpiry(currentBlockHeight: Int, minFinalExpiryDelta: CltvExpiryDelta): CltvExpiry {
        val randomDelay = when {
            min < max -> Lightning.secureRandom.nextLong(min.toLong(), max.toLong()).toInt()
            else -> max.toInt()
        }
        return (minFinalExpiryDelta + randomDelay).toCltvExpiry(currentBlockHeight.toLong())
    }
}

/**
 * @param loggerFactory factory for creating [Logger] objects sharing the same configuration.
 * @param chain bitcoin chain we're interested in.
 * @param keyManager derive private keys and secrets from your seed.
 * @param features features supported by the lightning node.
 * @param dustLimit threshold below which outputs will not be generated in commitment or HTLC transactions (i.e. HTLCs below this amount plus HTLC transaction fees are not enforceable on-chain).
 * @param maxRemoteDustLimit maximum dust limit we let our peer use for his commitment (in theory it should always be 546 sats).
 * @param onChainFeeConf on-chain feerates that will be applied to various transactions.
 * @param maxHtlcValueInFlightMsat cap on the total value of pending HTLCs in a channel: this lets us limit our exposure to HTLCs risk.
 * @param maxAcceptedHtlcs cap on the number of pending HTLCs in a channel: this lets us limit our exposure to HTLCs risk.
 * @param expiryDeltaBlocks cltv-expiry-delta used in our channel_update: since our channels are private and we don't relay payments, this will be basically ignored.
 * @param minFinalCltvExpiryDelta cltv-expiry-delta that we require when receiving a payment.
 * @param fulfillSafetyBeforeTimeoutBlocks number of blocks necessary to react to a malicious peer that doesn't acknowledge and sign our HTLC preimages.
 * @param checkHtlcTimeoutAfterStartupDelay delay before we check for timed out HTLCs in our channels after a wallet restart.
 * @param bolt11InvoiceExpiry duration for which bolt11 invoices that we create are valid.
 * @param bolt12InvoiceExpiry duration for which bolt12 invoices that we create are valid.
 * @param htlcMinimum minimum accepted HTLC value.
 * @param toRemoteDelayBlocks number of blocks our peer will have to wait before they get their main output back in case they force-close a channel.
 * @param maxToLocalDelayBlocks maximum number of blocks we will have to wait before we get our main output back in case we force-close a channel.
 * @param minDepthBlocks minimum depth of a transaction before we consider it safely confirmed.
 * @param feeBase base fee used in our channel_update: since our channels are private and we don't relay payments, this will be basically ignored.
 * @param feeProportionalMillionths proportional fee used in our channel_update: since our channels are private and we don't relay payments, this will be basically ignored.
 * @param pingInterval delay between ping messages.
 * @param initialRandomReconnectDelay delay before which we reconnect to our peers (will be randomized based on this value).
 * @param maxReconnectInterval maximum delay between reconnection attempts.
 * @param mppAggregationWindow amount of time we will wait to receive all parts of a multipart payment.
 * @param maxPaymentAttempts maximum number of retries when attempting an outgoing payment.
 * @param paymentRecipientExpiryParams configure the expiry delta used for the final node when sending payments.
 * @param zeroConfPeers list of peers with whom we use zero-conf (note that this is a strong trust assumption).
 * @param liquidityPolicy fee policy for liquidity events, can be modified at any time.
 */
data class NodeParams(
    val loggerFactory: LoggerFactory,
    val chain: Chain,
    val keyManager: KeyManager,
    val features: Features,
    val dustLimit: Satoshi,
    val maxRemoteDustLimit: Satoshi,
    val onChainFeeConf: OnChainFeeConf,
    val maxHtlcValueInFlightMsat: Long,
    val maxAcceptedHtlcs: Int,
    val expiryDeltaBlocks: CltvExpiryDelta,
    val minFinalCltvExpiryDelta: CltvExpiryDelta,
    val fulfillSafetyBeforeTimeoutBlocks: CltvExpiryDelta,
    val checkHtlcTimeoutAfterStartupDelay: Duration,
    val checkHtlcTimeoutInterval: Duration,
    val bolt11InvoiceExpiry: Duration,
    val bolt12InvoiceExpiry: Duration,
    val htlcMinimum: MilliSatoshi,
    val toRemoteDelayBlocks: CltvExpiryDelta,
    val maxToLocalDelayBlocks: CltvExpiryDelta,
    val minDepthBlocks: Int,
    val feeBase: MilliSatoshi,
    val feeProportionalMillionths: Int,
    val pingInterval: Duration,
    val initialRandomReconnectDelay: Duration,
    val maxReconnectInterval: Duration,
    val mppAggregationWindow: Duration,
    val maxPaymentAttempts: Int,
    val paymentRecipientExpiryParams: RecipientCltvExpiryParams,
    val zeroConfPeers: Set<PublicKey>,
    val liquidityPolicy: MutableStateFlow<LiquidityPolicy>,
) {
    val nodePrivateKey get() = keyManager.nodeKeys.nodeKey.privateKey
    val nodeId get() = keyManager.nodeKeys.nodeKey.publicKey
    val chainHash get() = chain.chainHash

    internal val _nodeEvents = MutableSharedFlow<NodeEvents>(replay = 10)
    val nodeEvents: SharedFlow<NodeEvents> get() = _nodeEvents.asSharedFlow()

    init {
        // Verify required features are set and obsolete features aren't set.
        require(features.hasFeature(Feature.VariableLengthOnion, FeatureSupport.Mandatory)) { "${Feature.VariableLengthOnion.rfcName} should be mandatory" }
        require(features.hasFeature(Feature.PaymentSecret, FeatureSupport.Mandatory)) { "${Feature.PaymentSecret.rfcName} should be mandatory" }
        require(features.hasFeature(Feature.ChannelType, FeatureSupport.Mandatory)) { "${Feature.ChannelType.rfcName} should be mandatory" }
        require(features.hasFeature(Feature.DualFunding, FeatureSupport.Mandatory)) { "${Feature.DualFunding.rfcName} should be mandatory" }
        require(features.hasFeature(Feature.RouteBlinding)) { "${Feature.RouteBlinding.rfcName} should be supported" }
        require(!features.hasFeature(Feature.ZeroConfChannels)) { "${Feature.ZeroConfChannels.rfcName} has been deprecated: use the zeroConfPeers whitelist instead" }
        require(!features.hasFeature(Feature.TrustedSwapInClient)) { "${Feature.TrustedSwapInClient.rfcName} has been deprecated" }
        require(!features.hasFeature(Feature.TrustedSwapInProvider)) { "${Feature.TrustedSwapInProvider.rfcName} has been deprecated" }
        require(!features.hasFeature(Feature.PayToOpenClient)) { "${Feature.PayToOpenClient.rfcName} has been deprecated" }
        require(!features.hasFeature(Feature.PayToOpenProvider)) { "${Feature.PayToOpenProvider.rfcName} has been deprecated" }
        Features.validateFeatureGraph(features)
        // Verify expiry parameters are consistent with each other.
        require((fulfillSafetyBeforeTimeoutBlocks * 2) < minFinalCltvExpiryDelta) { "min_final_expiry_delta must be at least twice as long as fulfill_safety_before_timeout_blocks" }
    }

    /**
     * Library integrators should use this constructor and override values.
     */
    constructor(chain: Chain, loggerFactory: LoggerFactory, keyManager: KeyManager) : this(
        loggerFactory = loggerFactory,
        chain = chain,
        keyManager = keyManager,
        features = Features(
            Feature.OptionDataLossProtect to FeatureSupport.Optional,
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
            Feature.BasicMultiPartPayment to FeatureSupport.Optional,
            Feature.Wumbo to FeatureSupport.Optional,
            Feature.StaticRemoteKey to FeatureSupport.Mandatory,
            Feature.AnchorOutputs to FeatureSupport.Optional, // can't set Mandatory because peers prefers AnchorOutputsZeroFeeHtlcTx
            Feature.RouteBlinding to FeatureSupport.Optional,
            Feature.DualFunding to FeatureSupport.Mandatory,
            Feature.ShutdownAnySegwit to FeatureSupport.Mandatory,
            Feature.Quiescence to FeatureSupport.Mandatory,
            Feature.ChannelType to FeatureSupport.Mandatory,
            Feature.PaymentMetadata to FeatureSupport.Optional,
            Feature.ExperimentalTrampolinePayment to FeatureSupport.Optional,
            Feature.ZeroReserveChannels to FeatureSupport.Optional,
            Feature.WakeUpNotificationClient to FeatureSupport.Optional,
            Feature.ChannelBackupClient to FeatureSupport.Optional,
            Feature.ExperimentalSplice to FeatureSupport.Optional,
            Feature.OnTheFlyFunding to FeatureSupport.Optional,
            Feature.FundingFeeCredit to FeatureSupport.Optional,
        ),
        dustLimit = 546.sat,
        maxRemoteDustLimit = 600.sat,
        onChainFeeConf = OnChainFeeConf(
            closeOnOfflineMismatch = true,
            updateFeeMinDiffRatio = 0.1,
            feerateTolerance = FeerateTolerance(ratioLow = 0.01, ratioHigh = 100.0)
        ),
        maxHtlcValueInFlightMsat = 20_000_000_000L,
        maxAcceptedHtlcs = 6,
        expiryDeltaBlocks = CltvExpiryDelta(144),
        // We use a long expiry delta here for a few reasons:
        //  - we want to ensure we're able to get HTLC-success txs confirmed if our peer ignores our preimage
        //  - we may be offline for a while, so we want our peer to be able to hold HTLCs and forward them when we come back online
        minFinalCltvExpiryDelta = CltvExpiryDelta(144),
        fulfillSafetyBeforeTimeoutBlocks = CltvExpiryDelta(12),
        checkHtlcTimeoutAfterStartupDelay = 30.seconds,
        checkHtlcTimeoutInterval = 10.seconds,
        bolt11InvoiceExpiry = 24.hours,
        bolt12InvoiceExpiry = 24.hours,
        htlcMinimum = 1000.msat,
        minDepthBlocks = 3,
        toRemoteDelayBlocks = CltvExpiryDelta(2016),
        maxToLocalDelayBlocks = CltvExpiryDelta(1008),
        feeBase = 1000.msat,
        feeProportionalMillionths = 100,
        pingInterval = 30.seconds,
        initialRandomReconnectDelay = 5.seconds,
        maxReconnectInterval = 60.minutes,
        mppAggregationWindow = 60.seconds,
        maxPaymentAttempts = 5,
        zeroConfPeers = emptySet(),
        paymentRecipientExpiryParams = RecipientCltvExpiryParams(CltvExpiryDelta(72), CltvExpiryDelta(144)),
        liquidityPolicy = MutableStateFlow<LiquidityPolicy>(
            LiquidityPolicy.Auto(
                inboundLiquidityTarget = null,
                maxAbsoluteFee = 2_000.sat,
                maxRelativeFeeBasisPoints = 3_000 /* 3000 = 30 % */,
                skipAbsoluteFeeCheck = false,
                considerOnlyMiningFeeForAbsoluteFeeCheck = false,
                maxAllowedFeeCredit = 0.msat
            )
        ),
    )

    /**
     * We generate a default, deterministic Bolt 12 offer based on the node's seed and its trampoline node.
     * This offer will stay valid after restoring the seed on a different device.
     * @return the default offer and the private key that will sign invoices for this offer.
     */
    fun defaultOffer(trampolineNodeId: PublicKey): Pair<OfferTypes.Offer, PrivateKey> {
        // We generate a deterministic blindingSecret based on:
        //  - a custom tag indicating that this is used in the Bolt 12 context
        //  - our trampoline node, which is used as an introduction node for the offer's blinded path
        //  - our private key, which ensures that nobody else can generate the same blindingSecret
        val blindingSecret = PrivateKey(Crypto.sha256("bolt 12 default offer".toByteArray(Charsets.UTF_8).byteVector() + trampolineNodeId.value + nodePrivateKey.value).byteVector32())
        // We don't use our currently activated features, otherwise the offer would change when we add support for new features.
        // If we add a new feature that we would like to use by default, we will need to explicitly create a new offer.
        return OfferTypes.Offer.createBlindedOffer(amount = null, description = null, this, trampolineNodeId, Features.empty, blindingSecret, pathId = null)
    }
}
