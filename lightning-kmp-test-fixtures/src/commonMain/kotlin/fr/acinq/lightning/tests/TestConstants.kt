package fr.acinq.lightning.tests

import fr.acinq.bitcoin.*
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.FeerateTolerance
import fr.acinq.lightning.blockchain.fee.OnChainFeeConf
import fr.acinq.lightning.channel.LocalParams
import fr.acinq.lightning.crypto.LocalKeyManager
import fr.acinq.lightning.io.PeerChannels
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector32
import fr.acinq.lightning.wire.OnionRoutingPacket
import fr.acinq.secp256k1.Hex

@OptIn(ExperimentalUnsignedTypes::class)
object TestConstants {
    const val defaultBlockHeight = 400_000
    val fundingAmount = 1_000_000.sat
    val pushMsat = 200_000_000.msat
    val feeratePerKw = FeeratePerKw(10_000.sat)
    val emptyOnionPacket = OnionRoutingPacket(0, ByteVector(ByteArray(33)), ByteVector(ByteArray(OnionRoutingPacket.PaymentPacketLength)), ByteVector32.Zeroes)

    val trampolineFees = listOf(
        TrampolineFees(0.sat, 0, CltvExpiryDelta(576)),
        TrampolineFees(1.sat, 100, CltvExpiryDelta(576)),
        TrampolineFees(3.sat, 100, CltvExpiryDelta(576)),
        TrampolineFees(5.sat, 500, CltvExpiryDelta(576)),
        TrampolineFees(5.sat, 1000, CltvExpiryDelta(576)),
        TrampolineFees(5.sat, 1200, CltvExpiryDelta(576))
    )

    object Alice {
        private val entropy = Hex.decode("0101010101010101010101010101010101010101010101010101010101010101")
        private val mnemonics = MnemonicCode.toMnemonics(entropy)
        private val seed = MnemonicCode.toSeed(mnemonics, "").toByteVector32()

        val keyManager = LocalKeyManager(seed, Block.RegtestGenesisBlock.hash)
        val walletParams = WalletParams(NodeUri(randomKey().publicKey(), "alice.com", 9735), trampolineFees, InvoiceDefaultRoutingFees(1_000.msat, 100, CltvExpiryDelta(144)))
        val nodeParams = NodeParams(
            keyManager = keyManager,
            alias = "alice",
            features = Features(
                Feature.InitialRoutingSync to FeatureSupport.Optional,
                Feature.OptionDataLossProtect to FeatureSupport.Optional,
                Feature.ChannelRangeQueries to FeatureSupport.Optional,
                Feature.ChannelRangeQueriesExtended to FeatureSupport.Optional,
                Feature.VariableLengthOnion to FeatureSupport.Mandatory,
                Feature.PaymentSecret to FeatureSupport.Mandatory,
                Feature.BasicMultiPartPayment to FeatureSupport.Optional,
                Feature.Wumbo to FeatureSupport.Optional,
                Feature.StaticRemoteKey to FeatureSupport.Mandatory,
                Feature.AnchorOutputs to FeatureSupport.Mandatory,
                Feature.TrampolinePayment to FeatureSupport.Optional,
                Feature.WakeUpNotificationProvider to FeatureSupport.Optional,
                Feature.PayToOpenProvider to FeatureSupport.Optional,
                Feature.TrustedSwapInProvider to FeatureSupport.Optional,
                Feature.ChannelBackupProvider to FeatureSupport.Optional,
            ),
            dustLimit = 1_100.sat,
            maxRemoteDustLimit = 1_500.sat,
            onChainFeeConf = OnChainFeeConf(
                closeOnOfflineMismatch = true,
                updateFeeMinDiffRatio = 0.1,
                feerateTolerance = FeerateTolerance(ratioLow = 0.5, ratioHigh = 5.0)
            ),
            maxHtlcValueInFlightMsat = 1_500_000_000L,
            maxAcceptedHtlcs = 100,
            expiryDeltaBlocks = CltvExpiryDelta(144),
            fulfillSafetyBeforeTimeoutBlocks = CltvExpiryDelta(6),
            checkHtlcTimeoutAfterStartupDelaySeconds = 15,
            htlcMinimum = 0.msat,
            minDepthBlocks = 3,
            toRemoteDelayBlocks = CltvExpiryDelta(144),
            maxToLocalDelayBlocks = CltvExpiryDelta(2048),
            feeBase = 100.msat,
            feeProportionalMillionth = 10,
            reserveToFundingRatio = 0.01, // note: not used (overridden below)
            maxReserveToFundingRatio = 0.05,
            revocationTimeoutSeconds = 20,
            authTimeoutSeconds = 10,
            initTimeoutSeconds = 10,
            pingIntervalSeconds = 30,
            pingTimeoutSeconds = 10,
            pingDisconnect = true,
            autoReconnect = false,
            initialRandomReconnectDelaySeconds = 5,
            maxReconnectIntervalSeconds = 3600,
            chainHash = Block.RegtestGenesisBlock.hash,
            channelFlags = 1,
            paymentRequestExpirySeconds = 3600,
            multiPartPaymentExpirySeconds = 60,
            minFundingSatoshis = 1_000.sat,
            maxFundingSatoshis = 25_000_000.sat,
            maxPaymentAttempts = 5,
            enableTrampolinePayment = true
        )

        private val closingPubKeyInfo = keyManager.closingPubkeyScript(PublicKey.Generator)
        val channelParams: LocalParams = PeerChannels.makeChannelParams(
            nodeParams,
            defaultFinalScriptPubkey = ByteVector(closingPubKeyInfo.second),
            isFunder = true,
            fundingAmount
        ).copy(channelReserve = 10_000.sat) // Bob will need to keep that much satoshis as direct payment
    }

    object Bob {
        private val entropy = Hex.decode("0202020202020202020202020202020202020202020202020202020202020202")
        val mnemonics = MnemonicCode.toMnemonics(entropy)
        private val seed = MnemonicCode.toSeed(mnemonics, "").toByteVector32()
        val keyManager = LocalKeyManager(seed, Block.RegtestGenesisBlock.hash)
        val walletParams = WalletParams(NodeUri(randomKey().publicKey(), "bob.com", 9735), trampolineFees, InvoiceDefaultRoutingFees(1_000.msat, 100, CltvExpiryDelta(144)))
        val nodeParams = NodeParams(
            keyManager = keyManager,
            alias = "bob",
            features = Features(
                Feature.InitialRoutingSync to FeatureSupport.Optional,
                Feature.OptionDataLossProtect to FeatureSupport.Optional,
                Feature.ChannelRangeQueries to FeatureSupport.Optional,
                Feature.ChannelRangeQueriesExtended to FeatureSupport.Optional,
                Feature.VariableLengthOnion to FeatureSupport.Mandatory,
                Feature.PaymentSecret to FeatureSupport.Mandatory,
                Feature.BasicMultiPartPayment to FeatureSupport.Optional,
                Feature.Wumbo to FeatureSupport.Optional,
                Feature.StaticRemoteKey to FeatureSupport.Mandatory,
                Feature.AnchorOutputs to FeatureSupport.Mandatory,
                Feature.TrampolinePayment to FeatureSupport.Optional,
                Feature.WakeUpNotificationClient to FeatureSupport.Optional,
                Feature.PayToOpenClient to FeatureSupport.Optional,
                Feature.TrustedSwapInClient to FeatureSupport.Optional,
                Feature.ChannelBackupClient to FeatureSupport.Optional,
            ),
            dustLimit = 1_000.sat,
            maxRemoteDustLimit = 1_500.sat,
            onChainFeeConf = OnChainFeeConf(
                closeOnOfflineMismatch = true,
                updateFeeMinDiffRatio = 0.1,
                feerateTolerance = FeerateTolerance(ratioLow = 0.5, ratioHigh = 5.0)
            ),
            maxHtlcValueInFlightMsat = 1_500_000_000L,
            maxAcceptedHtlcs = 100,
            expiryDeltaBlocks = CltvExpiryDelta(144),
            fulfillSafetyBeforeTimeoutBlocks = CltvExpiryDelta(6),
            checkHtlcTimeoutAfterStartupDelaySeconds = 15,
            htlcMinimum = 1_000.msat,
            minDepthBlocks = 3,
            toRemoteDelayBlocks = CltvExpiryDelta(144),
            maxToLocalDelayBlocks = CltvExpiryDelta(1024),
            feeBase = 10.msat,
            feeProportionalMillionth = 10,
            reserveToFundingRatio = 0.01, // note: not used (overridden below)
            maxReserveToFundingRatio = 0.05,
            revocationTimeoutSeconds = 20,
            authTimeoutSeconds = 10,
            initTimeoutSeconds = 10,
            pingIntervalSeconds = 30,
            pingTimeoutSeconds = 10,
            pingDisconnect = true,
            autoReconnect = false,
            initialRandomReconnectDelaySeconds = 5,
            maxReconnectIntervalSeconds = 3600,
            chainHash = Block.RegtestGenesisBlock.hash,
            channelFlags = 1,
            paymentRequestExpirySeconds = 3600,
            multiPartPaymentExpirySeconds = 60,
            minFundingSatoshis = 1_000.sat,
            maxFundingSatoshis = 25_000_000.sat,
            maxPaymentAttempts = 5,
            enableTrampolinePayment = true
        )

        private val closingPubKeyInfo = keyManager.closingPubkeyScript(PublicKey.Generator)
        val channelParams: LocalParams = PeerChannels.makeChannelParams(
            nodeParams,
            defaultFinalScriptPubkey = ByteVector(closingPubKeyInfo.second),
            isFunder = false,
            fundingAmount
        ).copy(channelReserve = 20_000.sat) // Alice will need to keep that much satoshis as direct payment
    }

}
