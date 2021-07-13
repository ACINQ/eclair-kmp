package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.Block
import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Feature
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.utils.toMilliSatoshi
import fr.acinq.lightning.wire.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WaitForOpenChannelTestsCommon : LightningTestSuite() {

    @Test
    fun `reject other channel types than anchor outputs`() {
        val alice = WaitForInit(
            StaticParams(TestConstants.Alice.nodeParams, TestConstants.Bob.keyManager.nodeId),
            Pair(TestConstants.defaultBlockHeight, Block.RegtestGenesisBlock.header),
            OnChainFeerates(TestConstants.feeratePerKw, TestConstants.feeratePerKw, TestConstants.feeratePerKw)
        )
        val bobInit = Init(TestConstants.Bob.nodeParams.features.toByteArray().toByteVector())
        val unsupportedChannelTypes = listOf(ChannelType.SupportedChannelType.Standard, ChannelType.SupportedChannelType.StaticRemoteKey)
        unsupportedChannelTypes.forEach { channelType ->
            val (alice1, actions1) = alice.process(
                ChannelEvent.InitFunder(
                    ByteVector32.Zeroes,
                    TestConstants.fundingAmount,
                    0.msat,
                    FeeratePerKw.CommitmentFeerate,
                    TestConstants.feeratePerKw,
                    TestConstants.Alice.channelParams,
                    bobInit,
                    0,
                    ChannelConfig.standard,
                    channelType,
                    null
                )
            )
            assertTrue(alice1 is Aborted)
            assertTrue(actions1.isEmpty())
        }
    }

    @Test
    fun `recv OpenChannel (without wumbo)`() {
        val (_, bob, open) = TestsHelper.init(aliceFeatures = TestConstants.Alice.nodeParams.features.remove(Feature.Wumbo))
        // Since https://github.com/lightningnetwork/lightning-rfc/pull/714 we must include an empty upfront_shutdown_script.
        assertEquals(open.tlvStream.get(), ChannelTlv.UpfrontShutdownScriptTlv(ByteVector.empty))
        assertEquals(open.tlvStream.get(), ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs))
        assertTrue(open.channelReserveSatoshis > 0.sat)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open))
        assertTrue(bob1 is WaitForFundingCreated)
        assertTrue(bob1.channelConfig.hasOption(ChannelConfigOption.FundingPubKeyBasedChannelKeyPath))
        assertEquals(bob1.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs)))
        actions.hasOutgoingMessage<AcceptChannel>()
    }

    @Test
    fun `recv OpenChannel (wumbo)`() {
        val (_, bob, open) = TestsHelper.init(fundingAmount = 20_000_000.sat)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open))
        assertTrue(bob1 is WaitForFundingCreated)
        assertEquals(bob1.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.Wumbo)))
        actions.hasOutgoingMessage<AcceptChannel>()
    }

    @Test
    fun `recv OpenChannel (zero-reserve)`() {
        val (_, bob, open) = TestsHelper.init(bobFeatures = TestConstants.Bob.nodeParams.features.add(Feature.ZeroReserveChannels to FeatureSupport.Optional))
        assertEquals(0.sat, open.channelReserveSatoshis)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open))
        assertTrue(bob1 is WaitForFundingCreated)
        assertTrue(bob1.channelConfig.hasOption(ChannelConfigOption.FundingPubKeyBasedChannelKeyPath))
        assertEquals(bob1.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.Wumbo, Feature.ZeroReserveChannels)))
        actions.hasOutgoingMessage<AcceptChannel>()
    }

    @Test
    fun `recv OpenChannel (zero-conf)`() {
        val (_, bob, open) = TestsHelper.init(bobFeatures = TestConstants.Bob.nodeParams.features.add(Feature.ZeroConfChannels to FeatureSupport.Optional))
        assertTrue(open.channelReserveSatoshis > 0.sat)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open))
        assertTrue(bob1 is WaitForFundingCreated)
        assertTrue(bob1.channelConfig.hasOption(ChannelConfigOption.FundingPubKeyBasedChannelKeyPath))
        assertEquals(bob1.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.Wumbo, Feature.ZeroConfChannels)))
        val accept = actions.hasOutgoingMessage<AcceptChannel>()
        assertEquals(0, accept.minimumDepth)
    }

    @Test
    fun `recv OpenChannel (missing channel type)`() {
        val (_, bob, open) = TestsHelper.init()
        val open1 = open.copy(tlvStream = TlvStream(listOf()))
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, MissingChannelType(open.temporaryChannelId, ChannelType.SupportedChannelType.AnchorOutputs).message))
        assertTrue(bob1 is Aborted)
    }

    @Test
    fun `recv OpenChannel (invalid channel type)`() {
        val (_, bob, open) = TestsHelper.init()
        val open1 = open.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.StaticRemoteKey))))
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, InvalidChannelType(open.temporaryChannelId, ChannelType.SupportedChannelType.AnchorOutputs, ChannelType.SupportedChannelType.StaticRemoteKey).message))
        assertTrue(bob1 is Aborted)
    }

    @Test
    fun `recv OpenChannel (invalid chain)`() {
        val (_, bob, open) = TestsHelper.init()
        val open1 = open.copy(chainHash = Block.LivenetGenesisBlock.hash)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, InvalidChainHash(open.temporaryChannelId, bob.staticParams.nodeParams.chainHash, Block.LivenetGenesisBlock.hash).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv OpenChannel (funding too low)`() {
        val (_, bob, open) = TestsHelper.init(fundingAmount = 100.sat)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, InvalidFundingAmount(open.temporaryChannelId, 100.sat, bob.staticParams.nodeParams.minFundingSatoshis, bob.staticParams.nodeParams.maxFundingSatoshis).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv OpenChannel (funding too high)`() {
        val (_, bob, open) = TestsHelper.init(fundingAmount = 30_000_000.sat)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, InvalidFundingAmount(open.temporaryChannelId, 30_000_000.sat, bob.staticParams.nodeParams.minFundingSatoshis, bob.staticParams.nodeParams.maxFundingSatoshis).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv OpenChannel (invalid max accepted htlcs)`() {
        val (_, bob, open) = TestsHelper.init()
        val open1 = open.copy(maxAcceptedHtlcs = Channel.MAX_ACCEPTED_HTLCS + 1)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, InvalidMaxAcceptedHtlcs(open.temporaryChannelId, Channel.MAX_ACCEPTED_HTLCS + 1, Channel.MAX_ACCEPTED_HTLCS).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv OpenChannel (invalid push_msat)`() {
        val (_, bob, open) = TestsHelper.init()
        val open1 = open.copy(pushMsat = open.fundingSatoshis.toMilliSatoshi() + 10.msat)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, InvalidPushAmount(open.temporaryChannelId, open.fundingSatoshis.toMilliSatoshi() + 10.msat, open.fundingSatoshis.toMilliSatoshi()).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv OpenChannel (to_self_delay too high)`() {
        val (_, bob, open) = TestsHelper.init()
        val invalidToSelfDelay = bob.staticParams.nodeParams.maxToLocalDelayBlocks + CltvExpiryDelta(10)
        val open1 = open.copy(toSelfDelay = invalidToSelfDelay)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, ToSelfDelayTooHigh(open.temporaryChannelId, invalidToSelfDelay, bob.staticParams.nodeParams.maxToLocalDelayBlocks).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv OpenChannel (reserve too high)`() {
        val (_, bob, open) = TestsHelper.init()
        val reserveTooHigh = open.fundingSatoshis * 0.3
        val open1 = open.copy(channelReserveSatoshis = reserveTooHigh)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, ChannelReserveTooHigh(open.temporaryChannelId, reserveTooHigh, 0.3, bob.staticParams.nodeParams.maxReserveToFundingRatio).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv OpenChannel (reserve below dust)`() {
        val (_, bob, open) = TestsHelper.init()
        val reserveTooSmall = open.dustLimitSatoshis - 1.sat
        val open1 = open.copy(channelReserveSatoshis = reserveTooSmall)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, DustLimitTooLarge(open.temporaryChannelId, open.dustLimitSatoshis, reserveTooSmall).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv OpenChannel (reserve below dust, zero-reserve channel)`() {
        val (_, bob, open) = TestsHelper.init(bobFeatures = TestConstants.Bob.nodeParams.features.add(Feature.ZeroReserveChannels to FeatureSupport.Optional))
        assertEquals(0.sat, open.channelReserveSatoshis)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open))
        assertTrue { bob1 is WaitForFundingCreated }
        actions.hasOutgoingMessage<AcceptChannel>()
    }

    @Test
    fun `recv OpenChannel (dust limit too high)`() {
        val (_, bob, open) = TestsHelper.init()
        val dustLimitTooHigh = 2000.sat
        val open1 = open.copy(dustLimitSatoshis = dustLimitTooHigh)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, DustLimitTooLarge(open.temporaryChannelId, dustLimitTooHigh, bob.staticParams.nodeParams.maxRemoteDustLimit).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv OpenChannel (toLocal + toRemote below reserve)`() {
        val (_, bob, open) = TestsHelper.init()
        val fundingAmount = open.channelReserveSatoshis + 499.sat
        val pushMsat = 500.sat.toMilliSatoshi()
        val open1 = open.copy(fundingSatoshis = fundingAmount, pushMsat = pushMsat)
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open1))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(open.temporaryChannelId, ChannelReserveNotMet(open.temporaryChannelId, pushMsat, (open.channelReserveSatoshis - 1.sat).toMilliSatoshi(), open.channelReserveSatoshis).message))
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv Error`() {
        val (_, bob, _) = TestsHelper.init()
        val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertTrue { bob1 is Aborted }
        assertTrue { actions.isEmpty() }
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (_, bob, _) = TestsHelper.init()
        val (bob1, actions) = bob.process(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue { bob1 is Aborted }
        assertTrue { actions.isEmpty() }
    }

    @Test
    fun `recv Disconnected`() {
        val (_, bob, _) = TestsHelper.init()
        val (bob1, actions) = bob.process(ChannelEvent.Disconnected)
        assertTrue { bob1 is WaitForOpenChannel }
        assertTrue { actions.isEmpty() }
    }

}
