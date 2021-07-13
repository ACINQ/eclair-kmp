package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.Block
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Satoshi
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Feature
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.Features
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.AcceptChannel
import fr.acinq.lightning.wire.ChannelTlv
import fr.acinq.lightning.wire.Error
import fr.acinq.lightning.wire.TlvStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WaitForAcceptChannelTestsCommon : LightningTestSuite() {

    @Test
    fun `recv AcceptChannel`() {
        val (alice, _, accept) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept))
        assertTrue(alice1 is WaitForFundingInternal)
        assertEquals(1, actions1.size)
        val funding = actions1.find<ChannelAction.Blockchain.MakeFundingTx>()
        assertEquals(TestConstants.fundingAmount, funding.amount)
        assertEquals(TestConstants.feeratePerKw, funding.feerate)
        assertEquals(alice1.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.Wumbo)))
    }

    @Test
    fun `recv AcceptChannel (zero conf)`() {
        val (alice, _, accept) = init(
            aliceFeatures = TestConstants.Alice.nodeParams.features.add(Feature.ZeroConfChannels to FeatureSupport.Optional),
            bobFeatures = TestConstants.Bob.nodeParams.features.add(Feature.ZeroConfChannels to FeatureSupport.Optional),
        )
        assertEquals(0, accept.minimumDepth)
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept))
        assertTrue(alice1 is WaitForFundingInternal)
        assertEquals(1, actions1.size)
        actions1.find<ChannelAction.Blockchain.MakeFundingTx>()
        assertEquals(alice1.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.Wumbo, Feature.ZeroConfChannels)))
    }

    @Test
    fun `recv AcceptChannel (zero reserve)`() {
        val (alice, _, accept) = init(
            bobFeatures = TestConstants.Bob.nodeParams.features.add(Feature.ZeroReserveChannels to FeatureSupport.Optional),
        )
        assertTrue(accept.minimumDepth > 0)
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept))
        assertTrue(alice1 is WaitForFundingInternal)
        assertEquals(1, actions1.size)
        actions1.find<ChannelAction.Blockchain.MakeFundingTx>()
        assertEquals(alice1.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.Wumbo, Feature.ZeroReserveChannels)))
    }

    @Test
    fun `recv AcceptChannel (missing channel type)`() {
        val (alice, _, accept) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept.copy(tlvStream = TlvStream(listOf()))))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, MissingChannelType(accept.temporaryChannelId, ChannelType.SupportedChannelType.AnchorOutputs).message))
    }

    @Test
    fun `recv AcceptChannel (invalid channel type)`() {
        val (alice, _, accept) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept.copy(tlvStream = TlvStream(listOf(ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.Standard))))))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, InvalidChannelType(accept.temporaryChannelId, ChannelType.SupportedChannelType.AnchorOutputs, ChannelType.SupportedChannelType.Standard).message))
    }

    @Test
    fun `recv AcceptChannel (invalid max accepted htlcs)`() {
        val (alice, _, accept) = init()
        // spec says max = 483
        val invalidMaxAcceptedHtlcs = 484
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept.copy(maxAcceptedHtlcs = invalidMaxAcceptedHtlcs)))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, InvalidMaxAcceptedHtlcs(accept.temporaryChannelId, invalidMaxAcceptedHtlcs, Channel.MAX_ACCEPTED_HTLCS).message))
    }

    @Test
    fun `recv AcceptChannel (dust limit too low)`() {
        val (alice, _, accept) = init()
        // we don't want their dust limit to be below 330
        val lowDustLimitSatoshis = 329.sat
        // but we only enforce it on mainnet
        val aliceMainnet = alice.copy(staticParams = alice.staticParams.copy(nodeParams = alice.staticParams.nodeParams.copy(chainHash = Block.LivenetGenesisBlock.hash)))
        val (alice1, actions1) = aliceMainnet.process(ChannelEvent.MessageReceived(accept.copy(dustLimitSatoshis = lowDustLimitSatoshis)))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, DustLimitTooSmall(accept.temporaryChannelId, lowDustLimitSatoshis, Channel.MIN_DUST_LIMIT).message))
    }

    @Test
    fun `recv AcceptChannel (dust limit too high)`() {
        val (alice, _, accept) = init()
        // we don't want their dust limit to be too high
        val highDustLimitSatoshis = 2000.sat
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept.copy(dustLimitSatoshis = highDustLimitSatoshis)))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, DustLimitTooLarge(accept.temporaryChannelId, highDustLimitSatoshis, alice.staticParams.nodeParams.maxRemoteDustLimit).message))
    }

    @Test
    fun `recv AcceptChannel (to_self_delay too high)`() {
        val (alice, _, accept) = init()
        val delayTooHigh = CltvExpiryDelta(10_000)
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept.copy(toSelfDelay = delayTooHigh)))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, ToSelfDelayTooHigh(accept.temporaryChannelId, delayTooHigh, alice.staticParams.nodeParams.maxToLocalDelayBlocks).message))
    }

    @Test
    fun `recv AcceptChannel (reserve too high)`() {
        val (alice, _, accept) = init()
        // 30% is huge, recommended ratio is 1%
        val reserveTooHigh = TestConstants.fundingAmount * 0.3
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept.copy(channelReserveSatoshis = reserveTooHigh)))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, ChannelReserveTooHigh(accept.temporaryChannelId, reserveTooHigh, 0.3, 0.05).message))
    }

    @Test
    fun `recv AcceptChannel (reserve below dust limit)`() {
        val (alice, _, accept) = init()
        val reserveTooSmall = accept.dustLimitSatoshis - 1.sat
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept.copy(channelReserveSatoshis = reserveTooSmall)))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, DustLimitTooLarge(accept.temporaryChannelId, accept.dustLimitSatoshis, reserveTooSmall).message))
    }

    @Test
    fun `recv AcceptChannel (reserve below our dust limit)`() {
        val (alice, _, accept) = init()
        val open = alice.lastSent
        val reserveTooSmall = open.dustLimitSatoshis - 1.sat
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(accept.copy(channelReserveSatoshis = reserveTooSmall)))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, ChannelReserveBelowOurDustLimit(accept.temporaryChannelId, reserveTooSmall, open.dustLimitSatoshis).message))
    }

    @Test
    fun `recv AcceptChannel (dust limit above our reserve)`() {
        val (alice, _, accept) = init()
        val open = alice.lastSent
        val dustTooBig = open.channelReserveSatoshis + 1.sat
        val aliceDustLimitTolerance = alice.copy(staticParams = alice.staticParams.copy(nodeParams = alice.staticParams.nodeParams.copy(maxRemoteDustLimit = 15_000.sat)))
        val (alice1, actions1) = aliceDustLimitTolerance.process(ChannelEvent.MessageReceived(accept.copy(dustLimitSatoshis = dustTooBig)))
        assertTrue(alice1 is Aborted)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, DustLimitAboveOurChannelReserve(accept.temporaryChannelId, dustTooBig, open.channelReserveSatoshis).message))
    }

    @Test
    fun `recv Error`() {
        val (alice, _, _) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertTrue(alice1 is Aborted)
        assertTrue(actions1.isEmpty())
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (alice, _, _) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(alice1 is Aborted)
        assertTrue(actions1.isEmpty())
    }

    companion object {
        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            currentHeight: Int = TestConstants.defaultBlockHeight,
            fundingAmount: Satoshi = TestConstants.fundingAmount,
            aliceFeatures: Features = TestConstants.Alice.nodeParams.features,
            bobFeatures: Features = TestConstants.Bob.nodeParams.features,
        ): Triple<WaitForAcceptChannel, WaitForFundingCreated, AcceptChannel> {
            val (alice, bob, open) = TestsHelper.init(channelType, aliceFeatures, bobFeatures, currentHeight, fundingAmount)
            assertEquals(open.tlvStream.get(), ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs))
            val (bob1, actions) = bob.process(ChannelEvent.MessageReceived(open))
            assertTrue(bob1 is WaitForFundingCreated)
            val accept = actions.hasOutgoingMessage<AcceptChannel>()
            assertEquals(accept.tlvStream.get(), ChannelTlv.ChannelTypeTlv(ChannelType.SupportedChannelType.AnchorOutputs))
            if (bob1.channelFeatures.hasFeature(Feature.ZeroConfChannels)) {
                assertEquals(0, accept.minimumDepth)
            } else {
                assertEquals(3, accept.minimumDepth)
            }
            return Triple(alice, bob1, accept)
        }
    }

}