package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Chain
import fr.acinq.bitcoin.Satoshi
import fr.acinq.lightning.ChannelEvents
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Features
import fr.acinq.lightning.Lightning.randomBytes64
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.*
import kotlin.test.*

class WaitForAcceptChannelTestsCommon : LightningTestSuite() {

    @Test
    fun `recv AcceptChannel`() {
        val (alice, _, accept) = init()
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept))
        assertIs<LNChannel<WaitForFundingCreated>>(alice1)
        assertEquals(3, actions1.size)
        actions1.find<ChannelAction.ChannelId.IdAssigned>()
        assertEquals(ChannelEvents.Creating(alice1.state), actions1.find<ChannelAction.EmitEvent>().event)
        val txAddInput = actions1.findOutgoingMessage<TxAddInput>()
        assertNotEquals(txAddInput.channelId, accept.temporaryChannelId)
        assertEquals(alice1.channelId, txAddInput.channelId)
        assertEquals(alice1.state.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.DualFunding)))
    }

    @Test
    fun `recv AcceptChannel -- liquidity ads`() {
        val (alice, _, accept) = init(requestRemoteFunding = TestConstants.bobFundingAmount)
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept))
        assertIs<LNChannel<WaitForFundingCreated>>(alice1)
        val purchase = alice1.state.liquidityPurchase
        assertNotNull(purchase)
        assertTrue(purchase.fees.total > 0.sat)
        actions1.hasOutgoingMessage<TxAddInput>()
    }

    @Test
    fun `recv AcceptChannel -- without non-initiator contribution`() {
        val (alice, _, accept) = init(bobFundingAmount = 0.sat)
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept))
        assertIs<LNChannel<WaitForFundingCreated>>(alice1)
        assertEquals(3, actions1.size)
        actions1.find<ChannelAction.ChannelId.IdAssigned>()
        actions1.findOutgoingMessage<TxAddInput>()
        assertEquals(alice1.state.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.DualFunding)))
        assertEquals(ChannelEvents.Creating(alice1.state), actions1.find<ChannelAction.EmitEvent>().event)
    }

    @Test
    fun `recv AcceptChannel -- zero conf`() {
        val (alice, _, accept) = init(channelType = ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, zeroConf = true)
        assertEquals(0, accept.minimumDepth)
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept))
        assertIs<LNChannel<WaitForFundingCreated>>(alice1)
        assertEquals(3, actions1.size)
        actions1.find<ChannelAction.ChannelId.IdAssigned>()
        assertEquals(ChannelEvents.Creating(alice1.state), actions1.find<ChannelAction.EmitEvent>().event)
        actions1.findOutgoingMessage<TxAddInput>()
        assertEquals(alice1.state.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.ZeroReserveChannels, Feature.DualFunding)))
    }

    @Test
    fun `recv AcceptChannel -- missing channel type`() = runSuspendTest {
        val (alice, _, accept) = init()
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept.copy(tlvStream = TlvStream.empty())))
        assertIs<LNChannel<Aborted>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, MissingChannelType(accept.temporaryChannelId).message))
        assertIs<ChannelFundingResponse.Failure.InvalidChannelParameters>(alice.state.init.replyTo.await())
    }

    @Test
    fun `recv AcceptChannel -- invalid channel type`() {
        val (alice, _, accept) = init()
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept.copy(tlvStream = TlvStream(ChannelTlv.ChannelTypeTlv(ChannelType.UnsupportedChannelType(Features.empty))))))
        assertIs<LNChannel<Aborted>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, InvalidChannelType(accept.temporaryChannelId, ChannelType.SupportedChannelType.AnchorOutputs, ChannelType.UnsupportedChannelType(Features.empty)).message))
    }

    @Test
    fun `recv AcceptChannel -- funding negative`() {
        val (alice, _, accept) = init()
        val (alice1, actions) = alice.process(ChannelCommand.MessageReceived(accept.copy(fundingAmount = (-1).sat)))
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, InvalidFundingAmount(accept.temporaryChannelId, (-1).sat).message))
        assertIs<LNChannel<Aborted>>(alice1)
    }

    @Test
    fun `recv AcceptChannel -- missing liquidity ads`() = runSuspendTest {
        val (alice, _, accept) = init(requestRemoteFunding = TestConstants.bobFundingAmount)
        val accept1 = accept.copy(tlvStream = accept.tlvStream.copy(records = accept.tlvStream.records.filterNot { it is ChannelTlv.ProvideFundingTlv }.toSet()))
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept1))
        assertIs<LNChannel<Aborted>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, MissingLiquidityAds(accept.temporaryChannelId).message))
        assertIs<ChannelFundingResponse.Failure.InvalidLiquidityAds>(alice.state.init.replyTo.await())
    }

    @Test
    fun `recv AcceptChannel -- invalid liquidity ads amount`() = runSuspendTest {
        val (alice, _, accept) = init(requestRemoteFunding = TestConstants.bobFundingAmount)
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept.copy(fundingAmount = TestConstants.bobFundingAmount - 100.sat)))
        assertIs<LNChannel<Aborted>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, InvalidLiquidityAdsAmount(accept.temporaryChannelId, TestConstants.bobFundingAmount - 100.sat, TestConstants.bobFundingAmount).message))
        assertIs<ChannelFundingResponse.Failure.InvalidLiquidityAds>(alice.state.init.replyTo.await())
    }

    @Test
    fun `recv AcceptChannel -- invalid liquidity ads signature`() = runSuspendTest {
        val (alice, _, accept) = init(requestRemoteFunding = TestConstants.bobFundingAmount)
        val willFund = ChannelTlv.ProvideFundingTlv(accept.willFund!!.copy(signature = randomBytes64()))
        val accept1 = accept.copy(tlvStream = accept.tlvStream.copy(records = accept.tlvStream.records.filterNot { it is ChannelTlv.ProvideFundingTlv }.toSet() + willFund))
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept1))
        assertIs<LNChannel<Aborted>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, InvalidLiquidityAdsSig(accept.temporaryChannelId).message))
        assertIs<ChannelFundingResponse.Failure.InvalidLiquidityAds>(alice.state.init.replyTo.await())
    }

    @Test
    fun `recv AcceptChannel -- invalid max accepted htlcs`() {
        val (alice, _, accept) = init()
        // spec says max = 483
        val invalidMaxAcceptedHtlcs = 484
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept.copy(maxAcceptedHtlcs = invalidMaxAcceptedHtlcs)))
        assertIs<LNChannel<Aborted>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, InvalidMaxAcceptedHtlcs(accept.temporaryChannelId, invalidMaxAcceptedHtlcs, Channel.MAX_ACCEPTED_HTLCS).message))
    }

    @Test
    fun `recv AcceptChannel -- dust limit too low`() {
        val (alice, _, accept) = init()
        // we don't want their dust limit to be below 354
        val lowDustLimitSatoshis = 353.sat
        // but we only enforce it on mainnet
        val aliceMainnet = alice.copy(ctx = alice.ctx.copy(staticParams = alice.ctx.staticParams.copy(nodeParams = alice.staticParams.nodeParams.copy(chain = Chain.Mainnet))))
        val (alice1, actions1) = aliceMainnet.process(ChannelCommand.MessageReceived(accept.copy(dustLimit = lowDustLimitSatoshis)))
        assertIs<LNChannel<Aborted>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, DustLimitTooSmall(accept.temporaryChannelId, lowDustLimitSatoshis, Channel.MIN_DUST_LIMIT).message))
    }

    @Test
    fun `recv AcceptChannel -- dust limit too high`() {
        val (alice, _, accept) = init()
        // we don't want their dust limit to be too high
        val highDustLimitSatoshis = 2000.sat
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept.copy(dustLimit = highDustLimitSatoshis)))
        assertIs<LNChannel<Aborted>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, DustLimitTooLarge(accept.temporaryChannelId, highDustLimitSatoshis, alice.staticParams.nodeParams.maxRemoteDustLimit).message))
    }

    @Test
    fun `recv AcceptChannel -- to_self_delay too high`() {
        val (alice, _, accept) = init()
        val delayTooHigh = CltvExpiryDelta(10_000)
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(accept.copy(toSelfDelay = delayTooHigh)))
        assertIs<LNChannel<Aborted>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error, Error(accept.temporaryChannelId, ToSelfDelayTooHigh(accept.temporaryChannelId, delayTooHigh, alice.staticParams.nodeParams.maxToLocalDelayBlocks).message))
    }

    @Test
    fun `recv Error`() = runSuspendTest {
        val (alice, _, _) = init()
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertIs<LNChannel<Aborted>>(alice1)
        assertTrue(actions1.isEmpty())
        assertIs<ChannelFundingResponse.Failure.AbortedByPeer>(alice.state.init.replyTo.await())
    }

    companion object {
        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            aliceFeatures: Features = TestConstants.Alice.nodeParams.features,
            bobFeatures: Features = TestConstants.Bob.nodeParams.features,
            currentHeight: Int = TestConstants.defaultBlockHeight,
            aliceFundingAmount: Satoshi = TestConstants.aliceFundingAmount,
            bobFundingAmount: Satoshi = TestConstants.bobFundingAmount,
            requestRemoteFunding: Satoshi? = null,
            zeroConf: Boolean = false,
        ): Triple<LNChannel<WaitForAcceptChannel>, LNChannel<WaitForFundingCreated>, AcceptDualFundedChannel> {
            val (alice, bob, open) = TestsHelper.init(channelType, aliceFeatures, bobFeatures, aliceUsePeerStorage = true, bobUsePeerStorage = true, currentHeight, aliceFundingAmount, bobFundingAmount, requestRemoteFunding, zeroConf)
            assertEquals(open.fundingAmount, aliceFundingAmount)
            assertEquals(open.channelType, channelType)
            requestRemoteFunding?.let {
                assertTrue(open.channelFlags.nonInitiatorPaysCommitFees)
                assertNotNull(open.requestFunding)
            }
            val (bob1, actions) = bob.process(ChannelCommand.MessageReceived(open))
            assertIs<LNChannel<WaitForFundingCreated>>(bob1)
            val accept = actions.hasOutgoingMessage<AcceptDualFundedChannel>()
            assertEquals(open.temporaryChannelId, accept.temporaryChannelId)
            assertEquals(accept.fundingAmount, bobFundingAmount)
            assertEquals(accept.channelType, channelType)
            when (zeroConf) {
                true -> assertEquals(0, accept.minimumDepth)
                false -> assertEquals(3, accept.minimumDepth)
            }
            return Triple(alice, bob1, accept)
        }
    }

}