package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchSpent
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toMilliSatoshi
import fr.acinq.lightning.wire.AcceptChannel
import fr.acinq.lightning.wire.Error
import fr.acinq.lightning.wire.FundingCreated
import fr.acinq.lightning.wire.FundingSigned
import kotlin.test.Test
import kotlin.test.assertTrue

class WaitForFundingCreatedTestsCommon : LightningTestSuite() {
    @Test
    fun `recv FundingCreated`() {
        val (_, bob, fundingCreated) = init(ChannelType.SupportedChannelType.AnchorOutputs, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (bob1, actions1) = bob.process(ChannelEvent.MessageReceived(fundingCreated))
        assertTrue { bob1 is WaitForFundingConfirmed }
        actions1.findOutgoingMessage<FundingSigned>()
        actions1.hasWatch<WatchSpent>()
        actions1.hasWatch<WatchConfirmed>()
        actions1.has<ChannelAction.ChannelId.IdSwitch>()
        actions1.has<ChannelAction.Storage.StoreState>()
    }

    @Test
    fun `recv FundingCreated (with channel origin)`() {
        val (_, bob, fundingCreated) = init(ChannelType.SupportedChannelType.AnchorOutputs, TestConstants.fundingAmount, TestConstants.pushMsat, channelOrigin = ChannelOrigin.PayToOpenOrigin(ByteVector32.One, 42.sat))
        val (bob1, actions1) = bob.process(ChannelEvent.MessageReceived(fundingCreated))
        assertTrue { bob1 is WaitForFundingConfirmed }
        actions1.findOutgoingMessage<FundingSigned>()
        actions1.hasWatch<WatchSpent>()
        actions1.hasWatch<WatchConfirmed>()
        actions1.has<ChannelAction.ChannelId.IdSwitch>()
        actions1.has<ChannelAction.Storage.StoreState>()
        actions1.contains(ChannelAction.Storage.StoreIncomingAmount(TestConstants.pushMsat, ChannelOrigin.PayToOpenOrigin(ByteVector32.One, 42.sat)))
    }

    @Test
    fun `recv FundingCreated (funder can't pay fees)`() {
        val (_, bob, fundingCreated) = init(ChannelType.SupportedChannelType.AnchorOutputs, 1_000_100.sat, 1_000_000.sat.toMilliSatoshi())
        val (bob1, actions1) = bob.process(ChannelEvent.MessageReceived(fundingCreated))
        actions1.hasOutgoingMessage<Error>()
        assertTrue { bob1 is Aborted }
    }

    @Test
    fun `recv Error`() {
        val (_, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (bob1, actions1) = bob.process(ChannelEvent.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertTrue { bob1 is Aborted }
        assertTrue { actions1.isEmpty() }
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (_, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (bob1, actions1) = bob.process(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue { bob1 is Aborted }
        assertTrue { actions1.isEmpty() }
    }

    @Test
    fun `recv Disconnected`() {
        val (_, bob, fundingCreated) = init(ChannelType.SupportedChannelType.AnchorOutputs, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (bob1, _) = bob.process(ChannelEvent.MessageReceived(fundingCreated))
        assertTrue { bob1 is WaitForFundingConfirmed }
        val (bob2, actions2) = bob1.process(ChannelEvent.Disconnected)
        assertTrue { bob2 is Offline }
        assertTrue { actions2.isEmpty() }
    }

    companion object {
        fun init(
            channelType: ChannelType.SupportedChannelType,
            fundingAmount: Satoshi,
            pushAmount: MilliSatoshi,
            aliceFeatures: Features = TestConstants.Alice.nodeParams.features,
            bobFeatures: Features = TestConstants.Bob.nodeParams.features,
            channelOrigin: ChannelOrigin? = null
        ): Triple<WaitForFundingSigned, WaitForFundingCreated, FundingCreated> {
            val (a, b, open) = TestsHelper.init(channelType, aliceFeatures, bobFeatures, 0, fundingAmount, pushAmount, channelOrigin)
            val (b1, actions) = b.process(ChannelEvent.MessageReceived(open))
            val accept = actions.findOutgoingMessage<AcceptChannel>()
            val (a1, actions2) = a.process(ChannelEvent.MessageReceived(accept))
            val fundingRequest = actions2.filterIsInstance<ChannelAction.Blockchain.MakeFundingTx>().first()
            val fundingTx = Transaction(version = 2, txIn = listOf(TxIn(OutPoint(ByteVector32.Zeroes, 0), TxIn.SEQUENCE_FINAL)), txOut = listOf(TxOut(fundingRequest.amount, fundingRequest.pubkeyScript)), lockTime = 0)
            val (a2, actions3) = a1.process(ChannelEvent.MakeFundingTxResponse(fundingTx, 0, Satoshi(0)))
            val fundingCreated = actions3.findOutgoingMessage<FundingCreated>()
            return Triple(a2 as WaitForFundingSigned, b1 as WaitForFundingCreated, fundingCreated)
        }
    }
}
