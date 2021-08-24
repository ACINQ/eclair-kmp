package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Features
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_DEPTHOK
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_SPENT
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchSpent
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.serialization.Serialization
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.AcceptChannel
import fr.acinq.lightning.wire.Error
import fr.acinq.lightning.wire.FundingCreated
import fr.acinq.lightning.wire.FundingSigned
import kotlin.test.*

class WaitForFundingSignedTestsCommon : LightningTestSuite() {

    @Test
    fun `recv FundingSigned with valid signature`() {
        val (alice, _, fundingSigned) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(fundingSigned))
        assertTrue(alice1 is WaitForFundingConfirmed)
        assertEquals(4, actions1.size)
        actions1.has<ChannelAction.Storage.StoreState>()
        val fundingTx = actions1.findTxs().first()
        val watchConfirmed = actions1.findWatch<WatchConfirmed>()
        assertEquals(WatchConfirmed(alice1.channelId, fundingTx, 3, BITCOIN_FUNDING_DEPTHOK), watchConfirmed)
        val watchSpent = actions1.findWatch<WatchSpent>()
        assertEquals(WatchSpent(alice1.channelId, fundingTx, 0, BITCOIN_FUNDING_SPENT), watchSpent)
    }

    @Test
    fun `recv FundingSigned with encrypted channel data`() {
        val (alice, bob, fundingSigned) = init()
        assertTrue(alice.localParams.features.hasFeature(Feature.ChannelBackupProvider))
        assertTrue(bob.commitments.localParams.features.hasFeature(Feature.ChannelBackupClient))
        val blob = Serialization.encrypt(bob.staticParams.nodeParams.nodePrivateKey.value, bob)
        assertEquals(blob, fundingSigned.channelData)
    }

    @Test
    fun `recv FundingSigned without encrypted channel data`() {
        val (alice, bob, fundingSigned) = init(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
        assertTrue(alice.localParams.features.hasFeature(Feature.ChannelBackupProvider))
        assertFalse(bob.commitments.localParams.features.hasFeature(Feature.ChannelBackupClient))
        assertTrue(fundingSigned.channelData.isEmpty())
    }

    @Test
    fun `recv FundingSigned with invalid signature`() {
        val (alice, _, fundingSigned) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.MessageReceived(fundingSigned.copy(signature = ByteVector64.Zeroes)))
        assertTrue(alice1 is Aborted)
        actions1.hasOutgoingMessage<Error>()
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (alice, _, _) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(alice1 is Aborted)
        assertNull(actions1.findOutgoingMessageOpt<Error>())
    }

    @Test
    fun `recv CMD_FORCECLOSE`() {
        val (alice, _, _) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.ExecuteCommand(CMD_FORCECLOSE))
        assertTrue(alice1 is Aborted)
        assertNull(actions1.findOutgoingMessageOpt<Error>())
    }

    @Ignore
    fun `recv Disconnected`() {
        val (alice, _, _) = init()
        val (alice1, actions1) = alice.process(ChannelEvent.Disconnected)
        assertTrue(alice1 is Aborted)
        assertTrue(actions1.isNotEmpty()) // funding utxos should have been freed
    }

    companion object {
        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            currentHeight: Int = TestConstants.defaultBlockHeight,
            fundingAmount: Satoshi = TestConstants.fundingAmount,
            aliceFeatures: Features = TestConstants.Alice.nodeParams.features,
            bobFeatures: Features = TestConstants.Bob.nodeParams.features,
        ): Triple<WaitForFundingSigned, WaitForFundingConfirmed, FundingSigned> {
            val (alice, bob, open) = TestsHelper.init(channelType, aliceFeatures, bobFeatures, currentHeight = currentHeight, fundingAmount = fundingAmount)
            val (bob1, actionsBob1) = bob.process(ChannelEvent.MessageReceived(open))
            val accept = actionsBob1.findOutgoingMessage<AcceptChannel>()
            val (alice1, actionsAlice1) = alice.process(ChannelEvent.MessageReceived(accept))
            val fundingRequest = actionsAlice1.filterIsInstance<ChannelAction.Blockchain.MakeFundingTx>().first()
            val fundingTx = Transaction(version = 2, txIn = listOf(TxIn(OutPoint(ByteVector32.Zeroes, 0), TxIn.SEQUENCE_FINAL)), txOut = listOf(TxOut(fundingRequest.amount, fundingRequest.pubkeyScript)), lockTime = 0)
            val (alice2, actionsAlice2) = alice1.process(ChannelEvent.MakeFundingTxResponse(fundingTx, 0, 100.sat))
            assertTrue(alice2 is WaitForFundingSigned)
            val fundingCreated = actionsAlice2.findOutgoingMessage<FundingCreated>()
            val (bob2, actionsBob2) = bob1.process(ChannelEvent.MessageReceived(fundingCreated))
            val fundingSigned = actionsBob2.findOutgoingMessage<FundingSigned>()
            assertTrue(bob2 is WaitForFundingConfirmed)
            return Triple(alice2, bob2, fundingSigned)
        }
    }

}