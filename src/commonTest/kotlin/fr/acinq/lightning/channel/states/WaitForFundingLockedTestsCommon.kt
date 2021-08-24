package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.processEx
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.*
import kotlin.test.*

class WaitForFundingLockedTestsCommon : LightningTestSuite() {

    @Test
    fun `recv FundingLocked`() {
        val (alice, bob, fundingLocked) = init()
        val (alice1, actionsAlice1) = alice.processEx(ChannelEvent.MessageReceived(fundingLocked.second))
        assertTrue(alice1 is Normal)
        assertEquals(2, actionsAlice1.size)
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsAlice1.findWatch<WatchConfirmed>().event, BITCOIN_FUNDING_DEEPLYBURIED)
        val (bob1, actionsBob1) = bob.processEx(ChannelEvent.MessageReceived(fundingLocked.first))
        assertTrue(bob1 is Normal)
        assertEquals(2, actionsBob1.size)
        actionsBob1.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsBob1.findWatch<WatchConfirmed>().event, BITCOIN_FUNDING_DEEPLYBURIED)
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (remote commit)`() {
        val (alice, bob, _) = init()
        // bob publishes his commitment tx
        run {
            val bobCommitTx = bob.commitments.localCommit.publishableTxs.commitTx.tx
            val (alice1, actions1) = alice.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
            assertTrue(alice1 is Closing)
            assertNotNull(alice1.remoteCommitPublished)
            assertEquals(1, actions1.findTxs().size)
            assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
        }
        // alice publishes her commitment tx
        run {
            val aliceCommitTx = alice.commitments.localCommit.publishableTxs.commitTx.tx
            val (bob1, actions1) = bob.processEx(ChannelEvent.WatchReceived(WatchEventSpent(bob.channelId, BITCOIN_FUNDING_SPENT, aliceCommitTx)))
            assertTrue(bob1 is Closing)
            assertNotNull(bob1.remoteCommitPublished)
            assertEquals(1, actions1.findTxs().size)
            assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
        }
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (other commit)`() {
        val (alice, _, _) = init()
        val aliceCommitTx = alice.commitments.localCommit.publishableTxs.commitTx.tx
        val unknownTx = Transaction(2, aliceCommitTx.txIn, listOf(), 0)
        val (alice1, actions1) = alice.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, unknownTx)))
        assertTrue(alice1 is ErrorInformationLeak)
        assertTrue(actions1.isEmpty())
    }

    @Test
    fun `recv Error`() {
        val (alice, bob, _) = init()
        listOf(alice, bob).forEach { state ->
            val commitTx = state.commitments.localCommit.publishableTxs.commitTx.tx
            val (state1, actions1) = state.processEx(ChannelEvent.MessageReceived(Error(state.channelId, "no lightning for you sir")))
            assertTrue(state1 is Closing)
            assertNotNull(state1.localCommitPublished)
            assertNull(actions1.findOutgoingMessageOpt<Error>())
            actions1.hasTx(commitTx)
            actions1.hasWatch<WatchConfirmed>()
        }
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (alice, bob, _) = init()
        listOf(alice, bob).forEach { state ->
            val (state1, actions1) = state.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
            assertEquals(state, state1)
            assertEquals(1, actions1.size)
            actions1.hasCommandError<CommandUnavailableInThisState>()
        }
    }

    @Test
    fun `recv CMD_FORCECLOSE`() {
        val (alice, bob, _) = init()
        listOf(alice, bob).forEach { state ->
            val commitTx = state.commitments.localCommit.publishableTxs.commitTx.tx
            val (state1, actions1) = state.processEx(ChannelEvent.ExecuteCommand(CMD_FORCECLOSE))
            assertTrue(state1 is Closing)
            assertNotNull(state1.localCommitPublished)
            val error = actions1.hasOutgoingMessage<Error>()
            assertEquals(ForcedLocalCommit(bob.channelId).message, error.toAscii())
            actions1.hasTx(commitTx)
            actions1.hasWatch<WatchConfirmed>()
        }
    }

    @Test
    fun `recv CMD_FORCECLOSE (nothing at stake)`() {
        val (_, bob, _) = init(pushMsat = 0.msat)
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FORCECLOSE))
        assertTrue(bob1 is Aborted)
        assertEquals(1, actions1.size)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(ForcedLocalCommit(bob.channelId).message, error.toAscii())
    }

    companion object {
        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            currentHeight: Int = TestConstants.defaultBlockHeight,
            fundingAmount: Satoshi = TestConstants.fundingAmount,
            pushMsat: MilliSatoshi = TestConstants.pushMsat
        ): Triple<WaitForFundingLocked, WaitForFundingLocked, Pair<FundingLocked, FundingLocked>> {
            val (alice, bob, open) = TestsHelper.init(channelType, currentHeight = currentHeight, fundingAmount = fundingAmount, pushMsat = pushMsat)
            val (bob1, actionsBob1) = bob.processEx(ChannelEvent.MessageReceived(open))
            val accept = actionsBob1.findOutgoingMessage<AcceptChannel>()
            val (alice1, actionsAlice1) = alice.processEx(ChannelEvent.MessageReceived(accept))
            val fundingRequest = actionsAlice1.filterIsInstance<ChannelAction.Blockchain.MakeFundingTx>().first()
            val fundingTx = Transaction(version = 2, txIn = listOf(TxIn(OutPoint(ByteVector32.Zeroes, 0), TxIn.SEQUENCE_FINAL)), txOut = listOf(TxOut(fundingRequest.amount, fundingRequest.pubkeyScript)), lockTime = 0)
            val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.MakeFundingTxResponse(fundingTx, 0, 100.sat))
            val fundingCreated = actionsAlice2.findOutgoingMessage<FundingCreated>()
            val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.MessageReceived(fundingCreated))
            val fundingSigned = actionsBob2.findOutgoingMessage<FundingSigned>()
            val channelId = fundingSigned.channelId
            val (alice3, _) = alice2.processEx(ChannelEvent.MessageReceived(fundingSigned))
            val (alice4, actionsAlice4) = alice3.processEx(ChannelEvent.WatchReceived(WatchEventConfirmed(channelId, BITCOIN_FUNDING_DEPTHOK, currentHeight, 42, fundingTx)))
            assertTrue(alice4 is WaitForFundingLocked)
            actionsAlice4.hasWatch<WatchLost>()
            val fundingLockedAlice = actionsAlice4.findOutgoingMessage<FundingLocked>()
            val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.WatchReceived(WatchEventConfirmed(channelId, BITCOIN_FUNDING_DEPTHOK, currentHeight, 42, fundingTx)))
            assertTrue(bob3 is WaitForFundingLocked)
            actionsBob3.hasWatch<WatchLost>()
            val fundingLockedBob = actionsBob3.findOutgoingMessage<FundingLocked>()
            return Triple(alice4, bob3, Pair(fundingLockedAlice, fundingLockedBob))
        }
    }

}