package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.Satoshi
import fr.acinq.bitcoin.Transaction
import fr.acinq.lightning.ChannelEvents
import fr.acinq.lightning.Features
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.wire.*
import kotlin.test.*

class WaitForChannelReadyTestsCommon : LightningTestSuite() {

    @Test
    fun `recv TxSignatures -- zero conf`() {
        val (alice, _, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, zeroConf = true)
        val txSigsAlice = getFundingSigs(alice)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(txSigsAlice))
        assertIs<WaitForChannelReady>(bob1.state)
        assertEquals(actionsBob1.size, 2)
        assertEquals(actionsBob1.find<ChannelAction.Blockchain.PublishTx>().tx.txid, txSigsAlice.txId)
        actionsBob1.has<ChannelAction.Storage.StoreState>()
    }

    @Test
    fun `recv TxSignatures and restart -- zero conf`() {
        val (alice, _, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, zeroConf = true)
        val txSigsAlice = getFundingSigs(alice)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(txSigsAlice))
        val fundingTx = actionsBob1.find<ChannelAction.Blockchain.PublishTx>().tx
        val (bob2, actionsBob2) = LNChannel(bob1.ctx, WaitForInit).process(ChannelCommand.Init.Restore(bob1.state as PersistedChannelState))
        assertIs<Offline>(bob2.state)
        assertEquals(actionsBob2.size, 2)
        assertEquals(actionsBob2.find<ChannelAction.Blockchain.PublishTx>().tx, fundingTx)
        assertEquals(actionsBob2.findWatch<WatchConfirmed>().txId, fundingTx.txid)
    }

    @Test
    fun `recv TxSignatures -- duplicate`() {
        val (alice, _, _, _) = init()
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(TxSignatures(alice.channelId, alice.commitments.latest.fundingTxId, listOf())))
        assertEquals(alice1, alice)
        assertTrue(actions1.isEmpty())
    }

    @Test
    fun `recv TxSignatures -- invalid`() {
        val (alice, _, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, zeroConf = true)
        val invalidTxSigsAlice = getFundingSigs(alice).copy(tlvs = TlvStream.empty())
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(invalidTxSigsAlice))
        assertEquals(bob, bob1)
        assertEquals(actionsBob1.size, 1)
        actionsBob1.hasOutgoingMessage<Warning>()
    }

    @Test
    fun `recv ChannelReady`() {
        val (alice, channelReadyAlice, bob, channelReadyBob) = init()
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(channelReadyBob))
        assertIs<Normal>(alice1.state)
        actionsAlice1.find<ChannelAction.Storage.SetLocked>().also {
            assertEquals(alice.commitments.latest.fundingTxId, it.txId)
        }
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        assertIs<ChannelEvents.Confirmed>(actionsAlice1.find<ChannelAction.EmitEvent>().event)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(channelReadyAlice))
        assertIs<Normal>(bob1.state)
        actionsBob1.find<ChannelAction.Storage.SetLocked>().also {
            assertEquals(bob.commitments.latest.fundingTxId, it.txId)
        }
        actionsBob1.has<ChannelAction.Storage.StoreState>()
        assertIs<ChannelEvents.Confirmed>(actionsBob1.find<ChannelAction.EmitEvent>().event)
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- remote commit`() {
        val (alice, _, bob, _) = init()
        // bob publishes his commitment tx
        run {
            val bobCommitTx = bob.commitments.latest.localCommit.publishableTxs.commitTx.tx
            val (alice1, actions1) = alice.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
            assertIs<Closing>(alice1.state)
            assertNotNull(alice1.state.remoteCommitPublished)
            assertEquals(1, actions1.findPublishTxs().size)
            assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
        }
        // alice publishes her commitment tx
        run {
            val aliceCommitTx = alice.commitments.latest.localCommit.publishableTxs.commitTx.tx
            val (bob1, actions1) = bob.process(ChannelCommand.WatchReceived(WatchEventSpent(bob.channelId, BITCOIN_FUNDING_SPENT, aliceCommitTx)))
            assertIs<Closing>(bob1.state)
            assertNotNull(bob1.state.remoteCommitPublished)
            assertEquals(1, actions1.findPublishTxs().size)
            assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
        }
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- other commit`() {
        val (alice, _, _) = init()
        val aliceCommitTx = alice.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val unknownTx = Transaction(2, aliceCommitTx.txIn, listOf(), 0)
        val (alice1, actions1) = alice.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, unknownTx)))
        assertEquals(alice.state, alice1.state)
        assertTrue(actions1.isEmpty())
    }

    @Test
    fun `recv Error`() {
        val (alice, _, bob, _) = init()
        listOf(alice, bob).forEach { state ->
            val commitTx = state.commitments.latest.localCommit.publishableTxs.commitTx.tx
            val (state1, actions1) = state.process(ChannelCommand.MessageReceived(Error(state.channelId, "no lightning for you sir")))
            assertIs<Closing>(state1.state)
            assertNotNull(state1.state.localCommitPublished)
            assertNull(actions1.findOutgoingMessageOpt<Error>())
            actions1.hasPublishTx(commitTx)
            actions1.hasWatch<WatchConfirmed>()
        }
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose`() {
        val (alice, _, bob, _) = init()
        listOf(alice, bob).forEach { state ->
            val (state1, actions1) = state.process(ChannelCommand.Close.MutualClose(null, null))
            assertEquals(state, state1)
            assertEquals(1, actions1.size)
            actions1.hasCommandError<CommandUnavailableInThisState>()
        }
    }

    @Test
    fun `recv ChannelCommand_Close_ForceClose`() {
        val (alice, _, bob, _) = init()
        listOf(alice, bob).forEach { state ->
            val commitTx = state.commitments.latest.localCommit.publishableTxs.commitTx.tx
            val (state1, actions1) = state.process(ChannelCommand.Close.ForceClose)
            assertIs<Closing>(state1.state)
            assertNotNull(state1.state.localCommitPublished)
            val error = actions1.hasOutgoingMessage<Error>()
            assertEquals(ForcedLocalCommit(bob.channelId).message, error.toAscii())
            actions1.hasPublishTx(commitTx)
            actions1.hasWatch<WatchConfirmed>()
        }
    }

    private fun getFundingSigs(channel: LNChannel<WaitForChannelReady>): TxSignatures {
        assertIs<LocalFundingStatus.UnconfirmedFundingTx>(channel.commitments.latest.localFundingStatus)
        return (channel.commitments.latest.localFundingStatus as LocalFundingStatus.UnconfirmedFundingTx).sharedTx.localSigs
    }

    companion object {
        data class Fixture(val alice: LNChannel<WaitForChannelReady>, val channelReadyAlice: ChannelReady, val bob: LNChannel<WaitForChannelReady>, val channelReadyBob: ChannelReady)

        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            aliceFeatures: Features = TestConstants.Alice.nodeParams.features,
            bobFeatures: Features = TestConstants.Bob.nodeParams.features,
            aliceUsePeerStorage: Boolean = false,
            bobUsePeerStorage: Boolean = true,
            currentHeight: Int = TestConstants.defaultBlockHeight,
            aliceFundingAmount: Satoshi = TestConstants.aliceFundingAmount,
            bobFundingAmount: Satoshi = TestConstants.bobFundingAmount,
            requestRemoteFunding: Satoshi? = null,
            zeroConf: Boolean = false,
        ): Fixture {
            return if (zeroConf) {
                val (alice, commitAlice, bob, commitBob) = WaitForFundingSignedTestsCommon.init(channelType, aliceFeatures, bobFeatures, aliceUsePeerStorage, bobUsePeerStorage, currentHeight, aliceFundingAmount, bobFundingAmount, requestRemoteFunding, zeroConf)
                val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(commitBob))
                assertIs<LNChannel<WaitForFundingSigned>>(alice1)
                assertTrue(actionsAlice1.isEmpty())
                val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(commitAlice))
                assertIs<LNChannel<WaitForChannelReady>>(bob1)
                assertEquals(actionsBob1.findWatch<WatchConfirmed>().event, BITCOIN_FUNDING_DEPTHOK)
                val txSigsBob = actionsBob1.findOutgoingMessage<TxSignatures>()
                val channelReadyBob = actionsBob1.findOutgoingMessage<ChannelReady>()
                val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(txSigsBob))
                assertIs<LNChannel<WaitForChannelReady>>(alice2)
                assertEquals(actionsAlice2.find<ChannelAction.Blockchain.PublishTx>().tx.txid, txSigsBob.txId)
                assertEquals(actionsAlice2.findWatch<WatchConfirmed>().event, BITCOIN_FUNDING_DEPTHOK)
                val channelReadyAlice = actionsAlice2.findOutgoingMessage<ChannelReady>()
                actionsAlice2.has<ChannelAction.Storage.StoreState>()
                Fixture(alice2, channelReadyAlice, bob1, channelReadyBob)
            } else {
                val (alice, bob, fundingTx) = WaitForFundingConfirmedTestsCommon.init(channelType, aliceFeatures, bobFeatures, aliceUsePeerStorage, bobUsePeerStorage, currentHeight, aliceFundingAmount, bobFundingAmount, requestRemoteFunding)
                val (alice1, actionsAlice1) = alice.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
                assertIs<LNChannel<WaitForChannelReady>>(alice1)
                val channelReadyAlice = actionsAlice1.findOutgoingMessage<ChannelReady>()
                val (bob1, actionsBob1) = bob.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
                assertIs<LNChannel<WaitForChannelReady>>(bob1)
                val channelReadyBob = actionsBob1.findOutgoingMessage<ChannelReady>()
                Fixture(alice1, channelReadyAlice, bob1, channelReadyBob)
            }
        }
    }

}