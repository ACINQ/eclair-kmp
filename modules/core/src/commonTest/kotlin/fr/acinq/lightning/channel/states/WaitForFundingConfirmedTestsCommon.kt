package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Features
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.*
import kotlin.test.*

class WaitForFundingConfirmedTestsCommon : LightningTestSuite() {

    @Test
    fun `recv TxSignatures -- duplicate`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(bob.state.latestFundingTx.sharedTx.localSigs))
        assertIs<WaitForFundingConfirmed>(alice1.state)
        assertEquals(alice1.state.rbfStatus, RbfStatus.RbfAborted)
        assertEquals(actionsAlice1.size, 1)
        actionsAlice1.hasOutgoingMessage<TxAbort>()
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK`() {
        val (alice, bob, fundingTx) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        run {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
            assertIs<WaitForChannelReady>(alice1.state)
            assertEquals(3, actionsAlice1.size)
            actionsAlice1.hasOutgoingMessage<ChannelReady>()
            actionsAlice1.has<ChannelAction.Storage.StoreState>()
            val watch = actionsAlice1.hasWatch<WatchSpent>()
            assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
            assertEquals(watch.txId, fundingTx.txid)
            assertEquals(watch.outputIndex.toLong(), alice.state.commitments.latest.commitInput.outPoint.index)
        }
        run {
            val (bob1, actionsBob1) = bob.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
            assertIs<WaitForChannelReady>(bob1.state)
            assertEquals(3, actionsBob1.size)
            actionsBob1.hasOutgoingMessage<ChannelReady>()
            actionsBob1.has<ChannelAction.Storage.StoreState>()
            val watch = actionsBob1.hasWatch<WatchSpent>()
            assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
            assertEquals(watch.txId, fundingTx.txid)
            assertEquals(watch.outputIndex.toLong(), bob.state.commitments.latest.commitInput.outPoint.index)
        }
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- rbf in progress`() {
        val (alice, bob, fundingTx) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(TxInitRbf(alice.state.channelId, 0, FeeratePerKw(6000.sat), TestConstants.aliceFundingAmount)))
        assertIs<WaitForFundingConfirmed>(bob1.state)
        assertIs<RbfStatus.InProgress>(bob1.state.rbfStatus)
        assertEquals(actionsBob1.size, 1)
        actionsBob1.hasOutgoingMessage<TxAckRbf>()
        // The funding transaction confirms while the RBF attempt is in progress.
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
        assertIs<WaitForChannelReady>(bob2.state)
        val watch = actionsBob2.hasWatch<WatchSpent>()
        assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
        assertEquals(watch.txId, fundingTx.txid)
        assertEquals(watch.outputIndex.toLong(), bob.state.commitments.latest.commitInput.outPoint.index)
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- previous funding tx`() {
        val (alice, bob, previousFundingTx, walletAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, bob1, fundingTx) = rbf(alice, bob, walletAlice)
        assertNotEquals(previousFundingTx.txid, fundingTx.txid)
        run {
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, previousFundingTx)))
            assertIs<WaitForChannelReady>(bob2.state)
            assertEquals(1, bob2.commitments.active.size)
            assertEquals(previousFundingTx.txid, bob2.commitments.latest.fundingTxId)
            assertIs<LocalFundingStatus.ConfirmedFundingTx>(bob2.commitments.latest.localFundingStatus)
            val watch = actionsBob2.hasWatch<WatchSpent>()
            assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
            assertEquals(watch.txId, previousFundingTx.txid)
            assertEquals(watch.outputIndex.toLong(), bob.state.commitments.latest.commitInput.outPoint.index)
        }
        run {
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, previousFundingTx)))
            assertIs<WaitForChannelReady>(alice2.state)
            assertEquals(1, alice2.commitments.active.size)
            assertEquals(previousFundingTx.txid, alice2.commitments.latest.fundingTxId)
            assertIs<LocalFundingStatus.ConfirmedFundingTx>(alice2.commitments.latest.localFundingStatus)
            val watch = actionsAlice2.hasWatch<WatchSpent>()
            assertEquals(watch.event, BITCOIN_FUNDING_SPENT)
            assertEquals(watch.txId, previousFundingTx.txid)
            assertEquals(watch.outputIndex.toLong(), bob.state.commitments.latest.commitInput.outPoint.index)
        }
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- after restart`() {
        val (alice, bob, fundingTx) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        run {
            val (alice1, _) = LNChannel(alice.ctx, WaitForInit).process(ChannelCommand.Init.Restore(alice.state))
                .also { (state, actions) ->
                    assertIs<Offline>(state.state)
                    assertEquals(actions.size, 2)
                    actions.hasPublishTx(fundingTx)
                    assertEquals(actions.findWatch<WatchConfirmed>().txId, fundingTx.txid)
                }
            val (_, _) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
                .also { (state, actions) ->
                    assertIs<Offline>(state.state)
                    assertEquals(actions.size, 2)
                    actions.hasWatchFundingSpent(fundingTx.txid)
                    actions.has<ChannelAction.Storage.StoreState>()
                }
        }
        run {
            val (bob1, _) = LNChannel(bob.ctx, WaitForInit).process(ChannelCommand.Init.Restore(bob.state))
                .also { (state, actions) ->
                    assertIs<Offline>(state.state)
                    assertEquals(actions.size, 2)
                    actions.hasPublishTx(fundingTx)
                    assertEquals(actions.findWatch<WatchConfirmed>().txId, fundingTx.txid)
                }
            val (_, _) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
                .also { (state, actions) ->
                    assertIs<Offline>(state.state)
                    assertEquals(actions.size, 2)
                    actions.hasWatchFundingSpent(fundingTx.txid)
                    actions.has<ChannelAction.Storage.StoreState>()
                }
        }
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- after restart -- previous funding tx`() {
        val (alice, bob, fundingTx1, walletAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, bob1, fundingTx2) = rbf(alice, bob, walletAlice)
        run {
            val (alice2, _) = LNChannel(alice.ctx, WaitForInit).process(ChannelCommand.Init.Restore(alice1.state))
                .also { (state, actions) ->
                    assertIs<Offline>(state.state)
                    assertEquals(actions.size, 4)
                    actions.hasPublishTx(fundingTx1)
                    actions.hasPublishTx(fundingTx2)
                    assertEquals(actions.findWatches<WatchConfirmed>().map { it.txId }.toSet(), setOf(fundingTx1.txid, fundingTx2.txid))
                }
            val (_, _) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx1)))
                .also { (state, actions) ->
                    assertIs<Offline>(state.state)
                    assertEquals(state.commitments.active.size, 1)
                    assertTrue(state.commitments.inactive.isEmpty())
                    assertEquals(state.commitments.latest.fundingTxId, fundingTx1.txid)
                    assertEquals(actions.size, 2)
                    actions.hasWatchFundingSpent(fundingTx1.txid)
                    actions.has<ChannelAction.Storage.StoreState>()
                }
        }
        run {
            val (bob2, _) = LNChannel(bob.ctx, WaitForInit).process(ChannelCommand.Init.Restore(bob1.state))
                .also { (state, actions) ->
                    assertIs<Offline>(state.state)
                    assertEquals(actions.size, 4)
                    actions.hasPublishTx(fundingTx1)
                    actions.hasPublishTx(fundingTx2)
                    assertEquals(actions.findWatches<WatchConfirmed>().map { it.txId }.toSet(), setOf(fundingTx1.txid, fundingTx2.txid))
                }
            val (_, _) = bob2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx1)))
                .also { (state, actions) ->
                    assertIs<Offline>(state.state)
                    assertEquals(state.commitments.active.size, 1)
                    assertTrue(state.commitments.inactive.isEmpty())
                    assertEquals(state.commitments.latest.fundingTxId, fundingTx1.txid)
                    assertEquals(actions.size, 2)
                    actions.hasWatchFundingSpent(fundingTx1.txid)
                    actions.has<ChannelAction.Storage.StoreState>()
                }
        }
    }

    @Test
    fun `recv TxInitRbf`() {
        val (alice, bob, _, walletAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, bob1) = rbf(alice, bob, walletAlice)
        assertEquals(alice1.state.previousFundingTxs.size, 1)
        assertEquals(bob1.state.previousFundingTxs.size, 1)
        assertTrue(alice1.state.commitments.latest.fundingTxId != alice.state.commitments.latest.fundingTxId)
        assertTrue(bob1.state.commitments.latest.fundingTxId != bob.state.commitments.latest.fundingTxId)
        assertEquals(alice1.state.commitments.latest.fundingTxId, bob1.state.commitments.latest.fundingTxId)
    }

    @Test
    fun `recv TxInitRbf -- invalid feerate`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(TxInitRbf(alice.state.channelId, 0, TestConstants.feeratePerKw, alice.state.latestFundingTx.fundingParams.localContribution)))
        assertEquals(actions1.size, 1)
        assertEquals(actions1.hasOutgoingMessage<TxAbort>().toAscii(), InvalidRbfFeerate(alice.state.channelId, TestConstants.feeratePerKw, TestConstants.feeratePerKw * 25 / 24).message)
        val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(TxAbort(alice.state.channelId, "acking tx_abort")))
        assertEquals(bob2, bob)
        assertTrue(actions2.isEmpty())
    }

    @Test
    fun `recv TxInitRbf -- failed rbf attempt`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(TxInitRbf(alice.state.channelId, 0, TestConstants.feeratePerKw * 1.25, alice.state.latestFundingTx.fundingParams.localContribution)))
        assertIs<WaitForFundingConfirmed>(bob1.state)
        assertIs<RbfStatus.InProgress>(bob1.state.rbfStatus)
        assertEquals(actions1.size, 1)
        actions1.hasOutgoingMessage<TxAckRbf>()
        val txAddInput = alice.state.latestFundingTx.sharedTx.tx.localInputs.first().run { TxAddInput(alice.channelId, serialId, previousTx, previousTxOutput, sequence) }
        val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(txAddInput))
        assertEquals(actions2.size, 1)
        actions2.hasOutgoingMessage<TxAddInput>()
        val (bob3, actions3) = bob2.process(ChannelCommand.MessageReceived(TxAbort(alice.state.channelId, "changed my mind")))
        assertIs<WaitForFundingConfirmed>(bob3.state)
        assertEquals(bob3.state.rbfStatus, RbfStatus.None)
        assertEquals(actions3.size, 1)
        actions3.hasOutgoingMessage<TxAbort>()
    }

    @Test
    fun `recv ChannelReady`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val channelReadyAlice = ChannelReady(alice.state.channelId, randomKey().publicKey())
        val channelReadyBob = ChannelReady(bob.state.channelId, randomKey().publicKey())
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(channelReadyBob))
        assertIs<WaitForFundingConfirmed>(alice1.state)
        assertEquals(alice1.state.deferred, channelReadyBob)
        assertTrue(actionsAlice1.isEmpty())
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(channelReadyAlice))
        assertIs<WaitForFundingConfirmed>(bob1.state)
        assertEquals(bob1.state.deferred, channelReadyAlice)
        assertTrue(actionsBob1.isEmpty())
    }

    @Test
    fun `recv ChannelReady -- no remote contribution`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        val channelReadyAlice = ChannelReady(alice.state.channelId, randomKey().publicKey())
        val channelReadyBob = ChannelReady(bob.state.channelId, randomKey().publicKey())
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(channelReadyBob))
        assertIs<WaitForFundingConfirmed>(alice1.state)
        assertEquals(alice1.state.deferred, channelReadyBob)
        assertTrue(actionsAlice1.isEmpty())
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(channelReadyAlice))
        assertIs<WaitForFundingConfirmed>(bob1.state)
        assertEquals(bob1.state.deferred, channelReadyAlice)
        assertTrue(actionsBob1.isEmpty())
    }

    @Test
    fun `recv Error`() {
        val (_, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(Error(bob.state.channelId, "oops")))
        assertIs<Closing>(bob1.state)
        assertNotNull(bob1.state.localCommitPublished)
        actions1.hasPublishTx(bob.state.commitments.latest.localCommit.publishableTxs.commitTx.tx)
        assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
    }

    @Test
    fun `recv Error -- previous funding tx confirms`() {
        val (alice, bob, previousFundingTx, walletAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val commitTxAlice1 = alice.state.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val commitTxBob1 = bob.state.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice1, bob1, fundingTx) = rbf(alice, bob, walletAlice)
        val commitTxAlice2 = alice1.state.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val commitTxBob2 = bob1.state.commitments.latest.localCommit.publishableTxs.commitTx.tx
        assertNotEquals(previousFundingTx.txid, fundingTx.txid)
        assertNotEquals(commitTxAlice1.txid, commitTxAlice2.txid)
        assertNotEquals(commitTxBob1.txid, commitTxBob2.txid)
        run {
            // Bob receives an error and publishes his latest commitment.
            val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(Error(bob.state.channelId, "oops")))
            assertIs<Closing>(bob2.state)
            assertTrue(bob2.commitments.active.size > 1)
            actions2.hasPublishTx(commitTxBob2)
            val lcp1 = bob2.state.localCommitPublished
            assertNotNull(lcp1)
            assertTrue(lcp1.commitTx.txIn.map { it.outPoint.txid }.contains(fundingTx.txid))
            // A previous funding transaction confirms, so Bob publishes the corresponding commit tx.
            val (bob3, actions3) = bob2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.state.channelId, BITCOIN_FUNDING_DEPTHOK, 50, 0, previousFundingTx)))
            assertIs<Closing>(bob3.state)
            assertEquals(bob3.state.commitments.active.size, 1)
            actions3.hasPublishTx(commitTxBob1)
            val lcp2 = bob3.state.localCommitPublished
            assertNotNull(lcp2)
            assertTrue(lcp2.commitTx.txIn.map { it.outPoint.txid }.contains(previousFundingTx.txid))
            // Alice publishes her commit tx, Bob reacts by spending his remote main output.
            val (bob4, actions4) = bob3.process(ChannelCommand.WatchReceived(WatchEventSpent(bob.state.channelId, BITCOIN_FUNDING_SPENT, commitTxAlice1)))
            assertIs<Closing>(bob4.state)
            assertNotNull(bob4.state.localCommitPublished)
            assertNotNull(bob4.state.remoteCommitPublished)
            val claimMain = actions4.findPublishTxs().first()
            assertEquals(claimMain.txIn.first().outPoint.txid, commitTxAlice1.txid)
        }
        run {
            // Alice receives an error and publishes her latest commitment.
            val (alice2, actions2) = alice1.process(ChannelCommand.MessageReceived(Error(alice.state.channelId, "oops")))
            assertIs<Closing>(alice2.state)
            assertTrue(alice2.commitments.active.size > 1)
            actions2.hasPublishTx(commitTxAlice2)
            val lcp1 = alice2.state.localCommitPublished
            assertNotNull(lcp1)
            assertTrue(lcp1.commitTx.txIn.map { it.outPoint.txid }.contains(fundingTx.txid))
            // A previous funding transaction confirms, so Alice publishes the corresponding commit tx.
            val (alice3, actions3) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.state.channelId, BITCOIN_FUNDING_DEPTHOK, 50, 0, previousFundingTx)))
            assertIs<Closing>(alice3.state)
            assertEquals(alice3.commitments.active.size, 1)
            actions3.hasPublishTx(commitTxAlice1)
            val lcp2 = alice3.state.localCommitPublished
            assertNotNull(lcp2)
            assertTrue(lcp2.commitTx.txIn.map { it.outPoint.txid }.contains(previousFundingTx.txid))
            // Bob publishes his commit tx, Alice reacts by spending her remote main output.
            val (alice4, actions4) = alice3.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.state.channelId, BITCOIN_FUNDING_SPENT, commitTxBob1)))
            assertIs<Closing>(alice4.state)
            assertNotNull(alice4.state.localCommitPublished)
            assertNotNull(alice4.state.remoteCommitPublished)
            val claimMain = actions4.findPublishTxs().first()
            assertEquals(claimMain.txIn.first().outPoint.txid, commitTxBob1.txid)
        }
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose`() {
        val (alice, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        listOf(alice, bob).forEach { state ->
            val (state1, actions1) = state.process(ChannelCommand.Close.MutualClose(null, null))
            assertEquals(state, state1)
            actions1.hasCommandError<CommandUnavailableInThisState>()
        }
    }

    @Test
    fun `recv ChannelCommand_Close_ForceClose`() {
        val (alice, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        listOf(alice, bob).forEach { state ->
            val (state1, actions1) = state.process(ChannelCommand.Close.ForceClose)
            assertIs<Closing>(state1.state)
            assertNotNull(state1.state.localCommitPublished)
            actions1.hasPublishTx(state1.state.localCommitPublished!!.commitTx)
            actions1.hasPublishTx(state1.state.localCommitPublished!!.claimMainDelayedOutputTx!!.tx)
            assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
        }
    }

    @Test
    fun `recv CheckHtlcTimeout`() {
        val (alice, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        listOf(alice, bob).forEach { state ->
            run {
                val (state1, actions1) = state.process(ChannelCommand.Commitment.CheckHtlcTimeout)
                assertEquals(state, state1)
                assertTrue(actions1.isEmpty())
            }
        }
    }

    @Test
    fun `recv Disconnected`() {
        val (alice, bob) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.Disconnected)
        assertIs<Offline>(alice1.state)
        assertTrue(actionsAlice1.isEmpty())
        val (bob1, actionsBob1) = bob.process(ChannelCommand.Disconnected)
        assertIs<Offline>(bob1.state)
        assertTrue(actionsBob1.isEmpty())
    }

    companion object {
        data class Fixture(val alice: LNChannel<WaitForFundingConfirmed>, val bob: LNChannel<WaitForFundingConfirmed>, val fundingTx: Transaction, val walletAlice: List<WalletState.Utxo>)

        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            aliceFeatures: Features = TestConstants.Alice.nodeParams.features.initFeatures(),
            bobFeatures: Features = TestConstants.Bob.nodeParams.features.initFeatures(),
            aliceUsePeerStorage: Boolean = false,
            bobUsePeerStorage: Boolean = true,
            currentHeight: Int = TestConstants.defaultBlockHeight,
            aliceFundingAmount: Satoshi = TestConstants.aliceFundingAmount,
            bobFundingAmount: Satoshi = TestConstants.bobFundingAmount,
            requestRemoteFunding: Satoshi? = null,
        ): Fixture {
            val (alice, commitAlice, bob, commitBob, walletAlice) = WaitForFundingSignedTestsCommon.init(
                channelType,
                aliceFeatures,
                bobFeatures,
                aliceUsePeerStorage,
                bobUsePeerStorage,
                currentHeight,
                aliceFundingAmount,
                bobFundingAmount,
                requestRemoteFunding,
                zeroConf = false
            )
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(commitBob))
            assertIs<WaitForFundingSigned>(alice1.state)
            assertTrue(actionsAlice1.isEmpty())
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(commitAlice))
            assertIs<WaitForFundingConfirmed>(bob1.state)
            assertEquals(actionsBob1.findWatch<WatchConfirmed>().event, BITCOIN_FUNDING_DEPTHOK)
            val txSigsBob = actionsBob1.findOutgoingMessage<TxSignatures>()
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(txSigsBob))
            assertIs<LNChannel<WaitForFundingConfirmed>>(alice2)
            val fundingTxAlice = alice2.state.latestFundingTx.signedTx
            assertNotNull(fundingTxAlice)
            val txSigsAlice = actionsAlice2.findOutgoingMessage<TxSignatures>()
            assertEquals(actionsAlice2.findWatch<WatchConfirmed>().event, BITCOIN_FUNDING_DEPTHOK)
            actionsAlice2.hasPublishTx(fundingTxAlice)
            actionsAlice2.has<ChannelAction.Storage.StoreState>()
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(txSigsAlice))
            assertIs<LNChannel<WaitForFundingConfirmed>>(bob2)
            val fundingTxBob = bob2.state.latestFundingTx.signedTx
            assertNotNull(fundingTxBob)
            actionsBob2.hasPublishTx(fundingTxBob)
            actionsBob2.has<ChannelAction.Storage.StoreState>()
            assertEquals(fundingTxAlice.txid, fundingTxBob.txid)
            return Fixture(alice2, bob2, fundingTxAlice, walletAlice)
        }

        fun createRbfCommand(alice: LNChannel<WaitForFundingConfirmed>, wallet: List<WalletState.Utxo>): ChannelCommand.Funding.BumpFundingFee {
            val previousFundingParams = alice.state.latestFundingTx.fundingParams
            val previousFundingTx = alice.state.latestFundingTx.sharedTx
            assertIs<FullySignedSharedTransaction>(previousFundingTx)
            // Alice adds a new input that increases her contribution and covers the additional fees.
            val script = alice.staticParams.nodeParams.keyManager.swapInOnChainWallet.legacySwapInProtocol.pubkeyScript
            val parentTx = Transaction(2, listOf(TxIn(OutPoint(TxId(randomBytes32()), 1), 0)), listOf(TxOut(30_000.sat, script)), 0)
            val wallet1 = wallet + listOf(WalletState.Utxo(parentTx.txid, 0, 42, parentTx, WalletState.AddressMeta.Single))
            return ChannelCommand.Funding.BumpFundingFee(previousFundingTx.feerate * 1.1, previousFundingParams.localContribution + 20_000.sat, wallet1, previousFundingTx.tx.lockTime + 1)
        }

        fun rbf(alice: LNChannel<WaitForFundingConfirmed>, bob: LNChannel<WaitForFundingConfirmed>, walletAlice: List<WalletState.Utxo>): Triple<LNChannel<WaitForFundingConfirmed>, LNChannel<WaitForFundingConfirmed>, Transaction> {
            val previousFundingParams = alice.state.latestFundingTx.fundingParams
            val previousFundingTx = alice.state.latestFundingTx.sharedTx
            assertIs<FullySignedSharedTransaction>(previousFundingTx)
            val command = createRbfCommand(alice, walletAlice)
            val (alice1, actionsAlice1) = alice.process(command)
            assertEquals(actionsAlice1.size, 1)
            val txInitRbf = actionsAlice1.findOutgoingMessage<TxInitRbf>()
            assertEquals(txInitRbf.fundingContribution, previousFundingParams.localContribution + 20_000.sat)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(txInitRbf))
            assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
            assertEquals(actionsBob1.size, 1)
            val txAckRbf = actionsBob1.findOutgoingMessage<TxAckRbf>()
            assertEquals(txAckRbf.fundingContribution, previousFundingParams.remoteContribution) // the non-initiator doesn't change its contribution
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(txAckRbf))
            assertIs<LNChannel<WaitForFundingConfirmed>>(alice2)
            assertEquals(actionsAlice2.size, 1)
            // Alice and Bob build the next funding transaction.
            val (alice3, bob2) = completeInteractiveTxRbf(alice2, bob1, actionsAlice2.findOutgoingMessage())
            val fundingTx = alice3.state.latestFundingTx.sharedTx
            assertIs<FullySignedSharedTransaction>(fundingTx)
            assertNotEquals(previousFundingTx.txId, fundingTx.txId)
            assertEquals(fundingTx.signedTx.lockTime, previousFundingTx.tx.lockTime + 1)
            assertEquals(alice3.state.commitments.latest.fundingAmount, alice.state.commitments.latest.fundingAmount + 20_000.sat)
            assertEquals(alice3.state.rbfStatus, RbfStatus.None)
            assertEquals(bob2.state.rbfStatus, RbfStatus.None)
            return Triple(alice3, bob2, fundingTx.signedTx)
        }

        private fun completeInteractiveTxRbf(
            alice: LNChannel<WaitForFundingConfirmed>,
            bob: LNChannel<WaitForFundingConfirmed>,
            messageAlice: InteractiveTxMessage
        ): Pair<LNChannel<WaitForFundingConfirmed>, LNChannel<WaitForFundingConfirmed>> {
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(messageAlice))
            assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
            assertEquals(actionsBob1.size, 1)
            val messageBob = actionsBob1.findOutgoingMessage<InteractiveTxConstructionMessage>()
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(messageBob))
            assertIs<LNChannel<WaitForFundingConfirmed>>(alice1)
            return when (val txComplete = actionsAlice1.findOutgoingMessageOpt<TxComplete>()) {
                null -> {
                    assertEquals(actionsAlice1.size, 1)
                    completeInteractiveTxRbf(alice1, bob1, actionsAlice1.findOutgoingMessage())
                }
                else -> {
                    assertEquals(actionsAlice1.size, 3)
                    val commitSigAlice = actionsAlice1.findOutgoingMessage<CommitSig>()
                    actionsAlice1.has<ChannelAction.Storage.StoreState>()
                    val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(txComplete))
                    assertEquals(actionsBob2.size, 2)
                    val commitSigBob = actionsBob2.findOutgoingMessage<CommitSig>()
                    actionsBob2.has<ChannelAction.Storage.StoreState>()
                    val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(commitSigBob))
                    assertTrue(actionsAlice2.isEmpty())
                    val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(commitSigAlice))
                    assertIs<LNChannel<WaitForFundingConfirmed>>(bob3)
                    assertEquals(actionsBob3.size, 3)
                    actionsBob3.has<ChannelAction.Storage.StoreState>()
                    val watchBob = actionsBob3.findWatch<WatchConfirmed>()
                    val txSigsBob = actionsBob3.findOutgoingMessage<TxSignatures>()
                    val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(txSigsBob))
                    assertIs<LNChannel<WaitForFundingConfirmed>>(alice3)
                    assertEquals(actionsAlice3.size, 4)
                    val txSigsAlice = actionsAlice3.hasOutgoingMessage<TxSignatures>()
                    val watchAlice = actionsAlice3.findWatch<WatchConfirmed>()
                    actionsAlice3.has<ChannelAction.Storage.StoreState>()
                    val fundingTxAlice = actionsAlice3.find<ChannelAction.Blockchain.PublishTx>().tx
                    val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(txSigsAlice))
                    assertIs<LNChannel<WaitForFundingConfirmed>>(bob4)
                    assertEquals(actionsBob4.size, 2)
                    val fundingTxBob = actionsBob4.find<ChannelAction.Blockchain.PublishTx>().tx
                    actionsBob4.has<ChannelAction.Storage.StoreState>()
                    assertEquals(fundingTxAlice.txid, fundingTxBob.txid)
                    assertEquals(watchAlice.txId, fundingTxAlice.txid)
                    assertEquals(watchBob.txId, fundingTxBob.txid)
                    Pair(alice3, bob4)
                }
            }
        }
    }

}
