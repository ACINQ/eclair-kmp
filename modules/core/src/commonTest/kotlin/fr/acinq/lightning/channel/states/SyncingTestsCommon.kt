package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxId
import fr.acinq.lightning.Feature
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.*
import kotlin.test.*

class SyncingTestsCommon : LightningTestSuite() {

    @Test
    fun `detect that a remote commit tx was published`() {
        val (alice, bob, _) = run {
            val (alice, bob) = init()
            disconnect(alice, bob)
        }
        val aliceCommitTx = alice.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (bob1, actions) = bob.process(ChannelCommand.WatchReceived(WatchEventSpent(bob.state.channelId, BITCOIN_FUNDING_SPENT, aliceCommitTx)))
        assertIs<Closing>(bob1.state)
        // we published a tx to claim our main output
        val claimTx = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }.first()
        Transaction.correctlySpends(claimTx, alice.commitments.latest.localCommit.publishableTxs.commitTx.tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        val watches = actions.findWatches<WatchConfirmed>()
        assertEquals(watches.map { it.txId }.toSet(), setOf(aliceCommitTx.txid, claimTx.txid))
    }

    @Test
    fun `detect that a revoked commit tx was published`() {
        val (_, bob, revokedTx) = run {
            val (alice, bob) = init()
            val (nodes, _, _) = TestsHelper.addHtlc(10_000_000.msat, payer = alice, payee = bob)
            val (alice1, bob1) = nodes
            val (alice2, bob2) = TestsHelper.crossSign(alice1, bob1)
            val (alice3, bob3, _) = disconnect(alice2, bob2)
            Triple(alice3, bob3, alice.commitments.latest.localCommit.publishableTxs.commitTx.tx)
        }
        val (bob1, actions) = bob.process(ChannelCommand.WatchReceived(WatchEventSpent(bob.state.channelId, BITCOIN_FUNDING_SPENT, revokedTx)))
        assertIs<Closing>(bob1.state)
        val claimTxs = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }
        assertEquals(claimTxs.size, 2)
        claimTxs.forEach { Transaction.correctlySpends(it, revokedTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }
        val watches = actions.findWatches<WatchConfirmed>()
        // we watch the revoked tx and our "claim main output tx"
        assertEquals(watches.map { it.txId }.toSet(), setOf(revokedTx.txid, bob1.state.revokedCommitPublished.first().claimMainOutputTx!!.tx.txid))
    }

    @Test
    fun `reestablish channel with previous funding txs`() {
        val (alice, bob, previousFundingTx, walletAlice) = WaitForFundingConfirmedTestsCommon.init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, bob1, fundingTx) = WaitForFundingConfirmedTestsCommon.rbf(alice, bob, walletAlice)
        assertNotEquals(previousFundingTx.txid, fundingTx.txid)
        val (alice2, bob2, channelReestablishAlice, channelReestablishBob0) = disconnectWithBackup(alice1, bob1)
        assertNull(channelReestablishBob0)
        assertNull(channelReestablishAlice.nextFundingTxId)

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(bob1, bob3)
        assertEquals(1, actionsBob3.size)
        val channelReestablishBob = actionsBob3.hasOutgoingMessage<ChannelReestablish>()
        assertNull(channelReestablishBob.nextFundingTxId)

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(alice1, alice3)
        assertTrue(actionsAlice3.isEmpty())
    }

    @Test
    fun `forget unsigned channel`() {
        val (alice, _, bob, _) = WaitForFundingSignedTestsCommon.init()
        val fundingTxId = alice.state.signingSession.fundingTx.txId
        val (_, bob1, _, channelReestablishBob) = disconnectWithBackup(alice, bob)
        assertNotNull(channelReestablishBob)
        assertEquals(channelReestablishBob.nextFundingTxId, fundingTxId)

        // Alice acts as if they were disconnected before she sent commit_sig: she has forgotten that channel.
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(Error(channelReestablishBob.channelId, "sorry bro no channel here")))
        assertIs<Aborted>(bob2.state)
        assertEquals(1, actionsBob2.size)
        actionsBob2.find<ChannelAction.Storage.RemoveChannel>().also { assertEquals(bob.channelId, it.data.channelId) }
    }

    @Test
    fun `reestablish unsigned channel -- commit_sig not received`() {
        val (alice, _, bob, _) = WaitForFundingSignedTestsCommon.init()
        val fundingTxId = alice.state.signingSession.fundingTx.txId
        val (alice1, bob1, channelReestablishAlice, channelReestablishBob) = disconnectWithBackup(alice, bob)
        assertNotNull(channelReestablishBob)
        assertEquals(channelReestablishAlice.nextFundingTxId, fundingTxId)
        assertEquals(channelReestablishAlice.nextLocalCommitmentNumber, 0)
        assertEquals(channelReestablishBob.nextFundingTxId, fundingTxId)
        assertEquals(channelReestablishBob.nextLocalCommitmentNumber, 0)

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(actionsBob2.size, 1)
        val commitSigBob = actionsBob2.hasOutgoingMessage<CommitSig>()

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(actionsAlice2.size, 1)
        val commitSigAlice = actionsAlice2.hasOutgoingMessage<CommitSig>()

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertIs<WaitForFundingConfirmed>(bob3.state)
        val txSigsBob = actionsBob3.hasOutgoingMessage<TxSignatures>()
        actionsBob3.has<ChannelAction.Storage.StoreState>()

        val (alice3, _) = alice2.process(ChannelCommand.MessageReceived(commitSigBob))
        assertIs<WaitForFundingSigned>(alice3.state)
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<WaitForFundingConfirmed>(alice4.state)
        actionsAlice4.hasOutgoingMessage<TxSignatures>()
        actionsAlice4.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsAlice4.find<ChannelAction.Blockchain.PublishTx>().tx.txid, fundingTxId)
    }

    @Test
    fun `reestablish unsigned channel -- commit_sig received by Alice`() {
        val (alice, _, bob, commitSigBob) = WaitForFundingSignedTestsCommon.init()
        val (alice1, _) = alice.process(ChannelCommand.MessageReceived(commitSigBob))
        assertIs<LNChannel<WaitForFundingSigned>>(alice1)
        assertIs<WaitForFundingSigned>(alice1.state)
        val fundingTxId = alice1.state.signingSession.fundingTx.txId
        val (alice2, bob1, channelReestablishAlice, channelReestablishBob) = disconnectWithBackup(alice1, bob)
        assertNotNull(channelReestablishBob)
        assertEquals(channelReestablishAlice.nextFundingTxId, fundingTxId)
        assertEquals(channelReestablishAlice.nextLocalCommitmentNumber, 1)
        assertEquals(channelReestablishBob.nextFundingTxId, fundingTxId)
        assertEquals(channelReestablishBob.nextLocalCommitmentNumber, 0)

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        // Bob is waiting for Alice's commit_sig before sending his tx_signatures.
        assertTrue(actionsBob2.isEmpty())

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(actionsAlice3.size, 1)
        val commitSigAlice = actionsAlice3.hasOutgoingMessage<CommitSig>()

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertIs<WaitForFundingConfirmed>(bob3.state)
        val txSigsBob = actionsBob3.findOutgoingMessage<TxSignatures>()

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<WaitForFundingConfirmed>(alice4.state)
        val txSigsAlice = actionsAlice4.hasOutgoingMessage<TxSignatures>()
        actionsAlice4.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsAlice4.find<ChannelAction.Blockchain.PublishTx>().tx.txid, fundingTxId)

        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(txSigsAlice))
        assertIs<WaitForFundingConfirmed>(bob4.state)
        actionsBob4.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsBob4.find<ChannelAction.Blockchain.PublishTx>().tx.txid, fundingTxId)
    }

    @Test
    fun `reestablish unsigned channel -- commit_sig received by Bob`() {
        val (alice, commitSigAlice, bob, _) = WaitForFundingSignedTestsCommon.init()
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
        actionsBob1.hasOutgoingMessage<TxSignatures>()
        val fundingTxId = bob1.state.latestFundingTx.txId
        val (alice1, bob2, channelReestablishAlice, channelReestablishBob0) = disconnectWithBackup(alice, bob1)
        assertNull(channelReestablishBob0)
        assertEquals(channelReestablishAlice.nextFundingTxId, fundingTxId)
        assertEquals(channelReestablishAlice.nextLocalCommitmentNumber, 0)

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        val channelReestablishBob = actionsBob3.hasOutgoingMessage<ChannelReestablish>()
        assertEquals(channelReestablishBob.nextFundingTxId, fundingTxId)
        assertEquals(channelReestablishBob.nextLocalCommitmentNumber, 1)
        val commitSigBob = actionsBob3.hasOutgoingMessage<CommitSig>()
        val txSigsBob = actionsBob3.hasOutgoingMessage<TxSignatures>()

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertTrue(actionsAlice2.isEmpty())
        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(commitSigBob))
        assertTrue(actionsAlice3.isEmpty())
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<WaitForFundingConfirmed>(alice4.state)
        val txSigsAlice = actionsAlice4.hasOutgoingMessage<TxSignatures>()
        actionsAlice4.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsAlice4.find<ChannelAction.Blockchain.PublishTx>().tx.txid, fundingTxId)

        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(txSigsAlice))
        assertIs<WaitForFundingConfirmed>(bob4.state)
        actionsBob4.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsBob4.find<ChannelAction.Blockchain.PublishTx>().tx.txid, fundingTxId)
    }

    @Test
    fun `reestablish unsigned channel -- commit_sig received`() {
        val (alice, commitSigAlice, bob, commitSigBob) = WaitForFundingSignedTestsCommon.init()
        val (alice1, _) = alice.process(ChannelCommand.MessageReceived(commitSigBob))
        assertIs<LNChannel<WaitForFundingSigned>>(alice1)
        assertIs<WaitForFundingSigned>(alice1.state)
        val (bob1, _) = bob.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
        assertIs<WaitForFundingConfirmed>(bob1.state)
        val fundingTxId = bob1.state.latestFundingTx.txId
        val (alice2, bob2, channelReestablishAlice, channelReestablishBob0) = disconnectWithBackup(alice1, bob1)
        assertNull(channelReestablishBob0)
        assertEquals(channelReestablishAlice.nextFundingTxId, fundingTxId)
        assertEquals(channelReestablishAlice.nextLocalCommitmentNumber, 1)

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        val channelReestablishBob = actionsBob3.hasOutgoingMessage<ChannelReestablish>()
        assertEquals(channelReestablishBob.nextFundingTxId, fundingTxId)
        assertEquals(channelReestablishBob.nextLocalCommitmentNumber, 1)
        assertNull(actionsBob3.findOutgoingMessageOpt<CommitSig>())
        val txSigsBob = actionsBob3.hasOutgoingMessage<TxSignatures>()

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertTrue(actionsAlice3.isEmpty())
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(commitSigBob))
        assertTrue(actionsAlice4.isEmpty())
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<WaitForFundingConfirmed>(alice5.state)
        val txSigsAlice = actionsAlice5.hasOutgoingMessage<TxSignatures>()
        actionsAlice5.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsAlice5.find<ChannelAction.Blockchain.PublishTx>().tx.txid, fundingTxId)

        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(txSigsAlice))
        assertIs<WaitForFundingConfirmed>(bob4.state)
        actionsBob4.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsBob4.find<ChannelAction.Blockchain.PublishTx>().tx.txid, fundingTxId)
    }

    @Test
    fun `reestablish unsigned channel -- tx_signatures received by Alice`() {
        val (alice, commitSigAlice, bob, commitSigBob) = WaitForFundingSignedTestsCommon.init()
        val (alice1, _) = alice.process(ChannelCommand.MessageReceived(commitSigBob))
        assertIs<LNChannel<WaitForFundingSigned>>(alice1)
        assertIs<WaitForFundingSigned>(alice1.state)
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
        assertIs<WaitForFundingConfirmed>(bob1.state)
        val fundingTxId = bob1.state.latestFundingTx.txId
        val txSigsBob = actionsBob1.hasOutgoingMessage<TxSignatures>()
        val (alice2, _) = alice1.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<LNChannel<WaitForFundingConfirmed>>(alice2)
        assertIs<WaitForFundingConfirmed>(alice2.state)
        val (alice3, bob2, channelReestablishAlice, channelReestablishBob0) = disconnectWithBackup(alice2, bob1)
        assertNull(channelReestablishBob0)
        assertNull(channelReestablishAlice.nextFundingTxId)
        assertEquals(channelReestablishAlice.nextLocalCommitmentNumber, 1)

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(actionsBob3.size, 1)
        val channelReestablishBob = actionsBob3.hasOutgoingMessage<ChannelReestablish>()
        assertNull(actionsBob3.findOutgoingMessageOpt<CommitSig>())
        assertNull(actionsBob3.findOutgoingMessageOpt<TxSignatures>())
        assertEquals(channelReestablishBob.nextFundingTxId, fundingTxId)
        assertEquals(channelReestablishBob.nextLocalCommitmentNumber, 1)

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertIs<WaitForFundingConfirmed>(alice4.state)
        assertEquals(actionsAlice4.size, 1)
        val txSigsAlice = actionsAlice4.hasOutgoingMessage<TxSignatures>()

        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(txSigsAlice))
        assertIs<WaitForFundingConfirmed>(bob4.state)
        actionsBob4.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsBob4.find<ChannelAction.Blockchain.PublishTx>().tx.txid, fundingTxId)
    }

    @Test
    fun `reestablish unsigned rbf attempt -- commit_sig not received`() {
        val (alice, _, bob, _, rbfFundingTxId) = createUnsignedRbf()
        val (alice1, bob1, channelReestablishAlice, channelReestablishBob0) = disconnectWithBackup(alice, bob)
        assertNull(channelReestablishBob0)
        assertEquals(channelReestablishAlice.nextFundingTxId, rbfFundingTxId)
        assertEquals(channelReestablishAlice.nextLocalCommitmentNumber, 0)

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertEquals(actionsBob2.size, 2)
        val channelReestablishBob = actionsBob2.hasOutgoingMessage<ChannelReestablish>()
        assertEquals(channelReestablishBob.nextFundingTxId, rbfFundingTxId)
        assertEquals(channelReestablishBob.nextLocalCommitmentNumber, 0)
        val commitSigBob = actionsBob2.hasOutgoingMessage<CommitSig>()

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertEquals(actionsAlice2.size, 1)
        val commitSigAlice = actionsAlice2.hasOutgoingMessage<CommitSig>()

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertIs<WaitForFundingConfirmed>(bob3.state)
        assertEquals(bob3.state.rbfStatus, RbfStatus.None)
        assertEquals(bob3.state.commitments.active.size, 2)
        val txSigsBob = actionsBob3.hasOutgoingMessage<TxSignatures>()
        actionsBob3.has<ChannelAction.Storage.StoreState>()

        val (alice3, _) = alice2.process(ChannelCommand.MessageReceived(commitSigBob))
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<WaitForFundingConfirmed>(alice4.state)
        assertEquals(alice4.state.rbfStatus, RbfStatus.None)
        assertEquals(alice4.state.commitments.active.size, 2)
        actionsAlice4.hasOutgoingMessage<TxSignatures>()
        actionsAlice4.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsAlice4.find<ChannelAction.Blockchain.PublishTx>().tx.txid, rbfFundingTxId)
    }

    @Test
    fun `reestablish unsigned rbf attempt -- commit_sig received`() {
        val (alice, commitSigAlice, bob, commitSigBob, rbfFundingTxId) = createUnsignedRbf()
        val (alice1, _) = alice.process(ChannelCommand.MessageReceived(commitSigBob))
        assertIs<LNChannel<WaitForFundingConfirmed>>(alice1)
        val (bob1, _) = bob.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertIs<LNChannel<WaitForFundingConfirmed>>(bob1)
        val (alice2, bob2, channelReestablishAlice, channelReestablishBob0) = disconnectWithBackup(alice1, bob1)
        assertNull(channelReestablishBob0)
        assertEquals(channelReestablishAlice.nextFundingTxId, rbfFundingTxId)
        assertEquals(channelReestablishAlice.nextLocalCommitmentNumber, 1)

        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(channelReestablishAlice))
        assertIs<WaitForFundingConfirmed>(bob3.state)
        assertEquals(bob3.state.rbfStatus, RbfStatus.None)
        assertEquals(actionsBob3.size, 2)
        val channelReestablishBob = actionsBob3.hasOutgoingMessage<ChannelReestablish>()
        assertEquals(channelReestablishBob.nextFundingTxId, rbfFundingTxId)
        assertEquals(channelReestablishBob.nextLocalCommitmentNumber, 1)
        assertNull(actionsBob3.findOutgoingMessageOpt<CommitSig>())
        val txSigsBob = actionsBob3.hasOutgoingMessage<TxSignatures>()

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(channelReestablishBob))
        assertTrue(actionsAlice3.isEmpty())

        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(commitSigAlice))
        assertIs<WaitForFundingConfirmed>(bob4.state)
        assertEquals(bob4.state.rbfStatus, RbfStatus.None)
        assertEquals(bob4.state.commitments.active.size, 2)
        assertTrue(actionsBob4.isEmpty())

        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(commitSigBob))
        assertTrue(actionsAlice4.isEmpty())
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(txSigsBob))
        assertIs<WaitForFundingConfirmed>(alice5.state)
        assertEquals(alice5.state.rbfStatus, RbfStatus.None)
        assertEquals(alice5.state.commitments.active.size, 2)
        actionsAlice5.hasOutgoingMessage<TxSignatures>()
        actionsAlice5.has<ChannelAction.Storage.StoreState>()
        assertEquals(actionsAlice5.find<ChannelAction.Blockchain.PublishTx>().tx.txid, rbfFundingTxId)
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK`() {
        val (alice, bob, _) = WaitForFundingConfirmedTestsCommon.init(ChannelType.SupportedChannelType.AnchorOutputs)
        val fundingTx = alice.state.latestFundingTx.sharedTx.tx.buildUnsignedTx()
        val (alice1, bob1, _) = disconnectWithBackup(alice, bob)
        assertIs<WaitForFundingConfirmed>(alice1.state.state)
        assertIs<WaitForFundingConfirmed>(bob1.state.state)
        val (_, _) = alice1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
            .also { (state, actions) ->
                assertIs<Syncing>(state.state)
                assertIs<WaitForChannelReady>(state.state.state)
                assertEquals(2, actions.size)
                actions.hasWatchFundingSpent(fundingTx.txid)
                actions.has<ChannelAction.Storage.StoreState>()
            }
        val (_, _) = bob1.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
            .also { (state, actions) ->
                assertIs<Syncing>(state.state)
                assertIs<WaitForChannelReady>(state.state.state)
                assertEquals(2, actions.size)
                actions.hasWatchFundingSpent(fundingTx.txid)
                actions.has<ChannelAction.Storage.StoreState>()
            }
    }

    @Test
    fun `recv BITCOIN_FUNDING_DEPTHOK -- previous funding tx`() {
        val (alice, bob, previousFundingTx, walletAlice) = WaitForFundingConfirmedTestsCommon.init(ChannelType.SupportedChannelType.AnchorOutputs)
        val (alice1, bob1) = WaitForFundingConfirmedTestsCommon.rbf(alice, bob, walletAlice)
        val (alice2, bob2, _) = disconnectWithBackup(alice1, bob1)
        assertIs<WaitForFundingConfirmed>(alice2.state.state)
        assertIs<WaitForFundingConfirmed>(bob2.state.state)
        val (_, _) = alice2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(alice.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, previousFundingTx)))
            .also { (state, actions) ->
                assertIs<Syncing>(state.state)
                assertIs<WaitForChannelReady>(state.state.state)
                assertEquals(1, state.commitments.active.size)
                assertEquals(previousFundingTx.txid, state.commitments.latest.fundingTxId)
                assertIs<LocalFundingStatus.ConfirmedFundingTx>(state.commitments.latest.localFundingStatus)
                assertEquals(actions.size, 2)
                actions.hasWatchFundingSpent(previousFundingTx.txid)
                actions.has<ChannelAction.Storage.StoreState>()
            }
        val (_, _) = bob2.process(ChannelCommand.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, previousFundingTx)))
            .also { (state, actions) ->
                assertIs<Syncing>(state.state)
                assertIs<WaitForChannelReady>(state.state.state)
                assertEquals(1, state.commitments.active.size)
                assertEquals(previousFundingTx.txid, state.commitments.latest.fundingTxId)
                assertIs<LocalFundingStatus.ConfirmedFundingTx>(state.commitments.latest.localFundingStatus)
                assertEquals(actions.size, 2)
                actions.hasWatchFundingSpent(previousFundingTx.txid)
                actions.has<ChannelAction.Storage.StoreState>()
            }
    }

    @Test
    fun `recv ChannelCommand_Close_ForceClose`() {
        val (alice, _, _) = run {
            val (alice, bob) = init()
            disconnect(alice, bob)
        }
        val (alice1, actions1) = alice.process(ChannelCommand.Close.ForceClose)
        assertIs<Closing>(alice1.state)
        actions1.hasOutgoingMessage<Error>()
    }

    @Test
    fun `recv Disconnect after adding htlc but before processing settlement`() {
        val (alice, bob) = init()
        val (nodes1, _, add) = TestsHelper.addHtlc(55_000_000.msat, payer = bob, payee = alice)
        val (bob1, alice1) = nodes1
        val (bob2, alice2) = TestsHelper.crossSign(bob1, alice1)

        // Disconnect before Alice's payment handler processes the htlc.
        val (alice3, _, reestablish) = disconnect(alice2, bob2)

        // After reconnecting, Alice forwards the htlc again to her payment handler.
        val (_, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(reestablish.second))
        val processIncomingHtlc = actionsAlice4.find<ChannelAction.ProcessIncomingHtlc>()
        assertEquals(processIncomingHtlc.add, add)
    }

    companion object {
        fun init(): Pair<LNChannel<Normal>, LNChannel<Normal>> {
            // NB: we disable channel backups to ensure Bob sends his channel_reestablish on reconnection.
            val (alice, bob, _) = reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
            return Pair(alice, bob)
        }

        data class UnsignedRbfFixture(val alice: LNChannel<WaitForFundingConfirmed>, val commitSigAlice: CommitSig, val bob: LNChannel<WaitForFundingConfirmed>, val commitSigBob: CommitSig, val rbfFundingTxId: TxId)

        fun createUnsignedRbf(): UnsignedRbfFixture {
            val (alice, bob, _, wallet) = WaitForFundingConfirmedTestsCommon.init()
            val command = WaitForFundingConfirmedTestsCommon.createRbfCommand(alice, wallet)
            val (alice1, actionsAlice1) = alice.process(command)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<TxInitRbf>()))
            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<TxAckRbf>()))
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxAddInput>()))
            val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxAddInput>()))
            val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice3.findOutgoingMessage<TxAddInput>()))
            val (alice4, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(actionsBob3.findOutgoingMessage<TxComplete>()))
            val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(actionsAlice4.findOutgoingMessage<TxAddOutput>()))
            val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(actionsBob4.findOutgoingMessage<TxComplete>()))
            assertIs<LNChannel<WaitForFundingConfirmed>>(alice5)
            assertIs<WaitForFundingConfirmed>(alice5.state)
            assertIs<RbfStatus.WaitingForSigs>(alice5.state.rbfStatus)
            val (bob5, actionsBob5) = bob4.process(ChannelCommand.MessageReceived(actionsAlice5.findOutgoingMessage<TxComplete>()))
            assertIs<LNChannel<WaitForFundingConfirmed>>(bob5)
            assertIs<WaitForFundingConfirmed>(bob5.state)
            assertIs<RbfStatus.WaitingForSigs>(bob5.state.rbfStatus)
            val commitSigAlice = actionsAlice5.hasOutgoingMessage<CommitSig>()
            val commitSigBob = actionsBob5.hasOutgoingMessage<CommitSig>()
            return UnsignedRbfFixture(alice5, commitSigAlice, bob5, commitSigBob, (alice5.state.rbfStatus as RbfStatus.WaitingForSigs).session.fundingTx.txId)
        }

        fun disconnect(alice: LNChannel<ChannelStateWithCommitments>, bob: LNChannel<ChannelStateWithCommitments>): Triple<LNChannel<Syncing>, LNChannel<Syncing>, Pair<ChannelReestablish, ChannelReestablish>> {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.Disconnected)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.Disconnected)
            assertIs<Offline>(alice1.state)
            assertTrue(actionsAlice1.isEmpty())
            assertIs<Offline>(bob1.state)
            assertTrue(actionsBob1.isEmpty())

            val aliceInit = Init(alice1.commitments.params.localParams.features)
            val bobInit = Init(bob1.commitments.params.localParams.features)
            assertFalse(bob1.commitments.params.localParams.features.hasFeature(Feature.ChannelBackupClient))

            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Connected(aliceInit, bobInit))
            assertIs<LNChannel<Syncing>>(alice2)
            val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.Connected(bobInit, aliceInit))
            assertIs<LNChannel<Syncing>>(bob2)
            val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()
            return Triple(alice2, bob2, Pair(channelReestablishA, channelReestablishB))
        }

        data class SyncingFixture(val alice: LNChannel<Syncing>, val bob: LNChannel<Syncing>, val channelReestablishAlice: ChannelReestablish, val channelReestablishBob: ChannelReestablish?)

        fun disconnectWithBackup(alice: LNChannel<PersistedChannelState>, bob: LNChannel<PersistedChannelState>): SyncingFixture {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.Disconnected)
            val (bob1, actionsBob1) = bob.process(ChannelCommand.Disconnected)
            assertIs<Offline>(alice1.state)
            assertTrue(actionsAlice1.isEmpty())
            assertIs<Offline>(bob1.state)
            assertTrue(actionsBob1.isEmpty())

            val aliceFeatures = when (alice.state) {
                is WaitForFundingSigned -> alice.state.channelParams.localParams.features
                is ChannelStateWithCommitments -> alice.state.commitments.params.localParams.features
            }
            val aliceInit = Init(aliceFeatures)
            assertTrue(aliceFeatures.hasFeature(Feature.ChannelBackupProvider))
            val bobFeatures = when (bob.state) {
                is WaitForFundingSigned -> bob.state.channelParams.localParams.features
                is ChannelStateWithCommitments -> bob.state.commitments.params.localParams.features
            }
            val bobInit = Init(bobFeatures)
            assertTrue(bobFeatures.hasFeature(Feature.ChannelBackupClient))

            val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Connected(aliceInit, bobInit))
            assertIs<LNChannel<Syncing>>(alice2)
            val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
            val (bob2, actionsBob2) = bob1.process(ChannelCommand.Connected(bobInit, aliceInit))
            assertIs<LNChannel<Syncing>>(bob2)
            val channelReestablishB = when (bob2.state.state) {
                is WaitForFundingSigned -> {
                    assertEquals(1, actionsBob2.size)
                    actionsBob2.findOutgoingMessage<ChannelReestablish>()
                }
                else -> {
                    assertTrue(actionsBob2.isEmpty())
                    null
                }
            }
            return SyncingFixture(alice2, bob2, channelReestablishA, channelReestablishB)
        }
    }

}