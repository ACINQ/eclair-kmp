package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Lightning
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.processEx
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.utils.currentTimestampMillis
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.*
import kotlin.test.*

class WaitForFundingConfirmedTestsCommon : LightningTestSuite() {
    @Test
    fun `receive FundingLocked`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val fundingTx = alice.fundingTx!!
        val (bob1, actionsBob) = bob.processEx(ChannelEvent.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
        val fundingLocked = actionsBob.findOutgoingMessage<FundingLocked>()
        assertTrue { bob1 is WaitForFundingLocked }
        val (alice1, actionsAlice) = alice.processEx(ChannelEvent.MessageReceived(fundingLocked))
        assertTrue { alice1 is WaitForFundingConfirmed && alice1.deferred == fundingLocked }
        assertTrue { actionsAlice.isEmpty() } // alice waits until she sees on-chain confirmations herself
    }

    @Test
    fun `receive BITCOIN_FUNDING_DEPTHOK`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val fundingTx = alice.fundingTx!!
        val (bob1, actions) = bob.processEx(ChannelEvent.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, fundingTx)))
        actions.findOutgoingMessage<FundingLocked>()
        actions.hasWatch<WatchLost>()
        actions.has<ChannelAction.Storage.StoreState>()
        assertTrue { bob1 is WaitForFundingLocked }
    }

    @Test
    fun `receive BITCOIN_FUNDING_DEPTHOK (bad funding pubkey script)`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val fundingTx = alice.fundingTx!!
        val badOutputScript = Scripts.multiSig2of2(Lightning.randomKey().publicKey(), Lightning.randomKey().publicKey())
        val badFundingTx = fundingTx.copy(txOut = fundingTx.txOut.updated(0, fundingTx.txOut[0].updatePublicKeyScript(badOutputScript)))

        val (bob1, actions1) = bob.processEx(ChannelEvent.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, badFundingTx)))
        assertTrue(bob1 is Closing)

        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(InvalidCommitmentSignature(bob.channelId, badFundingTx).message, error.toAscii())

        val commitTx = bob1.localCommitPublished?.commitTx
        assertNotNull(commitTx)
        val claimDelayedOutputTx = bob1.localCommitPublished?.claimMainDelayedOutputTx
        assertNotNull(claimDelayedOutputTx)

        val publishAsap = actions1.findTxs()
        assertEquals(2, publishAsap.size)
        assertEquals(commitTx.txid, publishAsap.first().txid)
        assertEquals(claimDelayedOutputTx.tx.txid, publishAsap.last().txid)

        assertEquals(2, actions1.findWatches<WatchConfirmed>().size)
        val watches = actions1.findWatches<WatchConfirmed>()
        assertEquals(commitTx.txid, watches.first().txId)
        assertEquals(claimDelayedOutputTx.tx.txid, watches.last().txId)
    }

    @Test
    fun `receive BITCOIN_FUNDING_DEPTHOK (bad funding amount)`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val fundingTx = alice.fundingTx
        assertNotNull(fundingTx)
        val badAmount = 1_234_567.sat
        val badFundingTx = fundingTx.copy(txOut = fundingTx.txOut.updated(0, fundingTx.txOut[0].updateAmount(badAmount)))

        val (bob1, actions1) = bob.processEx(ChannelEvent.WatchReceived(WatchEventConfirmed(bob.channelId, BITCOIN_FUNDING_DEPTHOK, 42, 0, badFundingTx)))
        assertTrue(bob1 is Closing)

        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(InvalidCommitmentSignature(bob.channelId, badFundingTx).message, error.toAscii())

        val commitTx = bob1.localCommitPublished?.commitTx
        assertNotNull(commitTx)
        val claimDelayedOutputTx = bob1.localCommitPublished?.claimMainDelayedOutputTx
        assertNotNull(claimDelayedOutputTx)

        val publishAsap = actions1.findTxs()
        assertEquals(2, publishAsap.size)
        assertEquals(commitTx.txid, publishAsap.first().txid)
        assertEquals(claimDelayedOutputTx.tx.txid, publishAsap.last().txid)

        assertEquals(2, actions1.findWatches<WatchConfirmed>().size)
        val watches = actions1.findWatches<WatchConfirmed>()
        assertEquals(commitTx.txid, watches.first().txId)
        assertEquals(claimDelayedOutputTx.tx.txid, watches.last().txId)
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (remote commit)`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)

        // case 1: alice publishes her commitment tx
        run {
            val (bob1, actions1) = bob.processEx(ChannelEvent.WatchReceived(WatchEventSpent(bob.channelId, BITCOIN_FUNDING_SPENT, alice.commitments.localCommit.publishableTxs.commitTx.tx)))
            assertTrue(bob1 is Closing)
            assertNotNull(bob1.remoteCommitPublished)
            actions1.hasTx(bob1.remoteCommitPublished!!.claimMainOutputTx!!.tx)
            assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
        }

        // case 2: bob publishes his commitment tx
        run {
            val (alice1, actions1) = alice.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, bob.commitments.localCommit.publishableTxs.commitTx.tx)))
            assertTrue(alice1 is Closing)
            assertNotNull(alice1.remoteCommitPublished)
            actions1.hasTx(alice1.remoteCommitPublished!!.claimMainOutputTx!!.tx)
            assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
        }
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (other commit)`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val spendingTx = Transaction(version = 2, txIn = alice.commitments.localCommit.publishableTxs.commitTx.tx.txIn, txOut = listOf(), lockTime = 0)
        listOf(alice, bob).forEach { state ->
            val (state1, actions1) = state.processEx(ChannelEvent.WatchReceived(WatchEventSpent(state.channelId, BITCOIN_FUNDING_SPENT, spendingTx)))
            assertTrue(state1 is ErrorInformationLeak)
            assertTrue(actions1.isEmpty())
        }
    }

    @Test
    fun `recv Error`() {
        val (_, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (bob1, actions1) = bob.processEx(ChannelEvent.MessageReceived(Error(bob.channelId, "oops")))
        assertTrue(bob1 is Closing)
        assertNotNull(bob1.localCommitPublished)
        actions1.hasTx(bob.commitments.localCommit.publishableTxs.commitTx.tx)
        assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
    }

    @Test
    fun `recv CMD_CLOSE`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        listOf(alice, bob).forEach { state ->
            val (state1, actions1) = state.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null, null)))
            assertEquals(state, state1)
            actions1.hasCommandError<CommandUnavailableInThisState>()
        }
    }

    @Test
    fun `recv CMD_FORCECLOSE`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        listOf(alice, bob).forEach { state ->
            val (state1, actions1) = state.processEx(ChannelEvent.ExecuteCommand(CMD_FORCECLOSE))
            assertTrue(state1 is Closing)
            assertNotNull(state1.localCommitPublished)
            actions1.hasTx(state1.localCommitPublished!!.commitTx)
            actions1.hasTx(state1.localCommitPublished!!.claimMainDelayedOutputTx!!.tx)
            assertEquals(2, actions1.findWatches<WatchConfirmed>().size) // commit tx + main output
        }
    }

    @Test
    fun `recv CMD_FORCECLOSE (nothing at stake)`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, 0.msat)
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_FORCECLOSE))
        assertTrue(bob1 is Aborted)
        assertEquals(1, actions1.size)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(ForcedLocalCommit(alice.channelId).message, error.toAscii())
    }

    @Test
    fun `recv NewBlock`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        listOf(alice, bob).forEach { state ->
            run {
                val (state1, actions1) = state.processEx(ChannelEvent.NewBlock(state.currentBlockHeight + 1, Block.RegtestGenesisBlock.header))
                assertEquals(state.copy(currentTip = state1.currentTip), state1)
                assertTrue(actions1.isEmpty())
            }
            run {
                val (state1, actions1) = state.processEx(ChannelEvent.CheckHtlcTimeout)
                assertEquals(state, state1)
                assertTrue(actions1.isEmpty())
            }
        }
    }

    @Test
    fun `recv Disconnected`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (alice1, _) = alice.processEx(ChannelEvent.Disconnected)
        assertTrue { alice1 is Offline }
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue { bob1 is Offline }
    }

    @Test
    fun `recv Disconnected (get funding tx successful)`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (alice1, _) = alice.processEx(ChannelEvent.Disconnected)
        assertTrue { alice1 is Offline }
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue { bob1 is Offline }

        alice.fundingTx?.let {
            val (alice2, actions2) = alice1.process(ChannelEvent.GetFundingTxResponse(GetTxWithMetaResponse(it.txid, it, currentTimestampMillis())))
            assertTrue { alice2 is Offline }
            assertTrue { actions2.isEmpty() }
        } ?: fail("Alice's funding tx must not be null.")
    }

    @Test
    fun `recv Disconnected (get funding tx error)`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (alice1, _) = alice.processEx(ChannelEvent.Disconnected)
        assertTrue { alice1 is Offline }
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue { bob1 is Offline }

        alice.fundingTx?.let {
            val (alice2, actions2) = alice1.processEx(ChannelEvent.GetFundingTxResponse(GetTxWithMetaResponse(it.txid, null, currentTimestampMillis())))
            assertTrue { alice2 is Offline }
            assertTrue { actions2.isNotEmpty() }
            actions2.hasTx(it)
        } ?: fail("Alice's funding tx must not be null.")
    }

    @Test
    fun `on reconnection a zero-reserve channel needs to register a zero-confirmation watch on funding tx`() {
        val (alice, bob) = init(ChannelVersion.STANDARD or ChannelVersion.ZERO_RESERVE, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue { bob1 is Offline }

        val localInit = Init(ByteVector(TestConstants.Alice.channelParams.features.toByteArray()))
        val remoteInit = Init(ByteVector(TestConstants.Bob.channelParams.features.toByteArray()))

        val (bob2, actions2) = bob1.processEx(ChannelEvent.Connected(remoteInit, localInit))
        assertTrue(bob2 is Syncing)
        assertTrue(actions2.isEmpty())

        val channelReestablishAlice = run {
            val yourLastPerCommitmentSecret = alice.commitments.remotePerCommitmentSecrets.lastIndex?.let { alice.commitments.remotePerCommitmentSecrets.getHash(it) } ?: ByteVector32.Zeroes
            val channelKeyPath = alice.keyManager.channelKeyPath(alice.commitments.localParams, alice.commitments.channelVersion)
            val myCurrentPerCommitmentPoint = alice.keyManager.commitmentPoint(channelKeyPath, alice.commitments.localCommit.index)

            ChannelReestablish(
                channelId = alice.channelId,
                nextLocalCommitmentNumber = alice.commitments.localCommit.index + 1,
                nextRemoteRevocationNumber = alice.commitments.remoteCommit.index,
                yourLastCommitmentSecret = PrivateKey(yourLastPerCommitmentSecret),
                myCurrentPerCommitmentPoint = myCurrentPerCommitmentPoint
            ).withChannelData(alice.commitments.remoteChannelData)
        }

        val (bob3, actions3) = bob2.processEx(ChannelEvent.MessageReceived(channelReestablishAlice))
        assertEquals(bob, bob3)
        assertEquals(2, actions3.size)
        actions3.hasOutgoingMessage<ChannelReestablish>()
        val bobWatch = actions3.hasWatch<WatchConfirmed>()
        assertEquals(0, bobWatch.minDepth)
    }

    @Test
    fun `get funding tx in Syncing state`() {
        val (alice, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue { bob1 is Offline && bob1.state is WaitForFundingConfirmed }
        val localInit = Init(ByteVector(bob.commitments.localParams.features.toByteArray()))
        val remoteInit = Init(ByteVector(alice.commitments.localParams.features.toByteArray()))
        val (bob2, _) = bob1.processEx(ChannelEvent.Connected(localInit, remoteInit))
        assertTrue { bob2 is Syncing && bob2.state is WaitForFundingConfirmed }

        // Actual test start here
        // Nothing happens, we need to wait 2016 blocks for the funding tx to be confirmed
        val (bob3, _) = bob2.processEx(ChannelEvent.GetFundingTxResponse(GetTxWithMetaResponse(bob.commitments.commitInput.outPoint.txid, null, currentTimestampMillis())))
        assertEquals(bob2, bob3)
        // Fast forward after the funding timeout
        val (bob4, _) = bob3.processEx(ChannelEvent.NewBlock(bob3.currentBlockHeight + Channel.FUNDING_TIMEOUT_FUNDEE_BLOCK + 1, BlockHeader(0, ByteVector32.Zeroes, ByteVector32.Zeroes, 0, 0, 0)))
        // We give up, Channel is aborted
        val (bob5, actions5) = bob4.processEx(ChannelEvent.GetFundingTxResponse(GetTxWithMetaResponse(bob.commitments.commitInput.outPoint.txid, null, currentTimestampMillis())))
        assertTrue { bob5 is Aborted }
        assertEquals(1, actions5.size)
        val error = actions5.hasOutgoingMessage<Error>()
        assertEquals(Error(bob.channelId, FundingTxTimedout(bob.channelId).message), error)
    }

    @Test
    fun `get funding tx in Offline state`() {
        val (_, bob) = init(ChannelVersion.STANDARD, TestConstants.fundingAmount, TestConstants.pushMsat)
        val (bob1, _) = bob.process(ChannelEvent.Disconnected)
        assertTrue { bob1 is Offline && bob1.state is WaitForFundingConfirmed }

        // Actual test start here
        // Nothing happens, we need to wait 2016 blocks for the funding tx to be confirmed
        val (bob2, _) = bob1.processEx(ChannelEvent.GetFundingTxResponse(GetTxWithMetaResponse(bob.commitments.commitInput.outPoint.txid, null, currentTimestampMillis())))
        assertEquals(bob1, bob2)
        // Fast forward after the funding timeout
        val (bob3, _) = bob2.processEx(ChannelEvent.NewBlock(bob2.currentBlockHeight + Channel.FUNDING_TIMEOUT_FUNDEE_BLOCK + 1, BlockHeader(0, ByteVector32.Zeroes, ByteVector32.Zeroes, 0, 0, 0)))
        // We give up, Channel is aborted
        val (bob4, actions4) = bob3.processEx(ChannelEvent.GetFundingTxResponse(GetTxWithMetaResponse(bob.commitments.commitInput.outPoint.txid, null, currentTimestampMillis())))
        assertTrue { bob4 is Aborted }
        assertEquals(1, actions4.size)
        val error = actions4.hasOutgoingMessage<Error>()
        assertEquals(Error(bob.channelId, FundingTxTimedout(bob.channelId).message), error)
    }

    companion object {
        fun init(channelVersion: ChannelVersion, fundingAmount: Satoshi, pushAmount: MilliSatoshi): Pair<WaitForFundingConfirmed, WaitForFundingConfirmed> {
            val (alice, bob, fundingCreated) = WaitForFundingCreatedTestsCommon.init(channelVersion, fundingAmount, pushAmount)
            val (bob1, actions1) = bob.processEx(ChannelEvent.MessageReceived(fundingCreated))
            val fundingSigned = actions1.findOutgoingMessage<FundingSigned>()
            val (alice1, _) = alice.processEx(ChannelEvent.MessageReceived(fundingSigned))
            return Pair(alice1 as WaitForFundingConfirmed, bob1 as WaitForFundingConfirmed)
        }
    }
}
