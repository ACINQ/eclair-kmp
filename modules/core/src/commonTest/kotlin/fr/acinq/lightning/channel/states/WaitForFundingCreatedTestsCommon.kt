package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.Feature
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.Features
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.utils.toMilliSatoshi
import fr.acinq.lightning.wire.*
import kotlin.test.*

class WaitForFundingCreatedTestsCommon : LightningTestSuite() {

    private fun verifyCommits(signingSessionAlice: InteractiveTxSigningSession, signingSessionBob: InteractiveTxSigningSession, balanceAlice: MilliSatoshi, balanceBob: MilliSatoshi) {
        assertTrue(signingSessionAlice.localCommit.isLeft)
        val localCommitAlice = signingSessionAlice.localCommit.left!!
        val remoteCommitAlice = signingSessionAlice.remoteCommit
        assertTrue(signingSessionBob.localCommit.isLeft)
        val localCommitBob = signingSessionBob.localCommit.left!!
        val remoteCommitBob = signingSessionBob.remoteCommit
        assertEquals(localCommitAlice.spec.toLocal, balanceAlice)
        assertEquals(localCommitAlice.spec.toRemote, balanceBob)
        assertEquals(remoteCommitAlice.spec.toLocal, balanceBob)
        assertEquals(remoteCommitAlice.spec.toRemote, balanceAlice)
        assertEquals(localCommitBob.spec.toLocal, balanceBob)
        assertEquals(localCommitBob.spec.toRemote, balanceAlice)
        assertEquals(remoteCommitBob.spec.toLocal, balanceAlice)
        assertEquals(remoteCommitBob.spec.toRemote, balanceBob)
    }

    @Test
    fun `complete interactive-tx protocol`() = runSuspendTest {
        val (alice, bob, inputAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        // Alice ---- tx_add_input ----> Bob
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(inputAlice))
        // Alice <--- tx_complete ----- Bob
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<TxComplete>()))
        // Alice ---- tx_add_output ----> Bob
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<TxAddOutput>()))
        // Alice <--- tx_complete ----- Bob
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
        // Alice ---- tx_complete ----> Bob
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxComplete>()))
        val commitSigAlice = actionsAlice2.findOutgoingMessage<CommitSig>()
        val commitSigBob = actionsBob3.findOutgoingMessage<CommitSig>()
        assertEquals(commitSigAlice.channelId, commitSigBob.channelId)
        assertTrue(commitSigAlice.htlcSignatures.isEmpty())
        assertTrue(commitSigAlice.channelData.isEmpty())
        assertTrue(commitSigBob.htlcSignatures.isEmpty())
        assertFalse(commitSigBob.channelData.isEmpty())
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsBob3.has<ChannelAction.Storage.StoreState>()
        assertIs<WaitForFundingSigned>(alice2.state)
        assertIs<WaitForFundingSigned>(bob3.state)
        assertEquals(alice2.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.DualFunding)))
        assertEquals(bob3.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.DualFunding)))
        assertIs<ChannelFundingResponse.Success>(alice.state.replyTo.await()).also { assertEquals(0, it.fundingTxIndex) }
        assertIs<ChannelFundingResponse.Success>(bob.state.replyTo.await()).also { assertEquals(0, it.fundingTxIndex) }
        verifyCommits(alice2.state.signingSession, bob3.state.signingSession, TestConstants.aliceFundingAmount.toMilliSatoshi(), 0.msat)
    }

    @Test
    fun `complete interactive-tx protocol -- simple taproot channels`() {
        val (alice, bob, inputAlice) = init(
            ChannelType.SupportedChannelType.SimpleTaprootStaging,
            aliceFeatures = TestConstants.Alice.nodeParams.features.initFeatures().add(Feature.SimpleTaprootStaging to FeatureSupport.Mandatory),
            bobFeatures = TestConstants.Bob.nodeParams.features.initFeatures().add(Feature.SimpleTaprootStaging to FeatureSupport.Mandatory),
            bobFundingAmount = 0.sat
        )
        // Alice ---- tx_add_input ----> Bob
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(inputAlice))
        // Alice <--- tx_complete ----- Bob
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<TxComplete>()))
        // Alice ---- tx_add_output ----> Bob
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<TxAddOutput>()))
        // Alice <--- tx_complete ----- Bob
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
        // Alice ---- tx_complete ----> Bob
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxComplete>()))
        val commitSigAlice = actionsAlice2.findOutgoingMessage<CommitSig>()
        val commitSigBob = actionsBob3.findOutgoingMessage<CommitSig>()
        assertEquals(commitSigAlice.channelId, commitSigBob.channelId)
        assertTrue(commitSigAlice.htlcSignatures.isEmpty())
        assertTrue(commitSigAlice.channelData.isEmpty())
        assertTrue(commitSigBob.htlcSignatures.isEmpty())
        assertFalse(commitSigBob.channelData.isEmpty())
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsBob3.has<ChannelAction.Storage.StoreState>()
        assertIs<WaitForFundingSigned>(alice2.state)
        assertIs<WaitForFundingSigned>(bob3.state)
        assertEquals(alice2.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.ZeroReserveChannels, Feature.DualFunding, Feature.SimpleTaprootStaging)))
        assertEquals(bob3.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.ZeroReserveChannels, Feature.DualFunding, Feature.SimpleTaprootStaging)))
        verifyCommits(alice2.state.signingSession, bob3.state.signingSession, TestConstants.aliceFundingAmount.toMilliSatoshi(), 0.msat)
    }

    @Test
    fun `complete interactive-tx protocol -- with non-initiator contributions`() {
        val (alice, bob, inputAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs)
        // Alice ---- tx_add_input ----> Bob
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(inputAlice))
        // Alice <--- tx_add_input ----- Bob
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<TxAddInput>()))
        // Alice ---- tx_add_output ----> Bob
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<TxAddOutput>()))
        // Alice <--- tx_complete ----- Bob
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
        // Alice ---- tx_complete ----> Bob
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxComplete>()))
        val commitSigAlice = actionsAlice2.findOutgoingMessage<CommitSig>()
        val commitSigBob = actionsBob3.findOutgoingMessage<CommitSig>()
        assertEquals(commitSigAlice.channelId, commitSigBob.channelId)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsBob3.has<ChannelAction.Storage.StoreState>()
        assertIs<WaitForFundingSigned>(alice2.state)
        assertIs<WaitForFundingSigned>(bob3.state)
        assertEquals(alice2.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.DualFunding)))
        assertEquals(bob3.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.DualFunding)))
        verifyCommits(
            alice2.state.signingSession,
            bob3.state.signingSession,
            TestConstants.aliceFundingAmount.toMilliSatoshi(),
            TestConstants.bobFundingAmount.toMilliSatoshi()
        )
    }

    @Test
    fun `complete interactive-tx protocol -- with large non-initiator contributions`() {
        // Alice's funding amount is below the channel reserve: this is ok as long as she can pay the commit tx fees.
        val (alice, bob, inputAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs, aliceFundingAmount = 10_000.sat, bobFundingAmount = 1_500_000.sat)
        // Alice ---- tx_add_input ----> Bob
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(inputAlice))
        // Alice <--- tx_add_input ----- Bob
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<TxAddInput>()))
        // Alice ---- tx_add_output ----> Bob
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<TxAddOutput>()))
        // Alice <--- tx_complete ----- Bob
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
        // Alice ---- tx_complete ----> Bob
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxComplete>()))
        val commitSigAlice = actionsAlice2.findOutgoingMessage<CommitSig>()
        val commitSigBob = actionsBob3.findOutgoingMessage<CommitSig>()
        assertEquals(commitSigAlice.channelId, commitSigBob.channelId)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsBob3.has<ChannelAction.Storage.StoreState>()
        assertIs<WaitForFundingSigned>(alice2.state)
        assertIs<WaitForFundingSigned>(bob3.state)
        assertEquals(alice2.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.DualFunding)))
        assertEquals(bob3.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.DualFunding)))
        verifyCommits(alice2.state.signingSession, bob3.state.signingSession, balanceAlice = 10_000_000.msat, balanceBob = 1_500_000_000.msat)
    }

    @Test
    fun `complete interactive-tx protocol -- zero conf -- zero reserve`() {
        val (alice, bob, inputAlice) = init(ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, zeroConf = true)
        // Alice ---- tx_add_input ----> Bob
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(inputAlice))
        // Alice <--- tx_add_input ----- Bob
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(actionsBob1.findOutgoingMessage<TxAddInput>()))
        // Alice ---- tx_add_output ----> Bob
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(actionsAlice1.findOutgoingMessage<TxAddOutput>()))
        // Alice <--- tx_complete ----- Bob
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(actionsBob2.findOutgoingMessage<TxComplete>()))
        // Alice ---- tx_complete ----> Bob
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.MessageReceived(actionsAlice2.findOutgoingMessage<TxComplete>()))
        val commitSigAlice = actionsAlice2.findOutgoingMessage<CommitSig>()
        val commitSigBob = actionsBob3.findOutgoingMessage<CommitSig>()
        assertEquals(commitSigAlice.channelId, commitSigBob.channelId)
        actionsAlice2.has<ChannelAction.Storage.StoreState>()
        actionsBob3.has<ChannelAction.Storage.StoreState>()
        assertIs<WaitForFundingSigned>(alice2.state)
        assertIs<WaitForFundingSigned>(bob3.state)
        assertEquals(alice2.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.ZeroReserveChannels, Feature.DualFunding)))
        assertEquals(bob3.state.channelParams.channelFeatures, ChannelFeatures(setOf(Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.ZeroReserveChannels, Feature.DualFunding)))
        verifyCommits(alice2.state.signingSession, bob3.state.signingSession, TestConstants.aliceFundingAmount.toMilliSatoshi(), TestConstants.bobFundingAmount.toMilliSatoshi())
    }

    @Test
    fun `recv invalid interactive-tx message`() {
        val (_, bob, inputAlice) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        run {
            // Invalid serial_id.
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(inputAlice.copy(serialId = 1)))
            actionsBob1.hasOutgoingMessage<Error>()
            assertIs<Aborted>(bob1.state)
        }
        run {
            // Below dust.
            val txAddOutput = TxAddOutput(inputAlice.channelId, 2, 100.sat, Script.write(Script.pay2wpkh(randomKey().publicKey())).toByteVector())
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(txAddOutput))
            actionsBob1.hasOutgoingMessage<Error>()
            assertIs<Aborted>(bob1.state)
        }
    }

    @Test
    fun `recv CommitSig`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        run {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(CommitSig(alice.channelId, ByteVector64.Zeroes, listOf())))
            assertEquals(actionsAlice1.findOutgoingMessage<Error>().toAscii(), UnexpectedCommitSig(alice.channelId).message)
            assertIs<Aborted>(alice1.state)
        }
        run {
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(CommitSig(bob.channelId, ByteVector64.Zeroes, listOf())))
            assertEquals(actionsBob1.findOutgoingMessage<Error>().toAscii(), UnexpectedCommitSig(bob.channelId).message)
            assertIs<Aborted>(bob1.state)
        }
    }

    @Test
    fun `recv TxSignatures`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        run {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(TxSignatures(alice.channelId, TxId(randomBytes32()), listOf())))
            assertEquals(actionsAlice1.findOutgoingMessage<Error>().toAscii(), UnexpectedFundingSignatures(alice.channelId).message)
            assertIs<Aborted>(alice1.state)
        }
        run {
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(TxSignatures(bob.channelId, TxId(randomBytes32()), listOf())))
            assertEquals(actionsBob1.findOutgoingMessage<Error>().toAscii(), UnexpectedFundingSignatures(bob.channelId).message)
            assertIs<Aborted>(bob1.state)
        }
    }

    @Test
    fun `recv TxAbort`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        run {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(TxAbort(alice.channelId, "changed my mind")))
            assertEquals(actionsAlice1.size, 1)
            actionsAlice1.hasOutgoingMessage<TxAbort>()
            assertIs<Aborted>(alice1.state)
        }
        run {
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(TxAbort(bob.channelId, "changed my mind")))
            assertEquals(actionsBob1.size, 1)
            actionsBob1.hasOutgoingMessage<TxAbort>()
            assertIs<Aborted>(bob1.state)
        }
    }

    @Test
    fun `recv TxInitRbf`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        run {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(TxInitRbf(alice.channelId, 0, FeeratePerKw(7500.sat))))
            assertEquals(actionsAlice1.size, 1)
            assertEquals(actionsAlice1.findOutgoingMessage<Warning>().toAscii(), InvalidRbfAttempt(alice.channelId).message)
            assertEquals(alice, alice1)
        }
        run {
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(TxInitRbf(bob.channelId, 0, FeeratePerKw(7500.sat))))
            assertEquals(actionsBob1.size, 1)
            assertEquals(actionsBob1.findOutgoingMessage<Warning>().toAscii(), InvalidRbfAttempt(bob.channelId).message)
            assertEquals(bob, bob1)
        }
    }

    @Test
    fun `recv TxAckRbf`() {
        val (alice, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        run {
            val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(TxAckRbf(alice.channelId)))
            assertEquals(actionsAlice1.size, 1)
            assertEquals(actionsAlice1.findOutgoingMessage<Warning>().toAscii(), InvalidRbfAttempt(alice.channelId).message)
            assertEquals(alice, alice1)
        }
        run {
            val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(TxAckRbf(bob.channelId)))
            assertEquals(actionsBob1.size, 1)
            assertEquals(actionsBob1.findOutgoingMessage<Warning>().toAscii(), InvalidRbfAttempt(bob.channelId).message)
            assertEquals(bob, bob1)
        }
    }

    @Test
    fun `recv Error`() = runSuspendTest {
        val (_, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertIs<Aborted>(bob1.state)
        assertTrue(actions1.isEmpty())
        assertIs<ChannelFundingResponse.Failure.AbortedByPeer>(bob.state.replyTo.await())
    }

    @Test
    fun `recv ChannelCommand_Close_ForceClose`() {
        val (_, bob, _) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        val (bob1, actions1) = bob.process(ChannelCommand.Close.ForceClose)
        assertEquals(actions1.findOutgoingMessage<Error>().toAscii(), ForcedLocalCommit(bob.channelId).message)
        assertIs<Aborted>(bob1.state)
    }

    @Test
    fun `recv Disconnected`() = runSuspendTest {
        val (_, bob, txAddInput) = init(ChannelType.SupportedChannelType.AnchorOutputs, bobFundingAmount = 0.sat)
        val (bob1, _) = bob.process(ChannelCommand.MessageReceived(txAddInput))
        assertIs<WaitForFundingCreated>(bob1.state)
        val (bob2, actions2) = bob1.process(ChannelCommand.Disconnected)
        assertIs<Aborted>(bob2.state)
        assertTrue(actions2.isEmpty())
        assertIs<ChannelFundingResponse.Failure.Disconnected>(bob.state.replyTo.await())
    }

    companion object {
        data class Fixture(val alice: LNChannel<WaitForFundingCreated>, val bob: LNChannel<WaitForFundingCreated>, val aliceInput: TxAddInput, val aliceWallet: List<WalletState.Utxo>)

        fun init(
            channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
            aliceFeatures: Features = TestConstants.Alice.nodeParams.features.initFeatures(),
            bobFeatures: Features = TestConstants.Bob.nodeParams.features.initFeatures(),
            currentHeight: Int = TestConstants.defaultBlockHeight,
            aliceFundingAmount: Satoshi = TestConstants.aliceFundingAmount,
            bobFundingAmount: Satoshi = TestConstants.bobFundingAmount,
            requestRemoteFunding: Satoshi? = null,
            zeroConf: Boolean = false,
            channelOrigin: Origin? = null
        ): Fixture {
            val (a, b, open) = TestsHelper.init(channelType, aliceFeatures, bobFeatures, currentHeight, aliceFundingAmount, bobFundingAmount, requestRemoteFunding, zeroConf, channelOrigin)
            val (b1, actions) = b.process(ChannelCommand.MessageReceived(open))
            val accept = actions.findOutgoingMessage<AcceptDualFundedChannel>()
            assertIs<LNChannel<WaitForFundingCreated>>(b1)
            assertIs<WaitForFundingCreated>(b1.state)
            val (a1, actions2) = a.process(ChannelCommand.MessageReceived(accept))
            val aliceInput = actions2.findOutgoingMessage<TxAddInput>()
            assertIs<LNChannel<WaitForFundingCreated>>(a1)
            assertIs<WaitForFundingCreated>(a1.state)
            return Fixture(a1, b1, aliceInput, a.state.init.walletInputs)
        }
    }
}
