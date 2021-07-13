package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_SPENT
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.blockchain.WatchSpent
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.htlcSuccessTxs
import fr.acinq.lightning.channel.TestsHelper.htlcTimeoutTxs
import fr.acinq.lightning.channel.TestsHelper.processEx
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.*
import kotlin.test.*

class OfflineTestsCommon : LightningTestSuite() {

    @Test
    fun `handle disconnect - connect events (no messages sent yet)`() {
        val (alice, bob) = TestsHelper.reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
        val (alice1, _) = alice.processEx(ChannelEvent.Disconnected)
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue(alice1 is Offline)
        assertTrue(bob1 is Offline)

        val localInit = Init(ByteVector(alice.commitments.localParams.features.toByteArray()))
        val remoteInit = Init(ByteVector(bob.commitments.localParams.features.toByteArray()))

        val (alice2, actions) = alice1.processEx(ChannelEvent.Connected(localInit, remoteInit))
        assertTrue(alice2 is Syncing)
        val channelReestablishA = actions.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actions1) = bob1.processEx(ChannelEvent.Connected(remoteInit, localInit))
        assertTrue(bob2 is Syncing)
        val channelReestablishB = actions1.findOutgoingMessage<ChannelReestablish>()

        val bobCommitments = bob.commitments
        val aliceCommitments = alice.commitments
        val bobCurrentPerCommitmentPoint = bob.keyManager.commitmentPoint(
            bob.keyManager.channelKeyPath(bobCommitments.localParams, bobCommitments.channelConfig),
            bobCommitments.localCommit.index
        )
        val aliceCurrentPerCommitmentPoint = alice.keyManager.commitmentPoint(
            alice.keyManager.channelKeyPath(aliceCommitments.localParams, aliceCommitments.channelConfig),
            aliceCommitments.localCommit.index
        )

        // alice didn't receive any update or sig
        assertEquals(
            ChannelReestablish(alice.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), aliceCurrentPerCommitmentPoint),
            channelReestablishA.copy(tlvStream = TlvStream.empty())
        )
        assertEquals(
            ChannelReestablish(bob.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), bobCurrentPerCommitmentPoint),
            channelReestablishB
        )

        val (alice3, actions2) = alice2.processEx(ChannelEvent.MessageReceived(channelReestablishB))
        assertEquals(alice, alice3)
        assertEquals(2, actions2.size)
        actions2.hasOutgoingMessage<FundingLocked>()
        actions2.hasWatch<WatchConfirmed>()

        val (bob3, actions3) = bob2.processEx(ChannelEvent.MessageReceived(channelReestablishA))
        assertEquals(bob, bob3)
        assertEquals(2, actions3.size)
        actions3.hasOutgoingMessage<FundingLocked>()
        actions3.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `re-send update and sig after first commitment`() {
        val (alice0, bob0) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
            val cmdAdd = CMD_ADD_HTLC(1_000_000.msat, ByteVector32.Zeroes, CltvExpiryDelta(144).toCltvExpiry(alice0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket, UUID.randomUUID())
            val (alice1, actions1) = alice0.processEx(ChannelEvent.ExecuteCommand(cmdAdd))
            val add = actions1.hasOutgoingMessage<UpdateAddHtlc>()
            val (alice2, actions2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
            assertTrue(alice2 is Normal)
            actions2.hasOutgoingMessage<CommitSig>()
            val (bob1, _) = bob0.processEx(ChannelEvent.MessageReceived(add))
            assertTrue(bob1 is Normal)
            // bob doesn't receive the sig
            Pair(alice2, bob1)
        }

        val (alice1, _) = alice0.processEx(ChannelEvent.Disconnected)
        val (bob1, _) = bob0.processEx(ChannelEvent.Disconnected)
        assertTrue(alice1 is Offline)
        assertTrue(bob1 is Offline)

        val localInit = Init(ByteVector(alice0.commitments.localParams.features.toByteArray()))
        val remoteInit = Init(ByteVector(bob0.commitments.localParams.features.toByteArray()))

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.Connected(localInit, remoteInit))
        assertTrue(alice2 is Syncing)
        val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.Connected(remoteInit, localInit))
        assertTrue(bob2 is Syncing)
        val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()

        val bobCommitments = bob0.commitments
        val aliceCommitments = alice0.commitments
        val bobCurrentPerCommitmentPoint = bob0.keyManager.commitmentPoint(
            bob0.keyManager.channelKeyPath(bobCommitments.localParams, bobCommitments.channelConfig),
            bobCommitments.localCommit.index
        )
        val aliceCurrentPerCommitmentPoint = alice0.keyManager.commitmentPoint(
            alice0.keyManager.channelKeyPath(aliceCommitments.localParams, aliceCommitments.channelConfig),
            aliceCommitments.localCommit.index
        )

        // alice didn't receive any update or sig
        assertEquals(channelReestablishA, ChannelReestablish(alice0.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), aliceCurrentPerCommitmentPoint))
        // bob did not receive alice's sig
        assertEquals(channelReestablishB, ChannelReestablish(bob0.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), bobCurrentPerCommitmentPoint))

        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(channelReestablishB))
        // alice sends FundingLocked again
        actionsAlice3.hasOutgoingMessage<FundingLocked>()
        // alice re-sends the update and the sig
        val add = actionsAlice3.hasOutgoingMessage<UpdateAddHtlc>()
        val sig = actionsAlice3.hasOutgoingMessage<CommitSig>()

        val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.MessageReceived(channelReestablishA))
        actionsBob3.hasOutgoingMessage<FundingLocked>() // bob sends FundingLocked again
        assertNull(actionsBob3.findOutgoingMessageOpt<RevokeAndAck>()) // bob didn't receive the sig, so he cannot send a rev

        val (bob4, _) = bob3.processEx(ChannelEvent.MessageReceived(add))
        val (bob5, actionsBob5) = bob4.processEx(ChannelEvent.MessageReceived(sig))
        // bob sends back a revocation and a sig
        val revB = actionsBob5.hasOutgoingMessage<RevokeAndAck>()
        actionsBob5.hasCommand<CMD_SIGN>()
        val (bob6, actionsBob6) = bob5.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val sigB = actionsBob6.hasOutgoingMessage<CommitSig>()

        val (alice4, _) = alice3.processEx(ChannelEvent.MessageReceived(revB))
        val (alice5, actionsAlice5) = alice4.processEx(ChannelEvent.MessageReceived(sigB))
        assertTrue(alice5 is Normal)
        val revA = actionsAlice5.hasOutgoingMessage<RevokeAndAck>()

        val (bob7, _) = bob6.processEx(ChannelEvent.MessageReceived(revA))
        assertTrue(bob7 is Normal)

        assertEquals(1, alice5.commitments.localNextHtlcId)
        assertEquals(1, bob7.commitments.remoteNextHtlcId)
    }

    @Test
    fun `re-send lost revocation`() {
        val (alice0, bob0) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
            val cmdAdd = CMD_ADD_HTLC(1_000_000.msat, ByteVector32.Zeroes, CltvExpiryDelta(144).toCltvExpiry(alice0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket, UUID.randomUUID())
            val (alice1, actionsAlice1) = alice0.processEx(ChannelEvent.ExecuteCommand(cmdAdd))
            val add = actionsAlice1.hasOutgoingMessage<UpdateAddHtlc>()
            val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
            assertTrue(alice2 is Normal)
            val sig = actionsAlice2.hasOutgoingMessage<CommitSig>()
            val (bob1, _) = bob0.processEx(ChannelEvent.MessageReceived(add))
            val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.MessageReceived(sig))
            actionsBob2.hasOutgoingMessage<RevokeAndAck>()
            actionsBob2.hasCommand<CMD_SIGN>()
            val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
            assertTrue(bob3 is Normal)
            actionsBob3.hasOutgoingMessage<CommitSig>()
            // bob received the sig, but alice didn't receive the revocation
            Pair(alice2, bob3)
        }

        val (alice1, _) = alice0.processEx(ChannelEvent.Disconnected)
        val (bob1, _) = bob0.processEx(ChannelEvent.Disconnected)
        assertTrue(alice1 is Offline)
        assertTrue(bob1 is Offline)

        val localInit = Init(ByteVector(alice0.commitments.localParams.features.toByteArray()))
        val remoteInit = Init(ByteVector(bob0.commitments.localParams.features.toByteArray()))

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.Connected(localInit, remoteInit))
        assertTrue(alice2 is Syncing)
        val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.Connected(remoteInit, localInit))
        assertTrue(bob2 is Syncing)
        val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()

        val bobCommitments = bob0.commitments
        val aliceCommitments = alice0.commitments
        val bobCurrentPerCommitmentPoint = bob0.keyManager.commitmentPoint(
            bob0.keyManager.channelKeyPath(bobCommitments.localParams, bobCommitments.channelConfig),
            bobCommitments.localCommit.index
        )
        val aliceCurrentPerCommitmentPoint = alice0.keyManager.commitmentPoint(
            alice0.keyManager.channelKeyPath(aliceCommitments.localParams, aliceCommitments.channelConfig),
            aliceCommitments.localCommit.index
        )

        // alice didn't receive any update or sig
        assertEquals(channelReestablishA, ChannelReestablish(alice0.channelId, 1, 0, PrivateKey(ByteVector32.Zeroes), aliceCurrentPerCommitmentPoint))
        // bob did receive alice's sig
        assertEquals(channelReestablishB, ChannelReestablish(bob0.channelId, 2, 0, PrivateKey(ByteVector32.Zeroes), bobCurrentPerCommitmentPoint))

        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(channelReestablishB))
        // alice does not re-send messages bob already received
        assertNull(actionsAlice3.findOutgoingMessageOpt<FundingLocked>())
        assertNull(actionsAlice3.findOutgoingMessageOpt<UpdateAddHtlc>())
        assertNull(actionsAlice3.findOutgoingMessageOpt<CommitSig>())

        val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.MessageReceived(channelReestablishA))
        val revB = actionsBob3.hasOutgoingMessage<RevokeAndAck>() // bob re-sends his revocation
        val sigB = actionsBob3.hasOutgoingMessage<CommitSig>() // bob re-sends his signature

        val (alice4, _) = alice3.processEx(ChannelEvent.MessageReceived(revB))
        val (alice5, actionsAlice5) = alice4.processEx(ChannelEvent.MessageReceived(sigB))
        assertTrue(alice5 is Normal)
        val revA = actionsAlice5.hasOutgoingMessage<RevokeAndAck>()

        val (bob4, _) = bob3.processEx(ChannelEvent.MessageReceived(revA))
        assertTrue(bob4 is Normal)

        assertEquals(1, alice5.commitments.localNextHtlcId)
        assertEquals(1, bob4.commitments.remoteNextHtlcId)
    }

    @Test
    fun `resume htlc settlement`() {
        val (alice0, bob0, revB) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
            val (nodes1, r1, htlc1) = TestsHelper.addHtlc(15_000_000.msat, bob0, alice0)
            val (bob1, alice1) = TestsHelper.crossSign(nodes1.first, nodes1.second)
            val (bob2, alice2) = TestsHelper.fulfillHtlc(htlc1.id, r1, bob1, alice1)
            val (alice3, bob3) = TestsHelper.crossSign(alice2, bob2)
            val (nodes2, r2, htlc2) = TestsHelper.addHtlc(25_000_000.msat, bob3, alice3)
            val (bob4, alice4) = TestsHelper.crossSign(nodes2.first, nodes2.second)
            val (bob5, alice5) = TestsHelper.fulfillHtlc(htlc2.id, r2, bob4, alice4)
            val (alice6, actionsAlice) = alice5.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
            val commitSig = actionsAlice.findOutgoingMessage<CommitSig>()
            val (bob6, actionsBob) = bob5.processEx(ChannelEvent.MessageReceived(commitSig))
            val revokeAndAck = actionsBob.findOutgoingMessage<RevokeAndAck>()
            assertTrue(alice6 is Normal)
            assertTrue(bob6 is Normal)
            Triple(alice6, bob6, revokeAndAck)
        }

        val (alice1, _) = alice0.processEx(ChannelEvent.Disconnected)
        val (bob1, _) = bob0.processEx(ChannelEvent.Disconnected)
        assertTrue(alice1 is Offline)
        assertTrue(bob1 is Offline)

        val initA = Init(ByteVector(alice0.commitments.localParams.features.toByteArray()))
        val initB = Init(ByteVector(bob0.commitments.localParams.features.toByteArray()))
        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.Connected(initA, initB))
        assertTrue(alice2 is Syncing)
        val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.Connected(initB, initA))
        assertTrue(bob2 is Syncing)
        val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()
        assertEquals(channelReestablishA.nextLocalCommitmentNumber, 4)
        assertEquals(channelReestablishA.nextRemoteRevocationNumber, 3)
        assertEquals(channelReestablishB.nextLocalCommitmentNumber, 5)
        assertEquals(channelReestablishB.nextRemoteRevocationNumber, 3)

        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(channelReestablishB))
        // alice does not re-send messages bob already received
        assertTrue(actionsAlice3.filterIsInstance<ChannelAction.Message.Send>().isEmpty())

        val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.MessageReceived(channelReestablishA))
        assertEquals(1, actionsBob3.filterIsInstance<ChannelAction.Message.Send>().size)
        assertEquals(revB, actionsBob3.findOutgoingMessage())
        actionsBob3.hasCommand<CMD_SIGN>()
        val (bob4, actionsBob4) = bob3.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val sigB = actionsBob4.findOutgoingMessage<CommitSig>()

        val (alice4, actionsAlice4) = alice3.processEx(ChannelEvent.MessageReceived(revB))
        assertTrue(actionsAlice4.filterIsInstance<ChannelAction.Message.Send>().isEmpty())
        val (alice5, actionsAlice5) = alice4.processEx(ChannelEvent.MessageReceived(sigB))
        val revA = actionsAlice5.findOutgoingMessage<RevokeAndAck>()

        val (bob5, actionsBob5) = bob4.processEx(ChannelEvent.MessageReceived(revA))
        assertTrue(actionsBob5.filterIsInstance<ChannelAction.Message.Send>().isEmpty())

        assertTrue(alice5 is Normal)
        assertTrue(bob5 is Normal)
        assertEquals(4, alice5.commitments.localCommit.index)
        assertEquals(4, bob5.commitments.localCommit.index)
    }

    @Test
    fun `discover that we have a revoked commitment`() {
        val (alice, aliceOld, bob) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
            val (nodes1, r1, htlc1) = TestsHelper.addHtlc(250_000_000.msat, alice0, bob0)
            val (alice1, bob1) = TestsHelper.crossSign(nodes1.first, nodes1.second)
            val (nodes2, r2, htlc2) = TestsHelper.addHtlc(100_000_000.msat, alice1, bob1)
            val (alice2, bob2) = TestsHelper.crossSign(nodes2.first, nodes2.second)
            val (nodes3, r3, htlc3) = TestsHelper.addHtlc(10_000.msat, alice2, bob2)
            val (alice3, bob3) = TestsHelper.crossSign(nodes3.first, nodes3.second)
            assertTrue(alice3 is Normal)
            // alice will lose the following updates
            val (alice4, bob4) = TestsHelper.fulfillHtlc(htlc1.id, r1, alice3, bob3)
            val (bob5, alice5) = TestsHelper.crossSign(bob4, alice4)
            val (alice6, bob6) = TestsHelper.fulfillHtlc(htlc2.id, r2, alice5, bob5)
            val (bob7, alice7) = TestsHelper.crossSign(bob6, alice6)
            val (alice8, bob8) = TestsHelper.fulfillHtlc(htlc3.id, r3, alice7, bob7)
            val (bob9, alice9) = TestsHelper.crossSign(bob8, alice8)
            assertTrue(alice9 is Normal)
            assertTrue(bob9 is Normal)
            Triple(alice9, alice3, bob9)
        }

        val (aliceTmp1, _) = alice.processEx(ChannelEvent.Disconnected)
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue(aliceTmp1 is Offline)
        assertTrue(bob1 is Offline)
        // we manually replace alice's state with an older one
        val alice1 = aliceTmp1.copy(state = aliceOld)

        val localInit = Init(ByteVector(alice.commitments.localParams.features.toByteArray()))
        val remoteInit = Init(ByteVector(bob.commitments.localParams.features.toByteArray()))

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.Connected(localInit, remoteInit))
        assertTrue(alice2 is Syncing)
        val channelReestablishA = actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.Connected(remoteInit, localInit))
        assertTrue(bob2 is Syncing)
        val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>()

        // alice realizes she has an old state...
        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(channelReestablishB))
        // ...and asks bob to publish its current commitment
        val error = actionsAlice3.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), PleasePublishYourCommitment(aliceOld.channelId).message)
        assertTrue(alice3 is WaitForRemotePublishFutureCommitment)

        // bob is nice and publishes its commitment as soon as it detects that alice has an outdated commitment
        val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.MessageReceived(channelReestablishA))
        assertTrue(bob3 is Closing)
        assertNotNull(bob3.localCommitPublished)
        val bobCommitTx = bob3.localCommitPublished!!.commitTx
        actionsBob3.hasTx(bobCommitTx)

        // alice is able to claim her main output
        val (alice4, actionsAlice4) = alice3.processEx(ChannelEvent.WatchReceived(WatchEventSpent(aliceOld.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertTrue(alice4 is Closing)
        assertNotNull(alice4.futureRemoteCommitPublished)
        assertEquals(bobCommitTx, alice4.futureRemoteCommitPublished!!.commitTx)
        assertNotNull(alice4.futureRemoteCommitPublished!!.claimMainOutputTx)
        assertTrue(alice4.futureRemoteCommitPublished!!.claimHtlcTxs.isEmpty())
        actionsAlice4.hasTx(alice4.futureRemoteCommitPublished!!.claimMainOutputTx!!.tx)
        Transaction.correctlySpends(alice4.futureRemoteCommitPublished!!.claimMainOutputTx!!.tx, bobCommitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `counterparty lies about having a more recent commitment`() {
        val (alice0, bob0) = TestsHelper.reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
        val (alice1, _) = alice0.processEx(ChannelEvent.Disconnected)
        val (bob1, _) = bob0.processEx(ChannelEvent.Disconnected)
        assertTrue(alice1 is Offline)
        assertTrue(bob1 is Offline)

        val localInit = Init(ByteVector(alice0.commitments.localParams.features.toByteArray()))
        val remoteInit = Init(ByteVector(bob0.commitments.localParams.features.toByteArray()))

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.Connected(localInit, remoteInit))
        assertTrue(alice2 is Syncing)
        actionsAlice2.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.Connected(remoteInit, localInit))
        assertTrue(bob2 is Syncing)
        // let's forge a dishonest channel_reestablish
        val channelReestablishB = actionsBob2.findOutgoingMessage<ChannelReestablish>().copy(nextRemoteRevocationNumber = 42)

        // alice finds out bob is lying
        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(channelReestablishB))
        assertTrue(alice3 is Closing)
        assertNotNull(alice3.localCommitPublished)
        actionsAlice3.hasTx(alice3.localCommitPublished!!.commitTx)
        actionsAlice3.hasTx(alice3.localCommitPublished!!.claimMainDelayedOutputTx!!.tx)
        val error = actionsAlice3.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InvalidRevokedCommitProof(alice0.channelId, 0, 42, channelReestablishB.yourLastCommitmentSecret).message)
    }

    @Test
    fun `reprocess pending incoming htlcs after disconnection or wallet restart`() {
        val (alice, bob, htlcs) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
            val (aliceId, bobId) = Pair(alice0.staticParams.nodeParams.nodeId, bob0.staticParams.nodeParams.nodeId)
            val currentBlockHeight = alice0.currentBlockHeight.toLong()
            // We add some htlcs Alice ---> Bob
            val (alice1, bob1, htlc1) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(75_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice0, bob0)
            val (alice2, bob2, htlc2) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(50_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice1, bob1)
            val (alice3, bob3, htlc3) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(65_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice2, bob2)
            // And htlcs Bob ---> Alice
            val (bob4, alice4, htlc4) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(45_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob3, alice3)
            val (bob5, alice5, htlc5) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(55_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob4, alice4)
            val (alice6, bob6) = TestsHelper.crossSign(alice5, bob5)
            // And some htlcs aren't signed yet: they will be dropped when disconnecting, and may be retransmitted later.
            val (bob7, alice7, _) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(50_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob6, alice6)
            val (alice8, bob8, _) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(70_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice7, bob7)
            assertTrue(alice8 is Normal)
            assertTrue(bob8 is Normal)
            Triple(alice8, bob8, listOf(htlc1, htlc2, htlc3, htlc4, htlc5))
        }

        // Bob's wallet disconnects, but doesn't restart.
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue(bob1 is Offline)

        // Alice's wallet restarts.
        val initState = WaitForInit(alice.staticParams, alice.currentTip, alice.currentOnChainFeerates)
        val (alice1, actions1) = initState.processEx(ChannelEvent.Restore(alice))
        assertEquals(3, actions1.size)
        actions1.hasWatch<WatchSpent>()
        actions1.hasWatch<WatchConfirmed>()
        val getFundingTx = actions1.find<ChannelAction.Blockchain.GetFundingTx>()
        assertEquals(alice.commitments.commitInput.outPoint.txid, getFundingTx.txid)
        assertTrue(alice1 is Offline)

        val localInit = Init(ByteVector(alice.commitments.localParams.features.toByteArray()))
        val remoteInit = Init(ByteVector(bob.commitments.localParams.features.toByteArray()))

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.Connected(localInit, remoteInit))
        assertTrue(alice2 is Syncing)
        assertTrue(actionsAlice2.filterIsInstance<ChannelAction.ProcessIncomingHtlc>().isEmpty())
        val channelReestablishAlice = actionsAlice2.hasOutgoingMessage<ChannelReestablish>()
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.Connected(localInit, remoteInit))
        assertTrue(actionsBob2.filterIsInstance<ChannelAction.ProcessIncomingHtlc>().isEmpty())
        val channelReestablishBob = actionsBob2.hasOutgoingMessage<ChannelReestablish>()

        // Alice reprocesses the htlcs received from Bob.
        val (_, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(channelReestablishBob))
        assertEquals(3, actionsAlice3.size)
        val expectedHtlcsAlice = htlcs.drop(3).take(2).map { ChannelAction.ProcessIncomingHtlc(it) }
        assertEquals(expectedHtlcsAlice, actionsAlice3.filterIsInstance<ChannelAction.ProcessIncomingHtlc>())
        actionsAlice3.hasWatch<WatchConfirmed>()

        // Bob reprocesses the htlcs received from Alice.
        val (_, actionsBob3) = bob2.processEx(ChannelEvent.MessageReceived(channelReestablishAlice))
        assertEquals(4, actionsBob3.size)
        val expectedHtlcsBob = htlcs.take(3).map { ChannelAction.ProcessIncomingHtlc(it) }
        assertEquals(expectedHtlcsBob, actionsBob3.filterIsInstance<ChannelAction.ProcessIncomingHtlc>())
        actionsBob3.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `reprocess pending incoming htlcs after disconnection or wallet restart (htlc settlement signed by us)`() {
        val (alice, bob, htlcs) = run {
            val (alice0, bob0) = TestsHelper.reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
            val (aliceId, bobId) = Pair(alice0.staticParams.nodeParams.nodeId, bob0.staticParams.nodeParams.nodeId)
            val currentBlockHeight = alice0.currentBlockHeight.toLong()
            val preimage = randomBytes32()
            // Alice sends some htlcs to Bob.
            val (alice1, bob1, htlc1) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(75_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice0, bob0)
            val (alice2, bob2, htlc2) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(50_000.msat, bobId, currentBlockHeight, preimage).second, alice1, bob1)
            val (alice3, bob3, htlc3) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(65_000.msat, bobId, currentBlockHeight, randomBytes32()).second, alice2, bob2)
            // Bob sends some htlcs to Alice.
            val (bob4, alice4, htlc4) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(45_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob3, alice3)
            val (bob5, alice5, htlc5) = TestsHelper.addHtlc(TestsHelper.makeCmdAdd(55_000.msat, aliceId, currentBlockHeight, randomBytes32()).second, bob4, alice4)
            val (alice6, bob6) = TestsHelper.crossSign(alice5, bob5)
            // Bob settles the first two htlcs and sends his signature, but Alice doesn't receive these messages.
            val (bob7, _) = bob6.processEx(ChannelEvent.ExecuteCommand(CMD_FAIL_HTLC(htlc1.id, CMD_FAIL_HTLC.Reason.Failure(PaymentTimeout), commit = false)))
            val (bob8, _) = bob7.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(htlc2.id, preimage, commit = false)))
            val (bob9, _) = bob8.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
            Triple(alice6 as Normal, bob9 as Normal, listOf(htlc1, htlc2, htlc3, htlc4, htlc5))
        }

        // Alice and Bob are disconnected.
        val (alice1, _) = alice.processEx(ChannelEvent.Disconnected)
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue(alice1 is Offline)
        assertTrue(bob1 is Offline)

        val aliceInit = Init(ByteVector(alice.commitments.localParams.features.toByteArray()))
        val bobInit = Init(ByteVector(bob.commitments.localParams.features.toByteArray()))

        val (alice2, actionsAlice) = alice1.processEx(ChannelEvent.Connected(aliceInit, bobInit))
        val (bob2, _) = bob1.processEx(ChannelEvent.Connected(bobInit, aliceInit))
        assertTrue(alice2 is Syncing)
        assertTrue(bob2 is Syncing)
        val channelReestablishAlice = actionsAlice.hasOutgoingMessage<ChannelReestablish>()

        // Bob resends htlc settlement messages to Alice and reprocesses unsettled htlcs.
        val (_, actionsBob) = bob2.processEx(ChannelEvent.MessageReceived(channelReestablishAlice))
        assertEquals(5, actionsBob.size)
        val fail = actionsBob.hasOutgoingMessage<UpdateFailHtlc>()
        assertEquals(fail.id, htlcs[0].id)
        val fulfill = actionsBob.hasOutgoingMessage<UpdateFulfillHtlc>()
        assertEquals(fulfill.id, htlcs[1].id)
        actionsBob.hasOutgoingMessage<CommitSig>()
        assertEquals(listOf(ChannelAction.ProcessIncomingHtlc(htlcs[2])), actionsBob.filterIsInstance<ChannelAction.ProcessIncomingHtlc>())
        actionsBob.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `wait for their channel reestablish when using channel backup`() {
        val (alice, bob) = TestsHelper.reachNormal()
        assertTrue(bob.commitments.localParams.features.hasFeature(Feature.ChannelBackupClient))
        val (alice1, _) = alice.processEx(ChannelEvent.Disconnected)
        val (bob1, _) = bob.processEx(ChannelEvent.Disconnected)
        assertTrue(alice1 is Offline)
        assertTrue(bob1 is Offline)

        val localInit = Init(ByteVector(alice.commitments.localParams.features.toByteArray()))
        val remoteInit = Init(ByteVector(bob.commitments.localParams.features.toByteArray()))

        val (alice2, actions) = alice1.processEx(ChannelEvent.Connected(localInit, remoteInit))
        assertTrue(alice2 is Syncing)
        actions.findOutgoingMessage<ChannelReestablish>()
        val (bob2, actions1) = bob1.processEx(ChannelEvent.Connected(remoteInit, localInit))
        assertTrue(bob2 is Syncing)
        // Bob waits to receive Alice's channel reestablish before sending his own.
        assertTrue(actions1.isEmpty())
    }

    @Test
    fun `recv NewBlock (no htlc timed out)`() {
        val (alice0, bob0) = TestsHelper.reachNormal()
        val (nodes, _, _) = TestsHelper.addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = TestsHelper.crossSign(nodes.first, nodes.second)
        val (alice2, _) = alice1.processEx(ChannelEvent.Disconnected)
        assertTrue(alice2 is Offline)

        val (alice3, actions3) = alice2.processEx(ChannelEvent.NewBlock(alice2.currentBlockHeight + 1, alice2.currentTip.second))
        assertTrue(alice3 is Offline)
        assertEquals((alice2.state as Normal).copy(currentTip = alice3.currentTip), alice3.state)
        assertTrue(actions3.isEmpty())

        val (alice4, actions4) = alice3.processEx(ChannelEvent.CheckHtlcTimeout)
        assertTrue(alice4 is Offline)
        assertEquals(alice3, alice4)
        assertTrue(actions4.isEmpty())
    }

    @Test
    fun `recv NewBlock (an htlc timed out)`() {
        val (alice0, bob0) = TestsHelper.reachNormal()
        val (nodes, _, htlc) = TestsHelper.addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = TestsHelper.crossSign(nodes.first, nodes.second)
        val (alice2, _) = alice1.processEx(ChannelEvent.Disconnected)
        assertTrue(alice2 is Offline)

        // alice restarted after the htlc timed out
        val alice3 = alice2.copy(state = (alice2.state as Normal).copy(currentTip = alice2.currentTip.copy(first = htlc.cltvExpiry.toLong().toInt())))
        val (alice4, actions) = alice3.processEx(ChannelEvent.CheckHtlcTimeout)
        assertTrue(alice4 is Closing)
        assertNotNull(alice4.localCommitPublished)
        actions.hasOutgoingMessage<Error>()
        actions.has<ChannelAction.Storage.StoreState>()
        val lcp = alice4.localCommitPublished!!
        actions.hasTx(lcp.commitTx)
        assertEquals(1, lcp.htlcTimeoutTxs().size)
        assertEquals(1, lcp.claimHtlcDelayedTxs.size)
        assertEquals(4, actions.findTxs().size) // commit tx + main output + htlc-timeout + claim-htlc-delayed
        assertEquals(3, actions.findWatches<WatchConfirmed>().size) // commit tx + main output + claim-htlc-delayed
        assertEquals(1, actions.findWatches<WatchSpent>().size) // htlc-timeout
    }

    @Test
    fun `recv NewBlock (fulfilled signed htlc ignored by peer)`() {
        val (alice0, bob0) = TestsHelper.reachNormal()
        val (nodes, preimage, htlc) = TestsHelper.addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = TestsHelper.crossSign(nodes.first, nodes.second)
        val (bob2, actions2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(htlc.id, preimage)))
        actions2.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob3, _) = bob2.processEx(ChannelEvent.Disconnected)
        assertTrue(bob3 is Offline)

        // bob restarts when the fulfilled htlc is close to timing out: alice hasn't signed, so bob closes the channel
        val (bob4, actions4) = run {
            val (tmp, _) = bob3.processEx(ChannelEvent.NewBlock(htlc.cltvExpiry.toLong().toInt(), bob3.state.currentTip.second))
            tmp.processEx(ChannelEvent.CheckHtlcTimeout)
        }
        assertTrue(bob4 is Closing)
        assertNotNull(bob4.localCommitPublished)
        actions4.has<ChannelAction.Storage.StoreState>()

        val lcp = bob4.localCommitPublished!!
        assertNotNull(lcp.claimMainDelayedOutputTx)
        assertEquals(1, lcp.htlcSuccessTxs().size)
        Transaction.correctlySpends(lcp.htlcSuccessTxs().first().tx, lcp.commitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        assertEquals(1, lcp.claimHtlcDelayedTxs.size)
        Transaction.correctlySpends(lcp.claimHtlcDelayedTxs.first().tx, lcp.htlcSuccessTxs().first().tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        val txs = setOf(lcp.commitTx, lcp.claimMainDelayedOutputTx!!.tx, lcp.htlcSuccessTxs().first().tx, lcp.claimHtlcDelayedTxs.first().tx)
        assertEquals(txs, actions4.findTxs().toSet())
        val watchConfirmed = listOf(lcp.commitTx, lcp.claimMainDelayedOutputTx!!.tx, lcp.claimHtlcDelayedTxs.first().tx).map { it.txid }.toSet()
        assertEquals(watchConfirmed, actions4.findWatches<WatchConfirmed>().map { it.txId }.toSet())
        val watchSpent = setOf(lcp.htlcSuccessTxs().first().input.outPoint)
        assertEquals(watchSpent, actions4.findWatches<WatchSpent>().map { OutPoint(lcp.commitTx, it.outputIndex.toLong()) }.toSet())
    }

    @Test
    fun `recv CMD_FORCECLOSE`() {
        val (alice, _) = TestsHelper.reachNormal()
        val (alice1, _) = alice.processEx(ChannelEvent.Disconnected)
        assertTrue(alice1 is Offline)
        val commitTx = alice1.state.commitments.localCommit.publishableTxs.commitTx.tx
        val (alice2, actions2) = alice1.process(ChannelEvent.ExecuteCommand(CMD_FORCECLOSE))
        assertTrue(alice2 is Closing)
        actions2.hasTx(commitTx)
        assertNull(actions2.findOutgoingMessageOpt<Error>()) // we're offline so we shouldn't try to send messages
    }

    @Test
    fun `restore closing channel`() {
        val bob = run {
            val (alice, bob) = TestsHelper.reachNormal()
            // alice publishes her commitment tx
            val (bob1, _) = bob.processEx(ChannelEvent.WatchReceived(WatchEventSpent(bob.channelId, BITCOIN_FUNDING_SPENT, alice.commitments.localCommit.publishableTxs.commitTx.tx)))
            assertTrue(bob1 is Closing)
            assertNull(bob1.closingTypeAlreadyKnown())
            bob1
        }

        val state = WaitForInit(bob.staticParams, bob.currentTip, bob.currentOnChainFeerates)
        val (state1, actions) = state.processEx(ChannelEvent.Restore(bob))
        assertTrue { state1 is Closing }
        assertEquals(5, actions.size)
        val watchSpent = actions.hasWatch<WatchSpent>()
        assertEquals(bob.commitments.commitInput.outPoint.txid, watchSpent.txId)
        val remoteCommitPublished = bob.remoteCommitPublished
        assertNotNull(remoteCommitPublished)
        val claimMainOutputTx = remoteCommitPublished.claimMainOutputTx
        assertNotNull(claimMainOutputTx)
        actions.hasTx(claimMainOutputTx.tx)
        val watches = actions.findWatches<WatchConfirmed>()
        assertEquals(2, watches.size)
        assertNotNull(watches.first { it.txId == remoteCommitPublished.commitTx.txid })
        assertNotNull(watches.first { it.txId == claimMainOutputTx.tx.txid })
        actions.has<ChannelAction.Blockchain.GetFundingTx>()
    }
}
