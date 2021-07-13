package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.TestsHelper.addHtlc
import fr.acinq.lightning.channel.TestsHelper.claimHtlcSuccessTxs
import fr.acinq.lightning.channel.TestsHelper.claimHtlcTimeoutTxs
import fr.acinq.lightning.channel.TestsHelper.crossSign
import fr.acinq.lightning.channel.TestsHelper.fulfillHtlc
import fr.acinq.lightning.channel.TestsHelper.htlcSuccessTxs
import fr.acinq.lightning.channel.TestsHelper.htlcTimeoutTxs
import fr.acinq.lightning.channel.TestsHelper.makeCmdAdd
import fr.acinq.lightning.channel.TestsHelper.processEx
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.channel.TestsHelper.signAndRevack
import fr.acinq.lightning.crypto.sphinx.Sphinx
import fr.acinq.lightning.router.Announcements
import fr.acinq.lightning.serialization.Serialization
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.transactions.Transactions.weight2fee
import fr.acinq.lightning.transactions.incomings
import fr.acinq.lightning.transactions.outgoings
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import kotlin.test.*

@ExperimentalUnsignedTypes
class NormalTestsCommon : LightningTestSuite() {

    private val defaultAdd = CMD_ADD_HTLC(
        50_000_000.msat,
        randomBytes32(),
        CltvExpiryDelta(144).toCltvExpiry(TestConstants.defaultBlockHeight.toLong()),
        TestConstants.emptyOnionPacket,
        UUID.randomUUID()
    )

    @Test
    fun `recv CMD_ADD_HTLC`() {
        val (alice0, _) = reachNormal()
        val add = defaultAdd.copy(paymentHash = randomBytes32())

        val (alice1, actions) = alice0.processEx(ChannelEvent.ExecuteCommand(add))
        assertTrue(alice1 is Normal)
        assertTrue(alice1.commitments.availableBalanceForSend() < alice0.commitments.availableBalanceForSend())

        val htlc = actions.findOutgoingMessage<UpdateAddHtlc>()
        assertEquals(0, htlc.id)
        assertEquals(add.paymentHash, htlc.paymentHash)
        val expected = alice0.copy(
            commitments = alice0.commitments.copy(
                localNextHtlcId = 1,
                localChanges = alice0.commitments.localChanges.copy(proposed = listOf(htlc)),
                payments = mapOf(0L to add.paymentId)
            )
        )
        assertEquals(expected, alice1)
    }

    @Test
    fun `recv CMD_ADD_HTLC (incrementing ids)`() {
        val (alice0, _) = reachNormal()
        var alice = alice0
        for (i in 0 until 10) {
            val add = defaultAdd.copy(paymentHash = randomBytes32())
            val (tempAlice, actions) = alice.processEx(ChannelEvent.ExecuteCommand(add))
            alice = tempAlice as Normal

            val htlc = actions.findOutgoingMessage<UpdateAddHtlc>()
            assertEquals(i.toLong(), htlc.id)
            assertEquals(add.paymentHash, htlc.paymentHash)
        }
    }

    @Test
    fun `recv CMD_ADD_HTLC (expiry too small)`() {
        val (alice0, _) = reachNormal()
        // It's usually dangerous for Bob to accept HTLCs that are expiring soon. However it's not Alice's decision to reject
        // them when she's asked to relay; she should forward those HTLCs to Bob, and Bob will choose whether to fail them
        // or fulfill them (Bob could be #reckless and fulfill HTLCs with a very low expiry delta).
        val currentBlockHeight = alice0.currentBlockHeight.toLong()
        val expiryTooSmall = CltvExpiry(currentBlockHeight + 3)
        val add = defaultAdd.copy(cltvExpiry = expiryTooSmall)
        val (_, actions1) = alice0.processEx(ChannelEvent.ExecuteCommand(add))
        actions1.hasOutgoingMessage<UpdateAddHtlc>()
    }

    @Test
    fun `recv CMD_ADD_HTLC (expiry too big)`() {
        val (alice0, _) = reachNormal()
        val currentBlockHeight = alice0.currentBlockHeight.toLong()
        val expiryTooBig = (Channel.MAX_CLTV_EXPIRY_DELTA + 1).toCltvExpiry(currentBlockHeight)
        val add = defaultAdd.copy(cltvExpiry = expiryTooBig)
        val (alice1, actions1) = alice0.processEx(ChannelEvent.ExecuteCommand(add))
        val actualError = actions1.findCommandError<ExpiryTooBig>()
        val expectedError = ExpiryTooBig(alice0.channelId, Channel.MAX_CLTV_EXPIRY_DELTA.toCltvExpiry(currentBlockHeight), expiryTooBig, currentBlockHeight)
        assertEquals(expectedError, actualError)
        assertEquals(alice0, alice1)
    }

    @Test
    fun `recv CMD_ADD_HTLC (value too small)`() {
        val (alice0, _) = reachNormal()
        val add = defaultAdd.copy(amount = 50.msat)
        val (alice1, actions) = alice0.processEx(ChannelEvent.ExecuteCommand(add))
        val actualError = actions.findCommandError<HtlcValueTooSmall>()
        val expectedError = HtlcValueTooSmall(alice0.channelId, 1000.msat, 50.msat)
        assertEquals(expectedError, actualError)
        assertEquals(alice0, alice1)
    }

    @Test
    fun `recv CMD_ADD_HTLC (0 msat)`() {
        val (alice0, bob0) = reachNormal()
        // Alice has a minimum set to 0 msat (which should be invalid, but may mislead Bob into relaying 0-value HTLCs which is forbidden by the spec).
        assertEquals(0.msat, alice0.commitments.localParams.htlcMinimum)
        val add = defaultAdd.copy(amount = 0.msat)
        val (bob1, actions) = bob0.processEx(ChannelEvent.ExecuteCommand(add))
        val actualError = actions.findCommandError<HtlcValueTooSmall>()
        val expectedError = HtlcValueTooSmall(bob0.channelId, 1.msat, 0.msat)
        assertEquals(expectedError, actualError)
        assertEquals(bob0, bob1)
    }

    @Test
    fun `recv CMD_ADD_HTLC (increasing balance but still below reserve)`() {
        val (alice0, bob0) = reachNormal(pushMsat = 0.msat)
        assertFalse(alice0.commitments.channelFeatures.hasFeature(Feature.ZeroReserveChannels))
        assertFalse(bob0.commitments.channelFeatures.hasFeature(Feature.ZeroReserveChannels))
        assertEquals(0.msat, bob0.commitments.availableBalanceForSend())

        val cmdAdd = defaultAdd.copy(amount = 1_500.msat)
        val (alice1, actionsAlice) = alice0.processEx(ChannelEvent.ExecuteCommand(cmdAdd))
        assertTrue(alice1 is Normal)
        val add = actionsAlice.hasOutgoingMessage<UpdateAddHtlc>()

        val (bob1, actionsBob) = bob0.processEx(ChannelEvent.MessageReceived(add))
        assertTrue(bob1 is Normal)
        assertTrue(actionsBob.isEmpty())
        assertEquals(0.msat, bob1.commitments.availableBalanceForSend())
    }

    @Test
    fun `recv CMD_ADD_HTLC (insufficient funds)`() {
        val (alice0, _) = reachNormal()
        val add = defaultAdd.copy(amount = Int.MAX_VALUE.msat)
        val (alice1, actions) = alice0.processEx(ChannelEvent.ExecuteCommand(add))
        val actualError = actions.findCommandError<InsufficientFunds>()
        val expectError = InsufficientFunds(alice0.channelId, amount = Int.MAX_VALUE.msat, missing = 1_382_823.sat, reserve = 20_000.sat, fees = 7_140.sat)
        assertEquals(expectError, actualError)
        assertEquals(alice0, alice1)
    }

    @Test
    fun `recv CMD_ADD_HTLC (insufficient funds, missing 1 msat)`() {
        val (_, bob0) = reachNormal()
        val add = defaultAdd.copy(amount = bob0.commitments.availableBalanceForSend() + 1.sat.toMilliSatoshi())
        val (bob1, actions) = bob0.processEx(ChannelEvent.ExecuteCommand(add))
        val actualError = actions.findCommandError<InsufficientFunds>()
        val expectedError = InsufficientFunds(bob0.channelId, amount = add.amount, missing = 1.sat, reserve = 10000.sat, fees = 0.sat)
        assertEquals(expectedError, actualError)
        assertEquals(bob0, bob1)
    }

    @Test
    fun `recv CMD_ADD_HTLC (HTLC dips into remote funder fee reserve)`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(764_660_000.msat, alice0, bob0).first
        val (alice2, bob2) = crossSign(alice1, bob1)
        assertEquals(0.msat, (alice2 as ChannelStateWithCommitments).commitments.availableBalanceForSend())

        tailrec fun loop(bob: ChannelState, count: Int): ChannelState = if (count == 0) bob else {
            val (newBob, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 16_000_000.msat)))
            actions1.hasOutgoingMessage<UpdateAddHtlc>()
            loop(newBob, count - 1)
        }

        // actual test begins
        // at this point alice has the minimal amount to sustain a channel
        // alice maintains an extra reserve to accommodate for a few more HTLCs, so the first HTLCs should be allowed
        val bob3 = loop(bob2, 9)
        // but this one will dip alice below her reserve: we must wait for the previous HTLCs to settle before sending any more
        val (_, actionsBob4) = bob3.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 12_500_000.msat)))
        actionsBob4.findCommandError<RemoteCannotAffordFeesForNewHtlc>()
    }

    @Test
    fun `recv CMD_ADD_HTLC (insufficient funds with pending htlcs)`() {
        val (alice0, _) = reachNormal()
        val (alice1, actionsAlice1) = alice0.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 300_000_000.msat)))
        actionsAlice1.hasOutgoingMessage<UpdateAddHtlc>()
        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 300_000_000.msat)))
        actionsAlice2.hasOutgoingMessage<UpdateAddHtlc>()
        val (_, actionsAlice3) = alice2.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 500_000_000.msat)))
        val actualError = actionsAlice3.findCommandError<InsufficientFunds>()
        val expectError = InsufficientFunds(alice0.channelId, amount = 500_000_000.msat, missing = 338_780.sat, reserve = 20_000.sat, fees = 8_860.sat)
        assertEquals(expectError, actualError)
    }

    @Test
    fun `recv CMD_ADD_HTLC (insufficient funds with pending htlcs and 0 balance)`() {
        val (alice0, _) = reachNormal()
        val (alice1, actionsAlice1) = alice0.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 500_000_000.msat)))
        actionsAlice1.hasOutgoingMessage<UpdateAddHtlc>()
        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 200_000_000.msat)))
        actionsAlice2.hasOutgoingMessage<UpdateAddHtlc>()
        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 61_120_000.msat)))
        actionsAlice3.hasOutgoingMessage<UpdateAddHtlc>()
        val (_, actionsAlice4) = alice3.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 1_000_000.msat)))
        val actualError = actionsAlice4.findCommandError<InsufficientFunds>()
        val expectedError = InsufficientFunds(alice0.channelId, amount = 1_000_000.msat, missing = 900.sat, reserve = 20_000.sat, fees = 8_860.sat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv CMD_ADD_HTLC (over their max in-flight htlc value)`() {
        val bob0 = run {
            val (_, bob) = reachNormal()
            bob.copy(commitments = bob.commitments.copy(remoteParams = bob.commitments.remoteParams.copy(maxHtlcValueInFlightMsat = 150_000_000)))
        }
        val (_, actions) = bob0.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 151_000_000.msat)))
        val actualError = actions.findCommandError<HtlcValueTooHighInFlight>()
        val expectedError = HtlcValueTooHighInFlight(bob0.channelId, maximum = 150_000_000UL, actual = 151_000_000.msat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv CMD_ADD_HTLC (over our max in-flight htlc value)`() {
        val bob0 = run {
            val (_, bob) = reachNormal()
            bob.copy(commitments = bob.commitments.copy(localParams = bob.commitments.localParams.copy(maxHtlcValueInFlightMsat = 100_000_000)))
        }
        val (_, actions) = bob0.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 101_000_000.msat)))
        val actualError = actions.findCommandError<HtlcValueTooHighInFlight>()
        val expectedError = HtlcValueTooHighInFlight(bob0.channelId, maximum = 100_000_000UL, actual = 101_000_000.msat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv CMD_ADD_HTLC (over max in-flight htlc value with duplicate amounts)`() {
        val bob0 = run {
            val (_, bob) = reachNormal()
            bob.copy(commitments = bob.commitments.copy(remoteParams = bob.commitments.remoteParams.copy(maxHtlcValueInFlightMsat = 150_000_000)))
        }
        val (bob1, actionsBob1) = bob0.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 75_500_000.msat)))
        actionsBob1.hasOutgoingMessage<UpdateAddHtlc>()
        val (_, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 75_500_000.msat)))
        val actualError = actionsBob2.findCommandError<HtlcValueTooHighInFlight>()
        val expectedError = HtlcValueTooHighInFlight(bob0.channelId, maximum = 150_000_000UL, actual = 151_000_000.msat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv CMD_ADD_HTLC (over max accepted htlcs)`() {
        val (alice0, bob0) = reachNormal()

        // Bob accepts a maximum of 100 htlcs
        val alice1 = run {
            var alice = alice0
            for (i in 0 until bob0.staticParams.nodeParams.maxAcceptedHtlcs) {
                val (tempAlice, actions) = alice.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 1_000_000.msat)))
                actions.hasOutgoingMessage<UpdateAddHtlc>()
                alice = tempAlice as Normal
            }
            alice
        }

        val (_, actions) = alice1.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 1_000_000.msat)))
        val actualError = actions.findCommandError<TooManyAcceptedHtlcs>()
        val expectedError = TooManyAcceptedHtlcs(alice0.channelId, maximum = 100)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv CMD_ADD_HTLC (over max offered htlcs)`() {
        val (alice0, _) = reachNormal()
        // Bob accepts a maximum of 100 htlcs, but for Alice that value is only 5
        val alice1 = alice0.copy(commitments = alice0.commitments.copy(localParams = alice0.commitments.localParams.copy(maxAcceptedHtlcs = 5)))

        val alice2 = run {
            var alice = alice1
            for (i in 0 until 5) {
                val (tempAlice, actions) = alice.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 1_000_000.msat)))
                actions.hasOutgoingMessage<UpdateAddHtlc>()
                alice = tempAlice as Normal
            }
            alice
        }

        val (_, actions) = alice2.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = 1_000_000.msat)))
        val actualError = actions.findCommandError<TooManyOfferedHtlcs>()
        val expectedError = TooManyOfferedHtlcs(alice0.channelId, maximum = 5)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv CMD_ADD_HTLC (over capacity)`() {
        val (alice0, _) = reachNormal()
        val (alice1, actionsAlice1) = alice0.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(amount = TestConstants.fundingAmount.toMilliSatoshi() * 2 / 3)))
        actionsAlice1.hasOutgoingMessage<UpdateAddHtlc>()
        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        actionsAlice2.hasOutgoingMessage<CommitSig>()
        // this is over channel-capacity
        val failAdd = defaultAdd.copy(amount = TestConstants.fundingAmount.toMilliSatoshi() * 2 / 3)
        val (_, actionsAlice3) = alice2.processEx(ChannelEvent.ExecuteCommand(failAdd))
        val actualError = actionsAlice3.findCommandError<InsufficientFunds>()
        val expectedError = InsufficientFunds(alice0.channelId, failAdd.amount, 570_393.sat, 20_000.sat, 8_000.sat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv CMD_ADD_HTLC (after having sent Shutdown)`() {
        val (alice0, _) = reachNormal()
        val (alice1, actionsAlice1) = alice0.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        actionsAlice1.findOutgoingMessage<Shutdown>()
        assertTrue(alice1 is Normal && alice1.localShutdown != null && alice1.remoteShutdown == null)

        val (_, cmdAdd) = makeCmdAdd(500_000_000.msat, alice0.staticParams.nodeParams.nodeId, TestConstants.defaultBlockHeight.toLong(), randomBytes32())
        val (_, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(cmdAdd))
        assertNotNull(actionsAlice2.findCommandError<NoMoreHtlcsClosingInProgress>())
    }

    @Test
    fun `recv CMD_ADD_HTLC (after having received Shutdown)`() {
        val (alice0, bob0) = reachNormal()

        // let's make alice send an htlc
        val (_, cmdAdd1) = makeCmdAdd(500_000_000.msat, alice0.staticParams.nodeParams.nodeId, TestConstants.defaultBlockHeight.toLong(), randomBytes32())
        val (alice1, actionsAlice1) = alice0.processEx(ChannelEvent.ExecuteCommand(cmdAdd1))
        actionsAlice1.findOutgoingMessage<UpdateAddHtlc>()

        // at the same time bob initiates a closing
        val (_, actionsBob1) = bob0.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        val shutdown = actionsBob1.findOutgoingMessage<Shutdown>()

        val (alice2, _) = alice1.processEx(ChannelEvent.MessageReceived(shutdown))
        val (_, cmdAdd2) = makeCmdAdd(100_000_000.msat, alice0.staticParams.nodeParams.nodeId, TestConstants.defaultBlockHeight.toLong(), randomBytes32())
        val (_, actionsAlice3) = alice2.processEx(ChannelEvent.ExecuteCommand(cmdAdd2))
        assertNotNull(actionsAlice3.findCommandError<NoMoreHtlcsClosingInProgress>())
    }

    @Test
    fun `recv UpdateAddHtlc`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 15_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.processEx(ChannelEvent.MessageReceived(add))
        assertTrue(actions1.isEmpty())
        val expected = bob0.copy(commitments = bob0.commitments.copy(remoteNextHtlcId = 1, remoteChanges = bob0.commitments.remoteChanges.copy(proposed = listOf(add))))
        assertEquals(expected, bob1)
    }

    @Test
    fun `recv UpdateAddHtlc (unexpected id)`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 15_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.processEx(ChannelEvent.MessageReceived(add))
        assertTrue(actions1.isEmpty())
        val (bob2, actions2) = bob1.processEx(ChannelEvent.MessageReceived(add.copy(id = 1)))
        assertTrue(actions2.isEmpty())
        val (bob3, actions3) = bob2.processEx(ChannelEvent.MessageReceived(add.copy(id = 2)))
        assertTrue(actions3.isEmpty())
        val (bob4, actions4) = bob3.processEx(ChannelEvent.MessageReceived(add.copy(id = 4)))
        assertTrue(bob4 is Closing)
        val error = actions4.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnexpectedHtlcId(bob0.channelId, 3, 4).message)
    }

    @Test
    fun `recv UpdateAddHtlc (value too small)`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 150.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.processEx(ChannelEvent.MessageReceived(add))
        assertTrue(bob1 is Closing)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), HtlcValueTooSmall(bob0.channelId, 1_000.msat, add.amountMsat).message)
    }

    @Test
    fun `recv UpdateAddHtlc (insufficient funds)`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 800_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.processEx(ChannelEvent.MessageReceived(add))
        assertTrue(bob1 is Closing)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InsufficientFunds(bob0.channelId, 800_000_000.msat, 27_140.sat, 20_000.sat, 7_140.sat).message)
    }

    @Test
    fun `recv UpdateAddHtlc (insufficient funds with pending htlcs)`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 15_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.processEx(ChannelEvent.MessageReceived(add))
        assertTrue(actions1.isEmpty())
        val (bob2, actions2) = bob1.processEx(ChannelEvent.MessageReceived(add.copy(id = 1)))
        assertTrue(actions2.isEmpty())
        val (bob3, actions3) = bob2.processEx(ChannelEvent.MessageReceived(add.copy(id = 2)))
        assertTrue(actions3.isEmpty())
        val (bob4, actions4) = bob3.processEx(ChannelEvent.MessageReceived(add.copy(id = 3, amountMsat = 800_000_000.msat)))
        assertTrue(bob4 is Closing)
        val error = actions4.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InsufficientFunds(bob0.channelId, 800_000_000.msat, 74_720.sat, 20_000.sat, 9_720.sat).message)
    }

    @Test
    fun `recv UpdateAddHtlc (over max in-flight htlc value)`() {
        val alice0 = run {
            val (alice, _) = reachNormal()
            alice.copy(commitments = alice.commitments.copy(localParams = alice.commitments.localParams.copy(maxHtlcValueInFlightMsat = 150_000_000)))
        }
        val add = UpdateAddHtlc(alice0.channelId, 0, 151_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(alice0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (alice1, actions1) = alice0.processEx(ChannelEvent.MessageReceived(add))
        assertTrue(alice1 is Closing)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), HtlcValueTooHighInFlight(alice0.channelId, 150_000_000UL, 151_000_000.msat).message)
    }

    @Test
    fun `recv UpdateAddHtlc (over max accepted htlcs)`() {
        val (_, bob0) = reachNormal()

        // Bob accepts a maximum of 100 htlcs
        val bob1 = run {
            var bob = bob0
            for (i in 0 until bob0.staticParams.nodeParams.maxAcceptedHtlcs) {
                val add = UpdateAddHtlc(bob0.channelId, i.toLong(), 2_500_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
                val (tempBob, actions) = bob.processEx(ChannelEvent.MessageReceived(add))
                assertTrue(actions.isEmpty())
                bob = tempBob as Normal
            }
            bob
        }

        val nextHtlcId = bob1.commitments.remoteNextHtlcId
        val add = UpdateAddHtlc(bob0.channelId, nextHtlcId, 2_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob2, actions2) = bob1.processEx(ChannelEvent.MessageReceived(add))
        assertTrue(bob2 is Closing)
        val error = actions2.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), TooManyAcceptedHtlcs(bob0.channelId, bob0.staticParams.nodeParams.maxAcceptedHtlcs.toLong()).message)
    }

    @Test
    fun `recv CMD_SIGN`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, _) = addHtlc(50_000_000.msat, payer = alice0, payee = bob0).first
        val (alice2, actions) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actions.findOutgoingMessage<CommitSig>()
        assertEquals(1, commitSig.htlcSignatures.size)
        assertTrue(alice2 is ChannelStateWithCommitments)
        assertTrue(alice2.commitments.remoteNextCommitInfo.isLeft)
    }

    @Test
    fun `recv CMD_SIGN (two identical htlcs in each direction)`() {
        val (alice0, bob0) = reachNormal()
        val add = defaultAdd.copy(amount = 10_000_000.msat, paymentHash = randomBytes32())

        val (alice1, actionsAlice1) = alice0.processEx(ChannelEvent.ExecuteCommand(add))
        val htlc1 = actionsAlice1.findOutgoingMessage<UpdateAddHtlc>()
        val (bob1, _) = bob0.processEx(ChannelEvent.MessageReceived(htlc1))
        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(add))
        val htlc2 = actionsAlice2.findOutgoingMessage<UpdateAddHtlc>()
        val (bob2, _) = bob1.processEx(ChannelEvent.MessageReceived(htlc2))

        val (alice3, bob3) = crossSign(alice2, bob2)

        val (bob4, actionsBob4) = bob3.processEx(ChannelEvent.ExecuteCommand(add))
        val htlc3 = actionsBob4.findOutgoingMessage<UpdateAddHtlc>()
        val (alice4, _) = alice3.processEx(ChannelEvent.MessageReceived(htlc3))
        val (bob5, actionsBob5) = bob4.processEx(ChannelEvent.ExecuteCommand(add))
        val htlc4 = actionsBob5.findOutgoingMessage<UpdateAddHtlc>()
        alice4.processEx(ChannelEvent.MessageReceived(htlc4))

        val (_, actionsBob6) = bob5.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actionsBob6.findOutgoingMessage<CommitSig>()
        assertEquals(4, commitSig.htlcSignatures.size)
    }

    @Test
    fun `recv CMD_SIGN (check htlc info are persisted)`() {
        val (alice0, bob0) = reachNormal()
        // for the test to be really useful we have constraint on parameters
        assertTrue(alice0.staticParams.nodeParams.dustLimit > bob0.staticParams.nodeParams.dustLimit)
        // we're gonna exchange two htlcs in each direction, the goal is to have bob's commitment have 4 htlcs, and alice's
        // commitment only have 3. We will then check that alice indeed persisted 4 htlcs, and bob only 3.
        val aliceMinReceive = TestConstants.Alice.nodeParams.dustLimit + weight2fee(FeeratePerKw.CommitmentFeerate, Commitments.HTLC_SUCCESS_WEIGHT)
        val aliceMinOffer = TestConstants.Alice.nodeParams.dustLimit + weight2fee(FeeratePerKw.CommitmentFeerate, Commitments.HTLC_TIMEOUT_WEIGHT)
        val bobMinReceive = TestConstants.Bob.nodeParams.dustLimit + weight2fee(FeeratePerKw.CommitmentFeerate, Commitments.HTLC_SUCCESS_WEIGHT)
        val bobMinOffer = TestConstants.Bob.nodeParams.dustLimit + weight2fee(FeeratePerKw.CommitmentFeerate, Commitments.HTLC_TIMEOUT_WEIGHT)
        val addAlice1 = bobMinReceive + 10.sat // will be in alice and bob tx
        val addAlice2 = bobMinReceive + 20.sat // will be in alice and bob tx
        val addBob1 = aliceMinReceive + 10.sat // will be in alice and bob tx
        val addBob2 = bobMinOffer + 10.sat // will be only be in bob tx
        assertTrue(addAlice1 > aliceMinOffer && addAlice1 > bobMinReceive)
        assertTrue(addAlice2 > aliceMinOffer && addAlice2 > bobMinReceive)
        assertTrue(addBob1 > aliceMinReceive && addBob1 > bobMinOffer)
        assertTrue(addBob2 < aliceMinReceive && addBob2 > bobMinOffer)

        val (alice1, bob1) = addHtlc(addAlice1.toMilliSatoshi(), alice0, bob0).first
        val (alice2, bob2) = addHtlc(addAlice2.toMilliSatoshi(), alice1, bob1).first
        val (bob3, alice3) = addHtlc(addBob1.toMilliSatoshi(), bob2, alice2).first
        val (bob4, alice4) = addHtlc(addBob2.toMilliSatoshi(), bob3, alice3).first

        val (alice5, aActions5) = alice4.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig0 = aActions5.findOutgoingMessage<CommitSig>()

        val (bob5, bActions5) = bob4.processEx(ChannelEvent.MessageReceived(commitSig0))
        val revokeAndAck0 = bActions5.findOutgoingMessage<RevokeAndAck>()
        val commandSign0 = bActions5.findCommand<CMD_SIGN>()

        val (alice6, _) = alice5.processEx(ChannelEvent.MessageReceived(revokeAndAck0))
        val (bob6, bActions6) = bob5.processEx(ChannelEvent.ExecuteCommand(commandSign0))
        val commitSig1 = bActions6.findOutgoingMessage<CommitSig>()

        val (alice7, aActions7) = alice6.processEx(ChannelEvent.MessageReceived(commitSig1))
        val revokeAndAck1 = aActions7.findOutgoingMessage<RevokeAndAck>()
        val (bob7, _) = bob6.processEx(ChannelEvent.MessageReceived(revokeAndAck1))

        val commandSign1 = aActions7.findCommand<CMD_SIGN>()
        val (alice8, aActions8) = alice7.processEx(ChannelEvent.ExecuteCommand(commandSign1))
        val commitSig2 = aActions8.findOutgoingMessage<CommitSig>()

        val (_, bActions8) = bob7.processEx(ChannelEvent.MessageReceived(commitSig2))
        val revokeAndAck2 = bActions8.findOutgoingMessage<RevokeAndAck>()
        val (_, _) = alice8.processEx(ChannelEvent.MessageReceived(revokeAndAck2))

        val aliceHtlcInfos = buildList {
            addAll(aActions5.filterIsInstance<ChannelAction.Storage.StoreHtlcInfos>())
            addAll(aActions8.filterIsInstance<ChannelAction.Storage.StoreHtlcInfos>())
        }.map { it.htlcs }.flatten()

        val bobHtlcInfos = bActions6.filterIsInstance<ChannelAction.Storage.StoreHtlcInfos>().map { it.htlcs }.flatten()

        assertEquals(0, aliceHtlcInfos.count { it.channelId == alice0.channelId && it.commitmentNumber == 0L })
        assertEquals(2, aliceHtlcInfos.count { it.channelId == alice0.channelId && it.commitmentNumber == 1L })
        assertEquals(4, aliceHtlcInfos.count { it.channelId == alice0.channelId && it.commitmentNumber == 2L })
        assertEquals(0, bobHtlcInfos.count { it.channelId == bob0.channelId && it.commitmentNumber == 0L })
        assertEquals(3, bobHtlcInfos.count { it.channelId == bob0.channelId && it.commitmentNumber == 1L })
    }

    @Test
    fun `recv CMD_SIGN (htlcs with same pubkeyScript but different amounts)`() {
        val (alice0, bob0) = reachNormal()
        val add = defaultAdd.copy(amount = 10_000_000.msat, paymentHash = randomBytes32())
        val epsilons = listOf(3, 1, 5, 7, 6) // unordered on purpose
        val htlcCount = epsilons.size

        val (alice1, bob1) = run {
            var (alice1, bob1) = alice0 to bob0
            for (i in epsilons) {
                val (stateA, actionsA) = alice1.processEx(ChannelEvent.ExecuteCommand(add.copy(amount = add.amount + (i * 1000).msat)))
                alice1 = stateA as Normal
                val updateAddHtlc = actionsA.findOutgoingMessage<UpdateAddHtlc>()
                val (stateB, _) = bob1.processEx(ChannelEvent.MessageReceived(updateAddHtlc))
                bob1 = stateB as Normal
            }
            alice1 to bob1
        }

        val (_, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actionsAlice2.findOutgoingMessage<CommitSig>()
        assertEquals(htlcCount, commitSig.htlcSignatures.size)
        val (bob2, _) = bob1.processEx(ChannelEvent.MessageReceived(commitSig))
        bob2 as ChannelStateWithCommitments
        val htlcTxs = bob2.commitments.localCommit.publishableTxs.htlcTxsAndSigs
        assertEquals(htlcCount, htlcTxs.size)
        val amounts = htlcTxs.map { it.txinfo.tx.txOut.first().amount.sat }
        assertEquals(amounts, amounts.sorted())
    }

    @Test
    fun `recv CMD_SIGN (no changes)`() {
        val (alice0, _) = reachNormal()
        val (_, actions) = alice0.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(actions.isEmpty())
    }

    @Test
    fun `recv CMD_SIGN (while waiting for RevokeAndAck, no pending changes)`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, _) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertTrue(alice1 is Normal)
        assertTrue(alice1.commitments.remoteNextCommitInfo.isRight)

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        actionsAlice2.hasOutgoingMessage<CommitSig>()
        assertTrue(alice2 is Normal)
        assertNotNull(alice2.commitments.remoteNextCommitInfo.left)
        val waitForRevocation = alice2.commitments.remoteNextCommitInfo.left!!
        assertFalse(waitForRevocation.reSignAsap)

        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(alice3 is Normal)
        assertEquals(Either.Left(waitForRevocation), alice3.commitments.remoteNextCommitInfo)
        assertNull(actionsAlice3.findOutgoingMessageOpt<CommitSig>())
    }

    @Test
    fun `recv CMD_SIGN (while waiting for RevokeAndAck, with pending changes)`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertTrue(alice1 is Normal)
        assertTrue(alice1.commitments.remoteNextCommitInfo.isRight)

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        actionsAlice2.hasOutgoingMessage<CommitSig>()
        assertTrue(alice2 is Normal)
        assertNotNull(alice2.commitments.remoteNextCommitInfo.left)
        val waitForRevocation = alice2.commitments.remoteNextCommitInfo.left!!
        assertFalse(waitForRevocation.reSignAsap)

        val (alice3, _) = addHtlc(50_000_000.msat, alice2, bob1).first
        val (alice4, actionsAlice4) = alice3.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(alice4 is Normal)
        assertEquals(Either.Left(waitForRevocation.copy(reSignAsap = true)), alice4.commitments.remoteNextCommitInfo)
        assertTrue(actionsAlice4.isEmpty())
    }

    @Test
    fun `recv CMD_SIGN (going above reserve)`() {
        val (alice0, bob0) = reachNormal(pushMsat = 0.msat)
        assertEquals(0.msat, bob0.commitments.availableBalanceForSend())
        val (nodes1, preimage, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = nodes1
        val (_, bob2) = crossSign(alice1, bob1)
        val (bob3, actions3) = bob2.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(htlc.id, preimage)))
        actions3.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob4, actions4) = bob3.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(bob4 is Normal)
        actions4.hasOutgoingMessage<CommitSig>()
        assertTrue(bob4.commitments.availableBalanceForSend() > 0.msat)
    }

    @Test
    fun `recv CMD_SIGN (after CMD_UPDATE_FEE)`() {
        val (alice, _) = reachNormal()
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_UPDATE_FEE(FeeratePerKw.CommitmentFeerate + FeeratePerKw(1_000.sat))))
        actions1.hasOutgoingMessage<UpdateFee>()
        val (_, actions2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        actions2.hasOutgoingMessage<CommitSig>()
    }

    @Test
    fun `recv CMD_SIGN (channel backup, fundee)`() {
        val (alice, bob) = reachNormal()
        assertTrue(alice.commitments.localParams.features.hasFeature(Feature.ChannelBackupProvider))
        assertTrue(bob.commitments.localParams.features.hasFeature(Feature.ChannelBackupClient))
        val (_, cmdAdd) = makeCmdAdd(50_000_000.msat, alice.staticParams.nodeParams.nodeId, alice.currentBlockHeight.toLong())
        val (bob1, actions) = bob.processEx(ChannelEvent.ExecuteCommand(cmdAdd))
        val add = actions.findOutgoingMessage<UpdateAddHtlc>()
        val (alice1, _) = alice.processEx(ChannelEvent.MessageReceived(add))
        assertTrue { (alice1 as Normal).commitments.remoteChanges.proposed.contains(add) }
        val (bob2, actions2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actions2.findOutgoingMessage<CommitSig>()
        val blob = Serialization.encrypt(bob.staticParams.nodeParams.nodePrivateKey.value, bob2 as Normal)
        assertEquals(blob, commitSig.channelData)
    }

    @Test
    fun `recv CommitSig (one htlc received)`() {
        val (alice0, bob0) = reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
        val (nodes0, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = nodes0
        assertTrue(bob1 is Normal)

        val (_, bob2) = signAndRevack(alice1, bob1)
        val (bob3, actions3) = bob2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actions3.findOutgoingMessage<CommitSig>()
        assertTrue(commitSig.channelData.isEmpty())
        assertTrue(bob3 is Normal)
        assertTrue(bob3.commitments.localCommit.spec.htlcs.incomings().any { it.id == htlc.id })
        assertEquals(1, bob3.commitments.localCommit.publishableTxs.htlcTxsAndSigs.size)
        assertEquals(bob1.commitments.localCommit.spec.toLocal, bob3.commitments.localCommit.spec.toLocal)
        assertEquals(0, bob3.commitments.remoteChanges.acked.size)
        assertEquals(1, bob3.commitments.remoteChanges.signed.size)
    }

    @Test
    fun `recv CommitSig (one htlc sent)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes0, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = nodes0
        assertTrue(bob1 is Normal)

        val (alice2, bob2) = signAndRevack(alice1, bob1)
        val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(bob3 is Normal)
        val commitSig = actionsBob3.findOutgoingMessage<CommitSig>()
        val (alice3, _) = alice2.processEx(ChannelEvent.MessageReceived(commitSig))
        assertTrue(alice3 is Normal)
        assertTrue(alice3.commitments.localCommit.spec.htlcs.outgoings().any { it.id == htlc.id })
        assertEquals(1, alice3.commitments.localCommit.publishableTxs.htlcTxsAndSigs.size)
        assertEquals(1, alice3.commitments.localCommit.publishableTxs.htlcTxsAndSigs.size)
        assertEquals(bob1.commitments.localCommit.spec.toLocal, bob3.commitments.localCommit.spec.toLocal)
    }

    @Test
    fun `recv CommitSig (multiple htlcs in both directions)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes1, _, _) = addHtlc(50_000_000.msat, alice0, bob0) // a->b (regular)
        val (alice1, bob1) = nodes1
        val (nodes2, _, _) = addHtlc(8_000_000.msat, alice1, bob1) //  a->b (regular)
        val (alice2, bob2) = nodes2
        val (nodes3, _, _) = addHtlc(300_000.msat, bob2, alice2) //   b->a (dust)
        val (bob3, alice3) = nodes3
        val (nodes4, _, _) = addHtlc(1_000_000.msat, alice3, bob3) //  a->b (regular)
        val (alice4, bob4) = nodes4
        val (nodes5, _, _) = addHtlc(50_000_000.msat, bob4, alice4) // b->a (regular)
        val (bob5, alice5) = nodes5
        val (nodes6, _, _) = addHtlc(500_000.msat, alice5, bob5) //   a->b (dust)
        val (alice6, bob6) = nodes6
        val (nodes7, _, _) = addHtlc(4_000_000.msat, bob6, alice6) //  b->a (regular)
        val (bob7, alice7) = nodes7

        val (alice8, bob8) = signAndRevack(alice7, bob7)
        val (_, actionsBob9) = bob8.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actionsBob9.findOutgoingMessage<CommitSig>()
        val (alice9, _) = alice8.processEx(ChannelEvent.MessageReceived(commitSig))
        assertTrue(alice9 is Normal)
        assertEquals(1, alice9.commitments.localCommit.index)
        assertEquals(3, alice9.commitments.localCommit.publishableTxs.htlcTxsAndSigs.size)
    }

    @Test
    fun `recv CommitSig (only fee update)`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, actions1) = alice0.processEx(ChannelEvent.ExecuteCommand(CMD_UPDATE_FEE(FeeratePerKw.CommitmentFeerate + FeeratePerKw(1_000.sat), false)))
        val updateFee = actions1.findOutgoingMessage<UpdateFee>()
        assertEquals(FeeratePerKw.CommitmentFeerate + FeeratePerKw(1_000.sat), updateFee.feeratePerKw)
        val (bob1, _) = bob0.processEx(ChannelEvent.MessageReceived(updateFee))
        val (alice2, actions2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actions2.findOutgoingMessage<CommitSig>()
        val (_, actions3) = bob1.processEx(ChannelEvent.MessageReceived(commitSig))
        val revokeAndAck = actions3.findOutgoingMessage<RevokeAndAck>()
        val (alice3, _) = alice2.processEx(ChannelEvent.MessageReceived(revokeAndAck))
        assertTrue(alice3 is Normal)
    }

    @Test
    fun `recv CommitSig (two htlcs received with same preimage)`() {
        val (alice0, bob0) = reachNormal()
        val r = randomBytes32()
        val h = Crypto.sha256(r).toByteVector32()

        val (alice1, actionsAlice1) = alice0.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(paymentHash = h)))
        val htlc1 = actionsAlice1.findOutgoingMessage<UpdateAddHtlc>()
        val (bob1, _) = bob0.processEx(ChannelEvent.MessageReceived(htlc1))

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(defaultAdd.copy(paymentHash = h)))
        val htlc2 = actionsAlice2.findOutgoingMessage<UpdateAddHtlc>()
        val (bob2, _) = bob1.processEx(ChannelEvent.MessageReceived(htlc2))
        assertEquals(listOf(htlc1, htlc2), (bob2 as ChannelStateWithCommitments).commitments.remoteChanges.proposed)

        val (_, bob3) = crossSign(alice2, bob2)
        assertTrue(bob3 is Normal)
        assertTrue(bob3.commitments.localCommit.spec.htlcs.incomings().any { it.id == htlc1.id })
        assertEquals(2, bob3.commitments.localCommit.publishableTxs.htlcTxsAndSigs.size)
        assertEquals(bob2.commitments.localCommit.spec.toLocal, bob3.commitments.localCommit.spec.toLocal)
        assertEquals(2, bob3.commitments.localCommit.publishableTxs.commitTx.tx.txOut.count { it.amount == 50_000.sat })
    }

    @Test
    fun `recv CommitSig (no changes)`() {
        val (_, bob0) = reachNormal()
        val tx = bob0.commitments.localCommit.publishableTxs.commitTx.tx

        // signature is invalid but it doesn't matter
        val sig = CommitSig(ByteVector32.Zeroes, ByteVector64.Zeroes, emptyList())
        val (bob1, actionsBob1) = bob0.processEx(ChannelEvent.MessageReceived(sig))
        assertTrue(bob1 is Closing)
        actionsBob1.hasOutgoingMessage<Error>()

        assertEquals(2, actionsBob1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        assertEquals(tx, actionsBob1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().first().tx)
        assertEquals(tx.txid, actionsBob1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().last().tx.txIn.first().outPoint.txid)

        assertEquals(2, actionsBob1.findWatches<WatchConfirmed>().count())
        actionsBob1.findWatches<WatchConfirmed>().first().run {
            val e = event as? BITCOIN_TX_CONFIRMED
            assertNotNull(e)
            assertEquals(tx, e.tx)
        }
        actionsBob1.findWatches<WatchConfirmed>().last().run {
            val e = event as? BITCOIN_TX_CONFIRMED
            assertNotNull(e)
            assertEquals(tx.txid, actionsBob1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().last().tx.txIn.first().outPoint.txid)
        }
    }

    @Test
    fun `recv CommitSig (invalid signature)`() {
        val (_, bob0) = reachNormal()
        val tx = bob0.commitments.localCommit.publishableTxs.commitTx.tx

        // signature is invalid but it doesn't matter
        val sig = CommitSig(ByteVector32.Zeroes, ByteVector64.Zeroes, emptyList())
        val (bob1, actionsBob1) = bob0.processEx(ChannelEvent.MessageReceived(sig))
        assertTrue(bob1 is Closing)
        actionsBob1.hasOutgoingMessage<Error>()

        assertEquals(2, actionsBob1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        assertEquals(tx, actionsBob1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().first().tx)
        assertEquals(tx.txid, actionsBob1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().last().tx.txIn.first().outPoint.txid)

        assertEquals(2, actionsBob1.findWatches<WatchConfirmed>().count())
        actionsBob1.findWatches<WatchConfirmed>().first().run {
            val e = event as? BITCOIN_TX_CONFIRMED
            assertNotNull(e)
            assertEquals(tx, e.tx)
        }
        actionsBob1.findWatches<WatchConfirmed>().last().run {
            val e = event as? BITCOIN_TX_CONFIRMED
            assertNotNull(e)
            assertEquals(tx.txid, actionsBob1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().last().tx.txIn.first().outPoint.txid)
        }
    }

    @Test
    fun `recv CommitSig (bad htlc sig count)`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertTrue(bob1 is Normal)
        val tx = bob1.commitments.localCommit.publishableTxs.commitTx.tx

        val (_, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actionsAlice2.findOutgoingMessage<CommitSig>()
        val badCommitSig = commitSig.copy(htlcSignatures = commitSig.htlcSignatures + commitSig.htlcSignatures)

        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.MessageReceived(badCommitSig))
        assertTrue(bob2 is Closing)
        actionsBob2.hasOutgoingMessage<Error>()
        assertEquals(2, actionsBob2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        assertEquals(tx, actionsBob2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().first().tx)
        assertEquals(tx.txid, actionsBob2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().last().tx.txIn.first().outPoint.txid)

        assertEquals(2, actionsBob2.findWatches<WatchConfirmed>().count())
        actionsBob2.findWatches<WatchConfirmed>().first().run {
            val e = event as? BITCOIN_TX_CONFIRMED
            assertNotNull(e)
            assertEquals(tx, e.tx)
        }
        actionsBob2.findWatches<WatchConfirmed>().last().run {
            val e = event as? BITCOIN_TX_CONFIRMED
            assertNotNull(e)
            assertEquals(tx.txid, actionsBob2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().last().tx.txIn.first().outPoint.txid)
        }
    }

    @Test
    fun `recv CommitSig (invalid htlc sig)`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertTrue(bob1 is Normal)
        val tx = bob1.commitments.localCommit.publishableTxs.commitTx.tx

        val (_, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actionsAlice2.findOutgoingMessage<CommitSig>()
        val badCommitSig = commitSig.copy(htlcSignatures = listOf(commitSig.signature))
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.MessageReceived(badCommitSig))
        assertTrue(bob2 is Closing)
        actionsBob2.hasOutgoingMessage<Error>()
        assertEquals(2, actionsBob2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        assertEquals(tx, actionsBob2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().first().tx)
        assertEquals(tx.txid, actionsBob2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().last().tx.txIn.first().outPoint.txid)

        assertEquals(2, actionsBob2.findWatches<WatchConfirmed>().count())
        actionsBob2.findWatches<WatchConfirmed>().first().run {
            val e = event as? BITCOIN_TX_CONFIRMED
            assertNotNull(e)
            assertEquals(tx, e.tx)
        }
        actionsBob2.findWatches<WatchConfirmed>().last().run {
            val e = event as? BITCOIN_TX_CONFIRMED
            assertNotNull(e)
            assertEquals(tx.txid, actionsBob2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().last().tx.txIn.first().outPoint.txid)
        }
    }

    @Test
    fun `recv RevokeAndAck (channel backup, fundee)`() {
        val (alice, bob) = reachNormal()
        assertTrue(alice.commitments.localParams.features.hasFeature(Feature.ChannelBackupProvider))
        assertTrue(bob.commitments.localParams.features.hasFeature(Feature.ChannelBackupClient))
        val (_, cmdAdd) = makeCmdAdd(50_000_000.msat, alice.staticParams.nodeParams.nodeId, alice.currentBlockHeight.toLong())
        val (bob1, actions) = bob.processEx(ChannelEvent.ExecuteCommand(cmdAdd))
        val add = actions.findOutgoingMessage<UpdateAddHtlc>()
        val (alice1, _) = alice.processEx(ChannelEvent.MessageReceived(add))
        assertTrue(alice1 is Normal)
        assertTrue(alice1.commitments.remoteChanges.proposed.contains(add))
        val (bob2, actions2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actions2.findOutgoingMessage<CommitSig>()
        val (alice2, actions3) = alice1.processEx(ChannelEvent.MessageReceived(commitSig))
        val revack = actions3.findOutgoingMessage<RevokeAndAck>()
        val (bob3, _) = bob2.processEx(ChannelEvent.MessageReceived(revack))
        val (_, actions4) = alice2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig1 = actions4.findOutgoingMessage<CommitSig>()
        val (bob4, actions5) = bob3.processEx(ChannelEvent.MessageReceived(commitSig1))
        val revack1 = actions5.findOutgoingMessage<RevokeAndAck>()
        val blob = Serialization.encrypt(bob4.staticParams.nodeParams.nodePrivateKey.value, bob4 as Normal)
        assertEquals(blob, revack1.channelData)
    }

    @Test
    fun `recv RevokeAndAck (one htlc sent)`() {
        val (alice0, bob0) = reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ChannelBackupClient))
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(alice2 is Normal)
        assertTrue(alice2.commitments.remoteNextCommitInfo.isLeft)
        val commitSig = actionsAlice2.findOutgoingMessage<CommitSig>()
        val (_, actionsBob2) = bob1.processEx(ChannelEvent.MessageReceived(commitSig))
        val revokeAndAck = actionsBob2.findOutgoingMessage<RevokeAndAck>()
        assertTrue(revokeAndAck.channelData.isEmpty())

        val (alice3, _) = alice2.processEx(ChannelEvent.MessageReceived(revokeAndAck))
        assertTrue(alice3 is Normal)
        assertTrue(alice3.commitments.remoteNextCommitInfo.isRight)
        assertEquals(1, alice3.commitments.localChanges.acked.size)
    }

    @Test
    fun `recv RevokeAndAck (one htlc received)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, add) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = nodes

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig0 = actionsAlice2.findOutgoingMessage<CommitSig>()

        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.MessageReceived(commitSig0))
        val revokeAndAck0 = actionsBob2.findOutgoingMessage<RevokeAndAck>()
        val cmd = actionsBob2.findCommand<CMD_SIGN>()
        val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.ExecuteCommand(cmd))
        val (alice3, _) = alice2.processEx(ChannelEvent.MessageReceived(revokeAndAck0))
        assertTrue(alice3 is Normal)
        assertTrue(alice3.commitments.remoteNextCommitInfo.isRight)
        val commitSig1 = actionsBob3.findOutgoingMessage<CommitSig>()
        val (_, actionsAlice4) = alice3.processEx(ChannelEvent.MessageReceived(commitSig1))
        val revokeAndAck1 = actionsAlice4.findOutgoingMessage<RevokeAndAck>()
        val (bob4, actionsBob4) = bob3.processEx(ChannelEvent.MessageReceived(revokeAndAck1))
        assertTrue(bob4 is Normal)
        assertTrue(bob4.commitments.remoteNextCommitInfo.isRight)
        actionsBob4.has<ChannelAction.Storage.StoreState>()
        assertEquals(add, actionsBob4.find<ChannelAction.ProcessIncomingHtlc>().add)
    }

    @Test
    fun `recv RevokeAndAck (multiple htlcs in both directions)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes1, _, add1) = addHtlc(50_000_000.msat, alice0, bob0) // a->b (regular)
        val (alice1, bob1) = nodes1
        val (nodes2, _, add2) = addHtlc(8_000_000.msat, alice1, bob1) //  a->b (regular)
        val (alice2, bob2) = nodes2
        val (nodes3, _, _) = addHtlc(300_000.msat, bob2, alice2) //   b->a (dust)
        val (bob3, alice3) = nodes3
        val (nodes4, _, add3) = addHtlc(1_000_000.msat, alice3, bob3) //  a->b (regular)
        val (alice4, bob4) = nodes4
        val (nodes5, _, _) = addHtlc(50_000_000.msat, bob4, alice4) // b->a (regular)
        val (bob5, alice5) = nodes5
        val (nodes6, _, add4) = addHtlc(500_000.msat, alice5, bob5) //   a->b (dust)
        val (alice6, bob6) = nodes6
        val (nodes7, _, _) = addHtlc(4_000_000.msat, bob6, alice6) //  b->a (regular)
        val (bob7, alice7) = nodes7

        val (alice8, actionsAlice8) = alice7.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig0 = actionsAlice8.findOutgoingMessage<CommitSig>()
        val (bob8, actionsBob8) = bob7.processEx(ChannelEvent.MessageReceived(commitSig0))
        val revokeAndAck0 = actionsBob8.findOutgoingMessage<RevokeAndAck>()
        val cmd = actionsBob8.findCommand<CMD_SIGN>()
        val (bob9, actionsBob9) = bob8.processEx(ChannelEvent.ExecuteCommand(cmd))
        val (alice9, _) = alice8.processEx(ChannelEvent.MessageReceived(revokeAndAck0))
        assertTrue(alice9 is Normal)
        assertTrue(alice9.commitments.remoteNextCommitInfo.isRight)

        val commitSig1 = actionsBob9.findOutgoingMessage<CommitSig>()
        val (_, actionsAlice10) = alice9.processEx(ChannelEvent.MessageReceived(commitSig1))
        val revokeAndAck1 = actionsAlice10.findOutgoingMessage<RevokeAndAck>()
        val (bob10, actionsBob10) = bob9.processEx(ChannelEvent.MessageReceived(revokeAndAck1))
        assertTrue(bob10 is Normal)
        assertTrue(bob10.commitments.remoteNextCommitInfo.isRight)
        assertEquals(1, bob10.commitments.remoteCommit.index)
        assertEquals(7, bob10.commitments.remoteCommit.spec.htlcs.size)
        assertEquals(setOf(add1, add2, add3, add4), actionsBob10.filterIsInstance<ChannelAction.ProcessIncomingHtlc>().map { it.add }.toSet())
    }

    @Test
    fun `recv RevokeAndAck (with reSignAsap=true)`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertTrue(alice1 is Normal)
        assertTrue(alice1.commitments.remoteNextCommitInfo.isRight)

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig0 = actionsAlice2.findOutgoingMessage<CommitSig>()
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.MessageReceived(commitSig0))

        val (alice3, _) = addHtlc(50_000_000.msat, alice2, bob2).first
        val (alice4, _) = alice3.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(alice4 is Normal)
        assertTrue(alice4.commitments.remoteNextCommitInfo.left?.reSignAsap == true)

        val revokeAndAck0 = actionsBob2.findOutgoingMessage<RevokeAndAck>()
        val (alice5, actionsAlice5) = alice4.processEx(ChannelEvent.MessageReceived(revokeAndAck0))
        val cmd = actionsAlice5.findCommand<CMD_SIGN>()
        val (_, actionsAlice6) = alice5.processEx(ChannelEvent.ExecuteCommand(cmd))
        actionsAlice6.hasOutgoingMessage<CommitSig>()
    }

    @Test
    fun `recv RevokeAndAck (invalid preimage)`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertTrue(alice1 is Normal)
        val tx = alice1.commitments.localCommit.publishableTxs.commitTx.tx

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig0 = actionsAlice2.findOutgoingMessage<CommitSig>()
        val (_, actionsBob2) = bob1.processEx(ChannelEvent.MessageReceived(commitSig0))
        actionsBob2.hasOutgoingMessage<RevokeAndAck>()

        val (alice3, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(RevokeAndAck(ByteVector32.Zeroes, PrivateKey(randomBytes32()), PrivateKey(randomBytes32()).publicKey())))
        assertTrue(alice3 is Closing)
        actionsAlice3.hasOutgoingMessage<Error>()
        assertEquals(2, actionsAlice3.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        assertEquals(2, actionsAlice3.findWatches<WatchConfirmed>().count())
        actionsAlice3.hasTx(tx)
    }

    @Test
    fun `recv RevokeAndAck (unexpectedly)`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, _) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertTrue(alice1 is Normal)
        assertTrue(alice1.commitments.remoteNextCommitInfo.isRight)
        val tx = alice1.commitments.localCommit.publishableTxs.commitTx.tx

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.MessageReceived(RevokeAndAck(ByteVector32.Zeroes, PrivateKey(randomBytes32()), PrivateKey(randomBytes32()).publicKey())))
        assertTrue(alice2 is Closing)
        actionsAlice2.hasOutgoingMessage<Error>()
        assertEquals(2, actionsAlice2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        assertEquals(2, actionsAlice2.findWatches<WatchConfirmed>().count())
        actionsAlice2.hasTx(tx)
    }

    @Test
    fun `recv CMD_FULFILL_HTLC`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, r, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertTrue(bob1 is Normal)

        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(htlc.id, r)))
        val fulfillHtlc = actionsBob2.findOutgoingMessage<UpdateFulfillHtlc>()
        assertEquals(bob1.copy(commitments = bob1.commitments.copy(localChanges = bob1.commitments.localChanges.copy(bob1.commitments.localChanges.proposed + fulfillHtlc))), bob2)
    }

    @Test
    fun `recv CMD_FULFILL_HTLC (unknown htlc id)`() {
        val (_, bob0) = reachNormal()
        val cmd = CMD_FULFILL_HTLC(42, randomBytes32())

        val (_, actions) = bob0.processEx(ChannelEvent.ExecuteCommand(cmd))
        val actualError = actions.findCommandError<UnknownHtlcId>()
        val expectedError = UnknownHtlcId(bob0.channelId, 42)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv CMD_FULFILL_HTLC (invalid preimage)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertTrue(bob1 is Normal)

        val cmd = CMD_FULFILL_HTLC(htlc.id, ByteVector32.Zeroes)
        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(cmd))
        actionsBob2.hasCommandError<InvalidHtlcPreimage>()
        assertEquals(bob1, bob2)
    }

    @Test
    fun `recv UpdateFulfillHtlc`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, r, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = crossSign(nodes.first, nodes.second)
        val (_, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(htlc.id, r)))
        val fulfill = actionsBob2.findOutgoingMessage<UpdateFulfillHtlc>()
        assertTrue(alice1 is Normal)

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.MessageReceived(fulfill))
        assertEquals(alice1.copy(commitments = alice1.commitments.copy(remoteChanges = alice1.commitments.remoteChanges.copy(alice1.commitments.remoteChanges.proposed + fulfill))), alice2)
        val addSettled = actionsAlice2.filterIsInstance<ChannelAction.ProcessCmdRes.AddSettledFulfill>().first()
        assertEquals(htlc, addSettled.htlc)
        assertEquals(ChannelAction.HtlcResult.Fulfill.RemoteFulfill(fulfill), addSettled.result)
    }

    @Test
    fun `recv UpdateFulfillHtlc (unknown htlc id)`() {
        val (alice0, _) = reachNormal()
        val commitTx = alice0.commitments.localCommit.publishableTxs.commitTx.tx
        val (alice1, actions1) = alice0.processEx(ChannelEvent.MessageReceived(UpdateFulfillHtlc(alice0.channelId, 42, randomBytes32())))
        assertTrue(alice1 is Closing)
        assertTrue(actions1.contains(ChannelAction.Storage.StoreState(alice1)))
        assertTrue(actions1.contains(ChannelAction.Blockchain.PublishTx(commitTx)))
        assertTrue(actions1.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions1.filterIsInstance<ChannelAction.Blockchain.SendWatch>().all { it.watch is WatchConfirmed })
        val error = actions1.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice0.channelId, 42).message)
    }

    @Test
    fun `recv UpdateFulfillHtlc (sender has not signed htlc)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, r, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, actions1) = nodes.first.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(alice1 is Normal)
        actions1.findOutgoingMessage<CommitSig>()
        val commitTx = alice1.commitments.localCommit.publishableTxs.commitTx.tx
        val (alice2, actions2) = alice1.processEx(ChannelEvent.MessageReceived(UpdateFulfillHtlc(alice1.channelId, htlc.id, r)))
        assertTrue(alice2 is Closing)
        assertTrue(actions2.contains(ChannelAction.Storage.StoreState(alice2)))
        assertTrue(actions2.contains(ChannelAction.Blockchain.PublishTx(commitTx)))
        assertTrue(actions2.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions2.filterIsInstance<ChannelAction.Blockchain.SendWatch>().all { it.watch is WatchConfirmed })
        val error = actions2.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice0.channelId, 0).message)
    }

    @Test
    fun `recv UpdateFulfillHtlc (invalid preimage)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        assertTrue(alice1 is Normal)
        val commitTx = alice1.commitments.localCommit.publishableTxs.commitTx.tx
        val (alice2, actions2) = alice1.processEx(ChannelEvent.MessageReceived(UpdateFulfillHtlc(alice0.channelId, htlc.id, ByteVector32.Zeroes)))
        assertTrue(alice2 is Closing)
        assertTrue(actions2.contains(ChannelAction.Storage.StoreState(alice2)))
        assertTrue(actions2.contains(ChannelAction.Blockchain.PublishTx(commitTx)))
        assertEquals(4, actions2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().size) // commit tx + main delayed + htlc-timeout + htlc delayed
        assertEquals(4, actions2.filterIsInstance<ChannelAction.Blockchain.SendWatch>().size)
        val error = actions2.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InvalidHtlcPreimage(alice0.channelId, htlc.id).message)
    }

    @Test
    fun `recv CMD_FAIL_HTLC`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertTrue(bob1 is Normal)

        val cmd = CMD_FAIL_HTLC(htlc.id, CMD_FAIL_HTLC.Reason.Failure(PermanentChannelFailure))
        val (bob2, actions2) = bob1.processEx(ChannelEvent.ExecuteCommand(cmd))
        val fail = actions2.findOutgoingMessage<UpdateFailHtlc>()
        assertEquals(bob1.copy(commitments = bob1.commitments.copy(localChanges = bob1.commitments.localChanges.copy(bob1.commitments.localChanges.proposed + fail))), bob2)
    }

    @Test
    fun `recv CMD_FAIL_HTLC (unknown htlc id)`() {
        val (_, bob0) = reachNormal()
        val cmdFail = CMD_FAIL_HTLC(42, CMD_FAIL_HTLC.Reason.Failure(PermanentChannelFailure))
        val (bob1, actions1) = bob0.processEx(ChannelEvent.ExecuteCommand(cmdFail))
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmdFail, UnknownHtlcId(bob0.channelId, 42))))
        assertEquals(bob0, bob1)
    }

    @Test
    fun `recv CMD_FAIL_HTLC_MALFORMED`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertTrue(bob1 is Normal)

        val cmdFail = CMD_FAIL_MALFORMED_HTLC(htlc.id, Sphinx.hash(htlc.onionRoutingPacket), FailureMessage.BADONION)
        val (bob2, actions2) = bob1.processEx(ChannelEvent.ExecuteCommand(cmdFail))
        val fail = actions2.findOutgoingMessage<UpdateFailMalformedHtlc>()
        assertEquals(bob1.copy(commitments = bob1.commitments.copy(localChanges = bob1.commitments.localChanges.copy(bob1.commitments.localChanges.proposed + fail))), bob2)
    }

    @Test
    fun `recv CMD_FAIL_HTLC_MALFORMED (unknown htlc id)`() {
        val (_, bob0) = reachNormal()
        val cmdFail = CMD_FAIL_MALFORMED_HTLC(42, ByteVector32.Zeroes, FailureMessage.BADONION)
        val (bob1, actions1) = bob0.processEx(ChannelEvent.ExecuteCommand(cmdFail))
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmdFail, UnknownHtlcId(bob0.channelId, 42))))
        assertEquals(bob0, bob1)
    }

    @Test
    fun `recv CMD_FAIL_HTLC_MALFORMED (invalid failure_code)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)

        val cmdFail = CMD_FAIL_MALFORMED_HTLC(htlc.id, Sphinx.hash(htlc.onionRoutingPacket), 42)
        val (bob2, actions2) = bob1.processEx(ChannelEvent.ExecuteCommand(cmdFail))
        assertEquals(actions2, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmdFail, InvalidFailureCode(bob0.channelId))))
        assertEquals(bob1, bob2)
    }

    @Test
    fun `recv UpdateFailHtlc`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = crossSign(nodes.first, nodes.second)
        val (_, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_FAIL_HTLC(htlc.id, CMD_FAIL_HTLC.Reason.Failure(PermanentChannelFailure))))
        val fail = actionsBob2.findOutgoingMessage<UpdateFailHtlc>()
        assertTrue(alice1 is Normal)

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.MessageReceived(fail))
        assertTrue(alice2 is Normal)
        assertTrue(actionsAlice2.isEmpty())
        assertEquals(alice1.copy(commitments = alice1.commitments.copy(remoteChanges = alice1.commitments.remoteChanges.copy(alice1.commitments.remoteChanges.proposed + fail))), alice2)
    }

    @Test
    fun `recv UpdateFailHtlc (unknown htlc id)`() {
        val (alice0, _) = reachNormal()
        val commitTx = alice0.commitments.localCommit.publishableTxs.commitTx.tx
        val (alice1, actions1) = alice0.processEx(ChannelEvent.MessageReceived(UpdateFailHtlc(alice0.channelId, 42, ByteVector.empty)))
        assertTrue(alice1 is Closing)
        assertTrue(actions1.contains(ChannelAction.Storage.StoreState(alice1)))
        assertTrue(actions1.contains(ChannelAction.Blockchain.PublishTx(commitTx)))
        assertTrue(actions1.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions1.filterIsInstance<ChannelAction.Blockchain.SendWatch>().all { it.watch is WatchConfirmed })
        val error = actions1.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice0.channelId, 42).message)
    }

    @Test
    fun `recv UpdateFailHtlc (sender has not signed htlc)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, actions1) = nodes.first.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(alice1 is Normal)
        actions1.findOutgoingMessage<CommitSig>()
        val commitTx = alice1.commitments.localCommit.publishableTxs.commitTx.tx
        val (alice2, actions2) = alice1.processEx(ChannelEvent.MessageReceived(UpdateFailHtlc(alice1.channelId, htlc.id, ByteVector.empty)))
        assertTrue(alice2 is Closing)
        assertTrue(actions2.contains(ChannelAction.Storage.StoreState(alice2)))
        assertTrue(actions2.contains(ChannelAction.Blockchain.PublishTx(commitTx)))
        assertTrue(actions2.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions2.filterIsInstance<ChannelAction.Blockchain.SendWatch>().all { it.watch is WatchConfirmed })
        val error = actions2.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice0.channelId, 0).message)
    }

    @Test
    fun `recv UpdateFailMalformedHtlc`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = crossSign(nodes.first, nodes.second)
        val (_, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_FAIL_MALFORMED_HTLC(htlc.id, Sphinx.hash(htlc.onionRoutingPacket), FailureMessage.BADONION)))
        val fail = actionsBob2.findOutgoingMessage<UpdateFailMalformedHtlc>()
        assertTrue(alice1 is Normal)

        val (alice2, actionsAlice2) = alice1.processEx(ChannelEvent.MessageReceived(fail))
        assertTrue(alice2 is Normal)
        assertTrue(actionsAlice2.isEmpty())
        assertEquals(alice1.copy(commitments = alice1.commitments.copy(remoteChanges = alice1.commitments.remoteChanges.copy(alice1.commitments.remoteChanges.proposed + fail))), alice2)
    }

    @Test
    fun `recv UpdateFailMalformedHtlc (unknown htlc id)`() {
        val (alice0, _) = reachNormal()
        val commitTx = alice0.commitments.localCommit.publishableTxs.commitTx.tx
        val (alice1, actions1) = alice0.processEx(ChannelEvent.MessageReceived(UpdateFailMalformedHtlc(alice0.channelId, 42, ByteVector32.Zeroes, FailureMessage.BADONION)))
        assertTrue(alice1 is Closing)
        assertTrue(actions1.contains(ChannelAction.Storage.StoreState(alice1)))
        assertTrue(actions1.contains(ChannelAction.Blockchain.PublishTx(commitTx)))
        assertTrue(actions1.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions1.filterIsInstance<ChannelAction.Blockchain.SendWatch>().all { it.watch is WatchConfirmed })
        val error = actions1.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice0.channelId, 42).message)
    }

    @Test
    fun `recv UpdateFailMalformedHtlc (invalid failure_code)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        assertTrue(alice1 is Normal)
        val commitTx = alice1.commitments.localCommit.publishableTxs.commitTx.tx

        val (alice2, actions2) = alice1.processEx(ChannelEvent.MessageReceived(UpdateFailMalformedHtlc(alice0.channelId, htlc.id, Sphinx.hash(htlc.onionRoutingPacket), 42)))
        assertTrue(alice2 is Closing)
        assertTrue(actions2.contains(ChannelAction.Storage.StoreState(alice2)))
        assertTrue(actions2.contains(ChannelAction.Blockchain.PublishTx(commitTx)))
        assertEquals(4, actions2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().size) // commit tx + main delayed + htlc-timeout + htlc delayed
        assertEquals(4, actions2.filterIsInstance<ChannelAction.Blockchain.SendWatch>().size)
        val error = actions2.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InvalidFailureCode(alice0.channelId).message)
    }

    @Test
    fun `recv UpdateFee`() {
        val (_, bob) = reachNormal()
        val fee = UpdateFee(ByteVector32.Zeroes, FeeratePerKw(7_500.sat))
        val (bob1, _) = bob.processEx(ChannelEvent.MessageReceived(fee))
        bob1 as Normal
        assertEquals(bob.commitments.copy(remoteChanges = bob.commitments.remoteChanges.copy(proposed = bob.commitments.remoteChanges.proposed + fee)), bob1.commitments)
    }

    @Test
    fun `recv UpdateFee (2 in a row)`() {
        val (_, bob) = reachNormal()
        val fee1 = UpdateFee(ByteVector32.Zeroes, FeeratePerKw(7_500.sat))
        val (bob1, _) = bob.processEx(ChannelEvent.MessageReceived(fee1))
        val fee2 = UpdateFee(ByteVector32.Zeroes, FeeratePerKw(9_000.sat))
        val (bob2, _) = bob1.processEx(ChannelEvent.MessageReceived(fee2))
        assertTrue(bob2 is Normal)
        assertEquals(bob.commitments.copy(remoteChanges = bob.commitments.remoteChanges.copy(proposed = bob.commitments.remoteChanges.proposed + fee2)), bob2.commitments)
    }

    @Test
    fun `recv UpdateFee (sender cannot afford it)`() {
        val (alice, bob) = reachNormal()
        // We put all the balance on Bob's side, so that Alice cannot afford a feerate increase.
        val (nodes, _, _) = addHtlc(alice.commitments.availableBalanceForSend(), alice, bob)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertTrue(bob1 is Normal)
        val commitTx = bob1.commitments.localCommit.publishableTxs.commitTx.tx

        val fee = UpdateFee(ByteVector32.Zeroes, FeeratePerKw.CommitmentFeerate * 4)
        val (bob2, actions) = bob1.processEx(ChannelEvent.MessageReceived(fee))
        assertTrue(bob2 is Closing)
        actions.hasTx(commitTx)
        actions.hasWatch<WatchConfirmed>()
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), CannotAffordFees(bob.channelId, missing = 11_240.sat, reserve = 20_000.sat, fees = 26_580.sat).message)
    }

    @Test
    fun `recv UpdateFee (remote feerate is too small)`() {
        val (_, bob) = reachNormal()
        assertEquals(FeeratePerKw.CommitmentFeerate, bob.commitments.localCommit.spec.feerate)
        val (bob1, actions) = bob.processEx(ChannelEvent.MessageReceived(UpdateFee(bob.channelId, FeeratePerKw(252.sat))))
        assertTrue(bob1 is Closing)
        actions.hasTx(bob.commitments.localCommit.publishableTxs.commitTx.tx)
        actions.hasWatch<WatchConfirmed>()
        val error = actions.findOutgoingMessage<Error>()
        assertTrue(error.toAscii().contains("emote fee rate is too small: remoteFeeratePerKw=252"))
    }

    @Test
    fun `recv ChannelUpdate`() {
        val (alice, bob) = reachNormal()
        assertNull(alice.remoteChannelUpdate)
        assertNull(bob.remoteChannelUpdate)
        val aliceUpdate = Announcements.makeChannelUpdate(alice.staticParams.nodeParams.chainHash, alice.privateKey, alice.staticParams.remoteNodeId, alice.shortChannelId, CltvExpiryDelta(36), 5.msat, 15.msat, 150, 150_000.msat)
        val (bob1, actions1) = bob.processEx(ChannelEvent.MessageReceived(aliceUpdate))
        assertTrue(bob1 is Normal)
        assertEquals(bob1.remoteChannelUpdate, aliceUpdate)
        actions1.has<ChannelAction.Storage.StoreState>()

        val aliceUpdateOtherChannel = Announcements.makeChannelUpdate(alice.staticParams.nodeParams.chainHash, alice.privateKey, alice.staticParams.remoteNodeId, ShortChannelId(7), CltvExpiryDelta(12), 1.msat, 10.msat, 50, 15_000.msat)
        val (bob2, actions2) = bob1.processEx(ChannelEvent.MessageReceived(aliceUpdateOtherChannel))
        assertEquals(bob1, bob2)
        assertTrue(actions2.isEmpty())

        val bobUpdate = Announcements.makeChannelUpdate(bob.staticParams.nodeParams.chainHash, bob.privateKey, bob.staticParams.remoteNodeId, bob.shortChannelId, CltvExpiryDelta(24), 1.msat, 5.msat, 10, 125_000.msat)
        val (bob3, actions3) = bob2.processEx(ChannelEvent.MessageReceived(bobUpdate))
        assertEquals(bob1, bob3)
        assertTrue(actions3.isEmpty())
    }

    @Test
    fun `recv CMD_CLOSE (no pending htlcs)`() {
        val (alice, _) = reachNormal()
        assertNull(alice.localShutdown)
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(alice1 is Normal)
        actions1.hasOutgoingMessage<Shutdown>()
        assertNotNull(alice1.localShutdown)
    }

    @Test
    fun `recv CMD_CLOSE (with unacked sent htlcs)`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(1000.msat, payer = alice, payee = bob)
        val (alice1, _) = nodes
        val (alice2, actions1) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(alice2 is Normal)
        actions1.hasCommandError<CannotCloseWithUnsignedOutgoingHtlcs>()
    }

    @Test
    fun `recv CMD_CLOSE (with unacked received htlcs)`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(1000.msat, payer = alice, payee = bob)
        val (_, bob1) = nodes
        val (bob2, actions1) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(bob2 is Normal)
        actions1.hasOutgoingMessage<Shutdown>()
        assertNotNull(bob2.localShutdown)
    }

    @Test
    fun `recv CMD_CLOSE (with invalid final script)`() {
        val (alice, _) = reachNormal()
        assertNull(alice.localShutdown)
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(ByteVector("00112233445566778899"))))
        assertTrue(alice1 is Normal)
        actions1.hasCommandError<InvalidFinalScript>()
    }

    @Test
    fun `recv CMD_CLOSE (with signed sent htlcs)`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(1000.msat, payer = alice, payee = bob)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        val (alice2, actions1) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        actions1.hasOutgoingMessage<Shutdown>()
        assertTrue(alice2 is Normal)
        assertNotNull(alice2.localShutdown)
    }

    @Test
    fun `recv CMD_CLOSE (two in a row)`() {
        val (alice, _) = reachNormal()
        assertNull(alice.localShutdown)
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(alice1 is Normal)
        actions1.hasOutgoingMessage<Shutdown>()
        assertNotNull(alice1.localShutdown)
        val (alice2, actions2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(alice2 is Normal)
        actions2.hasCommandError<ClosingAlreadyInProgress>()
    }

    @Test
    fun `recv CMD_CLOSE (while waiting for a RevokeAndAck)`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(1000.msat, payer = alice, payee = bob)
        val (alice1, actions1) = nodes.first.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(alice1 is Normal)
        actions1.hasOutgoingMessage<CommitSig>()
        val (alice2, actions2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(alice2 is Normal)
        actions2.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv CMD_CLOSE (with unsigned fee update)`() {
        val (alice, _) = reachNormal()
        val (alice1, actions1) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_UPDATE_FEE(FeeratePerKw(20_000.sat), false)))
        actions1.hasOutgoingMessage<UpdateFee>()
        val (alice2, actions2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        actions2.hasCommandError<CannotCloseWithUnsignedOutgoingUpdateFee>()
        val (alice3, _) = alice2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val (alice4, actions4) = alice3.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        assertTrue(alice4 is Normal)
        actions4.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv Shutdown (no pending htlcs)`() {
        val (alice, bob) = reachNormal()
        val (alice1, actions1) = alice.processEx(ChannelEvent.MessageReceived(Shutdown(alice.channelId, bob.commitments.localParams.defaultFinalScriptPubKey)))
        assertTrue(alice1 is Negotiating)
        actions1.hasOutgoingMessage<Shutdown>()
        actions1.hasOutgoingMessage<ClosingSigned>()
    }

    @Test
    fun `recv Shutdown (with unacked sent htlcs)`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (bob1, actions1) = nodes.second.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))

        val shutdown = actions1.findOutgoingMessage<Shutdown>()
        val (alice1, actions2) = nodes.first.processEx(ChannelEvent.MessageReceived(shutdown))
        // Alice sends a new sig
        assertEquals(actions2, listOf(ChannelAction.Message.SendToSelf(CMD_SIGN)))
        val (alice2, actions3) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actions3.findOutgoingMessage<CommitSig>()

        // Bob replies with a revocation
        val (_, actions4) = bob1.processEx(ChannelEvent.MessageReceived(commitSig))
        val revack = actions4.findOutgoingMessage<RevokeAndAck>()

        // as soon as alice has received the revocation, she will send her shutdown message
        val (alice3, actions5) = alice2.processEx(ChannelEvent.MessageReceived(revack))
        assertTrue(alice3 is ShuttingDown)
        actions5.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv Shutdown (with unacked received htlcs)`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (bob1, actions1) = nodes.second.processEx(ChannelEvent.MessageReceived(Shutdown(alice.channelId, alice.commitments.localParams.defaultFinalScriptPubKey)))
        assertTrue(bob1 is Closing)
        actions1.hasOutgoingMessage<Error>()
        assertEquals(2, actions1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        actions1.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `recv Shutdown (with unsigned fee update)`() {
        val (alice, bob) = reachNormal()
        val (alice1, aliceActions1) = alice.processEx(ChannelEvent.ExecuteCommand(CMD_UPDATE_FEE(FeeratePerKw(20_000.sat), true)))
        val updateFee = aliceActions1.hasOutgoingMessage<UpdateFee>()
        val (alice2, aliceActions2) = alice1.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val sigAlice = aliceActions2.hasOutgoingMessage<CommitSig>()

        // Bob initiates a close before receiving the signature.
        val (bob1, _) = bob.processEx(ChannelEvent.MessageReceived(updateFee))
        val (bob2, bobActions2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        val shutdownBob = bobActions2.hasOutgoingMessage<Shutdown>()

        val (bob3, bobActions3) = bob2.processEx(ChannelEvent.MessageReceived(sigAlice))
        val revBob = bobActions3.hasOutgoingMessage<RevokeAndAck>()
        bobActions3.hasCommand<CMD_SIGN>()
        val (bob4, bobActions4) = bob3.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val sigBob = bobActions4.hasOutgoingMessage<CommitSig>()

        val (alice3, aliceActions3) = alice2.processEx(ChannelEvent.MessageReceived(shutdownBob))
        val shutdownAlice = aliceActions3.hasOutgoingMessage<Shutdown>()
        val (alice4, _) = alice3.processEx(ChannelEvent.MessageReceived(revBob))
        val (alice5, aliceActions5) = alice4.processEx(ChannelEvent.MessageReceived(sigBob))
        assertTrue(alice5 is Negotiating)
        val revAlice = aliceActions5.hasOutgoingMessage<RevokeAndAck>()
        val closingAlice = aliceActions5.hasOutgoingMessage<ClosingSigned>()

        val (bob5, _) = bob4.processEx(ChannelEvent.MessageReceived(shutdownAlice))
        val (bob6, _) = bob5.processEx(ChannelEvent.MessageReceived(revAlice))
        val (bob7, bobActions7) = bob6.processEx(ChannelEvent.MessageReceived(closingAlice))
        assertTrue(bob7 is Closing)
        val closingBob = bobActions7.hasOutgoingMessage<ClosingSigned>()
        val (alice6, _) = alice5.processEx(ChannelEvent.MessageReceived(closingBob))
        assertTrue(alice6 is Closing)
    }

    @Test
    fun `recv Shutdown (with invalid script)`() {
        val (_, bob) = reachNormal()
        val (bob1, actions1) = bob.processEx(ChannelEvent.MessageReceived(Shutdown(bob.channelId, ByteVector("00112233445566778899"))))
        assertTrue(bob1 is Closing)
        actions1.hasOutgoingMessage<Error>()
        assertEquals(2, actions1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        actions1.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `recv Shutdown (with invalid final script and signed htlcs, in response to a Shutdown)`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        val (bob2, actions1) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        actions1.hasOutgoingMessage<Shutdown>()

        // actual test begins
        val (bob3, actions2) = bob2.processEx(ChannelEvent.MessageReceived(Shutdown(bob.channelId, ByteVector("00112233445566778899"))))
        assertTrue(bob3 is Closing)
        actions2.hasOutgoingMessage<Error>()
        assertEquals(2, actions2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        actions2.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `recv Shutdown (with signed htlcs)`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (_, bob1) = crossSign(nodes.first, nodes.second)

        // actual test begins
        val (bob2, actions1) = bob1.processEx(ChannelEvent.MessageReceived(Shutdown(bob.channelId, alice.commitments.localParams.defaultFinalScriptPubKey)))
        assertTrue(bob2 is ShuttingDown)
        actions1.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv Shutdown (while waiting for a RevokeAndAck)`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (alice1, actions1) = nodes.first.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        actions1.hasOutgoingMessage<CommitSig>()
        val (_, actions2) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        val shutdown = actions2.findOutgoingMessage<Shutdown>()

        // actual test begins
        val (alice2, actions3) = alice1.processEx(ChannelEvent.MessageReceived(shutdown))
        assertTrue(alice2 is ShuttingDown)
        actions3.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv Shutdown (while waiting for a RevokeAndAck with pending outgoing htlc)`() {
        val (alice, bob) = reachNormal()
        // let's make bob send a Shutdown message
        val (bob1, actions1) = bob.processEx(ChannelEvent.ExecuteCommand(CMD_CLOSE(null)))
        val shutdown = actions1.findOutgoingMessage<Shutdown>()

        // this is just so we have something to sign
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob1)
        val (alice1, actions2) = nodes.first.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actions2.findOutgoingMessage<CommitSig>()
        val (bob2, actions3) = nodes.second.processEx(ChannelEvent.MessageReceived(commitSig))
        val revack = actions3.findOutgoingMessage<RevokeAndAck>()

        // adding an outgoing pending htlc
        val (nodes1, _, _) = addHtlc(50000000.msat, payer = alice1, payee = bob2)

        // actual test begins
        // alice eventually gets bob's shutdown
        val (alice3, actions4) = nodes1.first.processEx(ChannelEvent.MessageReceived(shutdown))
        // alice can't do anything for now other than waiting for bob to send the revocation
        assertTrue(actions4.isEmpty())
        // bob sends the revocation
        val (alice4, actions5) = alice3.processEx(ChannelEvent.MessageReceived(revack))
        assertTrue(actions5.contains(ChannelAction.Message.SendToSelf(CMD_SIGN)))
        // bob will also sign back
        val (bob3, actions6) = nodes1.second.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val (alice5, actions7) = alice4.processEx(ChannelEvent.MessageReceived(actions6.findOutgoingMessage<CommitSig>()))

        // then alice can sign the 2nd htlc
        assertTrue(actions7.contains(ChannelAction.Message.SendToSelf(CMD_SIGN)))
        val (alice6, actions8) = alice5.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        assertTrue(alice6 is Normal)
        val (_, actions9) = bob3.processEx(ChannelEvent.MessageReceived(actions8.findOutgoingMessage<CommitSig>()))
        // bob replies with the 2nd revocation
        val (alice7, actions11) = alice6.processEx(ChannelEvent.MessageReceived(actions9.findOutgoingMessage<RevokeAndAck>()))
        // then alice sends her shutdown
        assertTrue(alice7 is ShuttingDown)
        actions11.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (their commit with htlc)`() {
        val (alice0, bob0) = reachNormal()

        val (nodes0, _, _) = addHtlc(250_000_000.msat, payer = alice0, payee = bob0)
        val (alice1, bob1) = nodes0
        val (nodes1, preimage_alice2bob_2, _) = addHtlc(100_000_000.msat, payer = alice1, payee = bob1)
        val (alice2, bob2) = nodes1
        val (nodes2, _, _) = addHtlc(10_000.msat, payer = alice2, payee = bob2)
        val (alice3, bob3) = nodes2
        val (nodes3, preimage_bob2alice_1, _) = addHtlc(50_000_000.msat, payer = bob3, payee = alice3)
        val (bob4, alice4) = nodes3
        val (nodes4, _, _) = addHtlc(55_000_000.msat, payer = bob4, payee = alice4)
        val (bob5, alice5) = nodes4
        val (alice6, bob6) = crossSign(alice5, bob5)
        val (alice7, bob7) = fulfillHtlc(1, preimage_alice2bob_2, payer = alice6, payee = bob6)
        val (bob8, alice8) = fulfillHtlc(0, preimage_bob2alice_1, payer = bob7, payee = alice7)
        assertTrue(alice8 is Normal)
        assertTrue(bob8 is Normal)

        // at this point here is the situation from alice pov and what she should do when bob publishes his commit tx:
        // balances :
        //    alice's balance : 449 999 990                             => nothing to do
        //    bob's balance   :  95 000 000                             => nothing to do
        // htlcs :
        //    alice -> bob    : 250 000 000 (bob does not have the preimage)   => wait for the timeout and spend
        //    alice -> bob    : 100 000 000 (bob has the preimage)             => if bob does not use the preimage, wait for the timeout and spend
        //    alice -> bob    :      10 000 (dust)                             => won't appear in the commitment tx
        //    bob -> alice    :  50 000 000 (alice has the preimage)           => spend immediately using the preimage
        //    bob -> alice    :  55 000 000 (alice does not have the preimage) => nothing to do, bob will get his money back after the timeout

        val bobCommitTx = bob8.commitments.localCommit.publishableTxs.commitTx.tx
        assertEquals(8, bobCommitTx.txOut.size) // 2 main outputs, 4 pending htlcs and 2 anchors

        val (aliceClosing, actions) = alice8.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice8.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertTrue(aliceClosing is Closing)
        assertTrue(actions.isNotEmpty())

        // in response to that, alice publishes its claim txs
        val claimTxs = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }
        assertEquals(4, claimTxs.size)
        // in addition to its main output, alice can only claim 3 out of 4 htlcs,
        // she can't do anything regarding the htlc sent by bob for which she does not have the preimage
        val amountClaimed = claimTxs.map { claimHtlcTx ->
            assertEquals(1, claimHtlcTx.txIn.size)
            assertEquals(1, claimHtlcTx.txOut.size)
            Transaction.correctlySpends(claimHtlcTx, listOf(bobCommitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            claimHtlcTx.txOut[0].amount
        }.sum()
        // at best we have a little less than 450 000 + 250 000 + 100 000 + 50 000 = 850 000 (because fees)
        assertEquals(819_150.sat, amountClaimed)

        val rcp = aliceClosing.remoteCommitPublished!!
        val watchConfirmed = actions.findWatches<WatchConfirmed>()
        assertEquals(2, watchConfirmed.size)
        assertEquals(BITCOIN_TX_CONFIRMED(bobCommitTx), watchConfirmed[0].event)
        assertEquals(BITCOIN_TX_CONFIRMED(rcp.claimMainOutputTx!!.tx), watchConfirmed[1].event)
        assertEquals(4, actions.findWatches<WatchSpent>().count { it.event is BITCOIN_OUTPUT_SPENT })
        assertEquals(4, rcp.claimHtlcTxs.size)
        assertEquals(1, rcp.claimHtlcSuccessTxs().size)
        assertEquals(2, rcp.claimHtlcTimeoutTxs().size)
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (their next commit with htlc)`() {
        val (alice0, bob0) = reachNormal()

        val (nodes0, _, _) = addHtlc(250_000_000.msat, payer = alice0, payee = bob0)
        val (alice1, bob1) = nodes0
        val (nodes1, preimage_alice2bob_2, _) = addHtlc(100_000_000.msat, payer = alice1, payee = bob1)
        val (alice2, bob2) = nodes1
        val (nodes2, _, _) = addHtlc(10_000.msat, payer = alice2, payee = bob2)
        val (alice3, bob3) = nodes2
        val (nodes3, preimage_bob2alice_1, _) = addHtlc(50_000_000.msat, payer = bob3, payee = alice3)
        val (bob4, alice4) = nodes3
        val (nodes4, _, _) = addHtlc(55_000_000.msat, payer = bob4, payee = alice4)
        val (bob5, alice5) = nodes4
        val (alice6, bob6) = crossSign(alice5, bob5)
        val (alice7, bob7) = fulfillHtlc(1, preimage_alice2bob_2, payer = alice6, payee = bob6)
        val (bob8, alice8) = fulfillHtlc(0, preimage_bob2alice_1, payer = bob7, payee = alice7)
        // alice sign but we intercept bob's revocation
        val (alice9, actions8) = alice8.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actions8.findOutgoingMessage<CommitSig>()
        val (bob9, _) = bob8.processEx(ChannelEvent.MessageReceived(commitSig))
        assertTrue(alice9 is Normal)
        assertTrue(bob9 is Normal)

        // as far as alice knows, bob currently has two valid unrevoked commitment transactions

        // at this point here is the situation from bob's pov with the latest sig received from alice,
        // and what alice should do when bob publishes his commit tx:
        // balances :
        //    alice's balance : 499 999 990                             => nothing to do
        //    bob's balance   :  95 000 000                             => nothing to do
        // htlcs :
        //    alice -> bob    : 250 000 000 (bob does not have the preimage)   => wait for the timeout and spend
        //    alice -> bob    : 100 000 000 (bob has the preimage)             => if bob does not use the preimage, wait for the timeout and spend
        //    alice -> bob    :      10 000 (dust)                             => won't appear in the commitment tx
        //    bob -> alice    :  55 000 000 (alice does not have the preimage) => nothing to do, bob will get his money back after the timeout

        // bob publishes his current commit tx
        val bobCommitTx = bob9.commitments.localCommit.publishableTxs.commitTx.tx
        assertEquals(7, bobCommitTx.txOut.size) // 2 main outputs, 3 pending htlcs and 2 anchors

        val (aliceClosing, actions9) = alice9.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice9.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertTrue(aliceClosing is Closing)
        assertTrue(actions9.isNotEmpty())

        // in response to that, alice publishes its claim txs
        val claimTxs = actions9.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }
        assertEquals(3, claimTxs.size)
        // alice can only claim 2 out of 3 htlcs,
        // she can't do anything regarding the htlc sent by bob for which she does not have the preimage
        val amountClaimed = claimTxs.map { claimHtlcTx ->
            assertEquals(1, claimHtlcTx.txIn.size)
            assertEquals(1, claimHtlcTx.txOut.size)
            Transaction.correctlySpends(claimHtlcTx, listOf(bobCommitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            claimHtlcTx.txOut[0].amount
        }.sum()
        // at best we have a little less than 500 000 + 250 000 + 100 000 = 850 000 (because fees)
        assertEquals(825_750.sat, amountClaimed)

        val rcp = aliceClosing.nextRemoteCommitPublished!!
        val watchConfirmed = actions9.findWatches<WatchConfirmed>()
        assertEquals(2, watchConfirmed.size)
        assertEquals(BITCOIN_TX_CONFIRMED(bobCommitTx), watchConfirmed[0].event)
        assertEquals(BITCOIN_TX_CONFIRMED(rcp.claimMainOutputTx!!.tx), watchConfirmed[1].event)
        assertEquals(3, actions9.findWatches<WatchSpent>().count { it.event is BITCOIN_OUTPUT_SPENT })
        assertEquals(3, rcp.claimHtlcTxs.size)
        assertEquals(0, rcp.claimHtlcSuccessTxs().size)
        assertEquals(2, rcp.claimHtlcTimeoutTxs().size)
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT (revoked commit)`() {
        var (alice, bob) = reachNormal()
        // initially we have :
        // alice = 800 000 sat
        //   bob = 200 000 sat
        fun send(cmd: CMD_ADD_HTLC? = null): Pair<Transaction, UpdateAddHtlc> {
            val (alice1, bob1, add) = if (cmd != null) {
                addHtlc(cmd, payer = alice, payee = bob)
            } else {
                // alice sends 10 000 sat
                val (nodes, _, add) = addHtlc(10_000_000.msat, payer = alice, payee = bob)
                Triple(nodes.first, nodes.second, add)
            }
            alice = alice1 as Normal
            bob = bob1 as Normal
            crossSign(alice, bob).run {
                alice = first as Normal
                bob = second as Normal
            }
            return Pair(bob.commitments.localCommit.publishableTxs.commitTx.tx, add)
        }

        val (txs, adds) = run {
            // The first two HTLCs are duplicates (MPP)
            val (tx1, add1) = send()
            val (tx2, add2) = send(CMD_ADD_HTLC(add1.amountMsat, add1.paymentHash, add1.cltvExpiry, add1.onionRoutingPacket, UUID.randomUUID(), commit = false))
            val (otherTxs, otherAdds) = (2 until 10).map { send() }.unzip()
            Pair(listOf(tx1, tx2) + otherTxs, listOf(add1, add2) + otherAdds)
        }

        // bob now has 10 spendable tx, 9 of them being revoked
        // let's say that bob published this tx
        val revokedTx = txs[3]
        // channel state for this revoked tx is as follows:
        // alice = 760 000 sat
        //   bob = 200 000 sat
        //  a->b =  10 000 sat
        //  a->b =  10 000 sat
        //  a->b =  10 000 sat
        //  a->b =  10 000 sat
        assertEquals(8, revokedTx.txOut.size) // 2 anchor outputs + 2 main outputs + 4 htlc

        val (aliceClosing1, actions1) = alice.processEx(ChannelEvent.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, revokedTx)))
        assertTrue(aliceClosing1 is Closing)
        assertEquals(1, aliceClosing1.revokedCommitPublished.size)
        actions1.hasOutgoingMessage<Error>()
        assertEquals(ChannelAction.Storage.GetHtlcInfos(revokedTx.txid, 4), actions1.find<ChannelAction.Storage.GetHtlcInfos>())

        val (aliceClosing2, actions2) = aliceClosing1.processEx(ChannelEvent.GetHtlcInfosResponse(revokedTx.txid, adds.take(4).map { ChannelAction.Storage.HtlcInfo(alice.channelId, 4, it.paymentHash, it.cltvExpiry) }))
        assertTrue(aliceClosing2 is Closing)
        assertEquals(1, aliceClosing2.revokedCommitPublished.size)
        assertNull(actions2.findOutgoingMessageOpt<Error>())
        assertNull(actions2.findOpt<ChannelAction.Storage.GetHtlcInfos>())

        val claimTxs = actions2.findTxs()
        assertEquals(6, claimTxs.size)
        val mainOutputTx = claimTxs[0]
        val mainPenaltyTx = claimTxs[1]
        Transaction.correctlySpends(mainPenaltyTx, revokedTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        assertEquals(setOf(BITCOIN_TX_CONFIRMED(revokedTx), BITCOIN_TX_CONFIRMED(mainOutputTx)), actions2.findWatches<WatchConfirmed>().map { it.event }.toSet())

        val htlcPenaltyTxs = claimTxs.drop(2)
        assertTrue(htlcPenaltyTxs.all { it.txIn.size == 1 })
        htlcPenaltyTxs.forEach { Transaction.correctlySpends(it, revokedTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }
        val htlcInputs = htlcPenaltyTxs.map { it.txIn.first().outPoint }.toSet()
        assertEquals(4, htlcInputs.size) // each htlc-penalty tx spends a different output
        assertEquals(5, actions2.findWatches<WatchSpent>().count { it.event is BITCOIN_OUTPUT_SPENT })
        assertEquals(htlcInputs + mainPenaltyTx.txIn.first().outPoint, actions2.findWatches<WatchSpent>().map { OutPoint(it.txId.reversed(), it.outputIndex.toLong()) }.toSet())

        // two main outputs are 760 000 and 200 000 (minus fees)
        assertEquals(745_860.sat, mainOutputTx.txOut[0].amount)
        assertEquals(195_160.sat, mainPenaltyTx.txOut[0].amount)
        assertEquals(4_510.sat, htlcPenaltyTxs[0].txOut[0].amount)
        assertEquals(4_510.sat, htlcPenaltyTxs[1].txOut[0].amount)
        assertEquals(4_510.sat, htlcPenaltyTxs[2].txOut[0].amount)
        assertEquals(4_510.sat, htlcPenaltyTxs[3].txOut[0].amount)
    }

    @Test
    fun `recv NewBlock (no htlc timed out)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, _) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        assertTrue(alice1 is Normal)

        val (alice2, actions2) = alice1.processEx(ChannelEvent.NewBlock(alice1.currentBlockHeight + 1, alice1.currentTip.second))
        assertEquals(alice1.copy(currentTip = alice2.currentTip), alice2)
        assertTrue(actions2.isEmpty())

        val (alice3, actions3) = alice2.processEx(ChannelEvent.CheckHtlcTimeout)
        assertEquals(alice2, alice3)
        assertTrue(actions3.isEmpty())
    }

    @Test
    fun `recv NewBlock (an htlc timed out)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        assertTrue(alice1 is Normal)

        // alice restarted after the htlc timed out
        val alice2 = alice1.copy(currentTip = alice1.currentTip.copy(first = htlc.cltvExpiry.toLong().toInt()))
        val (alice3, actions) = alice2.processEx(ChannelEvent.CheckHtlcTimeout)
        assertTrue(alice3 is Closing)
        assertNotNull(alice3.localCommitPublished)
        actions.hasOutgoingMessage<Error>()
        actions.has<ChannelAction.Storage.StoreState>()
        val lcp = alice3.localCommitPublished!!
        actions.hasTx(lcp.commitTx)
        assertEquals(1, lcp.htlcTimeoutTxs().size)
        assertEquals(1, lcp.claimHtlcDelayedTxs.size)
        assertEquals(4, actions.findTxs().size) // commit tx + main output + htlc-timeout + claim-htlc-delayed
        assertEquals(3, actions.findWatches<WatchConfirmed>().size) // commit tx + main output + claim-htlc-delayed
        assertEquals(1, actions.findWatches<WatchSpent>().size) // htlc-timeout
    }

    private fun checkFulfillTimeout(bob: ChannelState, actions: List<ChannelAction>) {
        assertTrue(bob is Closing)
        assertNotNull(bob.localCommitPublished)
        actions.hasOutgoingMessage<Error>()
        actions.has<ChannelAction.Storage.StoreState>()

        val lcp = bob.localCommitPublished!!
        assertNotNull(lcp.claimMainDelayedOutputTx)
        assertEquals(1, lcp.htlcSuccessTxs().size)
        Transaction.correctlySpends(lcp.htlcSuccessTxs().first().tx, lcp.commitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        assertEquals(1, lcp.claimHtlcDelayedTxs.size)
        Transaction.correctlySpends(lcp.claimHtlcDelayedTxs.first().tx, lcp.htlcSuccessTxs().first().tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        val txs = setOf(lcp.commitTx, lcp.claimMainDelayedOutputTx!!.tx, lcp.htlcSuccessTxs().first().tx, lcp.claimHtlcDelayedTxs.first().tx)
        assertEquals(txs, actions.findTxs().toSet())
        val watchConfirmed = listOf(lcp.commitTx, lcp.claimMainDelayedOutputTx!!.tx, lcp.claimHtlcDelayedTxs.first().tx).map { it.txid }.toSet()
        assertEquals(watchConfirmed, actions.findWatches<WatchConfirmed>().map { it.txId }.toSet())
        val watchSpent = setOf(lcp.htlcSuccessTxs().first().input.outPoint)
        assertEquals(watchSpent, actions.findWatches<WatchSpent>().map { OutPoint(lcp.commitTx, it.outputIndex.toLong()) }.toSet())
    }

    @Test
    fun `recv NewBlock (fulfilled signed htlc ignored by peer)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, preimage, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)

        val (bob2, actions2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(htlc.id, preimage)))
        actions2.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob3, actions3) = bob2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        actions3.hasOutgoingMessage<CommitSig>()

        // fulfilled htlc is close to timing out and alice still hasn't signed, so bob closes the channel
        val (bob4, actions4) = run {
            val (tmp, _) = bob3.processEx(ChannelEvent.NewBlock(htlc.cltvExpiry.toLong().toInt() - 3, bob3.currentTip.second))
            tmp.processEx(ChannelEvent.CheckHtlcTimeout)
        }
        checkFulfillTimeout(bob4, actions4)
    }

    @Test
    fun `recv NewBlock (fulfilled proposed htlc ignored by peer)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, preimage, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)

        val (bob2, actions2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(htlc.id, preimage)))
        actions2.hasOutgoingMessage<UpdateFulfillHtlc>()

        // bob restarts when the fulfilled htlc is close to timing out
        val bob3 = (bob2 as Normal).copy(currentTip = bob2.currentTip.copy(first = htlc.cltvExpiry.toLong().toInt() - 3))
        // alice still hasn't signed, so bob closes the channel
        val (bob4, actions4) = bob3.processEx(ChannelEvent.CheckHtlcTimeout)
        checkFulfillTimeout(bob4, actions4)
    }

    @Test
    fun `recv NewBlock (fulfilled proposed htlc acked but not committed by peer)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, preimage, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = crossSign(nodes.first, nodes.second)

        val (bob2, actionsBob2) = bob1.processEx(ChannelEvent.ExecuteCommand(CMD_FULFILL_HTLC(htlc.id, preimage)))
        val fulfill = actionsBob2.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob3, actionsBob3) = bob2.processEx(ChannelEvent.ExecuteCommand(CMD_SIGN))
        val commitSig = actionsBob3.hasOutgoingMessage<CommitSig>()
        val (alice2, _) = alice1.processEx(ChannelEvent.MessageReceived(fulfill))
        val (_, actionsAlice3) = alice2.processEx(ChannelEvent.MessageReceived(commitSig))
        val ack = actionsAlice3.hasOutgoingMessage<RevokeAndAck>()
        val (bob4, _) = bob3.processEx(ChannelEvent.MessageReceived(ack))

        // fulfilled htlc is close to timing out and alice has revoked her previous commitment but not signed the new one, so bob closes the channel
        val (bob5, actions5) = run {
            val (tmp, _) = bob4.processEx(ChannelEvent.NewBlock(htlc.cltvExpiry.toLong().toInt() - 3, bob3.currentTip.second))
            tmp.processEx(ChannelEvent.CheckHtlcTimeout)
        }
        checkFulfillTimeout(bob5, actions5)
    }

    @Test
    fun `recv Disconnected`() {
        val (alice0, _) = reachNormal()
        val (alice1, _) = alice0.processEx(ChannelEvent.Disconnected)
        assertTrue(alice1 is Offline)
        val previousState = alice1.state
        assertTrue(previousState is Normal)
        assertEquals(alice0.channelUpdate, previousState.channelUpdate)
    }

    @Test
    fun `recv Disconnected (with htlcs)`() {
        val (alice0, bob0) = reachNormal()
        val (nodes0, _, htlc1) = addHtlc(250_000_000.msat, payer = alice0, payee = bob0)
        val (alice1, bob1) = nodes0
        val (nodes1, _, htlc2) = addHtlc(250_000_000.msat, payer = alice1, payee = bob1)
        val (alice2, _) = nodes1

        val (alice3, actions) = alice2.processEx(ChannelEvent.Disconnected)
        assertTrue(alice3 is Offline)

        val addSettledFailList = actions.filterIsInstance<ChannelAction.ProcessCmdRes.AddSettledFail>()
        assertEquals(2, addSettledFailList.size)
        assertTrue(addSettledFailList.all { it.result is ChannelAction.HtlcResult.Fail.Disconnected })
        assertEquals(htlc1.paymentHash, addSettledFailList.first().htlc.paymentHash)
        assertEquals(htlc2.paymentHash, addSettledFailList.last().htlc.paymentHash)
        assertEquals(alice2, alice3.state)
    }

    @Test
    fun `receive Error`() {
        val (alice0, bob0) = reachNormal()
        val (nodes0, _, _) = addHtlc(250_000_000.msat, payer = alice0, payee = bob0)
        val (nodes1, ra2, _) = addHtlc(100_000_000.msat, payer = nodes0.first, payee = nodes0.second)
        val (nodes2, _, _) = addHtlc(10_000.msat, payer = nodes1.first, payee = nodes1.second)
        val (nodes3, rb1, _) = addHtlc(50_000_000.msat, payer = nodes2.second, payee = nodes2.first)
        val (nodes4, _, _) = addHtlc(55_000_000.msat, payer = nodes3.first, payee = nodes3.second)
        val (bob1, alice1) = crossSign(nodes4.first, nodes4.second)
        val (alice2, bob2) = fulfillHtlc(1, ra2, alice1, bob1)
        val (_, alice3) = fulfillHtlc(0, rb1, bob2, alice2)

        // at this point here is the situation from alice pov and what she should do when she publishes his commit tx:
        // balances :
        //    alice's balance : 449 999 990                             => nothing to do
        //    bob's balance   :  95 000 000                             => nothing to do
        // htlcs :
        //    alice -> bob    : 250 000 000 (bob does not have the preimage)   => wait for the timeout and spend using 2nd stage htlc-timeout
        //    alice -> bob    : 100 000 000 (bob has the preimage)             => if bob does not use the preimage, wait for the timeout and spend using 2nd stage htlc-timeout
        //    alice -> bob    :          10 000 (dust)                             => won't appear in the commitment tx
        //    bob -> alice    :  50 000 000 (alice has the preimage)           => spend immediately using the preimage using htlc-success
        //    bob -> alice    :  55 000 000 (alice does not have the preimage) => nothing to do, bob will get his money back after the timeout

        // an error occurs and alice publishes her commit tx
        assertTrue(alice3 is Normal)
        val aliceCommitTx = alice3.commitments.localCommit.publishableTxs.commitTx
        val (alice4, actions) = alice3.processEx(ChannelEvent.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertTrue(alice4 is Closing)
        assertNotNull(alice4.localCommitPublished)
        assertEquals(alice4.localCommitPublished!!.commitTx, aliceCommitTx.tx)
        assertEquals(4, alice4.localCommitPublished!!.htlcTxs.size)
        assertEquals(1, alice4.localCommitPublished!!.htlcSuccessTxs().size)
        assertEquals(2, alice4.localCommitPublished!!.htlcTimeoutTxs().size)
        assertEquals(3, alice4.localCommitPublished!!.claimHtlcDelayedTxs.size)

        val txs = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }
        assertEquals(8, txs.size)
        // alice can only claim 3 out of 4 htlcs, she can't do anything regarding the htlc sent by bob for which she does not have the preimage
        // so we expect 8 transactions:
        // - alice's current commit tx
        // - 1 tx to claim the main delayed output
        // - 3 txs for each htlc
        // - 3 txs for each delayed output of the claimed htlc

        assertEquals(aliceCommitTx.tx, txs[0])
        assertEquals(aliceCommitTx.tx.txOut.size, 8) // 2 anchor outputs + 2 main output + 4 pending htlcs
        // the main delayed output spends the commitment transaction
        Transaction.correctlySpends(txs[1], aliceCommitTx.tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // 2nd stage transactions spend the commitment transaction
        Transaction.correctlySpends(txs[2], aliceCommitTx.tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        Transaction.correctlySpends(txs[3], aliceCommitTx.tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        Transaction.correctlySpends(txs[4], aliceCommitTx.tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // 3rd stage transactions spend their respective HTLC-Success/HTLC-Timeout transactions
        Transaction.correctlySpends(txs[5], txs[2], ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        Transaction.correctlySpends(txs[6], txs[3], ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        Transaction.correctlySpends(txs[7], txs[4], ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        assertEquals(
            actions.findWatches<WatchConfirmed>().map { it.txId },
            listOf(
                txs[0].txid, // commit tx
                txs[1].txid, // main delayed
                txs[5].txid, // htlc-delayed
                txs[6].txid, // htlc-delayed
                txs[7].txid  // htlc-delayed
            )
        )
        assertEquals(4, actions.findWatches<WatchSpent>().size)
    }

    @Test
    fun `receive Error (nothing at stake)`() {
        val (_, bob0) = reachNormal(pushMsat = 0.msat)
        val bobCommitTx = bob0.commitments.localCommit.publishableTxs.commitTx.tx
        val (bob1, actions) = bob0.processEx(ChannelEvent.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        val txs = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }
        assertEquals(txs, listOf(bobCommitTx))
        assertTrue(bob1 is Closing)
        assertEquals(bob1.localCommitPublished!!.commitTx, bobCommitTx)
    }
}
