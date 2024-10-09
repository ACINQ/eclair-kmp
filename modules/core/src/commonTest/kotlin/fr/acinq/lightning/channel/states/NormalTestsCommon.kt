package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.ChannelAction.Blockchain.PublishTx.Type
import fr.acinq.lightning.channel.TestsHelper.addHtlc
import fr.acinq.lightning.channel.TestsHelper.claimHtlcSuccessTxs
import fr.acinq.lightning.channel.TestsHelper.claimHtlcTimeoutTxs
import fr.acinq.lightning.channel.TestsHelper.crossSign
import fr.acinq.lightning.channel.TestsHelper.fulfillHtlc
import fr.acinq.lightning.channel.TestsHelper.htlcSuccessTxs
import fr.acinq.lightning.channel.TestsHelper.htlcTimeoutTxs
import fr.acinq.lightning.channel.TestsHelper.makeCmdAdd
import fr.acinq.lightning.channel.TestsHelper.reachNormal
import fr.acinq.lightning.channel.TestsHelper.signAndRevack
import fr.acinq.lightning.crypto.sphinx.Sphinx
import fr.acinq.lightning.router.Announcements
import fr.acinq.lightning.serialization.Encryption.from
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.transactions.Transactions.commitTxFeeMsat
import fr.acinq.lightning.transactions.Transactions.weight2fee
import fr.acinq.lightning.transactions.incomings
import fr.acinq.lightning.transactions.outgoings
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import kotlin.test.*

class NormalTestsCommon : LightningTestSuite() {

    private val defaultAdd = ChannelCommand.Htlc.Add(
        50_000_000.msat,
        randomBytes32(),
        CltvExpiryDelta(144).toCltvExpiry(TestConstants.defaultBlockHeight.toLong()),
        TestConstants.emptyOnionPacket,
        UUID.randomUUID()
    )

    @Test
    fun `recv ChannelCommand_Htlc_Add`() {
        val (alice0, _) = reachNormal()
        val add = defaultAdd.copy(paymentHash = randomBytes32())

        val (alice1, actions) = alice0.process(add)
        assertIs<LNChannel<Normal>>(alice1)
        assertTrue(alice1.commitments.availableBalanceForSend() < alice0.commitments.availableBalanceForSend())

        val htlc = actions.findOutgoingMessage<UpdateAddHtlc>()
        assertEquals(0, htlc.id)
        assertEquals(add.paymentHash, htlc.paymentHash)
        val expected = alice0.copy(
            state = alice0.state.copy(
                commitments = alice0.commitments.copy(
                    changes = alice0.commitments.changes.copy(
                        localNextHtlcId = 1,
                        localChanges = alice0.commitments.changes.localChanges.copy(proposed = listOf(htlc)),
                    ),
                    payments = mapOf(0L to add.paymentId)
                )
            )
        )
        assertEquals(expected, alice1)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- zero-reserve`() {
        val (_, bob0) = reachNormal(ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, bobFundingAmount = 10_000.sat)
        assertEquals(bob0.commitments.availableBalanceForSend(), 10_000_000.msat)
        val add = defaultAdd.copy(amount = 10_000_000.msat, paymentHash = randomBytes32())

        val (bob1, actions) = bob0.process(add)
        assertIs<LNChannel<Normal>>(bob1)
        assertEquals(bob1.commitments.availableBalanceForSend(), 0.msat)

        val htlc = actions.findOutgoingMessage<UpdateAddHtlc>()
        assertEquals(htlc.amountMsat, 10_000_000.msat)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- zero-conf -- zero-reserve`() {
        val (_, bob0) = reachNormal(ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, bobFundingAmount = 10_000.sat, zeroConf = true)
        assertEquals(bob0.commitments.availableBalanceForSend(), 10_000_000.msat)
        val add = defaultAdd.copy(amount = 10_000_000.msat, paymentHash = randomBytes32())

        val (bob1, actions) = bob0.process(add)
        assertIs<LNChannel<Normal>>(bob1)
        assertEquals(bob1.commitments.availableBalanceForSend(), 0.msat)

        val htlc = actions.findOutgoingMessage<UpdateAddHtlc>()
        assertEquals(htlc.amountMsat, 10_000_000.msat)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- incrementing ids`() {
        val (alice0, _) = reachNormal()
        var alice = alice0
        for (i in 0 until 10) {
            val add = defaultAdd.copy(paymentHash = randomBytes32())
            val (tempAlice, actions) = alice.process(add)
            assertIs<LNChannel<Normal>>(tempAlice)
            alice = tempAlice

            val htlc = actions.findOutgoingMessage<UpdateAddHtlc>()
            assertEquals(i.toLong(), htlc.id)
            assertEquals(add.paymentHash, htlc.paymentHash)
        }
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- expiry too small`() {
        val (alice0, _) = reachNormal()
        // It's usually dangerous for Bob to accept HTLCs that are expiring soon. However it's not Alice's decision to reject
        // them when she's asked to relay; she should forward those HTLCs to Bob, and Bob will choose whether to fail them
        // or fulfill them (Bob could be #reckless and fulfill HTLCs with a very low expiry delta).
        val currentBlockHeight = alice0.currentBlockHeight.toLong()
        val expiryTooSmall = CltvExpiry(currentBlockHeight + 3)
        val add = defaultAdd.copy(cltvExpiry = expiryTooSmall)
        val (_, actions1) = alice0.process(add)
        actions1.hasOutgoingMessage<UpdateAddHtlc>()
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- expiry too big`() {
        val (alice0, _) = reachNormal()
        val currentBlockHeight = alice0.currentBlockHeight.toLong()
        val expiryTooBig = (Channel.MAX_CLTV_EXPIRY_DELTA + 1).toCltvExpiry(currentBlockHeight)
        val add = defaultAdd.copy(cltvExpiry = expiryTooBig)
        val (alice1, actions1) = alice0.process(add)
        val actualError = actions1.findCommandError<ExpiryTooBig>()
        val expectedError = ExpiryTooBig(alice0.channelId, Channel.MAX_CLTV_EXPIRY_DELTA.toCltvExpiry(currentBlockHeight), expiryTooBig, currentBlockHeight)
        assertEquals(expectedError, actualError)
        assertEquals(alice0, alice1)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- value too small`() {
        val (alice0, _) = reachNormal()
        val add = defaultAdd.copy(amount = 50.msat)
        val (alice1, actions) = alice0.process(add)
        val actualError = actions.findCommandError<HtlcValueTooSmall>()
        val expectedError = HtlcValueTooSmall(alice0.channelId, 1000.msat, 50.msat)
        assertEquals(expectedError, actualError)
        assertEquals(alice0, alice1)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- 0 msat`() {
        val (alice0, bob0) = reachNormal()
        val add = defaultAdd.copy(amount = 0.msat)
        val (bob1, actions) = bob0.process(add)
        val actualError = actions.findCommandError<HtlcValueTooSmall>()
        val expectedError = HtlcValueTooSmall(bob0.channelId, alice0.commitments.params.localParams.htlcMinimum, 0.msat)
        assertEquals(expectedError, actualError)
        assertEquals(bob0, bob1)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- increasing balance but still below reserve`() {
        val (alice0, bob0) = reachNormal(bobFundingAmount = 0.sat)
        assertFalse(alice0.commitments.params.channelFeatures.hasFeature(Feature.ZeroReserveChannels))
        assertFalse(bob0.commitments.params.channelFeatures.hasFeature(Feature.ZeroReserveChannels))
        assertEquals(0.msat, bob0.commitments.availableBalanceForSend())

        val cmdAdd = defaultAdd.copy(amount = 1_500.msat)
        val (alice1, actionsAlice) = alice0.process(cmdAdd)
        assertIs<LNChannel<Normal>>(alice1)
        val add = actionsAlice.hasOutgoingMessage<UpdateAddHtlc>()

        val (bob1, actionsBob) = bob0.process(ChannelCommand.MessageReceived(add))
        assertIs<LNChannel<Normal>>(bob1)
        assertTrue(actionsBob.isEmpty())
        assertEquals(0.msat, bob1.commitments.availableBalanceForSend())
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- insufficient funds`() {
        val (alice0, _) = reachNormal()
        val add = defaultAdd.copy(amount = Int.MAX_VALUE.msat)
        val (alice1, actions) = alice0.process(add)
        val actualError = actions.findCommandError<InsufficientFunds>()
        val expectError = InsufficientFunds(alice0.channelId, amount = Int.MAX_VALUE.msat, missing = 1_322_823.sat, reserve = 10_000.sat, fees = 7_140.sat)
        assertEquals(expectError, actualError)
        assertEquals(alice0, alice1)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- insufficient funds + missing 1 msat`() {
        val (_, bob0) = reachNormal()
        val add = defaultAdd.copy(amount = bob0.commitments.availableBalanceForSend() + 1.sat.toMilliSatoshi())
        val (bob1, actions) = bob0.process(add)
        val actualError = actions.findCommandError<InsufficientFunds>()
        val expectedError = InsufficientFunds(bob0.channelId, amount = add.amount, missing = 1.sat, reserve = 10000.sat, fees = 0.sat)
        assertEquals(expectedError, actualError)
        assertEquals(bob0, bob1)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- commit tx fee greater than remote initiator balance`() {
        val (alice0, bob0) = reachNormal(bobFundingAmount = 200_000.sat)
        val (alice1, bob1) = addHtlc(824_160_000.msat, alice0, bob0).first
        val (alice2, bob2) = crossSign(alice1, bob1)
        assertEquals(0.msat, alice2.state.commitments.availableBalanceForSend())

        tailrec fun addHtlcs(alice: LNChannel<Normal>, bob: LNChannel<Normal>, count: Int): Pair<LNChannel<Normal>, LNChannel<Normal>> {
            if (count == 0) return Pair(alice, bob)
            val (newBob, actionsBob) = bob.process(defaultAdd.copy(amount = 8_000_000.msat))
            assertIs<LNChannel<Normal>>(newBob)
            val add = actionsBob.findOutgoingMessage<UpdateAddHtlc>()
            val (newAlice, actionsAlice) = alice.process(ChannelCommand.MessageReceived(add))
            assertIs<LNChannel<Normal>>(newAlice)
            assertTrue(actionsAlice.isEmpty())
            return addHtlcs(newAlice, newBob, count - 1)
        }

        // Add a bunch of HTLCs, which increases the commit tx fee that Alice has to pay and consume almost all of her balance.
        val (alice3, bob3) = addHtlcs(alice2, bob2, 21)
        run {
            // We can sign those HTLCs and make Alice drop below her reserve.
            val (_, alice4) = crossSign(bob3, alice3)
            val aliceCommit = alice4.commitments.active.first().localCommit
            assertTrue(aliceCommit.publishableTxs.commitTx.tx.txOut.all { txOut -> txOut.amount > 0.sat })
            val aliceBalance = aliceCommit.spec.toLocal - commitTxFeeMsat(alice4.commitments.params.localParams.dustLimit, aliceCommit.spec)
            assertTrue(aliceBalance >= 0.msat)
            assertTrue(aliceBalance < alice4.commitments.latest.localChannelReserve)
        }
        run {
            // If we try adding one more HTLC, Alice won't be able to pay the commit tx fee.
            // We must wait for the previous HTLCs to settle before sending any more.
            val (_, actionsBob4) = bob3.process(defaultAdd.copy(amount = 8_000_000.msat))
            actionsBob4.findCommandError<RemoteCannotAffordFeesForNewHtlc>()
        }
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- insufficient funds with pending htlcs`() {
        val (alice0, _) = reachNormal()
        val (alice1, actionsAlice1) = alice0.process(defaultAdd.copy(amount = 300_000_000.msat))
        actionsAlice1.hasOutgoingMessage<UpdateAddHtlc>()
        val (alice2, actionsAlice2) = alice1.process(defaultAdd.copy(amount = 300_000_000.msat))
        actionsAlice2.hasOutgoingMessage<UpdateAddHtlc>()
        val (_, actionsAlice3) = alice2.process(defaultAdd.copy(amount = 500_000_000.msat))
        val actualError = actionsAlice3.findCommandError<InsufficientFunds>()
        val expectError = InsufficientFunds(alice0.channelId, amount = 500_000_000.msat, missing = 278_780.sat, reserve = 10_000.sat, fees = 8_860.sat)
        assertEquals(expectError, actualError)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- insufficient funds with pending htlcs and 0 balance`() {
        val (alice0, _) = reachNormal()
        val (alice1, actionsAlice1) = alice0.process(defaultAdd.copy(amount = 500_000_000.msat))
        actionsAlice1.hasOutgoingMessage<UpdateAddHtlc>()
        val (alice2, actionsAlice2) = alice1.process(defaultAdd.copy(amount = 200_000_000.msat))
        actionsAlice2.hasOutgoingMessage<UpdateAddHtlc>()
        val (alice3, actionsAlice3) = alice2.process(defaultAdd.copy(amount = 121_120_000.msat))
        actionsAlice3.hasOutgoingMessage<UpdateAddHtlc>()
        val (_, actionsAlice4) = alice3.process(defaultAdd.copy(amount = 1_000_000.msat))
        val actualError = actionsAlice4.findCommandError<InsufficientFunds>()
        val expectedError = InsufficientFunds(alice0.channelId, amount = 1_000_000.msat, missing = 900.sat, reserve = 10_000.sat, fees = 8_860.sat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- over their max in-flight htlc value`() {
        val bob0 = run {
            val (_, bob) = reachNormal()
            bob.copy(state = bob.state.copy(commitments = bob.commitments.copy(params = bob.commitments.params.copy(remoteParams = bob.commitments.params.remoteParams.copy(maxHtlcValueInFlightMsat = 100_000_000)))))
        }
        val (_, actions) = bob0.process(defaultAdd.copy(amount = 101_000_000.msat))
        val actualError = actions.findCommandError<HtlcValueTooHighInFlight>()
        val expectedError = HtlcValueTooHighInFlight(bob0.channelId, maximum = 100_000_000UL, actual = 101_000_000.msat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- over our max in-flight htlc value`() {
        val bob0 = run {
            val (_, bob) = reachNormal()
            bob.copy(state = bob.state.copy(commitments = bob.commitments.copy(params = bob.commitments.params.copy(localParams = bob.commitments.params.localParams.copy(maxHtlcValueInFlightMsat = 100_000_000)))))
        }
        val (_, actions) = bob0.process(defaultAdd.copy(amount = 101_000_000.msat))
        val actualError = actions.findCommandError<HtlcValueTooHighInFlight>()
        val expectedError = HtlcValueTooHighInFlight(bob0.channelId, maximum = 100_000_000UL, actual = 101_000_000.msat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- over max in-flight htlc value with duplicate amounts`() {
        val bob0 = run {
            val (_, bob) = reachNormal()
            bob.copy(state = bob.state.copy(commitments = bob.commitments.copy(params = bob.commitments.params.copy(remoteParams = bob.commitments.params.remoteParams.copy(maxHtlcValueInFlightMsat = 100_000_000)))))
        }
        val (bob1, actionsBob1) = bob0.process(defaultAdd.copy(amount = 50_500_000.msat))
        actionsBob1.hasOutgoingMessage<UpdateAddHtlc>()
        val (_, actionsBob2) = bob1.process(defaultAdd.copy(amount = 50_500_000.msat))
        val actualError = actionsBob2.findCommandError<HtlcValueTooHighInFlight>()
        val expectedError = HtlcValueTooHighInFlight(bob0.channelId, maximum = 100_000_000UL, actual = 101_000_000.msat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- over max accepted htlcs`() {
        val (alice0, bob0) = reachNormal()

        // Bob accepts a maximum of 100 htlcs
        val alice1 = run {
            var alice = alice0
            for (i in 0 until bob0.staticParams.nodeParams.maxAcceptedHtlcs) {
                val (tempAlice, actions) = alice.process(defaultAdd.copy(amount = 1_000_000.msat))
                actions.hasOutgoingMessage<UpdateAddHtlc>()
                assertIs<LNChannel<Normal>>(tempAlice)
                alice = tempAlice
            }
            alice
        }

        val (_, actions) = alice1.process(defaultAdd.copy(amount = 1_000_000.msat))
        val actualError = actions.findCommandError<TooManyAcceptedHtlcs>()
        val expectedError = TooManyAcceptedHtlcs(alice0.channelId, maximum = 100)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- over max offered htlcs`() {
        val (alice0, _) = reachNormal()
        // Bob accepts a maximum of 100 htlcs, but for Alice that value is only 5
        val alice1 = alice0.copy(state = alice0.state.copy(commitments = alice0.commitments.copy(params = alice0.commitments.params.copy(localParams = alice0.commitments.params.localParams.copy(maxAcceptedHtlcs = 5)))))

        val alice2 = run {
            var alice = alice1
            for (i in 0 until 5) {
                val (tempAlice, actions) = alice.process(defaultAdd.copy(amount = 1_000_000.msat))
                actions.hasOutgoingMessage<UpdateAddHtlc>()
                assertIs<LNChannel<Normal>>(tempAlice)
                alice = tempAlice
            }
            alice
        }

        val (_, actions) = alice2.process(defaultAdd.copy(amount = 1_000_000.msat))
        val actualError = actions.findCommandError<TooManyOfferedHtlcs>()
        val expectedError = TooManyOfferedHtlcs(alice0.channelId, maximum = 5)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- over capacity`() {
        val (alice0, _) = reachNormal()
        val (alice1, actionsAlice1) = alice0.process(defaultAdd.copy(amount = alice0.commitments.latest.fundingAmount.toMilliSatoshi() * 2 / 3))
        actionsAlice1.hasOutgoingMessage<UpdateAddHtlc>()
        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        actionsAlice2.hasOutgoingMessage<CommitSig>()
        // this is over channel-capacity
        val failAdd = defaultAdd.copy(amount = alice0.commitments.latest.fundingAmount.toMilliSatoshi() * 2 / 3)
        val (_, actionsAlice3) = alice2.process(failAdd)
        val actualError = actionsAlice3.findCommandError<InsufficientFunds>()
        val expectedError = InsufficientFunds(alice0.channelId, failAdd.amount, 510_393.sat, 10_000.sat, 8_000.sat)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- after having sent Shutdown`() {
        val (alice0, _) = reachNormal()
        val (alice1, actionsAlice1) = alice0.process(ChannelCommand.Close.MutualClose(null, null))
        actionsAlice1.findOutgoingMessage<Shutdown>()
        assertIs<LNChannel<Normal>>(alice1)
        assertTrue(alice1.state.localShutdown != null && alice1.state.remoteShutdown == null)

        val (_, cmdAdd) = makeCmdAdd(500_000_000.msat, alice0.staticParams.nodeParams.nodeId, TestConstants.defaultBlockHeight.toLong(), randomBytes32())
        val (_, actionsAlice2) = alice1.process(cmdAdd)
        assertNotNull(actionsAlice2.findCommandError<NoMoreHtlcsClosingInProgress>())
    }

    @Test
    fun `recv ChannelCommand_Htlc_Add -- after having received Shutdown`() {
        val (alice0, bob0) = reachNormal()

        // let's make alice send an htlc
        val (_, cmdAdd1) = makeCmdAdd(500_000_000.msat, alice0.staticParams.nodeParams.nodeId, TestConstants.defaultBlockHeight.toLong(), randomBytes32())
        val (alice1, actionsAlice1) = alice0.process(cmdAdd1)
        actionsAlice1.findOutgoingMessage<UpdateAddHtlc>()

        // at the same time bob initiates a closing
        val (_, actionsBob1) = bob0.process(ChannelCommand.Close.MutualClose(null, null))
        val shutdown = actionsBob1.findOutgoingMessage<Shutdown>()

        val (alice2, _) = alice1.process(ChannelCommand.MessageReceived(shutdown))
        val (_, cmdAdd2) = makeCmdAdd(100_000_000.msat, alice0.staticParams.nodeParams.nodeId, TestConstants.defaultBlockHeight.toLong(), randomBytes32())
        val (_, actionsAlice3) = alice2.process(cmdAdd2)
        assertNotNull(actionsAlice3.findCommandError<NoMoreHtlcsClosingInProgress>())
    }

    @Test
    fun `recv UpdateAddHtlc`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 15_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.process(ChannelCommand.MessageReceived(add))
        assertTrue(actions1.isEmpty())
        assertEquals(
            bob0.copy(state = bob0.state.copy(commitments = bob0.commitments.copy(changes = bob0.commitments.changes.copy(remoteNextHtlcId = 1, remoteChanges = bob0.commitments.changes.remoteChanges.copy(proposed = listOf(add)))))),
            bob1
        )
    }

    @Test
    fun `recv UpdateAddHtlc -- zero-reserve`() {
        val (alice0, _) = reachNormal(ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, bobFundingAmount = 10_000.sat)
        assertEquals(alice0.commitments.availableBalanceForReceive(), 10_000_000.msat)
        val add = UpdateAddHtlc(alice0.channelId, 0, 10_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(alice0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (alice1, actions1) = alice0.process(ChannelCommand.MessageReceived(add))
        assertIs<LNChannel<Normal>>(alice1)
        assertTrue(actions1.isEmpty())
        assertEquals(alice1.commitments.changes.remoteChanges.proposed, listOf(add))
    }

    @Test
    fun `recv UpdateAddHtlc -- zero-conf -- zero-reserve`() {
        val (alice0, _) = reachNormal(ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, bobFundingAmount = 10_000.sat, zeroConf = true)
        assertEquals(alice0.commitments.availableBalanceForReceive(), 10_000_000.msat)
        val add = UpdateAddHtlc(alice0.channelId, 0, 10_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(alice0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (alice1, actions1) = alice0.process(ChannelCommand.MessageReceived(add))
        assertIs<LNChannel<Normal>>(alice1)
        assertTrue(actions1.isEmpty())
        assertEquals(alice1.commitments.changes.remoteChanges.proposed, listOf(add))
    }

    @Test
    fun `recv UpdateAddHtlc -- unexpected id`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 15_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.process(ChannelCommand.MessageReceived(add))
        assertTrue(actions1.isEmpty())
        val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(add.copy(id = 1)))
        assertTrue(actions2.isEmpty())
        val (bob3, actions3) = bob2.process(ChannelCommand.MessageReceived(add.copy(id = 2)))
        assertTrue(actions3.isEmpty())
        val (bob4, actions4) = bob3.process(ChannelCommand.MessageReceived(add.copy(id = 4)))
        assertIs<LNChannel<Closing>>(bob4)
        val error = actions4.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnexpectedHtlcId(bob0.channelId, 3, 4).message)
    }

    @Test
    fun `recv UpdateAddHtlc -- value too small`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 150.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.process(ChannelCommand.MessageReceived(add))
        assertIs<LNChannel<Closing>>(bob1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), HtlcValueTooSmall(bob0.channelId, 1_000.msat, add.amountMsat).message)
    }

    @Test
    fun `recv UpdateAddHtlc -- insufficient funds`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 850_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.process(ChannelCommand.MessageReceived(add))
        assertIs<LNChannel<Closing>>(bob1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InsufficientFunds(bob0.channelId, 800_000_000.msat, 17_140.sat, 10_000.sat, 7_140.sat).message)
    }

    @Test
    fun `recv UpdateAddHtlc -- insufficient funds with pending htlcs`() {
        val (_, bob0) = reachNormal()
        val add = UpdateAddHtlc(bob0.channelId, 0, 15_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob1, actions1) = bob0.process(ChannelCommand.MessageReceived(add))
        assertTrue(actions1.isEmpty())
        val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(add.copy(id = 1)))
        assertTrue(actions2.isEmpty())
        val (bob3, actions3) = bob2.process(ChannelCommand.MessageReceived(add.copy(id = 2)))
        assertTrue(actions3.isEmpty())
        val (bob4, actions4) = bob3.process(ChannelCommand.MessageReceived(add.copy(id = 3, amountMsat = 800_000_000.msat)))
        assertIs<LNChannel<Closing>>(bob4)
        val error = actions4.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InsufficientFunds(bob0.channelId, 800_000_000.msat, 14_720.sat, 10_000.sat, 9_720.sat).message)
    }

    @Test
    fun `recv UpdateAddHtlc -- over max in-flight htlc value`() {
        val alice0 = run {
            val (alice, _) = reachNormal()
            alice.copy(state = alice.state.copy(commitments = alice.commitments.copy(params = alice.commitments.params.copy(localParams = alice.commitments.params.localParams.copy(maxHtlcValueInFlightMsat = 100_000_000)))))
        }
        val add = UpdateAddHtlc(alice0.channelId, 0, 101_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(alice0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (alice1, actions1) = alice0.process(ChannelCommand.MessageReceived(add))
        assertIs<LNChannel<Closing>>(alice1)
        val error = actions1.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), HtlcValueTooHighInFlight(alice0.channelId, 100_000_000UL, 101_000_000.msat).message)
    }

    @Test
    fun `recv UpdateAddHtlc -- over max accepted htlcs`() {
        val (_, bob0) = reachNormal()

        // Bob accepts a maximum of 100 htlcs
        val bob1 = run {
            var bob = bob0
            for (i in 0 until bob0.staticParams.nodeParams.maxAcceptedHtlcs) {
                val add = UpdateAddHtlc(bob0.channelId, i.toLong(), 2_500_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
                val (tempBob, actions) = bob.process(ChannelCommand.MessageReceived(add))
                assertTrue(actions.isEmpty())
                assertIs<LNChannel<Normal>>(tempBob)
                bob = tempBob
            }
            bob
        }

        val nextHtlcId = bob1.commitments.changes.remoteNextHtlcId
        val add = UpdateAddHtlc(bob0.channelId, nextHtlcId, 2_000_000.msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(bob0.currentBlockHeight.toLong()), TestConstants.emptyOnionPacket)
        val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(add))
        assertIs<LNChannel<Closing>>(bob2)
        val error = actions2.hasOutgoingMessage<Error>()
        assertEquals(error.toAscii(), TooManyAcceptedHtlcs(bob0.channelId, bob0.staticParams.nodeParams.maxAcceptedHtlcs.toLong()).message)
    }

    @Test
    fun `recv ChannelCommand_Sign`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, _) = addHtlc(50_000_000.msat, payer = alice0, payee = bob0).first
        val (alice2, actions) = alice1.process(ChannelCommand.Commitment.Sign)
        val commitSig = actions.findOutgoingMessage<CommitSig>()
        assertEquals(1, commitSig.htlcSignatures.size)
        assertIs<LNChannel<ChannelStateWithCommitments>>(alice2)
        assertTrue(alice2.commitments.remoteNextCommitInfo.isLeft)
    }

    @Test
    fun `recv ChannelCommand_Sign -- two identical htlcs in each direction`() {
        val (alice0, bob0) = reachNormal()
        val add = defaultAdd.copy(amount = 10_000_000.msat, paymentHash = randomBytes32())

        val (alice1, actionsAlice1) = alice0.process(add)
        val htlc1 = actionsAlice1.findOutgoingMessage<UpdateAddHtlc>()
        val (bob1, _) = bob0.process(ChannelCommand.MessageReceived(htlc1))
        val (alice2, actionsAlice2) = alice1.process(add)
        val htlc2 = actionsAlice2.findOutgoingMessage<UpdateAddHtlc>()
        val (bob2, _) = bob1.process(ChannelCommand.MessageReceived(htlc2))

        assertIs<LNChannel<ChannelStateWithCommitments>>(alice2)
        assertIs<LNChannel<ChannelStateWithCommitments>>(bob2)
        val (alice3, bob3) = crossSign(alice2, bob2)

        val (bob4, actionsBob4) = bob3.process(add)
        val htlc3 = actionsBob4.findOutgoingMessage<UpdateAddHtlc>()
        val (alice4, _) = alice3.process(ChannelCommand.MessageReceived(htlc3))
        val (bob5, actionsBob5) = bob4.process(add)
        val htlc4 = actionsBob5.findOutgoingMessage<UpdateAddHtlc>()
        alice4.process(ChannelCommand.MessageReceived(htlc4))

        val (_, actionsBob6) = bob5.process(ChannelCommand.Commitment.Sign)
        val commitSig = actionsBob6.findOutgoingMessage<CommitSig>()
        assertEquals(4, commitSig.htlcSignatures.size)
    }

    @Test
    fun `recv ChannelCommand_Sign -- check htlc info are persisted`() {
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

        val (alice5, aActions5) = alice4.process(ChannelCommand.Commitment.Sign)
        val commitSig0 = aActions5.findOutgoingMessage<CommitSig>()

        val (bob5, bActions5) = bob4.process(ChannelCommand.MessageReceived(commitSig0))
        val revokeAndAck0 = bActions5.findOutgoingMessage<RevokeAndAck>()
        val commandSign0 = bActions5.findCommand<ChannelCommand.Commitment.Sign>()

        val (alice6, _) = alice5.process(ChannelCommand.MessageReceived(revokeAndAck0))
        val (bob6, bActions6) = bob5.process(commandSign0)
        val commitSig1 = bActions6.findOutgoingMessage<CommitSig>()

        val (alice7, aActions7) = alice6.process(ChannelCommand.MessageReceived(commitSig1))
        val revokeAndAck1 = aActions7.findOutgoingMessage<RevokeAndAck>()
        val (bob7, _) = bob6.process(ChannelCommand.MessageReceived(revokeAndAck1))

        val commandSign1 = aActions7.findCommand<ChannelCommand.Commitment.Sign>()
        val (alice8, aActions8) = alice7.process(commandSign1)
        val commitSig2 = aActions8.findOutgoingMessage<CommitSig>()

        val (_, bActions8) = bob7.process(ChannelCommand.MessageReceived(commitSig2))
        val revokeAndAck2 = bActions8.findOutgoingMessage<RevokeAndAck>()
        val (_, _) = alice8.process(ChannelCommand.MessageReceived(revokeAndAck2))

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
    fun `recv ChannelCommand_Sign -- htlcs with same pubkeyScript but different amounts`() {
        val (alice0, bob0) = reachNormal()
        val add = defaultAdd.copy(amount = 10_000_000.msat, paymentHash = randomBytes32())
        val epsilons = listOf(3, 1, 5, 7, 6) // unordered on purpose
        val htlcCount = epsilons.size

        val (alice1, bob1) = run {
            var (alice1, bob1) = alice0 to bob0
            for (i in epsilons) {
                val (stateA, actionsA) = alice1.process(add.copy(amount = add.amount + (i * 1000).msat))
                assertIs<LNChannel<Normal>>(stateA)
                alice1 = stateA
                val updateAddHtlc = actionsA.findOutgoingMessage<UpdateAddHtlc>()
                val (stateB, _) = bob1.process(ChannelCommand.MessageReceived(updateAddHtlc))
                assertIs<LNChannel<Normal>>(stateB)
                bob1 = stateB
            }
            alice1 to bob1
        }

        val (_, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        val commitSig = actionsAlice2.findOutgoingMessage<CommitSig>()
        assertEquals(htlcCount, commitSig.htlcSignatures.size)
        val (bob2, _) = bob1.process(ChannelCommand.MessageReceived(commitSig))
        assertIs<LNChannel<ChannelStateWithCommitments>>(bob2)
        val htlcTxs = bob2.commitments.latest.localCommit.publishableTxs.htlcTxsAndSigs
        assertEquals(htlcCount, htlcTxs.size)
        val amounts = htlcTxs.map { it.txinfo.tx.txOut.first().amount.sat }
        assertEquals(amounts, amounts.sorted())
    }

    @Test
    fun `recv ChannelCommand_Sign -- no changes`() {
        val (alice0, _) = reachNormal()
        val (_, actions) = alice0.process(ChannelCommand.Commitment.Sign)
        assertTrue(actions.isEmpty())
    }

    @Test
    fun `recv ChannelCommand_Sign -- while waiting for RevokeAndAck + no pending changes`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, _) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertIs<LNChannel<Normal>>(alice1)
        assertTrue(alice1.commitments.remoteNextCommitInfo.isRight)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        actionsAlice2.hasOutgoingMessage<CommitSig>()
        assertIs<LNChannel<Normal>>(alice2)
        assertNotNull(alice2.commitments.remoteNextCommitInfo.left)
        val waitForRevocation = alice2.commitments.remoteNextCommitInfo.left!!

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(alice3)
        assertEquals(Either.Left(waitForRevocation), alice3.commitments.remoteNextCommitInfo)
        assertNull(actionsAlice3.findOutgoingMessageOpt<CommitSig>())
    }

    @Test
    fun `recv ChannelCommand_Sign -- while waiting for RevokeAndAck + with pending changes`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertIs<LNChannel<Normal>>(alice1)
        assertTrue(alice1.commitments.remoteNextCommitInfo.isRight)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        actionsAlice2.hasOutgoingMessage<CommitSig>()
        assertIs<LNChannel<Normal>>(alice2)
        assertNotNull(alice2.commitments.remoteNextCommitInfo.left)
        val waitForRevocation = alice2.commitments.remoteNextCommitInfo.left!!

        val (alice3, _) = addHtlc(50_000_000.msat, alice2, bob1).first
        val (alice4, actionsAlice4) = alice3.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(alice4)
        assertEquals(Either.Left(waitForRevocation), alice4.commitments.remoteNextCommitInfo)
        assertTrue(actionsAlice4.isEmpty())
    }

    @Test
    fun `recv ChannelCommand_Sign -- going above reserve`() {
        val (alice0, bob0) = reachNormal(bobFundingAmount = 0.sat)
        assertEquals(0.msat, bob0.commitments.availableBalanceForSend())
        val (nodes1, preimage, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = nodes1
        val (_, bob2) = crossSign(alice1, bob1)
        val (bob3, actions3) = bob2.process(ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, preimage))
        actions3.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob4, actions4) = bob3.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(bob4)
        actions4.hasOutgoingMessage<CommitSig>()
        assertTrue(bob4.commitments.availableBalanceForSend() > 0.msat)
    }

    @Test
    fun `recv ChannelCommand_Sign -- after ChannelCommand_UpdateFee`() {
        val (alice, _) = reachNormal()
        val (alice1, actions1) = alice.process(ChannelCommand.Commitment.UpdateFee(FeeratePerKw.CommitmentFeerate + FeeratePerKw(1_000.sat)))
        actions1.hasOutgoingMessage<UpdateFee>()
        val (_, actions2) = alice1.process(ChannelCommand.Commitment.Sign)
        actions2.hasOutgoingMessage<CommitSig>()
    }

    @Test
    fun `recv CommitSig -- one htlc received`() {
        val (alice0, bob0) = reachNormal()
        val (nodes0, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = nodes0
        assertIs<LNChannel<Normal>>(bob1)

        val (_, bob2) = signAndRevack(alice1, bob1)
        val (bob3, _) = bob2.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(bob3)
        assertTrue(bob3.commitments.latest.localCommit.spec.htlcs.incomings().any { it.id == htlc.id })
        assertEquals(1, bob3.commitments.latest.localCommit.publishableTxs.htlcTxsAndSigs.size)
        assertEquals(bob1.commitments.latest.localCommit.spec.toLocal, bob3.commitments.latest.localCommit.spec.toLocal)
        assertEquals(0, bob3.commitments.changes.remoteChanges.acked.size)
        assertEquals(1, bob3.commitments.changes.remoteChanges.signed.size)
    }

    @Test
    fun `recv CommitSig -- one htlc sent`() {
        val (alice0, bob0) = reachNormal()
        val (nodes0, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = nodes0
        assertIs<LNChannel<Normal>>(bob1)

        val (alice2, bob2) = signAndRevack(alice1, bob1)
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(bob3)
        val commitSig = actionsBob3.findOutgoingMessage<CommitSig>()
        val (alice3, _) = alice2.process(ChannelCommand.MessageReceived(commitSig))
        assertIs<LNChannel<Normal>>(alice3)
        assertTrue(alice3.commitments.latest.localCommit.spec.htlcs.outgoings().any { it.id == htlc.id })
        assertEquals(1, alice3.commitments.latest.localCommit.publishableTxs.htlcTxsAndSigs.size)
        assertEquals(1, alice3.commitments.latest.localCommit.publishableTxs.htlcTxsAndSigs.size)
        assertEquals(bob1.commitments.latest.localCommit.spec.toLocal, bob3.commitments.latest.localCommit.spec.toLocal)
    }

    @Test
    fun `recv CommitSig -- multiple htlcs in both directions`() {
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
        val (_, actionsBob9) = bob8.process(ChannelCommand.Commitment.Sign)
        val commitSig = actionsBob9.findOutgoingMessage<CommitSig>()
        val (alice9, _) = alice8.process(ChannelCommand.MessageReceived(commitSig))
        assertIs<LNChannel<Normal>>(alice9)
        assertEquals(1, alice9.commitments.latest.localCommit.index)
        assertEquals(3, alice9.commitments.latest.localCommit.publishableTxs.htlcTxsAndSigs.size)
    }

    @Test
    fun `recv CommitSig -- multiple htlcs in both directions -- non-initiator pays commit fees`() {
        val (alice0, bob0) = reachNormal(requestRemoteFunding = TestConstants.bobFundingAmount)
        assertFalse(alice0.commitments.params.localParams.paysCommitTxFees)
        assertTrue(bob0.commitments.params.localParams.paysCommitTxFees)
        val (nodes1, _, _) = addHtlc(75_000_000.msat, alice0, bob0)
        val (alice1, bob1) = nodes1
        val (nodes2, _, _) = addHtlc(500_000.msat, alice1, bob1)
        val (alice2, bob2) = nodes2
        val (nodes3, _, _) = addHtlc(10_000_000.msat, bob2, alice2)
        val (bob3, alice3) = nodes3
        val (nodes4, _, _) = addHtlc(100_000.msat, bob3, alice3)
        val (bob4, alice4) = nodes4
        val (alice5, bob5) = crossSign(alice4, bob4)
        assertEquals(2, alice5.commitments.latest.localCommit.publishableTxs.htlcTxsAndSigs.size)
        assertEquals(2, bob5.commitments.latest.localCommit.publishableTxs.htlcTxsAndSigs.size)
        // Alice opened the channel, but Bob is paying the commitment fees.
        assertEquals(alice5.commitments.latest.localCommit.spec.toLocal - alice5.commitments.latest.localChannelReserve.toMilliSatoshi(), alice5.commitments.availableBalanceForSend())
        assertTrue(bob5.commitments.availableBalanceForSend() < bob5.commitments.latest.localCommit.spec.toLocal - bob5.commitments.latest.localChannelReserve.toMilliSatoshi())
    }

    @Test
    fun `recv CommitSig -- only fee update`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, actions1) = alice0.process(ChannelCommand.Commitment.UpdateFee(FeeratePerKw.CommitmentFeerate + FeeratePerKw(1_000.sat), false))
        val updateFee = actions1.findOutgoingMessage<UpdateFee>()
        assertEquals(FeeratePerKw.CommitmentFeerate + FeeratePerKw(1_000.sat), updateFee.feeratePerKw)
        val (bob1, _) = bob0.process(ChannelCommand.MessageReceived(updateFee))
        val (alice2, actions2) = alice1.process(ChannelCommand.Commitment.Sign)
        val commitSig = actions2.findOutgoingMessage<CommitSig>()
        val (_, actions3) = bob1.process(ChannelCommand.MessageReceived(commitSig))
        val revokeAndAck = actions3.findOutgoingMessage<RevokeAndAck>()
        val (alice3, _) = alice2.process(ChannelCommand.MessageReceived(revokeAndAck))
        assertIs<LNChannel<Normal>>(alice3)
    }

    @Test
    fun `recv CommitSig -- two htlcs received with same preimage`() {
        val (alice0, bob0) = reachNormal()
        val r = randomBytes32()
        val h = Crypto.sha256(r).toByteVector32()

        val (alice1, actionsAlice1) = alice0.process(defaultAdd.copy(paymentHash = h))
        val htlc1 = actionsAlice1.findOutgoingMessage<UpdateAddHtlc>()
        val (bob1, _) = bob0.process(ChannelCommand.MessageReceived(htlc1))

        val (alice2, actionsAlice2) = alice1.process(defaultAdd.copy(paymentHash = h))
        val htlc2 = actionsAlice2.findOutgoingMessage<UpdateAddHtlc>()
        val (bob2, _) = bob1.process(ChannelCommand.MessageReceived(htlc2))
        assertIs<LNChannel<ChannelStateWithCommitments>>(bob2)
        assertEquals(listOf(htlc1, htlc2), bob2.commitments.changes.remoteChanges.proposed)

        assertIs<LNChannel<Normal>>(alice2)
        assertIs<LNChannel<Normal>>(bob2)
        val (_, bob3) = crossSign(alice2, bob2)
        assertIs<LNChannel<Normal>>(bob3)
        assertTrue(bob3.commitments.latest.localCommit.spec.htlcs.incomings().any { it.id == htlc1.id })
        assertEquals(2, bob3.commitments.latest.localCommit.publishableTxs.htlcTxsAndSigs.size)
        assertEquals(bob2.commitments.latest.localCommit.spec.toLocal, bob3.commitments.latest.localCommit.spec.toLocal)
        assertEquals(2, bob3.commitments.latest.localCommit.publishableTxs.commitTx.tx.txOut.count { it.amount == 50_000.sat })
    }

    @Test
    fun `recv CommitSig -- no changes`() {
        val (_, bob0) = reachNormal()
        val tx = bob0.commitments.latest.localCommit.publishableTxs.commitTx.tx

        // signature is invalid but it doesn't matter
        val sig = CommitSig(ByteVector32.Zeroes, ByteVector64.Zeroes, emptyList())
        val (bob1, actionsBob1) = bob0.process(ChannelCommand.MessageReceived(sig))
        assertIs<LNChannel<Closing>>(bob1)
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
    fun `recv CommitSig -- invalid signature`() {
        val (_, bob0) = reachNormal()
        val tx = bob0.commitments.latest.localCommit.publishableTxs.commitTx.tx

        // signature is invalid but it doesn't matter
        val sig = CommitSig(ByteVector32.Zeroes, ByteVector64.Zeroes, emptyList())
        val (bob1, actionsBob1) = bob0.process(ChannelCommand.MessageReceived(sig))
        assertIs<LNChannel<Closing>>(bob1)
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
    fun `recv CommitSig -- bad htlc sig count`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertIs<LNChannel<Normal>>(bob1)
        val tx = bob1.commitments.latest.localCommit.publishableTxs.commitTx.tx

        val (_, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        val commitSig = actionsAlice2.findOutgoingMessage<CommitSig>()
        val badCommitSig = commitSig.copy(htlcSignatures = commitSig.htlcSignatures + commitSig.htlcSignatures)

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(badCommitSig))
        assertIs<LNChannel<Closing>>(bob2)
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
    fun `recv CommitSig -- invalid htlc sig`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertIs<LNChannel<Normal>>(bob1)
        val tx = bob1.commitments.latest.localCommit.publishableTxs.commitTx.tx

        val (_, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        val commitSig = actionsAlice2.findOutgoingMessage<CommitSig>()
        val badCommitSig = commitSig.copy(htlcSignatures = listOf(commitSig.signature))
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(badCommitSig))
        assertIs<LNChannel<Closing>>(bob2)
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
    fun `recv RevokeAndAck -- one htlc sent`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(alice2)
        assertTrue(alice2.commitments.remoteNextCommitInfo.isLeft)
        val commitSig = actionsAlice2.findOutgoingMessage<CommitSig>()
        val (_, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(commitSig))
        val revokeAndAck = actionsBob2.findOutgoingMessage<RevokeAndAck>()

        val (alice3, _) = alice2.process(ChannelCommand.MessageReceived(revokeAndAck))
        assertIs<LNChannel<Normal>>(alice3)
        assertTrue(alice3.commitments.remoteNextCommitInfo.isRight)
        assertEquals(1, alice3.commitments.changes.localChanges.acked.size)
    }

    @Test
    fun `recv RevokeAndAck -- one htlc received`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, add) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = nodes

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        val commitSig0 = actionsAlice2.findOutgoingMessage<CommitSig>()

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(commitSig0))
        val revokeAndAck0 = actionsBob2.findOutgoingMessage<RevokeAndAck>()
        val cmd = actionsBob2.findCommand<ChannelCommand.Commitment.Sign>()
        val (bob3, actionsBob3) = bob2.process(cmd)
        val (alice3, _) = alice2.process(ChannelCommand.MessageReceived(revokeAndAck0))
        assertIs<LNChannel<Normal>>(alice3)
        assertTrue(alice3.commitments.remoteNextCommitInfo.isRight)
        val commitSig1 = actionsBob3.findOutgoingMessage<CommitSig>()
        val (_, actionsAlice4) = alice3.process(ChannelCommand.MessageReceived(commitSig1))
        val revokeAndAck1 = actionsAlice4.findOutgoingMessage<RevokeAndAck>()
        val (bob4, actionsBob4) = bob3.process(ChannelCommand.MessageReceived(revokeAndAck1))
        assertIs<LNChannel<Normal>>(bob4)
        assertTrue(bob4.commitments.remoteNextCommitInfo.isRight)
        actionsBob4.has<ChannelAction.Storage.StoreState>()
        assertEquals(add, actionsBob4.find<ChannelAction.ProcessIncomingHtlc>().add)
    }

    @Test
    fun `recv RevokeAndAck -- multiple htlcs in both directions`() {
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

        val (alice8, actionsAlice8) = alice7.process(ChannelCommand.Commitment.Sign)
        val commitSig0 = actionsAlice8.findOutgoingMessage<CommitSig>()
        val (bob8, actionsBob8) = bob7.process(ChannelCommand.MessageReceived(commitSig0))
        val revokeAndAck0 = actionsBob8.findOutgoingMessage<RevokeAndAck>()
        val cmd = actionsBob8.findCommand<ChannelCommand.Commitment.Sign>()
        val (bob9, actionsBob9) = bob8.process(cmd)
        val (alice9, _) = alice8.process(ChannelCommand.MessageReceived(revokeAndAck0))
        assertIs<LNChannel<Normal>>(alice9)
        assertTrue(alice9.commitments.remoteNextCommitInfo.isRight)

        val commitSig1 = actionsBob9.findOutgoingMessage<CommitSig>()
        val (_, actionsAlice10) = alice9.process(ChannelCommand.MessageReceived(commitSig1))
        val revokeAndAck1 = actionsAlice10.findOutgoingMessage<RevokeAndAck>()
        val (bob10, actionsBob10) = bob9.process(ChannelCommand.MessageReceived(revokeAndAck1))
        assertIs<LNChannel<Normal>>(bob10)
        assertTrue(bob10.commitments.remoteNextCommitInfo.isRight)
        assertEquals(1, bob10.commitments.remoteCommitIndex)
        assertEquals(7, bob10.commitments.latest.remoteCommit.spec.htlcs.size)
        assertEquals(setOf(add1, add2, add3, add4), actionsBob10.filterIsInstance<ChannelAction.ProcessIncomingHtlc>().map { it.add }.toSet())
    }

    @Test
    fun `recv RevokeAndAck -- with pending sig`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertIs<LNChannel<Normal>>(alice1)
        assertTrue(alice1.commitments.remoteNextCommitInfo.isRight)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        val commitSig0 = actionsAlice2.findOutgoingMessage<CommitSig>()
        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(commitSig0))

        val (alice3, _) = addHtlc(50_000_000.msat, alice2, bob2).first
        val (alice4, _) = alice3.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(alice4)

        val revokeAndAck0 = actionsBob2.findOutgoingMessage<RevokeAndAck>()
        val (alice5, actionsAlice5) = alice4.process(ChannelCommand.MessageReceived(revokeAndAck0))
        val cmd = actionsAlice5.findCommand<ChannelCommand.Commitment.Sign>()
        val (_, actionsAlice6) = alice5.process(cmd)
        actionsAlice6.hasOutgoingMessage<CommitSig>()
    }

    @Test
    fun `recv RevokeAndAck -- invalid preimage`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, bob1) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertIs<LNChannel<Normal>>(alice1)
        val tx = alice1.commitments.latest.localCommit.publishableTxs.commitTx.tx

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.Commitment.Sign)
        val commitSig0 = actionsAlice2.findOutgoingMessage<CommitSig>()
        val (_, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(commitSig0))
        actionsBob2.hasOutgoingMessage<RevokeAndAck>()

        val (alice3, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(RevokeAndAck(ByteVector32.Zeroes, PrivateKey(randomBytes32()), PrivateKey(randomBytes32()).publicKey())))
        assertIs<LNChannel<Closing>>(alice3)
        actionsAlice3.hasOutgoingMessage<Error>()
        assertEquals(2, actionsAlice3.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        assertEquals(2, actionsAlice3.findWatches<WatchConfirmed>().count())
        actionsAlice3.hasPublishTx(tx)
    }

    @Test
    fun `recv RevokeAndAck -- unexpectedly`() {
        val (alice0, bob0) = reachNormal()
        val (alice1, _) = addHtlc(50_000_000.msat, alice0, bob0).first
        assertIs<LNChannel<Normal>>(alice1)
        assertTrue(alice1.commitments.remoteNextCommitInfo.isRight)
        val tx = alice1.commitments.latest.localCommit.publishableTxs.commitTx.tx

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(RevokeAndAck(ByteVector32.Zeroes, PrivateKey(randomBytes32()), PrivateKey(randomBytes32()).publicKey())))
        assertIs<LNChannel<Closing>>(alice2)
        actionsAlice2.hasOutgoingMessage<Error>()
        assertEquals(2, actionsAlice2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        assertEquals(2, actionsAlice2.findWatches<WatchConfirmed>().count())
        actionsAlice2.hasPublishTx(tx)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Settlement_Fulfill`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, r, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertIs<LNChannel<Normal>>(bob1)

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, r))
        val fulfillHtlc = actionsBob2.findOutgoingMessage<UpdateFulfillHtlc>()
        assertEquals(
            bob1.copy(state = bob1.state.copy(commitments = bob1.commitments.copy(changes = bob1.commitments.changes.copy(localChanges = bob1.commitments.changes.localChanges.copy(bob1.commitments.changes.localChanges.proposed + fulfillHtlc))))),
            bob2
        )
    }

    @Test
    fun `recv ChannelCommand_Htlc_Settlement_Fulfill -- unknown htlc id`() {
        val (_, bob0) = reachNormal()
        val cmd = ChannelCommand.Htlc.Settlement.Fulfill(42, randomBytes32())

        val (_, actions) = bob0.process(cmd)
        val actualError = actions.findCommandError<UnknownHtlcId>()
        val expectedError = UnknownHtlcId(bob0.channelId, 42)
        assertEquals(expectedError, actualError)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Settlement_Fulfill -- invalid preimage`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertIs<LNChannel<Normal>>(bob1)

        val cmd = ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, ByteVector32.Zeroes)
        val (bob2, actionsBob2) = bob1.process(cmd)
        actionsBob2.hasCommandError<InvalidHtlcPreimage>()
        assertEquals(bob1, bob2)
    }

    @Test
    fun `recv UpdateFulfillHtlc`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, r, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = crossSign(nodes.first, nodes.second)
        val (_, actionsBob2) = bob1.process(ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, r))
        val fulfill = actionsBob2.findOutgoingMessage<UpdateFulfillHtlc>()
        assertIs<LNChannel<Normal>>(alice1)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(fulfill))
        assertEquals(
            alice1.copy(state = alice1.state.copy(commitments = alice1.commitments.copy(changes = alice1.commitments.changes.copy(remoteChanges = alice1.commitments.changes.remoteChanges.copy(alice1.commitments.changes.remoteChanges.proposed + fulfill))))),
            alice2
        )
        val addSettled = actionsAlice2.filterIsInstance<ChannelAction.ProcessCmdRes.AddSettledFulfill>().first()
        assertEquals(htlc, addSettled.htlc)
        assertEquals(ChannelAction.HtlcResult.Fulfill.RemoteFulfill(fulfill), addSettled.result)
    }

    @Test
    fun `recv UpdateFulfillHtlc -- unknown htlc id`() {
        val (alice0, _) = reachNormal()
        val commitTx = alice0.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice1, actions1) = alice0.process(ChannelCommand.MessageReceived(UpdateFulfillHtlc(alice0.channelId, 42, randomBytes32())))
        assertIs<LNChannel<Closing>>(alice1)
        assertTrue(actions1.contains(ChannelAction.Storage.StoreState(alice1.state)))
        assertEquals(commitTx, actions1.hasPublishTx(Type.CommitTx))
        assertTrue(actions1.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions1.filterIsInstance<ChannelAction.Blockchain.SendWatch>().all { it.watch is WatchConfirmed })
        val error = actions1.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice0.channelId, 42).message)
    }

    @Test
    fun `recv UpdateFulfillHtlc -- sender has not signed htlc`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, r, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, actions1) = nodes.first.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(alice1)
        actions1.findOutgoingMessage<CommitSig>()
        val commitTx = alice1.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice2, actions2) = alice1.process(ChannelCommand.MessageReceived(UpdateFulfillHtlc(alice1.channelId, htlc.id, r)))
        assertIs<LNChannel<Closing>>(alice2)
        assertTrue(actions2.contains(ChannelAction.Storage.StoreState(alice2.state)))
        assertEquals(commitTx, actions2.hasPublishTx(Type.CommitTx))
        assertTrue(actions2.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions2.filterIsInstance<ChannelAction.Blockchain.SendWatch>().all { it.watch is WatchConfirmed })
        val error = actions2.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice0.channelId, 0).message)
    }

    @Test
    fun `recv UpdateFulfillHtlc -- invalid preimage`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        assertIs<LNChannel<Normal>>(alice1)
        val commitTx = alice1.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice2, actions2) = alice1.process(ChannelCommand.MessageReceived(UpdateFulfillHtlc(alice0.channelId, htlc.id, ByteVector32.Zeroes)))
        assertIs<LNChannel<Closing>>(alice2)
        assertTrue(actions2.contains(ChannelAction.Storage.StoreState(alice2.state)))
        assertEquals(commitTx, actions2.hasPublishTx(Type.CommitTx))
        assertEquals(4, actions2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().size) // commit tx + main delayed + htlc-timeout + htlc delayed
        assertEquals(4, actions2.filterIsInstance<ChannelAction.Blockchain.SendWatch>().size)
        val error = actions2.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InvalidHtlcPreimage(alice0.channelId, htlc.id).message)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Settlement_Fail`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertIs<LNChannel<Normal>>(bob1)

        val cmd = ChannelCommand.Htlc.Settlement.Fail(htlc.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(PermanentChannelFailure))
        val (bob2, actions2) = bob1.process(cmd)
        val fail = actions2.findOutgoingMessage<UpdateFailHtlc>()
        assertEquals(
            bob1.copy(state = bob1.state.copy(commitments = bob1.commitments.copy(changes = bob1.commitments.changes.copy(localChanges = bob1.commitments.changes.localChanges.copy(bob1.commitments.changes.localChanges.proposed + fail))))),
            bob2
        )
    }

    @Test
    fun `recv ChannelCommand_Htlc_Settlement_Fail -- unknown htlc id`() {
        val (_, bob0) = reachNormal()
        val cmdFail = ChannelCommand.Htlc.Settlement.Fail(42, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(PermanentChannelFailure))
        val (bob1, actions1) = bob0.process(cmdFail)
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmdFail, UnknownHtlcId(bob0.channelId, 42))))
        assertEquals(bob0, bob1)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Settlement_FailMalformed`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertIs<LNChannel<Normal>>(bob1)

        val cmdFail = ChannelCommand.Htlc.Settlement.FailMalformed(htlc.id, Sphinx.hash(htlc.onionRoutingPacket), FailureMessage.BADONION)
        val (bob2, actions2) = bob1.process(cmdFail)
        val fail = actions2.findOutgoingMessage<UpdateFailMalformedHtlc>()
        assertEquals(
            bob1.state.copy(commitments = bob1.commitments.copy(changes = bob1.commitments.changes.copy(localChanges = bob1.commitments.changes.localChanges.copy(bob1.commitments.changes.localChanges.proposed + fail)))),
            bob2.state
        )
    }

    @Test
    fun `recv ChannelCommand_Htlc_Settlement_FailMalformed -- unknown htlc id`() {
        val (_, bob0) = reachNormal()
        val cmdFail = ChannelCommand.Htlc.Settlement.FailMalformed(42, ByteVector32.Zeroes, FailureMessage.BADONION)
        val (bob1, actions1) = bob0.process(cmdFail)
        assertEquals(actions1, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmdFail, UnknownHtlcId(bob0.channelId, 42))))
        assertEquals(bob0, bob1)
    }

    @Test
    fun `recv ChannelCommand_Htlc_Settlement_FailMalformed -- invalid failure_code`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)

        val cmdFail = ChannelCommand.Htlc.Settlement.FailMalformed(htlc.id, Sphinx.hash(htlc.onionRoutingPacket), 42)
        val (bob2, actions2) = bob1.process(cmdFail)
        assertEquals(actions2, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmdFail, InvalidFailureCode(bob0.channelId))))
        assertEquals(bob1, bob2)
    }

    @Test
    fun `recv UpdateFailHtlc`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = crossSign(nodes.first, nodes.second)
        val (_, actionsBob2) = bob1.process(ChannelCommand.Htlc.Settlement.Fail(htlc.id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(PermanentChannelFailure)))
        val fail = actionsBob2.findOutgoingMessage<UpdateFailHtlc>()
        assertIs<LNChannel<Normal>>(alice1)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(fail))
        assertIs<LNChannel<Normal>>(alice2)
        assertTrue(actionsAlice2.isEmpty())
        assertEquals(
            alice1.state.copy(commitments = alice1.commitments.copy(changes = alice1.commitments.changes.copy(remoteChanges = alice1.commitments.changes.remoteChanges.copy(alice1.commitments.changes.remoteChanges.proposed + fail)))),
            alice2.state
        )
    }

    @Test
    fun `recv UpdateFailHtlc -- unknown htlc id`() {
        val (alice0, _) = reachNormal()
        val commitTx = alice0.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice1, actions1) = alice0.process(ChannelCommand.MessageReceived(UpdateFailHtlc(alice0.channelId, 42, ByteVector.empty)))
        assertIs<LNChannel<Closing>>(alice1)
        assertTrue(actions1.contains(ChannelAction.Storage.StoreState(alice1.state)))
        assertEquals(commitTx, actions1.hasPublishTx(Type.CommitTx))
        assertTrue(actions1.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions1.filterIsInstance<ChannelAction.Blockchain.SendWatch>().all { it.watch is WatchConfirmed })
        val error = actions1.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice0.channelId, 42).message)
    }

    @Test
    fun `recv UpdateFailHtlc -- sender has not signed htlc`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, actions1) = nodes.first.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(alice1)
        actions1.findOutgoingMessage<CommitSig>()
        val commitTx = alice1.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice2, actions2) = alice1.process(ChannelCommand.MessageReceived(UpdateFailHtlc(alice1.channelId, htlc.id, ByteVector.empty)))
        assertIs<LNChannel<Closing>>(alice2)
        assertTrue(actions2.contains(ChannelAction.Storage.StoreState(alice2.state)))
        assertEquals(commitTx, actions2.hasPublishTx(Type.CommitTx))
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
        val (_, actionsBob2) = bob1.process(ChannelCommand.Htlc.Settlement.FailMalformed(htlc.id, Sphinx.hash(htlc.onionRoutingPacket), FailureMessage.BADONION))
        val fail = actionsBob2.findOutgoingMessage<UpdateFailMalformedHtlc>()
        assertIs<LNChannel<Normal>>(alice1)

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(fail))
        assertIs<LNChannel<Normal>>(alice2)
        assertTrue(actionsAlice2.isEmpty())
        assertEquals(
            alice1.state.copy(commitments = alice1.commitments.copy(changes = alice1.commitments.changes.copy(remoteChanges = alice1.commitments.changes.remoteChanges.copy(alice1.commitments.changes.remoteChanges.proposed + fail)))),
            alice2.state
        )
    }

    @Test
    fun `recv UpdateFailMalformedHtlc -- unknown htlc id`() {
        val (alice0, _) = reachNormal()
        val commitTx = alice0.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (alice1, actions1) = alice0.process(ChannelCommand.MessageReceived(UpdateFailMalformedHtlc(alice0.channelId, 42, ByteVector32.Zeroes, FailureMessage.BADONION)))
        assertIs<LNChannel<Closing>>(alice1)
        assertTrue(actions1.contains(ChannelAction.Storage.StoreState(alice1.state)))
        assertEquals(commitTx, actions1.hasPublishTx(Type.CommitTx))
        assertTrue(actions1.findWatches<WatchConfirmed>().isNotEmpty())
        assertTrue(actions1.filterIsInstance<ChannelAction.Blockchain.SendWatch>().all { it.watch is WatchConfirmed })
        val error = actions1.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), UnknownHtlcId(alice0.channelId, 42).message)
    }

    @Test
    fun `recv UpdateFailMalformedHtlc -- invalid failure_code`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        assertIs<LNChannel<Normal>>(alice1)
        val commitTx = alice1.commitments.latest.localCommit.publishableTxs.commitTx.tx

        val (alice2, actions2) = alice1.process(ChannelCommand.MessageReceived(UpdateFailMalformedHtlc(alice0.channelId, htlc.id, Sphinx.hash(htlc.onionRoutingPacket), 42)))
        assertIs<LNChannel<Closing>>(alice2)
        assertTrue(actions2.contains(ChannelAction.Storage.StoreState(alice2.state)))
        assertEquals(commitTx, actions2.hasPublishTx(Type.CommitTx))
        assertEquals(4, actions2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().size) // commit tx + main delayed + htlc-timeout + htlc delayed
        assertEquals(4, actions2.filterIsInstance<ChannelAction.Blockchain.SendWatch>().size)
        val error = actions2.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), InvalidFailureCode(alice0.channelId).message)
    }

    @Test
    fun `recv UpdateFee`() {
        val (_, bob) = reachNormal()
        val fee = UpdateFee(ByteVector32.Zeroes, FeeratePerKw(7_500.sat))
        val (bob1, _) = bob.process(ChannelCommand.MessageReceived(fee))
        assertIs<LNChannel<Normal>>(bob1)
        assertEquals(bob.commitments.copy(changes = bob.commitments.changes.copy(remoteChanges = bob.commitments.changes.remoteChanges.copy(proposed = bob.commitments.changes.remoteChanges.proposed + fee))), bob1.commitments)
    }

    @Test
    fun `recv UpdateFee -- non-initiator pays commit fees`() {
        val (alice, bob) = reachNormal(requestRemoteFunding = TestConstants.bobFundingAmount)
        val fee = UpdateFee(ByteVector32.Zeroes, FeeratePerKw(7_500.sat))
        run {
            val (alice1, _) = alice.process(ChannelCommand.MessageReceived(fee))
            assertIs<LNChannel<Normal>>(alice1)
            assertTrue(alice1.commitments.changes.remoteChanges.proposed.contains(fee))
        }
        run {
            val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(fee))
            assertIs<LNChannel<Closing>>(bob1)
            actions1.findOutgoingMessage<Error>().also { assertEquals(NonInitiatorCannotSendUpdateFee(alice.channelId).message, it.toAscii()) }
        }
    }

    @Test
    fun `recv UpdateFee -- 2 in a row`() {
        val (_, bob) = reachNormal()
        val fee1 = UpdateFee(ByteVector32.Zeroes, FeeratePerKw(7_500.sat))
        val (bob1, _) = bob.process(ChannelCommand.MessageReceived(fee1))
        val fee2 = UpdateFee(ByteVector32.Zeroes, FeeratePerKw(9_000.sat))
        val (bob2, _) = bob1.process(ChannelCommand.MessageReceived(fee2))
        assertIs<LNChannel<Normal>>(bob2)
        assertEquals(bob.commitments.copy(changes = bob.commitments.changes.copy(remoteChanges = bob.commitments.changes.remoteChanges.copy(proposed = bob.commitments.changes.remoteChanges.proposed + fee2))), bob2.commitments)
    }

    @Test
    fun `recv UpdateFee -- sender cannot afford it`() {
        val (alice, bob) = reachNormal()
        // We put all the balance on Bob's side, so that Alice cannot afford a feerate increase.
        val (nodes, _, _) = addHtlc(alice.commitments.availableBalanceForSend(), alice, bob)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        assertIs<LNChannel<Normal>>(bob1)
        val commitTx = bob1.commitments.latest.localCommit.publishableTxs.commitTx.tx

        val fee = UpdateFee(ByteVector32.Zeroes, FeeratePerKw.CommitmentFeerate * 4)
        val (bob2, actions) = bob1.process(ChannelCommand.MessageReceived(fee))
        assertIs<LNChannel<Closing>>(bob2)
        actions.hasPublishTx(commitTx)
        actions.hasWatch<WatchConfirmed>()
        val error = actions.findOutgoingMessage<Error>()
        assertEquals(error.toAscii(), CannotAffordFees(bob.channelId, missing = 11_240.sat, reserve = 10_000.sat, fees = 26_580.sat).message)
    }

    @Test
    fun `recv UpdateFee -- remote feerate is too small`() {
        val (_, bob) = reachNormal()
        assertEquals(FeeratePerKw.CommitmentFeerate, bob.commitments.latest.localCommit.spec.feerate)
        val (bob1, actions) = bob.process(ChannelCommand.MessageReceived(UpdateFee(bob.channelId, FeeratePerKw(252.sat))))
        assertIs<LNChannel<Closing>>(bob1)
        actions.hasPublishTx(bob.commitments.latest.localCommit.publishableTxs.commitTx.tx)
        actions.hasWatch<WatchConfirmed>()
        val error = actions.findOutgoingMessage<Error>()
        assertTrue(error.toAscii().contains("emote fee rate is too small: remoteFeeratePerKw=252"))
    }

    @Test
    fun `recv ChannelUpdate`() {
        val (alice, bob) = reachNormal()
        assertNull(alice.state.remoteChannelUpdate)
        assertNull(bob.state.remoteChannelUpdate)
        val aliceUpdate = Announcements.makeChannelUpdate(alice.staticParams.nodeParams.chainHash, alice.ctx.privateKey, alice.staticParams.remoteNodeId, alice.state.shortChannelId, CltvExpiryDelta(36), 5.msat, 15.msat, 150, 150_000.msat)
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(aliceUpdate))
        assertIs<LNChannel<Normal>>(bob1)
        assertEquals(bob1.state.remoteChannelUpdate, aliceUpdate)
        actions1.has<ChannelAction.Storage.StoreState>()

        val aliceUpdateOtherChannel = Announcements.makeChannelUpdate(alice.staticParams.nodeParams.chainHash, alice.ctx.privateKey, alice.staticParams.remoteNodeId, ShortChannelId(7), CltvExpiryDelta(12), 1.msat, 10.msat, 50, 15_000.msat)
        val (bob2, actions2) = bob1.process(ChannelCommand.MessageReceived(aliceUpdateOtherChannel))
        assertEquals(bob1, bob2)
        assertTrue(actions2.isEmpty())

        val bobUpdate = Announcements.makeChannelUpdate(bob.staticParams.nodeParams.chainHash, bob.ctx.privateKey, bob.staticParams.remoteNodeId, bob.state.shortChannelId, CltvExpiryDelta(24), 1.msat, 5.msat, 10, 125_000.msat)
        val (bob3, actions3) = bob2.process(ChannelCommand.MessageReceived(bobUpdate))
        assertEquals(bob1, bob3)
        assertTrue(actions3.isEmpty())
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- no pending htlcs`() {
        val (alice, _) = reachNormal()
        assertNull(alice.state.localShutdown)
        val (alice1, actions1) = alice.process(ChannelCommand.Close.MutualClose(null, null))
        assertIs<LNChannel<Normal>>(alice1)
        actions1.hasOutgoingMessage<Shutdown>()
        assertNotNull(alice1.state.localShutdown)
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- with unacked sent htlcs`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(1000.msat, payer = alice, payee = bob)
        val (alice1, _) = nodes
        val (alice2, actions1) = alice1.process(ChannelCommand.Close.MutualClose(null, null))
        assertIs<LNChannel<Normal>>(alice2)
        actions1.hasCommandError<CannotCloseWithUnsignedOutgoingHtlcs>()
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- with unacked received htlcs`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(1000.msat, payer = alice, payee = bob)
        val (_, bob1) = nodes
        val (bob2, actions1) = bob1.process(ChannelCommand.Close.MutualClose(null, null))
        assertIs<LNChannel<Normal>>(bob2)
        actions1.hasOutgoingMessage<Shutdown>()
        assertNotNull(bob2.state.localShutdown)
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- with invalid final script`() {
        val (alice, _) = reachNormal()
        assertNull(alice.state.localShutdown)
        val (alice1, actions1) = alice.process(ChannelCommand.Close.MutualClose(ByteVector("00112233445566778899"), null))
        assertIs<LNChannel<Normal>>(alice1)
        actions1.hasCommandError<InvalidFinalScript>()
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- with unsupported native segwit script`() {
        val (alice, _) = reachNormal(aliceFeatures = TestConstants.Alice.nodeParams.features.remove(Feature.ShutdownAnySegwit))
        assertNull(alice.state.localShutdown)
        val (alice1, actions1) = alice.process(ChannelCommand.Close.MutualClose(ByteVector("51050102030405"), null))
        assertIs<LNChannel<Normal>>(alice1)
        actions1.hasCommandError<InvalidFinalScript>()
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- with native segwit script`() {
        val (alice, _) = reachNormal()
        assertNull(alice.state.localShutdown)
        val (alice1, actions1) = alice.process(ChannelCommand.Close.MutualClose(ByteVector("51050102030405"), null))
        actions1.hasOutgoingMessage<Shutdown>()
        assertIs<LNChannel<Normal>>(alice1)
        assertNotNull(alice1.state.localShutdown)
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- with signed sent htlcs`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(1000.msat, payer = alice, payee = bob)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        val (alice2, actions1) = alice1.process(ChannelCommand.Close.MutualClose(null, null))
        actions1.hasOutgoingMessage<Shutdown>()
        assertIs<LNChannel<Normal>>(alice2)
        assertNotNull(alice2.state.localShutdown)
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- two in a row`() {
        val (alice, _) = reachNormal()
        assertNull(alice.state.localShutdown)
        val (alice1, actions1) = alice.process(ChannelCommand.Close.MutualClose(null, null))
        assertIs<LNChannel<Normal>>(alice1)
        actions1.hasOutgoingMessage<Shutdown>()
        assertNotNull(alice1.state.localShutdown)
        val (alice2, actions2) = alice1.process(ChannelCommand.Close.MutualClose(null, null))
        assertIs<LNChannel<Normal>>(alice2)
        actions2.hasCommandError<ClosingAlreadyInProgress>()
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- while waiting for a RevokeAndAck`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(1000.msat, payer = alice, payee = bob)
        val (alice1, actions1) = nodes.first.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(alice1)
        actions1.hasOutgoingMessage<CommitSig>()
        val (alice2, actions2) = alice1.process(ChannelCommand.Close.MutualClose(null, null))
        assertIs<LNChannel<Normal>>(alice2)
        actions2.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv ChannelCommand_Close_MutualClose -- with unsigned fee update`() {
        val (alice, _) = reachNormal()
        val (alice1, actions1) = alice.process(ChannelCommand.Commitment.UpdateFee(FeeratePerKw(20_000.sat), false))
        actions1.hasOutgoingMessage<UpdateFee>()
        val (alice2, actions2) = alice1.process(ChannelCommand.Close.MutualClose(null, null))
        actions2.hasCommandError<CannotCloseWithUnsignedOutgoingUpdateFee>()
        val (alice3, _) = alice2.process(ChannelCommand.Commitment.Sign)
        val (alice4, actions4) = alice3.process(ChannelCommand.Close.MutualClose(null, null))
        assertIs<LNChannel<Normal>>(alice4)
        actions4.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv Shutdown -- no pending htlcs`() {
        val (alice, bob) = reachNormal()
        val (alice1, actions1) = alice.process(ChannelCommand.MessageReceived(Shutdown(alice.channelId, bob.commitments.params.localParams.defaultFinalScriptPubKey)))
        assertIs<LNChannel<Negotiating>>(alice1)
        actions1.hasOutgoingMessage<Shutdown>()
        actions1.hasOutgoingMessage<ClosingSigned>()
    }

    @Test
    fun `recv Shutdown -- with unacked sent htlcs`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (bob1, actions1) = nodes.second.process(ChannelCommand.Close.MutualClose(null, null))

        val shutdown = actions1.findOutgoingMessage<Shutdown>()
        val (alice1, actions2) = nodes.first.process(ChannelCommand.MessageReceived(shutdown))
        // Alice sends a new sig
        assertEquals(actions2, listOf(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign)))
        val (alice2, actions3) = alice1.process(ChannelCommand.Commitment.Sign)
        val commitSig = actions3.findOutgoingMessage<CommitSig>()

        // Bob replies with a revocation
        val (_, actions4) = bob1.process(ChannelCommand.MessageReceived(commitSig))
        val revack = actions4.findOutgoingMessage<RevokeAndAck>()

        // as soon as alice has received the revocation, she will send her shutdown message
        val (alice3, actions5) = alice2.process(ChannelCommand.MessageReceived(revack))
        assertIs<LNChannel<ShuttingDown>>(alice3)
        actions5.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv Shutdown -- with unacked received htlcs`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (bob1, actions1) = nodes.second.process(ChannelCommand.MessageReceived(Shutdown(alice.channelId, alice.commitments.params.localParams.defaultFinalScriptPubKey)))
        assertIs<LNChannel<Closing>>(bob1)
        actions1.hasOutgoingMessage<Error>()
        assertEquals(2, actions1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        actions1.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `recv Shutdown -- with unsigned fee update`() {
        val (alice, bob) = reachNormal()
        val (alice1, aliceActions1) = alice.process(ChannelCommand.Commitment.UpdateFee(FeeratePerKw(20_000.sat), true))
        val updateFee = aliceActions1.hasOutgoingMessage<UpdateFee>()
        val (alice2, aliceActions2) = alice1.process(ChannelCommand.Commitment.Sign)
        val sigAlice = aliceActions2.hasOutgoingMessage<CommitSig>()

        // Bob initiates a close before receiving the signature.
        val (bob1, _) = bob.process(ChannelCommand.MessageReceived(updateFee))
        val (bob2, bobActions2) = bob1.process(ChannelCommand.Close.MutualClose(null, null))
        val shutdownBob = bobActions2.hasOutgoingMessage<Shutdown>()

        val (bob3, bobActions3) = bob2.process(ChannelCommand.MessageReceived(sigAlice))
        val revBob = bobActions3.hasOutgoingMessage<RevokeAndAck>()
        bobActions3.hasCommand<ChannelCommand.Commitment.Sign>()
        val (bob4, bobActions4) = bob3.process(ChannelCommand.Commitment.Sign)
        val sigBob = bobActions4.hasOutgoingMessage<CommitSig>()

        val (alice3, aliceActions3) = alice2.process(ChannelCommand.MessageReceived(shutdownBob))
        val shutdownAlice = aliceActions3.hasOutgoingMessage<Shutdown>()
        val (alice4, _) = alice3.process(ChannelCommand.MessageReceived(revBob))
        val (alice5, aliceActions5) = alice4.process(ChannelCommand.MessageReceived(sigBob))
        assertIs<LNChannel<Negotiating>>(alice5)
        val revAlice = aliceActions5.hasOutgoingMessage<RevokeAndAck>()
        val closingAlice = aliceActions5.hasOutgoingMessage<ClosingSigned>()

        val (bob5, _) = bob4.process(ChannelCommand.MessageReceived(shutdownAlice))
        val (bob6, _) = bob5.process(ChannelCommand.MessageReceived(revAlice))
        val (bob7, bobActions7) = bob6.process(ChannelCommand.MessageReceived(closingAlice))
        assertIs<LNChannel<Closing>>(bob7)
        val closingBob = bobActions7.hasOutgoingMessage<ClosingSigned>()
        val (alice6, _) = alice5.process(ChannelCommand.MessageReceived(closingBob))
        assertIs<LNChannel<Closing>>(alice6)
    }

    @Test
    fun `recv Shutdown -- with invalid script`() {
        val (_, bob) = reachNormal()
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(Shutdown(bob.channelId, ByteVector("00112233445566778899"))))
        assertIs<LNChannel<Closing>>(bob1)
        actions1.hasOutgoingMessage<Error>()
        assertEquals(2, actions1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        actions1.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `recv Shutdown -- with unsupported native segwit script`() {
        val (_, bob) = reachNormal(bobFeatures = TestConstants.Bob.nodeParams.features.remove(Feature.ShutdownAnySegwit))
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(Shutdown(bob.channelId, ByteVector("51050102030405"))))
        assertIs<LNChannel<Closing>>(bob1)
        actions1.hasOutgoingMessage<Error>()
        assertEquals(2, actions1.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        actions1.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `recv Shutdown -- with native segwit script`() {
        val (_, bob) = reachNormal()
        val (bob1, actions1) = bob.process(ChannelCommand.MessageReceived(Shutdown(bob.channelId, ByteVector("51050102030405"))))
        assertIs<LNChannel<Negotiating>>(bob1)
        actions1.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv Shutdown -- with invalid final script and signed htlcs + in response to a Shutdown`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (_, bob1) = crossSign(nodes.first, nodes.second)
        val (bob2, actions1) = bob1.process(ChannelCommand.Close.MutualClose(null, null))
        actions1.hasOutgoingMessage<Shutdown>()

        // actual test begins
        val (bob3, actions2) = bob2.process(ChannelCommand.MessageReceived(Shutdown(bob.channelId, ByteVector("00112233445566778899"))))
        assertIs<LNChannel<Closing>>(bob3)
        actions2.hasOutgoingMessage<Error>()
        assertEquals(2, actions2.filterIsInstance<ChannelAction.Blockchain.PublishTx>().count())
        actions2.hasWatch<WatchConfirmed>()
    }

    @Test
    fun `recv Shutdown -- with signed htlcs`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (_, bob1) = crossSign(nodes.first, nodes.second)

        // actual test begins
        val (bob2, actions1) = bob1.process(ChannelCommand.MessageReceived(Shutdown(bob.channelId, alice.commitments.params.localParams.defaultFinalScriptPubKey)))
        assertIs<LNChannel<ShuttingDown>>(bob2)
        actions1.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv Shutdown -- while waiting for a RevokeAndAck`() {
        val (alice, bob) = reachNormal()
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob)
        val (alice1, actions1) = nodes.first.process(ChannelCommand.Commitment.Sign)
        actions1.hasOutgoingMessage<CommitSig>()
        val (_, actions2) = bob.process(ChannelCommand.Close.MutualClose(null, null))
        val shutdown = actions2.findOutgoingMessage<Shutdown>()

        // actual test begins
        val (alice2, actions3) = alice1.process(ChannelCommand.MessageReceived(shutdown))
        assertIs<LNChannel<ShuttingDown>>(alice2)
        actions3.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv Shutdown -- while waiting for a RevokeAndAck with pending outgoing htlc`() {
        val (alice, bob) = reachNormal()
        // let's make bob send a Shutdown message
        val (bob1, actions1) = bob.process(ChannelCommand.Close.MutualClose(null, null))
        val shutdown = actions1.findOutgoingMessage<Shutdown>()

        // this is just so we have something to sign
        val (nodes, _, _) = addHtlc(50000000.msat, payer = alice, payee = bob1)
        val (alice1, actions2) = nodes.first.process(ChannelCommand.Commitment.Sign)
        val commitSig = actions2.findOutgoingMessage<CommitSig>()
        val (bob2, actions3) = nodes.second.process(ChannelCommand.MessageReceived(commitSig))
        val revack = actions3.findOutgoingMessage<RevokeAndAck>()

        // adding an outgoing pending htlc
        val (nodes1, _, _) = addHtlc(50000000.msat, payer = alice1, payee = bob2)

        // actual test begins
        // alice eventually gets bob's shutdown
        val (alice3, actions4) = nodes1.first.process(ChannelCommand.MessageReceived(shutdown))
        // alice can't do anything for now other than waiting for bob to send the revocation
        assertTrue(actions4.isEmpty())
        // bob sends the revocation
        val (alice4, actions5) = alice3.process(ChannelCommand.MessageReceived(revack))
        assertTrue(actions5.contains(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign)))
        // bob will also sign back
        val (bob3, actions6) = nodes1.second.process(ChannelCommand.Commitment.Sign)
        val (alice5, actions7) = alice4.process(ChannelCommand.MessageReceived(actions6.findOutgoingMessage<CommitSig>()))

        // then alice can sign the 2nd htlc
        assertTrue(actions7.contains(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign)))
        val (alice6, actions8) = alice5.process(ChannelCommand.Commitment.Sign)
        assertIs<LNChannel<Normal>>(alice6)
        val (_, actions9) = bob3.process(ChannelCommand.MessageReceived(actions8.findOutgoingMessage<CommitSig>()))
        // bob replies with the 2nd revocation
        val (alice7, actions11) = alice6.process(ChannelCommand.MessageReceived(actions9.findOutgoingMessage<RevokeAndAck>()))
        // then alice sends her shutdown
        assertIs<LNChannel<ShuttingDown>>(alice7)
        actions11.hasOutgoingMessage<Shutdown>()
    }

    @Test
    fun `recv BITCOIN_FUNDING_SPENT -- their commit with htlc`() {
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
        assertIs<LNChannel<Normal>>(alice8)
        assertIs<LNChannel<Normal>>(bob8)

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

        val bobCommitTx = bob8.commitments.latest.localCommit.publishableTxs.commitTx.tx
        assertEquals(8, bobCommitTx.txOut.size) // 2 main outputs, 4 pending htlcs and 2 anchors

        val (aliceClosing, actions) = alice8.process(ChannelCommand.WatchReceived(WatchEventSpent(alice8.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertIs<LNChannel<Closing>>(aliceClosing)
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
        assertEquals(879_710.sat, amountClaimed)

        val rcp = aliceClosing.state.remoteCommitPublished!!
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
    fun `recv BITCOIN_FUNDING_SPENT -- their next commit with htlc`() {
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
        val (alice9, actions8) = alice8.process(ChannelCommand.Commitment.Sign)
        val commitSig = actions8.findOutgoingMessage<CommitSig>()
        val (bob9, _) = bob8.process(ChannelCommand.MessageReceived(commitSig))
        assertIs<LNChannel<Normal>>(alice9)
        assertIs<LNChannel<Normal>>(bob9)

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
        val bobCommitTx = bob9.commitments.latest.localCommit.publishableTxs.commitTx.tx
        assertEquals(7, bobCommitTx.txOut.size) // 2 main outputs, 3 pending htlcs and 2 anchors

        val (aliceClosing, actions9) = alice9.process(ChannelCommand.WatchReceived(WatchEventSpent(alice9.channelId, BITCOIN_FUNDING_SPENT, bobCommitTx)))
        assertIs<LNChannel<Closing>>(aliceClosing)
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
        assertEquals(883_440.sat, amountClaimed)

        val rcp = aliceClosing.state.nextRemoteCommitPublished!!
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
    fun `recv BITCOIN_FUNDING_SPENT -- revoked commit`() {
        var (alice, bob) = reachNormal()
        // initially we have :
        // alice = 800 000 sat
        //   bob = 200 000 sat
        fun send(cmd: ChannelCommand.Htlc.Add? = null): Pair<Transaction, UpdateAddHtlc> {
            val (alice1, bob1, add) = if (cmd != null) {
                addHtlc(cmd, payer = alice, payee = bob)
            } else {
                // alice sends 10 000 sat
                val (nodes, _, add) = addHtlc(10_000_000.msat, payer = alice, payee = bob)
                Triple(nodes.first, nodes.second, add)
            }
            assertIs<LNChannel<Normal>>(alice1)
            assertIs<LNChannel<Normal>>(bob1)
            alice = alice1
            bob = bob1
            crossSign(alice, bob).run {
                assertIs<LNChannel<Normal>>(first)
                assertIs<LNChannel<Normal>>(second)
                alice = first
                bob = second
            }
            return Pair(bob.commitments.latest.localCommit.publishableTxs.commitTx.tx, add)
        }

        val (txs, adds) = run {
            // The first two HTLCs are duplicates (MPP)
            val (tx1, add1) = send()
            val (tx2, add2) = send(ChannelCommand.Htlc.Add(add1.amountMsat, add1.paymentHash, add1.cltvExpiry, add1.onionRoutingPacket, UUID.randomUUID(), commit = false))
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

        val (aliceClosing1, actions1) = alice.process(ChannelCommand.WatchReceived(WatchEventSpent(alice.channelId, BITCOIN_FUNDING_SPENT, revokedTx)))
        assertIs<LNChannel<Closing>>(aliceClosing1)
        assertEquals(1, aliceClosing1.state.revokedCommitPublished.size)
        actions1.hasOutgoingMessage<Error>()
        assertEquals(ChannelAction.Storage.GetHtlcInfos(revokedTx.txid, 4), actions1.find())

        val (aliceClosing2, actions2) = aliceClosing1.process(ChannelCommand.Closing.GetHtlcInfosResponse(revokedTx.txid, adds.take(4).map { ChannelAction.Storage.HtlcInfo(alice.channelId, 4, it.paymentHash, it.cltvExpiry) }))
        assertIs<LNChannel<Closing>>(aliceClosing2)
        assertEquals(1, aliceClosing2.state.revokedCommitPublished.size)
        assertNull(actions2.findOutgoingMessageOpt<Error>())
        assertNull(actions2.findOpt<ChannelAction.Storage.GetHtlcInfos>())

        val claimTxs = actions2.findPublishTxs()
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
        assertEquals(htlcInputs + mainPenaltyTx.txIn.first().outPoint, actions2.findWatches<WatchSpent>().map { OutPoint(it.txId, it.outputIndex.toLong()) }.toSet())

        // two main outputs are 760 000 and 200 000 (minus fees)
        assertEquals(798_070.sat, mainOutputTx.txOut[0].amount)
        assertEquals(147_580.sat, mainPenaltyTx.txOut[0].amount)
        assertEquals(7_255.sat, htlcPenaltyTxs[0].txOut[0].amount)
        assertEquals(7_255.sat, htlcPenaltyTxs[1].txOut[0].amount)
        assertEquals(7_255.sat, htlcPenaltyTxs[2].txOut[0].amount)
        assertEquals(7_255.sat, htlcPenaltyTxs[3].txOut[0].amount)
    }

    @Test
    fun `recv CheckHtlcTimeout -- no htlc timed out`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, _) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        assertIs<LNChannel<Normal>>(alice1)

        val (alice3, actions3) = alice1.process(ChannelCommand.Commitment.CheckHtlcTimeout)
        assertEquals(alice1, alice3)
        assertTrue(actions3.isEmpty())
    }

    @Test
    fun `recv CheckHtlcTimeout -- an htlc timed out`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, _, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, _) = crossSign(nodes.first, nodes.second)
        assertIs<LNChannel<Normal>>(alice1)

        // alice restarted after the htlc timed out
        val alice2 = alice1.copy(ctx = alice1.ctx.copy(currentBlockHeight = htlc.cltvExpiry.toLong().toInt()))
        val (alice3, actions) = alice2.process(ChannelCommand.Commitment.CheckHtlcTimeout)
        assertIs<LNChannel<Closing>>(alice3)
        assertNotNull(alice3.state.localCommitPublished)
        actions.hasOutgoingMessage<Error>()
        actions.has<ChannelAction.Storage.StoreState>()
        val lcp = alice3.state.localCommitPublished!!
        actions.hasPublishTx(lcp.commitTx)
        assertEquals(1, lcp.htlcTimeoutTxs().size)
        assertEquals(1, lcp.claimHtlcDelayedTxs.size)
        assertEquals(4, actions.findPublishTxs().size) // commit tx + main output + htlc-timeout + claim-htlc-delayed
        assertEquals(3, actions.findWatches<WatchConfirmed>().size) // commit tx + main output + claim-htlc-delayed
        assertEquals(1, actions.findWatches<WatchSpent>().size) // htlc-timeout
    }

    private fun checkFulfillTimeout(bob: LNChannel<ChannelState>, actions: List<ChannelAction>) {
        assertIs<LNChannel<Closing>>(bob)
        assertNotNull(bob.state.localCommitPublished)
        actions.hasOutgoingMessage<Error>()
        actions.has<ChannelAction.Storage.StoreState>()

        val lcp = bob.state.localCommitPublished!!
        assertNotNull(lcp.claimMainDelayedOutputTx)
        assertEquals(1, lcp.htlcSuccessTxs().size)
        Transaction.correctlySpends(lcp.htlcSuccessTxs().first().tx, lcp.commitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        assertEquals(1, lcp.claimHtlcDelayedTxs.size)
        Transaction.correctlySpends(lcp.claimHtlcDelayedTxs.first().tx, lcp.htlcSuccessTxs().first().tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        val txs = setOf(lcp.commitTx, lcp.claimMainDelayedOutputTx!!.tx, lcp.htlcSuccessTxs().first().tx, lcp.claimHtlcDelayedTxs.first().tx)
        assertEquals(txs, actions.findPublishTxs().toSet())
        val watchConfirmed = listOf(lcp.commitTx, lcp.claimMainDelayedOutputTx!!.tx, lcp.claimHtlcDelayedTxs.first().tx).map { it.txid }.toSet()
        assertEquals(watchConfirmed, actions.findWatches<WatchConfirmed>().map { it.txId }.toSet())
        val watchSpent = setOf(lcp.htlcSuccessTxs().first().input.outPoint)
        assertEquals(watchSpent, actions.findWatches<WatchSpent>().map { OutPoint(lcp.commitTx, it.outputIndex.toLong()) }.toSet())
    }

    @Test
    fun `recv CheckHtlcTimeout -- fulfilled signed htlc ignored by peer`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, preimage, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)

        val (bob2, actions2) = bob1.process(ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, preimage))
        actions2.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob3, actions3) = bob2.process(ChannelCommand.Commitment.Sign)
        actions3.hasOutgoingMessage<CommitSig>()

        // fulfilled htlc is close to timing out and alice still hasn't signed, so bob closes the channel
        val (bob4, actions4) = run {
            val tmp = bob3.copy(ctx = bob3.ctx.copy(currentBlockHeight = htlc.cltvExpiry.toLong().toInt() - 3))
            tmp.process(ChannelCommand.Commitment.CheckHtlcTimeout)
        }
        checkFulfillTimeout(bob4, actions4)
    }

    @Test
    fun `recv NewBlock -- fulfilled proposed htlc ignored by peer`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, preimage, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (_, bob1) = crossSign(nodes.first, nodes.second)

        val (bob2, actions2) = bob1.process(ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, preimage))
        actions2.hasOutgoingMessage<UpdateFulfillHtlc>()

        // bob restarts when the fulfilled htlc is close to timing out
        val bob3 = bob2.copy(ctx = bob2.ctx.copy(currentBlockHeight = htlc.cltvExpiry.toLong().toInt() - 3))
        // alice still hasn't signed, so bob closes the channel
        val (bob4, actions4) = bob3.process(ChannelCommand.Commitment.CheckHtlcTimeout)
        checkFulfillTimeout(bob4, actions4)
    }

    @Test
    fun `recv NewBlock -- fulfilled proposed htlc acked but not committed by peer`() {
        val (alice0, bob0) = reachNormal()
        val (nodes, preimage, htlc) = addHtlc(50_000_000.msat, alice0, bob0)
        val (alice1, bob1) = crossSign(nodes.first, nodes.second)

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.Htlc.Settlement.Fulfill(htlc.id, preimage))
        val fulfill = actionsBob2.hasOutgoingMessage<UpdateFulfillHtlc>()
        val (bob3, actionsBob3) = bob2.process(ChannelCommand.Commitment.Sign)
        val commitSig = actionsBob3.hasOutgoingMessage<CommitSig>()
        val (alice2, _) = alice1.process(ChannelCommand.MessageReceived(fulfill))
        val (_, actionsAlice3) = alice2.process(ChannelCommand.MessageReceived(commitSig))
        val ack = actionsAlice3.hasOutgoingMessage<RevokeAndAck>()
        val (bob4, _) = bob3.process(ChannelCommand.MessageReceived(ack))

        // fulfilled htlc is close to timing out and alice has revoked her previous commitment but not signed the new one, so bob closes the channel
        val (bob5, actions5) = run {
            val tmp = bob4.copy(ctx = bob4.ctx.copy(currentBlockHeight = htlc.cltvExpiry.toLong().toInt() - 3))
            tmp.process(ChannelCommand.Commitment.CheckHtlcTimeout)
        }
        checkFulfillTimeout(bob5, actions5)
    }

    @Test
    fun `recv Disconnected`() {
        val (alice0, _) = reachNormal()
        val (alice1, _) = alice0.process(ChannelCommand.Disconnected)
        assertIs<LNChannel<Offline>>(alice1)
        val previousState = alice1.state.state
        assertIs<Normal>(previousState)
        assertEquals(alice0.state.channelUpdate, previousState.channelUpdate)
    }

    @Test
    fun `recv Disconnected -- with htlcs`() {
        val (alice0, bob0) = reachNormal()
        val (nodes0, _, htlc1) = addHtlc(250_000_000.msat, payer = alice0, payee = bob0)
        val (alice1, bob1) = nodes0
        val (nodes1, _, htlc2) = addHtlc(250_000_000.msat, payer = alice1, payee = bob1)
        val (alice2, _) = nodes1

        val (alice3, actions) = alice2.process(ChannelCommand.Disconnected)
        assertIs<LNChannel<Offline>>(alice3)

        val addSettledFailList = actions.filterIsInstance<ChannelAction.ProcessCmdRes.AddSettledFail>()
        assertEquals(2, addSettledFailList.size)
        assertTrue(addSettledFailList.all { it.result is ChannelAction.HtlcResult.Fail.Disconnected })
        assertEquals(htlc1.paymentHash, addSettledFailList.first().htlc.paymentHash)
        assertEquals(htlc2.paymentHash, addSettledFailList.last().htlc.paymentHash)
        assertEquals(alice2.state, alice3.state.state)
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
        assertIs<LNChannel<Normal>>(alice3)
        val aliceCommitTx = alice3.commitments.latest.localCommit.publishableTxs.commitTx
        val (alice4, actions) = alice3.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertIs<LNChannel<Closing>>(alice4)
        assertNotNull(alice4.state.localCommitPublished)
        assertEquals(alice4.state.localCommitPublished!!.commitTx, aliceCommitTx.tx)
        assertEquals(4, alice4.state.localCommitPublished!!.htlcTxs.size)
        assertEquals(1, alice4.state.localCommitPublished!!.htlcSuccessTxs().size)
        assertEquals(2, alice4.state.localCommitPublished!!.htlcTimeoutTxs().size)
        assertEquals(3, alice4.state.localCommitPublished!!.claimHtlcDelayedTxs.size)

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
    fun `receive Error -- nothing at stake`() {
        val (_, bob0) = reachNormal(bobFundingAmount = 0.sat)
        val bobCommitTx = bob0.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (bob1, actions) = bob0.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        val txs = actions.filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }
        assertEquals(txs, listOf(bobCommitTx))
        assertIs<Closing>(bob1.state)
        assertEquals(bob1.state.localCommitPublished!!.commitTx, bobCommitTx)
    }
}
