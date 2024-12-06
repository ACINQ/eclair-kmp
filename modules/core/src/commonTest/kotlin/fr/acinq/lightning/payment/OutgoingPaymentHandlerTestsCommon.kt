package fr.acinq.lightning.payment

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Chain
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.states.Offline
import fr.acinq.lightning.crypto.sphinx.FailurePacket
import fr.acinq.lightning.crypto.sphinx.Sphinx
import fr.acinq.lightning.db.InMemoryPaymentsDb
import fr.acinq.lightning.db.LightningOutgoingPayment
import fr.acinq.lightning.db.OutgoingPaymentsDb
import fr.acinq.lightning.io.PayInvoice
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import kotlin.test.*

class OutgoingPaymentHandlerTestsCommon : LightningTestSuite() {

    private val defaultWalletParams = WalletParams(
        NodeUri(TestConstants.Bob.nodeParams.nodeId, "bob.com", 9735),
        TestConstants.trampolineFees,
        InvoiceDefaultRoutingFees(1_000.msat, 100, CltvExpiryDelta(144)),
        TestConstants.swapInParams,
    )

    @Test
    fun `invalid payment amount`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val invoice = makeInvoice(amount = 100_000.msat, supportsTrampoline = true)
        val outgoingPaymentHandler = OutgoingPaymentHandler(alice.staticParams.nodeParams, defaultWalletParams, InMemoryPaymentsDb())
        val payment = PayInvoice(UUID.randomUUID(), MilliSatoshi(-1), LightningOutgoingPayment.Details.Normal(invoice))
        val result = outgoingPaymentHandler.sendPayment(payment, mapOf(), alice.currentBlockHeight)
        assertFailureEquals(result as OutgoingPaymentHandler.Failure, OutgoingPaymentHandler.Failure(payment, FinalFailure.InvalidPaymentAmount.toPaymentFailure()))
        assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
        assertNull(outgoingPaymentHandler.db.getLightningOutgoingPayment(payment.paymentId))
    }

    @Test
    fun `features not supported`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val features = Features(
            Feature.ChannelType to FeatureSupport.Mandatory,
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
            Feature.BasicMultiPartPayment to FeatureSupport.Optional,
            Feature.DualFunding to FeatureSupport.Mandatory,
            Feature.RouteBlinding to FeatureSupport.Optional,
        )
        // The following invoice requires payment_metadata.
        val invoice1 = run {
            val unsupportedFeatures = Features(
                Feature.VariableLengthOnion to FeatureSupport.Mandatory,
                Feature.PaymentSecret to FeatureSupport.Mandatory,
                Feature.PaymentMetadata to FeatureSupport.Mandatory
            )
            Bolt11InvoiceTestsCommon.createInvoiceUnsafe(features = unsupportedFeatures)
        }
        // The following invoice requires unknown feature bit 188.
        val invoice2 = run {
            val unsupportedFeatures = Features(
                mapOf(
                    Feature.VariableLengthOnion to FeatureSupport.Mandatory,
                    Feature.PaymentSecret to FeatureSupport.Mandatory
                ),
                setOf(UnknownFeature(188))
            )
            Bolt11InvoiceTestsCommon.createInvoiceUnsafe(features = unsupportedFeatures)
        }
        for (invoice in listOf(invoice1, invoice2)) {
            val outgoingPaymentHandler = OutgoingPaymentHandler(alice.staticParams.nodeParams.copy(features = features), defaultWalletParams, InMemoryPaymentsDb())
            val payment = PayInvoice(UUID.randomUUID(), 15_000.msat, LightningOutgoingPayment.Details.Normal(invoice))
            val result = outgoingPaymentHandler.sendPayment(payment, mapOf(), alice.currentBlockHeight)
            assertFailureEquals(result as OutgoingPaymentHandler.Failure, OutgoingPaymentHandler.Failure(payment, FinalFailure.FeaturesNotSupported.toPaymentFailure()))
            assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
            assertNull(outgoingPaymentHandler.db.getLightningOutgoingPayment(payment.paymentId))
        }
    }

    @Test
    fun `no available channels`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val invoice = makeInvoice(amount = 100_000.msat, supportsTrampoline = true)
        val outgoingPaymentHandler = OutgoingPaymentHandler(alice.staticParams.nodeParams, defaultWalletParams, InMemoryPaymentsDb())
        val payment = PayInvoice(UUID.randomUUID(), 100_000.msat, LightningOutgoingPayment.Details.Normal(invoice))
        val result = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to Offline(alice.state)), alice.currentBlockHeight)
        assertFailureEquals(result as OutgoingPaymentHandler.Failure, OutgoingPaymentHandler.Failure(payment, FinalFailure.ChannelNotConnected.toPaymentFailure()))
        assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))

        val dbPayment = outgoingPaymentHandler.db.getLightningOutgoingPayment(payment.paymentId)
        assertNotNull(dbPayment)
        assertEquals(100_000.msat, dbPayment.recipientAmount)
        assertEquals(invoice.nodeId, dbPayment.recipient)
        assertTrue(dbPayment.status is LightningOutgoingPayment.Status.Completed.Failed)
        assertEquals(FinalFailure.ChannelNotConnected, (dbPayment.status as LightningOutgoingPayment.Status.Completed.Failed).reason)
        assertTrue(dbPayment.parts.isEmpty())
    }

    @Test
    fun `insufficient funds`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val amount = alice.commitments.availableBalanceForSend() + 10.msat
        val invoice = makeInvoice(amount = amount, supportsTrampoline = true)
        val outgoingPaymentHandler = OutgoingPaymentHandler(alice.staticParams.nodeParams, defaultWalletParams, InMemoryPaymentsDb())
        val payment = PayInvoice(UUID.randomUUID(), amount, LightningOutgoingPayment.Details.Normal(invoice))
        val result = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), alice.currentBlockHeight)
        assertFailureEquals(result as OutgoingPaymentHandler.Failure, OutgoingPaymentHandler.Failure(payment, FinalFailure.InsufficientBalance.toPaymentFailure()))
        assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))

        val dbPayment = outgoingPaymentHandler.db.getLightningOutgoingPayment(payment.paymentId)
        assertNotNull(dbPayment)
        assertEquals(amount, dbPayment.recipientAmount)
        assertTrue(dbPayment.status is LightningOutgoingPayment.Status.Completed.Failed)
        assertEquals(FinalFailure.InsufficientBalance, (dbPayment.status as LightningOutgoingPayment.Status.Completed.Failed).reason)
        assertTrue(dbPayment.parts.isEmpty())
    }

    @Test
    fun `invoice already paid`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, defaultWalletParams, InMemoryPaymentsDb())
        val invoice = makeInvoice(amount = 100_000.msat, supportsTrampoline = true)
        val payment = PayInvoice(UUID.randomUUID(), 100_000.msat, LightningOutgoingPayment.Details.Normal(invoice))
        val result = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight) as OutgoingPaymentHandler.Progress
        val (channelId, add) = findAddHtlcCommand(result)
        outgoingPaymentHandler.processAddSettledFulfilled(createRemoteFulfill(channelId, add, randomBytes32())) as OutgoingPaymentHandler.Success

        val duplicatePayment = payment.copy(paymentId = UUID.randomUUID())
        val error = outgoingPaymentHandler.sendPayment(duplicatePayment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight) as OutgoingPaymentHandler.Failure
        assertEquals(error.failure.reason, FinalFailure.AlreadyPaid)
    }

    @Test
    fun `channel restrictions -- maxAcceptedHtlcs`() = runSuspendTest {
        var (alice, _) = TestsHelper.reachNormal()
        alice = alice.copy(state = alice.state.copy(commitments = alice.commitments.copy(params = alice.commitments.params.copy(remoteParams = alice.commitments.params.remoteParams.copy(maxAcceptedHtlcs = 1)))))
        val outgoingPaymentHandler = OutgoingPaymentHandler(alice.staticParams.nodeParams, defaultWalletParams, InMemoryPaymentsDb())

        run {
            // Send payment 1 of 2: this should work because we're still under the maxAcceptedHtlcs.
            val invoice = makeInvoice(amount = null, supportsTrampoline = true)
            val payment = PayInvoice(UUID.randomUUID(), 100_000.msat, LightningOutgoingPayment.Details.Normal(invoice))
            val progress = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), alice.currentBlockHeight)
            assertIs<OutgoingPaymentHandler.Progress>(progress)
            assertEquals(1, progress.actions.size)

            val (alice1, actions1) = alice.processSameState(progress.actions.first().channelCommand)
            assertTrue(actions1.filterIsInstance<ChannelAction.ProcessCmdRes>().isEmpty())
            alice = alice1
            assertNotNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))

            val dbPayment = outgoingPaymentHandler.db.getLightningOutgoingPayment(payment.paymentId)
            assertNotNull(dbPayment)
            assertEquals(LightningOutgoingPayment.Status.Pending, dbPayment.status)
            assertEquals(1, dbPayment.parts.size)
            assertTrue(dbPayment.parts.all { it.status is LightningOutgoingPayment.Part.Status.Pending })
        }
        run {
            // Send payment 2 of 2: this should exceed the configured maxAcceptedHtlcs.
            val invoice = makeInvoice(amount = null, supportsTrampoline = true)
            val payment = PayInvoice(UUID.randomUUID(), 50_000.msat, LightningOutgoingPayment.Details.Normal(invoice))
            val progress = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), alice.currentBlockHeight)
            assertIs<OutgoingPaymentHandler.Progress>(progress)
            assertEquals(1, progress.actions.size)

            val cmdAdd = progress.actions.first().channelCommand
            val (_, actions1) = alice.processSameState(cmdAdd)
            val addFailure = actions1.filterIsInstance<ChannelAction.ProcessCmdRes.AddFailed>().firstOrNull()
            assertNotNull(addFailure)
            // Now the channel error gets sent back to the OutgoingPaymentHandler.
            val failure = outgoingPaymentHandler.processAddFailed(alice.channelId, addFailure)
            val expected = OutgoingPaymentHandler.Failure(payment, OutgoingPaymentFailure(FinalFailure.NoAvailableChannels, listOf(Either.Left(TooManyAcceptedHtlcs(alice.channelId, 1)))))
            assertFailureEquals(failure as OutgoingPaymentHandler.Failure, expected)

            assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
            assertDbPaymentFailed(outgoingPaymentHandler.db, payment.paymentId, 1)
        }
    }

    @Test
    fun `channel restrictions -- maxHtlcValueInFlight`() = runSuspendTest {
        var (alice, _) = TestsHelper.reachNormal()
        val maxHtlcValueInFlightMsat = 150_000L
        alice = alice.copy(
            state = alice.state.copy(commitments = alice.commitments.copy(params = alice.commitments.params.copy(remoteParams = alice.commitments.params.remoteParams.copy(maxHtlcValueInFlightMsat = maxHtlcValueInFlightMsat))))
        )
        val outgoingPaymentHandler = OutgoingPaymentHandler(alice.staticParams.nodeParams, defaultWalletParams, InMemoryPaymentsDb())

        run {
            // Send payment 1 of 2: this should work because we're still under the maxHtlcValueInFlightMsat.
            val invoice = makeInvoice(amount = null, supportsTrampoline = true)
            val payment = PayInvoice(UUID.randomUUID(), 100_000.msat, LightningOutgoingPayment.Details.Normal(invoice))
            val progress = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), alice.currentBlockHeight)
            assertIs<OutgoingPaymentHandler.Progress>(progress)
            assertEquals(1, progress.actions.size)

            val (alice1, actions1) = alice.processSameState(progress.actions.first().channelCommand)
            assertTrue(actions1.filterIsInstance<ChannelAction.ProcessCmdRes>().isEmpty())
            alice = alice1
            assertNotNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))

            val dbPayment = outgoingPaymentHandler.db.getLightningOutgoingPayment(payment.paymentId)
            assertNotNull(dbPayment)
            assertEquals(LightningOutgoingPayment.Status.Pending, dbPayment.status)
            assertEquals(1, dbPayment.parts.size)
            assertTrue(dbPayment.parts.all { it.status is LightningOutgoingPayment.Part.Status.Pending })
        }
        run {
            // Send payment 2 of 2: this should exceed the configured maxHtlcValueInFlightMsat.
            val invoice = makeInvoice(amount = null, supportsTrampoline = true)
            val payment = PayInvoice(UUID.randomUUID(), 100_000.msat, LightningOutgoingPayment.Details.Normal(invoice))
            val progress = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), alice.currentBlockHeight)
            assertIs<OutgoingPaymentHandler.Progress>(progress)
            assertEquals(1, progress.actions.size)

            val cmdAdd = progress.actions.first().channelCommand
            val (_, actions1) = alice.processSameState(cmdAdd)
            val addFailure = actions1.filterIsInstance<ChannelAction.ProcessCmdRes.AddFailed>().firstOrNull()
            assertNotNull(addFailure)
            // Now the channel error gets sent back to the OutgoingPaymentHandler.
            val failure = outgoingPaymentHandler.processAddFailed(alice.channelId, addFailure)
            val expected = OutgoingPaymentHandler.Failure(payment, OutgoingPaymentFailure(FinalFailure.NoAvailableChannels, listOf(Either.Left(HtlcValueTooHighInFlight(alice.channelId, maxHtlcValueInFlightMsat.toULong(), 200_000.msat)))))
            assertFailureEquals(failure as OutgoingPaymentHandler.Failure, expected)

            assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
            assertDbPaymentFailed(outgoingPaymentHandler.db, payment.paymentId, 1)
        }
    }

    @Test
    fun `successful first attempt`() = runSuspendTest {
        val recipientKey = randomKey()
        val invoice = makeInvoice(amount = 195_000.msat, supportsTrampoline = true, privKey = recipientKey)
        val payment = PayInvoice(UUID.randomUUID(), 200_000.msat, LightningOutgoingPayment.Details.Normal(invoice)) // we slightly overpay the invoice amount
        val (alice, _) = TestsHelper.reachNormal()
        val walletParams = defaultWalletParams.copy(trampolineFees = listOf(TrampolineFees(3.sat, 10_000, CltvExpiryDelta(144))))
        val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, walletParams, InMemoryPaymentsDb())

        val result = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight) as OutgoingPaymentHandler.Progress
        val (channelId, add) = findAddHtlcCommand(result)
        assertEquals(205_000.msat, add.amount)
        assertEquals(payment.paymentHash, add.paymentHash)

        // The trampoline node should receive the right forwarding information.
        val (outerB, innerB, packetC) = PaymentPacketTestsCommon.decryptRelayToTrampoline(makeUpdateAddHtlc(channelId, add), TestConstants.Bob.nodeParams.nodePrivateKey)
        assertEquals(205_000.msat, outerB.amount)
        assertEquals(205_000.msat, outerB.totalAmount)
        assertEquals(CltvExpiry(TestConstants.defaultBlockHeight.toLong()) + CltvExpiryDelta(144) + Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA, outerB.expiry)
        assertEquals(200_000.msat, innerB.amountToForward)
        assertEquals(CltvExpiry(TestConstants.defaultBlockHeight.toLong()) + Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA, innerB.outgoingCltv)
        assertEquals(payment.recipient, innerB.outgoingNodeId)

        // The recipient should receive the right amount and expiry.
        val payloadBytesC = Sphinx.peel(recipientKey, payment.paymentHash, packetC).right!!
        val payloadC = PaymentOnion.FinalPayload.Standard.read(payloadBytesC.payload).right!!
        assertEquals(200_000.msat, payloadC.amount)
        assertEquals(CltvExpiry(TestConstants.defaultBlockHeight.toLong()) + Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA, payloadC.expiry)
        assertEquals(payloadC.amount, payloadC.totalAmount)
        assertEquals(invoice.paymentSecret, payloadC.paymentSecret)

        val preimage = randomBytes32()
        val success = outgoingPaymentHandler.processAddSettledFulfilled(createRemoteFulfill(channelId, add, preimage)) as OutgoingPaymentHandler.Success
        assertEquals(preimage, success.preimage)
        assertEquals(5_000.msat, success.payment.fees)
        assertEquals(200_000.msat, success.payment.recipientAmount)
        assertEquals(invoice.nodeId, success.payment.recipient)
        assertEquals(invoice.paymentHash, success.payment.paymentHash)
        assertEquals(invoice, (success.payment.details as LightningOutgoingPayment.Details.Normal).paymentRequest)
        assertEquals(preimage, (success.payment.status as LightningOutgoingPayment.Status.Completed.Succeeded.OffChain).preimage)
        assertEquals(1, success.payment.parts.size)
        val part = success.payment.parts.first()
        assertNotEquals(part.id, payment.paymentId)
        assertEquals(205_000.msat, part.amount)
        assertEquals(preimage, (part.status as LightningOutgoingPayment.Part.Status.Succeeded).preimage)

        assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
        assertDbPaymentSucceeded(outgoingPaymentHandler.db, payment.paymentId, amount = 200_000.msat, fees = 5_000.msat, partsCount = 1)
    }

    @Test
    fun `successful first attempt -- legacy recipient`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val walletParams = defaultWalletParams.copy(trampolineFees = listOf(TrampolineFees(10.sat, 0, CltvExpiryDelta(144))))
        val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, walletParams, InMemoryPaymentsDb())
        val recipientKey = randomKey()
        val extraHops = listOf(listOf(Bolt11Invoice.TaggedField.ExtraHop(randomKey().publicKey(), ShortChannelId(42), 10.msat, 100, CltvExpiryDelta(48))))
        val invoice = makeInvoice(amount = null, supportsTrampoline = false, privKey = recipientKey, extraHops = extraHops)
        val payment = PayInvoice(UUID.randomUUID(), 300_000.msat, LightningOutgoingPayment.Details.Normal(invoice))

        val result = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight) as OutgoingPaymentHandler.Progress
        val (channelId, add) = findAddHtlcCommand(result)
        assertEquals(310_000.msat, add.amount)
        assertEquals(payment.paymentHash, add.paymentHash)
        // The trampoline node should receive the right forwarding information.
        val (outerB, innerB) = PaymentPacketTestsCommon.decryptRelayToLegacy(makeUpdateAddHtlc(channelId, add), TestConstants.Bob.nodeParams.nodePrivateKey)
        assertEquals(add.amount, outerB.amount)
        assertEquals(310_000.msat, outerB.totalAmount)
        assertEquals(CltvExpiry(TestConstants.defaultBlockHeight.toLong()) + CltvExpiryDelta(144) + Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA, outerB.expiry)
        assertEquals(300_000.msat, innerB.amountToForward)
        assertEquals(CltvExpiry(TestConstants.defaultBlockHeight.toLong()) + Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA, innerB.outgoingCltv)
        assertEquals(payment.recipient, innerB.outgoingNodeId)
        assertEquals(invoice.paymentSecret, outerB.paymentSecret)
        assertEquals(invoice.features.toByteArray().toByteVector(), innerB.invoiceFeatures)
        assertEquals(invoice.routingInfo.map { it.hints }, innerB.invoiceRoutingInfo)

        val preimage = randomBytes32()
        val success = outgoingPaymentHandler.processAddSettledFulfilled(createRemoteFulfill(channelId, add, preimage))
        assertNotNull(success)
        assertEquals(preimage, success.preimage)
        assertEquals(10_000.msat, success.payment.fees)
        assertEquals(300_000.msat, success.payment.recipientAmount)
        assertEquals(invoice.nodeId, success.payment.recipient)
        assertEquals(invoice.paymentHash, success.payment.paymentHash)
        assertEquals(invoice, (success.payment.details as LightningOutgoingPayment.Details.Normal).paymentRequest)
        assertEquals(preimage, (success.payment.status as LightningOutgoingPayment.Status.Completed.Succeeded.OffChain).preimage)
        assertEquals(1, success.payment.parts.size)
        assertEquals(310_000.msat, success.payment.parts.first().amount)
        val status = success.payment.parts.first().status
        assertIs<LightningOutgoingPayment.Part.Status.Succeeded>(status)
        assertEquals(preimage, status.preimage)

        assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
        assertDbPaymentSucceeded(outgoingPaymentHandler.db, payment.paymentId, amount = 300_000.msat, fees = 10_000.msat, partsCount = 1)
    }

    @Test
    fun `successful first attempt -- random final expiry`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val walletParams = defaultWalletParams.copy(trampolineFees = listOf(TrampolineFees(25.sat, 0, CltvExpiryDelta(48))))
        val recipientExpiryParams = RecipientCltvExpiryParams(CltvExpiryDelta(144), CltvExpiryDelta(288))
        val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams.copy(paymentRecipientExpiryParams = recipientExpiryParams), walletParams, InMemoryPaymentsDb())
        val recipientKey = randomKey()
        val invoice = makeInvoice(amount = null, supportsTrampoline = true, privKey = recipientKey)
        val payment = PayInvoice(UUID.randomUUID(), 300_000.msat, LightningOutgoingPayment.Details.Normal(invoice))

        val result = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight) as OutgoingPaymentHandler.Progress
        val (channelId, add) = findAddHtlcCommand(result)
        // The trampoline node should receive the right forwarding information.
        val (outerB, innerB, packetC) = PaymentPacketTestsCommon.decryptRelayToTrampoline(makeUpdateAddHtlc(channelId, add), TestConstants.Bob.nodeParams.nodePrivateKey)
        assertEquals(add.amount, outerB.amount)
        val minFinalExpiry = CltvExpiry(TestConstants.defaultBlockHeight.toLong()) + Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA + recipientExpiryParams.min
        assertTrue(minFinalExpiry + CltvExpiryDelta(48) <= outerB.expiry)
        assertTrue(minFinalExpiry <= innerB.outgoingCltv)

        // The recipient should receive the right amount and expiry.
        val payloadBytesC = Sphinx.peel(recipientKey, payment.paymentHash, packetC).right!!
        val payloadC = PaymentOnion.FinalPayload.Standard.read(payloadBytesC.payload).right!!
        assertEquals(300_000.msat, payloadC.amount)
        assertTrue(minFinalExpiry <= payloadC.expiry)
        assertEquals(innerB.outgoingCltv, payloadC.expiry)
    }

    @Test
    fun `successful second attempt`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, defaultWalletParams, InMemoryPaymentsDb())
        val recipientKey = randomKey()
        val invoice = makeInvoice(amount = null, supportsTrampoline = true, privKey = recipientKey)
        val payment = PayInvoice(UUID.randomUUID(), 300_000.msat, LightningOutgoingPayment.Details.Normal(invoice))

        val progress1 = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
        assertIs<OutgoingPaymentHandler.Progress>(progress1)
        val (channelId1, add1) = findAddHtlcCommand(progress1)
        assertEquals(alice.channelId, channelId1)
        assertEquals(300_000.msat, add1.amount)

        // This first attempt fails because fees are too low.
        val attempt = outgoingPaymentHandler.getPendingPayment(payment.paymentId)!!
        val progress2 = outgoingPaymentHandler.processAddSettledFailed(
            channelId1,
            createTrampolineFailure(add1, attempt, TrampolineFeeOrExpiryInsufficient(100.msat, 100, CltvExpiryDelta(48))),
            mapOf(alice.channelId to alice.state),
            TestConstants.defaultBlockHeight
        )
        assertIs<OutgoingPaymentHandler.Progress>(progress2)
        val (channelId2, add2) = findAddHtlcCommand(progress2)
        assertEquals(channelId1, channelId2)
        assertEquals(301_030.msat, add2.amount)
        assertEquals(payment.paymentHash, add2.paymentHash)
        // The trampoline node should receive the right forwarding information.
        val (outerB, innerB, packetC) = PaymentPacketTestsCommon.decryptRelayToTrampoline(makeUpdateAddHtlc(channelId2, add2), TestConstants.Bob.nodeParams.nodePrivateKey)
        assertEquals(add2.amount, outerB.amount)
        assertEquals(301_030.msat, outerB.totalAmount)
        assertEquals(CltvExpiry(TestConstants.defaultBlockHeight.toLong()) + CltvExpiryDelta(576) + Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA, outerB.expiry)
        assertEquals(300_000.msat, innerB.amountToForward)
        assertEquals(CltvExpiry(TestConstants.defaultBlockHeight.toLong()) + Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA, innerB.outgoingCltv)
        assertEquals(payment.recipient, innerB.outgoingNodeId)

        // The recipient should receive the right amount and expiry.
        val payloadBytesC = Sphinx.peel(recipientKey, payment.paymentHash, packetC).right!!
        val payloadC = PaymentOnion.FinalPayload.Standard.read(payloadBytesC.payload).right!!
        assertEquals(300_000.msat, payloadC.amount)
        assertEquals(CltvExpiry(TestConstants.defaultBlockHeight.toLong()) + Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA, payloadC.expiry)
        assertEquals(payloadC.amount, payloadC.totalAmount)
        assertEquals(invoice.paymentSecret, payloadC.paymentSecret)

        val dbPayment1 = outgoingPaymentHandler.db.getLightningOutgoingPayment(payment.paymentId)
        assertNotNull(dbPayment1)
        assertIs<LightningOutgoingPayment.Status.Pending>(dbPayment1.status)
        assertEquals(1, dbPayment1.parts.filter { it.status is LightningOutgoingPayment.Part.Status.Failed }.size)
        assertEquals(1, dbPayment1.parts.filter { it.status is LightningOutgoingPayment.Part.Status.Pending }.size)

        // The second attempt succeeds.
        val preimage = randomBytes32()
        val success = outgoingPaymentHandler.processAddSettledFulfilled(createRemoteFulfill(channelId2, add2, preimage))
        assertIs<OutgoingPaymentHandler.Success>(success)
        assertEquals(preimage, success.preimage)
        assertEquals(1_030.msat, success.payment.fees)
        assertEquals(300_000.msat, success.payment.recipientAmount)
        assertEquals(invoice.nodeId, success.payment.recipient)
        assertEquals(invoice.paymentHash, success.payment.paymentHash)
        assertEquals(invoice, (success.payment.details as LightningOutgoingPayment.Details.Normal).paymentRequest)
        assertEquals(preimage, (success.payment.status as LightningOutgoingPayment.Status.Completed.Succeeded.OffChain).preimage)
        assertEquals(1, success.payment.parts.size)
        assertEquals(301_030.msat, success.payment.parts.first().amount)
        val status = success.payment.parts.first().status
        assertIs<LightningOutgoingPayment.Part.Status.Succeeded>(status)
        assertEquals(preimage, status.preimage)

        assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
        val dbPayment2 = outgoingPaymentHandler.db.getLightningOutgoingPayment(payment.paymentId)
        assertNotNull(dbPayment2)
        assertIs<LightningOutgoingPayment.Status.Completed.Succeeded.OffChain>(dbPayment2.status)
        assertEquals(1, dbPayment2.parts.size)
        assertTrue(dbPayment2.parts.all { it.status is LightningOutgoingPayment.Part.Status.Succeeded })
    }

    @Test
    fun `insufficient funds when retrying with higher fees`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal(aliceFundingAmount = 100_000.sat, bobFundingAmount = 0.sat)
        assertTrue(83_500_000.msat < alice.commitments.availableBalanceForSend())
        assertTrue(alice.commitments.availableBalanceForSend() < 84_000_000.msat)
        val walletParams = defaultWalletParams.copy(
            trampolineFees = listOf(
                TrampolineFees(100.sat, 0, CltvExpiryDelta(144)),
                TrampolineFees(1000.sat, 0, CltvExpiryDelta(144)),
            )
        )
        val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, walletParams, InMemoryPaymentsDb())
        val invoice = makeInvoice(amount = null, supportsTrampoline = true)
        val payment = PayInvoice(UUID.randomUUID(), 83_000_000.msat, LightningOutgoingPayment.Details.Normal(invoice))

        val progress = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
        assertIs<OutgoingPaymentHandler.Progress>(progress)
        val (_, add1) = findAddHtlcCommand(progress)
        assertEquals(83_100_000.msat, add1.amount)

        val attempt = outgoingPaymentHandler.getPendingPayment(payment.paymentId)!!
        val fail = outgoingPaymentHandler.processAddSettledFailed(
            alice.channelId,
            createTrampolineFailure(add1, attempt, TrampolineFeeOrExpiryInsufficient(100.msat, 100, CltvExpiryDelta(48))),
            mapOf(alice.channelId to alice.state),
            TestConstants.defaultBlockHeight
        )
        assertIs<OutgoingPaymentHandler.Failure>(fail)
        val expected = OutgoingPaymentHandler.Failure(payment, OutgoingPaymentFailure(FinalFailure.InsufficientBalance, listOf(Either.Right(TrampolineFeeOrExpiryInsufficient(100.msat, 100, CltvExpiryDelta(48))))))
        assertFailureEquals(expected, fail)

        assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
        assertDbPaymentFailed(outgoingPaymentHandler.db, payment.paymentId, 1)
    }

    @Test
    fun `retries exhausted`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val walletParams = defaultWalletParams.copy(
            trampolineFees = listOf(
                TrampolineFees(10.sat, 0, CltvExpiryDelta(144)),
                TrampolineFees(20.sat, 0, CltvExpiryDelta(144)),
            )
        )
        val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, walletParams, InMemoryPaymentsDb())
        val invoice = makeInvoice(amount = null, supportsTrampoline = true)
        val payment = PayInvoice(UUID.randomUUID(), 220_000.msat, LightningOutgoingPayment.Details.Normal(invoice))

        val progress1 = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
        assertIs<OutgoingPaymentHandler.Progress>(progress1)
        val (_, add1) = findAddHtlcCommand(progress1)
        assertEquals(230_000.msat, add1.amount)

        val attempt1 = outgoingPaymentHandler.getPendingPayment(payment.paymentId)!!
        val progress2 = outgoingPaymentHandler.processAddSettledFailed(
            alice.channelId,
            createTrampolineFailure(add1, attempt1, TrampolineFeeOrExpiryInsufficient(100.msat, 100, CltvExpiryDelta(48))),
            mapOf(alice.channelId to alice.state),
            TestConstants.defaultBlockHeight
        )
        assertIs<OutgoingPaymentHandler.Progress>(progress2)
        val (_, add2) = findAddHtlcCommand(progress2)
        assertEquals(240_000.msat, add2.amount)

        val attempt2 = outgoingPaymentHandler.getPendingPayment(payment.paymentId)!!
        val fail = outgoingPaymentHandler.processAddSettledFailed(alice.channelId, createTrampolineFailure(add2, attempt2, TemporaryTrampolineFailure), mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
        assertIs<OutgoingPaymentHandler.Failure>(fail)
        val expected = OutgoingPaymentHandler.Failure(
            payment,
            OutgoingPaymentFailure(FinalFailure.RetryExhausted, listOf(Either.Right(TrampolineFeeOrExpiryInsufficient(100.msat, 100, CltvExpiryDelta(48))), Either.Right(TemporaryTrampolineFailure)))
        )
        assertFailureEquals(expected, fail)

        assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
        assertDbPaymentFailed(outgoingPaymentHandler.db, payment.paymentId, 2)
    }

    @Test
    fun `non-retriable trampoline node failure`() = runSuspendTest {
        val fatalFailures = listOf(
            Pair(UnknownNextPeer, FinalFailure.RecipientUnreachable),
            Pair(UnknownNextTrampoline, FinalFailure.RecipientUnreachable),
            Pair(TemporaryNodeFailure, FinalFailure.UnknownError)
        )
        fatalFailures.forEach { (remoteFailure, userFailure) ->
            val (alice, _) = TestsHelper.reachNormal()
            val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, defaultWalletParams, InMemoryPaymentsDb())
            val invoice = makeInvoice(amount = null, supportsTrampoline = true)
            val payment = PayInvoice(UUID.randomUUID(), 50_000.msat, LightningOutgoingPayment.Details.Normal(invoice))

            val progress = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
            assertIs<OutgoingPaymentHandler.Progress>(progress)
            val (_, add) = findAddHtlcCommand(progress)
            assertEquals(50_000.msat, add.amount)

            val attempt = outgoingPaymentHandler.getPendingPayment(payment.paymentId)!!
            val fail = outgoingPaymentHandler.processAddSettledFailed(alice.channelId, createTrampolineFailure(add, attempt, remoteFailure), mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
            assertIs<OutgoingPaymentHandler.Failure>(fail)
            val expected = OutgoingPaymentHandler.Failure(payment, OutgoingPaymentFailure(userFailure, listOf(Either.Right(remoteFailure))))
            assertFailureEquals(expected, fail)

            assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
            assertDbPaymentFailed(outgoingPaymentHandler.db, payment.paymentId, 1)
        }
    }

    @Test
    fun `recipient failure`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, defaultWalletParams, InMemoryPaymentsDb())
        val invoice = makeInvoice(amount = null, supportsTrampoline = true)
        val payment = PayInvoice(UUID.randomUUID(), 50_000.msat, LightningOutgoingPayment.Details.Normal(invoice))

        val progress = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
        assertIs<OutgoingPaymentHandler.Progress>(progress)
        val (_, add) = findAddHtlcCommand(progress)
        assertEquals(50_000.msat, add.amount)

        val attempt = outgoingPaymentHandler.getPendingPayment(payment.paymentId)!!
        val fail = outgoingPaymentHandler.processAddSettledFailed(
            alice.channelId,
            createRecipientFailure(add, attempt, IncorrectOrUnknownPaymentDetails(50_000.msat, 0)),
            mapOf(alice.channelId to alice.state),
            TestConstants.defaultBlockHeight
        )
        assertIs<OutgoingPaymentHandler.Failure>(fail)
        val expected = OutgoingPaymentHandler.Failure(payment, OutgoingPaymentFailure(FinalFailure.RecipientRejectedPayment, listOf(Either.Right(IncorrectOrUnknownPaymentDetails(50_000.msat, 0)))))
        assertFailureEquals(expected, fail)

        assertNull(outgoingPaymentHandler.getPendingPayment(payment.paymentId))
        assertDbPaymentFailed(outgoingPaymentHandler.db, payment.paymentId, 1)
    }

    @Test
    fun `failure after a wallet restart`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val db = InMemoryPaymentsDb()

        // Step 1: a payment attempt is made.
        val (add, attempt) = run {
            val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, defaultWalletParams, db)
            val invoice = makeInvoice(amount = null, supportsTrampoline = true)
            val payment = PayInvoice(UUID.randomUUID(), 550_000.msat, LightningOutgoingPayment.Details.Normal(invoice))

            val progress = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
            assertIs<OutgoingPaymentHandler.Progress>(progress)
            val attempt = outgoingPaymentHandler.getPendingPayment(payment.paymentId)!!
            val (_, add) = findAddHtlcCommand(progress)
            Pair(add, attempt)
        }

        // Step 2: the wallet restarts and payment fails.
        run {
            val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, defaultWalletParams, db)
            val fail = outgoingPaymentHandler.processAddSettledFailed(alice.channelId, createTrampolineFailure(add, attempt, TemporaryNodeFailure), mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
            assertIs<OutgoingPaymentHandler.Failure>(fail)
            assertEquals(attempt.request, fail.request)
            assertEquals(FinalFailure.WalletRestarted, fail.failure.reason)
            assertEquals(1, fail.failure.failures.size)
            // Since we haven't stored the shared secrets, we can't decrypt remote failure.
            assertIs<LightningOutgoingPayment.Part.Status.Failure.Uninterpretable>(fail.failure.failures.first().failure)
        }
    }

    @Test
    fun `success after a wallet restart`() = runSuspendTest {
        val (alice, _) = TestsHelper.reachNormal()
        val preimage = randomBytes32()
        val invoice = makeInvoice(amount = null, supportsTrampoline = true)
        val payment = PayInvoice(UUID.randomUUID(), 550_000.msat, LightningOutgoingPayment.Details.Normal(invoice))
        val db = InMemoryPaymentsDb()

        // Step 1: a payment attempt is made.
        val add = run {
            val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, defaultWalletParams, db)
            val progress = outgoingPaymentHandler.sendPayment(payment, mapOf(alice.channelId to alice.state), TestConstants.defaultBlockHeight)
            assertIs<OutgoingPaymentHandler.Progress>(progress)
            findAddHtlcCommand(progress).second
        }

        // Step 2: the wallet restarts and payment succeeds.
        run {
            val outgoingPaymentHandler = OutgoingPaymentHandler(TestConstants.Alice.nodeParams, defaultWalletParams, db)
            val success = outgoingPaymentHandler.processAddSettledFulfilled(createRemoteFulfill(alice.channelId, add, preimage))
            assertIs<OutgoingPaymentHandler.Success>(success)
            assertEquals(preimage, success.preimage)
            assertEquals(1, success.payment.parts.size)
            assertEquals(payment, success.request)
            assertEquals(preimage, (success.payment.status as LightningOutgoingPayment.Status.Completed.Succeeded.OffChain).preimage)
        }
    }

    private fun makeInvoice(amount: MilliSatoshi?, supportsTrampoline: Boolean, privKey: PrivateKey = randomKey(), extraHops: List<List<Bolt11Invoice.TaggedField.ExtraHop>> = listOf()): Bolt11Invoice {
        val paymentPreimage: ByteVector32 = randomBytes32()
        val paymentHash = Crypto.sha256(paymentPreimage).toByteVector32()
        val invoiceFeatures: Map<Feature, FeatureSupport> = buildMap {
            put(Feature.VariableLengthOnion, FeatureSupport.Optional)
            put(Feature.PaymentSecret, FeatureSupport.Mandatory)
            put(Feature.BasicMultiPartPayment, FeatureSupport.Optional)
            if (supportsTrampoline) put(Feature.TrampolinePayment, FeatureSupport.Optional)
        }
        return Bolt11Invoice.create(
            chain = Chain.Mainnet,
            amount = amount,
            paymentHash = paymentHash,
            privateKey = privKey,
            description = Either.Left("unit test"),
            minFinalCltvExpiryDelta = Bolt11Invoice.DEFAULT_MIN_FINAL_EXPIRY_DELTA,
            features = Features(invoiceFeatures),
            extraHops = extraHops
        )
    }

    private fun findAddHtlcCommand(progress: OutgoingPaymentHandler.Progress): Pair<ByteVector32, ChannelCommand.Htlc.Add> {
        return progress.actions.firstNotNullOf {
            when (val cmd = it.channelCommand) {
                is ChannelCommand.Htlc.Add -> Pair(it.channelId, cmd)
                else -> null
            }
        }
    }

    private fun makeUpdateAddHtlc(channelId: ByteVector32, cmd: ChannelCommand.Htlc.Add, htlcId: Long = 0): UpdateAddHtlc = UpdateAddHtlc(channelId, htlcId, cmd.amount, cmd.paymentHash, cmd.cltvExpiry, cmd.onion)

    private fun createRemoteFulfill(channelId: ByteVector32, add: ChannelCommand.Htlc.Add, preimage: ByteVector32): ChannelAction.ProcessCmdRes.AddSettledFulfill {
        val updateAddHtlc = makeUpdateAddHtlc(channelId, add)
        return ChannelAction.ProcessCmdRes.AddSettledFulfill(add.paymentId, updateAddHtlc, ChannelAction.HtlcResult.Fulfill.RemoteFulfill(UpdateFulfillHtlc(channelId, updateAddHtlc.id, preimage)))
    }

    // Create a failure onion sent by the trampoline node.
    private fun createTrampolineFailure(add: ChannelCommand.Htlc.Add, attempt: OutgoingPaymentHandler.PaymentAttempt, failureMessage: FailureMessage): ChannelAction.ProcessCmdRes.AddSettledFail {
        // We are directly connected to our trampoline node, so we have a single outer shared secret.
        assertEquals(1, attempt.outgoing.outerSharedSecrets.size)
        val sharedSecret = attempt.outgoing.outerSharedSecrets.first().secret
        val reason = FailurePacket.create(sharedSecret, failureMessage)
        val updateAddHtlc = makeUpdateAddHtlc(randomBytes32(), add)
        return ChannelAction.ProcessCmdRes.AddSettledFail(
            add.paymentId,
            updateAddHtlc,
            ChannelAction.HtlcResult.Fail.RemoteFail(UpdateFailHtlc(updateAddHtlc.channelId, updateAddHtlc.id, reason.toByteVector()))
        )
    }

    // Create a failure onion sent by the final trampoline recipient.
    private fun createRecipientFailure(add: ChannelCommand.Htlc.Add, attempt: OutgoingPaymentHandler.PaymentAttempt, failureMessage: FailureMessage): ChannelAction.ProcessCmdRes.AddSettledFail {
        // We are directly connected to our trampoline node, so we have a single outer shared secret.
        assertEquals(1, attempt.outgoing.outerSharedSecrets.size)
        // We are using a trampoline hop from our trampoline node to the recipient, so we have two inner shared secrets.
        assertEquals(2, attempt.outgoing.innerSharedSecrets.size)
        // The recipient encrypts the failure with its trampoline shared secret.
        val failure = FailurePacket.create(attempt.outgoing.innerSharedSecrets.last().secret, failureMessage)
        // The trampoline node encrypts the failure with its trampoline shared secret.
        val intermediate = FailurePacket.wrap(failure, attempt.outgoing.innerSharedSecrets.first().secret)
        // The trampoline node encrypts the failure with its outer shared secret.
        val reason = FailurePacket.wrap(intermediate, attempt.outgoing.outerSharedSecrets.first().secret)
        val updateAddHtlc = makeUpdateAddHtlc(randomBytes32(), add)
        return ChannelAction.ProcessCmdRes.AddSettledFail(
            add.paymentId,
            updateAddHtlc,
            ChannelAction.HtlcResult.Fail.RemoteFail(UpdateFailHtlc(updateAddHtlc.channelId, updateAddHtlc.id, reason.toByteVector()))
        )
    }

    private suspend fun assertDbPaymentFailed(db: OutgoingPaymentsDb, paymentId: UUID, partsCount: Int) {
        val dbPayment = db.getLightningOutgoingPayment(paymentId)
        assertNotNull(dbPayment)
        assertTrue(dbPayment.status is LightningOutgoingPayment.Status.Completed.Failed)
        assertEquals(partsCount, dbPayment.parts.size)
        assertTrue(dbPayment.parts.all { it.status is LightningOutgoingPayment.Part.Status.Failed })
    }

    private suspend fun assertDbPaymentSucceeded(db: OutgoingPaymentsDb, paymentId: UUID, amount: MilliSatoshi, fees: MilliSatoshi, partsCount: Int) {
        val dbPayment = db.getLightningOutgoingPayment(paymentId)
        assertNotNull(dbPayment)
        assertEquals(amount, dbPayment.recipientAmount)
        assertEquals(fees, dbPayment.fees)
        assertTrue(dbPayment.status is LightningOutgoingPayment.Status.Completed.Succeeded.OffChain)
        assertEquals(partsCount, dbPayment.parts.size)
        assertTrue(dbPayment.parts.all { it.status is LightningOutgoingPayment.Part.Status.Succeeded })
    }

    private fun assertFailureEquals(f1: OutgoingPaymentHandler.Failure, f2: OutgoingPaymentHandler.Failure) {
        val f1b = f1.copy(failure = f1.failure.copy(failures = f1.failure.failures.map { it.copy(completedAt = 0) }))
        val f2b = f2.copy(failure = f2.failure.copy(failures = f2.failure.failures.map { it.copy(completedAt = 0) }))
        assertEquals(f1b, f2b)
    }

}
