package fr.acinq.lightning.payment

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.crypto.RouteBlinding
import fr.acinq.lightning.crypto.sphinx.DecryptedPacket
import fr.acinq.lightning.crypto.sphinx.Sphinx
import fr.acinq.lightning.io.OfferInvoiceReceived
import fr.acinq.lightning.io.OfferNotPaid
import fr.acinq.lightning.io.PayOffer
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.tests.utils.runSuspendTest
import fr.acinq.lightning.tests.utils.testLoggerFactory
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.MessageOnion
import fr.acinq.lightning.wire.OfferTypes
import fr.acinq.lightning.wire.OnionMessage
import fr.acinq.lightning.wire.RouteBlindingEncryptedData
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.first
import kotlin.test.*
import kotlin.time.Duration.Companion.seconds

class OfferManagerTestsCommon : LightningTestSuite() {
    private val aliceTrampolineKey = randomKey()
    private val bobTrampolineKey = randomKey()
    private val aliceWalletParams = TestConstants.Alice.walletParams.copy(trampolineNode = NodeUri(aliceTrampolineKey.publicKey(), "trampoline.com", 9735))
    private val bobWalletParams = TestConstants.Bob.walletParams.copy(trampolineNode = NodeUri(bobTrampolineKey.publicKey(), "trampoline.com", 9735))
    private val logger: MDCLogger = MDCLogger(testLoggerFactory.newLogger(this::class))

    /** Simulate the decryption step performed by the trampoline node when relaying onion messages. */
    private fun trampolineRelay(msg: OnionMessage, trampolineKey: PrivateKey): Pair<OnionMessage, Either<ShortChannelId, EncodedNodeId>> {
        val blindedPrivateKey = RouteBlinding.derivePrivateKey(trampolineKey, msg.pathKey)
        val decrypted = Sphinx.peel(blindedPrivateKey, ByteVector.empty, msg.onionRoutingPacket)
        assertIs<Either.Right<DecryptedPacket>>(decrypted)
        assertFalse(decrypted.value.isLastPacket)
        val message = MessageOnion.read(decrypted.value.payload.toByteArray())
        val (decryptedPayload, nextBlinding) = RouteBlinding.decryptPayload(trampolineKey, msg.pathKey, message.encryptedData).right!!
        val relayInfo = RouteBlindingEncryptedData.read(decryptedPayload.toByteArray()).right!!
        assertNull(relayInfo.pathId)
        assertEquals(Features.empty, relayInfo.allowedFeatures)
        val nextNode = relayInfo.nextNodeId?.let { Either.Right(it) } ?: Either.Left(relayInfo.outgoingChannelId!!)
        return Pair(OnionMessage(relayInfo.nextPathKeyOverride ?: nextBlinding, decrypted.value.nextPacket), nextNode)
    }

    private fun createOffer(offerManager: OfferManager, amount: MilliSatoshi? = null): OfferTypes.Offer {
        val blindingSecret = randomKey()
        val (offer, _) = OfferTypes.Offer.createBlindedOffer(
            amount,
            "Blockaccino",
            offerManager.nodeParams,
            offerManager.walletParams.trampolineNode.id,
            offerManager.nodeParams.features,
            blindingSecret,
        )
        offerManager.registerOffer(offer, null)
        return offer
    }

    private fun decryptPathId(invoice: Bolt12Invoice, trampolineKey: PrivateKey): OfferPaymentMetadata.V1 {
        val blindedRoute = invoice.blindedPaths.first().route.route
        assertEquals(2, blindedRoute.encryptedPayloads.size)
        val (_, nextBlinding) = RouteBlinding.decryptPayload(trampolineKey, blindedRoute.firstPathKey, blindedRoute.encryptedPayloads.first()).right!!
        val (lastPayload, _) = RouteBlinding.decryptPayload(TestConstants.Alice.nodeParams.nodePrivateKey, nextBlinding, blindedRoute.encryptedPayloads.last()).right!!
        val pathId = RouteBlindingEncryptedData.read(lastPayload.toByteArray()).right!!.pathId!!
        return OfferPaymentMetadata.fromPathId(TestConstants.Alice.nodeParams.nodeId, pathId) as OfferPaymentMetadata.V1
    }

    @Test
    fun `pay offer through the same trampoline node`() = runSuspendTest {
        // Alice and Bob use the same trampoline node.
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager, amount = 1000.msat)

        // Bob sends an invoice request to Alice.
        val currentBlockHeight = 0
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), null, 5500.msat, offer, 20.seconds)
        val (_, invoiceRequests) = bobOfferManager.requestInvoice(payOffer)
        assertTrue(invoiceRequests.size == 1)
        val (messageForAlice, nextNodeAlice) = trampolineRelay(invoiceRequests.first(), aliceTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId.WithPublicKey.Wallet(TestConstants.Alice.nodeParams.nodeId)), nextNodeAlice)
        // Alice sends an invoice back to Bob.
        val invoiceResponse = aliceOfferManager.receiveMessage(messageForAlice, listOf(), currentBlockHeight)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse)
        val (messageForBob, nextNodeBob) = trampolineRelay(invoiceResponse.message, aliceTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId.WithPublicKey.Wallet(TestConstants.Bob.nodeParams.nodeId)), nextNodeBob)
        val payInvoice = bobOfferManager.receiveMessage(messageForBob, listOf(), currentBlockHeight)
        assertIs<OnionMessageAction.PayInvoice>(payInvoice)
        assertEquals(OfferInvoiceReceived(payOffer, payInvoice.invoice), bobOfferManager.eventsFlow.first())
        assertEquals(payOffer, payInvoice.payOffer)
        assertEquals(1, payInvoice.invoice.blindedPaths.size)
        val path = payInvoice.invoice.blindedPaths.first()
        assertEquals(EncodedNodeId(aliceTrampolineKey.publicKey()), path.route.route.firstNodeId)
        assertEquals(aliceOfferManager.nodeParams.expiryDeltaBlocks + aliceOfferManager.nodeParams.minFinalCltvExpiryDelta, path.paymentInfo.cltvExpiryDelta)
        assertEquals(TestConstants.Alice.nodeParams.htlcMinimum, path.paymentInfo.minHtlc)
        assertEquals(payOffer.amount * 2, path.paymentInfo.maxHtlc)
        // The blinded path expires long after the invoice expiry to allow senders to add their own expiry delta.
        val (alicePayload, _) = RouteBlinding.decryptPayload(aliceTrampolineKey, path.route.route.firstPathKey, path.route.route.encryptedPayloads.first()).right!!
        val paymentConstraints = RouteBlindingEncryptedData.read(alicePayload.toByteArray()).right!!.paymentConstraints!!
        assertTrue(paymentConstraints.maxCltvExpiry > CltvExpiryDelta(720).toCltvExpiry(currentBlockHeight.toLong()))
    }

    @Test
    fun `pay offer through different trampoline nodes`() = runSuspendTest {
        // Alice and Bob use different trampoline nodes.
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, bobWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager)

        // Bob sends an invoice request to Alice.
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), null, 5500.msat, offer, 20.seconds)
        val (_, invoiceRequests) = bobOfferManager.requestInvoice(payOffer)
        assertTrue(invoiceRequests.size == 1)
        val (messageForAliceTrampoline, nextNodeAliceTrampoline) = trampolineRelay(invoiceRequests.first(), bobTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId(aliceTrampolineKey.publicKey())), nextNodeAliceTrampoline)
        val (messageForAlice, nextNodeAlice) = trampolineRelay(messageForAliceTrampoline, aliceTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId.WithPublicKey.Wallet(TestConstants.Alice.nodeParams.nodeId)), nextNodeAlice)
        // Alice sends an invoice back to Bob.
        val invoiceResponse = aliceOfferManager.receiveMessage(messageForAlice, listOf(), 0)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse)
        val (messageForBobTrampoline, nextNodeBobTrampoline) = trampolineRelay(invoiceResponse.message, aliceTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId(bobTrampolineKey.publicKey())), nextNodeBobTrampoline)
        val (messageForBob, nextNodeBob) = trampolineRelay(messageForBobTrampoline, bobTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId.WithPublicKey.Wallet(TestConstants.Bob.nodeParams.nodeId)), nextNodeBob)
        val payInvoice = bobOfferManager.receiveMessage(messageForBob, listOf(), 0)
        assertIs<OnionMessageAction.PayInvoice>(payInvoice)
        assertEquals(OfferInvoiceReceived(payOffer, payInvoice.invoice), bobOfferManager.eventsFlow.first())
        assertEquals(payOffer, payInvoice.payOffer)
        assertEquals(1, payInvoice.invoice.blindedPaths.size)
        val path = payInvoice.invoice.blindedPaths.first()
        assertEquals(EncodedNodeId(aliceTrampolineKey.publicKey()), path.route.route.firstNodeId)
        assertEquals(aliceOfferManager.nodeParams.expiryDeltaBlocks + aliceOfferManager.nodeParams.minFinalCltvExpiryDelta, path.paymentInfo.cltvExpiryDelta)
        assertEquals(TestConstants.Alice.nodeParams.htlcMinimum, path.paymentInfo.minHtlc)
        assertEquals(payOffer.amount * 2, path.paymentInfo.maxHtlc)
    }

    @Test
    fun `invoice request timed out`() = runSuspendTest {
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager)

        // Bob sends an invoice request to Alice.
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), null, 5500.msat, offer, 20.seconds)
        val (invoiceRequestPathId, invoiceRequests, request) = bobOfferManager.requestInvoice(payOffer)
        val (messageForAlice, _) = trampolineRelay(invoiceRequests.first(), aliceTrampolineKey)
        // The invoice request times out.
        bobOfferManager.checkInvoiceRequestTimeout(invoiceRequestPathId, payOffer)
        assertEquals(OfferNotPaid(payOffer, Bolt12InvoiceRequestFailure.NoResponse(request)), bobOfferManager.eventsFlow.first())
        // The timeout can be replayed without any side-effect.
        bobOfferManager.checkInvoiceRequestTimeout(invoiceRequestPathId, payOffer)
        // Alice sends an invoice back to Bob after the timeout.
        val invoiceResponse = aliceOfferManager.receiveMessage(messageForAlice, listOf(), 0)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse)
        val (messageForBob, _) = trampolineRelay(invoiceResponse.message, aliceTrampolineKey)
        assertNull(bobOfferManager.receiveMessage(messageForBob, listOf(), 0))
    }

    @Test
    fun `duplicate invoice request`() = runSuspendTest {
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager)

        // Bob sends two invoice requests to Alice.
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), null, 5500.msat, offer, 20.seconds)
        val (_, invoiceRequests) = bobOfferManager.requestInvoice(payOffer)
        val (messageForAlice, _) = trampolineRelay(invoiceRequests.first(), aliceTrampolineKey)
        // Alice sends two invoices back to Bob.
        val invoiceResponse1 = aliceOfferManager.receiveMessage(messageForAlice, listOf(), 0)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse1)
        val (messageForBob1, _) = trampolineRelay(invoiceResponse1.message, aliceTrampolineKey)
        val invoiceResponse2 = aliceOfferManager.receiveMessage(messageForAlice, listOf(), 0)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse2)
        val (messageForBob2, _) = trampolineRelay(invoiceResponse2.message, aliceTrampolineKey)
        // Bob pays the first invoice and ignores the second one.
        val payInvoice = bobOfferManager.receiveMessage(messageForBob1, listOf(), 0)
        assertIs<OnionMessageAction.PayInvoice>(payInvoice)
        assertEquals(OfferInvoiceReceived(payOffer, payInvoice.invoice), bobOfferManager.eventsFlow.first())
        assertEquals(payOffer, payInvoice.payOffer)
        assertNull(bobOfferManager.receiveMessage(messageForBob2, listOf(), 0))
    }

    @Test
    fun `receive invalid invoice request`() = runSuspendTest {
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager)

        // Bob sends an invalid invoice request to Alice.
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), null, 5500.msat, offer, 20.seconds)
        val (_, invoiceRequests) = bobOfferManager.requestInvoice(payOffer)
        val (messageForAlice, _) = trampolineRelay(invoiceRequests.first(), aliceTrampolineKey)
        assertNull(aliceOfferManager.receiveMessage(messageForAlice.copy(pathKey = randomKey().publicKey()), listOf(), 0))
    }

    @Test
    fun `receive invalid invoice response`() = runSuspendTest {
        // Alice and Bob use the same trampoline node.
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager)

        // Bob sends an invoice request to Alice.
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), null, 5500.msat, offer, 20.seconds)
        val (_, invoiceRequests) = bobOfferManager.requestInvoice(payOffer)
        val (messageForAlice, _) = trampolineRelay(invoiceRequests.first(), aliceTrampolineKey)
        // Alice sends an invalid response back to Bob.
        val invoiceResponse = aliceOfferManager.receiveMessage(messageForAlice, listOf(), 0)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse)
        val (messageForBob, _) = trampolineRelay(invoiceResponse.message, aliceTrampolineKey)
        assertNull(bobOfferManager.receiveMessage(messageForBob.copy(pathKey = randomKey().publicKey()), listOf(), 0))
    }

    @Test
    fun `receive invoice error -- amount below offer amount`() = runSuspendTest {
        // Alice and Bob use the same trampoline node.
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager, 50_000.msat)

        // Bob sends an invoice request to Alice that pays less than the offer amount.
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), null, 40_000.msat, offer, 20.seconds)
        val (_, invoiceRequests) = bobOfferManager.requestInvoice(payOffer)
        val (messageForAlice, _) = trampolineRelay(invoiceRequests.first(), aliceTrampolineKey)
        // Alice sends an invoice error back to Bob.
        val invoiceResponse = aliceOfferManager.receiveMessage(messageForAlice, listOf(), 0)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse)
        val (messageForBob, _) = trampolineRelay(invoiceResponse.message, aliceTrampolineKey)
        assertNull(bobOfferManager.receiveMessage(messageForBob, listOf(), 0))
        val event = bobOfferManager.eventsFlow.first()
        assertIs<OfferNotPaid>(event)
        assertIs<Bolt12InvoiceRequestFailure.ErrorFromRecipient>(event.reason)
    }

    @Test
    fun `receive invoice error -- amount too low`() = runSuspendTest {
        // Alice and Bob use the same trampoline node.
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager, null)

        // Bob sends an invoice request to Alice that pays less than the minimum htlc amount.
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), null, 10.msat, offer, 20.seconds)
        val (_, invoiceRequests) = bobOfferManager.requestInvoice(payOffer)
        val (messageForAlice, _) = trampolineRelay(invoiceRequests.first(), aliceTrampolineKey)
        // Alice sends an invoice error back to Bob.
        val invoiceResponse = aliceOfferManager.receiveMessage(messageForAlice, listOf(), 0)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse)
        val (messageForBob, _) = trampolineRelay(invoiceResponse.message, aliceTrampolineKey)
        assertNull(bobOfferManager.receiveMessage(messageForBob, listOf(), 0))
        val event = bobOfferManager.eventsFlow.first()
        assertIs<OfferNotPaid>(event)
        assertIs<Bolt12InvoiceRequestFailure.ErrorFromRecipient>(event.reason)
    }

    @Test
    fun `pay offer with payer note`() = runSuspendTest {
        // Alice and Bob use the same trampoline node.
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager, amount = 1000.msat)

        // Bob sends an invoice request to Alice.
        val payerNote = "Thanks for all the fish"
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), payerNote, 5500.msat, offer, 20.seconds)
        val (_, invoiceRequests) = bobOfferManager.requestInvoice(payOffer)
        assertTrue(invoiceRequests.size == 1)
        val (messageForAlice, nextNodeAlice) = trampolineRelay(invoiceRequests.first(), aliceTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId.WithPublicKey.Wallet(TestConstants.Alice.nodeParams.nodeId)), nextNodeAlice)
        // Alice sends an invoice back to Bob.
        val invoiceResponse = aliceOfferManager.receiveMessage(messageForAlice, listOf(), 0)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse)
        val (messageForBob, nextNodeBob) = trampolineRelay(invoiceResponse.message, aliceTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId.WithPublicKey.Wallet(TestConstants.Bob.nodeParams.nodeId)), nextNodeBob)
        val payInvoice = bobOfferManager.receiveMessage(messageForBob, listOf(), 0)
        assertIs<OnionMessageAction.PayInvoice>(payInvoice)
        assertEquals(OfferInvoiceReceived(payOffer, payInvoice.invoice), bobOfferManager.eventsFlow.first())
        assertEquals(payOffer, payInvoice.payOffer)

        // The payer note is correctly included in the payment metadata.
        val metadata = decryptPathId(payInvoice.invoice, aliceTrampolineKey)
        assertEquals(payerNote, metadata.payerNote)
    }

    @Test
    fun `pay offer with long payer note`() = runSuspendTest {
        // Alice and Bob use the same trampoline node.
        val aliceOfferManager = OfferManager(TestConstants.Alice.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val bobOfferManager = OfferManager(TestConstants.Bob.nodeParams, aliceWalletParams, MutableSharedFlow(replay = 10), logger)
        val offer = createOffer(aliceOfferManager, amount = 1000.msat)

        // Bob sends an invoice request to Alice.
        val payerNote = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        val payOffer = PayOffer(UUID.randomUUID(), randomKey(), payerNote, 5500.msat, offer, 20.seconds)
        val (_, invoiceRequests) = bobOfferManager.requestInvoice(payOffer)
        assertTrue(invoiceRequests.size == 1)
        val (messageForAlice, nextNodeAlice) = trampolineRelay(invoiceRequests.first(), aliceTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId.WithPublicKey.Wallet(TestConstants.Alice.nodeParams.nodeId)), nextNodeAlice)
        // Alice sends an invoice back to Bob.
        val invoiceResponse = aliceOfferManager.receiveMessage(messageForAlice, listOf(), 0)
        assertIs<OnionMessageAction.SendMessage>(invoiceResponse)
        val (messageForBob, nextNodeBob) = trampolineRelay(invoiceResponse.message, aliceTrampolineKey)
        assertEquals(Either.Right(EncodedNodeId.WithPublicKey.Wallet(TestConstants.Bob.nodeParams.nodeId)), nextNodeBob)
        val payInvoice = bobOfferManager.receiveMessage(messageForBob, listOf(), 0)
        assertIs<OnionMessageAction.PayInvoice>(payInvoice)
        assertEquals(OfferInvoiceReceived(payOffer, payInvoice.invoice), bobOfferManager.eventsFlow.first())
        assertEquals(payOffer, payInvoice.payOffer)

        // The payer note is truncated in the payment metadata.
        val metadata = decryptPathId(payInvoice.invoice, aliceTrampolineKey)
        assertEquals(64, metadata.payerNote!!.length)
        assertEquals(payerNote.take(63), metadata.payerNote!!.take(63))
    }

}