package fr.acinq.lightning.payment

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.nodeFee
import fr.acinq.lightning.Lightning.randomBytes
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomBytes64
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.channel.states.Channel
import fr.acinq.lightning.crypto.RouteBlinding
import fr.acinq.lightning.crypto.sphinx.PacketAndSecrets
import fr.acinq.lightning.crypto.sphinx.Sphinx
import fr.acinq.lightning.crypto.sphinx.Sphinx.hash
import fr.acinq.lightning.router.ChannelHop
import fr.acinq.lightning.router.NodeHop
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.currentTimestampMillis
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.utils.toByteVector32
import fr.acinq.lightning.wire.*
import kotlin.test.*

class PaymentPacketTestsCommon : LightningTestSuite() {

    companion object {
        private val privB = randomKey()
        private val b = privB.publicKey()
        private val privC = randomKey()
        private val c = privC.publicKey()
        private val privD = randomKey()
        private val d = privD.publicKey()
        private val defaultChannelUpdate = ChannelUpdate(randomBytes64(), Block.RegtestGenesisBlock.hash, ShortChannelId(0), 0, 1, 0, CltvExpiryDelta(0), 42000.msat, 0.msat, 0, 500000000.msat)
        private val channelUpdateBC = defaultChannelUpdate.copy(shortChannelId = ShortChannelId(1105), cltvExpiryDelta = CltvExpiryDelta(36), feeBaseMsat = 7_500.msat, feeProportionalMillionths = 250)
        private val channelUpdateCD = defaultChannelUpdate.copy(shortChannelId = ShortChannelId(1729), cltvExpiryDelta = CltvExpiryDelta(24), feeBaseMsat = 5_000.msat, feeProportionalMillionths = 100)

        private val finalAmount = 50_000_000.msat
        private const val currentBlockCount = 400_000L
        private val finalExpiry = CltvExpiry(currentBlockCount) + Channel.MIN_CLTV_EXPIRY_DELTA
        private val paymentPreimage = randomBytes32()
        private val paymentHash = Crypto.sha256(paymentPreimage).toByteVector32()
        private val paymentSecret = randomBytes32()
        private val paymentMetadata = randomBytes(64).toByteVector()

        private val nonTrampolineFeatures = Features(
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
            Feature.BasicMultiPartPayment to FeatureSupport.Optional,
        )
        private val trampolineFeatures = Features(
            Feature.VariableLengthOnion to FeatureSupport.Mandatory,
            Feature.PaymentSecret to FeatureSupport.Mandatory,
            Feature.BasicMultiPartPayment to FeatureSupport.Optional,
            Feature.ExperimentalTrampolinePayment to FeatureSupport.Optional,
        )

        // Amount and expiry sent by C to D.
        private val expiryCD = finalExpiry
        private val amountCD = finalAmount
        private val feeC = nodeFee(channelUpdateCD.feeBaseMsat, channelUpdateCD.feeProportionalMillionths, amountCD)

        // Amount and expiry sent by B to C.
        private val expiryBC = expiryCD + channelUpdateCD.cltvExpiryDelta
        private val amountBC = amountCD + feeC
        private val feeB = nodeFee(channelUpdateBC.feeBaseMsat, channelUpdateBC.feeProportionalMillionths, amountBC)

        // Amount and expiry sent by A to B.
        private val expiryAB = expiryBC + channelUpdateBC.cltvExpiryDelta
        private val amountAB = amountBC + feeB

        // C is directly connected to the recipient D.
        val nodeHop_cd = NodeHop(c, d, channelUpdateCD.cltvExpiryDelta, feeC)
        // B is not directly connected to the recipient D.
        val nodeHop_bd = NodeHop(b, d, channelUpdateBC.cltvExpiryDelta + channelUpdateCD.cltvExpiryDelta, feeB + feeC)

        // Wallets don't need to decrypt onions for intermediate nodes, but it's useful to test that encryption works correctly.
        fun decryptChannelRelay(add: UpdateAddHtlc, privateKey: PrivateKey): Pair<PaymentOnion.ChannelRelayPayload, OnionRoutingPacket> {
            val decrypted = Sphinx.peel(privateKey, add.paymentHash, add.onionRoutingPacket).right!!
            assertFalse(decrypted.isLastPacket)
            val decoded = PaymentOnion.ChannelRelayPayload.read(decrypted.payload).right!!
            return Pair(decoded, decrypted.nextPacket)
        }

        // Wallets don't need to create channel routes, but it's useful to test the end-to-end flow.
        fun encryptChannelRelay(paymentHash: ByteVector32, hops: List<ChannelHop>, finalPayload: PaymentOnion.FinalPayload): Triple<MilliSatoshi, CltvExpiry, PacketAndSecrets> {
            val (firstAmount, firstExpiry, payloads) = hops.drop(1).reversed().fold(Triple(finalPayload.amount, finalPayload.expiry, listOf<PaymentOnion.PerHopPayload>(finalPayload))) { (amount, expiry, payloads), hop ->
                val payload = PaymentOnion.ChannelRelayPayload.create(hop.lastUpdate.shortChannelId, amount, expiry)
                Triple(amount + hop.fee(amount), expiry + hop.cltvExpiryDelta, listOf(payload) + payloads)
            }
            val onion = OutgoingPaymentPacket.buildOnion(hops.map { it.nextNodeId }, payloads, paymentHash, OnionRoutingPacket.PaymentPacketLength)
            return Triple(firstAmount, firstExpiry, onion)
        }

        // Wallets don't need to decrypt onions for intermediate nodes, but it's useful to test that encryption works correctly.
        fun decryptRelayToTrampoline(add: UpdateAddHtlc, privateKey: PrivateKey): Triple<PaymentOnion.FinalPayload, PaymentOnion.NodeRelayPayload, OnionRoutingPacket> {
            val decrypted = Sphinx.peel(privateKey, add.paymentHash, add.onionRoutingPacket).right!!
            assertTrue(decrypted.isLastPacket)
            val outerPayload = PaymentOnion.FinalPayload.Standard.read(decrypted.payload).right!!
            val trampolineOnion = outerPayload.records.get<OnionPaymentPayloadTlv.TrampolineOnion>()
            assertNotNull(trampolineOnion)
            val decryptedInner = Sphinx.peel(privateKey, add.paymentHash, trampolineOnion.packet).right!!
            assertFalse(decryptedInner.isLastPacket)
            val innerPayload = PaymentOnion.NodeRelayPayload.read(decryptedInner.payload).right!!
            assertNull(innerPayload.records.get<OnionPaymentPayloadTlv.PaymentData>())
            assertNull(innerPayload.records.get<OnionPaymentPayloadTlv.PaymentMetadata>())
            assertNull(innerPayload.records.get<OnionPaymentPayloadTlv.InvoiceFeatures>())
            assertNull(innerPayload.records.get<OnionPaymentPayloadTlv.InvoiceRoutingInfo>())
            return Triple(outerPayload, innerPayload, decryptedInner.nextPacket)
        }

        // Wallets don't need to decrypt onions for intermediate nodes, but it's useful to test that encryption works correctly.
        fun decryptRelayToLegacy(add: UpdateAddHtlc, privateKey: PrivateKey): Pair<PaymentOnion.FinalPayload.Standard, PaymentOnion.RelayToNonTrampolinePayload> {
            val decrypted = Sphinx.peel(privateKey, add.paymentHash, add.onionRoutingPacket).right!!
            assertTrue(decrypted.isLastPacket)
            val outerPayload = PaymentOnion.FinalPayload.Standard.read(decrypted.payload).right!!
            val trampolineOnion = outerPayload.records.get<OnionPaymentPayloadTlv.TrampolineOnion>()
            assertNotNull(trampolineOnion)
            val decryptedInner = Sphinx.peel(privateKey, add.paymentHash, trampolineOnion.packet).right!!
            assertFalse(decryptedInner.isLastPacket)
            val innerPayload = PaymentOnion.RelayToNonTrampolinePayload.read(decryptedInner.payload).right!!
            return Pair(outerPayload, innerPayload)
        }

        // Wallets don't need to decrypt onions for intermediate nodes, but it's useful to test that encryption works correctly.
        fun decryptRelayToBlinded(add: UpdateAddHtlc, privateKey: PrivateKey): Pair<PaymentOnion.FinalPayload, PaymentOnion.RelayToBlindedPayload> {
            val decrypted = Sphinx.peel(privateKey, add.paymentHash, add.onionRoutingPacket).right!!
            assertTrue(decrypted.isLastPacket)
            val outerPayload = PaymentOnion.FinalPayload.Standard.read(decrypted.payload).right!!
            val trampolineOnion = outerPayload.records.get<OnionPaymentPayloadTlv.TrampolineOnion>()
            assertNotNull(trampolineOnion)
            val decryptedInner = Sphinx.peel(privateKey, add.paymentHash, trampolineOnion.packet).right!!
            assertTrue(decryptedInner.isLastPacket)
            val innerPayload = PaymentOnion.RelayToBlindedPayload.read(decryptedInner.payload).right!!
            return Pair(outerPayload, innerPayload)
        }

        fun createBlindedHtlcCD(): Pair<UpdateAddHtlc, OfferPaymentMetadata> {
            val paymentMetadata = OfferPaymentMetadata.V1(randomBytes32(), finalAmount, paymentPreimage, randomKey().publicKey(), "hello", 1, currentTimestampMillis())
            val blindedPayload = RouteBlindingEncryptedData(TlvStream(RouteBlindingEncryptedDataTlv.PathId(paymentMetadata.toPathId(privD))))
            val blindedRoute = RouteBlinding.create(randomKey(), listOf(d), listOf(blindedPayload.write().byteVector())).route
            val finalPayload = PaymentOnion.FinalPayload.Blinded(
                TlvStream(
                    OnionPaymentPayloadTlv.AmountToForward(finalAmount),
                    OnionPaymentPayloadTlv.TotalAmount(finalAmount),
                    OnionPaymentPayloadTlv.OutgoingCltv(finalExpiry),
                    OnionPaymentPayloadTlv.EncryptedRecipientData(blindedRoute.encryptedPayloads.last()),
                ),
                blindedPayload
            )
            val onionD = OutgoingPaymentPacket.buildOnion(listOf(blindedRoute.blindedNodeIds.last()), listOf(finalPayload), paymentHash, OnionRoutingPacket.PaymentPacketLength)
            val addD = UpdateAddHtlc(randomBytes32(), 1, finalAmount, paymentHash, finalExpiry, onionD.packet, blindedRoute.firstPathKey, null)
            return Pair(addD, paymentMetadata)
        }

        fun createBlindedPaymentInfo(u: ChannelUpdate): OfferTypes.PaymentInfo {
            return OfferTypes.PaymentInfo(u.feeBaseMsat, u.feeProportionalMillionths, u.cltvExpiryDelta, u.htlcMinimumMsat, u.htlcMaximumMsat!!, Features.empty)
        }
    }

    @Test
    fun `send a trampoline payment -- recipient connected to trampoline node`() {
        //        .--.
        //       /    \
        // b -> c      d
        val invoice = Bolt11Invoice.create(Chain.Regtest, finalAmount, paymentHash, privD, Either.Left("test"), CltvExpiryDelta(6), trampolineFeatures, paymentSecret, paymentMetadata)
        val (firstAmount, firstExpiry, onion) = OutgoingPaymentPacket.buildPacketToTrampolineRecipient(invoice, finalAmount, finalExpiry, nodeHop_cd)
        assertEquals(amountBC, firstAmount)
        assertEquals(expiryBC, firstExpiry)

        // B sends an HTLC to its trampoline node C.
        val addC = UpdateAddHtlc(randomBytes32(), 1, amountBC, paymentHash, expiryBC, onion.packet)
        val (outerC, innerC, packetD) = decryptRelayToTrampoline(addC, privC)
        assertEquals(amountBC, outerC.amount)
        assertEquals(amountBC, outerC.totalAmount)
        assertEquals(expiryBC, outerC.expiry)
        assertEquals(finalAmount, innerC.amountToForward)
        assertEquals(finalExpiry, innerC.outgoingCltv)
        assertEquals(d, innerC.outgoingNodeId)

        // C forwards the trampoline payment to D over its direct channel.
        val (amountD, expiryD, onionD) = run {
            val payloadD = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(innerC.amountToForward, innerC.amountToForward, innerC.outgoingCltv, randomBytes32(), packetD)
            encryptChannelRelay(paymentHash, listOf(ChannelHop(c, d, channelUpdateCD)), payloadD)
        }
        assertEquals(amountCD, amountD)
        assertEquals(expiryCD, expiryD)
        val addD = UpdateAddHtlc(randomBytes32(), 2, amountD, paymentHash, expiryD, onionD.packet)
        val payloadD = IncomingPaymentPacket.decrypt(addD, privD).right!!
        val expectedFinalPayload = PaymentOnion.FinalPayload.Standard(
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(finalAmount),
                OnionPaymentPayloadTlv.OutgoingCltv(finalExpiry),
                OnionPaymentPayloadTlv.PaymentData(paymentSecret, finalAmount),
                OnionPaymentPayloadTlv.PaymentMetadata(paymentMetadata)
            )
        )
        assertEquals(payloadD, expectedFinalPayload)
    }

    @Test
    fun `send a trampoline payment -- recipient not connected to trampoline node`() {
        //        .-> c -.
        //       /        \
        // a -> b          d
        val invoice = Bolt11Invoice.create(Chain.Regtest, finalAmount, paymentHash, privD, Either.Left("test"), CltvExpiryDelta(6), trampolineFeatures, paymentSecret, paymentMetadata)
        val (firstAmount, firstExpiry, onion) = OutgoingPaymentPacket.buildPacketToTrampolineRecipient(invoice, finalAmount, finalExpiry, nodeHop_bd)
        assertEquals(amountAB, firstAmount)
        assertEquals(expiryAB, firstExpiry)

        // A sends an HTLC to its trampoline node B.
        val addB = UpdateAddHtlc(randomBytes32(), 1, amountAB, paymentHash, expiryAB, onion.packet)
        val (outerB, innerB, packetC) = decryptRelayToTrampoline(addB, privB)
        assertEquals(amountAB, outerB.amount)
        assertEquals(amountAB, outerB.totalAmount)
        assertEquals(expiryAB, outerB.expiry)
        assertEquals(finalAmount, innerB.amountToForward)
        assertEquals(finalExpiry, innerB.outgoingCltv)
        assertEquals(d, innerB.outgoingNodeId)

        // B forwards the trampoline payment to D over an indirect channel route.
        val (amountC, expiryC, onionC) = run {
            val payloadD = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(innerB.amountToForward, innerB.amountToForward, innerB.outgoingCltv, randomBytes32(), packetC)
            encryptChannelRelay(paymentHash, listOf(ChannelHop(b, c, channelUpdateBC), ChannelHop(c, d, channelUpdateCD)), payloadD)
        }
        assertEquals(amountBC, amountC)
        assertEquals(expiryBC, expiryC)

        // C relays the payment to D.
        val addC = UpdateAddHtlc(randomBytes32(), 2, amountC, paymentHash, expiryC, onionC.packet)
        val (payloadC, packetD) = decryptChannelRelay(addC, privC)
        val addD = UpdateAddHtlc(randomBytes32(), 3, payloadC.amountToForward, paymentHash, payloadC.outgoingCltv, packetD)
        val payloadD = IncomingPaymentPacket.decrypt(addD, privD).right!!
        val expectedFinalPayload = PaymentOnion.FinalPayload.Standard(
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(finalAmount),
                OnionPaymentPayloadTlv.OutgoingCltv(finalExpiry),
                OnionPaymentPayloadTlv.PaymentData(paymentSecret, finalAmount),
                OnionPaymentPayloadTlv.PaymentMetadata(paymentMetadata)
            )
        )
        assertEquals(payloadD, expectedFinalPayload)
    }

    @Test
    fun `send a trampoline payment to legacy non-trampoline recipient`() {
        //        .-> c -.
        //       /        \
        // a -> b          d
        val routingHint = listOf(Bolt11Invoice.TaggedField.ExtraHop(c, channelUpdateCD.shortChannelId, channelUpdateCD.feeBaseMsat, channelUpdateCD.feeProportionalMillionths, channelUpdateCD.cltvExpiryDelta))
        val invoice = Bolt11Invoice.create(Chain.Regtest, finalAmount, paymentHash, privD, Either.Left("test"), CltvExpiryDelta(6), nonTrampolineFeatures, paymentSecret, paymentMetadata, extraHops = listOf(routingHint))
        val (firstAmount, firstExpiry, onion) = OutgoingPaymentPacket.buildPacketToLegacyRecipient(invoice, finalAmount, finalExpiry, nodeHop_bd)
        assertEquals(amountAB, firstAmount)
        assertEquals(expiryAB, firstExpiry)

        // A sends an HTLC to its trampoline node B.
        val addB = UpdateAddHtlc(randomBytes32(), 1, amountAB, paymentHash, expiryAB, onion.packet)
        val (outerB, innerB) = decryptRelayToLegacy(addB, privB)
        assertEquals(amountAB, outerB.amount)
        assertEquals(amountAB, outerB.totalAmount)
        assertEquals(expiryAB, outerB.expiry)
        assertEquals(invoice.paymentSecret, outerB.paymentSecret)
        assertEquals(finalAmount, innerB.amountToForward)
        assertEquals(finalAmount, innerB.totalAmount)
        assertEquals(finalExpiry, innerB.outgoingCltv)
        assertEquals(d, innerB.outgoingNodeId)
        assertEquals(invoice.paymentSecret, innerB.paymentSecret)
        assertEquals(invoice.paymentMetadata, innerB.paymentMetadata)
        assertEquals(ByteVector("024100"), innerB.invoiceFeatures) // var_onion_optin, payment_secret, basic_mpp
        assertEquals(listOf(routingHint), innerB.invoiceRoutingInfo)

        // B forwards the trampoline payment to D over an indirect channel route.
        val (amountC, expiryC, onionC) = run {
            val payloadD = PaymentOnion.FinalPayload.Standard.createSinglePartPayload(innerB.amountToForward, innerB.outgoingCltv, innerB.paymentSecret, innerB.paymentMetadata)
            encryptChannelRelay(paymentHash, listOf(ChannelHop(b, c, channelUpdateBC), ChannelHop(c, d, channelUpdateCD)), payloadD)
        }
        assertEquals(amountBC, amountC)
        assertEquals(expiryBC, expiryC)

        // C relays the payment to D.
        val addC = UpdateAddHtlc(randomBytes32(), 2, amountC, paymentHash, expiryC, onionC.packet)
        val (payloadC, packetD) = decryptChannelRelay(addC, privC)
        val addD = UpdateAddHtlc(randomBytes32(), 3, payloadC.amountToForward, paymentHash, payloadC.outgoingCltv, packetD)
        val payloadD = IncomingPaymentPacket.decrypt(addD, privD).right!!
        val expectedFinalPayload = PaymentOnion.FinalPayload.Standard(
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(finalAmount),
                OnionPaymentPayloadTlv.OutgoingCltv(finalExpiry),
                OnionPaymentPayloadTlv.PaymentData(paymentSecret, finalAmount),
                OnionPaymentPayloadTlv.PaymentMetadata(paymentMetadata),
            )
        )
        assertEquals(payloadD, expectedFinalPayload)
    }

    @Test
    fun `send a trampoline payment to blinded paths`() {
        val features = Features(Feature.BasicMultiPartPayment to FeatureSupport.Optional)
        val offer = OfferTypes.Offer.createNonBlindedOffer(finalAmount, "test offer", d, features, Block.RegtestGenesisBlock.hash)
        // D uses a 1-hop blinded path from its trampoline node C.
        val (invoice, blindedRoute) = run {
            val payerKey = randomKey()
            val request = OfferTypes.InvoiceRequest(offer, finalAmount, 1, features, payerKey, "hello", Block.RegtestGenesisBlock.hash)
            val paymentMetadata = OfferPaymentMetadata.V1(offer.offerId, finalAmount, paymentPreimage, payerKey.publicKey(), "hello", 1, currentTimestampMillis())
            val blindedPayloadC = RouteBlindingEncryptedData(
                TlvStream(
                    RouteBlindingEncryptedDataTlv.OutgoingChannelId(channelUpdateCD.shortChannelId),
                    RouteBlindingEncryptedDataTlv.PaymentRelay(channelUpdateCD.cltvExpiryDelta, channelUpdateCD.feeProportionalMillionths, channelUpdateCD.feeBaseMsat),
                    RouteBlindingEncryptedDataTlv.PaymentConstraints(finalExpiry, 1.msat),
                )
            )
            val blindedPayloadD = RouteBlindingEncryptedData(
                TlvStream(
                    RouteBlindingEncryptedDataTlv.PathId(paymentMetadata.toPathId(privD))
                )
            )
            val blindedRouteDetails = RouteBlinding.create(randomKey(), listOf(c, d), listOf(blindedPayloadC, blindedPayloadD).map { it.write().byteVector() })
            val paymentInfo = createBlindedPaymentInfo(channelUpdateCD)
            val path = Bolt12Invoice.Companion.PaymentBlindedContactInfo(OfferTypes.ContactInfo.BlindedPath(blindedRouteDetails.route), paymentInfo)
            val invoice = Bolt12Invoice(request, paymentPreimage, blindedRouteDetails.blindedPrivateKey(privD), 600, features, listOf(path))
            assertEquals(invoice.nodeId, blindedRouteDetails.route.blindedNodeIds.last())
            assertNotEquals(invoice.nodeId, d)
            Pair(invoice, blindedRouteDetails.route)
        }

        // B pays that invoice using its trampoline node C to relay to the invoice's blinded path.
        val (firstAmount, firstExpiry, onion) = OutgoingPaymentPacket.buildPacketToBlindedRecipient(invoice, finalAmount, finalExpiry, nodeHop_cd)
        assertEquals(amountBC, firstAmount)
        assertEquals(expiryBC, firstExpiry)

        // C decrypts the onion that contains a blinded path in the trampoline onion.
        val addC = UpdateAddHtlc(randomBytes32(), 1, firstAmount, paymentHash, firstExpiry, onion.packet)
        val (outerC, innerC) = decryptRelayToBlinded(addC, privC)
        assertEquals(amountBC, outerC.amount)
        assertEquals(amountBC, outerC.totalAmount)
        assertEquals(expiryBC, outerC.expiry)
        assertEquals(finalAmount, innerC.amountToForward)
        assertEquals(finalExpiry, innerC.outgoingCltv)
        assertEquals(listOf(blindedRoute), innerC.outgoingBlindedPaths.map { it.route.route })
        assertEquals(invoice.features.toByteArray().toByteVector(), innerC.invoiceFeatures)

        // C is the introduction node of the blinded path: it can decrypt the first blinded payload and relay to D.
        val addD = run {
            val (dataC, blindingD) = RouteBlinding.decryptPayload(privC, blindedRoute.firstPathKey, blindedRoute.encryptedPayloads.first()).right!!
            val payloadC = RouteBlindingEncryptedData.read(dataC.toByteArray()).right!!
            assertEquals(channelUpdateCD.shortChannelId, payloadC.outgoingChannelId)
            // C would normally create this payload based on the payment_relay field it received.
            val payloadD = PaymentOnion.FinalPayload.Blinded(
                TlvStream(
                    OnionPaymentPayloadTlv.AmountToForward(innerC.amountToForward),
                    OnionPaymentPayloadTlv.TotalAmount(innerC.amountToForward),
                    OnionPaymentPayloadTlv.OutgoingCltv(innerC.outgoingCltv),
                    OnionPaymentPayloadTlv.EncryptedRecipientData(blindedRoute.encryptedPayloads.last()),
                ),
                // This dummy value is ignored when creating the htlc (C is not the recipient).
                RouteBlindingEncryptedData(TlvStream(RouteBlindingEncryptedDataTlv.PathId(ByteVector("deadbeef"))))
            )
            val onionD = OutgoingPaymentPacket.buildOnion(listOf(blindedRoute.blindedNodeIds.last()), listOf(payloadD), addC.paymentHash, OnionRoutingPacket.PaymentPacketLength)
            UpdateAddHtlc(randomBytes32(), 2, innerC.amountToForward, addC.paymentHash, innerC.outgoingCltv, onionD.packet, blindingD, null)
        }

        // D can correctly decrypt the blinded payment.
        val payloadD = IncomingPaymentPacket.decrypt(addD, privD).right!!
        assertIs<PaymentOnion.FinalPayload.Blinded>(payloadD)
        assertEquals(finalAmount, payloadD.amount)
        assertEquals(finalExpiry, payloadD.expiry)
        val paymentMetadata = OfferPaymentMetadata.fromPathId(privD, payloadD.pathId, addD.paymentHash)
        assertNotNull(paymentMetadata)
        assertEquals(offer.offerId, paymentMetadata.offerId)
        assertEquals(paymentMetadata.paymentHash, invoice.paymentHash)
    }

    @Test
    fun `receive a channel payment`() {
        // c -> d
        val finalPayload = PaymentOnion.FinalPayload.Standard.createMultiPartPayload(finalAmount, finalAmount * 1.5, finalExpiry, paymentSecret, paymentMetadata)
        val (firstAmount, firstExpiry, onion) = encryptChannelRelay(paymentHash, listOf(ChannelHop(c, d, channelUpdateCD)), finalPayload)
        val addD = UpdateAddHtlc(randomBytes32(), 1, firstAmount, paymentHash, firstExpiry, onion.packet)
        val payloadD = IncomingPaymentPacket.decrypt(addD, privD).right!!
        assertEquals(finalPayload, payloadD)
    }

    @Test
    fun `receive a blinded channel payment`() {
        // c -> d
        val (addD, paymentMetadata) = createBlindedHtlcCD()
        val payloadD = IncomingPaymentPacket.decrypt(addD, privD).right!!
        assertIs<PaymentOnion.FinalPayload.Blinded>(payloadD)
        assertEquals(finalAmount, payloadD.amount)
        assertEquals(finalAmount, payloadD.totalAmount)
        assertEquals(finalExpiry, payloadD.expiry)
        assertEquals(paymentMetadata, OfferPaymentMetadata.fromPathId(privD, payloadD.pathId, addD.paymentHash))
    }

    @Test
    fun `fail to decrypt when the payment onion is invalid`() {
        val (firstAmount, firstExpiry, onion) = encryptChannelRelay(
            paymentHash,
            listOf(ChannelHop(c, d, channelUpdateCD)),
            PaymentOnion.FinalPayload.Standard.createSinglePartPayload(finalAmount, finalExpiry, paymentSecret, null)
        )
        val addD = UpdateAddHtlc(randomBytes32(), 1, firstAmount, paymentHash, firstExpiry, onion.packet.copy(payload = onion.packet.payload.reversed()))
        val failure = IncomingPaymentPacket.decrypt(addD, privD)
        assertTrue(failure.isLeft)
        assertEquals(InvalidOnionHmac.code, failure.left!!.code)
    }

    @Test
    fun `fail to decrypt when the trampoline onion is invalid`() {
        val invoice = Bolt11Invoice.create(Chain.Regtest, finalAmount, paymentHash, privD, Either.Left("test"), CltvExpiryDelta(6), trampolineFeatures, paymentSecret, paymentMetadata)
        val (firstAmount, firstExpiry, onion) = OutgoingPaymentPacket.buildPacketToTrampolineRecipient(invoice, finalAmount, finalExpiry, nodeHop_cd)
        val addC = UpdateAddHtlc(randomBytes32(), 1, firstAmount, paymentHash, firstExpiry, onion.packet)
        val (_, innerC, packetD) = decryptRelayToTrampoline(addC, privC)
        // C modifies the trampoline onion before forwarding the trampoline payment to D.
        val (amountD, expiryD, onionD) = run {
            val payloadD = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(innerC.amountToForward, innerC.amountToForward, innerC.outgoingCltv, randomBytes32(), packetD.copy(payload = packetD.payload.reversed()))
            encryptChannelRelay(paymentHash, listOf(ChannelHop(c, d, channelUpdateCD)), payloadD)
        }
        val addD = UpdateAddHtlc(randomBytes32(), 2, amountD, paymentHash, expiryD, onionD.packet)
        val failure = IncomingPaymentPacket.decrypt(addD, privD)
        assertTrue(failure.isLeft)
        assertEquals(InvalidOnionHmac.code, failure.left!!.code)
    }

    @Test
    fun `fail to decrypt when payment hash doesn't match associated data`() {
        val (firstAmount, firstExpiry, onion) = encryptChannelRelay(
            paymentHash.reversed(),
            listOf(ChannelHop(c, d, channelUpdateCD)),
            PaymentOnion.FinalPayload.Standard.createSinglePartPayload(finalAmount, finalExpiry, paymentSecret, paymentMetadata)
        )
        val addD = UpdateAddHtlc(randomBytes32(), 1, firstAmount, paymentHash, firstExpiry, onion.packet)
        val failure = IncomingPaymentPacket.decrypt(addD, privD)
        assertTrue(failure.isLeft)
        assertEquals(InvalidOnionHmac.code, failure.left!!.code)
    }

    @Test
    fun `fail to decrypt when blinded route data is invalid`() {
        val paymentMetadata = OfferPaymentMetadata.V1(randomBytes32(), finalAmount, paymentPreimage, randomKey().publicKey(), "hello", 1, currentTimestampMillis())
        val blindedPayload = RouteBlindingEncryptedData(TlvStream(RouteBlindingEncryptedDataTlv.PathId(paymentMetadata.toPathId(privD))))
        val blindedRoute = RouteBlinding.create(randomKey(), listOf(d), listOf(blindedPayload.write().byteVector())).route
        val payloadD = PaymentOnion.FinalPayload.Blinded(
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(finalAmount),
                OnionPaymentPayloadTlv.TotalAmount(finalAmount),
                OnionPaymentPayloadTlv.OutgoingCltv(finalExpiry),
                // The encrypted data is invalid.
                OnionPaymentPayloadTlv.EncryptedRecipientData(blindedRoute.encryptedPayloads.last().reversed()),
            ),
            blindedPayload
        )
        val onionD = OutgoingPaymentPacket.buildOnion(listOf(blindedRoute.blindedNodeIds.last()), listOf(payloadD), paymentHash, OnionRoutingPacket.PaymentPacketLength)
        val addD = UpdateAddHtlc(randomBytes32(), 1, finalAmount, paymentHash, finalExpiry, onionD.packet, blindedRoute.firstPathKey, null)
        val failure = IncomingPaymentPacket.decrypt(addD, privD)
        assertTrue(failure.isLeft)
        assertEquals(failure.left, InvalidOnionBlinding(hash(addD.onionRoutingPacket)))
    }

    @Test
    fun `fail to decrypt when amount has been modified by trampoline node`() {
        val invoice = Bolt11Invoice.create(Chain.Regtest, finalAmount, paymentHash, privD, Either.Left("test"), CltvExpiryDelta(6), trampolineFeatures, paymentSecret, paymentMetadata)
        val (firstAmount, firstExpiry, onion) = OutgoingPaymentPacket.buildPacketToTrampolineRecipient(invoice, finalAmount, finalExpiry, nodeHop_cd)
        val addC = UpdateAddHtlc(randomBytes32(), 1, firstAmount, paymentHash, firstExpiry, onion.packet)
        val (_, innerC, packetD) = decryptRelayToTrampoline(addC, privC)
        val (amountD, expiryD, onionD) = run {
            val payloadD = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(innerC.amountToForward, innerC.amountToForward, innerC.outgoingCltv, randomBytes32(), packetD)
            encryptChannelRelay(paymentHash, listOf(ChannelHop(c, d, channelUpdateCD)), payloadD)
        }
        val addD = UpdateAddHtlc(randomBytes32(), 2, amountD - 100.msat, paymentHash, expiryD, onionD.packet)
        val failure = IncomingPaymentPacket.decrypt(addD, privD)
        assertEquals(Either.Left(FinalIncorrectHtlcAmount(finalAmount - 100.msat)), failure)
    }

    @Test
    fun `fail to decrypt when expiry has been modified by trampoline node`() {
        val invoice = Bolt11Invoice.create(Chain.Regtest, finalAmount, paymentHash, privD, Either.Left("test"), CltvExpiryDelta(6), trampolineFeatures, paymentSecret, paymentMetadata)
        val (firstAmount, firstExpiry, onion) = OutgoingPaymentPacket.buildPacketToTrampolineRecipient(invoice, finalAmount, finalExpiry, nodeHop_cd)
        val addC = UpdateAddHtlc(randomBytes32(), 1, firstAmount, paymentHash, firstExpiry, onion.packet)
        val (_, innerC, packetD) = decryptRelayToTrampoline(addC, privC)
        val (amountD, expiryD, onionD) = run {
            val payloadD = PaymentOnion.FinalPayload.Standard.createTrampolinePayload(innerC.amountToForward, innerC.amountToForward, innerC.outgoingCltv, randomBytes32(), packetD)
            encryptChannelRelay(paymentHash, listOf(ChannelHop(c, d, channelUpdateCD)), payloadD)
        }
        val addD = UpdateAddHtlc(randomBytes32(), 2, amountD, paymentHash, expiryD - CltvExpiryDelta(12), onionD.packet)
        val failure = IncomingPaymentPacket.decrypt(addD, privD)
        assertEquals(Either.Left(FinalIncorrectCltvExpiry(finalExpiry - CltvExpiryDelta(12))), failure)
    }

    @Test
    fun `fail to decrypt blinded payment when amount is too low`() {
        val (addD, _) = createBlindedHtlcCD()
        // D receives a smaller amount than expected and rejects the payment.
        val failure = IncomingPaymentPacket.decrypt(addD.copy(amountMsat = addD.amountMsat - 1.msat), privD).left
        assertEquals(InvalidOnionBlinding(hash(addD.onionRoutingPacket)), failure)
    }

    @Test
    fun `fail to decrypt blinded payment when expiry is too low`() {
        val (addD, _) = createBlindedHtlcCD()
        // E receives a smaller expiry than expected and rejects the payment.
        val failure = IncomingPaymentPacket.decrypt(addD.copy(cltvExpiry = addD.cltvExpiry - CltvExpiryDelta(1)), privD).left
        assertEquals(InvalidOnionBlinding(hash(addD.onionRoutingPacket)), failure)
    }

    @Test
    fun `prune outgoing blinded paths`() {
        // We create an invoice with a large number of blinded paths.
        val features = Features(Feature.BasicMultiPartPayment to FeatureSupport.Optional)
        val offer = OfferTypes.Offer.createNonBlindedOffer(finalAmount, "test offer", d, features, Block.RegtestGenesisBlock.hash)
        val invoice = run {
            val payerKey = randomKey()
            val request = OfferTypes.InvoiceRequest(offer, finalAmount, 1, features, payerKey, "hello", Block.RegtestGenesisBlock.hash)
            val paymentMetadata = OfferPaymentMetadata.V1(offer.offerId, finalAmount, paymentPreimage, payerKey.publicKey(), "hello", 1, currentTimestampMillis())
            val blindedPayloadD = RouteBlindingEncryptedData(TlvStream(RouteBlindingEncryptedDataTlv.PathId(paymentMetadata.toPathId(privD))))
            val blindedPaths = (0 until 20L).map { i ->
                val blindedPayloadC = RouteBlindingEncryptedData(
                    TlvStream(
                        RouteBlindingEncryptedDataTlv.OutgoingChannelId(ShortChannelId(i)),
                        RouteBlindingEncryptedDataTlv.PaymentRelay(channelUpdateCD.cltvExpiryDelta, channelUpdateCD.feeProportionalMillionths, channelUpdateCD.feeBaseMsat),
                        RouteBlindingEncryptedDataTlv.PaymentConstraints(finalExpiry, 1.msat),
                    )
                )
                val blindedRouteDetails = RouteBlinding.create(randomKey(), listOf(c, d), listOf(blindedPayloadC, blindedPayloadD).map { it.write().byteVector() })
                val paymentInfo = createBlindedPaymentInfo(channelUpdateCD)
                Bolt12Invoice.Companion.PaymentBlindedContactInfo(OfferTypes.ContactInfo.BlindedPath(blindedRouteDetails.route), paymentInfo)
            }
            Bolt12Invoice(request, paymentPreimage, randomKey(), 600, features, blindedPaths)
        }
        // B sends an HTLC to its trampoline node C: we prune the blinded paths to fit inside the onion.
        val (firstAmount, firstExpiry, onion) = OutgoingPaymentPacket.buildPacketToBlindedRecipient(invoice, finalAmount, finalExpiry, nodeHop_cd)
        assertEquals(OnionRoutingPacket.PaymentPacketLength, onion.packet.payload.size())
        val addC = UpdateAddHtlc(randomBytes32(), 1, firstAmount, paymentHash, firstExpiry, onion.packet)
        val (_, innerC) = decryptRelayToBlinded(addC, privC)
        assertTrue(innerC.outgoingBlindedPaths.size < invoice.blindedPaths.size)
        innerC.outgoingBlindedPaths.forEach { assertTrue(invoice.blindedPaths.contains(it)) }
    }

    @Test
    fun `prune outgoing routing info`() {
        // We create an invoice with a large number of routing hints.
        val routingHints = (0 until 50L).map { i -> listOf(Bolt11Invoice.TaggedField.ExtraHop(randomKey().publicKey(), ShortChannelId(i), 5.msat, 25, CltvExpiryDelta(36))) }
        val invoice = Bolt11Invoice.create(Chain.Regtest, finalAmount, paymentHash, privD, Either.Left("test"), CltvExpiryDelta(6), nonTrampolineFeatures, paymentSecret, paymentMetadata, extraHops = routingHints)
        // A sends an HTLC to its trampoline node B: we prune the routing hints to fit inside the onion.
        val (firstAmount, firstExpiry, onion) = OutgoingPaymentPacket.buildPacketToLegacyRecipient(invoice, finalAmount, finalExpiry, nodeHop_bd)
        assertEquals(OnionRoutingPacket.PaymentPacketLength, onion.packet.payload.size())
        val addB = UpdateAddHtlc(randomBytes32(), 1, firstAmount, paymentHash, firstExpiry, onion.packet)
        val (_, innerB) = decryptRelayToLegacy(addB, privB)
        assertTrue(innerB.invoiceRoutingInfo.isNotEmpty())
        assertTrue(innerB.invoiceRoutingInfo.size < routingHints.size)
        innerB.invoiceRoutingInfo.forEach { assertTrue(routingHints.contains(it)) }
    }
}

