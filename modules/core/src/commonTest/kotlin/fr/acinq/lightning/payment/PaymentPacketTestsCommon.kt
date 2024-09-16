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
import fr.acinq.secp256k1.Hex
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
            Feature.TrampolinePayment to FeatureSupport.Optional,
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
            assertTrue(decryptedInner.isLastPacket)
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

    // See bolt04/trampoline-payment-onion-test.json
    @Test
    fun `send a trampoline payment -- reference test vector`() {
        //                    .-> Dave -.
        //                   /           \
        // Alice -> Bob -> Carol         Eve
        val paymentHash = ByteVector32("4242424242424242424242424242424242424242424242424242424242424242")
        // Alice creates a trampoline onion Carol -> Eve.
        val trampolineOnionForCarol = run {
            val paymentSecret = ByteVector32("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a")
            val carol = PublicKey.fromHex("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007")
            val eve = PublicKey.fromHex("02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145")
            val payloads = listOf(
                PaymentOnion.NodeRelayPayload.create(100_000_000.msat, CltvExpiry(800_000), eve),
                PaymentOnion.FinalPayload.Standard.createSinglePartPayload(100_000_000.msat, CltvExpiry(800_000), paymentSecret, paymentMetadata = null),
            )
            val sessionKey = PrivateKey.fromHex("0303030303030303030303030303030303030303030303030303030303030303")
            OutgoingPaymentPacket.buildOnion(sessionKey, listOf(carol, eve), payloads, paymentHash).packet
        }
        assertEquals(
            "0002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe3371860c0749bfd613056cfc5718beecc25a2f255fc7abbea3cd75ff820e9d30807d19b30f33626452fa54bb2d822e918558ed3e6714deb3f9a2a10895e7553c6f088c9a852043530dbc9abcc486030894364b205f5de60171b451ff462664ebce23b672579bf2a444ebfe0a81875c26d2fa16d426795b9b02ccbc4bdf909c583f0c2ebe9136510645917153ecb05181ca0c1b207824578ee841804a148f4c3df7306dcea52d94222907c9187bc31c0880fc084f0d88716e195c0abe7672d15217623",
            Hex.encode(OnionRoutingPacketSerializer(trampolineOnionForCarol.payload.size()).write(trampolineOnionForCarol)),
        )
        // Alice wraps it into a payment onion Alice -> Bob -> Carol.
        val onionForBob = run {
            val paymentSecret = ByteVector32("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b")
            val bob = PublicKey.fromHex("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c")
            val carol = PublicKey.fromHex("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007")
            val payloads = listOf(
                PaymentOnion.ChannelRelayPayload.create(ShortChannelId("572330x7x1105"), 100_005_000.msat, CltvExpiry(800_250)),
                PaymentOnion.FinalPayload.Standard.createTrampolinePayload(100_005_000.msat, 100_005_000.msat, CltvExpiry(800_250), paymentSecret, trampolineOnionForCarol),
            )
            val sessionKey = PrivateKey.fromHex("0404040404040404040404040404040404040404040404040404040404040404")
            OutgoingPaymentPacket.buildOnion(sessionKey, listOf(bob, carol), payloads, paymentHash, OnionRoutingPacket.PaymentPacketLength).packet
        }
        assertEquals(
            "0003462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b9149ce01cce1709194109ab594037113e897ab6120025c770527dd8537997e2528082b984fe078a5667978a573abeaf7977d9b8b6ee4f124d3352f7eea52cc66c0e76b8f6d7a25d4501a04ae190b17baff8e6378b36f165815f714559dfef275278eba897f5f229be70fc8a1980cf859d1c25fe90c77f006419770e19d29ba80be8f613d039dd05600734e0d1e218af441fe30877e717a26b7b37c2c071d62bf6d61dd17f7abfb81546d2c722c9a6dc581aa97fb6f3b513e5fbaf0d669fbf0714b2b016a0a8e356d55f267fa144f7501792f2a59269c5a22e555a914e2eb71eba5af519564f246cf58983ea3fa2674e3ab7d9969d8dffbb2bda2b2752657417937d46601eb8ebf1837221d4bdf55a4d6a97ecffde5a09bd409717fa19e440e55d775890aed89f72e65af515757e94a9b501e6bad048af55e1583adb2960a84f60fb5efd0352e77a34045fc6b221498f62810bd8294d995d9f513696f8633f29faaa9668d0c6fa0d0dd7fa13e2c185572485762bd2810dc12187f521fbefa9c320762ac1e107f7988d81c6ee201ab68a95d45d578027e271b6526154317877037dca17134ccd955a22a8481b8e1996d896fc4bf006154ed18ef279d4f255e3f1233d037aea2560011069a0ae56d6bfdd8327054ded12d85d120b8982bff970986db333baae7c95f85677726a8f74cc8bd1e5aca3d433c113048305ecce8e35caf0485a53df00284b52b42291a9ffe686b96442135b3107d8856bc652d674ee9a148e79b02c9972d3ca8c2b02609f3b358c4a67c540ba6769c4d83169bceda640b1d18b74d12b6df605b417dacf6f82d79d43bb40920898f818dc8344c036ae9c8bbf9ef52ea1ccf225c8825a4d8503df190b999e15a4be34c9d7bbf60d3b93bb7d6559f4a5916f5e40c3defeeca9337ccd1280e46d6727c5c91c2d898b685543d4ca7cfee23981323c43260b6387e7febb0fffb200a8c974ef36b3253d0fb9fe0c1c6017f2dbbdc169f3f061d9781521e8118164aeec31c3e59c199016f1025c295d8f7bdeb627d357105a2708c4c3a856b9e83ff37ed69f59f2d2e464ed1db5882925ebe2493a7ddb707e1a308fa445172a24b3ea60732f75f5c69b41fc11467ee93f37c9a6f7285ba42f716e2a0e30909056ea3e4f7985d14ca9ab280cc184ce98e2a0722d0447aa1a2eedc5e53ddfa53731df7eced406b10627b0bebd768a30bde0d470c0f1d10adc070f8d3029cacceec74e4833f4dc8c52c3f41733f5f896fceb425d0737e717a63bfb033df46286d99594dd01e2bd0a942ab792874177b32842f4833bc0340ddb74852e9cd6f29f1d997a4a4bf05dd5d12011f95e6ce18928e3a9b83b24d15f989bdf43370bcc657c3ac6601eaf5e951efdbd7ee69b1623dc5039b2dfc640692378ef032f17bc36cc00293ad90b7e18f5feb8f287a7061ed9713929aed9b14b8d566199fc7822b1c38daa16b6d83077b10af0e2b6e531ccc34ea248ea593128c9ff17defcee6618c29cd2d93cfed99b90319104b1fdcfea91e98b41d792782840fb7b25280d8565b0bcd874e79b1b323139e7fc88eb5f80f690ce30fcd81111076adb31de6aeced879b538c0b5f2b74c027cc582a540133952cb021424510312f13e15d403f700f3e15b41d677c5a1e7c4e692c5880cb4522c48e993381996a29615d2956781509cd74aec6a3c73b8536d1817e473dad4cbb1787e046606b692a44e5d21ef6b5219658b002f674367e90a2b610924e9ac543362257d4567728f2e61f61231cb5d7816e100bb6f6bd9a42329b728b18d7a696711650c16fd476e2f471f38af0f6b00d45c6e1fa492cc7962814953ab6ad1ce3d3f3dc950e64d18a8fdce6aabc14321576f06",
            Hex.encode(OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).write(onionForBob))
        )
        // Bob decrypts the payment onion and forwards it to Carol.
        val onionForCarol = run {
            val priv = PrivateKey.fromHex("4242424242424242424242424242424242424242424242424242424242424242")
            val add = UpdateAddHtlc(randomBytes32(), 1, 100_006_000.msat, paymentHash, CltvExpiry(800_300), onionForBob)
            decryptChannelRelay(add, priv).second
        }
        assertEquals(
            "00036d7fa1507cac3a1fda3308b465b71d817a2ee8dfde598c6bdb1dec73c7acf0165136fdd0fd9f3f7eac074f42b015825614214ac3b7ec95234538c9cfd04fc1a5128fa47c8d56e21e51bb843da8252c0abafb72395cf6ca8a186bd1de72341cb0f988e79988c39e4d444a4495120ccf3577576177a45c2a0fdc88776291d3af9e62d700c06206c769260859715ba5e1e7c0dc5f97dbf80decb564c885d0d6f0e10bddb225ee3d82a1e02b6a3735ea81ab91dada382a5752a940814e38c709e62d3427d69bfd09a19955c507aea300bf10578e3bda3d632a5de159f3fc0ff9311b2fc5d4a6c03582c4cd85c92d29bc285971f1019cb468942a7d3706e096f6ab105e7d8d525586a4f7987135af70d166317dc2b5b6c58345c54e87615d277e7ade5f0b9f8baed5f16e1b340492c4fa6b443f94544a4f083e4dfb778badf1084c0c39e998cd67ff5f1a6526fb163cfd48e04ff34d928a91f061781463b9f668a0d084e6c5bb80413968ee3185abd545b38f63f496d9fa16e67d84c08414df8c03d0efb1925edcdd14a4134424f65372166be4a8e66906a428eb726ae43ea6cf81256f082382e18b765e78cd21819045b5bcc5f4464b812215f8838acf73c5a4748a09ee10b6bcec9c201dc38ef009b23b9072d653c81316a59b36533732f4c4eeb29863bcf420155aa90378a111f0393599fb9dd42f69808c3552654b7352a6a1e2a71db0a0214c8d9021ef52d667da4d351a9a44a0cdbff34894d1994e7cced665061b6979f9e508d98ac9b2193f01694597e8189122daf0bd3c82743f5994678b4efb309028be23987bc18720388bc78be39b02276a0f3577390e36a5cd0dbab97b08a5c7f45a5a952681a2669e653004977b2a1e098a5bfee2ee927c2f51fc9dc66af120b5a40b01738c5db1e091f7141096e3c4d5905a695f02c852fd40412c7288c15befb522eec41232899863c17f66cbfefb3597c346fc7483a03d0f3f2dcaa6ae56d508d0df9298d80b2bcfcb91b30b298ca2415a3cbc8284bb2f4a5cfc244efe2d78a446d36d350bebd7ff30d70a2015679f1a3a63d841e2333fa30ebabf9d84576616f3c93a78a42948d991e1c628c3dbb3ad856fe97f9a3ce3d2b7e8e3ff2e1c3b2eb494dd9c947878120a8912afda70ca7d7829b9011f13c848d10e69274f4bd918c4c5531c8382e5f1c0b72ecabbd34d14190cde1a3247e4473c8016a122077f4a9cddf21c11680c2c25c342dacc7676304dd2466b47a172641e33de3cf9c2f476f57e0a90cdb7f8398dc012fd65df9a685a73b8f6f02a2ba3045e0cb308a72645370c827ac43da67f614e2d68b7811805b8144e6f21e94b679003486aa79bad22db09735d72e5a32c5831c3e44c9100322ae70c74df52ba98653624361b62d9500b704450e6e23d3373aae9697fed5e6133d1d1677608be513344590fd72569c6e19c070d303e8aa6f7196e7ac0f4039912cf1e9f050c6927340f9a96de229adbe7906072bc87c2214dc476d8dc7d81f2cb56d5a7407fe9fb378703f04fe19f1bb4b8f938c84072a4ac0b18de581b4b8b5971ce411cc82a0484764a6df49f8ffc3c858a299b4ffc9f96b933bd12f4fc876b6ce34f7c022ded91d51a03c5f14c29a9f7b28e45395782d74a3d795ac596b44ba36f805d62e3ba7976f10904784af7f5994cc57817979a0adf87e3b3e32047f0a4d68c2609c9405612b264094c49dd27836f4bdab4d68256b2b4d8e10411ff166065265fdd0c04c6c3ad989530f258b9549128765f0cc6af5e50cf15d3fd856e91580bf66a7ebce267726aee798b580df6deaee59fa90c5a35e06f36d4960c326d0418adcbe3ff4248bf04dc24a3758de2c58f97fd9e4333beae43428d184e3872ad52d2b4dd4d770da0dca339bf70a6b22dd05cf8547ec0a7a8d49543",
            Hex.encode(OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).write(onionForCarol))
        )
        // Carol decrypts the payment onion and the inner trampoline onion.
        val trampolineOnionForEve = run {
            val priv = PrivateKey.fromHex("4343434343434343434343434343434343434343434343434343434343434343")
            val add = UpdateAddHtlc(randomBytes32(), 1, 100_005_000.msat, paymentHash, CltvExpiry(800_250), onionForCarol)
            decryptRelayToTrampoline(add, priv).third
        }
        assertEquals(
            "00035e5c85814fdb522b4efeef99b44fe8a5d3d3412057bc213b98d6f605edb022c2ae4a9141f6ac403790afeed975061f024e2723d485f9cb35a3eaf881732f468dc19009bf195b561590798fb895b7b7065b5537018dec330e509e8618700c9c6e1df5d15b900ac3c34104b6abb1099fd2eca3b640d7d5fda9370e20c09035168fc64d954baa80361b965314c400da2d7a64d0536bf9e494aebb80aec358327a4a1a667fcff1daf241c99dd8c4fa907de5b931fb9daed083c157f5ea1dd960d142952f8ebe4e1ccaee4d565a093e2b91f94b04a884ce2e8c60aced3565e8d2d10de5",
            Hex.encode(OnionRoutingPacketSerializer(trampolineOnionForEve.payload.size()).write(trampolineOnionForEve)),
        )
        // Carol wraps the trampoline onion for Eve into a payment Carol -> Dave -> Eve.
        val onionForDave = run {
            val paymentSecret = ByteVector32("2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c")
            val dave = PublicKey.fromHex("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991")
            val eve = PublicKey.fromHex("02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145")
            val payloads = listOf(
                PaymentOnion.ChannelRelayPayload.create(ShortChannelId("572330x42x1729"), 100_000_000.msat, CltvExpiry(800_000)),
                PaymentOnion.FinalPayload.Standard.createTrampolinePayload(100_000_000.msat, 100_000_000.msat, CltvExpiry(800_000), paymentSecret, trampolineOnionForEve),
            )
            val sessionKey = PrivateKey.fromHex("0505050505050505050505050505050505050505050505050505050505050505")
            OutgoingPaymentPacket.buildOnion(sessionKey, listOf(dave, eve), payloads, paymentHash, OnionRoutingPacket.PaymentPacketLength).packet
        }
        assertEquals(
            "000362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f74125c590a7877d17303ddcdce79b0b33e006eaf4eff557631c70c7ab9a61105ffd738239016e84c2639ff5246f3d2167ea7ea7932138435a9cc427f7f9d838daa2b7f4c3bfb8c44e8e48d2fd744c1c5a7626d188b5690d36900eb0a498cd0b4139424bc1b65d74409a72fca8e36f239f4c80644963e80391ca1c707f727e3dc9656de66bfdf77823b0b5746c55c31978faffd65937b2c526478e4f30d08cc371fb9d045f65316af2d416c9a82ac412db84e4386901877670c8a2fcdd1b2f3276c5384f2feb23d4c62788cce78edc1194bf4fbd2af5670d2917cc940c41897fea944ebf908a1a90a1bd208b42209ccf2d480d2590bfce320ce185f12e77703f906e98b1a9ff701490b792a60faba11d75d691c2cecf867bb63062ec8c3bd1c2665dbd380e59cdffbfd028e5c86a1371fd3d5141e50986247a9f21143df0d1099e6df7e2044f1f4a87bc759cb7c2354616e39ace2d06165a580206ae9c5bc5005a6654215e7ab1bb619eb2df5bc11e3a8cfbc0a9c7e515c0f6d9d02512ef856d4782e54192ea63a173b4fcf02a11e85d2da6de47a6f8dd9bbfb30dccecd5e2195d5c9b0bf0bfc8b571b4962deacba4669afa017294b45e2668ad87168b9589f00f56275022f049f0cdece8c9e1f0f35035aa1af4a70103a7e8aa2b7a6579accf554c6a4f305981f5732036894765e086c167f5f342f313e4617da53b79303c72e0a6f03c3f592cb9c035c509c02dc09e5ea20b158a3f47b1722db86d354f7dfccbdaf6be21c7f473e143b459b2b06a21984f29ba80dfcd52696c76fb2a11f66383e33d88226f451317125fcfa02671015c359db52ee1462b1b820588d5c874765de4e7cc83b84dde8630b2a21325116cf53fd1eb369bed1330dfcbe0633698c518a376312624d78011922621e32e9b316a9329c3d1f967069d35844e60caf53e7a2bbbe695808de2e91dc16a9dd408ab2a8c363f2a5c34124f9c79010db4706e1315e1ff230741a9ab7e069318db587004bd0ccb71aad37c616b276bc0fe883865ba730b4d86ce2ae710185747d0860e00bb37b97fe71d79492a2e9a3bc07e5693f92de886fab3802ac62a8a4adcbf041eec05152cd28fd77154799e99674c8ea571519186ad9eb84a26edcef86473621e05515f3278810f931c662d037d9da73612c2f9d7d64e573595c402e9166299cbe356119ca38a3c6da77d6f864d61062b4300e388b631f60c25cb364b76561b4064c13e9e25d1ecb491472047157ea04fbbf6ccfe36cb2c030250b0335ae00255cf3670a61a5f207d72fccaac0b36a74d041f62341bc3759cd17d6e1c81aafcbbdc0f29906e54bc66dc1217031f881c9782eabe09de6835cdf4426113fb28e3bc0a73b007521c9a5abdc4a602c3c3358f0d3d81c8d84da5cc8acf1d15c9dd038ca64229097c666099a701b47bcf3a35e2541d4554a7bc1e3d4693b031c35f33b063d339558911870dd8bc3a52895612bee20ea8a7b0110da64362a357a4f9dbd7ff01155278c1173c57dd3d1b0947e58b571673544dbeff1c19cdb0ab9901671b3d043c4173fbcdf8e9cb03585bb9987414080046b6f283fc7c3aa245152941138636cd1b201e59080b8a7257bc2d7046c18d738c64804b088ac0983fbaeb92624f3ddc175afa3afc85cc8d83815bea41a195e883a4044a6406dbcb67682fc0522d2c920bc1d2372e95ea31408fcbe53e91c787e6da85255c40d0c9dbb0d4a5ded5886c90664bec4396f94782851fcd8565562a9df646025ad224078add8a05b8614ad0ce33141213a4650590ebaef22ef10b9cca5c4025eeaf58796baf052824d239586d7c706431fa1240f36a4f882d36ca608ece021b803386356f13a22bf3f42ef39d",
            Hex.encode(OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).write(onionForDave))
        )
        // Dave decrypts the payment onion and forwards it to Eve.
        val onionForEve = run {
            val priv = PrivateKey.fromHex("4444444444444444444444444444444444444444444444444444444444444444")
            val add = UpdateAddHtlc(randomBytes32(), 1, 100_001_000.msat, paymentHash, CltvExpiry(800_100), onionForDave)
            decryptChannelRelay(add, priv).second
        }
        assertEquals(
            "00037d517980f2321ce95c8ecea4aebceb2f62ebbbac598973439c79e9f66d28ce5c728d3226c796b85df07009baec8b4e46d73bf6bbf6f8dfa8bcf610bda5de6ebaf395b5a8572e30e91e402688834a13db55d04c28dc1bfdcc07c602532330ee6ce1bd6acce875c81fd53b8f7f4243ed940bb5e4897252763968a00c2b59d6cbfdf73bd86e4b9135a63dcf99612da557962da6b525c68b3159e4f56cd49cf654ca6240ec5a0c2365731266eb4263e16c90aed2fbd662de9aa22ce7bf8af18687d99550e48477c6c46f8a84957d24ac323381e69b57342d82e06082c645fcd96eb77ed4f563f04e7e7913e4bac16a78e56d223baead194b4cd80c97fa7d892d0288780ac90f1020e0cb43e267721bbbdd6fb759da9df2744882f4259a4e5bab60aaca2847311122c1d60a483c978d7b3042ae189892f85e1e7e3ad89d48769404b5dea1ddf1794b3c6b002286995e976b1de9c2457895a00952a06983986a619863e4c60f17e40a210e89273fa7f55ebd83887d451b5e658b9092e81540de49a4e4a05a757aa103ca5dc63194094869f067d5cc36e2d59de9d038f3b5a4b6fa4fd5b276db7b77182ddc96eaf53bfbfa2f988b785643047a5639965dde3baafeac2db4efbdf04da3520766c012c988d64c9e3aa2f723baa4926e413b18b93bdeec4e0761ef55bedea1de8751b49cb8a67a15ddeae511e06f03d36c2158aba897997c53a2f12e2db98214b093c0ee3c5fe6763dc7a3418db28a571a88da50a851eac78f78c29c489d6a09751976f4e456ffa23b71b3894e9263476d490e842de6a41fd085bf218691b1de3b4cf077f560fc86dd7f8d24c06912e5b9d53fc7b36d3f5bcde6cb9f22d5db09c0ec4e870466d0549f5fcd0e6849aa925f3f238b1a613c022ea22dc308899330113b60576b7fc8904233a77cf24ad2f9482cdc1265f6e74353d92d4fbff4a0a42dfebb92ac71c7fc2c79ccd1b187bd4542ed2d1808735179bebaba664f49a75d2823f7e7041e1cc0f717899b7eb2c2b9550be185f1a0b2245a48fdc205c5339742ad14e370193158997f4d4edff05297a4668705f667b2a858a0b8af56aa4b93fb41b30e16a50a75fdc0ce33dd94da254d8b1e55c40aa49444aacf4796a6979f0feca13924ff3a886d3e859e51d2d585ee919abcc82c396da1df7a4e97f415a01c25c1a5ae2fe65f4cc385e16d91e54836e12e7588d89ee41dfef277b97eb7d6c6ebfc6ed4f89b13d776904fad6e405123bca86068dc558dbbc284c65947f295b8828e7e35e80fd0981ba46229d47e646afa73f55070ae4a202b8c46719e6449632a4377eedbe83a69d1f422e73bc159172e631165dc5fe63e09dcace38218de2598204127255535d6c2197003383195af636cfd8615bd8a5db96057fe4ee67156685351d90c3db5bf61d3e573877572f58f982d9fbb35bd678143ccc1f2cccf1fd34c20e0a59b4c837540fac3964068eec3ffb8981a2ab774c542f74168ccd7fa9b08141cd0bda0d99ecee10a3857818370456c3c00d3f7b514f30ff6c31f11147851c8438411de3fc71719fbf79df3cab963231732c95850d59df90144161c2ef84a8b1c76a9494b8dd7234782bc61a6fc23222599a14163f78e117c99f33b3d2a4b11339903b41e7cfc253f1319d4c3ab1dc3d31a503c0bf9c233cb9216201d71abf915b8e50c0612b1fdba8ea8f248767256597151ba2f58dd67d470f8cfdfdc0bffceba618587f652a2155c58717a85e1eff38149b521f99449b35ed2a5ecb474fe60257d261017386ae08ea61cf907ebb7d2d5b1a55e50088449563d1d788d8b4f18ee57e24c6cab40dcd569495c6ea13fa1ca68dbeb6fed7462444ca94b6561471b4e1a75945d7327e5e56348bbd5cae106bf74976cc9288394a731b3555401e59c2718001171b6d6",
            Hex.encode(OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength).write(onionForEve))
        )
        // Eve decrypts the payment onion and the inner trampoline onion.
        run {
            val priv = PrivateKey.fromHex("4545454545454545454545454545454545454545454545454545454545454545")
            val add = UpdateAddHtlc(randomBytes32(), 1, 100_000_000.msat, paymentHash, CltvExpiry(800_000), onionForEve)
            val payload = IncomingPaymentPacket.decrypt(add, priv).right
            assertNotNull(payload)
            assertIs<PaymentOnion.FinalPayload.Standard>(payload)
            assertEquals(payload.amount, 100_000_000.msat)
            assertEquals(payload.totalAmount, 100_000_000.msat)
            assertEquals(payload.expiry, CltvExpiry(800_000))
            assertEquals(payload.paymentSecret, ByteVector32("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"))
        }
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
        assertEquals(finalExpiry, innerB.outgoingCltv)
        assertEquals(d, innerB.outgoingNodeId)
        assertEquals(invoice.paymentSecret, outerB.paymentSecret)
        assertEquals(invoice.paymentMetadata, innerB.paymentMetadata)
        assertEquals(ByteVector("024100"), innerB.invoiceFeatures) // var_onion_optin, payment_secret, basic_mpp
        assertEquals(listOf(routingHint), innerB.invoiceRoutingInfo)

        // B forwards the trampoline payment to D over an indirect channel route.
        val (amountC, expiryC, onionC) = run {
            val payloadD = PaymentOnion.FinalPayload.Standard.createSinglePartPayload(innerB.amountToForward, innerB.outgoingCltv, outerB.paymentSecret, innerB.paymentMetadata)
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
        val paymentMetadata = OfferPaymentMetadata.fromPathId(d, payloadD.pathId)
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
        assertEquals(paymentMetadata, OfferPaymentMetadata.fromPathId(d, payloadD.pathId))
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

