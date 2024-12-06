package fr.acinq.lightning.wire

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.byteVector
import fr.acinq.lightning.*
import fr.acinq.lightning.crypto.RouteBlinding
import fr.acinq.lightning.payment.Bolt11Invoice
import fr.acinq.lightning.payment.Bolt12Invoice
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PaymentOnionTestsCommon : LightningTestSuite() {

    @Test
    fun `encode - decode onion packet`() {
        val bin = Hex.decode(
            "0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a71da571226458c510bbadd1276f045c21c520a07d35da256ef75b4367962437b0dd10f7d61ab590531cf08000178a333a347f8b4072e216400406bdf3bf038659793a86cae5f52d32f3438527b47a1cfc54285a8afec3a4c9f3323db0c946f5d4cb2ce721caad69320c3a469a202f3e468c67eaf7a7cda226d0fd32f7b48084dca885d15222e60826d5d971f64172d98e0760154400958f00e86697aa1aa9d41bee8119a1ec866abe044a9ad635778ba61fc0776dc832b39451bd5d35072d2269cf9b040d6ba38b54ec35f81d7fc67678c3be47274f3c4cc472aff005c3469eb3bc140769ed4c7f0218ff8c6c7dd7221d189c65b3b9aaa71a01484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565ae82cd3f4e3b24c76eaa5616c6111343306ab35c1fe5ca4a77c0e314ed7dba39d6f1e0de791719c241a939cc493bea2bae1c1e932679ea94d29084278513c77b899cc98059d06a27d171b0dbdf6bee13ddc4fc17a0c4d2827d488436b57baa167544138ca2e64a11b43ac8a06cd0c2fba2d4d900ed2d9205305e2d7383cc98dacb078133de5f6fb6bed2ef26ba92cea28aafc3b9948dd9ae5559e8bd6920b8cea462aa445ca6a95e0e7ba52961b181c79e73bd581821df2b10173727a810c92b83b5ba4a0403eb710d2ca10689a35bec6c3a708e9e92f7d78ff3c5d9989574b00c6736f84c199256e76e19e78f0c98a9d580b4a658c84fc8f2096c2fbea8f5f8c59d0fdacb3be2802ef802abbecb3aba4acaac69a0e965abd8981e9896b1f6ef9d60f7a164b371af869fd0e48073742825e9434fc54da837e120266d53302954843538ea7c6c3dbfb4ff3b2fdbe244437f2a153ccf7bdb4c92aa08102d4f3cff2ae5ef86fab4653595e6a5837fa2f3e29f27a9cde5966843fb847a4a61f1e76c281fe8bb2b0a181d096100db5a1a5ce7a910238251a43ca556712eaadea167fb4d7d75825e440f3ecd782036d7574df8bceacb397abefc5f5254d2722215c53ff54af8299aaaad642c6d72a14d27882d9bbd539e1cc7a527526ba89b8c037ad09120e98ab042d3e8652b31ae0e478516bfaf88efca9f3676ffe99d2819dcaeb7610a626695f53117665d267d3f7abebd6bbd6733f645c72c389f03855bdf1e4b8075b516569b118233a0f0971d24b83113c0b096f5216a207ca99a7cddc81c130923fe3d91e7508c9ac5f2e914ff5dccab9e558566fa14efb34ac98d878580814b94b73acbfde9072f30b881f7f0fff42d4045d1ace6322d86a97d164aa84d93a60498065cc7c20e636f5862dc81531a88c60305a2e59a985be327a6902e4bed986dbf4a0b50c217af0ea7fdf9ab37f9ea1a1aaa72f54cf40154ea9b269f1a7c09f9f43245109431a175d50e2db0132337baa0ef97eed0fcf20489da36b79a1172faccc2f7ded7c60e00694282d93359c4682135642bc81f433574aa8ef0c97b4ade7ca372c5ffc23c7eddd839bab4e0f14d6df15c9dbeab176bec8b5701cf054eb3072f6dadc98f88819042bf10c407516ee58bce33fbe3b3d86a54255e577db4598e30a135361528c101683a5fcde7e8ba53f3456254be8f45fe3a56120ae96ea3773631fcb3873aa3abd91bcff00bd38bd43697a2e789e00da6077482e7b1b1a677b5afae4c54e6cbdf7377b694eb7d7a5b913476a5be923322d3de06060fd5e819635232a2cf4f0731da13b8546d1d6d4f8d75b9fce6c2341a71b0ea6f780df54bfdb0dd5cd9855179f602f917265f21f9190c70217774a6fbaaa7d63ad64199f4664813b955cff954949076dcf"
        )
        val expected = OnionRoutingPacket(
            0, ByteVector("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), ByteVector(
                "e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a71da571226458c510bbadd1276f045c21c520a07d35da256ef75b4367962437b0dd10f7d61ab590531cf08000178a333a347f8b4072e216400406bdf3bf038659793a86cae5f52d32f3438527b47a1cfc54285a8afec3a4c9f3323db0c946f5d4cb2ce721caad69320c3a469a202f3e468c67eaf7a7cda226d0fd32f7b48084dca885d15222e60826d5d971f64172d98e0760154400958f00e86697aa1aa9d41bee8119a1ec866abe044a9ad635778ba61fc0776dc832b39451bd5d35072d2269cf9b040d6ba38b54ec35f81d7fc67678c3be47274f3c4cc472aff005c3469eb3bc140769ed4c7f0218ff8c6c7dd7221d189c65b3b9aaa71a01484b122846c7c7b57e02e679ea8469b70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6565ae82cd3f4e3b24c76eaa5616c6111343306ab35c1fe5ca4a77c0e314ed7dba39d6f1e0de791719c241a939cc493bea2bae1c1e932679ea94d29084278513c77b899cc98059d06a27d171b0dbdf6bee13ddc4fc17a0c4d2827d488436b57baa167544138ca2e64a11b43ac8a06cd0c2fba2d4d900ed2d9205305e2d7383cc98dacb078133de5f6fb6bed2ef26ba92cea28aafc3b9948dd9ae5559e8bd6920b8cea462aa445ca6a95e0e7ba52961b181c79e73bd581821df2b10173727a810c92b83b5ba4a0403eb710d2ca10689a35bec6c3a708e9e92f7d78ff3c5d9989574b00c6736f84c199256e76e19e78f0c98a9d580b4a658c84fc8f2096c2fbea8f5f8c59d0fdacb3be2802ef802abbecb3aba4acaac69a0e965abd8981e9896b1f6ef9d60f7a164b371af869fd0e48073742825e9434fc54da837e120266d53302954843538ea7c6c3dbfb4ff3b2fdbe244437f2a153ccf7bdb4c92aa08102d4f3cff2ae5ef86fab4653595e6a5837fa2f3e29f27a9cde5966843fb847a4a61f1e76c281fe8bb2b0a181d096100db5a1a5ce7a910238251a43ca556712eaadea167fb4d7d75825e440f3ecd782036d7574df8bceacb397abefc5f5254d2722215c53ff54af8299aaaad642c6d72a14d27882d9bbd539e1cc7a527526ba89b8c037ad09120e98ab042d3e8652b31ae0e478516bfaf88efca9f3676ffe99d2819dcaeb7610a626695f53117665d267d3f7abebd6bbd6733f645c72c389f03855bdf1e4b8075b516569b118233a0f0971d24b83113c0b096f5216a207ca99a7cddc81c130923fe3d91e7508c9ac5f2e914ff5dccab9e558566fa14efb34ac98d878580814b94b73acbfde9072f30b881f7f0fff42d4045d1ace6322d86a97d164aa84d93a60498065cc7c20e636f5862dc81531a88c60305a2e59a985be327a6902e4bed986dbf4a0b50c217af0ea7fdf9ab37f9ea1a1aaa72f54cf40154ea9b269f1a7c09f9f43245109431a175d50e2db0132337baa0ef97eed0fcf20489da36b79a1172faccc2f7ded7c60e00694282d93359c4682135642bc81f433574aa8ef0c97b4ade7ca372c5ffc23c7eddd839bab4e0f14d6df15c9dbeab176bec8b5701cf054eb3072f6dadc98f88819042bf10c407516ee58bce33fbe3b3d86a54255e577db4598e30a135361528c101683a5fcde7e8ba53f3456254be8f45fe3a56120ae96ea3773631fcb3873aa3abd91bcff00bd38bd43697a2e789e00da6077482e7b1b1a677b5afae4c54e6cbdf7377b694eb7d7a5b913476a5be923322d3de06060fd5e819635232a2cf4f0731da13b8546d1d6d4f8d75b9fce6c2341a71b0ea6f780df54bfdb0dd5cd9855179f602f9172"
            ), ByteVector32("65f21f9190c70217774a6fbaaa7d63ad64199f4664813b955cff954949076dcf")
        )

        val serializer = OnionRoutingPacketSerializer(OnionRoutingPacket.PaymentPacketLength)
        val decoded = serializer.read(bin)
        assertEquals(decoded, expected)

        val encoded = serializer.write(decoded)
        assertContentEquals(bin, encoded)
    }

    @Test
    fun `encode - decode channel relay per-hop payload`() {
        val testCases = mapOf(
            PaymentOnion.ChannelRelayPayload.create(ShortChannelId(0), MilliSatoshi(0), CltvExpiry(0)) to Hex.decode("0e 0200 0400 06080000000000000000"),
            PaymentOnion.ChannelRelayPayload.create(ShortChannelId(42), MilliSatoshi(142000), CltvExpiry(500000)) to Hex.decode("14 0203022ab0 040307a120 0608000000000000002a"),
            PaymentOnion.ChannelRelayPayload.create(ShortChannelId(561), MilliSatoshi(1105), CltvExpiry(1729)) to Hex.decode("12 02020451 040206c1 06080000000000000231"),
            PaymentOnion.ChannelRelayPayload.create(ShortChannelId("572330x7x1105"), MilliSatoshi(100_005_000), CltvExpiry(800_250)) to Hex.decode("15 020405f5f488 04030c35fa 060808bbaa0000070451"),
            PaymentOnion.ChannelRelayPayload.create(ShortChannelId("572330x42x1729"), MilliSatoshi(100_000_000), CltvExpiry(800_000)) to Hex.decode("15 020405f5e100 04030c3500 060808bbaa00002a06c1"),
        )

        testCases.forEach {
            val expected = it.key
            val decoded = PaymentOnion.ChannelRelayPayload.read(it.value).right!!
            assertEquals(expected, decoded)
            val encoded = decoded.write()
            assertContentEquals(it.value, encoded)
        }
    }

    @Test
    fun `encode - decode blinded channel relay payload`() {
        val testCases = mapOf(
            // @formatter:off
            TlvStream(OnionPaymentPayloadTlv.EncryptedRecipientData(ByteVector("0ae636dc5963bcfe3a2f055c8b8f6d2c5cd818362032404a6e35995ba57e101eac7e5fa04bb33a8920f1")), OnionPaymentPayloadTlv.PathKey(PublicKey.fromHex("02988face71e92c345a068f740191fd8e53be14f0bb957ef730d3c5f76087b960e"))) to Hex.decode("4f 0a2a0ae636dc5963bcfe3a2f055c8b8f6d2c5cd818362032404a6e35995ba57e101eac7e5fa04bb33a8920f1 0c2102988face71e92c345a068f740191fd8e53be14f0bb957ef730d3c5f76087b960e"),
            // @formatter:on
        )

        testCases.forEach {
            val encoded = PaymentOnion.PerHopPayload.tlvSerializer.write(it.key)
            assertContentEquals(it.value, encoded)
            val decoded = PaymentOnion.BlindedChannelRelayPayload.read(it.value).right!!
            assertEquals(it.key, decoded.records)
        }
    }

    @Test
    fun `encode - decode node relay per-hop payload`() {
        val nodeId = PublicKey(Hex.decode("02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145"))
        val expected = PaymentOnion.NodeRelayPayload(TlvStream(OnionPaymentPayloadTlv.AmountToForward(100_000_000.msat), OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(800_000)), OnionPaymentPayloadTlv.OutgoingNodeId(nodeId)))
        val bin = Hex.decode("2e 020405f5e100 04030c3500 0e2102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145")

        val decoded = PaymentOnion.NodeRelayPayload.read(bin).right!!
        assertEquals(expected, decoded)
        assertEquals(decoded.amountToForward, 100_000_000.msat)
        assertEquals(decoded.totalAmount, 100_000_000.msat)
        assertEquals(decoded.outgoingCltv, CltvExpiry(800_000))
        assertEquals(decoded.outgoingNodeId, nodeId)

        val encoded = expected.write()
        assertContentEquals(bin, encoded)
    }

    @Test
    fun `encode - decode node relay to blinded per-hop payload`() {
        val blindedPath = RouteBlinding.BlindedRoute(
            EncodedNodeId(PublicKey.fromHex("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991")),
            PublicKey.fromHex("02988face71e92c345a068f740191fd8e53be14f0bb957ef730d3c5f76087b960e"),
            listOf(
                RouteBlinding.BlindedHop(
                    PublicKey.fromHex("0295d40514096a8be54859e7dfe947b376eaafea8afe5cb4eb2c13ff857ed0b4be"),
                    ByteVector("0ae636dc5963bcfe3a2f055c8b8f6d2c5cd818362032404a6e35995ba57e101eac7e5fa04bb33a8920f1")
                ),
                RouteBlinding.BlindedHop(
                    PublicKey.fromHex("020e2dbadcc2005e859819ddebbe88a834ae8a6d2b049233c07335f15cd1dc5f22"),
                    ByteVector("bc211f6ccd409888ca8ab027a5f21d229f9e18ff02cc1161a8344c91bdefc742d221db962561d528ec8f910cf9affeca95a6a9101c3ecd53953fe126a2d780acf9d49304e4bc5499d2a9219171786048c5f1b1e19d27d55ed28f8d")
                ),
            )
        )
        val paymentInfo = OfferTypes.PaymentInfo(100.msat, 1000, CltvExpiryDelta(144), 1.msat, 500_000_000.msat, Features.empty)
        val blindedPaths = listOf(Bolt12Invoice.Companion.PaymentBlindedContactInfo(OfferTypes.ContactInfo.BlindedPath(blindedPath), paymentInfo))
        val features = Features(Feature.TrampolinePayment to FeatureSupport.Optional, Feature.BasicMultiPartPayment to FeatureSupport.Optional)
        val expected = PaymentOnion.RelayToBlindedPayload(
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(150_000_000.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(850_000)),
                OnionPaymentPayloadTlv.RecipientFeatures(features.toByteArray().toByteVector()),
                OnionPaymentPayloadTlv.OutgoingBlindedPaths(blindedPaths)
            )
        )
        val bin = Hex.decode(
            "fd0143 020408f0d180 04030cf850 15080200000000020000 16fd012a032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e66868099102988face71e92c345a068f740191fd8e53be14f0bb957ef730d3c5f76087b960e020295d40514096a8be54859e7dfe947b376eaafea8afe5cb4eb2c13ff857ed0b4be002a0ae636dc5963bcfe3a2f055c8b8f6d2c5cd818362032404a6e35995ba57e101eac7e5fa04bb33a8920f1020e2dbadcc2005e859819ddebbe88a834ae8a6d2b049233c07335f15cd1dc5f22005bbc211f6ccd409888ca8ab027a5f21d229f9e18ff02cc1161a8344c91bdefc742d221db962561d528ec8f910cf9affeca95a6a9101c3ecd53953fe126a2d780acf9d49304e4bc5499d2a9219171786048c5f1b1e19d27d55ed28f8d00000064000003e800900000000000000001000000001dcd65000000"
        )

        val decoded = PaymentOnion.RelayToBlindedPayload.read(bin).right!!
        assertEquals(decoded, expected)
        assertEquals(decoded.amountToForward, 150_000_000.msat)
        assertEquals(decoded.outgoingCltv, CltvExpiry(850_000))
        assertEquals(decoded.recipientFeatures, features.toByteArray().byteVector())
        assertEquals(decoded.outgoingBlindedPaths, blindedPaths)

        val encoded = expected.write()
        assertContentEquals(bin, encoded)
    }

    @Test
    fun `encode - decode node relay to legacy per-hop payload`() {
        val nodeId = PublicKey(Hex.decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"))
        val features = ByteVector("0a")
        val node1 = PublicKey(Hex.decode("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"))
        val node2 = PublicKey(Hex.decode("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486"))
        val node3 = PublicKey(Hex.decode("02a051267759c3a149e3e72372f4e0c4054ba597ebfd0eda78a2273023667205ee"))
        val routingHints = listOf(
            listOf(Bolt11Invoice.TaggedField.ExtraHop(node1, ShortChannelId(1), 10.msat, 100, CltvExpiryDelta(144))),
            listOf(Bolt11Invoice.TaggedField.ExtraHop(node2, ShortChannelId(2), 20.msat, 150, CltvExpiryDelta(12)), Bolt11Invoice.TaggedField.ExtraHop(node3, ShortChannelId(3), 30.msat, 200, CltvExpiryDelta(24)))
        )
        val expected = PaymentOnion.RelayToNonTrampolinePayload(
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(561.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(42)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), 1105.msat),
                OnionPaymentPayloadTlv.RecipientFeatures(features),
                OnionPaymentPayloadTlv.OutgoingNodeId(nodeId),
                OnionPaymentPayloadTlv.InvoiceRoutingInfo(routingHints)
            )
        )
        val bin = Hex.decode(
            "f2 02020231 04012a 0822eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f2836866190451 0e2102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619 15010a fe000102339b01036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e200000000000000010000000a00000064009002025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce148600000000000000020000001400000096000c02a051267759c3a149e3e72372f4e0c4054ba597ebfd0eda78a2273023667205ee00000000000000030000001e000000c80018"
        )

        val decoded = PaymentOnion.RelayToNonTrampolinePayload.read(bin).right!!
        assertEquals(decoded, expected)
        assertEquals(decoded.amountToForward, 561.msat)
        assertEquals(decoded.paymentSecret, ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"))
        assertEquals(decoded.outgoingCltv, CltvExpiry(42))
        assertEquals(decoded.outgoingNodeId, nodeId)
        assertEquals(decoded.invoiceFeatures, features)
        assertEquals(decoded.invoiceRoutingInfo, routingHints)

        val encoded = expected.write()
        assertContentEquals(bin, encoded)
    }

    @Test
    fun `encode - decode final per-hop payload`() {
        val testCases = mapOf(
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(561.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(42)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), 0.msat)
            ) to Hex.decode("29 02020231 04012a 0820eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"),
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(561.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(42)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), 1105.msat)
            ) to Hex.decode("2b 02020231 04012a 0822eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f2836866190451"),
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(561.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(42)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), 4294967295L.msat)
            ) to Hex.decode("2d 02020231 04012a 0824eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619ffffffff"),
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(561.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(42)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), 4294967296L.msat)
            ) to Hex.decode("2e 02020231 04012a 0825eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f2836866190100000000"),
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(561.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(42)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), 1099511627775L.msat)
            ) to Hex.decode("2e 02020231 04012a 0825eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619ffffffffff"),
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(561.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(42)),
                OnionPaymentPayloadTlv.OutgoingChannelId(ShortChannelId(1105)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), 0.msat)
            ) to Hex.decode("33 02020231 04012a 06080000000000000451 0820eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"),
            TlvStream(
                setOf(
                    OnionPaymentPayloadTlv.AmountToForward(561.msat),
                    OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(42)),
                    OnionPaymentPayloadTlv.PaymentData(ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"), 0.msat)
                ),
                setOf(GenericTlv(65535, ByteVector("06c1")))
            ) to Hex.decode("2f 02020231 04012a 0820eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619 fdffff0206c1"),
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(100_000_000.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(800_000)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"), 100_000_000.msat),
            ) to Hex.decode(
                "31 020405f5e100 04030c3500 08242a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a05f5e100"
            ),
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(100_005_000.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(800_250)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"), 100_005_000.msat),
                OnionPaymentPayloadTlv.TrampolineOnion(
                    OnionRoutingPacket(
                        0,
                        ByteVector("02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"),
                        ByteVector("1860c0749bfd613056cfc5718beecc25a2f255fc7abbea3cd75ff820e9d30807d19b30f33626452fa54bb2d822e918558ed3e6714deb3f9a2a10895e7553c6f088c9a852043530dbc9abcc486030894364b205f5de60171b451ff462664ebce23b672579bf2a444ebfe0a81875c26d2fa16d426795b9b02ccbc4bdf909c583f0c2ebe9136510645917153ecb05181ca0c1b207824578ee841804a148f4c3df7306"),
                        ByteVector32("dcea52d94222907c9187bc31c0880fc084f0d88716e195c0abe7672d15217623")
                    )
                )
            ) to Hex.decode(
                "fd0116 020405f5f488 04030c35fa 08242b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b05f5f488 14e30002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe3371860c0749bfd613056cfc5718beecc25a2f255fc7abbea3cd75ff820e9d30807d19b30f33626452fa54bb2d822e918558ed3e6714deb3f9a2a10895e7553c6f088c9a852043530dbc9abcc486030894364b205f5de60171b451ff462664ebce23b672579bf2a444ebfe0a81875c26d2fa16d426795b9b02ccbc4bdf909c583f0c2ebe9136510645917153ecb05181ca0c1b207824578ee841804a148f4c3df7306dcea52d94222907c9187bc31c0880fc084f0d88716e195c0abe7672d15217623"
            ),
            TlvStream(
                OnionPaymentPayloadTlv.AmountToForward(100_000_000.msat),
                OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(800_000)),
                OnionPaymentPayloadTlv.PaymentData(ByteVector32("2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c"), 100_000_000.msat),
                OnionPaymentPayloadTlv.TrampolineOnion(
                    OnionRoutingPacket(
                        0,
                        ByteVector("035e5c85814fdb522b4efeef99b44fe8a5d3d3412057bc213b98d6f605edb022c2"),
                        ByteVector("ae4a9141f6ac403790afeed975061f024e2723d485f9cb35a3eaf881732f468dc19009bf195b561590798fb895b7b7065b5537018dec330e509e8618700c9c6e1df5d15b900ac3c34104b6abb1099fd2eca3b640d7d5fda9370e20c09035168fc64d954baa80361b965314c400da2d7a64d0536bf9e494aebb80aec358327a4a1a667fcff1daf241c99dd8c4fa907de5b931fb9daed083c157f5ea1dd960d14295"),
                        ByteVector32("2f8ebe4e1ccaee4d565a093e2b91f94b04a884ce2e8c60aced3565e8d2d10de5")
                    )
                )
            ) to Hex.decode(
                "fd0116 020405f5e100 04030c3500 08242c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c05f5e100 14e300035e5c85814fdb522b4efeef99b44fe8a5d3d3412057bc213b98d6f605edb022c2ae4a9141f6ac403790afeed975061f024e2723d485f9cb35a3eaf881732f468dc19009bf195b561590798fb895b7b7065b5537018dec330e509e8618700c9c6e1df5d15b900ac3c34104b6abb1099fd2eca3b640d7d5fda9370e20c09035168fc64d954baa80361b965314c400da2d7a64d0536bf9e494aebb80aec358327a4a1a667fcff1daf241c99dd8c4fa907de5b931fb9daed083c157f5ea1dd960d142952f8ebe4e1ccaee4d565a093e2b91f94b04a884ce2e8c60aced3565e8d2d10de5"
            ),
        )

        testCases.forEach {
            val expected = it.key
            val decoded = PaymentOnion.FinalPayload.Standard.read(it.value).right!!
            assertEquals(decoded, PaymentOnion.FinalPayload.Standard(expected))
            val encoded = PaymentOnion.FinalPayload.Standard(expected).write()
            assertContentEquals(it.value, encoded)
        }
    }

    @Test
    fun `encode - decode final blinded per-hop payload`() {
        val blindedTlvs = RouteBlindingEncryptedData(
            TlvStream(
                RouteBlindingEncryptedDataTlv.PathId(ByteVector("2a2a2a2a")),
                RouteBlindingEncryptedDataTlv.PaymentConstraints(CltvExpiry(1500), 1.msat)
            )
        )
        val testCases = mapOf(
            // @formatter:off
            TlvStream(OnionPaymentPayloadTlv.AmountToForward(561.msat), OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(1234567)), OnionPaymentPayloadTlv.EncryptedRecipientData(ByteVector("deadbeef")), OnionPaymentPayloadTlv.TotalAmount(1105.msat)) to Hex.decode("13 02020231 040312d687 0a04deadbeef 12020451"),
            TlvStream(OnionPaymentPayloadTlv.AmountToForward(561.msat), OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(1234567)), OnionPaymentPayloadTlv.EncryptedRecipientData(ByteVector("deadbeef")), OnionPaymentPayloadTlv.PathKey(PublicKey.fromHex("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2")), OnionPaymentPayloadTlv.TotalAmount(1105.msat)) to Hex.decode("36 02020231 040312d687 0a04deadbeef 0c21036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2 12020451"),
            TlvStream(OnionPaymentPayloadTlv.AmountToForward(150_000_000.msat), OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(850_000)), OnionPaymentPayloadTlv.EncryptedRecipientData(ByteVector("bc211f6ccd409888ca8ab027a5f21d229f9e18ff02cc1161a8344c91bdefc742d221db962561d528ec8f910cf9affeca95a6a9101c3ecd53953fe126a2d780acf9d49304e4bc5499d2a9219171786048c5f1b1e19d27d55ed28f8d")), OnionPaymentPayloadTlv.TotalAmount(150_000_000.msat)) to Hex.decode("6e 020408f0d180 04030cf850 0a5bbc211f6ccd409888ca8ab027a5f21d229f9e18ff02cc1161a8344c91bdefc742d221db962561d528ec8f910cf9affeca95a6a9101c3ecd53953fe126a2d780acf9d49304e4bc5499d2a9219171786048c5f1b1e19d27d55ed28f8d 120408f0d180"),
            // @formatter:on
        )
        testCases.forEach {
            val decoded = PaymentOnion.PerHopPayload.tlvSerializer.read(it.value)
            assertEquals(it.key, decoded)
            val payload = PaymentOnion.FinalPayload.Blinded(it.key, blindedTlvs)
            assertContentEquals(payload.write(), it.value)
        }
    }

    @Test
    fun `encode - decode final per-hop payload with custom user records`() {
        val tlvs = TlvStream(
            setOf(OnionPaymentPayloadTlv.AmountToForward(561.msat), OnionPaymentPayloadTlv.OutgoingCltv(CltvExpiry(42)), OnionPaymentPayloadTlv.PaymentData(ByteVector32.Zeroes, 0.msat)),
            setOf(GenericTlv(5432123457L, ByteVector("16c7ec71663784ff100b6eface1e60a97b92ea9d18b8ece5e558586bc7453828")))
        )
        val bin = Hex.decode("53 02020231 04012a 08200000000000000000000000000000000000000000000000000000000000000000 ff0000000143c7a0412016c7ec71663784ff100b6eface1e60a97b92ea9d18b8ece5e558586bc7453828")

        val encoded = PaymentOnion.FinalPayload.Standard(tlvs).write()
        assertContentEquals(bin, encoded)
        assertEquals(PaymentOnion.FinalPayload.Standard(tlvs), PaymentOnion.FinalPayload.Standard.read(bin).right)
    }

    @Test
    fun `decode multi-part final per-hop payload`() {
        val notMultiPart = PaymentOnion.FinalPayload.Standard.read(Hex.decode("29 02020231 04012a 08200000000000000000000000000000000000000000000000000000000000000000")).right!!
        assertEquals(notMultiPart.totalAmount, 561.msat)
        assertEquals(notMultiPart.paymentSecret, ByteVector32.Zeroes)

        val multiPart = PaymentOnion.FinalPayload.Standard.read(Hex.decode("2b 02020231 04012a 0822eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f2836866190451")).right!!
        assertEquals(multiPart.amount, 561.msat)
        assertEquals(multiPart.expiry, CltvExpiry(42))
        assertEquals(multiPart.totalAmount, 1105.msat)
        assertEquals(multiPart.paymentSecret, ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"))

        val multiPartNoTotalAmount = PaymentOnion.FinalPayload.Standard.read(Hex.decode("29 02020231 04012a 0820eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619")).right!!
        assertEquals(multiPartNoTotalAmount.amount, 561.msat)
        assertEquals(multiPartNoTotalAmount.expiry, CltvExpiry(42))
        assertEquals(multiPartNoTotalAmount.totalAmount, 561.msat)
        assertEquals(multiPartNoTotalAmount.paymentSecret, ByteVector32("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"))
    }

    @Test
    fun `decode final per-hop payload missing information`() {
        val testCases = listOf(
            Hex.decode("25 04012a 0820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), // missing amount
            Hex.decode("26 02020231 0820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), // missing cltv
            Hex.decode("07 02020231 04012a") // missing payment secret
        )

        testCases.forEach {
            assertTrue(PaymentOnion.FinalPayload.Standard.read(it).isLeft)
        }
    }

    @Test
    fun `decode invalid per-hop payload`() {
        val testCases = listOf(
            // Invalid fixed-size (legacy) payload.
            Hex.decode("00 000000000000002a 000000000000002a"), // invalid length
            Hex.decode("00 000000000000002a 0000000000022ab0 0007a120 000000000000000000000000"), // legacy channel relay payload
            Hex.decode("00 0000000000000000 0000000000000451 000006c1 000000000000000000000000"), // legacy final payload
            // Invalid variable-length (tlv) payload.
            Hex.decode("00"), // empty payload is missing required information
            Hex.decode("01"), // invalid length
            Hex.decode("01 0000"), // invalid length
            Hex.decode("04 0000 2a00"), // unknown even types
            Hex.decode("04 0000 0000"), // duplicate types
            Hex.decode("04 0100 0000") // unordered types
        )

        testCases.forEach {
            assertTrue(PaymentOnion.ChannelRelayPayload.read(it).isLeft)
            assertTrue(PaymentOnion.NodeRelayPayload.read(it).isLeft)
            assertTrue(PaymentOnion.FinalPayload.Standard.read(it).isLeft)
        }
    }

}