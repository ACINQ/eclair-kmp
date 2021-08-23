package fr.acinq.lightning.payment

import fr.acinq.bitcoin.*
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.*
import fr.acinq.secp256k1.Hex
import kotlin.test.*

class PaymentRequestTestsCommon : LightningTestSuite() {
    val priv = PrivateKey(Hex.decode("e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734"))
    val pub = priv.publicKey()
    val nodeId = pub

    init {
        assertEquals(nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
    }

    @Test
    fun `check minimal unit is used`() {
        assertEquals('p', PaymentRequest.unit(1.msat))
        assertEquals('p', PaymentRequest.unit(99.msat))
        assertEquals('n', PaymentRequest.unit(100.msat))
        assertEquals('p', PaymentRequest.unit(101.msat))
        assertEquals('n', PaymentRequest.unit(1.sat.toMilliSatoshi()))
        assertEquals('u', PaymentRequest.unit(100.sat.toMilliSatoshi()))
        assertEquals('n', PaymentRequest.unit(101.sat.toMilliSatoshi()))
        assertEquals('u', PaymentRequest.unit(1155400.sat.toMilliSatoshi()))
        assertEquals('m', PaymentRequest.unit(1.mbtc.toMilliSatoshi()))
        assertEquals('m', PaymentRequest.unit(10.mbtc.toMilliSatoshi()))
        assertEquals('m', PaymentRequest.unit(1.btc.toMilliSatoshi()))
    }

    @Test
    fun `decode empty amount`() {
        assertNull(PaymentRequest.decodeAmount(""))
        assertNull(PaymentRequest.decodeAmount("0"))
        assertNull(PaymentRequest.decodeAmount("0p"))
        assertNull(PaymentRequest.decodeAmount("0n"))
        assertNull(PaymentRequest.decodeAmount("0u"))
        assertNull(PaymentRequest.decodeAmount("0m"))
    }

    @Test
    fun `check that we can still decode non-minimal amount encoding`() {
        assertEquals(PaymentRequest.decodeAmount("1000u"), 100000000.msat)
        assertEquals(PaymentRequest.decodeAmount("1000000n"), 100000000.msat)
        assertEquals(PaymentRequest.decodeAmount("1000000000p"), 100000000.msat)
    }

    @Test
    fun `reject sub-millisatoshi amounts`() {
        assertFails { PaymentRequest.decodeAmount("1501p") }
    }

    @Test
    fun `Please make a donation of any amount using payment_hash 0001020304050607080900010203040506070809000102030405060708090102 to me @03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad`() {
        val ref =
            "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, null)
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(pr.description, "Please consider supporting this project")
        assertNull(pr.fallbackAddress)
        assertEquals(pr.tags.size, 4)
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `Please send $3 for a cup of coffee to the same peer, within 1 minute`() {
        val ref =
            "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(250000000))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(pr.description, "1 cup coffee")
        assertEquals(pr.expirySeconds, 60)
        assertNull(pr.fallbackAddress)
        assertEquals(pr.tags.size, 5)
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `Please send 0,0025 BTC for a cup of nonsense to the same peer, within one minute`() {
        val ref =
            "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(250000000))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(pr.description, "ナンセンス 1杯")
        assertNull(pr.fallbackAddress)
        assertEquals(pr.tags.size, 5)
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `Now send $24 for an entire list of things (hashed)`() {
        val ref =
            "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(2000000000))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(
            pr.descriptionHash,
            Crypto.sha256(
                "One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".encodeToByteArray()
            ).toByteVector32()
        )
        assertNull(pr.fallbackAddress)
        assertEquals(pr.tags.size, 4)
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `The same, on testnet, with a fallback address mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP`() {
        val ref =
            "lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lntb")
        assertEquals(pr.amount, MilliSatoshi(2000000000))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(
            pr.descriptionHash,
            Crypto.sha256(
                "One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".encodeToByteArray()
            ).toByteVector32()
        )
        assertEquals(pr.fallbackAddress, "mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP")
        assertEquals(pr.tags.size, 5)
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `On mainnet, with fallback address 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T with extra routing info to go via nodes 029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255 then 039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255`() {
        val ref =
            "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(2000000000))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(
            pr.descriptionHash,
            Crypto.sha256(
                "One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".encodeToByteArray()
            ).toByteVector32()
        )
        assertEquals(pr.fallbackAddress, "1RustyRX2oai4EYYDpQGWvEL62BBGqN9T")
        assertEquals(
            pr.routingInfo, listOf(
                PaymentRequest.TaggedField.RoutingInfo(
                    listOf(
                        PaymentRequest.TaggedField.ExtraHop(PublicKey(ByteVector("029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255")), ShortChannelId("66051x263430x1800"), 1.msat, 20, CltvExpiryDelta(3)),
                        PaymentRequest.TaggedField.ExtraHop(PublicKey(ByteVector("039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255")), ShortChannelId("197637x395016x2314"), 2.msat, 30, CltvExpiryDelta(4))
                    )
                )
            )
        )
        assertEquals(pr.tags.size, 6)
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `On mainnet, with fallback (p2sh) address 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX`() {
        val ref =
            "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z99qrsgqz6qsgww34xlatfj6e3sngrwfy3ytkt29d2qttr8qz2mnedfqysuqypgqex4haa2h8fx3wnypranf3pdwyluftwe680jjcfp438u82xqphf75ym"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(2000000000))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(
            pr.descriptionHash,
            Crypto.sha256(
                "One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".encodeToByteArray()
            ).toByteVector32()
        )
        assertEquals(pr.fallbackAddress, "3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX")
        assertEquals(pr.tags.size, 5)
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `On mainnet, with fallback (p2wpkh) address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`() {
        val ref =
            "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7k9qrsgqt29a0wturnys2hhxpner2e3plp6jyj8qx7548zr2z7ptgjjc7hljm98xhjym0dg52sdrvqamxdezkmqg4gdrvwwnf0kv2jdfnl4xatsqmrnsse"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(2000000000))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(
            pr.descriptionHash,
            Crypto.sha256(
                "One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".encodeToByteArray()
            ).toByteVector32()
        )
        assertEquals(pr.fallbackAddress, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        assertEquals(pr.tags.size, 5)
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `On mainnet, with fallback (p2wsh) address bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3`() {
        val ref =
            "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(2000000000))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(
            pr.descriptionHash,
            Crypto.sha256(
                "One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".encodeToByteArray()
            ).toByteVector32()
        )
        assertEquals(pr.fallbackAddress, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
        assertEquals(pr.tags.size, 5)
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `On mainnet, with fallback (p2wsh) address bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 and a minimum htlc cltv expiry of 12`() {
        val ref =
            "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygscqpvpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq999fraffdzl6c8j7qd325dfurcq7vl0mfkdpdvve9fy3hy4lw0x9j3zcj2qdh5e5pyrp6cncvmxrhchgey64culwmjtw9wym74xm6xqqevh9r0"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(2000000000))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.paymentSecret, ByteVector32("1111111111111111111111111111111111111111111111111111111111111111"))
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(pr.tags.size, 6)
        assertEquals(
            pr.descriptionHash,
            Crypto.sha256(
                "One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".encodeToByteArray()
            ).toByteVector32()
        )
        assertEquals(pr.fallbackAddress, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
        assertEquals(pr.minFinalExpiryDelta, CltvExpiryDelta(12))
        assertEquals(pr.features, ByteVector("4100"))
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `On mainnet, please send $30 for coffee beans to the same peer, which supports features 8, 14 and 99, using secret 0x1111111111111111111111111111111111111111111111111111111111111111`() {
        val refs = listOf(
            "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpz3uapa",
            // All upper-case
            "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpz3uapa".toUpperCase(),
            // With ignored fields
            "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2qrqqqfppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhpnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqspnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnpkqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz599y53s3ujmcfjp5xrdap68qxymkqphwsexhmhr8wdz5usdzkzrse33chw6dlp3jhuhge9ley7j2ayx36kawe7kmgg8sv5ugdyusdcqzn8z9x"
        )
        refs.forEach { ref ->
            val pr = PaymentRequest.read(ref)
            assertEquals(pr.prefix, "lnbc")
            assertEquals(pr.amount, MilliSatoshi(2500000000L))
            assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
            assertEquals(pr.paymentSecret, ByteVector32("1111111111111111111111111111111111111111111111111111111111111111"))
            assertEquals(pr.timestampSeconds, 1496314658L)
            assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
            assertEquals(pr.description, "coffee beans")
            assertEquals(pr.features, ByteVector("08000000000000000000004100"))
            val check = pr.sign(priv).write()
            assertEquals(ref.toLowerCase(), check)
        }
    }

    @Test
    fun `On mainnet, please send $30 for coffee beans to the same peer, which supports features 8, 14, 99 and 100, using secret 0x1111111111111111111111111111111111111111111111111111111111111111`() {
        val ref =
            "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q4psqqqqqqqqqqqqqqqqsgqtqyx5vggfcsll4wu246hz02kp85x4katwsk9639we5n5yngc3yhqkm35jnjw4len8vrnqnf5ejh0mzj9n3vz2px97evektfm2l6wqccp3y7372"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(2500000000L))
        assertEquals(pr.paymentHash, ByteVector32("0001020304050607080900010203040506070809000102030405060708090102"))
        assertEquals(pr.paymentSecret, ByteVector32("1111111111111111111111111111111111111111111111111111111111111111"))
        assertEquals(pr.timestampSeconds, 1496314658L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(pr.description, "coffee beans")
        assertNull(pr.fallbackAddress)
        assertEquals(pr.features, ByteVector("18000000000000000000004100"))
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `On mainnet, please send 0,00967878534 BTC for a list of items within one week, amount in pico BTC`() {
        val ref =
            "lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz"
        val pr = PaymentRequest.read(ref)
        assertEquals(pr.prefix, "lnbc")
        assertEquals(pr.amount, MilliSatoshi(967878534))
        assertEquals(pr.paymentHash, ByteVector32("462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f"))
        assertEquals(pr.features, Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory).toByteArray().toByteVector())
        assertEquals(pr.timestampSeconds, 1572468703L)
        assertEquals(pr.nodeId, PublicKey.fromHex("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))
        assertEquals(pr.description, "Blockstream Store: 88.85 USD for Blockstream Ledger Nano S x 1, \"Back In My Day\" Sticker x 2, \"I Got Lightning Working\" Sticker x 2 and 1 more items")
        assertNull(pr.fallbackAddress)
        assertEquals(pr.expirySeconds, 604800)
        assertEquals(pr.minFinalExpiryDelta, CltvExpiryDelta(10))
        assertEquals(
            pr.routingInfo,
            listOf(
                PaymentRequest.TaggedField.RoutingInfo(
                    listOf(
                        PaymentRequest.TaggedField.ExtraHop(
                            PublicKey(ByteVector("03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7")),
                            ShortChannelId("589390x3312x1"),
                            1000.msat,
                            2500,
                            CltvExpiryDelta(40)
                        )
                    )
                )
            )
        )
        val check = pr.sign(priv).write()
        assertEquals(ref, check)
    }

    @Test
    fun `reject invalid invoices`() {
        val refs = listOf(
            // Bech32 checksum is invalid.
            "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt",
            // Malformed bech32 string (no 1).
            "pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny",
            // Malformed bech32 string (mixed case).
            "LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny",
            // Signature is not recoverable.
            "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaxtrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspk28uwq",
            // String is too short.
            "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh",
            // Invalid multiplier.
            "lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqrrzc4cvfue4zp3hggxp47ag7xnrlr8vgcmkjxk3j5jqethnumgkpqp23z9jclu3v0a7e0aruz366e9wqdykw6dxhdzcjjhldxq0w6wgqcnu43j",
            // Invalid sub-millisatoshi precision.
            "lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk32uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp99202x"
        )
        refs.forEach {
            assertFails { PaymentRequest.read(it) }
        }
    }

    @Test
    fun `ignore unknown tags`() {
        val pr = PaymentRequest(
            prefix = "lntb",
            amount = 100_000.msat,
            timestampSeconds = currentTimestampSeconds(),
            nodeId = nodeId,
            tags = listOf(
                PaymentRequest.TaggedField.PaymentHash(ByteVector32.One),
                PaymentRequest.TaggedField.Description("description"),
                PaymentRequest.TaggedField.PaymentSecret(randomBytes32()),
                PaymentRequest.TaggedField.Features(ByteVector("4100")),
                PaymentRequest.TaggedField.UnknownTag(21, Bech32.eight2five("some data we don't understand".encodeToByteArray()).toList())
            ),
            signature = ByteVector.empty
        ).sign(priv)

        val serialized = pr.write()
        val pr1 = PaymentRequest.read(serialized)
        val unknownTag = pr1.tags.find { it is PaymentRequest.TaggedField.UnknownTag }
        assertEquals(21, unknownTag!!.tag)
    }

    @Test
    fun `feature bits to minimally-encoded feature bytes`() {
        val testCases = listOf(
            // 01000 01000 00101
            Pair(listOf<Int5>(8, 8, 5), ByteVector("2105")),
            // 00001 01000 01000 00101
            Pair(listOf<Int5>(1, 8, 8, 5), ByteVector("a105")),
            // 00011 00000 00000 00110
            Pair(listOf<Int5>(3, 0, 0, 6), ByteVector("018006")),
            // 00001 00000 00000 00110
            Pair(listOf<Int5>(1, 0, 0, 6), ByteVector("8006")),
            // 00001 00000 00000 00000
            Pair(listOf<Int5>(1, 0, 0, 0), ByteVector("8000")),
            // 00101 00000 00000 00000
            Pair(listOf<Int5>(5, 0, 0, 0), ByteVector("028000")),
            // 00101 11000 00000 00110
            Pair(listOf<Int5>(5, 24, 0, 6), ByteVector("02e006")),
            // 01001 11000 00000 00110
            Pair(listOf<Int5>(9, 24, 0, 6), ByteVector("04e006"))
        )

        testCases.forEach {
            assertEquals(it.second, PaymentRequest.TaggedField.Features.decode(it.first).bits)
        }
    }

    @Test
    fun `payment secret`() {
        val features =
            Features(Feature.VariableLengthOnion to FeatureSupport.Mandatory, Feature.PaymentSecret to FeatureSupport.Mandatory, Feature.BasicMultiPartPayment to FeatureSupport.Optional)
        val pr = PaymentRequest.create(Block.LivenetGenesisBlock.hash, 123.msat, ByteVector32.One, priv, "Some invoice", CltvExpiryDelta(18), features)
        assertNotNull(pr.paymentSecret)
        assertEquals(ByteVector("024100"), pr.features)

        val pr1 = PaymentRequest.read(pr.write())
        assertEquals(pr1.paymentSecret, pr.paymentSecret)

        // An invoice without the payment secret feature should be rejected
        assertFails { PaymentRequest.read("lnbc40n1pw9qjvwpp5qq3w2ln6krepcslqszkrsfzwy49y0407hvks30ec6pu9s07jur3sdpstfshq5n9v9jzucm0d5s8vmm5v5s8qmmnwssyj3p6yqenwdencqzysxqrrss7ju0s4dwx6w8a95a9p2xc5vudl09gjl0w2n02sjrvffde632nxwh2l4w35nqepj4j5njhh4z65wyfc724yj6dn9wajvajfn5j7em6wsq2elakl") }

        // An invoice that sets the payment secret feature bit must provide a payment secret.
        assertFails { PaymentRequest.read("lnbc1230p1pwljzn3pp5qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdq52dhk6efqd9h8vmmfvdjs9qypqsqylvwhf7xlpy6xpecsnpcjjuuslmzzgeyv90mh7k7vs88k2dkxgrkt75qyfjv5ckygw206re7spga5zfd4agtdvtktxh5pkjzhn9dq2cqz9upw7") }

        // Invoices must use a payment secret.
        assertFails {
            PaymentRequest.create(
                Block.LivenetGenesisBlock.hash,
                123.msat,
                ByteVector32.One,
                priv,
                "Invoice without secrets",
                CltvExpiryDelta(18),
                Features(Feature.VariableLengthOnion to FeatureSupport.Optional, Feature.BasicMultiPartPayment to FeatureSupport.Optional)
            )
        }
    }

    @Test
    fun filterFeatures() {
        assertEquals(
            expected = PaymentRequest.invoiceFeatures(
                Features(
                    activated = mapOf(
                        Feature.InitialRoutingSync to FeatureSupport.Optional,
                        Feature.StaticRemoteKey to FeatureSupport.Mandatory,
                        Feature.PaymentSecret to FeatureSupport.Mandatory,
                        Feature.TrampolinePayment to FeatureSupport.Optional,
                    ),
                    unknown = setOf(
                        UnknownFeature(47)
                    )
                )
            ),
            actual = Features(
                activated = mapOf(
                    Feature.PaymentSecret to FeatureSupport.Mandatory,
                    Feature.TrampolinePayment to FeatureSupport.Optional
                )
            )
        )
    }
}