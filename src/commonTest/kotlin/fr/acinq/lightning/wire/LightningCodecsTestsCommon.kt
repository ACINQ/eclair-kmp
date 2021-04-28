package fr.acinq.lightning.wire

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Features
import fr.acinq.lightning.Lightning.randomBytes
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomBytes64
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.ChannelOrigin
import fr.acinq.lightning.crypto.assertArrayEquals
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull

@OptIn(ExperimentalUnsignedTypes::class)
class LightningCodecsTestsCommon : LightningTestSuite() {

    private fun point(fill: Byte) = PrivateKey(ByteArray(32) { fill }).publicKey()

    fun publicKey(fill: Byte) = point(fill)

    @Test
    fun `encode - decode uint64`() {
        val testCases = mapOf(
            0UL to Hex.decode("00 00 00 00 00 00 00 00"),
            42UL to Hex.decode("00 00 00 00 00 00 00 2a"),
            6211610197754262546UL to Hex.decode("56 34 12 90 78 56 34 12"),
            17293822569102704638UL to Hex.decode("ef ff ff ff ff ff ff fe"),
            17293822569102704639UL to Hex.decode("ef ff ff ff ff ff ff ff"),
            18446744073709551614UL to Hex.decode("ff ff ff ff ff ff ff fe"),
            18446744073709551615UL to Hex.decode("ff ff ff ff ff ff ff ff")
        )

        testCases.forEach {
            val out = ByteArrayOutput()
            LightningCodecs.writeU64(it.key.toLong(), out)
            assertArrayEquals(it.value, out.toByteArray())
            val decoded = LightningCodecs.u64(ByteArrayInput(it.value))
            assertEquals(it.key, decoded.toULong())
        }
    }

    @Test
    fun `bigsize serialization`() {
        val raw = """[
    {
        "name": "zero",
        "value": 0,
        "bytes": "00"
    },
    {
        "name": "one byte value",
        "value": 42,
        "bytes": "2a"
    },
    {
        "name": "one byte high",
        "value": 252,
        "bytes": "fc"
    },
    {
        "name": "two byte low",
        "value": 253,
        "bytes": "fd00fd"
    },
    {
        "name": "two byte value",
        "value": 255,
        "bytes": "fd00ff"
    },
    {
        "name": "two byte value",
        "value": 550,
        "bytes": "fd0226"
    },
    {
        "name": "two byte high",
        "value": 65535,
        "bytes": "fdffff"
    },
    {
        "name": "four byte low",
        "value": 65536,
        "bytes": "fe00010000"
    },
    {
        "name": "four byte value",
        "value": 998000,
        "bytes": "fe000f3a70"
    },
    {
        "name": "four byte high",
        "value": 4294967295,
        "bytes": "feffffffff"
    },
    {
        "name": "eight byte low",
        "value": 4294967296,
        "bytes": "ff0000000100000000"
    },
    {
        "name": "eight byte high",
        "value": 18446744073709551615,
        "bytes": "ffffffffffffffffff"
    },
    {
        "name": "two byte not canonical",
        "value": 0,
        "bytes": "fd00fc",
        "exp_error": "decoded bigsize is not canonical"
    },
    {
        "name": "four byte not canonical",
        "value": 0,
        "bytes": "fe0000ffff",
        "exp_error": "decoded bigsize is not canonical"
    },
    {
        "name": "eight byte not canonical",
        "value": 0,
        "bytes": "ff00000000ffffffff",
        "exp_error": "decoded bigsize is not canonical"
    },
    {
        "name": "two byte short read",
        "value": 0,
        "bytes": "fd00",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "four byte short read",
        "value": 0,
        "bytes": "feffff",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "eight byte short read",
        "value": 0,
        "bytes": "ffffffffff",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "one byte no read",
        "value": 0,
        "bytes": "",
        "exp_error": "EOF"
    },
    {
        "name": "two byte no read",
        "value": 0,
        "bytes": "fd",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "four byte no read",
        "value": 0,
        "bytes": "fe",
        "exp_error": "unexpected EOF"
    },
    {
        "name": "eight byte no read",
        "value": 0,
        "bytes": "ff",
        "exp_error": "unexpected EOF"
    }
]"""

        val items = Json.parseToJsonElement(raw)
        items.jsonArray.forEach {
            val name = it.jsonObject["name"]?.jsonPrimitive?.content!!
            val bytes = Hex.decode(it.jsonObject["bytes"]?.jsonPrimitive?.content!!)
            val value = it.jsonObject["value"]?.jsonPrimitive?.content?.toULong()!!
            if (it.jsonObject["exp_error"] != null) {
                assertFails(name) { LightningCodecs.bigSize(ByteArrayInput(bytes)) }
            } else {
                assertEquals(value, LightningCodecs.bigSize(ByteArrayInput(bytes)).toULong(), name)
                val out = ByteArrayOutput()
                LightningCodecs.writeBigSize(value.toLong(), out)
                assertArrayEquals(bytes, out.toByteArray())
            }
        }
    }

    @Test
    fun `encode - decode init message`() {
        data class TestCase(val encoded: ByteVector, val rawFeatures: ByteVector, val networks: List<ByteVector32>, val valid: Boolean, val reEncoded: ByteVector? = null)

        val chainHash1 = ByteVector32.fromValidHex("0101010101010101010101010101010101010101010101010101010101010101")
        val chainHash2 = ByteVector32.fromValidHex("0202020202020202020202020202020202020202020202020202020202020202")

        val testCases = listOf(
            TestCase(ByteVector("0000 0000"), ByteVector(""), listOf(), true), // no features
            TestCase(ByteVector("0000 0002088a"), ByteVector("088a"), listOf(), true), // no global features
            TestCase(ByteVector("00020200 0000"), ByteVector("0200"), listOf(), true, ByteVector("0000 00020200")), // no local features
            TestCase(ByteVector("00020200 0002088a"), ByteVector("0a8a"), listOf(), true, ByteVector("0000 00020a8a")), // local and global - no conflict - same size
            TestCase(ByteVector("00020200 0003020002"), ByteVector("020202"), listOf(), true, ByteVector("0000 0003020202")), // local and global - no conflict - different sizes
            TestCase(ByteVector("00020a02 0002088a"), ByteVector("0a8a"), listOf(), true, ByteVector("0000 00020a8a")), // local and global - conflict - same size
            TestCase(ByteVector("00022200 000302aaa2"), ByteVector("02aaa2"), listOf(), true, ByteVector("0000 000302aaa2")), // local and global - conflict - different sizes
            TestCase(ByteVector("0000 0002088a 03012a05022aa2"), ByteVector("088a"), listOf(), true), // unknown odd records
            TestCase(ByteVector("0000 0002088a 03012a04022aa2"), ByteVector("088a"), listOf(), false), // unknown even records
            TestCase(ByteVector("0000 0002088a 0120010101010101010101010101010101010101010101010101010101010101"), ByteVector("088a"), listOf(), false), // invalid tlv stream
            TestCase(ByteVector("0000 0002088a 01200101010101010101010101010101010101010101010101010101010101010101"), ByteVector("088a"), listOf(chainHash1), true), // single network
            TestCase(
                ByteVector("0000 0002088a 014001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202"),
                ByteVector("088a"),
                listOf(chainHash1, chainHash2),
                true
            ), // multiple networks
            TestCase(ByteVector("0000 0002088a 0120010101010101010101010101010101010101010101010101010101010101010103012a"), ByteVector("088a"), listOf(chainHash1), true), // network and unknown odd records
            TestCase(ByteVector("0000 0002088a 0120010101010101010101010101010101010101010101010101010101010101010102012a"), ByteVector("088a"), listOf(), false) // network and unknown even records
        )

        for (testCase in testCases) {
            val result = kotlin.runCatching {
                val init = Init.read(testCase.encoded.toByteArray())
                assertEquals(testCase.rawFeatures, init.features)
                assertEquals(testCase.networks, init.networks)
                val encoded = init.write()
                assertEquals(testCase.reEncoded ?: testCase.encoded, ByteVector(encoded), testCase.toString())
            }
            assertEquals(result.isFailure, !testCase.valid, testCase.toString())
        }
    }

    @Test
    fun `encode - decode warning message`() {
        val testCases = mapOf(
            Warning("") to ByteVector("000100000000000000000000000000000000000000000000000000000000000000000000"),
            Warning("connection-level issue") to ByteVector("000100000000000000000000000000000000000000000000000000000000000000000016636f6e6e656374696f6e2d6c6576656c206973737565"),
            Warning(ByteVector32.One, "") to ByteVector("000101000000000000000000000000000000000000000000000000000000000000000000"),
            Warning(ByteVector32.One, "channel-specific issue") to ByteVector("0001010000000000000000000000000000000000000000000000000000000000000000166368616e6e656c2d7370656369666963206973737565"),
        )

        testCases.forEach {
            val decoded = LightningMessage.decode(it.value.toByteArray())
            assertNotNull(decoded)
            assertEquals(it.key, decoded)
            val reEncoded = LightningMessage.encode(decoded)
            assertEquals(it.value, ByteVector(reEncoded))
        }
    }

    @Test
    fun `encode - decode open_channel`() {
        val defaultOpen = OpenChannel(ByteVector32.Zeroes, ByteVector32.Zeroes, 1.sat, 1.msat, 1.sat, 1L, 1.sat, 1.msat, FeeratePerKw(1.sat), CltvExpiryDelta(1), 1, publicKey(1), point(2), point(3), point(4), point(5), point(6), 0.toByte())
        // Legacy encoding that omits the upfront_shutdown_script and trailing tlv stream.
        // To allow extending all messages with TLV streams, the upfront_shutdown_script was moved to a TLV stream extension
        // in https://github.com/lightningnetwork/lightning-rfc/pull/714 and made mandatory when including a TLV stream.
        // We don't make it mandatory at the codec level: it's the job of the actor creating the message to include it.
        val defaultEncoded =
            ByteVector("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000100010001031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f703f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a00")

        val testCases = mapOf(
            // legacy encoding without upfront_shutdown_script
            defaultEncoded to defaultOpen,
            // empty upfront_shutdown_script
            defaultEncoded + ByteVector("0000") to defaultOpen.copy(tlvStream = TlvStream(listOf(ChannelTlv.UpfrontShutdownScript(ByteVector.empty)))),
            // non-empty upfront_shutdown_script
            defaultEncoded + ByteVector("0004 01abcdef") to defaultOpen.copy(tlvStream = TlvStream(listOf(ChannelTlv.UpfrontShutdownScript(ByteVector("01abcdef"))))),
            // missing upfront_shutdown_script + unknown odd tlv records
            defaultEncoded + ByteVector("0302002a 050102") to defaultOpen.copy(tlvStream = TlvStream(listOf(), listOf(GenericTlv(3L, ByteVector("002a")), GenericTlv(5L, ByteVector("02"))))),
            // empty upfront_shutdown_script + unknown odd tlv records
            defaultEncoded + ByteVector("0000 0302002a 050102") to defaultOpen.copy(
                tlvStream = TlvStream(
                    listOf(ChannelTlv.UpfrontShutdownScript(ByteVector.empty)),
                    listOf(GenericTlv(3L, ByteVector("002a")), GenericTlv(5L, ByteVector("02")))
                )
            ),
            // non-empty upfront_shutdown_script + unknown odd tlv records
            defaultEncoded + ByteVector("0002 1234 0303010203") to defaultOpen.copy(tlvStream = TlvStream(listOf(ChannelTlv.UpfrontShutdownScript(ByteVector("1234"))), listOf(GenericTlv(3L, ByteVector("010203"))))),
            // channel origin tlv records
            defaultEncoded + ByteVector("fe47000005 2a 0001 187bf923f7f11ef732b73c417eb5a57cd4667b20a6f130ff505cd7ad3ab87281 00000000000004d2") to defaultOpen.copy(
                tlvStream = TlvStream(
                    listOf(
                        ChannelTlv.ChannelOriginTlv(
                            ChannelOrigin.PayToOpenOrigin(
                                ByteVector32.fromValidHex("187bf923f7f11ef732b73c417eb5a57cd4667b20a6f130ff505cd7ad3ab87281"),
                                1234.sat
                            )
                        )
                    )
                )
            ),
            defaultEncoded + ByteVector("fe47000005 2d 0002 223341754d3868536b584265746a644878577468524669483668596871463250726a72 00000000000001a4") to defaultOpen.copy(
                tlvStream = TlvStream(
                    listOf(
                        ChannelTlv.ChannelOriginTlv(
                            ChannelOrigin.SwapInOrigin(
                                "3AuM8hSkXBetjdHxWthRFiH6hYhqF2Prjr",
                                420.sat
                            )
                        )
                    )
                )
            )
        )

        testCases.forEach {
            val decoded = OpenChannel.read(it.key.toByteArray())
            val expected = it.value
            assertEquals(expected, decoded)
            val reEncoded = decoded.write()
            assertEquals(it.key, ByteVector(reEncoded))
        }
    }

    @Test
    fun `decode invalid open_channel`() {
        val defaultEncoded =
            ByteVector("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000100010001031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f703f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a00")
        val testCases = listOf(
            defaultEncoded + ByteVector("00"), // truncated length
            defaultEncoded + ByteVector("01"), // truncated length
            defaultEncoded + ByteVector("0004 123456"), // truncated upfront_shutdown_script
            defaultEncoded + ByteVector("0000 02012a"), // invalid tlv stream (unknown even record)
            defaultEncoded + ByteVector("0000 01012a 030201"), // invalid tlv stream (truncated)
            defaultEncoded + ByteVector("02012a"), // invalid tlv stream (unknown even record)
            defaultEncoded + ByteVector("01012a 030201") // invalid tlv stream (truncated)
        )
        testCases.forEach {
            assertFails { OpenChannel.read(it.toByteArray()) }
        }
    }

    @Test
    fun `encode - decode accept_channel`() {
        val defaultAccept = AcceptChannel(ByteVector32.Zeroes, 1.sat, 1L, 1.sat, 1.msat, 1, CltvExpiryDelta(1), 1, publicKey(1), point(2), point(3), point(4), point(5), point(6))
        // Legacy encoding that omits the upfront_shutdown_script and trailing tlv stream.
        // To allow extending all messages with TLV streams, the upfront_shutdown_script was moved to a TLV stream extension
        // in https://github.com/lightningnetwork/lightning-rfc/pull/714 and made mandatory when including a TLV stream.
        // We don't make it mandatory at the codec level: it's the job of the actor creating the message to include it.
        val defaultEncoded =
            ByteVector("000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000001000000000000000100000000000000010000000100010001031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f703f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a")
        val testCases = mapOf(
            defaultEncoded to defaultAccept, // legacy encoding without upfront_shutdown_script
            defaultEncoded + ByteVector("0000") to defaultAccept.copy(tlvStream = TlvStream(listOf(ChannelTlv.UpfrontShutdownScript(ByteVector.empty)))), // empty upfront_shutdown_script
            defaultEncoded + ByteVector("0004 01abcdef") to defaultAccept.copy(tlvStream = TlvStream(listOf(ChannelTlv.UpfrontShutdownScript(ByteVector("01abcdef"))))), // non-empty upfront_shutdown_script
            defaultEncoded + ByteVector("0000 0102002a 030102") to defaultAccept.copy(
                tlvStream = TlvStream(
                    listOf(ChannelTlv.UpfrontShutdownScript(ByteVector.empty)),
                    listOf(GenericTlv(1L, ByteVector("002a")), GenericTlv(3L, ByteVector("02")))
                )
            ), // empty upfront_shutdown_script + unknown odd tlv records
            defaultEncoded + ByteVector("0002 1234 0303010203") to defaultAccept.copy(
                tlvStream = TlvStream(
                    listOf(ChannelTlv.UpfrontShutdownScript(ByteVector("1234"))),
                    listOf(GenericTlv(3L, ByteVector("010203")))
                )
            ), // non-empty upfront_shutdown_script + unknown odd tlv records
            defaultEncoded + ByteVector("0303010203 05020123") to defaultAccept.copy(
                tlvStream = TlvStream(
                    listOf(),
                    listOf(GenericTlv(3L, ByteVector("010203")), GenericTlv(5L, ByteVector("0123")))
                )
            ) // no upfront_shutdown_script + unknown odd tlv records
        )

        testCases.forEach {
            val decoded = AcceptChannel.read(it.key.toByteArray())
            val expected = it.value
            assertEquals(expected, decoded)
            val reEncoded = decoded.write()
            assertEquals(it.key, ByteVector(reEncoded))
        }
    }

    @Test
    fun `encode - decode funding_signed (no channel data)`() {
        run {
            val bin = Hex.decode("00232056b684b3a084f17467369e894502541d7e3207bb66ef614d55368d9575c365cf6739d3421d0e7e3b890f974547c0828a03539147e49ae9b80a523ceb8a7397513cf247fdb414fead296b04e5d5fe8e7156836f53559c031d90463dfa633c3b")
            val decoded = LightningMessage.decode(bin)!!
            val expected = FundingSigned(
                ByteVector32("2056b684b3a084f17467369e894502541d7e3207bb66ef614d55368d9575c365"),
                ByteVector64("cf6739d3421d0e7e3b890f974547c0828a03539147e49ae9b80a523ceb8a7397513cf247fdb414fead296b04e5d5fe8e7156836f53559c031d90463dfa633c3b"),
                TlvStream.empty()
            )
            assertEquals(expected, decoded)
            val reencoded = LightningMessage.encode(decoded)
            assertArrayEquals(bin, reencoded)
        }
    }

    @Test
    fun `encode - decode funding_signed (small channel data)`() {
        run {
            val bin = Hex.decode(
                "00232056b684b3a084f17467369e894502541d7e3207bb66ef614d55368d9575c365cf6739d3421d0e7e3b890f974547c0828a03539147e49ae9b80a523ceb8a7397513cf247fdb414fead296b04e5d5fe8e7156836f53559c031d90463dfa633c3bfe47010000080101010101010101"
            )
            val decoded = LightningMessage.decode(bin)!!
            val expected = FundingSigned(
                ByteVector32("2056b684b3a084f17467369e894502541d7e3207bb66ef614d55368d9575c365"),
                ByteVector64("cf6739d3421d0e7e3b890f974547c0828a03539147e49ae9b80a523ceb8a7397513cf247fdb414fead296b04e5d5fe8e7156836f53559c031d90463dfa633c3b"),
                TlvStream(listOf(FundingSignedTlv.ChannelData(EncryptedChannelData(ByteVector("0101010101010101")))))
            )
            assertEquals(expected, decoded)
            val reencoded = LightningMessage.encode(decoded)
            assertArrayEquals(bin, reencoded)
        }
    }

    @Test
    fun `encode - decode funding_signed (large channel data)`() {
        run {
            val bin = Hex.decode(
                "00232056b684b3a084f17467369e894502541d7e3207bb66ef614d55368d9575c365cf6739d3421d0e7e3b890f974547c0828a03539147e49ae9b80a523ceb8a7397513cf247fdb414fead296b04e5d5fe8e7156836f53559c031d90463dfa633c3bfe47010000fd051401010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"
            )
            val decoded = LightningMessage.decode(bin)!!
            val expected = FundingSigned(
                ByteVector32("2056b684b3a084f17467369e894502541d7e3207bb66ef614d55368d9575c365"),
                ByteVector64("cf6739d3421d0e7e3b890f974547c0828a03539147e49ae9b80a523ceb8a7397513cf247fdb414fead296b04e5d5fe8e7156836f53559c031d90463dfa633c3b"),
                TlvStream(listOf(FundingSignedTlv.ChannelData(EncryptedChannelData(ByteArray(1300) { 1.toByte() }.toByteVector()))))
            )
            assertEquals(expected, decoded)
            val reencoded = LightningMessage.encode(decoded)
            assertArrayEquals(bin, reencoded)
        }
    }

    @Test
    fun `encode - decode channel_reestablish`() {
        val channelReestablish = ChannelReestablish(
            ByteVector32("c11b8fbd682b3c6ee11f9d7268e22bb5887cd4d3bf3338bfcc340583f685733c"),
            242842,
            42,
            PrivateKey.fromHex("34f159d37cf7b5de52ec0adc3968886232f90d272e8c82e8b6f7fcb7e57c4b55"),
            PublicKey.fromHex("02bf050efff417efc09eb211ca9e4e845920e2503740800e88505b25e6f0e1e867")
        )
        val encoded = LightningMessage.encode(channelReestablish)
        val expected =
            "0088c11b8fbd682b3c6ee11f9d7268e22bb5887cd4d3bf3338bfcc340583f685733c000000000003b49a000000000000002a34f159d37cf7b5de52ec0adc3968886232f90d272e8c82e8b6f7fcb7e57c4b5502bf050efff417efc09eb211ca9e4e845920e2503740800e88505b25e6f0e1e867"
        assertEquals(expected, Hex.encode(encoded))
    }

    @Test
    fun `encode - decode channel_update`() {
        val channelUpdate = ChannelUpdate(
            randomBytes64(),
            randomBytes32(),
            ShortChannelId(561),
            1105,
            0,
            1,
            CltvExpiryDelta(144),
            100.msat,
            0.msat,
            10,
            null
        )
        val encoded = LightningMessage.encode(channelUpdate)
        val decoded = LightningMessage.decode(encoded)
        assertEquals(channelUpdate, decoded)
    }

    @Test
    fun `decode channel_update with htlc_maximum_msat`() {
        // this was generated by c-lightning
        val encoded =
            ByteVector("010258fff7d0e987e2cdd560e3bb5a046b4efe7b26c969c2f51da1dceec7bcb8ae1b634790503d5290c1a6c51d681cf8f4211d27ed33a257dcc1102862571bf1792306226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0005a100000200005bc75919010100060000000000000001000000010000000a000000003a699d00")
        val decoded = LightningMessage.decode(encoded.toByteArray())!!
        val expected = ChannelUpdate(
            ByteVector64("58fff7d0e987e2cdd560e3bb5a046b4efe7b26c969c2f51da1dceec7bcb8ae1b634790503d5290c1a6c51d681cf8f4211d27ed33a257dcc1102862571bf17923"),
            ByteVector32("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"),
            ShortChannelId(0x5a10000020000L),
            1539791129,
            1,
            1,
            CltvExpiryDelta(6),
            1.msat,
            1.msat,
            10,
            980000000.msat
        )
        assertEquals(expected, decoded)
        val reEncoded = LightningMessage.encode(decoded).toByteVector()
        assertEquals(encoded, reEncoded)
    }

    @Test
    fun `encode - decode channel_update with unknown trailing bytes`() {
        val channelUpdate = ChannelUpdate(
            randomBytes64(),
            randomBytes32(),
            ShortChannelId(561),
            1105,
            0,
            1,
            CltvExpiryDelta(144),
            0.msat,
            10.msat,
            10,
            null,
            ByteVector("010203")
        )
        val encoded = LightningMessage.encode(channelUpdate)
        val decoded = LightningMessage.decode(encoded)
        assertEquals(channelUpdate, decoded)
    }

    @Test
    fun `encode - decode channel_announcement`() {
        val testCases = listOf(
            ChannelAnnouncement(
                randomBytes64(),
                randomBytes64(),
                randomBytes64(),
                randomBytes64(),
                Features(Hex.decode("09004200")),
                randomBytes32(),
                ShortChannelId(42),
                randomKey().publicKey(),
                randomKey().publicKey(),
                randomKey().publicKey(),
                randomKey().publicKey()
            ),
            ChannelAnnouncement(
                randomBytes64(),
                randomBytes64(),
                randomBytes64(),
                randomBytes64(),
                Features(mapOf()),
                randomBytes32(),
                ShortChannelId(42),
                randomKey().publicKey(),
                randomKey().publicKey(),
                randomKey().publicKey(),
                randomKey().publicKey(),
                ByteVector("01020304")
            ),
        )

        testCases.forEach {
            val encoded = LightningMessage.encode(it)
            val decoded = LightningMessage.decode(encoded)
            assertNotNull(decoded)
            assertEquals(it, decoded)
        }
    }

    @Test
    fun `encode - decode closing_signed`() {
        val defaultSig = ByteVector64("01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101")
        val testCases = listOf(
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 0000000000000000 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") to ClosingSigned(
                ByteVector32.One,
                0.sat,
                ByteVector64.Zeroes
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 00000000000003e8 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") to ClosingSigned(
                ByteVector32.One,
                1000.sat,
                ByteVector64.Zeroes
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 00000000000005dc 01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101") to ClosingSigned(
                ByteVector32.One,
                1500.sat,
                defaultSig
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 00000000000005dc 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 0110000000000000006400000000000007d0") to ClosingSigned(
                ByteVector32.One,
                1500.sat,
                ByteVector64.Zeroes,
                TlvStream(listOf(ClosingSignedTlv.FeeRange(100.sat, 2000.sat)))
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 00000000000003e8 01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101 0110000000000000006400000000000007d0") to ClosingSigned(
                ByteVector32.One,
                1000.sat,
                defaultSig,
                TlvStream(listOf(ClosingSignedTlv.FeeRange(100.sat, 2000.sat)))
            ),
            Hex.decode("0027 0100000000000000000000000000000000000000000000000000000000000000 0000000000000064 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 0110000000000000006400000000000003e8 030401020304") to ClosingSigned(
                ByteVector32.One,
                100.sat,
                ByteVector64.Zeroes,
                TlvStream(listOf(ClosingSignedTlv.FeeRange(100.sat, 1000.sat)), listOf(GenericTlv(3, ByteVector("01020304"))))
            ),
        )

        testCases.forEach {
            val decoded = LightningMessage.decode(it.first)
            assertNotNull(decoded)
            assertEquals(decoded, it.second)
            val reEncoded = LightningMessage.encode(decoded)
            assertArrayEquals(reEncoded, it.first)
        }
    }

    @Test
    fun `nonreg backup channel data`() {
        val channelId = randomBytes32()
        val signature = randomBytes64()
        val key = randomKey()
        val point = randomKey().publicKey()
        val randomData = randomBytes(42)

        // @formatter:off
        val refs = mapOf(
            Hex.decode("0023") + channelId.toByteArray() + signature.toByteArray() to FundingSigned(channelId, signature),
            Hex.decode("0023") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("01 02 0102") to FundingSigned(channelId, signature, TlvStream(listOf(), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0023") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("fe47010000 00") to FundingSigned(channelId, signature, TlvStream(listOf(FundingSignedTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0023") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 00")  to FundingSigned(channelId, signature, TlvStream(listOf(FundingSignedTlv.ChannelData(EncryptedChannelData.empty)), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0023") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("fe47010000 07 cccccccccccccc") to FundingSigned(channelId, signature).withChannelData(ByteVector("cccccccccccccc")),
            Hex.decode("0023") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 07 cccccccccccccc")  to FundingSigned(channelId, signature, TlvStream(listOf(FundingSignedTlv.ChannelData(EncryptedChannelData(ByteVector("cccccccccccccc")))), listOf(GenericTlv(1, ByteVector("0102"))))),

            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point, TlvStream(listOf(), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("fe47010000 00") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point, TlvStream(listOf(ChannelReestablishTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 00") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point, TlvStream(listOf(ChannelReestablishTlv.ChannelData(EncryptedChannelData(ByteVector.empty))), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("fe47010000 07 bbbbbbbbbbbbbb") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point).withChannelData(ByteVector("bbbbbbbbbbbbbb")),
            Hex.decode("0088") + channelId.toByteArray() + Hex.decode("0001020304050607 0809aabbccddeeff") + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 07 bbbbbbbbbbbbbb") to ChannelReestablish(channelId, 0x01020304050607L, 0x0809aabbccddeeffL, key, point, TlvStream(listOf(ChannelReestablishTlv.ChannelData(EncryptedChannelData(ByteVector("bbbbbbbbbbbbbb")))), listOf(GenericTlv(1, ByteVector("0102"))))),

            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000") to CommitSig(channelId, signature, listOf()),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000") + Hex.decode("01 02 0102") to CommitSig(channelId, signature, listOf(), TlvStream(listOf(), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000 fe47010000 00") to CommitSig(channelId, signature, listOf(), TlvStream(listOf(CommitSigTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000 01020102 fe47010000 00") to CommitSig(channelId, signature, listOf(), TlvStream(listOf(CommitSigTlv.ChannelData(EncryptedChannelData.empty)), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000 fe47010000 07 cccccccccccccc") to CommitSig(channelId, signature, listOf()).withChannelData(ByteVector("cccccccccccccc")),
            Hex.decode("0084") + channelId.toByteArray() + signature.toByteArray() + Hex.decode("0000 01020102 fe47010000 07 cccccccccccccc") to CommitSig(channelId, signature, listOf(), TlvStream(listOf(CommitSigTlv.ChannelData(EncryptedChannelData(ByteVector("cccccccccccccc")))), listOf(GenericTlv(1, ByteVector("0102"))))),

            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() to RevokeAndAck(channelId, key, point),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") to RevokeAndAck(channelId, key, point, TlvStream(listOf(), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("fe47010000 00") to RevokeAndAck(channelId, key, point, TlvStream(listOf(RevokeAndAckTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 00") to RevokeAndAck(channelId, key, point, TlvStream(listOf(RevokeAndAckTlv.ChannelData(EncryptedChannelData.empty)), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("fe47010000 07 cccccccccccccc") to RevokeAndAck(channelId, key, point).withChannelData(ByteVector("cccccccccccccc")),
            Hex.decode("0085") + channelId.toByteArray() + key.value.toByteArray() + point.value.toByteArray() + Hex.decode("01 02 0102") + Hex.decode("fe47010000 07 cccccccccccccc") to RevokeAndAck(channelId, key, point, TlvStream(listOf(RevokeAndAckTlv.ChannelData(EncryptedChannelData(ByteVector("cccccccccccccc")))), listOf(GenericTlv(1, ByteVector("0102"))))),

            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData to Shutdown(channelId, randomData.toByteVector()),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("01 02 0102") to Shutdown(channelId, randomData.toByteVector(), TlvStream(listOf(), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("fe47010000 00") to Shutdown(channelId, randomData.toByteVector(), TlvStream(listOf(ShutdownTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("01 02 0102") + Hex.decode("fe47010000 00") to Shutdown(channelId, randomData.toByteVector(), TlvStream(listOf(ShutdownTlv.ChannelData(EncryptedChannelData.empty)), listOf(GenericTlv(1, ByteVector("0102"))))),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("fe47010000 07 cccccccccccccc") to Shutdown(channelId, randomData.toByteVector()).withChannelData(ByteVector("cccccccccccccc")),
            Hex.decode("0026") + channelId.toByteArray() + Hex.decode("002a") + randomData + Hex.decode("01 02 0102") + Hex.decode("fe47010000 07 cccccccccccccc") to Shutdown(channelId, randomData.toByteVector(), TlvStream(listOf(ShutdownTlv.ChannelData(EncryptedChannelData(ByteVector("cccccccccccccc")))), listOf(GenericTlv(1, ByteVector("0102"))))),

            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() to ClosingSigned(channelId, 123456789.sat, signature),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("03 02 0102") to ClosingSigned(channelId, 123456789.sat, signature, TlvStream(listOf(), listOf(GenericTlv(3, ByteVector("0102"))))),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("fe47010000 00") to ClosingSigned(channelId, 123456789.sat, signature, TlvStream(listOf(ClosingSignedTlv.ChannelData(EncryptedChannelData.empty)))),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("03 02 0102") + Hex.decode("fe47010000 00") to ClosingSigned(channelId, 123456789.sat, signature, TlvStream(listOf(ClosingSignedTlv.ChannelData(EncryptedChannelData.empty)), listOf(GenericTlv(3, ByteVector("0102"))))),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("fe47010000 07 cccccccccccccc") to ClosingSigned(channelId, 123456789.sat, signature).withChannelData(ByteVector("cccccccccccccc")),
            Hex.decode("0027") + channelId.toByteArray() + Hex.decode("00000000075bcd15") + signature.toByteArray() + Hex.decode("03 02 0102") + Hex.decode("fe47010000 07 cccccccccccccc") to ClosingSigned(channelId, 123456789.sat, signature, TlvStream(listOf(ClosingSignedTlv.ChannelData(EncryptedChannelData(ByteVector("cccccccccccccc")))), listOf(GenericTlv(3, ByteVector("0102")))))
        )
        // @formatter:on

        refs.forEach {
            val decoded = LightningMessage.decode(it.key)
            assertEquals(it.value, decoded)
            val encoded = LightningMessage.encode(it.value)
            assertArrayEquals(it.key, encoded)
        }
    }

    @Test
    fun `encode - decode pay-to-open messages`() {
        val testCases = listOf(
            PayToOpenRequest(randomBytes32(), 10_000.sat, 5_000.msat, 100.msat, 10.sat, randomBytes32(), 100, OnionRoutingPacket(0, randomKey().publicKey().value, ByteVector("0102030405"), randomBytes32())),
            PayToOpenResponse(randomBytes32(), randomBytes32(), PayToOpenResponse.Result.Success(randomBytes32())),
            PayToOpenResponse(randomBytes32(), randomBytes32(), PayToOpenResponse.Result.Failure(null)),
            PayToOpenResponse(randomBytes32(), randomBytes32(), PayToOpenResponse.Result.Failure(ByteVector("deadbeef"))),
        )

        testCases.forEach {
            val encoded = LightningMessage.encode(it)
            val decoded = LightningMessage.decode(encoded)
            assertNotNull(decoded)
            assertEquals(it, decoded)
        }
    }

    @Test
    fun `encode - decode swap-in messages`() {
        val testCases = listOf(
            Pair(SwapInRequest(Block.LivenetGenesisBlock.blockId), Hex.decode("88bf000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")),
            Pair(
                SwapInResponse(Block.LivenetGenesisBlock.blockId, "bc1qms2el02t3fv8ecln0j74auassqwcg3ejekmypv"),
                Hex.decode("88c1000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f002a626331716d7332656c3032743366763865636c6e306a373461756173737177636733656a656b6d797076")
            ),
            Pair(SwapInPending("bc1qms2el02t3fv8ecln0j74auassqwcg3ejekmypv", Satoshi(123456)), Hex.decode("88bd002a626331716d7332656c3032743366763865636c6e306a373461756173737177636733656a656b6d797076000000000001e240")),
            Pair(SwapInConfirmed("39gzznpTuzhtjdN5R2LZu8GgWLR9NovLdi", MilliSatoshi(42_000_000)), Hex.decode("88c700223339677a7a6e7054757a68746a644e3552324c5a75384767574c52394e6f764c6469000000000280de80"))
        )

        testCases.forEach {
            val decoded = LightningMessage.decode(it.second)
            assertNotNull(decoded)
            assertEquals(it.first, decoded)
            val encoded = LightningMessage.encode(decoded)
            assertArrayEquals(it.second, encoded)
        }
    }
}