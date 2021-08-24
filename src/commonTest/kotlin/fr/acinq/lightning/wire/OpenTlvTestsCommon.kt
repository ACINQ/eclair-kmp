package fr.acinq.lightning.wire

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.lightning.channel.ChannelOrigin
import fr.acinq.lightning.channel.ChannelType
import fr.acinq.lightning.crypto.assertArrayEquals
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.sat
import fr.acinq.secp256k1.Hex
import kotlin.test.*

class OpenTlvTestsCommon : LightningTestSuite() {

    @Test
    fun `channel type TLV`() {
        val testCases = listOf(
            Pair(ChannelType.SupportedChannelType.Standard, Hex.decode("0100")),
            Pair(ChannelType.SupportedChannelType.StaticRemoteKey, Hex.decode("01021000")),
            Pair(ChannelType.SupportedChannelType.AnchorOutputs, Hex.decode("0103101000"))
        )

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(ChannelTlv.ChannelTypeTlv.tag to ChannelTlv.ChannelTypeTlv.Companion as TlvValueReader<ChannelTlv>)
        val tlvStreamSerializer = TlvStreamSerializer(false, readers)

        testCases.forEach {
            val decoded = tlvStreamSerializer.read(it.second)
            val encoded = tlvStreamSerializer.write(decoded)
            assertArrayEquals(it.second, encoded)
            val channelType = decoded.get<ChannelTlv.ChannelTypeTlv>()?.channelType
            assertNotNull(channelType)
            assertEquals(it.first, channelType)
        }
    }

    @Test
    fun `invalid channel type TLV`() {
        val testCases = listOf(
            Hex.decode("010101"),
            Hex.decode("01022000"),
            Hex.decode("0103202000"),
            Hex.decode("0103100000"),
            Hex.decode("0103401000"),
        )

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(ChannelTlv.ChannelTypeTlv.tag to ChannelTlv.ChannelTypeTlv.Companion as TlvValueReader<ChannelTlv>)
        val tlvStreamSerializer = TlvStreamSerializer(false, readers)

        testCases.forEach {
            val decoded = tlvStreamSerializer.read(it)
            val channelType = decoded.get<ChannelTlv.ChannelTypeTlv>()
            assertNotNull(channelType)
            assertTrue(channelType.channelType is ChannelType.UnsupportedChannelType)
        }
    }

    @Test
    fun `channel version TLV (legacy)`() {
        val testCases = listOf(
            Pair(ChannelType.SupportedChannelType.AnchorOutputs, Hex.decode("fe47000001 04 00000007")),
            Pair(ChannelType.SupportedChannelType.AnchorOutputs, Hex.decode("fe47000001 04 0000000f"))
        )

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(ChannelTlv.ChannelVersionTlv.tag to ChannelTlv.ChannelVersionTlv.Companion as TlvValueReader<ChannelTlv>)
        val tlvStreamSerializer = TlvStreamSerializer(false, readers)

        testCases.forEach {
            val decoded = tlvStreamSerializer.read(it.second)
            val channelType = decoded.get<ChannelTlv.ChannelVersionTlv>()?.channelType
            assertEquals(it.first, channelType)
        }
    }

    @Test
    fun `channel origin TLV`() {
        val testCases = listOf(
            Pair(
                ChannelOrigin.PayToOpenOrigin(ByteVector32.fromValidHex("187bf923f7f11ef732b73c417eb5a57cd4667b20a6f130ff505cd7ad3ab87281"), 1234.sat),
                Hex.decode("fe47000005 2a 0001 187bf923f7f11ef732b73c417eb5a57cd4667b20a6f130ff505cd7ad3ab87281 00000000000004d2")
            ),
            Pair(
                ChannelOrigin.SwapInOrigin("3AuM8hSkXBetjdHxWthRFiH6hYhqF2Prjr", 420.sat),
                Hex.decode("fe47000005 2d 0002 223341754d3868536b584265746a644878577468524669483668596871463250726a72 00000000000001a4")
            )
        )

        @Suppress("UNCHECKED_CAST")
        val readers = mapOf(ChannelTlv.ChannelOriginTlv.tag to ChannelTlv.ChannelOriginTlv.Companion as TlvValueReader<ChannelTlv>)
        val tlvStreamSerializer = TlvStreamSerializer(false, readers)

        testCases.forEach {
            val decoded = tlvStreamSerializer.read(it.second)
            val encoded = tlvStreamSerializer.write(decoded)
            assertArrayEquals(it.second, encoded)
            val channelOrigin = decoded.get<ChannelTlv.ChannelOriginTlv>()?.channelOrigin
            assertNotNull(channelOrigin)
            assertEquals(it.first, channelOrigin)
        }
    }

}
