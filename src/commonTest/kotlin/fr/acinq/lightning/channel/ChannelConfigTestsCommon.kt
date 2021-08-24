package fr.acinq.lightning.channel

import fr.acinq.lightning.crypto.assertArrayEquals
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals

class ChannelConfigTestsCommon : LightningTestSuite() {

    @Test
    fun `convert from bytes`() {
        assertArrayEquals(ChannelConfig(ChannelConfigOption.FundingPubKeyBasedChannelKeyPath).toByteArray(), Hex.decode("01"))
        assertEquals(ChannelConfig(ChannelConfigOption.FundingPubKeyBasedChannelKeyPath), ChannelConfig(Hex.decode("ff")))
        assertEquals(ChannelConfig(ChannelConfigOption.FundingPubKeyBasedChannelKeyPath), ChannelConfig(Hex.decode("01")))
        assertEquals(ChannelConfig(ChannelConfigOption.FundingPubKeyBasedChannelKeyPath), ChannelConfig(Hex.decode("0001")))
        assertEquals(ChannelConfig(), ChannelConfig(Hex.decode("00")))
        assertEquals(ChannelConfig(), ChannelConfig(Hex.decode("0000")))
        assertEquals(ChannelConfig(), ChannelConfig(Hex.decode("02")))
        assertEquals(ChannelConfig(), ChannelConfig(Hex.decode("fe")))
    }

}