package fr.acinq.lightning.wire

import fr.acinq.bitcoin.Block
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Lightning
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.utils.msat
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals

class FailureMessageTestsCommon : LightningTestSuite() {
    private val channelUpdate = ChannelUpdate(
        signature = Lightning.randomBytes64(),
        chainHash = Block.RegtestGenesisBlock.hash,
        shortChannelId = ShortChannelId(12345),
        timestampSeconds = 1234567,
        cltvExpiryDelta = CltvExpiryDelta(100),
        messageFlags = 0,
        channelFlags = 1,
        htlcMinimumMsat = 1000.msat,
        feeBaseMsat = 12.msat,
        feeProportionalMillionths = 76,
        htlcMaximumMsat = null
    )

    @ExperimentalUnsignedTypes
    @Test
    fun `encode - decode all failure messages`() {
        val msgs = listOf(
            InvalidRealm,
            TemporaryNodeFailure,
            PermanentNodeFailure,
            RequiredNodeFeatureMissing,
            InvalidOnionVersion(Lightning.randomBytes32()),
            InvalidOnionHmac(Lightning.randomBytes32()),
            InvalidOnionKey(Lightning.randomBytes32()),
            TemporaryChannelFailure(channelUpdate),
            PermanentChannelFailure,
            RequiredChannelFeatureMissing,
            UnknownNextPeer,
            AmountBelowMinimum(123456.msat, channelUpdate),
            FeeInsufficient(546463.msat, channelUpdate),
            IncorrectCltvExpiry(CltvExpiry(1211), channelUpdate),
            ExpiryTooSoon(channelUpdate),
            IncorrectOrUnknownPaymentDetails(123456.msat, 1105),
            FinalIncorrectCltvExpiry(CltvExpiry(1234)),
            FinalIncorrectHtlcAmount(123456.msat),
            ChannelDisabled(0, 1, channelUpdate),
            ExpiryTooFar,
            InvalidOnionPayload(561, 1105),
            PaymentTimeout,
            TemporaryTrampolineFailure,
            UnknownNextTrampoline,
            TrampolineFeeOrExpiryInsufficient(100.msat, 50, CltvExpiryDelta(36))
        )

        msgs.forEach {
            val encoded = FailureMessage.encode(it)
            val decoded = FailureMessage.decode(encoded)
            assertEquals(it, decoded)
        }
    }

    @Test
    fun `decode unknown failure messages`() {
        val testCases = listOf(
            // Deprecated incorrect_payment_amount.
            Pair("4010", 0x4010),
            // Deprecated final_expiry_too_soon.
            Pair("4011", 0x4011),
            // Unknown failure messages.
            Pair("00ff 42", 0xff),
            Pair("20ff 42", 0x20ff),
            Pair("60ff 42", 0x60ff)
        )

        testCases.forEach {
            val decoded = FailureMessage.decode(Hex.decode(it.first))
            assertEquals(UnknownFailureMessage(it.second), decoded)
        }
    }

    @Test
    fun `encode - decode channel update`() {
        val bin =
            "100700820102cc3e80149073ed487c76e48e9622bf980f78267b8a34a3f61921f2d8fce6063b08e74f34a073a13f2097337e4915bb4c001f3b5c4d81e9524ed575e1f45782196fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000008260500041300005b91b52f0003000e00000000000003e80000000100000001"
        val expected = TemporaryChannelFailure(
            ChannelUpdate(
                ByteVector64("cc3e80149073ed487c76e48e9622bf980f78267b8a34a3f61921f2d8fce6063b08e74f34a073a13f2097337e4915bb4c001f3b5c4d81e9524ed575e1f4578219"),
                Block.LivenetGenesisBlock.hash,
                ShortChannelId(0x826050004130000L),
                1536275759,
                0,
                3,
                CltvExpiryDelta(14),
                1000.msat,
                1.msat,
                1,
                null
            )
        )
        assertEquals(expected, FailureMessage.decode(Hex.decode(bin)))
    }
}