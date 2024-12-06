package fr.acinq.lightning.wire

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Output
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.utils.toByteVector32

sealed class FailureMessage {
    abstract val message: String
    abstract val code: Int

    companion object {
        const val BADONION = 0x8000
        const val PERM = 0x4000
        const val NODE = 0x2000
        const val UPDATE = 0x1000

        private fun readChannelUpdate(stream: ByteArrayInput): ChannelUpdate {
            val len = LightningCodecs.u16(stream)
            val tag = LightningCodecs.u16(stream)
            require(tag == ChannelUpdate.type.toInt()) { "channel update should be prefixed with its lightning message type" }
            return ChannelUpdate.read(LightningCodecs.bytes(stream, len - 2))
        }

        fun decode(input: ByteArray): FailureMessage {
            val stream = ByteArrayInput(input)
            return when (val code = LightningCodecs.u16(stream)) {
                InvalidRealm.code -> InvalidRealm
                TemporaryNodeFailure.code -> TemporaryNodeFailure
                PermanentNodeFailure.code -> PermanentNodeFailure
                RequiredNodeFeatureMissing.code -> RequiredNodeFeatureMissing
                InvalidOnionVersion.code -> InvalidOnionVersion(LightningCodecs.bytes(stream, 32).toByteVector32())
                InvalidOnionHmac.code -> InvalidOnionHmac(LightningCodecs.bytes(stream, 32).toByteVector32())
                InvalidOnionKey.code -> InvalidOnionKey(LightningCodecs.bytes(stream, 32).toByteVector32())
                TemporaryChannelFailure.code -> TemporaryChannelFailure(readChannelUpdate(stream))
                PermanentChannelFailure.code -> PermanentChannelFailure
                RequiredChannelFeatureMissing.code -> RequiredChannelFeatureMissing
                UnknownNextPeer.code -> UnknownNextPeer
                AmountBelowMinimum.code -> AmountBelowMinimum(MilliSatoshi(LightningCodecs.u64(stream)), readChannelUpdate(stream))
                FeeInsufficient.code -> FeeInsufficient(MilliSatoshi(LightningCodecs.u64(stream)), readChannelUpdate(stream))
                IncorrectCltvExpiry.code -> IncorrectCltvExpiry(CltvExpiry(LightningCodecs.u32(stream).toLong()), readChannelUpdate(stream))
                ExpiryTooSoon.code -> ExpiryTooSoon(readChannelUpdate(stream))
                IncorrectOrUnknownPaymentDetails.code -> {
                    val amount = if (stream.availableBytes > 0) MilliSatoshi(LightningCodecs.u64(stream)) else MilliSatoshi(0)
                    val blockHeight = if (stream.availableBytes > 0) LightningCodecs.u32(stream).toLong() else 0L
                    IncorrectOrUnknownPaymentDetails(amount, blockHeight)
                }
                FinalIncorrectCltvExpiry.code -> FinalIncorrectCltvExpiry(CltvExpiry(LightningCodecs.u32(stream).toLong()))
                FinalIncorrectHtlcAmount.code -> FinalIncorrectHtlcAmount(MilliSatoshi(LightningCodecs.u64(stream)))
                ChannelDisabled.code -> ChannelDisabled(LightningCodecs.byte(stream).toByte(), LightningCodecs.byte(stream).toByte(), readChannelUpdate(stream))
                ExpiryTooFar.code -> ExpiryTooFar
                InvalidOnionPayload.code -> InvalidOnionPayload(LightningCodecs.bigSize(stream), LightningCodecs.u16(stream))
                PaymentTimeout.code -> PaymentTimeout
                TemporaryTrampolineFailure.code -> TemporaryTrampolineFailure
                TrampolineFeeOrExpiryInsufficient.code -> TrampolineFeeOrExpiryInsufficient(MilliSatoshi(LightningCodecs.u32(stream).toLong()), LightningCodecs.u32(stream), CltvExpiryDelta(LightningCodecs.u16(stream)))
                UnknownNextTrampoline.code -> UnknownNextTrampoline
                else -> UnknownFailureMessage(code)
            }
        }

        private fun writeChannelUpdate(channelUpdate: ChannelUpdate, out: Output) {
            val bin = channelUpdate.write()
            LightningCodecs.writeU16(bin.size + 2, out)
            LightningCodecs.writeU16(ChannelUpdate.type.toInt(), out)
            LightningCodecs.writeBytes(bin, out)
        }

        fun encode(input: FailureMessage, out: Output) {
            LightningCodecs.writeU16(input.code, out)
            when (input) {
                InvalidRealm -> {}
                TemporaryNodeFailure -> {}
                PermanentNodeFailure -> {}
                RequiredNodeFeatureMissing -> {}
                is InvalidOnionVersion -> LightningCodecs.writeBytes(input.onionHash, out)
                is InvalidOnionHmac -> LightningCodecs.writeBytes(input.onionHash, out)
                is InvalidOnionKey -> LightningCodecs.writeBytes(input.onionHash, out)
                is InvalidOnionBlinding -> LightningCodecs.writeBytes(input.onionHash, out)
                is TemporaryChannelFailure -> writeChannelUpdate(input.update, out)
                PermanentChannelFailure -> {}
                RequiredChannelFeatureMissing -> {}
                UnknownNextPeer -> {}
                is AmountBelowMinimum -> {
                    LightningCodecs.writeU64(input.amount.toLong(), out)
                    writeChannelUpdate(input.update, out)
                }
                is FeeInsufficient -> {
                    LightningCodecs.writeU64(input.amount.toLong(), out)
                    writeChannelUpdate(input.update, out)
                }
                is IncorrectCltvExpiry -> {
                    LightningCodecs.writeU32(input.expiry.toLong().toInt(), out)
                    writeChannelUpdate(input.update, out)
                }
                is ExpiryTooSoon -> writeChannelUpdate(input.update, out)
                is IncorrectOrUnknownPaymentDetails -> {
                    LightningCodecs.writeU64(input.amount.toLong(), out)
                    LightningCodecs.writeU32(input.height.toInt(), out)
                }
                is FinalIncorrectCltvExpiry -> LightningCodecs.writeU32(input.expiry.toLong().toInt(), out)
                is FinalIncorrectHtlcAmount -> LightningCodecs.writeU64(input.amount.toLong(), out)
                is ChannelDisabled -> {
                    LightningCodecs.writeByte(input.messageFlags.toInt(), out)
                    LightningCodecs.writeByte(input.channelFlags.toInt(), out)
                    writeChannelUpdate(input.update, out)
                }
                ExpiryTooFar -> {}
                is InvalidOnionPayload -> {
                    LightningCodecs.writeBigSize(input.tag, out)
                    LightningCodecs.writeU16(input.offset, out)
                }
                PaymentTimeout -> {}
                TemporaryTrampolineFailure -> {}
                is TrampolineFeeOrExpiryInsufficient -> {
                    LightningCodecs.writeU32(input.feeBase.toLong().toInt(), out)
                    LightningCodecs.writeU32(input.feeProportionalMillionths, out)
                    LightningCodecs.writeU16(input.expiryDelta.toInt(), out)
                }
                UnknownNextTrampoline -> {}
                is UnknownFailureMessage -> {}
            }
        }

        fun encode(input: FailureMessage): ByteArray {
            val out = ByteArrayOutput()
            encode(input, out)
            return out.toByteArray()
        }
    }
}

// @formatter:off
interface BadOnion { val onionHash: ByteVector32 }
interface Perm
interface Node
interface Update { val update: ChannelUpdate }

object InvalidRealm : FailureMessage(), Perm {
    override val code get() = PERM or 1
    override val message get() = "realm was not understood by the processing node"
}
object TemporaryNodeFailure : FailureMessage(), Node {
    override val code get() = NODE or 2
    override val message get() = "general temporary failure of the processing node"
}
object PermanentNodeFailure : FailureMessage(), Perm, Node {
    override val code get() = PERM or NODE or 2
    override val message get() = "general permanent failure of the processing node"
}
object RequiredNodeFeatureMissing : FailureMessage(), Perm, Node {
    override val code get() = PERM or NODE or 3
    override val message get() = "processing node requires features that are missing from this onion"
}
data class InvalidOnionVersion(override val onionHash: ByteVector32) : FailureMessage(), BadOnion, Perm {
    override val code get() = InvalidOnionVersion.code
    override val message get() = "onion version was not understood by the processing node"
    companion object { const val code = BADONION or PERM or 4 }
}
data class InvalidOnionHmac(override val onionHash: ByteVector32) : FailureMessage(), BadOnion, Perm {
    override val code get() = InvalidOnionHmac.code
    override val message get() = "onion HMAC was incorrect when it reached the processing node"
    companion object { const val code = BADONION or PERM or 5 }
}
data class InvalidOnionKey(override val onionHash: ByteVector32) : FailureMessage(), BadOnion, Perm {
    override val code get() = InvalidOnionKey.code
    override val message get() = "ephemeral key was unparsable by the processing node"
    companion object { const val code = BADONION or PERM or 6 }
}
data class InvalidOnionBlinding(override val onionHash: ByteVector32) : FailureMessage(), BadOnion, Perm {
    override val code get() = InvalidOnionBlinding.code
    override val message get() = "the blinded onion didn't match the processing node's requirements"
    companion object { const val code = BADONION or PERM or 24 }
}
data class TemporaryChannelFailure(override val update: ChannelUpdate) : FailureMessage(), Update {
    override val code get() = TemporaryChannelFailure.code
    override val message get() = "channel ${update.shortChannelId} is currently unavailable"
    companion object { const val code = UPDATE or 7 }
}
object PermanentChannelFailure : FailureMessage(), Perm {
    override val code get() = PERM or 8
    override val message get() = "channel is permanently unavailable"
}
object RequiredChannelFeatureMissing : FailureMessage(), Perm {
    override val code get() = PERM or 9
    override val message get() = "channel requires features not present in the onion"
}
object UnknownNextPeer : FailureMessage(), Perm {
    override val code get() = PERM or 10
    override val message get() = "processing node does not know the next peer in the route"
}
data class AmountBelowMinimum(val amount: MilliSatoshi, override val update: ChannelUpdate) : FailureMessage(), Update {
    override val code get() = AmountBelowMinimum.code
    override val message get() = "payment amount was below the minimum required by the channel"
    companion object { const val code = UPDATE or 11 }
}
data class FeeInsufficient(val amount: MilliSatoshi, override val update: ChannelUpdate) : FailureMessage(), Update {
    override val code get() = FeeInsufficient.code
    override val message get() = "payment fee was below the minimum required by the channel"
    companion object { const val code = UPDATE or 12 }
}
data class IncorrectCltvExpiry(val expiry: CltvExpiry, override val update: ChannelUpdate) : FailureMessage(), Update {
    override val code get() = IncorrectCltvExpiry.code
    override val message get() = "payment expiry doesn't match the value in the onion"
    companion object { const val code = UPDATE or 13 }
}
data class ExpiryTooSoon(override val update: ChannelUpdate) : FailureMessage(), Update {
    override val code get() = ExpiryTooSoon.code
    override val message get() = "payment expiry is too close to the current block height for safe handling by the relaying node"
    companion object { const val code = UPDATE or 14 }
}
data class IncorrectOrUnknownPaymentDetails(val amount: MilliSatoshi, val height: Long) : FailureMessage(), Perm {
    override val code get() = IncorrectOrUnknownPaymentDetails.code
    override val message get() = "incorrect payment details or unknown payment hash"
    companion object { const val code = PERM or 15 }
}
data class FinalIncorrectCltvExpiry(val expiry: CltvExpiry) : FailureMessage() {
    override val code get() = FinalIncorrectCltvExpiry.code
    override val message get() = "payment expiry doesn't match the value in the onion"
    companion object { const val code = 18 }
}
data class FinalIncorrectHtlcAmount(val amount: MilliSatoshi) : FailureMessage() {
    override val code get() = FinalIncorrectHtlcAmount.code
    override val message get() = "payment amount is incorrect in the final htlc"
    companion object { const val code = 19 }
}
data class ChannelDisabled(val messageFlags: Byte, val channelFlags: Byte, override val update: ChannelUpdate) : FailureMessage(), Update {
    override val code get() = ChannelDisabled.code
    override val message get() = "channel is currently disabled"
    companion object { const val code = UPDATE or 20 }
}
data object ExpiryTooFar : FailureMessage() {
    override val code get() = 21
    override val message get() = "payment expiry is too far in the future"
}
data class InvalidOnionPayload(val tag: Long, val offset: Int) : FailureMessage(), Perm {
    override val code get() = InvalidOnionPayload.code
    override val message get() = "onion per-hop payload is invalid"
    companion object { const val code = PERM or 22 }
}
data object PaymentTimeout : FailureMessage() {
    override val code get() = 23
    override val message get() = "the complete payment amount was not received within a reasonable time"
}
data object TemporaryTrampolineFailure : FailureMessage(), Node {
    override val code get() = NODE or 25
    override val message get() = "the trampoline node was unable to relay the payment because of downstream temporary failures"
}
data class TrampolineFeeOrExpiryInsufficient(val feeBase: MilliSatoshi, val feeProportionalMillionths: Int, val expiryDelta: CltvExpiryDelta) : FailureMessage(), Node {
    override val code get() = TrampolineFeeOrExpiryInsufficient.code
    override val message get() = "trampoline fees or expiry are insufficient to relay the payment"
    companion object { const val code = NODE or 26 }
}
data object UnknownNextTrampoline : FailureMessage(), Perm {
    override val code get() = PERM or 27
    override val message get() = "the trampoline node was unable to find the next trampoline node"
}
/**
 * We allow remote nodes to send us unknown failure codes (e.g. deprecated failure codes).
 * By reading the PERM and NODE bits of the failure code we can still extract useful information for payment retry even
 * without knowing how to decode the failure payload (but we can't extract a channel update or onion hash).
 */
data class UnknownFailureMessage(override val code: Int) : FailureMessage() {
    override val message get() = "unknown failure message"
}
// @formatter:on
