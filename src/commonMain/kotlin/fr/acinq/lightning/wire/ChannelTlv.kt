package fr.acinq.lightning.wire

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Satoshi
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.lightning.channel.ChannelOrigin
import fr.acinq.lightning.channel.ChannelVersion
import fr.acinq.lightning.serialization.v2.SatoshiKSerializer
import fr.acinq.lightning.utils.BitField
import fr.acinq.lightning.utils.toByteVector
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
sealed class ChannelTlv : Tlv {
    /** Commitment to where the funds will go in case of a mutual close, which remote node will enforce in case we're compromised. */
    @Serializable
    data class UpfrontShutdownScript(@Contextual val scriptPubkey: ByteVector) : ChannelTlv() {
        val isEmpty: Boolean get() = scriptPubkey.isEmpty()

        override val tag: Long get() = UpfrontShutdownScript.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(scriptPubkey, out)
        }

        companion object : TlvValueReader<UpfrontShutdownScript> {
            const val tag: Long = 0

            override fun read(input: Input): UpfrontShutdownScript {
                val len = input.availableBytes
                val script = LightningCodecs.bytes(input, len)
                return UpfrontShutdownScript(ByteVector(script))
            }
        }
    }

    @Serializable
    data class ChannelVersionTlv(val channelVersion: ChannelVersion) : ChannelTlv() {
        override val tag: Long get() = ChannelVersionTlv.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(channelVersion.bits.bytes, out)
        }

        companion object : TlvValueReader<ChannelVersionTlv> {
            const val tag: Long = 0x47000001

            override fun read(input: Input): ChannelVersionTlv {
                val len = input.availableBytes
                val buffer = LightningCodecs.bytes(input, len)
                return ChannelVersionTlv(ChannelVersion(BitField.from(buffer)))
            }
        }
    }

    @Serializable
    data class ChannelOriginTlv(val channelOrigin: ChannelOrigin) : ChannelTlv() {
        override val tag: Long get() = ChannelOriginTlv.tag

        override fun write(out: Output) {
            when (channelOrigin) {
                is ChannelOrigin.PayToOpenOrigin -> {
                    LightningCodecs.writeU16(1, out)
                    LightningCodecs.writeBytes(channelOrigin.paymentHash, out)
                    LightningCodecs.writeU64(channelOrigin.fee.toLong(), out)
                }
                is ChannelOrigin.SwapInOrigin -> {
                    LightningCodecs.writeU16(2, out)
                    val addressBytes = channelOrigin.bitcoinAddress.encodeToByteArray()
                    LightningCodecs.writeBigSize(addressBytes.size.toLong(), out)
                    LightningCodecs.writeBytes(addressBytes, out)
                    LightningCodecs.writeU64(channelOrigin.fee.toLong(), out)
                }
            }
        }

        companion object : TlvValueReader<ChannelOriginTlv> {
            const val tag: Long = 0x47000005

            override fun read(input: Input): ChannelOriginTlv {
                val origin = when (LightningCodecs.u16(input)) {
                    1 -> ChannelOrigin.PayToOpenOrigin(
                        paymentHash = ByteVector32(LightningCodecs.bytes(input, 32)),
                        fee = Satoshi(LightningCodecs.u64(input))
                    )
                    2 -> {
                        val len = LightningCodecs.bigSize(input)
                        ChannelOrigin.SwapInOrigin(
                            bitcoinAddress = LightningCodecs.bytes(input, len).decodeToString(),
                            fee = Satoshi(LightningCodecs.u64(input))
                        )
                    }
                    else -> TODO("Unsupported channel origin discriminator")
                }
                return ChannelOriginTlv(origin)
            }
        }
    }
}

@Serializable
sealed class FundingSignedTlv : Tlv {
    @Serializable
    data class ChannelData(@Contextual val ecb: EncryptedChannelData) : FundingSignedTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

@Serializable
sealed class CommitSigTlv : Tlv {
    @Serializable
    data class ChannelData(@Contextual val ecb: EncryptedChannelData) : CommitSigTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

@Serializable
sealed class RevokeAndAckTlv : Tlv {
    @Serializable
    data class ChannelData(@Contextual val ecb: EncryptedChannelData) : RevokeAndAckTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

@Serializable
sealed class ChannelReestablishTlv : Tlv {
    @Serializable
    data class ChannelData(@Contextual val ecb: EncryptedChannelData) : ChannelReestablishTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

@Serializable
sealed class ShutdownTlv : Tlv {
    @Serializable
    data class ChannelData(@Contextual val ecb: EncryptedChannelData) : ShutdownTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

@Serializable
sealed class ClosingSignedTlv : Tlv {
    @Serializable
    data class FeeRange(@Serializable(with = SatoshiKSerializer::class) val min: Satoshi, @Serializable(with = SatoshiKSerializer::class) val max: Satoshi) : ClosingSignedTlv() {
        override val tag: Long get() = FeeRange.tag

        override fun write(out: Output) {
            LightningCodecs.writeU64(min.toLong(), out)
            LightningCodecs.writeU64(max.toLong(), out)
        }

        companion object : TlvValueReader<FeeRange> {
            const val tag: Long = 1
            override fun read(input: Input): FeeRange = FeeRange(Satoshi(LightningCodecs.u64(input)), Satoshi(LightningCodecs.u64(input)))
        }
    }

    @Serializable
    data class ChannelData(@Contextual val ecb: EncryptedChannelData) : ClosingSignedTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}
