package fr.acinq.lightning.wire

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Satoshi
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.lightning.Features
import fr.acinq.lightning.channel.ChannelOrigin
import fr.acinq.lightning.channel.ChannelType
import fr.acinq.lightning.utils.BitField
import fr.acinq.lightning.utils.toByteVector
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
sealed class ChannelTlv : Tlv {
    /** Commitment to where the funds will go in case of a mutual close, which remote node will enforce in case we're compromised. */
    @Serializable
    data class UpfrontShutdownScriptTlv(@Contextual val scriptPubkey: ByteVector) : ChannelTlv() {
        val isEmpty: Boolean get() = scriptPubkey.isEmpty()

        override val tag: Long get() = UpfrontShutdownScriptTlv.tag

        override fun write(out: Output) {
            LightningCodecs.writeBytes(scriptPubkey, out)
        }

        companion object : TlvValueReader<UpfrontShutdownScriptTlv> {
            const val tag: Long = 0

            override fun read(input: Input): UpfrontShutdownScriptTlv {
                val len = input.availableBytes
                val script = LightningCodecs.bytes(input, len)
                return UpfrontShutdownScriptTlv(ByteVector(script))
            }
        }
    }

    @Serializable
    data class ChannelTypeTlv(val channelType: ChannelType) : ChannelTlv() {
        override val tag: Long get() = ChannelTypeTlv.tag

        override fun write(out: Output) {
            val features = when (channelType) {
                is ChannelType.SupportedChannelType -> channelType.toFeatures()
                is ChannelType.UnsupportedChannelType -> channelType.featureBits
            }
            LightningCodecs.writeBytes(features.toByteArray(), out)
        }

        companion object : TlvValueReader<ChannelTypeTlv> {
            const val tag: Long = 1

            override fun read(input: Input): ChannelTypeTlv {
                val len = input.availableBytes
                val features = LightningCodecs.bytes(input, len)
                return ChannelTypeTlv(ChannelType.fromFeatures(Features(features)))
            }
        }
    }

    /** This legacy TLV was used before ChannelType was introduced: it should be removed whenever possible. */
    @Serializable
    data class ChannelVersionTlv(val channelType: ChannelType) : ChannelTlv() {
        override val tag: Long get() = ChannelVersionTlv.tag

        override fun write(out: Output) {
            val bits = BitField(4)
            when (channelType) {
                ChannelType.SupportedChannelType.AnchorOutputs -> {
                    bits.setRight(1)
                    bits.setRight(2)
                    bits.setRight(3)
                }
                ChannelType.SupportedChannelType.StaticRemoteKey -> {
                    bits.setRight(1)
                    bits.setRight(3)
                }
                ChannelType.SupportedChannelType.Standard -> {
                    bits.setRight(3)
                }
                is ChannelType.UnsupportedChannelType -> throw IllegalArgumentException("unsupported channel type: ${channelType.name}")
            }
            LightningCodecs.writeBytes(bits.bytes, out)
        }

        companion object : TlvValueReader<ChannelVersionTlv> {
            const val tag: Long = 0x47000001

            override fun read(input: Input): ChannelVersionTlv {
                val len = input.availableBytes
                val bits = BitField.from(LightningCodecs.bytes(input, len))
                val channelType = when {
                    bits.getRight(2) -> ChannelType.SupportedChannelType.AnchorOutputs
                    bits.getRight(1) -> ChannelType.SupportedChannelType.StaticRemoteKey
                    else -> ChannelType.SupportedChannelType.Standard
                }
                return ChannelVersionTlv(channelType)
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
    data class ChannelData(@Contextual val ecb: EncryptedChannelData) : ClosingSignedTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}
