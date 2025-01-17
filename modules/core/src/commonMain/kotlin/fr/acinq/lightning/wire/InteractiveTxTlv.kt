package fr.acinq.lightning.wire

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.utils.toByteVector64

sealed class TxAddInputTlv : Tlv {
    /**
     * When doing a splice, the initiator must provide the previous funding txId instead of the whole transaction.
     * Note that we actually encode this as a tx_hash to be consistent with other lightning messages.
     */
    data class SharedInputTxId(val txId: TxId) : TxAddInputTlv() {
        override val tag: Long get() = SharedInputTxId.tag
        override fun write(out: Output) = LightningCodecs.writeTxHash(TxHash(txId), out)

        companion object : TlvValueReader<SharedInputTxId> {
            const val tag: Long = 1105
            override fun read(input: Input): SharedInputTxId = SharedInputTxId(TxId(LightningCodecs.txHash(input)))
        }
    }

    /** When adding a swap-in input to an interactive-tx, the user needs to provide the corresponding script parameters. */
    data class SwapInParamsLegacy(val userKey: PublicKey, val serverKey: PublicKey, val refundDelay: Int) : TxAddInputTlv() {
        override val tag: Long get() = SwapInParamsLegacy.tag
        override fun write(out: Output) {
            LightningCodecs.writeBytes(userKey.value, out)
            LightningCodecs.writeBytes(serverKey.value, out)
            LightningCodecs.writeU32(refundDelay, out)
        }

        companion object : TlvValueReader<SwapInParamsLegacy> {
            const val tag: Long = 1107
            override fun read(input: Input): SwapInParamsLegacy = SwapInParamsLegacy(
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                LightningCodecs.u32(input)
            )
        }
    }

    /** When adding a swap-in input to an interactive-tx, the user needs to provide the corresponding script parameters. */
    data class SwapInParams(val userKey: PublicKey, val serverKey: PublicKey, val userRefundKey: PublicKey, val refundDelay: Int) : TxAddInputTlv() {
        override val tag: Long get() = SwapInParams.tag
        override fun write(out: Output) {
            LightningCodecs.writeBytes(userKey.value, out)
            LightningCodecs.writeBytes(serverKey.value, out)
            LightningCodecs.writeBytes(userRefundKey.value, out)
            LightningCodecs.writeU32(refundDelay, out)
        }

        companion object : TlvValueReader<SwapInParams> {
            const val tag: Long = 1109
            override fun read(input: Input): SwapInParams = SwapInParams(
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                PublicKey(LightningCodecs.bytes(input, 33)),
                LightningCodecs.u32(input)
            )
        }
    }
}

sealed class TxAddOutputTlv : Tlv

sealed class TxRemoveInputTlv : Tlv

sealed class TxRemoveOutputTlv : Tlv

sealed class TxCompleteTlv : Tlv {
    /** Public nonces for all Musig2 swap-in inputs (local and remote), ordered by serial id. */
    data class Nonces(val nonces: List<IndividualNonce>) : TxCompleteTlv() {
        override val tag: Long get() = Nonces.tag

        override fun write(out: Output) {
            nonces.forEach { LightningCodecs.writeBytes(it.toByteArray(), out) }
        }

        companion object : TlvValueReader<Nonces> {
            const val tag: Long = 101
            override fun read(input: Input): Nonces {
                val count = input.availableBytes / 66
                val nonces = (0 until count).map { IndividualNonce(LightningCodecs.bytes(input, 66)) }
                return Nonces(nonces)
            }
        }
    }
}

sealed class TxSignaturesTlv : Tlv {
    /** When doing a splice, each peer must provide their signature for the previous 2-of-2 funding output. */
    data class PreviousFundingTxSig(val sig: ByteVector64) : TxSignaturesTlv() {
        override val tag: Long get() = PreviousFundingTxSig.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(sig.toByteArray(), out)

        companion object : TlvValueReader<PreviousFundingTxSig> {
            const val tag: Long = 601
            override fun read(input: Input): PreviousFundingTxSig = PreviousFundingTxSig(LightningCodecs.bytes(input, 64).toByteVector64())
        }
    }

    /** Signatures from the swap user for inputs that belong to them. */
    data class SwapInUserSigs(val sigs: List<ByteVector64>) : TxSignaturesTlv() {
        override val tag: Long get() = SwapInUserSigs.tag
        override fun write(out: Output) = sigs.forEach { sig -> LightningCodecs.writeBytes(sig, out) }

        companion object : TlvValueReader<SwapInUserSigs> {
            const val tag: Long = 603
            override fun read(input: Input): SwapInUserSigs {
                val count = input.availableBytes / 64
                val sigs = (0 until count).map { LightningCodecs.bytes(input, 64).byteVector64() }
                return SwapInUserSigs(sigs)
            }
        }
    }

    /** Signatures from the swap server for inputs that belong to the user. */
    data class SwapInServerSigs(val sigs: List<ByteVector64>) : TxSignaturesTlv() {
        override val tag: Long get() = SwapInServerSigs.tag
        override fun write(out: Output) = sigs.forEach { sig -> LightningCodecs.writeBytes(sig, out) }

        companion object : TlvValueReader<SwapInServerSigs> {
            const val tag: Long = 605
            override fun read(input: Input): SwapInServerSigs {
                val count = input.availableBytes / 64
                val sigs = (0 until count).map { LightningCodecs.bytes(input, 64).byteVector64() }
                return SwapInServerSigs(sigs)
            }
        }
    }

    /** A partial musig2 signature, with the corresponding local and remote public nonces. */
    data class PartialSignature(val sig: ByteVector32, val localNonce: IndividualNonce, val remoteNonce: IndividualNonce)

    /** Partial musig2 signatures from the swap user for inputs that belong to them. */
    data class SwapInUserPartialSigs(val psigs: List<PartialSignature>) : TxSignaturesTlv() {
        override val tag: Long get() = SwapInUserPartialSigs.tag
        override fun write(out: Output) = psigs.forEach { psig ->
            LightningCodecs.writeBytes(psig.sig, out)
            LightningCodecs.writeBytes(psig.localNonce.toByteArray(), out)
            LightningCodecs.writeBytes(psig.remoteNonce.toByteArray(), out)
        }

        companion object : TlvValueReader<SwapInUserPartialSigs> {
            const val tag: Long = 607
            override fun read(input: Input): SwapInUserPartialSigs {
                val count = input.availableBytes / (32 + 66 + 66)
                val psigs = (0 until count).map {
                    val sig = LightningCodecs.bytes(input, 32).byteVector32()
                    val localNonce = IndividualNonce(LightningCodecs.bytes(input, 66))
                    val remoteNonce = IndividualNonce(LightningCodecs.bytes(input, 66))
                    PartialSignature(sig, localNonce, remoteNonce)
                }
                return SwapInUserPartialSigs(psigs)
            }
        }
    }

    /** Partial musig2 signatures from the swap server for inputs that belong to the user. */
    data class SwapInServerPartialSigs(val psigs: List<PartialSignature>) : TxSignaturesTlv() {
        override val tag: Long get() = SwapInServerPartialSigs.tag
        override fun write(out: Output) = psigs.forEach { psig ->
            LightningCodecs.writeBytes(psig.sig, out)
            LightningCodecs.writeBytes(psig.localNonce.toByteArray(), out)
            LightningCodecs.writeBytes(psig.remoteNonce.toByteArray(), out)
        }

        companion object : TlvValueReader<SwapInServerPartialSigs> {
            const val tag: Long = 609
            override fun read(input: Input): SwapInServerPartialSigs {
                val count = input.availableBytes / (32 + 66 + 66)
                val psigs = (0 until count).map {
                    val sig = LightningCodecs.bytes(input, 32).byteVector32()
                    val localNonce = IndividualNonce(LightningCodecs.bytes(input, 66))
                    val remoteNonce = IndividualNonce(LightningCodecs.bytes(input, 66))
                    PartialSignature(sig, localNonce, remoteNonce)
                }
                return SwapInServerPartialSigs(psigs)
            }
        }
    }

    data class ChannelData(val ecb: EncryptedChannelData) : TxSignaturesTlv() {
        override val tag: Long get() = ChannelData.tag
        override fun write(out: Output) = LightningCodecs.writeBytes(ecb.data, out)

        companion object : TlvValueReader<ChannelData> {
            const val tag: Long = 0x47010000
            override fun read(input: Input): ChannelData = ChannelData(EncryptedChannelData(LightningCodecs.bytes(input, input.availableBytes).toByteVector()))
        }
    }
}

sealed class TxInitRbfTlv : Tlv {
    /**
     * Amount that the peer will contribute to the transaction's shared output.
     * When used for splicing, this is a signed value that represents funds that are added or removed from the channel.
     */
    data class SharedOutputContributionTlv(val amount: Satoshi) : TxInitRbfTlv() {
        override val tag: Long get() = SharedOutputContributionTlv.tag

        override fun write(out: Output) = LightningCodecs.writeInt64(amount.toLong(), out)

        companion object : TlvValueReader<SharedOutputContributionTlv> {
            const val tag: Long = 0

            override fun read(input: Input): SharedOutputContributionTlv = SharedOutputContributionTlv(LightningCodecs.int64(input).sat)
        }
    }

    /** Require confirmed inputs for the transaction being built. */
    object RequireConfirmedInputsTlv : TxInitRbfTlv(), TlvValueReader<RequireConfirmedInputsTlv> {
        override val tag: Long get() = 2
        override fun write(out: Output) = Unit
        override fun read(input: Input): RequireConfirmedInputsTlv = this
    }
}

sealed class TxAckRbfTlv : Tlv {
    /**
     * Amount that the peer will contribute to the transaction's shared output.
     * When used for splicing, this is a signed value that represents funds that are added or removed from the channel.
     */
    data class SharedOutputContributionTlv(val amount: Satoshi) : TxAckRbfTlv() {
        override val tag: Long get() = SharedOutputContributionTlv.tag

        override fun write(out: Output) = LightningCodecs.writeInt64(amount.toLong(), out)

        companion object : TlvValueReader<SharedOutputContributionTlv> {
            const val tag: Long = 0

            override fun read(input: Input): SharedOutputContributionTlv = SharedOutputContributionTlv(LightningCodecs.int64(input).sat)
        }
    }

    /** Require confirmed inputs for the transaction being built. */
    object RequireConfirmedInputsTlv : TxAckRbfTlv(), TlvValueReader<RequireConfirmedInputsTlv> {
        override val tag: Long get() = 2
        override fun write(out: Output) = Unit
        override fun read(input: Input): RequireConfirmedInputsTlv = this
    }
}

sealed class TxAbortTlv : Tlv
