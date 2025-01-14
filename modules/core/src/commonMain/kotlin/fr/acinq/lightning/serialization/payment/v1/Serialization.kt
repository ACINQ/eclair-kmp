package fr.acinq.lightning.serialization.payment.v1

import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Output
import fr.acinq.lightning.db.*
import fr.acinq.lightning.payment.FinalFailure
import fr.acinq.lightning.serialization.OutputExtensions.writeBoolean
import fr.acinq.lightning.serialization.OutputExtensions.writeByteVector32
import fr.acinq.lightning.serialization.OutputExtensions.writeCollection
import fr.acinq.lightning.serialization.OutputExtensions.writeDelimited
import fr.acinq.lightning.serialization.OutputExtensions.writeNullable
import fr.acinq.lightning.serialization.OutputExtensions.writeNumber
import fr.acinq.lightning.serialization.OutputExtensions.writePrivateKey
import fr.acinq.lightning.serialization.OutputExtensions.writePublicKey
import fr.acinq.lightning.serialization.OutputExtensions.writeString
import fr.acinq.lightning.serialization.OutputExtensions.writeTxId
import fr.acinq.lightning.serialization.OutputExtensions.writeUuid
import fr.acinq.lightning.serialization.common.liquidityads.Serialization.writeLiquidityPurchase
import fr.acinq.lightning.wire.LiquidityAds

@Suppress("DEPRECATION")
object Serialization {

    const val VERSION_MAGIC = 1

    fun serialize(o: WalletPayment): ByteArray {
        val out = ByteArrayOutput()
        out.write(VERSION_MAGIC)
        out.writeWalletPayment(o)
        return out.toByteArray()
    }

    private fun Output.writeWalletPayment(o: WalletPayment) = when (o) {
        is IncomingPayment -> {
            write(0x00); writeIncomingPayment(o)
        }
        is OutgoingPayment -> {
            write(0x01); writeOutgoingPayment(o)
        }
    }

    private fun Output.writeIncomingPayment(o: IncomingPayment) = when (o) {
        is Bolt11IncomingPayment -> {
            write(0x00); writeBolt11IncomingPayment(o)
        }
        is Bolt12IncomingPayment -> {
            write(0x01); writeBolt12IncomingPayment(o)
        }
        is NewChannelIncomingPayment -> {
            write(0x02); writeNewChannelIncomingPayment(o)
        }
        is SpliceInIncomingPayment -> {
            write(0x03); writeSpliceInIncomingPayment(o)
        }
        is LegacyPayToOpenIncomingPayment -> {
            write(0x04); writeLegacyPayToOpenIncomingPayment(o)
        }
        is LegacySwapInIncomingPayment -> {
            write(0x05); writeLegacySwapInIncomingPayment(o)
        }
    }

    private fun Output.writeBolt11IncomingPayment(o: Bolt11IncomingPayment) = o.run {
        writeByteVector32(paymentPreimage)
        writeString(paymentRequest.write())
        writeCollection(o.parts) { writeLightningIncomingPaymentPart(it) }
        writeNumber(createdAt)
    }

    private fun Output.writeBolt12IncomingPayment(o: Bolt12IncomingPayment) = o.run {
        writeByteVector32(paymentPreimage)
        writeDelimited(metadata.encode().toByteArray())
        writeCollection(o.parts) { writeLightningIncomingPaymentPart(it) }
        writeNumber(createdAt)
    }

    private fun Output.writeLightningIncomingPaymentPart(o: LightningIncomingPayment.Part) = when (o) {
        is LightningIncomingPayment.Part.Htlc -> {
            write(0x00)
            writeNumber(o.amountReceived.toLong())
            writeByteVector32(o.channelId)
            writeNumber(o.htlcId)
            writeNullable(o.fundingFee) {
                writeNumber(it.amount.toLong())
                writeTxId(it.fundingTxId)
            }
            writeNumber(o.receivedAt)
        }
        is LightningIncomingPayment.Part.FeeCredit -> {
            write(0x01)
            writeNumber(o.amountReceived.toLong())
            writeNumber(o.receivedAt)
        }
    }

    private fun Output.writeNewChannelIncomingPayment(o: NewChannelIncomingPayment) = o.run {
        writeUuid(id)
        writeNumber(amountReceived.toLong())
        writeNumber(serviceFee.toLong())
        writeNumber(miningFee.toLong())
        writeByteVector32(channelId)
        writeTxId(txId)
        writeCollection(localInputs) { writeOutPoint(it) }
        writeNumber(createdAt)
        writeNullable(confirmedAt) { writeNumber(it) }
        writeNullable(lockedAt) { writeNumber(it) }
    }

    private fun Output.writeSpliceInIncomingPayment(o: SpliceInIncomingPayment) = o.run {
        writeUuid(id)
        writeNumber(amountReceived.toLong())
        writeNumber(miningFee.toLong())
        writeByteVector32(channelId)
        writeTxId(txId)
        writeCollection(localInputs) { writeOutPoint(it) }
        writeNumber(createdAt)
        writeNullable(confirmedAt) { writeNumber(it) }
        writeNullable(lockedAt) { writeNumber(it) }
    }

    private fun Output.writeLegacyPayToOpenIncomingPayment(o: LegacyPayToOpenIncomingPayment) = o.run {
        writeByteVector32(paymentPreimage)
        when (origin) {
            is LegacyPayToOpenIncomingPayment.Origin.Invoice -> {
                write(0x11); writeString(origin.paymentRequest.write())
            }
            is LegacyPayToOpenIncomingPayment.Origin.Offer -> {
                write(0x12); writeDelimited(origin.metadata.encode().toByteArray())
            }
        }
        writeCollection(parts) {
            when (it) {
                is LegacyPayToOpenIncomingPayment.Part.Lightning -> {
                    write(0x01)
                    writeNumber(it.amountReceived.toLong())
                    writeByteVector32(it.channelId)
                    writeNumber(it.htlcId)
                }
                is LegacyPayToOpenIncomingPayment.Part.OnChain -> {
                    write(0x02)
                    writeNumber(it.amountReceived.toLong())
                    writeNumber(it.serviceFee.toLong())
                    writeNumber(it.miningFee.toLong())
                    writeByteVector32(it.channelId)
                    writeTxId(it.txId)
                    writeNullable(it.confirmedAt) { writeNumber(it) }
                    writeNullable(it.lockedAt) { writeNumber(it) }
                }
            }
        }
        writeNumber(createdAt)
        writeNullable(completedAt) { writeNumber(it) }
    }

    private fun Output.writeLegacySwapInIncomingPayment(o: LegacySwapInIncomingPayment) = o.run {
        writeUuid(id)
        writeNumber(amountReceived.toLong())
        writeNumber(fees.toLong())
        writeNullable(address) { writeString(it) }
        writeNumber(createdAt)
        writeNullable(completedAt) { writeNumber(it) }
    }

    private fun Output.writeOutPoint(o: OutPoint) = o.run {
        writeTxId(txid)
        writeNumber(index)
    }

    private fun Output.writeOutgoingPayment(o: OutgoingPayment) = when (o) {
        is LightningOutgoingPayment -> {
            write(0x00); writeLightningOutgoingPayment(o)
        }
        is SpliceOutgoingPayment -> {
            write(0x01); writeSpliceOutgoingPayment(o)
        }
        is SpliceCpfpOutgoingPayment -> {
            write(0x02); writeSpliceCpfpOutgoingPayment(o)
        }
        is InboundLiquidityOutgoingPayment -> {
            write(0x03); writeInboundLiquidityOutgoingPayment(o)
        }
        is ChannelCloseOutgoingPayment -> {
            write(0x04); writeChannelCloseOutgoingPayment(o)
        }
    }

    private fun Output.writeLightningOutgoingPayment(o: LightningOutgoingPayment) = o.run {
        writeUuid(id)
        writeNumber(recipientAmount.toLong())
        writePublicKey(recipient)
        when (details) {
            is LightningOutgoingPayment.Details.Normal -> {
                write(0x00)
                writeString(details.paymentRequest.write())
            }
            is LightningOutgoingPayment.Details.Blinded -> {
                write(0x01)
                writeString(details.paymentRequest.write())
                writePrivateKey(details.payerKey)
            }
            is LightningOutgoingPayment.Details.SwapOut -> {
                write(0x02)
                writeString(details.address)
                writeString(details.paymentRequest.write())
                writeNumber(details.swapOutFee.toLong())
            }
        }
        writeCollection(parts) { part ->
            writeUuid(part.id)
            writeNumber(part.amount.toLong())
            writeCollection(part.route) { hop ->
                writePublicKey(hop.nodeId)
                writePublicKey(hop.nextNodeId)
                writeNullable(hop.shortChannelId) { writeNumber(it.toLong()) }
            }
            writeLightningOutgoingPaymentPartStatus(part.status)
            writeNumber(part.createdAt)
        }
        writeLightningOutgoingPaymentStatus(status)
        writeNumber(createdAt)
    }

    private fun Output.writeLightningOutgoingPaymentPartStatus(o: LightningOutgoingPayment.Part.Status) = when (o) {
        is LightningOutgoingPayment.Part.Status.Pending -> {
            write(0x00)
        }
        is LightningOutgoingPayment.Part.Status.Succeeded -> {
            write(0x01)
            writeByteVector32(o.preimage)
            writeNumber(o.completedAt)
        }
        is LightningOutgoingPayment.Part.Status.Failed -> {
            write(0x02)
            when (o.failure) {
                LightningOutgoingPayment.Part.Status.Failed.Failure.ChannelIsClosing ->
                    write(0x00)
                LightningOutgoingPayment.Part.Status.Failed.Failure.ChannelIsSplicing ->
                    write(0x01)
                LightningOutgoingPayment.Part.Status.Failed.Failure.NotEnoughFees ->
                    write(0x02)
                LightningOutgoingPayment.Part.Status.Failed.Failure.NotEnoughFunds ->
                    write(0x03)
                LightningOutgoingPayment.Part.Status.Failed.Failure.PaymentAmountTooBig ->
                    write(0x04)
                LightningOutgoingPayment.Part.Status.Failed.Failure.PaymentAmountTooSmall ->
                    write(0x05)
                LightningOutgoingPayment.Part.Status.Failed.Failure.PaymentExpiryTooBig ->
                    write(0x06)
                LightningOutgoingPayment.Part.Status.Failed.Failure.RecipientRejectedPayment ->
                    write(0x07)
                LightningOutgoingPayment.Part.Status.Failed.Failure.RecipientIsOffline ->
                    write(0x08)
                LightningOutgoingPayment.Part.Status.Failed.Failure.RecipientLiquidityIssue ->
                    write(0x09)
                LightningOutgoingPayment.Part.Status.Failed.Failure.TemporaryRemoteFailure ->
                    write(0x0a)
                LightningOutgoingPayment.Part.Status.Failed.Failure.TooManyPendingPayments ->
                    write(0x0b)
                is LightningOutgoingPayment.Part.Status.Failed.Failure.Uninterpretable -> {
                    write(0x0c)
                    writeString(o.failure.message)
                }
            }
            writeNumber(o.completedAt)
        }
    }

    private fun Output.writeLightningOutgoingPaymentStatus(o: LightningOutgoingPayment.Status) = when (o) {
        is LightningOutgoingPayment.Status.Pending -> {
            write(0x00)
        }
        is LightningOutgoingPayment.Status.Succeeded -> {
            write(0x01)
            writeByteVector32(o.preimage)
            writeNumber(o.completedAt)
        }
        is LightningOutgoingPayment.Status.Failed -> {
            write(0x02)
            when (o.reason) {
                FinalFailure.AlreadyPaid ->
                    write(0x00)
                FinalFailure.ChannelClosing ->
                    write(0x01)
                FinalFailure.ChannelNotConnected ->
                    write(0x02)
                FinalFailure.ChannelOpening ->
                    write(0x03)
                FinalFailure.FeaturesNotSupported ->
                    write(0x04)
                FinalFailure.InsufficientBalance ->
                    write(0x05)
                FinalFailure.InvalidPaymentAmount ->
                    write(0x06)
                FinalFailure.InvalidPaymentId ->
                    write(0x07)
                FinalFailure.NoAvailableChannels ->
                    write(0x08)
                FinalFailure.RecipientUnreachable ->
                    write(0x09)
                FinalFailure.RetryExhausted ->
                    write(0x0a)
                FinalFailure.UnknownError ->
                    write(0x0b)
                FinalFailure.WalletRestarted ->
                    write(0x0c)
            }
            writeNumber(o.completedAt)
        }
    }

    private fun Output.writeSpliceOutgoingPayment(o: SpliceOutgoingPayment) = o.run {
        writeUuid(id)
        writeNumber(recipientAmount.toLong())
        writeString(address)
        writeNumber(miningFees.toLong())
        writeByteVector32(channelId)
        writeTxId(txId)
        writeNumber(createdAt)
        writeNullable(confirmedAt) { writeNumber(it) }
        writeNullable(lockedAt) { writeNumber(it) }
    }

    private fun Output.writeSpliceCpfpOutgoingPayment(o: SpliceCpfpOutgoingPayment) = o.run {
        writeUuid(id)
        writeNumber(miningFees.toLong())
        writeByteVector32(channelId)
        writeTxId(txId)
        writeNumber(createdAt)
        writeNullable(confirmedAt) { writeNumber(it) }
        writeNullable(lockedAt) { writeNumber(it) }
    }

    private fun Output.writeInboundLiquidityOutgoingPayment(o: InboundLiquidityOutgoingPayment) = o.run {
        writeUuid(id)
        writeByteVector32(channelId)
        writeTxId(txId)
        writeNumber(localMiningFees.toLong())
        writeLiquidityPurchase(purchase)
        writeNumber(createdAt)
        writeNullable(confirmedAt) { writeNumber(it) }
        writeNullable(lockedAt) { writeNumber(it) }
    }

    private fun Output.writeChannelCloseOutgoingPayment(o: ChannelCloseOutgoingPayment) = o.run {
        writeUuid(id)
        writeNumber(recipientAmount.toLong())
        writeString(address)
        writeBoolean(isSentToDefaultAddress)
        writeNumber(miningFees.toLong())
        writeByteVector32(channelId)
        writeTxId(txId)
        writeNumber(createdAt)
        writeNullable(confirmedAt) { writeNumber(it) }
        writeNullable(lockedAt) { writeNumber(it) }
        when (closingType) {
            ChannelCloseOutgoingPayment.ChannelClosingType.Mutual -> write(0x00)
            ChannelCloseOutgoingPayment.ChannelClosingType.Local -> write(0x01)
            ChannelCloseOutgoingPayment.ChannelClosingType.Remote -> write(0x02)
            ChannelCloseOutgoingPayment.ChannelClosingType.Revoked -> write(0x03)
            ChannelCloseOutgoingPayment.ChannelClosingType.Other -> write(0x04)
        }
    }
}