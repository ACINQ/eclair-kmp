package fr.acinq.lightning.serialization.payment.v1

import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.byteVector
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.Input
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.db.*
import fr.acinq.lightning.payment.Bolt11Invoice
import fr.acinq.lightning.payment.Bolt12Invoice
import fr.acinq.lightning.payment.FinalFailure
import fr.acinq.lightning.payment.OfferPaymentMetadata
import fr.acinq.lightning.serialization.InputExtensions.readBoolean
import fr.acinq.lightning.serialization.InputExtensions.readByteVector32
import fr.acinq.lightning.serialization.InputExtensions.readCollection
import fr.acinq.lightning.serialization.InputExtensions.readDelimitedByteArray
import fr.acinq.lightning.serialization.InputExtensions.readNullable
import fr.acinq.lightning.serialization.InputExtensions.readNumber
import fr.acinq.lightning.serialization.InputExtensions.readPrivateKey
import fr.acinq.lightning.serialization.InputExtensions.readPublicKey
import fr.acinq.lightning.serialization.InputExtensions.readString
import fr.acinq.lightning.serialization.InputExtensions.readTxId
import fr.acinq.lightning.serialization.InputExtensions.readUuid
import fr.acinq.lightning.serialization.common.liquidityads.Deserialization.readLiquidityPurchase
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.LiquidityAds

@Suppress("DEPRECATION")
object Deserialization {

    fun deserialize(bin: ByteArray): WalletPayment {
        val input = ByteArrayInput(bin)
        val version = input.read()
        require(version == Serialization.VERSION_MAGIC) { "incorrect version $version, expected ${Serialization.VERSION_MAGIC}" }
        return input.readWalletPayment()
    }

    private fun Input.readWalletPayment(): WalletPayment = when (val discriminator = read()) {
        0x00 -> readIncomingPayment()
        0x01 -> readOutgoingPayment()
        else -> error("unknown discriminator $discriminator for class ${WalletPayment::class}")
    }

    private fun Input.readIncomingPayment(): IncomingPayment = when (val discriminator = read()) {
        0x00 -> readBolt11IncomingPayment()
        0x01 -> readBolt12IncomingPayment()
        0x02 -> readNewChannelIncomingPayment()
        0x03 -> readSpliceInIncomingPayment()
        0x04 -> readLegacyPayToOpenIncomingPayment()
        0x05 -> readLegacySwapInIncomingPayment()
        else -> error("unknown discriminator $discriminator for class ${IncomingPayment::class}")
    }

    private fun Input.readBolt11IncomingPayment() = Bolt11IncomingPayment(
        preimage = readByteVector32(),
        paymentRequest = Bolt11Invoice.read(readString()).get(),
        parts = readCollection { readLightningIncomingPaymentPart() }.toList(),
        createdAt = readNumber()
    )

    private fun Input.readBolt12IncomingPayment() = Bolt12IncomingPayment(
        preimage = readByteVector32(),
        metadata = OfferPaymentMetadata.decode(readDelimitedByteArray().byteVector()),
        parts = readCollection { readLightningIncomingPaymentPart() }.toList(),
        createdAt = readNumber()
    )

    private fun Input.readLightningIncomingPaymentPart(): LightningIncomingPayment.Part = when (val discriminator = read()) {
        0x00 -> LightningIncomingPayment.Part.Htlc(
            amountReceived = readNumber().msat,
            channelId = readByteVector32(),
            htlcId = readNumber(),
            fundingFee = readNullable {
                LiquidityAds.FundingFee(
                    amount = readNumber().msat,
                    fundingTxId = readTxId()
                )
            },
            receivedAt = readNumber()
        )
        0x01 -> LightningIncomingPayment.Part.FeeCredit(
            amountReceived = readNumber().msat,
            receivedAt = readNumber()
        )
        else -> error("unknown discriminator $discriminator for class ${LightningIncomingPayment.Part::class}")
    }

    private fun Input.readNewChannelIncomingPayment(): NewChannelIncomingPayment = NewChannelIncomingPayment(
        id = readUuid(),
        amountReceived = readNumber().msat,
        serviceFee = readNumber().msat,
        miningFee = readNumber().sat,
        channelId = readByteVector32(),
        txId = readTxId(),
        localInputs = readCollection { readOutPoint() }.toSet(),
        createdAt = readNumber(),
        confirmedAt = readNullable { readNumber() },
        lockedAt = readNullable { readNumber() },
    )

    private fun Input.readSpliceInIncomingPayment(): SpliceInIncomingPayment = SpliceInIncomingPayment(
        id = readUuid(),
        amountReceived = readNumber().msat,
        miningFee = readNumber().sat,
        channelId = readByteVector32(),
        txId = readTxId(),
        localInputs = readCollection { readOutPoint() }.toSet(),
        createdAt = readNumber(),
        confirmedAt = readNullable { readNumber() },
        lockedAt = readNullable { readNumber() },
    )

    private fun Input.readLegacyPayToOpenIncomingPayment(): LegacyPayToOpenIncomingPayment = LegacyPayToOpenIncomingPayment(
        paymentPreimage = readByteVector32(),
        origin = when (val discriminator = read()) {
            0x11 -> LegacyPayToOpenIncomingPayment.Origin.Invoice(Bolt11Invoice.read(readString()).get())
            0x12 -> LegacyPayToOpenIncomingPayment.Origin.Offer(OfferPaymentMetadata.decode(readDelimitedByteArray().byteVector()))
            else -> error("unknown discriminator $discriminator for class ${LegacyPayToOpenIncomingPayment::class}")
        },
        parts = readCollection {
            when (val discriminator = read()) {
                0x01 -> LegacyPayToOpenIncomingPayment.Part.Lightning(
                    amountReceived = readNumber().msat,
                    channelId = readByteVector32(),
                    htlcId = readNumber()
                )
                0x02 -> LegacyPayToOpenIncomingPayment.Part.OnChain(
                    amountReceived = readNumber().msat,
                    serviceFee = readNumber().msat,
                    miningFee = readNumber().sat,
                    channelId = readByteVector32(),
                    txId = readTxId(),
                    confirmedAt = readNullable { readNumber() },
                    lockedAt = readNullable { readNumber() },
                )
                else -> error("unknown discriminator $discriminator for class ${LegacyPayToOpenIncomingPayment::class}")
            }
        }.toList(),
        createdAt = readNumber(),
        completedAt = readNullable { readNumber() }
    )

    private fun Input.readLegacySwapInIncomingPayment(): LegacySwapInIncomingPayment = LegacySwapInIncomingPayment(
        id = readUuid(),
        amountReceived = readNumber().msat,
        fees = readNumber().msat,
        address = readNullable { readString() },
        createdAt = readNumber(),
        completedAt = readNullable { readNumber() }
    )

    private fun Input.readOutPoint(): OutPoint = OutPoint(
        txid = readTxId(),
        index = readNumber()
    )

    private fun Input.readOutgoingPayment(): OutgoingPayment = when (val discriminator = read()) {
        0x00 -> readLightningOutgoingPayment()
        0x01 -> readSpliceOutgoingPayment()
        0x02 -> readSpliceCpfpOutgoingPayment()
        0x03 -> readInboundLiquidityOutgoingPayment()
        0x04 -> readChannelCloseOutgoingPayment()
        else -> error("unknown discriminator $discriminator for class ${OutgoingPayment::class}")
    }

    private fun Input.readLightningOutgoingPayment(): LightningOutgoingPayment = LightningOutgoingPayment(
        id = readUuid(),
        recipientAmount = readNumber().msat,
        recipient = readPublicKey(),
        details = when (val discriminator = read()) {
            0x00 -> LightningOutgoingPayment.Details.Normal(
                paymentRequest = Bolt11Invoice.read(readString()).get()
            )
            0x01 -> LightningOutgoingPayment.Details.Blinded(
                paymentRequest = Bolt12Invoice.fromString(readString()).get(),
                payerKey = readPrivateKey()
            )
            0x02 -> LightningOutgoingPayment.Details.SwapOut(
                address = readString(),
                paymentRequest = Bolt11Invoice.read(readString()).get(),
                swapOutFee = readNumber().sat
            )
            else -> error("unknown discriminator $discriminator for class ${LightningOutgoingPayment.Details::class}")
        },
        parts = readCollection {
            LightningOutgoingPayment.Part(
                id = readUuid(),
                amount = readNumber().msat,
                route = readCollection {
                    LightningOutgoingPayment.Part.HopDesc(
                        nodeId = readPublicKey(),
                        nextNodeId = readPublicKey(),
                        shortChannelId = readNullable { ShortChannelId(readNumber()) }
                    )
                }.toList(),
                status = readLightningOutgoingPaymentPartStatus(),
                createdAt = readNumber()
            )
        }.toList(),
        status = readLightningOutgoingPaymentStatus(),
        createdAt = readNumber()
    )

    private fun Input.readLightningOutgoingPaymentPartStatus(): LightningOutgoingPayment.Part.Status = when (val discriminator = read()) {
        0x00 -> LightningOutgoingPayment.Part.Status.Pending
        0x01 -> LightningOutgoingPayment.Part.Status.Succeeded(
            preimage = readByteVector32(),
            completedAt = readNumber()
        )
        0x02 -> LightningOutgoingPayment.Part.Status.Failed(
            failure = when (val failureDiscriminator = read()) {
                0x00 -> LightningOutgoingPayment.Part.Status.Failed.Failure.ChannelIsClosing
                0x01 -> LightningOutgoingPayment.Part.Status.Failed.Failure.ChannelIsSplicing
                0x02 -> LightningOutgoingPayment.Part.Status.Failed.Failure.NotEnoughFees
                0x03 -> LightningOutgoingPayment.Part.Status.Failed.Failure.NotEnoughFunds
                0x04 -> LightningOutgoingPayment.Part.Status.Failed.Failure.PaymentAmountTooBig
                0x05 -> LightningOutgoingPayment.Part.Status.Failed.Failure.PaymentAmountTooSmall
                0x06 -> LightningOutgoingPayment.Part.Status.Failed.Failure.PaymentExpiryTooBig
                0x07 -> LightningOutgoingPayment.Part.Status.Failed.Failure.RecipientRejectedPayment
                0x08 -> LightningOutgoingPayment.Part.Status.Failed.Failure.RecipientIsOffline
                0x09 -> LightningOutgoingPayment.Part.Status.Failed.Failure.RecipientLiquidityIssue
                0x0a -> LightningOutgoingPayment.Part.Status.Failed.Failure.TemporaryRemoteFailure
                0x0b -> LightningOutgoingPayment.Part.Status.Failed.Failure.TooManyPendingPayments
                0x0c -> LightningOutgoingPayment.Part.Status.Failed.Failure.Uninterpretable(readString())
                else -> error("unknown discriminator $failureDiscriminator for class ${LightningOutgoingPayment.Part.Status.Failed.Failure::class}")
            },
            completedAt = readNumber()
        )
        else -> error("unknown discriminator $discriminator for class ${LightningOutgoingPayment.Part.Status::class}")
    }

    private fun Input.readLightningOutgoingPaymentStatus(): LightningOutgoingPayment.Status = when (val discriminator = read()) {
        0x00 -> LightningOutgoingPayment.Status.Pending
        0x01 -> LightningOutgoingPayment.Status.Succeeded(
            preimage = readByteVector32(),
            completedAt = readNumber()
        )
        0x02 -> LightningOutgoingPayment.Status.Failed(
            reason = when (val failureDiscriminator = read()) {
                0x00 -> FinalFailure.AlreadyPaid
                0x01 -> FinalFailure.ChannelClosing
                0x02 -> FinalFailure.ChannelNotConnected
                0x03 -> FinalFailure.ChannelOpening
                0x04 -> FinalFailure.FeaturesNotSupported
                0x05 -> FinalFailure.InsufficientBalance
                0x06 -> FinalFailure.InvalidPaymentAmount
                0x07 -> FinalFailure.InvalidPaymentId
                0x08 -> FinalFailure.NoAvailableChannels
                0x09 -> FinalFailure.RecipientUnreachable
                0x0a -> FinalFailure.RetryExhausted
                0x0b -> FinalFailure.UnknownError
                0x0c -> FinalFailure.WalletRestarted
                else -> error("unknown discriminator $failureDiscriminator for class ${LightningOutgoingPayment.Status.Failed::class}")
            },
            completedAt = readNumber()
        )
        else -> error("unknown discriminator $discriminator for class ${LightningOutgoingPayment.Status::class}")
    }

    private fun Input.readSpliceOutgoingPayment(): SpliceOutgoingPayment = SpliceOutgoingPayment(
        id = readUuid(),
        recipientAmount = readNumber().sat,
        address = readString(),
        miningFees = readNumber().sat,
        channelId = readByteVector32(),
        txId = readTxId(),
        createdAt = readNumber(),
        confirmedAt = readNullable { readNumber() },
        lockedAt = readNullable { readNumber() }
    )

    private fun Input.readSpliceCpfpOutgoingPayment(): SpliceCpfpOutgoingPayment = SpliceCpfpOutgoingPayment(
        id = readUuid(),
        miningFees = readNumber().sat,
        channelId = readByteVector32(),
        txId = readTxId(),
        createdAt = readNumber(),
        confirmedAt = readNullable { readNumber() },
        lockedAt = readNullable { readNumber() }
    )

    private fun Input.readInboundLiquidityOutgoingPayment(): InboundLiquidityOutgoingPayment = InboundLiquidityOutgoingPayment(
        id = readUuid(),
        channelId = readByteVector32(),
        txId = readTxId(),
        localMiningFees = readNumber().sat,
        purchase = readLiquidityPurchase(),
        createdAt = readNumber(),
        confirmedAt = readNullable { readNumber() },
        lockedAt = readNullable { readNumber() }
    )

    private fun Input.readChannelCloseOutgoingPayment(): ChannelCloseOutgoingPayment = ChannelCloseOutgoingPayment(
        id = readUuid(),
        recipientAmount = readNumber().sat,
        address = readString(),
        isSentToDefaultAddress = readBoolean(),
        miningFees = readNumber().sat,
        channelId = readByteVector32(),
        txId = readTxId(),
        createdAt = readNumber(),
        confirmedAt = readNullable { readNumber() },
        lockedAt = readNullable { readNumber() },
        closingType = when (val discriminator = read()) {
            0x00 -> ChannelCloseOutgoingPayment.ChannelClosingType.Mutual
            0x01 -> ChannelCloseOutgoingPayment.ChannelClosingType.Local
            0x02 -> ChannelCloseOutgoingPayment.ChannelClosingType.Remote
            0x03 -> ChannelCloseOutgoingPayment.ChannelClosingType.Revoked
            0x04 -> ChannelCloseOutgoingPayment.ChannelClosingType.Other
            else -> error("unknown discriminator $discriminator for class ${ChannelCloseOutgoingPayment.ChannelClosingType::class}")
        }
    )
}