@file:UseSerializers(
    ByteVectorSerializer::class,
    ByteVector32Serializer::class,
    ByteVector64Serializer::class,
    TxIdSerializer::class,
    SatoshiSerializer::class,
    MilliSatoshiSerializer::class
)

package fr.acinq.lightning.db.types

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Satoshi
import fr.acinq.bitcoin.TxId
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.db.serializers.ByteVector32Serializer
import fr.acinq.lightning.db.serializers.ByteVector64Serializer
import fr.acinq.lightning.db.serializers.ByteVectorSerializer
import fr.acinq.lightning.db.serializers.TxIdSerializer
import fr.acinq.lightning.db.serializers.*
import fr.acinq.lightning.db.types.LiquidityAds.PaymentDetails.Companion.toCoreType
import fr.acinq.lightning.db.types.LiquidityAds.PaymentDetails.Companion.toDbType
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

internal object LiquidityAds {

    @Serializable
    sealed class FundingFee {
        @Serializable
        data class V0(val amount: MilliSatoshi, val fundingTxId: TxId) : FundingFee()
    }

    @Serializable
    sealed class PaymentDetails {
        sealed class ChannelBalance : PaymentDetails() {
            @Serializable
            data object V0 : ChannelBalance()
        }

        sealed class FutureHtlc : PaymentDetails() {
            @Serializable
            data class V0(val paymentHashes: List<ByteVector32>) : FutureHtlc()
        }

        sealed class FutureHtlcWithPreimage : PaymentDetails() {
            @Serializable
            data class V0(val preimages: List<ByteVector32>) : FutureHtlcWithPreimage()
        }

        sealed class ChannelBalanceForFutureHtlc : PaymentDetails() {
            @Serializable
            data class V0(val paymentHashes: List<ByteVector32>) : ChannelBalanceForFutureHtlc()
        }

        companion object {

            fun PaymentDetails.toCoreType(): fr.acinq.lightning.wire.LiquidityAds.PaymentDetails = when (this) {
                is ChannelBalance.V0 -> fr.acinq.lightning.wire.LiquidityAds.PaymentDetails.FromChannelBalance
                is FutureHtlc.V0 -> fr.acinq.lightning.wire.LiquidityAds.PaymentDetails.FromFutureHtlc(this.paymentHashes)
                is FutureHtlcWithPreimage.V0 -> fr.acinq.lightning.wire.LiquidityAds.PaymentDetails.FromFutureHtlcWithPreimage(this.preimages)
                is ChannelBalanceForFutureHtlc.V0 -> fr.acinq.lightning.wire.LiquidityAds.PaymentDetails.FromChannelBalanceForFutureHtlc(this.paymentHashes)
            }

            fun fr.acinq.lightning.wire.LiquidityAds.PaymentDetails.toDbType(): PaymentDetails = when (this) {
                is fr.acinq.lightning.wire.LiquidityAds.PaymentDetails.FromChannelBalance -> ChannelBalance.V0
                is fr.acinq.lightning.wire.LiquidityAds.PaymentDetails.FromFutureHtlc -> FutureHtlc.V0(this.paymentHashes)
                is fr.acinq.lightning.wire.LiquidityAds.PaymentDetails.FromFutureHtlcWithPreimage -> FutureHtlcWithPreimage.V0(this.preimages)
                is fr.acinq.lightning.wire.LiquidityAds.PaymentDetails.FromChannelBalanceForFutureHtlc -> ChannelBalanceForFutureHtlc.V0(this.paymentHashes)
            }
        }
    }

    @Serializable
    sealed class Purchase {

        sealed class Standard : Purchase() {
            @Serializable
            data class V0(
                val amount: Satoshi,
                val miningFees: Satoshi,
                val serviceFee: Satoshi,
                val paymentDetails: PaymentDetails
            ) : Standard()
        }

        sealed class WithFeeCredit : Purchase() {
            @Serializable
            data class V0(
                val amount: Satoshi,
                val miningFees: Satoshi,
                val serviceFee: Satoshi,
                val paymentDetails: PaymentDetails,
                val feeCreditUsed: MilliSatoshi
            ) : WithFeeCredit()
        }

        companion object {

            fun Purchase.toCoreType(): fr.acinq.lightning.wire.LiquidityAds.Purchase = when (val data = this) {
                is Standard.V0 -> fr.acinq.lightning.wire.LiquidityAds.Purchase.Standard(
                    amount = data.amount,
                    fees = fr.acinq.lightning.wire.LiquidityAds.Fees(miningFee = data.miningFees, serviceFee = data.serviceFee),
                    paymentDetails = data.paymentDetails.toCoreType()
                )
                is WithFeeCredit.V0 -> fr.acinq.lightning.wire.LiquidityAds.Purchase.WithFeeCredit(
                    amount = data.amount,
                    fees = fr.acinq.lightning.wire.LiquidityAds.Fees(miningFee = data.miningFees, serviceFee = data.serviceFee),
                    feeCreditUsed = data.feeCreditUsed,
                    paymentDetails = data.paymentDetails.toCoreType()
                )
            }

            fun fr.acinq.lightning.wire.LiquidityAds.Purchase.toDbType(): Purchase = when (val value = this) {
                is fr.acinq.lightning.wire.LiquidityAds.Purchase.Standard -> Standard.V0(value.amount, value.fees.miningFee, value.fees.serviceFee, value.paymentDetails.toDbType())
                is fr.acinq.lightning.wire.LiquidityAds.Purchase.WithFeeCredit -> WithFeeCredit.V0(value.amount, value.fees.miningFee, value.fees.serviceFee, value.paymentDetails.toDbType(), value.feeCreditUsed)
            }
        }
    }
}