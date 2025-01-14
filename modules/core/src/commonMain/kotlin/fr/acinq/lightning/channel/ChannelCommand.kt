package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.WatchEvent
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.states.PersistedChannelState
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.wire.FailureMessage
import fr.acinq.lightning.wire.LightningMessage
import fr.acinq.lightning.wire.LiquidityAds
import fr.acinq.lightning.wire.OnionRoutingPacket
import kotlinx.coroutines.CompletableDeferred
import fr.acinq.lightning.wire.Init as InitMessage

/** Channel Events (inputs to be fed to the state machine). */
sealed class ChannelCommand {
    // @formatter:off
    data class Connected(val localInit: InitMessage, val remoteInit: InitMessage) : ChannelCommand()
    data object Disconnected : ChannelCommand()
    sealed class Init : ChannelCommand() {
        data class Initiator(
            val replyTo: CompletableDeferred<ChannelFundingResponse>,
            val fundingAmount: Satoshi,
            val walletInputs: List<WalletState.Utxo>,
            val commitTxFeerate: FeeratePerKw,
            val fundingTxFeerate: FeeratePerKw,
            val localParams: LocalParams,
            val remoteInit: InitMessage,
            val channelFlags: ChannelFlags,
            val channelConfig: ChannelConfig,
            val channelType: ChannelType.SupportedChannelType,
            val requestRemoteFunding: LiquidityAds.RequestFunding?,
            val channelOrigin: Origin?,
        ) : Init() {
            fun temporaryChannelId(keyManager: KeyManager): ByteVector32 = keyManager.channelKeys(localParams.fundingKeyPath).temporaryChannelId
        }

        data class NonInitiator(
            val replyTo: CompletableDeferred<ChannelFundingResponse>,
            val temporaryChannelId: ByteVector32,
            val fundingAmount: Satoshi,
            val walletInputs: List<WalletState.Utxo>,
            val localParams: LocalParams,
            val channelConfig: ChannelConfig,
            val remoteInit: InitMessage,
            val fundingRates: LiquidityAds.WillFundRates?
        ) : Init()

        data class Restore(val state: PersistedChannelState) : Init()
    }

    sealed class Funding : ChannelCommand() {
        // We only support a very limited fee bumping mechanism where all spendable utxos will be used (only used in tests).
        data class BumpFundingFee(val targetFeerate: FeeratePerKw, val fundingAmount: Satoshi, val walletInputs: List<WalletState.Utxo>, val lockTime: Long) : Funding()
    }

    data class MessageReceived(val message: LightningMessage) : ChannelCommand()
    data class WatchReceived(val watch: WatchEvent) : ChannelCommand()

    sealed interface ForbiddenDuringSplice
    sealed interface ForbiddenDuringQuiescence
    sealed class Htlc : ChannelCommand() {
        data class Add(val amount: MilliSatoshi, val paymentHash: ByteVector32, val cltvExpiry: CltvExpiry, val onion: OnionRoutingPacket, val paymentId: UUID, val commit: Boolean = false) : Htlc(), ForbiddenDuringSplice, ForbiddenDuringQuiescence

        sealed class Settlement : Htlc(), ForbiddenDuringSplice, ForbiddenDuringQuiescence {
            abstract val id: Long

            data class Fulfill(override val id: Long, val r: ByteVector32, val commit: Boolean = false) : Settlement()
            data class FailMalformed(override val id: Long, val onionHash: ByteVector32, val failureCode: Int, val commit: Boolean = false) : Settlement()
            data class Fail(override val id: Long, val reason: Reason, val commit: Boolean = false) : Settlement() {
                sealed class Reason {
                    data class Bytes(val bytes: ByteVector) : Reason()
                    data class Failure(val message: FailureMessage) : Reason()
                }
            }
        }
    }

    sealed class Commitment : ChannelCommand() {
        object Sign : Commitment(), ForbiddenDuringSplice
        data class UpdateFee(val feerate: FeeratePerKw, val commit: Boolean = false) : Commitment(), ForbiddenDuringSplice, ForbiddenDuringQuiescence
        data object CheckHtlcTimeout : Commitment()
        sealed class Splice : Commitment() {
            data class Request(
                val replyTo: CompletableDeferred<ChannelFundingResponse>,
                val spliceIn: SpliceIn?,
                val spliceOut: SpliceOut?,
                val requestRemoteFunding: LiquidityAds.RequestFunding?,
                val currentFeeCredit: MilliSatoshi,
                val feerate: FeeratePerKw,
                val origins: List<Origin>
            ) : Splice() {
                val spliceOutputs: List<TxOut> = spliceOut?.let { listOf(TxOut(it.amount, it.scriptPubKey)) } ?: emptyList()
                val liquidityFees: LiquidityAds.Fees? = requestRemoteFunding?.fees(feerate, isChannelCreation = false)

                data class SpliceIn(val walletInputs: List<WalletState.Utxo>)
                data class SpliceOut(val amount: Satoshi, val scriptPubKey: ByteVector)
            }
        }
    }

    sealed class Close : ChannelCommand() {
        data class MutualClose(val scriptPubKey: ByteVector?, val feerate: FeeratePerKw) : Close(), ForbiddenDuringSplice, ForbiddenDuringQuiescence
        data object ForceClose : Close()
    }

    sealed class Closing : ChannelCommand() {
        data class GetHtlcInfosResponse(val revokedCommitTxId: TxId, val htlcInfos: List<ChannelAction.Storage.HtlcInfo>) : Closing()
    }
    // @formatter:on
}

sealed class ChannelFundingResponse {
    /**
     * This response doesn't fully guarantee that the channel transaction will confirm, because our peer may potentially double-spend it.
     * Callers should wait for on-chain confirmations and handle double-spend events.
     */
    data class Success(
        val channelId: ByteVector32,
        val fundingTxIndex: Long,
        val fundingTxId: TxId,
        val capacity: Satoshi,
        val balance: MilliSatoshi,
        val liquidityPurchase: LiquidityAds.Purchase?,
    ) : ChannelFundingResponse()

    sealed class Failure : ChannelFundingResponse() {
        data class InsufficientFunds(val balanceAfterFees: MilliSatoshi, val liquidityFees: MilliSatoshi, val currentFeeCredit: MilliSatoshi) : Failure()
        data object InvalidSpliceOutPubKeyScript : ChannelFundingResponse.Failure()
        data object SpliceAlreadyInProgress : Failure()
        data object ConcurrentRemoteSplice : Failure()
        data object ChannelNotQuiescent : Failure()
        data class InvalidChannelParameters(val reason: ChannelException) : Failure()
        data class InvalidLiquidityAds(val reason: ChannelException) : Failure()
        data class FundingFailure(val reason: FundingContributionFailure) : Failure()
        data object CannotStartSession : Failure()
        data class InteractiveTxSessionFailed(val reason: InteractiveTxSessionAction.RemoteFailure) : Failure()
        data class CannotCreateCommitTx(val reason: ChannelException) : Failure()
        data class AbortedByPeer(val reason: String) : Failure()
        data class UnexpectedMessage(val msg: LightningMessage) : Failure()
        data object Disconnected : Failure()
    }
}