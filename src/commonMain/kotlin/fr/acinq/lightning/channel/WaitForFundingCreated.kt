@file:UseContextualSerialization(BlockHeader::class, ByteVector32::class, PublicKey::class, WalletState::class)
package fr.acinq.lightning.channel

import fr.acinq.bitcoin.BlockHeader
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.utils.Either
import fr.acinq.lightning.wire.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseContextualSerialization

/*
 * We build the funding transaction for a new channel.
 *
 *       Local                        Remote
 *         |       tx_add_input         |
 *         |<---------------------------|
 *         |       tx_add_input         |
 *         |--------------------------->|
 *         |            ...             |
 *         |       tx_add_output        |
 *         |<---------------------------|
 *         |       tx_add_output        |
 *         |--------------------------->|
 *         |            ...             |
 *         |      tx_add_complete       |
 *         |<---------------------------|
 *         |      tx_add_complete       |
 *         |--------------------------->|
 *         |        commit_sig          |
 *         |--------------------------->|
 */
@Serializable
data class WaitForFundingCreated(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    val localParams: LocalParams,
    val remoteParams: RemoteParams,
    val wallet: WalletState,
    val interactiveTxSession: InteractiveTxSession,
    val localPushAmount: MilliSatoshi,
    val remotePushAmount: MilliSatoshi,
    val commitTxFeerate: FeeratePerKw,
    val remoteFirstPerCommitmentPoint: PublicKey,
    val channelFlags: Byte,
    val channelConfig: ChannelConfig,
    val channelFeatures: ChannelFeatures,
    val channelOrigin: ChannelOrigin?
) : ChannelState() {
    val channelId: ByteVector32 = interactiveTxSession.fundingParams.channelId

    override fun processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when {
            cmd is ChannelCommand.MessageReceived && cmd.message is InteractiveTxConstructionMessage -> {
                val (interactiveTxSession1, interactiveTxAction) = interactiveTxSession.receive(cmd.message)
                when (interactiveTxAction) {
                    is InteractiveTxSessionAction.SendMessage -> Pair(this.copy(interactiveTxSession = interactiveTxSession1), listOf(ChannelAction.Message.Send(interactiveTxAction.msg)))
                    is InteractiveTxSessionAction.SignSharedTx -> {
                        val firstCommitTxRes = Helpers.Funding.makeFirstCommitTxs(
                            keyManager,
                            channelId,
                            localParams,
                            remoteParams,
                            interactiveTxSession.fundingParams.localAmount,
                            interactiveTxSession.fundingParams.remoteAmount,
                            localPushAmount,
                            remotePushAmount,
                            commitTxFeerate,
                            interactiveTxAction.sharedTx.buildUnsignedTx().hash,
                            interactiveTxAction.sharedOutputIndex,
                            remoteFirstPerCommitmentPoint
                        )
                        when (firstCommitTxRes) {
                            is Either.Left -> {
                                logger.error(firstCommitTxRes.value) { "c:$channelId cannot create first commit tx" }
                                handleLocalError(cmd, firstCommitTxRes.value)
                            }
                            is Either.Right -> {
                                val firstCommitTx = firstCommitTxRes.value
                                val localSigOfRemoteTx = keyManager.sign(firstCommitTx.remoteCommitTx, localParams.channelKeys.fundingPrivateKey)
                                val commitSig = CommitSig(channelId, localSigOfRemoteTx, listOf())
                                val nextState = WaitForFundingSigned(
                                    staticParams,
                                    currentTip,
                                    currentOnChainFeerates,
                                    localParams,
                                    remoteParams,
                                    wallet,
                                    interactiveTxSession1.fundingParams,
                                    localPushAmount,
                                    remotePushAmount,
                                    interactiveTxAction.sharedTx,
                                    firstCommitTx,
                                    remoteFirstPerCommitmentPoint,
                                    channelFlags,
                                    channelConfig,
                                    channelFeatures,
                                    channelOrigin
                                )
                                val actions = buildList {
                                    interactiveTxAction.txComplete?.let { add(ChannelAction.Message.Send(it)) }
                                    add(ChannelAction.Message.Send(commitSig))
                                }
                                Pair(nextState, actions)
                            }
                        }
                    }
                    is InteractiveTxSessionAction.RemoteFailure -> {
                        logger.warning { "c:$channelId interactive-tx failed: $interactiveTxAction" }
                        handleLocalError(cmd, DualFundingAborted(channelId, interactiveTxAction.toString()))
                    }
                }
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is CommitSig -> {
                logger.warning { "c:$channelId received commit_sig too early, aborting" }
                handleLocalError(cmd, UnexpectedCommitSig(channelId))
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is TxSignatures -> {
                logger.warning { "c:$channelId received tx_signatures too early, aborting" }
                handleLocalError(cmd, UnexpectedFundingSignatures(channelId))
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is TxInitRbf -> {
                logger.info { "c:$channelId ignoring unexpected tx_init_rbf message" }
                Pair(this, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfAttempt(channelId).message))))
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is TxAckRbf -> {
                logger.info { "c:$channelId ignoring unexpected tx_ack_rbf message" }
                Pair(this, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfAttempt(channelId).message))))
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is TxAbort -> {
                logger.warning { "c:$channelId our peer aborted the dual funding flow: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data.toHex()}" }
                Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            }
            cmd is ChannelCommand.MessageReceived && cmd.message is Error -> {
                logger.error { "c:$channelId peer sent error: ascii=${cmd.message.toAscii()} bin=${cmd.message.data.toHex()}" }
                Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            }
            cmd is ChannelCommand.ExecuteCommand && cmd.command is CloseCommand -> handleLocalError(cmd, ChannelFundingError(channelId))
            cmd is ChannelCommand.CheckHtlcTimeout -> Pair(this, listOf())
            cmd is ChannelCommand.NewBlock -> Pair(this.copy(currentTip = Pair(cmd.height, cmd.Header)), listOf())
            cmd is ChannelCommand.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = cmd.feerates), listOf())
            cmd is ChannelCommand.Disconnected -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            else -> unhandled(cmd)
        }
    }

    override fun handleLocalError(cmd: ChannelCommand, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$channelId error on event ${cmd::class} in state ${this::class}" }
        val error = Error(channelId, t.message)
        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
    }
}
