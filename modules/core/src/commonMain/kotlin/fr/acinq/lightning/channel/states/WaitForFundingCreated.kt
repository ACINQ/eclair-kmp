package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.wire.*
import kotlinx.coroutines.CompletableDeferred

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
data class WaitForFundingCreated(
    val replyTo: CompletableDeferred<ChannelFundingResponse>,
    val localParams: LocalParams,
    val remoteParams: RemoteParams,
    val interactiveTxSession: InteractiveTxSession,
    val commitTxFeerate: FeeratePerKw,
    val remoteFirstPerCommitmentPoint: PublicKey,
    val remoteSecondPerCommitmentPoint: PublicKey,
    val channelFlags: ChannelFlags,
    val channelConfig: ChannelConfig,
    val channelFeatures: ChannelFeatures,
    val liquidityPurchase: LiquidityAds.Purchase?,
    val channelOrigin: Origin?,
    val secondRemoteNonce: IndividualNonce?
) : ChannelState() {
    val channelId: ByteVector32 = interactiveTxSession.fundingParams.channelId

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.MessageReceived -> when (cmd.message) {
                is InteractiveTxConstructionMessage -> {
                    val (interactiveTxSession1, interactiveTxAction) = interactiveTxSession.receive(cmd.message)
                    when (interactiveTxAction) {
                        is InteractiveTxSessionAction.SendMessage -> Pair(this@WaitForFundingCreated.copy(interactiveTxSession = interactiveTxSession1), listOf(ChannelAction.Message.Send(interactiveTxAction.msg)))
                        is InteractiveTxSessionAction.SignSharedTx -> {
                            val channelParams = ChannelParams(channelId, channelConfig, channelFeatures, localParams, remoteParams, channelFlags)
                            val signingSession = InteractiveTxSigningSession.create(
                                interactiveTxSession1,
                                keyManager,
                                channelParams,
                                interactiveTxSession.fundingParams,
                                fundingTxIndex = 0,
                                interactiveTxAction.sharedTx,
                                liquidityPurchase,
                                localCommitmentIndex = 0,
                                remoteCommitmentIndex = 0,
                                commitTxFeerate,
                                remoteFirstPerCommitmentPoint,
                                emptySet()
                            )
                            when (signingSession) {
                                is Either.Left -> {
                                    logger.error(signingSession.value) { "cannot initiate interactive-tx signing session" }
                                    replyTo.complete(ChannelFundingResponse.Failure.CannotStartSession)
                                    handleLocalError(cmd, signingSession.value)
                                }
                                is Either.Right -> {
                                    val (session, commitSig) = signingSession.value
                                    // We cannot guarantee that the channel creation is successful: the only way to guarantee that is to wait for on-chain confirmations.
                                    // It is likely that we will restart before the transaction is confirmed, in which case we will lose the replyTo and the ability to notify the caller.
                                    // We should be able to resume the signing steps and complete the funding process if we disconnect, so we optimistically notify the caller now.
                                    replyTo.complete(
                                        ChannelFundingResponse.Success(
                                            channelId = channelId,
                                            fundingTxIndex = 0,
                                            fundingTxId = session.fundingTx.txId,
                                            capacity = session.fundingParams.fundingAmount,
                                            balance = session.localCommit.fold({ it.spec }, { it.spec }).toLocal,
                                            liquidityPurchase = liquidityPurchase,
                                        )
                                    )
                                    val nextState = WaitForFundingSigned(
                                        channelParams,
                                        session,
                                        remoteSecondPerCommitmentPoint,
                                        liquidityPurchase,
                                        channelOrigin,
                                        secondRemoteNonce
                                    )
                                    val actions = buildList {
                                        interactiveTxAction.txComplete?.let { add(ChannelAction.Message.Send(it)) }
                                        add(ChannelAction.Storage.StoreState(nextState))
                                        add(ChannelAction.Message.Send(commitSig))
                                    }
                                    Pair(nextState, actions)
                                }
                            }
                        }
                        is InteractiveTxSessionAction.RemoteFailure -> {
                            logger.warning { "interactive-tx failed: $interactiveTxAction" }
                            replyTo.complete(ChannelFundingResponse.Failure.InteractiveTxSessionFailed(interactiveTxAction))
                            handleLocalError(cmd, DualFundingAborted(channelId, interactiveTxAction.toString()))
                        }
                    }
                }
                is CommitSig -> {
                    logger.warning { "received commit_sig too early, aborting" }
                    replyTo.complete(ChannelFundingResponse.Failure.UnexpectedMessage(cmd.message))
                    handleLocalError(cmd, UnexpectedCommitSig(channelId))
                }
                is TxSignatures -> {
                    logger.warning { "received tx_signatures too early, aborting" }
                    replyTo.complete(ChannelFundingResponse.Failure.UnexpectedMessage(cmd.message))
                    handleLocalError(cmd, UnexpectedFundingSignatures(channelId))
                }
                is TxInitRbf -> {
                    logger.info { "ignoring unexpected tx_init_rbf message" }
                    replyTo.complete(ChannelFundingResponse.Failure.UnexpectedMessage(cmd.message))
                    Pair(this@WaitForFundingCreated, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfAttempt(channelId).message))))
                }
                is TxAckRbf -> {
                    logger.info { "ignoring unexpected tx_ack_rbf message" }
                    replyTo.complete(ChannelFundingResponse.Failure.UnexpectedMessage(cmd.message))
                    Pair(this@WaitForFundingCreated, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfAttempt(channelId).message))))
                }
                is TxAbort -> {
                    logger.warning { "our peer aborted the dual funding flow: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data.toHex()}" }
                    replyTo.complete(ChannelFundingResponse.Failure.AbortedByPeer(cmd.message.toAscii()))
                    Pair(Aborted, listOf(ChannelAction.Message.Send(TxAbort(channelId, DualFundingAborted(channelId, "requested by peer").message))))
                }
                is Error -> {
                    replyTo.complete(ChannelFundingResponse.Failure.AbortedByPeer(cmd.message.toAscii()))
                    handleRemoteError(cmd.message)
                }
                else -> unhandled(cmd)
            }
            is ChannelCommand.Close.MutualClose -> Pair(this@WaitForFundingCreated, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, CommandUnavailableInThisState(channelId, stateName))))
            is ChannelCommand.Close.ForceClose -> handleLocalError(cmd, ForcedLocalCommit(channelId))
            is ChannelCommand.Init -> unhandled(cmd)
            is ChannelCommand.Htlc -> unhandled(cmd)
            is ChannelCommand.Commitment -> unhandled(cmd)
            is ChannelCommand.WatchReceived -> unhandled(cmd)
            is ChannelCommand.Funding -> unhandled(cmd)
            is ChannelCommand.Closing -> unhandled(cmd)
            is ChannelCommand.Connected -> unhandled(cmd)
            is ChannelCommand.Disconnected -> {
                replyTo.complete(ChannelFundingResponse.Failure.Disconnected)
                Pair(Aborted, listOf())
            }
        }
    }
}
