package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.ChannelEvents
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.Helpers.Funding.computeChannelId
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.*

/*
 * We initiated a channel open and are waiting for our peer to accept it.
 *
 *       Local                        Remote
 *         |      accept_channel2       |
 *         |<---------------------------|
 *         |       tx_add_input         |
 *         |--------------------------->|
 */
data class WaitForAcceptChannel(
    val init: ChannelCommand.Init.Initiator,
    val lastSent: OpenDualFundedChannel,
    val channelOrigin: Origin?,
) : ChannelState() {
    val temporaryChannelId: ByteVector32 get() = lastSent.temporaryChannelId

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.MessageReceived -> when (cmd.message) {
                is AcceptDualFundedChannel -> {
                    val accept = cmd.message
                    when (val res = Helpers.validateParamsInitiator(staticParams.nodeParams, init, lastSent, accept)) {
                        is Either.Right -> {
                            val channelType = res.value
                            val channelFeatures = ChannelFeatures(channelType, localFeatures = init.localParams.features, remoteFeatures = init.remoteInit.features)
                            val remoteParams = RemoteParams(
                                nodeId = staticParams.remoteNodeId,
                                dustLimit = accept.dustLimit,
                                maxHtlcValueInFlightMsat = accept.maxHtlcValueInFlightMsat,
                                htlcMinimum = accept.htlcMinimum,
                                toSelfDelay = accept.toSelfDelay,
                                maxAcceptedHtlcs = accept.maxAcceptedHtlcs,
                                revocationBasepoint = accept.revocationBasepoint,
                                paymentBasepoint = accept.paymentBasepoint,
                                delayedPaymentBasepoint = accept.delayedPaymentBasepoint,
                                htlcBasepoint = accept.htlcBasepoint,
                                features = init.remoteInit.features
                            )
                            val channelId = computeChannelId(lastSent, accept)
                            val channelKeys = keyManager.channelKeys(init.localParams.fundingKeyPath)
                            val remoteFundingPubkey = accept.fundingPubkey
                            val dustLimit = accept.dustLimit.max(init.localParams.dustLimit)
                            val fundingParams = InteractiveTxParams(channelId, true, init.fundingAmount, accept.fundingAmount, remoteFundingPubkey, lastSent.lockTime, dustLimit, lastSent.fundingFeerate)
                            when (val liquidityPurchase = LiquidityAds.validateRemoteFunding(
                                lastSent.requestFunding,
                                staticParams.remoteNodeId,
                                channelId,
                                fundingParams.fundingPubkeyScript(channelKeys),
                                accept.fundingAmount,
                                lastSent.fundingFeerate,
                                isChannelCreation = true,
                                accept.feeCreditUsed,
                                accept.willFund
                            )) {
                                is Either.Left -> {
                                    logger.error { "rejecting liquidity proposal: ${liquidityPurchase.value.message}" }
                                    init.replyTo.complete(ChannelFundingResponse.Failure.InvalidLiquidityAds(liquidityPurchase.value))
                                    Pair(Aborted, listOf(ChannelAction.Message.Send(Error(cmd.message.temporaryChannelId, liquidityPurchase.value.message))))
                                }
                                is Either.Right -> when (val fundingContributions = FundingContributions.create(
                                    channelKeys,
                                    keyManager.swapInOnChainWallet,
                                    fundingParams,
                                    init.walletInputs,
                                    liquidityPurchase.value
                                )) {
                                    is Either.Left -> {
                                        logger.error { "could not fund channel: ${fundingContributions.value}" }
                                        init.replyTo.complete(ChannelFundingResponse.Failure.FundingFailure(fundingContributions.value))
                                        Pair(Aborted, listOf(ChannelAction.Message.Send(Error(channelId, ChannelFundingError(channelId).message))))
                                    }
                                    is Either.Right -> {
                                        // The channel initiator always sends the first interactive-tx message.
                                        val (interactiveTxSession, interactiveTxAction) = InteractiveTxSession(
                                            staticParams.remoteNodeId,
                                            channelKeys,
                                            keyManager.swapInOnChainWallet,
                                            fundingParams,
                                            0.msat,
                                            0.msat,
                                            emptySet(),
                                            fundingContributions.value
                                        ).send()
                                        when (interactiveTxAction) {
                                            is InteractiveTxSessionAction.SendMessage -> {
                                                val nextState = WaitForFundingCreated(
                                                    init.replyTo,
                                                    init.localParams,
                                                    remoteParams,
                                                    interactiveTxSession,
                                                    lastSent.commitmentFeerate,
                                                    accept.firstPerCommitmentPoint,
                                                    accept.secondPerCommitmentPoint,
                                                    lastSent.channelFlags,
                                                    init.channelConfig,
                                                    channelFeatures,
                                                    liquidityPurchase.value,
                                                    channelOrigin
                                                )
                                                val actions = listOf(
                                                    ChannelAction.ChannelId.IdAssigned(staticParams.remoteNodeId, temporaryChannelId, channelId),
                                                    ChannelAction.Message.Send(interactiveTxAction.msg),
                                                    ChannelAction.EmitEvent(ChannelEvents.Creating(nextState))
                                                )
                                                Pair(nextState, actions)
                                            }
                                            else -> {
                                                logger.error { "could not start interactive-tx session: $interactiveTxAction" }
                                                init.replyTo.complete(ChannelFundingResponse.Failure.CannotStartSession)
                                                Pair(Aborted, listOf(ChannelAction.Message.Send(Error(channelId, ChannelFundingError(channelId).message))))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        is Either.Left -> {
                            logger.error(res.value) { "invalid ${cmd.message::class} in state ${this::class}" }
                            init.replyTo.complete(ChannelFundingResponse.Failure.InvalidChannelParameters(res.value))
                            return Pair(Aborted, listOf(ChannelAction.Message.Send(Error(init.temporaryChannelId(keyManager), res.value.message))))
                        }
                    }
                }
                is CancelOnTheFlyFunding -> {
                    // Our peer won't accept this on-the-fly funding attempt: they probably already failed the corresponding HTLCs.
                    logger.warning { "on-the-fly funding was rejected by our peer: ${cmd.message.toAscii()}" }
                    init.replyTo.complete(ChannelFundingResponse.Failure.AbortedByPeer(cmd.message.toAscii()))
                    Pair(Aborted, listOf())
                }
                is Error -> {
                    init.replyTo.complete(ChannelFundingResponse.Failure.AbortedByPeer(cmd.message.toAscii()))
                    handleRemoteError(cmd.message)
                }
                else -> unhandled(cmd)
            }
            is ChannelCommand.Close.MutualClose -> Pair(this@WaitForAcceptChannel, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, CommandUnavailableInThisState(temporaryChannelId, stateName))))
            is ChannelCommand.Close.ForceClose -> handleLocalError(cmd, ForcedLocalCommit(temporaryChannelId))
            is ChannelCommand.Connected -> unhandled(cmd)
            is ChannelCommand.Disconnected -> {
                init.replyTo.complete(ChannelFundingResponse.Failure.Disconnected)
                Pair(Aborted, listOf())
            }
            is ChannelCommand.Init -> unhandled(cmd)
            is ChannelCommand.Commitment -> unhandled(cmd)
            is ChannelCommand.Htlc -> unhandled(cmd)
            is ChannelCommand.WatchReceived -> unhandled(cmd)
            is ChannelCommand.Funding -> unhandled(cmd)
            is ChannelCommand.Closing -> unhandled(cmd)
            is ChannelCommand.PeerBackupReceived -> unhandled(cmd)
        }
    }
}
