package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_DEPTHOK
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.crypto.ShaChain
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.*
import kotlin.math.absoluteValue

/*
 * We exchange signatures for a new channel.
 * We have already sent our commit_sig.
 * If we send our tx_signatures first, the protocol flow is:
 *
 *       Local                        Remote
 *         |         commit_sig         |
 *         |<---------------------------|
 *         |        tx_signatures       |
 *         |--------------------------->|
 *
 * Otherwise, it is:
 *
 *       Local                        Remote
 *         |         commit_sig         |
 *         |<---------------------------|
 *         |        tx_signatures       |
 *         |<---------------------------|
 *         |        tx_signatures       |
 *         |--------------------------->|
 */
data class WaitForFundingSigned(
    val channelParams: ChannelParams,
    val signingSession: InteractiveTxSigningSession,
    val remoteSecondPerCommitmentPoint: PublicKey,
    val liquidityPurchase: LiquidityAds.Purchase?,
    val channelOrigin: Origin?,
) : PersistedChannelState() {
    override val channelId: ByteVector32 = channelParams.channelId

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.MessageReceived -> when (cmd.message) {
                is CommitSig -> {
                    val (signingSession1, action) = signingSession.receiveCommitSig(channelParams.localParams.channelKeys(keyManager), channelParams, cmd.message, currentBlockHeight.toLong(), logger)
                    when (action) {
                        is InteractiveTxSigningSessionAction.AbortFundingAttempt -> handleLocalError(cmd, action.reason)
                        // No need to store their commit_sig, they will re-send it if we disconnect.
                        InteractiveTxSigningSessionAction.WaitForTxSigs -> Pair(this@WaitForFundingSigned.copy(signingSession = signingSession1), listOf())
                        is InteractiveTxSigningSessionAction.SendTxSigs -> sendTxSigs(action)
                    }
                }
                is TxSignatures -> {
                    when (val res = signingSession.receiveTxSigs(channelParams.localParams.channelKeys(keyManager), cmd.message, currentBlockHeight.toLong())) {
                        is Either.Left -> {
                            val action: InteractiveTxSigningSessionAction.AbortFundingAttempt = res.value
                            handleLocalError(cmd, action.reason)
                        }
                        is Either.Right -> {
                            val action: InteractiveTxSigningSessionAction.SendTxSigs = res.value
                            sendTxSigs(action)
                        }
                    }
                }
                is TxInitRbf -> {
                    logger.info { "ignoring unexpected tx_init_rbf message" }
                    Pair(this@WaitForFundingSigned, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfAttempt(channelId).message))))
                }
                is TxAckRbf -> {
                    logger.info { "ignoring unexpected tx_ack_rbf message" }
                    Pair(this@WaitForFundingSigned, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfAttempt(channelId).message))))
                }
                is TxAbort -> {
                    logger.warning { "our peer aborted the dual funding flow: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data.toHex()}" }
                    Pair(Aborted, listOf(ChannelAction.Message.Send(TxAbort(channelId, DualFundingAborted(channelId, "requested by peer").message))))
                }
                is Error -> handleRemoteError(cmd.message)
                else -> unhandled(cmd)
            }
            is ChannelCommand.WatchReceived -> unhandled(cmd)
            is ChannelCommand.Close.MutualClose -> Pair(this@WaitForFundingSigned, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, CommandUnavailableInThisState(channelId, stateName))))
            is ChannelCommand.Close.ForceClose -> handleLocalError(cmd, ChannelFundingError(channelId))
            is ChannelCommand.Init -> unhandled(cmd)
            is ChannelCommand.Commitment -> unhandled(cmd)
            is ChannelCommand.Htlc -> unhandled(cmd)
            is ChannelCommand.Funding -> unhandled(cmd)
            is ChannelCommand.Closing -> unhandled(cmd)
            is ChannelCommand.Connected -> unhandled(cmd)
            // We should be able to complete the channel open when reconnecting.
            is ChannelCommand.Disconnected -> Pair(Offline(this@WaitForFundingSigned), listOf())
            is ChannelCommand.PeerBackupReceived -> unhandled(cmd)
        }
    }

    private fun ChannelContext.sendTxSigs(action: InteractiveTxSigningSessionAction.SendTxSigs): Pair<ChannelState, List<ChannelAction>> {
        logger.info { "funding tx created with txId=${action.fundingTx.txId}, ${action.fundingTx.sharedTx.tx.localInputs.size} local inputs, ${action.fundingTx.sharedTx.tx.remoteInputs.size} remote inputs, ${action.fundingTx.sharedTx.tx.localOutputs.size} local outputs and ${action.fundingTx.sharedTx.tx.remoteOutputs.size} remote outputs" }
        // We watch for confirmation in all cases, to allow pruning outdated commitments when transactions confirm.
        val fundingMinDepth = Helpers.minDepthForFunding(staticParams.nodeParams, action.fundingTx.fundingParams.fundingAmount)
        val watchConfirmed = WatchConfirmed(channelId, action.commitment.fundingTxId, action.commitment.commitInput.txOut.publicKeyScript, fundingMinDepth.toLong(), BITCOIN_FUNDING_DEPTHOK)
        val commitments = Commitments(
            channelParams,
            CommitmentChanges.init(),
            active = listOf(action.commitment),
            inactive = emptyList(),
            payments = mapOf(),
            remoteNextCommitInfo = Either.Right(remoteSecondPerCommitmentPoint),
            remotePerCommitmentSecrets = ShaChain.init,
        )
        val commonActions = buildList {
            action.fundingTx.signedTx?.let { add(ChannelAction.Blockchain.PublishTx(it, ChannelAction.Blockchain.PublishTx.Type.FundingTx)) }
            add(ChannelAction.Blockchain.SendWatch(watchConfirmed))
            add(ChannelAction.Message.Send(action.localSigs))
            // If we purchased liquidity as part of the channel creation, we will add it to our payments db.
            liquidityPurchase?.let { purchase ->
                if (channelParams.localParams.isChannelOpener) {
                    // We only count the mining fees that we must refund to our peer as part of the liquidity purchase.
                    // If we're also contributing to the funding transaction, the mining fees we pay for our inputs and
                    // outputs will be recorded in the ViaNewChannel incoming payment entry below.
                    add(ChannelAction.Storage.StoreOutgoingPayment.ViaInboundLiquidityRequest(txId = action.fundingTx.txId, localMiningFees = 0.sat, purchase = purchase))
                    add(ChannelAction.EmitEvent(LiquidityEvents.Purchased(purchase)))
                }
            }
            // If we receive funds as part of the channel creation, we will add it to our payments db.
            if (action.commitment.localCommit.spec.toLocal > 0.msat) add(
                ChannelAction.Storage.StoreIncomingPayment.ViaNewChannel(
                    amountReceived = action.commitment.localCommit.spec.toLocal,
                    serviceFee = 0.msat,
                    // We only count the mining fees we're paying for our inputs and outputs.
                    // The mining fees for the remote inputs and outputs are paid by the remote node.
                    miningFee = action.fundingTx.sharedTx.tx.localFees.truncateToSatoshi(),
                    localInputs = action.fundingTx.sharedTx.tx.localInputs.map { it.outPoint }.toSet(),
                    txId = action.fundingTx.txId,
                    origin = channelOrigin
                )
            )
            listOfNotNull(channelOrigin).filterIsInstance<Origin.OnChainWallet>().forEach { origin ->
                add(ChannelAction.EmitEvent(SwapInEvents.Accepted(origin.inputs, origin.amountBeforeFees.truncateToSatoshi(), origin.fees)))
            }
        }
        return if (staticParams.useZeroConf) {
            logger.info { "channel is using 0-conf, we won't wait for the funding tx to confirm" }
            val nextPerCommitmentPoint = channelParams.localParams.channelKeys(keyManager).commitmentPoint(1)
            val channelReady = ChannelReady(channelId, nextPerCommitmentPoint, TlvStream(ChannelReadyTlv.ShortChannelIdTlv(ShortChannelId.peerId(staticParams.nodeParams.nodeId))))
            // We use part of the funding txid to create a dummy short channel id.
            // This gives us a probability of collisions of 0.1% for 5 0-conf channels and 1% for 20
            // Collisions mean that users may temporarily see incorrect numbers for their 0-conf channels (until they've been confirmed).
            val shortChannelId = ShortChannelId(0, Pack.int32BE(action.commitment.fundingTxId.value.slice(0, 16).toByteArray()).absoluteValue, action.commitment.commitInput.outPoint.index.toInt())
            val nextState = WaitForChannelReady(commitments, shortChannelId, channelReady)
            val actions = buildList {
                add(ChannelAction.Storage.StoreState(nextState))
                add(ChannelAction.EmitEvent(ChannelEvents.Created(nextState)))
                addAll(commonActions) // NB: order matters
                add(ChannelAction.Message.Send(channelReady))
            }
            Pair(nextState, actions)
        } else {
            logger.info { "will wait for $fundingMinDepth confirmations" }
            val nextState = WaitForFundingConfirmed(
                commitments,
                currentBlockHeight.toLong(),
                null,
                RbfStatus.None
            )
            val actions = buildList {
                add(ChannelAction.Storage.StoreState(nextState))
                add(ChannelAction.EmitEvent(ChannelEvents.Created(nextState)))
                addAll(commonActions) // NB: order matters
            }
            Pair(nextState, actions)
        }
    }
}
