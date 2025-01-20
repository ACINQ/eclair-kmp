package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.ChannelEvents
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.WatchEventConfirmed
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.router.Announcements
import fr.acinq.lightning.utils.toMilliSatoshi
import fr.acinq.lightning.wire.*

/** The channel funding transaction was confirmed, we exchange funding_locked messages. */
data class WaitForChannelReady(
    override val commitments: Commitments,
    val shortChannelId: ShortChannelId,
    val lastSent: ChannelReady
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.MessageReceived -> when (cmd.message) {
                is TxSignatures -> when (commitments.latest.localFundingStatus) {
                    is LocalFundingStatus.UnconfirmedFundingTx -> when (commitments.latest.localFundingStatus.sharedTx) {
                        is PartiallySignedSharedTransaction -> when (val fullySignedTx = commitments.latest.localFundingStatus.sharedTx.addRemoteSigs(channelKeys(), commitments.latest.localFundingStatus.fundingParams, cmd.message)) {
                            null -> {
                                logger.warning { "received invalid remote funding signatures for txId=${cmd.message.txId}" }
                                // The funding transaction may still confirm (since our peer should be able to generate valid signatures), so we cannot close the channel yet.
                                Pair(this@WaitForChannelReady, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidFundingSignature(channelId, cmd.message.txId).message))))
                            }
                            else -> {
                                when (val res = commitments.run { updateLocalFundingSigned(fullySignedTx) }) {
                                    is Either.Left -> Pair(this@WaitForChannelReady, listOf())
                                    is Either.Right -> {
                                        logger.info { "received remote funding signatures, publishing txId=${fullySignedTx.signedTx.txid}" }
                                        val nextState = this@WaitForChannelReady.copy(commitments = res.value.first)
                                        val actions = buildList {
                                            add(ChannelAction.Blockchain.PublishTx(fullySignedTx.signedTx, ChannelAction.Blockchain.PublishTx.Type.FundingTx))
                                            add(ChannelAction.Storage.StoreState(nextState))
                                        }
                                        Pair(nextState, actions)
                                    }
                                }
                            }
                        }
                        is FullySignedSharedTransaction -> {
                            logger.info { "ignoring duplicate remote funding signatures" }
                            Pair(this@WaitForChannelReady, listOf())
                        }
                    }
                    is LocalFundingStatus.ConfirmedFundingTx -> {
                        logger.info { "ignoring funding signatures for txId=${cmd.message.txId}, transaction is already confirmed" }
                        Pair(this@WaitForChannelReady, listOf())
                    }
                }
                is TxInitRbf -> {
                    logger.info { "rejecting tx_init_rbf, we have already accepted the channel" }
                    Pair(this@WaitForChannelReady, listOf(ChannelAction.Message.Send(TxAbort(channelId, InvalidRbfTxConfirmed(channelId, commitments.latest.fundingTxId).message))))
                }
                is ChannelReady -> {
                    if (commitments.isTaprootChannel) {
                        require(cmd.message.nextLocalNonce != null) { "missing next local nonce" }
                    }
                    // we create a channel_update early so that we can use it to send payments through this channel, but it won't be propagated to other nodes since the channel is not yet announced
                    val initialChannelUpdate = Announcements.makeChannelUpdate(
                        staticParams.nodeParams.chainHash,
                        staticParams.nodeParams.nodePrivateKey,
                        staticParams.remoteNodeId,
                        shortChannelId,
                        staticParams.nodeParams.expiryDeltaBlocks,
                        commitments.params.remoteParams.htlcMinimum,
                        staticParams.nodeParams.feeBase,
                        staticParams.nodeParams.feeProportionalMillionths.toLong(),
                        commitments.latest.fundingAmount.toMilliSatoshi(),
                        enable = Helpers.aboveReserve(commitments)
                    )
                    val nextState = Normal(
                        commitments.copy(nextRemoteNonces = cmd.message.nextLocalNonce?.let { listOf(it) } ?: listOf()),
                        shortChannelId,
                        initialChannelUpdate,
                        null,
                        null,
                        null,
                        null,
                        SpliceStatus.None,
                    )
                    val actions = listOf(
                        ChannelAction.Storage.StoreState(nextState),
                        ChannelAction.Storage.SetLocked(commitments.latest.fundingTxId),
                        ChannelAction.EmitEvent(ChannelEvents.Confirmed(nextState)),
                    )
                    Pair(nextState, actions)
                }
                is Error -> handleRemoteError(cmd.message)
                else -> unhandled(cmd)
            }
            is ChannelCommand.WatchReceived -> when (cmd.watch) {
                is WatchEventConfirmed -> updateFundingTxStatus(cmd.watch)
                is WatchEventSpent -> handlePotentialForceClose(cmd.watch)
            }
            is ChannelCommand.Close.MutualClose -> Pair(this@WaitForChannelReady, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, CommandUnavailableInThisState(channelId, stateName))))
            is ChannelCommand.Close.ForceClose -> handleLocalError(cmd, ForcedLocalCommit(channelId))
            is ChannelCommand.Commitment.CheckHtlcTimeout -> Pair(this@WaitForChannelReady, listOf())
            is ChannelCommand.Commitment -> unhandled(cmd)
            is ChannelCommand.Htlc -> unhandled(cmd)
            is ChannelCommand.Init -> unhandled(cmd)
            is ChannelCommand.Funding -> unhandled(cmd)
            is ChannelCommand.Closing -> unhandled(cmd)
            is ChannelCommand.Connected -> unhandled(cmd)
            is ChannelCommand.Disconnected -> Pair(Offline(this@WaitForChannelReady), listOf())
        }
    }
}
