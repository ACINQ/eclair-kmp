package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.blockchain.WatchEventConfirmed
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.wire.*

data class ShuttingDown(
    override val commitments: Commitments,
    val localShutdown: Shutdown,
    val remoteShutdown: Shutdown,
    val closingFeerate: FeeratePerKw?
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.MessageReceived -> {
                when (cmd.message) {
                    is UpdateFulfillHtlc -> when (val result = commitments.receiveFulfill(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> {
                            val (commitments1, paymentId, add) = result.value
                            val htlcResult = ChannelAction.HtlcResult.Fulfill.RemoteFulfill(cmd.message)
                            Pair(this@ShuttingDown.copy(commitments = commitments1), listOf(ChannelAction.ProcessCmdRes.AddSettledFulfill(paymentId, add, htlcResult)))
                        }
                    }
                    is UpdateFailHtlc -> when (val result = commitments.receiveFail(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> Pair(this@ShuttingDown.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFailMalformedHtlc -> when (val result = commitments.receiveFailMalformed(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> Pair(this@ShuttingDown.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFee -> when (val result = commitments.receiveFee(cmd.message, staticParams.nodeParams.onChainFeeConf.feerateTolerance)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> Pair(this@ShuttingDown.copy(commitments = result.value), listOf())
                    }
                    is CommitSig -> when (val sigs = aggregateSigs(cmd.message)) {
                        is List<CommitSig> -> when (val result = commitments.receiveCommit(sigs, channelKeys(), logger)) {
                            is Either.Left -> handleLocalError(cmd, result.value)
                            is Either.Right -> {
                                val (commitments1, revocation) = result.value
                                when {
                                    commitments1.hasNoPendingHtlcsOrFeeUpdate() -> startClosingNegotiation(commitments1, listOf(ChannelAction.Message.Send(revocation)))
                                    else -> {
                                        val nextState = this@ShuttingDown.copy(commitments = commitments1)
                                        val actions = buildList {
                                            add(ChannelAction.Storage.StoreState(nextState))
                                            add(ChannelAction.Message.Send(revocation))
                                            if (commitments1.changes.localHasChanges()) {
                                                // if we have newly acknowledged changes let's sign them
                                                add(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign))
                                            }
                                        }
                                        Pair(nextState, actions)
                                    }
                                }
                            }
                        }
                        else -> Pair(this@ShuttingDown, listOf())
                    }
                    is RevokeAndAck -> when (val result = commitments.receiveRevocation(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> {
                            val (commitments1, actions) = result.value
                            when {
                                commitments1.hasNoPendingHtlcsOrFeeUpdate() -> startClosingNegotiation(commitments1, actions)
                                else -> {
                                    val nextState = this@ShuttingDown.copy(commitments = commitments1)
                                    val actions1 = buildList {
                                        addAll(actions)
                                        add(ChannelAction.Storage.StoreState(nextState))
                                        if (commitments1.changes.localHasChanges() && commitments1.remoteNextCommitInfo.isLeft) {
                                            add(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign))
                                        }
                                    }
                                    Pair(nextState, actions1)
                                }
                            }
                        }
                    }
                    is Shutdown -> {
                        if (cmd.message.scriptPubKey != remoteShutdown.scriptPubKey) {
                            logger.debug { "our peer updated their shutdown script (previous=${remoteShutdown.scriptPubKey}, current=${cmd.message.scriptPubKey})" }
                            val nextState = this@ShuttingDown.copy(remoteShutdown = cmd.message)
                            Pair(nextState, listOf(ChannelAction.Storage.StoreState(nextState)))
                        } else {
                            // This is a retransmission of their previous shutdown, we can ignore it.
                            Pair(this@ShuttingDown, listOf())
                        }
                    }
                    is Error -> {
                        handleRemoteError(cmd.message)
                    }
                    else -> unhandled(cmd)
                }
            }
            is ChannelCommand.Htlc.Add -> {
                logger.info { "rejecting htlc request in state=${this::class}" }
                // we don't provide a channel_update: this will be a permanent channel failure
                handleCommandError(cmd, ChannelUnavailable(channelId))
            }
            is ChannelCommand.Commitment.Sign -> {
                if (!commitments.changes.localHasChanges()) {
                    logger.debug { "ignoring ChannelCommand.Commitment.Sign (nothing to sign)" }
                    Pair(this@ShuttingDown, listOf())
                } else if (commitments.remoteNextCommitInfo.isLeft) {
                    logger.debug { "already in the process of signing, will sign again as soon as possible" }
                    Pair(this@ShuttingDown, listOf())
                } else {
                    when (val result = commitments.sendCommit(channelKeys(), logger)) {
                        is Either.Left -> handleCommandError(cmd, result.value)
                        is Either.Right -> {
                            val commitments1 = result.value.first
                            val nextRemoteSpec = commitments1.latest.nextRemoteCommit!!.commit.spec
                            // we persist htlc data in order to be able to claim htlc outputs in case a revoked tx is published by our
                            // counterparty, so only htlcs above remote's dust_limit matter
                            val trimmedHtlcs = Transactions.trimOfferedHtlcs(commitments.params.remoteParams.dustLimit, nextRemoteSpec) + Transactions.trimReceivedHtlcs(commitments.params.remoteParams.dustLimit, nextRemoteSpec)
                            val htlcInfos = trimmedHtlcs.map { it.add }.map {
                                logger.info { "adding paymentHash=${it.paymentHash} cltvExpiry=${it.cltvExpiry} to htlcs db for commitNumber=${commitments1.nextRemoteCommitIndex}" }
                                ChannelAction.Storage.HtlcInfo(channelId, commitments1.nextRemoteCommitIndex, it.paymentHash, it.cltvExpiry)
                            }
                            val nextState = this@ShuttingDown.copy(commitments = commitments1)
                            val actions = buildList {
                                add(ChannelAction.Storage.StoreHtlcInfos(htlcInfos))
                                add(ChannelAction.Storage.StoreState(nextState))
                                addAll(result.value.second.map { ChannelAction.Message.Send(it) })
                            }
                            Pair(nextState, actions)
                        }
                    }
                }
            }
            is ChannelCommand.Htlc.Settlement.Fulfill -> handleCommandResult(cmd, commitments.sendFulfill(cmd), cmd.commit)
            is ChannelCommand.Htlc.Settlement.Fail -> handleCommandResult(cmd, commitments.sendFail(cmd, staticParams.nodeParams.nodePrivateKey), cmd.commit)
            is ChannelCommand.Htlc.Settlement.FailMalformed -> handleCommandResult(cmd, commitments.sendFailMalformed(cmd), cmd.commit)
            is ChannelCommand.Commitment.UpdateFee -> handleCommandResult(cmd, commitments.sendFee(cmd), cmd.commit)
            is ChannelCommand.Close.MutualClose -> {
                // We may be updating our closing script or feerate.
                val localShutdown1 = cmd.scriptPubKey?.let { if (it != localShutdown.scriptPubKey) localShutdown.copy(scriptPubKey = it) else null }
                when (localShutdown1) {
                    null -> {
                        val nextState = this@ShuttingDown.copy(closingFeerate = cmd.feerate)
                        Pair(nextState, listOf(ChannelAction.Storage.StoreState(nextState)))
                    }
                    else -> {
                        val nextState = this@ShuttingDown.copy(closingFeerate = cmd.feerate, localShutdown = localShutdown1)
                        val actions = listOf(
                            ChannelAction.Storage.StoreState(nextState),
                            ChannelAction.Message.Send(localShutdown1),
                        )
                        Pair(nextState, actions)
                    }
                }
            }
            is ChannelCommand.Close.ForceClose -> handleLocalError(cmd, ForcedLocalCommit(channelId))
            is ChannelCommand.WatchReceived -> when (val watch = cmd.watch) {
                is WatchEventConfirmed -> updateFundingTxStatus(watch)
                is WatchEventSpent -> handlePotentialForceClose(watch)
            }
            is ChannelCommand.Commitment.CheckHtlcTimeout -> checkHtlcTimeout()
            is ChannelCommand.Disconnected -> {
                // reset the commit_sig batch
                sigStash = emptyList()
                Pair(Offline(this@ShuttingDown), listOf())
            }
            else -> unhandled(cmd)
        }
    }

    private fun ChannelContext.startClosingNegotiation(commitments: Commitments, actions: List<ChannelAction>): Pair<ChannelState, List<ChannelAction>> {
        val localScript = localShutdown.scriptPubKey
        val remoteScript = remoteShutdown.scriptPubKey
        val currentHeight = currentBlockHeight.toLong()
        return when (closingFeerate) {
            null -> {
                logger.info { "mutual close was initiated by our peer, waiting for remote closing_complete" }
                val nextState = Negotiating(commitments, closingFeerate, localScript, remoteScript, listOf(), listOf(), currentHeight)
                val actions1 = listOf(ChannelAction.Storage.StoreState(nextState))
                Pair(nextState, actions + actions1)
            }
            else -> {
                when (val closingResult = Helpers.Closing.makeClosingTxs(channelKeys(), commitments.latest, localScript, remoteScript, closingFeerate, currentHeight)) {
                    is Either.Left -> {
                        logger.warning { "cannot create local closing txs, waiting for remote closing_complete: ${closingResult.value.message}" }
                        val nextState = Negotiating(commitments, closingFeerate, localScript, remoteScript, listOf(), listOf(), currentHeight)
                        val actions1 = listOf(ChannelAction.Storage.StoreState(nextState))
                        Pair(nextState, actions + actions1)
                    }
                    is Either.Right -> {
                        val (closingTxs, closingComplete) = closingResult.value
                        val nextState = Negotiating(commitments, closingFeerate, localScript, remoteScript, listOf(closingTxs), listOf(), currentHeight)
                        val actions1 = listOf(
                            ChannelAction.Storage.StoreState(nextState),
                            ChannelAction.Message.Send(closingComplete),
                        )
                        Pair(nextState, actions + actions1)
                    }
                }
            }
        }
    }

    private fun ChannelContext.handleCommandResult(command: ChannelCommand, result: Either<ChannelException, Pair<Commitments, LightningMessage>>, commit: Boolean): Pair<ChannelState, List<ChannelAction>> {
        return when (result) {
            is Either.Left -> handleCommandError(command, result.value)
            is Either.Right -> {
                val (commitments1, message) = result.value
                val actions = mutableListOf<ChannelAction>(ChannelAction.Message.Send(message))
                if (commit) {
                    actions.add(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign))
                }
                Pair(this@ShuttingDown.copy(commitments = commitments1), actions)
            }
        }
    }
}
