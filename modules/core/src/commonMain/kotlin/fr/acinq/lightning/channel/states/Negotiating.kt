package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.ClosingTx
import fr.acinq.lightning.wire.*

data class Negotiating(
    override val commitments: Commitments,
    val lastClosingFeerate: FeeratePerKw?,
    val localScript: ByteVector,
    val remoteScript: ByteVector,
    // Closing transactions we created, where we pay the fees (unsigned).
    val proposedClosingTxs: List<Transactions.ClosingTxs>,
    // Closing transactions we published: this contains our local transactions for
    // which they sent a signature, and their closing transactions that we signed.
    val publishedClosingTxs: List<ClosingTx>,
    val waitingSinceBlock: Long, // how many blocks since we initiated the closing
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.MessageReceived -> when (cmd.message) {
                is Shutdown -> {
                    if (cmd.message.scriptPubKey != remoteScript) {
                        // This may lead to a signature mismatch: peers must use closing_complete to update their closing script.
                        logger.warning { "received shutdown changing remote script, this may lead to a signature mismatch (previous=$remoteScript, current=${cmd.message.scriptPubKey})" }
                        val nextState = this@Negotiating.copy(remoteScript = cmd.message.scriptPubKey)
                        Pair(nextState, listOf(ChannelAction.Storage.StoreState(nextState)))
                    } else {
                        // This is a retransmission of their previous shutdown, we can ignore it.
                        Pair(this@Negotiating, listOf())
                    }
                }
                is ClosingComplete -> {
                    // Note that if there is a failure here and we don't send our closing_sig, they may eventually disconnect.
                    // On reconnection, we will retransmit shutdown with our latest scripts, so future signing attempts should work.
                    if (cmd.message.closeeScriptPubKey != localScript) {
                        logger.warning { "their closing_complete is not using our latest script: this may happen if we changed our script while they were sending closing_complete" }
                        // No need to persist their latest script, they will re-send it on reconnection.
                        val nextState = this@Negotiating.copy(remoteScript = cmd.message.closerScriptPubKey)
                        Pair(nextState, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidCloseeScript(channelId, cmd.message.closeeScriptPubKey, localScript).message))))
                    } else {
                        when (val result = Helpers.Closing.signClosingTx(channelKeys(), commitments.latest, cmd.message.closeeScriptPubKey, cmd.message.closerScriptPubKey, cmd.message)) {
                            is Either.Left -> {
                                logger.warning { "invalid closing_complete: ${result.value.message}" }
                                Pair(this@Negotiating, listOf(ChannelAction.Message.Send(Warning(channelId, result.value.message))))
                            }
                            is Either.Right -> {
                                val (signedClosingTx, closingSig) = result.value
                                logger.debug { "signing remote mutual close transaction: ${signedClosingTx.tx}" }
                                val nextState = this@Negotiating.copy(remoteScript = cmd.message.closerScriptPubKey, publishedClosingTxs = publishedClosingTxs + signedClosingTx)
                                val actions = listOf(
                                    ChannelAction.Storage.StoreState(nextState),
                                    ChannelAction.Blockchain.PublishTx(signedClosingTx),
                                    ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, signedClosingTx.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(signedClosingTx.tx))),
                                    ChannelAction.Message.Send(closingSig)
                                )
                                Pair(nextState, actions)
                            }
                        }
                    }
                }
                is ClosingSig -> {
                    when (val result = Helpers.Closing.receiveClosingSig(channelKeys(), commitments.latest, proposedClosingTxs.last(), cmd.message)) {
                        is Either.Left -> {
                            logger.warning { "invalid closing_sig: ${result.value.message}" }
                            Pair(this@Negotiating, listOf(ChannelAction.Message.Send(Warning(channelId, result.value.message))))
                        }
                        is Either.Right -> {
                            val signedClosingTx = result.value
                            logger.debug { "received signatures for local mutual close transaction: ${signedClosingTx.tx}" }
                            val nextState = this@Negotiating.copy(publishedClosingTxs = publishedClosingTxs + signedClosingTx)
                            val actions = listOf(
                                ChannelAction.Storage.StoreState(nextState),
                                ChannelAction.Blockchain.PublishTx(signedClosingTx),
                                ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, signedClosingTx.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(signedClosingTx.tx))),
                            )
                            Pair(nextState, actions)
                        }
                    }
                }
                is Error -> handleRemoteError(cmd.message)
                else -> unhandled(cmd)
            }
            is ChannelCommand.WatchReceived -> when (val watch = cmd.watch) {
                is WatchEventConfirmed -> when {
                    // One of our published transactions confirmed, the channel is now closed.
                    publishedClosingTxs.any { it.tx.txid == watch.tx.txid } -> completeMutualClose(publishedClosingTxs.first { it.tx.txid == watch.tx.txid })
                    // A transaction that we proposed for which they didn't send us their signature was confirmed, the channel is now closed.
                    proposedClosingTxs.flatMap { it.all }.any { it.tx.txid == watch.tx.txid } -> completeMutualClose(getMutualClosePublished(watch.tx))
                    // Otherwise, this must be a funding transaction that just got confirmed.
                    else -> updateFundingTxStatus(watch)
                }
                is WatchEventSpent -> when {
                    watch.event is BITCOIN_FUNDING_SPENT && publishedClosingTxs.any { it.tx.txid == watch.tx.txid } -> {
                        // This is one of the transactions we already published, we have nothing to do.
                        Pair(this@Negotiating, listOf())
                    }
                    watch.event is BITCOIN_FUNDING_SPENT && proposedClosingTxs.flatMap { it.all }.any { it.tx.txid == watch.tx.txid } -> {
                        // They published one of our closing transactions without sending us their signature.
                        val closingTx = getMutualClosePublished(watch.tx)
                        val nextState = this@Negotiating.copy(publishedClosingTxs = publishedClosingTxs + closingTx)
                        val actions = listOf(
                            ChannelAction.Storage.StoreState(nextState),
                            ChannelAction.Blockchain.PublishTx(closingTx),
                            ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, watch.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(watch.tx)))
                        )
                        Pair(nextState, actions)
                    }
                    else -> handlePotentialForceClose(watch)
                }
            }
            is ChannelCommand.Commitment.CheckHtlcTimeout -> checkHtlcTimeout()
            is ChannelCommand.Commitment -> unhandled(cmd)
            is ChannelCommand.Htlc.Add -> handleCommandError(cmd, ChannelUnavailable(channelId))
            is ChannelCommand.Htlc -> unhandled(cmd)
            is ChannelCommand.Close.ForceClose -> handleLocalError(cmd, ForcedLocalCommit(channelId))
            is ChannelCommand.Close.MutualClose -> {
                if (lastClosingFeerate?.let { cmd.feerate < it } == true) {
                    handleCommandError(cmd, InvalidRbfFeerate(channelId, cmd.feerate, lastClosingFeerate * 1.2))
                } else {
                    when (val result = Helpers.Closing.makeClosingTxs(channelKeys(), commitments.latest, cmd.scriptPubKey ?: localScript, remoteScript, cmd.feerate, currentBlockHeight.toLong())) {
                        is Either.Left -> handleCommandError(cmd, result.value)
                        is Either.Right -> {
                            val (closingTxs, closingComplete) = result.value
                            logger.debug { "signing local mutual close transactions: $closingTxs" }
                            val nextState = this@Negotiating.copy(localScript = closingComplete.closerScriptPubKey, lastClosingFeerate = cmd.feerate, proposedClosingTxs = proposedClosingTxs + closingTxs)
                            val actions = buildList {
                                add(ChannelAction.Storage.StoreState(nextState))
                                add(ChannelAction.Message.Send(closingComplete))
                            }
                            Pair(nextState, actions)
                        }
                    }
                }
            }
            is ChannelCommand.Init -> unhandled(cmd)
            is ChannelCommand.Funding -> unhandled(cmd)
            is ChannelCommand.Closing -> unhandled(cmd)
            is ChannelCommand.Connected -> unhandled(cmd)
            is ChannelCommand.Disconnected -> Pair(Offline(this@Negotiating), listOf())
        }
    }

    /** Return full information about a closing tx that we proposed and they then published. */
    internal fun getMutualClosePublished(tx: Transaction): ClosingTx {
        // They can publish a closing tx with any sig we sent them, even if we are not done negotiating.
        // They added their signature, so we use their version of the transaction.
        return proposedClosingTxs.flatMap { it.all }.first { it.tx.txid == tx.txid }.copy(tx = tx)
    }

    internal fun ChannelContext.completeMutualClose(signedClosingTx: ClosingTx): Pair<ChannelState, List<ChannelAction>> {
        logger.info { "channel was closed with txId=${signedClosingTx.tx.txid}" }
        val nextState = Closed(
            Closing(
                commitments,
                waitingSinceBlock = waitingSinceBlock,
                mutualCloseProposed = proposedClosingTxs.flatMap { it.all },
                mutualClosePublished = listOf(signedClosingTx)
            )
        )
        val actions = buildList {
            add(ChannelAction.Storage.StoreState(nextState))
            addAll(emitClosingEvents(this@Negotiating, nextState.state))
            add(ChannelAction.Storage.SetLocked(signedClosingTx.tx.txid))
        }
        return Pair(nextState, actions)
    }
}
