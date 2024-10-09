package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.updated
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.states.Channel.MAX_NEGOTIATION_ITERATIONS
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.ClosingTx
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.ClosingSigned
import fr.acinq.lightning.wire.ClosingSignedTlv
import fr.acinq.lightning.wire.Error
import fr.acinq.lightning.wire.Shutdown

data class Negotiating(
    override val commitments: Commitments,
    val localShutdown: Shutdown,
    val remoteShutdown: Shutdown,
    val closingTxProposed: List<List<ClosingTxProposed>>, // one list for every negotiation (there can be several in case of disconnection)
    val bestUnpublishedClosingTx: ClosingTx?,
    val closingFeerates: ClosingFeerates?
) : ChannelStateWithCommitments() {
    init {
        require(closingTxProposed.isNotEmpty()) { "there must always be a list for the current negotiation" }
        require(!paysClosingFees || !closingTxProposed.any { it.isEmpty() }) { "the node paying the closing fees must have at least one closing signature for every negotiation attempt because it initiates the closing" }
    }

    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.MessageReceived -> when (cmd.message) {
                is ClosingSigned -> {
                    val remoteClosingFee = cmd.message.feeSatoshis
                    logger.info { "received closing fee=$remoteClosingFee" }
                    when (val result =
                        Helpers.Closing.checkClosingSignature(channelKeys(), commitments.latest, localShutdown.scriptPubKey.toByteArray(), remoteShutdown.scriptPubKey.toByteArray(), cmd.message.feeSatoshis, cmd.message.signature)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> {
                            val (signedClosingTx, closingSignedRemoteFees) = result.value
                            val lastLocalClosingSigned = closingTxProposed.last().lastOrNull()?.localClosingSigned
                            when {
                                lastLocalClosingSigned?.feeSatoshis == remoteClosingFee -> {
                                    logger.info { "they accepted our fee, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                    completeMutualClose(signedClosingTx, null)
                                }
                                closingTxProposed.flatten().size >= MAX_NEGOTIATION_ITERATIONS -> {
                                    logger.warning { "could not agree on closing fees after $MAX_NEGOTIATION_ITERATIONS iterations, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                    completeMutualClose(signedClosingTx, closingSignedRemoteFees)
                                }
                                lastLocalClosingSigned?.tlvStream?.get<ClosingSignedTlv.FeeRange>()?.let { it.min <= remoteClosingFee && remoteClosingFee <= it.max } == true -> {
                                    val localFeeRange = lastLocalClosingSigned.tlvStream.get<ClosingSignedTlv.FeeRange>()!!
                                    logger.info { "they chose closing fee=$remoteClosingFee within our fee range (min=${localFeeRange.max} max=${localFeeRange.max}), publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                    completeMutualClose(signedClosingTx, closingSignedRemoteFees)
                                }
                                commitments.latest.localCommit.spec.toLocal == 0.msat -> {
                                    logger.info { "we have nothing at stake, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                    completeMutualClose(signedClosingTx, closingSignedRemoteFees)
                                }
                                else -> {
                                    val theirFeeRange = cmd.message.tlvStream.get<ClosingSignedTlv.FeeRange>()
                                    val ourFeeRange = closingFeerates ?: ClosingFeerates(currentOnChainFeerates().mutualCloseFeerate)
                                    when {
                                        theirFeeRange != null && !paysClosingFees -> {
                                            // if we are not paying the on-chain fees and they proposed a fee range, we pick a value in that range and they should accept it without further negotiation
                                            // we don't care much about the closing fee since they're paying it (not us) and we can use CPFP if we want to speed up confirmation
                                            val closingFees = Helpers.Closing.firstClosingFee(commitments.latest, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, ourFeeRange)
                                            val closingFee = when {
                                                closingFees.preferred > theirFeeRange.max -> theirFeeRange.max
                                                // if we underestimate the fee, then we're happy with whatever they propose (it will confirm more quickly and we're not paying it)
                                                closingFees.preferred < remoteClosingFee -> remoteClosingFee
                                                else -> closingFees.preferred
                                            }
                                            if (closingFee == remoteClosingFee) {
                                                logger.info { "accepting their closing fee=$remoteClosingFee, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                                completeMutualClose(signedClosingTx, closingSignedRemoteFees)
                                            } else {
                                                val (closingTx, closingSigned) = Helpers.Closing.makeClosingTx(
                                                    channelKeys(),
                                                    commitments.latest,
                                                    localShutdown.scriptPubKey.toByteArray(),
                                                    remoteShutdown.scriptPubKey.toByteArray(),
                                                    ClosingFees(closingFee, theirFeeRange.min, theirFeeRange.max)
                                                )
                                                logger.info { "proposing closing fee=${closingSigned.feeSatoshis}" }
                                                val closingProposed1 = closingTxProposed.updated(
                                                    closingTxProposed.lastIndex,
                                                    closingTxProposed.last() + listOf(ClosingTxProposed(closingTx, closingSigned))
                                                )
                                                val nextState = this@Negotiating.copy(
                                                    closingTxProposed = closingProposed1,
                                                    bestUnpublishedClosingTx = signedClosingTx
                                                )
                                                val actions = listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Message.Send(closingSigned))
                                                Pair(nextState, actions)
                                            }
                                        }
                                        else -> {
                                            val (closingTx, closingSigned) = run {
                                                // if we are not the initiator and we were waiting for them to send their first closing_signed, we compute our firstClosingFee, otherwise we use the last one we sent
                                                val localClosingFees = Helpers.Closing.firstClosingFee(commitments.latest, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, ourFeeRange)
                                                val nextPreferredFee = Helpers.Closing.nextClosingFee(lastLocalClosingSigned?.feeSatoshis ?: localClosingFees.preferred, remoteClosingFee)
                                                Helpers.Closing.makeClosingTx(
                                                    channelKeys(),
                                                    commitments.latest,
                                                    localShutdown.scriptPubKey.toByteArray(),
                                                    remoteShutdown.scriptPubKey.toByteArray(),
                                                    localClosingFees.copy(preferred = nextPreferredFee)
                                                )
                                            }
                                            when {
                                                lastLocalClosingSigned?.feeSatoshis == closingSigned.feeSatoshis -> {
                                                    // next computed fee is the same than the one we previously sent (probably because of rounding)
                                                    logger.info { "accepting their closing fee=$remoteClosingFee, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                                    completeMutualClose(signedClosingTx, null)
                                                }
                                                closingSigned.feeSatoshis == remoteClosingFee -> {
                                                    logger.info { "we have converged, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                                    completeMutualClose(signedClosingTx, closingSigned)
                                                }
                                                else -> {
                                                    logger.info { "proposing closing fee=${closingSigned.feeSatoshis}" }
                                                    val closingProposed1 = closingTxProposed.updated(
                                                        closingTxProposed.lastIndex,
                                                        closingTxProposed.last() + listOf(ClosingTxProposed(closingTx, closingSigned))
                                                    )
                                                    val nextState = this@Negotiating.copy(
                                                        closingTxProposed = closingProposed1,
                                                        bestUnpublishedClosingTx = signedClosingTx
                                                    )
                                                    val actions = listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Message.Send(closingSigned))
                                                    Pair(nextState, actions)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                is Error -> handleRemoteError(cmd.message)
                else -> unhandled(cmd)
            }
            is ChannelCommand.WatchReceived -> when (val watch = cmd.watch) {
                is WatchEventConfirmed -> updateFundingTxStatus(watch)
                is WatchEventSpent -> when {
                    watch.event is BITCOIN_FUNDING_SPENT && closingTxProposed.flatten().any { it.unsignedTx.tx.txid == watch.tx.txid } -> {
                        // they can publish a closing tx with any sig we sent them, even if we are not done negotiating
                        logger.info { "closing tx published: closingTxId=${watch.tx.txid}" }
                        val closingTx = getMutualClosePublished(watch.tx)
                        val nextState = Closing(
                            commitments,
                            waitingSinceBlock = currentBlockHeight.toLong(),
                            mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                            mutualClosePublished = listOf(closingTx)
                        )
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
            is ChannelCommand.Close.MutualClose -> handleCommandError(cmd, ClosingAlreadyInProgress(channelId))
            is ChannelCommand.Init -> unhandled(cmd)
            is ChannelCommand.Funding -> unhandled(cmd)
            is ChannelCommand.Closing -> unhandled(cmd)
            is ChannelCommand.Connected -> unhandled(cmd)
            is ChannelCommand.Disconnected -> Pair(Offline(this@Negotiating), listOf())
            is ChannelCommand.PeerBackupReceived -> unhandled(cmd)
        }
    }

    /** Return full information about a known closing tx. */
    internal fun getMutualClosePublished(tx: Transaction): ClosingTx {
        // they can publish a closing tx with any sig we sent them, even if we are not done negotiating
        // they added their signature, so we use their version of the transaction
        return closingTxProposed.flatten().first { it.unsignedTx.tx.txid == tx.txid }.unsignedTx.copy(tx = tx)
    }

    private fun ChannelContext.completeMutualClose(signedClosingTx: ClosingTx, closingSigned: ClosingSigned?): Pair<ChannelState, List<ChannelAction>> {
        val nextState = Closing(
            commitments,
            waitingSinceBlock = currentBlockHeight.toLong(),
            mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
            mutualClosePublished = listOf(signedClosingTx)
        )
        val actions = buildList {
            add(ChannelAction.Storage.StoreState(nextState))
            closingSigned?.let { add(ChannelAction.Message.Send(it)) }
            add(ChannelAction.Blockchain.PublishTx(signedClosingTx))
            add(ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, signedClosingTx.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(signedClosingTx.tx))))
        }
        return Pair(nextState, actions)
    }
}
