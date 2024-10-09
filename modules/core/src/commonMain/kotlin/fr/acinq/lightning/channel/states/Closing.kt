package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.Satoshi
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.updated
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.Helpers.Closing.claimCurrentLocalCommitTxOutputs
import fr.acinq.lightning.channel.Helpers.Closing.claimRemoteCommitTxOutputs
import fr.acinq.lightning.channel.Helpers.Closing.claimRevokedHtlcTxOutputs
import fr.acinq.lightning.channel.Helpers.Closing.claimRevokedRemoteCommitTxHtlcOutputs
import fr.acinq.lightning.channel.Helpers.Closing.extractPreimages
import fr.acinq.lightning.channel.Helpers.Closing.onChainOutgoingHtlcs
import fr.acinq.lightning.channel.Helpers.Closing.overriddenOutgoingHtlcs
import fr.acinq.lightning.channel.Helpers.Closing.timedOutHtlcs
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.ClosingTx
import fr.acinq.lightning.utils.getValue
import fr.acinq.lightning.wire.ChannelReestablish
import fr.acinq.lightning.wire.Error

data class ClosingFees(val preferred: Satoshi, val min: Satoshi, val max: Satoshi) {
    constructor(preferred: Satoshi) : this(preferred, preferred, preferred)
}

data class ClosingFeerates(val preferred: FeeratePerKw, val min: FeeratePerKw, val max: FeeratePerKw) {
    fun computeFees(closingTxWeight: Int): ClosingFees = ClosingFees(Transactions.weight2fee(preferred, closingTxWeight), Transactions.weight2fee(min, closingTxWeight), Transactions.weight2fee(max, closingTxWeight))

    companion object {
        operator fun invoke(preferred: FeeratePerKw): ClosingFeerates = ClosingFeerates(preferred, preferred / 2, preferred * 2)
    }
}

sealed class ClosingType
data class MutualClose(val tx: ClosingTx) : ClosingType()
data class LocalClose(val localCommit: LocalCommit, val localCommitPublished: LocalCommitPublished) : ClosingType()

sealed class RemoteClose : ClosingType() {
    abstract val remoteCommit: RemoteCommit
    abstract val remoteCommitPublished: RemoteCommitPublished
}

data class CurrentRemoteClose(override val remoteCommit: RemoteCommit, override val remoteCommitPublished: RemoteCommitPublished) : RemoteClose()
data class NextRemoteClose(override val remoteCommit: RemoteCommit, override val remoteCommitPublished: RemoteCommitPublished) : RemoteClose()

data class RecoveryClose(val remoteCommitPublished: RemoteCommitPublished) : ClosingType()
data class RevokedClose(val revokedCommitPublished: RevokedCommitPublished) : ClosingType()

data class Closing(
    override val commitments: Commitments,
    val waitingSinceBlock: Long, // how many blocks since we initiated the closing
    val mutualCloseProposed: List<ClosingTx> = emptyList(), // all exchanged closing sigs are flattened, we use this only to keep track of what publishable tx they have
    val mutualClosePublished: List<ClosingTx> = emptyList(),
    val localCommitPublished: LocalCommitPublished? = null,
    val remoteCommitPublished: RemoteCommitPublished? = null,
    val nextRemoteCommitPublished: RemoteCommitPublished? = null,
    val futureRemoteCommitPublished: RemoteCommitPublished? = null,
    val revokedCommitPublished: List<RevokedCommitPublished> = emptyList()
) : ChannelStateWithCommitments() {

    private val spendingTxs: List<Transaction> by lazy {
        mutualClosePublished.map { it.tx } + revokedCommitPublished.map { it.commitTx } + listOfNotNull(
            localCommitPublished?.commitTx,
            remoteCommitPublished?.commitTx,
            nextRemoteCommitPublished?.commitTx,
            futureRemoteCommitPublished?.commitTx
        )
    }

    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.WatchReceived -> {
                val watch = cmd.watch
                when {
                    watch is WatchEventConfirmed && watch.event is BITCOIN_FUNDING_DEPTHOK -> {
                        when (val res = acceptFundingTxConfirmed(watch)) {
                            is Either.Right -> {
                                val (commitments1, commitment, actions) = res.value
                                if (commitments.latest.fundingTxIndex == commitment.fundingTxIndex && commitments.latest.fundingTxId != commitment.fundingTxId) {
                                    // This is a corner case where:
                                    //  - the funding tx was RBF-ed
                                    //  - *and* we went to CLOSING before any funding tx got confirmed (probably due to a local or remote error)
                                    //  - *and* an older version of the funding tx confirmed and reached min depth (it won't be re-orged out)
                                    //
                                    // This means that:
                                    //  - the whole current commitment tree has been double-spent and can safely be forgotten
                                    //  - from now on, we only need to keep track of the commitment associated to the funding tx that got confirmed
                                    //
                                    // Force-closing is our only option here, if we are in this state the channel was closing and it is too late
                                    // to negotiate a mutual close.
                                    // The best funding tx candidate has been confirmed, we can forget alternative commitments.
                                    logger.info { "channel was confirmed at blockHeight=${watch.blockHeight} txIndex=${watch.txIndex} with a previous funding txid=${watch.tx.txid}" }
                                    val commitments2 = commitments1.copy(
                                        active = listOf(commitment),
                                        inactive = emptyList()
                                    )
                                    val (nextState, actions1) = this@Closing.copy(commitments = commitments2).run { spendLocalCurrent() }
                                    Pair(nextState, actions + actions1)
                                } else {
                                    // We're still on the same splice history, nothing to do
                                    val nextState = this@Closing.copy(commitments = commitments1)
                                    Pair(nextState, actions + listOf(ChannelAction.Storage.StoreState(nextState)))

                                }
                            }
                            is Either.Left -> Pair(this@Closing, listOf())
                        }
                    }
                    watch is WatchEventSpent && watch.event is BITCOIN_FUNDING_SPENT -> when {
                        commitments.all.any { it.fundingTxId == watch.tx.txid } -> {
                            // if the spending tx is itself a funding tx, this is a splice and there is nothing to do
                            Pair(this@Closing, listOf())
                        }
                        mutualClosePublished.any { it.tx.txid == watch.tx.txid } -> {
                            // we already know about this tx, probably because we have published it ourselves after successful negotiation
                            Pair(this@Closing, listOf())
                        }
                        mutualCloseProposed.any { it.tx.txid == watch.tx.txid } -> {
                            // at any time they can publish a closing tx with any sig we sent them
                            val closingTx = mutualCloseProposed.first { it.tx.txid == watch.tx.txid }.copy(tx = watch.tx)
                            val nextState = this@Closing.copy(mutualClosePublished = mutualClosePublished + listOf(closingTx))
                            val actions = listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Blockchain.PublishTx(closingTx))
                            Pair(nextState, actions)
                        }
                        localCommitPublished?.commitTx == watch.tx || remoteCommitPublished?.commitTx == watch.tx || nextRemoteCommitPublished?.commitTx == watch.tx || futureRemoteCommitPublished?.commitTx == watch.tx -> {
                            // this is because WatchSpent watches never expire and we are notified multiple times
                            Pair(this@Closing, listOf())
                        }
                        watch.tx.txid == commitments.latest.remoteCommit.txid -> {
                            // counterparty may attempt to spend its last commit tx at any time
                            handleRemoteSpentCurrent(watch.tx, commitments.latest)
                        }
                        watch.tx.txid == commitments.latest.nextRemoteCommit?.commit?.txid -> {
                            // counterparty may attempt to spend its next commit tx at any time
                            handleRemoteSpentNext(watch.tx, commitments.latest)
                        }
                        watch.tx.txIn.map { it.outPoint }.contains(commitments.latest.commitInput.outPoint) -> {
                            // counterparty may attempt to spend a revoked commit tx at any time
                            handleRemoteSpentOther(watch.tx)
                        }
                        else -> when (val commitment = commitments.resolveCommitment(watch.tx)) {
                            is Commitment -> {
                                logger.warning { "a commit tx for an older commitment has been published fundingTxId=${commitment.fundingTxId} fundingTxIndex=${commitment.fundingTxIndex}" }
                                Pair(this@Closing, listOf(ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, watch.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_ALTERNATIVE_COMMIT_TX_CONFIRMED))))
                            }
                            else -> {
                                logger.warning { "unrecognized tx=${watch.tx.txid}" }
                                Pair(this@Closing, listOf())
                            }
                        }
                    }
                    watch is WatchEventConfirmed && watch.event is BITCOIN_ALTERNATIVE_COMMIT_TX_CONFIRMED -> when (val commitment = commitments.resolveCommitment(watch.tx)) {
                        is Commitment -> {
                            logger.warning { "a commit tx for fundingTxIndex=${commitment.fundingTxIndex} fundingTxId=${commitment.fundingTxId} has been confirmed" }
                            val commitments1 = commitments.copy(
                                active = listOf(commitment),
                                inactive = emptyList()
                            )
                            val newState = this@Closing.copy(commitments = commitments1)
                            // This commitment may be revoked: we need to verify that its index matches our latest known index before overwriting our previous commitments.
                            when {
                                watch.tx.txid == commitments1.latest.localCommit.publishableTxs.commitTx.tx.txid -> {
                                    // our local commit has been published from the outside, it's unexpected but let's deal with it anyway
                                    newState.run { spendLocalCurrent() }
                                }
                                watch.tx.txid == commitments1.latest.remoteCommit.txid && commitments1.remoteCommitIndex == commitments.remoteCommitIndex -> {
                                    // counterparty may attempt to spend its last commit tx at any time
                                    newState.run { handleRemoteSpentCurrent(watch.tx, commitments1.latest) }
                                }
                                watch.tx.txid == commitments1.latest.nextRemoteCommit?.commit?.txid && commitments1.remoteCommitIndex == commitments.remoteCommitIndex && commitments.remoteNextCommitInfo.isLeft -> {
                                    // counterparty may attempt to spend its next commit tx at any time
                                    newState.run { handleRemoteSpentNext(watch.tx, commitments1.latest) }
                                }
                                else -> {
                                    // counterparty may attempt to spend a revoked commit tx at any time
                                    newState.run { handleRemoteSpentOther(watch.tx) }
                                }
                            }
                        }
                        else -> {
                            logger.warning { "unrecognized alternative commit tx=${watch.tx.txid}" }
                            Pair(this@Closing, listOf())
                        }
                    }
                    watch is WatchEventSpent && watch.event is BITCOIN_OUTPUT_SPENT -> {
                        // when a remote or local commitment tx containing outgoing htlcs is published on the network,
                        // we watch it in order to extract payment preimage if funds are pulled by the counterparty
                        // we can then use these preimages to fulfill payments
                        logger.info { "processing BITCOIN_OUTPUT_SPENT with txid=${watch.tx.txid} tx=${watch.tx}" }
                        val htlcSettledActions = mutableListOf<ChannelAction>()
                        extractPreimages(commitments.latest.localCommit, watch.tx).forEach { (htlc, preimage) ->
                            when (val paymentId = commitments.payments[htlc.id]) {
                                null -> {
                                    // if we don't have a reference to the payment, it means that we already have forwarded the fulfill so that's not a big deal.
                                    // this can happen if they send a signature containing the fulfill, then fail the channel before we have time to sign it
                                    logger.info { "cannot fulfill htlc #${htlc.id} paymentHash=${htlc.paymentHash} (payment not found)" }
                                }
                                else -> {
                                    logger.info { "fulfilling htlc #${htlc.id} paymentHash=${htlc.paymentHash} paymentId=$paymentId" }
                                    htlcSettledActions += ChannelAction.ProcessCmdRes.AddSettledFulfill(paymentId, htlc, ChannelAction.HtlcResult.Fulfill.OnChainFulfill(preimage))
                                }
                            }
                        }

                        val revokedCommitPublishActions = mutableListOf<ChannelAction>()
                        val revokedCommitPublished1 = revokedCommitPublished.map { rev ->
                            val (newRevokedCommitPublished, penaltyTxs) = claimRevokedHtlcTxOutputs(channelKeys(), commitments.params, rev, watch.tx, currentOnChainFeerates())
                            penaltyTxs.forEach {
                                revokedCommitPublishActions += ChannelAction.Blockchain.PublishTx(it)
                                revokedCommitPublishActions += ChannelAction.Blockchain.SendWatch(WatchSpent(channelId, watch.tx, it.input.outPoint.index.toInt(), BITCOIN_OUTPUT_SPENT))
                            }
                            newRevokedCommitPublished
                        }

                        val nextState = copy(revokedCommitPublished = revokedCommitPublished1)
                        val actions = buildList {
                            add(ChannelAction.Storage.StoreState(nextState))
                            // one of the outputs of the local/remote/revoked commit was spent
                            // we just put a watch to be notified when it is confirmed
                            add(ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, watch.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(watch.tx))))
                            addAll(revokedCommitPublishActions)
                            addAll(htlcSettledActions)
                        }
                        Pair(nextState, actions)
                    }
                    watch is WatchEventConfirmed && watch.event is BITCOIN_TX_CONFIRMED -> {
                        logger.info { "txid=${watch.tx.txid} has reached mindepth, updating closing state" }
                        // first we check if this tx belongs to one of the current local/remote commits, update it and update the channel data
                        val closing1 = this@Closing.copy(
                            localCommitPublished = localCommitPublished?.update(watch.tx),
                            remoteCommitPublished = remoteCommitPublished?.update(watch.tx),
                            nextRemoteCommitPublished = nextRemoteCommitPublished?.update(watch.tx),
                            futureRemoteCommitPublished = futureRemoteCommitPublished?.update(watch.tx),
                            revokedCommitPublished = revokedCommitPublished.map { it.update(watch.tx) }
                        )

                        // we may need to fail some htlcs in case a commitment tx was published and they have reached the timeout threshold
                        val htlcSettledActions = mutableListOf<ChannelAction>()
                        val timedOutHtlcs = when (val closingType = closing1.closingTypeAlreadyKnown()) {
                            is LocalClose -> timedOutHtlcs(closingType.localCommit, closingType.localCommitPublished, commitments.params.localParams.dustLimit, watch.tx)
                            is RemoteClose -> timedOutHtlcs(closingType.remoteCommit, closingType.remoteCommitPublished, commitments.params.remoteParams.dustLimit, watch.tx)
                            else -> setOf() // we lose htlc outputs in option_data_loss_protect scenarios (future remote commit)
                        }
                        timedOutHtlcs.forEach { add ->
                            when (val paymentId = commitments.payments[add.id]) {
                                null -> {
                                    // same as for fulfilling the htlc (no big deal)
                                    logger.info { "cannot fail timedout htlc #${add.id} paymentHash=${add.paymentHash} (payment not found)" }
                                }
                                else -> {
                                    logger.info { "failing htlc #${add.id} paymentHash=${add.paymentHash} paymentId=$paymentId: htlc timed out" }
                                    htlcSettledActions += ChannelAction.ProcessCmdRes.AddSettledFail(paymentId, add, ChannelAction.HtlcResult.Fail.OnChainFail(HtlcsTimedOutDownstream(channelId, setOf(add))))
                                }
                            }
                        }

                        // we also need to fail outgoing htlcs that we know will never reach the blockchain
                        overriddenOutgoingHtlcs(commitments.latest.localCommit, commitments.latest.remoteCommit, commitments.latest.nextRemoteCommit?.commit, closing1.revokedCommitPublished, watch.tx).forEach { add ->
                            when (val paymentId = commitments.payments[add.id]) {
                                null -> {
                                    // same as for fulfilling the htlc (no big deal)
                                    logger.info { "cannot fail overridden htlc #${add.id} paymentHash=${add.paymentHash} (payment not found)" }
                                }
                                else -> {
                                    logger.info { "failing htlc #${add.id} paymentHash=${add.paymentHash} paymentId=$paymentId: overridden by local commit" }
                                    htlcSettledActions += ChannelAction.ProcessCmdRes.AddSettledFail(paymentId, add, ChannelAction.HtlcResult.Fail.OnChainFail(HtlcOverriddenByLocalCommit(channelId, add)))
                                }
                            }
                        }

                        // for our outgoing payments, let's log something if we know that they will settle on chain
                        onChainOutgoingHtlcs(commitments.latest.localCommit, commitments.latest.remoteCommit, commitments.latest.nextRemoteCommit?.commit, watch.tx).forEach { add ->
                            commitments.payments[add.id]?.let { paymentId -> logger.info { "paymentId=$paymentId will settle on-chain (htlc #${add.id} sending ${add.amountMsat})" } }
                        }

                        val (nextState, closedActions) = when (val closingType = closing1.isClosed(watch.tx)) {
                            null -> Pair(closing1, listOf())
                            else -> {
                                logger.info { "channel is now closed" }
                                Pair(Closed(closing1), listOf(setClosingStatus(closingType)))
                            }
                        }
                        val actions = buildList {
                            add(ChannelAction.Storage.StoreState(nextState))
                            addAll(htlcSettledActions)
                            addAll(closedActions)
                        }
                        Pair(nextState, actions)
                    }
                    else -> unhandled(cmd)
                }
            }
            is ChannelCommand.Closing.GetHtlcInfosResponse -> {
                val index = revokedCommitPublished.indexOfFirst { it.commitTx.txid == cmd.revokedCommitTxId }
                if (index >= 0) {
                    val revokedCommitPublished1 = claimRevokedRemoteCommitTxHtlcOutputs(channelKeys(), commitments.params, revokedCommitPublished[index], currentOnChainFeerates(), cmd.htlcInfos)
                    val nextState = copy(revokedCommitPublished = revokedCommitPublished.updated(index, revokedCommitPublished1))
                    val actions = buildList {
                        add(ChannelAction.Storage.StoreState(nextState))
                        addAll(revokedCommitPublished1.run { doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()) })
                    }
                    Pair(nextState, actions)
                } else {
                    logger.warning { "cannot find revoked commit with txid=${cmd.revokedCommitTxId}" }
                    Pair(this@Closing, listOf())
                }
            }
            is ChannelCommand.MessageReceived -> when (cmd.message) {
                is ChannelReestablish -> {
                    // they haven't detected that we were closing and are trying to reestablish a connection
                    // we give them one of the published txs as a hint
                    // note spendingTx != Nil (that's a requirement of DATA_CLOSING)
                    val exc = FundingTxSpent(channelId, spendingTxs.first().txid)
                    val error = Error(channelId, exc.message)
                    Pair(this@Closing, listOf(ChannelAction.Message.Send(error)))
                }
                is Error -> {
                    logger.error { "peer sent error: ascii=${cmd.message.toAscii()} bin=${cmd.message.data.toHex()}" }
                    // nothing to do, there is already a spending tx published
                    Pair(this@Closing, listOf())
                }
                else -> unhandled(cmd)
            }
            is ChannelCommand.Close -> handleCommandError(cmd, ClosingAlreadyInProgress(channelId))
            is ChannelCommand.Htlc.Add -> {
                logger.info { "rejecting htlc request in state=${this::class}" }
                // we don't provide a channel_update: this will be a permanent channel failure
                handleCommandError(cmd, ChannelUnavailable(channelId))
            }
            is ChannelCommand.Htlc.Settlement.Fulfill -> when (val result = commitments.sendFulfill(cmd)) {
                is Either.Right -> {
                    logger.info { "got valid payment preimage, recalculating transactions to redeem the corresponding htlc on-chain" }
                    val commitments1 = result.value.first
                    val localCommitPublished1 = localCommitPublished?.let {
                        claimCurrentLocalCommitTxOutputs(channelKeys(), commitments1.latest, it.commitTx, currentOnChainFeerates())
                    }
                    val remoteCommitPublished1 = remoteCommitPublished?.let {
                        claimRemoteCommitTxOutputs(channelKeys(), commitments1.latest, commitments1.latest.remoteCommit, it.commitTx, currentOnChainFeerates())
                    }
                    val nextRemoteCommitPublished1 = nextRemoteCommitPublished?.let {
                        val remoteCommit = commitments1.latest.nextRemoteCommit?.commit ?: error("next remote commit must be defined")
                        claimRemoteCommitTxOutputs(channelKeys(), commitments1.latest, remoteCommit, it.commitTx, currentOnChainFeerates())
                    }
                    val republishList = buildList {
                        val minDepth = staticParams.nodeParams.minDepthBlocks.toLong()
                        localCommitPublished1?.run { addAll(doPublish(channelId, minDepth)) }
                        remoteCommitPublished1?.run { addAll(doPublish(channelId, minDepth)) }
                        nextRemoteCommitPublished1?.run { addAll(doPublish(channelId, minDepth)) }
                    }
                    val nextState = copy(
                        commitments = commitments1,
                        localCommitPublished = localCommitPublished1,
                        remoteCommitPublished = remoteCommitPublished1,
                        nextRemoteCommitPublished = nextRemoteCommitPublished1
                    )
                    val actions = buildList {
                        add(ChannelAction.Storage.StoreState(nextState))
                        addAll(republishList)
                    }
                    Pair(nextState, actions)
                }
                is Either.Left -> handleCommandError(cmd, result.value)
            }
            is ChannelCommand.Htlc.Settlement -> unhandled(cmd)
            is ChannelCommand.Commitment.CheckHtlcTimeout -> checkHtlcTimeout()
            is ChannelCommand.Commitment -> unhandled(cmd)
            is ChannelCommand.Init -> unhandled(cmd)
            is ChannelCommand.Funding -> unhandled(cmd)
            is ChannelCommand.Connected -> unhandled(cmd)
            is ChannelCommand.Disconnected -> unhandled(cmd)
            is ChannelCommand.PeerBackupReceived -> unhandled(cmd)
        }
    }

    /**
     * Checks if a channel is closed (i.e. its closing tx has been confirmed)
     *
     * @param additionalConfirmedTx additional confirmed transaction; we need this for the mutual close scenario because we don't store the closing tx in the channel state
     * @return the channel closing type, if applicable
     */
    private fun isClosed(additionalConfirmedTx: Transaction?): ClosingType? {
        return when {
            additionalConfirmedTx?.let { tx -> mutualClosePublished.any { it.tx.txid == tx.txid } } ?: false -> {
                val closingTx = mutualClosePublished.first { it.tx.txid == additionalConfirmedTx!!.txid }.copy(tx = additionalConfirmedTx!!)
                MutualClose(closingTx)
            }
            localCommitPublished?.isDone() ?: false -> LocalClose(commitments.latest.localCommit, localCommitPublished!!)
            remoteCommitPublished?.isDone() ?: false -> CurrentRemoteClose(commitments.latest.remoteCommit, remoteCommitPublished!!)
            nextRemoteCommitPublished?.isDone() ?: false -> NextRemoteClose(commitments.latest.nextRemoteCommit!!.commit, nextRemoteCommitPublished!!)
            futureRemoteCommitPublished?.isDone() ?: false -> RecoveryClose(futureRemoteCommitPublished!!)
            revokedCommitPublished.any { it.isDone() } -> RevokedClose(revokedCommitPublished.first { it.isDone() })
            else -> null
        }
    }

    fun closingTypeAlreadyKnown(): ClosingType? {
        return when {
            localCommitPublished?.isConfirmed() ?: false -> LocalClose(commitments.latest.localCommit, localCommitPublished!!)
            remoteCommitPublished?.isConfirmed() ?: false -> CurrentRemoteClose(commitments.latest.remoteCommit, remoteCommitPublished!!)
            nextRemoteCommitPublished?.isConfirmed() ?: false -> NextRemoteClose(commitments.latest.nextRemoteCommit!!.commit, nextRemoteCommitPublished!!)
            futureRemoteCommitPublished?.isConfirmed() ?: false -> RecoveryClose(futureRemoteCommitPublished!!)
            revokedCommitPublished.any { it.isConfirmed() } -> RevokedClose(revokedCommitPublished.first { it.isConfirmed() })
            else -> null
        }
    }

    companion object {
        /**
         * This method returns updates the status of the closing transaction that should be persisted in a database. It should be
         * called when the channel has been actually closed, so that we know those transactions are confirmed. Note that we only
         * keep track of the commit tx in the non-mutual-close case.
         */
        private fun setClosingStatus(closingType: ClosingType): ChannelAction.Storage.SetLocked {
            val txId = when (closingType) {
                is MutualClose -> closingType.tx.tx.txid
                is LocalClose -> closingType.localCommit.publishableTxs.commitTx.tx.txid
                is RemoteClose -> closingType.remoteCommit.txid
                is RecoveryClose -> closingType.remoteCommitPublished.commitTx.txid
                is RevokedClose -> closingType.revokedCommitPublished.commitTx.txid
            }
            return ChannelAction.Storage.SetLocked(txId)
        }
    }
}
