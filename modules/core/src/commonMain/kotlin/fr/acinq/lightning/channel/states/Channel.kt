package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Feature
import fr.acinq.lightning.NodeParams
import fr.acinq.lightning.SensitiveTaskEvents
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.Helpers.Closing.claimCurrentLocalCommitTxOutputs
import fr.acinq.lightning.channel.Helpers.Closing.claimRemoteCommitMainOutput
import fr.acinq.lightning.channel.Helpers.Closing.claimRemoteCommitTxOutputs
import fr.acinq.lightning.channel.Helpers.Closing.claimRevokedRemoteCommitTxOutputs
import fr.acinq.lightning.channel.Helpers.Closing.getRemotePerCommitmentSecret
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.db.ChannelClosingType
import fr.acinq.lightning.logging.*
import fr.acinq.lightning.serialization.Encryption.from
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.ClosingTx
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first

/*
 * Channel is implemented as a finite state machine
 * Its main method is (State, Event) -> (State, List<Action>)
 */

/** Channel static parameters. */
data class StaticParams(val nodeParams: NodeParams, val remoteNodeId: PublicKey) {
    val useZeroConf: Boolean = nodeParams.zeroConfPeers.contains(remoteNodeId)
}

data class ChannelContext(
    val staticParams: StaticParams,
    val currentBlockHeight: Int,
    val onChainFeerates: StateFlow<OnChainFeerates?>,
    override val logger: MDCLogger
) : LoggingContext {
    val keyManager: KeyManager get() = staticParams.nodeParams.keyManager
    val privateKey: PrivateKey get() = staticParams.nodeParams.nodePrivateKey
    suspend fun currentOnChainFeerates(): OnChainFeerates {
        logger.info { "retrieving feerates" }
        return onChainFeerates.filterNotNull().first()
            .also { logger.info { "using feerates=$it" } }
    }
}

/** Channel state. */
sealed class ChannelState {

    /**
     * @param cmd input event (for example, a message was received, a command was sent by the GUI/API, etc)
     * @return a (new state, list of actions) pair
     */
    abstract suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>>

    suspend fun ChannelContext.process(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return try {
            processInternal(cmd)
                .let { (newState, actions) -> Pair(newState, actions + onTransition(newState)) }
        } catch (t: Throwable) {
            handleLocalError(cmd, t)
        }
    }

    /** Add actions for some transitions */
    private fun ChannelContext.onTransition(newState: ChannelState): List<ChannelAction> {
        val oldState = when (this@ChannelState) {
            is Offline -> this@ChannelState.state
            is Syncing -> this@ChannelState.state
            else -> this@ChannelState
        }
        maybeSignalSensitiveTask(oldState, newState)
        return when {
            // we only want to fire the PaymentSent event when we transition to Closing for the first time
            oldState is ChannelStateWithCommitments && oldState !is Closing && newState is Closing -> emitClosingEvents(oldState, newState)
            else -> emptyList()
        }
    }

    /** Some transitions imply that we are in the middle of tasks that may require some time. */
    private fun ChannelContext.maybeSignalSensitiveTask(oldState: ChannelState, newState: ChannelState) {
        val spliceStatusBefore = (oldState as? Normal)?.spliceStatus
        val spliceStatusAfter = (newState as? Normal)?.spliceStatus
        when {
            spliceStatusBefore !is SpliceStatus.InProgress && spliceStatusAfter is SpliceStatus.InProgress -> // splice initiated
                staticParams.nodeParams._nodeEvents.tryEmit(SensitiveTaskEvents.TaskStarted(SensitiveTaskEvents.TaskIdentifier.InteractiveTx(spliceStatusAfter.spliceSession.fundingParams)))
            spliceStatusBefore is SpliceStatus.InProgress && spliceStatusAfter !is SpliceStatus.WaitingForSigs -> // splice aborted before reaching signing phase
                staticParams.nodeParams._nodeEvents.tryEmit(SensitiveTaskEvents.TaskEnded(SensitiveTaskEvents.TaskIdentifier.InteractiveTx(spliceStatusBefore.spliceSession.fundingParams)))
            spliceStatusBefore is SpliceStatus.WaitingForSigs && spliceStatusAfter !is SpliceStatus.WaitingForSigs -> // splice leaving signing phase (successfully or not)
                staticParams.nodeParams._nodeEvents.tryEmit(SensitiveTaskEvents.TaskEnded(SensitiveTaskEvents.TaskIdentifier.InteractiveTx(spliceStatusBefore.session.fundingParams)))
            else -> {}
        }
    }

    private fun ChannelContext.emitClosingEvents(oldState: ChannelStateWithCommitments, newState: Closing): List<ChannelAction> {
        val channelBalance = oldState.commitments.latest.localCommit.spec.toLocal
        return if (channelBalance > 0.msat) {
            when {
                newState.mutualClosePublished.isNotEmpty() -> {
                    // this code is only executed for the first transition to Closing, so there can only be one transaction here
                    val closingTx = newState.mutualClosePublished.first()
                    val finalAmount = closingTx.toLocalOutput?.amount ?: 0.sat
                    val address = closingTx.toLocalOutput?.publicKeyScript?.let { Bitcoin.addressFromPublicKeyScript(staticParams.nodeParams.chainHash, it.toByteArray()).right } ?: "unknown"
                    listOf(
                        ChannelAction.Storage.StoreOutgoingPayment.ViaClose(
                            amount = finalAmount,
                            miningFees = channelBalance.truncateToSatoshi() - finalAmount,
                            address = address,
                            txId = closingTx.tx.txid,
                            isSentToDefaultAddress = closingTx.toLocalOutput?.publicKeyScript == oldState.commitments.params.localParams.defaultFinalScriptPubKey,
                            closingType = ChannelClosingType.Mutual
                        )
                    )
                }
                else -> {
                    // this is a force close, the closing tx is a commit tx
                    // since force close scenarios may be complicated with multiple layers of transactions, we estimate global fees by listing all the final outputs
                    // going to us, and subtracting that from the current balance
                    val (commitTx, type) = when {
                        newState.localCommitPublished is LocalCommitPublished -> Pair(newState.localCommitPublished.commitTx, ChannelClosingType.Local)
                        newState.remoteCommitPublished is RemoteCommitPublished -> Pair(newState.remoteCommitPublished.commitTx, ChannelClosingType.Remote)
                        newState.nextRemoteCommitPublished is RemoteCommitPublished -> Pair(newState.nextRemoteCommitPublished.commitTx, ChannelClosingType.Remote)
                        newState.futureRemoteCommitPublished is RemoteCommitPublished -> Pair(newState.futureRemoteCommitPublished.commitTx, ChannelClosingType.Remote)
                        else -> {
                            val revokedCommitPublished = newState.revokedCommitPublished.first() // must be there
                            Pair(revokedCommitPublished.commitTx, ChannelClosingType.Revoked)
                        }
                    }
                    val address = Bitcoin.addressFromPublicKeyScript(
                        chainHash = staticParams.nodeParams.chainHash,
                        pubkeyScript = oldState.commitments.params.localParams.defaultFinalScriptPubKey.toByteArray() // force close always send to the default script
                    ).right ?: "unknown"
                    listOf(
                        ChannelAction.Storage.StoreOutgoingPayment.ViaClose(
                            amount = channelBalance.truncateToSatoshi(),
                            miningFees = 0.sat, // TODO: mining fees are tricky in force close scenario, we just lump everything in the amount field
                            address = address,
                            txId = commitTx.txid,
                            isSentToDefaultAddress = true, // force close always send to the default script
                            closingType = type
                        )
                    )
                }
            }
        } else emptyList() // balance == 0
    }

    internal fun ChannelContext.unhandled(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        when (cmd) {
            is ChannelCommand.MessageReceived -> logger.warning { "unhandled message ${cmd.message::class.simpleName} in state ${this@ChannelState::class.simpleName}" }
            is ChannelCommand.WatchReceived -> logger.warning { "unhandled watch event ${cmd.watch.event::class.simpleName} in state ${this@ChannelState::class.simpleName}" }
            else -> logger.warning { "unhandled command ${cmd::class.simpleName} in state ${this@ChannelState::class.simpleName}" }
        }
        return Pair(this@ChannelState, listOf())
    }

    internal fun ChannelContext.handleCommandError(cmd: ChannelCommand, error: ChannelException, channelUpdate: ChannelUpdate? = null): Pair<ChannelState, List<ChannelAction>> {
        logger.warning(error) { "processing command ${cmd::class.simpleName} in state ${this@ChannelState::class.simpleName} failed" }
        return when (cmd) {
            is ChannelCommand.Htlc.Add -> Pair(this@ChannelState, listOf(ChannelAction.ProcessCmdRes.AddFailed(cmd, error, channelUpdate)))
            else -> Pair(this@ChannelState, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, error)))
        }
    }

    internal fun ChannelContext.doPublish(tx: ClosingTx, channelId: ByteVector32): List<ChannelAction.Blockchain> = listOf(
        ChannelAction.Blockchain.PublishTx(tx),
        ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, tx.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(tx.tx)))
    )

    internal suspend fun ChannelContext.handleLocalError(cmd: ChannelCommand, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        when (cmd) {
            is ChannelCommand.MessageReceived -> logger.error(t) { "error on message ${cmd.message::class.simpleName}" }
            is ChannelCommand.WatchReceived -> logger.error { "error on watch event ${cmd.watch.event::class.simpleName}" }
            else -> logger.error(t) { "error on command ${cmd::class.simpleName}" }
        }

        fun abort(channelId: ByteVector32?, state: ChannelState): Pair<ChannelState, List<ChannelAction>> {
            val actions = buildList {
                channelId
                    ?.let { Error(it, t.message) }
                    ?.let { add(ChannelAction.Message.Send(it)) }
                (state as? PersistedChannelState)
                    ?.let { add(ChannelAction.Storage.RemoveChannel(state)) }
            }
            return Pair(Aborted, actions)
        }

        suspend fun forceClose(state: ChannelStateWithCommitments): Pair<ChannelState, List<ChannelAction>> {
            val error = Error(state.channelId, t.message)
            return state.run { spendLocalCurrent().run { copy(second = second + ChannelAction.Message.Send(error)) } }
        }

        return when (val state = this@ChannelState) {
            is WaitForInit -> abort(null, state)
            is WaitForOpenChannel -> abort(state.temporaryChannelId, state)
            is WaitForAcceptChannel -> abort(state.temporaryChannelId, state)
            is WaitForFundingCreated -> abort(state.channelId, state)
            is WaitForFundingSigned -> abort(state.channelId, state)
            is WaitForFundingConfirmed -> forceClose(state)
            is WaitForChannelReady -> forceClose(state)
            is Normal -> forceClose(state)
            is ShuttingDown -> forceClose(state)
            is Negotiating -> when {
                state.bestUnpublishedClosingTx != null -> {
                    // if we were in the process of closing and already received a closing sig from the counterparty, it's always better to use that
                    val nextState = Closing(
                        state.commitments,
                        waitingSinceBlock = currentBlockHeight.toLong(),
                        mutualCloseProposed = state.closingTxProposed.flatten().map { it.unsignedTx } + listOf(state.bestUnpublishedClosingTx),
                        mutualClosePublished = listOf(state.bestUnpublishedClosingTx)
                    )
                    val actions = listOf(
                        ChannelAction.Storage.StoreState(nextState),
                        ChannelAction.Blockchain.PublishTx(state.bestUnpublishedClosingTx),
                        ChannelAction.Blockchain.SendWatch(WatchConfirmed(state.channelId, state.bestUnpublishedClosingTx.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(state.bestUnpublishedClosingTx.tx)))
                    )
                    Pair(nextState, actions)
                }
                else -> forceClose(state)
            }
            is Closing -> {
                if (state.mutualClosePublished.isNotEmpty()) {
                    // we already have published a mutual close tx, it's always better to use that
                    Pair(state, emptyList())
                } else {
                    state.localCommitPublished?.let {
                        // we're already trying to claim our commitment, there's nothing more we can do
                        Pair(state, emptyList())
                    } ?: state.run { spendLocalCurrent() }
                }
            }
            is Closed -> Pair(state, emptyList())
            is Aborted -> Pair(state, emptyList())
            is Offline -> state.run { handleLocalError(cmd, t) }
            is Syncing -> state.run { handleLocalError(cmd, t) }
            is WaitForRemotePublishFutureCommitment -> Pair(state, emptyList())
            is LegacyWaitForFundingConfirmed -> forceClose(state)
            is LegacyWaitForFundingLocked -> forceClose(state)
        }
    }

    suspend fun ChannelContext.handleRemoteError(e: Error): Pair<ChannelState, List<ChannelAction>> {
        // see BOLT 1: only print out data verbatim if is composed of printable ASCII characters
        logger.error { "peer sent error: ascii='${e.toAscii()}' bin=${e.data.toHex()}" }
        return when (this@ChannelState) {
            is Closing -> Pair(this@ChannelState, listOf()) // nothing to do, there is already a spending tx published
            is Negotiating -> when (this@ChannelState.bestUnpublishedClosingTx) {
                null -> this.spendLocalCurrent()
                else -> {
                    val nexState = Closing(
                        commitments = commitments,
                        waitingSinceBlock = currentBlockHeight.toLong(),
                        mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                        mutualClosePublished = listOfNotNull(bestUnpublishedClosingTx)
                    )
                    Pair(nexState, buildList {
                        add(ChannelAction.Storage.StoreState(nexState))
                        addAll(doPublish(bestUnpublishedClosingTx, nexState.channelId))
                    })
                }
            }
            is WaitForFundingSigned -> Pair(Aborted, listOf(ChannelAction.Storage.RemoveChannel(this@ChannelState)))
            // NB: we publish the commitment even if we have nothing at stake (in a dataloss situation our peer will send us an error just for that)
            is ChannelStateWithCommitments -> this.spendLocalCurrent()
            // when there is no commitment yet, we just go to CLOSED state in case an error occurs
            else -> Pair(Aborted, listOf())
        }
    }

    val stateName: String
        get() = when (this) {
            is Offline -> "${this::class.simpleName}(${this.state::class.simpleName})"
            is Syncing -> "${this::class.simpleName}(${this.state::class.simpleName})"
            else -> "${this::class.simpleName}"
        }
}

/** A channel state that is persisted to the DB. */
sealed class PersistedChannelState : ChannelState() {
    abstract val channelId: ByteVector32

    internal fun ChannelContext.createChannelReestablish(): ChannelReestablish = when (val state = this@PersistedChannelState) {
        is WaitForFundingSigned -> {
            val myFirstPerCommitmentPoint = keyManager.channelKeys(state.channelParams.localParams.fundingKeyPath).commitmentPoint(0)
            ChannelReestablish(
                channelId = channelId,
                nextLocalCommitmentNumber = 1,
                nextRemoteRevocationNumber = 0,
                yourLastCommitmentSecret = PrivateKey(ByteVector32.Zeroes),
                myCurrentPerCommitmentPoint = myFirstPerCommitmentPoint,
                TlvStream(ChannelReestablishTlv.NextFunding(state.signingSession.fundingTx.txId))
            )
        }
        is ChannelStateWithCommitments -> {
            val yourLastPerCommitmentSecret = state.commitments.remotePerCommitmentSecrets.lastIndex?.let { state.commitments.remotePerCommitmentSecrets.getHash(it) } ?: ByteVector32.Zeroes
            val myCurrentPerCommitmentPoint = keyManager.channelKeys(state.commitments.params.localParams.fundingKeyPath).commitmentPoint(state.commitments.localCommitIndex)
            val unsignedFundingTxId = when (state) {
                is WaitForFundingConfirmed -> state.getUnsignedFundingTxId()
                is Normal -> state.getUnsignedFundingTxId() // a splice was in progress, we tell our peer that we are remembering it and are expecting signatures
                else -> null
            }
            val tlvs: TlvStream<ChannelReestablishTlv> = unsignedFundingTxId?.let { TlvStream(ChannelReestablishTlv.NextFunding(it)) } ?: TlvStream.empty()
            ChannelReestablish(
                channelId = channelId,
                nextLocalCommitmentNumber = state.commitments.localCommitIndex + 1,
                nextRemoteRevocationNumber = state.commitments.remoteCommitIndex,
                yourLastCommitmentSecret = PrivateKey(yourLastPerCommitmentSecret),
                myCurrentPerCommitmentPoint = myCurrentPerCommitmentPoint,
                tlvStream = tlvs
            )
        }
    }

    companion object {
        // this companion object is used by static extended function `fun PersistedChannelState.Companion.from` in Encryption.kt
    }
}

sealed class ChannelStateWithCommitments : PersistedChannelState() {
    abstract val commitments: Commitments
    override val channelId: ByteVector32 get() = commitments.channelId
    val isChannelOpener: Boolean get() = commitments.params.localParams.isChannelOpener
    val paysCommitTxFees: Boolean get() = commitments.params.localParams.paysCommitTxFees
    val paysClosingFees: Boolean get() = commitments.params.localParams.paysClosingFees
    val remoteNodeId: PublicKey get() = commitments.remoteNodeId

    fun ChannelContext.channelKeys(): KeyManager.ChannelKeys = commitments.params.localParams.channelKeys(keyManager)

    abstract fun updateCommitments(input: Commitments): ChannelStateWithCommitments

    /**
     * When a funding transaction confirms, we can prune previous commitments.
     * We also watch this funding transaction to be able to detect force-close attempts.
     */
    internal fun ChannelContext.acceptFundingTxConfirmed(w: WatchEventConfirmed): Either<Commitments, Triple<Commitments, Commitment, List<ChannelAction>>> {
        logger.info { "funding txid=${w.tx.txid} was confirmed at blockHeight=${w.blockHeight} txIndex=${w.txIndex}" }
        return commitments.run {
            updateLocalFundingConfirmed(w.tx).map { (commitments1, commitment) ->
                val watchSpent = WatchSpent(channelId, commitment.fundingTxId, commitment.commitInput.outPoint.index.toInt(), commitment.commitInput.txOut.publicKeyScript, BITCOIN_FUNDING_SPENT)
                val actions = buildList {
                    newlyLocked(commitments, commitments1).forEach { add(ChannelAction.Storage.SetLocked(it.fundingTxId)) }
                    add(ChannelAction.Blockchain.SendWatch(watchSpent))
                }
                Triple(commitments1, commitment, actions)
            }
        }
    }

    /**
     * Default handler when a funding transaction confirms.
     */
    internal fun ChannelContext.updateFundingTxStatus(w: WatchEventConfirmed): Pair<ChannelStateWithCommitments, List<ChannelAction>> {
        return when (val res = acceptFundingTxConfirmed(w)) {
            is Either.Left -> Pair(this@ChannelStateWithCommitments, listOf())
            is Either.Right -> {
                val (commitments1, _, actions) = res.value
                val nextState = this@ChannelStateWithCommitments.updateCommitments(commitments1)
                Pair(nextState, actions + listOf(ChannelAction.Storage.StoreState(nextState)))
            }
        }
    }

    /**
     * List [Commitment] that have been locked by both sides for the first time. It is more complicated that it may seem, because:
     * - remote will re-emit splice_locked at reconnection
     * - a splice_locked implicitly applies to all previous splices, and they may be pruned instantly
     */
    internal fun ChannelContext.newlyLocked(before: Commitments, after: Commitments): List<Commitment> {
        val lastLockedBefore = before.run { lastLocked() }?.fundingTxIndex ?: -1
        val lastLockedAfter = after.run { lastLocked() }?.fundingTxIndex ?: -1
        return commitments.all.filter { it.fundingTxIndex > 0 && it.fundingTxIndex > lastLockedBefore && it.fundingTxIndex <= lastLockedAfter }
    }

    /**
     * Analyze and react to a potential force-close transaction spending one of our funding transactions.
     */
    internal suspend fun ChannelContext.handlePotentialForceClose(w: WatchEventSpent): Pair<ChannelStateWithCommitments, List<ChannelAction>> = when {
        w.event != BITCOIN_FUNDING_SPENT -> Pair(this@ChannelStateWithCommitments, listOf())
        commitments.all.any { it.fundingTxId == w.tx.txid } -> Pair(this@ChannelStateWithCommitments, listOf()) // if the spending tx is itself a funding tx, this is a splice and there is nothing to do
        w.tx.txid == commitments.latest.localCommit.publishableTxs.commitTx.tx.txid -> spendLocalCurrent()
        w.tx.txid == commitments.latest.remoteCommit.txid -> handleRemoteSpentCurrent(w.tx, commitments.latest)
        w.tx.txid == commitments.latest.nextRemoteCommit?.commit?.txid -> handleRemoteSpentNext(w.tx, commitments.latest)
        w.tx.txIn.any { it.outPoint == commitments.latest.commitInput.outPoint } -> handleRemoteSpentOther(w.tx)
        else -> when (val commitment = commitments.resolveCommitment(w.tx)) {
            is Commitment -> {
                logger.warning { "a commit tx for an older commitment has been published fundingTxId=${commitment.fundingTxId} fundingTxIndex=${commitment.fundingTxIndex}" }
                // We try spending our latest commitment but we also watch their commitment: if it confirms, we will react by spending our corresponding outputs.
                val watch = ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, w.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_ALTERNATIVE_COMMIT_TX_CONFIRMED))
                spendLocalCurrent().run { copy(second = second + watch) }
            }
            else -> {
                logger.warning { "unrecognized tx=${w.tx.txid}" }
                // This case can happen in the following (harmless) scenario:
                //  - we create and publish a splice transaction, then we go offline
                //  - the transaction confirms while we are offline
                //  - we restart and set a watch-confirmed for the splice transaction and a watch-spent for the previous funding transaction
                //  - the watch-confirmed triggers first and we prune the previous funding transaction
                //  - the watch-spent for the previous funding transaction triggers because of the splice transaction
                //  - but we've already pruned the corresponding commitment: we should simply ignore the event
                Pair(this@ChannelStateWithCommitments, listOf())
            }
        }
    }

    internal suspend fun ChannelContext.handleRemoteSpentCurrent(commitTx: Transaction, commitment: FullCommitment): Pair<Closing, List<ChannelAction>> {
        logger.warning { "they published their current commit in txid=${commitTx.txid}" }
        require(commitTx.txid == commitment.remoteCommit.txid) { "txid mismatch" }

        val remoteCommitPublished = claimRemoteCommitTxOutputs(channelKeys(), commitment, commitment.remoteCommit, commitTx, currentOnChainFeerates())

        val nextState = when (this@ChannelStateWithCommitments) {
            is Closing -> this@ChannelStateWithCommitments.copy(remoteCommitPublished = remoteCommitPublished)
            is Negotiating -> Closing(
                commitments = commitments,
                waitingSinceBlock = currentBlockHeight.toLong(),
                mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                remoteCommitPublished = remoteCommitPublished
            )
            else -> Closing(
                commitments = commitments,
                waitingSinceBlock = currentBlockHeight.toLong(),
                remoteCommitPublished = remoteCommitPublished
            )
        }

        return Pair(nextState, buildList {
            add(ChannelAction.Storage.StoreState(nextState))
            addAll(remoteCommitPublished.run { doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()) })
        })
    }

    internal suspend fun ChannelContext.handleRemoteSpentNext(commitTx: Transaction, commitment: FullCommitment): Pair<ChannelStateWithCommitments, List<ChannelAction>> {
        logger.warning { "they published their next commit in txid=${commitTx.txid}" }
        require(commitment.nextRemoteCommit != null) { "next remote commit must be defined" }
        val remoteCommit = commitment.nextRemoteCommit.commit
        require(commitTx.txid == remoteCommit.txid) { "txid mismatch" }

        val remoteCommitPublished = claimRemoteCommitTxOutputs(channelKeys(), commitment, remoteCommit, commitTx, currentOnChainFeerates())

        val nextState = when (this@ChannelStateWithCommitments) {
            is Closing -> copy(nextRemoteCommitPublished = remoteCommitPublished)
            is Negotiating -> Closing(
                commitments = commitments,
                waitingSinceBlock = currentBlockHeight.toLong(),
                mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                nextRemoteCommitPublished = remoteCommitPublished
            )
            else -> Closing(
                commitments = commitments,
                waitingSinceBlock = currentBlockHeight.toLong(),
                nextRemoteCommitPublished = remoteCommitPublished
            )
        }

        return Pair(nextState, buildList {
            add(ChannelAction.Storage.StoreState(nextState))
            addAll(remoteCommitPublished.run { doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()) })
        })
    }

    internal suspend fun ChannelContext.handleRemoteSpentOther(tx: Transaction): Pair<ChannelStateWithCommitments, List<ChannelAction>> {
        logger.warning { "funding tx spent in txid=${tx.txid}" }
        return getRemotePerCommitmentSecret(channelKeys(), commitments.params, commitments.remotePerCommitmentSecrets, tx)?.let { (remotePerCommitmentSecret, commitmentNumber) ->
            logger.warning { "txid=${tx.txid} was a revoked commitment, publishing the penalty tx" }
            val revokedCommitPublished = claimRevokedRemoteCommitTxOutputs(channelKeys(), commitments.params, remotePerCommitmentSecret, tx, currentOnChainFeerates())
            val ex = FundingTxSpent(channelId, tx.txid)
            val error = Error(channelId, ex.message)
            val nextState = when (this@ChannelStateWithCommitments) {
                is Closing -> if (this@ChannelStateWithCommitments.revokedCommitPublished.contains(revokedCommitPublished)) {
                    this@ChannelStateWithCommitments
                } else {
                    this@ChannelStateWithCommitments.copy(revokedCommitPublished = this@ChannelStateWithCommitments.revokedCommitPublished + revokedCommitPublished)
                }
                is Negotiating -> Closing(
                    commitments = commitments,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                    revokedCommitPublished = listOf(revokedCommitPublished)
                )
                else -> Closing(
                    commitments = commitments,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    revokedCommitPublished = listOf(revokedCommitPublished)
                )
            }
            Pair(nextState, buildList {
                add(ChannelAction.Storage.StoreState(nextState))
                addAll(revokedCommitPublished.run { doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()) })
                add(ChannelAction.Message.Send(error))
                add(ChannelAction.Storage.GetHtlcInfos(revokedCommitPublished.commitTx.txid, commitmentNumber))
            })
        } ?: run {
            when (this@ChannelStateWithCommitments) {
                is WaitForRemotePublishFutureCommitment -> {
                    logger.warning { "they published their future commit (because we asked them to) in txid=${tx.txid}" }
                    val remoteCommitPublished = claimRemoteCommitMainOutput(channelKeys(), commitments.params, tx, currentOnChainFeerates().claimMainFeerate)
                    val nextState = Closing(
                        commitments = commitments,
                        waitingSinceBlock = currentBlockHeight.toLong(),
                        futureRemoteCommitPublished = remoteCommitPublished
                    )
                    Pair(nextState, buildList {
                        add(ChannelAction.Storage.StoreState(nextState))
                        addAll(remoteCommitPublished.run { doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()) })
                    })
                }
                else -> {
                    // Our peer may publish an alternative version of their commitment using a different feerate.
                    when (val remoteCommit = Commitments.alternativeFeerateCommits(commitments, channelKeys()).find { it.txid == tx.txid }) {
                        null -> {
                            logger.warning { "unrecognized tx=${tx.txid}" }
                            // This can happen if the user has two devices.
                            // - user creates a wallet on device #1
                            // - user restores the same wallet on device #2
                            // - user does a splice on device #2
                            // - user starts wallet on device #1
                            // The wallet on device #1 has a previous version of the channel, it is not aware of the splice tx. It won't be able
                            // to recognize the tx when the watcher notifies that the (old) funding tx was spent.
                            // However, there is a race with the reconnection logic, because then the device #1 will recover its latest state from the
                            // remote backup.
                            // So, the best thing to do here is to ignore the spending tx.
                            Pair(this@ChannelStateWithCommitments, listOf())
                        }
                        else -> {
                            logger.warning { "they published an alternative commitment with feerate=${remoteCommit.spec.feerate} txid=${tx.txid}" }
                            val remoteCommitPublished = claimRemoteCommitMainOutput(channelKeys(), commitments.params, tx, currentOnChainFeerates().claimMainFeerate)
                            val nextState = when (this@ChannelStateWithCommitments) {
                                is Closing -> this@ChannelStateWithCommitments.copy(remoteCommitPublished = remoteCommitPublished)
                                is Negotiating -> Closing(commitments, waitingSinceBlock = currentBlockHeight.toLong(), mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx }, remoteCommitPublished = remoteCommitPublished)
                                else -> Closing(commitments, waitingSinceBlock = currentBlockHeight.toLong(), remoteCommitPublished = remoteCommitPublished)
                            }
                            return Pair(nextState, buildList {
                                add(ChannelAction.Storage.StoreState(nextState))
                                addAll(remoteCommitPublished.run { doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()) })
                            })
                        }
                    }
                }
            }
        }
    }

    internal suspend fun ChannelContext.spendLocalCurrent(): Pair<ChannelStateWithCommitments, List<ChannelAction>> {
        val outdatedCommitment = when (this@ChannelStateWithCommitments) {
            is WaitForRemotePublishFutureCommitment -> true
            is Closing -> this@ChannelStateWithCommitments.futureRemoteCommitPublished != null
            else -> false
        }

        return if (outdatedCommitment) {
            logger.warning { "we have an outdated commitment: will not publish our local tx" }
            Pair(this@ChannelStateWithCommitments, listOf())
        } else {
            val commitTx = commitments.latest.localCommit.publishableTxs.commitTx.tx
            val localCommitPublished = claimCurrentLocalCommitTxOutputs(
                channelKeys(),
                commitments.latest,
                commitTx,
                currentOnChainFeerates()
            )
            val nextState = when (this@ChannelStateWithCommitments) {
                is Closing -> copy(localCommitPublished = localCommitPublished)
                is Negotiating -> Closing(
                    commitments = commitments,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                    localCommitPublished = localCommitPublished
                )
                else -> Closing(
                    commitments = commitments,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    localCommitPublished = localCommitPublished
                )
            }

            Pair(nextState, buildList {
                add(ChannelAction.Storage.StoreState(nextState))
                addAll(localCommitPublished.run { doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()) })
            })
        }
    }

    /**
     * Check HTLC timeout in our commitment and our remote's.
     * If HTLCs are at risk, we will publish our local commitment and close the channel.
     */
    internal suspend fun ChannelContext.checkHtlcTimeout(): Pair<ChannelStateWithCommitments, List<ChannelAction>> {
        logger.info { "checking htlcs timeout at blockHeight=${currentBlockHeight}" }
        val timedOutOutgoing = commitments.timedOutOutgoingHtlcs(currentBlockHeight.toLong())
        val almostTimedOutIncoming = commitments.almostTimedOutIncomingHtlcs(currentBlockHeight.toLong(), staticParams.nodeParams.fulfillSafetyBeforeTimeoutBlocks)
        val channelEx: ChannelException? = when {
            timedOutOutgoing.isNotEmpty() -> HtlcsTimedOutDownstream(channelId, timedOutOutgoing)
            almostTimedOutIncoming.isNotEmpty() -> FulfilledHtlcsWillTimeout(channelId, almostTimedOutIncoming)
            else -> null
        }
        return when (channelEx) {
            null -> Pair(this@ChannelStateWithCommitments, listOf())
            else -> {
                logger.error { channelEx.message }
                when {
                    this@ChannelStateWithCommitments is Closing -> Pair(this@ChannelStateWithCommitments, listOf()) // nothing to do, there is already a spending tx published
                    this@ChannelStateWithCommitments is Negotiating && this@ChannelStateWithCommitments.bestUnpublishedClosingTx != null -> {
                        val nexState = Closing(
                            commitments,
                            waitingSinceBlock = currentBlockHeight.toLong(),
                            mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                            mutualClosePublished = listOfNotNull(bestUnpublishedClosingTx)
                        )
                        Pair(nexState, buildList {
                            add(ChannelAction.Storage.StoreState(nexState))
                            addAll(doPublish(bestUnpublishedClosingTx, nexState.channelId))
                        })
                    }
                    else -> {
                        val error = Error(channelId, channelEx.message)
                        spendLocalCurrent().run { copy(second = second + ChannelAction.Message.Send(error)) }
                    }
                }
            }
        }
    }

    // in Normal and Shutdown we aggregate sigs for splices before processing
    var sigStash = emptyList<CommitSig>()

    /** For splices we will send one commit_sig per active commitments. */
    internal fun ChannelContext.aggregateSigs(commit: CommitSig): List<CommitSig>? {
        sigStash = sigStash + commit
        logger.debug { "received sig for batch of size=${commit.batchSize}" }
        return if (sigStash.size == commit.batchSize) {
            val sigs = sigStash
            sigStash = emptyList()
            sigs
        } else {
            null
        }
    }
}

object Channel {
    // https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#requirements
    const val MAX_ACCEPTED_HTLCS = 483

    // We may need to rely on our peer's commit tx in certain cases (backup/restore) so we must ensure their transactions
    // can propagate through the bitcoin network (assuming bitcoin core nodes with default policies).
    // The various dust limits enforced by the bitcoin network are summarized here:
    // https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#dust-limits
    // A dust limit of 354 sat ensures all segwit outputs will relay with default relay policies.
    val MIN_DUST_LIMIT = 354.sat

    // we won't exchange more than this many signatures when negotiating the closing fee
    const val MAX_NEGOTIATION_ITERATIONS = 20

    // this is defined in BOLT 11
    val MIN_CLTV_EXPIRY_DELTA = CltvExpiryDelta(18)
    val MAX_CLTV_EXPIRY_DELTA = CltvExpiryDelta(2 * 7 * 144) // two weeks

    // since BOLT 1.1, there is a max value for the refund delay of the main commitment tx
    val MAX_TO_SELF_DELAY = CltvExpiryDelta(2016)
}
