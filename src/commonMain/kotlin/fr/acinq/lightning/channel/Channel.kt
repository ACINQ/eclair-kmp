package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.lightning.*
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.channel.Channel.ANNOUNCEMENTS_MINCONF
import fr.acinq.lightning.channel.Channel.FUNDING_TIMEOUT_FUNDEE_BLOCK
import fr.acinq.lightning.channel.Channel.MAX_NEGOTIATION_ITERATIONS
import fr.acinq.lightning.channel.Channel.handleSync
import fr.acinq.lightning.channel.Helpers.Closing.extractPreimages
import fr.acinq.lightning.channel.Helpers.Closing.onChainOutgoingHtlcs
import fr.acinq.lightning.channel.Helpers.Closing.overriddenOutgoingHtlcs
import fr.acinq.lightning.channel.Helpers.Closing.timedOutHtlcs
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.crypto.ShaChain
import fr.acinq.lightning.db.ChannelClosingType
import fr.acinq.lightning.router.Announcements
import fr.acinq.lightning.serialization.Serialization
import fr.acinq.lightning.transactions.CommitmentSpec
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.ClosingTx
import fr.acinq.lightning.transactions.outgoings
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import org.kodein.log.Logger

/*
 * Channel is implemented as a finite state machine
 * Its main method is (State, Event) -> (State, List<Action>)
 */

/** Channel Events (inputs to be fed to the state machine). */
sealed class ChannelEvent {
    data class InitFunder(
        val temporaryChannelId: ByteVector32,
        val fundingAmount: Satoshi,
        val pushAmount: MilliSatoshi,
        val initialFeerate: FeeratePerKw,
        val fundingTxFeerate: FeeratePerKw,
        val localParams: LocalParams,
        val remoteInit: Init,
        val channelFlags: Byte,
        val channelVersion: ChannelVersion,
        val channelOrigin: ChannelOrigin? = null
    ) : ChannelEvent() {
        init {
            require(channelVersion.hasStaticRemotekey) { "channel version $channelVersion is invalid (static_remote_key is not set)" }
            require(channelVersion.hasAnchorOutputs) { "invalid channel version $channelVersion (anchor_outputs is not set)" }
        }
    }

    data class InitFundee(val temporaryChannelId: ByteVector32, val localParams: LocalParams, val remoteInit: Init) : ChannelEvent()
    data class Restore(val state: ChannelState) : ChannelEvent()
    object CheckHtlcTimeout : ChannelEvent()
    data class MessageReceived(val message: LightningMessage) : ChannelEvent()
    data class WatchReceived(val watch: WatchEvent) : ChannelEvent()
    data class ExecuteCommand(val command: Command) : ChannelEvent()
    data class MakeFundingTxResponse(val fundingTx: Transaction, val fundingTxOutputIndex: Int, val fee: Satoshi) : ChannelEvent()
    data class GetFundingTxResponse(val getTxResponse: GetTxWithMetaResponse) : ChannelEvent()
    data class GetHtlcInfosResponse(val revokedCommitTxId: ByteVector32, val htlcInfos: List<ChannelAction.Storage.HtlcInfo>) : ChannelEvent()
    data class NewBlock(val height: Int, val Header: BlockHeader) : ChannelEvent()
    data class SetOnChainFeerates(val feerates: OnChainFeerates) : ChannelEvent()
    object Disconnected : ChannelEvent()
    data class Connected(val localInit: Init, val remoteInit: Init) : ChannelEvent()
}

/** Channel Actions (outputs produced by the state machine). */
sealed class ChannelAction {

    data class ProcessLocalError(val error: Throwable, val trigger: ChannelEvent) : ChannelAction()

    sealed class Message : ChannelAction() {
        data class Send(val message: LightningMessage) : Message()
        data class SendToSelf(val command: Command) : Message()
    }

    sealed class ChannelId : ChannelAction() {
        data class IdAssigned(val remoteNodeId: PublicKey, val temporaryChannelId: ByteVector32, val channelId: ByteVector32) : ChannelId()
        data class IdSwitch(val oldChannelId: ByteVector32, val newChannelId: ByteVector32) : ChannelId()
    }

    sealed class Blockchain : ChannelAction() {
        data class MakeFundingTx(val pubkeyScript: ByteVector, val amount: Satoshi, val feerate: FeeratePerKw) : Blockchain()
        data class SendWatch(val watch: Watch) : Blockchain()
        data class PublishTx(val tx: Transaction) : Blockchain()
        data class GetFundingTx(val txid: ByteVector32) : Blockchain()
    }

    sealed class Storage : ChannelAction() {
        data class StoreState(val data: ChannelStateWithCommitments) : Storage()
        data class HtlcInfo(val channelId: ByteVector32, val commitmentNumber: Long, val paymentHash: ByteVector32, val cltvExpiry: CltvExpiry)
        data class StoreHtlcInfos(val htlcs: List<HtlcInfo>) : Storage()
        data class GetHtlcInfos(val revokedCommitTxId: ByteVector32, val commitmentNumber: Long) : Storage()
        data class StoreIncomingAmount(val amount: MilliSatoshi, val origin: ChannelOrigin?) : Storage()
        data class StoreChannelClosing(val amount: MilliSatoshi, val closingAddress: String, val isSentToDefaultAddress: Boolean) : Storage()
        data class StoreChannelClosed(val txids: List<ByteVector32>, val claimed: Satoshi, val closingType: ChannelClosingType) : Storage()
    }

    data class ProcessIncomingHtlc(val add: UpdateAddHtlc) : ChannelAction()

    /**
     * Process the result of executing a given command.
     * [[CMD_ADD_HTLC]] has a special treatment: there are two response patterns for this command:
     *  - either [[ProcessCmdRes.AddFailed]] immediately
     *  - or [[ProcessCmdRes.AddSettledFail]] / [[ProcessCmdRes.AddSettledFulfill]] (usually a while later)
     */
    sealed class ProcessCmdRes : ChannelAction() {
        data class NotExecuted(val cmd: Command, val t: ChannelException) : ProcessCmdRes()
        data class AddSettledFulfill(val paymentId: UUID, val htlc: UpdateAddHtlc, val result: HtlcResult.Fulfill) : ProcessCmdRes()
        data class AddSettledFail(val paymentId: UUID, val htlc: UpdateAddHtlc, val result: HtlcResult.Fail) : ProcessCmdRes()
        data class AddFailed(val cmd: CMD_ADD_HTLC, val error: ChannelException, val channelUpdate: ChannelUpdate?) : ProcessCmdRes() {
            override fun toString() = "cannot add htlc with paymentId=${cmd.paymentId} reason=${error.message}"
        }
    }

    sealed class HtlcResult {
        sealed class Fulfill : HtlcResult() {
            abstract val paymentPreimage: ByteVector32

            data class OnChainFulfill(override val paymentPreimage: ByteVector32) : Fulfill()
            data class RemoteFulfill(val fulfill: UpdateFulfillHtlc) : Fulfill() {
                override val paymentPreimage = fulfill.paymentPreimage
            }
        }

        sealed class Fail : HtlcResult() {
            data class RemoteFail(val fail: UpdateFailHtlc) : Fail()
            data class RemoteFailMalformed(val fail: UpdateFailMalformedHtlc) : Fail()
            data class OnChainFail(val cause: ChannelException) : Fail()
            data class Disconnected(val channelUpdate: ChannelUpdate) : Fail()
        }
    }
}

/** Channel static parameters. */
data class StaticParams(val nodeParams: NodeParams, val remoteNodeId: PublicKey)

/** Channel state. */
sealed class ChannelState {
    abstract val staticParams: StaticParams
    abstract val currentTip: Pair<Int, BlockHeader>
    abstract val currentOnChainFeerates: OnChainFeerates
    val currentBlockHeight: Int get() = currentTip.first
    val keyManager: KeyManager get() = staticParams.nodeParams.keyManager
    val privateKey: PrivateKey get() = staticParams.nodeParams.nodePrivateKey

    val logger by lightningLogger()

    /**
     * @param event input event (for example, a message was received, a command was sent by the GUI/API, etc)
     * @return a (new state, list of actions) pair
     */
    abstract fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>>

    fun process(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return try {
            val (newState, actions) = processInternal(event)
            val oldState = when (this) {
                is Offline -> this.state
                is Syncing -> this.state
                else -> this
            }
            val actions1 = when {
                oldState is WaitForFundingCreated && newState is WaitForFundingConfirmed -> {
                    actions + ChannelAction.Storage.StoreIncomingAmount(oldState.pushAmount, oldState.channelOrigin)
                }
                // we only want to fire the PaymentSent event when we transition to Closing for the first time
                oldState is WaitForInit && newState is Closing -> actions
                oldState is Closing && newState is Closing -> actions
                oldState is ChannelStateWithCommitments && newState is Closing -> {
                    val channelBalance = oldState.commitments.localCommit.spec.toLocal
                    if (channelBalance > 0.msat) {
                        val defaultScriptPubKey = oldState.commitments.localParams.defaultFinalScriptPubKey
                        val localShutdown = when (this) {
                            is Normal -> this.localShutdown
                            is Negotiating -> this.localShutdown
                            is ShuttingDown -> this.localShutdown
                            else -> null
                        }
                        if (localShutdown != null && localShutdown.scriptPubKey != defaultScriptPubKey) {
                            // Non-default output address
                            val btcAddr = Helpers.Closing.btcAddressFromScriptPubKey(
                                scriptPubKey = localShutdown.scriptPubKey,
                                chainHash = staticParams.nodeParams.chainHash
                            ) ?: "unknown"
                            actions + ChannelAction.Storage.StoreChannelClosing(
                                amount = channelBalance,
                                closingAddress = btcAddr,
                                isSentToDefaultAddress = false
                            )
                        } else {
                            // Default output address
                            val btcAddr = Helpers.Closing.btcAddressFromScriptPubKey(
                                scriptPubKey = defaultScriptPubKey,
                                chainHash = staticParams.nodeParams.chainHash
                            ) ?: "unknown"
                            actions + ChannelAction.Storage.StoreChannelClosing(
                                amount = channelBalance,
                                closingAddress = btcAddr,
                                isSentToDefaultAddress = true
                            )
                        }
                    } else /* channelBalance <= 0.msat */ {
                        actions
                    }
                }
                else -> actions
            }
            val actions2 = newState.updateActions(actions1)
            Pair(newState, actions2)
        } catch (t: Throwable) {
            handleLocalError(event, t)
        }
    }

    abstract fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>>

    internal fun unhandled(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        logger.warning { "unhandled event ${event::class} in state ${this::class}" }
        return Pair(this, listOf())
    }

    /** Update outgoing messages to include an encrypted backup when necessary. */
    private fun updateActions(actions: List<ChannelAction>): List<ChannelAction> = when {
        this is ChannelStateWithCommitments && this.isZeroReserve -> actions.map {
            when {
                it is ChannelAction.Message.Send && it.message is FundingSigned -> it.copy(message = it.message.withChannelData(Serialization.encrypt(privateKey.value, this)))
                it is ChannelAction.Message.Send && it.message is CommitSig -> it.copy(message = it.message.withChannelData(Serialization.encrypt(privateKey.value, this)))
                it is ChannelAction.Message.Send && it.message is RevokeAndAck -> it.copy(message = it.message.withChannelData(Serialization.encrypt(privateKey.value, this)))
                it is ChannelAction.Message.Send && it.message is Shutdown -> it.copy(message = it.message.withChannelData(Serialization.encrypt(privateKey.value, this)))
                it is ChannelAction.Message.Send && it.message is ClosingSigned -> it.copy(message = it.message.withChannelData(Serialization.encrypt(privateKey.value, this)))
                else -> it
            }
        }
        else -> actions
    }

    internal fun handleCommandError(cmd: Command, error: ChannelException, channelUpdate: ChannelUpdate? = null): Pair<ChannelState, List<ChannelAction>> {
        logger.warning(error) { "c:${error.channelId} processing ${cmd::class} in state ${this::class} failed" }
        return when (cmd) {
            is CMD_ADD_HTLC -> Pair(this, listOf(ChannelAction.ProcessCmdRes.AddFailed(cmd, error, channelUpdate)))
            else -> Pair(this, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, error)))
        }
    }

    internal fun handleGetFundingTx(getTxResponse: GetTxWithMetaResponse, waitingSinceBlock: Long, fundingTx_opt: Transaction?): Pair<ChannelState, List<ChannelAction>> = when {
        getTxResponse.tx_opt != null -> Pair(this, emptyList()) // the funding tx exists, nothing to do
        fundingTx_opt != null -> {
            // if we are funder, we never give up
            logger.info { "republishing the funding tx..." }
            // TODO we should also check if the funding tx has been double-spent
            // see eclair-2.13 -> Channel.scala -> checkDoubleSpent(fundingTx)
            this to listOf(ChannelAction.Blockchain.PublishTx(fundingTx_opt))
        }
        (currentTip.first - waitingSinceBlock) > FUNDING_TIMEOUT_FUNDEE_BLOCK -> {
            // if we are fundee, we give up after some time
            handleFundingTimeout()
        }
        else -> {
            // let's wait a little longer
            logger.info { "funding tx still hasn't been published in ${currentTip.first - waitingSinceBlock} blocks, will wait ${(FUNDING_TIMEOUT_FUNDEE_BLOCK - currentTip.first + waitingSinceBlock)} more blocks..." }
            Pair(this, emptyList())
        }
    }

    internal fun handleFundingPublishFailed(): Pair<ChannelState, List<ChannelAction.Message.Send>> {
        require(this is ChannelStateWithCommitments) { "${this::class} must be of type HasCommitments" }
        logger.error { "c:$channelId failed to publish funding tx" }
        val exc = ChannelFundingError(channelId)
        val error = Error(channelId, exc.message)
        // NB: we don't use the handleLocalError handler because it would result in the commit tx being published, which we don't want:
        // implementation *guarantees* that in case of BITCOIN_FUNDING_PUBLISH_FAILED, the funding tx hasn't and will never be published, so we can close the channel right away
        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
    }

    private fun handleFundingTimeout(): Pair<ChannelState, List<ChannelAction.Message.Send>> {
        return when (this) {
            is ChannelStateWithCommitments -> this.handleFundingTimeout()
            is Offline -> this.state.handleFundingTimeout()
            is Syncing -> this.state.handleFundingTimeout()
            else -> error("${this::class} does not handle funding tx timeouts")
        }
    }

    internal fun doPublish(tx: ClosingTx, channelId: ByteVector32): List<ChannelAction.Blockchain> = listOf(
        ChannelAction.Blockchain.PublishTx(tx.tx),
        ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, tx.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(tx.tx)))
    )

    fun handleRemoteError(e: Error): Pair<ChannelState, List<ChannelAction>> {
        // see BOLT 1: only print out data verbatim if is composed of printable ASCII characters
        logger.error { "c:${e.channelId} peer sent error: ascii='${e.toAscii()}' bin=${e.data.toHex()}" }

        return when {
            this is Closing -> Pair(this, listOf()) // nothing to do, there is already a spending tx published
            this is Negotiating && this.bestUnpublishedClosingTx != null -> {
                val nexState = Closing(
                    staticParams = staticParams,
                    currentTip = currentTip,
                    currentOnChainFeerates = currentOnChainFeerates,
                    commitments = commitments,
                    fundingTx = null,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                    mutualClosePublished = listOfNotNull(bestUnpublishedClosingTx)
                )
                Pair(nexState, buildList {
                    add(ChannelAction.Storage.StoreState(nexState))
                    addAll(doPublish(bestUnpublishedClosingTx, nexState.channelId))
                })
            }
            // NB: we publish the commitment even if we have nothing at stake (in a dataloss situation our peer will send us an error just for that)
            this is ChannelStateWithCommitments -> this.spendLocalCurrent()
            // when there is no commitment yet, we just go to CLOSED state in case an error occurs
            else -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
        }
    }
}

sealed class ChannelStateWithCommitments : ChannelState() {
    abstract val commitments: Commitments
    val channelId: ByteVector32 get() = commitments.channelId
    val isFunder: Boolean get() = commitments.localParams.isFunder
    val isZeroReserve: Boolean get() = commitments.isZeroReserve

    abstract fun updateCommitments(input: Commitments): ChannelStateWithCommitments

    internal fun handleRemoteSpentCurrent(commitTx: Transaction): Pair<Closing, List<ChannelAction>> {
        logger.warning { "c:$channelId they published their current commit in txid=${commitTx.txid}" }
        require(commitTx.txid == commitments.remoteCommit.txid) { "txid mismatch" }

        val remoteCommitPublished = Helpers.Closing.claimRemoteCommitTxOutputs(keyManager, commitments, commitments.remoteCommit, commitTx, currentOnChainFeerates)

        val nextState = when (this) {
            is Closing -> this.copy(remoteCommitPublished = remoteCommitPublished)
            is Negotiating -> Closing(
                staticParams = staticParams,
                currentTip = currentTip,
                currentOnChainFeerates = currentOnChainFeerates,
                commitments = commitments,
                fundingTx = null,
                waitingSinceBlock = currentBlockHeight.toLong(),
                mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                remoteCommitPublished = remoteCommitPublished
            )
            is WaitForFundingConfirmed -> Closing(
                staticParams = staticParams,
                currentTip = currentTip,
                currentOnChainFeerates = currentOnChainFeerates,
                commitments = commitments,
                fundingTx = fundingTx,
                waitingSinceBlock = currentBlockHeight.toLong(),
                remoteCommitPublished = remoteCommitPublished
            )
            else -> Closing(
                staticParams = staticParams,
                currentTip = currentTip,
                currentOnChainFeerates = currentOnChainFeerates,
                commitments = commitments,
                fundingTx = null,
                waitingSinceBlock = currentBlockHeight.toLong(),
                remoteCommitPublished = remoteCommitPublished
            )
        }

        return Pair(nextState, buildList {
            add(ChannelAction.Storage.StoreState(nextState))
            addAll(remoteCommitPublished.doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()))
        })
    }

    internal fun handleRemoteSpentNext(commitTx: Transaction): Pair<ChannelState, List<ChannelAction>> {
        logger.warning { "c:$channelId they published their next commit in txid=${commitTx.txid}" }
        require(commitments.remoteNextCommitInfo.isLeft) { "next remote commit must be defined" }
        val remoteCommit = commitments.remoteNextCommitInfo.left?.nextRemoteCommit
        require(remoteCommit != null) { "remote commit must not be null" }
        require(commitTx.txid == remoteCommit.txid) { "txid mismatch" }

        val remoteCommitPublished = Helpers.Closing.claimRemoteCommitTxOutputs(keyManager, commitments, remoteCommit, commitTx, currentOnChainFeerates)

        val nextState = when (this) {
            is Closing -> copy(nextRemoteCommitPublished = remoteCommitPublished)
            is Negotiating -> Closing(
                staticParams = staticParams,
                currentTip = currentTip,
                currentOnChainFeerates = currentOnChainFeerates,
                commitments = commitments,
                fundingTx = null,
                waitingSinceBlock = currentBlockHeight.toLong(),
                mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                nextRemoteCommitPublished = remoteCommitPublished
            )
            // NB: if there is a next commitment, we can't be in WaitForFundingConfirmed so we don't have the case where fundingTx is defined
            else -> Closing(
                staticParams = staticParams,
                currentTip = currentTip,
                currentOnChainFeerates = currentOnChainFeerates,
                commitments = commitments,
                fundingTx = null,
                waitingSinceBlock = currentBlockHeight.toLong(),
                nextRemoteCommitPublished = remoteCommitPublished
            )
        }

        return Pair(nextState, buildList {
            add(ChannelAction.Storage.StoreState(nextState))
            addAll(remoteCommitPublished.doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()))
        })
    }

    internal fun handleRemoteSpentOther(tx: Transaction): Pair<ChannelState, List<ChannelAction>> {
        logger.warning { "c:$channelId funding tx spent in txid=${tx.txid}" }

        return Helpers.Closing.claimRevokedRemoteCommitTxOutputs(keyManager, commitments, tx, currentOnChainFeerates)?.let { (revokedCommitPublished, txNumber) ->
            logger.warning { "c:$channelId txid=${tx.txid} was a revoked commitment, publishing the penalty tx" }
            val ex = FundingTxSpent(channelId, tx)
            val error = Error(channelId, ex.message)

            val nextState = when (this) {
                is Closing -> if (this.revokedCommitPublished.contains(revokedCommitPublished)) {
                    this
                } else {
                    this.copy(revokedCommitPublished = this.revokedCommitPublished + revokedCommitPublished)
                }
                is Negotiating -> Closing(
                    staticParams = staticParams,
                    currentTip = currentTip,
                    currentOnChainFeerates = currentOnChainFeerates,
                    commitments = commitments,
                    fundingTx = null,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                    revokedCommitPublished = listOf(revokedCommitPublished)
                )
                // NB: if there is a next commitment, we can't be in WaitForFundingConfirmed so we don't have the case where fundingTx is defined
                else -> Closing(
                    staticParams = staticParams,
                    currentTip = currentTip,
                    commitments = commitments,
                    currentOnChainFeerates = currentOnChainFeerates,
                    fundingTx = null,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    revokedCommitPublished = listOf(revokedCommitPublished)
                )
            }

            return Pair(nextState, buildList {
                add(ChannelAction.Storage.StoreState(nextState))
                addAll(revokedCommitPublished.doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()))
                add(ChannelAction.Message.Send(error))
                add(ChannelAction.Storage.GetHtlcInfos(revokedCommitPublished.commitTx.txid, txNumber))
            })
        } ?: run {
            // the published tx was neither their current commitment nor a revoked one
            logger.error { "c:$channelId couldn't identify txid=${tx.txid}, something very bad is going on!!!" }
            Pair(ErrorInformationLeak(staticParams, currentTip, currentOnChainFeerates, commitments), listOf())
        }
    }

    internal fun spendLocalCurrent(): Pair<ChannelState, List<ChannelAction>> {
        val outdatedCommitment = when (this) {
            is WaitForRemotePublishFutureCommitment -> true
            is Closing -> this.futureRemoteCommitPublished != null
            else -> false
        }

        return if (outdatedCommitment) {
            logger.warning { "c:$channelId we have an outdated commitment: will not publish our local tx" }
            Pair(this as ChannelState, listOf())
        } else {
            val commitTx = commitments.localCommit.publishableTxs.commitTx.tx
            val localCommitPublished = Helpers.Closing.claimCurrentLocalCommitTxOutputs(
                keyManager,
                commitments,
                commitTx,
                currentOnChainFeerates
            )
            val nextState = when (this) {
                is Closing -> copy(localCommitPublished = localCommitPublished)
                is Negotiating -> Closing(
                    staticParams = staticParams,
                    currentTip = currentTip,
                    currentOnChainFeerates = currentOnChainFeerates,
                    commitments = commitments,
                    fundingTx = null,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
                    localCommitPublished = localCommitPublished
                )
                is WaitForFundingConfirmed -> Closing(
                    staticParams = staticParams, currentTip = currentTip,
                    currentOnChainFeerates = currentOnChainFeerates,
                    commitments = commitments,
                    fundingTx = fundingTx,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    localCommitPublished = localCommitPublished
                )
                else -> Closing(
                    staticParams = staticParams, currentTip = currentTip,
                    currentOnChainFeerates = currentOnChainFeerates,
                    commitments = commitments,
                    fundingTx = null,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    localCommitPublished = localCommitPublished
                )
            }

            Pair(nextState, buildList {
                add(ChannelAction.Storage.StoreState(nextState))
                addAll(localCommitPublished.doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()))
            })
        }
    }

    /**
     * Check HTLC timeout in our commitment and our remote's.
     * If HTLCs are at risk, we will publish our local commitment and close the channel.
     */
    internal fun checkHtlcTimeout(): Pair<ChannelState, List<ChannelAction>> {
        val timedOutOutgoing = commitments.timedOutOutgoingHtlcs(currentBlockHeight.toLong())
        val almostTimedOutIncoming = commitments.almostTimedOutIncomingHtlcs(currentBlockHeight.toLong(), staticParams.nodeParams.fulfillSafetyBeforeTimeoutBlocks)
        val channelEx: ChannelException? = when {
            timedOutOutgoing.isNotEmpty() -> HtlcsTimedOutDownstream(channelId, timedOutOutgoing)
            almostTimedOutIncoming.isNotEmpty() -> FulfilledHtlcsWillTimeout(channelId, almostTimedOutIncoming)
            else -> null
        }
        return when (channelEx) {
            null -> Pair(this, listOf())
            else -> {
                logger.error { "c:$channelId ${channelEx.message}" }
                when {
                    this is Closing -> Pair(this, listOf()) // nothing to do, there is already a spending tx published
                    this is Negotiating && this.bestUnpublishedClosingTx != null -> {
                        val nexState = Closing(
                            staticParams,
                            currentTip,
                            currentOnChainFeerates,
                            commitments,
                            fundingTx = null,
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
                        val (nextState, actions) = spendLocalCurrent()
                        Pair(nextState, buildList {
                            addAll(actions)
                            add(ChannelAction.Message.Send(error))
                        })
                    }
                }
            }
        }
    }

    fun handleFundingTimeout(): Pair<ChannelState, List<ChannelAction.Message.Send>> {
        logger.warning { "c:$channelId funding tx hasn't been confirmed in time, cancelling channel delay=$FUNDING_TIMEOUT_FUNDEE_BLOCK blocks" }
        val exc = FundingTxTimedout(channelId)
        val error = Error(channelId, exc.message)
        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
    }
}

data class WaitForInit(override val staticParams: StaticParams, override val currentTip: Pair<Int, BlockHeader>, override val currentOnChainFeerates: OnChainFeerates) : ChannelState() {
    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when {
            event is ChannelEvent.InitFundee -> {
                val nextState = WaitForOpenChannel(staticParams, currentTip, currentOnChainFeerates, event.temporaryChannelId, event.localParams, event.remoteInit)
                Pair(nextState, listOf())
            }
            event is ChannelEvent.InitFunder -> {
                val fundingPubKey = event.localParams.channelKeys.fundingPubKey
                val paymentBasepoint = event.localParams.channelKeys.paymentBasepoint
                val open = OpenChannel(
                    staticParams.nodeParams.chainHash,
                    temporaryChannelId = event.temporaryChannelId,
                    fundingSatoshis = event.fundingAmount,
                    pushMsat = event.pushAmount,
                    dustLimitSatoshis = event.localParams.dustLimit,
                    maxHtlcValueInFlightMsat = event.localParams.maxHtlcValueInFlightMsat,
                    channelReserveSatoshis = event.localParams.channelReserve,
                    htlcMinimumMsat = event.localParams.htlcMinimum,
                    feeratePerKw = event.initialFeerate,
                    toSelfDelay = event.localParams.toSelfDelay,
                    maxAcceptedHtlcs = event.localParams.maxAcceptedHtlcs,
                    fundingPubkey = fundingPubKey,
                    revocationBasepoint = event.localParams.channelKeys.revocationBasepoint,
                    paymentBasepoint = paymentBasepoint,
                    delayedPaymentBasepoint = event.localParams.channelKeys.delayedPaymentBasepoint,
                    htlcBasepoint = event.localParams.channelKeys.htlcBasepoint,
                    firstPerCommitmentPoint = keyManager.commitmentPoint(event.localParams.channelKeys.shaSeed, 0),
                    channelFlags = event.channelFlags,
                    // In order to allow TLV extensions and keep backwards-compatibility, we include an empty upfront_shutdown_script.
                    // See https://github.com/lightningnetwork/lightning-rfc/pull/714.
                    tlvStream = TlvStream(
                        buildList {
                            add(ChannelTlv.UpfrontShutdownScript(ByteVector.empty))
                            if (event.channelVersion.isSet(ChannelVersion.ZERO_RESERVE_BIT)) add(ChannelTlv.ChannelVersionTlv(event.channelVersion))
                            if (event.channelOrigin != null) add(ChannelTlv.ChannelOriginTlv(event.channelOrigin))
                        }
                    )
                )
                val nextState = WaitForAcceptChannel(staticParams, currentTip, currentOnChainFeerates, event, open)
                Pair(nextState, listOf(ChannelAction.Message.Send(open)))
            }
            event is ChannelEvent.Restore && event.state is Closing && event.state.commitments.nothingAtStake() -> {
                logger.info { "c:${event.state.channelId} we have nothing at stake, going straight to CLOSED" }
                Pair(Closed(event.state), listOf())
            }
            event is ChannelEvent.Restore && event.state is Closing -> {
                val closingType = event.state.closingTypeAlreadyKnown()
                logger.info { "c:${event.state.channelId} channel is closing (closing type = ${closingType?.let { it::class } ?: "unknown yet"})" }
                // if the closing type is known:
                // - there is no need to watch the funding tx because it has already been spent and the spending tx has
                //   already reached mindepth
                // - there is no need to attempt to publish transactions for other type of closes
                when (closingType) {
                    is MutualClose -> {
                        Pair(event.state, doPublish(closingType.tx, event.state.channelId))
                    }
                    is LocalClose -> {
                        val actions = closingType.localCommitPublished.doPublish(event.state.channelId, event.state.staticParams.nodeParams.minDepthBlocks.toLong())
                        Pair(event.state, actions)
                    }
                    is RemoteClose -> {
                        val actions = closingType.remoteCommitPublished.doPublish(event.state.channelId, event.state.staticParams.nodeParams.minDepthBlocks.toLong())
                        Pair(event.state, actions)
                    }
                    is RevokedClose -> {
                        val actions = closingType.revokedCommitPublished.doPublish(event.state.channelId, event.state.staticParams.nodeParams.minDepthBlocks.toLong())
                        Pair(event.state, actions)
                    }
                    is RecoveryClose -> {
                        val actions = closingType.remoteCommitPublished.doPublish(event.state.channelId, event.state.staticParams.nodeParams.minDepthBlocks.toLong())
                        Pair(event.state, actions)
                    }
                    null -> {
                        // in all other cases we need to be ready for any type of closing
                        val commitments = event.state.commitments
                        val actions = mutableListOf<ChannelAction>(
                            ChannelAction.Blockchain.SendWatch(
                                WatchSpent(
                                    event.state.channelId,
                                    commitments.commitInput.outPoint.txid,
                                    commitments.commitInput.outPoint.index.toInt(),
                                    commitments.commitInput.txOut.publicKeyScript,
                                    BITCOIN_FUNDING_SPENT
                                )
                            ),
                            //SendWatch(WatchLost(event.state.channelId, commitments.commitInput.outPoint.txid, event.state.staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_FUNDING_LOST))
                        )
                        val minDepth = event.state.staticParams.nodeParams.minDepthBlocks.toLong()
                        event.state.mutualClosePublished.forEach { actions.addAll(doPublish(it, event.state.channelId)) }
                        event.state.localCommitPublished?.run { actions.addAll(doPublish(event.state.channelId, minDepth)) }
                        event.state.remoteCommitPublished?.run { actions.addAll(doPublish(event.state.channelId, minDepth)) }
                        event.state.nextRemoteCommitPublished?.run { actions.addAll(doPublish(event.state.channelId, minDepth)) }
                        event.state.revokedCommitPublished.forEach { actions.addAll(it.doPublish(event.state.channelId, minDepth)) }
                        event.state.futureRemoteCommitPublished?.run { actions.addAll(doPublish(event.state.channelId, minDepth)) }
                        // if commitment number is zero, we also need to make sure that the funding tx has been published
                        if (commitments.localCommit.index == 0L && commitments.remoteCommit.index == 0L) {
                            actions.add(ChannelAction.Blockchain.GetFundingTx(commitments.commitInput.outPoint.txid))
                        }
                        Pair(event.state, actions)
                    }
                }
            }
            event is ChannelEvent.Restore && event.state is ChannelStateWithCommitments -> {
                logger.info { "c:${event.state.channelId} restoring channel" }
                val watchSpent = WatchSpent(
                    event.state.channelId,
                    event.state.commitments.commitInput.outPoint.txid,
                    event.state.commitments.commitInput.outPoint.index.toInt(),
                    event.state.commitments.commitInput.txOut.publicKeyScript,
                    BITCOIN_FUNDING_SPENT
                )
                val watchConfirmed = WatchConfirmed(
                    event.state.channelId,
                    event.state.commitments.commitInput.outPoint.txid,
                    event.state.commitments.commitInput.txOut.publicKeyScript,
                    staticParams.nodeParams.minDepthBlocks.toLong(),
                    BITCOIN_FUNDING_DEPTHOK
                )
                val actions = listOf(
                    ChannelAction.Blockchain.SendWatch(watchSpent),
                    ChannelAction.Blockchain.SendWatch(watchConfirmed),
                    ChannelAction.Blockchain.GetFundingTx(event.state.commitments.commitInput.outPoint.txid)
                )
                Pair(Offline(event.state), actions)
            }
            event is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            event is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            event is ChannelEvent.ExecuteCommand && event.command is CloseCommand -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "error on event ${event::class} in state ${this::class}" }
        return Pair(this, listOf(ChannelAction.ProcessLocalError(t, event)))
    }
}

data class Offline(val state: ChannelStateWithCommitments) : ChannelState() {
    override val staticParams: StaticParams get() = state.staticParams
    override val currentTip: Pair<Int, BlockHeader> get() = state.currentTip
    override val currentOnChainFeerates: OnChainFeerates get() = state.currentOnChainFeerates

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        logger.warning { "c:${state.channelId} offline processing ${event::class}" }
        return when {
            event is ChannelEvent.Connected -> {
                when {
                    state is WaitForRemotePublishFutureCommitment -> {
                        // they already proved that we have an outdated commitment
                        // there isn't much to do except asking them again to publish their current commitment by sending an error
                        val exc = PleasePublishYourCommitment(state.channelId)
                        val error = Error(state.channelId, exc.message)
                        val nextState = state.updateCommitments(state.commitments.updateFeatures(event.localInit, event.remoteInit))
                        Pair(nextState, listOf(ChannelAction.Message.Send(error)))
                    }
                    state.isZeroReserve -> {
                        logger.info { "c:${state.channelId} syncing ${state::class}, waiting fo their channelReestablish message" }
                        val nextState = state.updateCommitments(state.commitments.updateFeatures(event.localInit, event.remoteInit))
                        Pair(Syncing(nextState, true), listOf())
                    }
                    else -> {
                        val yourLastPerCommitmentSecret = state.commitments.remotePerCommitmentSecrets.lastIndex?.let { state.commitments.remotePerCommitmentSecrets.getHash(it) } ?: ByteVector32.Zeroes
                        val myCurrentPerCommitmentPoint = keyManager.commitmentPoint(state.commitments.localParams.channelKeys.shaSeed, state.commitments.localCommit.index)

                        val channelReestablish = ChannelReestablish(
                            channelId = state.channelId,
                            nextLocalCommitmentNumber = state.commitments.localCommit.index + 1,
                            nextRemoteRevocationNumber = state.commitments.remoteCommit.index,
                            yourLastCommitmentSecret = PrivateKey(yourLastPerCommitmentSecret),
                            myCurrentPerCommitmentPoint = myCurrentPerCommitmentPoint
                        ).withChannelData(state.commitments.remoteChannelData)
                        logger.info { "c:${state.channelId} syncing ${state::class}" }
                        val nextState = state.updateCommitments(state.commitments.updateFeatures(event.localInit, event.remoteInit))
                        Pair(Syncing(nextState, false), listOf(ChannelAction.Message.Send(channelReestablish)))
                    }
                }
            }
            event is ChannelEvent.WatchReceived -> {
                val watch = event.watch
                when {
                    watch is WatchEventSpent -> when {
                        state is Negotiating && state.closingTxProposed.flatten().any { it.unsignedTx.tx.txid == watch.tx.txid } -> {
                            logger.info { "c:${state.channelId} closing tx published: closingTxId=${watch.tx.txid}" }
                            val closingTx = state.getMutualClosePublished(watch.tx)
                            val nextState = Closing(
                                staticParams,
                                currentTip,
                                currentOnChainFeerates,
                                state.commitments,
                                fundingTx = null,
                                waitingSinceBlock = currentBlockHeight.toLong(),
                                mutualCloseProposed = state.closingTxProposed.flatten().map { it.unsignedTx },
                                mutualClosePublished = listOf(closingTx)
                            )
                            val actions = listOf(
                                ChannelAction.Storage.StoreState(nextState),
                                ChannelAction.Blockchain.PublishTx(watch.tx),
                                ChannelAction.Blockchain.SendWatch(WatchConfirmed(state.channelId, watch.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(watch.tx)))
                            )
                            Pair(nextState, actions)
                        }
                        watch.tx.txid == state.commitments.remoteCommit.txid -> state.handleRemoteSpentCurrent(watch.tx)
                        watch.tx.txid == state.commitments.remoteNextCommitInfo.left?.nextRemoteCommit?.txid -> state.handleRemoteSpentNext(watch.tx)
                        state is WaitForRemotePublishFutureCommitment -> state.handleRemoteSpentFuture(watch.tx)
                        else -> state.handleRemoteSpentOther(watch.tx)
                    }
                    watch is WatchEventConfirmed && (watch.event is BITCOIN_FUNDING_DEPTHOK || watch.event is BITCOIN_FUNDING_DEEPLYBURIED) -> {
                        // just ignore this, we will put a new watch when we reconnect, and we'll be notified again
                        Pair(this, listOf())
                    }
                    else -> unhandled(event)
                }
            }
            event is ChannelEvent.GetFundingTxResponse && state is WaitForFundingConfirmed && event.getTxResponse.txid == state.commitments.commitInput.outPoint.txid -> handleGetFundingTx(
                event.getTxResponse,
                state.waitingSinceBlock,
                state.fundingTx
            )
            event is ChannelEvent.CheckHtlcTimeout -> {
                val (newState, actions) = state.checkHtlcTimeout()
                when (newState) {
                    is Closing -> Pair(newState, actions)
                    is Closed -> Pair(newState, actions)
                    else -> Pair(Offline(newState as ChannelStateWithCommitments), actions)
                }
            }
            event is ChannelEvent.NewBlock -> {
                val (newState, actions) = state.process(event)
                when (newState) {
                    is Closing -> Pair(newState, actions)
                    is Closed -> Pair(newState, actions)
                    else -> Pair(Offline(newState as ChannelStateWithCommitments), actions)
                }
            }
            event is ChannelEvent.ExecuteCommand && event.command is CMD_FORCECLOSE -> {
                val (newState, actions) = state.process(event)
                when (newState) {
                    // NB: it doesn't make sense to try to send outgoing messages if we're offline.
                    is Closing -> Pair(newState, actions.filterNot { it is ChannelAction.Message.Send })
                    is Closed -> Pair(newState, actions.filterNot { it is ChannelAction.Message.Send })
                    else -> Pair(Offline(newState as ChannelStateWithCommitments), actions)
                }
            }
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:${state.channelId} error on event ${event::class} in state ${this::class}" }
        return Pair(this, listOf(ChannelAction.ProcessLocalError(t, event)))
    }
}

/**
 * waitForTheirReestablishMessage == true means that we want to wait until we've received their channel_reestablish message before
 * we send ours (for example, to extract encrypted backup data from extra fields)
 * waitForTheirReestablishMessage == false means that we've already sent our channel_reestablish message
 */
data class Syncing(val state: ChannelStateWithCommitments, val waitForTheirReestablishMessage: Boolean) : ChannelState() {
    override val staticParams: StaticParams get() = state.staticParams
    override val currentTip: Pair<Int, BlockHeader> get() = state.currentTip
    override val currentOnChainFeerates: OnChainFeerates get() = state.currentOnChainFeerates

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        logger.warning { "c:${state.channelId} syncing processing ${event::class}" }
        return when {
            event is ChannelEvent.MessageReceived && event.message is ChannelReestablish ->
                when {
                    waitForTheirReestablishMessage -> {
                        val nextState = if (!event.message.channelData.isEmpty()) {
                            logger.info { "c:${state.channelId} channel_reestablish includes a peer backup" }
                            when (val decrypted = runTrying { Serialization.decrypt(state.staticParams.nodeParams.nodePrivateKey.value, event.message.channelData, staticParams.nodeParams) }) {
                                is Try.Success -> {
                                    if (decrypted.get().commitments.isMoreRecent(state.commitments)) {
                                        logger.warning { "c:${state.channelId} they have a more recent commitment, using it instead" }
                                        decrypted.get()
                                    } else {
                                        logger.info { "c:${state.channelId} ignoring their older backup" }
                                        state
                                    }
                                }
                                is Try.Failure -> {
                                    logger.error(decrypted.error) { "c:${state.channelId} ignoring unreadable channel data" }
                                    state
                                }
                            }
                        } else {
                            state
                        }

                        val yourLastPerCommitmentSecret = nextState.commitments.remotePerCommitmentSecrets.lastIndex?.let { nextState.commitments.remotePerCommitmentSecrets.getHash(it) } ?: ByteVector32.Zeroes
                        val myCurrentPerCommitmentPoint = keyManager.commitmentPoint(state.commitments.localParams.channelKeys.shaSeed, nextState.commitments.localCommit.index)

                        val channelReestablish = ChannelReestablish(
                            channelId = nextState.channelId,
                            nextLocalCommitmentNumber = nextState.commitments.localCommit.index + 1,
                            nextRemoteRevocationNumber = nextState.commitments.remoteCommit.index,
                            yourLastCommitmentSecret = PrivateKey(yourLastPerCommitmentSecret),
                            myCurrentPerCommitmentPoint = myCurrentPerCommitmentPoint
                        ).withChannelData(nextState.commitments.remoteChannelData)
                        val actions = listOf<ChannelAction>(ChannelAction.Message.Send(channelReestablish))
                        // now apply their reestablish message to the restored state
                        val (nextState1, actions1) = Syncing(nextState, waitForTheirReestablishMessage = false).processInternal(event)
                        Pair(nextState1, actions + actions1)
                    }
                    state is WaitForFundingConfirmed -> {
                        val minDepth = if (state.commitments.localParams.isFunder) {
                            staticParams.nodeParams.minDepthBlocks
                        } else {
                            // when we're fundee we scale the min_depth confirmations depending on the funding amount
                            if (state.commitments.isZeroReserve) 0 else Helpers.minDepthForFunding(staticParams.nodeParams, state.commitments.commitInput.txOut.amount)
                        }
                        // we put back the watch (operation is idempotent) because the event may have been fired while we were in OFFLINE
                        val watchConfirmed = WatchConfirmed(
                            state.channelId,
                            state.commitments.commitInput.outPoint.txid,
                            state.commitments.commitInput.txOut.publicKeyScript,
                            minDepth.toLong(),
                            BITCOIN_FUNDING_DEPTHOK
                        )
                        val actions = listOf(ChannelAction.Blockchain.SendWatch(watchConfirmed))
                        Pair(state, actions)
                    }
                    state is WaitForFundingLocked -> {
                        logger.debug { "c:${state.channelId} re-sending fundingLocked" }
                        val nextPerCommitmentPoint = keyManager.commitmentPoint(state.commitments.localParams.channelKeys.shaSeed, 1)
                        val fundingLocked = FundingLocked(state.commitments.channelId, nextPerCommitmentPoint)
                        val actions = listOf(ChannelAction.Message.Send(fundingLocked))
                        Pair(state, actions)
                    }
                    state is Normal -> {
                        when {
                            !Helpers.checkLocalCommit(state.commitments, event.message.nextRemoteRevocationNumber) -> {
                                // if next_remote_revocation_number is greater than our local commitment index, it means that either we are using an outdated commitment, or they are lying
                                // but first we need to make sure that the last per_commitment_secret that they claim to have received from us is correct for that next_remote_revocation_number minus 1
                                if (keyManager.commitmentSecret(state.commitments.localParams.channelKeys.shaSeed, event.message.nextRemoteRevocationNumber - 1) == event.message.yourLastCommitmentSecret) {
                                    logger.warning { "c:${state.channelId} counterparty proved that we have an outdated (revoked) local commitment!!! ourCommitmentNumber=${state.commitments.localCommit.index} theirCommitmentNumber=${event.message.nextRemoteRevocationNumber}" }
                                    // their data checks out, we indeed seem to be using an old revoked commitment, and must absolutely *NOT* publish it, because that would be a cheating attempt and they
                                    // would punish us by taking all the funds in the channel
                                    val exc = PleasePublishYourCommitment(state.channelId)
                                    val error = Error(state.channelId, exc.message.encodeToByteArray().toByteVector())
                                    val nextState = WaitForRemotePublishFutureCommitment(staticParams, state.currentTip, state.currentOnChainFeerates, state.commitments, event.message)
                                    val actions = listOf(
                                        ChannelAction.Storage.StoreState(nextState),
                                        ChannelAction.Message.Send(error)
                                    )
                                    Pair(nextState, actions)
                                } else {
                                    logger.warning { "c:${state.channelId} they lied! the last per_commitment_secret they claimed to have received from us is invalid" }
                                    val exc = InvalidRevokedCommitProof(state.channelId, state.commitments.localCommit.index, event.message.nextRemoteRevocationNumber, event.message.yourLastCommitmentSecret)
                                    val error = Error(state.channelId, exc.message.encodeToByteArray().toByteVector())
                                    val (nextState, spendActions) = state.spendLocalCurrent()
                                    val actions = buildList {
                                        addAll(spendActions)
                                        add(ChannelAction.Message.Send(error))
                                    }
                                    Pair(nextState, actions)
                                }
                            }
                            !Helpers.checkRemoteCommit(state.commitments, event.message.nextLocalCommitmentNumber) -> {
                                // if next_local_commit_number is more than one more our remote commitment index, it means that either we are using an outdated commitment, or they are lying
                                logger.warning { "c:${state.channelId} counterparty says that they have a more recent commitment than the one we know of!!! ourCommitmentNumber=${state.commitments.remoteNextCommitInfo.left?.nextRemoteCommit?.index ?: state.commitments.remoteCommit.index} theirCommitmentNumber=${event.message.nextLocalCommitmentNumber}" }
                                // there is no way to make sure that they are saying the truth, the best thing to do is ask them to publish their commitment right now
                                // maybe they will publish their commitment, in that case we need to remember their commitment point in order to be able to claim our outputs
                                // not that if they don't comply, we could publish our own commitment (it is not stale, otherwise we would be in the case above)
                                val exc = PleasePublishYourCommitment(state.channelId)
                                val error = Error(state.channelId, exc.message.encodeToByteArray().toByteVector())
                                val nextState = WaitForRemotePublishFutureCommitment(staticParams, state.currentTip, state.currentOnChainFeerates, state.commitments, event.message)
                                val actions = listOf(
                                    ChannelAction.Storage.StoreState(nextState),
                                    ChannelAction.Message.Send(error)
                                )
                                Pair(nextState, actions)
                            }
                            else -> {
                                // normal case, our data is up-to-date
                                val actions = ArrayList<ChannelAction>()
                                if (event.message.nextLocalCommitmentNumber == 1L && state.commitments.localCommit.index == 0L) {
                                    // If next_local_commitment_number is 1 in both the channel_reestablish it sent and received, then the node MUST retransmit funding_locked, otherwise it MUST NOT
                                    logger.debug { "c:${state.channelId} re-sending fundingLocked" }
                                    val nextPerCommitmentPoint = keyManager.commitmentPoint(state.commitments.localParams.channelKeys.shaSeed, 1)
                                    val fundingLocked = FundingLocked(state.commitments.channelId, nextPerCommitmentPoint)
                                    actions.add(ChannelAction.Message.Send(fundingLocked))
                                }

                                try {
                                    val (commitments1, sendQueue1) = handleSync(event.message, state, keyManager, logger)
                                    actions.addAll(sendQueue1)

                                    // BOLT 2: A node if it has sent a previous shutdown MUST retransmit shutdown.
                                    state.localShutdown?.let {
                                        logger.debug { "c:${state.channelId} re-sending local shutdown" }
                                        actions.add(ChannelAction.Message.Send(it))
                                    }

                                    if (!state.buried) {
                                        // even if we were just disconnected/reconnected, we need to put back the watch because the event may have been
                                        // fired while we were in OFFLINE (if not, the operation is idempotent anyway)
                                        val watchConfirmed = WatchConfirmed(
                                            state.channelId,
                                            state.commitments.commitInput.outPoint.txid,
                                            state.commitments.commitInput.txOut.publicKeyScript,
                                            ANNOUNCEMENTS_MINCONF.toLong(),
                                            BITCOIN_FUNDING_DEEPLYBURIED
                                        )
                                        actions.add(ChannelAction.Blockchain.SendWatch(watchConfirmed))
                                    }

                                    logger.info { "c:${state.channelId} switching to ${state::class}" }
                                    Pair(state.copy(commitments = commitments1), actions)
                                } catch (e: RevocationSyncError) {
                                    val error = Error(state.channelId, e.message)
                                    state.spendLocalCurrent().run { copy(second = second + ChannelAction.Message.Send(error)) }
                                }
                            }
                        }
                    }
                    // BOLT 2: A node if it has sent a previous shutdown MUST retransmit shutdown.
                    // negotiation restarts from the beginning, and is initialized by the funder
                    // note: in any case we still need to keep all previously sent closing_signed, because they may publish one of them
                    state is Negotiating && state.commitments.localParams.isFunder -> {
                        // we could use the last closing_signed we sent, but network fees may have changed while we were offline so it is better to restart from scratch
                        val (closingTx, closingSigned) = Helpers.Closing.makeFirstClosingTx(
                            keyManager,
                            state.commitments,
                            state.localShutdown.scriptPubKey.toByteArray(),
                            state.remoteShutdown.scriptPubKey.toByteArray(),
                            state.closingFeerates ?: ClosingFeerates(currentOnChainFeerates.mutualCloseFeerate)
                        )
                        val closingTxProposed1 = state.closingTxProposed + listOf(listOf(ClosingTxProposed(closingTx, closingSigned)))
                        val nextState = state.copy(closingTxProposed = closingTxProposed1)
                        val actions = listOf(
                            ChannelAction.Storage.StoreState(nextState),
                            ChannelAction.Message.Send(state.localShutdown),
                            ChannelAction.Message.Send(closingSigned)
                        )
                        return Pair(nextState, actions)
                    }
                    state is Negotiating -> {
                        // we start a new round of negotiation
                        val closingTxProposed1 = if (state.closingTxProposed.last().isEmpty()) state.closingTxProposed else state.closingTxProposed + listOf(listOf())
                        val nextState = state.copy(closingTxProposed = closingTxProposed1)
                        val actions = listOf(
                            ChannelAction.Storage.StoreState(nextState),
                            ChannelAction.Message.Send(state.localShutdown)
                        )
                        return Pair(nextState, actions)
                    }
                    else -> unhandled(event)
                }
            event is ChannelEvent.WatchReceived -> {
                val watch = event.watch
                when {
                    watch is WatchEventSpent -> when {
                        state is Negotiating && state.closingTxProposed.flatten().any { it.unsignedTx.tx.txid == watch.tx.txid } -> {
                            logger.info { "c:${state.channelId} closing tx published: closingTxId=${watch.tx.txid}" }
                            val closingTx = state.getMutualClosePublished(watch.tx)
                            val nextState = Closing(
                                staticParams,
                                currentTip,
                                currentOnChainFeerates,
                                state.commitments,
                                fundingTx = null,
                                waitingSinceBlock = currentBlockHeight.toLong(),
                                mutualCloseProposed = state.closingTxProposed.flatten().map { it.unsignedTx },
                                mutualClosePublished = listOf(closingTx)
                            )
                            val actions = listOf(
                                ChannelAction.Storage.StoreState(nextState),
                                ChannelAction.Blockchain.PublishTx(watch.tx),
                                ChannelAction.Blockchain.SendWatch(WatchConfirmed(state.channelId, watch.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(watch.tx)))
                            )
                            Pair(nextState, actions)
                        }
                        watch.tx.txid == state.commitments.remoteCommit.txid -> state.handleRemoteSpentCurrent(watch.tx)
                        watch.tx.txid == state.commitments.remoteNextCommitInfo.left?.nextRemoteCommit?.txid -> state.handleRemoteSpentNext(watch.tx)
                        state is WaitForRemotePublishFutureCommitment -> state.handleRemoteSpentFuture(watch.tx)
                        else -> state.handleRemoteSpentOther(watch.tx)
                    }
                    watch is WatchEventConfirmed && (watch.event is BITCOIN_FUNDING_DEPTHOK || watch.event is BITCOIN_FUNDING_DEEPLYBURIED) -> {
                        // just ignore this, we will put a new watch when we reconnect, and we'll be notified again
                        Pair(this, listOf())
                    }
                    else -> unhandled(event)
                }
            }
            event is ChannelEvent.GetFundingTxResponse && state is WaitForFundingConfirmed && event.getTxResponse.txid == state.commitments.commitInput.outPoint.txid -> handleGetFundingTx(
                event.getTxResponse,
                state.waitingSinceBlock,
                state.fundingTx
            )
            event is ChannelEvent.CheckHtlcTimeout -> {
                val (newState, actions) = state.checkHtlcTimeout()
                when (newState) {
                    is Closing -> Pair(newState, actions)
                    is Closed -> Pair(newState, actions)
                    else -> Pair(Syncing(newState as ChannelStateWithCommitments, waitForTheirReestablishMessage), actions)
                }
            }
            event is ChannelEvent.NewBlock -> {
                val (newState, actions) = state.process(event)
                when (newState) {
                    is Closing -> Pair(newState, actions)
                    is Closed -> Pair(newState, actions)
                    else -> Pair(Syncing(newState as ChannelStateWithCommitments, waitForTheirReestablishMessage), actions)
                }
            }
            event is ChannelEvent.Disconnected -> Pair(Offline(state), listOf())
            event is ChannelEvent.ExecuteCommand && event.command is CMD_FORCECLOSE -> {
                val (newState, actions) = state.process(event)
                when (newState) {
                    is Closing -> Pair(newState, actions)
                    is Closed -> Pair(newState, actions)
                    else -> Pair(Syncing(newState as ChannelStateWithCommitments, waitForTheirReestablishMessage), actions)
                }
            }
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:${state.channelId} error on event ${event::class} in state ${this::class}" }
        return Pair(this, listOf(ChannelAction.ProcessLocalError(t, event)))
    }

}

data class WaitForRemotePublishFutureCommitment(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val remoteChannelReestablish: ChannelReestablish
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when {
            event is ChannelEvent.WatchReceived && event.watch is WatchEventSpent && event.watch.event is BITCOIN_FUNDING_SPENT -> handleRemoteSpentFuture(event.watch.tx)
            event is ChannelEvent.Disconnected -> Pair(Offline(this), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:${commitments.channelId} error on event ${event::class} in state ${this::class}" }
        val error = Error(channelId, t.message)
        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
    }

    internal fun handleRemoteSpentFuture(tx: Transaction): Pair<ChannelState, List<ChannelAction>> {
        logger.warning { "c:${commitments.channelId} they published their future commit (because we asked them to) in txid=${tx.txid}" }
        val remoteCommitPublished = Helpers.Closing.claimRemoteCommitMainOutput(
            keyManager,
            commitments,
            tx,
            currentOnChainFeerates.claimMainFeerate
        )
        val nextState = Closing(
            staticParams = staticParams,
            currentTip = currentTip,
            commitments = commitments,
            currentOnChainFeerates = currentOnChainFeerates,
            fundingTx = null,
            waitingSinceBlock = currentBlockHeight.toLong(),
            futureRemoteCommitPublished = remoteCommitPublished
        )
        val actions = mutableListOf<ChannelAction>(ChannelAction.Storage.StoreState(nextState))
        actions.addAll(remoteCommitPublished.doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()))
        return Pair(nextState, actions)
    }
}

data class WaitForOpenChannel(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    val temporaryChannelId: ByteVector32,
    val localParams: LocalParams,
    val remoteInit: Init
) : ChannelState() {
    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when {
            event is ChannelEvent.MessageReceived ->
                when (event.message) {
                    is OpenChannel -> {
                        require(Features.canUseFeature(localParams.features, Features.invoke(remoteInit.features), Feature.StaticRemoteKey)) { "static_remote_key is not set" }
                        val channelVersion = event.message.channelVersion ?: ChannelVersion.STANDARD
                        require(channelVersion.hasStaticRemotekey) { "invalid channel version $channelVersion (static_remote_key is not set)" }
                        require(channelVersion.hasAnchorOutputs) { "invalid channel version $channelVersion (anchor_outputs is not set)" }
                        when (val err = Helpers.validateParamsFundee(staticParams.nodeParams, event.message, channelVersion)) {
                            is Either.Left -> {
                                logger.error(err.value) { "c:$temporaryChannelId invalid ${event.message::class} in state ${this::class}" }
                                return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(Error(temporaryChannelId, err.value.message))))
                            }
                        }
                        val channelOrigin = event.message.tlvStream.records.filterIsInstance<ChannelTlv.ChannelOriginTlv>().firstOrNull()?.channelOrigin

                        val fundingPubkey = localParams.channelKeys.fundingPubKey
                        val minimumDepth = Helpers.minDepthForFunding(staticParams.nodeParams, event.message.fundingSatoshis)
                        val paymentBasepoint = localParams.channelKeys.paymentBasepoint
                        val accept = AcceptChannel(
                            temporaryChannelId = event.message.temporaryChannelId,
                            dustLimitSatoshis = localParams.dustLimit,
                            maxHtlcValueInFlightMsat = localParams.maxHtlcValueInFlightMsat,
                            channelReserveSatoshis = localParams.channelReserve,
                            minimumDepth = minimumDepth.toLong(),
                            htlcMinimumMsat = localParams.htlcMinimum,
                            toSelfDelay = localParams.toSelfDelay,
                            maxAcceptedHtlcs = localParams.maxAcceptedHtlcs,
                            fundingPubkey = fundingPubkey,
                            revocationBasepoint = localParams.channelKeys.revocationBasepoint,
                            paymentBasepoint = paymentBasepoint,
                            delayedPaymentBasepoint = localParams.channelKeys.delayedPaymentBasepoint,
                            htlcBasepoint = localParams.channelKeys.htlcBasepoint,
                            firstPerCommitmentPoint = keyManager.commitmentPoint(keyManager.channelKeyPath(localParams, channelVersion), 0),
                            // In order to allow TLV extensions and keep backwards-compatibility, we include an empty upfront_shutdown_script.
                            // See https://github.com/lightningnetwork/lightning-rfc/pull/714.
                            tlvStream = TlvStream(listOf(ChannelTlv.UpfrontShutdownScript(ByteVector.empty)))
                        )
                        val remoteParams = RemoteParams(
                            nodeId = staticParams.remoteNodeId,
                            dustLimit = event.message.dustLimitSatoshis,
                            maxHtlcValueInFlightMsat = event.message.maxHtlcValueInFlightMsat,
                            channelReserve = event.message.channelReserveSatoshis, // remote requires local to keep this much satoshis as direct payment
                            htlcMinimum = event.message.htlcMinimumMsat,
                            toSelfDelay = event.message.toSelfDelay,
                            maxAcceptedHtlcs = event.message.maxAcceptedHtlcs,
                            fundingPubKey = event.message.fundingPubkey,
                            revocationBasepoint = event.message.revocationBasepoint,
                            paymentBasepoint = event.message.paymentBasepoint,
                            delayedPaymentBasepoint = event.message.delayedPaymentBasepoint,
                            htlcBasepoint = event.message.htlcBasepoint,
                            features = Features.invoke(remoteInit.features)
                        )
                        val nextState = WaitForFundingCreated(
                            staticParams,
                            currentTip,
                            currentOnChainFeerates,
                            event.message.temporaryChannelId,
                            localParams,
                            remoteParams,
                            event.message.fundingSatoshis,
                            event.message.pushMsat,
                            event.message.feeratePerKw,
                            event.message.firstPerCommitmentPoint,
                            event.message.channelFlags,
                            channelVersion,
                            channelOrigin,
                            accept
                        )
                        Pair(nextState, listOf(ChannelAction.Message.Send(accept)))
                    }
                    is Error -> {
                        logger.error { "c:$temporaryChannelId peer sent error: ascii=${event.message.toAscii()} bin=${event.message.data.toHex()}" }
                        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
                    }
                    else -> unhandled(event)
                }
            event is ChannelEvent.ExecuteCommand && event.command is CloseCommand -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            event is ChannelEvent.CheckHtlcTimeout -> Pair(this, listOf())
            event is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            event is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$temporaryChannelId error on event ${event::class} in state ${this::class}" }
        val error = Error(temporaryChannelId, t.message)
        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
    }
}

data class WaitForFundingCreated(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    val temporaryChannelId: ByteVector32,
    val localParams: LocalParams,
    val remoteParams: RemoteParams,
    val fundingAmount: Satoshi,
    val pushAmount: MilliSatoshi,
    val initialFeerate: FeeratePerKw,
    val remoteFirstPerCommitmentPoint: PublicKey,
    val channelFlags: Byte,
    val channelVersion: ChannelVersion,
    val channelOrigin: ChannelOrigin?,
    val lastSent: AcceptChannel
) : ChannelState() {
    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when {
            event is ChannelEvent.MessageReceived ->
                when (event.message) {
                    is FundingCreated -> {
                        // they fund the channel with their funding tx, so the money is theirs (but we are paid pushMsat)
                        val firstCommitTxRes = Helpers.Funding.makeFirstCommitTxs(
                            keyManager,
                            temporaryChannelId,
                            localParams,
                            remoteParams,
                            fundingAmount,
                            pushAmount,
                            initialFeerate,
                            event.message.fundingTxid,
                            event.message.fundingOutputIndex,
                            remoteFirstPerCommitmentPoint
                        )
                        when (firstCommitTxRes) {
                            is Either.Left -> {
                                logger.error(firstCommitTxRes.value) { "c:$temporaryChannelId cannot create first commit tx" }
                                handleLocalError(event, firstCommitTxRes.value)
                            }
                            is Either.Right -> {
                                val firstCommitTx = firstCommitTxRes.value
                                // check remote signature validity
                                val fundingPubKey = localParams.channelKeys.fundingPubKey
                                val localSigOfLocalTx = keyManager.sign(firstCommitTx.localCommitTx, localParams.channelKeys.fundingPrivateKey)
                                val signedLocalCommitTx = Transactions.addSigs(
                                    firstCommitTx.localCommitTx,
                                    fundingPubKey,
                                    remoteParams.fundingPubKey,
                                    localSigOfLocalTx,
                                    event.message.signature
                                )
                                when (val result = Transactions.checkSpendable(signedLocalCommitTx)) {
                                    is Try.Failure -> {
                                        logger.error(result.error) { "c:$temporaryChannelId their first commit sig is not valid for ${firstCommitTx.localCommitTx.tx}" }
                                        handleLocalError(event, result.error)
                                    }
                                    is Try.Success -> {
                                        val localSigOfRemoteTx = keyManager.sign(firstCommitTx.remoteCommitTx, localParams.channelKeys.fundingPrivateKey)
                                        val channelId = Lightning.toLongId(event.message.fundingTxid, event.message.fundingOutputIndex)
                                        // watch the funding tx transaction
                                        val commitInput = firstCommitTx.localCommitTx.input
                                        val fundingSigned = FundingSigned(channelId, localSigOfRemoteTx)
                                        val commitments = Commitments(
                                            channelVersion,
                                            localParams,
                                            remoteParams,
                                            channelFlags,
                                            LocalCommit(0, firstCommitTx.localSpec, PublishableTxs(signedLocalCommitTx, listOf())),
                                            RemoteCommit(0, firstCommitTx.remoteSpec, firstCommitTx.remoteCommitTx.tx.txid, remoteFirstPerCommitmentPoint),
                                            LocalChanges(listOf(), listOf(), listOf()),
                                            RemoteChanges(listOf(), listOf(), listOf()),
                                            localNextHtlcId = 0L,
                                            remoteNextHtlcId = 0L,
                                            payments = mapOf(),
                                            remoteNextCommitInfo = Either.Right(Lightning.randomKey().publicKey()), // we will receive their next per-commitment point in the next message, so we temporarily put a random byte array
                                            commitInput,
                                            ShaChain.init,
                                            channelId = channelId
                                        )
                                        // NB: we don't send a ChannelSignatureSent for the first commit
                                        logger.info { "c:$channelId waiting for them to publish the funding tx with fundingTxid=${commitInput.outPoint.txid}" }
                                        // phoenix channels have a zero mindepth for funding tx
                                        val fundingMinDepth = if (commitments.isZeroReserve) 0 else Helpers.minDepthForFunding(staticParams.nodeParams, fundingAmount)
                                        logger.info { "c:$channelId will wait for $fundingMinDepth confirmations" }
                                        val watchSpent = WatchSpent(channelId, commitInput.outPoint.txid, commitInput.outPoint.index.toInt(), commitments.commitInput.txOut.publicKeyScript, BITCOIN_FUNDING_SPENT)
                                        val watchConfirmed = WatchConfirmed(channelId, commitInput.outPoint.txid, commitments.commitInput.txOut.publicKeyScript, fundingMinDepth.toLong(), BITCOIN_FUNDING_DEPTHOK)
                                        val nextState = WaitForFundingConfirmed(
                                            staticParams,
                                            currentTip,
                                            currentOnChainFeerates,
                                            commitments,
                                            null,
                                            currentBlockHeight.toLong(),
                                            null,
                                            Either.Right(fundingSigned)
                                        )
                                        val actions = listOf(
                                            ChannelAction.Blockchain.SendWatch(watchSpent),
                                            ChannelAction.Blockchain.SendWatch(watchConfirmed),
                                            ChannelAction.Message.Send(fundingSigned),
                                            ChannelAction.ChannelId.IdSwitch(temporaryChannelId, channelId),
                                            ChannelAction.Storage.StoreState(nextState)
                                        )
                                        Pair(nextState, actions)
                                    }
                                }
                            }
                        }
                    }
                    is Error -> {
                        logger.error { "c:$temporaryChannelId peer sent error: ascii=${event.message.toAscii()} bin=${event.message.data.toHex()}" }
                        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
                    }
                    else -> unhandled(event)
                }
            event is ChannelEvent.ExecuteCommand && event.command is CloseCommand -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            event is ChannelEvent.CheckHtlcTimeout -> Pair(this, listOf())
            event is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            event is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$temporaryChannelId error on event ${event::class} in state ${this::class}" }
        val error = Error(temporaryChannelId, t.message)
        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
    }
}

data class WaitForAcceptChannel(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    val initFunder: ChannelEvent.InitFunder,
    val lastSent: OpenChannel
) : ChannelState() {
    private val temporaryChannelId: ByteVector32 get() = lastSent.temporaryChannelId

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when {
            event is ChannelEvent.MessageReceived && event.message is AcceptChannel -> {
                when (val err = Helpers.validateParamsFunder(staticParams.nodeParams, lastSent, event.message)) {
                    is Either.Left -> {
                        logger.error(err.value) { "c:$temporaryChannelId invalid ${event.message::class} in state ${this::class}" }
                        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(Error(initFunder.temporaryChannelId, err.value.message))))
                    }
                }
                val remoteParams = RemoteParams(
                    nodeId = staticParams.remoteNodeId,
                    dustLimit = event.message.dustLimitSatoshis,
                    maxHtlcValueInFlightMsat = event.message.maxHtlcValueInFlightMsat,
                    channelReserve = event.message.channelReserveSatoshis, // remote requires local to keep this much satoshis as direct payment
                    htlcMinimum = event.message.htlcMinimumMsat,
                    toSelfDelay = event.message.toSelfDelay,
                    maxAcceptedHtlcs = event.message.maxAcceptedHtlcs,
                    fundingPubKey = event.message.fundingPubkey,
                    revocationBasepoint = event.message.revocationBasepoint,
                    paymentBasepoint = event.message.paymentBasepoint,
                    delayedPaymentBasepoint = event.message.delayedPaymentBasepoint,
                    htlcBasepoint = event.message.htlcBasepoint,
                    features = Features(initFunder.remoteInit.features)
                )
                val localFundingPubkey = initFunder.localParams.channelKeys.fundingPubKey
                val fundingPubkeyScript = ByteVector(Script.write(Script.pay2wsh(Scripts.multiSig2of2(localFundingPubkey, remoteParams.fundingPubKey))))
                val makeFundingTx = ChannelAction.Blockchain.MakeFundingTx(fundingPubkeyScript, initFunder.fundingAmount, initFunder.fundingTxFeerate)
                val nextState = WaitForFundingInternal(
                    staticParams,
                    currentTip,
                    currentOnChainFeerates,
                    initFunder.temporaryChannelId,
                    initFunder.localParams,
                    remoteParams,
                    initFunder.fundingAmount,
                    initFunder.pushAmount,
                    initFunder.initialFeerate,
                    event.message.firstPerCommitmentPoint,
                    initFunder.channelVersion,
                    lastSent
                )
                Pair(nextState, listOf(makeFundingTx))
            }
            event is ChannelEvent.MessageReceived && event.message is Error -> {
                logger.error { "c:$temporaryChannelId peer sent error: ascii=${event.message.toAscii()} bin=${event.message.data.toHex()}" }
                Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            }
            event is ChannelEvent.ExecuteCommand && event.command is CloseCommand -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            event is ChannelEvent.CheckHtlcTimeout -> Pair(this, listOf())
            event is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            event is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$temporaryChannelId error on event ${event::class} in state ${this::class}" }
        val error = Error(initFunder.temporaryChannelId, t.message)
        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
    }
}

data class WaitForFundingInternal(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    val temporaryChannelId: ByteVector32,
    val localParams: LocalParams,
    val remoteParams: RemoteParams,
    val fundingAmount: Satoshi,
    val pushAmount: MilliSatoshi,
    val initialFeerate: FeeratePerKw,
    val remoteFirstPerCommitmentPoint: PublicKey,
    val channelVersion: ChannelVersion,
    val lastSent: OpenChannel
) : ChannelState() {
    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when {
            event is ChannelEvent.MakeFundingTxResponse -> {
                // let's create the first commitment tx that spends the yet uncommitted funding tx
                val firstCommitTxRes = Helpers.Funding.makeFirstCommitTxs(
                    keyManager,
                    temporaryChannelId,
                    localParams,
                    remoteParams,
                    fundingAmount,
                    pushAmount,
                    initialFeerate,
                    event.fundingTx.hash,
                    event.fundingTxOutputIndex,
                    remoteFirstPerCommitmentPoint
                )
                when (firstCommitTxRes) {
                    is Either.Left -> {
                        logger.error(firstCommitTxRes.value) { "c:$temporaryChannelId cannot create first commit tx" }
                        handleLocalError(event, firstCommitTxRes.value)
                    }
                    is Either.Right -> {
                        val firstCommitTx = firstCommitTxRes.value
                        require(event.fundingTx.txOut[event.fundingTxOutputIndex].publicKeyScript == firstCommitTx.localCommitTx.input.txOut.publicKeyScript) { "pubkey script mismatch!" }
                        val localSigOfRemoteTx = keyManager.sign(firstCommitTx.remoteCommitTx, localParams.channelKeys.fundingPrivateKey)
                        // signature of their initial commitment tx that pays remote pushMsat
                        val fundingCreated = FundingCreated(
                            temporaryChannelId = temporaryChannelId,
                            fundingTxid = event.fundingTx.hash,
                            fundingOutputIndex = event.fundingTxOutputIndex,
                            signature = localSigOfRemoteTx
                        )
                        val channelId = Lightning.toLongId(event.fundingTx.hash, event.fundingTxOutputIndex)
                        val channelIdAssigned = ChannelAction.ChannelId.IdAssigned(staticParams.remoteNodeId, temporaryChannelId, channelId) // we notify the peer asap so it knows how to route messages
                        //context.system.eventStream.publish(ChannelIdAssigned(self, remoteNodeId, temporaryChannelId, channelId))
                        // NB: we don't send a ChannelSignatureSent for the first commit
                        val nextState = WaitForFundingSigned(
                            staticParams,
                            currentTip,
                            currentOnChainFeerates,
                            channelId,
                            localParams,
                            remoteParams,
                            event.fundingTx,
                            event.fee,
                            firstCommitTx.localSpec,
                            firstCommitTx.localCommitTx,
                            RemoteCommit(0, firstCommitTx.remoteSpec, firstCommitTx.remoteCommitTx.tx.txid, remoteFirstPerCommitmentPoint),
                            lastSent.channelFlags,
                            channelVersion,
                            fundingCreated
                        )
                        Pair(nextState, listOf(channelIdAssigned, ChannelAction.Message.Send(fundingCreated)))
                    }
                }
            }
            event is ChannelEvent.MessageReceived && event.message is Error -> {
                logger.error { "c:$temporaryChannelId peer sent error: ascii=${event.message.toAscii()} bin=${event.message.data.toHex()}" }
                Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            }
            event is ChannelEvent.ExecuteCommand && event.command is CloseCommand -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            event is ChannelEvent.CheckHtlcTimeout -> Pair(this, listOf())
            event is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            event is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$temporaryChannelId error on event ${event::class} in state ${this::class}" }
        val error = Error(temporaryChannelId, t.message)
        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
    }
}

data class WaitForFundingSigned(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    val channelId: ByteVector32,
    val localParams: LocalParams,
    val remoteParams: RemoteParams,
    val fundingTx: Transaction,
    val fundingTxFee: Satoshi,
    val localSpec: CommitmentSpec,
    val localCommitTx: Transactions.TransactionWithInputInfo.CommitTx,
    val remoteCommit: RemoteCommit,
    val channelFlags: Byte,
    val channelVersion: ChannelVersion,
    val lastSent: FundingCreated
) : ChannelState() {
    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when {
            event is ChannelEvent.MessageReceived && event.message is FundingSigned -> {
                // we make sure that their sig checks out and that our first commit tx is spendable
                val fundingPubKey = localParams.channelKeys.fundingPubKey
                val localSigOfLocalTx = keyManager.sign(localCommitTx, localParams.channelKeys.fundingPrivateKey)
                val signedLocalCommitTx = Transactions.addSigs(localCommitTx, fundingPubKey, remoteParams.fundingPubKey, localSigOfLocalTx, event.message.signature)
                when (Transactions.checkSpendable(signedLocalCommitTx)) {
                    is Try.Failure -> handleLocalError(event, InvalidCommitmentSignature(channelId, signedLocalCommitTx.tx))
                    is Try.Success -> {
                        val commitInput = localCommitTx.input
                        val commitments = Commitments(
                            channelVersion, localParams, remoteParams, channelFlags,
                            LocalCommit(0, localSpec, PublishableTxs(signedLocalCommitTx, listOf())), remoteCommit,
                            LocalChanges(listOf(), listOf(), listOf()), RemoteChanges(listOf(), listOf(), listOf()),
                            localNextHtlcId = 0L, remoteNextHtlcId = 0L,
                            payments = mapOf(),
                            remoteNextCommitInfo = Either.Right(Lightning.randomKey().publicKey()), // we will receive their next per-commitment point in the next message, so we temporarily put a random byte array
                            commitInput, ShaChain.init, channelId, event.message.channelData
                        )
                        logger.info { "c:$channelId publishing funding tx for channelId=$channelId fundingTxid=${commitInput.outPoint.txid}" }
                        val watchSpent = WatchSpent(
                            this.channelId,
                            commitments.commitInput.outPoint.txid,
                            commitments.commitInput.outPoint.index.toInt(),
                            commitments.commitInput.txOut.publicKeyScript,
                            BITCOIN_FUNDING_SPENT
                        )
                        // phoenix channels have a zero mindepth for funding tx
                        val minDepthBlocks = if (commitments.channelVersion.isSet(ChannelVersion.ZERO_RESERVE_BIT)) 0 else staticParams.nodeParams.minDepthBlocks
                        val watchConfirmed = WatchConfirmed(
                            this.channelId,
                            commitments.commitInput.outPoint.txid,
                            commitments.commitInput.txOut.publicKeyScript,
                            minDepthBlocks.toLong(),
                            BITCOIN_FUNDING_DEPTHOK
                        )
                        logger.info { "c:$channelId committing txid=${fundingTx.txid}" }

                        val nextState = WaitForFundingConfirmed(staticParams, currentTip, currentOnChainFeerates, commitments, fundingTx, currentBlockHeight.toLong(), null, Either.Left(lastSent))
                        val actions = listOf(
                            ChannelAction.Blockchain.SendWatch(watchSpent),
                            ChannelAction.Blockchain.SendWatch(watchConfirmed),
                            ChannelAction.Storage.StoreState(nextState),
                            // we will publish the funding tx only after the channel state has been written to disk because we want to
                            // make sure we first persist the commitment that returns back the funds to us in case of problem
                            ChannelAction.Blockchain.PublishTx(fundingTx)
                        )
                        Pair(nextState, actions)
                    }
                }
            }
            event is ChannelEvent.MessageReceived && event.message is Error -> {
                logger.error { "c:$channelId peer sent error: ascii=${event.message.toAscii()} bin=${event.message.data.toHex()}" }
                Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            }
            event is ChannelEvent.ExecuteCommand && event.command is CloseCommand -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf())
            event is ChannelEvent.CheckHtlcTimeout -> Pair(this, listOf())
            event is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            event is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$channelId error on event ${event::class} in state ${this::class}" }
        val error = Error(channelId, t.message)
        return Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
    }
}

data class WaitForFundingConfirmed(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val fundingTx: Transaction?,
    val waitingSinceBlock: Long, // how many blocks have we been waiting for the funding tx to confirm
    val deferred: FundingLocked?,
    val lastSent: Either<FundingCreated, FundingSigned>
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when (event) {
            is ChannelEvent.MessageReceived -> when (event.message) {
                is FundingLocked -> Pair(this.copy(deferred = event.message), listOf())
                is Error -> handleRemoteError(event.message)
                else -> Pair(this, listOf())
            }
            is ChannelEvent.WatchReceived ->
                when (event.watch) {
                    is WatchEventConfirmed -> {
                        val result = runTrying {
                            Transaction.correctlySpends(
                                commitments.localCommit.publishableTxs.commitTx.tx,
                                listOf(event.watch.tx),
                                ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS
                            )
                        }
                        if (result is Try.Failure) {
                            logger.error { "c:$channelId funding tx verification failed: ${result.error}" }
                            return handleLocalError(event, InvalidCommitmentSignature(channelId, event.watch.tx))
                        }
                        val watchLost = WatchLost(this.channelId, commitments.commitInput.outPoint.txid, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_FUNDING_LOST)
                        val nextPerCommitmentPoint = keyManager.commitmentPoint(commitments.localParams.channelKeys.shaSeed, 1)
                        val fundingLocked = FundingLocked(commitments.channelId, nextPerCommitmentPoint)
                        // this is the temporary channel id that we will use in our channel_update message, the goal is to be able to use our channel
                        // as soon as it reaches NORMAL state, and before it is announced on the network
                        // (this id might be updated when the funding tx gets deeply buried, if there was a reorg in the meantime)
                        val blockHeight = event.watch.blockHeight
                        val txIndex = event.watch.txIndex
                        val shortChannelId = ShortChannelId(blockHeight, txIndex, commitments.commitInput.outPoint.index.toInt())
                        val nextState = WaitForFundingLocked(staticParams, currentTip, currentOnChainFeerates, commitments, shortChannelId, fundingLocked)
                        val actions = listOf(
                            ChannelAction.Blockchain.SendWatch(watchLost),
                            ChannelAction.Message.Send(fundingLocked),
                            ChannelAction.Storage.StoreState(nextState)
                        )
                        if (deferred != null) {
                            logger.info { "c:$channelId funding_locked has already been received" }
                            val resultPair = nextState.process(ChannelEvent.MessageReceived(deferred))
                            Pair(resultPair.first, actions + resultPair.second)
                        } else {
                            Pair(nextState, actions)
                        }
                    }
                    is WatchEventSpent -> when (event.watch.tx.txid) {
                        commitments.remoteCommit.txid -> handleRemoteSpentCurrent(event.watch.tx)
                        else -> handleRemoteSpentOther(event.watch.tx)
                    }
                    else -> unhandled(event)
                }
            is ChannelEvent.ExecuteCommand -> when (event.command) {
                is CMD_CLOSE -> Pair(this, listOf(ChannelAction.ProcessCmdRes.NotExecuted(event.command, CommandUnavailableInThisState(channelId, this::class.toString()))))
                is CMD_FORCECLOSE -> handleLocalError(event, ForcedLocalCommit(channelId))
                else -> unhandled(event)
            }
            is ChannelEvent.GetFundingTxResponse -> when (event.getTxResponse.txid) {
                commitments.commitInput.outPoint.txid -> handleGetFundingTx(event.getTxResponse, waitingSinceBlock, fundingTx)
                else -> Pair(this, emptyList())
            }
            is ChannelEvent.CheckHtlcTimeout -> Pair(this, listOf())
            is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            is ChannelEvent.Disconnected -> Pair(Offline(this), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$channelId error on event ${event::class} in state ${this::class}" }
        val error = Error(channelId, t.message)
        return when {
            commitments.nothingAtStake() -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
            else -> spendLocalCurrent().run { copy(second = second + ChannelAction.Message.Send(error)) }
        }
    }
}

data class WaitForFundingLocked(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val shortChannelId: ShortChannelId,
    val lastSent: FundingLocked
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when (event) {
            is ChannelEvent.MessageReceived -> when (event.message) {
                is FundingLocked -> {
                    // used to get the final shortChannelId, used in announcements (if minDepth >= ANNOUNCEMENTS_MINCONF this event will fire instantly)
                    val watchConfirmed = WatchConfirmed(
                        this.channelId,
                        commitments.commitInput.outPoint.txid,
                        commitments.commitInput.txOut.publicKeyScript,
                        ANNOUNCEMENTS_MINCONF.toLong(),
                        BITCOIN_FUNDING_DEEPLYBURIED
                    )
                    // we create a channel_update early so that we can use it to send payments through this channel, but it won't be propagated to other nodes since the channel is not yet announced
                    val initialChannelUpdate = Announcements.makeChannelUpdate(
                        staticParams.nodeParams.chainHash,
                        staticParams.nodeParams.nodePrivateKey,
                        staticParams.remoteNodeId,
                        shortChannelId,
                        staticParams.nodeParams.expiryDeltaBlocks,
                        commitments.remoteParams.htlcMinimum,
                        staticParams.nodeParams.feeBase,
                        staticParams.nodeParams.feeProportionalMillionth.toLong(),
                        commitments.localCommit.spec.totalFunds,
                        enable = Helpers.aboveReserve(commitments)
                    )
                    val nextState = Normal(
                        staticParams,
                        currentTip,
                        currentOnChainFeerates,
                        commitments.copy(remoteNextCommitInfo = Either.Right(event.message.nextPerCommitmentPoint)),
                        shortChannelId,
                        buried = false,
                        null,
                        initialChannelUpdate,
                        null,
                        null,
                        null,
                        null
                    )
                    val actions = listOf(
                        ChannelAction.Blockchain.SendWatch(watchConfirmed),
                        ChannelAction.Storage.StoreState(nextState)
                    )
                    Pair(nextState, actions)
                }
                is Error -> handleRemoteError(event.message)
                else -> unhandled(event)
            }
            is ChannelEvent.WatchReceived -> when (val watch = event.watch) {
                is WatchEventSpent -> when (watch.tx.txid) {
                    commitments.remoteCommit.txid -> handleRemoteSpentCurrent(watch.tx)
                    else -> handleRemoteSpentOther(watch.tx)
                }
                else -> unhandled(event)
            }
            is ChannelEvent.ExecuteCommand -> when (event.command) {
                is CMD_CLOSE -> Pair(this, listOf(ChannelAction.ProcessCmdRes.NotExecuted(event.command, CommandUnavailableInThisState(channelId, this::class.toString()))))
                is CMD_FORCECLOSE -> handleLocalError(event, ForcedLocalCommit(channelId))
                else -> unhandled(event)
            }
            is ChannelEvent.CheckHtlcTimeout -> Pair(this, listOf())
            is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            is ChannelEvent.Disconnected -> Pair(Offline(this), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$channelId error on event ${event::class} in state ${this::class}" }
        val error = Error(channelId, t.message)
        return when {
            commitments.nothingAtStake() -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
            else -> spendLocalCurrent().run { copy(second = second + ChannelAction.Message.Send(error)) }
        }
    }
}

data class Normal(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val shortChannelId: ShortChannelId,
    val buried: Boolean,
    val channelAnnouncement: ChannelAnnouncement?,
    val channelUpdate: ChannelUpdate,
    val remoteChannelUpdate: ChannelUpdate?,
    val localShutdown: Shutdown?,
    val remoteShutdown: Shutdown?,
    val closingFeerates: ClosingFeerates?
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when (event) {
            is ChannelEvent.ExecuteCommand -> {
                when (event.command) {
                    is CMD_ADD_HTLC -> {
                        if (localShutdown != null || remoteShutdown != null) {
                            // note: spec would allow us to keep sending new htlcs after having received their shutdown (and not sent ours)
                            // but we want to converge as fast as possible and they would probably not route them anyway
                            val error = NoMoreHtlcsClosingInProgress(channelId)
                            return handleCommandError(event.command, error, channelUpdate)
                        }
                        handleCommandResult(event.command, commitments.sendAdd(event.command, event.command.paymentId, currentBlockHeight.toLong()), event.command.commit)
                    }
                    is CMD_FULFILL_HTLC -> handleCommandResult(event.command, commitments.sendFulfill(event.command), event.command.commit)
                    is CMD_FAIL_HTLC -> handleCommandResult(event.command, commitments.sendFail(event.command, this.privateKey), event.command.commit)
                    is CMD_FAIL_MALFORMED_HTLC -> handleCommandResult(event.command, commitments.sendFailMalformed(event.command), event.command.commit)
                    is CMD_UPDATE_FEE -> handleCommandResult(event.command, commitments.sendFee(event.command), event.command.commit)
                    is CMD_SIGN -> when {
                        !commitments.localHasChanges() -> {
                            logger.warning { "c:$channelId no changes to sign" }
                            Pair(this, listOf())
                        }
                        commitments.remoteNextCommitInfo is Either.Left -> {
                            logger.debug { "c:$channelId already in the process of signing, will sign again as soon as possible" }
                            val commitments1 = commitments.copy(remoteNextCommitInfo = Either.Left(commitments.remoteNextCommitInfo.left!!.copy(reSignAsap = true)))
                            Pair(this.copy(commitments = commitments1), listOf())
                        }
                        else -> when (val result = commitments.sendCommit(keyManager, logger)) {
                            is Either.Left -> handleCommandError(event.command, result.value, channelUpdate)
                            is Either.Right -> {
                                val commitments1 = result.value.first
                                val nextRemoteCommit = commitments1.remoteNextCommitInfo.left!!.nextRemoteCommit
                                val nextCommitNumber = nextRemoteCommit.index
                                // we persist htlc data in order to be able to claim htlc outputs in case a revoked tx is published by our
                                // counterparty, so only htlcs above remote's dust_limit matter
                                val trimmedHtlcs = Transactions.trimOfferedHtlcs(commitments.remoteParams.dustLimit, nextRemoteCommit.spec) + Transactions.trimReceivedHtlcs(commitments.remoteParams.dustLimit, nextRemoteCommit.spec)
                                val htlcInfos = trimmedHtlcs.map { it.add }.map {
                                    logger.info { "c:$channelId adding paymentHash=${it.paymentHash} cltvExpiry=${it.cltvExpiry} to htlcs db for commitNumber=$nextCommitNumber" }
                                    ChannelAction.Storage.HtlcInfo(channelId, nextCommitNumber, it.paymentHash, it.cltvExpiry)
                                }
                                val nextState = this.copy(commitments = commitments1)
                                val actions = listOf(
                                    ChannelAction.Storage.StoreHtlcInfos(htlcInfos),
                                    ChannelAction.Storage.StoreState(nextState),
                                    ChannelAction.Message.Send(result.value.second)
                                )
                                Pair(nextState, actions)
                            }
                        }
                    }
                    is CMD_CLOSE -> {
                        val localScriptPubkey = event.command.scriptPubKey ?: commitments.localParams.defaultFinalScriptPubKey
                        when {
                            this.localShutdown != null -> handleCommandError(event.command, ClosingAlreadyInProgress(channelId), channelUpdate)
                            this.commitments.localHasUnsignedOutgoingHtlcs() -> handleCommandError(event.command, CannotCloseWithUnsignedOutgoingHtlcs(channelId), channelUpdate)
                            this.commitments.localHasUnsignedOutgoingUpdateFee() -> handleCommandError(event.command, CannotCloseWithUnsignedOutgoingUpdateFee(channelId), channelUpdate)
                            !Helpers.Closing.isValidFinalScriptPubkey(localScriptPubkey) -> handleCommandError(event.command, InvalidFinalScript(channelId), channelUpdate)
                            else -> {
                                val shutdown = Shutdown(channelId, localScriptPubkey)
                                val newState = this.copy(localShutdown = shutdown, closingFeerates = event.command.feerates)
                                val actions = listOf(ChannelAction.Storage.StoreState(newState), ChannelAction.Message.Send(shutdown))
                                Pair(newState, actions)
                            }
                        }
                    }
                    is CMD_FORCECLOSE -> handleLocalError(event, ForcedLocalCommit(channelId))
                }
            }
            is ChannelEvent.MessageReceived -> {
                when (event.message) {
                    is UpdateAddHtlc -> when (val result = commitments.receiveAdd(event.message)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> {
                            val newState = this.copy(commitments = result.value)
                            Pair(newState, listOf())
                        }
                    }
                    is UpdateFulfillHtlc -> when (val result = commitments.receiveFulfill(event.message)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> {
                            val (commitments1, paymentId, add) = result.value
                            val htlcResult = ChannelAction.HtlcResult.Fulfill.RemoteFulfill(event.message)
                            Pair(this.copy(commitments = commitments1), listOf(ChannelAction.ProcessCmdRes.AddSettledFulfill(paymentId, add, htlcResult)))
                        }
                    }
                    is UpdateFailHtlc -> when (val result = commitments.receiveFail(event.message)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> Pair(this.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFailMalformedHtlc -> when (val result = commitments.receiveFailMalformed(event.message)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> Pair(this.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFee -> when (val result = commitments.receiveFee(event.message, staticParams.nodeParams.onChainFeeConf.feerateTolerance)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> Pair(this.copy(commitments = result.value), listOf())
                    }
                    is CommitSig -> when (val result = commitments.receiveCommit(event.message, keyManager, logger)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> {
                            val nextState = this.copy(commitments = result.value.first)
                            val actions = mutableListOf<ChannelAction>()
                            actions.add(ChannelAction.Message.Send(result.value.second))
                            actions.add(ChannelAction.Storage.StoreState(nextState))
                            if (result.value.first.localHasChanges()) {
                                actions.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
                            }
                            Pair(nextState, actions)
                        }
                    }
                    is RevokeAndAck -> when (val result = commitments.receiveRevocation(event.message)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> {
                            val commitments1 = result.value.first
                            val actions = mutableListOf<ChannelAction>()
                            actions.addAll(result.value.second)
                            if (result.value.first.localHasChanges() && commitments.remoteNextCommitInfo.left?.reSignAsap == true) {
                                actions.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
                            }
                            val nextState = if (this.remoteShutdown != null && !commitments1.localHasUnsignedOutgoingHtlcs()) {
                                // we were waiting for our pending htlcs to be signed before replying with our local shutdown
                                val localShutdown = Shutdown(channelId, commitments.localParams.defaultFinalScriptPubKey)
                                actions.add(ChannelAction.Message.Send(localShutdown))

                                if (commitments1.remoteCommit.spec.htlcs.isNotEmpty()) {
                                    // we just signed htlcs that need to be resolved now
                                    ShuttingDown(staticParams, currentTip, currentOnChainFeerates, commitments1, localShutdown, remoteShutdown, closingFeerates)
                                } else {
                                    logger.warning { "c:$channelId we have no htlcs but have not replied with our Shutdown yet, this should never happen" }
                                    val closingTxProposed = if (isFunder) {
                                        val (closingTx, closingSigned) = Helpers.Closing.makeFirstClosingTx(
                                            keyManager,
                                            commitments1,
                                            localShutdown.scriptPubKey.toByteArray(),
                                            remoteShutdown.scriptPubKey.toByteArray(),
                                            closingFeerates ?: ClosingFeerates(currentOnChainFeerates.mutualCloseFeerate),
                                        )
                                        listOf(listOf(ClosingTxProposed(closingTx, closingSigned)))
                                    } else {
                                        listOf(listOf())
                                    }
                                    Negotiating(staticParams, currentTip, currentOnChainFeerates, commitments1, localShutdown, remoteShutdown, closingTxProposed, bestUnpublishedClosingTx = null, closingFeerates)
                                }
                            } else {
                                this.copy(commitments = commitments1)
                            }
                            actions.add(0, ChannelAction.Storage.StoreState(nextState))
                            Pair(nextState, actions)
                        }
                    }
                    is ChannelUpdate -> {
                        if (event.message.shortChannelId == shortChannelId && event.message.isRemote(staticParams.nodeParams.nodeId, staticParams.remoteNodeId)) {
                            val nextState = this.copy(remoteChannelUpdate = event.message)
                            Pair(nextState, listOf(ChannelAction.Storage.StoreState(nextState)))
                        } else {
                            Pair(this, listOf())
                        }
                    }
                    is Shutdown -> {
                        // they have pending unsigned htlcs         => they violated the spec, close the channel
                        // they don't have pending unsigned htlcs
                        //    we have pending unsigned htlcs
                        //      we already sent a shutdown message  => spec violation (we can't send htlcs after having sent shutdown)
                        //      we did not send a shutdown message
                        //        we are ready to sign              => we stop sending further htlcs, we initiate a signature
                        //        we are waiting for a rev          => we stop sending further htlcs, we wait for their revocation, will resign immediately after, and then we will send our shutdown message
                        //    we have no pending unsigned htlcs
                        //      we already sent a shutdown message
                        //        there are pending signed changes  => send our shutdown message, go to SHUTDOWN
                        //        there are no changes              => send our shutdown message, go to NEGOTIATING
                        //      we did not send a shutdown message
                        //        there are pending signed changes  => go to SHUTDOWN
                        //        there are no changes              => go to NEGOTIATING
                        when {
                            !Helpers.Closing.isValidFinalScriptPubkey(event.message.scriptPubKey) -> handleLocalError(event, InvalidFinalScript(channelId))
                            commitments.remoteHasUnsignedOutgoingHtlcs() -> handleLocalError(event, CannotCloseWithUnsignedOutgoingHtlcs(channelId))
                            commitments.remoteHasUnsignedOutgoingUpdateFee() -> handleLocalError(event, CannotCloseWithUnsignedOutgoingUpdateFee(channelId))
                            commitments.localHasUnsignedOutgoingHtlcs() -> {
                                require(localShutdown == null) { "can't have pending unsigned outgoing htlcs after having sent Shutdown" }
                                // are we in the middle of a signature?
                                when (commitments.remoteNextCommitInfo) {
                                    is Either.Left -> {
                                        // yes, let's just schedule a new signature ASAP, which will include all pending unsigned changes
                                        val commitments1 = commitments.copy(remoteNextCommitInfo = Either.Left(commitments.remoteNextCommitInfo.value.copy(reSignAsap = true)))
                                        val newState = this.copy(commitments = commitments1, remoteShutdown = event.message)
                                        Pair(newState, listOf())
                                    }
                                    is Either.Right -> {
                                        // no, let's sign right away
                                        val newState = this.copy(remoteShutdown = event.message, commitments = commitments.copy(remoteChannelData = event.message.channelData))
                                        Pair(newState, listOf(ChannelAction.Message.SendToSelf(CMD_SIGN)))
                                    }
                                }
                            }
                            else -> {
                                // so we don't have any unsigned outgoing changes
                                val actions = mutableListOf<ChannelAction>()
                                val localShutdown = this.localShutdown ?: Shutdown(channelId, commitments.localParams.defaultFinalScriptPubKey)
                                if (this.localShutdown == null) actions.add(ChannelAction.Message.Send(localShutdown))
                                val commitments1 = commitments.copy(remoteChannelData = event.message.channelData)
                                when {
                                    commitments1.hasNoPendingHtlcsOrFeeUpdate() && commitments1.localParams.isFunder -> {
                                        val (closingTx, closingSigned) = Helpers.Closing.makeFirstClosingTx(
                                            keyManager,
                                            commitments1,
                                            localShutdown.scriptPubKey.toByteArray(),
                                            event.message.scriptPubKey.toByteArray(),
                                            closingFeerates ?: ClosingFeerates(currentOnChainFeerates.mutualCloseFeerate),
                                        )
                                        val nextState = Negotiating(
                                            staticParams,
                                            currentTip,
                                            currentOnChainFeerates,
                                            commitments1,
                                            localShutdown,
                                            event.message,
                                            listOf(listOf(ClosingTxProposed(closingTx, closingSigned))),
                                            bestUnpublishedClosingTx = null,
                                            closingFeerates
                                        )
                                        actions.addAll(listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Message.Send(closingSigned)))
                                        Pair(nextState, actions)
                                    }
                                    commitments1.hasNoPendingHtlcsOrFeeUpdate() -> {
                                        val nextState = Negotiating(staticParams, currentTip, currentOnChainFeerates, commitments1, localShutdown, event.message, listOf(listOf()), null, closingFeerates)
                                        actions.add(ChannelAction.Storage.StoreState(nextState))
                                        Pair(nextState, actions)
                                    }
                                    else -> {
                                        // there are some pending changes, we need to wait for them to be settled (fail/fulfill htlcs and sign fee updates)
                                        val nextState = ShuttingDown(staticParams, currentTip, currentOnChainFeerates, commitments1, localShutdown, event.message, closingFeerates)
                                        actions.add(ChannelAction.Storage.StoreState(nextState))
                                        Pair(nextState, actions)
                                    }
                                }
                            }
                        }
                    }
                    is Error -> handleRemoteError(event.message)
                    else -> unhandled(event)
                }
            }
            is ChannelEvent.CheckHtlcTimeout -> checkHtlcTimeout()
            is ChannelEvent.NewBlock -> {
                logger.info { "c:$channelId new tip ${event.height} ${event.Header.hash}" }
                Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            }
            is ChannelEvent.SetOnChainFeerates -> {
                logger.info { "c:$channelId using on-chain fee rates ${event.feerates}" }
                Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            }
            is ChannelEvent.WatchReceived -> when (val watch = event.watch) {
                is WatchEventSpent -> when (watch.tx.txid) {
                    commitments.remoteCommit.txid -> handleRemoteSpentCurrent(watch.tx)
                    commitments.remoteNextCommitInfo.left?.nextRemoteCommit?.txid -> handleRemoteSpentNext(watch.tx)
                    else -> handleRemoteSpentOther(watch.tx)
                }
                else -> unhandled(event)
            }
            is ChannelEvent.Disconnected -> {
                // if we have pending unsigned outgoing htlcs, then we cancel them and advertise the fact that the channel is now disabled.
                val failedHtlcs = mutableListOf<ChannelAction>()
                val proposedHtlcs = commitments.localChanges.proposed.filterIsInstance<UpdateAddHtlc>()
                if (proposedHtlcs.isNotEmpty()) {
                    logger.info { "c:$channelId updating channel_update announcement (reason=disabled)" }
                    val channelUpdate = Announcements.disableChannel(channelUpdate, staticParams.nodeParams.nodePrivateKey, staticParams.remoteNodeId)
                    proposedHtlcs.forEach { htlc ->
                        commitments.payments[htlc.id]?.let { paymentId ->
                            failedHtlcs.add(ChannelAction.ProcessCmdRes.AddSettledFail(paymentId, htlc, ChannelAction.HtlcResult.Fail.Disconnected(channelUpdate)))
                        } ?: logger.warning { "c:$channelId cannot find payment for $htlc" }
                    }
                }
                Pair(Offline(this), failedHtlcs)
            }
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$channelId error on event ${event::class} in state ${this::class}" }
        val error = Error(channelId, t.message)
        return when {
            commitments.nothingAtStake() -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
            else -> spendLocalCurrent().run { copy(second = second + ChannelAction.Message.Send(error)) }
        }
    }

    private fun handleCommandResult(command: Command, result: Either<ChannelException, Pair<Commitments, LightningMessage>>, commit: Boolean): Pair<ChannelState, List<ChannelAction>> {
        return when (result) {
            is Either.Left -> handleCommandError(command, result.value, channelUpdate)
            is Either.Right -> {
                val (commitments1, message) = result.value
                val actions = mutableListOf<ChannelAction>(ChannelAction.Message.Send(message))
                if (commit) {
                    actions.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
                }
                Pair(this.copy(commitments = commitments1), actions)
            }
        }
    }
}

data class ShuttingDown(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val localShutdown: Shutdown,
    val remoteShutdown: Shutdown,
    val closingFeerates: ClosingFeerates?
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when (event) {
            is ChannelEvent.MessageReceived -> {
                when (event.message) {
                    is UpdateFulfillHtlc -> when (val result = commitments.receiveFulfill(event.message)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> {
                            val (commitments1, paymentId, add) = result.value
                            val htlcResult = ChannelAction.HtlcResult.Fulfill.RemoteFulfill(event.message)
                            Pair(this.copy(commitments = commitments1), listOf(ChannelAction.ProcessCmdRes.AddSettledFulfill(paymentId, add, htlcResult)))
                        }
                    }
                    is UpdateFailHtlc -> when (val result = commitments.receiveFail(event.message)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> Pair(this.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFailMalformedHtlc -> when (val result = commitments.receiveFailMalformed(event.message)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> Pair(this.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFee -> when (val result = commitments.receiveFee(event.message, staticParams.nodeParams.onChainFeeConf.feerateTolerance)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> Pair(this.copy(commitments = result.value), listOf())
                    }
                    is CommitSig -> when (val result = commitments.receiveCommit(event.message, keyManager, logger)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> {
                            val (commitments1, revocation) = result.value
                            when {
                                commitments1.hasNoPendingHtlcsOrFeeUpdate() && commitments1.localParams.isFunder -> {
                                    val (closingTx, closingSigned) = Helpers.Closing.makeFirstClosingTx(
                                        keyManager,
                                        commitments1,
                                        localShutdown.scriptPubKey.toByteArray(),
                                        remoteShutdown.scriptPubKey.toByteArray(),
                                        closingFeerates ?: ClosingFeerates(currentOnChainFeerates.mutualCloseFeerate)
                                    )
                                    val nextState = Negotiating(
                                        staticParams,
                                        currentTip,
                                        currentOnChainFeerates,
                                        commitments1,
                                        localShutdown,
                                        remoteShutdown,
                                        listOf(listOf(ClosingTxProposed(closingTx, closingSigned))),
                                        bestUnpublishedClosingTx = null,
                                        closingFeerates
                                    )
                                    val actions = listOf(
                                        ChannelAction.Storage.StoreState(nextState),
                                        ChannelAction.Message.Send(revocation),
                                        ChannelAction.Message.Send(closingSigned)
                                    )
                                    Pair(nextState, actions)
                                }
                                commitments1.hasNoPendingHtlcsOrFeeUpdate() -> {
                                    val nextState = Negotiating(staticParams, currentTip, currentOnChainFeerates, commitments1, localShutdown, remoteShutdown, listOf(listOf()), null, closingFeerates)
                                    val actions = listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Message.Send(revocation))
                                    Pair(nextState, actions)
                                }
                                else -> {
                                    val nextState = this.copy(commitments = commitments1)
                                    val actions = mutableListOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Message.Send(revocation))
                                    if (commitments1.localHasChanges()) {
                                        // if we have newly acknowledged changes let's sign them
                                        actions.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
                                    }
                                    Pair(nextState, actions)
                                }
                            }
                        }
                    }
                    is RevokeAndAck -> when (val result = commitments.receiveRevocation(event.message)) {
                        is Either.Left -> handleLocalError(event, result.value)
                        is Either.Right -> {
                            val (commitments1, actions) = result.value
                            val actions1 = actions.toMutableList()
                            when {
                                commitments1.hasNoPendingHtlcsOrFeeUpdate() && commitments1.localParams.isFunder -> {
                                    val (closingTx, closingSigned) = Helpers.Closing.makeFirstClosingTx(
                                        keyManager,
                                        commitments1,
                                        localShutdown.scriptPubKey.toByteArray(),
                                        remoteShutdown.scriptPubKey.toByteArray(),
                                        closingFeerates ?: ClosingFeerates(currentOnChainFeerates.mutualCloseFeerate)
                                    )
                                    val nextState = Negotiating(
                                        staticParams,
                                        currentTip,
                                        currentOnChainFeerates,
                                        commitments1,
                                        localShutdown,
                                        remoteShutdown,
                                        listOf(listOf(ClosingTxProposed(closingTx, closingSigned))),
                                        bestUnpublishedClosingTx = null,
                                        closingFeerates
                                    )
                                    actions1.addAll(listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Message.Send(closingSigned)))
                                    Pair(nextState, actions1)
                                }
                                commitments1.hasNoPendingHtlcsOrFeeUpdate() -> {
                                    val nextState = Negotiating(staticParams, currentTip, currentOnChainFeerates, commitments1, localShutdown, remoteShutdown, listOf(listOf()), null, closingFeerates)
                                    actions1.add(ChannelAction.Storage.StoreState(nextState))
                                    Pair(nextState, actions1)
                                }
                                else -> {
                                    val nextState = this.copy(commitments = commitments1)
                                    actions1.add(ChannelAction.Storage.StoreState(nextState))
                                    if (commitments1.localHasChanges() && commitments1.remoteNextCommitInfo.isLeft && commitments1.remoteNextCommitInfo.left!!.reSignAsap) {
                                        actions1.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
                                    }
                                    Pair(nextState, actions1)
                                }
                            }
                        }
                    }
                    is Error -> {
                        handleRemoteError(event.message)
                    }
                    else -> unhandled(event)
                }
            }
            is ChannelEvent.ExecuteCommand -> when {
                event.command is CMD_ADD_HTLC -> {
                    logger.info { "c:$channelId rejecting htlc request in state=${this::class}" }
                    // we don't provide a channel_update: this will be a permanent channel failure
                    handleCommandError(event.command, ChannelUnavailable(channelId))
                }
                event.command is CMD_SIGN && !commitments.localHasChanges() -> {
                    logger.debug { "c:$channelId ignoring CMD_SIGN (nothing to sign)" }
                    Pair(this, listOf())
                }
                event.command is CMD_SIGN && commitments.remoteNextCommitInfo.isLeft -> {
                    logger.debug { "c:$channelId already in the process of signing, will sign again as soon as possible" }
                    Pair(this.copy(commitments = this.commitments.copy(remoteNextCommitInfo = Either.Left(this.commitments.remoteNextCommitInfo.left!!.copy(reSignAsap = true)))), listOf())
                }
                event.command is CMD_SIGN -> when (val result = commitments.sendCommit(keyManager, logger)) {
                    is Either.Left -> handleCommandError(event.command, result.value)
                    is Either.Right -> {
                        val commitments1 = result.value.first
                        val nextRemoteCommit = commitments1.remoteNextCommitInfo.left!!.nextRemoteCommit
                        val nextCommitNumber = nextRemoteCommit.index
                        // we persist htlc data in order to be able to claim htlc outputs in case a revoked tx is published by our
                        // counterparty, so only htlcs above remote's dust_limit matter
                        val trimmedHtlcs = Transactions.trimOfferedHtlcs(commitments.remoteParams.dustLimit, nextRemoteCommit.spec) + Transactions.trimReceivedHtlcs(commitments.remoteParams.dustLimit, nextRemoteCommit.spec)
                        val htlcInfos = trimmedHtlcs.map { it.add }.map {
                            logger.info { "c:$channelId adding paymentHash=${it.paymentHash} cltvExpiry=${it.cltvExpiry} to htlcs db for commitNumber=$nextCommitNumber" }
                            ChannelAction.Storage.HtlcInfo(channelId, nextCommitNumber, it.paymentHash, it.cltvExpiry)
                        }
                        val nextState = this.copy(commitments = commitments1)
                        val actions = listOf(
                            ChannelAction.Storage.StoreHtlcInfos(htlcInfos),
                            ChannelAction.Storage.StoreState(nextState),
                            ChannelAction.Message.Send(result.value.second)
                        )
                        Pair(nextState, actions)
                    }
                }
                event.command is CMD_FULFILL_HTLC -> handleCommandResult(event.command, commitments.sendFulfill(event.command), event.command.commit)
                event.command is CMD_FAIL_HTLC -> handleCommandResult(event.command, commitments.sendFail(event.command, staticParams.nodeParams.nodePrivateKey), event.command.commit)
                event.command is CMD_FAIL_MALFORMED_HTLC -> handleCommandResult(event.command, commitments.sendFailMalformed(event.command), event.command.commit)
                event.command is CMD_UPDATE_FEE -> handleCommandResult(event.command, commitments.sendFee(event.command), event.command.commit)
                event.command is CMD_CLOSE -> handleCommandError(event.command, ClosingAlreadyInProgress(channelId))
                event.command is CMD_FORCECLOSE -> handleLocalError(event, ForcedLocalCommit(channelId))
                else -> unhandled(event)
            }
            is ChannelEvent.WatchReceived -> when (val watch = event.watch) {
                is WatchEventSpent -> when (watch.tx.txid) {
                    commitments.remoteCommit.txid -> handleRemoteSpentCurrent(watch.tx)
                    commitments.remoteNextCommitInfo.left?.nextRemoteCommit?.txid -> handleRemoteSpentNext(watch.tx)
                    else -> handleRemoteSpentOther(watch.tx)
                }
                else -> unhandled(event)
            }
            is ChannelEvent.CheckHtlcTimeout -> checkHtlcTimeout()
            is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            is ChannelEvent.Disconnected -> Pair(Offline(this), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "error on event ${event::class} in state ${this::class}" }
        val error = Error(channelId, t.message)
        return spendLocalCurrent().run { copy(second = second + ChannelAction.Message.Send(error)) }
    }

    private fun handleCommandResult(command: Command, result: Either<ChannelException, Pair<Commitments, LightningMessage>>, commit: Boolean): Pair<ChannelState, List<ChannelAction>> {
        return when (result) {
            is Either.Left -> handleCommandError(command, result.value)
            is Either.Right -> {
                val (commitments1, message) = result.value
                val actions = mutableListOf<ChannelAction>(ChannelAction.Message.Send(message))
                if (commit) {
                    actions.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
                }
                Pair(this.copy(commitments = commitments1), actions)
            }
        }
    }
}

data class Negotiating(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val localShutdown: Shutdown,
    val remoteShutdown: Shutdown,
    val closingTxProposed: List<List<ClosingTxProposed>>, // one list for every negotiation (there can be several in case of disconnection)
    val bestUnpublishedClosingTx: ClosingTx?,
    val closingFeerates: ClosingFeerates?
) : ChannelStateWithCommitments() {
    init {
        require(closingTxProposed.isNotEmpty()) { "there must always be a list for the current negotiation" }
        require(!commitments.localParams.isFunder || !closingTxProposed.any { it.isEmpty() }) { "funder must have at least one closing signature for every negotiation attempt because it initiates the closing" }
    }

    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when {
            event is ChannelEvent.MessageReceived && event.message is ClosingSigned -> {
                val remoteClosingFee = event.message.feeSatoshis
                logger.info { "c:$channelId received closing fee=$remoteClosingFee" }
                when (val result = Helpers.Closing.checkClosingSignature(keyManager, commitments, localShutdown.scriptPubKey.toByteArray(), remoteShutdown.scriptPubKey.toByteArray(), event.message.feeSatoshis, event.message.signature)) {
                    is Either.Left -> handleLocalError(event, result.value)
                    is Either.Right -> {
                        val (signedClosingTx, closingSignedRemoteFees) = result.value
                        val lastLocalClosingSigned = closingTxProposed.last().lastOrNull()?.localClosingSigned
                        when {
                            lastLocalClosingSigned?.feeSatoshis == remoteClosingFee -> {
                                logger.info { "c:$channelId they accepted our fee, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                completeMutualClose(signedClosingTx, null)
                            }
                            closingTxProposed.flatten().size >= MAX_NEGOTIATION_ITERATIONS -> {
                                logger.warning { "c:$channelId could not agree on closing fees after $MAX_NEGOTIATION_ITERATIONS iterations, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                completeMutualClose(signedClosingTx, closingSignedRemoteFees)
                            }
                            lastLocalClosingSigned?.tlvStream?.get<ClosingSignedTlv.FeeRange>()?.let { it.min <= remoteClosingFee && remoteClosingFee <= it.max } == true -> {
                                val localFeeRange = lastLocalClosingSigned.tlvStream.get<ClosingSignedTlv.FeeRange>()!!
                                logger.info { "c:$channelId they chose closing fee=$remoteClosingFee within our fee range (min=${localFeeRange.max} max=${localFeeRange.max}), publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                completeMutualClose(signedClosingTx, closingSignedRemoteFees)
                            }
                            commitments.localCommit.spec.toLocal == 0.msat -> {
                                logger.info { "c:$channelId we have nothing at stake, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                completeMutualClose(signedClosingTx, closingSignedRemoteFees)
                            }
                            else -> {
                                val theirFeeRange = event.message.tlvStream.get<ClosingSignedTlv.FeeRange>()
                                val ourFeeRange = closingFeerates ?: ClosingFeerates(currentOnChainFeerates.mutualCloseFeerate)
                                when {
                                    theirFeeRange != null && !commitments.localParams.isFunder -> {
                                        // if we are fundee and they proposed a fee range, we pick a value in that range and they should accept it without further negotiation
                                        // we don't care much about the closing fee since they're paying it (not us) and we can use CPFP if we want to speed up confirmation
                                        val closingFees = Helpers.Closing.firstClosingFee(commitments, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, ourFeeRange)
                                        val closingFee = when {
                                            closingFees.preferred > theirFeeRange.max -> theirFeeRange.max
                                            // if we underestimate the fee, then we're happy with whatever they propose (it will confirm more quickly and we're not paying it)
                                            closingFees.preferred < remoteClosingFee -> remoteClosingFee
                                            else -> closingFees.preferred
                                        }
                                        if (closingFee == remoteClosingFee) {
                                            logger.info { "c:$channelId accepting their closing fee=$remoteClosingFee, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                            completeMutualClose(signedClosingTx, closingSignedRemoteFees)
                                        } else {
                                            val (closingTx, closingSigned) = Helpers.Closing.makeClosingTx(
                                                keyManager,
                                                commitments,
                                                localShutdown.scriptPubKey.toByteArray(),
                                                remoteShutdown.scriptPubKey.toByteArray(),
                                                ClosingFees(closingFee, theirFeeRange.min, theirFeeRange.max)
                                            )
                                            logger.info { "c:$channelId proposing closing fee=${closingSigned.feeSatoshis}" }
                                            val closingProposed1 = closingTxProposed.updated(
                                                closingTxProposed.lastIndex,
                                                closingTxProposed.last() + listOf(ClosingTxProposed(closingTx, closingSigned))
                                            )
                                            val nextState = this.copy(
                                                commitments = commitments.copy(remoteChannelData = event.message.channelData),
                                                closingTxProposed = closingProposed1,
                                                bestUnpublishedClosingTx = signedClosingTx
                                            )
                                            val actions = listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Message.Send(closingSigned))
                                            Pair(nextState, actions)
                                        }
                                    }
                                    else -> {
                                        val (closingTx, closingSigned) = run {
                                            // if we are fundee and we were waiting for them to send their first closing_signed, we compute our firstClosingFee, otherwise we use the last one we sent
                                            val localClosingFees = Helpers.Closing.firstClosingFee(commitments, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, ourFeeRange)
                                            val nextPreferredFee = Helpers.Closing.nextClosingFee(lastLocalClosingSigned?.feeSatoshis ?: localClosingFees.preferred, remoteClosingFee)
                                            Helpers.Closing.makeClosingTx(keyManager, commitments, localShutdown.scriptPubKey.toByteArray(), remoteShutdown.scriptPubKey.toByteArray(), localClosingFees.copy(preferred = nextPreferredFee))
                                        }
                                        when {
                                            lastLocalClosingSigned?.feeSatoshis == closingSigned.feeSatoshis -> {
                                                // next computed fee is the same than the one we previously sent (probably because of rounding)
                                                logger.info { "c:$channelId accepting their closing fee=$remoteClosingFee, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                                completeMutualClose(signedClosingTx, null)
                                            }
                                            closingSigned.feeSatoshis == remoteClosingFee -> {
                                                logger.info { "c:$channelId we have converged, publishing closing tx: closingTxId=${signedClosingTx.tx.txid}" }
                                                completeMutualClose(signedClosingTx, closingSigned)
                                            }
                                            else -> {
                                                logger.info { "c:$channelId proposing closing fee=${closingSigned.feeSatoshis}" }
                                                val closingProposed1 = closingTxProposed.updated(
                                                    closingTxProposed.lastIndex,
                                                    closingTxProposed.last() + listOf(ClosingTxProposed(closingTx, closingSigned))
                                                )
                                                val nextState = this.copy(
                                                    commitments = commitments.copy(remoteChannelData = event.message.channelData),
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
            event is ChannelEvent.MessageReceived && event.message is Error -> handleRemoteError(event.message)
            event is ChannelEvent.WatchReceived -> when (val watch = event.watch) {
                is WatchEventSpent -> when {
                    watch.event is BITCOIN_FUNDING_SPENT && closingTxProposed.flatten().any { it.unsignedTx.tx.txid == watch.tx.txid } -> {
                        // they can publish a closing tx with any sig we sent them, even if we are not done negotiating
                        logger.info { "c:$channelId closing tx published: closingTxId=${watch.tx.txid}" }
                        val closingTx = getMutualClosePublished(watch.tx)
                        val nextState = Closing(
                            staticParams,
                            currentTip,
                            currentOnChainFeerates,
                            commitments,
                            fundingTx = null,
                            waitingSinceBlock = currentBlockHeight.toLong(),
                            mutualCloseProposed = this.closingTxProposed.flatten().map { it.unsignedTx },
                            mutualClosePublished = listOf(closingTx)
                        )
                        val actions = listOf(
                            ChannelAction.Storage.StoreState(nextState),
                            ChannelAction.Blockchain.PublishTx(watch.tx),
                            ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, watch.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(watch.tx)))
                        )
                        Pair(nextState, actions)
                    }
                    watch.tx.txid == commitments.remoteCommit.txid -> handleRemoteSpentCurrent(watch.tx)
                    watch.tx.txid == commitments.remoteNextCommitInfo.left?.nextRemoteCommit?.txid -> handleRemoteSpentNext(watch.tx)
                    else -> handleRemoteSpentOther(watch.tx)
                }
                else -> unhandled(event)
            }
            event is ChannelEvent.CheckHtlcTimeout -> checkHtlcTimeout()
            event is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            event is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            event is ChannelEvent.Disconnected -> Pair(Offline(this), listOf())
            event is ChannelEvent.ExecuteCommand && event.command is CMD_ADD_HTLC -> handleCommandError(event.command, ChannelUnavailable(channelId))
            event is ChannelEvent.ExecuteCommand && event.command is CMD_CLOSE -> handleCommandError(event.command, ClosingAlreadyInProgress(channelId))
            else -> unhandled(event)
        }
    }

    /** Return full information about a known closing tx. */
    internal fun getMutualClosePublished(tx: Transaction): ClosingTx {
        // they can publish a closing tx with any sig we sent them, even if we are not done negotiating
        // they added their signature, so we use their version of the transaction
        return closingTxProposed.flatten().first { it.unsignedTx.tx.txid == tx.txid }.unsignedTx.copy(tx = tx)
    }

    private fun completeMutualClose(signedClosingTx: ClosingTx, closingSigned: ClosingSigned?): Pair<ChannelState, List<ChannelAction>> {
        val nextState = Closing(
            staticParams,
            currentTip,
            currentOnChainFeerates,
            commitments,
            fundingTx = null,
            waitingSinceBlock = currentBlockHeight.toLong(),
            mutualCloseProposed = closingTxProposed.flatten().map { it.unsignedTx },
            mutualClosePublished = listOf(signedClosingTx)
        )
        val actions = buildList {
            add(ChannelAction.Storage.StoreState(nextState))
            closingSigned?.let { add(ChannelAction.Message.Send(it)) }
            add(ChannelAction.Blockchain.PublishTx(signedClosingTx.tx))
            add(ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, signedClosingTx.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(signedClosingTx.tx))))
        }
        return Pair(nextState, actions)
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$channelId error on event ${event::class} in state ${this::class}" }
        val error = Error(channelId, t.message)
        return when {
            commitments.nothingAtStake() -> Pair(Aborted(staticParams, currentTip, currentOnChainFeerates), listOf(ChannelAction.Message.Send(error)))
            bestUnpublishedClosingTx != null -> {
                // if we were in the process of closing and already received a closing sig from the counterparty, it's always better to use that
                val nextState = Closing(
                    staticParams,
                    currentTip,
                    currentOnChainFeerates,
                    commitments,
                    fundingTx = null,
                    waitingSinceBlock = currentBlockHeight.toLong(),
                    mutualCloseProposed = this.closingTxProposed.flatten().map { it.unsignedTx } + listOf(bestUnpublishedClosingTx),
                    mutualClosePublished = listOf(bestUnpublishedClosingTx)
                )
                val actions = listOf(
                    ChannelAction.Storage.StoreState(nextState),
                    ChannelAction.Blockchain.PublishTx(bestUnpublishedClosingTx.tx),
                    ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, bestUnpublishedClosingTx.tx, staticParams.nodeParams.minDepthBlocks.toLong(), BITCOIN_TX_CONFIRMED(bestUnpublishedClosingTx.tx)))
                )
                Pair(nextState, actions)
            }
            else -> spendLocalCurrent().run { copy(second = second + ChannelAction.Message.Send(error)) }
        }
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
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val fundingTx: Transaction?, // this will be non-empty if we are funder and we got in closing while waiting for our own tx to be published
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

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return when (event) {
            is ChannelEvent.WatchReceived -> {
                val watch = event.watch
                when {
                    watch is WatchEventSpent && watch.event is BITCOIN_FUNDING_SPENT -> when {
                        mutualClosePublished.any { it.tx.txid == watch.tx.txid } -> {
                            // we already know about this tx, probably because we have published it ourselves after successful negotiation
                            Pair(this, listOf())
                        }
                        mutualCloseProposed.any { it.tx.txid == watch.tx.txid } -> {
                            // at any time they can publish a closing tx with any sig we sent them
                            val closingTx = mutualCloseProposed.first { it.tx.txid == watch.tx.txid }.copy(tx = watch.tx)
                            val nextState = this.copy(mutualClosePublished = this.mutualClosePublished + listOf(closingTx))
                            val actions = listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Blockchain.PublishTx(watch.tx))
                            Pair(nextState, actions)
                        }
                        localCommitPublished?.commitTx == watch.tx || remoteCommitPublished?.commitTx == watch.tx || nextRemoteCommitPublished?.commitTx == watch.tx || futureRemoteCommitPublished?.commitTx == watch.tx -> {
                            // this is because WatchSpent watches never expire and we are notified multiple times
                            Pair(this, listOf())
                        }
                        watch.tx.txid == commitments.remoteCommit.txid -> {
                            // counterparty may attempt to spend its last commit tx at any time
                            handleRemoteSpentCurrent(watch.tx)
                        }
                        watch.tx.txid == commitments.remoteNextCommitInfo.left?.nextRemoteCommit?.txid -> {
                            // counterparty may attempt to spend its next commit tx at any time
                            handleRemoteSpentNext(watch.tx)
                        }
                        else -> {
                            // counterparty may attempt to spend a revoked commit tx at any time
                            handleRemoteSpentOther(watch.tx)
                        }
                    }
                    watch is WatchEventSpent && watch.event is BITCOIN_OUTPUT_SPENT -> {
                        // when a remote or local commitment tx containing outgoing htlcs is published on the network,
                        // we watch it in order to extract payment preimage if funds are pulled by the counterparty
                        // we can then use these preimages to fulfill payments
                        logger.info { "c:$channelId processing BITCOIN_OUTPUT_SPENT with txid=${watch.tx.txid} tx=${watch.tx}" }
                        val htlcSettledActions = mutableListOf<ChannelAction>()
                        commitments.localCommit.extractPreimages(watch.tx).forEach { (htlc, preimage) ->
                            when (val paymentId = commitments.payments[htlc.id]) {
                                null -> {
                                    // if we don't have a reference to the payment, it means that we already have forwarded the fulfill so that's not a big deal.
                                    // this can happen if they send a signature containing the fulfill, then fail the channel before we have time to sign it
                                    logger.info { "c:$channelId cannot fulfill htlc #${htlc.id} paymentHash=${htlc.paymentHash} (payment not found)" }
                                }
                                else -> {
                                    logger.info { "c:$channelId fulfilling htlc #${htlc.id} paymentHash=${htlc.paymentHash} paymentId=$paymentId" }
                                    htlcSettledActions += ChannelAction.ProcessCmdRes.AddSettledFulfill(paymentId, htlc, ChannelAction.HtlcResult.Fulfill.OnChainFulfill(preimage))
                                }
                            }
                        }

                        val revokedCommitPublishActions = mutableListOf<ChannelAction>()
                        val revokedCommitPublished1 = revokedCommitPublished.map { rev ->
                            val (newRevokedCommitPublished, penaltyTxs) = Helpers.Closing.claimRevokedHtlcTxOutputs(keyManager, commitments, rev, watch.tx, currentOnChainFeerates)
                            penaltyTxs.forEach {
                                revokedCommitPublishActions += ChannelAction.Blockchain.PublishTx(it.tx)
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
                        logger.info { "c:$channelId txid=${watch.tx.txid} has reached mindepth, updating closing state" }
                        // first we check if this tx belongs to one of the current local/remote commits, update it and update the channel data
                        val closing1 = this.copy(
                            localCommitPublished = this.localCommitPublished?.update(watch.tx),
                            remoteCommitPublished = this.remoteCommitPublished?.update(watch.tx),
                            nextRemoteCommitPublished = this.nextRemoteCommitPublished?.update(watch.tx),
                            futureRemoteCommitPublished = this.futureRemoteCommitPublished?.update(watch.tx),
                            revokedCommitPublished = this.revokedCommitPublished.map { it.update(watch.tx) }
                        )
                        closing1.networkFeePaid(watch.tx)?.let {
                            logger.info { "c:$channelId paid fee=${it.first} for txid=${watch.tx.txid} desc=${it.second}" }
                        } ?: run {
                            logger.info { "c:$channelId paid UNKNOWN fee for txid=${watch.tx.txid}" }
                        }

                        // we may need to fail some htlcs in case a commitment tx was published and they have reached the timeout threshold
                        val htlcSettledActions = mutableListOf<ChannelAction>()
                        val timedOutHtlcs = when (val closingType = closing1.closingTypeAlreadyKnown()) {
                            is LocalClose -> closingType.localCommit.timedOutHtlcs(closingType.localCommitPublished, commitments.localParams.dustLimit, watch.tx)
                            is RemoteClose -> closingType.remoteCommit.timedOutHtlcs(closingType.remoteCommitPublished, commitments.remoteParams.dustLimit, watch.tx)
                            else -> setOf() // we lose htlc outputs in option_data_loss_protect scenarios (future remote commit)
                        }
                        timedOutHtlcs.forEach { add ->
                            when (val paymentId = commitments.payments[add.id]) {
                                null -> {
                                    // same as for fulfilling the htlc (no big deal)
                                    logger.info { "c:$channelId cannot fail timedout htlc #${add.id} paymentHash=${add.paymentHash} (payment not found)" }
                                }
                                else -> {
                                    logger.info { "c:$channelId failing htlc #${add.id} paymentHash=${add.paymentHash} paymentId=$paymentId: htlc timed out" }
                                    htlcSettledActions += ChannelAction.ProcessCmdRes.AddSettledFail(paymentId, add, ChannelAction.HtlcResult.Fail.OnChainFail(HtlcsTimedOutDownstream(channelId, setOf(add))))
                                }
                            }
                        }

                        // we also need to fail outgoing htlcs that we know will never reach the blockchain
                        overriddenOutgoingHtlcs(commitments.localCommit, commitments.remoteCommit, commitments.remoteNextCommitInfo.left?.nextRemoteCommit, closing1.revokedCommitPublished, watch.tx).forEach { add ->
                            when (val paymentId = commitments.payments[add.id]) {
                                null -> {
                                    // same as for fulfilling the htlc (no big deal)
                                    logger.info { "c:$channelId cannot fail overridden htlc #${add.id} paymentHash=${add.paymentHash} (payment not found)" }
                                }
                                else -> {
                                    logger.info { "c:$channelId failing htlc #${add.id} paymentHash=${add.paymentHash} paymentId=$paymentId: overridden by local commit" }
                                    htlcSettledActions += ChannelAction.ProcessCmdRes.AddSettledFail(paymentId, add, ChannelAction.HtlcResult.Fail.OnChainFail(HtlcOverriddenByLocalCommit(channelId, add)))
                                }
                            }
                        }

                        // for our outgoing payments, let's log something if we know that they will settle on chain
                        onChainOutgoingHtlcs(commitments.localCommit, commitments.remoteCommit, commitments.remoteNextCommitInfo.left?.nextRemoteCommit, watch.tx).forEach { add ->
                            commitments.payments[add.id]?.let { paymentId -> logger.info { "c:$channelId paymentId=$paymentId will settle on-chain (htlc #${add.id} sending ${add.amountMsat})" } }
                        }

                        val (nextState, closedActions) = when (val closingType = closing1.isClosed(watch.tx)) {
                            null -> Pair(closing1, listOf())
                            else -> {
                                logger.info { "c:$channelId channel is now closed" }
                                if (closingType !is MutualClose) {
                                    logger.debug { "c:$channelId last known remoteChannelData=${commitments.remoteChannelData}" }
                                }
                                Pair(Closed(closing1), listOf(closing1.storeChannelClosed(watch.tx)))
                            }
                        }
                        val actions = buildList {
                            add(ChannelAction.Storage.StoreState(nextState))
                            addAll(htlcSettledActions)
                            addAll(closedActions)
                        }
                        Pair(nextState, actions)
                    }
                    else -> unhandled(event)
                }
            }
            is ChannelEvent.GetHtlcInfosResponse -> {
                val index = revokedCommitPublished.indexOfFirst { it.commitTx.txid == event.revokedCommitTxId }
                if (index >= 0) {
                    val revokedCommitPublished1 = Helpers.Closing.claimRevokedRemoteCommitTxHtlcOutputs(keyManager, commitments, revokedCommitPublished[index], currentOnChainFeerates, event.htlcInfos)
                    val nextState = copy(revokedCommitPublished = revokedCommitPublished.updated(index, revokedCommitPublished1))
                    val actions = buildList {
                        add(ChannelAction.Storage.StoreState(nextState))
                        addAll(revokedCommitPublished1.doPublish(channelId, staticParams.nodeParams.minDepthBlocks.toLong()))
                    }
                    Pair(nextState, actions)
                } else {
                    logger.warning { "c:$channelId cannot find revoked commit with txid=${event.revokedCommitTxId}" }
                    Pair(this, listOf())
                }
            }
            is ChannelEvent.MessageReceived -> when (event.message) {
                is ChannelReestablish -> {
                    // they haven't detected that we were closing and are trying to reestablish a connection
                    // we give them one of the published txs as a hint
                    // note spendingTx != Nil (that's a requirement of DATA_CLOSING)
                    val exc = FundingTxSpent(channelId, spendingTxs.first())
                    val error = Error(channelId, exc.message)
                    Pair(this, listOf(ChannelAction.Message.Send(error)))
                }
                is Error -> {
                    logger.error { "c:$channelId peer sent error: ascii=${event.message.toAscii()} bin=${event.message.data.toHex()}" }
                    // nothing to do, there is already a spending tx published
                    Pair(this, listOf())
                }
                else -> unhandled(event)
            }
            is ChannelEvent.ExecuteCommand -> when (event.command) {
                is CMD_CLOSE -> handleCommandError(event.command, ClosingAlreadyInProgress(channelId))
                is CMD_ADD_HTLC -> {
                    logger.info { "c:$channelId rejecting htlc request in state=${this::class}" }
                    // we don't provide a channel_update: this will be a permanent channel failure
                    handleCommandError(event.command, ChannelUnavailable(channelId))
                }
                is CMD_FULFILL_HTLC -> when (val result = commitments.sendFulfill(event.command)) {
                    is Either.Right -> {
                        logger.info { "c:$channelId got valid payment preimage, recalculating transactions to redeem the corresponding htlc on-chain" }
                        val commitments1 = result.value.first
                        val localCommitPublished1 = localCommitPublished?.let {
                            Helpers.Closing.claimCurrentLocalCommitTxOutputs(keyManager, commitments1, it.commitTx, currentOnChainFeerates)
                        }
                        val remoteCommitPublished1 = remoteCommitPublished?.let {
                            Helpers.Closing.claimRemoteCommitTxOutputs(keyManager, commitments1, commitments1.remoteCommit, it.commitTx, currentOnChainFeerates)
                        }
                        val nextRemoteCommitPublished1 = nextRemoteCommitPublished?.let {
                            val remoteCommit = commitments1.remoteNextCommitInfo.left?.nextRemoteCommit ?: error("next remote commit must be defined")
                            Helpers.Closing.claimRemoteCommitTxOutputs(keyManager, commitments1, remoteCommit, it.commitTx, currentOnChainFeerates)
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
                    is Either.Left -> handleCommandError(event.command, result.value)
                }
                else -> unhandled(event)
            }
            is ChannelEvent.GetFundingTxResponse -> when (event.getTxResponse.txid) {
                commitments.commitInput.outPoint.txid -> handleGetFundingTx(event.getTxResponse, waitingSinceBlock, fundingTx)
                else -> Pair(this, emptyList())
            }
            is ChannelEvent.CheckHtlcTimeout -> checkHtlcTimeout()
            is ChannelEvent.NewBlock -> Pair(this.copy(currentTip = Pair(event.height, event.Header)), listOf())
            is ChannelEvent.SetOnChainFeerates -> Pair(this.copy(currentOnChainFeerates = event.feerates), listOf())
            is ChannelEvent.Disconnected -> Pair(Offline(this), listOf())
            else -> unhandled(event)
        }
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$channelId error processing ${event::class} in state ${this::class}" }
        return localCommitPublished?.let {
            // we're already trying to claim our commitment, there's nothing more we can do
            Pair(this, listOf())
        } ?: spendLocalCurrent()
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
            localCommitPublished?.isDone() ?: false -> LocalClose(commitments.localCommit, localCommitPublished!!)
            remoteCommitPublished?.isDone() ?: false -> CurrentRemoteClose(commitments.remoteCommit, remoteCommitPublished!!)
            nextRemoteCommitPublished?.isDone() ?: false -> NextRemoteClose(commitments.remoteNextCommitInfo.left!!.nextRemoteCommit, nextRemoteCommitPublished!!)
            futureRemoteCommitPublished?.isDone() ?: false -> RecoveryClose(futureRemoteCommitPublished!!)
            revokedCommitPublished.any { it.isDone() } -> RevokedClose(revokedCommitPublished.first { it.isDone() })
            else -> null
        }
    }

    fun closingTypeAlreadyKnown(): ClosingType? {
        return when {
            localCommitPublished?.isConfirmed() ?: false -> LocalClose(commitments.localCommit, localCommitPublished!!)
            remoteCommitPublished?.isConfirmed() ?: false -> CurrentRemoteClose(commitments.remoteCommit, remoteCommitPublished!!)
            nextRemoteCommitPublished?.isConfirmed() ?: false -> NextRemoteClose(commitments.remoteNextCommitInfo.left!!.nextRemoteCommit, nextRemoteCommitPublished!!)
            futureRemoteCommitPublished?.isConfirmed() ?: false -> RecoveryClose(futureRemoteCommitPublished!!)
            revokedCommitPublished.any { it.isConfirmed() } -> RevokedClose(revokedCommitPublished.first { it.isConfirmed() })
            else -> null
        }
    }

    /**
     * This helper function returns the fee paid by the given transaction.
     * It relies on the current channel data to find the parent tx and compute the fee, and also provides a description.
     *
     * @param tx a tx for which we want to compute the fee
     * @return if the parent tx is found, a tuple (fee, description)
     */
    private fun networkFeePaid(tx: Transaction): Pair<Satoshi, String>? {
        // we can compute the fees only for transactions with a single parent for which we know the output amount
        if (tx.txIn.size != 1) return null
        // only the funder pays the fee for the commit tx, but 2nd-stage and 3rd-stage tx fees are paid by their recipients
        val isCommitTx = tx.txIn.any { it.outPoint == commitments.commitInput.outPoint }
        if (isCommitTx && !commitments.localParams.isFunder) return null

        // we build a map with all known txs (that's not particularly efficient, but it doesn't really matter)
        val txs = buildList {
            mutualClosePublished.map { it.tx to "mutual" }.forEach { add(it) }
            localCommitPublished?.let { localCommitPublished ->
                add(localCommitPublished.commitTx to "local-commit")
                localCommitPublished.claimMainDelayedOutputTx?.let { add(it.tx to "local-main-delayed") }
                localCommitPublished.htlcTxs.values.forEach {
                    when (it) {
                        is Transactions.TransactionWithInputInfo.HtlcTx.HtlcSuccessTx -> add(it.tx to "local-htlc-success")
                        is Transactions.TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx -> add(it.tx to "local-htlc-timeout")
                    }
                }
                localCommitPublished.claimHtlcDelayedTxs.forEach { add(it.tx to "local-htlc-delayed") }
            }
            remoteCommitPublished?.let { remoteCommitPublished ->
                add(remoteCommitPublished.commitTx to "remote-commit")
                remoteCommitPublished.claimMainOutputTx?.let { add(it.tx to "remote-main") }
                remoteCommitPublished.claimHtlcTxs.values.forEach {
                    when (it) {
                        is Transactions.TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcSuccessTx -> add(it.tx to "remote-htlc-success")
                        is Transactions.TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx -> add(it.tx to "remote-htlc-timeout")
                    }
                }
            }
            nextRemoteCommitPublished?.let { nextRemoteCommitPublished ->
                add(nextRemoteCommitPublished.commitTx to "remote-commit")
                nextRemoteCommitPublished.claimMainOutputTx?.let { add(it.tx to "remote-main") }
                nextRemoteCommitPublished.claimHtlcTxs.values.forEach {
                    when (it) {
                        is Transactions.TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcSuccessTx -> add(it.tx to "remote-htlc-success")
                        is Transactions.TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx -> add(it.tx to "remote-htlc-timeout")
                    }
                }
            }
            revokedCommitPublished.forEach { revokedCommitPublished ->
                add(revokedCommitPublished.commitTx to "revoked-commit")
                revokedCommitPublished.claimMainOutputTx?.let { add(it.tx to "revoked-main") }
                revokedCommitPublished.mainPenaltyTx?.let { add(it.tx to "revoked-main-penalty") }
                revokedCommitPublished.htlcPenaltyTxs.forEach { add(it.tx to "revoked-htlc-penalty") }
                revokedCommitPublished.claimHtlcDelayedPenaltyTxs.forEach { add(it.tx to "revoked-htlc-penalty-delayed") }
            }
        }.map { (tx, desc) ->
            // will allow easy lookup of parent transaction
            tx.txid to (tx to desc)
        }.toMap()

        return txs[tx.txid]?.let { (_, desc) ->
            val parentTxOut = if (isCommitTx) {
                commitments.commitInput.txOut
            } else {
                val outPoint = tx.txIn.first().outPoint
                txs[outPoint.txid]?.let { (parent, _) -> parent.txOut[outPoint.index.toInt()] }
            }
            parentTxOut?.let { txOut -> txOut.amount - tx.txOut.map { it.amount }.sum() }?.let { it to desc }
        }
    }

    private fun storeChannelClosed(additionalConfirmedTx: Transaction?): ChannelAction.Storage.StoreChannelClosed {
        // We want to give the user the list of btc transactions for their outputs
        val txids = mutableListOf<ByteVector32>()
        var claimed = 0.sat
        val type = when {
            mutualClosePublished.isNotEmpty() -> ChannelClosingType.Mutual
            localCommitPublished != null -> ChannelClosingType.Local
            remoteCommitPublished != null -> ChannelClosingType.Remote
            nextRemoteCommitPublished != null -> ChannelClosingType.Remote
            futureRemoteCommitPublished != null -> ChannelClosingType.Remote
            revokedCommitPublished.isNotEmpty() -> ChannelClosingType.Revoked
            else -> ChannelClosingType.Other
        }
        additionalConfirmedTx?.let { confirmedTx ->
            mutualClosePublished.firstOrNull { it.tx == confirmedTx }?.let {
                txids += it.tx.txid
                claimed += it.toLocalOutput?.amount ?: 0.sat
            }
        }
        localCommitPublished?.let {
            val confirmedTxids = it.irrevocablySpent.values.map { it.txid }.toSet()
            val allTxs = listOfNotNull(it.claimMainDelayedOutputTx?.tx) +
                    it.claimHtlcDelayedTxs.map { it.tx }
            val confirmedTxs = allTxs.filter { confirmedTxids.contains(it.txid) }
            if (confirmedTxs.isNotEmpty()) {
                txids += confirmedTxs.map { it.txid }
                claimed += confirmedTxs.map { it.txOut.first().amount }.sum()
            }
        }
        listOfNotNull(
            remoteCommitPublished,
            nextRemoteCommitPublished,
            futureRemoteCommitPublished
        ).forEach {
            val confirmedTxids = it.irrevocablySpent.values.map { it.txid }.toSet()
            val allTxs = listOfNotNull(it.claimMainOutputTx?.tx) +
                    it.claimHtlcTxs.mapNotNull { it.value?.tx }
            val confirmedTxs = allTxs.filter { confirmedTxids.contains(it.txid) }
            if (confirmedTxs.isNotEmpty()) {
                txids += confirmedTxs.map { it.txid }
                claimed += confirmedTxs.map { it.txOut.first().amount }.sum()
            }
        }
        revokedCommitPublished.forEach {
            val confirmedTxids = it.irrevocablySpent.values.map { it.txid }.toSet()
            val allTxs = listOfNotNull(it.claimMainOutputTx?.tx, it.mainPenaltyTx?.tx) +
                    it.htlcPenaltyTxs.map { it.tx } +
                    it.claimHtlcDelayedPenaltyTxs.map { it.tx }
            val confirmedTxs = allTxs.filter { confirmedTxids.contains(it.txid) }
            if (confirmedTxs.isNotEmpty()) {
                txids += confirmedTxs.map { it.txid }
                claimed += confirmedTxs.map { it.txOut.first().amount }.sum()
            }
        }
        return ChannelAction.Storage.StoreChannelClosed(txids, claimed, type)
    }
}

/**
 * Channel is closed i.t its funding tx has been spent and the spending transactions have been confirmed, it can be forgotten
 */
data class Closed(val state: Closing) : ChannelStateWithCommitments() {
    override val staticParams: StaticParams get() = state.staticParams
    override val currentTip: Pair<Int, BlockHeader> get() = state.currentTip
    override val currentOnChainFeerates: OnChainFeerates get() = state.currentOnChainFeerates
    override val commitments: Commitments get() = state.commitments

    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments {
        return this.copy(state = state.updateCommitments(input) as Closing)
    }

    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return Pair(this, listOf())
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "c:$channelId error on event ${event::class} in state ${this::class}" }
        return Pair(this, listOf())
    }
}

/**
 * Channel has been aborted before it was funded (because we did not receive a FundingCreated or FundingSigned message for example)
 */
data class Aborted(override val staticParams: StaticParams, override val currentTip: Pair<Int, BlockHeader>, override val currentOnChainFeerates: OnChainFeerates) : ChannelState() {
    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return Pair(this, listOf())
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        return Pair(this, listOf())
    }
}

data class ErrorInformationLeak(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments
) : ChannelStateWithCommitments() {
    override fun processInternal(event: ChannelEvent): Pair<ChannelState, List<ChannelAction>> {
        return Pair(this, listOf())
    }

    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments {
        return this.copy(commitments = input)
    }

    override fun handleLocalError(event: ChannelEvent, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        return Pair(this, listOf())
    }
}

object Channel {
    // see https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#requirements
    const val ANNOUNCEMENTS_MINCONF = 6

    // https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#requirements
    val MAX_FUNDING = 10.btc
    const val MAX_ACCEPTED_HTLCS = 483

    // We may need to rely on our peer's commit tx in certain cases (backup/restore) so we must ensure their transactions
    // can propagate through the bitcoin network (assuming bitcoin core nodes with default policies).
    // A minimal spend of a p2wsh output is 110 bytes and bitcoin core's dust-relay-fee is 3000 sat/kb, which amounts to 330 sat.
    val MIN_DUST_LIMIT = 330.sat

    // we won't exchange more than this many signatures when negotiating the closing fee
    const val MAX_NEGOTIATION_ITERATIONS = 20

    // this is defined in BOLT 11
    val MIN_CLTV_EXPIRY_DELTA = CltvExpiryDelta(18)
    val MAX_CLTV_EXPIRY_DELTA = CltvExpiryDelta(7 * 144) // one week

    // since BOLT 1.1, there is a max value for the refund delay of the main commitment tx
    val MAX_TO_SELF_DELAY = CltvExpiryDelta(2016)

    // as a fundee, we will wait that block count for the funding tx to confirm (funder will rely on the funding tx being double-spent)
    const val FUNDING_TIMEOUT_FUNDEE_BLOCK = 2016

    fun handleSync(channelReestablish: ChannelReestablish, d: ChannelStateWithCommitments, keyManager: KeyManager, log: Logger): Pair<Commitments, List<ChannelAction>> {
        val sendQueue = ArrayList<ChannelAction>()
        // first we clean up unacknowledged updates
        log.debug { "discarding proposed OUT: ${d.commitments.localChanges.proposed}" }
        log.debug { "discarding proposed IN: ${d.commitments.remoteChanges.proposed}" }
        val commitments1 = d.commitments.copy(
            localChanges = d.commitments.localChanges.copy(proposed = emptyList()),
            remoteChanges = d.commitments.remoteChanges.copy(proposed = emptyList()),
            localNextHtlcId = d.commitments.localNextHtlcId - d.commitments.localChanges.proposed.filterIsInstance<UpdateAddHtlc>().size,
            remoteNextHtlcId = d.commitments.remoteNextHtlcId - d.commitments.remoteChanges.proposed.filterIsInstance<UpdateAddHtlc>().size
        )
        log.debug { "localNextHtlcId=${d.commitments.localNextHtlcId}->${commitments1.localNextHtlcId}" }
        log.debug { "remoteNextHtlcId=${d.commitments.remoteNextHtlcId}->${commitments1.remoteNextHtlcId}" }

        fun resendRevocation() {
            // let's see the state of remote sigs
            when (commitments1.localCommit.index) {
                channelReestablish.nextRemoteRevocationNumber -> {
                    // nothing to do
                }
                channelReestablish.nextRemoteRevocationNumber + 1 -> {
                    // our last revocation got lost, let's resend it
                    log.debug { "re-sending last revocation" }
                    val localPerCommitmentSecret = keyManager.commitmentSecret(d.commitments.localParams.channelKeys.shaSeed, d.commitments.localCommit.index - 1)
                    val localNextPerCommitmentPoint = keyManager.commitmentPoint(d.commitments.localParams.channelKeys.shaSeed, d.commitments.localCommit.index + 1)
                    val revocation = RevokeAndAck(commitments1.channelId, localPerCommitmentSecret, localNextPerCommitmentPoint)
                    sendQueue.add(ChannelAction.Message.Send(revocation))
                }
                else -> throw RevocationSyncError(d.channelId)
            }
        }

        when {
            commitments1.remoteNextCommitInfo.isLeft && commitments1.remoteNextCommitInfo.left!!.nextRemoteCommit.index + 1 == channelReestablish.nextLocalCommitmentNumber -> {
                // we had sent a new sig and were waiting for their revocation
                // they had received the new sig but their revocation was lost during the disconnection
                // they will send us the revocation, nothing to do here
                log.debug { "waiting for them to re-send their last revocation" }
                resendRevocation()
            }
            commitments1.remoteNextCommitInfo.isLeft && commitments1.remoteNextCommitInfo.left!!.nextRemoteCommit.index == channelReestablish.nextLocalCommitmentNumber -> {
                // we had sent a new sig and were waiting for their revocation
                // they didn't receive the new sig because of the disconnection
                // we just resend the same updates and the same sig
                val revWasSentLast = commitments1.localCommit.index > commitments1.remoteNextCommitInfo.left!!.sentAfterLocalCommitIndex
                if (!revWasSentLast) resendRevocation()

                log.debug { "re-sending previously local signed changes: ${commitments1.localChanges.signed}" }
                commitments1.localChanges.signed.forEach { sendQueue.add(ChannelAction.Message.Send(it)) }
                log.debug { "re-sending the exact same previous sig" }
                sendQueue.add(ChannelAction.Message.Send(commitments1.remoteNextCommitInfo.left!!.sent))
                if (revWasSentLast) resendRevocation()
            }
            commitments1.remoteNextCommitInfo.isRight && commitments1.remoteCommit.index + 1 == channelReestablish.nextLocalCommitmentNumber -> {
                // there wasn't any sig in-flight when the disconnection occurred
                resendRevocation()
            }
            else -> throw RevocationSyncError(d.channelId)
        }

        if (commitments1.localHasChanges()) {
            sendQueue.add(ChannelAction.Message.SendToSelf(CMD_SIGN))
        }

        // When a channel is reestablished after a wallet restarts, we need to reprocess incoming HTLCs that may have been only partially processed
        // (either because they didn't reach the payment handler, or because the payment handler response didn't reach the channel).
        // Otherwise these HTLCs will stay in our commitment until they timeout and our peer closes the channel.
        //
        // We are interested in incoming HTLCs, that have been *cross-signed* (otherwise they wouldn't have been forwarded to the payment handler).
        // They signed it first, so the HTLC will first appear in our commitment tx, and later on in their commitment when we subsequently sign it.
        // That's why we need to look in *their* commitment with direction=OUT.
        //
        // We also need to filter out htlcs that we already settled and signed (the settlement messages are being retransmitted).
        val alreadySettled = commitments1.localChanges.signed.filterIsInstance<HtlcSettlementMessage>().map { it.id }.toSet()
        val htlcsToReprocess = commitments1.remoteCommit.spec.htlcs.outgoings().filter { !alreadySettled.contains(it.id) }
        log.debug { "re-processing signed IN: $htlcsToReprocess" }
        sendQueue.addAll(htlcsToReprocess.map { ChannelAction.ProcessIncomingHtlc(it) })

        return Pair(commitments1, sendQueue)
    }
}
