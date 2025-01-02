package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.Bitcoin
import fr.acinq.bitcoin.SigHash
import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_DEPTHOK
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchEventConfirmed
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*

data class Normal(
    override val commitments: Commitments,
    val shortChannelId: ShortChannelId,
    val channelUpdate: ChannelUpdate,
    val remoteChannelUpdate: ChannelUpdate?,
    val localShutdown: Shutdown?,
    val remoteShutdown: Shutdown?,
    val closingFeerates: ClosingFeerates?,
    val spliceStatus: SpliceStatus,
) : ChannelStateWithCommitments() {

    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        val forbiddenPreSplice = cmd is ChannelCommand.ForbiddenDuringQuiescence && spliceStatus is QuiescenceNegotiation
        val forbiddenDuringSplice = cmd is ChannelCommand.ForbiddenDuringSplice && spliceStatus is QuiescentSpliceStatus
        if (forbiddenPreSplice || forbiddenDuringSplice) {
            return when (cmd) {
                is ChannelCommand.Htlc.Settlement -> {
                    // Htlc settlement commands are ignored and will be replayed when the splice completes.
                    // This could create issues if we're keeping htlcs that should be settled pending for too long, as they could timeout.
                    logger.warning { "ignoring ${cmd::class.simpleName} for htlc #${cmd.id} during splice: will be replayed once splice is complete" }
                    Pair(this@Normal, listOf())
                }
                else -> handleCommandError(cmd, ForbiddenDuringSplice(channelId, cmd::class.simpleName), channelUpdate)
            }
        }
        return when (cmd) {
            is ChannelCommand.Htlc.Add -> {
                if (localShutdown != null || remoteShutdown != null) {
                    // note: spec would allow us to keep sending new htlcs after having received their shutdown (and not sent ours)
                    // but we want to converge as fast as possible and they would probably not route them anyway
                    val error = NoMoreHtlcsClosingInProgress(channelId)
                    return handleCommandError(cmd, error, channelUpdate)
                }
                handleCommandResult(cmd, commitments.sendAdd(cmd, cmd.paymentId, currentBlockHeight.toLong()), cmd.commit)
            }
            is ChannelCommand.Htlc.Settlement.Fulfill -> handleCommandResult(cmd, commitments.sendFulfill(cmd), cmd.commit)
            is ChannelCommand.Htlc.Settlement.Fail -> handleCommandResult(cmd, commitments.sendFail(cmd, this.privateKey), cmd.commit)
            is ChannelCommand.Htlc.Settlement.FailMalformed -> handleCommandResult(cmd, commitments.sendFailMalformed(cmd), cmd.commit)
            is ChannelCommand.Commitment.UpdateFee -> handleCommandResult(cmd, commitments.sendFee(cmd), cmd.commit)
            is ChannelCommand.Commitment.Sign -> when {
                !commitments.changes.localHasChanges() -> {
                    logger.info { "no changes to sign" }
                    Pair(this@Normal, listOf())
                }
                commitments.remoteNextCommitInfo is Either.Left -> {
                    logger.debug { "already in the process of signing, will sign again as soon as possible" }
                    Pair(this@Normal, listOf())
                }
                else -> when (val result = commitments.sendCommit(channelKeys(), logger)) {
                    is Either.Left -> handleCommandError(cmd, result.value, channelUpdate)
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
                        val nextState = this@Normal.copy(commitments = commitments1)
                        val actions = buildList {
                            add(ChannelAction.Storage.StoreHtlcInfos(htlcInfos))
                            add(ChannelAction.Storage.StoreState(nextState))
                            addAll(result.value.second.map { ChannelAction.Message.Send(it) })
                        }
                        Pair(nextState, actions)
                    }
                }
            }
            is ChannelCommand.Close.MutualClose -> {
                val allowAnySegwit = Features.canUseFeature(commitments.params.localParams.features, commitments.params.remoteParams.features, Feature.ShutdownAnySegwit)
                val localScriptPubkey = cmd.scriptPubKey ?: commitments.params.localParams.defaultFinalScriptPubKey
                when {
                    localShutdown != null -> handleCommandError(cmd, ClosingAlreadyInProgress(channelId), channelUpdate)
                    commitments.changes.localHasUnsignedOutgoingHtlcs() -> handleCommandError(cmd, CannotCloseWithUnsignedOutgoingHtlcs(channelId), channelUpdate)
                    commitments.changes.localHasUnsignedOutgoingUpdateFee() -> handleCommandError(cmd, CannotCloseWithUnsignedOutgoingUpdateFee(channelId), channelUpdate)
                    !Helpers.Closing.isValidFinalScriptPubkey(localScriptPubkey, allowAnySegwit) -> handleCommandError(cmd, InvalidFinalScript(channelId), channelUpdate)
                    else -> {
                        val shutdown = Shutdown(channelId, localScriptPubkey)
                        val newState = this@Normal.copy(localShutdown = shutdown, closingFeerates = cmd.feerates)
                        val actions = listOf(ChannelAction.Storage.StoreState(newState), ChannelAction.Message.Send(shutdown))
                        Pair(newState, actions)
                    }
                }
            }
            is ChannelCommand.Close.ForceClose -> handleLocalError(cmd, ForcedLocalCommit(channelId))
            is ChannelCommand.Funding.BumpFundingFee -> unhandled(cmd)
            is ChannelCommand.Commitment.Splice.Request -> when (spliceStatus) {
                is SpliceStatus.None -> {
                    if (commitments.localIsQuiescent()) {
                        Pair(this@Normal.copy(spliceStatus = SpliceStatus.InitiatorQuiescent(cmd)), listOf(ChannelAction.Message.Send(Stfu(channelId, initiator = true))))
                    } else {
                        Pair(this@Normal.copy(spliceStatus = SpliceStatus.QuiescenceRequested(cmd)), emptyList())
                    }
                }
                else -> {
                    logger.warning { "cannot initiate splice, another splice is already in progress" }
                    cmd.replyTo.complete(ChannelFundingResponse.Failure.SpliceAlreadyInProgress)
                    Pair(this@Normal, emptyList())
                }
            }
            is ChannelCommand.MessageReceived -> when {
                cmd.message is ForbiddenMessageDuringSplice && spliceStatus is QuiescentSpliceStatus -> {
                    logger.warning { "received forbidden message ${cmd::class.simpleName} during splicing with status ${spliceStatus::class.simpleName}" }
                    // Instead of force-closing (which would cost us on-chain fees), we try to resolve this issue by disconnecting.
                    // This will abort the splice attempt if it hasn't been signed yet, and restore the channel to a clean state.
                    // If the splice attempt was signed, it gives us an opportunity to re-exchange signatures on reconnection before
                    // the forbidden message. It also provides the opportunity for our peer to update their node to get rid of that
                    // bug and resume normal execution.
                    val actions = buildList {
                        add(ChannelAction.Message.Send(Warning(channelId, ForbiddenDuringSplice(channelId, cmd.message::class.simpleName).message)))
                        add(ChannelAction.Disconnect)
                    }
                    Pair(this@Normal, actions)
                }
                else -> when (cmd.message) {
                    is UpdateAddHtlc -> when (val result = commitments.receiveAdd(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> {
                            val newState = this@Normal.copy(commitments = result.value)
                            Pair(newState, listOf())
                        }
                    }
                    is UpdateFulfillHtlc -> when (val result = commitments.receiveFulfill(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> {
                            val (commitments1, paymentId, add) = result.value
                            val htlcResult = ChannelAction.HtlcResult.Fulfill.RemoteFulfill(cmd.message)
                            Pair(this@Normal.copy(commitments = commitments1), listOf(ChannelAction.ProcessCmdRes.AddSettledFulfill(paymentId, add, htlcResult)))
                        }
                    }
                    is UpdateFailHtlc -> when (val result = commitments.receiveFail(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> Pair(this@Normal.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFailMalformedHtlc -> when (val result = commitments.receiveFailMalformed(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> Pair(this@Normal.copy(commitments = result.value.first), listOf())
                    }
                    is UpdateFee -> when (val result = commitments.receiveFee(cmd.message, staticParams.nodeParams.onChainFeeConf.feerateTolerance)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> Pair(this@Normal.copy(commitments = result.value), listOf())
                    }
                    is CommitSig -> when {
                        spliceStatus == SpliceStatus.Aborted -> {
                            logger.warning { "received commit_sig after sending tx_abort, they probably sent it before receiving our tx_abort, ignoring..." }
                            Pair(this@Normal, listOf())
                        }
                        spliceStatus is SpliceStatus.WaitingForSigs -> {
                            val (signingSession1, action) = spliceStatus.session.receiveCommitSig(channelKeys(), commitments.params, cmd.message, currentBlockHeight.toLong(), logger)
                            when (action) {
                                is InteractiveTxSigningSessionAction.AbortFundingAttempt -> {
                                    logger.warning { "splice attempt failed: ${action.reason.message} (fundingTxId=${spliceStatus.session.fundingTx.txId})" }
                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, action.reason.message))))
                                }
                                // No need to store their commit_sig, they will re-send it if we disconnect.
                                InteractiveTxSigningSessionAction.WaitForTxSigs -> {
                                    logger.info { "waiting for tx_sigs" }
                                    Pair(this@Normal.copy(spliceStatus = spliceStatus.copy(session = signingSession1)), listOf())
                                }
                                is InteractiveTxSigningSessionAction.SendTxSigs -> sendSpliceTxSigs(spliceStatus.origins, action, spliceStatus.liquidityPurchase, cmd.message.channelData)
                            }
                        }
                        ignoreRetransmittedCommitSig(cmd.message) -> {
                            // We haven't received our peer's tx_signatures for the latest funding transaction and asked them to resend it on reconnection.
                            // They also resend their corresponding commit_sig, but we have already received it so we should ignore it.
                            // Note that the funding transaction may have confirmed while we were offline.
                            logger.info { "ignoring commit_sig, we're still waiting for tx_signatures" }
                            Pair(this@Normal, listOf())
                        }
                        // NB: in all other cases we process the commit_sig normally. We could do a full pattern matching on all splice statuses, but it would force us to handle
                        // corner cases like race condition between splice_init and a non-splice commit_sig
                        else -> {
                            when (val sigs = aggregateSigs(cmd.message)) {
                                is List<CommitSig> -> when (val result = commitments.receiveCommit(sigs, channelKeys(), logger)) {
                                    is Either.Left -> handleLocalError(cmd, result.value)
                                    is Either.Right -> {
                                        val commitments1 = result.value.first
                                        val spliceStatus1 = when {
                                            spliceStatus is SpliceStatus.QuiescenceRequested && commitments1.localIsQuiescent() -> SpliceStatus.InitiatorQuiescent(spliceStatus.command)
                                            spliceStatus is SpliceStatus.ReceivedStfu && commitments1.localIsQuiescent() -> SpliceStatus.NonInitiatorQuiescent
                                            else -> spliceStatus
                                        }
                                        val nextState = this@Normal.copy(commitments = commitments1, spliceStatus = spliceStatus1)
                                        val actions = mutableListOf<ChannelAction>()
                                        actions.add(ChannelAction.Storage.StoreState(nextState))
                                        actions.add(ChannelAction.Message.Send(result.value.second))
                                        if (commitments1.changes.localHasChanges()) {
                                            actions.add(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign))
                                        }
                                        // If we're now quiescent, we may send our stfu message.
                                        when {
                                            spliceStatus is SpliceStatus.QuiescenceRequested && commitments1.localIsQuiescent() -> actions.add(ChannelAction.Message.Send(Stfu(channelId, initiator = true)))
                                            spliceStatus is SpliceStatus.ReceivedStfu && commitments1.localIsQuiescent() -> actions.add(ChannelAction.Message.Send(Stfu(channelId, initiator = false)))
                                            else -> {}
                                        }
                                        Pair(nextState, actions)
                                    }
                                }
                                else -> Pair(this@Normal, listOf())
                            }
                        }
                    }
                    is RevokeAndAck -> when (val result = commitments.receiveRevocation(cmd.message)) {
                        is Either.Left -> handleLocalError(cmd, result.value)
                        is Either.Right -> {
                            val commitments1 = result.value.first
                            val actions = mutableListOf<ChannelAction>()
                            actions.addAll(result.value.second)
                            if (result.value.first.changes.localHasChanges()) {
                                actions.add(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign))
                            }
                            val nextState = if (remoteShutdown != null && !commitments1.changes.localHasUnsignedOutgoingHtlcs()) {
                                // we were waiting for our pending htlcs to be signed before replying with our local shutdown
                                val localShutdown = Shutdown(channelId, commitments.params.localParams.defaultFinalScriptPubKey)
                                actions.add(ChannelAction.Message.Send(localShutdown))
                                if (commitments1.latest.remoteCommit.spec.htlcs.isNotEmpty()) {
                                    // we just signed htlcs that need to be resolved now
                                    ShuttingDown(commitments1, localShutdown, remoteShutdown, closingFeerates)
                                } else {
                                    logger.warning { "we have no htlcs but have not replied with our Shutdown yet, this should never happen" }
                                    val closingTxProposed = if (paysClosingFees) {
                                        val (closingTx, closingSigned) = Helpers.Closing.makeFirstClosingTx(
                                            channelKeys(),
                                            commitments1.latest,
                                            localShutdown.scriptPubKey.toByteArray(),
                                            remoteShutdown.scriptPubKey.toByteArray(),
                                            closingFeerates ?: ClosingFeerates(currentOnChainFeerates().mutualCloseFeerate),
                                        )
                                        listOf(listOf(ClosingTxProposed(closingTx, closingSigned)))
                                    } else {
                                        listOf(listOf())
                                    }
                                    Negotiating(commitments1, localShutdown, remoteShutdown, closingTxProposed, bestUnpublishedClosingTx = null, closingFeerates)
                                }
                            } else {
                                this@Normal.copy(commitments = commitments1)
                            }
                            actions.add(0, ChannelAction.Storage.StoreState(nextState))
                            Pair(nextState, actions)
                        }
                    }
                    is ChannelUpdate -> {
                        if (cmd.message.isRemote(staticParams.nodeParams.nodeId, staticParams.remoteNodeId)) {
                            val nextState = this@Normal.copy(remoteChannelUpdate = cmd.message)
                            Pair(nextState, listOf(ChannelAction.Storage.StoreState(nextState)))
                        } else {
                            Pair(this@Normal, listOf())
                        }
                    }
                    is Shutdown -> {
                        val allowAnySegwit = Features.canUseFeature(commitments.params.localParams.features, commitments.params.remoteParams.features, Feature.ShutdownAnySegwit)
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
                            !Helpers.Closing.isValidFinalScriptPubkey(cmd.message.scriptPubKey, allowAnySegwit) -> handleLocalError(cmd, InvalidFinalScript(channelId))
                            commitments.changes.remoteHasUnsignedOutgoingHtlcs() -> handleLocalError(cmd, CannotCloseWithUnsignedOutgoingHtlcs(channelId))
                            commitments.changes.remoteHasUnsignedOutgoingUpdateFee() -> handleLocalError(cmd, CannotCloseWithUnsignedOutgoingUpdateFee(channelId))
                            commitments.changes.localHasUnsignedOutgoingHtlcs() -> {
                                require(localShutdown == null) { "can't have pending unsigned outgoing htlcs after having sent Shutdown" }
                                // are we in the middle of a signature?
                                when (commitments.remoteNextCommitInfo) {
                                    is Either.Left -> {
                                        // we already have a signature in progress, will resign when we receive the revocation
                                        Pair(this@Normal.copy(remoteShutdown = cmd.message), listOf())
                                    }
                                    is Either.Right -> {
                                        // no, let's sign right away
                                        val newState = this@Normal.copy(remoteShutdown = cmd.message, commitments = commitments.copy(remoteChannelData = cmd.message.channelData))
                                        Pair(newState, listOf(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign)))
                                    }
                                }
                            }
                            else -> {
                                // so we don't have any unsigned outgoing changes
                                val actions = mutableListOf<ChannelAction>()
                                val localShutdown = this@Normal.localShutdown ?: Shutdown(channelId, commitments.params.localParams.defaultFinalScriptPubKey)
                                if (this@Normal.localShutdown == null) actions.add(ChannelAction.Message.Send(localShutdown))
                                val commitments1 = commitments.copy(remoteChannelData = cmd.message.channelData)
                                when {
                                    commitments1.hasNoPendingHtlcsOrFeeUpdate() && paysClosingFees -> {
                                        val (closingTx, closingSigned) = Helpers.Closing.makeFirstClosingTx(
                                            channelKeys(),
                                            commitments1.latest,
                                            localShutdown.scriptPubKey.toByteArray(),
                                            cmd.message.scriptPubKey.toByteArray(),
                                            closingFeerates ?: ClosingFeerates(currentOnChainFeerates().mutualCloseFeerate),
                                        )
                                        val nextState = Negotiating(
                                            commitments1,
                                            localShutdown,
                                            cmd.message,
                                            listOf(listOf(ClosingTxProposed(closingTx, closingSigned))),
                                            bestUnpublishedClosingTx = null,
                                            closingFeerates
                                        )
                                        actions.addAll(listOf(ChannelAction.Storage.StoreState(nextState), ChannelAction.Message.Send(closingSigned)))
                                        Pair(nextState, actions)
                                    }
                                    commitments1.hasNoPendingHtlcsOrFeeUpdate() -> {
                                        val nextState = Negotiating(commitments1, localShutdown, cmd.message, listOf(listOf()), null, closingFeerates)
                                        actions.add(ChannelAction.Storage.StoreState(nextState))
                                        Pair(nextState, actions)
                                    }
                                    else -> {
                                        // there are some pending changes, we need to wait for them to be settled (fail/fulfill htlcs and sign fee updates)
                                        val nextState = ShuttingDown(commitments1, localShutdown, cmd.message, closingFeerates)
                                        actions.add(ChannelAction.Storage.StoreState(nextState))
                                        Pair(nextState, actions)
                                    }
                                }
                            }
                        }
                    }
                    is Stfu -> when {
                        localShutdown != null -> {
                            logger.warning { "our peer sent stfu but we sent shutdown first" }
                            // We don't need to do anything, they should accept our shutdown.
                            Pair(this@Normal, listOf())
                        }
                        !commitments.remoteIsQuiescent() -> {
                            logger.warning { "our peer sent stfu but is not quiescent" }
                            val actions = buildList {
                                add(ChannelAction.Message.Send(Warning(channelId, InvalidSpliceNotQuiescent(channelId).message)))
                                add(ChannelAction.Disconnect)
                            }
                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.None), actions)
                        }
                        else -> when (spliceStatus) {
                            is SpliceStatus.None -> {
                                if (commitments.localIsQuiescent()) {
                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.NonInitiatorQuiescent), listOf(ChannelAction.Message.Send(Stfu(channelId, initiator = false))))
                                } else {
                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.ReceivedStfu(cmd.message)), emptyList())
                                }
                            }
                            is SpliceStatus.QuiescenceRequested -> {
                                // We could keep track of our splice attempt and merge it with the remote splice instead of cancelling it.
                                // But this is an edge case that should rarely occur, so it's probably not worth the additional complexity.
                                logger.warning { "our peer initiated quiescence before us, cancelling our splice attempt" }
                                spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.ConcurrentRemoteSplice)
                                Pair(this@Normal.copy(spliceStatus = SpliceStatus.ReceivedStfu(cmd.message)), emptyList())
                            }
                            is SpliceStatus.InitiatorQuiescent -> {
                                // if both sides send stfu at the same time, the quiescence initiator is the channel initiator
                                if (!cmd.message.initiator || isChannelOpener) {
                                    if (commitments.isQuiescent()) {
                                        val parentCommitment = commitments.active.first()
                                        val fundingContribution = FundingContributions.computeSpliceContribution(
                                            isInitiator = true,
                                            commitment = parentCommitment,
                                            walletInputs = spliceStatus.command.spliceIn?.walletInputs ?: emptyList(),
                                            localOutputs = spliceStatus.command.spliceOutputs,
                                            targetFeerate = spliceStatus.command.feerate
                                        )
                                        val commitTxFees = when {
                                            paysCommitTxFees -> Transactions.commitTxFee(commitments.params.remoteParams.dustLimit, parentCommitment.remoteCommit.spec)
                                            else -> 0.sat
                                        }
                                        val liquidityFees = when (val requestRemoteFunding = spliceStatus.command.requestRemoteFunding) {
                                            null -> 0.msat
                                            else -> when (requestRemoteFunding.paymentDetails.paymentType) {
                                                LiquidityAds.PaymentType.FromChannelBalance -> requestRemoteFunding.fees(spliceStatus.command.feerate, isChannelCreation = false).total.toMilliSatoshi()
                                                LiquidityAds.PaymentType.FromChannelBalanceForFutureHtlc -> requestRemoteFunding.fees(spliceStatus.command.feerate, isChannelCreation = false).total.toMilliSatoshi()
                                                // Liquidity fees will be deducted from future HTLCs instead of being paid immediately.
                                                LiquidityAds.PaymentType.FromFutureHtlc -> 0.msat
                                                LiquidityAds.PaymentType.FromFutureHtlcWithPreimage -> 0.msat
                                                is LiquidityAds.PaymentType.Unknown -> 0.msat
                                            }
                                        }
                                        val liquidityFeesOwed = (liquidityFees - spliceStatus.command.currentFeeCredit).max(0.msat)
                                        val balanceAfterFees = parentCommitment.localCommit.spec.toLocal + fundingContribution.toMilliSatoshi() - liquidityFeesOwed
                                        if (balanceAfterFees < parentCommitment.localChannelReserve(commitments.params).max(commitTxFees)) {
                                            logger.warning { "cannot do splice: insufficient funds (balanceAfterFees=$balanceAfterFees, liquidityFees=$liquidityFees, feeCredit=${spliceStatus.command.currentFeeCredit})" }
                                            spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.InsufficientFunds(balanceAfterFees, liquidityFees, spliceStatus.command.currentFeeCredit))
                                            val action = listOf(ChannelAction.Message.Send(TxAbort(channelId, InvalidSpliceRequest(channelId).message)))
                                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), action)
                                        } else if (spliceStatus.command.spliceOut?.scriptPubKey?.let { Helpers.Closing.isValidFinalScriptPubkey(it, allowAnySegwit = true) } == false) {
                                            logger.warning { "cannot do splice: invalid splice-out script" }
                                            spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.InvalidSpliceOutPubKeyScript)
                                            val action = listOf(ChannelAction.Message.Send(TxAbort(channelId, InvalidSpliceRequest(channelId).message)))
                                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), action)
                                        } else {
                                            val spliceInit = SpliceInit(
                                                channelId,
                                                fundingContribution = fundingContribution,
                                                lockTime = currentBlockHeight.toLong(),
                                                feerate = spliceStatus.command.feerate,
                                                fundingPubkey = channelKeys().fundingPubKey(parentCommitment.fundingTxIndex + 1),
                                                requestFunding = spliceStatus.command.requestRemoteFunding,
                                            )
                                            logger.info { "initiating splice with local.amount=${spliceInit.fundingContribution}" }
                                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.Requested(spliceStatus.command, spliceInit)), listOf(ChannelAction.Message.Send(spliceInit)))
                                        }
                                    } else {
                                        logger.warning { "cannot initiate splice, channel not quiescent" }
                                        spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.ChannelNotQuiescent)
                                        val actions = buildList {
                                            add(ChannelAction.Message.Send(Warning(channelId, InvalidSpliceNotQuiescent(channelId).message)))
                                            add(ChannelAction.Disconnect)
                                        }
                                        Pair(this@Normal.copy(spliceStatus = SpliceStatus.None), actions)
                                    }
                                } else {
                                    logger.warning { "concurrent stfu received and our peer is the channel initiator, cancelling our splice attempt" }
                                    spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.ConcurrentRemoteSplice)
                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.NonInitiatorQuiescent), emptyList())
                                }
                            }
                            else -> {
                                logger.warning { "ignoring duplicate stfu" }
                                Pair(this@Normal, emptyList())
                            }
                        }
                    }
                    is SpliceInit -> when (spliceStatus) {
                        is SpliceStatus.None -> {
                            logger.warning { "rejecting splice attempt: quiescence not negotiated" }
                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, InvalidSpliceNotQuiescent(channelId).message))))
                        }
                        is SpliceStatus.NonInitiatorQuiescent ->
                            if (commitments.isQuiescent()) {
                                logger.info { "accepting splice with remote.amount=${cmd.message.fundingContribution}" }
                                val parentCommitment = commitments.active.first()
                                val spliceAck = SpliceAck(
                                    channelId,
                                    fundingContribution = 0.sat, // only remote contributes to the splice
                                    fundingPubkey = channelKeys().fundingPubKey(parentCommitment.fundingTxIndex + 1),
                                    willFund = null,
                                )
                                val fundingParams = InteractiveTxParams(
                                    channelId = channelId,
                                    isInitiator = false,
                                    localContribution = spliceAck.fundingContribution,
                                    remoteContribution = cmd.message.fundingContribution,
                                    sharedInput = SharedFundingInput.Multisig2of2(parentCommitment),
                                    remoteFundingPubkey = cmd.message.fundingPubkey,
                                    localOutputs = emptyList(),
                                    lockTime = cmd.message.lockTime,
                                    dustLimit = commitments.params.localParams.dustLimit.max(commitments.params.remoteParams.dustLimit),
                                    targetFeerate = cmd.message.feerate
                                )
                                val session = InteractiveTxSession(
                                    staticParams.remoteNodeId,
                                    channelKeys(),
                                    keyManager.swapInOnChainWallet,
                                    fundingParams,
                                    previousLocalBalance = parentCommitment.localCommit.spec.toLocal,
                                    previousRemoteBalance = parentCommitment.localCommit.spec.toRemote,
                                    localHtlcs = parentCommitment.localCommit.spec.htlcs,
                                    fundingContributions = FundingContributions(emptyList(), emptyList()), // as non-initiator we don't contribute to this splice for now
                                    previousTxs = emptyList()
                                )
                                val nextState = this@Normal.copy(
                                    spliceStatus = SpliceStatus.InProgress(
                                        replyTo = null,
                                        session,
                                        liquidityPurchase = null,
                                        origins = listOf()
                                    )
                                )
                                Pair(nextState, listOf(ChannelAction.Message.Send(spliceAck)))
                            } else {
                                logger.warning { "rejecting splice attempt: channel is not quiescent" }
                                Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, InvalidSpliceNotQuiescent(channelId).message))))
                            }
                        is SpliceStatus.Aborted -> {
                            logger.info { "rejecting splice attempt: our previous tx_abort was not acked" }
                            Pair(this@Normal, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidSpliceAbortNotAcked(channelId).message))))
                        }
                        else -> {
                            logger.info { "rejecting splice attempt: the current splice attempt must be completed or aborted first" }
                            Pair(this@Normal, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidSpliceAlreadyInProgress(channelId).message))))
                        }
                    }
                    is SpliceAck -> when (spliceStatus) {
                        is SpliceStatus.Requested -> {
                            logger.info { "our peer accepted our splice request with remote.amount=${cmd.message.fundingContribution} liquidityFees=${spliceStatus.command.liquidityFees}" }
                            when (val liquidityPurchase = LiquidityAds.validateRemoteFunding(
                                spliceStatus.command.requestRemoteFunding,
                                remoteNodeId,
                                channelId,
                                Helpers.Funding.makeFundingPubKeyScript(spliceStatus.spliceInit.fundingPubkey, cmd.message.fundingPubkey),
                                cmd.message.fundingContribution,
                                spliceStatus.spliceInit.feerate,
                                isChannelCreation = false,
                                cmd.message.feeCreditUsed,
                                cmd.message.willFund,
                            )) {
                                is Either.Left<ChannelException> -> {
                                    logger.error { "rejecting liquidity proposal: ${liquidityPurchase.value.message}" }
                                    spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.InvalidLiquidityAds(liquidityPurchase.value))
                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, liquidityPurchase.value.message))))
                                }
                                is Either.Right<LiquidityAds.Purchase?> -> {
                                    val parentCommitment = commitments.active.first()
                                    val sharedInput = SharedFundingInput.Multisig2of2(parentCommitment)
                                    val fundingParams = InteractiveTxParams(
                                        channelId = channelId,
                                        isInitiator = true,
                                        localContribution = spliceStatus.spliceInit.fundingContribution,
                                        remoteContribution = cmd.message.fundingContribution,
                                        sharedInput = sharedInput,
                                        remoteFundingPubkey = cmd.message.fundingPubkey,
                                        localOutputs = spliceStatus.command.spliceOutputs,
                                        lockTime = spliceStatus.spliceInit.lockTime,
                                        dustLimit = commitments.params.localParams.dustLimit.max(commitments.params.remoteParams.dustLimit),
                                        targetFeerate = spliceStatus.spliceInit.feerate
                                    )
                                    when (val fundingContributions = FundingContributions.create(
                                        channelKeys = channelKeys(),
                                        swapInKeys = keyManager.swapInOnChainWallet,
                                        params = fundingParams,
                                        sharedUtxo = Pair(sharedInput, SharedFundingInputBalances(toLocal = parentCommitment.localCommit.spec.toLocal, toRemote = parentCommitment.localCommit.spec.toRemote, toHtlcs = parentCommitment.localCommit.spec.htlcs.map { it.add.amountMsat }.sum())),
                                        walletInputs = spliceStatus.command.spliceIn?.walletInputs ?: emptyList(),
                                        localOutputs = spliceStatus.command.spliceOutputs,
                                        liquidityPurchase = liquidityPurchase.value,
                                        changePubKey = null // we don't want a change output: we're spending every funds available
                                    )) {
                                        is Either.Left -> {
                                            logger.error { "could not create splice contributions: ${fundingContributions.value}" }
                                            spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.FundingFailure(fundingContributions.value))
                                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, ChannelFundingError(channelId).message))))
                                        }
                                        is Either.Right -> {
                                            // The splice initiator always sends the first interactive-tx message.
                                            val (interactiveTxSession, interactiveTxAction) = InteractiveTxSession(
                                                staticParams.remoteNodeId,
                                                channelKeys(),
                                                keyManager.swapInOnChainWallet,
                                                fundingParams,
                                                previousLocalBalance = parentCommitment.localCommit.spec.toLocal,
                                                previousRemoteBalance = parentCommitment.localCommit.spec.toRemote,
                                                localHtlcs = parentCommitment.localCommit.spec.htlcs,
                                                fundingContributions = fundingContributions.value,
                                                previousTxs = emptyList()
                                            ).send()
                                            when (interactiveTxAction) {
                                                is InteractiveTxSessionAction.SendMessage -> {
                                                    val nextState = this@Normal.copy(
                                                        spliceStatus = SpliceStatus.InProgress(
                                                            replyTo = spliceStatus.command.replyTo,
                                                            interactiveTxSession,
                                                            liquidityPurchase = liquidityPurchase.value,
                                                            origins = spliceStatus.command.origins,
                                                        )
                                                    )
                                                    Pair(nextState, listOf(ChannelAction.Message.Send(interactiveTxAction.msg)))
                                                }
                                                else -> {
                                                    logger.error { "could not start interactive-tx session: $interactiveTxAction" }
                                                    spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.CannotStartSession)
                                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, ChannelFundingError(channelId).message))))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else -> {
                            logger.warning { "ignoring unexpected splice_ack" }
                            Pair(this@Normal, emptyList())
                        }
                    }
                    is InteractiveTxConstructionMessage -> when (spliceStatus) {
                        is SpliceStatus.InProgress -> {
                            val (interactiveTxSession, interactiveTxAction) = spliceStatus.spliceSession.receive(cmd.message)
                            when (interactiveTxAction) {
                                is InteractiveTxSessionAction.SendMessage -> Pair(this@Normal.copy(spliceStatus = spliceStatus.copy(spliceSession = interactiveTxSession)), listOf(ChannelAction.Message.Send(interactiveTxAction.msg)))
                                is InteractiveTxSessionAction.SignSharedTx -> {
                                    val parentCommitment = commitments.active.first()
                                    val signingSession = InteractiveTxSigningSession.create(
                                        interactiveTxSession,
                                        keyManager,
                                        commitments.params,
                                        spliceStatus.spliceSession.fundingParams,
                                        fundingTxIndex = parentCommitment.fundingTxIndex + 1,
                                        interactiveTxAction.sharedTx,
                                        liquidityPurchase = spliceStatus.liquidityPurchase,
                                        localCommitmentIndex = parentCommitment.localCommit.index,
                                        remoteCommitmentIndex = parentCommitment.remoteCommit.index,
                                        parentCommitment.localCommit.spec.feerate,
                                        parentCommitment.remoteCommit.remotePerCommitmentPoint,
                                        localHtlcs = parentCommitment.localCommit.spec.htlcs
                                    )
                                    when (signingSession) {
                                        is Either.Left -> {
                                            logger.error(signingSession.value) { "cannot initiate interactive-tx splice signing session" }
                                            spliceStatus.replyTo?.complete(ChannelFundingResponse.Failure.CannotCreateCommitTx(signingSession.value))
                                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, signingSession.value.message))))
                                        }
                                        is Either.Right -> {
                                            val (session, commitSig) = signingSession.value
                                            logger.info { "splice funding tx created with txId=${session.fundingTx.txId}, ${session.fundingTx.tx.localInputs.size} local inputs, ${session.fundingTx.tx.remoteInputs.size} remote inputs, ${session.fundingTx.tx.localOutputs.size} local outputs and ${session.fundingTx.tx.remoteOutputs.size} remote outputs" }
                                            // We cannot guarantee that the splice is successful: the only way to guarantee that is to wait for on-chain confirmations.
                                            // It is likely that we will restart before the transaction is confirmed, in which case we will lose the replyTo and the ability to notify the caller.
                                            // We should be able to resume the signing steps and complete the splice if we disconnect, so we optimistically notify the caller now.
                                            spliceStatus.replyTo?.complete(
                                                ChannelFundingResponse.Success(
                                                    channelId = channelId,
                                                    fundingTxIndex = session.fundingTxIndex,
                                                    fundingTxId = session.fundingTx.txId,
                                                    capacity = session.fundingParams.fundingAmount,
                                                    balance = session.localCommit.fold({ it.spec }, { it.spec }).toLocal,
                                                    liquidityPurchase = spliceStatus.liquidityPurchase,
                                                )
                                            )
                                            val nextState = this@Normal.copy(spliceStatus = SpliceStatus.WaitingForSigs(session, spliceStatus.liquidityPurchase, spliceStatus.origins))
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
                                    spliceStatus.replyTo?.complete(ChannelFundingResponse.Failure.InteractiveTxSessionFailed(interactiveTxAction))
                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, interactiveTxAction.toString()))))
                                }
                            }
                        }
                        else -> {
                            logger.info { "ignoring unexpected interactive-tx message: ${cmd.message::class}" }
                            Pair(this@Normal, listOf(ChannelAction.Message.Send(Warning(channelId, UnexpectedInteractiveTxMessage(channelId, cmd.message).message))))
                        }
                    }
                    is TxSignatures -> when (spliceStatus) {
                        is SpliceStatus.WaitingForSigs -> {
                            when (val res = spliceStatus.session.receiveTxSigs(channelKeys(), cmd.message, currentBlockHeight.toLong())) {
                                is Either.Left -> {
                                    val action: InteractiveTxSigningSessionAction.AbortFundingAttempt = res.value
                                    logger.warning { "splice attempt failed: ${action.reason.message}" }
                                    Pair(this@Normal.copy(spliceStatus = SpliceStatus.Aborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, action.reason.message))))
                                }
                                is Either.Right -> {
                                    val action: InteractiveTxSigningSessionAction.SendTxSigs = res.value
                                    sendSpliceTxSigs(spliceStatus.origins, action, spliceStatus.liquidityPurchase, cmd.message.channelData)
                                }
                            }
                        }
                        else -> when (commitments.latest.localFundingStatus) {
                            is LocalFundingStatus.UnconfirmedFundingTx -> when (commitments.latest.localFundingStatus.sharedTx) {
                                is PartiallySignedSharedTransaction -> when (val fullySignedTx =
                                    commitments.latest.localFundingStatus.sharedTx.addRemoteSigs(channelKeys(), commitments.latest.localFundingStatus.fundingParams, cmd.message)) {
                                    null -> {
                                        logger.warning { "received invalid remote funding signatures for txId=${cmd.message.txId}" }
                                        logger.warning { "tx=${commitments.latest.localFundingStatus.sharedTx}" }
                                        // The funding transaction may still confirm (since our peer should be able to generate valid signatures), so we cannot close the channel yet.
                                        Pair(this@Normal, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidFundingSignature(channelId, cmd.message.txId).message))))
                                    }
                                    else -> {
                                        when (val res = commitments.run { updateLocalFundingSigned(fullySignedTx) }) {
                                            is Either.Left -> Pair(this@Normal, listOf())
                                            is Either.Right -> {
                                                logger.info { "received remote funding signatures, publishing txId=${fullySignedTx.signedTx.txid} fundingTxIndex=${commitments.latest.fundingTxIndex}" }
                                                val nextState = this@Normal.copy(commitments = res.value.first)
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
                                    logger.info { "ignoring duplicate remote funding signatures for txId=${cmd.message.txId}" }
                                    Pair(this@Normal, listOf())
                                }
                            }
                            is LocalFundingStatus.ConfirmedFundingTx -> {
                                logger.info { "ignoring funding signatures for txId=${cmd.message.txId}, transaction is already confirmed" }
                                Pair(this@Normal, listOf())
                            }
                        }
                    }
                    is TxAbort -> when (spliceStatus) {
                        is SpliceStatus.Requested -> {
                            logger.info { "our peer rejected our splice request: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data}" }
                            spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.AbortedByPeer(cmd.message.toAscii()))
                            val actions = buildList {
                                add(ChannelAction.Message.Send(TxAbort(channelId, SpliceAborted(channelId).message)))
                                addAll(endQuiescence())
                            }
                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.None), actions)
                        }
                        is SpliceStatus.InProgress -> {
                            logger.info { "our peer aborted the splice attempt: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data}" }
                            spliceStatus.replyTo?.complete(ChannelFundingResponse.Failure.AbortedByPeer(cmd.message.toAscii()))
                            val actions = buildList {
                                add(ChannelAction.Message.Send(TxAbort(channelId, SpliceAborted(channelId).message)))
                                addAll(endQuiescence())
                            }
                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.None), actions)
                        }
                        is SpliceStatus.WaitingForSigs -> {
                            logger.info { "our peer aborted the splice attempt: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data}" }
                            val nextState = this@Normal.copy(spliceStatus = SpliceStatus.None)
                            val actions = buildList {
                                add(ChannelAction.Storage.StoreState(nextState))
                                add(ChannelAction.Message.Send(TxAbort(channelId, SpliceAborted(channelId).message)))
                                addAll(endQuiescence())
                            }
                            Pair(nextState, actions)
                        }
                        is SpliceStatus.Aborted -> {
                            logger.info { "our peer acked our previous tx_abort" }
                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.None), endQuiescence())
                        }
                        is SpliceStatus.None -> {
                            logger.info { "our peer wants to abort the splice, but we've already negotiated a splice transaction: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data}" }
                            // We ack their tx_abort but we keep monitoring the funding transaction until it's confirmed or double-spent.
                            Pair(this@Normal, listOf(ChannelAction.Message.Send(TxAbort(channelId, SpliceAborted(channelId).message))))
                        }
                        is SpliceStatus.NonInitiatorQuiescent -> {
                            logger.info { "our peer aborted their own splice attempt: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data}" }
                            val actions = buildList {
                                add(ChannelAction.Message.Send(TxAbort(channelId, SpliceAborted(channelId).message)))
                                addAll(endQuiescence())
                            }
                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.None), actions)
                        }
                        is QuiescenceNegotiation -> {
                            logger.info { "our peer aborted the splice during quiescence negotiation, disconnecting: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data}" }
                            val actions = buildList {
                                add(ChannelAction.Message.Send(Warning(channelId, UnexpectedInteractiveTxMessage(channelId, cmd.message).message)))
                                add(ChannelAction.Disconnect)
                            }
                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.None), actions)
                        }
                    }
                    is CancelOnTheFlyFunding -> when (spliceStatus) {
                        is SpliceStatus.Requested -> {
                            logger.info { "our peer rejected our on-the-fly splice request: ascii='${cmd.message.toAscii()}'" }
                            spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.AbortedByPeer(cmd.message.toAscii()))
                            Pair(this@Normal.copy(spliceStatus = SpliceStatus.None), endQuiescence())
                        }
                        else -> {
                            logger.warning { "received unexpected cancel_on_the_fly_funding (spliceStatus=${spliceStatus::class.simpleName}, message='${cmd.message.toAscii()}')" }
                            Pair(this@Normal, listOf(ChannelAction.Disconnect))
                        }
                    }
                    is SpliceLocked -> {
                        when (val res = commitments.run { updateRemoteFundingStatus(cmd.message.fundingTxId) }) {
                            is Either.Left -> Pair(this@Normal, emptyList())
                            is Either.Right -> {
                                val (commitments1, _) = res.value
                                val nextState = this@Normal.copy(commitments = commitments1)
                                val actions = buildList {
                                    newlyLocked(commitments, commitments1).forEach { add(ChannelAction.Storage.SetLocked(it.fundingTxId)) }
                                    add(ChannelAction.Storage.StoreState(nextState))
                                }
                                Pair(nextState, actions)
                            }
                        }
                    }
                    is Error -> handleRemoteError(cmd.message)
                    else -> unhandled(cmd)
                }
            }
            is ChannelCommand.Commitment.CheckHtlcTimeout -> checkHtlcTimeout()
            is ChannelCommand.WatchReceived -> when (val watch = cmd.watch) {
                is WatchEventConfirmed -> {
                    val (nextState, actions) = updateFundingTxStatus(watch)
                    if (!staticParams.useZeroConf && nextState.commitments.active.any { it.fundingTxId == watch.tx.txid && it.fundingTxIndex > 0 }) {
                        // We're not using 0-conf and a splice transaction is confirmed, so we send splice_locked.
                        val spliceLocked = SpliceLocked(channelId, watch.tx.txid)
                        Pair(nextState, actions + ChannelAction.Message.Send(spliceLocked))
                    } else {
                        Pair(nextState, actions)
                    }
                }
                is WatchEventSpent -> handlePotentialForceClose(watch)
            }
            is ChannelCommand.Disconnected -> {
                // if we have pending unsigned outgoing htlcs, then we cancel them and advertise the fact that the channel is now disabled.
                val failedHtlcs = mutableListOf<ChannelAction>()
                val proposedHtlcs = commitments.changes.localChanges.proposed.filterIsInstance<UpdateAddHtlc>()
                proposedHtlcs.forEach { htlc ->
                    commitments.payments[htlc.id]?.let { paymentId ->
                        failedHtlcs.add(ChannelAction.ProcessCmdRes.AddSettledFail(paymentId, htlc, ChannelAction.HtlcResult.Fail.Disconnected))
                    } ?: logger.warning { "cannot find payment for $htlc" }
                }
                // If we are splicing and are early in the process, then we cancel it.
                val spliceStatus1 = when (spliceStatus) {
                    is SpliceStatus.None -> SpliceStatus.None
                    is SpliceStatus.Aborted -> SpliceStatus.None
                    is SpliceStatus.Requested -> {
                        spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.Disconnected)
                        SpliceStatus.None
                    }
                    is SpliceStatus.InProgress -> {
                        spliceStatus.replyTo?.complete(ChannelFundingResponse.Failure.Disconnected)
                        SpliceStatus.None
                    }
                    is SpliceStatus.WaitingForSigs -> spliceStatus
                    is SpliceStatus.NonInitiatorQuiescent -> SpliceStatus.None
                    is QuiescenceNegotiation.NonInitiator -> SpliceStatus.None
                    is QuiescenceNegotiation.Initiator -> {
                        spliceStatus.command.replyTo.complete(ChannelFundingResponse.Failure.Disconnected)
                        SpliceStatus.None
                    }
                }
                // reset the commit_sig batch
                sigStash = emptyList()
                Pair(Offline(this@Normal.copy(spliceStatus = spliceStatus1)), failedHtlcs)
            }
            is ChannelCommand.Connected -> unhandled(cmd)
            is ChannelCommand.Closing -> unhandled(cmd)
            is ChannelCommand.Init -> unhandled(cmd)
        }
    }

    private fun ChannelContext.sendSpliceTxSigs(
        origins: List<Origin>,
        action: InteractiveTxSigningSessionAction.SendTxSigs,
        liquidityPurchase: LiquidityAds.Purchase?,
        remoteChannelData: EncryptedChannelData
    ): Pair<Normal, List<ChannelAction>> {
        logger.info { "sending tx_sigs" }
        // We watch for confirmation in all cases, to allow pruning outdated commitments when transactions confirm.
        val fundingMinDepth = Helpers.minDepthForFunding(staticParams.nodeParams, action.fundingTx.fundingParams.fundingAmount)
        val watchConfirmed = WatchConfirmed(channelId, action.commitment.fundingTxId, action.commitment.commitInput.txOut.publicKeyScript, fundingMinDepth.toLong(), BITCOIN_FUNDING_DEPTHOK)
        val commitments = commitments.add(action.commitment).copy(remoteChannelData = remoteChannelData)
        val nextState = this@Normal.copy(commitments = commitments, spliceStatus = SpliceStatus.None)
        val actions = buildList {
            add(ChannelAction.Storage.StoreState(nextState))
            action.fundingTx.signedTx?.let { add(ChannelAction.Blockchain.PublishTx(it, ChannelAction.Blockchain.PublishTx.Type.FundingTx)) }
            add(ChannelAction.Blockchain.SendWatch(watchConfirmed))
            add(ChannelAction.Message.Send(action.localSigs))
            // If we purchased liquidity as part of the splice, we will add it to our payments db.
            liquidityPurchase?.let { purchase ->
                // If we are purchasing liquidity without any other operation (splice-in, splice-out or splice-cpfp),
                // we must include the mining fees we're paying for the shared input and shared output.
                // Otherwise, we only count the mining fees that we must refund to our peer as part of the liquidity
                // purchase: the mining fees we pay for our inputs/outputs and the shared input/output will be recorded
                // in the dedicated splice entry below.
                val isPurchaseOnly = action.fundingTx.sharedTx.tx.let {
                    action.fundingTx.fundingParams.isInitiator && it.localInputs.isEmpty() && it.localOutputs.isEmpty() && it.remoteInputs.isNotEmpty()
                }
                val localMiningFees = if (isPurchaseOnly) action.fundingTx.sharedTx.tx.localFees.truncateToSatoshi() else 0.sat
                add(ChannelAction.Storage.StoreOutgoingPayment.ViaInboundLiquidityRequest(txId = action.fundingTx.txId, localMiningFees = localMiningFees, purchase = purchase))
                add(ChannelAction.EmitEvent(LiquidityEvents.Purchased(purchase)))
            }
            // NB: the following assumes that there can't be a splice-in and a splice-out simultaneously,
            // or more than one splice-out, because we attribute all local mining fees to each payment entry.
            if (action.fundingTx.sharedTx.tx.localInputs.isNotEmpty()) add(
                ChannelAction.Storage.StoreIncomingPayment.ViaSpliceIn(
                    amountReceived = action.fundingTx.sharedTx.tx.localInputs.map { i -> i.txOut.amount }.sum().toMilliSatoshi() - action.fundingTx.sharedTx.tx.localFees,
                    miningFee = action.fundingTx.sharedTx.tx.localFees.truncateToSatoshi(),
                    localInputs = action.fundingTx.sharedTx.tx.localInputs.map { it.outPoint }.toSet(),
                    txId = action.fundingTx.txId,
                    origin = origins.filterIsInstance<Origin.OnChainWallet>().firstOrNull()
                )
            )
            addAll(action.fundingTx.fundingParams.localOutputs.map { txOut ->
                ChannelAction.Storage.StoreOutgoingPayment.ViaSpliceOut(
                    amount = txOut.amount,
                    miningFees = action.fundingTx.sharedTx.tx.localFees.truncateToSatoshi(),
                    address = Bitcoin.addressFromPublicKeyScript(staticParams.nodeParams.chainHash, txOut.publicKeyScript.toByteArray()).right ?: "unknown",
                    txId = action.fundingTx.txId
                )
            })
            // If we initiated the splice but there are no new inputs on either side and no new output on our side, it's a cpfp.
            if (action.fundingTx.fundingParams.isInitiator && action.fundingTx.sharedTx.tx.localInputs.isEmpty() && action.fundingTx.sharedTx.tx.remoteInputs.isEmpty() && action.fundingTx.fundingParams.localOutputs.isEmpty()) {
                add(ChannelAction.Storage.StoreOutgoingPayment.ViaSpliceCpfp(miningFees = action.fundingTx.sharedTx.tx.localFees.truncateToSatoshi(), txId = action.fundingTx.txId))
            }
            origins.filterIsInstance<Origin.OnChainWallet>().forEach { origin ->
                add(ChannelAction.EmitEvent(SwapInEvents.Accepted(origin.inputs, origin.amountBeforeFees.truncateToSatoshi(), origin.fees)))
            }
            if (staticParams.useZeroConf) {
                logger.info { "channel is using 0-conf, sending splice_locked right away" }
                val spliceLocked = SpliceLocked(channelId, action.fundingTx.txId)
                add(ChannelAction.Message.Send(spliceLocked))
            }
            addAll(endQuiescence())
        }
        return Pair(nextState, actions)
    }

    /** This function should be used to ignore a commit_sig that we've already received. */
    private fun ignoreRetransmittedCommitSig(commit: CommitSig): Boolean {
        // If we already have a signed commitment transaction containing their signature, we must have previously received that commit_sig.
        val commitTx = commitments.latest.localCommit.publishableTxs.commitTx.tx
        return commitments.params.channelFeatures.hasFeature(Feature.DualFunding) &&
                commit.batchSize == 1 &&
                commitTx.txIn.first().witness.stack.contains(Scripts.der(commit.signature, SigHash.SIGHASH_ALL))
    }

    /** If we haven't completed the signing steps of an interactive-tx session, we will ask our peer to retransmit signatures for the corresponding transaction. */
    fun getUnsignedFundingTxId(): TxId? = when {
        spliceStatus is SpliceStatus.WaitingForSigs -> spliceStatus.session.fundingTx.txId
        commitments.latest.localFundingStatus is LocalFundingStatus.UnconfirmedFundingTx && commitments.latest.localFundingStatus.sharedTx is PartiallySignedSharedTransaction -> commitments.latest.localFundingStatus.txId
        else -> null
    }

    /** Returns true if the [shortChannelId] matches one of our commitments or our alias. */
    fun matchesShortChannelId(shortChannelId: ShortChannelId): Boolean = shortChannelId == this.shortChannelId || this.commitments.resolveCommitment(shortChannelId) != null

    private fun ChannelContext.handleCommandResult(command: ChannelCommand, result: Either<ChannelException, Pair<Commitments, LightningMessage>>, commit: Boolean): Pair<ChannelState, List<ChannelAction>> {
        return when (result) {
            is Either.Left -> handleCommandError(command, result.value, channelUpdate)
            is Either.Right -> {
                val (commitments1, message) = result.value
                val actions = mutableListOf<ChannelAction>(ChannelAction.Message.Send(message))
                if (commit) {
                    actions.add(ChannelAction.Message.SendToSelf(ChannelCommand.Commitment.Sign))
                }
                Pair(this@Normal.copy(commitments = commitments1), actions)
            }
        }
    }

    private fun endQuiescence(): List<ChannelAction> {
        return commitments.reprocessIncomingHtlcs()
    }
}
