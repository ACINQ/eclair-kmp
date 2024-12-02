package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.TxId
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_DEPTHOK
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchEventConfirmed
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.*

/** We wait for the channel funding transaction to confirm. */
data class WaitForFundingConfirmed(
    override val commitments: Commitments,
    val waitingSinceBlock: Long, // how many blocks have we been waiting for the funding tx to confirm
    val deferred: ChannelReady?,
    // We can have at most one ongoing RBF attempt.
    val rbfStatus: RbfStatus
) : ChannelStateWithCommitments() {

    val latestFundingTx = commitments.latest.localFundingStatus as LocalFundingStatus.UnconfirmedFundingTx
    private val allFundingTxs = commitments.active.map { it.localFundingStatus }.filterIsInstance<LocalFundingStatus.UnconfirmedFundingTx>()
    val previousFundingTxs = allFundingTxs.filter { it.txId != latestFundingTx.txId }

    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.MessageReceived -> when (cmd.message) {
                is TxSignatures -> when (latestFundingTx.sharedTx) {
                    is PartiallySignedSharedTransaction -> when (val fullySignedTx = latestFundingTx.sharedTx.addRemoteSigs(channelKeys(), latestFundingTx.fundingParams, cmd.message)) {
                        null -> {
                            logger.warning { "received invalid remote funding signatures for txId=${cmd.message.txId}" }
                            // The funding transaction may still confirm (since our peer should be able to generate valid signatures), so we cannot close the channel yet.
                            Pair(this@WaitForFundingConfirmed, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidFundingSignature(channelId, cmd.message.txId).message))))
                        }
                        else -> {
                            when (val res = commitments.run { updateLocalFundingSigned(fullySignedTx) }) {
                                is Either.Left -> Pair(this@WaitForFundingConfirmed, listOf())
                                is Either.Right -> {
                                    logger.info { "received remote funding signatures, publishing txId=${fullySignedTx.signedTx.txid}" }
                                    val nextState = this@WaitForFundingConfirmed.copy(commitments = res.value.first)
                                    val actions = buildList {
                                        add(ChannelAction.Blockchain.PublishTx(fullySignedTx.signedTx, ChannelAction.Blockchain.PublishTx.Type.FundingTx))
                                        add(ChannelAction.Storage.StoreState(nextState))
                                    }
                                    Pair(nextState, actions)
                                }
                            }
                        }
                    }
                    is FullySignedSharedTransaction -> when (rbfStatus) {
                        is RbfStatus.WaitingForSigs -> {
                            when (val res = rbfStatus.session.receiveTxSigs(channelKeys(), cmd.message, currentBlockHeight.toLong())) {
                                is Either.Left -> {
                                    val action: InteractiveTxSigningSessionAction.AbortFundingAttempt = res.value
                                    logger.warning { "rbf attempt failed: ${action.reason.message}" }
                                    Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.RbfAborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, action.reason.message))))
                                }
                                is Either.Right -> {
                                    val action: InteractiveTxSigningSessionAction.SendTxSigs = res.value
                                    sendRbfTxSigs(action)
                                }
                            }
                        }
                        else -> {
                            logger.warning { "rejecting unexpected tx_signatures for txId=${cmd.message.txId}" }
                            Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.RbfAborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, UnexpectedFundingSignatures(channelId).message))))
                        }
                    }
                }
                is TxInitRbf -> {
                    if (isChannelOpener) {
                        logger.info { "rejecting tx_init_rbf, we're the initiator, not them!" }
                        Pair(this@WaitForFundingConfirmed, listOf(ChannelAction.Message.Send(Error(channelId, InvalidRbfNonInitiator(channelId).message))))
                    } else {
                        val minNextFeerate = latestFundingTx.fundingParams.minNextFeerate
                        when (rbfStatus) {
                            RbfStatus.None -> {
                                if (cmd.message.feerate < minNextFeerate) {
                                    logger.info { "rejecting rbf attempt: the new feerate must be at least $minNextFeerate (proposed=${cmd.message.feerate})" }
                                    Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.RbfAborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, InvalidRbfFeerate(channelId, cmd.message.feerate, minNextFeerate).message))))
                                } else {
                                    logger.info { "our peer wants to raise the feerate of the funding transaction (previous=${latestFundingTx.fundingParams.targetFeerate} target=${cmd.message.feerate})" }
                                    val fundingParams = InteractiveTxParams(
                                        channelId,
                                        isChannelOpener,
                                        latestFundingTx.fundingParams.localContribution, // we don't change our funding contribution
                                        cmd.message.fundingContribution,
                                        latestFundingTx.fundingParams.remoteFundingPubkey,
                                        cmd.message.lockTime,
                                        latestFundingTx.fundingParams.dustLimit,
                                        cmd.message.feerate
                                    )
                                    val toSend = buildList<Either<InteractiveTxInput.Outgoing, InteractiveTxOutput.Outgoing>> {
                                        addAll(latestFundingTx.sharedTx.tx.localInputs.map { Either.Left(it) })
                                        addAll(latestFundingTx.sharedTx.tx.localOutputs.map { Either.Right(it) })
                                    }
                                    val session = InteractiveTxSession(staticParams.remoteNodeId, channelKeys(), keyManager.swapInOnChainWallet, fundingParams, SharedFundingInputBalances(0.msat, 0.msat, 0.msat), toSend, previousFundingTxs.map { it.sharedTx }, commitments.latest.localCommit.spec.htlcs)
                                    val nextState = this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.InProgress(session))
                                    Pair(nextState, listOf(ChannelAction.Message.Send(TxAckRbf(channelId, fundingParams.localContribution))))
                                }
                            }
                            RbfStatus.RbfAborted -> {
                                logger.info { "rejecting rbf attempt: our previous tx_abort was not acked" }
                                Pair(this@WaitForFundingConfirmed, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfTxAbortNotAcked(channelId).message))))
                            }
                            else -> {
                                logger.info { "rejecting rbf attempt: the current rbf attempt must be completed or aborted first" }
                                Pair(this@WaitForFundingConfirmed, listOf(ChannelAction.Message.Send(Warning(channelId, InvalidRbfAlreadyInProgress(channelId).message))))
                            }
                        }
                    }
                }
                is TxAckRbf -> when (rbfStatus) {
                    is RbfStatus.RbfRequested -> {
                        logger.info { "our peer accepted our rbf attempt and will contribute ${cmd.message.fundingContribution} to the funding transaction" }
                        val fundingParams = InteractiveTxParams(
                            channelId,
                            isChannelOpener,
                            rbfStatus.command.fundingAmount,
                            cmd.message.fundingContribution,
                            latestFundingTx.fundingParams.remoteFundingPubkey,
                            rbfStatus.command.lockTime,
                            latestFundingTx.fundingParams.dustLimit,
                            rbfStatus.command.targetFeerate
                        )
                        when (val contributions = FundingContributions.create(channelKeys(), keyManager.swapInOnChainWallet, fundingParams, rbfStatus.command.walletInputs, null)) {
                            is Either.Left -> {
                                logger.warning { "error creating funding contributions: ${contributions.value}" }
                                Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.RbfAborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, ChannelFundingError(channelId).message))))
                            }
                            is Either.Right -> {
                                val (session, action) = InteractiveTxSession(staticParams.remoteNodeId, channelKeys(), keyManager.swapInOnChainWallet, fundingParams, 0.msat, 0.msat, emptySet(), contributions.value, previousFundingTxs.map { it.sharedTx }).send()
                                when (action) {
                                    is InteractiveTxSessionAction.SendMessage -> {
                                        val nextState = this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.InProgress(session))
                                        Pair(nextState, listOf(ChannelAction.Message.Send(action.msg)))
                                    }
                                    else -> {
                                        logger.warning { "could not start rbf session: $action" }
                                        Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.RbfAborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, ChannelFundingError(channelId).message))))
                                    }
                                }
                            }
                        }
                    }
                    else -> {
                        logger.info { "ignoring unexpected tx_ack_rbf" }
                        Pair(this@WaitForFundingConfirmed, listOf(ChannelAction.Message.Send(Warning(channelId, UnexpectedInteractiveTxMessage(channelId, cmd.message).message))))
                    }
                }
                is InteractiveTxConstructionMessage -> when (rbfStatus) {
                    is RbfStatus.InProgress -> {
                        val (rbfSession1, interactiveTxAction) = rbfStatus.rbfSession.receive(cmd.message)
                        when (interactiveTxAction) {
                            is InteractiveTxSessionAction.SendMessage -> Pair(this@WaitForFundingConfirmed.copy(rbfStatus = rbfStatus.copy(rbfSession1)), listOf(ChannelAction.Message.Send(interactiveTxAction.msg)))
                            is InteractiveTxSessionAction.SignSharedTx -> {
                                val replacedCommitment = commitments.latest
                                val signingSession = InteractiveTxSigningSession.create(
                                    rbfSession1,
                                    keyManager,
                                    commitments.params,
                                    rbfSession1.fundingParams,
                                    fundingTxIndex = replacedCommitment.fundingTxIndex,
                                    interactiveTxAction.sharedTx,
                                    liquidityPurchase = null,
                                    localCommitmentIndex = replacedCommitment.localCommit.index,
                                    remoteCommitmentIndex = replacedCommitment.remoteCommit.index,
                                    replacedCommitment.localCommit.spec.feerate,
                                    replacedCommitment.remoteCommit.remotePerCommitmentPoint,
                                    replacedCommitment.localCommit.spec.htlcs
                                )
                                when (signingSession) {
                                    is Either.Left -> {
                                        logger.error(signingSession.value) { "cannot initiate interactive-tx rbf signing session" }
                                        Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.RbfAborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, signingSession.value.message))))
                                    }
                                    is Either.Right -> {
                                        val (session, commitSig) = signingSession.value
                                        val nextState = this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.WaitingForSigs(session))
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
                                logger.warning { "rbf attempt failed: $interactiveTxAction" }
                                Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.RbfAborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, ChannelFundingError(channelId).message))))
                            }
                        }
                    }
                    else -> {
                        logger.info { "ignoring unexpected interactive-tx message: ${cmd.message::class}" }
                        Pair(this@WaitForFundingConfirmed, listOf(ChannelAction.Message.Send(Warning(channelId, UnexpectedInteractiveTxMessage(channelId, cmd.message).message))))
                    }
                }
                is CommitSig -> when (rbfStatus) {
                    is RbfStatus.WaitingForSigs -> {
                        val (signingSession1, action) = rbfStatus.session.receiveCommitSig(channelKeys(), commitments.params, cmd.message, currentBlockHeight.toLong(), logger)
                        when (action) {
                            is InteractiveTxSigningSessionAction.AbortFundingAttempt -> {
                                logger.warning { "rbf attempt failed: ${action.reason.message}" }
                                Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.RbfAborted), listOf(ChannelAction.Message.Send(TxAbort(channelId, action.reason.message))))
                            }
                            // No need to store their commit_sig, they will re-send it if we disconnect.
                            InteractiveTxSigningSessionAction.WaitForTxSigs -> Pair(this@WaitForFundingConfirmed.copy(rbfStatus = rbfStatus.copy(session = signingSession1)), listOf())
                            is InteractiveTxSigningSessionAction.SendTxSigs -> sendRbfTxSigs(action)
                        }
                    }
                    else -> {
                        logger.info { "ignoring redundant commit_sig" }
                        Pair(this@WaitForFundingConfirmed, listOf())
                    }
                }
                is TxAbort -> when (rbfStatus) {
                    RbfStatus.None -> {
                        logger.info { "our peer wants to abort the funding attempt, but we've already negotiated a funding transaction: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data.toHex()}" }
                        // We ack their tx_abort but we keep monitoring the funding transaction until it's confirmed or double-spent.
                        Pair(this@WaitForFundingConfirmed, listOf(ChannelAction.Message.Send(TxAbort(channelId, DualFundingAborted(channelId, "requested by remote").message))))
                    }
                    RbfStatus.RbfAborted -> {
                        logger.info { "our peer acked our previous tx_abort" }
                        Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.None), listOf())
                    }
                    else -> {
                        logger.info { "our peer aborted the rbf attempt: ascii='${cmd.message.toAscii()}' bin=${cmd.message.data.toHex()}" }
                        Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.None), listOf(ChannelAction.Message.Send(TxAbort(channelId, RbfAttemptAborted(channelId).message))))
                    }
                }
                is ChannelReady -> Pair(this@WaitForFundingConfirmed.copy(deferred = cmd.message), listOf())
                is Error -> handleRemoteError(cmd.message)
                else -> unhandled(cmd)
            }
            is ChannelCommand.WatchReceived -> when (cmd.watch) {
                is WatchEventConfirmed -> when (val res = acceptFundingTxConfirmed(cmd.watch)) {
                    is Either.Left -> Pair(this@WaitForFundingConfirmed, listOf())
                    is Either.Right -> {
                        val (commitments1, commitment, actions) = res.value
                        val nextPerCommitmentPoint = channelKeys().commitmentPoint(1)
                        val channelReady = ChannelReady(channelId, nextPerCommitmentPoint, TlvStream(ChannelReadyTlv.ShortChannelIdTlv(ShortChannelId.peerId(staticParams.nodeParams.nodeId))))
                        // this is the temporary channel id that we will use in our channel_update message, the goal is to be able to use our channel
                        // as soon as it reaches NORMAL state, and before it is announced on the network
                        // (this id might be updated when the funding tx gets deeply buried, if there was a reorg in the meantime)
                        val shortChannelId = ShortChannelId(cmd.watch.blockHeight, cmd.watch.txIndex, commitment.commitInput.outPoint.index.toInt())
                        val nextState = WaitForChannelReady(commitments1, shortChannelId, channelReady)
                        val actions1 = buildList {
                            if (rbfStatus != RbfStatus.None) add(ChannelAction.Message.Send(TxAbort(channelId, InvalidRbfTxConfirmed(channelId, cmd.watch.tx.txid).message)))
                            add(ChannelAction.Message.Send(channelReady))
                            add(ChannelAction.Storage.StoreState(nextState))
                        }
                        if (deferred != null) {
                            logger.info { "channel_ready has already been received" }
                            val (nextState1, actions2) = nextState.run { process(ChannelCommand.MessageReceived(deferred)) }
                            Pair(nextState1, actions + actions1 + actions2)
                        } else {
                            Pair(nextState, actions + actions1)
                        }
                    }
                }
                else -> unhandled(cmd)
            }
            is ChannelCommand.Funding.BumpFundingFee -> when {
                !latestFundingTx.fundingParams.isInitiator -> {
                    logger.warning { "cannot initiate rbf, we're not the initiator" }
                    Pair(this@WaitForFundingConfirmed, listOf())
                }
                rbfStatus != RbfStatus.None -> {
                    logger.warning { "cannot initiate rbf, another one is already in progress" }
                    Pair(this@WaitForFundingConfirmed, listOf())
                }
                else -> {
                    logger.info { "initiating rbf (current feerate = ${latestFundingTx.fundingParams.targetFeerate}, next feerate = ${cmd.targetFeerate})" }
                    val txInitRbf = TxInitRbf(channelId, cmd.lockTime, cmd.targetFeerate, cmd.fundingAmount)
                    Pair(this@WaitForFundingConfirmed.copy(rbfStatus = RbfStatus.RbfRequested(cmd)), listOf(ChannelAction.Message.Send(txInitRbf)))
                }
            }
            is ChannelCommand.Close.MutualClose -> Pair(
                this@WaitForFundingConfirmed,
                listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, CommandUnavailableInThisState(channelId, stateName)))
            )
            is ChannelCommand.Close.ForceClose -> handleLocalError(cmd, ForcedLocalCommit(channelId))
            is ChannelCommand.Commitment.CheckHtlcTimeout -> Pair(this@WaitForFundingConfirmed, listOf())
            is ChannelCommand.Commitment -> unhandled(cmd)
            is ChannelCommand.Htlc -> unhandled(cmd)
            is ChannelCommand.Init -> unhandled(cmd)
            is ChannelCommand.Closing -> unhandled(cmd)
            is ChannelCommand.Connected -> unhandled(cmd)
            is ChannelCommand.Disconnected -> {
                val rbfStatus1 = when (rbfStatus) {
                    // We keep track of the RBF status: we should be able to complete the signature steps on reconnection.
                    is RbfStatus.WaitingForSigs -> rbfStatus
                    else -> RbfStatus.None
                }
                Pair(Offline(this@WaitForFundingConfirmed.copy(rbfStatus = rbfStatus1)), listOf())
            }
            is ChannelCommand.PeerBackupReceived -> unhandled(cmd)
        }
    }

    private fun ChannelContext.sendRbfTxSigs(action: InteractiveTxSigningSessionAction.SendTxSigs): Pair<WaitForFundingConfirmed, List<ChannelAction>> {
        logger.info { "rbf funding tx created with txId=${action.fundingTx.txId}, ${action.fundingTx.sharedTx.tx.localInputs.size} local inputs, ${action.fundingTx.sharedTx.tx.remoteInputs.size} remote inputs, ${action.fundingTx.sharedTx.tx.localOutputs.size} local outputs and ${action.fundingTx.sharedTx.tx.remoteOutputs.size} remote outputs" }
        val fundingMinDepth = Helpers.minDepthForFunding(staticParams.nodeParams, action.fundingTx.fundingParams.fundingAmount)
        logger.info { "will wait for $fundingMinDepth confirmations" }
        val watchConfirmed = WatchConfirmed(channelId, action.commitment.fundingTxId, action.commitment.commitInput.txOut.publicKeyScript, fundingMinDepth.toLong(), BITCOIN_FUNDING_DEPTHOK)
        val nextState = WaitForFundingConfirmed(
            commitments.add(action.commitment),
            waitingSinceBlock,
            deferred,
            RbfStatus.None
        )
        val actions = buildList {
            add(ChannelAction.Storage.StoreState(nextState))
            action.fundingTx.signedTx?.let { add(ChannelAction.Blockchain.PublishTx(it, ChannelAction.Blockchain.PublishTx.Type.FundingTx)) }
            add(ChannelAction.Blockchain.SendWatch(watchConfirmed))
            add(ChannelAction.Message.Send(action.localSigs))
        }
        return Pair(nextState, actions)
    }

    /** If we haven't completed the signing steps of an interactive-tx session, we will ask our peer to retransmit signatures for the corresponding transaction. */
    fun getUnsignedFundingTxId(): TxId? {
        return when (rbfStatus) {
            is RbfStatus.WaitingForSigs -> rbfStatus.session.fundingTx.txId
            else -> when (latestFundingTx.sharedTx) {
                is PartiallySignedSharedTransaction -> latestFundingTx.txId
                is FullySignedSharedTransaction -> null
            }
        }
    }
}
