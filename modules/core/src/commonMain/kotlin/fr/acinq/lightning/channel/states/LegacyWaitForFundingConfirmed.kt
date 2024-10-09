package fr.acinq.lightning.channel.states

import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.Try
import fr.acinq.bitcoin.utils.runTrying
import fr.acinq.lightning.ShortChannelId
import fr.acinq.lightning.blockchain.WatchEventConfirmed
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.wire.ChannelReady
import fr.acinq.lightning.wire.Error
import fr.acinq.lightning.wire.FundingCreated
import fr.acinq.lightning.wire.FundingSigned

/**
 * We changed the channel funding flow to use dual funding, and removed the ability to open legacy channels.
 * However, users may have legacy channels that were waiting for the funding transaction to confirm.
 * This class handles this scenario, and lets those channels safely transition to the normal state.
 */
data class LegacyWaitForFundingConfirmed(
    override val commitments: Commitments,
    val fundingTx: Transaction?,
    val waitingSinceBlock: Long, // how many blocks have we been waiting for the funding tx to confirm
    val deferred: ChannelReady?,
    val lastSent: Either<FundingCreated, FundingSigned>
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override suspend fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when (cmd) {
            is ChannelCommand.MessageReceived -> when (cmd.message) {
                is ChannelReady -> Pair(this@LegacyWaitForFundingConfirmed.copy(deferred = cmd.message), listOf())
                is Error -> handleRemoteError(cmd.message)
                else -> Pair(this@LegacyWaitForFundingConfirmed, listOf())
            }
            is ChannelCommand.WatchReceived ->
                when (cmd.watch) {
                    is WatchEventConfirmed -> {
                        val result = runTrying {
                            commitments.latest.localCommit.publishableTxs.commitTx.tx.correctlySpends(listOf(cmd.watch.tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
                        }
                        if (result is Try.Failure) {
                            logger.error { "funding tx verification failed: ${result.error}" }
                            return handleLocalError(cmd, InvalidCommitmentSignature(channelId, cmd.watch.tx.txid))
                        }
                        val nextPerCommitmentPoint = channelKeys().commitmentPoint(1)
                        val channelReady = ChannelReady(commitments.channelId, nextPerCommitmentPoint)
                        // this is the temporary channel id that we will use in our channel_update message, the goal is to be able to use our channel
                        // as soon as it reaches NORMAL state, and before it is announced on the network
                        // (this id might be updated when the funding tx gets deeply buried, if there was a reorg in the meantime)
                        val blockHeight = cmd.watch.blockHeight
                        val txIndex = cmd.watch.txIndex
                        val shortChannelId = ShortChannelId(blockHeight, txIndex, commitments.latest.commitInput.outPoint.index.toInt())
                        val nextState = LegacyWaitForFundingLocked(commitments, shortChannelId, channelReady)
                        val actions = listOf(
                            ChannelAction.Message.Send(channelReady),
                            ChannelAction.Storage.StoreState(nextState)
                        )
                        if (deferred != null) {
                            logger.info { "funding_locked has already been received" }
                            val resultPair = nextState.run { process(ChannelCommand.MessageReceived(deferred)) }
                            Pair(resultPair.first, actions + resultPair.second)
                        } else {
                            Pair(nextState, actions)
                        }
                    }
                    is WatchEventSpent -> when (cmd.watch.tx.txid) {
                        commitments.latest.remoteCommit.txid -> handleRemoteSpentCurrent(cmd.watch.tx, commitments.latest)
                        else -> handleRemoteSpentOther(cmd.watch.tx)
                    }
                }
            is ChannelCommand.Close.MutualClose -> Pair(this@LegacyWaitForFundingConfirmed, listOf(ChannelAction.ProcessCmdRes.NotExecuted(cmd, CommandUnavailableInThisState(channelId, this::class.toString()))))
            is ChannelCommand.Close.ForceClose -> handleLocalError(cmd, ForcedLocalCommit(channelId))
            is ChannelCommand.Init -> unhandled(cmd)
            is ChannelCommand.Funding -> unhandled(cmd)
            is ChannelCommand.Htlc -> unhandled(cmd)
            is ChannelCommand.Commitment -> unhandled(cmd)
            is ChannelCommand.Closing -> unhandled(cmd)
            is ChannelCommand.Connected -> unhandled(cmd)
            is ChannelCommand.Disconnected -> Pair(Offline(this@LegacyWaitForFundingConfirmed), listOf())
            is ChannelCommand.PeerBackupReceived -> unhandled(cmd)
        }
    }
}