package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.NodeParams
import fr.acinq.lightning.channel.Helpers.publishIfNeeded
import fr.acinq.lightning.channel.Helpers.watchConfirmedIfNeeded
import fr.acinq.lightning.channel.Helpers.watchSpentIfNeeded
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.logging.LoggingContext
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.*
import fr.acinq.lightning.utils.toMilliSatoshi

/**
 * Details about a force-close where we published our commitment.
 *
 * @param commitTx commitment tx.
 * @param claimMainDelayedOutputTx tx claiming our main output (if we have one).
 * @param htlcTxs txs claiming HTLCs. There will be one entry for each pending HTLC. The value will be null only for
 * incoming HTLCs for which we don't have the preimage (we can't claim them yet).
 * @param claimHtlcDelayedTxs 3rd-stage txs (spending the output of HTLC txs).
 * @param claimAnchorTxs txs spending anchor outputs to bump the feerate of the commitment tx (if applicable).
 * @param irrevocablySpent map of relevant outpoints that have been spent and the confirmed transaction that spends them.
 */
data class LocalCommitPublished(
    val commitTx: Transaction,
    val claimMainDelayedOutputTx: ClaimLocalDelayedOutputTx? = null,
    val htlcTxs: Map<OutPoint, HtlcTx?> = emptyMap(),
    val claimHtlcDelayedTxs: List<ClaimLocalDelayedOutputTx> = emptyList(),
    val claimAnchorTxs: List<ClaimAnchorOutputTx> = emptyList(),
    val irrevocablySpent: Map<OutPoint, Transaction> = emptyMap()
) {
    /**
     * In CLOSING state, when we are notified that a transaction has been confirmed, we check if this tx belongs in the
     * local commit scenario and keep track of it.
     *
     * We need to keep track of all transactions spending the outputs of the commitment tx, because some outputs can be
     * spent both by us and our counterparty. Because of that, some of our transactions may never confirm and we don't
     * want to wait forever before declaring that the channel is CLOSED.
     *
     * @param tx a transaction that has been irrevocably confirmed
     */
    fun update(tx: Transaction): LocalCommitPublished {
        // even if our txs only have one input, maybe our counterparty uses a different scheme so we need to iterate
        // over all of them to check if they are relevant
        val relevantOutpoints = tx.txIn.map { it.outPoint }.filter { outPoint ->
            // is this the commit tx itself? (we could do this outside of the loop...)
            val isCommitTx = commitTx.txid == tx.txid
            // does the tx spend an output of the local commitment tx?
            val spendsTheCommitTx = commitTx.txid == outPoint.txid
            // is the tx one of our 3rd stage delayed txs? (a 3rd stage tx is a tx spending the output of an htlc tx, which
            // is itself spending the output of the commitment tx)
            val is3rdStageDelayedTx = claimHtlcDelayedTxs.map { it.input.outPoint }.contains(outPoint)
            isCommitTx || spendsTheCommitTx || is3rdStageDelayedTx
        }
        // then we add the relevant outpoints to the map keeping track of which txid spends which outpoint
        return this.copy(irrevocablySpent = irrevocablySpent + relevantOutpoints.associateWith { tx }.toMap())
    }

    /**
     * A local commit is considered done when:
     * - all commitment tx outputs that we can spend have been spent and confirmed (even if the spending tx was not ours)
     * - all 3rd stage txs (txs spending htlc txs) have been confirmed
     */
    fun isDone(): Boolean {
        val confirmedTxs = irrevocablySpent.values.map { it.txid }.toSet()
        // is the commitment tx buried? (we need to check this because we may not have any outputs)
        val isCommitTxConfirmed = confirmedTxs.contains(commitTx.txid)
        // is our main output confirmed (if we have one)?
        val isMainOutputConfirmed = claimMainDelayedOutputTx?.let { irrevocablySpent.contains(it.input.outPoint) } ?: true
        // are all htlc outputs from the commitment tx spent (we need to check them all because we may receive preimages later)?
        val allHtlcsSpent = (htlcTxs.keys - irrevocablySpent.keys).isEmpty()
        // are all outputs from htlc txs spent?
        val unconfirmedHtlcDelayedTxs = claimHtlcDelayedTxs.map { it.input.outPoint }
            // only the txs which parents are already confirmed may get confirmed (note that this also eliminates outputs that have been double-spent by a competing tx)
            .filter { input -> confirmedTxs.contains(input.txid) }
            // has the tx already been confirmed?
            .filterNot { input -> irrevocablySpent.contains(input) }
        return isCommitTxConfirmed && isMainOutputConfirmed && allHtlcsSpent && unconfirmedHtlcDelayedTxs.isEmpty()
    }

    fun isConfirmed(): Boolean {
        return irrevocablySpent.values.any { it.txid == commitTx.txid } || irrevocablySpent.keys.any { it.txid == commitTx.txid }
    }

    fun isHtlcTimeout(tx: Transaction): Boolean {
        return tx.txIn
            .filter { htlcTxs[it.outPoint] is HtlcTx.HtlcTimeoutTx }
            .map { it.witness }
            .mapNotNull(Scripts.extractPaymentHashFromHtlcTimeout())
            .isNotEmpty()
    }

    fun isHtlcSuccess(tx: Transaction): Boolean {
        return tx.txIn
            .filter { htlcTxs[it.outPoint] is HtlcTx.HtlcSuccessTx }
            .map { it.witness }
            .mapNotNull(Scripts.extractPreimageFromHtlcSuccess())
            .isNotEmpty()
    }

    internal fun LoggingContext.doPublish(channelId: ByteVector32, minDepth: Long): List<ChannelAction> {
        val publishQueue = buildList {
            add(ChannelAction.Blockchain.PublishTx(commitTx, ChannelAction.Blockchain.PublishTx.Type.CommitTx))
            claimMainDelayedOutputTx?.let { add(ChannelAction.Blockchain.PublishTx(it)) }
            addAll(htlcTxs.values.filterNotNull().map { ChannelAction.Blockchain.PublishTx(it) })
            addAll(claimHtlcDelayedTxs.map { ChannelAction.Blockchain.PublishTx(it) })
        }
        val publishList = publishIfNeeded(publishQueue, irrevocablySpent)

        // we watch:
        // - the commitment tx itself, so that we can handle the case where we don't have any outputs
        // - 'final txs' that send funds to our wallet and that spend outputs that only us control
        val watchConfirmedQueue = buildList {
            add(commitTx)
            claimMainDelayedOutputTx?.let { add(it.tx) }
            addAll(claimHtlcDelayedTxs.map { it.tx })
        }
        val watchConfirmedList = watchConfirmedIfNeeded(watchConfirmedQueue, irrevocablySpent, channelId, minDepth)

        // we watch outputs of the commitment tx that both parties may spend
        val watchSpentQueue = htlcTxs.keys.toList()
        val watchSpentList = watchSpentIfNeeded(commitTx, watchSpentQueue, irrevocablySpent, channelId)

        return buildList {
            addAll(publishList)
            addAll(watchConfirmedList)
            addAll(watchSpentList)
        }
    }
}

/**
 * Details about a force-close where they published their commitment.
 *
 * @param commitTx commitment tx.
 * @param claimMainOutputTx tx claiming our main output (if we have one).
 * @param claimHtlcTxs txs claiming HTLCs. There will be one entry for each pending HTLC. The value will be null only
 * for incoming HTLCs for which we don't have the preimage (we can't claim them yet).
 * @param claimAnchorTxs txs spending anchor outputs to bump the feerate of the commitment tx (if applicable).
 * @param irrevocablySpent map of relevant outpoints that have been spent and the confirmed transaction that spends them.
 */
data class RemoteCommitPublished(
    val commitTx: Transaction,
    val claimMainOutputTx: ClaimRemoteCommitMainOutputTx? = null,
    val claimHtlcTxs: Map<OutPoint, ClaimHtlcTx?> = emptyMap(),
    val claimAnchorTxs: List<ClaimAnchorOutputTx> = emptyList(),
    val irrevocablySpent: Map<OutPoint, Transaction> = emptyMap()
) {
    /**
     * In CLOSING state, when we are notified that a transaction has been confirmed, we check if this tx belongs in the
     * remote commit scenario and keep track of it.
     *
     * We need to keep track of all transactions spending the outputs of the commitment tx, because some outputs can be
     * spent both by us and our counterparty. Because of that, some of our transactions may never confirm and we don't
     * want to wait forever before declaring that the channel is CLOSED.
     *
     * @param tx a transaction that has been irrevocably confirmed
     */
    fun update(tx: Transaction): RemoteCommitPublished {
        // even if our txs only have one input, maybe our counterparty uses a different scheme so we need to iterate
        // over all of them to check if they are relevant
        val relevantOutpoints = tx.txIn.map { it.outPoint }.filter {
            // is this the commit tx itself? (we could do this outside of the loop...)
            val isCommitTx = commitTx.txid == tx.txid
            // does the tx spend an output of the commitment tx?
            val spendsTheCommitTx = commitTx.txid == it.txid
            isCommitTx || spendsTheCommitTx
        }
        // then we add the relevant outpoints to the map keeping track of which txid spends which outpoint
        return this.copy(irrevocablySpent = irrevocablySpent + relevantOutpoints.associateWith { tx }.toMap())
    }

    /**
     * A remote commit is considered done when all commitment tx outputs that we can spend have been spent and confirmed
     * (even if the spending tx was not ours).
     */
    fun isDone(): Boolean {
        val confirmedTxs = irrevocablySpent.values.map { it.txid }.toSet()
        // is the commitment tx buried? (we need to check this because we may not have any outputs)
        val isCommitTxConfirmed = confirmedTxs.contains(commitTx.txid)
        // is our main output confirmed (if we have one)?
        val isMainOutputConfirmed = claimMainOutputTx?.let { irrevocablySpent.contains(it.input.outPoint) } ?: true
        // are all htlc outputs from the commitment tx spent (we need to check them all because we may receive preimages later)?
        val allHtlcsSpent = (claimHtlcTxs.keys - irrevocablySpent.keys).isEmpty()
        return isCommitTxConfirmed && isMainOutputConfirmed && allHtlcsSpent
    }

    fun isConfirmed(): Boolean {
        return irrevocablySpent.values.any { it.txid == commitTx.txid } || irrevocablySpent.keys.any { it.txid == commitTx.txid }
    }

    fun isClaimHtlcTimeout(tx: Transaction): Boolean {
        return tx.txIn
            .filter { claimHtlcTxs[it.outPoint] is ClaimHtlcTx.ClaimHtlcTimeoutTx }
            .map { it.witness }
            .mapNotNull(Scripts.extractPaymentHashFromClaimHtlcTimeout())
            .isNotEmpty()
    }

    fun isClaimHtlcSuccess(tx: Transaction): Boolean {
        return tx.txIn
            .filter { claimHtlcTxs[it.outPoint] is ClaimHtlcTx.ClaimHtlcSuccessTx }
            .map { it.witness }
            .mapNotNull(Scripts.extractPreimageFromClaimHtlcSuccess())
            .isNotEmpty()
    }

    internal fun LoggingContext.doPublish(channelId: ByteVector32, minDepth: Long): List<ChannelAction> {
        val publishQueue = buildList {
            claimMainOutputTx?.let { add(ChannelAction.Blockchain.PublishTx(it)) }
            addAll(claimHtlcTxs.values.filterNotNull().map { ChannelAction.Blockchain.PublishTx(it) })
        }
        val publishList = publishIfNeeded(publishQueue, irrevocablySpent)

        // we watch:
        // - the commitment tx itself, so that we can handle the case where we don't have any outputs
        // - 'final txs' that send funds to our wallet and that spend outputs that only us control
        val watchConfirmedQueue = buildList {
            add(commitTx)
            claimMainOutputTx?.let { add(it.tx) }
        }
        val watchEventConfirmedList = watchConfirmedIfNeeded(watchConfirmedQueue, irrevocablySpent, channelId, minDepth)

        // we watch outputs of the commitment tx that both parties may spend
        val watchSpentQueue = claimHtlcTxs.keys.toList()
        val watchEventSpentList = watchSpentIfNeeded(commitTx, watchSpentQueue, irrevocablySpent, channelId)

        return buildList {
            addAll(publishList)
            addAll(watchEventConfirmedList)
            addAll(watchEventSpentList)
        }
    }
}

/**
 * Details about a force-close where they published one of their revoked commitments.
 *
 * @param commitTx revoked commitment tx.
 * @param claimMainOutputTx tx claiming our main output (if we have one).
 * @param mainPenaltyTx penalty tx claiming their main output (if they have one).
 * @param htlcPenaltyTxs penalty txs claiming every HTLC output.
 * @param claimHtlcDelayedPenaltyTxs penalty txs claiming the output of their HTLC txs (if they managed to get them confirmed before our htlcPenaltyTxs).
 * @param irrevocablySpent map of relevant outpoints that have been spent and the confirmed transaction that spends them.
 */
data class RevokedCommitPublished(
    val commitTx: Transaction,
    val remotePerCommitmentSecret: PrivateKey,
    val claimMainOutputTx: ClaimRemoteCommitMainOutputTx? = null,
    val mainPenaltyTx: MainPenaltyTx? = null,
    val htlcPenaltyTxs: List<HtlcPenaltyTx> = emptyList(),
    val claimHtlcDelayedPenaltyTxs: List<ClaimHtlcDelayedOutputPenaltyTx> = emptyList(),
    val irrevocablySpent: Map<OutPoint, Transaction> = emptyMap()
) {
    /**
     * In CLOSING state, when we are notified that a transaction has been confirmed, we check if this tx belongs in the
     * revoked commit scenario and keep track of it.
     *
     * We need to keep track of all transactions spending the outputs of the commitment tx, because some outputs can be
     * spent both by us and our counterparty. Because of that, some of our transactions may never confirm and we don't
     * want to wait forever before declaring that the channel is CLOSED.
     *
     * @param tx a transaction that has been irrevocably confirmed
     */
    fun update(tx: Transaction): RevokedCommitPublished {
        // even if our txs only have one input, maybe our counterparty uses a different scheme so we need to iterate
        // over all of them to check if they are relevant
        val relevantOutpoints = tx.txIn.map { it.outPoint }.filter { outPoint ->
            // is this the commit tx itself? (we could do this outside of the loop...)
            val isCommitTx = commitTx.txid == tx.txid
            // does the tx spend an output of the commitment tx?
            val spendsTheCommitTx = commitTx.txid == outPoint.txid
            // is the tx a 3rd stage txs? (a 3rd stage tx is a tx spending the output of an htlc tx, which
            // is itself spending the output of the commitment tx)
            val is3rdStageDelayedTx = claimHtlcDelayedPenaltyTxs.map { it.input.outPoint }.contains(outPoint)
            isCommitTx || spendsTheCommitTx || is3rdStageDelayedTx
        }
        // then we add the relevant outpoints to the map keeping track of which txid spends which outpoint
        return this.copy(irrevocablySpent = irrevocablySpent + relevantOutpoints.associateWith { tx }.toMap())
    }

    /**
     * A remote commit is considered done when all commitment tx outputs that we can spend have been spent and confirmed
     * (even if the spending tx was not ours).
     */
    fun isDone(): Boolean {
        val confirmedTxs = irrevocablySpent.values.map { it.txid }.toSet()
        // is the commitment tx buried? (we need to check this because we may not have any outputs)
        val isCommitTxConfirmed = confirmedTxs.contains(commitTx.txid)
        // are there remaining spendable outputs from the commitment tx?
        val unspentCommitTxOutputs = run {
            val commitOutputsSpendableByUs = (listOfNotNull(claimMainOutputTx) + listOfNotNull(mainPenaltyTx) + htlcPenaltyTxs).map { it.input.outPoint }
            commitOutputsSpendableByUs.toSet() - irrevocablySpent.keys
        }
        // are all outputs from htlc txs spent?
        val unconfirmedHtlcDelayedTxs = claimHtlcDelayedPenaltyTxs.map { it.input.outPoint }
            // only the txs which parents are already confirmed may get confirmed (note that this also eliminates outputs that have been double-spent by a competing tx)
            .filter { input -> confirmedTxs.contains(input.txid) }
            // if one of the tx inputs has been spent, the tx has already been confirmed or a competing tx has been confirmed
            .filterNot { input -> irrevocablySpent.contains(input) }
        return isCommitTxConfirmed && unspentCommitTxOutputs.isEmpty() && unconfirmedHtlcDelayedTxs.isEmpty()
    }

    fun isConfirmed(): Boolean {
        return irrevocablySpent.values.any { it.txid == commitTx.txid } || irrevocablySpent.keys.any { it.txid == commitTx.txid }
    }

    internal fun LoggingContext.doPublish(channelId: ByteVector32, minDepth: Long): List<ChannelAction> {
        val publishQueue = buildList {
            claimMainOutputTx?.let { add(ChannelAction.Blockchain.PublishTx(it)) }
            mainPenaltyTx?.let { add(ChannelAction.Blockchain.PublishTx(it)) }
            addAll(htlcPenaltyTxs.map { ChannelAction.Blockchain.PublishTx(it) })
            addAll(claimHtlcDelayedPenaltyTxs.map { ChannelAction.Blockchain.PublishTx(it) })
        }
        val publishList = publishIfNeeded(publishQueue, irrevocablySpent)

        // we watch:
        // - the commitment tx itself, so that we can handle the case where we don't have any outputs
        // - 'final txs' that send funds to our wallet and that spend outputs that only us control
        val watchConfirmedQueue = buildList {
            add(commitTx)
            claimMainOutputTx?.let { add(it.tx) }
        }
        val watchEventConfirmedList = watchConfirmedIfNeeded(watchConfirmedQueue, irrevocablySpent, channelId, minDepth)

        // we watch outputs of the commitment tx that both parties may spend
        val watchSpentQueue = buildList {
            mainPenaltyTx?.let { add(it.input.outPoint) }
            addAll(htlcPenaltyTxs.map { it.input.outPoint })
        }
        val watchEventSpentList = watchSpentIfNeeded(commitTx, watchSpentQueue, irrevocablySpent, channelId)

        return buildList {
            addAll(publishList)
            addAll(watchEventConfirmedList)
            addAll(watchEventSpentList)
        }
    }
}

data class LocalParams(
    val nodeId: PublicKey,
    val fundingKeyPath: KeyPath,
    val dustLimit: Satoshi,
    val maxHtlcValueInFlightMsat: Long, // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
    val htlcMinimum: MilliSatoshi,
    val toSelfDelay: CltvExpiryDelta,
    val maxAcceptedHtlcs: Int,
    val isChannelOpener: Boolean,
    val paysCommitTxFees: Boolean,
    val defaultFinalScriptPubKey: ByteVector,
    val features: Features
) {
    constructor(nodeParams: NodeParams, isChannelOpener: Boolean, payCommitTxFees: Boolean) : this(
        nodeId = nodeParams.nodeId,
        fundingKeyPath = nodeParams.keyManager.newFundingKeyPath(isChannelOpener), // we make sure that initiator and non-initiator key path end differently
        dustLimit = nodeParams.dustLimit,
        maxHtlcValueInFlightMsat = nodeParams.maxHtlcValueInFlightMsat,
        htlcMinimum = nodeParams.htlcMinimum,
        toSelfDelay = nodeParams.toRemoteDelayBlocks, // we choose their delay
        maxAcceptedHtlcs = nodeParams.maxAcceptedHtlcs,
        isChannelOpener = isChannelOpener,
        paysCommitTxFees = payCommitTxFees,
        defaultFinalScriptPubKey = nodeParams.keyManager.finalOnChainWallet.pubkeyScript(addressIndex = 0), // the default closing address is the same for all channels
        features = nodeParams.features.initFeatures()
    )

    fun channelKeys(keyManager: KeyManager) = keyManager.channelKeys(fundingKeyPath)
}

data class RemoteParams(
    val nodeId: PublicKey,
    val dustLimit: Satoshi,
    val maxHtlcValueInFlightMsat: Long, // this is not MilliSatoshi because it can exceed the total amount of MilliSatoshi
    val htlcMinimum: MilliSatoshi,
    val toSelfDelay: CltvExpiryDelta,
    val maxAcceptedHtlcs: Int,
    val revocationBasepoint: PublicKey,
    val paymentBasepoint: PublicKey,
    val delayedPaymentBasepoint: PublicKey,
    val htlcBasepoint: PublicKey,
    val features: Features
)

/**
 * The [nonInitiatorPaysCommitFees] parameter can be set to true when the sender wants the receiver to pay the commitment transaction fees.
 * This is not part of the BOLTs and won't be needed anymore once commitment transactions don't pay any on-chain fees.
 */
data class ChannelFlags(val announceChannel: Boolean, val nonInitiatorPaysCommitFees: Boolean)

/**
 * @param miningFee fee paid to miners for the underlying on-chain transaction.
 * @param serviceFee fee paid to our peer for any service provided with the on-chain transaction.
 */
data class ChannelManagementFees(val miningFee: Satoshi, val serviceFee: Satoshi) {
    val total: Satoshi = miningFee + serviceFee
}

/** Reason for creating a new channel or splicing into an existing channel. */
// @formatter:off
sealed class Origin {
    /** Amount of the origin payment, before fees are paid. */
    abstract val amountBeforeFees: MilliSatoshi
    /** Fees applied for the channel funding transaction. */
    abstract val fees: ChannelManagementFees

    fun amountReceived(): MilliSatoshi = amountBeforeFees - fees.total.toMilliSatoshi()

    data class OnChainWallet(val inputs: Set<OutPoint>, override val amountBeforeFees: MilliSatoshi, override val fees: ChannelManagementFees) : Origin()
    data class OffChainPayment(val paymentPreimage: ByteVector32, override val amountBeforeFees: MilliSatoshi, override val fees: ChannelManagementFees) : Origin() {
        val paymentHash: ByteVector32 = Crypto.sha256(paymentPreimage).byteVector32()
    }
}
// @formatter:on
