package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.Crypto.ripemd160
import fr.acinq.bitcoin.Crypto.sha256
import fr.acinq.bitcoin.Script.pay2tr
import fr.acinq.bitcoin.Script.pay2wsh
import fr.acinq.bitcoin.Script.write
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.SecretNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.Try
import fr.acinq.bitcoin.utils.flatMap
import fr.acinq.bitcoin.utils.runTrying
import fr.acinq.lightning.Feature
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.NodeParams
import fr.acinq.lightning.blockchain.BITCOIN_OUTPUT_SPENT
import fr.acinq.lightning.blockchain.BITCOIN_TX_CONFIRMED
import fr.acinq.lightning.blockchain.WatchConfirmed
import fr.acinq.lightning.blockchain.WatchSpent
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.FeerateTolerance
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.channel.Helpers.Closing.inputsAlreadySpent
import fr.acinq.lightning.channel.states.Channel
import fr.acinq.lightning.channel.states.ClosingFeerates
import fr.acinq.lightning.channel.states.ClosingFees
import fr.acinq.lightning.crypto.Bolt3Derivation.deriveForCommitment
import fr.acinq.lightning.crypto.Bolt3Derivation.deriveForRevocation
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.crypto.ShaChain
import fr.acinq.lightning.logging.*
import fr.acinq.lightning.transactions.*
import fr.acinq.lightning.transactions.Scripts.multiSig2of2
import fr.acinq.lightning.transactions.Scripts.musig2Aggregate
import fr.acinq.lightning.transactions.Scripts.musig2FundingScript
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.ClaimHtlcDelayedOutputPenaltyTx
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.ClosingTx
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.HtlcTx.HtlcSuccessTx
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx
import fr.acinq.lightning.transactions.Transactions.commitTxFee
import fr.acinq.lightning.transactions.Transactions.makeCommitTxOutputs
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import kotlin.math.max

object Helpers {

    /**
     * Returns the number of confirmations needed to safely handle the funding transaction,
     * we make sure the cumulative block reward largely exceeds the channel size.
     *
     * @param fundingAmount funding amount of the channel
     * @return number of confirmations needed
     */
    fun minDepthForFunding(nodeParams: NodeParams, fundingAmount: Satoshi): Int {
        val blockReward = 6.25f // this is true as of ~May 2020, but will be too large after 2024
        val scalingFactor = 15
        val btc = fundingAmount.toLong().toDouble() / 100_000_000L
        val blocksToReachFunding: Int = (((scalingFactor * btc) / blockReward) + 1).toInt()
        return max(nodeParams.minDepthBlocks, blocksToReachFunding)
    }

    /** Called by the non-initiator. */
    fun validateParamsNonInitiator(nodeParams: NodeParams, open: OpenDualFundedChannel): Either<ChannelException, ChannelType> {
        // NB: we only accept channels from peers who support explicit channel type negotiation.
        val channelType = open.channelType ?: return Either.Left(MissingChannelType(open.temporaryChannelId))
        if (channelType is ChannelType.UnsupportedChannelType) {
            return Either.Left(InvalidChannelType(open.temporaryChannelId, ChannelType.SupportedChannelType.AnchorOutputsZeroReserve, channelType))
        }

        // BOLT #2: if the chain_hash value, within the open_channel, message is set to a hash of a chain that is unknown to the receiver:
        // MUST reject the channel.
        if (nodeParams.chainHash != open.chainHash) {
            return Either.Left(InvalidChainHash(open.temporaryChannelId, local = nodeParams.chainHash, remote = open.chainHash))
        }

        // BOLT #2: The receiving node MUST fail the channel if: to_self_delay is unreasonably large.
        if (open.toSelfDelay > Channel.MAX_TO_SELF_DELAY || open.toSelfDelay > nodeParams.maxToLocalDelayBlocks) {
            return Either.Left(ToSelfDelayTooHigh(open.temporaryChannelId, open.toSelfDelay, nodeParams.maxToLocalDelayBlocks))
        }

        // BOLT #2: The receiving node MUST fail the channel if: max_accepted_htlcs is greater than 483.
        if (open.maxAcceptedHtlcs > Channel.MAX_ACCEPTED_HTLCS) {
            return Either.Left(InvalidMaxAcceptedHtlcs(open.temporaryChannelId, open.maxAcceptedHtlcs, Channel.MAX_ACCEPTED_HTLCS))
        }

        // BOLT #2: The receiving node MUST fail the channel if: it considers feerate_per_kw too small for timely processing.
        if (isFeeTooSmall(open.commitmentFeerate)) {
            return Either.Left(FeerateTooSmall(open.temporaryChannelId, open.commitmentFeerate))
        }

        if (open.dustLimit > nodeParams.maxRemoteDustLimit) {
            return Either.Left(DustLimitTooLarge(open.temporaryChannelId, open.dustLimit, nodeParams.maxRemoteDustLimit))
        }

        if (open.dustLimit < Channel.MIN_DUST_LIMIT) {
            return Either.Left(DustLimitTooSmall(open.temporaryChannelId, open.dustLimit, Channel.MIN_DUST_LIMIT))
        }

        if (isFeeDiffTooHigh(FeeratePerKw.CommitmentFeerate, open.commitmentFeerate, nodeParams.onChainFeeConf.feerateTolerance)) {
            return Either.Left(FeerateTooDifferent(open.temporaryChannelId, FeeratePerKw.CommitmentFeerate, open.commitmentFeerate))
        }

        if (channelType is ChannelType.SupportedChannelType.SimpleTaprootStaging && open.nextLocalNonces.size < 2) {
            return Either.Left(MissingNextLocalNonces(open.temporaryChannelId))
        }

        return Either.Right(channelType)
    }

    /** Called by the initiator. */
    fun validateParamsInitiator(nodeParams: NodeParams, init: ChannelCommand.Init.Initiator, open: OpenDualFundedChannel, accept: AcceptDualFundedChannel): Either<ChannelException, ChannelType> {
        require(open.channelType != null) { "we should have sent a channel type in open_channel" }
        if (accept.channelType == null) {
            // We only open channels to peers who support explicit channel type negotiation.
            return Either.Left(MissingChannelType(accept.temporaryChannelId))
        }
        if (open.channelType != accept.channelType) {
            return Either.Left(InvalidChannelType(accept.temporaryChannelId, open.channelType!!, accept.channelType!!))
        }

        if (accept.fundingAmount < 0.sat) {
            return Either.Left(InvalidFundingAmount(accept.temporaryChannelId, accept.fundingAmount))
        }

        if (accept.maxAcceptedHtlcs > Channel.MAX_ACCEPTED_HTLCS) {
            return Either.Left(InvalidMaxAcceptedHtlcs(accept.temporaryChannelId, accept.maxAcceptedHtlcs, Channel.MAX_ACCEPTED_HTLCS))
        }

        if (accept.dustLimit < Channel.MIN_DUST_LIMIT) {
            return Either.Left(DustLimitTooSmall(accept.temporaryChannelId, accept.dustLimit, Channel.MIN_DUST_LIMIT))
        }

        if (accept.dustLimit > nodeParams.maxRemoteDustLimit) {
            return Either.Left(DustLimitTooLarge(accept.temporaryChannelId, accept.dustLimit, nodeParams.maxRemoteDustLimit))
        }

        // if minimum_depth is unreasonably large: MAY reject the channel.
        if (accept.toSelfDelay > Channel.MAX_TO_SELF_DELAY || accept.toSelfDelay > nodeParams.maxToLocalDelayBlocks) {
            return Either.Left(ToSelfDelayTooHigh(accept.temporaryChannelId, accept.toSelfDelay, nodeParams.maxToLocalDelayBlocks))
        }

        if (accept.channelType is ChannelType.SupportedChannelType.SimpleTaprootStaging && accept.nextLocalNonces.size < 2) {
            return Either.Left(MissingNextLocalNonces(open.temporaryChannelId))
        }

        return Either.Right(init.channelType)
    }

    /**
     * @param remoteFeerate remote fee rate per kiloweight
     * @return true if the remote fee rate is too small
     */
    private fun isFeeTooSmall(remoteFeerate: FeeratePerKw): Boolean = remoteFeerate < FeeratePerKw.MinimumFeeratePerKw

    /**
     * @param referenceFee reference fee rate per kiloweight
     * @param currentFee current fee rate per kiloweight
     * @param tolerance maximum fee rate mismatch tolerated
     * @return true if the difference between proposed and reference fee rates is too high.
     */
    fun isFeeDiffTooHigh(referenceFee: FeeratePerKw, currentFee: FeeratePerKw, tolerance: FeerateTolerance): Boolean =
        currentFee < referenceFee * tolerance.ratioLow || referenceFee * tolerance.ratioHigh < currentFee

    /**
     * This indicates whether our side of the channel is above the reserve requested by our counterparty. In other words,
     * this tells if we can use the channel to make a payment.
     */
    fun aboveReserve(commitments: Commitments): Boolean = commitments.active.all {
        val remoteCommit = it.nextRemoteCommit?.commit ?: it.remoteCommit
        val toRemote = remoteCommit.spec.toRemote.truncateToSatoshi()
        // NB: this is an approximation (we don't take network fees into account)
        toRemote > it.localChannelReserve(commitments.params)
    }

    /** This helper method will publish txs only if they haven't yet reached minDepth. */
    fun LoggingContext.publishIfNeeded(txs: List<ChannelAction.Blockchain.PublishTx>, irrevocablySpent: Map<OutPoint, Transaction>): List<ChannelAction.Blockchain.PublishTx> {
        val (skip, process) = txs.partition { it.tx.inputsAlreadySpent(irrevocablySpent) }
        skip.forEach { tx -> logger.info { "no need to republish txid=${tx.tx.txid}, it has already been confirmed" } }
        return process.map { publish ->
            logger.info(mapOf("txType" to publish.txType)) { "publishing txid=${publish.tx.txid}" }
            publish
        }
    }

    /** This helper method will watch txs only if they haven't yet reached minDepth. */
    fun LoggingContext.watchConfirmedIfNeeded(txs: List<Transaction>, irrevocablySpent: Map<OutPoint, Transaction>, channelId: ByteVector32, minDepth: Long): List<ChannelAction.Blockchain.SendWatch> {
        val (skip, process) = txs.partition { it.inputsAlreadySpent(irrevocablySpent) }
        skip.forEach { tx -> logger.info { "no need to watch txid=${tx.txid}, it has already been confirmed" } }
        return process.map { tx -> ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, tx, minDepth, BITCOIN_TX_CONFIRMED(tx))) }
    }

    /** This helper method will watch txs only if the utxo they spend hasn't already been irrevocably spent. */
    fun LoggingContext.watchSpentIfNeeded(parentTx: Transaction, outputs: List<OutPoint>, irrevocablySpent: Map<OutPoint, Transaction>, channelId: ByteVector32): List<ChannelAction.Blockchain.SendWatch> {
        val (skip, process) = outputs.partition { irrevocablySpent.contains(it) }
        skip.forEach { output -> logger.info { "no need to watch output=${output.txid}:${output.index}, it has already been spent by txid=${irrevocablySpent[output]?.txid}" } }
        return process.map { output ->
            require(output.txid == parentTx.txid) { "output doesn't belong to the given parentTx: txid=${output.txid} but expected txid=${parentTx.txid}" }
            ChannelAction.Blockchain.SendWatch(WatchSpent(channelId, parentTx, output.index.toInt(), BITCOIN_OUTPUT_SPENT))
        }
    }

    object Funding {

        /** Compute the channelId of a dual-funded channel. */
        fun computeChannelId(open: OpenDualFundedChannel, accept: AcceptDualFundedChannel): ByteVector32 {
            return if (LexicographicalOrdering.isLessThan(open.revocationBasepoint.value, accept.revocationBasepoint.value)) {
                (open.revocationBasepoint.value + accept.revocationBasepoint.value).sha256()
            } else {
                (accept.revocationBasepoint.value + open.revocationBasepoint.value).sha256()
            }
        }

        fun makeFundingPubKeyScript(localFundingPubkey: PublicKey, remoteFundingPubkey: PublicKey, isTaprootChannel: Boolean): ByteVector {
            return when (isTaprootChannel) {
                true -> write(musig2FundingScript(localFundingPubkey, remoteFundingPubkey)).toByteVector()
                else -> write(pay2wsh(multiSig2of2(localFundingPubkey, remoteFundingPubkey))).toByteVector()
            }
        }

        fun makeFundingInputInfo(
            fundingTxId: TxId,
            fundingTxOutputIndex: Int,
            fundingAmount: Satoshi,
            fundingPubkey1: PublicKey,
            fundingPubkey2: PublicKey,
            isTaprootChannel: Boolean
        ): Transactions.InputInfo {
            return if (isTaprootChannel) {
                val fundingScript = musig2FundingScript(fundingPubkey1, fundingPubkey2)
                val fundingTxOut = TxOut(fundingAmount, fundingScript)
                Transactions.InputInfo.TaprootInput(OutPoint(fundingTxId, fundingTxOutputIndex.toLong()), fundingTxOut, musig2Aggregate(fundingPubkey1, fundingPubkey2), null)
            } else {
                val fundingScript = multiSig2of2(fundingPubkey1, fundingPubkey2)
                val fundingTxOut = TxOut(fundingAmount, pay2wsh(fundingScript))
                Transactions.InputInfo.SegwitInput(OutPoint(fundingTxId, fundingTxOutputIndex.toLong()), fundingTxOut, ByteVector(write(fundingScript)))
            }
        }

        data class PairOfCommitTxs(val localSpec: CommitmentSpec, val localCommitTx: Transactions.TransactionWithInputInfo.CommitTx, val localHtlcTxs: List<Transactions.TransactionWithInputInfo.HtlcTx>, val remoteSpec: CommitmentSpec, val remoteCommitTx: Transactions.TransactionWithInputInfo.CommitTx, val remoteHtlcTxs: List<Transactions.TransactionWithInputInfo.HtlcTx>)

        /**
         * Creates both sides' first commitment transaction.
         *
         * @return (localSpec, localTx, remoteSpec, remoteTx, fundingTxOutput)
         */
        fun makeCommitTxs(
            channelKeys: KeyManager.ChannelKeys,
            channelId: ByteVector32,
            localParams: LocalParams,
            remoteParams: RemoteParams,
            fundingAmount: Satoshi,
            toLocal: MilliSatoshi,
            toRemote: MilliSatoshi,
            localHtlcs: Set<DirectedHtlc>,
            localCommitmentIndex: Long,
            remoteCommitmentIndex: Long,
            commitTxFeerate: FeeratePerKw,
            fundingTxIndex: Long,
            fundingTxId: TxId,
            fundingTxOutputIndex: Int,
            remoteFundingPubkey: PublicKey,
            remotePerCommitmentPoint: PublicKey
        ): Either<ChannelException, PairOfCommitTxs> {
            val localSpec = CommitmentSpec(localHtlcs, commitTxFeerate, toLocal = toLocal, toRemote = toRemote)
            val remoteSpec = CommitmentSpec(localHtlcs.map{ it.opposite() }.toSet(), commitTxFeerate, toLocal = toRemote, toRemote = toLocal)

            val isTaprootChannel = Features.canUseFeature(localParams.features, remoteParams.features, Feature.SimpleTaprootStaging)
            if (!localParams.paysCommitTxFees) {
                // They are responsible for paying the commitment transaction fee: we need to make sure they can afford it!
                // Note that the reserve may not be always be met: we could be using dual funding with a large funding amount on
                // our side and a small funding amount on their side. But we shouldn't care as long as they can pay the fees for
                // the commitment transaction.
                val fees = commitTxFee(remoteParams.dustLimit, remoteSpec, isTaprootChannel)
                val missing = fees - remoteSpec.toLocal.truncateToSatoshi()
                if (missing > 0.sat) {
                    return Either.Left(CannotAffordFirstCommitFees(channelId, missing = missing, fees = fees))
                }
            }

            val fundingPubKey = channelKeys.fundingPubKey(fundingTxIndex)
            val commitmentInput = makeFundingInputInfo(fundingTxId, fundingTxOutputIndex, fundingAmount, fundingPubKey, remoteFundingPubkey, isTaprootChannel)
            val localPerCommitmentPoint = channelKeys.commitmentPoint(localCommitmentIndex)
            val (localCommitTx, localHtlcTxs) = Commitments.makeLocalTxs(
                channelKeys,
                commitTxNumber = localCommitmentIndex,
                localParams,
                remoteParams,
                fundingTxIndex = fundingTxIndex,
                remoteFundingPubKey = remoteFundingPubkey,
                commitmentInput,
                localPerCommitmentPoint = localPerCommitmentPoint,
                localSpec
            )
            val (remoteCommitTx, remoteHtlcTxs) = Commitments.makeRemoteTxs(
                channelKeys,
                commitTxNumber = remoteCommitmentIndex,
                localParams,
                remoteParams,
                fundingTxIndex = fundingTxIndex,
                remoteFundingPubKey = remoteFundingPubkey,
                commitmentInput,
                remotePerCommitmentPoint = remotePerCommitmentPoint,
                remoteSpec
            )

            return Either.Right(PairOfCommitTxs(localSpec, localCommitTx, localHtlcTxs, remoteSpec, remoteCommitTx, remoteHtlcTxs))
        }

    }

    object Closing {
        // used only to compute tx weights and estimate fees
        private val dummyPublicKey by lazy { PrivateKey(ByteArray(32) { 1.toByte() }).publicKey() }

        private fun isValidFinalScriptPubkey(scriptPubKey: ByteArray, allowAnySegwit: Boolean): Boolean {
            return runTrying {
                val script = Script.parse(scriptPubKey)
                when {
                    Script.isPay2pkh(script) -> true
                    Script.isPay2sh(script) -> true
                    Script.isPay2wpkh(script) -> true
                    Script.isPay2wsh(script) -> true
                    // option_shutdown_anysegwit doesn't cover segwit v0
                    Script.isNativeWitnessScript(script) && script[0] != OP_0 -> allowAnySegwit
                    else -> false
                }
            }.getOrElse { false }
        }

        fun isValidFinalScriptPubkey(scriptPubKey: ByteVector, allowAnySegwit: Boolean): Boolean = isValidFinalScriptPubkey(scriptPubKey.toByteArray(), allowAnySegwit)

        private fun firstClosingFee(commitment: FullCommitment, localScriptPubkey: ByteArray, remoteScriptPubkey: ByteArray, requestedFeerate: ClosingFeerates): ClosingFees {
            // this is just to estimate the weight which depends on the size of the pubkey scripts
            val dummyClosingTx = Transactions.makeClosingTx(commitment.commitInput, localScriptPubkey, remoteScriptPubkey, commitment.params.localParams.paysClosingFees, 0.sat, 0.sat, commitment.localCommit.spec)
            val closingWeight = Transaction.weight(Transactions.addSigs(dummyClosingTx, dummyPublicKey, commitment.remoteFundingPubkey, Transactions.PlaceHolderSig, Transactions.PlaceHolderSig).tx)
            return requestedFeerate.computeFees(closingWeight)
        }

        fun firstClosingFee(commitment: FullCommitment, localScriptPubkey: ByteVector, remoteScriptPubkey: ByteVector, requestedFeerate: ClosingFeerates): ClosingFees =
            firstClosingFee(commitment, localScriptPubkey.toByteArray(), remoteScriptPubkey.toByteArray(), requestedFeerate)

        fun nextClosingFee(localClosingFee: Satoshi, remoteClosingFee: Satoshi): Satoshi = ((localClosingFee + remoteClosingFee) / 4) * 2

        fun makeFirstClosingTx(
            channelKeys: KeyManager.ChannelKeys,
            commitment: FullCommitment,
            localScriptPubkey: ByteArray,
            remoteScriptPubkey: ByteArray,
            requestedFeerate: ClosingFeerates,
            localClosingNonce: Pair<SecretNonce, IndividualNonce>? = null,
            remoteClosingNonce: IndividualNonce? = null
        ): Pair<ClosingTx, ClosingSigned> {
            val closingFees = firstClosingFee(commitment, localScriptPubkey, remoteScriptPubkey, requestedFeerate)
            return makeClosingTx(channelKeys, commitment, localScriptPubkey, remoteScriptPubkey, closingFees, localClosingNonce, remoteClosingNonce)
        }

        fun makeClosingTx(
            channelKeys: KeyManager.ChannelKeys,
            commitment: FullCommitment,
            localScriptPubkey: ByteArray,
            remoteScriptPubkey: ByteArray,
            closingFees: ClosingFees,
            localClosingNonce: Pair<SecretNonce, IndividualNonce>? = null,
            remoteClosingNonce: IndividualNonce? = null
        ): Pair<ClosingTx, ClosingSigned> {
            val allowAnySegwit = Features.canUseFeature(commitment.params.localParams.features, commitment.params.remoteParams.features, Feature.ShutdownAnySegwit)
            require(isValidFinalScriptPubkey(localScriptPubkey, allowAnySegwit)) { "invalid localScriptPubkey" }
            require(isValidFinalScriptPubkey(remoteScriptPubkey, allowAnySegwit)) { "invalid remoteScriptPubkey" }
            val dustLimit = commitment.params.localParams.dustLimit.max(commitment.params.remoteParams.dustLimit)
            val closingTx = Transactions.makeClosingTx(commitment.commitInput, localScriptPubkey, remoteScriptPubkey, commitment.params.localParams.paysClosingFees, dustLimit, closingFees.preferred, commitment.localCommit.spec)
            val closingSigned = when (commitment.isTaprootChannel) {
                true -> {
                    val localClosingPartialSig = Transactions.partialSign(
                        closingTx,
                        channelKeys.fundingKey(commitment.fundingTxIndex),
                        channelKeys.fundingKey(commitment.fundingTxIndex).publicKey(),
                        commitment.remoteFundingPubkey,
                        localClosingNonce!!,
                        remoteClosingNonce!!
                    ).right!!
                    ClosingSigned(commitment.channelId, closingFees.preferred, ByteVector64.Zeroes, TlvStream(ClosingSignedTlv.FeeRange(closingFees.min, closingFees.max), ClosingSignedTlv.PartialSignature(localClosingPartialSig)))
                }

                else -> {
                    val localClosingSig = Transactions.sign(closingTx, channelKeys.fundingKey(commitment.fundingTxIndex))
                    ClosingSigned(commitment.channelId, closingFees.preferred, localClosingSig, TlvStream(ClosingSignedTlv.FeeRange(closingFees.min, closingFees.max)))
                }
            }
            return Pair(closingTx, closingSigned)
        }

        fun checkClosingSignature(
            channelKeys: KeyManager.ChannelKeys,
            commitment: FullCommitment,
            localScriptPubkey: ByteArray,
            remoteScriptPubkey: ByteArray,
            remoteClosingFee: Satoshi,
            remoteClosingSig: ByteVector64
        ): Either<ChannelException, Pair<ClosingTx, ClosingSigned>> {
            val (closingTx, closingSigned) = makeClosingTx(channelKeys, commitment, localScriptPubkey, remoteScriptPubkey, ClosingFees(remoteClosingFee))
            return if (checkClosingDustAmounts(closingTx)) {
                val signedClosingTx = Transactions.addSigs(closingTx, channelKeys.fundingPubKey(commitment.fundingTxIndex), commitment.remoteFundingPubkey, closingSigned.signature, remoteClosingSig)
                when (Transactions.checkSpendable(signedClosingTx)) {
                    is Try.Success -> Either.Right(Pair(signedClosingTx, closingSigned))
                    is Try.Failure -> Either.Left(InvalidCloseSignature(commitment.channelId, signedClosingTx.tx.txid))
                }
            } else {
                Either.Left(InvalidCloseAmountBelowDust(commitment.channelId, closingTx.tx.txid))
            }
        }

        fun checkClosingSignature(
            channelKeys: KeyManager.ChannelKeys,
            commitment: FullCommitment,
            localScriptPubkey: ByteArray,
            remoteScriptPubkey: ByteArray,
            remoteClosingFee: Satoshi,
            localClosingNonce: Pair<SecretNonce, IndividualNonce>,
            remoteClosingNonce: IndividualNonce,
            remoteClosingPartialSig: ByteVector32
        ): Either<ChannelException, Pair<ClosingTx, ClosingSigned>> {
            val (closingTx, closingSigned) = makeClosingTx(channelKeys, commitment, localScriptPubkey, remoteScriptPubkey, ClosingFees(remoteClosingFee), localClosingNonce, remoteClosingNonce)
            return if (checkClosingDustAmounts(closingTx)) {
                val fundingKey = channelKeys.fundingKey(commitment.fundingTxIndex)
                val signingAttempt =
                    Transactions.aggregatePartialSignatures(closingTx, closingSigned.partialSignature!!, remoteClosingPartialSig, fundingKey.publicKey(), commitment.remoteFundingPubkey, localClosingNonce.second, remoteClosingNonce)
                        .map { aggsig -> Transactions.addAggregatedSignature(closingTx, aggsig) }
                when (signingAttempt) {
                    is Either.Left -> Either.Left(InvalidCloseSignature(commitment.channelId, closingTx.tx.txid))
                    is Either.Right -> {
                        val signedClosingTx = signingAttempt.right
                        when (Transactions.checkSpendable(signedClosingTx)) {
                            is Try.Success -> Either.Right(Pair(signedClosingTx, closingSigned))
                            is Try.Failure -> Either.Left(InvalidCloseSignature(commitment.channelId, signedClosingTx.tx.txid))
                        }
                    }
                }
            } else {
                Either.Left(InvalidCloseAmountBelowDust(commitment.channelId, closingTx.tx.txid))
            }
        }

        /**
         * Check that all closing outputs are above bitcoin's dust limit for their script type, otherwise there is a risk
         * that the closing transaction will not be relayed to miners' mempool and will not confirm.
         * The various dust limits are detailed in https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#dust-limits
         */
        fun checkClosingDustAmounts(closingTx: ClosingTx): Boolean {
            return closingTx.tx.txOut.all { txOut ->
                val publicKeyScript = Script.parse(txOut.publicKeyScript)
                when {
                    Script.isPay2pkh(publicKeyScript) -> txOut.amount >= 546.sat
                    Script.isPay2sh(publicKeyScript) -> txOut.amount >= 540.sat
                    Script.isPay2wpkh(publicKeyScript) -> txOut.amount >= 294.sat
                    Script.isPay2wsh(publicKeyScript) -> txOut.amount >= 330.sat
                    Script.isNativeWitnessScript(publicKeyScript) -> txOut.amount >= 354.sat
                    else -> txOut.amount >= 546.sat
                }
            }
        }

        /**
         * Claim all the outputs that we've received from our current commit tx. This will be done using 2nd stage HTLC transactions.
         *
         * @param commitment our commitment data, which includes payment preimages.
         * @return a list of transactions (one per output that we can claim).
         */
        fun LoggingContext.claimCurrentLocalCommitTxOutputs(channelKeys: KeyManager.ChannelKeys, commitment: FullCommitment, tx: Transaction, feerates: OnChainFeerates): LocalCommitPublished {
            val localCommit = commitment.localCommit
            val localParams = commitment.params.localParams
            require(localCommit.publishableTxs.commitTx.tx.txid == tx.txid) { "txid mismatch, provided tx is not the current local commit tx" }
            val localPerCommitmentPoint = channelKeys.commitmentPoint(commitment.localCommit.index)
            val localRevocationPubkey = commitment.params.remoteParams.revocationBasepoint.deriveForRevocation(localPerCommitmentPoint)
            val localDelayedPubkey = channelKeys.delayedPaymentBasepoint.deriveForCommitment(localPerCommitmentPoint)
            val feerateDelayed = feerates.claimMainFeerate

            // first we will claim our main output as soon as the delay is over
            val mainDelayedTx = generateTx("main-delayed-output") {
                Transactions.makeClaimLocalDelayedOutputTx(
                    tx,
                    localParams.dustLimit,
                    localRevocationPubkey,
                    commitment.params.remoteParams.toSelfDelay,
                    localDelayedPubkey,
                    localParams.defaultFinalScriptPubKey.toByteArray(),
                    feerateDelayed,
                    commitment.isTaprootChannel
                )
            }?.let {
                val sig = it.sign(channelKeys.delayedPaymentKey.deriveForCommitment(localPerCommitmentPoint), SigHash.SIGHASH_ALL)
                Transactions.addSigs(it, sig)
            }

            // those are the preimages to existing received htlcs
            val preimages = commitment.changes.localChanges.all.filterIsInstance<UpdateFulfillHtlc>().map { it.paymentPreimage }

            val htlcTxs = localCommit.publishableTxs.htlcTxsAndSigs.associate { (txInfo, localSig, remoteSig) ->
                when (txInfo) {
                    is HtlcSuccessTx -> when (val preimage = preimages.firstOrNull { r -> r.sha256() == txInfo.paymentHash }) {
                        // incoming htlc for which we don't have the preimage: we can't spend it immediately, but we may learn the
                        // preimage later, otherwise it will eventually timeout and they will get their funds back
                        null -> Pair(txInfo.input.outPoint, null)
                        // incoming htlc for which we have the preimage: we can spend it directly
                        else -> Pair(txInfo.input.outPoint, Transactions.addSigs(txInfo, localSig, remoteSig, preimage))
                    }
                    // outgoing htlc: they may or may not have the preimage, the only thing to do is try to get back our funds after timeout
                    is HtlcTimeoutTx -> Pair(txInfo.input.outPoint, Transactions.addSigs(txInfo, localSig, remoteSig))
                }
            }

            // all htlc output to us are delayed, so we need to claim them as soon as the delay is over
            val htlcDelayedTxs = htlcTxs.values.filterNotNull().mapNotNull { txInfo ->
                generateTx("claim-htlc-delayed") {
                    Transactions.makeHtlcDelayedTx(
                        txInfo.tx,
                        localParams.dustLimit,
                        localRevocationPubkey,
                        commitment.params.remoteParams.toSelfDelay,
                        localDelayedPubkey,
                        localParams.defaultFinalScriptPubKey.toByteArray(),
                        feerateDelayed,
                        commitment.isTaprootChannel
                    )
                }?.let {
                    val sig = Transactions.sign(it, channelKeys.delayedPaymentKey.deriveForCommitment(localPerCommitmentPoint), SigHash.SIGHASH_ALL)
                    Transactions.addSigs(it, sig)
                }
            }

            return LocalCommitPublished(
                commitTx = tx,
                claimMainDelayedOutputTx = mainDelayedTx,
                htlcTxs = htlcTxs,
                claimHtlcDelayedTxs = htlcDelayedTxs,
                claimAnchorTxs = emptyList(),
                irrevocablySpent = emptyMap()
            )
        }

        /**
         * Claim all the outputs that we've received from their current commit tx.
         *
         * @param commitment our commitment data, which includes payment preimages.
         * @param remoteCommit the remote commitment data to use to claim outputs (it can be their current or next commitment).
         * @param tx the remote commitment transaction that has just been published.
         * @return a list of transactions (one per output that we can claim).
         */
        fun LoggingContext.claimRemoteCommitTxOutputs(channelKeys: KeyManager.ChannelKeys, commitment: FullCommitment, remoteCommit: RemoteCommit, tx: Transaction, feerates: OnChainFeerates): RemoteCommitPublished {
            val localParams = commitment.params.localParams
            val remoteParams = commitment.params.remoteParams
            val commitInput = commitment.commitInput
            val (remoteCommitTx, _) = Commitments.makeRemoteTxs(
                channelKeys,
                commitTxNumber = remoteCommit.index,
                localParams,
                remoteParams,
                fundingTxIndex = commitment.fundingTxIndex,
                remoteFundingPubKey = commitment.remoteFundingPubkey,
                commitInput,
                remoteCommit.remotePerCommitmentPoint,
                remoteCommit.spec
            )
            require(remoteCommitTx.tx.txid == tx.txid) { "txid mismatch, provided tx is not the current remote commit tx" }

            val localPaymentPubkey = channelKeys.paymentBasepoint
            val localHtlcPubkey = channelKeys.htlcBasepoint.deriveForCommitment(remoteCommit.remotePerCommitmentPoint)
            val remoteDelayedPaymentPubkey = remoteParams.delayedPaymentBasepoint.deriveForCommitment(remoteCommit.remotePerCommitmentPoint)
            val remoteHtlcPubkey = remoteParams.htlcBasepoint.deriveForCommitment(remoteCommit.remotePerCommitmentPoint)
            val remoteRevocationPubkey = channelKeys.revocationBasepoint.deriveForRevocation(remoteCommit.remotePerCommitmentPoint)
            val outputs = makeCommitTxOutputs(
                commitment.remoteFundingPubkey,
                channelKeys.fundingPubKey(commitment.fundingTxIndex),
                !localParams.paysCommitTxFees,
                remoteParams.dustLimit,
                remoteRevocationPubkey,
                localParams.toSelfDelay,
                remoteDelayedPaymentPubkey,
                localPaymentPubkey,
                remoteHtlcPubkey,
                localHtlcPubkey,
                remoteCommit.spec,
                commitment.isTaprootChannel
            )

            // we need to use a rather high fee for htlc-claim because we compete with the counterparty
            val feerateClaimHtlc = feerates.fastFeerate

            // those are the preimages to existing received htlcs
            val preimages = commitment.changes.localChanges.all.filterIsInstance<UpdateFulfillHtlc>().map { it.paymentPreimage }

            // remember we are looking at the remote commitment so IN for them is really OUT for us and vice versa
            val claimHtlcTxs = remoteCommit.spec.htlcs.mapNotNull { htlc ->
                when (htlc) {
                    is OutgoingHtlc -> {
                        generateTx("claim-htlc-success") {
                            Transactions.makeClaimHtlcSuccessTx(
                                remoteCommitTx.tx,
                                outputs,
                                localParams.dustLimit,
                                localHtlcPubkey,
                                remoteHtlcPubkey,
                                remoteRevocationPubkey,
                                localParams.defaultFinalScriptPubKey.toByteArray(),
                                htlc.add,
                                feerateClaimHtlc
                            )
                        }?.let { claimHtlcTx ->
                            when (val preimage = preimages.firstOrNull { r -> r.sha256() == htlc.add.paymentHash }) {
                                // incoming htlc for which we don't have the preimage: we can't spend it immediately, but we may learn the
                                // preimage later, otherwise it will eventually timeout and they will get their funds back
                                null -> Pair(claimHtlcTx.input.outPoint, null)
                                // incoming htlc for which we have the preimage: we can spend it directly
                                else -> {
                                    val sig = Transactions.sign(claimHtlcTx, channelKeys.htlcKey.deriveForCommitment(remoteCommit.remotePerCommitmentPoint), SigHash.SIGHASH_ALL)
                                    Pair(claimHtlcTx.input.outPoint, Transactions.addSigs(claimHtlcTx, sig, preimage))
                                }
                            }
                        }
                    }
                    is IncomingHtlc -> {
                        // outgoing htlc: they may or may not have the preimage, the only thing to do is try to get back our funds after timeout
                        generateTx("claim-htlc-timeout") {
                            Transactions.makeClaimHtlcTimeoutTx(
                                remoteCommitTx.tx,
                                outputs,
                                localParams.dustLimit,
                                localHtlcPubkey,
                                remoteHtlcPubkey,
                                remoteRevocationPubkey,
                                localParams.defaultFinalScriptPubKey.toByteArray(),
                                htlc.add,
                                feerateClaimHtlc
                            )
                        }?.let { claimHtlcTx ->
                            val sig = Transactions.sign(claimHtlcTx, channelKeys.htlcKey.deriveForCommitment(remoteCommit.remotePerCommitmentPoint), SigHash.SIGHASH_ALL)
                            Pair(claimHtlcTx.input.outPoint, Transactions.addSigs(claimHtlcTx, sig))
                        }
                    }
                }
            }.toMap()

            // we claim our output and add the htlc txs we just created
            return claimRemoteCommitMainOutput(channelKeys, commitment.params, tx, feerates.claimMainFeerate, commitment.isTaprootChannel).copy(claimHtlcTxs = claimHtlcTxs)
        }

        /**
         * Claim our main output only from their commit tx.
         *
         * @param tx the remote commitment transaction that has just been published.
         * @return a transaction to claim our main output.
         */
        internal fun LoggingContext.claimRemoteCommitMainOutput(channelKeys: KeyManager.ChannelKeys, params: ChannelParams, tx: Transaction, claimMainFeerate: FeeratePerKw, isTaprootChannel: Boolean): RemoteCommitPublished {
            val localPaymentPoint = channelKeys.paymentBasepoint

            val mainTx = generateTx("claim-remote-delayed-output") {
                Transactions.makeClaimRemoteDelayedOutputTx(
                    tx,
                    params.localParams.dustLimit,
                    localPaymentPoint,
                    params.localParams.defaultFinalScriptPubKey,
                    claimMainFeerate,
                    isTaprootChannel
                )
            }?.let {
                val sig = Transactions.sign(it, channelKeys.paymentKey)
                Transactions.addSigs(it, sig)
            }

            return RemoteCommitPublished(commitTx = tx, claimMainOutputTx = mainTx)
        }

        /**
         * When an unexpected transaction spending the funding tx is detected, we must be in one of the following scenarios:
         *
         *  - it is a revoked commitment: we then extract the remote per-commitment secret and publish penalty transactions
         *  - it is a future commitment: if we lost future state, our peer could publish a future commitment (which may be
         *    revoked, but we won't be able to know because we lost the corresponding state)
         *  - it is not a valid commitment transaction: if our peer was able to steal our funding private key, they can
         *    spend the funding transaction however they want, and we won't be able to do anything about it
         *
         * This function returns the per-commitment secret in the first case, and null in the other cases.
         */
        fun getRemotePerCommitmentSecret(channelKeys: KeyManager.ChannelKeys, params: ChannelParams, remotePerCommitmentSecrets: ShaChain, tx: Transaction): Pair<PrivateKey, Long>? {
            // a valid tx will always have at least one input, but this ensures we don't throw in tests
            val sequence = tx.txIn.first().sequence
            val obscuredTxNumber = Transactions.decodeTxNumber(sequence, tx.lockTime)
            val localPaymentPoint = channelKeys.paymentBasepoint
            // this tx has been published by remote, so we need to invert local/remote params
            val commitmentNumber = Transactions.obscuredCommitTxNumber(obscuredTxNumber, !params.localParams.isChannelOpener, params.remoteParams.paymentBasepoint, localPaymentPoint)
            if (commitmentNumber > 0xffffffffffffL) {
                // txNumber must be lesser than 48 bits long
                return null
            }
            // now we know what commit number this tx is referring to, we can derive the commitment point from the shachain
            val hash = remotePerCommitmentSecrets.getHash(0xFFFFFFFFFFFFL - commitmentNumber) ?: return null
            return Pair(PrivateKey(hash), commitmentNumber)
        }

        /**
         * When a revoked commitment transaction spending the funding tx is detected, we build a set of transactions that
         * will punish our peer by stealing all their funds.
         */
        fun LoggingContext.claimRevokedRemoteCommitTxOutputs(channelKeys: KeyManager.ChannelKeys, params: ChannelParams, remotePerCommitmentSecret: PrivateKey, commitTx: Transaction, feerates: OnChainFeerates, isTaprootChannel: Boolean): RevokedCommitPublished {
            val localPaymentPoint = channelKeys.paymentBasepoint
            val remotePerCommitmentPoint = remotePerCommitmentSecret.publicKey()
            val remoteDelayedPaymentPubkey = params.remoteParams.delayedPaymentBasepoint.deriveForCommitment(remotePerCommitmentPoint)
            val remoteRevocationPubkey = channelKeys.revocationBasepoint.deriveForRevocation(remotePerCommitmentPoint)

            val feerateMain = feerates.claimMainFeerate
            // we need to use a high fee here for punishment txs because after a delay they can be spent by the counterparty
            val feeratePenalty = feerates.fastFeerate

            // first we will claim our main output right away
            val mainTx = generateTx("claim-remote-delayed-output") {
                Transactions.makeClaimRemoteDelayedOutputTx(
                    commitTx,
                    params.localParams.dustLimit,
                    localPaymentPoint,
                    params.localParams.defaultFinalScriptPubKey,
                    feerateMain,
                    isTaprootChannel
                )
            }?.let {
                val sig = Transactions.sign(it, channelKeys.paymentKey)
                Transactions.addSigs(it, sig)
            }

            // then we punish them by stealing their main output
            val mainPenaltyTx = generateTx("main-penalty") {
                Transactions.makeMainPenaltyTx(
                    commitTx,
                    params.localParams.dustLimit,
                    remoteRevocationPubkey,
                    params.localParams.defaultFinalScriptPubKey.toByteArray(),
                    params.localParams.toSelfDelay,
                    remoteDelayedPaymentPubkey,
                    feeratePenalty,
                    isTaprootChannel
                )
            }?.let {
                val sig = Transactions.sign(it, channelKeys.revocationKey.deriveForRevocation(remotePerCommitmentSecret))
                Transactions.addSigs(it, sig)
            }

            return RevokedCommitPublished(commitTx = commitTx, remotePerCommitmentSecret = remotePerCommitmentSecret, claimMainOutputTx = mainTx, mainPenaltyTx = mainPenaltyTx)
        }

        /**
         * Once we've fetched htlc information for a revoked commitment from the DB, we create penalty transactions to claim all htlc outputs.
         */
        fun LoggingContext.claimRevokedRemoteCommitTxHtlcOutputs(
            channelKeys: KeyManager.ChannelKeys,
            params: ChannelParams,
            revokedCommitPublished: RevokedCommitPublished,
            feerates: OnChainFeerates,
            htlcInfos: List<ChannelAction.Storage.HtlcInfo>
        ): RevokedCommitPublished {
            // we need to use a high fee here for punishment txs because after a delay they can be spent by the counterparty
            val feeratePenalty = feerates.fastFeerate
            val remotePerCommitmentPoint = revokedCommitPublished.remotePerCommitmentSecret.publicKey()
            val remoteRevocationPubkey = channelKeys.revocationBasepoint.deriveForRevocation(remotePerCommitmentPoint)
            val remoteHtlcPubkey = params.remoteParams.htlcBasepoint.deriveForCommitment(remotePerCommitmentPoint)
            val localHtlcPubkey = channelKeys.htlcBasepoint.deriveForCommitment(remotePerCommitmentPoint)

            // we retrieve the information needed to rebuild htlc scripts
            logger.info { "found ${htlcInfos.size} htlcs for txid=${revokedCommitPublished.commitTx.txid}" }
            val htlcPenaltyTxs = when (params.isTaprootChannel) {
                true -> {
                    val scriptTrees = htlcInfos.flatMap { htlcInfo ->
                        val receivedTree = Scripts.Taproot.receivedHtlcTree(remoteHtlcPubkey, localHtlcPubkey, htlcInfo.paymentHash, htlcInfo.cltvExpiry)
                        val offeredTree = Scripts.Taproot.offeredHtlcTree(remoteHtlcPubkey, localHtlcPubkey, htlcInfo.paymentHash)
                        listOf(receivedTree, offeredTree)
                    }.associate { scriptTree -> write(pay2tr(remoteRevocationPubkey.xOnly(), scriptTree)).byteVector() to scriptTree }

                    // and finally we steal the htlc outputs
                    revokedCommitPublished.commitTx.txOut.mapIndexedNotNull { outputIndex, txOut ->
                        scriptTrees[txOut.publicKeyScript]?.let { scriptTree ->
                            generateTx("htlc-penalty") {
                                Transactions.makeHtlcPenaltyTx(
                                    revokedCommitPublished.commitTx,
                                    outputIndex,
                                    remoteRevocationPubkey.xOnly(),
                                    scriptTree,
                                    params.localParams.dustLimit,
                                    params.localParams.defaultFinalScriptPubKey.toByteArray(),
                                    feeratePenalty
                                )
                            }?.let { htlcPenaltyTx ->
                                val sig = Transactions.sign(htlcPenaltyTx, channelKeys.revocationKey.deriveForRevocation(revokedCommitPublished.remotePerCommitmentSecret))
                                Transactions.addSigs(htlcPenaltyTx, sig, remoteRevocationPubkey)
                            }
                        }
                    }
                }

                else -> {
                    val htlcsRedeemScripts = htlcInfos.flatMap { htlcInfo ->
                        val htlcReceived = Scripts.htlcReceived(remoteHtlcPubkey, localHtlcPubkey, remoteRevocationPubkey, ripemd160(htlcInfo.paymentHash), htlcInfo.cltvExpiry)
                        val htlcOffered = Scripts.htlcOffered(remoteHtlcPubkey, localHtlcPubkey, remoteRevocationPubkey, ripemd160(htlcInfo.paymentHash))
                        listOf(htlcReceived, htlcOffered)
                    }.associate { redeemScript -> write(pay2wsh(redeemScript)).toByteVector() to write(redeemScript).toByteVector() }

                    // and finally we steal the htlc outputs
                    revokedCommitPublished.commitTx.txOut.mapIndexedNotNull { outputIndex, txOut ->
                        htlcsRedeemScripts[txOut.publicKeyScript]?.let { redeemScript ->
                            generateTx("htlc-penalty") {
                                Transactions.makeHtlcPenaltyTx(
                                    revokedCommitPublished.commitTx,
                                    outputIndex,
                                    redeemScript.toByteArray(),
                                    params.localParams.dustLimit,
                                    params.localParams.defaultFinalScriptPubKey.toByteArray(),
                                    feeratePenalty
                                )
                            }?.let { htlcPenaltyTx ->
                                val sig = Transactions.sign(htlcPenaltyTx, channelKeys.revocationKey.deriveForRevocation(revokedCommitPublished.remotePerCommitmentSecret))
                                Transactions.addSigs(htlcPenaltyTx, sig, remoteRevocationPubkey)
                            }
                        }
                    }
                }
            }

            return revokedCommitPublished.copy(htlcPenaltyTxs = htlcPenaltyTxs)
        }

        /**
         * Claims the output of an [[HtlcSuccessTx]] or [[HtlcTimeoutTx]] transaction using a revocation key.
         *
         * In case a revoked commitment with pending HTLCs is published, there are two ways the HTLC outputs can be taken as punishment:
         * - by spending the corresponding output of the commitment tx, using [[ClaimHtlcDelayedOutputPenaltyTx]] that we generate as soon as we detect that a revoked commit
         * has been spent; note that those transactions will compete with [[HtlcSuccessTx]] and [[HtlcTimeoutTx]] published by the counterparty.
         * - by spending the delayed output of [[HtlcSuccessTx]] and [[HtlcTimeoutTx]] if those get confirmed; because the output of these txs is protected by
         * an OP_CSV delay, we will have time to spend them with a revocation key. In that case, we generate the spending transactions "on demand",
         * this is the purpose of this method.
         *
         * NB: when anchor outputs is used, htlc transactions can be aggregated in a single transaction if they share the same
         * lockTime (thanks to the use of sighash_single | sighash_anyonecanpay), so we may need to claim multiple outputs.
         */
        fun LoggingContext.claimRevokedHtlcTxOutputs(
            channelKeys: KeyManager.ChannelKeys,
            params: ChannelParams,
            revokedCommitPublished: RevokedCommitPublished,
            htlcTx: Transaction,
            feerates: OnChainFeerates,
            isTaprootChannel: Boolean
        ): Pair<RevokedCommitPublished, List<ClaimHtlcDelayedOutputPenaltyTx>> {
            val claimTxs = buildList {
                revokedCommitPublished.claimMainOutputTx?.let { add(it) }
                revokedCommitPublished.mainPenaltyTx?.let { add(it) }
                addAll(revokedCommitPublished.htlcPenaltyTxs)
            }
            val isHtlcTx = htlcTx.txIn.any { it.outPoint.txid == revokedCommitPublished.commitTx.txid } && !claimTxs.any { it.tx.txid == htlcTx.txid }
            if (isHtlcTx) {
                logger.info { "looks like txid=${htlcTx.txid} could be a 2nd level htlc tx spending revoked commit txid=${revokedCommitPublished.commitTx.txid}" }
                // Let's assume that htlcTx is an HtlcSuccessTx or HtlcTimeoutTx and try to generate a tx spending its output using a revocation key
                val remotePerCommitmentPoint = revokedCommitPublished.remotePerCommitmentSecret.publicKey()
                val remoteDelayedPaymentPubkey = params.remoteParams.delayedPaymentBasepoint.deriveForCommitment(remotePerCommitmentPoint)
                val remoteRevocationPubkey = channelKeys.revocationBasepoint.deriveForRevocation(remotePerCommitmentPoint)

                // we need to use a high fee here for punishment txs because after a delay they can be spent by the counterparty
                val feeratePenalty = feerates.fastFeerate

                val penaltyTxs = Transactions.makeClaimDelayedOutputPenaltyTxs(
                    htlcTx,
                    params.localParams.dustLimit,
                    remoteRevocationPubkey,
                    params.localParams.toSelfDelay,
                    remoteDelayedPaymentPubkey,
                    params.localParams.defaultFinalScriptPubKey.toByteArray(),
                    feeratePenalty,
                    isTaprootChannel
                ).mapNotNull { claimDelayedOutputPenaltyTx ->
                    generateTx("claim-htlc-delayed-penalty") {
                        claimDelayedOutputPenaltyTx
                    }?.let {
                        val sig = Transactions.sign(it, channelKeys.revocationKey.deriveForRevocation(revokedCommitPublished.remotePerCommitmentSecret))
                        val signedTx = Transactions.addSigs(it, sig)
                        // we need to make sure that the tx is indeed valid
                        when (runTrying { signedTx.tx.correctlySpends(listOf(htlcTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }) {
                            is Try.Success -> signedTx
                            is Try.Failure -> null
                        }
                    }
                }

                return revokedCommitPublished.copy(claimHtlcDelayedPenaltyTxs = revokedCommitPublished.claimHtlcDelayedPenaltyTxs + penaltyTxs) to penaltyTxs
            } else {
                return revokedCommitPublished to listOf()
            }
        }

        /**
         * In CLOSING state, any time we see a new transaction, we try to extract a preimage from it in order to fulfill the
         * corresponding incoming htlc in an upstream channel.
         *
         * Not doing that would result in us losing money, because the downstream node would pull money from one side, and
         * the upstream node would get refunded after a timeout.
         *
         * @return a set of pairs (add, preimage) if extraction was successful:
         *           - add is the htlc in the downstream channel from which we extracted the preimage
         *           - preimage needs to be sent to the upstream channel
         */
        fun LoggingContext.extractPreimages(localCommit: LocalCommit, tx: Transaction): Set<Pair<UpdateAddHtlc, ByteVector32>> {
            val htlcSuccess = tx.txIn.map { it.witness }.mapNotNull(Scripts.extractPreimageFromHtlcSuccess())
                .onEach { logger.info { "extracted paymentPreimage=$it from tx=$tx (htlc-success)" } }
            val claimHtlcSuccess = tx.txIn.map { it.witness }.mapNotNull(Scripts.extractPreimageFromClaimHtlcSuccess())
                .onEach { logger.info { "extracted paymentPreimage=$it from tx=$tx (claim-htlc-success)" } }
            val paymentPreimages = (htlcSuccess + claimHtlcSuccess).toSet()

            return paymentPreimages.flatMap { paymentPreimage ->
                // we only consider htlcs in our local commitment, because we only care about outgoing htlcs, which disappear first in the remote commitment
                // if an outgoing htlc is in the remote commitment, then:
                // - either it is in the local commitment (it was never fulfilled)
                // - or we have already received the fulfill and forwarded it upstream
                localCommit.spec.htlcs.filter { it is OutgoingHtlc && it.add.paymentHash.contentEquals(sha256(paymentPreimage)) }.map { it.add to paymentPreimage }
            }.toSet()
        }

        /**
         * In CLOSING state, when we are notified that a transaction has been confirmed, we analyze it to find out if one or
         * more htlcs have timed out and need to be failed in an upstream channel.
         *
         * @param tx a tx that has reached min_depth
         * @return a set of htlcs that need to be failed upstream
         */
        fun LoggingContext.timedOutHtlcs(localCommit: LocalCommit, localCommitPublished: LocalCommitPublished, localDustLimit: Satoshi, tx: Transaction): Set<UpdateAddHtlc> {
            val untrimmedHtlcs = Transactions.trimOfferedHtlcs(localDustLimit, localCommit.spec).map { it.add }
            return when {
                tx.txid == localCommit.publishableTxs.commitTx.tx.txid -> {
                    // the tx is a commitment tx, we can immediately fail all dust htlcs (they don't have an output in the tx)
                    (localCommit.spec.htlcs.outgoings() - untrimmedHtlcs.toSet()).toSet()
                }
                localCommitPublished.isHtlcTimeout(tx) -> {
                    // maybe this is a timeout tx, in that case we can resolve and fail the corresponding htlc
                    tx.txIn.mapNotNull { txIn ->
                        when (val htlcTx = localCommitPublished.htlcTxs[txIn.outPoint]) {
                            is HtlcTimeoutTx -> when (val htlc = untrimmedHtlcs.find { it.id == htlcTx.htlcId }) {
                                null -> {
                                    logger.error { "could not find htlc #${htlcTx.htlcId} for htlc-timeout tx=$tx" }
                                    null
                                }
                                else -> {
                                    logger.info { "htlc-timeout tx for htlc #${htlc.id} paymentHash=${htlc.paymentHash} expiry=${tx.lockTime} has been confirmed (tx=$tx)" }
                                    htlc
                                }
                            }
                            else -> null
                        }
                    }.toSet()
                }
                else -> emptySet()
            }
        }

        /**
         * In CLOSING state, when we are notified that a transaction has been confirmed, we analyze it to find out if one or
         * more htlcs have timed out and need to be failed in an upstream channel.
         *
         * @param tx a tx that has reached min_depth
         * @return a set of htlcs that need to be failed upstream
         */
        fun LoggingContext.timedOutHtlcs(remoteCommit: RemoteCommit, remoteCommitPublished: RemoteCommitPublished, remoteDustLimit: Satoshi, tx: Transaction): Set<UpdateAddHtlc> {
            val untrimmedHtlcs = Transactions.trimReceivedHtlcs(remoteDustLimit, remoteCommit.spec).map { it.add }
            return when {
                tx.txid == remoteCommit.txid -> {
                    // the tx is a commitment tx, we can immediately fail all dust htlcs (they don't have an output in the tx)
                    (remoteCommit.spec.htlcs.incomings() - untrimmedHtlcs.toSet()).toSet()
                }
                remoteCommitPublished.isClaimHtlcTimeout(tx) -> {
                    // maybe this is a timeout tx, in that case we can resolve and fail the corresponding htlc
                    tx.txIn.mapNotNull { txIn ->
                        when (val htlcTx = remoteCommitPublished.claimHtlcTxs[txIn.outPoint]) {
                            is ClaimHtlcTimeoutTx -> when (val htlc = untrimmedHtlcs.find { it.id == htlcTx.htlcId }) {
                                null -> {
                                    logger.error { "could not find htlc #${htlcTx.htlcId} for claim-htlc-timeout tx=$tx" }
                                    null
                                }
                                else -> {
                                    logger.info { "claim-htlc-timeout tx for htlc #${htlc.id} paymentHash=${htlc.paymentHash} expiry=${tx.lockTime} has been confirmed (tx=$tx)" }
                                    htlc
                                }
                            }
                            else -> null
                        }
                    }.toSet()
                }
                else -> emptySet()
            }
        }

        /**
         * As soon as a local or remote commitment reaches min_depth, we know which htlcs will be settled on-chain (whether
         * or not they actually have an output in the commitment tx).
         *
         * @param tx a transaction that is sufficiently buried in the blockchain
         */
        fun onChainOutgoingHtlcs(localCommit: LocalCommit, remoteCommit: RemoteCommit, nextRemoteCommit: RemoteCommit?, tx: Transaction): Set<UpdateAddHtlc> = when {
            localCommit.publishableTxs.commitTx.tx.txid == tx.txid -> localCommit.spec.htlcs.outgoings().toSet()
            remoteCommit.txid == tx.txid -> remoteCommit.spec.htlcs.incomings().toSet()
            nextRemoteCommit?.txid == tx.txid -> nextRemoteCommit.spec.htlcs.incomings().toSet()
            else -> emptySet()
        }

        /**
         * If a commitment tx reaches min_depth, we need to fail the outgoing htlcs that will never reach the blockchain.
         * It could be because only us had signed them, or because a revoked commitment got confirmed.
         */
        fun overriddenOutgoingHtlcs(localCommit: LocalCommit, remoteCommit: RemoteCommit, nextRemoteCommit: RemoteCommit?, revokedCommitPublished: List<RevokedCommitPublished>, tx: Transaction): Set<UpdateAddHtlc> = when {
            localCommit.publishableTxs.commitTx.tx.txid == tx.txid -> {
                // our commit got confirmed, so any htlc that is in their commitment but not in ours will never reach the chain
                val htlcsInRemoteCommit = remoteCommit.spec.htlcs + nextRemoteCommit?.spec?.htlcs.orEmpty()
                // NB: from the point of view of the remote, their incoming htlcs are our outgoing htlcs
                htlcsInRemoteCommit.incomings().toSet() - localCommit.spec.htlcs.outgoings().toSet()
            }
            revokedCommitPublished.map { it.commitTx.txid }.contains(tx.txid) -> {
                // a revoked commitment got confirmed: we will claim its outputs, but we also need to fail htlcs that are pending in the latest commitment
                (nextRemoteCommit ?: remoteCommit).spec.htlcs.incomings().toSet()
            }
            remoteCommit.txid == tx.txid -> when (nextRemoteCommit) {
                null -> emptySet() // their last commitment got confirmed, so no htlcs will be overridden, they will timeout or be fulfilled on chain
                else -> {
                    // we had signed a new commitment but they committed the previous one
                    // any htlc that we signed in the new commitment that they didn't sign will never reach the chain
                    nextRemoteCommit.spec.htlcs.incomings().toSet() - localCommit.spec.htlcs.outgoings().toSet()
                }
            }
            else -> emptySet()
        }

        /**
         * This helper function tells if the utxos consumed by the given transaction has already been irrevocably spent (possibly by this very transaction)
         *
         * It can be useful to:
         *   - not attempt to publish this tx when we know this will fail
         *   - not watch for confirmations if we know the tx is already confirmed
         *   - not watch the corresponding utxo when we already know the final spending tx
         *
         * @param irrevocablySpent a map of known spent outpoints
         * @return true if we know for sure that the utxos consumed by the tx have already irrevocably been spent, false otherwise
         */
        fun Transaction.inputsAlreadySpent(irrevocablySpent: Map<OutPoint, Transaction>): Boolean {
            // NB: some transactions may have multiple inputs (e.g. htlc txs)
            val outPoints = txIn.map { it.outPoint }
            return outPoints.any { irrevocablySpent.contains(it) }
        }

        /**
         * Wraps transaction generation in a Try and filters failures to avoid one transaction negatively impacting a whole commitment.
         */
        private fun <T : Transactions.TransactionWithInputInfo> LoggingContext.generateTx(desc: String, attempt: () -> Transactions.TxResult<T>): T? =
            when (val result = runTrying { attempt() }) {
                is Try.Success -> when (val txResult = result.get()) {
                    is Transactions.TxResult.Success -> {
                        logger.info { "tx generation success: desc=$desc txid=${txResult.result.tx.txid} amount=${txResult.result.tx.txOut.map { it.amount }.sum()} tx=${txResult.result.tx}" }
                        txResult.result
                    }
                    is Transactions.TxResult.Skipped -> {
                        logger.info { "tx generation skipped: desc=$desc reason: ${txResult.why}" }
                        null
                    }
                }
                is Try.Failure -> {
                    logger.warning { "tx generation failure: desc=$desc reason: ${result.error.message}" }
                    null
                }
            }
    }
}
