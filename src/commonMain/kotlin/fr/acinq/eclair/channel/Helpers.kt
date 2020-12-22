package fr.acinq.eclair.channel

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.Crypto.ripemd160
import fr.acinq.bitcoin.Crypto.sha256
import fr.acinq.bitcoin.Script.pay2wsh
import fr.acinq.bitcoin.Script.write
import fr.acinq.eclair.Feature
import fr.acinq.eclair.MilliSatoshi
import fr.acinq.eclair.NodeParams
import fr.acinq.eclair.blockchain.BITCOIN_OUTPUT_SPENT
import fr.acinq.eclair.blockchain.BITCOIN_TX_CONFIRMED
import fr.acinq.eclair.blockchain.WatchConfirmed
import fr.acinq.eclair.blockchain.WatchSpent
import fr.acinq.eclair.blockchain.fee.FeeratePerKw
import fr.acinq.eclair.blockchain.fee.FeerateTolerance
import fr.acinq.eclair.blockchain.fee.OnChainFeerates
import fr.acinq.eclair.channel.Helpers.Closing.inputsAlreadySpent
import fr.acinq.eclair.crypto.ChaCha20Poly1305
import fr.acinq.eclair.crypto.Generators
import fr.acinq.eclair.crypto.KeyManager
import fr.acinq.eclair.transactions.*
import fr.acinq.eclair.transactions.Scripts.multiSig2of2
import fr.acinq.eclair.transactions.Transactions.TransactionWithInputInfo.HtlcSuccessTx
import fr.acinq.eclair.transactions.Transactions.TransactionWithInputInfo.HtlcTimeoutTx
import fr.acinq.eclair.transactions.Transactions.commitTxFee
import fr.acinq.eclair.transactions.Transactions.makeCommitTxOutputs
import fr.acinq.eclair.utils.*
import fr.acinq.eclair.wire.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlin.math.max
import kotlin.native.concurrent.ThreadLocal

@ThreadLocal
object Helpers {

    val logger by eclairLogger()

    /**
     * Returns the number of confirmations needed to safely handle the funding transaction,
     * we make sure the cumulative block reward largely exceeds the channel size.
     *
     * @param fundingAmount funding amount of the channel
     * @return number of confirmations needed
     */
    fun minDepthForFunding(nodeParams: NodeParams, fundingAmount: Satoshi): Int =
        if (fundingAmount <= Channel.MAX_FUNDING) {
            nodeParams.minDepthBlocks
        } else {
            val blockReward = 6.25f // this is true as of ~May 2020, but will be too large after 2024
            val scalingFactor = 15
            val btc = fundingAmount.toLong().toDouble() / 100_000_000L
            val blocksToReachFunding: Int = (((scalingFactor * btc) / blockReward) + 1).toInt()
            max(nodeParams.minDepthBlocks, blocksToReachFunding)
        }

    /** Called by the fundee. */
    fun validateParamsFundee(nodeParams: NodeParams, open: OpenChannel, channelVersion: ChannelVersion): Either<ChannelException, Unit> {
        // BOLT #2: if the chain_hash value, within the open_channel, message is set to a hash of a chain that is unknown to the receiver:
        // MUST reject the channel.
        if (nodeParams.chainHash != open.chainHash) {
            return Either.Left(InvalidChainHash(open.temporaryChannelId, local = nodeParams.chainHash, remote = open.chainHash))
        }

        if (open.fundingSatoshis < nodeParams.minFundingSatoshis || open.fundingSatoshis > nodeParams.maxFundingSatoshis) {
            return Either.Left(InvalidFundingAmount(open.temporaryChannelId, open.fundingSatoshis, nodeParams.minFundingSatoshis, nodeParams.maxFundingSatoshis))
        }

        // BOLT #2: Channel funding limits
        if (open.fundingSatoshis >= Channel.MAX_FUNDING && !nodeParams.features.hasFeature(Feature.Wumbo)) {
            return Either.Left(InvalidFundingAmount(open.temporaryChannelId, open.fundingSatoshis, nodeParams.minFundingSatoshis, Channel.MAX_FUNDING))
        }

        // BOLT #2: The receiving node MUST fail the channel if: push_msat is greater than funding_satoshis * 1000.
        if (open.pushMsat > open.fundingSatoshis) {
            return Either.Left(InvalidPushAmount(open.temporaryChannelId, open.pushMsat, open.fundingSatoshis.toMilliSatoshi()))
        }

        // BOLT #2: The receiving node MUST fail the channel if: to_self_delay is unreasonably large.
        if (open.toSelfDelay > Channel.MAX_TO_SELF_DELAY || open.toSelfDelay > nodeParams.maxToLocalDelayBlocks) {
            return Either.Left(ToSelfDelayTooHigh(open.temporaryChannelId, open.toSelfDelay, nodeParams.maxToLocalDelayBlocks))
        }

        // BOLT #2: The receiving node MUST fail the channel if: max_accepted_htlcs is greater than 483.
        if (open.maxAcceptedHtlcs > Channel.MAX_ACCEPTED_HTLCS) {
            return Either.Left(InvalidMaxAcceptedHtlcs(open.temporaryChannelId, open.maxAcceptedHtlcs, Channel.MAX_ACCEPTED_HTLCS))
        }

        // BOLT #2: The receiving node MUST fail the channel if: push_msat is greater than funding_satoshis * 1000.
        if (isFeeTooSmall(open.feeratePerKw)) {
            return Either.Left(FeerateTooSmall(open.temporaryChannelId, open.feeratePerKw))
        }

        if (channelVersion.isSet(ChannelVersion.ZERO_RESERVE_BIT)) {
            // in zero-reserve channels, we don't make any requirements on the fundee's reserve (set by the funder in the open_message).
        } else {
            // BOLT #2: The receiving node MUST fail the channel if: dust_limit_satoshis is greater than channel_reserve_satoshis.
            if (open.dustLimitSatoshis > open.channelReserveSatoshis) {
                return Either.Left(DustLimitTooLarge(open.temporaryChannelId, open.dustLimitSatoshis, open.channelReserveSatoshis))
            }
        }

        // BOLT #2: The receiving node MUST fail the channel if both to_local and to_remote amounts for the initial commitment
        // transaction are less than or equal to channel_reserve_satoshis (see BOLT 3).
        val (toLocalMsat, toRemoteMsat) = Pair(open.pushMsat, open.fundingSatoshis.toMilliSatoshi() - open.pushMsat)
        if (toLocalMsat < open.channelReserveSatoshis && toRemoteMsat < open.channelReserveSatoshis) {
            return Either.Left(ChannelReserveNotMet(open.temporaryChannelId, toLocalMsat, toRemoteMsat, open.channelReserveSatoshis))
        }

        if (isFeeDiffTooHigh(FeeratePerKw.CommitmentFeerate, open.feeratePerKw, nodeParams.onChainFeeConf.feerateTolerance)) {
            return Either.Left(FeerateTooDifferent(open.temporaryChannelId, FeeratePerKw.CommitmentFeerate, open.feeratePerKw))
        }

        // only enforce dust limit check on mainnet
        if (nodeParams.chainHash == Block.LivenetGenesisBlock.hash && open.dustLimitSatoshis < Channel.MIN_DUSTLIMIT) {
            return Either.Left(DustLimitTooSmall(open.temporaryChannelId, open.dustLimitSatoshis, Channel.MIN_DUSTLIMIT))
        }

        // we don't check that the funder's amount for the initial commitment transaction is sufficient for full fee payment
        // now, but it will be done later when we receive `funding_created`
        val reserveToFundingRatio = open.channelReserveSatoshis.toLong().toDouble() / max(open.fundingSatoshis.toLong(), 1)
        if (reserveToFundingRatio > nodeParams.maxReserveToFundingRatio) {
            return Either.Left(ChannelReserveTooHigh(open.temporaryChannelId, open.channelReserveSatoshis, reserveToFundingRatio, nodeParams.maxReserveToFundingRatio))
        }

        return Either.Right(Unit)
    }

    /** Called by the funder. */
    fun validateParamsFunder(nodeParams: NodeParams, open: OpenChannel, accept: AcceptChannel): Either<ChannelException, Unit> {
        if (accept.maxAcceptedHtlcs > Channel.MAX_ACCEPTED_HTLCS) {
            return Either.Left(InvalidMaxAcceptedHtlcs(accept.temporaryChannelId, accept.maxAcceptedHtlcs, Channel.MAX_ACCEPTED_HTLCS))
        }
        // only enforce dust limit check on mainnet
        if (nodeParams.chainHash == Block.LivenetGenesisBlock.hash && accept.dustLimitSatoshis < Channel.MIN_DUSTLIMIT) {
            return Either.Left(DustLimitTooSmall(accept.temporaryChannelId, accept.dustLimitSatoshis, Channel.MIN_DUSTLIMIT))
        }

        // BOLT #2: The receiving node MUST fail the channel if: dust_limit_satoshis is greater than channel_reserve_satoshis.
        if (accept.dustLimitSatoshis > accept.channelReserveSatoshis) {
            return Either.Left(DustLimitTooLarge(accept.temporaryChannelId, accept.dustLimitSatoshis, accept.channelReserveSatoshis))
        }

        // if minimum_depth is unreasonably large: MAY reject the channel.
        if (accept.toSelfDelay > Channel.MAX_TO_SELF_DELAY || accept.toSelfDelay > nodeParams.maxToLocalDelayBlocks) {
            return Either.Left(ToSelfDelayTooHigh(accept.temporaryChannelId, accept.toSelfDelay, nodeParams.maxToLocalDelayBlocks))
        }

        if ((open.channelVersion ?: ChannelVersion.STANDARD).isSet(ChannelVersion.ZERO_RESERVE_BIT)) {
            // in zero-reserve channels, we don't make any requirements on the fundee's reserve (set by the funder in the open_message).
        } else {
            // if channel_reserve_satoshis from the open_channel message is less than dust_limit_satoshis:
            // MUST reject the channel. Other fields have the same requirements as their counterparts in open_channel.
            if (open.channelReserveSatoshis < accept.dustLimitSatoshis) {
                return Either.Left(DustLimitAboveOurChannelReserve(accept.temporaryChannelId, accept.dustLimitSatoshis, open.channelReserveSatoshis))
            }
        }

        // if channel_reserve_satoshis is less than dust_limit_satoshis within the open_channel message: MUST reject the channel.
        if (accept.channelReserveSatoshis < open.dustLimitSatoshis) {
            return Either.Left(ChannelReserveBelowOurDustLimit(accept.temporaryChannelId, accept.channelReserveSatoshis, open.dustLimitSatoshis))
        }

        val reserveToFundingRatio = accept.channelReserveSatoshis.toLong().toDouble() / max(open.fundingSatoshis.toLong(), 1)
        if (reserveToFundingRatio > nodeParams.maxReserveToFundingRatio) {
            return Either.Left(ChannelReserveTooHigh(open.temporaryChannelId, accept.channelReserveSatoshis, reserveToFundingRatio, nodeParams.maxReserveToFundingRatio))
        }

        return Either.Right(Unit)
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
    fun aboveReserve(commitments: Commitments): Boolean {
        val remoteCommit = when (commitments.remoteNextCommitInfo) {
            is Either.Left -> commitments.remoteNextCommitInfo.value.nextRemoteCommit
            else -> commitments.remoteCommit
        }
        val toRemote = remoteCommit.spec.toRemote.truncateToSatoshi()
        // NB: this is an approximation (we don't take network fees into account)
        return toRemote > commitments.remoteParams.channelReserve
    }

    /**
     * Tells whether or not their expected next remote commitment number matches with our data
     *
     * @return
     *         - true if parties are in sync or remote is behind
     *         - false if we are behind
     */
    fun checkLocalCommit(commitments: Commitments, nextRemoteRevocationNumber: Long): Boolean {
        return when {
            // they just sent a new commit_sig, we have received it but they didn't receive our revocation
            commitments.localCommit.index == nextRemoteRevocationNumber -> true
            // we are in sync
            commitments.localCommit.index == nextRemoteRevocationNumber + 1 -> true
            // remote is behind: we return true because things are fine on our side
            commitments.localCommit.index > nextRemoteRevocationNumber + 1 -> true
            // we are behind
            else -> false
        }
    }

    /**
     * Tells whether or not their expected next local commitment number matches with our data
     *
     * @return
     *         - true if parties are in sync or remote is behind
     *         - false if we are behind
     */
    fun checkRemoteCommit(commitments: Commitments, nextLocalCommitmentNumber: Long): Boolean {
        return when {
            commitments.remoteNextCommitInfo.isLeft ->
                when {
                    // we just sent a new commit_sig but they didn't receive it
                    nextLocalCommitmentNumber == commitments.remoteNextCommitInfo.left!!.nextRemoteCommit.index -> true
                    // we just sent a new commit_sig, they have received it but we haven't received their revocation
                    nextLocalCommitmentNumber == (commitments.remoteNextCommitInfo.left!!.nextRemoteCommit.index + 1) -> true
                    // they are behind
                    nextLocalCommitmentNumber < commitments.remoteNextCommitInfo.left!!.nextRemoteCommit.index -> true
                    else -> false
                }
            commitments.remoteNextCommitInfo.isRight ->
                when {
                    // they have acknowledged the last commit_sig we sent
                    nextLocalCommitmentNumber == (commitments.remoteCommit.index + 1) -> true
                    // they are behind
                    nextLocalCommitmentNumber < (commitments.remoteCommit.index + 1) -> true
                    else -> false
                }
            else -> false
        }
    }

    /** This helper method will publish txs only if they haven't yet reached minDepth. */
    fun publishIfNeeded(txs: List<Transaction>, irrevocablySpent: Map<OutPoint, ByteVector32>, channelId: ByteVector32): List<ChannelAction.Blockchain.PublishTx> {
        val (skip, process) = txs.partition { it.inputsAlreadySpent(irrevocablySpent) }
        skip.forEach { tx -> logger.info { "c:$channelId no need to republish txid=${tx.txid}, it has already been confirmed" } }
        return process.map { tx ->
            logger.info { "c:$channelId publishing txid=${tx.txid}" }
            ChannelAction.Blockchain.PublishTx(tx)
        }
    }

    /** This helper method will watch txs only if they haven't yet reached minDepth. */
    fun watchConfirmedIfNeeded(txs: List<Transaction>, irrevocablySpent: Map<OutPoint, ByteVector32>, channelId: ByteVector32, minDepth: Long): List<ChannelAction.Blockchain.SendWatch> {
        val (skip, process) = txs.partition { it.inputsAlreadySpent(irrevocablySpent) }
        skip.forEach { tx -> logger.info { "c:$channelId no need to watch txid=${tx.txid}, it has already been confirmed" } }
        return process.map { tx -> ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, tx, minDepth, BITCOIN_TX_CONFIRMED(tx))) }
    }

    /** This helper method will watch txs only if the utxo they spend hasn't already been irrevocably spent. */
    fun watchSpentIfNeeded(parentTx: Transaction, txs: List<Transaction>, irrevocablySpent: Map<OutPoint, ByteVector32>, channelId: ByteVector32): List<ChannelAction.Blockchain.SendWatch> {
        val (skip, process) = txs.partition { it.inputsAlreadySpent(irrevocablySpent) }
        skip.forEach { tx -> logger.info { "c:$channelId no need to watch txid=${tx.txid}, it has already been confirmed" } }
        return process.map { ChannelAction.Blockchain.SendWatch(WatchSpent(channelId, parentTx, it.txIn.first().outPoint.index.toInt(), BITCOIN_OUTPUT_SPENT)) }
    }

    object Funding {

        fun makeFundingInputInfo(
            fundingTxId: ByteVector32,
            fundingTxOutputIndex: Int,
            fundingAmount: Satoshi,
            fundingPubkey1: PublicKey,
            fundingPubkey2: PublicKey
        ): Transactions.InputInfo {
            val fundingScript = multiSig2of2(fundingPubkey1, fundingPubkey2)
            val fundingTxOut = TxOut(fundingAmount, pay2wsh(fundingScript))
            return Transactions.InputInfo(
                OutPoint(fundingTxId, fundingTxOutputIndex.toLong()),
                fundingTxOut,
                ByteVector(write(fundingScript))
            )
        }

        data class FirstCommitTx(val localSpec: CommitmentSpec, val localCommitTx: Transactions.TransactionWithInputInfo.CommitTx, val remoteSpec: CommitmentSpec, val remoteCommitTx: Transactions.TransactionWithInputInfo.CommitTx)

        /**
         * Creates both sides' first commitment transaction.
         *
         * @return (localSpec, localTx, remoteSpec, remoteTx, fundingTxOutput)
         */
        fun makeFirstCommitTxs(
            keyManager: KeyManager,
            channelVersion: ChannelVersion,
            temporaryChannelId: ByteVector32,
            localParams: LocalParams,
            remoteParams: RemoteParams,
            fundingAmount: Satoshi,
            pushMsat: MilliSatoshi,
            initialFeerate: FeeratePerKw,
            fundingTxHash: ByteVector32,
            fundingTxOutputIndex: Int,
            remoteFirstPerCommitmentPoint: PublicKey
        ): Either<ChannelException, FirstCommitTx> {
            val toLocalMsat = if (localParams.isFunder) MilliSatoshi(fundingAmount) - pushMsat else pushMsat
            val toRemoteMsat = if (localParams.isFunder) pushMsat else MilliSatoshi(fundingAmount) - pushMsat

            val localSpec = CommitmentSpec(setOf(), feerate = initialFeerate, toLocal = toLocalMsat, toRemote = toRemoteMsat)
            val remoteSpec = CommitmentSpec(setOf(), feerate = initialFeerate, toLocal = toRemoteMsat, toRemote = toLocalMsat)

            if (!localParams.isFunder) {
                // they are funder, therefore they pay the fee: we need to make sure they can afford it!
                val localToRemoteMsat = remoteSpec.toLocal
                val fees = commitTxFee(remoteParams.dustLimit, remoteSpec)
                val missing = localToRemoteMsat.truncateToSatoshi() - localParams.channelReserve - fees
                if (missing < Satoshi(0)) {
                    return Either.Left(CannotAffordFees(temporaryChannelId, missing = -missing, reserve = localParams.channelReserve, fees = fees))
                }
            }

            val fundingPubKey = keyManager.fundingPublicKey(localParams.fundingKeyPath)
            val channelKeyPath = keyManager.channelKeyPath(localParams, channelVersion)
            val commitmentInput = makeFundingInputInfo(fundingTxHash, fundingTxOutputIndex, fundingAmount, fundingPubKey.publicKey, remoteParams.fundingPubKey)
            val localPerCommitmentPoint = keyManager.commitmentPoint(channelKeyPath, 0)
            val localCommitTx = Commitments.makeLocalTxs(keyManager, channelVersion, 0, localParams, remoteParams, commitmentInput, localPerCommitmentPoint, localSpec).first
            val remoteCommitTx = Commitments.makeRemoteTxs(keyManager, channelVersion, 0, localParams, remoteParams, commitmentInput, remoteFirstPerCommitmentPoint, remoteSpec).first

            return Either.Right(FirstCommitTx(localSpec, localCommitTx, remoteSpec, remoteCommitTx))
        }
    }

    object Closing {
        // used only to compute tx weights and estimate fees
        private val dummyPublicKey by lazy { PrivateKey(ByteArray(32) { 1.toByte() }).publicKey() }

        private fun isValidFinalScriptPubkey(scriptPubKey: ByteArray): Boolean {
            return runTrying {
                val script = Script.parse(scriptPubKey)
                Script.isPay2pkh(script) || Script.isPay2sh(script) || Script.isPay2wpkh(script) || Script.isPay2wsh(script)
            }.getOrElse { false }
        }

        fun isValidFinalScriptPubkey(scriptPubKey: ByteVector): Boolean = isValidFinalScriptPubkey(scriptPubKey.toByteArray())

        fun firstClosingFee(commitments: Commitments, localScriptPubkey: ByteArray, remoteScriptPubkey: ByteArray, requestedFeerate: FeeratePerKw): Satoshi {
            // this is just to estimate the weight which depends on the size of the pubkey scripts
            val dummyClosingTx = Transactions.makeClosingTx(commitments.commitInput, localScriptPubkey, remoteScriptPubkey, commitments.localParams.isFunder, Satoshi(0), Satoshi(0), commitments.localCommit.spec)
            val closingWeight = Transaction.weight(Transactions.addSigs(dummyClosingTx, dummyPublicKey, commitments.remoteParams.fundingPubKey, Transactions.PlaceHolderSig, Transactions.PlaceHolderSig).tx)
            return Transactions.weight2fee(requestedFeerate, closingWeight)
        }

        fun firstClosingFee(commitments: Commitments, localScriptPubkey: ByteVector, remoteScriptPubkey: ByteVector, requestedFeerate: FeeratePerKw): Satoshi =
            firstClosingFee(commitments, localScriptPubkey.toByteArray(), remoteScriptPubkey.toByteArray(), requestedFeerate)

        fun nextClosingFee(localClosingFee: Satoshi, remoteClosingFee: Satoshi): Satoshi = ((localClosingFee + remoteClosingFee) / 4) * 2

        fun makeFirstClosingTx(
            keyManager: KeyManager,
            commitments: Commitments,
            localScriptPubkey: ByteArray,
            remoteScriptPubkey: ByteArray,
            requestedFeerate: FeeratePerKw
        ): Pair<Transactions.TransactionWithInputInfo.ClosingTx, ClosingSigned> {
            val closingFee = firstClosingFee(commitments, localScriptPubkey, remoteScriptPubkey, requestedFeerate)
            return makeClosingTx(keyManager, commitments, localScriptPubkey, remoteScriptPubkey, closingFee)
        }

        fun makeClosingTx(
            keyManager: KeyManager,
            commitments: Commitments,
            localScriptPubkey: ByteArray,
            remoteScriptPubkey: ByteArray,
            closingFee: Satoshi
        ): Pair<Transactions.TransactionWithInputInfo.ClosingTx, ClosingSigned> {
            require(isValidFinalScriptPubkey(localScriptPubkey)) { "invalid localScriptPubkey" }
            require(isValidFinalScriptPubkey(remoteScriptPubkey)) { "invalid remoteScriptPubkey" }
            val dustLimit = commitments.localParams.dustLimit.max(commitments.remoteParams.dustLimit)
            val closingTx = Transactions.makeClosingTx(commitments.commitInput, localScriptPubkey, remoteScriptPubkey, commitments.localParams.isFunder, dustLimit, closingFee, commitments.localCommit.spec)
            val localClosingSig = keyManager.sign(closingTx, keyManager.fundingPublicKey(commitments.localParams.fundingKeyPath))
            val closingSigned = ClosingSigned(commitments.channelId, closingFee, localClosingSig)
            return Pair(closingTx, closingSigned)
        }

        fun checkClosingSignature(
            keyManager: KeyManager,
            commitments: Commitments,
            localScriptPubkey: ByteArray,
            remoteScriptPubkey: ByteArray,
            remoteClosingFee: Satoshi,
            remoteClosingSig: ByteVector64
        ): Either<ChannelException, Transaction> {
            val (closingTx, closingSigned) = makeClosingTx(keyManager, commitments, localScriptPubkey, remoteScriptPubkey, remoteClosingFee)
            val signedClosingTx = Transactions.addSigs(closingTx, keyManager.fundingPublicKey(commitments.localParams.fundingKeyPath).publicKey, commitments.remoteParams.fundingPubKey, closingSigned.signature, remoteClosingSig)
            return when (Transactions.checkSpendable(signedClosingTx)) {
                is Try.Success -> Either.Right(signedClosingTx.tx)
                is Try.Failure -> Either.Left(InvalidCloseSignature(commitments.channelId, signedClosingTx.tx))
            }
        }

        /**
         * Claim all the outputs that we've received from our current commit tx. This will be done using 2nd stage HTLC transactions.
         *
         * @param commitments our commitment data, which include payment preimages.
         * @return a list of transactions (one per output that we can claim).
         */
        fun claimCurrentLocalCommitTxOutputs(keyManager: KeyManager, commitments: Commitments, tx: Transaction, feerates: OnChainFeerates): LocalCommitPublished {
            val localCommit = commitments.localCommit
            val localParams = commitments.localParams
            val channelVersion = commitments.channelVersion
            require(localCommit.publishableTxs.commitTx.tx.txid == tx.txid) { "txid mismatch, provided tx is not the current local commit tx" }
            val channelKeyPath = keyManager.channelKeyPath(localParams, channelVersion)
            val localPerCommitmentPoint = keyManager.commitmentPoint(channelKeyPath, commitments.localCommit.index)
            val localRevocationPubkey = Generators.revocationPubKey(commitments.remoteParams.revocationBasepoint, localPerCommitmentPoint)
            val localDelayedPubkey = Generators.derivePubKey(keyManager.delayedPaymentPoint(channelKeyPath).publicKey, localPerCommitmentPoint)
            val feerateDelayed = feerates.claimMainFeerate

            // first we will claim our main output as soon as the delay is over
            val mainDelayedTx = generateTx("main-delayed-output") {
                Transactions.makeClaimLocalDelayedOutputTx(
                    tx,
                    localParams.dustLimit,
                    localRevocationPubkey,
                    commitments.remoteParams.toSelfDelay,
                    localDelayedPubkey,
                    localParams.defaultFinalScriptPubKey.toByteArray(),
                    feerateDelayed
                )
            }?.let {
                val sig = keyManager.sign(it, keyManager.delayedPaymentPoint(channelKeyPath), localPerCommitmentPoint, SigHash.SIGHASH_ALL)
                Transactions.addSigs(it, sig).tx
            }

            // those are the preimages to existing received htlcs
            val preimages = commitments.localChanges.all.filterIsInstance<UpdateFulfillHtlc>().map { it.paymentPreimage }

            val htlcTxs = localCommit.publishableTxs.htlcTxsAndSigs.mapNotNull { (txInfo, localSig, remoteSig) ->
                when (txInfo) {
                    // incoming htlc for which we have the preimage: we spend it directly
                    // incoming htlc for which we don't have the preimage: nothing to do, it will timeout eventually and they will get their funds back
                    is HtlcSuccessTx -> {
                        preimages.firstOrNull { r ->
                            sha256(r).toByteVector() == txInfo.paymentHash
                        }?.let { preimage -> Transactions.addSigs(txInfo, localSig, remoteSig, preimage) }
                    }

                    // outgoing htlc: they may or may not have the preimage, the only thing to do is try to get back our funds after timeout
                    is HtlcTimeoutTx -> Transactions.addSigs(txInfo, localSig, remoteSig)
                    else -> null
                }
            }

            // all htlc output to us are delayed, so we need to claim them as soon as the delay is over
            val htlcDelayedTxs = htlcTxs.mapNotNull { txInfo ->
                generateTx("claim-htlc-delayed") {
                    Transactions.makeClaimLocalDelayedOutputTx(
                        txInfo.tx,
                        localParams.dustLimit,
                        localRevocationPubkey,
                        commitments.remoteParams.toSelfDelay,
                        localDelayedPubkey,
                        localParams.defaultFinalScriptPubKey.toByteArray(),
                        feerateDelayed
                    )
                }?.let {
                    val sig = keyManager.sign(it, keyManager.delayedPaymentPoint(channelKeyPath), localPerCommitmentPoint, SigHash.SIGHASH_ALL)
                    Transactions.addSigs(it, sig).tx
                }
            }

            return LocalCommitPublished(
                commitTx = tx,
                claimMainDelayedOutputTx = mainDelayedTx,
                htlcSuccessTxs = htlcTxs.filterIsInstance<HtlcSuccessTx>().map(HtlcSuccessTx::tx),
                htlcTimeoutTxs = htlcTxs.filterIsInstance<HtlcTimeoutTx>().map(HtlcTimeoutTx::tx),
                claimHtlcDelayedTxs = htlcDelayedTxs
            )
        }

        /**
         * Claim all the outputs that we've received from their current commit tx.
         *
         * @param commitments our commitment data, which include payment preimages.
         * @param remoteCommit the remote commitment data to use to claim outputs (it can be their current or next commitment).
         * @param tx the remote commitment transaction that has just been published.
         * @return a list of transactions (one per output that we can claim).
         */
        fun claimRemoteCommitTxOutputs(keyManager: KeyManager, commitments: Commitments, remoteCommit: RemoteCommit, tx: Transaction, feerates: OnChainFeerates): RemoteCommitPublished {
            val channelVersion = commitments.channelVersion
            val localParams = commitments.localParams
            val remoteParams = commitments.remoteParams
            val commitInput = commitments.commitInput
            val (remoteCommitTx, _, _) = Commitments.makeRemoteTxs(
                keyManager,
                channelVersion,
                remoteCommit.index,
                localParams,
                remoteParams,
                commitInput,
                remoteCommit.remotePerCommitmentPoint,
                remoteCommit.spec
            )
            require(remoteCommitTx.tx.txid == tx.txid) { "txid mismatch, provided tx is not the current remote commit tx" }

            val channelKeyPath = keyManager.channelKeyPath(localParams, channelVersion)
            val localPaymentPubkey = keyManager.paymentPoint(channelKeyPath).publicKey
            val localHtlcPubkey = Generators.derivePubKey(keyManager.htlcPoint(channelKeyPath).publicKey, remoteCommit.remotePerCommitmentPoint)
            val remoteDelayedPaymentPubkey = Generators.derivePubKey(remoteParams.delayedPaymentBasepoint, remoteCommit.remotePerCommitmentPoint)
            val remoteHtlcPubkey = Generators.derivePubKey(remoteParams.htlcBasepoint, remoteCommit.remotePerCommitmentPoint)
            val remoteRevocationPubkey = Generators.revocationPubKey(keyManager.revocationPoint(channelKeyPath).publicKey, remoteCommit.remotePerCommitmentPoint)
            val outputs = makeCommitTxOutputs(
                commitments.remoteParams.fundingPubKey,
                keyManager.fundingPublicKey(commitments.localParams.fundingKeyPath).publicKey,
                !localParams.isFunder,
                remoteParams.dustLimit,
                remoteRevocationPubkey,
                localParams.toSelfDelay,
                remoteDelayedPaymentPubkey,
                localPaymentPubkey,
                remoteHtlcPubkey,
                localHtlcPubkey,
                remoteCommit.spec
            )

            // we need to use a rather high fee for htlc-claim because we compete with the counterparty
            val feerateClaimHtlc = feerates.fastFeerate

            // those are the preimages to existing received htlcs
            val preimages = commitments.localChanges.all.filterIsInstance<UpdateFulfillHtlc>().map { it.paymentPreimage }

            // remember we are looking at the remote commitment so IN for them is really OUT for us and vice versa

            val claimHtlcSuccessTxs = remoteCommit.spec.htlcs.filterIsInstance<OutgoingHtlc>().map { it.add }.mapNotNull { add ->
                // incoming htlc for which we have the preimage: we spend it directly.
                // incoming htlc for which we don't have the preimage: nothing to do, it will timeout eventually and they will get their funds back.
                // NB: we are looking at the remote's commitment, from its point of view it's an outgoing htlc.
                preimages.firstOrNull { r -> sha256(r).toByteVector() == add.paymentHash }?.let { preimage ->
                    generateTx("claim-htlc-success") {
                        Transactions.makeClaimHtlcSuccessTx(
                            remoteCommitTx.tx,
                            outputs,
                            localParams.dustLimit,
                            localHtlcPubkey,
                            remoteHtlcPubkey,
                            remoteRevocationPubkey,
                            localParams.defaultFinalScriptPubKey.toByteArray(),
                            add,
                            feerateClaimHtlc
                        )
                    }?.let {
                        val sig = keyManager.sign(it, keyManager.htlcPoint(channelKeyPath), remoteCommit.remotePerCommitmentPoint, SigHash.SIGHASH_ALL)
                        Transactions.addSigs(it, sig, preimage).tx
                    }
                }
            }

            val claimHtlcTimeoutTxs = remoteCommit.spec.htlcs.filterIsInstance<IncomingHtlc>().map { it.add }.mapNotNull { add ->
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
                        add,
                        feerateClaimHtlc
                    )
                }?.let {
                    val sig = keyManager.sign(it, keyManager.htlcPoint(channelKeyPath), remoteCommit.remotePerCommitmentPoint, SigHash.SIGHASH_ALL)
                    Transactions.addSigs(it, sig).tx
                }
            }

            // we claim our output and add the htlc txs we just created
            return claimRemoteCommitMainOutput(keyManager, commitments, tx, feerates.claimMainFeerate).copy(
                claimHtlcSuccessTxs = claimHtlcSuccessTxs,
                claimHtlcTimeoutTxs = claimHtlcTimeoutTxs
            )
        }

        /**
         * Claim our main output only from their commit tx.
         *
         * @param commitments either our current commitment data in case of usual remote uncooperative closing or our outdated commitment data
         * in case of data loss protection procedure; in any case it is used only to get some constant parameters, not commitment data.
         * @param tx the remote commitment transaction that has just been published.
         * @return a transaction to claim our main output.
         */
        internal fun claimRemoteCommitMainOutput(keyManager: KeyManager, commitments: Commitments, tx: Transaction, claimMainFeerate: FeeratePerKw): RemoteCommitPublished {
            val channelKeyPath = keyManager.channelKeyPath(commitments.localParams, commitments.channelVersion)
            val localPaymentPoint = keyManager.paymentPoint(channelKeyPath)

            val mainTx = generateTx("claim-remote-delayed-output") {
                Transactions.makeClaimRemoteDelayedOutputTx(
                    tx,
                    commitments.localParams.dustLimit,
                    localPaymentPoint.publicKey,
                    commitments.localParams.defaultFinalScriptPubKey,
                    claimMainFeerate
                )
            }?.let {
                val sig = keyManager.sign(it, localPaymentPoint)
                Transactions.addSigs(it, sig).tx
            }

            return RemoteCommitPublished(commitTx = tx, claimMainOutputTx = mainTx)
        }

        /**
         * When an unexpected transaction spending the funding tx is detected, we can use our secrets to identify the commitment number.
         * This can then be used to find the necessary information to build penalty txs for every htlc output.
         */
        private fun extractTxNumber(keyManager: KeyManager, commitments: Commitments, tx: Transaction): Long {
            require(tx.txIn.size == 1) { "commitment tx should have 1 input" }
            val channelKeyPath = keyManager.channelKeyPath(commitments.localParams, commitments.channelVersion)
            val obscuredTxNumber = Transactions.decodeTxNumber(tx.txIn.first().sequence, tx.lockTime)
            val localPaymentPoint = keyManager.paymentPoint(channelKeyPath)
            // this tx has been published by remote, so we need to invert local/remote params
            val txNumber = Transactions.obscuredCommitTxNumber(obscuredTxNumber, !commitments.localParams.isFunder, commitments.remoteParams.paymentBasepoint, localPaymentPoint.publicKey)
            require(txNumber <= 0xffffffffffffL) { "txNumber must be lesser than 48 bits long" }
            logger.warning { "c:${commitments.channelId} a revoked commit has been published with txNumber=$txNumber" }
            return txNumber
        }

        /**
         * When an unexpected transaction spending the funding tx is detected:
         * 1) we find out if the published transaction is one of our remote's revoked txs
         * 2) and then:
         *  a) if it is a revoked tx we build a set of transactions that will punish them by stealing all their funds
         *  b) otherwise there is nothing we can do
         *
         * @return a [[RevokedCommitPublished]] object containing a penalty transaction for the remote's main output and the commitment number.
         * With the commitment number, the caller should fetch information about the htlcs in this commitment and then call [[claimRevokedRemoteCommitTxHtlcOutputs]].
         */
        fun claimRevokedRemoteCommitTxOutputs(keyManager: KeyManager, commitments: Commitments, tx: Transaction, feerates: OnChainFeerates): Pair<RevokedCommitPublished, Long>? {
            val txNumber = extractTxNumber(keyManager, commitments, tx)
            // now we know what commit number this tx is referring to, we can derive the commitment point from the shachain
            val hash = commitments.remotePerCommitmentSecrets.getHash(0xFFFFFFFFFFFFL - txNumber) ?: return null

            val channelKeyPath = keyManager.channelKeyPath(commitments.localParams, commitments.channelVersion)
            val localPaymentPoint = keyManager.paymentPoint(channelKeyPath)
            val remotePerCommitmentSecret = PrivateKey.fromHex(hash.toHex())
            val remotePerCommitmentPoint = remotePerCommitmentSecret.publicKey()
            val remoteDelayedPaymentPubkey = Generators.derivePubKey(commitments.remoteParams.delayedPaymentBasepoint, remotePerCommitmentPoint)
            val remoteRevocationPubkey = Generators.revocationPubKey(keyManager.revocationPoint(channelKeyPath).publicKey, remotePerCommitmentPoint)

            val feerateMain = feerates.claimMainFeerate
            // we need to use a high fee here for punishment txs because after a delay they can be spent by the counterparty
            val feeratePenalty = feerates.fastFeerate

            // first we will claim our main output right away
            val mainTx = generateTx("claim-remote-delayed-output") {
                Transactions.makeClaimRemoteDelayedOutputTx(
                    tx,
                    commitments.localParams.dustLimit,
                    localPaymentPoint.publicKey,
                    commitments.localParams.defaultFinalScriptPubKey,
                    feerateMain
                )
            }?.let {
                val sig = keyManager.sign(it, localPaymentPoint)
                Transactions.addSigs(it, sig).tx
            }

            // then we punish them by stealing their main output
            val mainPenaltyTx = generateTx("main-penalty") {
                Transactions.makeMainPenaltyTx(
                    tx,
                    commitments.localParams.dustLimit,
                    remoteRevocationPubkey,
                    commitments.localParams.defaultFinalScriptPubKey.toByteArray(),
                    commitments.localParams.toSelfDelay,
                    remoteDelayedPaymentPubkey,
                    feeratePenalty
                )
            }?.let {
                val sig = keyManager.sign(it, keyManager.revocationPoint(channelKeyPath), remotePerCommitmentSecret)
                Transactions.addSigs(it, sig).tx
            }

            return Pair(RevokedCommitPublished(commitTx = tx, remotePerCommitmentSecret = remotePerCommitmentSecret, claimMainOutputTx = mainTx, mainPenaltyTx = mainPenaltyTx), txNumber)
        }

        /**
         * Once we've fetched htlc information for a revoked commitment from the DB, we create penalty transactions to claim all htlc outputs.
         */
        fun claimRevokedRemoteCommitTxHtlcOutputs(
            keyManager: KeyManager,
            commitments: Commitments,
            revokedCommitPublished: RevokedCommitPublished,
            feerates: OnChainFeerates,
            htlcInfos: List<ChannelAction.Storage.HtlcInfo>
        ): RevokedCommitPublished {
            // we need to use a high fee here for punishment txs because after a delay they can be spent by the counterparty
            val feeratePenalty = feerates.fastFeerate

            val channelKeyPath = keyManager.channelKeyPath(commitments.localParams, commitments.channelVersion)
            val remotePerCommitmentPoint = revokedCommitPublished.remotePerCommitmentSecret.publicKey()
            val remoteRevocationPubkey = Generators.revocationPubKey(keyManager.revocationPoint(channelKeyPath).publicKey, remotePerCommitmentPoint)
            val remoteHtlcPubkey = Generators.derivePubKey(commitments.remoteParams.htlcBasepoint, remotePerCommitmentPoint)
            val localHtlcPubkey = Generators.derivePubKey(keyManager.htlcPoint(channelKeyPath).publicKey, remotePerCommitmentPoint)

            // we retrieve the information needed to rebuild htlc scripts
            logger.info { "c:${commitments.channelId} found ${htlcInfos.size} htlcs for txid=${revokedCommitPublished.commitTx.txid}" }
            val htlcsRedeemScripts = htlcInfos.flatMap { htlcInfo ->
                val htlcReceived = Scripts.htlcReceived(remoteHtlcPubkey, localHtlcPubkey, remoteRevocationPubkey, ripemd160(htlcInfo.paymentHash), htlcInfo.cltvExpiry)
                val htlcOffered = Scripts.htlcOffered(remoteHtlcPubkey, localHtlcPubkey, remoteRevocationPubkey, ripemd160(htlcInfo.paymentHash))
                listOf(htlcReceived, htlcOffered)
            }.map { redeemScript -> write(pay2wsh(redeemScript)).toByteVector() to write(redeemScript).toByteVector() }.toMap()

            // and finally we steal the htlc outputs
            val htlcPenaltyTxs = revokedCommitPublished.commitTx.txOut.mapIndexedNotNull { outputIndex, txOut ->
                htlcsRedeemScripts[txOut.publicKeyScript]?.let { redeemScript ->
                    generateTx("htlc-penalty") {
                        Transactions.makeHtlcPenaltyTx(
                            revokedCommitPublished.commitTx,
                            outputIndex,
                            redeemScript.toByteArray(),
                            commitments.localParams.dustLimit,
                            commitments.localParams.defaultFinalScriptPubKey.toByteArray(),
                            feeratePenalty
                        )
                    }?.let { htlcPenaltyTx ->
                        val sig = keyManager.sign(htlcPenaltyTx, keyManager.revocationPoint(channelKeyPath), revokedCommitPublished.remotePerCommitmentSecret)
                        Transactions.addSigs(htlcPenaltyTx, sig, remoteRevocationPubkey).tx
                    }
                }
            }

            return revokedCommitPublished.copy(htlcPenaltyTxs = htlcPenaltyTxs)
        }

        /**
         * Claims the output of an [[HtlcSuccessTx]] or [[HtlcTimeoutTx]] transaction using a revocation key.
         *
         * In case a revoked commitment with pending HTLCs is published, there are two ways the HTLC outputs can be taken as punishment:
         * - by spending the corresponding output of the commitment tx, using [[HtlcPenaltyTx]] that we generate as soon as we detect that a revoked commit
         * has been spent; note that those transactions will compete with [[HtlcSuccessTx]] and [[HtlcTimeoutTx]] published by the counterparty.
         * - by spending the delayed output of [[HtlcSuccessTx]] and [[HtlcTimeoutTx]] if those get confirmed; because the output of these txs is protected by
         * an OP_CSV delay, we will have time to spend them with a revocation key. In that case, we generate the spending transactions "on demand",
         * this is the purpose of this method.
         */
        fun claimRevokedHtlcTxOutputs(keyManager: KeyManager, commitments: Commitments, revokedCommitPublished: RevokedCommitPublished, htlcTx: Transaction, feerates: OnChainFeerates): Pair<RevokedCommitPublished, Transaction?> {
            val claimTxs = buildList {
                revokedCommitPublished.claimMainOutputTx?.let { add(it) }
                revokedCommitPublished.mainPenaltyTx?.let { add(it) }
                addAll(revokedCommitPublished.htlcPenaltyTxs)
            }

            if (htlcTx.txIn.map { it.outPoint.txid }.contains(revokedCommitPublished.commitTx.txid) && !claimTxs.map { it.txid }.toSet().contains(htlcTx.txid)) {
                logger.info { "c:${commitments.channelId} looks like txid=${htlcTx.txid} could be a 2nd level htlc tx spending revoked commit txid=${revokedCommitPublished.commitTx.txid}" }
                // Let's assume that htlcTx is an HtlcSuccessTx or HtlcTimeoutTx and try to generate a tx spending its output using a revocation key
                val channelKeyPath = keyManager.channelKeyPath(commitments.localParams, commitments.channelVersion)
                val remotePerCommitmentPoint = revokedCommitPublished.remotePerCommitmentSecret.publicKey()
                val remoteDelayedPaymentPubkey = Generators.derivePubKey(commitments.remoteParams.delayedPaymentBasepoint, remotePerCommitmentPoint)
                val remoteRevocationPubkey = Generators.revocationPubKey(keyManager.revocationPoint(channelKeyPath).publicKey, remotePerCommitmentPoint)

                // we need to use a high fee here for punishment txs because after a delay they can be spent by the counterparty
                val feeratePenalty = feerates.fastFeerate

                val signedTx = generateTx("claim-htlc-delayed-penalty") {
                    Transactions.makeClaimDelayedOutputPenaltyTx(
                        htlcTx,
                        commitments.localParams.dustLimit,
                        remoteRevocationPubkey,
                        commitments.localParams.toSelfDelay,
                        remoteDelayedPaymentPubkey,
                        commitments.localParams.defaultFinalScriptPubKey.toByteArray(),
                        feeratePenalty
                    )
                }?.let {
                    val sig = keyManager.sign(it, keyManager.revocationPoint(channelKeyPath), revokedCommitPublished.remotePerCommitmentSecret)
                    val signedTx = Transactions.addSigs(it, sig).tx
                    // we need to make sure that the tx is indeed valid
                    when (runTrying { Transaction.correctlySpends(signedTx, listOf(htlcTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }) {
                        is Try.Success -> signedTx
                        is Try.Failure -> null
                    }
                } ?: return revokedCommitPublished to null

                return revokedCommitPublished.copy(claimHtlcDelayedPenaltyTxs = revokedCommitPublished.claimHtlcDelayedPenaltyTxs + signedTx) to signedTx
            } else {
                return revokedCommitPublished to null
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
        fun LocalCommit.extractPreimages(tx: Transaction): Set<Pair<UpdateAddHtlc, ByteVector32>> {
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
                spec.htlcs.filter { it is OutgoingHtlc && it.add.paymentHash.contentEquals(sha256(paymentPreimage)) }.map { it.add to paymentPreimage }
            }.toSet()
        }

        /**
         * We may have multiple HTLCs with the same payment hash because of MPP.
         * When a timeout transaction is confirmed, we need to find the best matching HTLC to fail upstream.
         * We need to handle potentially duplicate HTLCs (same amount and expiry): this function will use a deterministic
         * ordering of transactions and HTLCs to handle this.
         */
        private fun Transaction.findTimedOutHtlc(paymentHash160: ByteVector, htlcs: List<UpdateAddHtlc>, timeoutTxs: List<Transaction>, extractPaymentHash: (ScriptWitness) -> ByteVector?): UpdateAddHtlc? {
            // We use a deterministic ordering to match HTLCs to their corresponding HTLC-timeout tx.
            // We don't match on the expected amounts because this is error-prone: computing the correct weight of a claim-htlc-timeout
            // is hard because signatures can be either 71, 72 or 73 bytes long (ECDSA DER encoding).
            // We could instead look at the spent outpoint, but that requires more lookups and access to the published commitment transaction.
            // It's simpler to just use the amount as the first ordering key: since the feerate is the same for all timeout
            // transactions we will find the right HTLC to fail upstream.
            val matchingHtlcs = htlcs
                .filter { it.cltvExpiry.toLong() == lockTime && ripemd160(it.paymentHash).toByteVector() == paymentHash160 }
                .sortedWith(compareBy({ it.amountMsat.toLong() }, { it.id }))

            val matchingTxs = timeoutTxs
                .filter { t -> t.lockTime == t.lockTime && t.txIn.map { it.witness }.map(extractPaymentHash).contains(paymentHash160) }
                .sortedWith(compareBy({ t -> t.txOut.map { it.amount.sat }.sum() }, { it.txid.toHex() }))

            if (matchingTxs.size != matchingHtlcs.size) {
                logger.error { "some htlcs don't have a corresponding timeout transaction: tx=$this, htlcs=${matchingHtlcs.map { it.id }.joinToString()}, timeout-txs=${matchingTxs.joinToString()}" }
            }

            return matchingHtlcs.zip(matchingTxs).firstOrNull { (_, timeoutTx) -> timeoutTx.txid == txid }?.first
        }

        /**
         * In CLOSING state, when we are notified that a transaction has been confirmed, we analyze it to find out if one or
         * more htlcs have timed out and need to be failed in an upstream channel.
         *
         * @param tx a tx that has reached min_depth
         * @return a set of htlcs that need to be failed upstream
         */
        fun LocalCommit.timedOutHtlcs(localCommitPublished: LocalCommitPublished, localDustLimit: Satoshi, tx: Transaction): Set<UpdateAddHtlc> {
            val untrimmedHtlcs = Transactions.trimOfferedHtlcs(localDustLimit, spec).map { it.add }
            return if (tx.txid == publishableTxs.commitTx.tx.txid) {
                // the tx is a commitment tx, we can immediately fail all dust htlcs (they don't have an output in the tx)
                (spec.htlcs.outgoings() - untrimmedHtlcs).toSet()
            } else {
                // maybe this is a timeout tx, in that case we can resolve and fail the corresponding htlc
                tx.txIn
                    .map { it.witness }
                    .mapNotNull(Scripts.extractPaymentHashFromHtlcTimeout())
                    .mapNotNull { paymentHash160 ->
                        logger.info { ("extracted paymentHash160=$paymentHash160 and expiry=${tx.lockTime} from tx=$tx (htlc-timeout)") }
                        tx.findTimedOutHtlc(
                            paymentHash160,
                            untrimmedHtlcs,
                            localCommitPublished.htlcTimeoutTxs,
                            Scripts.extractPaymentHashFromHtlcTimeout()
                        )
                    }.toSet()
            }
        }

        /**
         * In CLOSING state, when we are notified that a transaction has been confirmed, we analyze it to find out if one or
         * more htlcs have timed out and need to be failed in an upstream channel.
         *
         * @param tx a tx that has reached min_depth
         * @return a set of htlcs that need to be failed upstream
         */
        fun RemoteCommit.timedOutHtlcs(remoteCommitPublished: RemoteCommitPublished, remoteDustLimit: Satoshi, tx: Transaction): Set<UpdateAddHtlc> {
            val untrimmedHtlcs = Transactions.trimReceivedHtlcs(remoteDustLimit, spec).map { it.add }
            return if (tx.txid == txid) {
                // the tx is a commitment tx, we can immediately fail all dust htlcs (they don't have an output in the tx)
                (spec.htlcs.incomings() - untrimmedHtlcs).toSet()
            } else {
                // maybe this is a timeout tx, in that case we can resolve and fail the corresponding htlc
                tx.txIn
                    .map { it.witness }
                    .mapNotNull(Scripts.extractPaymentHashFromClaimHtlcTimeout())
                    .mapNotNull { paymentHash160 ->
                        logger.info { "extracted paymentHash160=$paymentHash160 and expiry=${tx.lockTime} from tx=$tx (claim-htlc-timeout)" }
                        tx.findTimedOutHtlc(
                            paymentHash160,
                            untrimmedHtlcs,
                            remoteCommitPublished.claimHtlcTimeoutTxs,
                            Scripts.extractPaymentHashFromClaimHtlcTimeout()
                        )
                    }.toSet()
            }
        }

        /**
         * As soon as a local or remote commitment reaches min_depth, we know which htlcs will be settled on-chain (whether
         * or not they actually have an output in the commitment tx).
         *
         * @param tx a transaction that is sufficiently buried in the blockchain
         */
        fun onChainOutgoingHtlcs(localCommit: LocalCommit, remoteCommit: RemoteCommit, nextRemoteCommit_opt: RemoteCommit?, tx: Transaction): Set<UpdateAddHtlc> = when {
            localCommit.publishableTxs.commitTx.tx.txid == tx.txid -> localCommit.spec.htlcs.outgoings().toSet()
            remoteCommit.txid == tx.txid -> remoteCommit.spec.htlcs.incomings().toSet()
            nextRemoteCommit_opt?.txid == tx.txid -> nextRemoteCommit_opt.spec.htlcs.incomings().toSet()
            else -> emptySet()
        }

        /**
         * If a commitment tx reaches min_depth, we need to fail the outgoing htlcs that will never reach the blockchain.
         * It could be because only us had signed them, or because a revoked commitment got confirmed.
         */
        fun overriddenOutgoingHtlcs(localCommit: LocalCommit, remoteCommit: RemoteCommit, nextRemoteCommit: RemoteCommit?, revokedCommitPublished: List<RevokedCommitPublished>, tx: Transaction): Set<UpdateAddHtlc> = when {
            localCommit.publishableTxs.commitTx.tx.txid == tx.txid -> {
                // our commit got confirmed, so any htlc that we signed but they didn't sign will never reach the chain
                val mostRecentRemoteCommit = nextRemoteCommit ?: remoteCommit
                // NB: from the point of view of the remote, their incoming htlcs are our outgoing htlcs
                mostRecentRemoteCommit.spec.htlcs.incomings().toSet() - localCommit.spec.htlcs.outgoings().toSet()
            }
            remoteCommit.txid == tx.txid -> when (nextRemoteCommit) {
                null -> emptySet() // their last commitment got confirmed, so no htlcs will be overridden, they will timeout or be fulfilled on chain
                else -> {
                    // we had signed a new commitment but they committed the previous one
                    // any htlc that we signed in the new commitment that they didn't sign will never reach the chain
                    nextRemoteCommit.spec.htlcs.incomings().toSet() - localCommit.spec.htlcs.outgoings().toSet()
                }
            }
            revokedCommitPublished.map { it.commitTx.txid }.contains(tx.txid) -> {
                // a revoked commitment got confirmed: we will claim its outputs, but we also need to fail htlcs that are pending in the latest commitment
                (nextRemoteCommit ?: remoteCommit).spec.htlcs.incomings().toSet()
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
        fun Transaction.inputsAlreadySpent(irrevocablySpent: Map<OutPoint, ByteVector32>): Boolean {
            // NB: some transactions may have multiple inputs (e.g. htlc txs)
            val outPoints = txIn.map { it.outPoint }
            return outPoints.any { irrevocablySpent.contains(it) }
        }

        /**
         * Wraps transaction generation in a Try and filters failures to avoid one transaction negatively impacting a whole commitment.
         */
        private fun <T : Transactions.TransactionWithInputInfo> generateTx(desc: String, attempt: () -> Transactions.TxResult<T>): T? =
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

    @OptIn(ExperimentalSerializationApi::class)
    fun encrypt(key: ByteVector32, state: ChannelStateWithCommitments): ByteArray {
        val bin = ChannelStateWithCommitments.serialize(state)
        // NB: there is a chance of collision here, due to how the nonce is calculated. Probability of collision is once every 2.2E19 times.
        // See https://en.wikipedia.org/wiki/Birthday_attack
        val nonce = sha256(bin).take(12).toByteArray()
        val (ciphertext, tag) = ChaCha20Poly1305.encrypt(key.toByteArray(), nonce, bin, ByteArray(0))
        return ciphertext + nonce + tag
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun decrypt(key: ByteVector32, data: ByteArray): ChannelStateWithCommitments {
        // nonce is 12B, tag is 16B
        val ciphertext = data.dropLast(12 + 16)
        val nonce = data.takeLast(12 + 16).take(12)
        val tag = data.takeLast(16)
        val plaintext = ChaCha20Poly1305.decrypt(key.toByteArray(), nonce.toByteArray(), ciphertext.toByteArray(), ByteArray(0), tag.toByteArray())
        return ChannelStateWithCommitments.deserialize(plaintext)
    }

    fun decrypt(key: PrivateKey, data: ByteArray): ChannelStateWithCommitments = decrypt(key.value, data)

    fun decrypt(key: PrivateKey, data: ByteVector): ChannelStateWithCommitments = decrypt(key, data.toByteArray())
}
