package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.Crypto.ripemd160
import fr.acinq.bitcoin.Crypto.sha256
import fr.acinq.bitcoin.Script.pay2wsh
import fr.acinq.bitcoin.Script.write
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
import fr.acinq.lightning.crypto.Generators
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.transactions.*
import fr.acinq.lightning.transactions.Scripts.multiSig2of2
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
import kotlin.native.concurrent.ThreadLocal

@ThreadLocal
object Helpers {

    val logger by lightningLogger()

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
    fun validateParamsFundee(nodeParams: NodeParams, open: OpenChannel, localParams: LocalParams, remoteFeatures: Features): Either<ChannelException, ChannelFeatures> {
        // NB: we only accept channels from peers who support explicit channel type negotiation.
        val channelType = open.channelType ?: return Either.Left(MissingChannelType(open.temporaryChannelId, ChannelType.SupportedChannelType.AnchorOutputs))
        if (channelType != ChannelType.SupportedChannelType.AnchorOutputs) {
            return Either.Left(InvalidChannelType(open.temporaryChannelId, ChannelType.SupportedChannelType.AnchorOutputs, channelType))
        }

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

        if (open.dustLimitSatoshis > nodeParams.maxRemoteDustLimit) {
            return Either.Left(DustLimitTooLarge(open.temporaryChannelId, open.dustLimitSatoshis, nodeParams.maxRemoteDustLimit))
        }

        if (open.channelReserveSatoshis == 0.sat && localParams.features.hasFeature(Feature.ZeroReserveChannels)) {
            // NB: if the funder doesn't require us to have a reserve, we can't ensure that dust_limit_satoshis is greater than our reserve.
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
        if (nodeParams.chainHash == Block.LivenetGenesisBlock.hash && open.dustLimitSatoshis < Channel.MIN_DUST_LIMIT) {
            return Either.Left(DustLimitTooSmall(open.temporaryChannelId, open.dustLimitSatoshis, Channel.MIN_DUST_LIMIT))
        }

        // we don't check that the funder's amount for the initial commitment transaction is sufficient for full fee payment
        // now, but it will be done later when we receive `funding_created`
        val reserveToFundingRatio = open.channelReserveSatoshis.toLong().toDouble() / max(open.fundingSatoshis.toLong(), 1)
        if (reserveToFundingRatio > nodeParams.maxReserveToFundingRatio) {
            return Either.Left(ChannelReserveTooHigh(open.temporaryChannelId, open.channelReserveSatoshis, reserveToFundingRatio, nodeParams.maxReserveToFundingRatio))
        }

        val channelFeatures = ChannelFeatures(
            buildSet {
                addAll(channelType.features)
                if (Features.canUseFeature(localParams.features, remoteFeatures, Feature.Wumbo)) add(Feature.Wumbo)
                if (open.channelReserveSatoshis == 0.sat) add(Feature.ZeroReserveChannels)
                // NB: we currently force unconfirmed channels regardless of what our peer supports.
                // We should fix that once it is fully specified.
                if (localParams.features.hasFeature(Feature.ZeroConfChannels)) add(Feature.ZeroConfChannels)
            }
        )

        return Either.Right(channelFeatures)
    }

    /** Called by the funder. */
    fun validateParamsFunder(nodeParams: NodeParams, init: ChannelEvent.InitFunder, open: OpenChannel, accept: AcceptChannel): Either<ChannelException, ChannelFeatures> {
        require(open.channelType != null) { "we should have sent a channel type in open_channel" }
        if (accept.channelType == null) {
            // We only open channels to peers who support explicit channel type negotiation.
            return Either.Left(MissingChannelType(accept.temporaryChannelId, open.channelType!!))
        }
        if (open.channelType != accept.channelType) {
            return Either.Left(InvalidChannelType(accept.temporaryChannelId, open.channelType!!, accept.channelType!!))
        }

        if (accept.maxAcceptedHtlcs > Channel.MAX_ACCEPTED_HTLCS) {
            return Either.Left(InvalidMaxAcceptedHtlcs(accept.temporaryChannelId, accept.maxAcceptedHtlcs, Channel.MAX_ACCEPTED_HTLCS))
        }
        // only enforce dust limit check on mainnet
        if (nodeParams.chainHash == Block.LivenetGenesisBlock.hash && accept.dustLimitSatoshis < Channel.MIN_DUST_LIMIT) {
            return Either.Left(DustLimitTooSmall(accept.temporaryChannelId, accept.dustLimitSatoshis, Channel.MIN_DUST_LIMIT))
        }

        if (accept.dustLimitSatoshis > nodeParams.maxRemoteDustLimit) {
            return Either.Left(DustLimitTooLarge(accept.temporaryChannelId, accept.dustLimitSatoshis, nodeParams.maxRemoteDustLimit))
        }

        // BOLT #2: The receiving node MUST fail the channel if: dust_limit_satoshis is greater than channel_reserve_satoshis.
        if (accept.dustLimitSatoshis > accept.channelReserveSatoshis) {
            return Either.Left(DustLimitTooLarge(accept.temporaryChannelId, accept.dustLimitSatoshis, accept.channelReserveSatoshis))
        }

        // if minimum_depth is unreasonably large: MAY reject the channel.
        if (accept.toSelfDelay > Channel.MAX_TO_SELF_DELAY || accept.toSelfDelay > nodeParams.maxToLocalDelayBlocks) {
            return Either.Left(ToSelfDelayTooHigh(accept.temporaryChannelId, accept.toSelfDelay, nodeParams.maxToLocalDelayBlocks))
        }

        if (open.channelReserveSatoshis == 0.sat) {
            // if we proposed a zero-reserve channel to our peer, we don't make any additional requirement on dust limit.
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

        val channelFeatures = ChannelFeatures(
            buildSet {
                addAll(init.channelType.features)
                if (Features.canUseFeature(init.localParams.features, Features(init.remoteInit.features), Feature.Wumbo)) add(Feature.Wumbo)
                if (open.channelReserveSatoshis == 0.sat || accept.channelReserveSatoshis == 0.sat) add(Feature.ZeroReserveChannels)
                // NB: we currently force unconfirmed channels regardless of what our peer supports.
                // We should fix that once it is fully specified.
                if (init.localParams.features.hasFeature(Feature.ZeroConfChannels)) add(Feature.ZeroConfChannels)
            }
        )

        return Either.Right(channelFeatures)
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
    fun publishIfNeeded(txs: List<Transaction>, irrevocablySpent: Map<OutPoint, Transaction>, channelId: ByteVector32): List<ChannelAction.Blockchain.PublishTx> {
        val (skip, process) = txs.partition { it.inputsAlreadySpent(irrevocablySpent) }
        skip.forEach { tx -> logger.info { "c:$channelId no need to republish txid=${tx.txid}, it has already been confirmed" } }
        return process.map { tx ->
            logger.info { "c:$channelId publishing txid=${tx.txid}" }
            ChannelAction.Blockchain.PublishTx(tx)
        }
    }

    /** This helper method will watch txs only if they haven't yet reached minDepth. */
    fun watchConfirmedIfNeeded(txs: List<Transaction>, irrevocablySpent: Map<OutPoint, Transaction>, channelId: ByteVector32, minDepth: Long): List<ChannelAction.Blockchain.SendWatch> {
        val (skip, process) = txs.partition { it.inputsAlreadySpent(irrevocablySpent) }
        skip.forEach { tx -> logger.info { "c:$channelId no need to watch txid=${tx.txid}, it has already been confirmed" } }
        return process.map { tx -> ChannelAction.Blockchain.SendWatch(WatchConfirmed(channelId, tx, minDepth, BITCOIN_TX_CONFIRMED(tx))) }
    }

    /** This helper method will watch txs only if the utxo they spend hasn't already been irrevocably spent. */
    fun watchSpentIfNeeded(parentTx: Transaction, outputs: List<OutPoint>, irrevocablySpent: Map<OutPoint, Transaction>, channelId: ByteVector32): List<ChannelAction.Blockchain.SendWatch> {
        val (skip, process) = outputs.partition { irrevocablySpent.contains(it) }
        skip.forEach { output -> logger.info { "c:$channelId no need to watch output=${output.txid}:${output.index}, it has already been spent by txid=${irrevocablySpent[output]?.txid}" } }
        return process.map { output ->
            require(output.txid == parentTx.txid) { "output doesn't belong to the given parentTx: txid=${output.txid} but expected txid=${parentTx.txid}" }
            ChannelAction.Blockchain.SendWatch(WatchSpent(channelId, parentTx, output.index.toInt(), BITCOIN_OUTPUT_SPENT))
        }
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

            val fundingPubKey = localParams.channelKeys.fundingPubKey
            val commitmentInput = makeFundingInputInfo(fundingTxHash, fundingTxOutputIndex, fundingAmount, fundingPubKey, remoteParams.fundingPubKey)
            val localPerCommitmentPoint = keyManager.commitmentPoint(localParams.channelKeys.shaSeed, 0)
            val localCommitTx = Commitments.makeLocalTxs(0, localParams, remoteParams, commitmentInput, localPerCommitmentPoint, localSpec).first
            val remoteCommitTx = Commitments.makeRemoteTxs(0, localParams, remoteParams, commitmentInput, remoteFirstPerCommitmentPoint, remoteSpec).first

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

        // To be replaced with corresponding function in bitcoin-kmp
        fun btcAddressFromScriptPubKey(scriptPubKey: ByteVector, chainHash: ByteVector32): String? {
            return runTrying {
                val script = Script.parse(scriptPubKey)
                when {
                    Script.isPay2pkh(script) -> {
                        // OP_DUP OP_HASH160 OP_PUSHDATA(20) OP_EQUALVERIFY OP_CHECKSIG
                        val opPushData = script[2] as OP_PUSHDATA
                        val prefix = when (chainHash) {
                            Block.LivenetGenesisBlock.hash -> Base58.Prefix.PubkeyAddress
                            Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash -> Base58.Prefix.PubkeyAddressTestnet
                            else -> null
                        } ?: return null
                        Base58Check.encode(prefix, opPushData.data)
                    }
                    Script.isPay2sh(script) -> {
                        // OP_HASH160 OP_PUSHDATA(20) OP_EQUAL
                        val opPushData = script[1] as OP_PUSHDATA
                        val prefix = when (chainHash) {
                            Block.LivenetGenesisBlock.hash -> Base58.Prefix.ScriptAddress
                            Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash -> Base58.Prefix.ScriptAddressTestnet
                            else -> null
                        } ?: return null
                        Base58Check.encode(prefix, opPushData.data)
                    }
                    Script.isPay2wpkh(script) || Script.isPay2wsh(script) -> {
                        // isPay2wpkh : OP_0 OP_PUSHDATA(20)
                        // isPay2wsh  : OP_0 OP_PUSHDATA(32)
                        val opPushData = script[1] as OP_PUSHDATA
                        val hrp = when (chainHash) {
                            Block.LivenetGenesisBlock.hash -> "bc"
                            Block.TestnetGenesisBlock.hash -> "tb"
                            Block.RegtestGenesisBlock.hash -> "bcrt"
                            else -> null
                        } ?: return null
                        Bech32.encodeWitnessAddress(hrp, 0, opPushData.data.toByteArray())
                    }
                    else -> null
                } // </when>
            }.getOrElse { null }
        }

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
            val localClosingSig = keyManager.sign(closingTx, commitments.localParams.channelKeys.fundingPrivateKey)
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
        ): Either<ChannelException, ClosingTx> {
            val (closingTx, closingSigned) = makeClosingTx(keyManager, commitments, localScriptPubkey, remoteScriptPubkey, remoteClosingFee)
            val signedClosingTx = Transactions.addSigs(closingTx, commitments.localParams.channelKeys.fundingPubKey, commitments.remoteParams.fundingPubKey, closingSigned.signature, remoteClosingSig)
            return when (Transactions.checkSpendable(signedClosingTx)) {
                is Try.Success -> Either.Right(signedClosingTx)
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
            require(localCommit.publishableTxs.commitTx.tx.txid == tx.txid) { "txid mismatch, provided tx is not the current local commit tx" }
            val localPerCommitmentPoint = keyManager.commitmentPoint(commitments.localParams.channelKeys.shaSeed, commitments.localCommit.index)
            val localRevocationPubkey = Generators.revocationPubKey(commitments.remoteParams.revocationBasepoint, localPerCommitmentPoint)
            val localDelayedPubkey = Generators.derivePubKey(localParams.channelKeys.delayedPaymentBasepoint, localPerCommitmentPoint)
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
                val sig = keyManager.sign(it, localParams.channelKeys.delayedPaymentKey, localPerCommitmentPoint, SigHash.SIGHASH_ALL)
                Transactions.addSigs(it, sig)
            }

            // those are the preimages to existing received htlcs
            val preimages = commitments.localChanges.all.filterIsInstance<UpdateFulfillHtlc>().map { it.paymentPreimage }

            val htlcTxs = localCommit.publishableTxs.htlcTxsAndSigs.map { (txInfo, localSig, remoteSig) ->
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
            }.toMap()

            // all htlc output to us are delayed, so we need to claim them as soon as the delay is over
            val htlcDelayedTxs = htlcTxs.values.filterNotNull().mapNotNull { txInfo ->
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
                    val sig = keyManager.sign(it, localParams.channelKeys.delayedPaymentKey, localPerCommitmentPoint, SigHash.SIGHASH_ALL)
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
         * @param commitments our commitment data, which include payment preimages.
         * @param remoteCommit the remote commitment data to use to claim outputs (it can be their current or next commitment).
         * @param tx the remote commitment transaction that has just been published.
         * @return a list of transactions (one per output that we can claim).
         */
        fun claimRemoteCommitTxOutputs(keyManager: KeyManager, commitments: Commitments, remoteCommit: RemoteCommit, tx: Transaction, feerates: OnChainFeerates): RemoteCommitPublished {
            val localParams = commitments.localParams
            val remoteParams = commitments.remoteParams
            val commitInput = commitments.commitInput
            val (remoteCommitTx, _) = Commitments.makeRemoteTxs(
                remoteCommit.index,
                localParams,
                remoteParams,
                commitInput,
                remoteCommit.remotePerCommitmentPoint,
                remoteCommit.spec
            )
            require(remoteCommitTx.tx.txid == tx.txid) { "txid mismatch, provided tx is not the current remote commit tx" }

            val channelKeyPath = keyManager.channelKeyPath(localParams, commitments.channelConfig)
            val localPaymentPubkey = keyManager.paymentPoint(channelKeyPath).publicKey
            val localHtlcPubkey = Generators.derivePubKey(keyManager.htlcPoint(channelKeyPath).publicKey, remoteCommit.remotePerCommitmentPoint)
            val remoteDelayedPaymentPubkey = Generators.derivePubKey(remoteParams.delayedPaymentBasepoint, remoteCommit.remotePerCommitmentPoint)
            val remoteHtlcPubkey = Generators.derivePubKey(remoteParams.htlcBasepoint, remoteCommit.remotePerCommitmentPoint)
            val remoteRevocationPubkey = Generators.revocationPubKey(keyManager.revocationPoint(channelKeyPath).publicKey, remoteCommit.remotePerCommitmentPoint)
            val outputs = makeCommitTxOutputs(
                commitments.remoteParams.fundingPubKey,
                commitments.localParams.channelKeys.fundingPubKey,
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
                                    val sig = keyManager.sign(claimHtlcTx, localParams.channelKeys.htlcKey, remoteCommit.remotePerCommitmentPoint, SigHash.SIGHASH_ALL)
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
                            val sig = keyManager.sign(claimHtlcTx, localParams.channelKeys.htlcKey, remoteCommit.remotePerCommitmentPoint, SigHash.SIGHASH_ALL)
                            Pair(claimHtlcTx.input.outPoint, Transactions.addSigs(claimHtlcTx, sig))
                        }
                    }
                }
            }.toMap()

            // we claim our output and add the htlc txs we just created
            return claimRemoteCommitMainOutput(keyManager, commitments, tx, feerates.claimMainFeerate).copy(claimHtlcTxs = claimHtlcTxs)
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
            val localPaymentPoint = commitments.localParams.channelKeys.paymentBasepoint

            val mainTx = generateTx("claim-remote-delayed-output") {
                Transactions.makeClaimRemoteDelayedOutputTx(
                    tx,
                    commitments.localParams.dustLimit,
                    localPaymentPoint,
                    commitments.localParams.defaultFinalScriptPubKey,
                    claimMainFeerate
                )
            }?.let {
                val sig = keyManager.sign(it, commitments.localParams.channelKeys.paymentKey)
                Transactions.addSigs(it, sig)
            }

            return RemoteCommitPublished(commitTx = tx, claimMainOutputTx = mainTx)
        }

        /**
         * When an unexpected transaction spending the funding tx is detected, we can use our secrets to identify the commitment number.
         * This can then be used to find the necessary information to build penalty txs for every htlc output.
         */
        private fun extractTxNumber(keyManager: KeyManager, commitments: Commitments, tx: Transaction): Long {
            require(tx.txIn.size == 1) { "commitment tx should have 1 input" }
            val channelKeyPath = keyManager.channelKeyPath(commitments.localParams, commitments.channelConfig)
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

            val localPaymentPoint = commitments.localParams.channelKeys.paymentBasepoint
            val remotePerCommitmentSecret = PrivateKey.fromHex(hash.toHex())
            val remotePerCommitmentPoint = remotePerCommitmentSecret.publicKey()
            val remoteDelayedPaymentPubkey = Generators.derivePubKey(commitments.remoteParams.delayedPaymentBasepoint, remotePerCommitmentPoint)
            val remoteRevocationPubkey = Generators.revocationPubKey(commitments.localParams.channelKeys.revocationBasepoint, remotePerCommitmentPoint)

            val feerateMain = feerates.claimMainFeerate
            // we need to use a high fee here for punishment txs because after a delay they can be spent by the counterparty
            val feeratePenalty = feerates.fastFeerate

            // first we will claim our main output right away
            val mainTx = generateTx("claim-remote-delayed-output") {
                Transactions.makeClaimRemoteDelayedOutputTx(
                    tx,
                    commitments.localParams.dustLimit,
                    localPaymentPoint,
                    commitments.localParams.defaultFinalScriptPubKey,
                    feerateMain
                )
            }?.let {
                val sig = keyManager.sign(it, commitments.localParams.channelKeys.paymentKey)
                Transactions.addSigs(it, sig)
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
                val sig = keyManager.sign(it, commitments.localParams.channelKeys.revocationKey, remotePerCommitmentSecret)
                Transactions.addSigs(it, sig)
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
            val remotePerCommitmentPoint = revokedCommitPublished.remotePerCommitmentSecret.publicKey()
            val remoteRevocationPubkey = Generators.revocationPubKey(commitments.localParams.channelKeys.revocationBasepoint, remotePerCommitmentPoint)
            val remoteHtlcPubkey = Generators.derivePubKey(commitments.remoteParams.htlcBasepoint, remotePerCommitmentPoint)
            val localHtlcPubkey = Generators.derivePubKey(commitments.localParams.channelKeys.htlcBasepoint, remotePerCommitmentPoint)

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
                        val sig = keyManager.sign(htlcPenaltyTx, commitments.localParams.channelKeys.revocationKey, revokedCommitPublished.remotePerCommitmentSecret)
                        Transactions.addSigs(htlcPenaltyTx, sig, remoteRevocationPubkey)
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
        fun claimRevokedHtlcTxOutputs(
            keyManager: KeyManager,
            commitments: Commitments,
            revokedCommitPublished: RevokedCommitPublished,
            htlcTx: Transaction,
            feerates: OnChainFeerates
        ): Pair<RevokedCommitPublished, List<ClaimHtlcDelayedOutputPenaltyTx>> {
            val claimTxs = buildList {
                revokedCommitPublished.claimMainOutputTx?.let { add(it) }
                revokedCommitPublished.mainPenaltyTx?.let { add(it) }
                addAll(revokedCommitPublished.htlcPenaltyTxs)
            }
            val isHtlcTx = htlcTx.txIn.any { it.outPoint.txid == revokedCommitPublished.commitTx.txid } && !claimTxs.any { it.tx.txid == htlcTx.txid }
            if (isHtlcTx) {
                logger.info { "c:${commitments.channelId} looks like txid=${htlcTx.txid} could be a 2nd level htlc tx spending revoked commit txid=${revokedCommitPublished.commitTx.txid}" }
                // Let's assume that htlcTx is an HtlcSuccessTx or HtlcTimeoutTx and try to generate a tx spending its output using a revocation key
                val remotePerCommitmentPoint = revokedCommitPublished.remotePerCommitmentSecret.publicKey()
                val remoteDelayedPaymentPubkey = Generators.derivePubKey(commitments.remoteParams.delayedPaymentBasepoint, remotePerCommitmentPoint)
                val remoteRevocationPubkey = Generators.revocationPubKey(commitments.localParams.channelKeys.revocationBasepoint, remotePerCommitmentPoint)

                // we need to use a high fee here for punishment txs because after a delay they can be spent by the counterparty
                val feeratePenalty = feerates.fastFeerate

                val penaltyTxs = Transactions.makeClaimDelayedOutputPenaltyTxs(
                    htlcTx,
                    commitments.localParams.dustLimit,
                    remoteRevocationPubkey,
                    commitments.localParams.toSelfDelay,
                    remoteDelayedPaymentPubkey,
                    commitments.localParams.defaultFinalScriptPubKey.toByteArray(),
                    feeratePenalty
                ).mapNotNull { claimDelayedOutputPenaltyTx ->
                    generateTx("claim-htlc-delayed-penalty") {
                        claimDelayedOutputPenaltyTx
                    }?.let {
                        val sig = keyManager.sign(it, commitments.localParams.channelKeys.revocationKey, revokedCommitPublished.remotePerCommitmentSecret)
                        val signedTx = Transactions.addSigs(it, sig)
                        // we need to make sure that the tx is indeed valid
                        when (runTrying { Transaction.correctlySpends(signedTx.tx, listOf(htlcTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS) }) {
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
         * In CLOSING state, when we are notified that a transaction has been confirmed, we analyze it to find out if one or
         * more htlcs have timed out and need to be failed in an upstream channel.
         *
         * @param tx a tx that has reached min_depth
         * @return a set of htlcs that need to be failed upstream
         */
        fun LocalCommit.timedOutHtlcs(localCommitPublished: LocalCommitPublished, localDustLimit: Satoshi, tx: Transaction): Set<UpdateAddHtlc> {
            val untrimmedHtlcs = Transactions.trimOfferedHtlcs(localDustLimit, spec).map { it.add }
            return when {
                tx.txid == publishableTxs.commitTx.tx.txid -> {
                    // the tx is a commitment tx, we can immediately fail all dust htlcs (they don't have an output in the tx)
                    (spec.htlcs.outgoings() - untrimmedHtlcs).toSet()
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
        fun RemoteCommit.timedOutHtlcs(remoteCommitPublished: RemoteCommitPublished, remoteDustLimit: Satoshi, tx: Transaction): Set<UpdateAddHtlc> {
            val untrimmedHtlcs = Transactions.trimReceivedHtlcs(remoteDustLimit, spec).map { it.add }
            return when {
                tx.txid == txid -> {
                    // the tx is a commitment tx, we can immediately fail all dust htlcs (they don't have an output in the tx)
                    (spec.htlcs.incomings() - untrimmedHtlcs).toSet()
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
                // our commit got confirmed, so any htlc that is in their commitment but not in ours will never reach the chain
                val htlcsInRemoteCommit = remoteCommit.spec.htlcs + nextRemoteCommit?.spec?.htlcs.orEmpty()
                // NB: from the point of view of the remote, their incoming htlcs are our outgoing htlcs
                htlcsInRemoteCommit.incomings().toSet() - localCommit.spec.htlcs.outgoings().toSet()
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
        fun Transaction.inputsAlreadySpent(irrevocablySpent: Map<OutPoint, Transaction>): Boolean {
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
}
