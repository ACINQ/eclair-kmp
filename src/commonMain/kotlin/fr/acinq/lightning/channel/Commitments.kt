package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.Crypto.sha256
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Features
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.FeerateTolerance
import fr.acinq.lightning.crypto.Generators
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.crypto.ShaChain
import fr.acinq.lightning.payment.OutgoingPacket
import fr.acinq.lightning.transactions.CommitmentSpec
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.CommitTx
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.HtlcTx
import fr.acinq.lightning.transactions.Transactions.commitTxFee
import fr.acinq.lightning.transactions.Transactions.commitTxFeeMsat
import fr.acinq.lightning.transactions.Transactions.htlcOutputFee
import fr.acinq.lightning.transactions.Transactions.makeCommitTxOutputs
import fr.acinq.lightning.transactions.Transactions.offeredHtlcTrimThreshold
import fr.acinq.lightning.transactions.Transactions.receivedHtlcTrimThreshold
import fr.acinq.lightning.transactions.incomings
import fr.acinq.lightning.transactions.outgoings
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import org.kodein.log.Logger
import kotlin.math.min

// @formatter:off
data class LocalChanges(val proposed: List<UpdateMessage>, val signed: List<UpdateMessage>, val acked: List<UpdateMessage>) {
    val all: List<UpdateMessage> get() = proposed + signed + acked
}

data class RemoteChanges(val proposed: List<UpdateMessage>, val acked: List<UpdateMessage>, val signed: List<UpdateMessage>)
data class HtlcTxAndSigs(val txinfo: HtlcTx, val localSig: ByteVector64, val remoteSig: ByteVector64)
data class PublishableTxs(val commitTx: CommitTx, val htlcTxsAndSigs: List<HtlcTxAndSigs>)
data class LocalCommit(val index: Long, val spec: CommitmentSpec, val publishableTxs: PublishableTxs)
data class RemoteCommit(val index: Long, val spec: CommitmentSpec, val txid: ByteVector32, val remotePerCommitmentPoint: PublicKey)
data class WaitingForRevocation(val nextRemoteCommit: RemoteCommit, val sent: CommitSig, val sentAfterLocalCommitIndex: Long, val reSignAsap: Boolean = false)
// @formatter:on

/**
 * about remoteNextCommitInfo:
 * we either:
 * - have built and signed their next commit tx with their next revocation hash which can now be discarded
 * - have their next per-commitment point
 * So, when we've signed and sent a commit message and are waiting for their revocation message,
 * theirNextCommitInfo is their next commit tx. The rest of the time, it is their next per-commitment point
 */
data class Commitments(
    val channelConfig: ChannelConfig,
    val channelFeatures: ChannelFeatures,
    val localParams: LocalParams,
    val remoteParams: RemoteParams,
    val channelFlags: Byte,
    val localCommit: LocalCommit,
    val remoteCommit: RemoteCommit,
    val localChanges: LocalChanges,
    val remoteChanges: RemoteChanges,
    val localNextHtlcId: Long,
    val remoteNextHtlcId: Long,
    val payments: Map<Long, UUID>, // for outgoing htlcs, maps to paymentId
    val remoteNextCommitInfo: Either<WaitingForRevocation, PublicKey>,
    val commitInput: Transactions.InputInfo,
    val remotePerCommitmentSecrets: ShaChain,
    val channelId: ByteVector32,
    val remoteChannelData: EncryptedChannelData = EncryptedChannelData.empty
) {
    init {
        require(channelFeatures.channelType == ChannelType.SupportedChannelType.AnchorOutputs) { "invalid channel type: ${channelFeatures.channelType.name}" }
    }

    fun updateFeatures(localInit: Init, remoteInit: Init) = this.copy(
        localParams = localParams.copy(features = Features(localInit.features)),
        remoteParams = remoteParams.copy(features = Features(remoteInit.features))
    )

    fun hasNoPendingHtlcs(): Boolean = localCommit.spec.htlcs.isEmpty() && remoteCommit.spec.htlcs.isEmpty() && remoteNextCommitInfo.isRight

    fun hasNoPendingHtlcsOrFeeUpdate(): Boolean {
        val hasNoPendingFeeUpdate = (localChanges.signed + localChanges.acked + remoteChanges.signed + remoteChanges.acked).find { it is UpdateFee } == null
        return hasNoPendingHtlcs() && hasNoPendingFeeUpdate
    }

    /**
     * @return true if channel was never open, or got closed immediately, had never any htlcs and local never had a positive balance
     */
    fun nothingAtStake(): Boolean = localCommit.index == 0L &&
            localCommit.spec.toLocal == 0.msat &&
            remoteCommit.index == 0L &&
            remoteCommit.spec.toRemote == 0.msat &&
            remoteNextCommitInfo.isRight

    fun timedOutOutgoingHtlcs(blockHeight: Long): Set<UpdateAddHtlc> {
        fun expired(add: UpdateAddHtlc) = blockHeight >= add.cltvExpiry.toLong()

        val thisCommitAdds = localCommit.spec.htlcs.outgoings().filter(::expired).toSet() + remoteCommit.spec.htlcs.incomings().filter(::expired).toSet()
        return when (remoteNextCommitInfo) {
            is Either.Left -> thisCommitAdds + remoteNextCommitInfo.value.nextRemoteCommit.spec.htlcs.incomings().filter(::expired).toSet()
            is Either.Right -> thisCommitAdds
        }
    }

    /**
     * Incoming HTLCs that are close to timing out are potentially dangerous. If we released the pre-image for those
     * HTLCs, we need to get a remote signed updated commitment that removes this HTLC.
     * Otherwise when we get close to the timeout, we risk an on-chain race condition between their HTLC timeout
     * and our HTLC success in case of a force-close.
     */
    fun almostTimedOutIncomingHtlcs(blockHeight: Long, fulfillSafety: CltvExpiryDelta): Set<UpdateAddHtlc> {
        val relayedFulfills = localChanges.all.filterIsInstance<UpdateFulfillHtlc>().map { it.id }.toSet()
        return localCommit.spec.htlcs.incomings().filter { relayedFulfills.contains(it.id) && blockHeight >= (it.cltvExpiry - fulfillSafety).toLong() }.toSet()
    }

    private fun addLocalProposal(proposal: UpdateMessage): Commitments = copy(localChanges = localChanges.copy(proposed = localChanges.proposed + proposal))

    private fun addRemoteProposal(proposal: UpdateMessage): Commitments = copy(remoteChanges = remoteChanges.copy(proposed = remoteChanges.proposed + proposal))

    // NB: when computing availableBalanceForSend and availableBalanceForReceive, the funder keeps an extra buffer on top
    // of its usual channel reserve to avoid getting channels stuck in case the on-chain feerate increases (see
    // https://github.com/lightningnetwork/lightning-rfc/issues/728 for details).
    //
    // This extra buffer (which we call "funder fee buffer") is calculated as follows:
    //  1) Simulate a x2 feerate increase and compute the corresponding commit tx fee (note that it may trim some HTLCs)
    //  2) Add the cost of adding a new untrimmed HTLC at that increased feerate. This ensures that we'll be able to
    //     actually use the channel to add new HTLCs if the feerate doubles.
    //
    // If for example the current feerate is 1000 sat/kw, the dust limit 546 sat, and we have 3 pending outgoing HTLCs for
    // respectively 1250 sat, 2000 sat and 2500 sat.
    // commit tx fee = commitWeight * feerate + 3 * htlcOutputWeight * feerate = 724 * 1000 + 3 * 172 * 1000 = 1240 sat
    // To calculate the funder fee buffer, we first double the feerate and calculate the corresponding commit tx fee.
    // By doubling the feerate, the first HTLC becomes trimmed so the result is: 724 * 2000 + 2 * 172 * 2000 = 2136 sat
    // We then add the additional fee for a potential new untrimmed HTLC: 172 * 2000 = 344 sat
    // The funder fee buffer is 2136 + 344 = 2480 sat
    //
    // If there are many pending HTLCs that are only slightly above the trim threshold, the funder fee buffer may be
    // smaller than the current commit tx fee because those HTLCs will be trimmed and the commit tx weight will decrease.
    // For example if we have 10 outgoing HTLCs of 1250 sat:
    //  - commit tx fee = 724 * 1000 + 10 * 172 * 1000 = 2444 sat
    //  - commit tx fee at twice the feerate = 724 * 2000 = 1448 sat (all HTLCs have been trimmed)
    //  - cost of an additional untrimmed HTLC = 172 * 2000 = 344 sat
    //  - funder fee buffer = 1448 + 344 = 1792 sat
    // In that case the current commit tx fee is higher than the funder fee buffer and will dominate the balance restrictions.

    fun availableBalanceForSend(): MilliSatoshi {
        // we need to base the next current commitment on the last sig we sent, even if we didn't yet receive their revocation
        val remoteCommit1 = when (remoteNextCommitInfo) {
            is Either.Left -> remoteNextCommitInfo.value.nextRemoteCommit
            is Either.Right -> remoteCommit
        }
        val reduced = CommitmentSpec.reduce(remoteCommit1.spec, remoteChanges.acked, localChanges.proposed)
        val balanceNoFees = (reduced.toRemote - remoteParams.channelReserve.toMilliSatoshi()).coerceAtLeast(0.msat)
        return if (localParams.isFunder) {
            // The funder always pays the on-chain fees, so we must subtract that from the amount we can send.
            val commitFees = commitTxFeeMsat(remoteParams.dustLimit, reduced)
            // the funder needs to keep a "funder fee buffer" (see explanation above)
            val funderFeeBuffer = commitTxFeeMsat(remoteParams.dustLimit, reduced.copy(feerate = reduced.feerate * 2)) + htlcOutputFee(reduced.feerate * 2)
            val amountToReserve = commitFees.coerceAtLeast(funderFeeBuffer)
            if (balanceNoFees - amountToReserve < offeredHtlcTrimThreshold(remoteParams.dustLimit, reduced).toMilliSatoshi()) {
                // htlc will be trimmed
                (balanceNoFees - amountToReserve).coerceAtLeast(0.msat)
            } else {
                // htlc will have an output in the commitment tx, so there will be additional fees.
                val commitFees1 = commitFees + htlcOutputFee(reduced.feerate)
                // we take the additional fees for that htlc output into account in the fee buffer at a x2 feerate increase
                val funderFeeBuffer1 = funderFeeBuffer + htlcOutputFee(reduced.feerate * 2)
                val amountToReserve1 = commitFees1.coerceAtLeast(funderFeeBuffer1)
                (balanceNoFees - amountToReserve1).coerceAtLeast(0.msat)
            }
        } else {
            // The fundee doesn't pay on-chain fees.
            balanceNoFees
        }
    }

    fun availableBalanceForReceive(): MilliSatoshi {
        val reduced = CommitmentSpec.reduce(localCommit.spec, localChanges.acked, remoteChanges.proposed)
        val balanceNoFees = (reduced.toRemote - localParams.channelReserve.toMilliSatoshi()).coerceAtLeast(0.msat)
        return if (localParams.isFunder) {
            // The fundee doesn't pay on-chain fees so we don't take those into account when receiving.
            balanceNoFees
        } else {
            // The funder always pays the on-chain fees, so we must subtract that from the amount we can receive.
            val commitFees = commitTxFeeMsat(localParams.dustLimit, reduced)
            // we expected the funder to keep a "funder fee buffer" (see explanation above)
            val funderFeeBuffer = commitTxFeeMsat(localParams.dustLimit, reduced.copy(feerate = reduced.feerate * 2)) + htlcOutputFee(reduced.feerate * 2)
            val amountToReserve = commitFees.coerceAtLeast(funderFeeBuffer)
            if (balanceNoFees - amountToReserve < receivedHtlcTrimThreshold(localParams.dustLimit, reduced).toMilliSatoshi()) {
                // htlc will be trimmed
                (balanceNoFees - amountToReserve).coerceAtLeast(0.msat)
            } else {
                // htlc will have an output in the commitment tx, so there will be additional fees.
                val commitFees1 = commitFees + htlcOutputFee(reduced.feerate)
                // we take the additional fees for that htlc output into account in the fee buffer at a x2 feerate increase
                val funderFeeBuffer1 = funderFeeBuffer + htlcOutputFee(reduced.feerate * 2)
                val amountToReserve1 = commitFees1.coerceAtLeast(funderFeeBuffer1)
                (balanceNoFees - amountToReserve1).coerceAtLeast(0.msat)
            }
        }
    }

    fun isMoreRecent(other: Commitments): Boolean {
        return this.localCommit.index > other.localCommit.index ||
                this.remoteCommit.index > other.remoteCommit.index ||
                (this.remoteCommit.index == other.remoteCommit.index && this.remoteNextCommitInfo.isLeft && other.remoteNextCommitInfo.isRight)
    }

    /**
     * @param cmd add HTLC command
     * @param paymentId id of the payment
     * @param blockHeight current block height
     * @return either Failure(failureMessage) with a BOLT #4 failure or Success(new commitments, updateAddHtlc)
     */
    @OptIn(ExperimentalUnsignedTypes::class)
    fun sendAdd(cmd: CMD_ADD_HTLC, paymentId: UUID, blockHeight: Long): Either<ChannelException, Pair<Commitments, UpdateAddHtlc>> {
        val maxExpiry = Channel.MAX_CLTV_EXPIRY_DELTA.toCltvExpiry(blockHeight)
        // we don't want to use too high a refund timeout, because our funds will be locked during that time if the payment is never fulfilled
        if (cmd.cltvExpiry >= maxExpiry) {
            return Either.Left(ExpiryTooBig(channelId, maximum = maxExpiry, actual = cmd.cltvExpiry, blockCount = blockHeight))
        }

        // even if remote advertises support for 0 msat htlc, we limit ourselves to values strictly positive, hence the max(1 msat)
        val htlcMinimum = remoteParams.htlcMinimum.coerceAtLeast(1.msat)
        if (cmd.amount < htlcMinimum) {
            return Either.Left(HtlcValueTooSmall(channelId, minimum = htlcMinimum, actual = cmd.amount))
        }

        // let's compute the current commitment *as seen by them* with this change taken into account
        val add = UpdateAddHtlc(channelId, localNextHtlcId, cmd.amount, cmd.paymentHash, cmd.cltvExpiry, cmd.onion)
        // we increment the local htlc index and add an entry to the origins map
        val commitments1 = addLocalProposal(add).copy(localNextHtlcId = localNextHtlcId + 1, payments = payments + mapOf(add.id to paymentId))
        // we need to base the next current commitment on the last sig we sent, even if we didn't yet receive their revocation
        val remoteCommit1 = when (remoteNextCommitInfo) {
            is Either.Left -> remoteNextCommitInfo.value.nextRemoteCommit
            is Either.Right -> remoteCommit
        }
        val reduced = CommitmentSpec.reduce(remoteCommit1.spec, commitments1.remoteChanges.acked, commitments1.localChanges.proposed)
        // the HTLC we are about to create is outgoing, but from their point of view it is incoming
        val outgoingHtlcs = reduced.htlcs.incomings()

        // note that the funder pays the fee, so if sender != funder, both sides will have to afford this payment
        val fees = commitTxFee(commitments1.remoteParams.dustLimit, reduced)
        // the funder needs to keep an extra buffer to be able to handle a x2 feerate increase and an additional htlc to avoid
        // getting the channel stuck (see https://github.com/lightningnetwork/lightning-rfc/issues/728).
        val funderFeeBuffer = commitTxFeeMsat(commitments1.remoteParams.dustLimit, reduced.copy(feerate = reduced.feerate * 2)) + htlcOutputFee(reduced.feerate * 2)
        // NB: increasing the feerate can actually remove htlcs from the commit tx (if they fall below the trim threshold)
        // which may result in a lower commit tx fee; this is why we take the max of the two.
        val missingForSender = reduced.toRemote - commitments1.remoteParams.channelReserve.toMilliSatoshi() - (if (commitments1.localParams.isFunder) fees.toMilliSatoshi().coerceAtLeast(funderFeeBuffer) else 0.msat)
        val missingForReceiver = reduced.toLocal - commitments1.localParams.channelReserve.toMilliSatoshi() - (if (commitments1.localParams.isFunder) 0.msat else fees.toMilliSatoshi())
        if (missingForSender < 0.msat) {
            val actualFees = if (commitments1.localParams.isFunder) fees else 0.sat
            return Either.Left(InsufficientFunds(channelId, cmd.amount, -missingForSender.truncateToSatoshi(), commitments1.remoteParams.channelReserve, actualFees))
        } else if (missingForReceiver < 0.msat) {
            if (localParams.isFunder) {
                // receiver is fundee; it is ok if it can't maintain its channel_reserve for now, as long as its balance is increasing, which is the case if it is receiving a payment
            } else {
                return Either.Left(RemoteCannotAffordFeesForNewHtlc(channelId, amount = cmd.amount, missing = -missingForReceiver.truncateToSatoshi(), reserve = commitments1.remoteParams.channelReserve, fees = fees))
            }
        }

        // README: we check against our peer's max_htlc_value_in_flight_msat parameter, as per the BOLTS, but also against our own setting
        val htlcValueInFlight = outgoingHtlcs.map { it.amountMsat }.sum()
        val maxHtlcValueInFlightMsat = min(commitments1.remoteParams.maxHtlcValueInFlightMsat, commitments1.localParams.maxHtlcValueInFlightMsat)
        if (htlcValueInFlight.toLong() > maxHtlcValueInFlightMsat) {
            return Either.Left(HtlcValueTooHighInFlight(channelId, maximum = maxHtlcValueInFlightMsat.toULong(), actual = htlcValueInFlight))
        }

        if (outgoingHtlcs.size > commitments1.remoteParams.maxAcceptedHtlcs) {
            return Either.Left(TooManyAcceptedHtlcs(channelId, maximum = commitments1.remoteParams.maxAcceptedHtlcs.toLong()))
        }

        // README: this is not part of the LN Bolts: we also check against our own limit, to avoid creating commit txs that have too many outputs
        if (outgoingHtlcs.size > commitments1.localParams.maxAcceptedHtlcs) {
            return Either.Left(TooManyOfferedHtlcs(channelId, maximum = commitments1.localParams.maxAcceptedHtlcs.toLong()))
        }

        return Either.Right(Pair(commitments1, add))
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    fun receiveAdd(add: UpdateAddHtlc): Either<ChannelException, Commitments> {
        if (add.id != remoteNextHtlcId) {
            return Either.Left(UnexpectedHtlcId(channelId, expected = remoteNextHtlcId, actual = add.id))
        }

        // we used to not enforce a strictly positive minimum, hence the max(1 msat)
        val htlcMinimum = localParams.htlcMinimum.coerceAtLeast(1.msat)
        if (add.amountMsat < htlcMinimum) {
            return Either.Left(HtlcValueTooSmall(channelId, minimum = htlcMinimum, actual = add.amountMsat))
        }

        // let's compute the current commitment *as seen by us* including this change
        val commitments1 = addRemoteProposal(add).copy(remoteNextHtlcId = remoteNextHtlcId + 1)
        val reduced = CommitmentSpec.reduce(commitments1.localCommit.spec, commitments1.localChanges.acked, commitments1.remoteChanges.proposed)
        val incomingHtlcs = reduced.htlcs.incomings()

        // note that the funder pays the fee, so if sender != funder, both sides will have to afford this payment
        val fees = commitTxFee(commitments1.remoteParams.dustLimit, reduced)
        // NB: we don't enforce the funderFeeReserve (see sendAdd) because it would confuse a remote funder that doesn't have this mitigation in place
        // We could enforce it once we're confident a large portion of the network implements it.
        val missingForSender = reduced.toRemote - commitments1.localParams.channelReserve.toMilliSatoshi() - (if (commitments1.localParams.isFunder) 0.sat else fees).toMilliSatoshi()
        val missingForReceiver = reduced.toLocal - commitments1.remoteParams.channelReserve.toMilliSatoshi() - (if (commitments1.localParams.isFunder) fees else 0.sat).toMilliSatoshi()
        if (missingForSender < 0.sat) {
            val actualFees = if (commitments1.localParams.isFunder) 0.sat else fees
            return Either.Left(InsufficientFunds(channelId, add.amountMsat, -missingForSender.truncateToSatoshi(), commitments1.localParams.channelReserve, actualFees))
        } else if (missingForReceiver < 0.sat) {
            @Suppress("ControlFlowWithEmptyBody")
            if (localParams.isFunder) {
                return Either.Left(CannotAffordFees(channelId, missing = -missingForReceiver.truncateToSatoshi(), reserve = commitments1.remoteParams.channelReserve, fees = fees))
            } else {
                // receiver is fundee; it is ok if it can't maintain its channel_reserve for now, as long as its balance is increasing, which is the case if it is receiving a payment
            }
        }

        val htlcValueInFlight = incomingHtlcs.map { it.amountMsat }.sum()
        if (commitments1.localParams.maxHtlcValueInFlightMsat < htlcValueInFlight.toLong()) {
            return Either.Left(HtlcValueTooHighInFlight(channelId, maximum = commitments1.localParams.maxHtlcValueInFlightMsat.toULong(), actual = htlcValueInFlight))
        }

        if (incomingHtlcs.size > commitments1.localParams.maxAcceptedHtlcs) {
            return Either.Left(TooManyAcceptedHtlcs(channelId, maximum = commitments1.localParams.maxAcceptedHtlcs.toLong()))
        }

        return Either.Right(commitments1)
    }

    private fun getOutgoingHtlcCrossSigned(htlcId: Long): UpdateAddHtlc? {
        val localSigned = (remoteNextCommitInfo.left?.nextRemoteCommit ?: remoteCommit).spec.findIncomingHtlcById(htlcId) ?: return null
        val remoteSigned = localCommit.spec.findOutgoingHtlcById(htlcId) ?: return null
        require(localSigned.add == remoteSigned.add)
        return localSigned.add
    }

    private fun getIncomingHtlcCrossSigned(htlcId: Long): UpdateAddHtlc? {
        val localSigned = (remoteNextCommitInfo.left?.nextRemoteCommit ?: remoteCommit).spec.findOutgoingHtlcById(htlcId) ?: return null
        val remoteSigned = localCommit.spec.findIncomingHtlcById(htlcId) ?: return null
        require(localSigned.add == remoteSigned.add)
        return localSigned.add
    }

    fun sendFulfill(cmd: CMD_FULFILL_HTLC): Either<ChannelException, Pair<Commitments, UpdateFulfillHtlc>> {
        val htlc = getIncomingHtlcCrossSigned(cmd.id) ?: return Either.Left(UnknownHtlcId(channelId, cmd.id))
        return when {
            // we have already sent a fail/fulfill for this htlc
            alreadyProposed(localChanges.proposed, htlc.id) -> Either.Left(UnknownHtlcId(channelId, cmd.id))
            htlc.paymentHash.contentEquals(sha256(cmd.r)) -> {
                val fulfill = UpdateFulfillHtlc(channelId, cmd.id, cmd.r)
                val commitments1 = addLocalProposal(fulfill)
                Either.Right(Pair(commitments1, fulfill))
            }
            else -> Either.Left(InvalidHtlcPreimage(channelId, cmd.id))
        }
    }

    fun receiveFulfill(fulfill: UpdateFulfillHtlc): Either<ChannelException, Triple<Commitments, UUID, UpdateAddHtlc>> {
        val htlc = getOutgoingHtlcCrossSigned(fulfill.id) ?: return Either.Left(UnknownHtlcId(channelId, fulfill.id))
        val paymentId = payments[fulfill.id] ?: return Either.Left(UnknownHtlcId(channelId, fulfill.id))
        return when {
            htlc.paymentHash.contentEquals(sha256(fulfill.paymentPreimage)) -> Either.Right(Triple(addRemoteProposal(fulfill), paymentId, htlc))
            else -> Either.Left(InvalidHtlcPreimage(channelId, fulfill.id))
        }
    }

    fun sendFail(cmd: CMD_FAIL_HTLC, nodeSecret: PrivateKey): Either<ChannelException, Pair<Commitments, UpdateFailHtlc>> {
        val htlc = getIncomingHtlcCrossSigned(cmd.id) ?: return Either.Left(UnknownHtlcId(channelId, cmd.id))
        return when {
            // we have already sent a fail/fulfill for this htlc
            alreadyProposed(localChanges.proposed, htlc.id) -> Either.Left(UnknownHtlcId(channelId, cmd.id))
            else -> {
                when (val result = OutgoingPacket.buildHtlcFailure(nodeSecret, htlc.paymentHash, htlc.onionRoutingPacket, cmd.reason)) {
                    is Either.Right -> {
                        val fail = UpdateFailHtlc(channelId, cmd.id, result.value)
                        val commitments1 = addLocalProposal(fail)
                        Either.Right(Pair(commitments1, fail))
                    }
                    is Either.Left -> Either.Left(CannotExtractSharedSecret(channelId, htlc))
                }
            }
        }
    }

    fun sendFailMalformed(cmd: CMD_FAIL_MALFORMED_HTLC): Either<ChannelException, Pair<Commitments, UpdateFailMalformedHtlc>> {
        // BADONION bit must be set in failure_code
        if ((cmd.failureCode and FailureMessage.BADONION) == 0) return Either.Left(InvalidFailureCode(channelId))
        val htlc = getIncomingHtlcCrossSigned(cmd.id) ?: return Either.Left(UnknownHtlcId(channelId, cmd.id))
        return when {
            // we have already sent a fail/fulfill for this htlc
            alreadyProposed(localChanges.proposed, htlc.id) -> Either.Left(UnknownHtlcId(channelId, cmd.id))
            else -> {
                val fail = UpdateFailMalformedHtlc(channelId, cmd.id, cmd.onionHash, cmd.failureCode)
                val commitments1 = addLocalProposal(fail)
                Either.Right(Pair(commitments1, fail))
            }
        }
    }

    fun receiveFail(fail: UpdateFailHtlc): Either<ChannelException, Triple<Commitments, UUID, UpdateAddHtlc>> {
        val htlc = getOutgoingHtlcCrossSigned(fail.id) ?: return Either.Left(UnknownHtlcId(channelId, fail.id))
        val paymentId = payments[fail.id] ?: return Either.Left(UnknownHtlcId(channelId, fail.id))
        return Either.Right(Triple(addRemoteProposal(fail), paymentId, htlc))
    }

    fun receiveFailMalformed(fail: UpdateFailMalformedHtlc): Either<ChannelException, Triple<Commitments, UUID, UpdateAddHtlc>> {
        // A receiving node MUST fail the channel if the BADONION bit in failure_code is not set for update_fail_malformed_htlc.
        if ((fail.failureCode and FailureMessage.BADONION) == 0) return Either.Left(InvalidFailureCode(channelId))
        val htlc = getOutgoingHtlcCrossSigned(fail.id) ?: return Either.Left(UnknownHtlcId(channelId, fail.id))
        val paymentId = payments[fail.id] ?: return Either.Left(UnknownHtlcId(channelId, fail.id))
        return Either.Right(Triple(addRemoteProposal(fail), paymentId, htlc))
    }

    fun sendFee(cmd: CMD_UPDATE_FEE): Either<ChannelException, Pair<Commitments, UpdateFee>> {
        if (!localParams.isFunder) return Either.Left(FundeeCannotSendUpdateFee(channelId))
        // let's compute the current commitment *as seen by them* with this change taken into account
        val fee = UpdateFee(channelId, cmd.feerate)
        // update_fee replace each other, so we can remove previous ones
        val commitments1 = copy(localChanges = localChanges.copy(proposed = localChanges.proposed.filterNot { it is UpdateFee } + fee))
        val reduced = CommitmentSpec.reduce(commitments1.remoteCommit.spec, commitments1.remoteChanges.acked, commitments1.localChanges.proposed)

        // a node cannot spend pending incoming htlcs, and need to keep funds above the reserve required by the counterparty, after paying the fee
        // we look from remote's point of view, so if local is funder remote doesn't pay the fees
        val fees = commitTxFee(commitments1.remoteParams.dustLimit, reduced)
        val missing = reduced.toRemote.truncateToSatoshi() - commitments1.remoteParams.channelReserve - fees
        if (missing < 0.sat) return Either.Left(CannotAffordFees(channelId, -missing, commitments1.localParams.channelReserve, fees))
        return Either.Right(Pair(commitments1, fee))
    }

    fun receiveFee(fee: UpdateFee, feerateTolerance: FeerateTolerance): Either<ChannelException, Commitments> {
        if (localParams.isFunder) return Either.Left(FundeeCannotSendUpdateFee(channelId))
        if (fee.feeratePerKw < FeeratePerKw.MinimumFeeratePerKw) return Either.Left(FeerateTooSmall(channelId, remoteFeeratePerKw = fee.feeratePerKw))
        if (Helpers.isFeeDiffTooHigh(FeeratePerKw.CommitmentFeerate, fee.feeratePerKw, feerateTolerance)) return Either.Left(FeerateTooDifferent(channelId, FeeratePerKw.CommitmentFeerate, fee.feeratePerKw))
        // NB: we check that the funder can afford this new fee even if spec allows to do it at next signature
        // It is easier to do it here because under certain (race) conditions spec allows a lower-than-normal fee to be paid,
        // and it would be tricky to check if the conditions are met at signing
        // (it also means that we need to check the fee of the initial commitment tx somewhere)

        // let's compute the current commitment *as seen by us* including this change
        // update_fee replace each other, so we can remove previous ones
        val commitments1 = copy(remoteChanges = remoteChanges.copy(proposed = remoteChanges.proposed.filterNot { it is UpdateFee } + fee))
        val reduced = CommitmentSpec.reduce(commitments1.localCommit.spec, commitments1.localChanges.acked, commitments1.remoteChanges.proposed)

        // a node cannot spend pending incoming htlcs, and need to keep funds above the reserve required by the counterparty, after paying the fee
        val fees = commitTxFee(commitments1.remoteParams.dustLimit, reduced)
        val missing = reduced.toRemote.truncateToSatoshi() - commitments1.localParams.channelReserve - fees
        if (missing < 0.sat) return Either.Left(CannotAffordFees(channelId, -missing, commitments1.localParams.channelReserve, fees))
        return Either.Right(commitments1)
    }

    fun localHasUnsignedOutgoingHtlcs(): Boolean = localChanges.proposed.find { it is UpdateAddHtlc } != null

    fun remoteHasUnsignedOutgoingHtlcs(): Boolean = remoteChanges.proposed.find { it is UpdateAddHtlc } != null

    fun localHasUnsignedOutgoingUpdateFee(): Boolean = localChanges.proposed.find { it is UpdateFee } != null

    fun remoteHasUnsignedOutgoingUpdateFee(): Boolean = remoteChanges.proposed.find { it is UpdateFee } != null

    fun localHasChanges(): Boolean = remoteChanges.acked.isNotEmpty() || localChanges.proposed.isNotEmpty()

    fun remoteHasChanges(): Boolean = localChanges.acked.isNotEmpty() || remoteChanges.proposed.isNotEmpty()

    fun sendCommit(keyManager: KeyManager, log: Logger): Either<ChannelException, Pair<Commitments, CommitSig>> {
        val remoteNextPerCommitmentPoint = remoteNextCommitInfo.right ?: return Either.Left(CannotSignBeforeRevocation(channelId))
        if (!localHasChanges()) return Either.Left(CannotSignWithoutChanges(channelId))

        // remote commitment will include all local changes + remote acked changes
        val spec = CommitmentSpec.reduce(remoteCommit.spec, remoteChanges.acked, localChanges.proposed)
        val (remoteCommitTx, htlcTxs) = makeRemoteTxs(remoteCommit.index + 1, localParams, remoteParams, commitInput, remoteNextPerCommitmentPoint, spec)
        val sig = keyManager.sign(remoteCommitTx, localParams.channelKeys.fundingPrivateKey)

        val sortedHtlcTxs: List<HtlcTx> = htlcTxs.sortedBy { it.input.outPoint.index }
        // we sign our peer's HTLC txs with SIGHASH_SINGLE || SIGHASH_ANYONECANPAY
        val htlcSigs = sortedHtlcTxs.map { keyManager.sign(it, localParams.channelKeys.htlcKey, remoteNextPerCommitmentPoint, SigHash.SIGHASH_SINGLE or SigHash.SIGHASH_ANYONECANPAY) }

        // NB: IN/OUT htlcs are inverted because this is the remote commit
        log.info {
            val htlcsIn = spec.htlcs.outgoings().map { it.id }.joinToString(",")
            val htlcsOut = spec.htlcs.incomings().map { it.id }.joinToString(",")
            "c:$channelId built remote commit number=${remoteCommit.index + 1} toLocalMsat=${spec.toLocal.toLong()} toRemoteMsat=${spec.toRemote.toLong()} htlc_in=$htlcsIn htlc_out=$htlcsOut feeratePerKw=${spec.feerate} txid=${remoteCommitTx.tx.txid} tx=${remoteCommitTx.tx}"
        }

        val commitSig = CommitSig(channelId, sig, htlcSigs.toList())
        val commitments1 = copy(
            remoteNextCommitInfo = Either.Left(WaitingForRevocation(RemoteCommit(remoteCommit.index + 1, spec, remoteCommitTx.tx.txid, remoteNextPerCommitmentPoint), commitSig, localCommit.index)),
            localChanges = localChanges.copy(proposed = emptyList(), signed = localChanges.proposed),
            remoteChanges = remoteChanges.copy(acked = emptyList(), signed = remoteChanges.acked)
        )
        return Either.Right(Pair(commitments1, commitSig))
    }

    fun receiveCommit(commit: CommitSig, keyManager: KeyManager, log: Logger): Either<ChannelException, Pair<Commitments, RevokeAndAck>> {
        // they sent us a signature for *their* view of *our* next commit tx
        // so in terms of rev.hashes and indexes we have:
        // ourCommit.index -> our current revocation hash, which is about to become our old revocation hash
        // ourCommit.index + 1 -> our next revocation hash, used by *them* to build the sig we've just received, and which
        // is about to become our current revocation hash
        // ourCommit.index + 2 -> which is about to become our next revocation hash
        // we will reply to this sig with our old revocation hash preimage (at index) and our next revocation hash (at index + 1)
        // and will increment our index

        // lnd sometimes sends a new signature without any changes, which is a (harmless) spec violation
        if (!remoteHasChanges()) {
            //  return Either.Left(CannotSignWithoutChanges(commitments.channelId))
            log.warning { "c:$channelId received a commit sig with no changes (probably coming from lnd)" }
        }

        // check that their signature is valid
        // signatures are now optional in the commit message, and will be sent only if the other party is actually
        // receiving money i.e its commit tx has one output for them

        val spec = CommitmentSpec.reduce(localCommit.spec, localChanges.acked, remoteChanges.proposed)
        val localPerCommitmentPoint = keyManager.commitmentPoint(localParams.channelKeys.shaSeed, localCommit.index + 1)
        val (localCommitTx, htlcTxs) = makeLocalTxs(localCommit.index + 1, localParams, remoteParams, commitInput, localPerCommitmentPoint, spec)
        val sig = Transactions.sign(localCommitTx, localParams.channelKeys.fundingPrivateKey)

        log.info {
            val htlcsIn = spec.htlcs.incomings().map { it.id }.joinToString(",")
            val htlcsOut = spec.htlcs.outgoings().map { it.id }.joinToString(",")
            "c:$channelId built local commit number=${localCommit.index + 1} toLocalMsat=${spec.toLocal.toLong()} toRemoteMsat=${spec.toRemote.toLong()} htlc_in=$htlcsIn htlc_out=$htlcsOut feeratePerKw=${spec.feerate} txid=${localCommitTx.tx.txid} tx=${localCommitTx.tx}"
        }

        // no need to compute htlc sigs if commit sig doesn't check out
        val signedCommitTx = Transactions.addSigs(localCommitTx, localParams.channelKeys.fundingPubKey, remoteParams.fundingPubKey, sig, commit.signature)
        when (val check = Transactions.checkSpendable(signedCommitTx)) {
            is Try.Failure -> {
                log.error(check.error) { "c:$channelId remote signature $commit is invalid" }
                return Either.Left(InvalidCommitmentSignature(channelId, signedCommitTx.tx))
            }
        }

        val sortedHtlcTxs: List<HtlcTx> = htlcTxs.sortedBy { it.input.outPoint.index }
        if (commit.htlcSignatures.size != sortedHtlcTxs.size) {
            return Either.Left(HtlcSigCountMismatch(channelId, sortedHtlcTxs.size, commit.htlcSignatures.size))
        }
        val htlcSigs = sortedHtlcTxs.map { keyManager.sign(it, localParams.channelKeys.htlcKey, localPerCommitmentPoint, SigHash.SIGHASH_ALL) }
        val remoteHtlcPubkey = Generators.derivePubKey(remoteParams.htlcBasepoint, localPerCommitmentPoint)
        // combine the sigs to make signed txs
        val htlcTxsAndSigs = Triple(sortedHtlcTxs, htlcSigs, commit.htlcSignatures).zipped().map { (htlcTx, localSig, remoteSig) ->
            when (htlcTx) {
                is HtlcTx.HtlcTimeoutTx -> {
                    if (Transactions.checkSpendable(Transactions.addSigs(htlcTx, localSig, remoteSig)).isFailure) {
                        return Either.Left(InvalidHtlcSignature(channelId, htlcTx.tx))
                    }
                    HtlcTxAndSigs(htlcTx, localSig, remoteSig)
                }
                is HtlcTx.HtlcSuccessTx -> {
                    // we can't check that htlc-success tx are spendable because we need the payment preimage; thus we only check the remote sig
                    // which was created with SIGHASH_SINGLE || SIGHASH_ANYONECANPAY
                    if (!Transactions.checkSig(htlcTx, remoteSig, remoteHtlcPubkey, SigHash.SIGHASH_SINGLE or SigHash.SIGHASH_ANYONECANPAY)) {
                        return Either.Left(InvalidHtlcSignature(channelId, htlcTx.tx))
                    }
                    HtlcTxAndSigs(htlcTx, localSig, remoteSig)
                }
            }
        }

        // we will send our revocation preimage + our next revocation hash
        val localPerCommitmentSecret = keyManager.commitmentSecret(localParams.channelKeys.shaSeed, localCommit.index)
        val localNextPerCommitmentPoint = keyManager.commitmentPoint(localParams.channelKeys.shaSeed, localCommit.index + 2)
        val revocation = RevokeAndAck(channelId, localPerCommitmentSecret, localNextPerCommitmentPoint)

        // update our commitment data
        val localCommit1 = LocalCommit(localCommit.index + 1, spec, PublishableTxs(signedCommitTx, htlcTxsAndSigs))
        val ourChanges1 = localChanges.copy(acked = emptyList())
        val theirChanges1 = remoteChanges.copy(proposed = emptyList(), acked = remoteChanges.acked + remoteChanges.proposed)
        val commitments1 = copy(localCommit = localCommit1, localChanges = ourChanges1, remoteChanges = theirChanges1)

        return Either.Right(Pair(commitments1, revocation))
    }

    fun receiveRevocation(revocation: RevokeAndAck): Either<ChannelException, Pair<Commitments, List<ChannelAction>>> {
        val theirNextCommit = remoteNextCommitInfo.left?.nextRemoteCommit ?: return Either.Left(UnexpectedRevocation(channelId))
        if (revocation.perCommitmentSecret.publicKey() != remoteCommit.remotePerCommitmentPoint) return Either.Left(InvalidRevocation(channelId))

        // the outgoing following htlcs have been completed (fulfilled or failed) when we received this revocation
        // they have been removed from both local and remote commitment
        // (since fulfill/fail are sent by remote, they are (1) signed by them, (2) revoked by us, (3) signed by us, (4) revoked by them
        val completedOutgoingHtlcs = remoteCommit.spec.htlcs.incomings().map { it.id } - theirNextCommit.spec.htlcs.incomings().map { it.id }
        // we remove the newly completed htlcs from the payments map
        val payments1 = payments - completedOutgoingHtlcs
        val actions = mutableListOf<ChannelAction>()
        remoteChanges.signed.forEach {
            when (it) {
                is UpdateAddHtlc -> actions += ChannelAction.ProcessIncomingHtlc(it)
                is UpdateFailHtlc -> {
                    val paymentId = payments[it.id]
                    val add = remoteCommit.spec.findIncomingHtlcById(it.id)?.add
                    if (paymentId != null && add != null) {
                        actions += ChannelAction.ProcessCmdRes.AddSettledFail(paymentId, add, ChannelAction.HtlcResult.Fail.RemoteFail(it))
                    }
                }
                is UpdateFailMalformedHtlc -> {
                    val paymentId = payments[it.id]
                    val add = remoteCommit.spec.findIncomingHtlcById(it.id)?.add
                    if (paymentId != null && add != null) {
                        actions += ChannelAction.ProcessCmdRes.AddSettledFail(paymentId, add, ChannelAction.HtlcResult.Fail.RemoteFailMalformed(it))
                    }
                }
                else -> Unit
            }
        }
        val commitments1 = this.copy(
            localChanges = localChanges.copy(signed = emptyList(), acked = localChanges.acked + localChanges.signed),
            remoteChanges = remoteChanges.copy(signed = emptyList()),
            remoteCommit = theirNextCommit,
            remoteNextCommitInfo = Either.Right(revocation.nextPerCommitmentPoint),
            remotePerCommitmentSecrets = remotePerCommitmentSecrets.addHash(revocation.perCommitmentSecret.value, 0xFFFFFFFFFFFFL - remoteCommit.index),
            payments = payments1
        )
        return Either.Right(Pair(commitments1, actions.toList()))
    }

    companion object {

        val ANCHOR_AMOUNT = 330.sat
        const val COMMIT_WEIGHT = 1124
        const val HTLC_OUTPUT_WEIGHT = 172
        const val HTLC_TIMEOUT_WEIGHT = 666
        const val HTLC_SUCCESS_WEIGHT = 706

        fun alreadyProposed(changes: List<UpdateMessage>, id: Long): Boolean = changes.any {
            when (it) {
                is UpdateFulfillHtlc -> id == it.id
                is UpdateFailHtlc -> id == it.id
                is UpdateFailMalformedHtlc -> id == it.id
                else -> false
            }
        }

        fun makeLocalTxs(
            commitTxNumber: Long,
            localParams: LocalParams,
            remoteParams: RemoteParams,
            commitmentInput: Transactions.InputInfo,
            localPerCommitmentPoint: PublicKey,
            spec: CommitmentSpec
        ): Pair<CommitTx, List<HtlcTx>> {
            val localDelayedPaymentPubkey = Generators.derivePubKey(localParams.channelKeys.delayedPaymentBasepoint, localPerCommitmentPoint)
            val localHtlcPubkey = Generators.derivePubKey(localParams.channelKeys.htlcBasepoint, localPerCommitmentPoint)
            val remotePaymentPubkey = remoteParams.paymentBasepoint
            val remoteHtlcPubkey = Generators.derivePubKey(remoteParams.htlcBasepoint, localPerCommitmentPoint)
            val localRevocationPubkey = Generators.revocationPubKey(remoteParams.revocationBasepoint, localPerCommitmentPoint)
            val localPaymentBasepoint = localParams.channelKeys.paymentBasepoint
            val outputs = makeCommitTxOutputs(
                localParams.channelKeys.fundingPubKey,
                remoteParams.fundingPubKey,
                localParams.isFunder,
                localParams.dustLimit,
                localRevocationPubkey,
                remoteParams.toSelfDelay,
                localDelayedPaymentPubkey,
                remotePaymentPubkey,
                localHtlcPubkey,
                remoteHtlcPubkey,
                spec
            )
            val commitTx = Transactions.makeCommitTx(commitmentInput, commitTxNumber, localPaymentBasepoint, remoteParams.paymentBasepoint, localParams.isFunder, outputs)
            val htlcTxs = Transactions.makeHtlcTxs(commitTx.tx, localParams.dustLimit, localRevocationPubkey, remoteParams.toSelfDelay, localDelayedPaymentPubkey, spec.feerate, outputs)
            return Pair(commitTx, htlcTxs)
        }

        fun makeRemoteTxs(
            commitTxNumber: Long, localParams: LocalParams,
            remoteParams: RemoteParams, commitmentInput: Transactions.InputInfo,
            remotePerCommitmentPoint: PublicKey,
            spec: CommitmentSpec
        ): Pair<CommitTx, List<HtlcTx>> {
            val localPaymentPubkey = localParams.channelKeys.paymentBasepoint
            val localHtlcPubkey = Generators.derivePubKey(localParams.channelKeys.htlcBasepoint, remotePerCommitmentPoint)
            val remoteDelayedPaymentPubkey = Generators.derivePubKey(remoteParams.delayedPaymentBasepoint, remotePerCommitmentPoint)
            val remoteHtlcPubkey = Generators.derivePubKey(remoteParams.htlcBasepoint, remotePerCommitmentPoint)
            val remoteRevocationPubkey = Generators.revocationPubKey(localParams.channelKeys.revocationBasepoint, remotePerCommitmentPoint)
            val outputs = makeCommitTxOutputs(
                remoteParams.fundingPubKey,
                localParams.channelKeys.fundingPubKey,
                !localParams.isFunder,
                remoteParams.dustLimit,
                remoteRevocationPubkey,
                localParams.toSelfDelay,
                remoteDelayedPaymentPubkey,
                localPaymentPubkey,
                remoteHtlcPubkey,
                localHtlcPubkey,
                spec
            )
            // NB: we are creating the remote commit tx, so local/remote parameters are inverted.
            val commitTx = Transactions.makeCommitTx(commitmentInput, commitTxNumber, remoteParams.paymentBasepoint, localPaymentPubkey, !localParams.isFunder, outputs)
            val htlcTxs = Transactions.makeHtlcTxs(commitTx.tx, remoteParams.dustLimit, remoteRevocationPubkey, localParams.toSelfDelay, remoteDelayedPaymentPubkey, spec.feerate, outputs)
            return Pair(commitTx, htlcTxs)
        }
    }
}
