package fr.acinq.lightning.channel

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.Satoshi
import fr.acinq.bitcoin.Transaction
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.wire.AnnouncementSignatures
import fr.acinq.lightning.wire.UpdateAddHtlc

open class ChannelException(open val channelId: ByteVector32, override val message: String) : RuntimeException(message) {
    fun details(): String = "$channelId: $message"
}

// @formatter:off
data class DebugTriggeredException                 (override val channelId: ByteVector32) : ChannelException(channelId, "debug-mode triggered failure")
data class InvalidChainHash                        (override val channelId: ByteVector32, val local: ByteVector32, val remote: ByteVector32) : ChannelException(channelId, "invalid chainHash (local=$local remote=$remote)")
data class InvalidFundingAmount                    (override val channelId: ByteVector32, val fundingAmount: Satoshi, val min: Satoshi, val max: Satoshi) : ChannelException(channelId, "invalid funding_satoshis=$fundingAmount (min=$min max=$max)")
data class InvalidPushAmount                       (override val channelId: ByteVector32, val pushAmount: MilliSatoshi, val max: MilliSatoshi) : ChannelException(channelId, "invalid pushAmount=$pushAmount (max=$max)")
data class InvalidMaxAcceptedHtlcs                 (override val channelId: ByteVector32, val maxAcceptedHtlcs: Int, val max: Int) : ChannelException(channelId, "invalid max_accepted_htlcs=$maxAcceptedHtlcs (max=$max)")
data class InvalidChannelType                      (override val channelId: ByteVector32, val ourChannelType: ChannelType, val theirChannelType: ChannelType) : ChannelException(channelId, "invalid channel_type=${theirChannelType.name}, expected channel_type=${ourChannelType.name}")
data class MissingChannelType                      (override val channelId: ByteVector32, val expected: ChannelType) : ChannelException(channelId, "missing channel_type, expected channel_type=${expected.name}")
data class DustLimitTooSmall                       (override val channelId: ByteVector32, val dustLimit: Satoshi, val min: Satoshi) : ChannelException(channelId, "dustLimit=$dustLimit is too small (min=$min)")
data class DustLimitTooLarge                       (override val channelId: ByteVector32, val dustLimit: Satoshi, val max: Satoshi) : ChannelException(channelId, "dustLimit=$dustLimit is too large (max=$max)")
data class DustLimitAboveOurChannelReserve         (override val channelId: ByteVector32, val dustLimit: Satoshi, val channelReserve: Satoshi) : ChannelException(channelId, "dustLimit=$dustLimit is above our channelReserve=$channelReserve")
data class ToSelfDelayTooHigh                      (override val channelId: ByteVector32, val toSelfDelay: CltvExpiryDelta, val max: CltvExpiryDelta) : ChannelException(channelId, "unreasonable to_self_delay=$toSelfDelay (max=$max)")
data class ChannelReserveTooHigh                   (override val channelId: ByteVector32, val channelReserve: Satoshi, val reserveToFundingRatio: Double, val maxReserveToFundingRatio: Double) : ChannelException(channelId, "channelReserve too high: reserve=$channelReserve fundingRatio=$reserveToFundingRatio maxFundingRatio=$maxReserveToFundingRatio")
data class ChannelReserveBelowOurDustLimit         (override val channelId: ByteVector32, val channelReserve: Satoshi, val dustLimit: Satoshi) : ChannelException(channelId, "their channelReserve=$channelReserve is below our dustLimit=$dustLimit")
data class ChannelReserveNotMet                    (override val channelId: ByteVector32, val toLocal: MilliSatoshi, val toRemote: MilliSatoshi, val reserve: Satoshi) : ChannelException(channelId, "channel reserve is not met toLocal=$toLocal toRemote=$toRemote reserve=$reserve")
data class ChannelFundingError                     (override val channelId: ByteVector32) : ChannelException(channelId, "channel funding error")
data class NoMoreHtlcsClosingInProgress            (override val channelId: ByteVector32) : ChannelException(channelId, "cannot send new htlcs, closing in progress")
data class NoMoreFeeUpdateClosingInProgress        (override val channelId: ByteVector32) : ChannelException(channelId, "cannot send new update_fee, closing in progress")
data class ClosingAlreadyInProgress                (override val channelId: ByteVector32) : ChannelException(channelId, "closing already in progress")
data class CannotCloseWithUnsignedOutgoingHtlcs    (override val channelId: ByteVector32) : ChannelException(channelId, "cannot close when there are unsigned outgoing htlc")
data class CannotCloseWithUnsignedOutgoingUpdateFee(override val channelId: ByteVector32) : ChannelException(channelId, "cannot close when there is an unsigned fee update")
data class ChannelUnavailable                      (override val channelId: ByteVector32) : ChannelException(channelId, "channel is unavailable (offline or closing)")
data class InvalidFinalScript                      (override val channelId: ByteVector32) : ChannelException(channelId, "invalid final script")
data class FundingTxTimedout                       (override val channelId: ByteVector32) : ChannelException(channelId, "funding tx timed out")
data class FundingTxSpent                          (override val channelId: ByteVector32, val spendingTx: Transaction) : ChannelException(channelId, "funding tx has been spent by txid=${spendingTx.txid}")
data class HtlcsTimedOutDownstream                 (override val channelId: ByteVector32, val htlcs: Set<UpdateAddHtlc>) : ChannelException(channelId, "one or more htlcs timed out downstream: ids=${htlcs.map { it.id } .joinToString(",")}")
data class FulfilledHtlcsWillTimeout               (override val channelId: ByteVector32, val htlcs: Set<UpdateAddHtlc>) : ChannelException(channelId, "one or more htlcs that should be fulfilled are close to timing out: ids=${htlcs.map { it.id }.joinToString()}")
data class HtlcOverriddenByLocalCommit             (override val channelId: ByteVector32, val htlc: UpdateAddHtlc) : ChannelException(channelId, "htlc ${htlc.id} was overridden by local commit")
data class FeerateTooSmall                         (override val channelId: ByteVector32, val remoteFeeratePerKw: FeeratePerKw) : ChannelException(channelId, "remote fee rate is too small: remoteFeeratePerKw=${remoteFeeratePerKw.toLong()}")
data class FeerateTooDifferent                     (override val channelId: ByteVector32, val localFeeratePerKw: FeeratePerKw, val remoteFeeratePerKw: FeeratePerKw) : ChannelException(channelId, "local/remote feerates are too different: remoteFeeratePerKw=${remoteFeeratePerKw.toLong()} localFeeratePerKw=${localFeeratePerKw.toLong()}")
data class InvalidAnnouncementSignatures           (override val channelId: ByteVector32, val annSigs: AnnouncementSignatures) : ChannelException(channelId, "invalid announcement signatures: $annSigs")
data class InvalidCommitmentSignature              (override val channelId: ByteVector32, val tx: Transaction) : ChannelException(channelId, "invalid commitment signature: tx=$tx")
data class InvalidHtlcSignature                    (override val channelId: ByteVector32, val tx: Transaction) : ChannelException(channelId, "invalid htlc signature: tx=$tx")
data class InvalidCloseSignature                   (override val channelId: ByteVector32, val tx: Transaction) : ChannelException(channelId, "invalid close signature: tx=$tx")
data class InvalidCloseFee                         (override val channelId: ByteVector32, val fee: Satoshi) : ChannelException(channelId, "invalid close fee: fee_satoshis=$fee")
data class HtlcSigCountMismatch                    (override val channelId: ByteVector32, val expected: Int, val actual: Int) : ChannelException(channelId, "htlc sig count mismatch: expected=$expected actual: $actual")
data class ForcedLocalCommit                       (override val channelId: ByteVector32) : ChannelException(channelId, "forced local commit")
data class UnexpectedHtlcId                        (override val channelId: ByteVector32, val expected: Long, val actual: Long) : ChannelException(channelId, "unexpected htlc id: expected=$expected actual=$actual")
data class ExpiryTooSmall                          (override val channelId: ByteVector32, val minimum: CltvExpiry, val actual: CltvExpiry, val blockCount: Long) : ChannelException(channelId, "expiry too small: minimum=$minimum actual=$actual blockCount=$blockCount")
data class ExpiryTooBig                            (override val channelId: ByteVector32, val maximum: CltvExpiry, val actual: CltvExpiry, val blockCount: Long) : ChannelException(channelId, "expiry too big: maximum=$maximum actual=$actual blockCount=$blockCount")
data class HtlcValueTooSmall                       (override val channelId: ByteVector32, val minimum: MilliSatoshi, val actual: MilliSatoshi) : ChannelException(channelId, "htlc value too small: minimum=$minimum actual=$actual")
@OptIn(ExperimentalUnsignedTypes::class)
data class HtlcValueTooHighInFlight                (override val channelId: ByteVector32, val maximum: ULong, val actual: MilliSatoshi) : ChannelException(channelId, "in-flight htlcs hold too much value: maximum=$maximum actual=$actual")
data class TooManyAcceptedHtlcs                    (override val channelId: ByteVector32, val maximum: Long) : ChannelException(channelId, "too many accepted htlcs: maximum=$maximum")
data class TooManyOfferedHtlcs                     (override val channelId: ByteVector32, val maximum: Long) : ChannelException(channelId, "too many offered htlcs: maximum=$maximum")
data class InsufficientFunds                       (override val channelId: ByteVector32, val amount: MilliSatoshi, val missing: Satoshi, val reserve: Satoshi, val fees: Satoshi) : ChannelException(channelId, "insufficient funds: missing=$missing reserve=$reserve fees=$fees")
data class RemoteCannotAffordFeesForNewHtlc        (override val channelId: ByteVector32, val amount: MilliSatoshi, val missing: Satoshi, val reserve: Satoshi, val fees: Satoshi) : ChannelException(channelId, "remote can't afford increased commit tx fees once new HTLC is added: missing=$missing reserve=$reserve fees=$fees")
data class InvalidHtlcPreimage                     (override val channelId: ByteVector32, val id: Long) : ChannelException(channelId, "invalid htlc preimage for htlc id=$id")
data class UnknownHtlcId                           (override val channelId: ByteVector32, val id: Long) : ChannelException(channelId, "unknown htlc id=$id")
data class CannotExtractSharedSecret               (override val channelId: ByteVector32, val htlc: UpdateAddHtlc) : ChannelException(channelId, "can't extract shared secret: paymentHash=${htlc.paymentHash} onion=${htlc.onionRoutingPacket}")
data class FundeeCannotSendUpdateFee               (override val channelId: ByteVector32) : ChannelException(channelId, "only the funder should send update_fee message")
data class CannotAffordFees                        (override val channelId: ByteVector32, val missing: Satoshi, val reserve: Satoshi, val fees: Satoshi) : ChannelException(channelId, "can't pay the fee: missing=$missing reserve=$reserve fees=$fees")
data class CannotSignWithoutChanges                (override val channelId: ByteVector32) : ChannelException(channelId, "cannot sign when there are no change")
data class CannotSignBeforeRevocation              (override val channelId: ByteVector32) : ChannelException(channelId, "cannot sign until next revocation hash is received")
data class UnexpectedRevocation                    (override val channelId: ByteVector32) : ChannelException(channelId, "received unexpected RevokeAndAck message")
data class InvalidRevocation                       (override val channelId: ByteVector32) : ChannelException(channelId, "invalid revocation")
data class InvalidRevokedCommitProof               (override val channelId: ByteVector32, val ourCommitmentNumber: Long, val theirCommitmentNumber: Long, val perCommitmentSecret: PrivateKey) : ChannelException(channelId, "counterparty claimed that we have a revoked commit but their proof doesn't check out: ourCommitmentNumber=$ourCommitmentNumber theirCommitmentNumber=$theirCommitmentNumber perCommitmentSecret=$perCommitmentSecret")
data class CommitmentSyncError                     (override val channelId: ByteVector32) : ChannelException(channelId, "commitment sync error")
data class RevocationSyncError                     (override val channelId: ByteVector32) : ChannelException(channelId, "revocation sync error")
data class InvalidFailureCode                      (override val channelId: ByteVector32) : ChannelException(channelId, "UpdateFailMalformedHtlc message doesn't have BADONION bit set")
data class PleasePublishYourCommitment             (override val channelId: ByteVector32) : ChannelException(channelId, "please publish your local commitment")
data class CommandUnavailableInThisState           (override val channelId: ByteVector32, val state: String) : ChannelException(channelId, "cannot execute command in state=$state")
// @formatter:on
