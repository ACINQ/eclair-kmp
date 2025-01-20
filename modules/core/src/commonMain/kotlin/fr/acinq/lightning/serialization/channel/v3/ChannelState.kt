@file:OptIn(ExperimentalSerializationApi::class)
@file:UseSerializers(
    KeyPathKSerializer::class,
    EitherSerializer::class,
    ShaChainSerializer::class,
    BlockHeaderKSerializer::class,
    BlockHashKSerializer::class,
    FundingSignedSerializer::class,
    ChannelUpdateSerializer::class,
    ByteVectorKSerializer::class,
    ByteVector32KSerializer::class,
    ByteVector64KSerializer::class,
    ChannelAnnouncementSerializer::class,
    PublicKeyKSerializer::class,
    PrivateKeyKSerializer::class,
    ShutdownSerializer::class,
    ClosingSignedSerializer::class,
    SatoshiKSerializer::class,
    UpdateAddHtlcSerializer::class,
    CommitSigSerializer::class,
    EncryptedChannelDataSerializer::class,
    ChannelReestablishDataSerializer::class,
    FundingCreatedSerializer::class,
    CommitSigTlvSerializer::class,
    ShutdownTlvSerializer::class,
    ClosingSignedTlvSerializer::class,
    ChannelReadyTlvSerializer::class,
    ChannelReestablishTlvSerializer::class,
    TlvStreamSerializer::class,
    GenericTlvSerializer::class,
    OnionRoutingPacketSerializer::class,
    FeeratePerKwSerializer::class,
    MilliSatoshiSerializer::class,
    UUIDSerializer::class,
    OutPointKSerializer::class,
    TxOutKSerializer::class,
    TransactionKSerializer::class,
    InputInfoKSerializer::class
)

package fr.acinq.lightning.serialization.v3

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.ChannelFlags
import fr.acinq.lightning.channel.InteractiveTxOutput
import fr.acinq.lightning.channel.SpliceStatus
import fr.acinq.lightning.channel.states.*
import fr.acinq.lightning.channel.states.Closed
import fr.acinq.lightning.channel.states.Negotiating
import fr.acinq.lightning.channel.states.Normal
import fr.acinq.lightning.channel.states.ShuttingDown
import fr.acinq.lightning.channel.states.WaitForRemotePublishFutureCommitment
import fr.acinq.lightning.crypto.ShaChain
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object InputInfoKSerializer : KSerializer<Transactions.InputInfo> {
    @Serializable
    @SerialName("fr.acinq.lightning.transactions.InputInfo")
    private data class InputInfoSurrogate(@Contextual val outPoint: OutPoint, @Contextual val txOut: TxOut, @Contextual val redeemScript: ByteVector) {

        constructor(input: Transactions.InputInfo.SegwitInput) : this(input.outPoint, input.txOut, input.redeemScript)
    }

    override val descriptor: SerialDescriptor = InputInfoSurrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: Transactions.InputInfo) {
        val surrogate = InputInfoSurrogate(value as Transactions.InputInfo.SegwitInput)
        return encoder.encodeSerializableValue(InputInfoSurrogate.serializer(), surrogate)
    }

    override fun deserialize(decoder: Decoder): Transactions.InputInfo {
        val surrogate = decoder.decodeSerializableValue(InputInfoSurrogate.serializer())
        return Transactions.InputInfo.SegwitInput(surrogate.outPoint, surrogate.txOut, surrogate.redeemScript)
    }
}

@Serializer(forClass = FundingSigned::class)
object FundingSignedSerializer

@Serializer(forClass = Shutdown::class)
object ShutdownSerializer

@Serializer(forClass = ClosingSigned::class)
object ClosingSignedSerializer

@Serializer(forClass = ChannelUpdate::class)
object ChannelUpdateSerializer

@Serializer(forClass = ChannelAnnouncement::class)
object ChannelAnnouncementSerializer

object UpdateAddHtlcSerializer : KSerializer<UpdateAddHtlc> {
    @Serializable
    @SerialName("fr.acinq.lightning.wire.UpdateAddHtlc")
    private data class Surrogate(
        val channelId: ByteVector32,
        val id: Long,
        val amountMsat: MilliSatoshi,
        val paymentHash: ByteVector32,
        val cltvExpiry: CltvExpiry,
        val onionRoutingPacket: OnionRoutingPacket,
    )

    override val descriptor: SerialDescriptor = Surrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: UpdateAddHtlc) {
        val surrogate = Surrogate(value.channelId, value.id, value.amountMsat, value.paymentHash, value.cltvExpiry, value.onionRoutingPacket)
        return encoder.encodeSerializableValue(Surrogate.serializer(), surrogate)
    }

    override fun deserialize(decoder: Decoder): UpdateAddHtlc {
        val surrogate = decoder.decodeSerializableValue(Surrogate.serializer())
        return UpdateAddHtlc(surrogate.channelId, surrogate.id, surrogate.amountMsat, surrogate.paymentHash, surrogate.cltvExpiry, surrogate.onionRoutingPacket, null, null)
    }
}

@Serializer(forClass = UpdateFulfillHtlc::class)
object UpdateFulfillHtlcSerializer

@Serializer(forClass = UpdateFailHtlc::class)
object UpdateFailHtlcSerializer

@Serializer(forClass = UpdateFailMalformedHtlc::class)
object UpdateFailMalformedHtlcSerializer

@Serializer(forClass = UpdateFee::class)
object UpdateFeeSerializer

@Serializer(forClass = CommitSig::class)
object CommitSigSerializer

@Serializer(forClass = EncryptedChannelData::class)
object EncryptedChannelDataSerializer

@Serializer(forClass = ChannelReestablish::class)
object ChannelReestablishDataSerializer

@Serializable
internal data class FundingLocked(
    val channelId: ByteVector32,
    val nextPerCommitmentPoint: PublicKey,
)

@Serializer(forClass = FundingCreated::class)
object FundingCreatedSerializer

@Serializer(forClass = ChannelReadyTlv.ShortChannelIdTlv::class)
object ChannelReadyTlvShortChannelIdTlvSerializer

@Serializer(forClass = ClosingSignedTlv.FeeRange::class)
object ClosingSignedTlvFeeRangeSerializer

@Serializer(forClass = ShutdownTlv.ChannelData::class)
object ShutdownTlvChannelDataSerializer

@Serializer(forClass = ShutdownTlv::class)
object ShutdownTlvSerializer

@Serializer(forClass = CommitSigTlv::class)
object CommitSigTlvSerializer

@Serializer(forClass = ClosingSignedTlv::class)
object ClosingSignedTlvSerializer

@Serializer(forClass = ChannelReadyTlv::class)
object ChannelReadyTlvSerializer

@Serializer(forClass = ChannelReestablishTlv::class)
object ChannelReestablishTlvSerializer

@Serializable
data class TlvStreamSurrogate(val records: Set<Tlv>, val unknown: Set<GenericTlv> = setOf())
class TlvStreamSerializer<T : Tlv> : KSerializer<TlvStream<T>> {
    private val delegateSerializer = TlvStreamSurrogate.serializer()
    override val descriptor: SerialDescriptor = delegateSerializer.descriptor
    override fun deserialize(decoder: Decoder): TlvStream<T> {
        val o = delegateSerializer.deserialize(decoder)
        @Suppress("UNCHECKED_CAST")
        return TlvStream(o.records.map { it as T }.toSet(), o.unknown)
    }

    override fun serialize(encoder: Encoder, value: TlvStream<T>) = TODO("Not yet implemented")
}

@Serializer(forClass = GenericTlv::class)
object GenericTlvSerializer

@Serializer(forClass = OnionRoutingPacket::class)
object OnionRoutingPacketSerializer

@Serializer(forClass = FeeratePerKw::class)
object FeeratePerKwSerializer

@Serializer(forClass = MilliSatoshi::class)
object MilliSatoshiSerializer

@Serializer(forClass = UUID::class)
object UUIDSerializer

@Serializable
internal sealed class DirectedHtlc {
    abstract val add: UpdateAddHtlc

    fun to(): fr.acinq.lightning.transactions.DirectedHtlc = when (this) {
        is IncomingHtlc -> fr.acinq.lightning.transactions.IncomingHtlc(this.add)
        is OutgoingHtlc -> fr.acinq.lightning.transactions.OutgoingHtlc(this.add)
    }
}

@Serializable
internal data class IncomingHtlc(override val add: UpdateAddHtlc) : DirectedHtlc()

@Serializable
internal data class OutgoingHtlc(override val add: UpdateAddHtlc) : DirectedHtlc()

@Serializable
internal data class CommitmentSpec(
    val htlcs: Set<DirectedHtlc>,
    val feerate: FeeratePerKw,
    val toLocal: MilliSatoshi,
    val toRemote: MilliSatoshi
) {
    fun export() = fr.acinq.lightning.transactions.CommitmentSpec(htlcs.map { it.to() }.toSet(), feerate, toLocal, toRemote)

}

@Serializable
internal data class LocalChanges(val proposed: List<UpdateMessage>, val signed: List<UpdateMessage>, val acked: List<UpdateMessage>) {
    fun export() = fr.acinq.lightning.channel.LocalChanges(proposed, signed, acked)
}

@Serializable
internal data class RemoteChanges(val proposed: List<UpdateMessage>, val acked: List<UpdateMessage>, val signed: List<UpdateMessage>) {
    fun export() = fr.acinq.lightning.channel.RemoteChanges(proposed, acked, signed)
}

@Serializable
internal data class HtlcTxAndSigs(
    val txinfo: Transactions.TransactionWithInputInfo.HtlcTx,
    val localSig: ByteVector64,
    val remoteSig: ByteVector64
) {
    fun export() = fr.acinq.lightning.channel.HtlcTxAndSigs(txinfo, localSig, remoteSig)
}

@Serializable
internal data class PublishableTxs(val commitTx: Transactions.TransactionWithInputInfo.CommitTx, val htlcTxsAndSigs: List<HtlcTxAndSigs>) {
    fun export() = fr.acinq.lightning.channel.PublishableTxs(commitTx, htlcTxsAndSigs.map { it.export() })
}

@Serializable
internal data class LocalCommit(val index: Long, val spec: CommitmentSpec, val publishableTxs: PublishableTxs) {
    fun export() = fr.acinq.lightning.channel.LocalCommit(index, spec.export(), publishableTxs.export())
}

@Serializable
internal data class RemoteCommit(
    val index: Long,
    val spec: CommitmentSpec,
    val txid: ByteVector32,
    val remotePerCommitmentPoint: PublicKey
) {
    fun export() = fr.acinq.lightning.channel.RemoteCommit(index, spec.export(), TxId(txid), remotePerCommitmentPoint)
}

@Serializable
internal data class WaitingForRevocation(val nextRemoteCommit: RemoteCommit, val sent: CommitSig, val sentAfterLocalCommitIndex: Long, val reSignAsap: Boolean = false)

@Serializable
internal data class LocalCommitPublished(
    val commitTx: Transaction,
    val claimMainDelayedOutputTx: Transactions.TransactionWithInputInfo.ClaimLocalDelayedOutputTx? = null,
    val htlcTxs: Map<OutPoint, Transactions.TransactionWithInputInfo.HtlcTx?> = emptyMap(),
    val claimHtlcDelayedTxs: List<Transactions.TransactionWithInputInfo.ClaimLocalDelayedOutputTx> = emptyList(),
    val claimAnchorTxs: List<Transactions.TransactionWithInputInfo.ClaimAnchorOutputTx> = emptyList(),
    val irrevocablySpent: Map<OutPoint, Transaction> = emptyMap()
) {
    fun export() = fr.acinq.lightning.channel.LocalCommitPublished(commitTx, claimMainDelayedOutputTx, htlcTxs, claimHtlcDelayedTxs, claimAnchorTxs, irrevocablySpent)
}

@Serializable
internal data class RemoteCommitPublished(
    val commitTx: Transaction,
    val claimMainOutputTx: Transactions.TransactionWithInputInfo.ClaimRemoteCommitMainOutputTx? = null,
    val claimHtlcTxs: Map<OutPoint, Transactions.TransactionWithInputInfo.ClaimHtlcTx?> = emptyMap(),
    val claimAnchorTxs: List<Transactions.TransactionWithInputInfo.ClaimAnchorOutputTx> = emptyList(),
    val irrevocablySpent: Map<OutPoint, Transaction> = emptyMap()
) {
    fun export() = fr.acinq.lightning.channel.RemoteCommitPublished(commitTx, claimMainOutputTx, claimHtlcTxs, claimAnchorTxs, irrevocablySpent)
}

@Serializable
internal data class RevokedCommitPublished(
    val commitTx: Transaction,
    val remotePerCommitmentSecret: PrivateKey,
    val claimMainOutputTx: Transactions.TransactionWithInputInfo.ClaimRemoteCommitMainOutputTx? = null,
    val mainPenaltyTx: Transactions.TransactionWithInputInfo.MainPenaltyTx? = null,
    val htlcPenaltyTxs: List<Transactions.TransactionWithInputInfo.HtlcPenaltyTx> = emptyList(),
    val claimHtlcDelayedPenaltyTxs: List<Transactions.TransactionWithInputInfo.ClaimHtlcDelayedOutputPenaltyTx> = emptyList(),
    val irrevocablySpent: Map<OutPoint, Transaction> = emptyMap()
) {
    fun export() = fr.acinq.lightning.channel.RevokedCommitPublished(commitTx, remotePerCommitmentSecret, claimMainOutputTx, mainPenaltyTx, htlcPenaltyTxs, claimHtlcDelayedPenaltyTxs, irrevocablySpent)
}

/**
 * README: by design, we do not include channel private keys and secret here, so they won't be included in our backups (local files, encrypted peer backup, ...), so even
 * if these backups were compromised channel private keys would not be leaked unless the main seed was also compromised.
 * This means that they will be recomputed once when we convert serialized data to their "live" counterparts.
 */
@Serializable
internal data class LocalParams(
    val nodeId: PublicKey,
    val fundingKeyPath: KeyPath,
    val dustLimit: Satoshi,
    val maxHtlcValueInFlightMsat: Long,
    val channelReserve: Satoshi,
    val htlcMinimum: MilliSatoshi,
    val toSelfDelay: CltvExpiryDelta,
    val maxAcceptedHtlcs: Int,
    val isFunder: Boolean,
    val defaultFinalScriptPubKey: ByteVector,
    val features: Features
) {
    fun export() = fr.acinq.lightning.channel.LocalParams(
        nodeId,
        fundingKeyPath,
        dustLimit,
        maxHtlcValueInFlightMsat,
        htlcMinimum,
        toSelfDelay,
        maxAcceptedHtlcs,
        isFunder,
        isFunder,
        defaultFinalScriptPubKey,
        features
    )
}

@Serializable
internal data class RemoteParams(
    val nodeId: PublicKey,
    val dustLimit: Satoshi,
    val maxHtlcValueInFlightMsat: Long,
    val channelReserve: Satoshi,
    val htlcMinimum: MilliSatoshi,
    val toSelfDelay: CltvExpiryDelta,
    val maxAcceptedHtlcs: Int,
    val fundingPubKey: PublicKey,
    val revocationBasepoint: PublicKey,
    val paymentBasepoint: PublicKey,
    val delayedPaymentBasepoint: PublicKey,
    val htlcBasepoint: PublicKey,
    val features: Features
) {
    fun export() = fr.acinq.lightning.channel.RemoteParams(
        nodeId,
        dustLimit,
        maxHtlcValueInFlightMsat,
        htlcMinimum,
        toSelfDelay,
        maxAcceptedHtlcs,
        revocationBasepoint,
        paymentBasepoint,
        delayedPaymentBasepoint,
        htlcBasepoint,
        features
    )
}

@Serializable
internal data class ChannelConfig(val bin: ByteVector) {
    fun export() = fr.acinq.lightning.channel.ChannelConfig(bin.toByteArray())
}

@Serializable
internal data class ChannelType(val bin: ByteVector)

@Serializable
internal data class ChannelFeatures(val bin: ByteVector) {
    fun export() = fr.acinq.lightning.channel.ChannelFeatures(Features(bin.toByteArray()).activated.keys)
}

@Serializable
internal data class ClosingFeerates(val preferred: FeeratePerKw, val min: FeeratePerKw, val max: FeeratePerKw) {
    fun export() = fr.acinq.lightning.channel.states.ClosingFeerates(preferred, min, max)
}

@Serializable
internal data class ClosingTxProposed(val unsignedTx: Transactions.TransactionWithInputInfo.ClosingTx, val localClosingSigned: ClosingSigned) {
    fun export() = fr.acinq.lightning.channel.ClosingTxProposed(unsignedTx, localClosingSigned)
}

@Serializable
internal data class Commitments(
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
    val payments: Map<Long, UUID>,
    val remoteNextCommitInfo: Either<WaitingForRevocation, PublicKey>,
    val commitInput: Transactions.InputInfo,
    val remotePerCommitmentSecrets: ShaChain,
    val channelId: ByteVector32,
    val remoteChannelData: EncryptedChannelData = EncryptedChannelData.empty
) {
    fun export() = fr.acinq.lightning.channel.Commitments(
        fr.acinq.lightning.channel.ChannelParams(
            channelId,
            channelConfig.export(),
            channelFeatures.export(),
            localParams.export(),
            remoteParams.export(),
            ChannelFlags(announceChannel = false, nonInitiatorPaysCommitFees = false),
        ),
        fr.acinq.lightning.channel.CommitmentChanges(
            localChanges.export(),
            remoteChanges.export(),
            localNextHtlcId,
            remoteNextHtlcId,
        ),
        active = listOf(
            fr.acinq.lightning.channel.Commitment(
                fundingTxIndex = 0,
                remoteFundingPubkey = remoteParams.fundingPubKey,
                // We previously didn't store the funding transaction, so we act as if it were unconfirmed.
                // We will put a WatchConfirmed when starting, which will return the confirmed transaction.
                fr.acinq.lightning.channel.LocalFundingStatus.UnconfirmedFundingTx(
                    fr.acinq.lightning.channel.PartiallySignedSharedTransaction(
                        fr.acinq.lightning.channel.SharedTransaction(null, InteractiveTxOutput.Shared(0, commitInput.txOut.publicKeyScript, localCommit.spec.toLocal, localCommit.spec.toRemote, 0.msat), listOf(), listOf(), listOf(), listOf(), 0),
                        // We must correctly set the txId here.
                        TxSignatures(channelId, commitInput.outPoint.txid, listOf()),
                    ),
                    fr.acinq.lightning.channel.InteractiveTxParams(channelId, localParams.isFunder, commitInput.txOut.amount, commitInput.txOut.amount, remoteParams.fundingPubKey, 0, localParams.dustLimit, localCommit.spec.feerate),
                    0
                ),
                fr.acinq.lightning.channel.RemoteFundingStatus.Locked,
                localCommit.export(),
                remoteCommit.export(),
                remoteNextCommitInfo.fold({ x -> fr.acinq.lightning.channel.NextRemoteCommit(x.sent, x.nextRemoteCommit.export()) }, { _ -> null })
            )
        ),
        inactive = emptyList(),
        payments,
        remoteNextCommitInfo.transform({ x -> fr.acinq.lightning.channel.WaitingForRevocation(x.sentAfterLocalCommitIndex) }, { y -> y }),
        remotePerCommitmentSecrets,
        remoteChannelData
    )
}

@Serializable
internal data class OnChainFeerates(val mutualCloseFeerate: FeeratePerKw, val claimMainFeerate: FeeratePerKw, val fastFeerate: FeeratePerKw)

@Serializable
internal data class StaticParams(val chainHash: ByteVector32, val remoteNodeId: PublicKey)

@Serializable
internal sealed class ChannelStateWithCommitments {
    abstract val staticParams: StaticParams
    abstract val currentTip: Pair<Int, BlockHeader>
    abstract val currentOnChainFeerates: OnChainFeerates
    abstract val commitments: Commitments
    val channelId: ByteVector32 get() = commitments.channelId
    abstract fun export(): PersistedChannelState
}

@Serializable
internal data class WaitForRemotePublishFutureCommitment(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val remoteChannelReestablish: ChannelReestablish
) : ChannelStateWithCommitments() {
    override fun export() =
        WaitForRemotePublishFutureCommitment(commitments.export(), remoteChannelReestablish)
}

/**
 * This class contains data used for channels opened before the migration to dual-funding.
 * We cannot update it or rename it otherwise we would break serialization backwards-compatibility.
 */
@Serializable
internal data class WaitForFundingConfirmed(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val fundingTx: Transaction?,
    val waitingSinceBlock: Long, // how long have we been waiting for the funding tx to confirm
    val deferred: FundingLocked?,
    val lastSent: Either<FundingCreated, FundingSigned>
) : ChannelStateWithCommitments() {
    override fun export() = LegacyWaitForFundingConfirmed(
        commitments.export(),
        fundingTx,
        waitingSinceBlock,
        deferred?.let { ChannelReady(it.channelId, it.nextPerCommitmentPoint) },
        lastSent
    )
}

/**
 * This class contains data used for channels opened before the migration to dual-funding.
 * We cannot update it or rename it otherwise we would break serialization backwards-compatibility.
 */
@Serializable
internal data class WaitForFundingLocked(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val shortChannelId: ShortChannelId,
    val lastSent: FundingLocked
) : ChannelStateWithCommitments() {
    override fun export() = LegacyWaitForFundingLocked(
        commitments.export(),
        shortChannelId,
        ChannelReady(lastSent.channelId, lastSent.nextPerCommitmentPoint)
    )
}

@Serializable
internal data class Normal(
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
    override fun export() = Normal(
        commitments.export(),
        shortChannelId,
        channelUpdate,
        remoteChannelUpdate,
        localShutdown,
        remoteShutdown,
        closingFeerates?.export(),
        SpliceStatus.None,
    )
}

@Serializable
internal data class ShuttingDown(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val localShutdown: Shutdown,
    val remoteShutdown: Shutdown,
    val closingFeerates: ClosingFeerates?
) : ChannelStateWithCommitments() {
    override fun export() = ShuttingDown(
        commitments.export(),
        localShutdown,
        remoteShutdown,
        closingFeerates?.export()
    )
}

@Serializable
internal data class Negotiating(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val localShutdown: Shutdown,
    val remoteShutdown: Shutdown,
    val closingTxProposed: List<List<ClosingTxProposed>>,
    val bestUnpublishedClosingTx: Transactions.TransactionWithInputInfo.ClosingTx?,
    val closingFeerates: ClosingFeerates?
) : ChannelStateWithCommitments() {
    init {
        require(closingTxProposed.isNotEmpty()) { "there must always be a list for the current negotiation" }
        require(!commitments.localParams.isFunder || !closingTxProposed.any { it.isEmpty() }) { "initiator must have at least one closing signature for every negotiation attempt because it initiates the closing" }
    }

    override fun export() = Negotiating(
        commitments.export(),
        localShutdown,
        remoteShutdown,
        closingTxProposed.map { x -> x.map { it.export() } },
        bestUnpublishedClosingTx,
        closingFeerates?.export()
    )
}

@Serializable
internal data class Closing(
    override val staticParams: StaticParams,
    override val currentTip: Pair<Int, BlockHeader>,
    override val currentOnChainFeerates: OnChainFeerates,
    override val commitments: Commitments,
    val fundingTx: Transaction?,
    val waitingSinceBlock: Long,
    val mutualCloseProposed: List<Transactions.TransactionWithInputInfo.ClosingTx> = emptyList(),
    val mutualClosePublished: List<Transactions.TransactionWithInputInfo.ClosingTx> = emptyList(),
    val localCommitPublished: LocalCommitPublished? = null,
    val remoteCommitPublished: RemoteCommitPublished? = null,
    val nextRemoteCommitPublished: RemoteCommitPublished? = null,
    val futureRemoteCommitPublished: RemoteCommitPublished? = null,
    val revokedCommitPublished: List<RevokedCommitPublished> = emptyList()
) : ChannelStateWithCommitments() {
    override fun export() = fr.acinq.lightning.channel.states.Closing(
        commitments.export(),
        waitingSinceBlock,
        mutualCloseProposed,
        mutualClosePublished,
        localCommitPublished?.export(),
        remoteCommitPublished?.export(),
        nextRemoteCommitPublished?.export(),
        futureRemoteCommitPublished?.export(),
        revokedCommitPublished.map { it.export() }
    )
}

@Serializable
internal data class Closed(val state: Closing) : ChannelStateWithCommitments() {
    override val commitments: Commitments get() = state.commitments
    override val staticParams: StaticParams get() = state.staticParams
    override val currentTip: Pair<Int, BlockHeader> get() = state.currentTip
    override val currentOnChainFeerates: OnChainFeerates get() = state.currentOnChainFeerates
    override fun export() = Closed(state.export())
}

internal object ShaChainSerializer : KSerializer<ShaChain> {
    @Serializable
    private data class Surrogate(val knownHashes: List<Pair<String, ByteArray>>, val lastIndex: Long? = null)

    override val descriptor: SerialDescriptor = Surrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: ShaChain) {
        val surrogate = Surrogate(
            value.knownHashes.map { Pair(it.key.toBinaryString(), it.value.toByteArray()) },
            value.lastIndex
        )
        return encoder.encodeSerializableValue(Surrogate.serializer(), surrogate)
    }

    override fun deserialize(decoder: Decoder): ShaChain {
        val surrogate = decoder.decodeSerializableValue(Surrogate.serializer())
        return ShaChain(surrogate.knownHashes.associate { it.first.toBooleanList() to ByteVector32(it.second) }, surrogate.lastIndex)
    }

    private fun List<Boolean>.toBinaryString(): String = this.map { if (it) '1' else '0' }.joinToString(separator = "")
    private fun String.toBooleanList(): List<Boolean> = this.map { it == '1' }
}

class EitherSerializer<A : Any, B : Any>(val aSer: KSerializer<A>, val bSer: KSerializer<B>) : KSerializer<Either<A, B>> {
    @Serializable
    internal data class Surrogate<A : Any, B : Any>(val isRight: Boolean, val left: A?, val right: B?)

    override val descriptor = Surrogate.serializer<A, B>(aSer, bSer).descriptor

    override fun serialize(encoder: Encoder, value: Either<A, B>) {
        val surrogate = Surrogate(value.isRight, value.left, value.right)
        return encoder.encodeSerializableValue(Surrogate.serializer<A, B>(aSer, bSer), surrogate)
    }

    override fun deserialize(decoder: Decoder): Either<A, B> {
        val surrogate = decoder.decodeSerializableValue(Surrogate.serializer<A, B>(aSer, bSer))
        return if (surrogate.isRight) Either.Right(surrogate.right!!) else Either.Left(surrogate.left!!)
    }
}