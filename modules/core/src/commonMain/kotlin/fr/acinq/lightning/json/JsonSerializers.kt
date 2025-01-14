@file:OptIn(ExperimentalSerializationApi::class)
@file:UseSerializers(
    // This is used by Kotlin at compile time to resolve serializers (defined in this file)
    // in order to build serializers for other classes (also defined in this file).
    // If we used @Serializable annotations directly on the actual classes, Kotlin would be
    // able to resolve serializers by itself. It is verbose, but it allows us to contain
    // serialization code in this file.
    JsonSerializers.CommitmentSerializer::class,
    JsonSerializers.CommitmentsSerializer::class,
    JsonSerializers.LocalParamsSerializer::class,
    JsonSerializers.RemoteParamsSerializer::class,
    JsonSerializers.LocalCommitSerializer::class,
    JsonSerializers.RemoteCommitSerializer::class,
    JsonSerializers.NextRemoteCommitSerializer::class,
    JsonSerializers.LocalChangesSerializer::class,
    JsonSerializers.RemoteChangesSerializer::class,
    JsonSerializers.EitherSerializer::class,
    JsonSerializers.ShaChainSerializer::class,
    JsonSerializers.ByteVectorSerializer::class,
    JsonSerializers.ByteVector32Serializer::class,
    JsonSerializers.ByteVector64Serializer::class,
    JsonSerializers.BlockHashSerializer::class,
    JsonSerializers.PublicKeySerializer::class,
    JsonSerializers.PrivateKeySerializer::class,
    JsonSerializers.TxIdSerializer::class,
    JsonSerializers.KeyPathSerializer::class,
    JsonSerializers.SatoshiSerializer::class,
    JsonSerializers.MilliSatoshiSerializer::class,
    JsonSerializers.CltvExpirySerializer::class,
    JsonSerializers.CltvExpiryDeltaSerializer::class,
    JsonSerializers.FeeratePerKwSerializer::class,
    JsonSerializers.CommitmentSpecSerializer::class,
    JsonSerializers.PublishableTxsSerializer::class,
    JsonSerializers.HtlcTxAndSigsSerializer::class,
    JsonSerializers.ChannelConfigSerializer::class,
    JsonSerializers.ChannelFeaturesSerializer::class,
    JsonSerializers.FeaturesSerializer::class,
    JsonSerializers.ShortChannelIdSerializer::class,
    JsonSerializers.ChannelKeysSerializer::class,
    JsonSerializers.TransactionSerializer::class,
    JsonSerializers.OutPointSerializer::class,
    JsonSerializers.TxOutSerializer::class,
    JsonSerializers.LocalCommitPublishedSerializer::class,
    JsonSerializers.RemoteCommitPublishedSerializer::class,
    JsonSerializers.RevokedCommitPublishedSerializer::class,
    JsonSerializers.OnionRoutingPacketSerializer::class,
    JsonSerializers.FundingSignedSerializer::class,
    JsonSerializers.UpdateAddHtlcSerializer::class,
    JsonSerializers.UpdateAddHtlcTlvSerializer::class,
    JsonSerializers.UpdateAddHtlcTlvPathKeySerializer::class,
    JsonSerializers.UpdateFulfillHtlcSerializer::class,
    JsonSerializers.UpdateFailHtlcSerializer::class,
    JsonSerializers.UpdateFailMalformedHtlcSerializer::class,
    JsonSerializers.UpdateFeeSerializer::class,
    JsonSerializers.ChannelUpdateSerializer::class,
    JsonSerializers.ChannelAnnouncementSerializer::class,
    JsonSerializers.WaitingForRevocationSerializer::class,
    JsonSerializers.SharedFundingInputSerializer::class,
    JsonSerializers.InteractiveTxParamsSerializer::class,
    JsonSerializers.SignedSharedTransactionSerializer::class,
    JsonSerializers.InteractiveTxSigningSessionSerializer::class,
    JsonSerializers.RbfStatusSerializer::class,
    JsonSerializers.SpliceStatusSerializer::class,
    JsonSerializers.LiquidityFeesSerializer::class,
    JsonSerializers.LiquidityPaymentDetailsSerializer::class,
    JsonSerializers.LiquidityPurchaseSerializer::class,
    JsonSerializers.ChannelFlagsSerializer::class,
    JsonSerializers.ChannelParamsSerializer::class,
    JsonSerializers.ChannelOriginSerializer::class,
    JsonSerializers.CommitmentChangesSerializer::class,
    JsonSerializers.LocalFundingStatusSerializer::class,
    JsonSerializers.RemoteFundingStatusSerializer::class,
    JsonSerializers.ShutdownSerializer::class,
    JsonSerializers.ClosingCompleteSerializer::class,
    JsonSerializers.ClosingSigSerializer::class,
    JsonSerializers.CommitSigSerializer::class,
    JsonSerializers.EncryptedChannelDataSerializer::class,
    JsonSerializers.ChannelReestablishDataSerializer::class,
    JsonSerializers.FundingCreatedSerializer::class,
    JsonSerializers.ChannelReadySerializer::class,
    JsonSerializers.ChannelReadyTlvShortChannelIdTlvSerializer::class,
    JsonSerializers.ShutdownTlvChannelDataSerializer::class,
    JsonSerializers.GenericTlvSerializer::class,
    JsonSerializers.TlvStreamSerializer::class,
    JsonSerializers.ShutdownTlvSerializer::class,
    JsonSerializers.ClosingCompleteTlvSerializer::class,
    JsonSerializers.ClosingSigTlvSerializer::class,
    JsonSerializers.ChannelReestablishTlvSerializer::class,
    JsonSerializers.ChannelReadyTlvSerializer::class,
    JsonSerializers.CommitSigTlvAlternativeFeerateSigSerializer::class,
    JsonSerializers.CommitSigTlvAlternativeFeerateSigsSerializer::class,
    JsonSerializers.CommitSigTlvBatchSerializer::class,
    JsonSerializers.CommitSigTlvSerializer::class,
    JsonSerializers.UUIDSerializer::class,
    JsonSerializers.ClosingSerializer::class,
    JsonSerializers.Bolt11ExtraHopSerializer::class,
    JsonSerializers.Bolt11UnknownTagSerializer::class,
    JsonSerializers.Bolt11InvalidTagSerializer::class,
    JsonSerializers.EncodedNodeIdSerializer::class,
    JsonSerializers.BlindedHopSerializer::class,
    JsonSerializers.BlindedRouteSerializer::class,
)
@file:UseContextualSerialization(
    PersistedChannelState::class
)

package fr.acinq.lightning.json

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.states.*
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.crypto.RouteBlinding
import fr.acinq.lightning.crypto.ShaChain
import fr.acinq.lightning.json.JsonSerializers.LongSerializer
import fr.acinq.lightning.json.JsonSerializers.StringSerializer
import fr.acinq.lightning.json.JsonSerializers.SurrogateSerializer
import fr.acinq.lightning.payment.Bolt11Invoice
import fr.acinq.lightning.payment.Bolt11Invoice.TaggedField
import fr.acinq.lightning.transactions.CommitmentSpec
import fr.acinq.lightning.transactions.IncomingHtlc
import fr.acinq.lightning.transactions.OutgoingHtlc
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.wire.*
import fr.acinq.lightning.wire.OfferTypes.OfferChains
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.PolymorphicModuleBuilder
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import kotlinx.serialization.modules.polymorphic

/**
 * Json support for [ChannelState] based on `kotlinx-serialization`.
 *
 * The implementation is self-contained, all serializers are defined here as opposed to tagging
 * our classes with `@Serializable`. Depending on the class to serialize, we use two techniques
 * to define serializers:
 *  - `@Serializer(forClass = T::class)`, simplest method, equivalent to tagging T with `@Serializable`
 *  - [SurrogateSerializer] and its children ([StringSerializer], [LongSerializer]) for more complex cases
 *
 * Note that we manually have to define polymorphic classes in [SerializersModule], which would be done automatically
 * by Kotlin if we directly tagged `sealed classes` with `@Serializable`.
 */
object JsonSerializers {

    @OptIn(ExperimentalSerializationApi::class)
    val json = Json {
        prettyPrint = true
        serializersModule = SerializersModule {
            // we need to explicitly define a [PolymorphicSerializer] for sealed classes, but not for interfaces
            fun PolymorphicModuleBuilder<ChannelStateWithCommitments>.registerChannelStateWithCommitmentsSubclasses() {
                subclass(LegacyWaitForFundingConfirmed::class, LegacyWaitForFundingConfirmedSerializer)
                subclass(LegacyWaitForFundingLocked::class, LegacyWaitForFundingLockedSerializer)
                subclass(WaitForFundingConfirmed::class, WaitForFundingConfirmedSerializer)
                subclass(WaitForChannelReady::class, WaitForChannelReadySerializer)
                subclass(Normal::class, NormalSerializer)
                subclass(ShuttingDown::class, ShuttingDownSerializer)
                subclass(Negotiating::class, NegotiatingSerializer)
                subclass(Closing::class, ClosingSerializer)
                subclass(WaitForRemotePublishFutureCommitment::class, WaitForRemotePublishFutureCommitmentSerializer)
                subclass(Closed::class, ClosedSerializer)
            }

            fun PolymorphicModuleBuilder<PersistedChannelState>.registerPersistedChannelStateSubclasses() {
                registerChannelStateWithCommitmentsSubclasses()
                subclass(WaitForFundingSigned::class, WaitForFundingSignedSerializer)
            }

            contextual(PolymorphicSerializer(ChannelState::class))
            polymorphicDefaultSerializer(ChannelState::class) { ChannelStateSerializer }
            polymorphic(ChannelState::class) {
                registerPersistedChannelStateSubclasses()
                subclass(Offline::class, OfflineSerializer)
                subclass(Syncing::class, SyncingSerializer)
            }

            contextual(PolymorphicSerializer(PersistedChannelState::class))
            polymorphicDefaultSerializer(PersistedChannelState::class) { ChannelStateSerializer }
            polymorphic(PersistedChannelState::class) {
                registerPersistedChannelStateSubclasses()
            }

            contextual(PolymorphicSerializer(ChannelStateWithCommitments::class))
            polymorphicDefaultSerializer(ChannelStateWithCommitments::class) { ChannelStateSerializer }
            polymorphic(ChannelStateWithCommitments::class) {
                registerChannelStateWithCommitmentsSubclasses()
            }

            polymorphic(UpdateMessage::class) {
                subclass(UpdateAddHtlc::class, UpdateAddHtlcSerializer)
                subclass(UpdateFailHtlc::class, UpdateFailHtlcSerializer)
                subclass(UpdateFailMalformedHtlc::class, UpdateFailMalformedHtlcSerializer)
                subclass(UpdateFulfillHtlc::class, UpdateFulfillHtlcSerializer)
                subclass(UpdateFee::class, UpdateFeeSerializer)
            }
            polymorphic(Tlv::class) {
                subclass(ChannelReadyTlv.ShortChannelIdTlv::class, ChannelReadyTlvShortChannelIdTlvSerializer)
                subclass(CommitSigTlv.AlternativeFeerateSigs::class, CommitSigTlvAlternativeFeerateSigsSerializer)
                subclass(CommitSigTlv.Batch::class, CommitSigTlvBatchSerializer)
                subclass(ShutdownTlv.ChannelData::class, ShutdownTlvChannelDataSerializer)
                subclass(UpdateAddHtlcTlv.PathKey::class, UpdateAddHtlcTlvPathKeySerializer)
            }
            // TODO The following declarations are required because serializers for [TransactionWithInputInfo]
            //  depend themselves on @Contextual serializers. Once we get rid of v2/v3 serialization and we
            //  define our own context-less serializers in this file, we will be able to clean up
            //  those declarations.
            contextual(OutPointSerializer)
            contextual(TxOutSerializer)
            contextual(TransactionSerializer)
            contextual(ByteVectorSerializer)
            contextual(ByteVector32Serializer)

            contextual(Bolt11InvoiceSerializer)
            contextual(OfferSerializer)
        }
    }

    @Serializable
    data class ChannelStateSurrogateSerializer(val forState: String)
    object ChannelStateSerializer : SurrogateSerializer<ChannelState, ChannelStateSurrogateSerializer>(
        transform = { ChannelStateSurrogateSerializer(it::class.qualifiedName!!) },
        delegateSerializer = ChannelStateSurrogateSerializer.serializer()
    )

    @Serializer(forClass = Offline::class)
    object OfflineSerializer

    @Serializer(forClass = Syncing::class)
    object SyncingSerializer

    @Serializer(forClass = LegacyWaitForFundingConfirmed::class)
    object LegacyWaitForFundingConfirmedSerializer

    @Serializer(forClass = LegacyWaitForFundingLocked::class)
    object LegacyWaitForFundingLockedSerializer

    @Serializer(forClass = WaitForFundingSigned::class)
    object WaitForFundingSignedSerializer

    @Serializer(forClass = WaitForFundingConfirmed::class)
    object WaitForFundingConfirmedSerializer

    @Serializer(forClass = WaitForChannelReady::class)
    object WaitForChannelReadySerializer

    @Serializer(forClass = Normal::class)
    object NormalSerializer

    @Serializer(forClass = ShuttingDown::class)
    object ShuttingDownSerializer

    @Serializer(forClass = Negotiating::class)
    object NegotiatingSerializer

    @Serializer(forClass = Closing::class)
    object ClosingSerializer

    @Serializer(forClass = WaitForRemotePublishFutureCommitment::class)
    object WaitForRemotePublishFutureCommitmentSerializer

    @Serializer(forClass = Closed::class)
    object ClosedSerializer

    @Serializable
    data class SharedFundingInputSurrogate(val outPoint: OutPoint, val amount: Satoshi)
    object SharedFundingInputSerializer : SurrogateSerializer<SharedFundingInput, SharedFundingInputSurrogate>(
        transform = { i ->
            when (i) {
                is SharedFundingInput.Multisig2of2 -> SharedFundingInputSurrogate(i.info.outPoint, i.info.txOut.amount)
            }
        },
        delegateSerializer = SharedFundingInputSurrogate.serializer()
    )

    @Serializer(forClass = InteractiveTxParams::class)
    object InteractiveTxParamsSerializer

    @Serializer(forClass = SignedSharedTransaction::class)
    object SignedSharedTransactionSerializer

    @Serializable
    data class InteractiveTxSigningSessionSurrogate(val fundingParams: InteractiveTxParams, val fundingTxId: TxId)
    object InteractiveTxSigningSessionSerializer : SurrogateSerializer<InteractiveTxSigningSession, InteractiveTxSigningSessionSurrogate>(
        transform = { s -> InteractiveTxSigningSessionSurrogate(s.fundingParams, s.fundingTx.txId) },
        delegateSerializer = InteractiveTxSigningSessionSurrogate.serializer()
    )

    @Serializer(forClass = RbfStatus::class)
    object RbfStatusSerializer

    object SpliceStatusSerializer : StringSerializer<SpliceStatus>({ it::class.simpleName!! })

    @Serializer(forClass = LiquidityAds.Fees::class)
    object LiquidityFeesSerializer

    @Serializer(forClass = LiquidityAds.PaymentDetails::class)
    object LiquidityPaymentDetailsSerializer

    @Serializer(forClass = LiquidityAds.Purchase::class)
    object LiquidityPurchaseSerializer

    @Serializer(forClass = ChannelFlags::class)
    object ChannelFlagsSerializer

    @Serializer(forClass = ChannelParams::class)
    object ChannelParamsSerializer

    @Serializer(forClass = Origin::class)
    object ChannelOriginSerializer

    @Serializer(forClass = CommitmentChanges::class)
    object CommitmentChangesSerializer

    @Serializable
    data class LocalFundingStatusSurrogate(val status: String, val txId: TxId)
    object LocalFundingStatusSerializer : SurrogateSerializer<LocalFundingStatus, LocalFundingStatusSurrogate>(
        transform = { o ->
            when (o) {
                is LocalFundingStatus.UnconfirmedFundingTx -> LocalFundingStatusSurrogate("unconfirmed", o.txId)
                is LocalFundingStatus.ConfirmedFundingTx -> LocalFundingStatusSurrogate("confirmed", o.txId)
            }
        },
        delegateSerializer = LocalFundingStatusSurrogate.serializer()
    )

    @Serializable
    data class RemoteFundingStatusSurrogate(val status: String)
    object RemoteFundingStatusSerializer : SurrogateSerializer<RemoteFundingStatus, RemoteFundingStatusSurrogate>(
        transform = { o ->
            when (o) {
                RemoteFundingStatus.NotLocked -> RemoteFundingStatusSurrogate("not-locked")
                RemoteFundingStatus.Locked -> RemoteFundingStatusSurrogate("locked")
            }
        },
        delegateSerializer = RemoteFundingStatusSurrogate.serializer()
    )

    @Serializer(forClass = Commitment::class)
    object CommitmentSerializer

    @Serializer(forClass = Commitments::class)
    object CommitmentsSerializer

    @Serializer(forClass = LocalParams::class)
    object LocalParamsSerializer

    @Serializer(forClass = RemoteParams::class)
    object RemoteParamsSerializer

    @Serializer(forClass = LocalCommit::class)
    object LocalCommitSerializer

    @Serializer(forClass = RemoteCommit::class)
    object RemoteCommitSerializer

    @Serializer(forClass = NextRemoteCommit::class)
    object NextRemoteCommitSerializer

    @Serializer(forClass = LocalChanges::class)
    object LocalChangesSerializer

    @Serializer(forClass = RemoteChanges::class)
    object RemoteChangesSerializer

    /**
     * Delegate serialization of type [T] to serialization of type [S].
     * @param transform a conversion method from [T] to [S]
     * @param delegateSerializer serializer for [S]
     */
    sealed class SurrogateSerializer<T, S>(val transform: (T) -> S, private val delegateSerializer: KSerializer<S>) : KSerializer<T> {
        override val descriptor: SerialDescriptor get() = delegateSerializer.descriptor
        override fun serialize(encoder: Encoder, value: T) = delegateSerializer.serialize(encoder, transform(value))
        override fun deserialize(decoder: Decoder): T = TODO("json deserialization is not supported")
    }

    sealed class StringSerializer<T>(toString: (T) -> String = { it.toString() }) : SurrogateSerializer<T, String>(toString, String.serializer())
    sealed class LongSerializer<T>(toLong: (T) -> Long) : SurrogateSerializer<T, Long>(toLong, Long.serializer())

    object ShaChainSerializer : StringSerializer<ShaChain>({ "<redacted>" })
    object PrivateKeySerializer : StringSerializer<PrivateKey>({ "<redacted>" })
    object OnionRoutingPacketSerializer : StringSerializer<OnionRoutingPacket>({ "<redacted>" })
    object ByteVectorSerializer : StringSerializer<ByteVector>()
    object ByteVector32Serializer : StringSerializer<ByteVector32>()
    object ByteVector64Serializer : StringSerializer<ByteVector64>()
    object BlockHashSerializer : StringSerializer<BlockHash>()
    object PublicKeySerializer : StringSerializer<PublicKey>()
    object TxIdSerializer : StringSerializer<TxId>()
    object KeyPathSerializer : StringSerializer<KeyPath>()
    object ShortChannelIdSerializer : StringSerializer<ShortChannelId>()
    object OutPointSerializer : StringSerializer<OutPoint>({ "${it.txid}:${it.index}" })
    object TransactionSerializer : StringSerializer<Transaction>()

    @Serializer(forClass = PublishableTxs::class)
    object PublishableTxsSerializer

    @Serializable
    data class CommitmentsSpecSurrogate(val htlcsIn: List<UpdateAddHtlc>, val htlcsOut: List<UpdateAddHtlc>, val feerate: FeeratePerKw, val toLocal: MilliSatoshi, val toRemote: MilliSatoshi)
    object CommitmentSpecSerializer : SurrogateSerializer<CommitmentSpec, CommitmentsSpecSurrogate>(
        transform = { o ->
            CommitmentsSpecSurrogate(
                htlcsIn = o.htlcs.filterIsInstance<IncomingHtlc>().map { it.add },
                htlcsOut = o.htlcs.filterIsInstance<OutgoingHtlc>().map { it.add },
                feerate = o.feerate, toLocal = o.toLocal, toRemote = o.toRemote
            )
        },
        delegateSerializer = CommitmentsSpecSurrogate.serializer()
    )

    @Serializer(forClass = HtlcTxAndSigs::class)
    object HtlcTxAndSigsSerializer

    object ChannelConfigSerializer : SurrogateSerializer<ChannelConfig, List<String>>(
        transform = { o -> o.options.map { it.name } },
        delegateSerializer = ListSerializer(String.serializer())
    )

    object ChannelFeaturesSerializer : SurrogateSerializer<ChannelFeatures, List<String>>(
        transform = { o -> o.features.map { it.rfcName } },
        delegateSerializer = ListSerializer(String.serializer())
    )

    @Serializable
    data class FeaturesSurrogate(val activated: Map<String, String>, val unknown: Set<Int>)
    object FeaturesSerializer : SurrogateSerializer<Features, FeaturesSurrogate>(
        transform = { o -> FeaturesSurrogate(o.activated.map { it.key.rfcName to it.value.name }.toMap(), o.unknown.map { it.bitIndex }.toSet()) },
        delegateSerializer = FeaturesSurrogate.serializer()
    )

    @Serializable
    data class TxOutSurrogate(val amount: Satoshi, val publicKeyScript: ByteVector)
    object TxOutSerializer : SurrogateSerializer<TxOut, TxOutSurrogate>(
        transform = { o -> TxOutSurrogate(o.amount, o.publicKeyScript) },
        delegateSerializer = TxOutSurrogate.serializer()
    )

    object SatoshiSerializer : LongSerializer<Satoshi>({ it.toLong() })
    object MilliSatoshiSerializer : LongSerializer<MilliSatoshi>({ it.toLong() })
    object CltvExpirySerializer : LongSerializer<CltvExpiry>({ it.toLong() })
    object CltvExpiryDeltaSerializer : LongSerializer<CltvExpiryDelta>({ it.toLong() })
    object FeeratePerKwSerializer : LongSerializer<FeeratePerKw>({ it.toLong() })

    object ChannelKeysSerializer : SurrogateSerializer<KeyManager.ChannelKeys, KeyPath>(
        transform = { it.fundingKeyPath },
        delegateSerializer = KeyPathSerializer
    )

    @Serializer(forClass = LocalCommitPublished::class)
    object LocalCommitPublishedSerializer

    @Serializer(forClass = RemoteCommitPublished::class)
    object RemoteCommitPublishedSerializer

    @Serializer(forClass = RevokedCommitPublished::class)
    object RevokedCommitPublishedSerializer

    @Serializer(forClass = FundingSigned::class)
    object FundingSignedSerializer

    @Serializer(forClass = EncryptedChannelData::class)
    object EncryptedChannelDataSerializer

    @Serializer(forClass = UpdateAddHtlcTlv.PathKey::class)
    object UpdateAddHtlcTlvPathKeySerializer

    @Serializer(forClass = UpdateAddHtlcTlv::class)
    object UpdateAddHtlcTlvSerializer

    @Serializer(forClass = UpdateAddHtlc::class)
    object UpdateAddHtlcSerializer

    @Serializer(forClass = UpdateFulfillHtlc::class)
    object UpdateFulfillHtlcSerializer

    @Serializer(forClass = UpdateFailHtlc::class)
    object UpdateFailHtlcSerializer

    @Serializer(forClass = UpdateFailMalformedHtlc::class)
    object UpdateFailMalformedHtlcSerializer

    @Serializer(forClass = UpdateFee::class)
    object UpdateFeeSerializer

    @Serializer(forClass = ChannelUpdate::class)
    object ChannelUpdateSerializer

    @Serializer(forClass = ChannelAnnouncement::class)
    object ChannelAnnouncementSerializer

    @Serializer(forClass = Shutdown::class)
    object ShutdownSerializer

    @Serializer(forClass = ClosingComplete::class)
    object ClosingCompleteSerializer

    @Serializer(forClass = ClosingSig::class)
    object ClosingSigSerializer

    @Serializer(forClass = CommitSig::class)
    object CommitSigSerializer

    @Serializer(forClass = ChannelReestablish::class)
    object ChannelReestablishDataSerializer

    @Serializer(forClass = FundingCreated::class)
    object FundingCreatedSerializer

    @Serializer(forClass = ChannelReady::class)
    object ChannelReadySerializer

    @Serializer(forClass = ChannelReadyTlv.ShortChannelIdTlv::class)
    object ChannelReadyTlvShortChannelIdTlvSerializer

    @Serializer(forClass = ShutdownTlv.ChannelData::class)
    object ShutdownTlvChannelDataSerializer

    @Serializer(forClass = ShutdownTlv::class)
    object ShutdownTlvSerializer

    @Serializer(forClass = CommitSigTlv.AlternativeFeerateSig::class)
    object CommitSigTlvAlternativeFeerateSigSerializer

    @Serializer(forClass = CommitSigTlv.AlternativeFeerateSigs::class)
    object CommitSigTlvAlternativeFeerateSigsSerializer

    @Serializer(forClass = CommitSigTlv.Batch::class)
    object CommitSigTlvBatchSerializer

    @Serializer(forClass = CommitSigTlv::class)
    object CommitSigTlvSerializer

    @Serializer(forClass = ClosingCompleteTlv::class)
    object ClosingCompleteTlvSerializer

    @Serializer(forClass = ClosingSigTlv::class)
    object ClosingSigTlvSerializer

    @Serializer(forClass = ChannelReadyTlv::class)
    object ChannelReadyTlvSerializer

    @Serializer(forClass = ChannelReestablishTlv::class)
    object ChannelReestablishTlvSerializer

    @Serializer(forClass = GenericTlv::class)
    object GenericTlvSerializer

    @Serializable
    data class TlvStreamSurrogate(val records: Set<Tlv>, val unknown: Set<GenericTlv> = setOf())
    class TlvStreamSerializer<T : Tlv> : KSerializer<TlvStream<T>> {
        private val delegateSerializer = TlvStreamSurrogate.serializer()
        override val descriptor: SerialDescriptor = delegateSerializer.descriptor
        override fun serialize(encoder: Encoder, value: TlvStream<T>) =
            delegateSerializer.serialize(encoder, TlvStreamSurrogate(value.records, value.unknown))

        override fun deserialize(decoder: Decoder): TlvStream<T> = TODO("json deserialization is not supported")
    }

    class EitherSerializer<A : Any, B : Any>(val aSer: KSerializer<A>, val bSer: KSerializer<B>) : KSerializer<Either<A, B>> {
        @Serializable
        data class Surrogate<A : Any, B : Any>(val left: A?, val right: B?)

        override val descriptor = Surrogate.serializer(aSer, bSer).descriptor

        override fun serialize(encoder: Encoder, value: Either<A, B>) {
            val surrogate = Surrogate(value.left, value.right)
            return encoder.encodeSerializableValue(Surrogate.serializer(aSer, bSer), surrogate)
        }

        override fun deserialize(decoder: Decoder): Either<A, B> = TODO("json deserialization is not supported")
    }

    @Serializer(forClass = WaitingForRevocation::class)
    object WaitingForRevocationSerializer

    object UUIDSerializer : StringSerializer<UUID>()

    @Serializer(forClass = TaggedField.ExtraHop::class)
    object Bolt11ExtraHopSerializer

    @Serializer(forClass = TaggedField.UnknownTag::class)
    object Bolt11UnknownTagSerializer

    @Serializer(forClass = TaggedField.InvalidTag::class)
    object Bolt11InvalidTagSerializer

    @Serializable
    data class Bolt11InvoiceSurrogate(
        val chain: String,
        val amount: MilliSatoshi?,
        val paymentHash: ByteVector32,
        val description: String?,
        val descriptionHash: ByteVector32?,
        val minFinalCltvExpiryDelta: CltvExpiryDelta?,
        val paymentSecret: ByteVector32,
        val paymentMetadata: ByteVector?,
        val expirySeconds: Long?,
        val extraHops: List<List<TaggedField.ExtraHop>>,
        val features: Features?,
        val timestampSeconds: Long,
        val unknownTags: List<TaggedField.UnknownTag>?,
        val invalidTags: List<TaggedField.InvalidTag>?,
    )

    object Bolt11InvoiceSerializer : SurrogateSerializer<Bolt11Invoice, Bolt11InvoiceSurrogate>(
        transform = { o ->
            Bolt11InvoiceSurrogate(
                chain = o.chain?.name?.lowercase() ?: "unknown",
                amount = o.amount,
                paymentHash = o.paymentHash,
                description = o.description,
                descriptionHash = o.descriptionHash,
                minFinalCltvExpiryDelta = o.minFinalExpiryDelta,
                paymentSecret = o.paymentSecret,
                paymentMetadata = o.paymentMetadata,
                expirySeconds = o.expirySeconds,
                extraHops = o.routingInfo.map { it.hints },
                features = o.features.let { if (it == Features.empty) null else it },
                timestampSeconds = o.timestampSeconds,
                unknownTags = o.tags.filterIsInstance<TaggedField.UnknownTag>().run { ifEmpty { null } },
                invalidTags = o.tags.filterIsInstance<TaggedField.InvalidTag>().run { ifEmpty { null } }
            )
        },
        delegateSerializer = Bolt11InvoiceSurrogate.serializer()
    )

    @Serializable
    data class EncodedNodeIdSurrogate(val isNode1: Boolean?, val scid: ShortChannelId?, val publicKey: PublicKey?, val walletPublicKey: PublicKey?)
    object EncodedNodeIdSerializer : SurrogateSerializer<EncodedNodeId, EncodedNodeIdSurrogate>(
        transform = { o ->
            when (o) {
                is EncodedNodeId.WithPublicKey.Plain -> EncodedNodeIdSurrogate(isNode1 = null, scid = null, publicKey = o.publicKey, walletPublicKey = null)
                is EncodedNodeId.WithPublicKey.Wallet -> EncodedNodeIdSurrogate(isNode1 = null, scid = null, publicKey = null, walletPublicKey = o.publicKey)
                is EncodedNodeId.ShortChannelIdDir -> EncodedNodeIdSurrogate(isNode1 = o.isNode1, scid = o.scid, publicKey = null, walletPublicKey = null)
            }
        },
        delegateSerializer = EncodedNodeIdSurrogate.serializer()
    )

    @Serializer(forClass = RouteBlinding.BlindedHop::class)
    object BlindedHopSerializer

    @Serializer(forClass = RouteBlinding.BlindedRoute::class)
    object BlindedRouteSerializer

    @Serializable
    data class OfferSurrogate(
        val chain: String,
        val chainHashes: List<BlockHash>?,
        val amount: MilliSatoshi?,
        val currency: String?,
        val issuer: String?,
        val quantityMax: Long?,
        val description: String?,
        val metadata: ByteVector?,
        val expirySeconds: Long?,
        val issuerId: PublicKey?,
        val path: List<RouteBlinding.BlindedRoute>?,
        val features: Features?,
        val unknownTlvs: List<GenericTlv>?
    )
    object OfferSerializer : SurrogateSerializer<OfferTypes.Offer, OfferSurrogate>(
        transform = { o ->
            OfferSurrogate(
                chain = when {
                    o.chains.isEmpty() -> Chain.Mainnet.name
                    o.chains.contains(Chain.Mainnet.chainHash) && o.chains.size == 1 -> Chain.Mainnet.name
                    o.chains.contains(Chain.Testnet3.chainHash) && o.chains.size == 1 -> Chain.Testnet3.name
                    o.chains.contains(Chain.Testnet4.chainHash) && o.chains.size == 1 -> Chain.Testnet4.name
                    o.chains.contains(Chain.Regtest.chainHash) && o.chains.size == 1 -> Chain.Regtest.name
                    else -> "unknown"
                }.lowercase(),
                chainHashes = o.records.get<OfferChains>()?.chains,
                amount = o.amount,
                currency = o.currency,
                issuer = o.issuer,
                quantityMax = o.quantityMax,
                description = o.description,
                metadata = o.metadata,
                expirySeconds = o.expirySeconds,
                issuerId = o.issuerId,
                path = o.paths?.map { it.route }?.run { ifEmpty { null } },
                features = o.features.let { if (it == Features.empty) null else it },
                unknownTlvs = o.records.unknown.toList().run { ifEmpty { null } }
            )
        },
        delegateSerializer = OfferSurrogate.serializer()
    )
}
