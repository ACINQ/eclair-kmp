package fr.acinq.lightning.io

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.blockchain.IClient
import fr.acinq.lightning.blockchain.IWatcher
import fr.acinq.lightning.blockchain.WatchEvent
import fr.acinq.lightning.blockchain.computeSpliceCpfpFeerate
import fr.acinq.lightning.blockchain.electrum.*
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.blockchain.mempool.MempoolSpaceClient
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.states.*
import fr.acinq.lightning.crypto.noise.*
import fr.acinq.lightning.db.*
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.logging.mdc
import fr.acinq.lightning.logging.withMDC
import fr.acinq.lightning.payment.*
import fr.acinq.lightning.serialization.channel.Encryption.from
import fr.acinq.lightning.serialization.channel.Serialization.DeserializationResult
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import fr.acinq.lightning.wire.Ping
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.Channel.Factory.UNLIMITED
import kotlinx.coroutines.channels.onFailure
import kotlinx.coroutines.flow.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

sealed class PeerCommand

/** Open a channel, consuming all the spendable utxos in the wallet state provided. */
data class OpenChannel(
    val fundingAmount: Satoshi,
    val walletInputs: List<WalletState.Utxo>,
    val commitTxFeerate: FeeratePerKw,
    val fundingTxFeerate: FeeratePerKw,
    val channelType: ChannelType.SupportedChannelType
) : PeerCommand()

/** Consume all the spendable utxos in the wallet state provided to open a channel or splice into an existing channel. */
data class AddWalletInputsToChannel(val walletInputs: List<WalletState.Utxo>) : PeerCommand() {
    val totalAmount: Satoshi = walletInputs.map { it.amount }.sum()
}

/**
 * Initiate a channel open or a splice to allow receiving an off-chain payment.
 *
 * @param paymentAmount total amount of the off-chain payment (before fees are paid).
 * @param requestedAmount requested inbound liquidity, which will allow receiving the off-chain payment.
 * @param fundingRate funding rate applied by our peer for this amount.
 * @param preimage preimage of the off-chain payment.
 * @param willAddHtlcs HTLCs that will be relayed to us once additional liquidity is available.
 */
data class AddLiquidityForIncomingPayment(val paymentAmount: MilliSatoshi, val requestedAmount: Satoshi, val fundingRate: LiquidityAds.FundingRate, val preimage: ByteVector32, val willAddHtlcs: List<WillAddHtlc>) : PeerCommand() {
    val paymentHash: ByteVector32 = Crypto.sha256(preimage.toByteArray()).byteVector32()

    fun fees(fundingFeerate: FeeratePerKw, isChannelCreation: Boolean): LiquidityAds.Fees = fundingRate.fees(fundingFeerate, requestedAmount, requestedAmount, isChannelCreation)

    companion object {
        /**
         * When we open a new channel without contributing any input, we won't be able to pay on-chain fees for our
         * weight of the funding transaction. If we don't do anything, the resulting transaction will thus have a
         * lower feerate than requested and may not confirm.
         *
         * To avoid that, we ask our peer to target a higher feerate than the one we actually want. They will pay
         * more mining fees to satisfy that feerate, while we won't pay any mining fees. We should be paying for the
         * shared output, which doesn't add too much weight, so we add 25%. This is hacky but should result in an
         * effective feerate that is somewhat close to the initial feerate we wanted. Note that we will pay liquidity
         * fees based on this inflated feerate, which will refund our peer for this hack.
         */
        const val ChannelOpenFeerateRatio = 1.25

        /**
         * When our balance is low, we won't be able to pay the mining fees for our weight of the splice transaction.
         * If we don't do anything, the resulting transaction will thus have a lower feerate than requested and may
         * not confirm.
         *
         * To avoid that, we ask our peer to target a higher feerate than the one we actually want. They will pay more
         * mining fees to satisfy that feerate, while we'll pay whatever we can from our current balance. We should be
         * paying for the shared input and shared output, which is a lot of weight, so we add 50%. This is hacky but
         * should result in an effective feerate that is somewhat close to the initial feerate we wanted. Note that we
         * will pay liquidity fees based on the inflated feerate, which will refund our peer for this hack.
         */
        const val SpliceWithNoBalanceFeerateRatio = 1.5
    }
}

data class PeerConnection(val id: Long, val output: Channel<LightningMessage>, val logger: MDCLogger) {
    fun send(msg: LightningMessage) {
        // We can safely use trySend because we use unlimited channel buffers.
        // If the connection was closed, the message will automatically be dropped.
        val result = output.trySend(msg)
        result.onFailure { failure ->
            when (msg) {
                is Ping -> logger.warning { "cannot send $msg: ${failure?.message}" } // no need to display the full stack trace for pings, they will spam the logs when user is disconnected
                else -> logger.warning(failure) { "cannot send $msg" }
            }
        }
    }
}

data class Connected(val peerConnection: PeerConnection) : PeerCommand()
data class MessageReceived(val connectionId: Long, val msg: LightningMessage) : PeerCommand()
data class WatchReceived(val watch: WatchEvent) : PeerCommand()
data class WrappedChannelCommand(val channelId: ByteVector32, val channelCommand: ChannelCommand) : PeerCommand()
data object Disconnected : PeerCommand()

sealed class PaymentCommand : PeerCommand()
private data object CheckPaymentsTimeout : PaymentCommand()
private data class CheckInvoiceRequestTimeout(val pathId: ByteVector32, val payOffer: PayOffer) : PaymentCommand()

// @formatter:off
sealed class SendPayment : PaymentCommand() {
    abstract val paymentId: UUID
    abstract val amount: MilliSatoshi
}
data class PayInvoice(override val paymentId: UUID, override val amount: MilliSatoshi, val paymentDetails: LightningOutgoingPayment.Details, val trampolineFeesOverride: List<TrampolineFees>? = null) : SendPayment() {
    val paymentHash: ByteVector32 = paymentDetails.paymentHash
    val recipient: PublicKey = paymentDetails.paymentRequest.nodeId
}
data class PayOffer(override val paymentId: UUID, val payerKey: PrivateKey, val payerNote: String?, override val amount: MilliSatoshi, val offer: OfferTypes.Offer, val fetchInvoiceTimeout: Duration, val trampolineFeesOverride: List<TrampolineFees>? = null) : SendPayment()
// @formatter:on

data class PurgeExpiredPayments(val fromCreatedAt: Long, val toCreatedAt: Long) : PaymentCommand()

data class SendOnionMessage(val message: OnionMessage) : PeerCommand()
data class SendOnTheFlyFundingMessage(val message: OnTheFlyFundingMessage) : PeerCommand()

sealed class PeerEvent

data class PaymentProgress(val request: SendPayment, val fees: MilliSatoshi) : PeerEvent()
sealed class SendPaymentResult : PeerEvent() {
    abstract val request: SendPayment
}
/** We couldn't obtain a valid invoice to pay the corresponding offer. */
data class OfferNotPaid(override val request: PayOffer, val reason: Bolt12InvoiceRequestFailure) : SendPaymentResult()
/** We couldn't pay the corresponding invoice. */
data class PaymentNotSent(override val request: PayInvoice, val reason: OutgoingPaymentFailure) : SendPaymentResult()
/** We successfully paid the corresponding request. */
data class PaymentSent(override val request: PayInvoice, val payment: LightningOutgoingPayment) : SendPaymentResult()

data class OfferInvoiceReceived(val request: PayOffer, val invoice: Bolt12Invoice) : PeerEvent()
data class ChannelClosing(val channelId: ByteVector32) : PeerEvent()

/**
 * Useful to handle transparent migration on Phoenix Android between eclair-core and lightning-kmp.
 */
data class PhoenixAndroidLegacyInfoEvent(val info: PhoenixAndroidLegacyInfo) : PeerEvent()

data class AddressAssigned(val address: String) : PeerEvent()

/**
 * The peer we establish a connection to. This object contains the TCP socket, a flow of the channels with that peer, and watches
 * the events on those channels and processes the relevant actions. The dialogue with the peer is done in coroutines.
 *
 * @param nodeParams Low level, Lightning related parameters that our node will use in relation to this Peer.
 * @param walletParams High level parameters for our node. It especially contains the Peer's [NodeUri].
 * @param watcher Watches events from the Electrum client and publishes transactions and events.
 * @param db Wraps the various databases persisting the channels and payments data related to the Peer.
 * @param socketBuilder Builds the TCP socket used to connect to the Peer.
 * @param initTlvStream Optional stream of TLV for the [Init] message we send to this Peer after connection. Empty by default.
 */
@OptIn(ExperimentalStdlibApi::class)
class Peer(
    val nodeParams: NodeParams,
    val walletParams: WalletParams,
    val client: IClient,
    val watcher: IWatcher,
    val db: Databases,
    socketBuilder: TcpSocket.Builder?,
    scope: CoroutineScope,
    private val initTlvStream: TlvStream<InitTlv> = TlvStream.empty()
) : CoroutineScope by scope {
    companion object {
        private const val prefix: Byte = 0x00
        private val prologue = "lightning".encodeToByteArray()
    }

    var socketBuilder: TcpSocket.Builder? = socketBuilder
        set(value) {
            logger.debug { "swap socket builder=$value" }
            field = value
        }

    val remoteNodeId: PublicKey = walletParams.trampolineNode.id

    // We use unlimited buffers, otherwise we may end up in a deadlock since we're both
    // receiving *and* sending to those channels in the same coroutine.
    private val input = Channel<PeerCommand>(UNLIMITED)

    private val swapInCommands = Channel<SwapInCommand>(UNLIMITED)

    private val logger = MDCLogger(logger = nodeParams.loggerFactory.newLogger(this::class), staticMdc = mapOf("remoteNodeId" to remoteNodeId))

    // The channels map, as initially loaded from the database at "boot" (on Peer.init).
    // As the channelsFlow is unavailable until the electrum connection is up-and-running,
    // this may provide useful information for the UI.
    private val _bootChannelsFlow = MutableStateFlow<Map<ByteVector32, ChannelState>?>(null)
    val bootChannelsFlow: StateFlow<Map<ByteVector32, ChannelState>?> get() = _bootChannelsFlow

    // channels map, indexed by channel id
    // note that a channel starts with a temporary id then switches to its final id once accepted
    private val _channelsFlow = MutableStateFlow<Map<ByteVector32, ChannelState>>(HashMap())
    val channelsFlow: StateFlow<Map<ByteVector32, ChannelState>> get() = _channelsFlow

    private var _channels by _channelsFlow
    val channels: Map<ByteVector32, ChannelState> get() = _channelsFlow.value

    private val _connectionState = MutableStateFlow<Connection>(Connection.CLOSED(null))
    val connectionState: StateFlow<Connection> get() = _connectionState

    private val _eventsFlow = MutableSharedFlow<PeerEvent>(replay = 0, extraBufferCapacity = 64, onBufferOverflow = BufferOverflow.SUSPEND)
    val eventsFlow: SharedFlow<PeerEvent> get() = _eventsFlow.asSharedFlow()

    // encapsulates logic for validating incoming payments
    private val incomingPaymentHandler = IncomingPaymentHandler(nodeParams, db.payments)

    // encapsulates logic for sending payments
    private val outgoingPaymentHandler = OutgoingPaymentHandler(nodeParams, walletParams, db.payments)

    private val features = nodeParams.features

    private val ourInit = Init(features.initFeatures(), initTlvStream)
    private var theirInit: Init? = null

    val currentTipFlow = MutableStateFlow<Int?>(null)
    val onChainFeeratesFlow = MutableStateFlow<OnChainFeerates?>(null)
    val peerFeeratesFlow = MutableStateFlow<RecommendedFeerates?>(null)
    val remoteFundingRates = MutableStateFlow<LiquidityAds.WillFundRates?>(null)
    val feeCreditFlow = MutableStateFlow<MilliSatoshi>(0.msat)

    private val _channelLogger = nodeParams.loggerFactory.newLogger(ChannelState::class)
    private suspend fun ChannelState.process(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        val state = this
        val ctx = ChannelContext(
            StaticParams(nodeParams, remoteNodeId),
            currentTipFlow.filterNotNull().first(),
            onChainFeeratesFlow,
            logger = MDCLogger(
                logger = _channelLogger,
                staticMdc = mapOf("remoteNodeId" to remoteNodeId) + state.mdc()
            )
        )
        return state.run { ctx.process(cmd) }
            .also { (state1, _) ->
                if (state1::class != state::class) {
                    ctx.logger.info { "${state.stateName} -> ${state1.stateName}" }
                }
            }
    }

    val finalWallet = (client as? IElectrumClient)?.let { electrumClient -> FinalWallet(nodeParams.chain, nodeParams.keyManager.finalOnChainWallet, electrumClient, scope, nodeParams.loggerFactory) }
    val swapInWallet = (client as? IElectrumClient)?.let { electrumClient -> SwapInWallet(nodeParams.chain, nodeParams.keyManager.swapInOnChainWallet, electrumClient, scope, nodeParams.loggerFactory) }

    private var swapInJob: Job? = null

    private val offerManager = OfferManager(nodeParams, walletParams, _eventsFlow, logger)

    init {
        logger.info { "initializing peer" }
        launch {
            when (client) {
                is IElectrumClient -> client.notifications.filterIsInstance<HeaderSubscriptionResponse>()
                    .collect { msg ->
                        currentTipFlow.value = msg.blockHeight
                    }
                is MempoolSpaceClient -> while (true) {
                    runCatching {
                        client.getBlockTipHeight()?.let { currentBlockHeight ->
                            logger.debug { "current block height is $currentBlockHeight" }
                            currentTipFlow.value = currentBlockHeight
                        }
                    }
                    delay(1.minutes)
                }
            }

        }
        launch {
            suspend fun updateFeerates() {
                client.getFeerates()?.let { feerates ->
                    logger.info { "on-chain fees: $feerates" }
                    onChainFeeratesFlow.value = OnChainFeerates(feerates)
                } ?: logger.error { "cannot retrieve feerates!" }
            }

            when (client) {
                is IElectrumClient -> client.connectionStatus.filter { it is ElectrumConnectionStatus.Connected }.collect {
                    // onchain fees are retrieved punctually, when electrum status moves to Connection.ESTABLISHED
                    // since the application is not running most of the time, and when it is, it will be only for a few minutes, this is good enough.
                    // (for a node that is online most of the time things would be different and we would need to re-evaluate onchain fee estimates on a regular basis)
                    updateFeerates()
                }
                is MempoolSpaceClient -> while (true) {
                    updateFeerates()
                    delay(3.minutes)
                }
            }
        }
        launch {
            watcher.openWatchNotificationsFlow().collect {
                logger.debug { "notification: $it" }
                input.send(WrappedChannelCommand(it.channelId, ChannelCommand.WatchReceived(it)))
            }
        }
        launch {
            // we don't restore closed channels
            val bootChannels = db.channels.listLocalChannels().filterNot { it is Closed || it is LegacyWaitForFundingConfirmed }
            _bootChannelsFlow.value = bootChannels.associateBy { it.channelId }
            val channelIds = bootChannels.map {
                logger.info { "restoring channel ${it.channelId} from local storage" }
                val state = WaitForInit
                val (state1, actions) = state.process(ChannelCommand.Init.Restore(it))
                processActions(it.channelId, peerConnection, actions)
                _channels = _channels + (it.channelId to state1)
                it.channelId
            }
            logger.info { "restored ${channelIds.size} channels" }
            launch {
                // the swap-in manager executes commands, but will not do anything until startWatchSwapInWallet() is called
                val swapInManager = SwapInManager(bootChannels, logger)
                processSwapInCommands(swapInManager)
            }
            launch {
                // If we have some htlcs that have timed out, we may need to close channels to ensure we don't lose funds.
                // But maybe we were offline for too long and it is why our peer couldn't settle these htlcs in time.
                // We give them a bit of time after we reconnect to send us their latest htlc updates.
                delay(nodeParams.checkHtlcTimeoutAfterStartupDelay)
                logger.info { "checking for timed out htlcs for channels: ${channelIds.joinToString(", ")}" }
                channelIds.forEach { input.send(WrappedChannelCommand(it, ChannelCommand.Commitment.CheckHtlcTimeout)) }
            }
            run()
        }
        launch {
            var previousState = connectionState.value
            connectionState.filter { it != previousState }.collect {
                logger.info { "connection state changed: ${it::class.simpleName}" }
                previousState = it
            }
        }

        launch {
            reloadOffersFromPersistance()
        }
    }

    data class ConnectionJob(val job: Job, val socket: TcpSocket) {
        fun cancel() {
            job.cancel()
            socket.close()
        }
    }

    private var connectionJob: ConnectionJob? = null

    suspend fun connect(connectTimeout: Duration, handshakeTimeout: Duration): Boolean {
        return if (connectionState.value is Connection.CLOSED) {
            // Clean up previous connection state: we do this here to ensure that it is handled before the Connected event for the new connection.
            // That means we're not sending this event if we don't reconnect. It's ok, since that has the same effect as not detecting a disconnection and closing the app.
            input.send(Disconnected)
            _connectionState.value = Connection.ESTABLISHING

            val connectionId = currentTimestampMillis()
            val logger = MDCLogger(logger = nodeParams.loggerFactory.newLogger(this::class), staticMdc = mapOf("remoteNodeId" to remoteNodeId, "connectionId" to connectionId))
            logger.info { "connecting to ${walletParams.trampolineNode.host}" }
            val socket = openSocket(connectTimeout) ?: return false

            val priv = nodeParams.nodePrivateKey
            val pub = priv.publicKey()
            val keyPair = Pair(pub.value.toByteArray(), priv.value.toByteArray())
            val (enc, dec, ck) = try {
                withTimeout(handshakeTimeout) {
                    handshake(
                        keyPair,
                        remoteNodeId.value.toByteArray(),
                        { s -> socket.receiveFully(s) },
                        { b -> socket.send(b) }
                    )
                }
            } catch (ex: Throwable) {
                logger.warning(ex) { "Noise handshake: ${ex.message}: " }
                socket.close()
                _connectionState.value = Connection.CLOSED(ex as? TcpSocket.IOException)
                return false
            }

            val session = LightningSession(enc, dec, ck)
            _connectionState.value = Connection.ESTABLISHED
            // TODO use atomic counter instead
            val peerConnection = PeerConnection(connectionId, Channel(UNLIMITED), logger)
            // Inform the peer about the new connection.
            input.send(Connected(peerConnection))
            connectionJob = connectionLoop(socket, session, peerConnection, logger)
            true
        } else {
            logger.warning { "Peer is already connecting / connected" }
            false
        }
    }

    fun disconnect() {
        connectionJob?.cancel()
        connectionJob = null
        _connectionState.value = Connection.CLOSED(null)
    }

    private suspend fun openSocket(timeout: Duration): TcpSocket? {
        var socket: TcpSocket? = null
        return try {
            withTimeout(timeout) {
                socket = socketBuilder?.connect(
                    host = walletParams.trampolineNode.host,
                    port = walletParams.trampolineNode.port,
                    tls = TcpSocket.TLS.DISABLED,
                    loggerFactory = nodeParams.loggerFactory
                ) ?: error("socket builder is null.")
                socket
            }
        } catch (ex: Throwable) {
            logger.warning(ex) { "TCP connect: ${ex.message}: " }
            val ioException = when (ex) {
                is TcpSocket.IOException -> ex
                else -> TcpSocket.IOException.ConnectionRefused(ex)
            }
            socket?.close()
            _connectionState.value = Connection.CLOSED(ioException)
            null
        }
    }

    private fun connectionLoop(socket: TcpSocket, session: LightningSession, peerConnection: PeerConnection, logger: MDCLogger): ConnectionJob {
        val job = launch {
            fun closeSocket(ex: TcpSocket.IOException?) {
                if (_connectionState.value is Connection.CLOSED) return
                logger.warning { "closing TCP socket: ${ex?.message}" }
                socket.close()
                _connectionState.value = Connection.CLOSED(ex)
                cancel()
            }

            suspend fun doPing() {
                val ping = Ping(10, ByteVector("deadbeef"))
                while (isActive) {
                    delay(nodeParams.pingInterval)
                    peerConnection.send(ping)
                }
            }

            suspend fun checkPaymentsTimeout() {
                while (isActive) {
                    delay(nodeParams.checkHtlcTimeoutInterval)
                    input.send(CheckPaymentsTimeout)
                }
            }

            suspend fun receiveLoop() {
                try {
                    while (isActive) {
                        val received = session.receive { size -> socket.receiveFully(size) }
                        try {
                            val msg = LightningMessage.decode(received)
                            input.send(MessageReceived(peerConnection.id, msg))
                        } catch (e: Throwable) {
                            logger.warning { "cannot deserialize message: ${received.byteVector().toHex()}" }
                        }
                    }
                    closeSocket(null)
                } catch (ex: Throwable) {
                    logger.warning { "TCP receive: ${ex.message}" }
                    closeSocket(ex as? TcpSocket.IOException)
                } finally {
                    peerConnection.output.close()
                }
            }

            suspend fun sendLoop() {
                try {
                    for (msg in peerConnection.output) {
                        when (msg) {
                            is Ping -> {} // Avoids polluting the logs with pings/pongs
                            is Pong -> {}
                            is OnionMessage -> logger.info { "sending ${msg.copy(onionRoutingPacket = msg.onionRoutingPacket.copy(payload = ByteVector.empty))} (truncated payload)" } // Not printing the payload, which can be very large
                            else -> logger.info { "sending $msg" }
                        }
                        val encoded = LightningMessage.encode(msg)
                        session.send(encoded) { data, flush -> socket.send(data, flush) }
                    }
                } catch (ex: Throwable) {
                    logger.warning { "TCP send: ${ex.message}" }
                    closeSocket(ex as? TcpSocket.IOException)
                } finally {
                    peerConnection.output.close()
                }
            }

            launch(CoroutineName("keep-alive")) { doPing() }
            launch(CoroutineName("check-payments-timeout")) { checkPaymentsTimeout() }
            launch(CoroutineName("send-loop")) { sendLoop() }
            val receiveJob = launch(CoroutineName("receive-loop")) { receiveLoop() }
            // Suspend until the coroutine is cancelled or the socket is closed.
            receiveJob.join()
        }

        return ConnectionJob(job, socket)
    }

    /** We try swapping funds in whenever one of those fields is updated. */
    data class TrySwapInFlow(val currentBlockHeight: Int, val walletState: WalletState, val feerate: FeeratePerKw, val liquidityPolicy: LiquidityPolicy)

    /**
     * This function needs to be called after [Peer] is initialized, to start watching the swap-in wallet
     * and trigger swap-ins.
     * Warning: not thread-safe!
     */
    suspend fun startWatchSwapInWallet() {
        when {
            swapInWallet == null -> logger.warning { "swap-in wallet unavailable" }
            else -> {
                logger.info { "starting swap-in watch job" }
                if (swapInJob != null) {
                    logger.info { "swap-in watch job already started" }
                    return
                }
                logger.info { "waiting for peer to be ready" }
                waitForPeerReady()
                swapInJob = launch {
                    swapInWallet.wallet.walletStateFlow
                        .combine(currentTipFlow.filterNotNull()) { walletState, currentTip -> Pair(walletState, currentTip) }
                        .combine(peerFeeratesFlow.filterNotNull()) { (walletState, currentTip), feerates -> Triple(walletState, currentTip, feerates.fundingFeerate) }
                        .combine(nodeParams.liquidityPolicy) { (walletState, currentTip, feerate), policy -> TrySwapInFlow(currentTip, walletState, feerate, policy) }
                        .collect { w -> swapInCommands.send(SwapInCommand.TrySwapIn(w.currentBlockHeight, w.walletState, walletParams.swapInParams)) }
                }
            }
        }
    }

    suspend fun stopWatchSwapInWallet() {
        logger.info { "stopping swap-in watch job" }
        swapInJob?.cancelAndJoin()
        swapInJob = null
    }

    private suspend fun processSwapInCommands(swapInManager: SwapInManager) {
        for (command in swapInCommands) {
            swapInManager.process(command)?.let { requestChannelOpen -> input.send(requestChannelOpen) }
        }
    }

    suspend fun send(cmd: PeerCommand) {
        input.send(cmd)
    }

    /**
     * This function blocks until the peer is connected and existing channels have been fully reestablished.
     */
    private suspend fun waitForPeerReady() {
        // In theory we would only need to verify that no channel is in state Offline/Syncing, but there is a corner
        // case where a channel permanently stays in Syncing, because it is only present locally, and the peer will
        // never send a channel_reestablish (this happens e.g. due to an error at funding). That is why we consider
        // the peer ready if "all channels are synced" OR "peer has been connected for 10s".
        _peerConnection.filterNotNull().first()
        val result = withTimeoutOrNull(10.seconds) {
            channelsFlow.first { it.values.all { channel -> channel !is Offline && channel !is Syncing } }
        }
        if (result == null) {
            logger.info { "peer ready timeout elapsed, not all channels are synced but proceeding anyway" }
        }
    }

    /**
     * Estimate the actual feerate to use (and corresponding fee to pay) in order to reach the target feerate
     * for a splice out, taking into account potential unconfirmed parent splices.
     */
    suspend fun estimateFeeForSpliceOut(amount: Satoshi, scriptPubKey: ByteVector, targetFeerate: FeeratePerKw): Pair<FeeratePerKw, ChannelManagementFees>? {
        return channels.values
            .filterIsInstance<Normal>()
            .firstOrNull { it.commitments.availableBalanceForSend() > amount }
            ?.let { channel ->
                val weight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = channel.commitments.active.first(), walletInputs = emptyList(), localOutputs = listOf(TxOut(amount, scriptPubKey)))
                val (actualFeerate, miningFee) = client.computeSpliceCpfpFeerate(channel.commitments, targetFeerate, spliceWeight = weight, logger)
                Pair(actualFeerate, ChannelManagementFees(miningFee, 0.sat))
            }
    }

    /**
     * Estimate the actual feerate to use (and corresponding fee to pay) in order to reach the target feerate
     * for a cpfp splice.
     * @return The adjusted feerate to use in [spliceCpfp], such that the whole transaction chain has a feerate equivalent
     *         to [targetFeerate].
     *         NB: if the output feerate is equal to the input feerate then the cpfp is useless and
     *         should not be attempted.
     */
    suspend fun estimateFeeForSpliceCpfp(channelId: ByteVector32, targetFeerate: FeeratePerKw): Pair<FeeratePerKw, ChannelManagementFees>? {
        return channels.values
            .filterIsInstance<Normal>()
            .find { it.channelId == channelId }
            ?.let { channel ->
                val weight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = channel.commitments.active.first(), walletInputs = emptyList(), localOutputs = emptyList())
                val (actualFeerate, miningFee) = client.computeSpliceCpfpFeerate(channel.commitments, targetFeerate, spliceWeight = weight, logger)
                Pair(actualFeerate, ChannelManagementFees(miningFee, 0.sat))
            }
    }

    /**
     * Estimate the actual feerate to use (and corresponding fee to pay) to purchase inbound liquidity with a splice
     * that reaches the target feerate.
     */
    suspend fun estimateFeeForInboundLiquidity(amount: Satoshi, targetFeerate: FeeratePerKw, fundingRate: LiquidityAds.FundingRate): Pair<FeeratePerKw, ChannelManagementFees>? {
        return channels.values
            .filterIsInstance<Normal>()
            .firstOrNull()
            ?.let { channel ->
                val weight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = channel.commitments.active.first(), walletInputs = emptyList(), localOutputs = emptyList()) + fundingRate.fundingWeight
                // The mining fee below pays for the entirety of the splice transaction, including inputs and outputs from the liquidity provider.
                val (actualFeerate, miningFee) = client.computeSpliceCpfpFeerate(channel.commitments, targetFeerate, spliceWeight = weight, logger)
                // The mining fee below only covers the remote node's inputs and outputs, which are already included in the mining fee above.
                val fundingFees = fundingRate.fees(actualFeerate, amount, amount, isChannelCreation = false)
                Pair(actualFeerate, ChannelManagementFees(miningFee, fundingFees.serviceFee))
            }
    }

    /**
     * Do a splice out using any suitable channel.
     *
     * @return [ChannelFundingResponse] if a splice was attempted, or {null} if no suitable channel was found
     */
    suspend fun spliceOut(amount: Satoshi, scriptPubKey: ByteVector, feerate: FeeratePerKw): ChannelFundingResponse? {
        return channels.values
            .filterIsInstance<Normal>()
            .firstOrNull { it.commitments.availableBalanceForSend() > amount }
            ?.let { channel ->
                val spliceCommand = ChannelCommand.Commitment.Splice.Request(
                    replyTo = CompletableDeferred(),
                    spliceIn = null,
                    spliceOut = ChannelCommand.Commitment.Splice.Request.SpliceOut(amount, scriptPubKey),
                    requestRemoteFunding = null,
                    currentFeeCredit = feeCreditFlow.value,
                    feerate = feerate,
                    origins = listOf(),
                )
                send(WrappedChannelCommand(channel.channelId, spliceCommand))
                spliceCommand.replyTo.await()
            }
    }

    suspend fun spliceCpfp(channelId: ByteVector32, feerate: FeeratePerKw): ChannelFundingResponse? {
        return channels.values
            .filterIsInstance<Normal>()
            .find { it.channelId == channelId }
            ?.let { channel ->
                val spliceCommand = ChannelCommand.Commitment.Splice.Request(
                    replyTo = CompletableDeferred(),
                    // no additional inputs or outputs, the splice is only meant to bump fees
                    spliceIn = null,
                    spliceOut = null,
                    requestRemoteFunding = null,
                    currentFeeCredit = feeCreditFlow.value,
                    feerate = feerate,
                    origins = listOf(),
                )
                send(WrappedChannelCommand(channel.channelId, spliceCommand))
                spliceCommand.replyTo.await()
            }
    }

    suspend fun requestInboundLiquidity(amount: Satoshi, feerate: FeeratePerKw, fundingRate: LiquidityAds.FundingRate): ChannelFundingResponse? {
        return channels.values
            .filterIsInstance<Normal>()
            .firstOrNull()
            ?.let { channel ->
                val spliceCommand = ChannelCommand.Commitment.Splice.Request(
                    replyTo = CompletableDeferred(),
                    spliceIn = null,
                    spliceOut = null,
                    requestRemoteFunding = LiquidityAds.RequestFunding(amount, fundingRate, LiquidityAds.PaymentDetails.FromChannelBalance),
                    currentFeeCredit = feeCreditFlow.value,
                    feerate = feerate,
                    origins = listOf(),
                )
                send(WrappedChannelCommand(channel.channelId, spliceCommand))
                spliceCommand.replyTo.await()
            }
    }

    suspend fun payInvoice(amount: MilliSatoshi, paymentRequest: Bolt11Invoice): SendPaymentResult {
        val res = CompletableDeferred<SendPaymentResult>()
        val paymentId = UUID.randomUUID()
        this.launch {
            res.complete(eventsFlow
                .filterIsInstance<SendPaymentResult>()
                .filter { it.request.paymentId == paymentId }
                .first()
            )
        }
        send(PayInvoice(paymentId, amount, LightningOutgoingPayment.Details.Normal(paymentRequest)))
        return res.await()
    }

    suspend fun payOffer(amount: MilliSatoshi, offer: OfferTypes.Offer, payerKey: PrivateKey, payerNote: String?, fetchInvoiceTimeout: Duration): SendPaymentResult {
        val res = CompletableDeferred<SendPaymentResult>()
        val paymentId = UUID.randomUUID()
        this.launch {
            res.complete(eventsFlow
                .filterIsInstance<SendPaymentResult>()
                .filter { it.request.paymentId == paymentId }
                .first()
            )
        }
        send(PayOffer(paymentId, payerKey, payerNote, amount, offer, fetchInvoiceTimeout))
        return res.await()
    }

    suspend fun createInvoice(paymentPreimage: ByteVector32, amount: MilliSatoshi?, description: Either<String, ByteVector32>, expiry: Duration? = null): Bolt11Invoice {
        // we add one extra hop which uses a virtual channel with a "peer id", using the highest remote fees and expiry across all
        // channels to maximize the likelihood of success on the first payment attempt
        val remoteChannelUpdates = _channels.values.mapNotNull { channelState ->
            when (channelState) {
                is Normal -> channelState.remoteChannelUpdate
                is Offline -> (channelState.state as? Normal)?.remoteChannelUpdate
                is Syncing -> (channelState.state as? Normal)?.remoteChannelUpdate
                else -> null
            }
        }
        val extraHops = listOf(
            listOf(
                Bolt11Invoice.TaggedField.ExtraHop(
                    nodeId = walletParams.trampolineNode.id,
                    shortChannelId = ShortChannelId.peerId(nodeParams.nodeId),
                    feeBase = remoteChannelUpdates.maxOfOrNull { it.feeBaseMsat } ?: walletParams.invoiceDefaultRoutingFees.feeBase,
                    feeProportionalMillionths = remoteChannelUpdates.maxOfOrNull { it.feeProportionalMillionths } ?: walletParams.invoiceDefaultRoutingFees.feeProportional,
                    cltvExpiryDelta = remoteChannelUpdates.maxOfOrNull { it.cltvExpiryDelta } ?: walletParams.invoiceDefaultRoutingFees.cltvExpiryDelta
                )
            )
        )
        return incomingPaymentHandler.createInvoice(paymentPreimage, amount, description, extraHops, expiry ?: nodeParams.bolt11InvoiceExpiry)
    }

    /** Creates a custom offer and register it with the `offerManager`.
     *  @param secret A random private key for creating the blinded path of the offer. Must be unique to this offer.
     *  The offer returned is deterministic, if you need to persist you just need to save the parameters used to create it.
     */
    suspend fun createOffer(secret: PrivateKey, amount: MilliSatoshi?, description: String?): OfferTypes.Offer {
        val (offer, _) = OfferTypes.Offer.createBlindedOffer(amount, description, nodeParams, remoteNodeId, Features.empty, secret)
        offerManager.registerOffer(offer, secret.value)
        db.offers.addOffer(offer, secret)
        return offer
    }

    /**
     * Reload the offers from the database to allow to reuse custom offers across restarts.
     */
    suspend fun reloadOffersFromPersistance() {
        val offers = db.offers.listOffers()
        offers.forEach { (pathId, offer) ->
            offerManager.registerOffer(offer, pathId.value)
        }
    }

    // The (node_id, fcm_token) tuple only needs to be registered once.
    // And after that, only if the tuple changes (e.g. different fcm_token).
    fun registerFcmToken(token: String?) {
        val message = if (token == null) UnsetFCMToken else FCMToken(token)
        peerConnection?.send(message)
    }

    /**
     * Request a BIP-353's compliant DNS address from our peer.
     *
     * This will only return if there are existing channels with the peer, otherwise it will hang. This should be handled by the caller.
     *
     * @param languageSubtag IETF BCP 47 language tag (en, fr, de, es, ...) to indicate preference for the words that make up the address
     */
    suspend fun requestAddress(languageSubtag: String): String {
        val replyTo = CompletableDeferred<String>()
        this.launch {
            eventsFlow
                .filterIsInstance<AddressAssigned>()
                .first()
                .let { event -> replyTo.complete(event.address) }
        }
        peerConnection?.send(DNSAddressRequest(nodeParams.chainHash, nodeParams.defaultOffer(walletParams.trampolineNode.id).first, languageSubtag))
        return replyTo.await()
    }

    sealed class SelectChannelResult {
        /** We have a channel that is available for payments and splicing. */
        data class Available(val channel: Normal) : SelectChannelResult()
        /** We have a channel, or will have one soon, but it is not ready yet. */
        data object NotReady : SelectChannelResult()
        /** We don't have any channel, or our channel is closing, so we need a new one. */
        data object None : SelectChannelResult()
    }

    private fun selectChannelForSplicing(): SelectChannelResult = when (val channel = channels.values.firstOrNull { it is Normal }) {
        is Normal -> when {
            channel.spliceStatus == SpliceStatus.None -> SelectChannelResult.Available(channel)
            else -> SelectChannelResult.NotReady
        }
        else -> when {
            // We haven't finished reconnecting to our peer.
            channels.values.any { it is Offline || it is Syncing } -> SelectChannelResult.NotReady
            // We are currently funding a new channel, which should be available soon.
            channels.values.any { it is WaitForOpenChannel || it is WaitForAcceptChannel || it is WaitForFundingCreated || it is WaitForFundingSigned } -> SelectChannelResult.NotReady
            // We have funded a channel and are waiting for it to be ready.
            channels.values.any { it is WaitForFundingConfirmed || it is WaitForChannelReady } -> SelectChannelResult.NotReady
            // All channels are closing, we need a new one.
            channels.values.all { it is ShuttingDown || it is Negotiating || it is Closing || it is Closed || it is Aborted } -> SelectChannelResult.None
            // Otherwise we need a new channel.
            else -> SelectChannelResult.None
        }
    }

    private suspend fun processActions(channelId: ByteVector32, peerConnection: PeerConnection?, actions: List<ChannelAction>) {
        // we peek into the actions to see if the id of the channel is going to change, but we're not processing it yet
        val actualChannelId = actions.filterIsInstance<ChannelAction.ChannelId.IdAssigned>().firstOrNull()?.channelId ?: channelId
        logger.withMDC(mapOf("channelId" to actualChannelId)) { logger ->
            actions.forEach { action ->
                when (action) {
                    is ChannelAction.Message.Send -> peerConnection?.send(action.message) // ignore if disconnected
                    // sometimes channel actions include "self" command (such as ChannelCommand.Commitment.Sign)
                    is ChannelAction.Message.SendToSelf -> input.send(WrappedChannelCommand(actualChannelId, action.command))
                    is ChannelAction.Blockchain.SendWatch -> watcher.watch(action.watch)
                    is ChannelAction.Blockchain.PublishTx -> watcher.publish(action.tx)
                    is ChannelAction.ProcessIncomingHtlc -> processIncomingPayment(Either.Right(action.add))
                    is ChannelAction.ProcessCmdRes.NotExecuted -> logger.warning(action.t) { "command not executed" }
                    is ChannelAction.ProcessCmdRes.AddFailed -> {
                        when (val result = outgoingPaymentHandler.processAddFailed(actualChannelId, action)) {
                            is OutgoingPaymentHandler.Failure -> _eventsFlow.emit(PaymentNotSent(result.request, result.failure))
                            null -> logger.debug { "non-final error, more partial payments are still pending: ${action.error.message}" }
                        }
                    }
                    is ChannelAction.ProcessCmdRes.AddSettledFail -> {
                        val currentTip = currentTipFlow.filterNotNull().first()
                        when (val result = outgoingPaymentHandler.processAddSettledFailed(actualChannelId, action, _channels, currentTip)) {
                            is OutgoingPaymentHandler.Progress -> {
                                _eventsFlow.emit(PaymentProgress(result.request, result.fees))
                                result.actions.forEach { input.send(it) }
                            }

                            is OutgoingPaymentHandler.Success -> _eventsFlow.emit(PaymentSent(result.request, result.payment))
                            is OutgoingPaymentHandler.Failure -> _eventsFlow.emit(PaymentNotSent(result.request, result.failure))
                            null -> logger.debug { "non-final error, another payment attempt (retry) is still pending: ${action.result}" }
                        }
                    }
                    is ChannelAction.ProcessCmdRes.AddSettledFulfill -> {
                        when (val result = outgoingPaymentHandler.processAddSettledFulfilled(action)) {
                            is OutgoingPaymentHandler.Success -> _eventsFlow.emit(PaymentSent(result.request, result.payment))
                            null -> logger.error { "unknown payment fulfilled: this should never happen" }
                        }
                    }
                    is ChannelAction.Storage.StoreState -> {
                        logger.info { "storing state=${action.data::class.simpleName}" }
                        db.channels.addOrUpdateChannel(action.data)
                    }
                    is ChannelAction.Storage.RemoveChannel -> {
                        logger.info { "removing channelId=${action.data.channelId} state=${action.data::class.simpleName}" }
                        db.channels.removeChannel(action.data.channelId)
                    }
                    is ChannelAction.Storage.StoreHtlcInfos -> {
                        action.htlcs.forEach { db.channels.addHtlcInfo(actualChannelId, it.commitmentNumber, it.paymentHash, it.cltvExpiry) }
                    }
                    is ChannelAction.Storage.StoreIncomingPayment -> {
                        logger.info { "storing $action" }
                        val payment = when (action) {
                            is ChannelAction.Storage.StoreIncomingPayment.ViaNewChannel ->
                                NewChannelIncomingPayment(
                                    id = UUID.randomUUID(),
                                    amountReceived = action.amountReceived,
                                    serviceFee = action.serviceFee,
                                    miningFee = action.miningFee,
                                    channelId = channelId,
                                    txId = action.txId,
                                    localInputs = action.localInputs,
                                    createdAt = currentTimestampMillis(),
                                    confirmedAt = null,
                                    lockedAt = null,
                                )
                            is ChannelAction.Storage.StoreIncomingPayment.ViaSpliceIn ->
                                SpliceInIncomingPayment(
                                    id = UUID.randomUUID(),
                                    amountReceived = action.amountReceived,
                                    miningFee = action.miningFee,
                                    channelId = channelId,
                                    txId = action.txId,
                                    localInputs = action.localInputs,
                                    createdAt = currentTimestampMillis(),
                                    confirmedAt = null,
                                    lockedAt = null,
                                )
                        }
                        nodeParams._nodeEvents.emit(PaymentEvents.PaymentReceived(payment))
                        db.payments.addIncomingPayment(payment)
                    }
                    is ChannelAction.Storage.StoreOutgoingPayment -> {
                        logger.info { "storing $action" }
                        val payment = when (action) {
                            is ChannelAction.Storage.StoreOutgoingPayment.ViaSpliceOut ->
                                SpliceOutgoingPayment(
                                    id = UUID.randomUUID(),
                                    recipientAmount = action.amount,
                                    address = action.address,
                                    miningFees = action.miningFees,
                                    channelId = channelId,
                                    txId = action.txId,
                                    createdAt = currentTimestampMillis(),
                                    confirmedAt = null,
                                    lockedAt = null
                                )
                            is ChannelAction.Storage.StoreOutgoingPayment.ViaSpliceCpfp ->
                                SpliceCpfpOutgoingPayment(
                                    id = UUID.randomUUID(),
                                    miningFees = action.miningFees,
                                    channelId = channelId,
                                    txId = action.txId,
                                    createdAt = currentTimestampMillis(),
                                    confirmedAt = null,
                                    lockedAt = null
                                )
                            is ChannelAction.Storage.StoreOutgoingPayment.ViaInboundLiquidityRequest ->
                                InboundLiquidityOutgoingPayment(
                                    id = UUID.randomUUID(),
                                    channelId = channelId,
                                    txId = action.txId,
                                    localMiningFees = action.localMiningFees,
                                    purchase = action.purchase,
                                    createdAt = currentTimestampMillis(),
                                    confirmedAt = null,
                                    lockedAt = null
                                )
                            is ChannelAction.Storage.StoreOutgoingPayment.ViaClose -> {
                                _eventsFlow.emit(ChannelClosing(channelId))
                                ChannelCloseOutgoingPayment(
                                    id = UUID.randomUUID(),
                                    recipientAmount = action.amount,
                                    address = action.address,
                                    isSentToDefaultAddress = action.isSentToDefaultAddress,
                                    miningFees = action.miningFees,
                                    channelId = channelId,
                                    txId = action.txId,
                                    createdAt = currentTimestampMillis(),
                                    confirmedAt = null,
                                    lockedAt = currentTimestampMillis(), // channel close are not splices, they are final
                                    closingType = action.closingType
                                )
                            }
                        }
                        nodeParams._nodeEvents.emit(PaymentEvents.PaymentSent(payment))
                        db.payments.addOutgoingPayment(payment)
                    }
                    is ChannelAction.Storage.SetLocked -> {
                        logger.info { "setting status locked for txid=${action.txId}" }
                        db.payments.setLocked(action.txId)
                    }
                    is ChannelAction.Storage.GetHtlcInfos -> {
                        val htlcInfos = db.channels.listHtlcInfos(actualChannelId, action.commitmentNumber).map { ChannelAction.Storage.HtlcInfo(actualChannelId, action.commitmentNumber, it.first, it.second) }
                        input.send(WrappedChannelCommand(actualChannelId, ChannelCommand.Closing.GetHtlcInfosResponse(action.revokedCommitTxId, htlcInfos)))
                    }
                    is ChannelAction.ChannelId.IdAssigned -> {
                        logger.info { "switching channel id from ${action.temporaryChannelId} to ${action.channelId}" }
                        _channels[action.temporaryChannelId]?.let { _channels = _channels + (action.channelId to it) - action.temporaryChannelId }
                    }
                    is ChannelAction.EmitEvent -> nodeParams._nodeEvents.emit(action.event)
                    is ChannelAction.Disconnect -> {
                        logger.warning { "channel disconnected due to a protocol error" }
                        disconnect()
                    }
                }
            }
        }
    }

    private suspend fun processIncomingPayment(item: Either<WillAddHtlc, UpdateAddHtlc>) {
        val currentBlockHeight = currentTipFlow.filterNotNull().first()
        val currentFeerate = peerFeeratesFlow.filterNotNull().first().fundingFeerate
        val currentFeeCredit = feeCreditFlow.value
        val result = when (item) {
            is Either.Right -> incomingPaymentHandler.process(item.value, theirInit!!.features, currentBlockHeight, currentFeerate, remoteFundingRates.value, currentFeeCredit)
            is Either.Left -> incomingPaymentHandler.process(item.value, theirInit!!.features, currentBlockHeight, currentFeerate, remoteFundingRates.value, currentFeeCredit)
        }
        when (result) {
            is IncomingPaymentHandler.ProcessAddResult.Accepted -> {
                if (result.incomingPayment.parts.size > 1) {
                    // this was a multi-part payment, we signal that the task is finished
                    nodeParams._nodeEvents.tryEmit(SensitiveTaskEvents.TaskEnded(SensitiveTaskEvents.TaskIdentifier.IncomingMultiPartPayment(result.incomingPayment.paymentHash)))
                }
            }
            is IncomingPaymentHandler.ProcessAddResult.Pending -> if (result.pendingPayment.parts.size == 1) {
                // this is the first part of a multi-part payment, we request to keep the app alive to receive subsequent parts
                nodeParams._nodeEvents.tryEmit(SensitiveTaskEvents.TaskStarted(SensitiveTaskEvents.TaskIdentifier.IncomingMultiPartPayment(result.incomingPayment.paymentHash)))
            }
            else -> Unit
        }
        result.actions.forEach { input.send(it) }
    }

    private suspend fun handshake(
        ourKeys: Pair<ByteArray, ByteArray>,
        theirPubkey: ByteArray,
        r: suspend (Int) -> ByteArray,
        w: suspend (ByteArray) -> Unit
    ): Triple<CipherState, CipherState, ByteArray> {

        /**
         * See BOLT #8: during the handshake phase we are expecting 3 messages of 50, 50 and 66 bytes (including the prefix)
         *
         * @param reader handshake state reader
         * @return the size of the message the reader is expecting
         */
        fun expectedLength(reader: HandshakeStateReader): Int = when (reader.messages.size) {
            3, 2 -> 50
            1 -> 66
            else -> throw RuntimeException("invalid state")
        }

        val writer = HandshakeState.initializeWriter(
            handshakePatternXK, prologue,
            ourKeys, Pair(ByteArray(0), ByteArray(0)), theirPubkey, ByteArray(0),
            Secp256k1DHFunctions, Chacha20Poly1305CipherFunctions, SHA256HashFunctions
        )
        val (state1, message, _) = writer.write(ByteArray(0))
        w(byteArrayOf(prefix) + message)

        val payload = r(expectedLength(state1))
        require(payload[0] == prefix)

        val (writer1, _, _) = state1.read(payload.drop(1).toByteArray())
        val (_, message1, foo) = writer1.write(ByteArray(0))
        val (enc, dec, ck) = foo!!
        w(byteArrayOf(prefix) + message1)
        return Triple(enc, dec, ck)
    }

    private suspend fun run() {
        logger.info { "peer is active" }
        for (event in input) {
            logger.withMDC(logger.staticMdc + (peerConnection?.logger?.staticMdc ?: emptyMap()) + ((event as? MessageReceived)?.msg?.mdc() ?: emptyMap())) { logger ->
                processEvent(event, logger)
            }
        }
    }

    // MUST ONLY BE SET BY processEvent()
    private val _peerConnection = MutableStateFlow<PeerConnection?>(null)
    private val peerConnection: PeerConnection?
        get() = _peerConnection.value

    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun processEvent(cmd: PeerCommand, logger: MDCLogger) {
        when (cmd) {
            is Connected -> {
                logger.info { "new connection with id=${cmd.peerConnection.id}, sending init $ourInit" }
                _peerConnection.value = cmd.peerConnection
                peerConnection?.send(ourInit)
            }
            is MessageReceived -> {
                if (cmd.connectionId != peerConnection?.id) {
                    logger.warning { "ignoring ${cmd.msg} for connectionId=${cmd.connectionId}" }
                    return
                }
                val msg = cmd.msg
                msg.let { if (it !is Ping && it !is Pong) logger.info { "received $it" } }
                when (msg) {
                    is UnknownMessage -> {
                        logger.warning { "unhandled code=${msg.type}" }
                    }
                    is Init -> {
                        logger.info { "peer is using features ${msg.features}" }
                        when (val error = Features.validateFeatureGraph(msg.features)) {
                            is Features.Companion.FeatureException -> {
                                logger.error(error) { "feature validation error" }
                                disconnect()
                            }
                            else -> {
                                theirInit = msg
                                nodeParams._nodeEvents.emit(PeerConnected(remoteNodeId, msg))
                                remoteFundingRates.value = msg.liquidityRates
                                _channels = _channels.mapValues { entry ->
                                    val (state1, actions) = entry.value.process(ChannelCommand.Connected(ourInit, msg))
                                    processActions(entry.key, peerConnection, actions)
                                    state1
                                }
                            }
                        }
                    }
                    is RecommendedFeerates -> {
                        peerFeeratesFlow.value = msg
                    }
                    is CurrentFeeCredit -> {
                        if (nodeParams.features.hasFeature(Feature.FundingFeeCredit)) {
                            feeCreditFlow.value = msg.amount
                        }
                    }
                    is Ping -> {
                        val pong = Pong(ByteVector(ByteArray(msg.pongLength)))
                        peerConnection?.send(pong)
                    }
                    is Pong -> {
                        logger.debug { "received pong" }
                    }
                    is Warning -> {
                        // NB: we don't forward warnings to the channel because it shouldn't take any automatic action,
                        // these warnings are meant for humans.
                        logger.warning { "peer sent warning: ${msg.toAscii()}" }
                    }
                    is OpenDualFundedChannel -> {
                        if (theirInit == null) {
                            logger.error { "they sent open_channel before init" }
                        } else if (_channels.containsKey(msg.temporaryChannelId)) {
                            logger.warning { "ignoring open_channel with duplicate temporaryChannelId=${msg.temporaryChannelId}" }
                        } else {
                            val localParams = LocalParams(nodeParams, isChannelOpener = false, payCommitTxFees = msg.channelFlags.nonInitiatorPaysCommitFees)
                            val state = WaitForInit
                            val channelConfig = ChannelConfig.standard
                            val initCommand = ChannelCommand.Init.NonInitiator(
                                replyTo = CompletableDeferred(),
                                temporaryChannelId = msg.temporaryChannelId,
                                fundingAmount = 0.sat,
                                walletInputs = listOf(),
                                localParams = localParams,
                                channelConfig = channelConfig,
                                remoteInit = theirInit!!,
                                fundingRates = null
                            )
                            val (state1, actions1) = state.process(initCommand)
                            val (state2, actions2) = state1.process(ChannelCommand.MessageReceived(msg))
                            _channels = _channels + (msg.temporaryChannelId to state2)
                            processActions(msg.temporaryChannelId, peerConnection, actions1 + actions2)
                        }
                    }
                    is ChannelReestablish -> {
                        val local: ChannelState? = _channels[msg.channelId]
                        val backup: DeserializationResult? = msg.channelData.takeIf { !it.isEmpty() }?.let { channelData ->
                            PersistedChannelState
                                .from(nodeParams.nodePrivateKey, channelData)
                                .onFailure { logger.warning(it) { "unreadable backup" } }
                                .getOrNull()
                        }

                        suspend fun recoverChannel(recovered: PersistedChannelState) {
                            db.channels.addOrUpdateChannel(recovered)

                            val state = WaitForInit
                            val event1 = ChannelCommand.Init.Restore(recovered)
                            val (state1, actions1) = state.process(event1)
                            processActions(msg.channelId, peerConnection, actions1)

                            val event2 = ChannelCommand.Connected(ourInit, theirInit!!)
                            val (state2, actions2) = state1.process(event2)
                            processActions(msg.channelId, peerConnection, actions2)

                            val event3 = ChannelCommand.MessageReceived(msg)
                            val (state3, actions3) = state2.process(event3)
                            processActions(msg.channelId, peerConnection, actions3)
                            _channels = _channels + (msg.channelId to state3)
                        }

                        when {
                            backup is DeserializationResult.UnknownVersion -> {
                                logger.warning { "peer sent a reestablish with a backup generated by a more recent of phoenix: version=${backup.version}." }
                                // In this corner case, we do not want to return an error to the peer, because they will force-close and we will be unable to
                                // do anything as we can't read the data. Best thing is to not answer, and tell the user to upgrade the app.
                                logger.error { "need to upgrade your app!" }
                                nodeParams._nodeEvents.emit(UpgradeRequired)
                            }
                            local == null && backup == null -> {
                                logger.warning { "peer sent a reestablish for a unknown channel with no or undecipherable backup" }
                                peerConnection?.send(Error(msg.channelId, "unknown channel"))
                            }
                            local == null && backup is DeserializationResult.Success -> {
                                logger.warning { "recovering channel from peer backup" }
                                recoverChannel(backup.state)
                            }
                            local is Syncing && local.state is ChannelStateWithCommitments && backup is DeserializationResult.Success && backup.state is ChannelStateWithCommitments && backup.state.commitments.isMoreRecent(local.state.commitments) -> {
                                logger.warning { "recovering channel from peer backup (it is more recent)" }
                                recoverChannel(backup.state)
                            }
                            local is ChannelState -> {
                                val (state1, actions1) = local.process(ChannelCommand.MessageReceived(msg))
                                processActions(msg.channelId, peerConnection, actions1)
                                _channels = _channels + (msg.channelId to state1)
                            }
                        }
                    }
                    is HasTemporaryChannelId -> {
                        _channels[msg.temporaryChannelId]?.let { state ->
                            logger.info { "received ${msg::class.simpleName} for temporary channel ${msg.temporaryChannelId}" }
                            val event1 = ChannelCommand.MessageReceived(msg)
                            val (state1, actions) = state.process(event1)
                            _channels = _channels + (msg.temporaryChannelId to state1)
                            processActions(msg.temporaryChannelId, peerConnection, actions)
                        } ?: run {
                            logger.error { "received ${msg::class.simpleName} for unknown temporary channel ${msg.temporaryChannelId}" }
                            peerConnection?.send(Error(msg.temporaryChannelId, "unknown channel"))
                        }
                    }
                    is HasChannelId -> {
                        if (msg is Error && msg.channelId == ByteVector32.Zeroes) {
                            logger.error { "connection error: ${msg.toAscii()}" }
                        } else {
                            _channels[msg.channelId]?.let { state ->
                                val event1 = ChannelCommand.MessageReceived(msg)
                                val (state1, actions) = state.process(event1)
                                processActions(msg.channelId, peerConnection, actions)
                                _channels = _channels + (msg.channelId to state1)
                            } ?: run {
                                logger.error { "received ${msg::class.simpleName} for unknown channel ${msg.channelId}" }
                                peerConnection?.send(Error(msg.channelId, "unknown channel"))
                            }
                        }
                    }
                    is ChannelUpdate -> {
                        _channels.values.filterIsInstance<Normal>().find { it.shortChannelId == msg.shortChannelId }?.let { state ->
                            val event1 = ChannelCommand.MessageReceived(msg)
                            val (state1, actions) = state.process(event1)
                            processActions(state.channelId, peerConnection, actions)
                            _channels = _channels + (state.channelId to state1)
                        }
                    }
                    is WillAddHtlc -> when {
                        nodeParams.features.hasFeature(Feature.OnTheFlyFunding) -> when {
                            nodeParams.liquidityPolicy.value is LiquidityPolicy.Disable -> {
                                logger.warning { "cannot accept on-the-fly funding: policy set to disabled" }
                                val failure = OutgoingPaymentPacket.buildWillAddHtlcFailure(nodeParams.nodePrivateKey, msg, TemporaryNodeFailure)
                                input.send(SendOnTheFlyFundingMessage(failure))
                                nodeParams._nodeEvents.emit(LiquidityEvents.Rejected(msg.amount, 0.msat, LiquidityEvents.Source.OffChainPayment, LiquidityEvents.Rejected.Reason.PolicySetToDisabled))
                            }
                            else -> when (selectChannelForSplicing()) {
                                is SelectChannelResult.Available -> processIncomingPayment(Either.Left(msg))
                                SelectChannelResult.None -> processIncomingPayment(Either.Left(msg))
                                SelectChannelResult.NotReady -> {
                                    // Once the channel will be ready, we may have enough inbound liquidity to receive the payment without
                                    // an on-chain operation, which is more efficient. We thus reject that payment and wait for the sender to retry.
                                    logger.warning { "cannot accept on-the-fly funding: another funding attempt is already in-progress" }
                                    val failure = OutgoingPaymentPacket.buildWillAddHtlcFailure(nodeParams.nodePrivateKey, msg, TemporaryNodeFailure)
                                    input.send(SendOnTheFlyFundingMessage(failure))
                                    nodeParams._nodeEvents.emit(LiquidityEvents.Rejected(msg.amount, 0.msat, LiquidityEvents.Source.OffChainPayment, LiquidityEvents.Rejected.Reason.ChannelFundingInProgress))
                                }
                            }
                        }
                        else -> {
                            // If we don't support on-the-fly funding, we simply ignore that proposal.
                            // Our peer will fail the corresponding HTLCs after a small delay.
                            logger.info { "ignoring on-the-fly funding (amount=${msg.amount}): on-the-fly funding is disabled" }
                        }
                    }
                    is PhoenixAndroidLegacyInfo -> {
                        logger.info { "received ${msg::class.simpleName} hasChannels=${msg.hasChannels}" }
                        _eventsFlow.emit(PhoenixAndroidLegacyInfoEvent(msg))
                    }
                    is OnionMessage -> {
                        logger.info { "received ${msg::class.simpleName}" }
                        val remoteChannelUpdates = _channels.values.mapNotNull { channelState ->
                            when (channelState) {
                                is Normal -> channelState.remoteChannelUpdate
                                is Offline -> (channelState.state as? Normal)?.remoteChannelUpdate
                                is Syncing -> (channelState.state as? Normal)?.remoteChannelUpdate
                                else -> null
                            }
                        }
                        offerManager.receiveMessage(msg, remoteChannelUpdates, currentTipFlow.filterNotNull().first())?.let {
                            when (it) {
                                is OnionMessageAction.PayInvoice -> input.send(
                                    PayInvoice(
                                        it.payOffer.paymentId,
                                        it.payOffer.amount,
                                        LightningOutgoingPayment.Details.Blinded(it.invoice, it.payOffer.payerKey),
                                        it.payOffer.trampolineFeesOverride
                                    )
                                )
                                is OnionMessageAction.SendMessage -> input.send(SendOnionMessage(it.message))
                            }
                        }
                    }
                    is DNSAddressResponse -> {
                        logger.info { "bip353 dns address assigned: ${msg.address}" }
                        _eventsFlow.emit(AddressAssigned(msg.address))
                    }
                }
            }
            is WatchReceived -> {
                if (!_channels.containsKey(cmd.watch.channelId)) {
                    logger.error { "received watch event ${cmd.watch} for unknown channel ${cmd.watch.channelId}}" }
                } else {
                    val state = _channels[cmd.watch.channelId] ?: error("channel ${cmd.watch.channelId} not found")
                    val event1 = ChannelCommand.WatchReceived(cmd.watch)
                    val (state1, actions) = state.process(event1)
                    processActions(cmd.watch.channelId, peerConnection, actions)
                    _channels = _channels + (cmd.watch.channelId to state1)
                }
            }
            is OpenChannel -> {
                val localParams = LocalParams(nodeParams, isChannelOpener = true, payCommitTxFees = true)
                val state = WaitForInit
                val (state1, actions1) = state.process(
                    ChannelCommand.Init.Initiator(
                        replyTo = CompletableDeferred(),
                        fundingAmount = cmd.fundingAmount,
                        walletInputs = cmd.walletInputs,
                        commitTxFeerate = cmd.commitTxFeerate,
                        fundingTxFeerate = cmd.fundingTxFeerate,
                        localParams = localParams,
                        remoteInit = theirInit!!,
                        channelFlags = ChannelFlags(announceChannel = false, nonInitiatorPaysCommitFees = false),
                        channelConfig = ChannelConfig.standard,
                        channelType = cmd.channelType,
                        requestRemoteFunding = null,
                        channelOrigin = null,
                    )
                )
                val msg = actions1.filterIsInstance<ChannelAction.Message.Send>().map { it.message }.filterIsInstance<OpenDualFundedChannel>().first()
                _channels = _channels + (msg.temporaryChannelId to state1)
                processActions(msg.temporaryChannelId, peerConnection, actions1)
            }
            is AddWalletInputsToChannel -> {
                when (val available = selectChannelForSplicing()) {
                    is SelectChannelResult.Available -> {
                        // We have a channel and we are connected.
                        val targetFeerate = peerFeeratesFlow.filterNotNull().first().fundingFeerate
                        val weight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = available.channel.commitments.active.first(), walletInputs = cmd.walletInputs, localOutputs = emptyList())
                        val (feerate, fee) = client.computeSpliceCpfpFeerate(available.channel.commitments, targetFeerate, spliceWeight = weight, logger)
                        logger.info { "requesting splice-in using balance=${cmd.walletInputs.balance} feerate=$feerate fee=$fee" }
                        when (val rejected = nodeParams.liquidityPolicy.value.maybeReject(cmd.walletInputs.balance.toMilliSatoshi(), ChannelManagementFees(miningFee = fee, serviceFee = 0.sat), LiquidityEvents.Source.OnChainWallet, logger)) {
                            is LiquidityEvents.Rejected -> {
                                logger.info { "rejecting splice: reason=${rejected.reason}" }
                                nodeParams._nodeEvents.emit(rejected)
                                swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                            }
                            else -> {
                                val spliceCommand = ChannelCommand.Commitment.Splice.Request(
                                    replyTo = CompletableDeferred(),
                                    spliceIn = ChannelCommand.Commitment.Splice.Request.SpliceIn(cmd.walletInputs),
                                    spliceOut = null,
                                    requestRemoteFunding = null,
                                    currentFeeCredit = feeCreditFlow.value,
                                    feerate = feerate,
                                    origins = listOf(Origin.OnChainWallet(cmd.walletInputs.map { it.outPoint }.toSet(), cmd.totalAmount.toMilliSatoshi(), ChannelManagementFees(fee, 0.sat)))
                                )
                                // If the splice fails, we immediately unlock the utxos to reuse them in the next attempt.
                                spliceCommand.replyTo.invokeOnCompletion { ex ->
                                    if (ex == null && spliceCommand.replyTo.getCompleted() is ChannelFundingResponse.Failure) {
                                        swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                                    }
                                }
                                input.send(WrappedChannelCommand(available.channel.channelId, spliceCommand))
                                nodeParams._nodeEvents.emit(SwapInEvents.Requested(cmd.walletInputs))
                            }
                        }
                    }
                    SelectChannelResult.NotReady -> {
                        // There are existing channels but not immediately usable (e.g. creating, disconnected), we don't do anything yet.
                        logger.info { "ignoring request to add utxos to channel, existing channels are not ready for splice-in: ${channels.values.map { it::class.simpleName }}" }
                        swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                    }
                    SelectChannelResult.None -> {
                        // Either there are no channels, or they will never be suitable for a splice-in: we open a new channel.
                        val currentFeerates = peerFeeratesFlow.filterNotNull().first()
                        // We need our peer to contribute, because they must have enough funds to pay the commitment fees.
                        // That means they will add at least one input to the funding transaction, and pay the corresponding mining fees.
                        // We always request a liquidity purchase, even for a dummy amount, which ensures that we refund their mining fees.
                        val inboundLiquidityTarget = when (val policy = nodeParams.liquidityPolicy.first()) {
                            is LiquidityPolicy.Disable -> 1.sat
                            is LiquidityPolicy.Auto -> policy.inboundLiquidityTarget ?: 1.sat
                        }
                        when (val fundingRate = remoteFundingRates.value?.findRate(inboundLiquidityTarget)) {
                            null -> {
                                logger.warning { "cannot find suitable funding rate (remoteFundingRates=${remoteFundingRates.value}, inboundLiquidityTarget=$inboundLiquidityTarget)" }
                                swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                            }
                            else -> {
                                val requestRemoteFunding = LiquidityAds.RequestFunding(inboundLiquidityTarget, fundingRate, LiquidityAds.PaymentDetails.FromChannelBalance)
                                val (localFundingAmount, fees) = run {
                                    // We need to know the local channel funding amount to be able use channel opening messages.
                                    // We must pay on-chain fees for our inputs/outputs of the transaction: we compute them first
                                    // and proceed backwards to retrieve the funding amount.
                                    val dummyFundingScript = Script.write(Scripts.multiSig2of2(Transactions.PlaceHolderPubKey, Transactions.PlaceHolderPubKey)).byteVector()
                                    val localMiningFee = Transactions.weight2fee(currentFeerates.fundingFeerate, FundingContributions.computeWeightPaid(isInitiator = true, null, dummyFundingScript, cmd.walletInputs, emptyList()))
                                    val localFundingAmount = cmd.totalAmount - localMiningFee
                                    val fundingFees = requestRemoteFunding.fees(currentFeerates.fundingFeerate, isChannelCreation = true)
                                    // We also refund the liquidity provider for some of the on-chain fees they will pay for their inputs/outputs of the transaction.
                                    // This will be taken from our channel balance during the interactive-tx construction, they shouldn't be deducted from our funding amount.
                                    val totalFees = ChannelManagementFees(miningFee = localMiningFee + fundingFees.miningFee, serviceFee = fundingFees.serviceFee)
                                    Pair(localFundingAmount, totalFees)
                                }
                                if (cmd.totalAmount - fees.total < nodeParams.dustLimit) {
                                    logger.warning { "cannot create channel, not enough funds to pay fees (fees=${fees.total}, available=${cmd.totalAmount})" }
                                    swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                                } else {
                                    val totalAmount = cmd.walletInputs.balance.toMilliSatoshi() + requestRemoteFunding.requestedAmount.toMilliSatoshi()
                                    when (val rejected = nodeParams.liquidityPolicy.first().maybeReject(totalAmount, fees, LiquidityEvents.Source.OnChainWallet, logger)) {
                                        is LiquidityEvents.Rejected -> {
                                            logger.info { "rejecting channel open: reason=${rejected.reason}" }
                                            nodeParams._nodeEvents.emit(rejected)
                                            swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                                        }
                                        else -> {
                                            // We ask our peer to pay the commit tx fees.
                                            val localParams = LocalParams(nodeParams, isChannelOpener = true, payCommitTxFees = false)
                                            val channelFlags = ChannelFlags(announceChannel = false, nonInitiatorPaysCommitFees = true)
                                            val initCommand = ChannelCommand.Init.Initiator(
                                                replyTo = CompletableDeferred(),
                                                fundingAmount = localFundingAmount,
                                                walletInputs = cmd.walletInputs,
                                                commitTxFeerate = currentFeerates.commitmentFeerate,
                                                fundingTxFeerate = currentFeerates.fundingFeerate,
                                                localParams = localParams,
                                                remoteInit = theirInit!!,
                                                channelFlags = channelFlags,
                                                channelConfig = ChannelConfig.standard,
                                                channelType = ChannelType.SupportedChannelType.AnchorOutputsZeroReserve,
                                                requestRemoteFunding = requestRemoteFunding,
                                                channelOrigin = Origin.OnChainWallet(cmd.walletInputs.map { it.outPoint }.toSet(), cmd.totalAmount.toMilliSatoshi(), fees),
                                            )
                                            // If the channel creation fails, we immediately unlock the utxos to reuse them in the next attempt.
                                            initCommand.replyTo.invokeOnCompletion { ex ->
                                                if (ex == null && initCommand.replyTo.getCompleted() is ChannelFundingResponse.Failure) {
                                                    swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                                                }
                                            }
                                            val (state, actions) = WaitForInit.process(initCommand)
                                            val msg = actions.filterIsInstance<ChannelAction.Message.Send>().map { it.message }.filterIsInstance<OpenDualFundedChannel>().first()
                                            _channels = _channels + (msg.temporaryChannelId to state)
                                            processActions(msg.temporaryChannelId, peerConnection, actions)
                                            nodeParams._nodeEvents.emit(SwapInEvents.Requested(cmd.walletInputs))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            is AddLiquidityForIncomingPayment -> {
                val currentFeerates = peerFeeratesFlow.filterNotNull().first()
                val paymentTypes = remoteFundingRates.value?.paymentTypes ?: setOf()
                val currentFeeCredit = feeCreditFlow.value
                when (val available = selectChannelForSplicing()) {
                    is SelectChannelResult.Available -> {
                        // We don't contribute any input or output, but we must pay on-chain fees for the shared input and output.
                        // We pay those on-chain fees using our current channel balance.
                        val localBalance = available.channel.commitments.active.first().localCommit.spec.toLocal
                        val spliceWeight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = available.channel.commitments.active.first(), walletInputs = listOf(), localOutputs = listOf())
                        val (fundingFeerate, localMiningFee) = client.computeSpliceCpfpFeerate(available.channel.commitments, currentFeerates.fundingFeerate, spliceWeight, logger)
                        val (targetFeerate, paymentDetails) = when {
                            localBalance + currentFeeCredit >= localMiningFee + cmd.fees(fundingFeerate, isChannelCreation = false).total -> {
                                // We have enough funds to pay the mining fee and the lease fees.
                                // This the ideal scenario because the fees can be paid immediately with the splice transaction.
                                Pair(fundingFeerate, LiquidityAds.PaymentDetails.FromChannelBalanceForFutureHtlc(listOf(cmd.paymentHash)))
                            }
                            else -> {
                                val targetFeerate = when {
                                    localBalance >= localMiningFee * 0.75 -> fundingFeerate
                                    // Our current balance is too low to pay the mining fees for our weight of the splice transaction.
                                    // We target a higher feerate so that the effective feerate isn't too low compared to our target.
                                    else -> fundingFeerate * AddLiquidityForIncomingPayment.SpliceWithNoBalanceFeerateRatio
                                }
                                // We cannot pay the liquidity fees from our channel balance, so we fall back to future HTLCs.
                                val paymentDetails = when {
                                    paymentTypes.contains(LiquidityAds.PaymentType.FromFutureHtlc) -> LiquidityAds.PaymentDetails.FromFutureHtlc(listOf(cmd.paymentHash))
                                    paymentTypes.contains(LiquidityAds.PaymentType.FromFutureHtlcWithPreimage) -> LiquidityAds.PaymentDetails.FromFutureHtlcWithPreimage(listOf(cmd.preimage))
                                    else -> null
                                }
                                Pair(targetFeerate, paymentDetails)
                            }
                        }
                        when (paymentDetails) {
                            null -> {
                                // Our peer doesn't allow paying liquidity fees from future HTLCs.
                                // We'll need to wait until we have more channel balance or do a splice-in to purchase more inbound liquidity.
                                logger.warning { "cannot request on-the-fly splice: payment types not supported (${paymentTypes.joinToString()})" }
                            }
                            else -> {
                                val leaseFees = cmd.fees(targetFeerate, isChannelCreation = false)
                                val totalFees = ChannelManagementFees(miningFee = localMiningFee.min(localBalance.truncateToSatoshi()) + leaseFees.miningFee, serviceFee = leaseFees.serviceFee)
                                logger.info { "requesting on-the-fly splice for paymentHash=${cmd.paymentHash} requestedAmount=${cmd.requestedAmount} feerate=$targetFeerate fee=${totalFees.total} paymentType=${paymentDetails.paymentType}" }
                                val spliceCommand = ChannelCommand.Commitment.Splice.Request(
                                    replyTo = CompletableDeferred(),
                                    spliceIn = null,
                                    spliceOut = null,
                                    requestRemoteFunding = LiquidityAds.RequestFunding(cmd.requestedAmount, cmd.fundingRate, paymentDetails),
                                    currentFeeCredit = currentFeeCredit,
                                    feerate = targetFeerate,
                                    origins = listOf(Origin.OffChainPayment(cmd.preimage, cmd.paymentAmount, totalFees))
                                )
                                val (state, actions) = available.channel.process(spliceCommand)
                                _channels = _channels + (available.channel.channelId to state)
                                processActions(available.channel.channelId, peerConnection, actions)
                            }
                        }
                    }
                    SelectChannelResult.None -> {
                        // We ask our peer to pay the commit tx fees.
                        val localParams = LocalParams(nodeParams, isChannelOpener = true, payCommitTxFees = false)
                        val channelFlags = ChannelFlags(announceChannel = false, nonInitiatorPaysCommitFees = true)
                        // Since we don't have inputs to contribute, we're unable to pay on-chain fees for the shared output.
                        // We target a higher feerate so that the effective feerate isn't too low compared to our target.
                        val fundingFeerate = currentFeerates.fundingFeerate * AddLiquidityForIncomingPayment.ChannelOpenFeerateRatio
                        // We don't pay any local on-chain fees, our fee is only for the liquidity lease.
                        val leaseFees = cmd.fees(fundingFeerate, isChannelCreation = true)
                        val totalFees = ChannelManagementFees(miningFee = leaseFees.miningFee, serviceFee = leaseFees.serviceFee)
                        // We cannot pay the liquidity fees from our channel balance, so we fall back to future HTLCs.
                        val paymentDetails = when {
                            paymentTypes.contains(LiquidityAds.PaymentType.FromFutureHtlc) -> LiquidityAds.PaymentDetails.FromFutureHtlc(listOf(cmd.paymentHash))
                            paymentTypes.contains(LiquidityAds.PaymentType.FromFutureHtlcWithPreimage) -> LiquidityAds.PaymentDetails.FromFutureHtlcWithPreimage(listOf(cmd.preimage))
                            else -> null
                        }
                        when (paymentDetails) {
                            null -> {
                                // Our peer doesn't allow paying liquidity fees from future HTLCs.
                                // We'll need to swap-in some funds to create a new channel.
                                logger.warning { "cannot request on-the-fly channel: payment types not supported (${paymentTypes.joinToString()})" }
                            }
                            else -> {
                                logger.info { "requesting on-the-fly channel for paymentHash=${cmd.paymentHash} feerate=$fundingFeerate fee=${totalFees.total} paymentType=${paymentDetails.paymentType}" }
                                val (state, actions) = WaitForInit.process(
                                    ChannelCommand.Init.Initiator(
                                        replyTo = CompletableDeferred(),
                                        fundingAmount = 0.sat, // we don't have funds to contribute
                                        walletInputs = listOf(),
                                        commitTxFeerate = currentFeerates.commitmentFeerate,
                                        fundingTxFeerate = fundingFeerate,
                                        localParams = localParams,
                                        remoteInit = theirInit!!,
                                        channelFlags = channelFlags,
                                        channelConfig = ChannelConfig.standard,
                                        channelType = ChannelType.SupportedChannelType.AnchorOutputsZeroReserve,
                                        requestRemoteFunding = LiquidityAds.RequestFunding(cmd.requestedAmount, cmd.fundingRate, paymentDetails),
                                        channelOrigin = Origin.OffChainPayment(cmd.preimage, cmd.paymentAmount, totalFees),
                                    )
                                )
                                val msg = actions.filterIsInstance<ChannelAction.Message.Send>().map { it.message }.filterIsInstance<OpenDualFundedChannel>().first()
                                _channels = _channels + (msg.temporaryChannelId to state)
                                processActions(msg.temporaryChannelId, peerConnection, actions)
                            }
                        }
                    }
                    SelectChannelResult.NotReady -> {
                        // There is an existing channel but not immediately usable (e.g. we're already in the process of funding it).
                        logger.warning { "cancelling on-the-fly funding, existing channels are not ready for splice-in: ${channels.values.map { it::class.simpleName }}" }
                        cmd.willAddHtlcs.forEach {
                            val failure = OutgoingPaymentPacket.buildWillAddHtlcFailure(nodeParams.nodePrivateKey, it, TemporaryNodeFailure)
                            input.send(SendOnTheFlyFundingMessage(failure))
                        }
                        nodeParams._nodeEvents.emit(LiquidityEvents.Rejected(cmd.requestedAmount.toMilliSatoshi(), 0.msat, LiquidityEvents.Source.OffChainPayment, LiquidityEvents.Rejected.Reason.ChannelFundingInProgress))
                    }
                }
            }
            is PayInvoice -> {
                val currentTip = currentTipFlow.filterNotNull().first()
                when (val result = outgoingPaymentHandler.sendPayment(cmd, _channels, currentTip)) {
                    is OutgoingPaymentHandler.Progress -> {
                        _eventsFlow.emit(PaymentProgress(result.request, result.fees))
                        result.actions.forEach { input.send(it) }
                    }
                    is OutgoingPaymentHandler.Failure -> _eventsFlow.emit(PaymentNotSent(result.request, result.failure))
                }
            }
            is PurgeExpiredPayments -> {
                incomingPaymentHandler.purgeExpiredPayments(cmd.fromCreatedAt, cmd.toCreatedAt)
            }
            is CheckPaymentsTimeout -> {
                val actions = incomingPaymentHandler.checkPaymentsTimeout(currentTimestampSeconds())
                actions.forEach { input.send(it) }
            }
            is WrappedChannelCommand -> {
                if (cmd.channelId == ByteVector32.Zeroes) {
                    // this is for all channels
                    _channels.forEach { (key, value) ->
                        val (state1, actions) = value.process(cmd.channelCommand)
                        processActions(key, peerConnection, actions)
                        _channels = _channels + (key to state1)
                    }
                } else {
                    _channels[cmd.channelId]?.let { state ->
                        val (state1, actions) = state.process(cmd.channelCommand)
                        processActions(cmd.channelId, peerConnection, actions)
                        _channels = _channels + (cmd.channelId to state1)
                    } ?: logger.error { "received ${cmd.channelCommand::class.simpleName} for an unknown channel ${cmd.channelId}" }
                }
            }
            is Disconnected -> {
                when (peerConnection) {
                    null -> logger.info { "ignoring disconnected event, we're already disconnected" }
                    else -> {
                        logger.warning { "disconnecting channels from connectionId=${peerConnection?.id}" }
                        _peerConnection.value = null
                        _channels.forEach { (key, value) ->
                            val (state1, actions) = value.process(ChannelCommand.Disconnected)
                            _channels = _channels + (key to state1)
                            processActions(key, peerConnection, actions)
                        }
                        // We must purge pending incoming payments: incoming HTLCs that aren't settled yet will be
                        // re-processed on reconnection, and we must not keep HTLCs pending in the payment handler since
                        // another instance of the application may resolve them, which would lead to inconsistent
                        // payment handler state (whereas the channel state is kept consistent thanks to the encrypted
                        // channel backup).
                        incomingPaymentHandler.purgePendingPayments()
                    }
                }
            }
            is PayOffer -> {
                val (pathId, invoiceRequests) = offerManager.requestInvoice(cmd)
                invoiceRequests.forEach { input.send(SendOnionMessage(it)) }
                this.launch {
                    delay(cmd.fetchInvoiceTimeout)
                    input.send(CheckInvoiceRequestTimeout(pathId, cmd))
                }
            }
            is CheckInvoiceRequestTimeout -> offerManager.checkInvoiceRequestTimeout(cmd.pathId, cmd.payOffer)
            is SendOnionMessage -> peerConnection?.send(cmd.message)
            is SendOnTheFlyFundingMessage -> peerConnection?.send(cmd.message)
        }
    }
}
