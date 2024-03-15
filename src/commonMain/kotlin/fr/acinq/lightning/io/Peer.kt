package fr.acinq.lightning.io

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.*
import fr.acinq.lightning.blockchain.WatchEvent
import fr.acinq.lightning.blockchain.electrum.*
import fr.acinq.lightning.blockchain.fee.FeeratePerByte
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.channel.states.*
import fr.acinq.lightning.crypto.noise.*
import fr.acinq.lightning.db.*
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.logging.mdc
import fr.acinq.lightning.logging.withMDC
import fr.acinq.lightning.payment.*
import fr.acinq.lightning.serialization.Encryption.from
import fr.acinq.lightning.serialization.Serialization.DeserializationResult
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.utils.UUID.Companion.randomUUID
import fr.acinq.lightning.wire.*
import fr.acinq.lightning.wire.Ping
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.Channel.Factory.UNLIMITED
import kotlinx.coroutines.channels.onFailure
import kotlinx.coroutines.flow.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

sealed class PeerCommand

/** Open a channel, consuming all the spendable utxos in the wallet state provided. */
data class OpenChannel(
    val fundingAmount: Satoshi,
    val pushAmount: MilliSatoshi,
    val walletInputs: List<WalletState.Utxo>,
    val commitTxFeerate: FeeratePerKw,
    val fundingTxFeerate: FeeratePerKw,
    val channelType: ChannelType.SupportedChannelType
) : PeerCommand()

/** Consume all the spendable utxos in the wallet state provided to open a channel or splice into an existing channel. */
data class OpenOrSpliceChannel(val walletInputs: List<WalletState.Utxo>) : PeerCommand() {
    val totalAmount: Satoshi = walletInputs.map { it.amount }.sum()
}

/**
 * Initiate a channel open or a splice to allow receiving an off-chain payment.
 *
 * @param paymentAmount total payment amount (including amount that may have been received with HTLCs).
 */
data class OpenOrSplicePayment(val paymentAmount: MilliSatoshi, val preimage: ByteVector32) : PeerCommand() {
    val paymentHash: ByteVector32 = Crypto.sha256(preimage).byteVector32()
}

data class PeerConnection(val id: Long, val output: Channel<LightningMessage>, val delayedCommands: Channel<PeerCommand>, val logger: MDCLogger) {
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
data class SendPayment(val paymentId: UUID, val amount: MilliSatoshi, val recipient: PublicKey, val paymentRequest: PaymentRequest, val trampolineFeesOverride: List<TrampolineFees>? = null) : PaymentCommand() {
    val paymentHash: ByteVector32 = paymentRequest.paymentHash
}

data class PurgeExpiredPayments(val fromCreatedAt: Long, val toCreatedAt: Long) : PaymentCommand()

sealed class PeerEvent
@Deprecated("Replaced by NodeEvents", replaceWith = ReplaceWith("PaymentEvents.PaymentReceived", "fr.acinq.lightning.PaymentEvents"))
data class PaymentReceived(val incomingPayment: IncomingPayment, val received: IncomingPayment.Received) : PeerEvent()
data class PaymentProgress(val request: SendPayment, val fees: MilliSatoshi) : PeerEvent()
sealed class SendPaymentResult : PeerEvent() {
    abstract val request: SendPayment
}
data class PaymentNotSent(override val request: SendPayment, val reason: OutgoingPaymentFailure) : SendPaymentResult()
data class PaymentSent(override val request: SendPayment, val payment: LightningOutgoingPayment) : SendPaymentResult()
data class ChannelClosing(val channelId: ByteVector32) : PeerEvent()

/**
 * Useful to handle transparent migration on Phoenix Android between eclair-core and lightning-kmp.
 */
data class PhoenixAndroidLegacyInfoEvent(val info: PhoenixAndroidLegacyInfo) : PeerEvent()

/**
 * The peer we establish a connection to. This object contains the TCP socket, a flow of the channels with that peer, and watches
 * the events on those channels and processes the relevant actions. The dialogue with the peer is done in coroutines.
 *
 * @param nodeParams Low level, Lightning related parameters that our node will use in relation to this Peer.
 * @param walletParams High level parameters for our node. It especially contains the Peer's [NodeUri].
 * @param watcher Watches events from the Electrum client and publishes transactions and events.
 * @param db Wraps the various databases persisting the channels and payments data related to the Peer.
 * @param leaseRates Rates at which our peer sells their liquidity.
 * @param socketBuilder Builds the TCP socket used to connect to the Peer.
 * @param initTlvStream Optional stream of TLV for the [Init] message we send to this Peer after connection. Empty by default.
 */
@OptIn(ExperimentalStdlibApi::class)
class Peer(
    val nodeParams: NodeParams,
    val walletParams: WalletParams,
    val watcher: ElectrumWatcher,
    val db: Databases,
    val leaseRates: List<LiquidityAds.BoundedLeaseRate>,
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
    private val incomingPaymentHandler = IncomingPaymentHandler(nodeParams, db.payments, leaseRates)

    // encapsulates logic for sending payments
    private val outgoingPaymentHandler = OutgoingPaymentHandler(nodeParams, walletParams, db.payments)

    private val features = nodeParams.features

    private val ourInit = Init(features.initFeatures(), initTlvStream)
    private var theirInit: Init? = null

    val currentTipFlow = MutableStateFlow<Pair<Int, BlockHeader>?>(null)
    val onChainFeeratesFlow = MutableStateFlow<OnChainFeerates?>(null)
    val peerFeeratesFlow = MutableStateFlow<RecommendedFeerates?>(null)

    private val _channelLogger = nodeParams.loggerFactory.newLogger(ChannelState::class)
    private suspend fun ChannelState.process(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        val state = this
        val ctx = ChannelContext(
            StaticParams(nodeParams, remoteNodeId),
            currentTipFlow.filterNotNull().first().first,
            onChainFeeratesFlow.filterNotNull().first(),
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

    val finalWallet = FinalWallet(nodeParams.chain, nodeParams.keyManager.finalOnChainWallet, watcher.client, scope, nodeParams.loggerFactory)
    val swapInWallet = SwapInWallet(nodeParams.chain, nodeParams.keyManager.swapInOnChainWallet, watcher.client, scope, nodeParams.loggerFactory)

    private var swapInJob: Job? = null

    init {
        logger.info { "initializing peer" }
        launch {
            watcher.client.notifications.filterIsInstance<HeaderSubscriptionResponse>()
                .collect { msg ->
                    currentTipFlow.value = msg.blockHeight to msg.header
                }
        }
        launch {
            watcher.client.connectionStatus.filter { it is ElectrumConnectionStatus.Connected }.collect {
                // onchain fees are retrieved punctually, when electrum status moves to Connection.ESTABLISHED
                // since the application is not running most of the time, and when it is, it will be only for a few minutes, this is good enough.
                // (for a node that is online most of the time things would be different and we would need to re-evaluate onchain fee estimates on a regular basis)
                updateEstimateFees()
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
    }

    private suspend fun updateEstimateFees() {
        watcher.client.connectionStatus.filter { it is ElectrumConnectionStatus.Connected }.first()
        val sortedFees = listOf(
            watcher.client.estimateFees(2),
            watcher.client.estimateFees(6),
            watcher.client.estimateFees(18),
            watcher.client.estimateFees(144),
        )
        logger.info { "on-chain fees: $sortedFees" }
        // TODO: If some feerates are null, we may implement a retry
        onChainFeeratesFlow.value = OnChainFeerates(
            fundingFeerate = sortedFees[3] ?: FeeratePerKw(FeeratePerByte(2.sat)),
            mutualCloseFeerate = sortedFees[2] ?: FeeratePerKw(FeeratePerByte(10.sat)),
            claimMainFeerate = sortedFees[1] ?: FeeratePerKw(FeeratePerByte(20.sat)),
            fastFeerate = sortedFees[0] ?: FeeratePerKw(FeeratePerByte(50.sat))
        )
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
            } catch (ex: TcpSocket.IOException) {
                logger.warning(ex) { "Noise handshake: ${ex.message}: " }
                socket.close()
                _connectionState.value = Connection.CLOSED(ex)
                return false
            }

            val session = LightningSession(enc, dec, ck)
            // TODO use atomic counter instead
            val peerConnection = PeerConnection(connectionId, Channel(UNLIMITED), Channel(UNLIMITED), logger)
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

            suspend fun processDelayedCommands() {
                while (isActive) {
                    for (cmd in peerConnection.delayedCommands) {
                        delay(3.seconds)
                        logger.info { "processing delayed command ${cmd::class.simpleName}" }
                        input.send(cmd)
                    }
                }
            }

            suspend fun receiveLoop() {
                try {
                    while (isActive) {
                        val received = session.receive { size -> socket.receiveFully(size) }
                        try {
                            when (val msg = LightningMessage.decode(received)) {
                                // We treat this message immediately, which ensures that other operations can
                                // suspend until we receive our peer's feerates without deadlocking.
                                is RecommendedFeerates -> {
                                    logger.info { "received peer recommended feerates: $msg" }
                                    peerFeeratesFlow.value = msg
                                }
                                else -> input.send(MessageReceived(peerConnection.id, msg))
                            }
                        } catch (e: Throwable) {
                            logger.warning { "cannot deserialize message: ${received.byteVector().toHex()}" }
                        }
                    }
                    closeSocket(null)
                } catch (ex: TcpSocket.IOException) {
                    logger.warning { "TCP receive: ${ex.message}" }
                    closeSocket(ex)
                } finally {
                    peerConnection.output.close()
                }
            }

            suspend fun sendLoop() {
                try {
                    for (msg in peerConnection.output) {
                        // Avoids polluting the logs with pings/pongs
                        if (msg !is Ping && msg !is Pong) logger.info { "sending $msg" }
                        val encoded = LightningMessage.encode(msg)
                        session.send(encoded) { data, flush -> socket.send(data, flush) }
                    }
                } catch (ex: TcpSocket.IOException) {
                    logger.warning { "TCP send: ${ex.message}" }
                    closeSocket(ex)
                } finally {
                    peerConnection.output.close()
                }
            }

            launch(CoroutineName("keep-alive")) { doPing() }
            launch(CoroutineName("check-payments-timeout")) { checkPaymentsTimeout() }
            launch(CoroutineName("process-delayed-commands")) { processDelayedCommands() }
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
        logger.info { "starting swap-in watch job" }
        if (swapInJob != null) {
            logger.info { "swap-in watch job already started" }
            return
        }
        logger.info { "waiting for peer to be ready" }
        waitForPeerReady()
        swapInJob = launch {
            swapInWallet.wallet.walletStateFlow
                .combine(currentTipFlow.filterNotNull()) { walletState, currentTip -> Pair(walletState, currentTip.first) }
                .combine(peerFeeratesFlow.filterNotNull()) { (walletState, currentTip), feerates -> Triple(walletState, currentTip, feerates.fundingFeerate) }
                .combine(nodeParams.liquidityPolicy) { (walletState, currentTip, feerate), policy -> TrySwapInFlow(currentTip, walletState, feerate, policy) }
                .collect { w -> swapInCommands.send(SwapInCommand.TrySwapIn(w.currentBlockHeight, w.walletState, walletParams.swapInParams)) }
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
        connectionState.first { it is Connection.ESTABLISHED }
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
    suspend fun estimateFeeForSpliceOut(amount: Satoshi, scriptPubKey: ByteVector, targetFeerate: FeeratePerKw): Pair<FeeratePerKw, TransactionFees>? {
        return channels.values
            .filterIsInstance<Normal>()
            .firstOrNull { it.commitments.availableBalanceForSend() > amount }
            ?.let { channel ->
                val weight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = channel.commitments.active.first(), walletInputs = emptyList(), localOutputs = listOf(TxOut(amount, scriptPubKey)))
                val (actualFeerate, miningFee) = watcher.client.computeSpliceCpfpFeerate(channel.commitments, targetFeerate, spliceWeight = weight, logger)
                Pair(actualFeerate, TransactionFees(miningFee, 0.sat))
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
    suspend fun estimateFeeForSpliceCpfp(channelId: ByteVector32, targetFeerate: FeeratePerKw): Pair<FeeratePerKw, TransactionFees>? {
        return channels.values
            .filterIsInstance<Normal>()
            .find { it.channelId == channelId }
            ?.let { channel ->
                val weight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = channel.commitments.active.first(), walletInputs = emptyList(), localOutputs = emptyList())
                val (actualFeerate, miningFee) = watcher.client.computeSpliceCpfpFeerate(channel.commitments, targetFeerate, spliceWeight = weight, logger)
                Pair(actualFeerate, TransactionFees(miningFee, 0.sat))
            }
    }

    /**
     * Estimate the actual feerate to use (and corresponding fee to pay) to purchase inbound liquidity with a splice
     * that reaches the target feerate.
     */
    suspend fun estimateFeeForInboundLiquidity(amount: Satoshi, targetFeerate: FeeratePerKw, leaseRate: LiquidityAds.LeaseRate): Pair<FeeratePerKw, TransactionFees>? {
        return channels.values
            .filterIsInstance<Normal>()
            .firstOrNull()
            ?.let { channel ->
                val weight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = channel.commitments.active.first(), walletInputs = emptyList(), localOutputs = emptyList()) + leaseRate.fundingWeight
                // The mining fee below pays for the entirety of the splice transaction, including inputs and outputs from the liquidity provider.
                val (actualFeerate, miningFee) = watcher.client.computeSpliceCpfpFeerate(channel.commitments, targetFeerate, spliceWeight = weight, logger)
                // The mining fee in the lease only covers the remote node's inputs and outputs, they are already included in the mining fee above.
                val leaseFees = leaseRate.fees(actualFeerate, amount, amount)
                Pair(actualFeerate, TransactionFees(miningFee, leaseFees.serviceFee))
            }
    }

    /**
     * Do a splice out using any suitable channel
     * @return  [ChannelCommand.Commitment.Splice.Response] if a splice was attempted, or {null} if no suitable
     *          channel was found
     */
    suspend fun spliceOut(amount: Satoshi, scriptPubKey: ByteVector, feerate: FeeratePerKw): ChannelCommand.Commitment.Splice.Response? {
        return channels.values
            .filterIsInstance<Normal>()
            .firstOrNull { it.commitments.availableBalanceForSend() > amount }
            ?.let { channel ->
                val spliceCommand = ChannelCommand.Commitment.Splice.Request(
                    replyTo = CompletableDeferred(),
                    spliceIn = null,
                    spliceOut = ChannelCommand.Commitment.Splice.Request.SpliceOut(amount, scriptPubKey),
                    requestRemoteFunding = null,
                    feerate = feerate,
                    origins = listOf(),
                )
                send(WrappedChannelCommand(channel.channelId, spliceCommand))
                spliceCommand.replyTo.await()
            }
    }

    suspend fun spliceCpfp(channelId: ByteVector32, feerate: FeeratePerKw): ChannelCommand.Commitment.Splice.Response? {
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
                    feerate = feerate,
                    origins = listOf(),
                )
                send(WrappedChannelCommand(channel.channelId, spliceCommand))
                spliceCommand.replyTo.await()
            }
    }

    suspend fun requestInboundLiquidity(amount: Satoshi, feerate: FeeratePerKw, leaseRate: LiquidityAds.LeaseRate): ChannelCommand.Commitment.Splice.Response? {
        return channels.values
            .filterIsInstance<Normal>()
            .firstOrNull()
            ?.let { channel ->
                val leaseStart = currentTipFlow.filterNotNull().first().first
                val spliceCommand = ChannelCommand.Commitment.Splice.Request(
                    replyTo = CompletableDeferred(),
                    spliceIn = null,
                    spliceOut = null,
                    requestRemoteFunding = LiquidityAds.RequestRemoteFunding(amount, leaseStart, leaseRate),
                    feerate = feerate,
                    origins = listOf(),
                )
                send(WrappedChannelCommand(channel.channelId, spliceCommand))
                spliceCommand.replyTo.await()
            }
    }

    suspend fun sendLightning(amount: MilliSatoshi, paymentRequest: Bolt11Invoice): SendPaymentResult {
        val res = CompletableDeferred<SendPaymentResult>()
        val paymentId = randomUUID()
        this.launch {
            res.complete(eventsFlow
                .filterIsInstance<SendPaymentResult>()
                .filter { it.request.paymentId == paymentId }
                .first()
            )
        }
        send(SendPayment(paymentId, amount, paymentRequest.nodeId, paymentRequest))
        return res.await()
    }

    suspend fun createInvoice(paymentPreimage: ByteVector32, amount: MilliSatoshi?, description: Either<String, ByteVector32>, expirySeconds: Long? = null): Bolt11Invoice {
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
        return incomingPaymentHandler.createInvoice(paymentPreimage, amount, description, extraHops, expirySeconds)
    }

    // The (node_id, fcm_token) tuple only needs to be registered once.
    // And after that, only if the tuple changes (e.g. different fcm_token).
    fun registerFcmToken(token: String?) {
        val message = if (token == null) UnsetFCMToken else FCMToken(token)
        peerConnection?.send(message)
    }

    /** Return true if we are currently funding a channel. */
    private fun channelFundingIsInProgress(): Boolean = when (val channel = _channels.values.firstOrNull { it is Normal }) {
        is Normal -> channel.spliceStatus != SpliceStatus.None
        else -> _channels.values.any { it is WaitForAcceptChannel || it is WaitForFundingCreated || it is WaitForFundingSigned || it is WaitForFundingConfirmed || it is WaitForChannelReady }
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
                        when (val result = outgoingPaymentHandler.processAddFailed(actualChannelId, action, _channels)) {
                            is OutgoingPaymentHandler.Progress -> {
                                _eventsFlow.emit(PaymentProgress(result.request, result.fees))
                                result.actions.forEach { input.send(it) }
                            }

                            is OutgoingPaymentHandler.Failure -> _eventsFlow.emit(PaymentNotSent(result.request, result.failure))
                            null -> logger.debug { "non-final error, more partial payments are still pending: ${action.error.message}" }
                        }
                    }
                    is ChannelAction.ProcessCmdRes.AddSettledFail -> {
                        val currentTip = currentTipFlow.filterNotNull().first()
                        when (val result = outgoingPaymentHandler.processAddSettled(actualChannelId, action, _channels, currentTip.first)) {
                            is OutgoingPaymentHandler.Progress -> {
                                _eventsFlow.emit(PaymentProgress(result.request, result.fees))
                                result.actions.forEach { input.send(it) }
                            }

                            is OutgoingPaymentHandler.Success -> _eventsFlow.emit(PaymentSent(result.request, result.payment))
                            is OutgoingPaymentHandler.Failure -> _eventsFlow.emit(PaymentNotSent(result.request, result.failure))
                            null -> logger.debug { "non-final error, more partial payments are still pending: ${action.result}" }
                        }
                    }
                    is ChannelAction.ProcessCmdRes.AddSettledFulfill -> {
                        when (val result = outgoingPaymentHandler.processAddSettled(action)) {
                            is OutgoingPaymentHandler.Success -> _eventsFlow.emit(PaymentSent(result.request, result.payment))
                            is OutgoingPaymentHandler.PreimageReceived -> logger.debug(mapOf("paymentId" to result.request.paymentId)) { "payment preimage received: ${result.preimage}" }
                            null -> logger.debug { "unknown payment" }
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
                        logger.info { "storing incoming payment $action" }
                        incomingPaymentHandler.process(actualChannelId, action)
                    }
                    is ChannelAction.Storage.StoreOutgoingPayment -> {
                        logger.info { "storing $action" }
                        db.payments.addOutgoingPayment(
                            when (action) {
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
                                        miningFees = action.miningFees,
                                        lease = action.lease,
                                        createdAt = currentTimestampMillis(),
                                        confirmedAt = null,
                                        lockedAt = null
                                    )
                                is ChannelAction.Storage.StoreOutgoingPayment.ViaClose ->
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
                        )
                        _eventsFlow.emit(ChannelClosing(channelId))
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

    private suspend fun processIncomingPayment(item: Either<MaybeAddHtlc, UpdateAddHtlc>) {
        val currentBlockHeight = currentTipFlow.filterNotNull().first().first
        val currentFeerate = peerFeeratesFlow.filterNotNull().first().fundingFeerate
        val result = when (item) {
            is Either.Right -> incomingPaymentHandler.process(item.value, currentBlockHeight, currentFeerate)
            is Either.Left -> incomingPaymentHandler.process(item.value, currentBlockHeight, currentFeerate)
        }
        when (result) {
            is IncomingPaymentHandler.ProcessAddResult.Accepted -> {
                if ((result.incomingPayment.received?.receivedWith?.size ?: 0) > 1) {
                    // this was a multi-part payment, we signal that the task is finished
                    nodeParams._nodeEvents.tryEmit(SensitiveTaskEvents.TaskEnded(SensitiveTaskEvents.TaskIdentifier.IncomingMultiPartPayment(result.incomingPayment.paymentHash)))
                }
                @Suppress("DEPRECATION")
                _eventsFlow.emit(PaymentReceived(result.incomingPayment, result.received))
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
    private var peerConnection: PeerConnection? = null

    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun processEvent(cmd: PeerCommand, logger: MDCLogger) {
        when (cmd) {
            is Connected -> {
                logger.info { "new connection with id=${cmd.peerConnection.id}, sending init $ourInit" }
                peerConnection = cmd.peerConnection
                cmd.peerConnection.send(ourInit)
                // Check pending on-the-fly funding requests: we must re-send open_channel or splice_init.
                db.payments.listPendingOnTheFlyPayments().forEach { (payment, pending) ->
                    cmd.peerConnection.delayedCommands.send(OpenOrSplicePayment(pending.amount, payment.preimage))
                }
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
                                // TODO: disconnect peer
                            }
                            else -> {
                                theirInit = msg
                                _connectionState.value = Connection.ESTABLISHED
                                _channels = _channels.mapValues { entry ->
                                    val (state1, actions) = entry.value.process(ChannelCommand.Connected(ourInit, theirInit!!))
                                    processActions(entry.key, peerConnection, actions)
                                    state1
                                }
                            }
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
                            val (state1, actions1) = state.process(ChannelCommand.Init.NonInitiator(msg.temporaryChannelId, 0.sat, 0.msat, listOf(), localParams, channelConfig, theirInit!!, leaseRate = null))
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
                    is MaybeAddHtlc -> {
                        // If we don't support on-the-fly funding, we simply ignore that proposal.
                        // Our peer will fail the corresponding HTLCs after a small delay.
                        if (nodeParams.features.hasFeature(Feature.OnTheFlyFundingClient) && nodeParams.liquidityPolicy.value is LiquidityPolicy.Auto) {
                            // If a channel funding attempt is already in progress, we won't be able to immediately accept the payment.
                            // Once the channel funding is complete, we may have enough inbound liquidity to receive the payment without
                            // an on-chain operation, which is more efficient. We thus reject the payment and wait for the sender to retry.
                            if (channelFundingIsInProgress()) {
                                val rejected = LiquidityEvents.Rejected(msg.amount, 0.msat, LiquidityEvents.Source.OffChainPayment, LiquidityEvents.Rejected.Reason.ChannelFundingInProgress)
                                logger.info { "ignoring maybe_add_htlc: reason=${rejected.reason}" }
                                nodeParams._nodeEvents.emit(rejected)
                            } else {
                                processIncomingPayment(Either.Left(msg))
                            }
                        } else {
                            logger.info { "ignoring on-the-fly funding (amount=${msg.amount}): disabled by policy" }
                        }
                    }
                    is PhoenixAndroidLegacyInfo -> {
                        logger.info { "received ${msg::class.simpleName} hasChannels=${msg.hasChannels}" }
                        _eventsFlow.emit(PhoenixAndroidLegacyInfoEvent(msg))
                    }
                    is OnionMessage -> {
                        logger.info { "received ${msg::class.simpleName}" }
                        // TODO: process onion message
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
                        cmd.fundingAmount,
                        cmd.pushAmount,
                        cmd.walletInputs,
                        cmd.commitTxFeerate,
                        cmd.fundingTxFeerate,
                        localParams,
                        theirInit!!,
                        ChannelFlags(announceChannel = false, nonInitiatorPaysCommitFees = false),
                        ChannelConfig.standard,
                        cmd.channelType,
                        requestRemoteFunding = null,
                        channelOrigin = null,
                    )
                )
                val msg = actions1.filterIsInstance<ChannelAction.Message.Send>().map { it.message }.filterIsInstance<OpenDualFundedChannel>().first()
                _channels = _channels + (msg.temporaryChannelId to state1)
                processActions(msg.temporaryChannelId, peerConnection, actions1)
            }
            is OpenOrSpliceChannel -> {
                when (val channel = channels.values.firstOrNull { it is Normal }) {
                    is Normal -> {
                        // We have a channel and we are connected (otherwise state would be Offline/Syncing).
                        val targetFeerate = peerFeeratesFlow.filterNotNull().first().fundingFeerate
                        val weight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = channel.commitments.active.first(), walletInputs = cmd.walletInputs, localOutputs = emptyList())
                        val (feerate, fee) = watcher.client.computeSpliceCpfpFeerate(channel.commitments, targetFeerate, spliceWeight = weight, logger)
                        logger.info { "requesting splice-in using balance=${cmd.walletInputs.balance} feerate=$feerate fee=$fee" }
                        when (val rejected = nodeParams.liquidityPolicy.value.maybeReject(cmd.walletInputs.balance.toMilliSatoshi(), fee.toMilliSatoshi(), LiquidityEvents.Source.OnChainWallet, logger)) {
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
                                    feerate = feerate,
                                    origins = listOf(Origin.OnChainWallet(cmd.walletInputs.map { it.outPoint }.toSet(), cmd.totalAmount.toMilliSatoshi(), TransactionFees(fee, 0.sat)))
                                )
                                // If the splice fails, we immediately unlock the utxos to reuse them in the next attempt.
                                spliceCommand.replyTo.invokeOnCompletion { ex ->
                                    if (ex == null && spliceCommand.replyTo.getCompleted() is ChannelCommand.Commitment.Splice.Response.Failure) {
                                        swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                                    }
                                }
                                input.send(WrappedChannelCommand(channel.channelId, spliceCommand))
                                nodeParams._nodeEvents.emit(SwapInEvents.Requested(cmd.walletInputs))
                            }
                        }
                    }
                    else -> {
                        if (channels.values.all { it is ShuttingDown || it is Negotiating || it is Closing || it is Closed || it is Aborted }) {
                            // Either there are no channels, or they will never be suitable for a splice-in: we open a new channel.
                            val currentFeerates = peerFeeratesFlow.filterNotNull().first()
                            val requestRemoteFunding = run {
                                // We need our peer to contribute, because they must have enough funds to pay the commitment fees.
                                val inboundLiquidityTarget = when (val policy = nodeParams.liquidityPolicy.value) {
                                    is LiquidityPolicy.Disable -> LiquidityPolicy.minInboundLiquidityTarget // we don't disable creating a channel using our own wallet inputs
                                    is LiquidityPolicy.Auto -> policy.inboundLiquidityTarget ?: LiquidityPolicy.minInboundLiquidityTarget
                                }
                                val leaseRate = LiquidityAds.chooseLeaseRate(inboundLiquidityTarget, leaseRates)
                                LiquidityAds.RequestRemoteFunding(inboundLiquidityTarget, currentTipFlow.filterNotNull().first().first, leaseRate)
                            }
                            val (localFundingAmount, fees) = run {
                                val dummyFundingScript = Helpers.Funding.makeFundingPubKeyScript(Transactions.PlaceHolderPubKey, Transactions.PlaceHolderPubKey)
                                val localMiningFee = Transactions.weight2fee(currentFeerates.fundingFeerate, FundingContributions.computeWeightPaid(isInitiator = true, null, dummyFundingScript, cmd.walletInputs, emptyList()))
                                // We directly pay the on-chain fees for our inputs/outputs of the transaction.
                                val localFundingAmount = cmd.totalAmount - localMiningFee
                                val leaseFees = requestRemoteFunding.rate.fees(currentFeerates.fundingFeerate, requestRemoteFunding.fundingAmount, requestRemoteFunding.fundingAmount)
                                // We also refund the liquidity provider for some of the on-chain fees they will pay for their inputs/outputs of the transaction.
                                val totalFees = TransactionFees(miningFee = localMiningFee + leaseFees.miningFee, serviceFee = leaseFees.serviceFee)
                                Pair(localFundingAmount, totalFees)
                            }
                            if (cmd.totalAmount - fees.total < nodeParams.dustLimit) {
                                logger.warning { "cannot create channel, not enough funds to pay fees (fees=${fees.total}, available=${cmd.totalAmount})" }
                                swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                            } else {
                                when (val rejected = nodeParams.liquidityPolicy.value.maybeReject(requestRemoteFunding.fundingAmount.toMilliSatoshi(), fees.total.toMilliSatoshi(), LiquidityEvents.Source.OnChainWallet, logger)) {
                                    is LiquidityEvents.Rejected -> {
                                        logger.info { "rejecting channel open: reason=${rejected.reason}" }
                                        nodeParams._nodeEvents.emit(rejected)
                                        swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                                    }
                                    else -> {
                                        // We ask our peer to pay the commit tx fees.
                                        val localParams = LocalParams(nodeParams, isChannelOpener = true, payCommitTxFees = false)
                                        val channelFlags = ChannelFlags(announceChannel = false, nonInitiatorPaysCommitFees = true)
                                        val (state, actions) = WaitForInit.process(
                                            ChannelCommand.Init.Initiator(
                                                fundingAmount = localFundingAmount,
                                                pushAmount = 0.msat,
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
                                        )
                                        val msg = actions.filterIsInstance<ChannelAction.Message.Send>().map { it.message }.filterIsInstance<OpenDualFundedChannel>().first()
                                        _channels = _channels + (msg.temporaryChannelId to state)
                                        processActions(msg.temporaryChannelId, peerConnection, actions)
                                        nodeParams._nodeEvents.emit(SwapInEvents.Requested(cmd.walletInputs))
                                    }
                                }
                            }
                        } else {
                            // There are existing channels but not immediately usable (e.g. creating, disconnected), we don't do anything yet.
                            logger.warning { "ignoring request to add utxos to channel, existing channels are not ready for splice-in: ${channels.values.map { it::class.simpleName }}" }
                            swapInCommands.trySend(SwapInCommand.UnlockWalletInputs(cmd.walletInputs.map { it.outPoint }.toSet()))
                        }
                    }
                }
            }
            is OpenOrSplicePayment -> {
                val channel = channels.values.firstOrNull { it is Normal }
                val currentFeerates = peerFeeratesFlow.filterNotNull().first()
                // We need our peer to contribute, because they must have enough funds to pay the commitment fees.
                // They will fund more than what we request to also cover the maybe_add_htlc parts that they will push to us.
                // We only pay fees for the additional liquidity we request, not for the maybe_add_htlc amounts.
                val remoteFundingAmount = when (val policy = nodeParams.liquidityPolicy.value) {
                    // We already checked our liquidity policy in the IncomingPaymentHandler before accepting the payment.
                    // If it is now disabled, it means the user concurrently updated their policy, but we're already committed
                    // to accepting this payment, which passed the previous policy.
                    is LiquidityPolicy.Disable -> LiquidityPolicy.minInboundLiquidityTarget
                    is LiquidityPolicy.Auto -> policy.inboundLiquidityTarget ?: LiquidityPolicy.minInboundLiquidityTarget
                }
                val leaseRate = LiquidityAds.chooseLeaseRate(remoteFundingAmount, leaseRates)
                val requestRemoteFunding = LiquidityAds.RequestRemoteFunding(remoteFundingAmount, currentTipFlow.filterNotNull().first().first, leaseRate)
                when {
                    channelFundingIsInProgress() -> {
                        logger.warning { "delaying on-the-fly funding, funding is already in progress" }
                        peerConnection?.delayedCommands?.send(cmd)
                    }
                    channel is Normal -> {
                        // We don't contribute any input or output, but we must pay on-chain fees for the shared input and output.
                        // We pay those on-chain fees using our current channel balance.
                        val localBalance = channel.commitments.active.first().localCommit.spec.toLocal
                        val weight = FundingContributions.computeWeightPaid(isInitiator = true, commitment = channel.commitments.active.first(), walletInputs = listOf(), localOutputs = emptyList())
                        val (targetFeerate, localMiningFee) = watcher.client.computeSpliceCpfpFeerate(channel.commitments, currentFeerates.fundingFeerate, spliceWeight = weight, logger)
                        val fundingFeerate = when {
                            localBalance <= localMiningFee * 0.75 -> {
                                // Our current balance is too low to pay the on-chain fees.
                                // We consume all of it in on-chain fees, and also target a higher feerate.
                                // This ensures that the resulting feerate won't be too low compared to our target.
                                // We must cover the shared input and the shared output, which is a lot of weight, so we add 50%.
                                targetFeerate * 1.5
                            }
                            else -> targetFeerate
                        }
                        val leaseFees = leaseRate.fees(fundingFeerate, remoteFundingAmount, remoteFundingAmount)
                        val totalFees = TransactionFees(miningFee = localMiningFee.min(localBalance.truncateToSatoshi()) + leaseFees.miningFee, serviceFee = leaseFees.serviceFee)
                        logger.info { "requesting on-the-fly splice for paymentHash=${cmd.paymentHash} feerate=$fundingFeerate fee=${totalFees.total}" }
                        val spliceCommand = ChannelCommand.Commitment.Splice.Request(
                            replyTo = CompletableDeferred(),
                            spliceIn = null,
                            spliceOut = null,
                            requestRemoteFunding = requestRemoteFunding,
                            feerate = fundingFeerate,
                            origins = listOf(Origin.OffChainPayment(cmd.preimage, cmd.paymentAmount, totalFees))
                        )
                        val (state, actions) = channel.process(spliceCommand)
                        _channels = _channels + (channel.channelId to state)
                        processActions(channel.channelId, peerConnection, actions)
                    }
                    channels.values.all { it is ShuttingDown || it is Negotiating || it is Closing || it is Closed || it is Aborted } -> {
                        // We ask our peer to pay the commit tx fees.
                        val localParams = LocalParams(nodeParams, isChannelOpener = true, payCommitTxFees = false)
                        val channelFlags = ChannelFlags(announceChannel = false, nonInitiatorPaysCommitFees = true)
                        // Since we don't have inputs to contribute, we're unable to pay on-chain fees for the shared output.
                        // We target a higher feerate so that the effective feerate isn't too low compared to our target.
                        // We must cover the shared output, which doesn't add too much weight, so we add 25%.
                        val fundingFeerate = currentFeerates.fundingFeerate * 1.25
                        val leaseFees = leaseRate.fees(fundingFeerate, remoteFundingAmount, remoteFundingAmount)
                        // We don't pay any local on-chain fees, our fee is only for the liquidity lease.
                        val totalFees = TransactionFees(miningFee = leaseFees.miningFee, serviceFee = leaseFees.serviceFee)
                        logger.info { "requesting on-the-fly channel for paymentHash=${cmd.paymentHash} feerate=$fundingFeerate fee=${leaseFees.total}" }
                        val (state, actions) = WaitForInit.process(
                            ChannelCommand.Init.Initiator(
                                fundingAmount = 0.sat, // we don't have funds to contribute
                                pushAmount = 0.msat,
                                walletInputs = listOf(),
                                commitTxFeerate = currentFeerates.commitmentFeerate,
                                fundingTxFeerate = fundingFeerate,
                                localParams = localParams,
                                remoteInit = theirInit!!,
                                channelFlags = channelFlags,
                                channelConfig = ChannelConfig.standard,
                                channelType = ChannelType.SupportedChannelType.AnchorOutputsZeroReserve,
                                requestRemoteFunding = requestRemoteFunding,
                                channelOrigin = Origin.OffChainPayment(cmd.preimage, cmd.paymentAmount, totalFees),
                            )
                        )
                        val msg = actions.filterIsInstance<ChannelAction.Message.Send>().map { it.message }.filterIsInstance<OpenDualFundedChannel>().first()
                        _channels = _channels + (msg.temporaryChannelId to state)
                        processActions(msg.temporaryChannelId, peerConnection, actions)
                    }
                    else -> {
                        // There is an existing channel but not immediately usable (e.g. disconnected), we don't do anything yet.
                        logger.warning { "delaying on-the-fly funding, existing channels are not ready for splice-in: ${channels.values.map { it::class.simpleName }}" }
                        peerConnection?.delayedCommands?.send(cmd)
                    }
                }
            }
            is SendPayment -> {
                val currentTip = currentTipFlow.filterNotNull().first()
                when (val result = outgoingPaymentHandler.sendPayment(cmd, _channels, currentTip.first)) {
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
                        peerConnection = null
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
        }
    }
}
