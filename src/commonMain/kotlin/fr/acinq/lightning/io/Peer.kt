package fr.acinq.lightning.io

import fr.acinq.bitcoin.*
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomKeyPath
import fr.acinq.lightning.blockchain.GetTxWithMeta
import fr.acinq.lightning.blockchain.WatchEvent
import fr.acinq.lightning.blockchain.electrum.*
import fr.acinq.lightning.blockchain.fee.FeeratePerByte
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.crypto.noise.*
import fr.acinq.lightning.db.Databases
import fr.acinq.lightning.db.IncomingPayment
import fr.acinq.lightning.db.OutgoingPayment
import fr.acinq.lightning.payment.IncomingPaymentHandler
import fr.acinq.lightning.payment.OutgoingPaymentFailure
import fr.acinq.lightning.payment.OutgoingPaymentHandler
import fr.acinq.lightning.payment.PaymentRequest
import fr.acinq.lightning.serialization.Serialization
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import fr.acinq.lightning.wire.Ping
import fr.acinq.secp256k1.Hex
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BroadcastChannel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.Channel.Factory.BUFFERED
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.flow.*
import kotlin.time.ExperimentalTime
import kotlin.time.seconds

sealed class PeerEvent
data class BytesReceived(val data: ByteArray) : PeerEvent()
data class WatchReceived(val watch: WatchEvent) : PeerEvent()
data class WrappedChannelEvent(val channelId: ByteVector32, val channelEvent: ChannelEvent) : PeerEvent()
object Disconnected : PeerEvent()

sealed class PaymentEvent : PeerEvent()
data class ReceivePayment(val paymentPreimage: ByteVector32, val amount: MilliSatoshi?, val description: String, val expirySeconds: Long? = null, val result: CompletableDeferred<PaymentRequest>) : PaymentEvent()
object CheckPaymentsTimeout : PaymentEvent()
data class PayToOpenResponseEvent(val payToOpenResponse: PayToOpenResponse) : PeerEvent()
data class SendPayment(val paymentId: UUID, val amount: MilliSatoshi, val recipient: PublicKey, val details: OutgoingPayment.Details.Normal) : PaymentEvent() {
    val paymentHash: ByteVector32 = details.paymentHash
}

sealed class PeerListenerEvent
data class PaymentRequestGenerated(val receivePayment: ReceivePayment, val request: String) : PeerListenerEvent()
data class PaymentReceived(val incomingPayment: IncomingPayment, val received: IncomingPayment.Received) : PeerListenerEvent()
data class PaymentProgress(val request: SendPayment, val fees: MilliSatoshi) : PeerListenerEvent()
data class PaymentNotSent(val request: SendPayment, val reason: OutgoingPaymentFailure) : PeerListenerEvent()
data class PaymentSent(val request: SendPayment, val payment: OutgoingPayment) : PeerListenerEvent()
data class ChannelClosing(val channelId: ByteVector32) : PeerListenerEvent()

object SendSwapInRequest : PeerEvent()
data class SwapInResponseEvent(val swapInResponse: SwapInResponse) : PeerListenerEvent()
data class SwapInPendingEvent(val swapInPending: SwapInPending) : PeerListenerEvent()
data class SwapInConfirmedEvent(val swapInConfirmed: SwapInConfirmed) : PeerListenerEvent()

@OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class, ExperimentalTime::class)
class Peer(
    val nodeParams: NodeParams,
    val walletParams: WalletParams,
    val watcher: ElectrumWatcher,
    val db: Databases,
    socketBuilder: TcpSocket.Builder?,
    scope: CoroutineScope
) : CoroutineScope by scope {
    companion object {
        private const val prefix: Byte = 0x00
        private val prologue = "lightning".encodeToByteArray()
    }

    public var socketBuilder: TcpSocket.Builder? = socketBuilder
        set(value) {
            logger.debug { "n:$remoteNodeId swap socket builder=$value" }
            field = value
        }

    public val remoteNodeId: PublicKey = walletParams.trampolineNode.id

    private val input = Channel<PeerEvent>(BUFFERED)
    private var output = Channel<ByteArray>(BUFFERED)
    public val outputLightningMessages: ReceiveChannel<ByteArray> get() = output

    private val logger by lightningLogger()

    // The channels map, as initially loaded from the database at "boot" (on Peer.init).
    // As the channelsFlow is unavailable until the electrum connection is up-and-running,
    // this may provide useful information for the UI.
    private val _bootChannelsFlow = MutableStateFlow<Map<ByteVector32, ChannelState>?>(null)
    val bootChannelsFlow: StateFlow<Map<ByteVector32, ChannelState>?> get() = _bootChannelsFlow

    // channels map, indexed by channel id
    // note that a channel starts with a temporary id then switches to its final id once the funding tx is known
    private val _channelsFlow = MutableStateFlow<Map<ByteVector32, ChannelState>>(HashMap())
    val channelsFlow: StateFlow<Map<ByteVector32, ChannelState>> get() = _channelsFlow

    private var _channels by _channelsFlow
    val channels: Map<ByteVector32, ChannelState> get() = _channelsFlow.value

    private val _connectionState = MutableStateFlow(Connection.CLOSED)
    val connectionState: StateFlow<Connection> get() = _connectionState

    private val listenerEventChannel = BroadcastChannel<PeerListenerEvent>(BUFFERED)

    // encapsulates logic for validating incoming payments
    private val incomingPaymentHandler = IncomingPaymentHandler(nodeParams, walletParams, db.payments)

    // encapsulates logic for sending payments
    private val outgoingPaymentHandler = OutgoingPaymentHandler(nodeParams.nodeId, walletParams, db.payments)

    private val features = nodeParams.features

    private val ourInit = Init(features.toByteArray().toByteVector())
    private var theirInit: Init? = null

    public val currentTipFlow = MutableStateFlow<Pair<Int, BlockHeader>?>(null)
    public val onChainFeeratesFlow = MutableStateFlow<OnChainFeerates?>(null)

    init {
        val electrumNotificationsChannel = watcher.client.openNotificationsSubscription()
        launch {
            electrumNotificationsChannel.consumeAsFlow().filterIsInstance<HeaderSubscriptionResponse>()
                .collect { msg ->
                    currentTipFlow.value = msg.height to msg.header
                    input.send(WrappedChannelEvent(ByteVector32.Zeroes, ChannelEvent.NewBlock(msg.height, msg.header)))
                }
        }
        launch {
            watcher.client.connectionState.filter { it == Connection.ESTABLISHED }.collect {
                watcher.client.sendMessage(AskForHeaderSubscriptionUpdate)
                // onchain fees are retrieved punctually, when electrum status moves to Connection.ESTABLISHED
                // since the application is not running most of the time, and when it is, it will be only for a few minutes, this is good enough.
                // (for a node that is online most of the time things would be different and we would need to re-evaluate onchain fee estimates on a regular basis)
                updateEstimateFees()
            }
        }
        launch {
            watcher.openWatchNotificationsFlow().collect {
                logger.debug { "n:$remoteNodeId notification: $it" }
                input.send(WrappedChannelEvent(it.channelId, ChannelEvent.WatchReceived(it)))
            }
        }
        launch {
            watcher.openTxNotificationsFlow().collect {
                logger.debug { "n:$remoteNodeId tx: ${it.second} for channel: ${it.first}" }
                input.send(WrappedChannelEvent(it.first, ChannelEvent.GetFundingTxResponse(it.second)))
            }
        }
        launch {
            // we don't restore closed channels
            val bootChannels = db.channels.listLocalChannels().filterNot { it is Closed }
            _bootChannelsFlow.value = bootChannels.map { it.channelId to it }.toMap()
            // restore channels (nb: suspends on currentTipFlow & onChainFeeratesFlow)
            val channelIds = bootChannels.map {
                logger.info { "n:$remoteNodeId restoring ${it.channelId}" }
                val state = WaitForInit(
                    staticParams = StaticParams(nodeParams, remoteNodeId),
                    currentTip = currentTipFlow.filterNotNull().first(),
                    currentOnChainFeerates = onChainFeeratesFlow.filterNotNull().first()
                )
                val (state1, actions) = state.process(ChannelEvent.Restore(it as ChannelState))
                processActions(it.channelId, actions)
                _channels = _channels + (it.channelId to state1)
                it.channelId
            }
            logger.info { "n:$remoteNodeId restored channels: ${channelIds.joinToString(", ")}" }
            launch {
                // If we have some htlcs that have timed out, we may need to close channels to ensure we don't lose funds.
                // But maybe we were offline for too long and it is why our peer couldn't settle these htlcs in time.
                // We give them a bit of time after we reconnect to send us their latest htlc updates.
                delay(timeMillis = nodeParams.checkHtlcTimeoutAfterStartupDelaySeconds.toLong() * 1000)
                logger.info { "n:$remoteNodeId checking for timed out htlcs for channels: ${channelIds.joinToString(", ")}" }
                channelIds.forEach { input.send(WrappedChannelEvent(it, ChannelEvent.CheckHtlcTimeout)) }
            }
            run()
        }
        launch {
            var previousState = connectionState.value
            connectionState.filter { it != previousState }.collect {
                logger.info { "n:$remoteNodeId connection state changed: $it" }
                if (it == Connection.CLOSED) input.send(Disconnected)
                previousState = it
            }
        }
    }

    private suspend fun updateEstimateFees() {
        val electrumFeesChannel = watcher.client.openNotificationsSubscription()
        val flow = electrumFeesChannel.consumeAsFlow().filterIsInstance<EstimateFeeResponse>()

        watcher.client.connectionState.filter { it == Connection.ESTABLISHED }.first()
        watcher.client.sendElectrumRequest(EstimateFees(2))
        watcher.client.sendElectrumRequest(EstimateFees(6))
        watcher.client.sendElectrumRequest(EstimateFees(10))
        val fees = mutableListOf<EstimateFeeResponse>()
        flow.take(3).toCollection(fees)
        logger.info { "on-chain fees: $fees" }
        val sortedFees = fees.sortedBy { it.confirmations }
        // TODO: If some feerates are null, we may implement a retry
        onChainFeeratesFlow.value = OnChainFeerates(
            mutualCloseFeerate = sortedFees[2].feerate ?: FeeratePerKw(FeeratePerByte(20.sat)),
            claimMainFeerate = sortedFees[1].feerate ?: FeeratePerKw(FeeratePerByte(20.sat)),
            fastFeerate = sortedFees[0].feerate ?: FeeratePerKw(FeeratePerByte(50.sat))
        )
    }

    fun connect() {
        if (connectionState.value == Connection.CLOSED) establishConnection()
        else logger.warning { "Peer is already connecting / connected" }
    }

    fun disconnect() {
        if (this::socket.isInitialized) socket.close()
        output.close()
    }

    // Warning : lateinit vars have to be used AFTER their init to avoid any crashes
    //
    // This shouldn't be used outside the establishedConnection() function
    // Except from the disconnect() one that check if the lateinit var has been initialized
    private lateinit var socket: TcpSocket
    private fun establishConnection() = launch {
        logger.info { "n:$remoteNodeId connecting to ${walletParams.trampolineNode.host}" }
        _connectionState.value = Connection.ESTABLISHING
        socket = try {
            socketBuilder?.connect(walletParams.trampolineNode.host, walletParams.trampolineNode.port) ?: error("socket builder is null.")
        } catch (ex: Throwable) {
            logger.warning { "n:$remoteNodeId TCP connect: ${ex.message}" }
            _connectionState.value = Connection.CLOSED
            return@launch
        }

        fun closeSocket() {
            if (_connectionState.value == Connection.CLOSED) return
            logger.warning { "closing TCP socket." }
            socket.close()
            _connectionState.value = Connection.CLOSED
            cancel()
        }

        val priv = nodeParams.nodePrivateKey
        val pub = priv.publicKey()
        val keyPair = Pair(pub.value.toByteArray(), priv.value.toByteArray())
        val (enc, dec, ck) = try {
            handshake(
                keyPair,
                remoteNodeId.value.toByteArray(),
                { s -> socket.receiveFully(s) },
                { b -> socket.send(b) }
            )
        } catch (ex: TcpSocket.IOException) {
            logger.warning { "n:$remoteNodeId TCP handshake: ${ex.message}" }
            closeSocket()
            return@launch
        }
        val session = LightningSession(enc, dec, ck)

        suspend fun send(message: ByteArray) {
            try {
                session.send(message) { data, flush -> socket.send(data, flush) }
            } catch (ex: TcpSocket.IOException) {
                logger.warning { "n:$remoteNodeId TCP send: ${ex.message}" }
                closeSocket()
            }
        }

        logger.info { "n:$remoteNodeId sending init $ourInit" }
        send(LightningMessage.encode(ourInit))

        suspend fun doPing() {
            val ping = Ping(10, ByteVector("deadbeef"))
            while (isActive) {
                delay(30.seconds)
                sendToPeer(ping)
            }
        }

        suspend fun checkPaymentsTimeout() {
            while (isActive) {
                delay(30.seconds)
                input.send(CheckPaymentsTimeout)
            }
        }

        suspend fun listen() {
            try {
                while (isActive) {
                    val received = session.receive { size -> socket.receiveFully(size) }
                    input.send(BytesReceived(received))
                }
            } catch (ex: TcpSocket.IOException) {
                logger.warning { "n:$remoteNodeId TCP receive: ${ex.message}" }
            } finally {
                closeSocket()
            }
        }

        suspend fun respond() {
            // Reset the output channel to avoid sending obsolete messages
            output = Channel(BUFFERED)
            for (msg in output) send(msg)
        }

        launch { doPing() }
        launch { checkPaymentsTimeout() }
        launch { respond() }

        listen() // This suspends until the coroutines is cancelled or the socket is closed
    }

    suspend fun send(event: PeerEvent) {
        input.send(event)
    }

    fun openListenerEventSubscription() = listenerEventChannel.openSubscription()

    suspend fun sendToPeer(msg: LightningMessage) {
        val encoded = LightningMessage.encode(msg)
        // Avoids polluting the logs with pings/pongs
        if (msg !is Ping && msg !is Pong) logger.info { "n:$remoteNodeId sending $msg" }
        if (!output.isClosedForSend) output.send(encoded)
    }

    // The (node_id, fcm_token) tuple only needs to be registered once.
    // And after that, only if the tuple changes (e.g. different fcm_token).
    fun registerFcmToken(token: String?) {
        launch {
            sendToPeer(if (token == null) UnsetFCMToken else FCMToken(token))
        }
    }

    private suspend fun processActions(channelId: ByteVector32, actions: List<ChannelAction>) {
        var actualChannelId: ByteVector32 = channelId
        actions.forEach { action ->
            when {
                action is ChannelAction.Message.Send && _connectionState.value == Connection.ESTABLISHED -> sendToPeer(action.message)
                // sometimes channel actions include "self" command (such as CMD_SIGN)
                action is ChannelAction.Message.SendToSelf -> input.send(WrappedChannelEvent(actualChannelId, ChannelEvent.ExecuteCommand(action.command)))
                action is ChannelAction.Blockchain.SendWatch -> watcher.watch(action.watch)
                action is ChannelAction.Blockchain.PublishTx -> watcher.publish(action.tx)
                action is ChannelAction.Blockchain.GetFundingTx -> watcher.send(GetTxWithMetaEvent(GetTxWithMeta(channelId, action.txid)))
                action is ChannelAction.ProcessIncomingHtlc -> processIncomingPayment(Either.Right(action.add))
                action is ChannelAction.ProcessCmdRes.NotExecuted -> logger.warning(action.t) { "n:$remoteNodeId c:$actualChannelId command not executed" }
                action is ChannelAction.ProcessCmdRes.AddFailed -> {
                    when (val result = outgoingPaymentHandler.processAddFailed(actualChannelId, action, _channels)) {
                        is OutgoingPaymentHandler.Progress -> {
                            listenerEventChannel.send(PaymentProgress(result.request, result.fees))
                            result.actions.forEach { input.send(it) }
                        }
                        is OutgoingPaymentHandler.Failure -> listenerEventChannel.send(PaymentNotSent(result.request, result.failure))
                        null -> logger.debug { "n:$remoteNodeId c:$actualChannelId non-final error, more partial payments are still pending: ${action.error.message}" }
                    }
                }
                action is ChannelAction.ProcessCmdRes.AddSettledFail -> {
                    val currentTip = currentTipFlow.filterNotNull().first()
                    when (val result = outgoingPaymentHandler.processAddSettled(actualChannelId, action, _channels, currentTip.first)) {
                        is OutgoingPaymentHandler.Progress -> {
                            listenerEventChannel.send(PaymentProgress(result.request, result.fees))
                            result.actions.forEach { input.send(it) }
                        }
                        is OutgoingPaymentHandler.Success -> listenerEventChannel.send(PaymentSent(result.request, result.payment))
                        is OutgoingPaymentHandler.Failure -> listenerEventChannel.send(PaymentNotSent(result.request, result.failure))
                        null -> logger.debug { "n:$remoteNodeId c:$actualChannelId non-final error, more partial payments are still pending: ${action.result}" }
                    }
                }
                action is ChannelAction.ProcessCmdRes.AddSettledFulfill -> {
                    when (val result = outgoingPaymentHandler.processAddSettled(action)) {
                        is OutgoingPaymentHandler.Success -> listenerEventChannel.send(PaymentSent(result.request, result.payment))
                        is OutgoingPaymentHandler.PreimageReceived -> logger.debug { "n:$remoteNodeId c:$actualChannelId p:${result.request.paymentId} payment preimage received: ${result.preimage}" }
                        null -> logger.debug { "n:$remoteNodeId c:$actualChannelId unknown payment" }
                    }
                }
                action is ChannelAction.Storage.StoreState -> {
                    logger.info { "n:$remoteNodeId c:$actualChannelId storing state=${action.data::class}" }
                    db.channels.addOrUpdateChannel(action.data)
                }
                action is ChannelAction.Storage.StoreHtlcInfos -> {
                    action.htlcs.forEach { db.channels.addHtlcInfo(actualChannelId, it.commitmentNumber, it.paymentHash, it.cltvExpiry) }
                }
                action is ChannelAction.Storage.StoreIncomingAmount -> {
                    logger.info { "n:$remoteNodeId c:$channelId storing incoming amount=${action.amount} with origin=${action.origin}" }
                    incomingPaymentHandler.process(actualChannelId, action)
                }
                action is ChannelAction.Storage.GetHtlcInfos -> {
                    val htlcInfos = db.channels.listHtlcInfos(actualChannelId, action.commitmentNumber).map { ChannelAction.Storage.HtlcInfo(actualChannelId, action.commitmentNumber, it.first, it.second) }
                    input.send(WrappedChannelEvent(actualChannelId, ChannelEvent.GetHtlcInfosResponse(action.revokedCommitTxId, htlcInfos)))
                }
                action is ChannelAction.Storage.StoreChannelClosing -> {
                    val dbId = UUID.fromBytes(channelId.take(16).toByteArray())
                    val recipient = if (action.isSentToDefaultAddress) nodeParams.nodeId else PublicKey.Generator
                    val payment = OutgoingPayment(
                        id = dbId,
                        recipientAmount = action.amount,
                        recipient = recipient,
                        details = OutgoingPayment.Details.ChannelClosing(
                            channelId = channelId,
                            closingAddress = action.closingAddress,
                            isSentToDefaultAddress = action.isSentToDefaultAddress
                        ),
                        parts = listOf<OutgoingPayment.Part>(),
                        status = OutgoingPayment.Status.Pending
                    )
                    db.payments.addOutgoingPayment(payment)
                    listenerEventChannel.send(ChannelClosing(channelId))
                }
                action is ChannelAction.Storage.StoreChannelClosed -> {
                    val dbId = UUID.fromBytes(channelId.take(16).toByteArray())
                    val completed = OutgoingPayment.Status.Completed.Succeeded.OnChain(action.txids, action.claimed, action.closingType)
                    db.payments.completeOutgoingPayment(dbId, completed)
                    listenerEventChannel.send(ChannelClosing(channelId))
                }
                action is ChannelAction.ChannelId.IdSwitch -> {
                    logger.info { "n:$remoteNodeId c:$actualChannelId switching channel id from ${action.oldChannelId} to ${action.newChannelId}" }
                    actualChannelId = action.newChannelId
                    _channels[action.oldChannelId]?.let { _channels = _channels + (action.newChannelId to it) }
                }
                action is ChannelAction.ProcessLocalError -> logger.error(action.error) { "error in channel $actualChannelId" }
                else -> logger.warning { "n:$remoteNodeId c:$actualChannelId unhandled action: ${action::class}" }
            }
        }
    }

    private suspend fun processIncomingPayment(item: Either<PayToOpenRequest, UpdateAddHtlc>) {
        val currentBlockHeight = currentTipFlow.filterNotNull().first().first
        val result = when (item) {
            is Either.Right -> incomingPaymentHandler.process(item.value, currentBlockHeight)
            is Either.Left -> incomingPaymentHandler.process(item.value, currentBlockHeight)
        }
        when (result) {
            is IncomingPaymentHandler.ProcessAddResult.Accepted -> listenerEventChannel.send(PaymentReceived(result.incomingPayment, result.received))
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

        val writer = makeWriter(ourKeys, theirPubkey)
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

    private fun makeWriter(localStatic: Pair<ByteArray, ByteArray>, remoteStatic: ByteArray) = HandshakeState.initializeWriter(
        handshakePatternXK, prologue,
        localStatic, Pair(ByteArray(0), ByteArray(0)), remoteStatic, ByteArray(0),
        Secp256k1DHFunctions, Chacha20Poly1305CipherFunctions, SHA256HashFunctions
    )

    private fun makeReader(localStatic: Pair<ByteArray, ByteArray>) = HandshakeState.initializeReader(
        handshakePatternXK, prologue,
        localStatic, Pair(ByteArray(0), ByteArray(0)), ByteArray(0), ByteArray(0),
        Secp256k1DHFunctions, Chacha20Poly1305CipherFunctions, SHA256HashFunctions
    )

    private suspend fun run() {
        logger.info { "n:$remoteNodeId peer is active" }
        for (event in input) {
            processEvent(event)
        }
    }

    private suspend fun processEvent(event: PeerEvent) {
        when {
            event is BytesReceived -> {
                val msg = LightningMessage.decode(event.data)
                msg?.let { if (it !is Ping && it !is Pong) logger.info { "n:$remoteNodeId received $it" } }
                when {
                    msg is Init -> {
                        val theirFeatures = Features(msg.features)
                        logger.info { "n:$remoteNodeId peer is using features $theirFeatures" }
                        when (val error = Features.validateFeatureGraph(features)) {
                            is Features.Companion.FeatureException -> {
                                logger.error(error)
                                // TODO: disconnect peer
                            }
                            null -> {
                                theirInit = msg
                                _connectionState.value = Connection.ESTABLISHED
                                _channels = _channels.mapValues { entry ->
                                    val (state1, actions) = entry.value.process(ChannelEvent.Connected(ourInit, theirInit!!))
                                    processActions(entry.key, actions)
                                    state1
                                }
                            }
                        }
                    }
                    msg is Ping -> {
                        val pong = Pong(ByteVector(ByteArray(msg.pongLength)))
                        sendToPeer(pong)
                    }
                    msg is Pong -> {
                        logger.debug { "n:$remoteNodeId received pong" }
                    }
                    msg is Warning -> {
                        // NB: we don't forward warnings to the channel because it shouldn't take any automatic action,
                        // these warnings are meant for humans.
                        logger.warning { "n:$remoteNodeId c:${msg.channelId} peer sent warning: ${msg.toAscii()}" }
                    }
                    msg is Error && msg.channelId == ByteVector32.Zeroes -> {
                        logger.error { "n:$remoteNodeId connection error: ${msg.toAscii()}" }
                    }
                    msg is OpenChannel && theirInit == null -> {
                        logger.error { "n:$remoteNodeId they sent open_channel before init" }
                    }
                    msg is OpenChannel && _channels.containsKey(msg.temporaryChannelId) -> {
                        logger.warning { "n:$remoteNodeId ignoring open_channel with duplicate temporaryChannelId=${msg.temporaryChannelId}" }
                    }
                    msg is OpenChannel -> {
                        val fundingKeyPath = randomKeyPath(4)
                        val fundingPubkey = nodeParams.keyManager.fundingPublicKey(fundingKeyPath)
                        val (_, closingPubkeyScript) = nodeParams.keyManager.closingPubkeyScript(fundingPubkey.publicKey)
                        val localParams = LocalParams(
                            nodeParams.nodeId,
                            nodeParams.keyManager.channelKeys(fundingKeyPath),
                            nodeParams.dustLimit,
                            nodeParams.maxHtlcValueInFlightMsat,
                            Satoshi(600),
                            nodeParams.htlcMinimum,
                            nodeParams.toRemoteDelayBlocks,
                            nodeParams.maxAcceptedHtlcs,
                            false,
                            closingPubkeyScript.toByteVector(),
                            features
                        )
                        val state = WaitForInit(
                            StaticParams(nodeParams, remoteNodeId),
                            currentTipFlow.filterNotNull().first(),
                            onChainFeeratesFlow.filterNotNull().first()
                        )
                        val channelConfig = ChannelConfig.standard
                        val (state1, actions1) = state.process(ChannelEvent.InitFundee(msg.temporaryChannelId, localParams, channelConfig, theirInit!!))
                        val (state2, actions2) = state1.process(ChannelEvent.MessageReceived(msg))
                        processActions(msg.temporaryChannelId, actions1 + actions2)
                        _channels = _channels + (msg.temporaryChannelId to state2)
                        logger.info { "n:$remoteNodeId c:${msg.temporaryChannelId} new state: ${state2::class}" }
                    }
                    msg is ChannelReestablish && !_channels.containsKey(msg.channelId) -> {
                        if (msg.channelData.isEmpty()) {
                            sendToPeer(Error(msg.channelId, "unknown channel"))
                        } else {
                            when (val decrypted = runTrying { Serialization.decrypt(nodeParams.nodePrivateKey.value, msg.channelData, nodeParams) }) {
                                is Try.Success -> {
                                    logger.warning { "n:$remoteNodeId restoring channelId=${msg.channelId} from peer backup" }
                                    val backup = decrypted.result
                                    val state = WaitForInit(StaticParams(nodeParams, remoteNodeId), currentTipFlow.filterNotNull().first(), onChainFeeratesFlow.filterNotNull().first())
                                    val event1 = ChannelEvent.Restore(backup as ChannelState)
                                    val (state1, actions1) = state.process(event1)
                                    processActions(msg.channelId, actions1)

                                    val event2 = ChannelEvent.Connected(ourInit, theirInit!!)
                                    val (state2, actions2) = state1.process(event2)
                                    processActions(msg.channelId, actions2)

                                    val event3 = ChannelEvent.MessageReceived(msg)
                                    val (state3, actions3) = state2.process(event3)
                                    processActions(msg.channelId, actions3)
                                    _channels = _channels + (msg.channelId to state3)
                                }
                                is Try.Failure -> {
                                    logger.error(decrypted.error) { "n:$remoteNodeId failed to restore channelId=${msg.channelId} from peer backup" }
                                    sendToPeer(Error(msg.channelId, "unknown channel"))
                                }
                            }
                        }
                    }
                    msg is HasTemporaryChannelId && !_channels.containsKey(msg.temporaryChannelId) -> {
                        logger.error { "n:$remoteNodeId received ${msg::class} for unknown temporary channel ${msg.temporaryChannelId}" }
                        sendToPeer(Error(msg.temporaryChannelId, "unknown channel"))
                    }
                    msg is HasTemporaryChannelId -> {
                        logger.info { "n:$remoteNodeId received ${msg::class} for temporary channel ${msg.temporaryChannelId}" }
                        val state = _channels[msg.temporaryChannelId] ?: error("channel ${msg.temporaryChannelId} not found")
                        val event1 = ChannelEvent.MessageReceived(msg)
                        val (state1, actions) = state.process(event1)
                        processActions(msg.temporaryChannelId, actions)
                        _channels = _channels + (msg.temporaryChannelId to state1)
                        logger.info { "n:$remoteNodeId c:${msg.temporaryChannelId} new state: ${state1::class}" }
                        actions.filterIsInstance<ChannelAction.ChannelId.IdSwitch>().forEach {
                            logger.info { "n:$remoteNodeId id switch from ${it.oldChannelId} to ${it.newChannelId}" }
                            _channels = _channels - it.oldChannelId + (it.newChannelId to state1)
                        }
                    }
                    msg is HasChannelId && !_channels.containsKey(msg.channelId) -> {
                        logger.error { "n:$remoteNodeId received ${msg::class} for unknown channel ${msg.channelId}" }
                        sendToPeer(Error(msg.channelId, "unknown channel"))
                    }
                    msg is HasChannelId -> {
                        logger.info { "n:$remoteNodeId received ${msg::class} for channel ${msg.channelId}" }
                        val state = _channels[msg.channelId] ?: error("channel ${msg.channelId} not found")
                        val event1 = ChannelEvent.MessageReceived(msg)
                        val (state1, actions) = state.process(event1)
                        processActions(msg.channelId, actions)
                        _channels = _channels + (msg.channelId to state1)
                        logger.info { "n:$remoteNodeId c:${msg.channelId} new state: ${state1::class}" }
                    }
                    msg is ChannelUpdate -> {
                        logger.info { "n:$remoteNodeId received ${msg::class} for channel ${msg.shortChannelId}" }
                        _channels.values.filterIsInstance<Normal>().find { it.shortChannelId == msg.shortChannelId }?.let { state ->
                            val event1 = ChannelEvent.MessageReceived(msg)
                            val (state1, actions) = state.process(event1)
                            processActions(state.channelId, actions)
                            _channels = _channels + (state.channelId to state1)
                        }
                    }
                    msg is PayToOpenRequest -> {
                        logger.info { "n:$remoteNodeId received ${msg::class}" }
                        processIncomingPayment(Either.Left(msg))
                    }
                    msg is SwapInResponse -> {
                        logger.info { "n:$remoteNodeId received ${msg::class} bitcoinAddress=${msg.bitcoinAddress}" }
                        listenerEventChannel.send(SwapInResponseEvent(msg))
                    }
                    msg is SwapInPending -> {
                        logger.info { "n:$remoteNodeId received ${msg::class} bitcoinAddress=${msg.bitcoinAddress} amount=${msg.amount}" }
                        listenerEventChannel.send(SwapInPendingEvent(msg))
                    }
                    msg is SwapInConfirmed -> {
                        logger.info { "n:$remoteNodeId received ${msg::class} bitcoinAddress=${msg.bitcoinAddress} amount=${msg.amount}" }
                        listenerEventChannel.send(SwapInConfirmedEvent(msg))
                    }
                    else -> logger.warning { "n:$remoteNodeId received unhandled message ${Hex.encode(event.data)}" }
                }
            }
            event is WatchReceived && !_channels.containsKey(event.watch.channelId) -> {
                logger.error { "n:$remoteNodeId received watch event ${event.watch} for unknown channel ${event.watch.channelId}}" }
            }
            event is WatchReceived -> {
                val state = _channels[event.watch.channelId] ?: error("channel ${event.watch.channelId} not found")
                val event1 = ChannelEvent.WatchReceived(event.watch)
                val (state1, actions) = state.process(event1)
                processActions(event.watch.channelId, actions)
                _channels = _channels + (event.watch.channelId to state1)
                logger.info { "n:$remoteNodeId c:${event.watch.channelId} new state: ${state1::class}" }
            }
            event is ReceivePayment -> {
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
                        PaymentRequest.TaggedField.ExtraHop(
                            nodeId = walletParams.trampolineNode.id,
                            shortChannelId = ShortChannelId.peerId(nodeParams.nodeId),
                            feeBase = remoteChannelUpdates.map { it.feeBaseMsat }.maxOrNull() ?: walletParams.invoiceDefaultRoutingFees.feeBase,
                            feeProportionalMillionths = remoteChannelUpdates.map { it.feeProportionalMillionths }.maxOrNull() ?: walletParams.invoiceDefaultRoutingFees.feeProportional,
                            cltvExpiryDelta = remoteChannelUpdates.map { it.cltvExpiryDelta }.maxOrNull() ?: walletParams.invoiceDefaultRoutingFees.cltvExpiryDelta
                        )
                    )
                )
                val pr = incomingPaymentHandler.createInvoice(event.paymentPreimage, event.amount, event.description, extraHops, event.expirySeconds)
                listenerEventChannel.send(PaymentRequestGenerated(event, pr.write()))
                event.result.complete(pr)
            }
            event is PayToOpenResponseEvent -> {
                logger.info { "n:$remoteNodeId sending ${event.payToOpenResponse::class}" }
                sendToPeer(event.payToOpenResponse)
            }
            event is SendPayment -> {
                val currentTip = currentTipFlow.filterNotNull().first()
                when (val result = outgoingPaymentHandler.sendPayment(event, _channels, currentTip.first)) {
                    is OutgoingPaymentHandler.Progress -> {
                        listenerEventChannel.send(PaymentProgress(result.request, result.fees))
                        result.actions.forEach { input.send(it) }
                    }
                    is OutgoingPaymentHandler.Failure -> listenerEventChannel.send(PaymentNotSent(result.request, result.failure))
                }
            }
            event is CheckPaymentsTimeout -> {
                val actions = incomingPaymentHandler.checkPaymentsTimeout(currentTimestampSeconds())
                actions.forEach { input.send(it) }
            }
            event is SendSwapInRequest -> {
                val msg = SwapInRequest(nodeParams.chainHash)
                logger.info { "n:$remoteNodeId sending ${msg::class}" }
                sendToPeer(msg)
            }
            event is WrappedChannelEvent && event.channelId == ByteVector32.Zeroes -> {
                // this is for all channels
                _channels.forEach { (key, value) ->
                    val (state1, actions) = value.process(event.channelEvent)
                    processActions(key, actions)
                    _channels = _channels + (key to state1)
                }
            }
            event is WrappedChannelEvent -> when (val state = _channels[event.channelId]) {
                null -> logger.error { "n:$remoteNodeId received ${event.channelEvent::class} for an unknown channel ${event.channelId}" }
                else -> {
                    val (state1, actions) = state.process(event.channelEvent)
                    processActions(event.channelId, actions)
                    _channels = _channels + (event.channelId to state1)
                }
            }
            event is Disconnected -> {
                logger.warning { "n:$remoteNodeId disconnecting channels" }
                _channels.forEach { (key, value) ->
                    val (state1, actions) = value.process(ChannelEvent.Disconnected)
                    processActions(key, actions)
                    _channels = _channels + (key to state1)
                }
            }
        }
    }
}
