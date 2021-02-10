package fr.acinq.eclair.blockchain.electrum

import fr.acinq.bitcoin.BlockHeader
import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.eclair.blockchain.electrum.ElectrumClient.Companion.logger
import fr.acinq.eclair.blockchain.electrum.ElectrumClient.Companion.version
import fr.acinq.eclair.io.TcpSocket
import fr.acinq.eclair.io.linesFlow
import fr.acinq.eclair.io.send
import fr.acinq.eclair.utils.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BroadcastChannel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.Channel.Factory.BUFFERED
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.filter
import kotlinx.serialization.json.Json
import kotlin.native.concurrent.ThreadLocal
import kotlin.time.ExperimentalTime
import kotlin.time.seconds


/*
    Events
 */
internal sealed class ClientEvent
internal object Connected : ClientEvent()
internal object Disconnected : ClientEvent()
internal data class ReceivedResponse(val response: Either<ElectrumResponse, JsonRPCResponse>) : ClientEvent()
internal data class SendElectrumApiCall(val electrumRequest: ElectrumRequest) : ClientEvent()
internal object AskForHeader : ClientEvent()

/*
    Actions
 */
internal sealed class ElectrumClientAction
internal data class SendRequest(val request: String) : ElectrumClientAction()
internal data class SendHeader(val height: Int, val blockHeader: BlockHeader) : ElectrumClientAction()
internal data class SendResponse(val response: ElectrumResponse) : ElectrumClientAction()
internal data class BroadcastStatus(val connection: Connection) : ElectrumClientAction()

/**
 * [ElectrumClient] State
 *
 * +--> ClientClosed ----> WaitingForConnection ----+
 * |                                                |
 * |                                                |
 * +-- Running <-- WaitForTip <--- WaitForVersion --+
 *     ^     |
 *     +-----+
 *
 */
internal sealed class ClientState {
    abstract fun process(event: ClientEvent): Pair<ClientState, List<ElectrumClientAction>>
}

internal object WaitingForVersion : ClientState() {
    override fun process(event: ClientEvent): Pair<ClientState, List<ElectrumClientAction>> = when {
        event is ReceivedResponse && event.response is Either.Right -> {
            when (parseJsonResponse(version, event.response.value)) {
                is ServerVersionResponse -> newState {
                    state = WaitingForTip
                    actions = listOf(SendRequest(HeaderSubscription.asJsonRPCRequest()))
                }
                is ServerError -> newState {
                    state = ClientClosed
                    actions = listOf(BroadcastStatus(Connection.CLOSED))
                }
                else -> returnState() // TODO handle error?
            }
        }
        else -> unhandled(event)
    }
}

internal object WaitingForTip : ClientState() {
    override fun process(event: ClientEvent): Pair<ClientState, List<ElectrumClientAction>> =
        when (event) {
            is ReceivedResponse -> {
                when (val rpcResponse = event.response) {
                    is Either.Right ->
                        when (val response = parseJsonResponse(HeaderSubscription, rpcResponse.value)) {
                            is HeaderSubscriptionResponse -> newState {
                                state = ClientRunning(height = response.height, tip = response.header)
                                actions = listOf(BroadcastStatus(Connection.ESTABLISHED), SendResponse(response))
                            }
                            else -> returnState()
                        }
                    else -> returnState()
                }
            }
            else -> unhandled(event)
        }
}

internal data class ClientRunning(val height: Int, val tip: BlockHeader, val requests: MutableMap<Int, ElectrumRequest> = mutableMapOf()) : ClientState() {
    override fun process(event: ClientEvent): Pair<ClientState, List<ElectrumClientAction>> = when (event) {
        is AskForHeader -> returnState(SendHeader(height, tip))
        is SendElectrumApiCall -> returnState(sendRequest(event.electrumRequest))
        is ReceivedResponse -> when (val response = event.response) {
            is Either.Left -> when (val electrumResponse = response.value) {
                is HeaderSubscriptionResponse -> newState {
                    state = copy(height = electrumResponse.height, tip = electrumResponse.header)
                    actions = listOf(SendResponse(electrumResponse))
                }
                is ScriptHashSubscriptionResponse -> returnState(SendResponse(electrumResponse))
                else -> returnState()
            }
            is Either.Right -> {
                requests[response.value.id]?.takeUnless { it is Ping }?.let { originRequest ->
                    returnState(SendResponse(parseJsonResponse(originRequest, response.value)))
                } ?: returnState()
            }
        }
        else -> unhandled(event)
    }

    private fun sendRequest(electrumRequest: ElectrumRequest): SendRequest {
        val newRequestId = requests.maxOfOrNull { it.key + 1 } ?: 0
        requests[newRequestId] = electrumRequest
        return SendRequest(electrumRequest.asJsonRPCRequest(newRequestId))
    }
}

internal object ClientClosed : ClientState() {
    override fun process(event: ClientEvent): Pair<ClientState, List<ElectrumClientAction>> =
        when (event) {
            Connected -> newState {
                state = WaitingForVersion
                actions = listOf(SendRequest(version.asJsonRPCRequest()))
            }
            else -> unhandled(event)
        }
}

private fun ClientState.unhandled(event: ClientEvent): Pair<ClientState, List<ElectrumClientAction>> =
    when (event) {
        Disconnected -> ClientClosed to emptyList()
        AskForHeader -> returnState() // TODO something else ?
        else -> {
            logger.warning { "cannot process event ${event::class} in state ${this::class}" }
            returnState()
        }
    }

private class ClientStateBuilder {
    var state: ClientState = ClientClosed
    var actions = emptyList<ElectrumClientAction>()
    fun build() = state to actions
}

private fun newState(init: ClientStateBuilder.() -> Unit) = ClientStateBuilder().apply(init).build()

private fun ClientState.returnState(actions: List<ElectrumClientAction> = emptyList()): Pair<ClientState, List<ElectrumClientAction>> = this to actions
private fun ClientState.returnState(action: ElectrumClientAction): Pair<ClientState, List<ElectrumClientAction>> = this to listOf(action)

@OptIn(ExperimentalCoroutinesApi::class, ExperimentalTime::class)
class ElectrumClient(
    socketBuilder: TcpSocket.Builder?,
    scope: CoroutineScope
) : CoroutineScope by scope {

    var socketBuilder: TcpSocket.Builder? = socketBuilder
        set(value) {
            logger.debug { "swap socket builder=$value" }
            field = value
        }

    private val json = Json { ignoreUnknownKeys = true }

    private val eventChannel: Channel<ClientEvent> = Channel(BUFFERED)
    private val output: Channel<ByteArray> = Channel(BUFFERED)

    private val _connectionState = MutableStateFlow(Connection.CLOSED)
    val connectionState: StateFlow<Connection> get() = _connectionState

    private val notificationsChannel = BroadcastChannel<ElectrumMessage>(BUFFERED)

    fun openNotificationsSubscription() = notificationsChannel.openSubscription()

    private var state: ClientState = ClientClosed

    private var runJob: Job? = null

    init {
        logger.info { "initializing electrum client" }
        launch {
            var previousState = connectionState.value
            connectionState.filter { it != previousState }.collect {
                logger.info { "connection state changed: $it" }
                if (it == Connection.CLOSED) eventChannel.send(Disconnected)
                previousState = it
            }
        }
        runJob = launch { run() }
    }

    private suspend fun run() {
        eventChannel.consumeEach { event ->

            val (newState, actions) = state.process(event)
            state = newState

            actions.forEach { action ->
                yield()
                when (action) {
                    is SendRequest -> output.send(action.request.encodeToByteArray())
                    is SendHeader -> notificationsChannel.send(HeaderSubscriptionResponse(action.height, action.blockHeader))
                    is SendResponse -> notificationsChannel.send(action.response)
                    is BroadcastStatus -> if (_connectionState.value != action.connection) _connectionState.value = action.connection
                }
            }
        }
    }

    fun connect(serverAddress: ServerAddress) {
        if (_connectionState.value == Connection.CLOSED) establishConnection(serverAddress)
        else logger.warning { "electrum client is already running" }
    }

    fun disconnect() {
        socket?.close()
        socket = null
    }

    private var socket: TcpSocket? = null
    private fun establishConnection(serverAddress: ServerAddress) = launch {
        _connectionState.value = Connection.ESTABLISHING
        socket = try {
            val (host, port, tls) = serverAddress
            logger.info { "attempting connection to electrumx instance [host=$host, port=$port, tls=$tls]" }
            socketBuilder?.connect(host, port, tls) ?: error("socket builder is null.")
        } catch (ex: Throwable) {
            logger.warning { "TCP connect: ${ex.message}" }
            _connectionState.value = Connection.CLOSED
            return@launch
        }

        val requiredSocket = socket
        requireNotNull(requiredSocket) { "TCP socket is null." }

        logger.info { "connected to electrumx instance" }
        eventChannel.send(Connected)

        fun closeSocket() {
            if (_connectionState.value == Connection.CLOSED) return
            logger.warning { "closing TCP socket." }
            requiredSocket.close()
            _connectionState.value = Connection.CLOSED
            cancel()
        }

        suspend fun send(message: ByteArray) {
            try {
                requiredSocket.send(message)
            } catch (ex: TcpSocket.IOException) {
                logger.warning { "TCP send: ${ex.message}" }
                closeSocket()
            }
        }

        suspend fun ping() {
            while (isActive) {
                delay(30.seconds)
                send(Ping.asJsonRPCRequest(-1).encodeToByteArray())
            }
        }

        suspend fun respond() {
            for (msg in output) { send(msg) }
        }

        suspend fun listen() {
            try {
                requiredSocket.linesFlow().collect {
                    val electrumResponse = json.decodeFromString(ElectrumResponseDeserializer, it)
                    eventChannel.send(ReceivedResponse(electrumResponse))
                }
            } catch (ex: TcpSocket.IOException) {
                logger.warning { "TCP receive: ${ex.message}" }
            } finally {
                closeSocket()
            }
        }

        launch { ping() }
        launch { respond() }

        listen() // This suspends until the coroutines is cancelled or the socket is closed
    }

    fun sendElectrumRequest(request: ElectrumRequest): Unit = sendMessage(SendElectrumRequest(request))

    fun sendMessage(message: ElectrumMessage) {
        launch {
            when (message) {
                is AskForHeaderSubscriptionUpdate -> eventChannel.send(AskForHeader)
                is SendElectrumRequest -> eventChannel.send(SendElectrumApiCall(message.electrumRequest))
                else -> logger.warning{ "sendMessage does not support message: ${message::class}" }
            }
        }
    }

    fun stop() {
        logger.info { "electrum client stopping" }
        socket?.close()
        // Cancel event consumer
        runJob?.cancel()
        // Cancel broadcast channels
        notificationsChannel.cancel()
        // Cancel event channel
        eventChannel.cancel()
    }

    @ThreadLocal
    companion object {
        const val ELECTRUM_CLIENT_NAME = "3.3.6"
        const val ELECTRUM_PROTOCOL_VERSION = "1.4"
        val logger by eclairLogger<ElectrumClient>()
        val version = ServerVersion()
        internal fun computeScriptHash(publicKeyScript: ByteVector): ByteVector32 = Crypto.sha256(publicKeyScript).toByteVector32().reversed()
    }
}
