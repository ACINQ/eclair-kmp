package fr.acinq.eclair.io

import fr.acinq.eclair.io.ios_network_framework.nw_k_connection_receive
import fr.acinq.eclair.io.ios_network_framework.nw_k_parameters_create_secure_tcp
import fr.acinq.eclair.io.ios_network_framework.nw_k_parameters_create_secure_tcp_custom
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.Network.*
import platform.Security.sec_protocol_options_set_peer_authentication_required
import platform.Security.sec_protocol_options_set_verify_block
import platform.darwin.dispatch_data_t
import platform.darwin.dispatch_get_main_queue
import platform.posix.ECONNREFUSED
import platform.posix.ECONNRESET
import platform.posix.ECANCELED
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine


private fun nw_error_t.toIOException(): TcpSocket.IOException =
    when (nw_error_get_error_domain(this)) {
        nw_error_domain_posix -> when (nw_error_get_error_code(this)) {
            ECONNREFUSED -> TcpSocket.IOException.ConnectionRefused()
            ECONNRESET, ECANCELED -> TcpSocket.IOException.ConnectionClosed()
            else -> TcpSocket.IOException.Unknown("Posix error ${nw_error_get_error_code(this)}: ${this?.debugDescription} ")
        }
        nw_error_domain_dns -> TcpSocket.IOException.Unknown("DNS: ${this?.debugDescription}")
        nw_error_domain_tls -> TcpSocket.IOException.Unknown("TLS: ${this?.debugDescription}")
        else -> TcpSocket.IOException.Unknown("Unknown: ${this?.debugDescription}")
    }


@OptIn(ExperimentalUnsignedTypes::class)
internal suspend fun nw_connection_t.receiveData(min: Int, max: Int): dispatch_data_t {
    return suspendCoroutine { continuation ->
        nw_k_connection_receive(this, min.toUInt(), max.toUInt()) { data, isComplete, error ->
            when {
                error != null -> continuation.resumeWithException(error.toIOException())
                data != null -> continuation.resume(data)
                isComplete -> continuation.resumeWithException(TcpSocket.IOException.ConnectionClosed())
                else -> continuation.resumeWithException(Exception("Connection has no error, no data and is not complete"))
            }
        }
    }
}

internal suspend fun nw_connection_t.sendData(data: dispatch_data_t, flush: Boolean) {
    suspendCancellableCoroutine<Unit> { continuation ->
        nw_connection_send(this, data, null, flush) { error ->
            if (error != null) continuation.resumeWithException(error.toIOException())
            else continuation.resume(Unit)
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
private suspend fun nw_connection_t.start() {
    suspendCancellableCoroutine<Unit> { continuation ->
        nw_connection_set_queue(this, dispatch_get_main_queue())

        nw_connection_set_state_changed_handler(this) { state, error ->
            when {
                error != null -> {
                    nw_connection_set_state_changed_handler(this, null)
                    continuation.resumeWithException(error.toIOException())
                }
                state == nw_connection_state_ready -> {
                    nw_connection_set_state_changed_handler(this, null)
                    continuation.resume(Unit)
                }
            }
        }
        nw_connection_start(this)
    }
}

internal fun nw_connection_t.cancel() {
    nw_connection_cancel(this)
}

internal class NwTls(val safe: Boolean, val auth: Boolean)

internal suspend fun openClientConnection(host: String, port: Int, tls: NwTls?): nw_connection_t {
    val endpoint = nw_endpoint_create_host(host, port.toString())

    val parameters =
        when {
            tls == null -> nw_k_parameters_create_secure_tcp(false)
            tls.safe && tls.auth -> nw_k_parameters_create_secure_tcp(true)
            else -> nw_k_parameters_create_secure_tcp_custom {
                val secOptions = nw_tls_copy_sec_protocol_options(it)
                if (!tls.safe) sec_protocol_options_set_verify_block(secOptions, { _, _, handler -> handler!!(true) }, dispatch_get_main_queue())
                if (!tls.auth) sec_protocol_options_set_peer_authentication_required(secOptions, false)
            }
        }

    val connection = nw_connection_create(endpoint, parameters)
    connection.start()

    return connection
}

internal class NwListener(private val listener: nw_listener_t, val connections: ReceiveChannel<nw_connection_t>) {

    @OptIn(ExperimentalUnsignedTypes::class)
    val port: Int = nw_listener_get_port(listener).toInt()

    fun close() {
        nw_listener_cancel(listener)
    }
}

@OptIn(ExperimentalUnsignedTypes::class, ExperimentalCoroutinesApi::class)
internal suspend fun openListener(scope: CoroutineScope, host: String, port: String): NwListener {
    val params = nw_k_parameters_create_secure_tcp(false)
    val endpoint = nw_endpoint_create_host(host, port)
    nw_parameters_set_local_endpoint(params, endpoint)
    val listener = nw_listener_create(params)
    nw_listener_set_queue(listener, dispatch_get_main_queue())

    val connections = Channel<nw_connection_t>()
    nw_listener_set_new_connection_handler(listener) { connection ->
        nw_connection_set_queue(connection, dispatch_get_main_queue())
        scope.launch {
            connection.start()
            connections.send(connection)
        }
    }

    suspendCoroutine<Unit> { continuation ->
        var continued = false
        nw_listener_set_state_changed_handler(listener) { state, error ->
            if (state == nw_listener_state_cancelled) connections.close()

            if (!continued) {
                when {
                    error != null -> {
                        continued = true
                        continuation.resumeWithException(error.toIOException())
                    }
                    state == nw_listener_state_ready -> {
                        continued = true
                        continuation.resume(Unit)
                    }
                }
            }
        }
        nw_listener_start(listener)
    }

    return NwListener(listener, connections)
}

@OptIn(ExperimentalUnsignedTypes::class)
suspend fun transferLoop(from: nw_connection_t, to: nw_connection_t) {
    try {
        while (true) {
            val data = from.receiveData(1, 8 * 1024)
            to.sendData(data, true)
        }
    } catch (_: TcpSocket.IOException.ConnectionClosed) {}
}
