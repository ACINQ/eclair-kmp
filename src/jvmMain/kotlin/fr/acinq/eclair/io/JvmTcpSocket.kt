package fr.acinq.eclair.io

import fr.acinq.eclair.utils.eclairLogger
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.network.tls.*
import io.ktor.util.*
import io.ktor.utils.io.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.withContext
import java.net.ConnectException
import java.net.SocketException
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

class JvmTcpSocket(socket: Socket) : TcpSocket {
    private val connection = socket.connection()

    private val logger by eclairLogger()

    override suspend fun send(bytes: ByteArray?, offset: Int, length: Int, flush: Boolean) =
        withContext(Dispatchers.IO) {
            try {
                if (bytes != null) connection.output.writeFully(bytes, offset, length)
                if (flush) connection.output.flush()
            } catch (ex: java.io.IOException) {
                throw TcpSocket.IOException.ConnectionClosed(ex)
            } catch (ex: Throwable) {
                throw TcpSocket.IOException.Unknown(ex.message, ex)
            }
        }

    private inline fun <R> tryReceive(receive: () -> R): R {
        try {
            return receive()
        } catch (ex: ClosedReceiveChannelException) {
            throw TcpSocket.IOException.ConnectionClosed(ex)
        } catch (ex: SocketException) {
            throw TcpSocket.IOException.ConnectionClosed(ex)
        } catch (ex: Throwable) {
            throw TcpSocket.IOException.Unknown(ex.message, ex)
        }
    }

    private suspend fun <R> receive(read: suspend () -> R): R =
        withContext(Dispatchers.IO) {
            tryReceive { read() }
        }

    override suspend fun receiveFully(buffer: ByteArray, offset: Int, length: Int): Unit = receive { connection.input.readFully(buffer, offset, length) }

    override suspend fun receiveAvailable(buffer: ByteArray, offset: Int, maxLength: Int): Int {
        return tryReceive { connection.input.readAvailable(buffer, 0, maxLength) }
            .takeUnless { it == -1 } ?: throw TcpSocket.IOException.ConnectionClosed()
    }

    override suspend fun startTls(tls: TcpSocket.TLS): TcpSocket =
        JvmTcpSocket(when (tls) {
            TcpSocket.TLS.SAFE -> connection.tls(Dispatchers.IO)
            TcpSocket.TLS.UNSAFE_CERTIFICATES -> connection.tls(Dispatchers.IO) {
                logger.warning { "Using unsafe TLS!" }
                trustManager = UnsafeX509TrustManager
            }
        })

    override fun close() {
        connection.socket.close()
    }
}

private object UnsafeX509TrustManager : X509TrustManager {
    override fun checkClientTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
    override fun checkServerTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
    override fun getAcceptedIssuers(): Array<X509Certificate>? = null
}

@OptIn(KtorExperimentalAPI::class)
internal actual object PlatformSocketBuilder : TcpSocket.Builder {

    private val selectorManager = ActorSelectorManager(Dispatchers.IO)
    private val logger by eclairLogger<JvmTcpSocket>()

    override suspend fun connect(host: String, port: Int, tls: TcpSocket.TLS?): TcpSocket =
        withContext(Dispatchers.IO) {
            try {
                JvmTcpSocket(aSocket(selectorManager).tcp().connect(host, port).let { socket ->
                    when (tls) {
                        null -> socket
                        TcpSocket.TLS.SAFE -> socket.tls(Dispatchers.IO)
                        TcpSocket.TLS.UNSAFE_CERTIFICATES -> socket.tls(Dispatchers.IO) {
                            logger.warning { "Using unsafe TLS!" }
                            trustManager = UnsafeX509TrustManager
                        }
                    }
                })
            } catch (ex: ConnectException) {
                throw TcpSocket.IOException.ConnectionRefused()
            } catch (ex: SocketException) {
                throw TcpSocket.IOException.Unknown(ex.message)
            }
        }
}
