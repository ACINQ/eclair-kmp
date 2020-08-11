package fr.acinq.eklair.io

import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.network.tls.*
import io.ktor.util.*
import io.ktor.utils.io.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.withContext
import org.kodein.log.LoggerFactory
import org.kodein.log.newLogger
import java.net.SocketException
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

class JvmTcpSocket(val socket: Socket) : TcpSocket {
    private val readChannel = socket.openReadChannel()
    private val writeChannel = socket.openWriteChannel()

    override suspend fun send(bytes: ByteArray?, flush: Boolean) =
        withContext(Dispatchers.IO) {
            if (bytes != null) writeChannel.writeFully(bytes, 0, bytes.size)
            if (flush) writeChannel.flush()
        }

    private suspend fun <R> receive(read: suspend () -> R): R =
        withContext(Dispatchers.IO) {
            try {
                read()
            } catch (_: ClosedReceiveChannelException) {
                throw TcpSocket.IOException.ConnectionClosed
            } catch (_: SocketException) {
                throw TcpSocket.IOException.ConnectionClosed
            } catch (t: Throwable) {
                throw TcpSocket.IOException.Unknown(t.message)
            }
        }

    override suspend fun receiveFully(buffer: ByteArray): Unit = receive { readChannel.readFully(buffer) }

    override suspend fun receiveAvailable(buffer: ByteArray): Int =
        readChannel.readAvailable(buffer).takeUnless { it == -1 } ?: throw TcpSocket.IOException.ConnectionClosed

    override fun close() {
        socket.close()
    }

}

@OptIn(KtorExperimentalAPI::class)
internal actual object PlatformSocketBuilder : TcpSocket.Builder {
    val selectorManager = ActorSelectorManager(Dispatchers.IO)
    override suspend fun connect(host: String, port: Int, tls: TcpSocket.TLS?): TcpSocket =
        withContext(Dispatchers.IO) {
            JvmTcpSocket(
                aSocket(selectorManager).tcp().connect(host, port).let { socket ->
                    when (tls) {
                        null -> socket
                        TcpSocket.TLS.SAFE -> socket.tls(Dispatchers.IO)
                        TcpSocket.TLS.UNSAFE_CERTIFICATES -> socket.tls(Dispatchers.IO) {
                            LoggerFactory.default.newLogger(JvmTcpSocket::class).warning { "Using unsafe TLS!" }
                            trustManager = object : X509TrustManager {
                                override fun checkClientTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
                                override fun checkServerTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
                                override fun getAcceptedIssuers(): Array<X509Certificate>? = null
                            }
                        }
                    }
                }
            )
        }
}
