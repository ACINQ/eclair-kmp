package fr.acinq.eclair.io

import fr.acinq.eclair.utils.decodeToString
import fr.acinq.eclair.utils.splitByLines
import fr.acinq.eclair.utils.subArray
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow


@OptIn(ExperimentalStdlibApi::class)
interface TcpSocket {

    sealed class IOException(override val message: String, cause: Throwable? = null) : Exception(message, cause) {
        class ConnectionRefused(cause: Throwable? = null) : IOException("Connection refused", cause)
        class ConnectionClosed(cause: Throwable? = null) : IOException("Connection closed", cause)
        class Unknown(message: String?, cause: Throwable? = null) : IOException(message ?: "Unknown", cause)
    }

    suspend fun send(bytes: ByteArray?, offset: Int, length: Int, flush: Boolean = true)

    suspend fun receiveFully(buffer: ByteArray, offset: Int, length: Int)
    suspend fun receiveAvailable(buffer: ByteArray, offset: Int, maxLength: Int): Int

    suspend fun startTls(tls: TLS = TLS.SAFE): TcpSocket

    fun close()

    enum class TLS {
        SAFE, UNSAFE_CERTIFICATES
    }

    interface Builder {
        suspend fun connect(host: String, port: Int, tls: TLS? = null): TcpSocket

        companion object {
            operator fun invoke(): Builder = PlatformSocketBuilder
        }
    }
}

suspend fun TcpSocket.send(bytes: ByteArray, flush: Boolean = true) = send(bytes, 0, bytes.size, flush)
suspend fun TcpSocket.receiveFully(buffer: ByteArray) = receiveFully(buffer, 0, buffer.size)
suspend fun TcpSocket.receiveAvailable(buffer: ByteArray) = receiveAvailable(buffer, 0, buffer.size)

internal expect object PlatformSocketBuilder : TcpSocket.Builder

suspend fun TcpSocket.receiveFully(size: Int): ByteArray =
    ByteArray(size).also { receiveFully(it) }

fun TcpSocket.linesFlow(): Flow<String> =
    flow {
        val buffer = ByteArray(8192)
        while (true) {
            val size = receiveAvailable(buffer)
            emit(buffer.subArray(size))
        }
    }
        .decodeToString()
        .splitByLines()