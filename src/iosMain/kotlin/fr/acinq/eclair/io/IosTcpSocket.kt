package fr.acinq.eclair.io

import fr.acinq.eclair.utils.eclairLogger
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch
import platform.Network.nw_connection_t
import kotlin.native.concurrent.ThreadLocal


@OptIn(ExperimentalUnsignedTypes::class)
class IosTcpSocket(private val connection: nw_connection_t) : TcpSocket {
    override suspend fun send(bytes: ByteArray?, offset: Int, length: Int, flush: Boolean): Unit {
        if (bytes != null) {
            bytes.useDataView(offset, length) { data ->
                connection.sendData(data, flush)
            }
        } else {
            connection.sendData(null, flush)
        }
    }

    private suspend fun receive(buffer: ByteArray, offset: Int, min: Int, max: Int): Int {
        val data = connection.receiveData(min, max)
        data.copyTo(buffer, offset)
        return data.size()
    }

    override suspend fun receiveFully(buffer: ByteArray, offset: Int, length: Int) {
        receive(buffer, offset, length, length)
    }

    override suspend fun receiveAvailable(buffer: ByteArray, offset: Int, maxLength: Int): Int {
        return receive(buffer, offset, 1, maxLength)
    }

    override suspend fun startTls(tls: TcpSocket.TLS): TcpSocket {
        val listener = openListener(MainScope(), "127.0.0.1", "0")
        MainScope().launch {
            val listeningConnection = listener.connections.receive()

            launch {
                transferLoop(listeningConnection, connection)
                connection.cancel()
                listener.close()
            }
            launch {
                transferLoop(connection, listeningConnection)
                listeningConnection.cancel()
            }
        }

        val tlsConnection = openClientConnection("127.0.0.1", listener.port,
            when (tls) {
                TcpSocket.TLS.SAFE -> NwTls(safe = true, auth = false)
                TcpSocket.TLS.UNSAFE_CERTIFICATES -> NwTls(safe = false, auth = false)
            }
        )

        return IosTcpSocket(tlsConnection)
    }

    override fun close() {
        connection.cancel()
    }
}

@ThreadLocal
internal actual object PlatformSocketBuilder : TcpSocket.Builder {
    private val logger by eclairLogger<IosTcpSocket>()

    @OptIn(ExperimentalUnsignedTypes::class)
    override suspend fun connect(host: String, port: Int, tls: TcpSocket.TLS?): TcpSocket {
        val connection = openClientConnection(host, port,
            when (tls) {
                null -> null
                TcpSocket.TLS.SAFE -> NwTls(safe = true, auth = true)
                TcpSocket.TLS.UNSAFE_CERTIFICATES -> NwTls(safe = false, auth = false)
            }
        )
        return IosTcpSocket(connection)
    }
}

