package fr.acinq.eclair.blockchain.electrum

import fr.acinq.eclair.tests.utils.EclairTestSuite
import kotlin.test.Test
import kotlin.test.assertEquals


class ElectrumRequestTest : EclairTestSuite() {

    @Test
    fun `ServerVersion stringify JSON-RPC format`() {
        assertEquals(buildString {
            append("""{"jsonrpc":"2.0","id":0,"method":"server.version","params":["3.3.6","1.4"]}""")
            appendLine()
        }, ServerVersion().asJsonRPCRequest(0))

        assertEquals(buildString {
            append("""{"jsonrpc":"2.0","id":0,"method":"server.version","params":["eclair-kmp-test","1.4.2"]}""")
            appendLine()
        }, ServerVersion(clientName = "eclair-kmp-test", protocolVersion = "1.4.2").asJsonRPCRequest(0))
    }

    @Test
    fun `Ping stringify JSON-RPC format`() {
        assertEquals(buildString {
            append("""{"jsonrpc":"2.0","id":0,"method":"server.ping","params":[]}""")
            appendLine()
        }, Ping.asJsonRPCRequest(0))
    }
}