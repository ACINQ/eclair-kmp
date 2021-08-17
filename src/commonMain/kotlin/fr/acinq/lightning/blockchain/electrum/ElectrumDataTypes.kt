package fr.acinq.lightning.blockchain.electrum

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.readNBytes
import fr.acinq.lightning.blockchain.fee.FeeratePerKB
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.utils.*
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*

/**
 * Common communication objects between [ElectrumClient] and external ressources (e.g. [ElectrumWatcher])
 * See the documentation for the ElectrumX protocol there: https://github.com/spesmilo/electrumx/
 */
sealed class ElectrumMessage
sealed class ElectrumSubscription : ElectrumMessage()
object AskForHeaderSubscriptionUpdate : ElectrumSubscription()
data class SendElectrumRequest(val electrumRequest: ElectrumRequest) : ElectrumMessage()

/**
 * [ElectrumClient] requests / responses
 */
sealed class ElectrumRequest(vararg params: Any) {
    abstract val method: String
    private val parameters = params.toList()

    fun asJsonRPCRequest(id: Int = 0): String {
        val request = JsonRPCRequest(
            id = id,
            method = method,
            params = parameters.asJsonRPCParameters()
        )
        return buildString {
            append(json.encodeToString(JsonRPCRequest.serializer(), request))
            appendLine()
        }
    }

    companion object {
        private val json = Json { encodeDefaults = true }
    }
}

sealed class ElectrumResponse : ElectrumMessage()

data class ServerVersion(
    private val clientName: String = ElectrumClient.ELECTRUM_CLIENT_NAME,
    private val protocolVersion: String = ElectrumClient.ELECTRUM_PROTOCOL_VERSION
) : ElectrumRequest(clientName, protocolVersion) {
    override val method: String = "server.version"
}

data class ServerVersionResponse(val clientName: String, val protocolVersion: String) : ElectrumResponse()

object Ping : ElectrumRequest() {
    override val method: String = "server.ping"
}

object PingResponse : ElectrumResponse()

data class GetScriptHashHistory(val scriptHash: ByteVector32) : ElectrumRequest(scriptHash) {
    override val method: String = "blockchain.scripthash.get_history"
}

data class TransactionHistoryItem(val height: Int, val tx_hash: ByteVector32)
data class GetScriptHashHistoryResponse(val scriptHash: ByteVector32, val history: List<TransactionHistoryItem>) : ElectrumResponse()

data class ScriptHashListUnspent(val scriptHash: ByteVector32) : ElectrumRequest(scriptHash) {
    override val method: String = "blockchain.scripthash.listunspent"
}

data class UnspentItem(val tx_hash: ByteVector32, val tx_pos: Int, val value: Long, val height: Long) {
    val outPoint by lazy { OutPoint(tx_hash.reversed(), tx_pos.toLong()) }
}

data class ScriptHashListUnspentResponse(val scriptHash: ByteVector32, val unspents: List<UnspentItem>) : ElectrumResponse()

data class BroadcastTransaction(val tx: Transaction) : ElectrumRequest(tx) {
    override val method: String = "blockchain.transaction.broadcast"
}

data class BroadcastTransactionResponse(val tx: Transaction, val error: JsonRPCError? = null) : ElectrumResponse()

data class GetTransactionIdFromPosition(val height: Int, val tx_pos: Int, val merkle: Boolean = false) : ElectrumRequest(height, tx_pos, merkle) {
    override val method: String = "blockchain.transaction.id_from_pos"
}

data class GetTransactionIdFromPositionResponse(val txid: ByteVector32, val height: Int, val tx_pos: Int, val merkle: List<ByteVector32> = emptyList()) : ElectrumResponse()

data class GetTransaction(val txid: ByteVector32, val contextOpt: Any? = null) : ElectrumRequest(txid) {
    override val method: String = "blockchain.transaction.get"
}

data class GetTransactionResponse(val tx: Transaction, val contextOpt: Any? = null) : ElectrumResponse()

data class GetHeader(val height: Int) : ElectrumRequest(height) {
    override val method: String = "blockchain.block.header"
}

data class GetHeaderResponse(val height: Int, val header: BlockHeader) : ElectrumResponse()

data class GetHeaders(val start_height: Int, val count: Int, val cp_height: Int = 0) : ElectrumRequest(start_height, count, cp_height) {
    override val method: String = "blockchain.block.headers"
}

data class GetHeadersResponse(val start_height: Int, val headers: List<BlockHeader>, val max: Int) : ElectrumResponse() {
    override fun toString(): String = "GetHeadersResponse($start_height, ${headers.size}, ${headers.first()}, ${headers.last()}, $max)"
}

data class GetMerkle(val txid: ByteVector32, val height: Int, val contextOpt: Transaction? = null) : ElectrumRequest(txid, height) {
    override val method: String = "blockchain.transaction.get_merkle"
}

data class GetMerkleResponse(val txid: ByteVector32, val merkle: List<ByteVector32>, val block_height: Int, val pos: Int, val contextOpt: Transaction? = null) : ElectrumResponse() {
    val root: ByteVector32 by lazy {
        tailrec fun loop(pos: Int, hashes: List<ByteVector32>): ByteVector32 {
            return if (hashes.size == 1) hashes[0]
            else {
                val h = if (pos % 2 == 1) Crypto.hash256(hashes[1] + hashes[0]) else Crypto.hash256(hashes[0] + hashes[1])
                loop(pos / 2, listOf(h.byteVector32()) + hashes.drop(2))
            }
        }

        @Suppress("UNCHECKED_CAST")
        loop(pos, listOf(txid.reversed()) + merkle.map { it.reversed() })
    }
}

data class EstimateFees(val confirmations: Int) : ElectrumRequest(confirmations) {
    override val method: String = "blockchain.estimatefee"
}

data class EstimateFeeResponse(val confirmations: Int, val feerate: FeeratePerKw?) : ElectrumResponse()


data class ScriptHashSubscription(val scriptHash: ByteVector32) : ElectrumRequest(scriptHash) {
    override val method: String = "blockchain.scripthash.subscribe"
}

data class ScriptHashSubscriptionResponse(val scriptHash: ByteVector32, val status: String = "") : ElectrumResponse()

object HeaderSubscription : ElectrumRequest() {
    override val method: String = "blockchain.headers.subscribe"
}

data class HeaderSubscriptionResponse(val height: Int, val header: BlockHeader) : ElectrumResponse()

/**
 * Other Electrum responses
 */
data class TransactionHistory(val history: List<TransactionHistoryItem>) : ElectrumResponse()
data class AddressStatus(val address: String, val status: String?) : ElectrumResponse()
data class ServerError(val request: ElectrumRequest, val error: JsonRPCError) : ElectrumResponse()

/**
 * ElectrumResponse deserializer
 */
object ElectrumResponseDeserializer : KSerializer<Either<ElectrumResponse, JsonRPCResponse>> {
    private val json = Json { ignoreUnknownKeys = true }

    override fun deserialize(decoder: Decoder): Either<ElectrumResponse, JsonRPCResponse> {
        // Decoder -> JsonInput
        val input = decoder as? JsonDecoder
            ?: throw SerializationException("This class can be loaded only by JSON")
        // JsonInput => JsonElement (JsonObject in this case)
        val jsonObject = input.decodeJsonElement() as? JsonObject
            ?: throw SerializationException("Expected JsonObject")

        return when (val method = jsonObject["method"]) {
            is JsonPrimitive -> {
                val params = jsonObject["params"]?.jsonArray.orEmpty().takeIf { it.isNotEmpty() }
                    ?: throw SerializationException("Parameters for ${method.content} notification should not null or be empty.")

                when (method.content) {
                    "blockchain.headers.subscribe" -> params.first().jsonObject.let { header ->
                        val height = header.getValue("height").jsonPrimitive.int
                        val hex = header.getValue("hex").jsonPrimitive.content
                        Either.Left(HeaderSubscriptionResponse(height, BlockHeader.read(hex)))
                    }
                    "blockchain.scripthash.subscribe" -> {
                        val scriptHash = params[0].jsonPrimitive.content
                        val status = params[1].jsonPrimitive.contentOrNull
                        Either.Left(ScriptHashSubscriptionResponse(ByteVector32.fromValidHex(scriptHash), status ?: ""))
                    }
                    else -> throw SerializationException("JSON-RPC Method ${method.content} is not supported")
                }
            }
            else -> Either.Right(json.decodeFromJsonElement(JsonRPCResponseDeserializer(json), jsonObject))
        }
    }

    override fun serialize(encoder: Encoder, value: Either<ElectrumResponse, JsonRPCResponse>) {
        throw SerializationException("This ($value) is not meant to be serialized!")
    }

    override val descriptor: SerialDescriptor
        get() = buildClassSerialDescriptor("fr.acinq.lightning.utils.Either")
}

class JsonRPCResponseDeserializer(val json: Json) : KSerializer<JsonRPCResponse> {
    override fun deserialize(decoder: Decoder): JsonRPCResponse {
        val jsonObject = (decoder as? JsonDecoder)?.decodeJsonElement() as? JsonObject ?: throw SerializationException("Expected JsonObject")
        val error = jsonObject["error"]
        return if (error != null && error is JsonPrimitive && error.isString) {
            JsonRPCResponse(id = (jsonObject["id"] as? JsonPrimitive)?.intOrNull ?: 0, error = JsonRPCError(code = 0, error.content))
        } else {
            json.decodeFromJsonElement(JsonRPCResponse.serializer(), jsonObject)
        }
    }

    override fun serialize(encoder: Encoder, value: JsonRPCResponse) {
        throw SerializationException("This ($value) is not meant to be serialized!")
    }

    override val descriptor: SerialDescriptor
        get() = buildClassSerialDescriptor("fr.acinq.lightning.utils.JsonRPCResponse")
}

internal fun parseJsonResponse(request: ElectrumRequest, rpcResponse: JsonRPCResponse): ElectrumResponse =
    if (rpcResponse.error != null) when (request) {
        is BroadcastTransaction -> BroadcastTransactionResponse(request.tx, rpcResponse.error)
        else -> ServerError(
            request = request,
            error = rpcResponse.error
        )
    }
    else if (rpcResponse.id != null && rpcResponse.id < 0 ) PingResponse
    else when (request) {
        is ServerVersion -> {
            val resultArray = rpcResponse.result.jsonArray
            ServerVersionResponse(resultArray[0].toString(), resultArray[1].toString())
        }
        Ping -> PingResponse
        is GetScriptHashHistory -> {
            val jsonArray = rpcResponse.result.jsonArray
            val items = jsonArray.map {
                val height = it.jsonObject.getValue("height").jsonPrimitive.int
                val txHash = it.jsonObject.getValue("tx_hash").jsonPrimitive.content
                TransactionHistoryItem(height, ByteVector32.fromValidHex(txHash))
            }
            GetScriptHashHistoryResponse(request.scriptHash, items)
        }
        is ScriptHashListUnspent -> {
            val jsonArray = rpcResponse.result.jsonArray
            val items = jsonArray.map {
                val txHash = it.jsonObject.getValue("tx_hash").jsonPrimitive.content
                val txPos = it.jsonObject.getValue("tx_pos").jsonPrimitive.int
                val value = it.jsonObject.getValue("value").jsonPrimitive.long
                val height = it.jsonObject.getValue("height").jsonPrimitive.long
                UnspentItem(ByteVector32.fromValidHex(txHash), txPos, value, height)
            }
            ScriptHashListUnspentResponse(request.scriptHash, items)
        }
        is GetTransactionIdFromPosition -> {
            val (txHash, leaves) = if (rpcResponse.result is JsonPrimitive) {
                rpcResponse.result.content to emptyList()
            } else {
                val jsonObject = rpcResponse.result.jsonObject
                jsonObject.getValue("tx_hash").jsonPrimitive.content to
                        jsonObject.getValue("merkle").jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }
            }

            GetTransactionIdFromPositionResponse(ByteVector32.fromValidHex(txHash), request.height, request.tx_pos, leaves)
        }
        is GetTransaction -> {
            val hex = rpcResponse.result.jsonPrimitive.content
            GetTransactionResponse(Transaction.read(hex), request.contextOpt)
        }
        is ScriptHashSubscription -> {
            val status = when (rpcResponse.result) {
                is JsonPrimitive -> rpcResponse.result.jsonPrimitive.content
                else -> ""
            }
            ScriptHashSubscriptionResponse(request.scriptHash, status)
        }
        is BroadcastTransaction -> {
            val message = rpcResponse.result.jsonPrimitive.content
            // if we got here, it means that the server's response does not contain an error and message should be our
            // transaction id. However, it seems that at least on testnet some servers still use an older version of the
            // Electrum protocol and return an error message in the result field
            val result = runTrying<ByteVector32> {
                ByteVector32.fromValidHex(message)
            }
            when (result) {
                is Try.Success -> {
                    if (result.result == request.tx.txid) BroadcastTransactionResponse(request.tx)
                    else BroadcastTransactionResponse(request.tx, JsonRPCError(1, "response txid $result does not match request txid ${request.tx.txid}"))
                }
                is Try.Failure -> {
                    BroadcastTransactionResponse(request.tx, JsonRPCError(1, message))
                }
            }
        }
        is GetHeader -> {
            val hex = rpcResponse.result.jsonPrimitive.content
            GetHeaderResponse(request.height, BlockHeader.read(hex))
        }
        is GetHeaders -> {
            val jsonObject = rpcResponse.result.jsonObject
            val max = jsonObject.getValue("max").jsonPrimitive.int
            val hex = jsonObject.getValue("hex").jsonPrimitive.content

            val blockHeaders = buildList {
                val input = ByteArrayInput(Hex.decode(hex))
                require(input.availableBytes % 80 == 0)

                val headerSize = 80
                var header = input.readNBytes(headerSize)
                while (header != null) {
                    add(BlockHeader.read(header))
                    header = input.readNBytes(headerSize)
                }
            }

            GetHeadersResponse(request.start_height, blockHeaders, max)
        }
        is GetMerkle -> {
            val jsonObject = rpcResponse.result.jsonObject
            val leaves = jsonObject.getValue("merkle").jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }
            val blockHeight = jsonObject.getValue("block_height").jsonPrimitive.int
            val pos = jsonObject.getValue("pos").jsonPrimitive.int
            GetMerkleResponse(request.txid, leaves, blockHeight, pos, request.contextOpt)
        }
        is EstimateFees -> {
            val btcperkb: Double? = if (rpcResponse.result.jsonPrimitive.intOrNull == -1) null else rpcResponse.result.jsonPrimitive.double
            val feeratePerKb = btcperkb?.let { FeeratePerKB(Satoshi((it * 100_000_000).toLong())) }
            val feeratePerKw = feeratePerKb?.let { FeeratePerKw(it) }
            EstimateFeeResponse(request.confirmations, feeratePerKw)
        }
        HeaderSubscription -> {
            val jsonObject = rpcResponse.result.jsonObject
            val height = jsonObject.getValue("height").jsonPrimitive.int
            val hex = jsonObject.getValue("hex").jsonPrimitive.content
            HeaderSubscriptionResponse(height, BlockHeader.read(hex))
        }
    }
