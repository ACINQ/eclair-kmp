package fr.acinq.lightning.channel

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.utils.UUID
import fr.acinq.lightning.wire.FailureMessage
import fr.acinq.lightning.wire.OnionRoutingPacket

sealed class Command

data class CMD_ADD_HTLC(val amount: MilliSatoshi, val paymentHash: ByteVector32, val cltvExpiry: CltvExpiry, val onion: OnionRoutingPacket, val paymentId: UUID, val commit: Boolean = false) : Command()

sealed class HtlcSettlementCommand : Command() {
    abstract val id: Long
}

data class CMD_FULFILL_HTLC(override val id: Long, val r: ByteVector32, val commit: Boolean = false) : HtlcSettlementCommand()
data class CMD_FAIL_MALFORMED_HTLC(override val id: Long, val onionHash: ByteVector32, val failureCode: Int, val commit: Boolean = false) : HtlcSettlementCommand()
data class CMD_FAIL_HTLC(override val id: Long, val reason: Reason, val commit: Boolean = false) : HtlcSettlementCommand() {
    sealed class Reason {
        data class Bytes(val bytes: ByteVector) : Reason()
        data class Failure(val message: FailureMessage) : Reason()
    }
}

object CMD_SIGN : Command()
data class CMD_UPDATE_FEE(val feerate: FeeratePerKw, val commit: Boolean = false) : Command()

sealed class CloseCommand : Command()
data class CMD_CLOSE(val scriptPubKey: ByteVector?) : CloseCommand()
object CMD_FORCECLOSE : CloseCommand()
