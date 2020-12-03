package fr.acinq.eclair.io.peer

import fr.acinq.eclair.Eclair
import fr.acinq.eclair.channel.*
import fr.acinq.eclair.channel.TestsHelper.makeCmdAdd
import fr.acinq.eclair.channel.TestsHelper.reachNormal
import fr.acinq.eclair.db.OutgoingPayment
import fr.acinq.eclair.io.*
import fr.acinq.eclair.payment.PaymentRequest
import fr.acinq.eclair.tests.newPeer
import fr.acinq.eclair.tests.newPeers
import fr.acinq.eclair.tests.utils.EclairTestSuite
import fr.acinq.eclair.tests.utils.runSuspendTest
import fr.acinq.eclair.utils.UUID
import fr.acinq.eclair.utils.msat
import fr.acinq.eclair.utils.sat
import fr.acinq.eclair.utils.toMilliSatoshi
import fr.acinq.eclair.wire.LightningMessage
import fr.acinq.eclair.wire.UpdateAddHtlc
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.receiveOrNull
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.flow.first
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.ExperimentalTime
import kotlin.time.seconds

@OptIn(ExperimentalCoroutinesApi::class, ExperimentalTime::class)
class ConnectionTest : EclairTestSuite() {

    @Test
    fun `connection lost`() = runSuspendTest {
        val (alice0, bob0) = reachNormal()
        val peer = newPeer(bob0) { channels.addOrUpdateChannel(alice0) }

        peer.send(Disconnected)
        // Wait until alice is Offline
        peer.channelsFlow.first { it.values.size == 1 && it.values.all { channelState -> channelState is Offline } }
    }

    @Test
    fun `payment test between two phoenix nodes`() = runSuspendTest {
        val (alice0, bob0) = reachNormal()
//        val (bob1, alice1) = reachNormal()
//        val (alice2, bob2) = reachNormal()
        val (alice, bob) = newPeers(this, listOf(alice0 to bob0))

        val msg = alice.output.consumeAsFlow().first { LightningMessage.decode(it) is UpdateAddHtlc }
        bob.send(BytesReceived(msg))

        val paymentPreimage = Eclair.randomBytes32()
        val deferredInvoice = CompletableDeferred<PaymentRequest>()
        bob.send(ReceivePayment(paymentPreimage, 15_000_000.msat,"test invoice", deferredInvoice))
        val invoice = deferredInvoice.await()

        alice.send(SendPayment(UUID.randomUUID(), invoice.amount!!, alice.remoteNodeId, OutgoingPayment.Details.Normal(invoice)))
    }
}