package fr.acinq.lightning.blockchain.electrum

import fr.acinq.bitcoin.BlockHeader
import fr.acinq.lightning.tests.utils.LightningTestSuite
import org.kodein.log.LoggerFactory
import org.kodein.log.newLogger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ElectrumClientStateTest : LightningTestSuite() {
    private val testBlockHeader = BlockHeader.read("000000203e343602423924ffc4bccdc08ef468c3ba80187c2200dcb6b60e82d71cdbae236f4a9fd886c3d1ae9659a571f8d0d697c78cb0d6e23112859ba5fc26e46d6744a4f4175fffff7f2000000000")
    private val logger = LoggerFactory.default.newLogger(this::class)

    @Test
    fun `WaitingForTip state`() {
        // TODO
    }

    @Test
    fun `ClientRunning state`() {
        // TODO
    }

    @Test
    fun `ClientClosed state`() {
        ClientClosed.process(ElectrumClientCommand.Connected, logger).let { (newState, actions) ->
            assertEquals(WaitingForVersion, newState)
            assertEquals(1, actions.size)
            assertTrue(actions[0] is ElectrumClientAction.SendRequest)
        }
    }

    @Test
    fun `unhandled events`() {
        listOf(
            WaitingForVersion, WaitingForTip, ClientRunning(0, testBlockHeader), ClientClosed
        ).forEach { state ->
            state.process(ElectrumClientCommand.Disconnected, logger).let { (nextState, actions) ->
                assertEquals(ClientClosed, nextState)
                assertTrue(actions.isEmpty())
            }

            if (state !is ClientRunning)
                state.process(ElectrumClientCommand.AskForHeader, logger).let { (nextState, actions) ->
                    assertEquals(state, nextState)
                    assertTrue(actions.isEmpty())
                }
        }
    }
}
