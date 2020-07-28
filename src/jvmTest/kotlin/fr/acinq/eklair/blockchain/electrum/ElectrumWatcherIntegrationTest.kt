package fr.acinq.eklair.blockchain.electrum

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.SigHash.SIGHASH_ALL
import fr.acinq.eklair.blockchain.*
import fr.acinq.eklair.blockchain.bitcoind.BitcoindService
import fr.acinq.eklair.utils.sat
import fr.acinq.secp256k1.Hex
import io.ktor.util.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.TestCoroutineScope
import kotlinx.coroutines.withTimeout
import org.junit.FixMethodOrder
import org.junit.runners.MethodSorters
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.time.ExperimentalTime
import kotlin.time.milliseconds

@OptIn(ExperimentalCoroutinesApi::class, KtorExperimentalAPI::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class ElectrumWatcherIntegrationTest {
    private val TIMEOUT = 60_000L // Must be lower

    @Test
    fun `01 watch for confirmed transactions`() = runBlocking {
        val client = ElectrumClient("localhost", 51001, false, this).apply { start() }
        val watcher = ElectrumWatcher(client, this).apply { start() }

        val (address,_) = BitcoindService.getNewAddress()
        val tx = BitcoindService.sendToAddress(address, 1.0)

        val listener = Channel<WatchEventConfirmed>()
        watcher.watch(
            WatchConfirmed(
                listener,
                ByteVector32.Zeroes,
                tx.txid,
                tx.txOut[0].publicKeyScript,
                4,
                BITCOIN_FUNDING_DEPTHOK
            )
        )
        BitcoindService.generateBlocks(5)

        withTimeout(TIMEOUT) {
            val confirmed = listener.receive()
            assertEquals(tx.txid, confirmed.tx.txid)
        }

        watcher.stop()
        client.stop()
    }

    @Test
    fun `02 watch for confirmed transactions created while being offline`() = runBlocking {
        val client = ElectrumClient("localhost", 51001, false, this).apply { start() }
        val watcher = ElectrumWatcher(client, this).apply { start() }

        val (address,_) = BitcoindService.getNewAddress()
        val tx = BitcoindService.sendToAddress(address, 1.0)

        BitcoindService.generateBlocks(5)

        val listener = Channel<WatchEventConfirmed>()
        watcher.watch(WatchConfirmed(
            listener,
            ByteVector32.Zeroes,
            tx.txid,
            tx.txOut[0].publicKeyScript,
            4,
            BITCOIN_FUNDING_DEPTHOK
        ))

        withTimeout(TIMEOUT) {
            val confirmed = listener.receive()
            assertEquals(tx.txid, confirmed.tx.txid)
        }

        watcher.stop()
        client.stop()
    }

    @Test
    fun `03 watch for spent transactions`() = runBlocking {
        val client = ElectrumClient("localhost", 51001, false, this).apply { start() }
        val watcher = ElectrumWatcher(client, this).apply { start() }

        val (address, privateKey) = BitcoindService.getNewAddress()
        val tx = BitcoindService.sendToAddress(address, 1.0)

        // find the output for the address we generated and create a tx that spends it
        val pos= tx.txOut.indexOfFirst {
            it.publicKeyScript == Script.write(Script.pay2wpkh(privateKey.publicKey())).byteVector()
        }
        assert(pos != -1)

        val spendingTx = kotlin.run {
            val tmp = Transaction(version = 2,
                txIn = listOf(TxIn(OutPoint(tx, pos.toLong()), signatureScript = emptyList(), sequence = TxIn.SEQUENCE_FINAL)),
                txOut = listOf(TxOut(tx.txOut[pos].amount - 1000.sat, publicKeyScript = Script.pay2wpkh(privateKey.publicKey()))),
                lockTime = 0)

            val sig = Transaction.signInput(
                tmp,
                0,
                Script.pay2pkh(privateKey.publicKey()),
                SIGHASH_ALL,
                tx.txOut[pos].amount,
                SigVersion.SIGVERSION_WITNESS_V0,
                privateKey
            ).byteVector()
            val signedTx = tmp.updateWitness(0, ScriptWitness(listOf(sig, privateKey.publicKey().value)))
            Transaction.correctlySpends(signedTx, listOf(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            signedTx
        }

        val listener = Channel<WatchEventSpent>()
        watcher.watch(WatchSpent(
            listener,
            ByteVector32.Zeroes,
            tx.txid,
            pos,
            tx.txOut[pos].publicKeyScript,
            BITCOIN_FUNDING_SPENT
        ))

        // send raw tx
        val sentTx = BitcoindService.sendRawTransaction(spendingTx)
        assertEquals(spendingTx, sentTx)
        BitcoindService.generateBlocks(2)

        withTimeout(TIMEOUT) {
            val msg = listener.receive()
            assertEquals(spendingTx.txid, msg.tx.txid)
        }

        watcher.stop()
        client.stop()
    }

    @Test
    fun `04 watch for spent transactions while being offline`() = runBlocking {
        val client = ElectrumClient("localhost", 51001, false, this).apply { start() }
        val watcher = ElectrumWatcher(client, this).apply { start() }

        val (address, privateKey) = BitcoindService.getNewAddress()
        val tx = BitcoindService.sendToAddress(address, 1.0)

        // find the output for the address we generated and create a tx that spends it
        val pos= tx.txOut.indexOfFirst {
            it.publicKeyScript == Script.write(Script.pay2wpkh(privateKey.publicKey())).byteVector()
        }
        assert(pos != -1)

        val spendingTx = kotlin.run {
            val tmp = Transaction(version = 2,
                txIn = listOf(TxIn(OutPoint(tx, pos.toLong()), signatureScript = emptyList(), sequence = TxIn.SEQUENCE_FINAL)),
                txOut = listOf(TxOut(tx.txOut[pos].amount - 1000.sat, publicKeyScript = Script.pay2wpkh(privateKey.publicKey()))),
                lockTime = 0)

            val sig = Transaction.signInput(
                tmp,
                0,
                Script.pay2pkh(privateKey.publicKey()),
                SIGHASH_ALL,
                tx.txOut[pos].amount,
                SigVersion.SIGVERSION_WITNESS_V0,
                privateKey
            ).byteVector()
            val signedTx = tmp.updateWitness(0, ScriptWitness(listOf(sig, privateKey.publicKey().value)))
            Transaction.correctlySpends(signedTx, listOf(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            signedTx
        }

        // send raw tx
        val sentTx = BitcoindService.sendRawTransaction(spendingTx)
        assertEquals(spendingTx, sentTx)
        BitcoindService.generateBlocks(2)

        val listener = Channel<WatchEventSpent>()
        watcher.watch(WatchSpent(
            listener,
            ByteVector32.Zeroes,
            tx.txid,
            pos,
            tx.txOut[pos].publicKeyScript,
            BITCOIN_FUNDING_SPENT
        ))

        withTimeout(TIMEOUT) {
            val msg = listener.receive()
            assertEquals(spendingTx.txid, msg.tx.txid)
        }

        watcher.stop()
        client.stop()
    }

    @Test
    fun `05 watch for mempool transactions (txs in mempool before we set the watch)`() = runBlocking {
        val client = ElectrumClient("localhost", 51001, false, this).apply { start() }
        val watcher = ElectrumWatcher(client, this).apply { start() }

//        val statusListener = Channel<ElectrumMessage>()
//        val status = statusListener.receive()
//        assertTrue { status is ElectrumClientReady }
//        client.sendMessage(ElectrumStatusSubscription(statusListener))

        val (address, privateKey) = BitcoindService.getNewAddress()
        val tx = BitcoindService.sendToAddress(address, 1.0)
        val (tx1, tx2) = BitcoindService.createUnspentTxChain(tx, privateKey)

        val sentTx1 = BitcoindService.sendRawTransaction(tx1)
        assertEquals(tx1, sentTx1)
        val sentTx2 = BitcoindService.sendRawTransaction(tx2)
        assertEquals(tx2, sentTx2)

        // wait until tx1 and tx2 are in the mempool (as seen by our ElectrumX server)
        withTimeout(30_000) {
            while (true) {
                val getHistoryListener = Channel<ElectrumMessage>()
                client.sendMessage(SendElectrumRequest(GetScriptHashHistory(ElectrumClient.computeScriptHash(tx2.txOut[0].publicKeyScript)), getHistoryListener))

                val (_, history) = getHistoryListener.receive() as GetScriptHashHistoryResponse
                if (history.map { it.tx_hash }.toSet() == setOf(tx.txid, tx1.txid, tx2.txid)) break

                delay(5_000)
            }
        }

        val listener = Channel<WatchEventConfirmed>()
        watcher.watch(WatchConfirmed(
            listener,
            ByteVector32.Zeroes,
            tx2.txid,
            tx2.txOut[0].publicKeyScript,
            0,
            BITCOIN_FUNDING_DEPTHOK
        ))

        withTimeout(TIMEOUT) {
            val confirmed = listener.receive()
            assertEquals(tx2.txid, confirmed.tx.txid)
        }

        watcher.stop()
        client.stop()
    }

    @Test
    fun `06 watch for mempool transactions (txs not yet in the mempool when we set the watch)`()  = runBlocking {
        val client = ElectrumClient("localhost", 51001, false, this).apply { start() }
        val watcher = ElectrumWatcher(client, this).apply { start() }

//        val statusListener = Channel<ElectrumMessage>()
//        client.sendMessage(ElectrumStatusSubscription(statusListener))
//        statusListener.consumeEach { if (it is ElectrumClientReady) return@consumeEach }

        val (address, privateKey) = BitcoindService.getNewAddress()
        val tx = BitcoindService.sendToAddress(address, 1.0)
        val (tx1, tx2) = BitcoindService.createUnspentTxChain(tx, privateKey)

        val listener = Channel<WatchEventConfirmed>()
        watcher.watch(WatchConfirmed(
            listener,
            ByteVector32.Zeroes,
            tx2.txid,
            tx2.txOut[0].publicKeyScript,
            0,
            BITCOIN_FUNDING_DEPTHOK
        ))

        val sentTx1 = BitcoindService.sendRawTransaction(tx1)
        assertEquals(tx1, sentTx1)
        val sentTx2 = BitcoindService.sendRawTransaction(tx2)
        assertEquals(tx2, sentTx2)

        withTimeout(TIMEOUT) {
            val confirmed = listener.receive()
            assertEquals(tx2.txid, confirmed.tx.txid)
        }

        watcher.stop()
        client.stop()
    }

    @Test
    @OptIn(ExperimentalTime::class)
    fun `07 get transaction`() = runBlocking {
        val testScope = TestCoroutineScope()
        // Run on a production server
        val electrumClient = ElectrumClient("electrum.acinq.co", 50002, true, testScope).apply { start() }
        val electrumWatcher = ElectrumWatcher(electrumClient, testScope).apply { start() }

        delay(1_000) // Wait for the electrum client to be ready

        // tx is in the blockchain
        kotlin.run {
            val txid = ByteVector32(Hex.decode("c0b18008713360d7c30dae0940d88152a4bbb10faef5a69fefca5f7a7e1a06cc"))
            val listener = Channel<GetTxWithMetaResponse>()
            electrumWatcher.send(GetTxWithMetaEvent(txid, listener))
            val res = listener.receive()
            assertEquals(res.txid, txid)
            assertEquals(
                res.tx_opt,
                Transaction.read("0100000001b5cbd7615a7494f60304695c180eb255113bd5effcf54aec6c7dfbca67f533a1010000006a473044022042115a5d1a489bbc9bd4348521b098025625c9b6c6474f84b96b11301da17a0602203ccb684b1d133ff87265a6017ef0fdd2d22dd6eef0725c57826f8aaadcc16d9d012103629aa3df53cad290078bbad26491f1e11f9c01697c65db0967561f6f142c993cffffffff02801015000000000017a914b8984d6344eed24689cdbc77adaf73c66c4fdd688734e9e818000000001976a91404607585722760691867b42d43701905736be47d88ac00000000")
            )
            assert(res.lastBlockTimestamp > System.currentTimeMillis().milliseconds.inSeconds - 7200) // this server should be in sync
        }

        // tx doesn't exist
        kotlin.run {
            val txid = ByteVector32(Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
            val listener = Channel<GetTxWithMetaResponse>()
            electrumWatcher.send(GetTxWithMetaEvent(txid, listener))
            val res = listener.receive()
            assertEquals(res.txid, txid)
            assertNull(res.tx_opt)
            assert(res.lastBlockTimestamp > System.currentTimeMillis().milliseconds.inSeconds - 7200) // this server should be in sync
        }

        electrumWatcher.stop()
        electrumClient.stop()
    }

    /*
    - OK:
        test("watch for confirmed transactions")
        test("watch for confirmed transactions when being offline")
        test("get transaction")
    - KO:
        test("watch for spent transactions")
        test("generate unique dummy scids") => UnitTests
        test("watch for mempool transactions (txs in mempool before we set the watch)")
        test("watch for mempool transactions (txs not yet in the mempool when we set the watch)")
     */
}