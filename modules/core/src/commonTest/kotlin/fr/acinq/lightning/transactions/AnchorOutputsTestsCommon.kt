package fr.acinq.lightning.transactions

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Try
import fr.acinq.bitcoin.utils.runTrying
import fr.acinq.lightning.CltvExpiry
import fr.acinq.lightning.CltvExpiryDelta
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.channel.Commitments
import fr.acinq.lightning.channel.LocalParams
import fr.acinq.lightning.channel.RemoteParams
import fr.acinq.lightning.crypto.Bolt3Derivation.deriveForCommitment
import fr.acinq.lightning.crypto.KeyManager.ChannelKeys
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.HtlcTx.HtlcSuccessTx
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.UpdateAddHtlc
import kotlinx.serialization.json.Json
import org.kodein.memory.file.FileSystem
import org.kodein.memory.file.Path
import org.kodein.memory.file.openReadableFile
import org.kodein.memory.file.resolve
import org.kodein.memory.system.Environment
import org.kodein.memory.text.readString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AnchorOutputsTestsCommon {
    val local_funding_privkey = PrivateKey.fromHex("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901")
    val local_funding_pubkey = PublicKey.fromHex(" 023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb")
    val remote_funding_pubkey = PublicKey.fromHex("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1")
    val local_privkey = PrivateKey.fromHex("bb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f27469449101")
    val localpubkey = PublicKey.fromHex("030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7")
    val remotepubkey = PublicKey.fromHex("0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b")
    val local_delayedpubkey = PublicKey.fromHex("03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c")
    val local_revocation_pubkey = PublicKey.fromHex("0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19")
    val remote_funding_privkey = PrivateKey.fromHex("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e1301")
    val local_payment_basepoint_secret = PrivateKey.fromHex("111111111111111111111111111111111111111111111111111111111111111101")
    val remote_revocation_basepoint_secret = PrivateKey.fromHex("222222222222222222222222222222222222222222222222222222222222222201")
    val local_delayed_payment_basepoint_secret = PrivateKey.fromHex("333333333333333333333333333333333333333333333333333333333333333301")
    val remote_payment_basepoint_secret = PrivateKey.fromHex("444444444444444444444444444444444444444444444444444444444444444401")
    val local_per_commitment_secret = PrivateKey.fromHex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010001")

    // From remote_revocation_basepoint_secret
    val remote_revocation_basepoint = PublicKey.fromHex("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27")

    // From local_delayed_payment_basepoint_secret
    val local_delayed_payment_basepoint = PublicKey.fromHex("023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1")
    val local_per_commitment_point = PublicKey.fromHex("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486")
    val remote_privkey = PrivateKey.fromHex("8deba327a7cc6d638ab0eb025770400a6184afcba6713c210d8d10e199ff2fda01")

    // From local_delayed_payment_basepoint_secret, local_per_commitment_point and local_delayed_payment_basepoint
    val local_delayed_privkey = PrivateKey.fromHex("adf3464ce9c2f230fd2582fda4c6965e4993ca5524e8c9580e3df0cf226981ad01")

    val local_htlc_privkey = local_payment_basepoint_secret.deriveForCommitment(local_per_commitment_point)
    val local_payment_privkey = local_payment_basepoint_secret
    val local_delayed_payment_privkey = local_delayed_payment_basepoint_secret.deriveForCommitment(local_per_commitment_point)

    val remote_htlc_privkey = remote_payment_basepoint_secret.deriveForCommitment(local_per_commitment_point)
    val remote_payment_privkey = remote_payment_basepoint_secret

    val funding_tx =
        Transaction.read("0200000001adbb20ea41a8423ea937e76e8151636bf6093b70eaff942930d20576600521fd000000006b48304502210090587b6201e166ad6af0227d3036a9454223d49a1f11839c1a362184340ef0240220577f7cd5cca78719405cbf1de7414ac027f0239ef6e214c90fcaab0454d84b3b012103535b32d5eb0a6ed0982a0479bbadc9868d9836f6ba94dd5a63be16d875069184ffffffff028096980000000000220020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd20256d29010000001600143ca33c2e4446f4a305f23c80df8ad1afdcf652f900000000")
    val commitTxInput = Transactions.InputInfo.SegwitInput(
        OutPoint(funding_tx, 0),
        funding_tx.txOut[0],
        Scripts.multiSig2of2(local_funding_pubkey, remote_funding_pubkey)
    )
    val preimages = listOf(
        ByteVector32("0000000000000000000000000000000000000000000000000000000000000000"),
        ByteVector32("0101010101010101010101010101010101010101010101010101010101010101"),
        ByteVector32("0202020202020202020202020202020202020202020202020202020202020202"),
        ByteVector32("0303030303030303030303030303030303030303030303030303030303030303"),
        ByteVector32("0404040404040404040404040404040404040404040404040404040404040404"),
    )
    val htlcs = listOf(
        IncomingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, 1000000.msat, preimages[0].sha256(), CltvExpiry(500), TestConstants.emptyOnionPacket)),
        IncomingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 1, 2000000.msat, preimages[1].sha256(), CltvExpiry(501), TestConstants.emptyOnionPacket)),
        OutgoingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 2, 2000000.msat, preimages[2].sha256(), CltvExpiry(502), TestConstants.emptyOnionPacket)),
        OutgoingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 3, 3000000.msat, preimages[3].sha256(), CltvExpiry(503), TestConstants.emptyOnionPacket)),
        IncomingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 4, 4000000.msat, preimages[4].sha256(), CltvExpiry(504), TestConstants.emptyOnionPacket)),
    )

    // high level tests which calls Commitments methods to generate transactions
    private fun runHighLevelTest(testCase: TestCase) {
        val channelKeys = ChannelKeys(KeyPath.empty, { local_funding_privkey }, local_payment_basepoint_secret, local_delayed_payment_basepoint_secret, local_payment_basepoint_secret, local_payment_basepoint_secret, randomBytes32())
        val localParams = LocalParams(
            TestConstants.Alice.nodeParams.nodeId,
            KeyPath.empty,
            546.sat, 1000000000L, 0.msat, CltvExpiryDelta(144), 1000,
            isChannelOpener = true, paysCommitTxFees = true,
            Script.write(Script.pay2wpkh(randomKey().publicKey())).toByteVector(),
            TestConstants.Alice.nodeParams.features,
        )
        val remoteParams = RemoteParams(
            TestConstants.Bob.nodeParams.nodeId,
            546.sat,
            1000000000L,
            0.msat,
            CltvExpiryDelta(144),
            1000,
            remote_revocation_basepoint,
            remote_payment_privkey.publicKey(),
            PrivateKey.fromHex("444444444444444444444444444444444444444444444444444444444444444401").publicKey(),
            PrivateKey.fromHex("444444444444444444444444444444444444444444444444444444444444444401").publicKey(),
            TestConstants.Bob.nodeParams.features
        )
        val spec = CommitmentSpec(
            if (testCase.UseTestHtlcs) htlcs.toSet() else setOf(),
            FeeratePerKw(testCase.FeePerKw.sat),
            testCase.LocalBalance.msat,
            testCase.RemoteBalance.msat
        )

        /* The test vector values are derived, as per Key Derivation, though it's not
        required for this test. They're included here for completeness and
        in case someone wants to reproduce the test vectors themselves:

        INTERNAL: remote_funding_privkey: 1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e1301
        INTERNAL: local_payment_basepoint_secret: 111111111111111111111111111111111111111111111111111111111111111101
        INTERNAL: remote_revocation_basepoint_secret: 222222222222222222222222222222222222222222222222222222222222222201
        INTERNAL: local_delayed_payment_basepoint_secret: 333333333333333333333333333333333333333333333333333333333333333301
        INTERNAL: remote_payment_basepoint_secret: 444444444444444444444444444444444444444444444444444444444444444401
        x_local_per_commitment_secret: 1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010001
        # From remote_revocation_basepoint_secret
                INTERNAL: remote_revocation_basepoint: 02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27
        # From local_delayed_payment_basepoint_secret
                INTERNAL: local_delayed_payment_basepoint: 023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1
        INTERNAL: local_per_commitment_point: 025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486
        INTERNAL: remote_privkey: 8deba327a7cc6d638ab0eb025770400a6184afcba6713c210d8d10e199ff2fda01
        # From local_delayed_payment_basepoint_secret, local_per_commitment_point and local_delayed_payment_basepoint
        INTERNAL: local_delayed_privkey: adf3464ce9c2f230fd2582fda4c6965e4993ca5524e8c9580e3df0cf226981ad01
        */

        val (commitTx, htlcTxs) = Commitments.makeLocalTxs(
            channelKeys,
            42, localParams, remoteParams,
            fundingTxIndex = 0,
            remote_funding_pubkey,
            Transactions.InputInfo.SegwitInput(OutPoint(funding_tx, 0), funding_tx.txOut[0], Scripts.multiSig2of2(local_funding_pubkey, remote_funding_pubkey)),
            local_per_commitment_point,
            spec
        )

        val localSig = Transactions.sign(commitTx, local_funding_privkey)
        val remoteSig = Transactions.sign(commitTx, remote_funding_privkey)
        val signedTx = Transactions.addSigs(commitTx, local_funding_pubkey, remote_funding_pubkey, localSig, remoteSig)
        assertEquals(Transaction.read(testCase.ExpectedCommitmentTxHex), signedTx.tx)
        val txs = testCase.HtlcDescs.map { Transaction.read(it.ResolutionTxHex).txid to Transaction.read(it.ResolutionTxHex) }.toMap()
        val remoteHtlcSigs = testCase.HtlcDescs.map { Transaction.read(it.ResolutionTxHex).txid to ByteVector(it.RemoteSigHex) }.toMap()
        assertTrue { remoteHtlcSigs.keys.containsAll(htlcTxs.map { it.tx.txid }) }
        htlcTxs.forEach { htlcTx ->
            val localHtlcSig = Transactions.sign(htlcTx, local_htlc_privkey, SigHash.SIGHASH_ALL)
            val remoteHtlcSig = Crypto.der2compact(remoteHtlcSigs[htlcTx.tx.txid]!!.toByteArray())
            val expectedTx = txs[htlcTx.tx.txid]
            val signed = when (htlcTx) {
                is HtlcSuccessTx -> Transactions.addSigs(htlcTx, localHtlcSig, remoteHtlcSig, preimages.find { it.sha256() == htlcTx.paymentHash }!!)
                is HtlcTimeoutTx -> Transactions.addSigs(htlcTx, localHtlcSig, remoteHtlcSig)
            }
            assertEquals(expectedTx, signed.tx)
        }
    }

    // low-level tests where transactions are built manually using low-level primitives
    private fun runLowLevelTest(testCase: TestCase) {
        val spec = CommitmentSpec(
            if (testCase.UseTestHtlcs) htlcs.toSet() else setOf(),
            FeeratePerKw(testCase.FeePerKw.sat),
            testCase.LocalBalance.msat,
            testCase.RemoteBalance.msat
        )
        val outputs = Transactions.makeCommitTxOutputs(
            local_funding_pubkey,
            remote_funding_pubkey,
            true,
            546.sat,
            local_revocation_pubkey,
            CltvExpiryDelta(144),
            local_delayed_payment_privkey.publicKey(),
            remote_payment_privkey.publicKey(),
            local_htlc_privkey.publicKey(),
            remote_htlc_privkey.publicKey(),
            spec,
            false
        )
        val commitTx = Transactions.makeCommitTx(
            commitTxInput,
            42L,
            local_payment_basepoint_secret.publicKey(),
            remote_payment_basepoint_secret.publicKey(),
            true,
            outputs
        )
        val localSig = Transactions.sign(commitTx, local_funding_privkey)
        val remoteSig = Transactions.sign(commitTx, remote_funding_privkey)
        val signedTx = Transactions.addSigs(commitTx, local_funding_pubkey, remote_funding_pubkey, localSig, remoteSig)
        assertEquals(testCase.ExpectedCommitmentTx, signedTx.tx)

        val txs = testCase.HtlcDescs.map { it.ResolutionTx.txid to it.ResolutionTx }.toMap()
        val remoteHtlcSigs = testCase.HtlcDescs.map { it.ResolutionTx.txid to ByteVector(it.RemoteSigHex) }.toMap()
        val htlcTxs = Transactions.makeHtlcTxs(commitTx.tx, 546.sat, local_revocation_pubkey, CltvExpiryDelta(144), local_delayedpubkey, spec.feerate, outputs)
        assertTrue { remoteHtlcSigs.keys.containsAll(htlcTxs.map { it.tx.txid }) }
        htlcTxs.forEach { htlcTx ->
            val localHtlcSig = Transactions.sign(htlcTx, local_htlc_privkey, SigHash.SIGHASH_ALL)
            val remoteHtlcSig = Crypto.der2compact(remoteHtlcSigs[htlcTx.tx.txid]!!.toByteArray())
            val expectedTx = txs[htlcTx.tx.txid]
            val signed = when (htlcTx) {
                is HtlcSuccessTx -> Transactions.addSigs(htlcTx, localHtlcSig, remoteHtlcSig, preimages.find { it.sha256() == htlcTx.paymentHash }!!)
                is HtlcTimeoutTx -> Transactions.addSigs(htlcTx, localHtlcSig, remoteHtlcSig)
            }
            assertEquals(expectedTx, signed.tx)
        }
    }

    @Test
    fun `BOLT 3 test vectors`() {
        testCases.forEach {
            val result = runTrying { runLowLevelTest(it) }
            if (result is Try.Failure) error("low level test ${it.Name} failed: ${result.error}}")
            val result1 = runTrying { runHighLevelTest(it) }
            if (result1 is Try.Failure) error("high level test ${it.Name} failed: ${result1.error}}")
        }
    }

    companion object {
        @kotlinx.serialization.Serializable
        data class HtlcDesc(val RemoteSigHex: String, val ResolutionTxHex: String) {
            val ResolutionTx get() = Transaction.read(ResolutionTxHex)
        }

        @kotlinx.serialization.Serializable
        data class TestCase(val Name: String, val LocalBalance: Long, val RemoteBalance: Long, val FeePerKw: Int, val UseTestHtlcs: Boolean, val HtlcDescs: Array<HtlcDesc>, val ExpectedCommitmentTxHex: String, val RemoteSigHex: String) {
            val ExpectedCommitmentTx get() = Transaction.read(ExpectedCommitmentTxHex)
        }

        val format = Json { ignoreUnknownKeys = true }
        val json = run {
            val resourceDir = Environment.findVariable("TEST_RESOURCES_PATH")?.let { Path(it) } ?: FileSystem.workingDir().resolve("src/commonTest/resources")
            val file = resourceDir.resolve("bolt3_anchor_outputs_test_vectors.json")
            file.openReadableFile().run { readString(sizeBytes = remaining) }
        }
        val testCases = format.decodeFromString<Array<TestCase>>(json)
    }
}