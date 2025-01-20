package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.crypto.LocalKeyManager
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.transactions.Scripts
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.toByteVector
import fr.acinq.lightning.utils.toByteVector32
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RecoveryTestsCommon {
    @Test
    fun `use funding pubkeys from published commitment to spend our output`() {
        // Alice creates and uses a LN channel to Bob
        val (alice, bob) = TestsHelper.reachNormal()
        val (alice1, _) = TestsHelper.addHtlc(MilliSatoshi(50000), alice, bob).first

        // Alice force-closes the channel and publishes her commit tx
        val (_, actions) = alice1.process(ChannelCommand.Close.ForceClose)
        val transactions = actions.findPublishTxs()
        val commitTx = transactions[0]
        val aliceTx = transactions[1]

        // how can Bob find and spend his output in Alice's published commit tx with just his wallet seed (derived from his mnemonic words) and nothing else?

        // extract funding pubkeys from the commit tx witness, which is a multisig 2-of-2
        val redeemScript = Script.parse(commitTx.txIn[0].witness.last())
        assertTrue(redeemScript.size == 5 && redeemScript[0] == OP_2 && redeemScript[3] == OP_2 && redeemScript[4] == OP_CHECKMULTISIG)
        val pub1 = PublicKey((redeemScript[1] as OP_PUSHDATA).data)
        val pub2 = PublicKey((redeemScript[2] as OP_PUSHDATA).data)

        // use Bob's mnemonic words to initialise his key manager
        val seed = MnemonicCode.toSeed(TestConstants.Bob.mnemonics, "").toByteVector32()
        val keyManager = LocalKeyManager(seed, Chain.Regtest, TestConstants.aliceSwapInServerXpub)

        // recompute our channel keys from the extracted funding pubkey and see if we can find and spend our output
        fun findAndSpend(fundingKey: PublicKey): Transaction? {
            val channelKeys = keyManager.recoverChannelKeys(fundingKey)
            val localPaymentPoint = channelKeys.paymentBasepoint
            val mainTx = Transactions.makeClaimRemoteDelayedOutputTx(
                commitTx,
                TestConstants.Bob.nodeParams.dustLimit,
                localPaymentPoint,
                Script.write(Script.pay2wpkh(fundingKey)).toByteVector(),
                FeeratePerKw(Satoshi(750)),
                isTaprootChannel = false
            )
            return when (mainTx) {
                is Transactions.TxResult.Success -> {
                    val sig = Transactions.sign(mainTx.result, channelKeys.paymentKey)
                    val signedTx = Transactions.addSigs(mainTx.result, sig).tx
                    Transaction.correctlySpends(signedTx, commitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
                    signedTx
                }
                else -> null
            }
        }

        // this is the script of the output that we're spending
        val bobTx = findAndSpend(pub1) ?: findAndSpend(pub2)!!
        assertNotEquals(aliceTx, bobTx)

        val outputScript = Script.parse(commitTx.txOut[bobTx.txIn[0].outPoint.index.toInt()].publicKeyScript)

        // this is what our main output script should be
        fun ourDelayedOutputScript(pub: PublicKey): List<ScriptElt> {
            val channelKeys = keyManager.recoverChannelKeys(pub)
            return Script.pay2wsh(Scripts.toRemoteDelayed(channelKeys.paymentBasepoint))
        }

        assertTrue(outputScript == ourDelayedOutputScript(pub1) || outputScript == ourDelayedOutputScript(pub2))
    }
}
