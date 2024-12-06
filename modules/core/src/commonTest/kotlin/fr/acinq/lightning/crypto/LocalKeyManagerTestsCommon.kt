package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.blockchain.fee.FeeratePerByte
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.transactions.SwapInProtocol
import fr.acinq.lightning.utils.toByteVector
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class LocalKeyManagerTestsCommon : LightningTestSuite() {

    @Test
    fun `generate the same node id from the same seed`() {
        // if this test breaks it means that we will generate a different node id from
        // the same seed, which could be a problem during an upgrade
        val seed = ByteVector("17b086b228025fa8f4416324b6ba2ec36e68570ae2fc3d392520969f2a9d0c1501")
        val keyManager = LocalKeyManager(seed, Chain.Regtest, TestConstants.aliceSwapInServerXpub)
        assertEquals(keyManager.nodeKeys.nodeKey.publicKey, PublicKey.fromHex("0392ea6e914abcee840dc8a763b02ba5ac47e0ac3fadcd5294f9516fe353882522"))
    }

    @Test
    fun `generate channel keys`() {
        val seed = ByteVector("aeb3e9b5642cd4523e9e09164047f60adb413633549c3c6189192921311894d501")
        val keyManager = LocalKeyManager(seed, Chain.Regtest, TestConstants.aliceSwapInServerXpub)
        val fundingKeyPath = makeFundingKeyPath(ByteVector("06535806c1aa73971ec4877a5e2e684fa636136c073810f190b63eefc58ca488"), isInitiator = false)
        val channelKeys = keyManager.channelKeys(fundingKeyPath)

        // README !
        // test data generated with v1.0-beta11, but they should never change
        // if this test fails it means that we cannot restore channels created with older versions of lightning-kmp without
        // some kind of migration process
        val errorMsg = "channel key generation is broken !!!"
        assertEquals(fundingKeyPath, channelKeys.fundingKeyPath, errorMsg)
        assertEquals(PrivateKey.fromHex("cd85f39fad742e5c742eeab16f5f1acaa9d9c48977767c7daa4708a47b7222ec"), channelKeys.fundingKey(0), errorMsg)
        assertEquals(PrivateKey.fromHex("ad635d9d4919e5657a9f306963a5976b533e9d70c8defa454f1bd958fae316c8"), channelKeys.paymentKey, errorMsg)
        assertEquals(PrivateKey.fromHex("0f3c23df3feec614117de23d0b3f014174271826a16e59a17d9ebb655cc55e3f"), channelKeys.delayedPaymentKey, errorMsg)
        assertEquals(PrivateKey.fromHex("ee211f583f3b1b1fb10dca7c82708d985fde641e83e28080f669eb496de85113"), channelKeys.revocationKey, errorMsg)
        assertEquals(ByteVector32.fromValidHex("6255a59ea8155d41e62cddef2c8c63a077f75e23fd3eec1fd4881f6851412518"), channelKeys.shaSeed, errorMsg)
    }

    @Test
    fun `generate different node ids from the same seed on different chains`() {
        val seed = ByteVector("17b086b228025fa8f4416324b6ba2ec36e68570ae2fc3d392520969f2a9d0c1501")
        val keyManager1 = LocalKeyManager(seed, Chain.Regtest, DeterministicWallet.encode(dummyExtendedPubkey, testnet = true))
        val keyManager2 = LocalKeyManager(seed, Chain.Mainnet, DeterministicWallet.encode(dummyExtendedPubkey, testnet = false))
        assertNotEquals(keyManager1.nodeKeys.nodeKey.publicKey, keyManager2.nodeKeys.nodeKey.publicKey)
        val fundingKeyPath = KeyPath("1")
        val channelKeys1 = keyManager1.channelKeys(fundingKeyPath)
        val channelKeys2 = keyManager2.channelKeys(fundingKeyPath)
        assertNotEquals(channelKeys1.fundingPubKey(0), channelKeys2.fundingPubKey(0))
        assertNotEquals(channelKeys1.commitmentPoint(1), channelKeys2.commitmentPoint(1))
    }

    @Test
    fun `compute channel key path from funding keys`() {
        // if this test fails it means that we don't generate the same channel key path from the same funding pubkey, which
        // will break existing channels !
        val pub = PrivateKey(ByteVector32.fromValidHex("0101010101010101010101010101010101010101010101010101010101010101")).publicKey()
        val keyPath = LocalKeyManager.channelKeyPath(pub)
        assertEquals(keyPath.toString(), "m/1909530642'/1080788911/847211985'/1791010671/1303008749'/34154019'/723973395/767609665")
    }

    private fun makeFundingKeyPath(entropy: ByteVector, isInitiator: Boolean): KeyPath {
        val items = (0..7).toList().map { Pack.int32BE(entropy.toByteArray(), it * 4).toLong() and 0xFFFFFFFFL }
        val last = DeterministicWallet.hardened(if (isInitiator) 1L else 0L)
        return KeyPath(items + last)
    }

    @Test
    fun `test vectors -- testnet + initiator`() {
        val seed = ByteVector("17b086b228025fa8f4416324b6ba2ec36e68570ae2fc3d392520969f2a9d0c1501")
        val keyManager = LocalKeyManager(seed, Chain.Regtest, TestConstants.aliceSwapInServerXpub)
        val fundingKeyPath = makeFundingKeyPath(ByteVector("be4fa97c62b9f88437a3be577b31eb48f2165c7bc252194a15ff92d995778cfb"), isInitiator = true)

        val localParams = TestConstants.Alice.channelParams(payCommitTxFees = true).copy(fundingKeyPath = fundingKeyPath)
        val channelKeys = keyManager.channelKeys(localParams.fundingKeyPath)

        assertEquals(channelKeys.fundingPubKey(0), PrivateKey.fromHex("730c0f99408dbfbff00146acf84183ce539fabeeb22c143212f459d71374f715").publicKey())
        assertEquals(channelKeys.revocationBasepoint, PrivateKey.fromHex("ef2aa0a9b4d0bdbc5ee5025f0d16285dc9d17228af1b2cc1e1456252c2d9d207").publicKey())
        assertEquals(channelKeys.paymentBasepoint, PrivateKey.fromHex("e1b76bd22587f88f0903c65aa47f4862152297b4e8dcf3af1f60e762a4ab04e5").publicKey())
        assertEquals(channelKeys.delayedPaymentBasepoint, PrivateKey.fromHex("93d78a9604571baab6882344747a9372f8d0b9e01b569b431314699e397b73e6").publicKey())
        assertEquals(channelKeys.htlcBasepoint, PrivateKey.fromHex("b08ab019cfc8a2b28992d3915ed217b71a596bc85dc766e0fb1fee805ef531c1").publicKey())
        assertEquals(channelKeys.commitmentSecret(0).value, ShaChain.shaChainFromSeed(ByteVector32.fromValidHex("5de1ddde2a94029007f18676b3e9f0141782b95a4aa84061711e554d4111dbb3"), 0xFFFFFFFFFFFFL))
    }

    @Test
    fun `test vectors -- testnet + non-initiator`() {
        val seed = ByteVector("aeb3e9b5642cd4523e9e09164047f60adb413633549c3c6189192921311894d501")
        val keyManager = LocalKeyManager(seed, Chain.Regtest, TestConstants.aliceSwapInServerXpub)
        val fundingKeyPath = makeFundingKeyPath(ByteVector("06535806c1aa73971ec4877a5e2e684fa636136c073810f190b63eefc58ca488"), isInitiator = false)

        val localParams = TestConstants.Alice.channelParams(payCommitTxFees = true).copy(fundingKeyPath = fundingKeyPath)
        val channelKeys = keyManager.channelKeys(localParams.fundingKeyPath)

        assertEquals(channelKeys.fundingPubKey(0), PrivateKey.fromHex("cd85f39fad742e5c742eeab16f5f1acaa9d9c48977767c7daa4708a47b7222ec").publicKey())
        assertEquals(channelKeys.revocationBasepoint, PrivateKey.fromHex("ee211f583f3b1b1fb10dca7c82708d985fde641e83e28080f669eb496de85113").publicKey())
        assertEquals(channelKeys.paymentBasepoint, PrivateKey.fromHex("ad635d9d4919e5657a9f306963a5976b533e9d70c8defa454f1bd958fae316c8").publicKey())
        assertEquals(channelKeys.delayedPaymentBasepoint, PrivateKey.fromHex("0f3c23df3feec614117de23d0b3f014174271826a16e59a17d9ebb655cc55e3f").publicKey())
        assertEquals(channelKeys.htlcBasepoint, PrivateKey.fromHex("664ca828a0510950f24859b62203af192ccc1188f20eb87de33c76e7e04ab0d4").publicKey())
        assertEquals(channelKeys.commitmentSecret(0).value, ShaChain.shaChainFromSeed(ByteVector32.fromValidHex("6255a59ea8155d41e62cddef2c8c63a077f75e23fd3eec1fd4881f6851412518"), 0xFFFFFFFFFFFFL))
    }

    @Test
    fun `test vectors -- mainnet + initiator`() {
        val seed = ByteVector("d8d5431487c2b19ee6486aad6c3bdfb99d10b727bade7fa848e2ab7901c15bff01")
        val keyManager = LocalKeyManager(seed, Chain.Mainnet, DeterministicWallet.encode(dummyExtendedPubkey, testnet = false))
        val fundingKeyPath = makeFundingKeyPath(ByteVector("ec1c41cd6be2b6e4ef46c1107f6c51fbb2066d7e1f7720bde4715af233ae1322"), isInitiator = true)

        val localParams = TestConstants.Alice.channelParams(payCommitTxFees = true).copy(fundingKeyPath = fundingKeyPath)
        val channelKeys = keyManager.channelKeys(localParams.fundingKeyPath)

        assertEquals(channelKeys.fundingPubKey(0), PrivateKey.fromHex("b3b3f1af2ef961ee7aa62451a93a1fd57ea126c81008e5d95ced822cca30da6e").publicKey())
        assertEquals(channelKeys.revocationBasepoint, PrivateKey.fromHex("119ae90789c0b9a68e5cfa2eee08b62cc668b2cd758403dfa7eabde1dc0b6d0a").publicKey())
        assertEquals(channelKeys.paymentBasepoint, PrivateKey.fromHex("882003004cf9c58003f4be161c0ea72879ea9bae8893fd37fb0b3980e0bed0f7").publicKey())
        assertEquals(channelKeys.delayedPaymentBasepoint, PrivateKey.fromHex("7bf712af4006aefeef189b91346f5e3f9a470cc4be9fff9b2ef290032c1bfd3b").publicKey())
        assertEquals(channelKeys.htlcBasepoint, PrivateKey.fromHex("17c685f22bce6f9f1c704477f8ecc7c89b1bf20536fcd30c48fc13666f8d62aa").publicKey())
        assertEquals(channelKeys.commitmentSecret(0).value, ShaChain.shaChainFromSeed(ByteVector32.fromValidHex("cb94d016a90a5558d0d53f928046be41f0584acd8993a399bbd2cb40e5376dac"), 0xFFFFFFFFFFFFL))
    }

    @Test
    fun `test vectors -- mainnet + non-initiator`() {
        val seed = ByteVector("4b809dd593b36131c454d60c2f7bdfd49d12ec455e5b657c47a9ca0f5dfc5eef01")
        val keyManager = LocalKeyManager(seed, Chain.Mainnet, DeterministicWallet.encode(dummyExtendedPubkey, testnet = false))
        val fundingKeyPath = makeFundingKeyPath(ByteVector("2b4f045be5303d53f9d3a84a1e70c12251168dc29f300cf9cece0ec85cd8182b"), isInitiator = false)

        val localParams = TestConstants.Alice.channelParams(payCommitTxFees = true).copy(fundingKeyPath = fundingKeyPath)
        val channelKeys = keyManager.channelKeys(localParams.fundingKeyPath)

        assertEquals(channelKeys.fundingPubKey(0), PrivateKey.fromHex("033880995016c275e725da625e4a78ea8c3215ab8ea54145fa3124bbb2e4a3d4").publicKey())
        assertEquals(channelKeys.revocationBasepoint, PrivateKey.fromHex("16d8dd5e6a22de173288cdb7905cfbbcd9efab99471eb735ff95cb7fbdf43e45").publicKey())
        assertEquals(channelKeys.paymentBasepoint, PrivateKey.fromHex("1682a3b6ebcee107156c49f5d7e29423b1abcc396add6357e9e2d0721881fda0").publicKey())
        assertEquals(channelKeys.delayedPaymentBasepoint, PrivateKey.fromHex("2f047edff3e96d16d726a265ddb95d61f695d34b1861f10f80c1758271b00523").publicKey())
        assertEquals(channelKeys.htlcBasepoint, PrivateKey.fromHex("3e740f7d7d214db23ca17b9586e22f004497dbef585781f5a864ed794ad695c6").publicKey())
        assertEquals(channelKeys.commitmentSecret(0).value, ShaChain.shaChainFromSeed(ByteVector32.fromValidHex("a7968178e0472a53eb5a45bb86d8c4591509fbaeba1e223acc80cc28d37b4804"), 0xFFFFFFFFFFFFL))
    }

    @Test
    fun `bip84 addresses`() {
        // basic test taken from https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
        val mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ")
        val seed = MnemonicCode.toSeed(mnemonics, "").toByteVector()
        val keyManager = LocalKeyManager(seed, Chain.Mainnet, DeterministicWallet.encode(dummyExtendedPubkey, testnet = false))
        assertEquals(keyManager.finalOnChainWallet.address(addressIndex = 0L), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
        assertEquals(keyManager.finalOnChainWallet.address(addressIndex = 1L), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")
        assertEquals(keyManager.finalOnChainWallet.privateKey(addressIndex = 1L).toBase58(Base58.Prefix.SecretKey), "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy")
        assertEquals(keyManager.finalOnChainWallet.privateKey(addressIndex = 0L).toBase58(Base58.Prefix.SecretKey), "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d")
        assertEquals(keyManager.finalOnChainWallet.xpub, "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
    }

    @Test
    fun `bip84 addresses testnet`() {
        // reference data was generated from electrum 4.1.5
        val mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ")
        val seed = MnemonicCode.toSeed(mnemonics, "").toByteVector()
        val keyManager = LocalKeyManager(seed, Chain.Testnet3, TestConstants.aliceSwapInServerXpub)
        assertEquals(keyManager.finalOnChainWallet.privateKey(addressIndex = 0L).toBase58(Base58.Prefix.SecretKeyTestnet), "cTGhosGriPpuGA586jemcuH9pE9spwUmneMBmYYzrQEbY92DJrbo")
        assertEquals(keyManager.finalOnChainWallet.privateKey(addressIndex = 1L).toBase58(Base58.Prefix.SecretKeyTestnet), "cQFUndrpAyMaE3HAsjMCXiT94MzfsABCREat1x7Qe3Mtq9KihD4V")
        assertEquals(keyManager.finalOnChainWallet.xpub, "vpub5Y6cjg78GGuNLsaPhmYsiw4gYX3HoQiRBiSwDaBXKUafCt9bNwWQiitDk5VZ5BVxYnQdwoTyXSs2JHRPAgjAvtbBrf8ZhDYe2jWAqvZVnsc")
    }

    @Test
    fun `swap-in addresses regtest`() {
        assertEquals(PublicKey.fromHex("03d598883dc23081c5926dab28dbd075d542c4fba544471921dbb96a31d7bc4919"), TestConstants.Alice.keyManager.swapInOnChainWallet.userPublicKey)
        assertEquals(PublicKey.fromHex("020bc21d9cb5ecc60fc2002195429d55ff4dfd0888e377a1b3226b4dc1ee7cedf3"), TestConstants.Bob.keyManager.swapInOnChainWallet.userPublicKey)
        assertEquals(TestConstants.Alice.keyManager.swapInOnChainWallet.remoteServerPublicKey, TestConstants.Bob.keyManager.swapInOnChainWallet.localServerPrivateKey(TestConstants.Alice.nodeParams.nodeId).publicKey())
        assertEquals(TestConstants.Bob.keyManager.swapInOnChainWallet.remoteServerPublicKey, TestConstants.Alice.keyManager.swapInOnChainWallet.localServerPrivateKey(TestConstants.Bob.nodeParams.nodeId).publicKey())
        assertEquals(TestConstants.Alice.keyManager.swapInOnChainWallet.remoteServerPublicKey, PublicKey.fromHex("0256e948180f33f067246710a41656084fc245b97eda081efe1e488b21577d60fd"))
        assertEquals(TestConstants.Bob.keyManager.swapInOnChainWallet.remoteServerPublicKey, PublicKey.fromHex("02d8c2f4fe8a017ff3a30eb2a4477f3ebe64ae930f67f907270712a70b18cb8951"))
        assertEquals(
            "wsh(and_v(v:pk([14620948/51h/0h/0h]tpubDCvYeHUZisCMV3h1zPevPWQmNPfA3g3vnu7gDqskXVCbJB1VKk2F7LApV6TTdm1sCyGout8ma27CCHvYTuMZxpwrcHnLwL4kaXW8z2KfFcW),or_d(pk(0256e948180f33f067246710a41656084fc245b97eda081efe1e488b21577d60fd),older(25920))))",
            TestConstants.Alice.keyManager.swapInOnChainWallet.legacyDescriptor
        )
        assertEquals(
            "wsh(and_v(v:pk([85185511/51h/0h/0h]tpubDDt5vQap1awkteTeYioVGLQvj75xrFvjuW6WjNumsedvckEHAMUACubuKtmjmXViDPYMvtnEQt6EGj3eeMVSGRKxRZqCme37j5jAUMhkX5L),or_d(pk(02d8c2f4fe8a017ff3a30eb2a4477f3ebe64ae930f67f907270712a70b18cb8951),older(25920))))",
            TestConstants.Bob.keyManager.swapInOnChainWallet.legacyDescriptor
        )
    }

    @Test
    fun `spend swap-in transactions`() {
        val swapInTx = Transaction(
            version = 2,
            txIn = listOf(),
            txOut = listOf(
                TxOut(Satoshi(100000), TestConstants.Alice.keyManager.swapInOnChainWallet.legacySwapInProtocol.pubkeyScript),
                TxOut(Satoshi(150000), TestConstants.Alice.keyManager.swapInOnChainWallet.legacySwapInProtocol.pubkeyScript),
                TxOut(Satoshi(150000), Script.pay2wpkh(randomKey().publicKey())),
                TxOut(Satoshi(100000), TestConstants.Alice.keyManager.swapInOnChainWallet.getSwapInProtocol(0).pubkeyScript),
                TxOut(Satoshi(150000), TestConstants.Alice.keyManager.swapInOnChainWallet.getSwapInProtocol(1).pubkeyScript),
                TxOut(Satoshi(150000), Script.pay2wpkh(randomKey().publicKey()))
            ),
            lockTime = 0
        )
        val recoveryTx = TestConstants.Alice.keyManager.swapInOnChainWallet.createRecoveryTransaction(swapInTx, TestConstants.Alice.keyManager.finalOnChainWallet.address(0), FeeratePerKw(FeeratePerByte(Satoshi(5))))!!
        assertEquals(4, recoveryTx.txIn.size)
        Transaction.correctlySpends(recoveryTx, swapInTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `compute descriptors to recover swap-in funds`() {
        val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
        val master = DeterministicWallet.generate(seed)
        val chain = Chain.Regtest
        val userPublicKey = PrivateKey.fromHex("0101010101010101010101010101010101010101010101010101010101010101").publicKey()
        val remoteServerPublicKey = PrivateKey.fromHex("0202020202020202020202020202020202020202020202020202020202020202").publicKey()
        val userRefundExtendedPrivateKey = master.derivePrivateKey(KeyManager.SwapInOnChainKeys.swapInUserRefundKeyPath(chain))
        val refundDelay = 2590
        assertEquals(
            "tr(1fc559d9c96c5953895d3150e64ebf3dd696a0b08e758650b48ff6251d7e60d1,and_v(v:pk(tprv8hWm2EfcAbMerYoXeHA9w6faUqXdiQeWfSxxWpzh3Yc1FAjB2vv1sbBNY1dX3HraotvBAEeY2hzz1X4vc3SC516K1ebBvLYrkA6LstQdbNX/*),older(2590)))#90ftphf9",
            SwapInProtocol.privateDescriptor(chain, userPublicKey, remoteServerPublicKey, refundDelay, userRefundExtendedPrivateKey)
        )
        assertEquals(
            "tr(1fc559d9c96c5953895d3150e64ebf3dd696a0b08e758650b48ff6251d7e60d1,and_v(v:pk(tpubDECoAehrJy3Kk1qKXvpkLWKh3s3ZsjqREkZjoM2zTpQQ5eywfKjc45oEi8GMq1mpWxM2kg79Lp5DzznQKGRE15btY327vgLcLbfZLrgAWrv/*),older(2590)))#xmhrglc6",
            SwapInProtocol.publicDescriptor(chain, userPublicKey, remoteServerPublicKey, refundDelay, userRefundExtendedPrivateKey.extendedPublicKey)
        )
    }

    companion object {
        val dummyExtendedPubkey = DeterministicWallet.generate(ByteVector("deadbeef")).extendedPublicKey
    }
}
