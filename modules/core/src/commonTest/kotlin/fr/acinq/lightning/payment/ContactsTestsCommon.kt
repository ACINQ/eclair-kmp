package fr.acinq.lightning.payment

import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.wire.OfferTypes
import fr.acinq.lightning.wire.TlvStream
import kotlin.test.Test
import kotlin.test.assertEquals

class ContactsTestsCommon : LightningTestSuite() {

    @Test
    fun `derive deterministic contact secret -- official test vectors`() {
        // See https://github.com/lightning/blips/blob/master/blip-0042.md
        val trampolineNodeId = PublicKey.fromHex("02f40ffcf9991911063c6fe5a2e48aa31801ba37f18c303d1abe7942e61adcc5e2")
        val aliceOfferAndKey = TestConstants.Alice.nodeParams.defaultOffer(trampolineNodeId)
        assertEquals("4ed1a01dae275f7b7ba503dbae23dddd774a8d5f64788ef7a768ed647dd0e1eb", aliceOfferAndKey.privateKey.value.toHex())
        assertEquals("0284c9c6f04487ac22710176377680127dfcf110aa0fa8186793c7dd01bafdcfd9", aliceOfferAndKey.privateKey.publicKey().toHex())
        assertEquals(
            "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsrejlwh4vyz70s46r62vtakl4sxztqj6gxjged0wx0ly8qtrygufcsyq5agaes6v605af5rr9ydnj9srneudvrmc73n7evp72tzpqcnd28puqr8a3wmcff9wfjwgk32650vl747m2ev4zsjagzucntctlmcpc6vhmdnxlywneg5caqz0ansr45z2faxq7unegzsnyuduzys7kzyugpwcmhdqqj0h70zy92p75pseunclwsrwhaelvsqy9zsejcytxulndppmykcznn7y5h",
            aliceOfferAndKey.offer.encode()
        )
        run {
            // Offers that don't contain an issuer_id.
            val bobOfferAndKey = TestConstants.Bob.nodeParams.defaultOffer(trampolineNodeId)
            assertEquals("12afb8248c7336e6aea5fe247bc4bac5dcabfb6017bd67b32c8195a6c56b8333", bobOfferAndKey.privateKey.value.toHex())
            assertEquals("035e4d1b7237898390e7999b6835ef83cd93b98200d599d29075b45ab0fedc2b34", bobOfferAndKey.privateKey.publicKey().toHex())
            assertEquals(
                "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsz4n88s74qhussxsu0vs3c4unck4yelk67zdc29ree3sztvjn7pc9qyqlcpj54jnj67aa9rd2n5dhjlxyfmv3vgqymrks2nf7gnf5u200mn5qrxfrxh9d0ug43j5egklhwgyrfv3n84gyjd2aajhwqxa0cc7zn37sncrwptz4uhlp523l83xpjx9dw72spzecrtex3ku3h3xpepeuend5rtmurekfmnqsq6kva9yr4k3dtplku9v6qqyxr5ep6lls3hvrqyt9y7htaz9qj",
                bobOfferAndKey.offer.encode(),
            )
            val contactSecretAlice = Contacts.computeContactSecret(aliceOfferAndKey, bobOfferAndKey.offer)
            assertEquals("810641fab614f8bc1441131dc50b132fd4d1e2ccd36f84b887bbab3a6d8cc3d8", contactSecretAlice.primarySecret.toHex())
            val contactSecretBob = Contacts.computeContactSecret(bobOfferAndKey, aliceOfferAndKey.offer)
            assertEquals(contactSecretAlice, contactSecretBob)
        }
        run {
            // The remote offer contains an issuer_id and a blinded path.
            val issuerKey = PrivateKey.fromHex("bcaafa8ed73da11437ce58c7b3458567a870168c0da325a40292fed126b97845")
            assertEquals("023f54c2d913e2977c7fc7dfec029750d128d735a39341d8b08d56fb6edf47c8c6", issuerKey.publicKey().toHex())
            val bobOffer = run {
                val defaultOffer = TestConstants.Bob.nodeParams.defaultOffer(trampolineNodeId).offer
                defaultOffer.copy(records = TlvStream(defaultOffer.records.records + OfferTypes.OfferIssuerId(issuerKey.publicKey())))
            }
            assertEquals(issuerKey.publicKey(), bobOffer.issuerId)
            assertEquals(
                "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsz4n88s74qhussxsu0vs3c4unck4yelk67zdc29ree3sztvjn7pc9qyqlcpj54jnj67aa9rd2n5dhjlxyfmv3vgqymrks2nf7gnf5u200mn5qrxfrxh9d0ug43j5egklhwgyrfv3n84gyjd2aajhwqxa0cc7zn37sncrwptz4uhlp523l83xpjx9dw72spzecrtex3ku3h3xpepeuend5rtmurekfmnqsq6kva9yr4k3dtplku9v6qqyxr5ep6lls3hvrqyt9y7htaz9qjzcssy065ctv38c5h03lu0hlvq2t4p5fg6u668y6pmzcg64hmdm050jxx",
                bobOffer.encode()
            )
            val contactSecretAlice = Contacts.computeContactSecret(aliceOfferAndKey, bobOffer)
            assertEquals("4e0aa72cc42eae9f8dc7c6d2975bbe655683ada2e9abfdfe9f299d391ed9736c", contactSecretAlice.primarySecret.toHex())
            val contactSecretBob = Contacts.computeContactSecret(OfferTypes.OfferAndKey(bobOffer, issuerKey), aliceOfferAndKey.offer)
            assertEquals(contactSecretAlice, contactSecretBob)

        }
    }

}