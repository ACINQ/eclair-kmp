package fr.acinq.lightning.payment

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.byteVector32
import fr.acinq.lightning.Feature
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.Features
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.utils.msat
import fr.acinq.lightning.wire.OfferTypes
import kotlin.experimental.xor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OfferPaymentMetadataTestsCommon {

    @Test
    fun `encode - decode v1 metadata`() {
        val nodeKey = randomKey()
        val metadata = OfferPaymentMetadata.V1(
            offerId = randomBytes32(),
            amount = 50_000_000.msat,
            preimage = randomBytes32(),
            payerKey = randomKey().publicKey(),
            payerNote = null,
            quantity = 1,
            createdAtMillis = 0
        )
        assertEquals(metadata, OfferPaymentMetadata.decode(metadata.encode()))
        val pathId = metadata.toPathId(nodeKey)
        assertEquals(metadata, OfferPaymentMetadata.fromPathId(nodeKey, pathId, Crypto.sha256(metadata.preimage).byteVector32()))
    }

    @Test
    fun `encode - decode v1 metadata with payer note`() {
        val nodeKey = randomKey()
        val metadata = OfferPaymentMetadata.V1(
            offerId = randomBytes32(),
            amount = 100_000_000.msat,
            preimage = randomBytes32(),
            payerKey = randomKey().publicKey(),
            payerNote = "Thanks for all the fish",
            quantity = 42,
            createdAtMillis = 0
        )
        assertEquals(metadata, OfferPaymentMetadata.decode(metadata.encode()))
        val pathId = metadata.toPathId(nodeKey)
        assertEquals(metadata, OfferPaymentMetadata.fromPathId(nodeKey, pathId, Crypto.sha256(metadata.preimage).byteVector32()))
    }

    @Test
    fun `encode - decode v2 metadata`() {
        val nodeKey = randomKey()
        val preimage = randomBytes32()
        val paymentHash = Crypto.sha256(preimage).byteVector32()
        val metadata = OfferPaymentMetadata.V2(
            offerId = randomBytes32(),
            amount = 200_000_000.msat,
            preimage = preimage,
            payerKey = randomKey().publicKey(),
            payerNote = "thanks for all the fish",
            quantity = 1,
            contactSecret = null,
            payerOffer = null,
            payerAddress = null,
            createdAtMillis = 0
        )
        assertEquals(metadata, OfferPaymentMetadata.decode(metadata.encode()))
        val pathId = metadata.toPathId(nodeKey)
        assertTrue(pathId.size() in 150..200)
        assertEquals(metadata, OfferPaymentMetadata.fromPathId(nodeKey, pathId, paymentHash))
    }

    @Test
    fun `encode - decode v2 metadata with contact offer`() {
        val nodeKey = randomKey()
        val preimage = randomBytes32()
        val paymentHash = Crypto.sha256(preimage).byteVector32()
        val payerOffer = OfferTypes.Offer.createBlindedOffer(
            amount = null,
            description = null,
            nodeParams = TestConstants.Alice.nodeParams,
            trampolineNodeId = randomKey().publicKey(),
            features = Features(
                Feature.VariableLengthOnion to FeatureSupport.Optional,
                Feature.PaymentSecret to FeatureSupport.Optional,
                Feature.BasicMultiPartPayment to FeatureSupport.Optional,
            ),
            blindedPathSessionKey = randomKey()
        ).offer
        val metadata = OfferPaymentMetadata.V2(
            offerId = randomBytes32(),
            amount = 200_000_000.msat,
            preimage = preimage,
            payerKey = randomKey().publicKey(),
            payerNote = "hello there",
            quantity = 1,
            contactSecret = randomBytes32(),
            payerOffer = payerOffer,
            payerAddress = null,
            createdAtMillis = 0
        )
        assertEquals(metadata, OfferPaymentMetadata.decode(metadata.encode()))
        val pathId = metadata.toPathId(nodeKey)
        assertTrue(pathId.size() in 400..450)
        assertEquals(metadata, OfferPaymentMetadata.fromPathId(nodeKey, pathId, paymentHash))
    }

    @Test
    fun `encode - decode v2 metadata with contact address`() {
        val nodeKey = randomKey()
        val preimage = randomBytes32()
        val paymentHash = Crypto.sha256(preimage).byteVector32()
        val metadata = OfferPaymentMetadata.V2(
            offerId = randomBytes32(),
            amount = 200_000_000.msat,
            preimage = preimage,
            payerKey = randomKey().publicKey(),
            payerNote = "hello there",
            quantity = 1,
            contactSecret = randomBytes32(),
            payerOffer = null,
            payerAddress = UnverifiedContactAddress(ContactAddress.fromString("alice@acinq.co")!!, randomKey().publicKey()),
            createdAtMillis = 0
        )
        assertEquals(metadata, OfferPaymentMetadata.decode(metadata.encode()))
        val pathId = metadata.toPathId(nodeKey)
        assertEquals(236, pathId.size())
        assertEquals(metadata, OfferPaymentMetadata.fromPathId(nodeKey, pathId, paymentHash))
    }

    @Test
    fun `decode invalid path_id`() {
        val nodeKey = randomKey()
        val preimage = randomBytes32()
        val paymentHash = Crypto.sha256(preimage).byteVector32()
        val metadataV1 = OfferPaymentMetadata.V1(
            offerId = randomBytes32(),
            amount = 50_000_000.msat,
            preimage = preimage,
            payerKey = randomKey().publicKey(),
            payerNote = null,
            quantity = 1,
            createdAtMillis = 0
        )
        val metadataV2 = OfferPaymentMetadata.V2(
            offerId = randomBytes32(),
            amount = 50_000_000.msat,
            preimage = preimage,
            payerKey = randomKey().publicKey(),
            payerNote = null,
            quantity = 1,
            contactSecret = randomBytes32(),
            payerOffer = null,
            payerAddress = null,
            createdAtMillis = 0
        )
        val testCases = listOf(
            ByteVector.empty,
            ByteVector("02deadbeef"), // invalid version
            metadataV1.toPathId(nodeKey).dropRight(1), // not enough bytes
            metadataV1.toPathId(nodeKey).concat(ByteVector("deadbeef")), // too many bytes
            metadataV1.toPathId(randomKey()), // signed with different key
            metadataV2.toPathId(nodeKey).drop(1), // missing bytes at the start
            metadataV2.toPathId(nodeKey).dropRight(1), // missing bytes at the end
            metadataV2.toPathId(nodeKey).let { it.update(13, it[13].xor(0xff.toByte())) }, // modified bytes
            metadataV2.toPathId(nodeKey).concat(ByteVector("deadbeef")), // additional bytes
            metadataV2.toPathId(randomKey()), // encrypted with different key
        )
        testCases.forEach {
            assertNull(OfferPaymentMetadata.fromPathId(nodeKey, it, paymentHash))
        }
    }

}