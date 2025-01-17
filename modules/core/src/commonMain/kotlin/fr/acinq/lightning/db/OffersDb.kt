package fr.acinq.lightning.db

import fr.acinq.bitcoin.PrivateKey
import fr.acinq.lightning.wire.OfferTypes

/**
 * This interface is used to store the offers created by the user.
 *
 * An implementor of this interface should keep in mind that an
 * offer could be reconstructed using the `secret`, amount and/or
 * description.
 */
interface OffersDb {
    /* Add a new offer just created by the user */
    suspend fun addOffer(offer: OfferTypes.Offer, secret: PrivateKey)

    /* List all the offers stored in the db and the secret */
    suspend fun listOffers(): List<Pair<PrivateKey, OfferTypes.Offer>>

    /* Revoke an offer by a given secret */
    suspend fun revokingOffer(secret: PrivateKey)
}