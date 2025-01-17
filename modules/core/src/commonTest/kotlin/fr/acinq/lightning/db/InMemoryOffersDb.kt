package fr.acinq.lightning.db

import fr.acinq.bitcoin.PrivateKey
import fr.acinq.lightning.wire.OfferTypes

class InMemoryOffersDb: OffersDb {
    private val offers = HashMap<PrivateKey, OfferTypes.Offer>()
    
    override suspend fun addOffer(offer: OfferTypes.Offer, secret: PrivateKey) {
        offers.put(secret, offer)
    }

    override suspend fun listOffers(): List<Pair<PrivateKey, OfferTypes.Offer>> {
        return offers.toList()
    }

    override suspend fun revokingOffer(secret: PrivateKey) {
        offers.remove(secret)
    }
}