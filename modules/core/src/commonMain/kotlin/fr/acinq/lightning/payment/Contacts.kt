package fr.acinq.lightning.payment

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.byteVector32
import fr.acinq.lightning.wire.OfferTypes
import io.ktor.utils.io.core.*

/**
 * BIP 353 human-readable address of a contact.
 */
data class ContactAddress(val name: String, val domain: String) {
    init {
        require(name.length < 256) { "bip353 name must be smaller than 256 characters" }
        require(domain.length < 256) { "bip353 domain must be smaller than 256 characters" }
    }

    override fun toString(): String = "$name@$domain"

    companion object {
        fun fromString(address: String): ContactAddress? {
            val parts = address.replace("₿", "").split('@')
            return when {
                parts.size != 2 -> null
                parts.any { it.length > 255 } -> null
                else -> ContactAddress(parts.first(), parts.last())
            }
        }
    }
}

/**
 * Contact secrets are used to mutually authenticate payments.
 *
 * The first node to add the other to its contacts list will generate the [primarySecret] and send it when paying.
 * If the second node adds the first node to its contacts list from the received payment, it will use the same
 * [primarySecret] and both nodes are able to identify payments from each other.
 *
 * But if the second node independently added the first node to its contacts list, it may have generated a
 * different [primarySecret]. Each node has a different [primarySecret], but they will store the other node's
 * [primarySecret] in their [additionalRemoteSecrets], which lets them correctly identify payments.
 *
 * When sending a payment, we must always send the [primarySecret].
 * When receiving payments, we must check if the received contact_secret matches either the [primarySecret]
 * or any of the [additionalRemoteSecrets].
 */
data class ContactSecrets(val primarySecret: ByteVector32, val additionalRemoteSecrets: Set<ByteVector32>) {
    /**
     * This function should be used when we attribute an incoming payment to an existing contact.
     * This can be necessary when:
     *  - our contact added us without using the contact_secret we initially sent them
     *  - our contact is using a different wallet from the one(s) we have already stored
     */
    fun addRemoteSecret(remoteSecret: ByteVector32): ContactSecrets {
        return this.copy(additionalRemoteSecrets = additionalRemoteSecrets + remoteSecret)
    }
}

/**
 * Contacts are trusted people to which we may want to reveal our identity when paying them.
 * We're also able to figure out when incoming payments have been made by one of our contacts.
 * See [bLIP 42](https://github.com/lightning/blips/blob/master/blip-0042.md) for more details.
 */
object Contacts {

    /**
     * We derive our contact secret deterministically based on our offer and our contact's offer.
     * This provides a few interesting properties:
     *  - if we remove a contact and re-add it using the same offer, we will generate the same contact secret
     *  - if our contact is using the same deterministic algorithm with a single static offer, they will also generate the same contact secret
     *
     * Note that this function must only be used when adding a contact that hasn't paid us before.
     * If we're adding a contact that paid us before, we must use the contact_secret they sent us,
     * which ensures that when we pay them, they'll be able to know it was coming from us (see
     * [fromRemoteSecret]).
     */
    fun computeContactSecret(ourOffer: OfferTypes.OfferAndKey, theirOffer: OfferTypes.Offer): ContactSecrets {
        // If their offer doesn't contain an issuerId, it must contain blinded paths.
        val offerNodeId = theirOffer.issuerId ?: theirOffer.paths?.first()?.nodeId!!
        val ecdh = offerNodeId.times(ourOffer.privateKey)
        val primarySecret = Crypto.sha256("blip42_contact_secret".toByteArray() + ecdh.value.toByteArray()).byteVector32()
        return ContactSecrets(primarySecret, setOf())
    }

    /**
     * When adding a contact from which we've received a payment, we must use the contact_secret
     * they sent us: this ensures that they'll be able to identify payments coming from us.
     */
    fun fromRemoteSecret(remoteSecret: ByteVector32): ContactSecrets = ContactSecrets(remoteSecret, setOf())

}