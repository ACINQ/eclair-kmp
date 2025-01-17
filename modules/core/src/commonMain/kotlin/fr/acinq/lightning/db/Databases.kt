package fr.acinq.lightning.db

interface Databases {
    val channels: ChannelsDb
    val payments: PaymentsDb
    val offers: OffersDb
}