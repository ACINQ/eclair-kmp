package fr.acinq.lightning.serialization

import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.lightning.channel.PersistedChannelState
import fr.acinq.lightning.serialization.v4.Deserialization.fromBinV4
import fr.acinq.lightning.serialization.v4.Serialization.toBinV4

object Serialization {

    fun serialize(state: PersistedChannelState): ByteArray {
        return state.toBinV4()
    }

    fun deserialize(bin: ByteArray): PersistedChannelState {
        return when {
            // v4 uses a 1-byte version discriminator
            bin[0].toInt() == 4 -> bin.fromBinV4()
            // v2/v3 use a 4-bytes version discriminator
            Pack.int32BE(bin) == 3 -> fr.acinq.lightning.serialization.v3.Serialization.deserialize(bin)
            Pack.int32BE(bin) == 2  -> fr.acinq.lightning.serialization.v2.Serialization.deserialize(bin)
            else -> error("unknown serialization version")
        }
    }

}