package fr.acinq.lightning.utils

import fr.acinq.lightning.channel.fsm.PersistedChannelState
import fr.acinq.lightning.serialization.Serialization

val Serialization.DeserializationResult.value: PersistedChannelState
    get() = (this as Serialization.DeserializationResult.Success).state