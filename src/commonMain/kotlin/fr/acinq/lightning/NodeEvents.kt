package fr.acinq.lightning

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Satoshi
import fr.acinq.lightning.channel.WaitForFundingConfirmed
import fr.acinq.lightning.channel.WaitForFundingCreated
import fr.acinq.lightning.wire.PleaseOpenChannel
import fr.acinq.lightning.wire.PleaseOpenChannelFailure

sealed interface NodeEvents

sealed interface SwapInEvents : NodeEvents {
    data class Requested(val req: PleaseOpenChannel) : SwapInEvents
    data class Accepted(val requestId: ByteVector32, val fundingFee: Satoshi, val serviceFee: MilliSatoshi) : SwapInEvents
    data class Rejected(val requestId: ByteVector32, val failure: PleaseOpenChannelFailure, val requiredFees: MilliSatoshi?) : SwapInEvents
}

sealed interface ChannelEvents : NodeEvents {
    data class Creating(val state: WaitForFundingCreated) : ChannelEvents
    data class Created(val state: WaitForFundingConfirmed) : ChannelEvents
}
