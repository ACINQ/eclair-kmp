package fr.acinq.lightning.utils

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.pin
import kotlinx.cinterop.usePinned
import platform.Foundation.create
import platform.Foundation.NSData
import platform.posix.memcpy

fun NSData.toByteArray(): ByteArray {
    val data = this
    return ByteArray(data.length.toInt()).apply {
        if (data.length > 0uL) {
            usePinned { pinned ->
                memcpy(pinned.addressOf(0), data.bytes, data.length)
            }
        }
    }
}

fun ByteArray.toNSData(): NSData {
    if (isEmpty()) return NSData()
    val pinned = pin()
    return NSData.create(
        bytesNoCopy = pinned.addressOf(0),
        length = size.toULong(),
        deallocator = { _, _ -> pinned.unpin() }
    )
}