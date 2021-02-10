package fr.acinq.eclair.io

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.darwin.*
import platform.posix.memcpy


@OptIn(ExperimentalUnsignedTypes::class)
internal fun dispatch_data_t.copyTo(buffer: ByteArray, offset: Int) {
    buffer.usePinned { pinned ->
        dispatch_data_apply(this) { _, dataOffset, src, size ->
            memcpy(pinned.addressOf(offset + dataOffset.toInt()), src, size)
            true
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
internal inline fun <R> ByteArray.useDataView(offset: Int, length: Int, block: (dispatch_data_t) -> R): R {
    usePinned { pinned ->
        val data = pinned.let { dispatch_data_create(pinned.addressOf(offset), length.toULong(), dispatch_get_main_queue(), ({})) }
        return block(data)
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
internal fun dispatch_data_t.size(): Int = dispatch_data_get_size(this).toInt()
