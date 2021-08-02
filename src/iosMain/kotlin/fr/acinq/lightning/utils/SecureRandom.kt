package fr.acinq.lightning.utils

import swift.phoenix_crypto.*
import kotlinx.cinterop.autoreleasepool

actual fun runtimeEntropy(): ByteArray {
    autoreleasepool {
        val result = NativeWeakRandom.sample()
        return result.toByteArray()
    }
}