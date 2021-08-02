package fr.acinq.lightning.utils

import kotlin.random.Random

// https://github.com/Kotlin/KEEP/issues/184
expect fun Random.Default.secure(): Random

/**
 * This function should return some entropy based on application-specific runtime data.
 * It doesn't need to be very strong entropy as it's only used as a backup, but it should be as good as possible.
 */
expect fun runtimeEntropy(): ByteArray