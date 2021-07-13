package fr.acinq.lightning.utils

sealed class Try<T> {
    abstract val isSuccess: Boolean
    val isFailure: Boolean get() = !isSuccess
    abstract fun get(): T
    abstract fun getOrElse(f: () -> T): T
    abstract fun recoverWith(f: () -> Try<T>): Try<T>
    abstract fun <R> map(f: (T) -> R): Try<R>

    data class Success<T>(val result: T) : Try<T>() {
        override val isSuccess: Boolean = true
        override fun get(): T = result
        override fun getOrElse(f: () -> T): T = result
        override fun recoverWith(f: () -> Try<T>): Try<T> = this
        override fun <R> map(f: (T) -> R): Try<R> = runTrying { f(result) }
    }

    data class Failure<T>(val error: Throwable) : Try<T>() {
        override val isSuccess: Boolean = false
        override fun get(): T = throw error
        override fun getOrElse(f: () -> T): T = f()
        override fun recoverWith(f: () -> Try<T>): Try<T> = f()

        @Suppress("UNCHECKED_CAST")
        override fun <R> map(f: (T) -> R): Try<R> = this as Try<R>
    }

    companion object {
        operator fun <T> invoke(block: () -> T): Try<T> = runTrying(block)
    }
}

inline fun <R> runTrying(block: () -> R): Try<R> =
    try {
        Try.Success(block())
    } catch (e: Throwable) {
        Try.Failure(e)
    }

inline fun <T, R> T.runTrying(block: T.() -> R): Try<R> =
    try {
        Try.Success(block())
    } catch (e: Throwable) {
        Try.Failure(e)
    }
