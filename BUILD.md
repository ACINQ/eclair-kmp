# Building

lightning-kmp is a [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library.
It can run on many different platforms, including mobile devices (iOS and Android).

## Requirements

On all platforms:

- [Docker](https://www.docker.com/) 18.03 or newer is required if you want to run all tests

For iOS, you need to have [Xcode](https://developer.apple.com/xcode/) and [Homebrew](https://brew.sh/) installed, and then:

```sh
brew install libtool
brew install gmp
```

Our tests use the ktor-client which [depends on libcurl](https://ktor.io/docs/client-engines.html#curl). On Linux, you need to install the `libcurl4-gnutls-dev` package:

```sh
sudo apt-get install libcurl4-gnutls-dev
```

## Build

You should start by cloning the repository locally:

```sh
git clone git@github.com:ACINQ/lightning-kmp.git
cd lightning-kmp
```

To build the project library and install it locally, you can run:

```sh
./gradlew build
./gradlew publishToMavenLocal
```

To run all tests on all platforms:

```sh
./gradlew allTests
```

To run tests on a single platform, for example the JVM:

```sh
./gradlew jvmTest
```
