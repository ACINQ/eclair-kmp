import org.jetbrains.kotlin.gradle.plugin.mpp.DefaultCInteropSettings
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest

plugins {
    alias(libs.plugins.multiplatform)
    alias(libs.plugins.serialization)
    alias(libs.plugins.dokka)
    `maven-publish`
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()

kotlin {
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
    }

    linuxX64()

    if (currentOs.isMacOsX) {
        macosX64()

        macosArm64()

        fun DefaultCInteropSettings.configureFor(platform: String) {
            val interopTask = tasks[interopProcessingTaskName]
            interopTask.dependsOn(":lightning-kmp-ios-crypto:buildCrypto$platform")
            val libPath = "$rootDir/modules/ios-crypto/build/Release-${platform.lowercase()}"
            extraOpts("-libraryPath", libPath)
            includeDirs.headerFilterOnly("$libPath/include")
        }

        iosX64 { // ios simulator on intel devices
            compilations["main"].cinterops.create("PhoenixCrypto") {
                configureFor("Iphonesimulator")
            }
        }

        iosArm64 { // actual ios devices
            compilations["main"].cinterops.create("PhoenixCrypto") {
                configureFor("Iphoneos")
            }
        }

        iosSimulatorArm64 { // actual ios devices
            compilations["main"].cinterops.create("PhoenixCrypto") {
                configureFor("Iphonesimulator")
            }
        }
    }

    sourceSets {
        commonMain {
            dependencies {
                api("fr.acinq.bitcoin:bitcoin-kmp:${libs.versions.bitcoinkmp.get()}")
                api("org.jetbrains.kotlinx:kotlinx-coroutines-core:${libs.versions.kotlinx.coroutines.get()}")
                api("org.jetbrains.kotlinx:kotlinx-serialization-core:${libs.versions.kotlinx.serialization.get()}")
                api("org.jetbrains.kotlinx:kotlinx-serialization-cbor:${libs.versions.kotlinx.serialization.get()}")
                api("org.jetbrains.kotlinx:kotlinx-serialization-json:${libs.versions.kotlinx.serialization.get()}")
                api("org.jetbrains.kotlinx:kotlinx-datetime:${libs.versions.kotlinx.datetime.get()}")
                api("co.touchlab:kermit:${libs.versions.kermit.get()}")
                api("io.ktor:ktor-network:${libs.versions.ktor.get()}")
                api("io.ktor:ktor-network-tls:${libs.versions.ktor.get()}")
                api("io.ktor:ktor-client-core:${libs.versions.ktor.get()}")
                api("io.ktor:ktor-client-auth:${libs.versions.ktor.get()}")
                api("io.ktor:ktor-client-json:${libs.versions.ktor.get()}")
                api("io.ktor:ktor-client-content-negotiation:${libs.versions.ktor.get()}")
                api("io.ktor:ktor-serialization-kotlinx-json:${libs.versions.ktor.get()}")
            }
        }

        commonTest {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
                implementation("org.kodein.memory:klio-files:${libs.versions.test.kodein.memory.get()}")
            }
        }

        jvmMain {
            dependencies {
                api("io.ktor:ktor-client-okhttp:${libs.versions.ktor.get()}")
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:${libs.versions.secpjnijvm.get()}")
                implementation("org.slf4j:slf4j-api:${libs.versions.slf4j.get()}")
            }
        }

        jvmTest {
            dependencies {
                implementation(kotlin("test-junit"))
                implementation("org.bouncycastle:bcprov-jdk15on:${libs.versions.test.bouncycastle.get()}")
                implementation("ch.qos.logback:logback-classic:${libs.versions.test.logback.get()}")
                implementation("org.xerial:sqlite-jdbc:${libs.versions.test.sqlitejdbc.get()}")
            }
        }

        if (currentOs.isMacOsX) {
            iosMain {
                dependencies {
                    api("io.ktor:ktor-client-ios:${libs.versions.ktor.get()}")
                }
            }
            macosMain {
                dependencies {
                    api("io.ktor:ktor-client-darwin:${libs.versions.ktor.get()}")
                }
            }
        }

        linuxMain {
            dependencies {
                api("io.ktor:ktor-client-curl:${libs.versions.ktor.get()}")
            }
        }

        all {
            languageSettings.optIn("kotlin.RequiresOptIn")
            languageSettings.optIn("kotlin.ExperimentalStdlibApi")
        }
    }

    configurations.all {
        // do not cache changing (i.e. SNAPSHOT) dependencies
        resolutionStrategy.cacheChangingModulesFor(0, TimeUnit.SECONDS)
    }

    targets.all {
        compilations.all {
            kotlinOptions {
                allWarningsAsErrors = true
                // We use expect/actual for classes (see Chacha20Poly1305CipherFunctions). This feature is in beta and raises a warning.
                // See https://youtrack.jetbrains.com/issue/KT-61573
                kotlinOptions.freeCompilerArgs += "-Xexpect-actual-classes"
            }
        }
    }
}

val dokkaOutputDir = layout.buildDirectory.dir("dokka")
tasks.dokkaHtml {
    outputDirectory.set(file(dokkaOutputDir))
    dokkaSourceSets {
        configureEach {
            val platformName = platform.get().name
            displayName.set(platformName)

            perPackageOption {
                matchingRegex.set(".*\\.internal.*") // will match all .internal packages and sub-packages
                suppress.set(true)
            }
        }
    }
}

val deleteDokkaOutputDir by tasks.register<Delete>("deleteDokkaOutputDirectory") {
    delete(dokkaOutputDir)
}

val javadocJar = tasks.create<Jar>("javadocJar") {
    archiveClassifier.set("javadoc")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    dependsOn(deleteDokkaOutputDir, tasks.dokkaHtml)
    from(dokkaOutputDir)
}

publishing {
    publications.withType<MavenPublication>().configureEach {
        version = project.version.toString()
        artifact(javadocJar)
        pom {
            name.set("Kotlin Multiplatform Lightning Network Engine")
            description.set("A Kotlin Multiplatform implementation of the Lightning Network")
            url.set("https://github.com/ACINQ/lightning-kmp")
            licenses {
                license {
                    name.set("Apache License v2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0")
                }
            }
            issueManagement {
                system.set("Github")
                url.set("https://github.com/ACINQ/lightning-kmp/issues")
            }
            scm {
                connection.set("https://github.com/ACINQ/lightning-kmp.git")
                url.set("https://github.com/ACINQ/lightning-kmp")
            }
            developers {
                developer {
                    name.set("ACINQ")
                    email.set("hello@acinq.co")
                }
            }
        }
    }

    repositories {
        mavenLocal()
    }
}

// Disable cross compilation
afterEvaluate {
    val targets = when {
        currentOs.isLinux -> listOf()
        else -> listOf("linuxX64")
    }.mapNotNull { kotlin.targets.findByName(it) as? KotlinNativeTarget }

    configure(targets) {
        compilations.all {
            cinterops.all { tasks[interopProcessingTaskName].enabled = false }
            compileTaskProvider.get().enabled = false
            tasks[processResourcesTaskName].enabled = false
        }
        binaries.all { linkTask.enabled = false }

        mavenPublication {
            val publicationToDisable = this
            tasks.withType<AbstractPublishToMaven>().all { onlyIf { publication != publicationToDisable } }
            tasks.withType<GenerateModuleMetadata>().all { onlyIf { publication.get() != publicationToDisable } }
        }
    }
}

afterEvaluate {
    tasks.withType<AbstractTestTask> {
        val verboseTests = project.findProperty("verboseTests") == "ON"
        testLogging {
            showExceptions = true
            showStackTraces = true
            if (verboseTests) {
                events("passed", "skipped", "failed")
                showStandardStreams = true
            } else {
                events("skipped", "failed")
            }
            afterSuite(KotlinClosure2({ desc: TestDescriptor, result: TestResult ->
                if (desc.parent == null && result.failedTestCount == 0L) {
                    println("${result.testCount} tests completed: ${result.successfulTestCount} passed, ${result.failedTestCount} failed, ${result.skippedTestCount} skipped")
                }
            }))
        }
    }
    tasks.withType<org.jetbrains.kotlin.gradle.targets.jvm.tasks.KotlinJvmTest> {
        environment("TEST_RESOURCES_PATH", projectDir.resolve("src/commonTest/resources"))
    }

    tasks.withType<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeHostTest> {
        environment("TEST_RESOURCES_PATH", projectDir.resolve("src/commonTest/resources"))
    }

    tasks.withType<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest> {
        environment("SIMCTL_CHILD_TEST_RESOURCES_PATH", projectDir.resolve("src/commonTest/resources"))
    }
}

/** Electrum integration test environment + tasks configuration */
val dockerTestEnv by tasks.creating(Exec::class) {
    workingDir = rootDir.resolve("testing")
    commandLine("bash", "env.sh", "remove", "net-create", "btc-create", "elx-create", "btc-start", "elx-start")
}

val dockerCleanup by tasks.creating(Exec::class) {
    workingDir = rootDir.resolve("testing")
    commandLine("bash", "env.sh", "elx-stop", "btc-stop", "remove")
}

val includeIntegrationTests = project.findProperty("integrationTests") == "include"
tasks.withType<AbstractTestTask> {
    if (includeIntegrationTests) {
        dependsOn(dockerTestEnv)
        finalizedBy(dockerCleanup)
    } else {
        filter.excludeTestsMatching("*IntegrationTest")
    }
}

// Those tests use TLS sockets which are not supported on Linux and MacOS
tasks
    .filterIsInstance<KotlinNativeTest>()
    .filter { it.name == "macosX64Test" || it.name == "macosArm64Test" || it.name == "linuxX64Test" }
    .map {
        it.filter.excludeTestsMatching("*IntegrationTest")
        it.filter.excludeTestsMatching("*ElectrumClientTest")
        it.filter.excludeTestsMatching("*ElectrumMiniWalletTest")
        it.filter.excludeTestsMatching("*SwapInWalletTestsCommon")
    }

// Those tests do not work with the ios simulator
tasks
    .filterIsInstance<KotlinNativeSimulatorTest>()
    .map {
        it.filter.excludeTestsMatching("*MempoolSpace*Test")
    }

// Make NS_FORMAT_ARGUMENT(1) a no-op
// This fixes an issue when building PhoenixCrypto using XCode 13
// More on this: https://youtrack.jetbrains.com/issue/KT-48807#focus=Comments-27-5210791.0-0
tasks.withType(org.jetbrains.kotlin.gradle.tasks.CInteropProcess::class.java) {
    settings.compilerOpts("-DNS_FORMAT_ARGUMENT(A)=")
}
