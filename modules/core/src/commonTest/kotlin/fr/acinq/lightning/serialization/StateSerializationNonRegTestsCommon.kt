package fr.acinq.lightning.serialization

import fr.acinq.lightning.json.JsonSerializers
import fr.acinq.lightning.utils.value
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.encodeToString
import org.kodein.memory.file.*
import org.kodein.memory.system.Environment
import org.kodein.memory.text.readString
import org.kodein.memory.text.writeString
import kotlin.test.Test
import kotlin.test.assertEquals

class StateSerializationNonRegTestsCommon {

    /**
     * If test doesn't pass, set debug to `true`, run the test again and look for the `actual.json` file next to `data.json` in the resources. Then just
     * compare the two json files (easy within IntelliJ) and see what the difference is.
     */
    fun regtest(dir: String, debug: Boolean) {
        Path(Environment.findVariable("TEST_RESOURCES_PATH")!!)
            .resolve("nonreg", dir)
            .listDir() // list all test cases
            .forEach { path ->
                val bin = path.resolve("data.bin").openReadableFile().run { readString(sizeBytes = remaining) }
                val ref = path.resolve("data.json").openReadableFile().run { readString(sizeBytes = remaining) }
                val state = Serialization.deserialize(Hex.decode(bin)).value
                val json = JsonSerializers.json.encodeToString(state)
                val tmpFile = path.resolve("actual.json")
                if (debug) {
                    tmpFile.openWriteableFile().run {
                        writeString(json)
                        close()
                    }
                }
                // deserialized data must match static json reference file
                assertEquals(ref, json, path.toString())
                if (debug) {
                    tmpFile.delete()
                }
                // we also make sure that serialization round-trip is identity
                assertEquals(state, Serialization.deserialize(Serialization.serialize(state)).value, path.toString())
            }
    }

    @Test
    fun `non-reg test with v4 serialization`() {
        regtest("v4", debug = false)
    }
}