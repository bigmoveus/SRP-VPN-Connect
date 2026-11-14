package tr.com.srp.vpn

import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.lang.reflect.Proxy

/** The Aether profiles ProfileStore keeps: Private mode (the user's own server) is gone, and a stored profile of it leaves at load. */
class AetherProfileTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val private = """{"type": "aether", "node_id": "PRIVATE", "ae_mode": "private", "address": "vpn.example.com", "port": "51820",
        "wg_address": "10.66.66.3/32", "wg_secret_ref": "wg-keys", "ae_license_ref": "license"}"""
    private val public = """{"type": "aether", "node_id": "PUBLIC", "ae_mode": "public", "ae_transport": "masque-both", "ae_tor": "only",
        "wg_secret_ref": "kept-keys"}"""
    private val deleted = ArrayList<Any?>()

    /** What ProfileStore.load() makes of a stored list; the SecretStore's preferences run on the JVM: no secret is stored, and the
     *  names deleted are recorded in [deleted] */
    private fun load(vararg items: String): Pair<List<Profile>, String> {
        val file = File(folder.root, "profiles.json")
        file.writeText(items.joinToString(",", "[", "]"))
        val types = arrayOf(SharedPreferences::class.java, SharedPreferences.Editor::class.java)
        val preferences = Proxy.newProxyInstance(javaClass.classLoader, types) { proxy, method, arguments ->
            if (method.name == "remove") deleted.add(arguments[0])
            if (method.name == "edit" || method.name == "remove") proxy else null
        } as SharedPreferences
        val context = object : ContextWrapper(null) {
            override fun getFilesDir() = folder.root
            override fun getSharedPreferences(name: String?, mode: Int) = preferences
        }
        return ProfileStore(context).load() to file.readText()
    }

    @Test
    fun dropsAStoredPrivateModeProfileAtLoad() {
        val (profiles, saved) = load(private, public)

        assertEquals(listOf("PUBLIC"), profiles.map { it.nodeId })
        assertEquals("masque-both" to "only", profiles[0].aetherTransport to profiles[0].aetherTor)
        // The Private profile's secrets went as when the user deletes a profile; the save took the keys the other one had kept from that mode
        assertEquals(listOf("wg-keys", "license", "kept-keys"), deleted)
        assertFalse(saved, "PRIVATE" in saved || "ae_mode" in saved || "wg_" in saved)
    }

    @Test
    fun aProfileOfAnOlderBuildLosesTheKeysItKeptFromPrivateMode() {
        val (profiles, saved) = load(public)

        assertEquals(listOf("PUBLIC"), profiles.map { it.nodeId })
        assertEquals(listOf<Any?>("kept-keys"), deleted)
        assertFalse(saved, "ae_mode" in saved || "wg_" in saved)
    }
}
