package tr.com.srp.vpn

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlin.concurrent.thread
import kotlin.math.roundToInt

/** What the home screen shows, kept for the whole process so that it survives screen rotation. */
object AppModel {
    const val PULL_TITLE = "Pull to ping every profile"
    private const val TESTING = "Testing…"
    private const val SAVED_LATENCY = "SRPProfileLatency"

    private lateinit var context: Context
    private lateinit var store: ProfileStore
    private val main = Handler(Looper.getMainLooper())
    private val allPinger = TcpPinger()
    private val singlePinger = TcpPinger()

    val profiles = mutableStateListOf<Profile>()
    var selectedId by mutableStateOf<String?>(null)
    val latencyText = mutableStateMapOf<String, String>()
    /** Milliseconds behind each finished result (-1 = failed); absent while a test runs. */
    val latencyMs = mutableStateMapOf<String, Int>()
    var pullTitle by mutableStateOf(PULL_TITLE)
    var pinging by mutableStateOf(false)
    /** An upload or download of the country database is running; it outlives the screen that started it. */
    var geoIpUpdating by mutableStateOf(false)
    private var singlePingId: String? = null
    private var connectedPingId: String? = null
    private var connectedPingRun = 0

    val selected get() = profiles.firstOrNull { it.nodeId == selectedId }

    fun attach(applicationContext: Context) {
        if (::context.isInitialized) return
        context = applicationContext
        store = ProfileStore(context)
        profiles.addAll(store.load())
        loadSavedLatency()
    }

    fun put(profile: Profile) {
        val index = profiles.indexOfFirst { it.nodeId == profile.nodeId }
        if (index >= 0) profiles[index] = profile else profiles.add(profile)
        save()
    }

    fun delete(profile: Profile) {
        store.deleteSecrets(profile)
        profiles.removeAll { it.nodeId == profile.nodeId }
        if (selectedId == profile.nodeId) selectedId = null
        save()
        saveLatency() // drops the deleted profile's result
    }

    private fun save() {
        store.save(profiles)
        // The save gives new profiles their secret references.
        val saved = store.load()
        profiles.clear()
        profiles.addAll(saved)
    }

    private fun loadSavedLatency() {
        val saved = context.getSharedPreferences(SAVED_LATENCY, Context.MODE_PRIVATE)
        for ((id, value) in saved.all) {
            val entry = Json.parseOrNull(value as? String) as? Map<*, *> ?: continue
            latencyText[id] = entry["text"] as? String ?: continue
            latencyMs[id] = (entry["ms"] as? Number)?.toInt() ?: continue
        }
    }

    /** Keeps the last finished result of each existing profile across launches. */
    private fun saveLatency() {
        val editor = context.getSharedPreferences(SAVED_LATENCY, Context.MODE_PRIVATE).edit().clear()
        for (profile in profiles) {
            val text = latencyText[profile.nodeId]
            val milliseconds = latencyMs[profile.nodeId]
            if (!text.isNullOrEmpty() && milliseconds != null) editor.putString(profile.nodeId, Json.write(mapOf("text" to text, "ms" to milliseconds.toLong())))
        }
        editor.apply()
    }

    private fun record(id: String, text: String, milliseconds: Int?) {
        latencyText[id] = text
        if (milliseconds == null) latencyMs.remove(id) else latencyMs[id] = milliseconds
    }

    /** A cancelled test leaves no result rather than a stale "Testing…". */
    private fun clearUnfinished(ids: List<String>) {
        for (id in ids) if (latencyMs[id] == null && latencyText[id] == TESTING) latencyText.remove(id)
    }

    private fun connectedProfile(): Profile? {
        if (VpnState.status.value != VpnState.Status.Connected) return null
        return profiles.firstOrNull { it.nodeId == VpnState.connectedProfileId } ?: selected
    }

    /** Pings every profile; the toast text comes back when none has a TCP server to ping. */
    fun pingAll(toast: (String) -> Unit) {
        val connected = connectedProfile()
        val targets = profiles.filter { it.nodeId != connected?.nodeId && TcpPinger.endpoint(it) != null }
        targets.forEach { record(it.nodeId, TESTING, null) }
        if (connected != null) measureConnected()
        if (targets.isEmpty()) {
            pinging = false
            if (connected == null) toast("None of these profiles has a TCP server to ping; connect to one to measure its delay")
            return
        }
        val ids = targets.map { it.nodeId }
        pinging = true
        allPinger.ping(targets, { id, milliseconds, timedOut ->
            record(id, TcpPinger.text(milliseconds, timedOut), milliseconds)
        }, { completed, total ->
            pullTitle = "Pinged $completed of $total"
        }, {
            clearUnfinished(ids)
            saveLatency()
            pinging = false
            pullTitle = PULL_TITLE
        })
    }

    fun pingProfile(profile: Profile, toast: (String) -> Unit) {
        if (connectedProfile()?.nodeId == profile.nodeId) {
            measureConnected()
            return
        }
        if (TcpPinger.endpoint(profile) == null) {
            toast("This profile has no TCP server to ping; connect to it to measure its delay")
            return
        }
        // A new test replaces the one still running, which leaves no result.
        singlePingId?.let { clearUnfinished(listOf(it)) }
        singlePingId = profile.nodeId
        record(profile.nodeId, TESTING, null)
        singlePinger.ping(listOf(profile), { id, milliseconds, timedOut ->
            record(id, TcpPinger.text(milliseconds, timedOut), milliseconds)
        }, { _, _ -> }, {
            clearUnfinished(listOf(profile.nodeId))
            saveLatency()
        })
    }

    /** Times a request through the tunnel; it runs by itself after connecting. */
    fun measureConnected() {
        val profile = connectedProfile() ?: return
        val client = VpnState.client ?: return
        record(profile.nodeId, TESTING, null)
        val run = ++connectedPingRun
        connectedPingId = profile.nodeId
        client.measurePing { milliseconds ->
            main.post {
                if (run != connectedPingRun) return@post
                connectedPingId = null
                // The connection ended during the test, which says nothing about its delay.
                if (VpnState.status.value != VpnState.Status.Connected) {
                    clearUnfinished(listOf(profile.nodeId))
                    return@post
                }
                when {
                    milliseconds >= 0 -> record(profile.nodeId, "Ping: ${milliseconds.toDouble().roundToInt()} ms", milliseconds.toInt())
                    milliseconds == -2L -> record(profile.nodeId, "Timeout", -1)
                    else -> record(profile.nodeId, "Failed", -1)
                }
                saveLatency()
            }
        }
    }

    /** The connection ended: a test still running leaves no result. */
    fun cancelConnectedPing() {
        connectedPingRun++
        connectedPingId?.let { clearUnfinished(listOf(it)) }
        connectedPingId = null
    }

    /** Runs an upload or download of the country database. [finished] gets the reason it failed, or null. */
    fun updateGeoIp(work: () -> Unit, finished: (String?) -> Unit) {
        geoIpUpdating = true
        thread(name = "geoip-update") {
            val failure = try {
                work()
                null
            } catch (error: Exception) {
                error.message ?: "The file could not be read."
            }
            main.post {
                geoIpUpdating = false
                finished(failure)
            }
        }
    }
}
