package tr.com.srp.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import java.net.Inet4Address
import java.net.InetAddress
import kotlin.random.Random

/** wireguard-go and amneziawg-go (the iOS app's versions) with their JNI layer and the Ping probe (go/wireguard), in libwg-go.so. */
internal object WireGuardNative {
    init {
        System.loadLibrary("wg-go")
    }

    /** wireguard-go on a duplicate of the TUN descriptor with these UAPI settings: a handle, or -1. */
    @JvmStatic external fun turnOn(settings: String, tunFd: Int): Int
    /** amneziawg-go the same way; the calls below serve both engines. */
    @JvmStatic external fun turnOnAmnezia(settings: String, tunFd: Int): Int
    /** Why the last start failed, in the engine's words, or null. */
    @JvmStatic external fun lastError(): String?
    @JvmStatic external fun turnOff(handle: Int)
    @JvmStatic external fun setConfig(handle: Int, settings: String): Long
    /** The UAPI get text; it holds the private key, so it is parsed and never logged. */
    @JvmStatic external fun getConfig(handle: Int): String?
    @JvmStatic external fun bumpSockets(handle: Int)
    @JvmStatic external fun setVerbose(on: Boolean)
    /** "E " (error) or "V " (verbose) and a line of the engine's log, or null after the timeout. */
    @JvmStatic external fun nextLog(timeoutMs: Int): String?
    /** Triples of protocol, IPv4 address and local port whose packets come to [nextProbe] instead of the TUN. */
    @JvmStatic external fun setProbeFlows(handle: Int, flows: IntArray)
    @JvmStatic external fun submit(handle: Int, packet: ByteArray)
    @JvmStatic external fun nextProbe(handle: Int, timeoutMs: Int): ByteArray?

    // shortcut: unused since Aether's Private mode went; remove with the next rebuild of the Go runtime
    @JvmStatic external fun netstackStart(uapi: String, ifAddr: String, listen: String, target: String): Int
    @JvmStatic external fun netstackStop(handle: Int)
}

/** A wg-quick configuration, read as SRPWireGuardClient.m reads it (with AmneziaWG's settings, which WireGuard itself refuses). */
internal data class WireGuardConf(
    val privateKey: String,
    val addresses: List<String>,
    val dns: List<String>,
    val mtu: Int,
    val peerPublicKey: String,
    val presharedKey: String,
    val endpointHost: String,
    val endpointPort: Int,
    val allowedIps: List<String>,
    val keepalive: Int,
    /** PersistentKeepalive as AmneziaWG's engine takes it: "25", or a range such as "20-30" ([keepalive] is its low end) */
    val keepaliveSpec: String = keepalive.toString(),
    /** AmneziaWG's device settings in the engine's form (jc=4, h1=…, header_protection_key=<hex>, …) */
    val amneziaUapi: List<String> = emptyList(),
    /** The AmneziaWG settings of the file as written (Jc, S1, H1, …) */
    val amneziaKeys: List<String> = emptyList(),
    val s2: Int = 0,
    val s4: Int = 0,
    /** ContentPaddingAddition or RandomTrailers: a keepalive can grow to the largest packet sent */
    val padsKeepalives: Boolean = false,
    /** RandomTrailers on with a range in H1-H3 and no HeaderProtectionKey: the server's engine may drop some of the phone's packets */
    val trailersWithRanges: Boolean = false,
) {
    /** The engine's settings: the device (with AmneziaWG's for [amnezia]), then the peer as [peer] gives it. */
    fun uapi(endpointIp: String, keepalive: String = keepaliveSpec, amnezia: Boolean = false): String? {
        val private = base64ToHex(privateKey) ?: return null
        val device = if (amnezia) amneziaUapi.joinToString("") { "$it\n" } else ""
        return "private_key=$private\nlisten_port=0\n$device" + (peer(endpointIp, keepalive) ?: return null)
    }

    /** The peer afresh (replace_peers, without the session it had), with this persistent keepalive ("0" for none). */
    fun peer(endpointIp: String, keepalive: String): String? {
        val public = base64ToHex(peerPublicKey) ?: return null
        return buildString {
            append("replace_peers=true\npublic_key=$public\n")
            if (presharedKey.isNotEmpty()) append("preshared_key=${base64ToHex(presharedKey) ?: return null}\n")
            append("endpoint=${if (':' in endpointIp) "[$endpointIp]" else endpointIp}:$endpointPort\n")
            allowedIps.forEach { append("allowed_ip=$it\n") }
            if (keepalive != "0" && keepalive.isNotEmpty()) append("persistent_keepalive_interval=$keepalive\n")
        }
    }

    /**
     * The tunnel's MTU: the file's, else 1420; AmneziaWG adds S4 bytes to every data packet, so without an MTU in the file it
     * takes S4 off, and a full-size packet stays within a 1500-byte path as WireGuard's own does (SRPWGEffectiveMTU).
     */
    fun tunnelMtu(amnezia: Boolean) = if (mtu > 0) mtu else if (amnezia && s4 > 0) maxOf(1280, 1420 - s4) else 1420

    /**
     * Sent bytes that are more than keepalives, for the silence check (SRPWGSilenceBytes): WireGuard's keepalive is 32 bytes. AmneziaWG
     * pads every data packet with S4 bytes, and with content padding or random trailers a keepalive can grow to the largest packet
     * sent (S4 + 32 + MTU); the bound covers the keepalives a 30-second window can hold.
     */
    fun silenceBytes(amnezia: Boolean): Long {
        if (!amnezia) return 296
        var size = s4 + 32L
        if (padsKeepalives) size = maxOf(500L, s4 + 32L + tunnelMtu(true))
        val count = (if (keepalive > 0) 30 / keepalive + 1 else 0) + 2
        return maxOf(296L, count * size)
    }

    /** The VPN interface: the config's addresses, its AllowedIPs as routes, its DNS and MTU ([tunnelMtu]). */
    fun tunnelSettings(amnezia: Boolean = false): TunnelSettings {
        val v4 = addresses.firstOrNull { ProbePackets.ipv4(it.substringBefore('/')) != null } ?: addresses.first()
        val extra = addresses.filter { it != v4 }.map { it.substringBefore('/') to (it.substringAfter('/', "").toIntOrNull() ?: if (':' in it) 128 else 32) }
        val routes = allowedIps.map { it.substringBefore('/') to (it.substringAfter('/', "").toIntOrNull() ?: if (':' in it) 128 else 32) }
        return TunnelSettings(v4.substringBefore('/'), dns, routes.ifEmpty { listOf("0.0.0.0" to 0) }, tunnelMtu(amnezia),
            addressPrefix = v4.substringAfter('/', "").toIntOrNull() ?: 32, extraAddresses = extra)
    }

    companion object {
        /** The config, or why it is not one (in SRPWGParseConfig's words). */
        fun parse(text: String): Pair<WireGuardConf?, String?> {
            var section = ""
            var privateKey = ""
            var peerPublicKey = ""
            var presharedKey = ""
            var endpoint = ""
            var mtu = 0
            var keepalive = 0
            var keepaliveSpec = "0"
            val addresses = mutableListOf<String>()
            val dns = mutableListOf<String>()
            val allowed = mutableListOf<String>()
            val awgValues = mutableMapOf<String, String>()   // engine key -> value
            val awgKeys = mutableListOf<String>()
            for (raw in text.lines()) {
                val line = raw.substringBefore('#').substringBefore(';').trim()
                if (line.isEmpty()) continue
                if (line.startsWith("[") && ']' in line) {
                    section = line.substring(1, line.indexOf(']')).lowercase()
                    continue
                }
                if ('=' !in line) continue
                val key = line.substringBefore('=').trim().lowercase()
                val value = line.substringAfter('=').trim()
                fun list() = value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                when (section) {
                    "interface" -> {
                        AMNEZIA_NAMES[key]?.let { name ->
                            awgKeys += name
                            awgValue(key, name, value)?.let { (engineValue, problem) ->
                                if (problem != null) return null to problem
                                awgValues[key] = engineValue
                            }
                        }
                        when (key) {
                            "privatekey" -> privateKey = value
                            "address" -> addresses += list()
                            "dns" -> dns += list()
                            "mtu" -> mtu = value.toIntOrNull() ?: 0
                        }
                    }
                    "peer" -> when (key) {
                        "publickey" -> peerPublicKey = value
                        "presharedkey" -> presharedKey = value
                        "endpoint" -> endpoint = value
                        "allowedips" -> allowed += list()
                        "persistentkeepalive" -> {
                            // wg takes a number or "off"; the AmneziaWG engine also a range, picking a value in it each time
                            keepaliveSpec = if (value.lowercase() == "off") "0" else range(value, 65535, true)
                                ?: return null to "PersistentKeepalive must be a number of seconds (AmneziaWG also takes a range such as 20-30)."
                            keepalive = keepaliveSpec.substringBefore('-').toInt()
                            if ('-' in keepaliveSpec) awgKeys += "a PersistentKeepalive range"
                        }
                    }
                }
            }
            val (host, port) = endpointParts(endpoint)
            return when {
                privateKey.isEmpty() -> null to "The config has no [Interface] PrivateKey."
                peerPublicKey.isEmpty() -> null to "The config has no [Peer] PublicKey."
                host.isEmpty() || port <= 0 -> null to "The config has no valid [Peer] Endpoint."
                addresses.isEmpty() -> null to "The config has no [Interface] Address."
                else -> {
                    val h = listOf("h1", "h2", "h3").map { awgValues[it].orEmpty() }
                    WireGuardConf(privateKey, addresses, dns, mtu, peerPublicKey, presharedKey, host, port, allowed, keepalive, keepaliveSpec,
                        amneziaUapi = AMNEZIA_ORDER.mapNotNull { key -> awgValues[key]?.let { "${engineKey(key)}=$it" } },
                        amneziaKeys = awgKeys,
                        s2 = awgValues["s2"]?.toInt() ?: 0,
                        s4 = awgValues["s4"]?.toInt() ?: 0,
                        padsKeepalives = awgValues["contentpaddingaddition"] != null || awgValues["randomtrailers"] == "true",
                        trailersWithRanges = awgValues["randomtrailers"] == "true" && h.any { '-' in it } &&
                            awgValues["headerprotectionkey"].isNullOrEmpty()) to null
                }
            }
        }

        /** The AmneziaWG settings of an [Interface] (file key, lowercase -> the name as written in messages) */
        private val AMNEZIA_NAMES = linkedMapOf("jc" to "Jc", "jmin" to "Jmin", "jmax" to "Jmax", "s1" to "S1", "s2" to "S2", "s3" to "S3",
            "s4" to "S4", "h1" to "H1", "h2" to "H2", "h3" to "H3", "h4" to "H4", "i1" to "I1", "i2" to "I2", "i3" to "I3", "i4" to "I4",
            "i5" to "I5", "headerprotectionkey" to "HeaderProtectionKey", "contentpaddingaddition" to "ContentPaddingAddition",
            "rekeyaftertime" to "RekeyAfterTime", "rekeytimeout" to "RekeyTimeout", "rejectaftertime" to "RejectAfterTime",
            "keepalivetimeout" to "KeepaliveTimeout", "maxhandshakeattempts" to "MaxHandshakeAttempts", "randomtrailers" to "RandomTrailers",
            "disablecookies" to "DisableCookies")
        /** The order SRPWireGuardClient.m gives them to the engine */
        private val AMNEZIA_ORDER = AMNEZIA_NAMES.keys.toList()

        private fun engineKey(key: String) = when (key) {
            "headerprotectionkey" -> "header_protection_key"
            "contentpaddingaddition" -> "content_padding_addition"
            "rekeyaftertime" -> "rekey_after_time"
            "rekeytimeout" -> "rekey_timeout"
            "rejectaftertime" -> "reject_after_time"
            "keepalivetimeout" -> "keepalive_timeout"
            "maxhandshakeattempts" -> "max_handshake_attempts"
            "randomtrailers" -> "random_trailers"
            "disablecookies" -> "disable_cookies"
            else -> key
        }

        /**
         * An AmneziaWG value as the engine takes it, or why it is not one: numbers (Jc, Jmin, Jmax, S1-S4 up to 65535), ranges (H1-H4 up
         * to 2^32-1, the padding and timings up to 65535, as the awg tool takes them), booleans, the header protection key, I1-I5 as written
         */
        private fun awgValue(key: String, name: String, value: String): Pair<String, String?>? = when (key) {
            "jc", "jmin", "jmax", "s1", "s2", "s3", "s4" ->
                range(value, 65535, false)?.let { it to null } ?: ("" to "$name must be a whole number from 0 to 65535.")
            "h1", "h2", "h3", "h4" ->
                range(value, 4294967295L, true)?.let { it to null } ?: ("" to "$name must be a number or a range such as 1000000-1999999.")
            "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts" ->
                range(value, 65535, true)?.let { it to null } ?: ("" to "$name must be a number or a range such as 10-20.")
            "randomtrailers", "disablecookies" -> when (bool(value)) {
                true -> "true" to null
                false -> "false" to null
                null -> "" to "$name must be on or off."
            }
            "headerprotectionkey" -> base64ToHex(value)?.let { it to null } ?: ("" to "the HeaderProtectionKey is not valid base64 (32 bytes).")
            else -> value to null
        }

        /** "N" or "N-M" with N <= M <= max (the AmneziaWG engine's ranges), normalized; null when the value is not one */
        fun range(value: String, max: Long, allowRange: Boolean): String? {
            val parts = value.split('-')
            if (parts.size > (if (allowRange) 2 else 1)) return null
            val bounds = parts.map { part ->
                val digits = part.trim()
                if (digits.isEmpty() || digits.length > 10 || digits.any { it !in '0'..'9' }) return null
                digits.toLong().takeIf { it <= max } ?: return null
            }
            if (bounds.size == 2 && bounds[1] < bounds[0]) return null
            return bounds.joinToString("-")
        }

        /** The awg tool's booleans (on/off or a number) and the usual true/false */
        private fun bool(value: String): Boolean? = when (value.lowercase()) {
            "on", "true", "yes" -> true
            "off", "false", "no" -> false
            else -> range(value, 4294967295L, false)?.let { it != "0" }
        }

        /** host and port of an Endpoint value: host:port or [IPv6]:port */
        fun endpointParts(value: String): Pair<String, Int> {
            if (value.startsWith("[")) {
                val close = value.indexOf(']')
                if (close < 0) return "" to 0
                return value.substring(1, close) to (value.substring(close + 1).removePrefix(":").toIntOrNull() ?: 0)
            }
            val colon = value.lastIndexOf(':')
            return if (colon < 0) value to 0 else value.substring(0, colon) to (value.substring(colon + 1).toIntOrNull() ?: 0)
        }

        /** The engine takes keys in hex; wg-quick files carry base64 of 32 bytes. */
        fun base64ToHex(value: String): String? {
            val raw = runCatching { java.util.Base64.getDecoder().decode(value) }.getOrNull() ?: return null
            if (raw.size != 32) return null
            return raw.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }

        /** The peer's last handshake (seconds since 1970, 0 for none), bytes received and sent, from a UAPI get. */
        fun peerState(uapi: String): Triple<Long, Long, Long>? {
            val values = uapi.lines().mapNotNull { line ->
                val key = line.substringBefore('=', "")
                if (key in listOf("last_handshake_time_sec", "rx_bytes", "tx_bytes")) key to (line.substringAfter('=').toLongOrNull() ?: 0L) else null
            }.toMap()
            if (values.size != 3) return null
            return Triple(values.getValue("last_handshake_time_sec"), values.getValue("rx_bytes"), values.getValue("tx_bytes"))
        }
    }
}

/** The handshake failure, as the iPhone app words it. */
internal fun wireGuardNoHandshakeMessage(port: Int, amnezia: Boolean = false) =
    if (amnezia) "The server did not answer the AmneziaWG handshake: the server's public key or the preshared key may not match, the server " +
        "may not have this profile's public key as a peer, its obfuscation settings (S1-S4, H1-H4, HeaderProtectionKey, RandomTrailers) may " +
        "differ from this profile's, or UDP port $port may be closed."
    else "The server did not answer the WireGuard handshake: the server's public key or the preshared key may not match, the server may not have " +
        "this profile's public key as a peer, or UDP port $port may be closed."

/** WireGuard takes none of AmneziaWG's settings: a file that has them belongs to an AmneziaWG profile (SRPWGAmneziaKeysMessage). */
internal fun amneziaKeysMessage(keys: List<String>) =
    "This configuration has AmneziaWG settings (${keys.take(4).joinToString(", ")}${if (keys.size > 4) ", …" else ""}): use the AmneziaWG VPN protocol for it."

/** S3, S4 or H4 other than the server's: the handshake is answered (S1, S2, H1, H2 match), every data packet dropped. */
internal const val AMNEZIA_NO_TRAFFIC_MESSAGE =
    "The server answers the AmneziaWG handshake but none of the traffic: S3, S4 or H4 may differ from the server's."

/** Why the engine refused the settings, from its own error ("Unable to set the configuration: IPC error -22: failed to parse I1: …"). */
internal fun engineRefusedMessage(name: String, engineError: String?): String {
    val match = engineError?.let { Regex("""IPC error -?[0-9]+: """).find(it) }
    return if (match != null) "$name refused the configuration: ${engineError.substring(match.range.last + 1)}"
    else "$name: the engine refused the configuration (see log)."
}

/**
 * WireGuard and AmneziaWG as SRPWireGuardClient.m runs them on iPhone: connected once the server answered a handshake, attempts of 10
 * seconds (1 + Retry Times with Auto Reconnect), the server counted as gone when nothing comes back for 30 seconds while the phone
 * sends, Auto Reconnect and Retry Times after that, On Sleep, and new sockets on every network change. AmneziaWG runs amneziawg-go with
 * the file's obfuscation settings, and ends a session whose handshake the server answers but none of the traffic.
 */
class WireGuardClient(
    private val profile: Profile,
    private val connectivity: ConnectivityManager,
    private val host: TunnelHost,
) : TunnelClient {
    private val autoReconnect = profile.autoReconnect
    private val retryTimes = profile.retryTimes.coerceAtLeast(0)
    private val onSleep = profile.onSleep
    private val logLevel = profile.logLevel
    private val amnezia = profile.isAmnezia
    private val name = if (amnezia) "AmneziaWG" else "WireGuard"

    private var conf: WireGuardConf? = null
    private var endpointIp = ""
    @Volatile private var handle = -1
    private var closed = false
    private var up = false
    private var reconnecting = false
    private var paused = false
    private var keepaliveTemp = false
    /** The device was just turned on: its peer has sent nothing yet */
    private var peerFresh = false
    private var attempts = 0
    private var attemptStart = 0L
    private var handshakeBefore = 0L
    /** Sent bytes in 30 s of silence that are more than keepalives (WireGuardConf.silenceBytes) */
    private var silenceBytes = SILENCE_SENT_BYTES
    private val samples = ArrayDeque<LongArray>()   // (elapsed ms, rx, tx, last handshake) every 5 s
    private var lastCounterLine = 0L
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetwork: Network? = null
    private var lastKind = ""
    private var tunnelAddress = ByteArray(4)

    private var pingCallback: ((Long) -> Unit)? = null
    private var pingPort = 0
    private var pingStarted = 0L
    private var pingHttpStarted = false
    private var pingEpoch = 0

    private val startTimeout = Runnable {
        if (!closed && !up) failWithReason("Connection timed out. The server did not respond.")
    }
    private val poll = object : Runnable {
        override fun run() {
            pollAttempt()
            if (!closed && pollActive) worker.postDelayed(this, 250)
        }
    }
    private var pollActive = false
    private val monitor = object : Runnable {
        override fun run() {
            if (closed) return
            watch()
            worker.postDelayed(this, 5000)
        }
    }

    fun start() {
        current = this
        logThread
        probeThread
        worker.post {
            // Each attempt takes 10 s: this only catches a start that never got that far
            val budget = if (autoReconnect && retryTimes > 0) 1 + retryTimes else 1
            worker.postDelayed(startTimeout, 30_000L + 12_000L * budget)
            startDevice()
        }
    }

    override fun close() {
        worker.post {
            if (closed) return@post
            ConnectionLog.m("$name: disconnecting")
            closeNow()
        }
    }

    override fun pauseForSleep() {
        worker.post {
            if (onSleep == 2 || closed || handle < 0 || paused) return@post
            stopPolling()
            worker.removeCallbacks(monitor)
            WireGuardNative.turnOff(handle)
            handle = -1
            paused = true
            ConnectionLog.m("$name: closed for sleep (On Sleep ${if (onSleep == 0) "Off" else "Pause"})")
        }
    }

    override fun wakeFromSleep() {
        worker.post {
            if (closed) return@post
            if (!paused) {
                if (handle >= 0) refreshEndpoint()
                return@post
            }
            paused = false
            if (onSleep == 0 && !autoReconnect) return@post failWithReason("The connection was closed while the device slept.")
            ConnectionLog.m("$name: awake: connecting again")
            if (!turnOn()) return@post
            reconnecting = true
            attempts = 0
            startAttempt()
        }
    }

    /** What a network change does (the tests' path switch): the endpoint looked up again and new sockets on the current network. */
    fun switchNetworkPath() {
        worker.post {
            if (closed || handle < 0) return@post
            ConnectionLog.m("$name: re-binding the sockets on the current network")
            refreshEndpoint()
        }
    }

    override fun measurePing(result: (Long) -> Unit) {
        worker.post {
            if (closed || !up || handle < 0) {
                result(-1)
                return@post
            }
            pingCallback?.invoke(-1)
            pingCallback = result
            pingPort = Random.nextInt(40000) + 20000
            pingHttpStarted = false
            pingStarted = SystemClock.elapsedRealtime()
            val epoch = ++pingEpoch
            WireGuardNative.setProbeFlows(handle, intArrayOf(ProbePackets.PROTOCOL_TCP, ProbePackets.ipv4Int(PROBE_ADDRESS), pingPort))
            sendPingSyn(epoch)
            worker.postDelayed({ if (epoch == pingEpoch) finishPing(-2) }, PING_TIMEOUT_MS)
        }
    }

    private fun startDevice() {
        if (closed) return
        val text = profile.wgEffectiveConfig()
        if (text.isNullOrEmpty()) return failWithReason("No WireGuard/AmneziaWG config is stored in this VPN profile. Import a .conf file or use Manual Configuration.")
        val (parsed, problem) = WireGuardConf.parse(text)
        if (parsed == null) return failWithReason("Invalid $name config: $problem")
        if (!amnezia && parsed.amneziaKeys.isNotEmpty()) return failWithReason(amneziaKeysMessage(parsed.amneziaKeys))
        val address = resolve(parsed.endpointHost) ?: return failWithReason("The $name endpoint ${parsed.endpointHost} could not be resolved.")
        if (WireGuardConf.base64ToHex(parsed.privateKey) == null || WireGuardConf.base64ToHex(parsed.peerPublicKey) == null) {
            return failWithReason("Invalid $name config: a key is not valid base64 (32 bytes).")
        }
        if (parsed.presharedKey.isNotEmpty() && WireGuardConf.base64ToHex(parsed.presharedKey) == null) {
            return failWithReason("Invalid $name config: the PresharedKey is not valid base64 (32 bytes).")
        }
        conf = parsed
        endpointIp = address
        silenceBytes = parsed.silenceBytes(amnezia)
        tunnelAddress = ProbePackets.ipv4(parsed.tunnelSettings(amnezia).address) ?: ByteArray(4)
        val keepalive = if (parsed.keepalive > 0) "${if (amnezia) parsed.keepaliveSpec else parsed.keepalive} s" else "off"
        ConnectionLog.m("$name: connecting to ${parsed.endpointHost} ($address) port ${parsed.endpointPort} over UDP, keepalive " +
            "$keepalive, preshared key ${if (parsed.presharedKey.isNotEmpty()) "yes" else "no"}")
        if (amnezia) {
            // What the file sets (names only: the header protection key is a secret, the I1-I5 chains are long)
            val set = parsed.amneziaKeys.distinct()
            ConnectionLog.m("AmneziaWG: obfuscation ${if (set.isEmpty()) "none (WireGuard's own format)" else set.joinToString(" ")}, MTU ${parsed.tunnelMtu(true)}")
            if (parsed.trailersWithRanges) {
                // The app's engine (our amneziawg-go fork) keeps these packets, and with header protection it also sends packets the
                // server's first-match classification reads right; without it the server can still drop some of the phone's packets
                ConnectionLog.m("AmneziaWG: note: with RandomTrailers on, ranges in H1-H3 and no HeaderProtectionKey, the server's AmneziaWG may take " +
                    "some of the phone's data packets for handshake messages and drop them (uploads slow down); a HeaderProtectionKey " +
                    "or single values in H1-H3 avoid it")
            }
        }
        WireGuardNative.setVerbose(logLevel >= 2)
        if (!turnOn()) return
        ConnectionLog.m("$name: device up")
        startPathMonitor()
        attempts = 0
        startAttempt()
    }

    /**
     * The VPN interface (the same one again after sleep) and the engine on it, without the peer's keepalive: a device that starts
     * with one sends a handshake initiation at once, and a second one from the first attempt within the same few milliseconds is
     * dropped by the server as a replay
     */
    private fun turnOn(): Boolean {
        val config = conf ?: return false
        val settings = config.uapi(endpointIp, keepalive = "0", amnezia = amnezia) ?: run {
            failWithReason("Invalid $name config: a key is not valid base64 (32 bytes).")
            return false
        }
        var started = -1
        val error = host.applyTunnelSettings(config.tunnelSettings(amnezia)) { fd ->
            started = if (amnezia) WireGuardNative.turnOnAmnezia(settings, fd) else WireGuardNative.turnOn(settings, fd)
        }
        if (error != null) {
            failWithReason("The VPN interface could not be set up: $error")
            return false
        }
        if (started < 0) {
            failWithReason(engineRefusedMessage(name, WireGuardNative.lastError()))
            return false
        }
        handle = started
        peerFresh = true
        return true
    }

    private fun resolve(name: String): String? = runCatching {
        val all = InetAddress.getAllByName(name)
        (all.firstOrNull { it is Inet4Address } ?: all.first()).hostAddress
    }.getOrNull()

    /** Retry Times: before the first handshake 1 attempt, or 1 + Retry Times with Auto Reconnect; afterwards Retry Times (0 = no limit), one without Auto Reconnect */
    private fun attemptBudget(): Int = when {
        !up -> if (autoReconnect && retryTimes > 0) 1 + retryTimes else 1
        !autoReconnect -> 1
        retryTimes > 0 -> retryTimes
        else -> Int.MAX_VALUE
    }

    /**
     * One attempt: a persistent keepalive switched on (from 0) makes the engine send a handshake initiation at once. On a device just
     * turned on that is all; later attempts set the peer up afresh, without the session it had (after a server restart the old
     * session key would only be dropped, and the engine would re-handshake on its own only 2 minutes later).
     */
    private fun startAttempt() {
        val config = conf ?: return
        if (closed || handle < 0) return
        attempts++
        attemptStart = SystemClock.elapsedRealtime()
        val keepalive = if (config.keepalive <= 0) "25" else if (amnezia) config.keepaliveSpec else config.keepalive.toString()
        if (peerFresh) {
            peerFresh = false
            WireGuardNative.setConfig(handle, "public_key=${WireGuardConf.base64ToHex(config.peerPublicKey)}\nupdate_only=true\npersistent_keepalive_interval=$keepalive\n")
        } else {
            config.peer(endpointIp, keepalive)?.let { WireGuardNative.setConfig(handle, it) }
        }
        keepaliveTemp = config.keepalive == 0
        handshakeBefore = state()?.first ?: 0L
        if (attempts > 1 || up) ConnectionLog.m("$name: handshake attempt $attempts")
        stopPolling()
        pollActive = true
        worker.postDelayed(poll, 250)
    }

    private fun stopPolling() {
        pollActive = false
        worker.removeCallbacks(poll)
    }

    private fun state(): Triple<Long, Long, Long>? = if (handle < 0) null else WireGuardNative.getConfig(handle)?.let { WireGuardConf.peerState(it) }

    private fun restoreKeepalive() {
        val config = conf ?: return
        if (keepaliveTemp && handle >= 0) {
            WireGuardNative.setConfig(handle, "public_key=${WireGuardConf.base64ToHex(config.peerPublicKey)}\nupdate_only=true\npersistent_keepalive_interval=0\n")
            keepaliveTemp = false
        }
    }

    private fun pollAttempt() {
        val config = conf ?: return
        if (closed || handle < 0) return stopPolling()
        val waited = SystemClock.elapsedRealtime() - attemptStart
        val handshake = state()?.first ?: 0L
        if (handshake > handshakeBefore) {
            stopPolling()
            restoreKeepalive()
            if (!up) {
                up = true
                worker.removeCallbacks(startTimeout)
                ConnectionLog.m("$name: session established: handshake with ${config.endpointHost}:${config.endpointPort} after ${"%.1f".format(waited / 1000.0)} s")
                host.onConnected()
            } else {
                ConnectionLog.m("$name: the server answers again: handshake after ${"%.1f".format(waited / 1000.0)} s (attempt $attempts)")
            }
            reconnecting = false
            attempts = 0
            startMonitor()
            return
        }
        if (waited < ATTEMPT_MS) return
        stopPolling()
        ConnectionLog.m("$name: no handshake in ${ATTEMPT_MS / 1000} seconds (attempt $attempts)")
        if (attempts < attemptBudget() && !closed) {
            refreshEndpoint()
            startAttempt()
            return
        }
        restoreKeepalive()
        val reason = when {
            attempts > 1 -> "Could not ${if (up) "reconnect" else "connect"} after $attempts attempt${if (attempts == 1) "" else "s"}. (The server did not answer the $name handshake.)"
            up -> "Could not reconnect: the server did not answer the $name handshake."
            else -> wireGuardNoHandshakeMessage(config.endpointPort, amnezia)
        }
        failWithReason(reason)
    }

    private fun startMonitor() {
        worker.removeCallbacks(monitor)
        samples.clear()
        lastCounterLine = SystemClock.elapsedRealtime()
        worker.postDelayed(monitor, 5000)
    }

    /** Every 5 s: nothing received for 30 s while the phone sent more than keepalives means the server stopped answering */
    private fun watch() {
        if (reconnecting || paused || handle < 0) return
        val (handshake, rx, tx) = state() ?: return
        val now = SystemClock.elapsedRealtime()
        samples.addLast(longArrayOf(now, rx, tx, handshake))
        while (samples.isNotEmpty() && now - samples.first()[0] > 60_000) samples.removeFirst()
        if (logLevel >= 1 && now - lastCounterLine >= 30_000) {
            lastCounterLine = now
            val age = if (handshake > 0) System.currentTimeMillis() / 1000 - handshake else -1
            ConnectionLog.m("$name: last handshake $age s ago, received $rx bytes, sent $tx bytes")
        }
        val base = samples.lastOrNull { now - it[0] >= SILENCE_MS }
        if (base != null && rx == base[1] && tx - base[2] >= silenceBytes) return peerLost()
        // AmneziaWG: a server whose S3, S4 or H4 differ from the profile's answers every handshake (S1, S2, H1 and H2 match) and drops
        // every data packet. The engine, hearing nothing back while it sends, starts a new handshake every 15 s or so, each answered, so
        // the server never falls silent. Two or more handshakes in 40 s that brought back nothing but their answers (92 + S2 bytes, a
        // random trailer at most 500 more), while the phone sent, end the VPN with that reason (SRPWireGuardClient.m).
        val older = samples.lastOrNull { now - it[0] >= HANDSHAKE_ONLY_MS } ?: return
        if (!amnezia) return
        var handshakes = 0
        var last = older[3]
        samples.filter { it[0] > older[0] }.forEach { if (it[3] != last) { handshakes++; last = it[3] } }
        val answers = handshakes * (92L + (conf?.s2 ?: 0) + 500)
        if (handshakes >= 2 && rx - older[1] <= answers && tx - older[2] >= silenceBytes) {
            ConnectionLog.m("AmneziaWG: $handshakes handshakes in ${HANDSHAKE_ONLY_MS / 1000} seconds were answered, nothing else came back")
            failWithReason(AMNEZIA_NO_TRAFFIC_MESSAGE)
        }
    }

    private fun peerLost() {
        val reason = "The server stopped answering: nothing came back for ${SILENCE_MS / 1000} seconds"
        ConnectionLog.m("$name: $reason")
        if (!autoReconnect) return failWithReason("$reason (auto reconnect is off).")
        worker.removeCallbacks(monitor)
        reconnecting = true
        attempts = 0
        refreshEndpoint()
        startAttempt()
    }

    /** The endpoint's name looked up again (it may point elsewhere now), and new sockets on the network the phone uses now */
    private fun refreshEndpoint() {
        val config = conf ?: return
        if (handle < 0) return
        val address = resolve(config.endpointHost)
        if (address != null && address != endpointIp) {
            ConnectionLog.m("$name: ${config.endpointHost} is now $address")
            endpointIp = address
            WireGuardNative.setConfig(handle, "public_key=${WireGuardConf.base64ToHex(config.peerPublicKey)}\nupdate_only=true\n" +
                "endpoint=${if (':' in address) "[$address]" else address}:${config.endpointPort}\n")
        }
        WireGuardNative.bumpSockets(handle)
    }

    private fun startPathMonitor() {
        if (networkCallback != null || closed) return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                val kind = if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) "Wi-Fi"
                           else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) "cellular" else "another network"
                val previous = lastNetwork
                val previousKind = lastKind
                lastNetwork = network
                lastKind = kind
                if (previous == null || (previous == network && previousKind == kind) || closed || handle < 0 || paused) return
                ConnectionLog.m("$name: network changed ($kind): the sockets move to it")
                refreshEndpoint()
            }
        }
        networkCallback = callback
        // The default network of the app that made the VPN is that VPN, although the app is outside it, and it stays the same
        // network when Wi-Fi goes: the best network that is not a VPN is the one this app's sockets really use. Before Android 12
        // only the VPN's transports (Wi-Fi or mobile data) show the change.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val request = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
            connectivity.registerBestMatchingNetworkCallback(request, callback, worker)
        } else {
            connectivity.registerDefaultNetworkCallback(callback, worker)
        }
    }

    private fun stopPathMonitor() {
        networkCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        networkCallback = null
    }

    private fun sendPingSyn(epoch: Int) {
        if (epoch != pingEpoch || pingCallback == null || pingHttpStarted || closed || handle < 0) return
        WireGuardNative.submit(handle, ProbePackets.syn(tunnelAddress, ProbePackets.ipv4(PROBE_ADDRESS) ?: ByteArray(4), pingPort))
        worker.postDelayed({ sendPingSyn(epoch) }, 1000)
    }

    private fun finishPing(value: Long) {
        val callback = pingCallback ?: return
        pingCallback = null
        pingEpoch++
        if (handle >= 0) WireGuardNative.setProbeFlows(handle, IntArray(0))
        callback(value)
    }

    private fun handlePingPacket(packet: ByteArray) {
        if (pingCallback == null || packet.size < 40 || (packet[0].toInt() and 0xff) shr 4 != 4 || packet[9].toInt() != ProbePackets.PROTOCOL_TCP) return
        val ihl = (packet[0].toInt() and 0x0f) * 4
        val headerLength = ((packet[ihl + 12].toInt() and 0xff) shr 4) * 4
        if (headerLength < 20 || packet.size < ihl + headerLength || u16(packet, ihl) != 80 || u16(packet, ihl + 2) != pingPort) return
        val flags = packet[ihl + 13].toInt() and 0xff
        if (pingHttpStarted) {
            val payloadLength = packet.size - ihl - headerLength
            if (payloadLength >= 5 && String(packet, ihl + headerLength, 5) == "HTTP/") finishPing(SystemClock.elapsedRealtime() - pingStarted)
            else if (payloadLength == 0 && flags and 0x05 != 0) finishPing(-1)
            return
        }
        if (flags and 0x12 == 0x12 && handle >= 0) {
            pingHttpStarted = true
            WireGuardNative.submit(handle, ProbePackets.httpRequest(tunnelAddress, ProbePackets.ipv4(PROBE_ADDRESS) ?: ByteArray(4), pingPort, u32(packet, ihl + 4) + 1))
        }
    }

    private fun u16(bytes: ByteArray, offset: Int) = ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun u32(bytes: ByteArray, offset: Int) = (u16(bytes, offset) shl 16) or u16(bytes, offset + 2)

    private fun failWithReason(reason: String) {
        if (closed) return
        ConnectionLog.m("$name: closing with reason: $reason")
        closeNow()
        host.onFailure(reason)
    }

    private fun closeNow() {
        if (closed) return
        closed = true
        stopPolling()
        worker.removeCallbacks(monitor)
        worker.removeCallbacks(startTimeout)
        stopPathMonitor()
        pingCallback?.invoke(-1)
        pingCallback = null
        if (handle >= 0) {
            WireGuardNative.turnOff(handle)
            handle = -1
        }
        if (current === this) current = null
        host.onClosed()
    }

    companion object {
        private val worker by lazy { Handler(HandlerThread("srp.wireguard").apply { start() }.looper) }
        @Volatile private var current: WireGuardClient? = null

        /** The engine's log lines: errors at every level, its own steps at Debug (as on iPhone) */
        private val logThread by lazy {
            Thread({
                while (true) {
                    val line = WireGuardNative.nextLog(1000) ?: continue
                    ConnectionLog.m("[${if (current?.amnezia == true) "awg" else "wg"}] ${line.substring(2)}")
                }
            }, "srp.wireguard.log").apply {
                isDaemon = true
                start()
            }
        }

        private val probeThread by lazy {
            Thread({
                while (true) {
                    val client = current
                    val handle = client?.handle ?: -1
                    if (client == null || handle < 0) {
                        Thread.sleep(250)
                        continue
                    }
                    val packet = WireGuardNative.nextProbe(handle, 500) ?: continue
                    worker.post { if (current === client) client.handlePingPacket(packet) }
                }
            }, "srp.wireguard.probes").apply {
                isDaemon = true
                start()
            }
        }

        private const val ATTEMPT_MS = 10_000L
        private const val SILENCE_MS = 30_000L
        private const val HANDSHAKE_ONLY_MS = 40_000L
        private const val SILENCE_SENT_BYTES = 296L
        private const val PROBE_ADDRESS = "1.1.1.1"
        private const val PING_TIMEOUT_MS = 15_000L
    }
}
