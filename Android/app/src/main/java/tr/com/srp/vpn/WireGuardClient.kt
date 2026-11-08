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

/** wireguard-go (the iOS app's version) with its JNI layer and the Ping probe (go/wireguard), in libwg-go.so. */
internal object WireGuardNative {
    init {
        System.loadLibrary("wg-go")
    }

    /** The engine on a duplicate of the TUN descriptor with these UAPI settings: a handle, or -1. */
    @JvmStatic external fun turnOn(settings: String, tunFd: Int): Int
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
}

/** A wg-quick configuration, read as SRPWireGuardClient.m reads it. */
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
) {
    /** The engine's settings: the device, then the peer as [peer] gives it. */
    fun uapi(endpointIp: String, keepaliveSeconds: Int = keepalive): String? {
        val private = base64ToHex(privateKey) ?: return null
        return "private_key=$private\nlisten_port=0\n" + (peer(endpointIp, keepaliveSeconds) ?: return null)
    }

    /** The peer afresh (replace_peers, without the session it had), with this persistent keepalive. */
    fun peer(endpointIp: String, keepaliveSeconds: Int): String? {
        val public = base64ToHex(peerPublicKey) ?: return null
        return buildString {
            append("replace_peers=true\npublic_key=$public\n")
            if (presharedKey.isNotEmpty()) append("preshared_key=${base64ToHex(presharedKey) ?: return null}\n")
            append("endpoint=${if (':' in endpointIp) "[$endpointIp]" else endpointIp}:$endpointPort\n")
            allowedIps.forEach { append("allowed_ip=$it\n") }
            if (keepaliveSeconds > 0) append("persistent_keepalive_interval=$keepaliveSeconds\n")
        }
    }

    /** The VPN interface: the config's addresses, its AllowedIPs as routes, its DNS and MTU (1420 unless it says). */
    fun tunnelSettings(): TunnelSettings {
        val v4 = addresses.firstOrNull { ProbePackets.ipv4(it.substringBefore('/')) != null } ?: addresses.first()
        val extra = addresses.filter { it != v4 }.map { it.substringBefore('/') to (it.substringAfter('/', "").toIntOrNull() ?: if (':' in it) 128 else 32) }
        val routes = allowedIps.map { it.substringBefore('/') to (it.substringAfter('/', "").toIntOrNull() ?: if (':' in it) 128 else 32) }
        return TunnelSettings(v4.substringBefore('/'), dns, routes.ifEmpty { listOf("0.0.0.0" to 0) }, if (mtu > 0) mtu else 1420,
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
            val addresses = mutableListOf<String>()
            val dns = mutableListOf<String>()
            val allowed = mutableListOf<String>()
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
                    "interface" -> when (key) {
                        "privatekey" -> privateKey = value
                        "address" -> addresses += list()
                        "dns" -> dns += list()
                        "mtu" -> mtu = value.toIntOrNull() ?: 0
                    }
                    "peer" -> when (key) {
                        "publickey" -> peerPublicKey = value
                        "presharedkey" -> presharedKey = value
                        "endpoint" -> endpoint = value
                        "allowedips" -> allowed += list()
                        "persistentkeepalive" -> keepalive = value.toIntOrNull() ?: 0
                    }
                }
            }
            val (host, port) = endpointParts(endpoint)
            return when {
                privateKey.isEmpty() -> null to "The config has no [Interface] PrivateKey."
                peerPublicKey.isEmpty() -> null to "The config has no [Peer] PublicKey."
                host.isEmpty() || port <= 0 -> null to "The config has no valid [Peer] Endpoint."
                addresses.isEmpty() -> null to "The config has no [Interface] Address."
                else -> WireGuardConf(privateKey, addresses, dns, mtu, peerPublicKey, presharedKey, host, port, allowed, keepalive) to null
            }
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
internal fun wireGuardNoHandshakeMessage(port: Int) =
    "The server did not answer the WireGuard handshake: the server's public key or the preshared key may not match, the server may not have " +
        "this profile's public key as a peer, or UDP port $port may be closed."

/**
 * WireGuard as SRPWireGuardClient.m runs it on iPhone: connected once the server answered a handshake, attempts of 10 seconds
 * (1 + Retry Times with Auto Reconnect), the server counted as gone when nothing comes back for 30 seconds while the phone
 * sends, Auto Reconnect and Retry Times after that, On Sleep, and new sockets on every network change.
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
    private val samples = ArrayDeque<LongArray>()   // (elapsed ms, rx, tx) every 5 s
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
            ConnectionLog.m("WireGuard: disconnecting")
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
            ConnectionLog.m("WireGuard: closed for sleep (On Sleep ${if (onSleep == 0) "Off" else "Pause"})")
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
            ConnectionLog.m("WireGuard: awake: connecting again")
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
            ConnectionLog.m("WireGuard: re-binding the sockets on the current network")
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
        if (parsed == null) return failWithReason("Invalid WireGuard config: $problem")
        val address = resolve(parsed.endpointHost) ?: return failWithReason("The WireGuard endpoint ${parsed.endpointHost} could not be resolved.")
        if (WireGuardConf.base64ToHex(parsed.privateKey) == null || WireGuardConf.base64ToHex(parsed.peerPublicKey) == null) {
            return failWithReason("Invalid WireGuard config: a key is not valid base64 (32 bytes).")
        }
        if (parsed.presharedKey.isNotEmpty() && WireGuardConf.base64ToHex(parsed.presharedKey) == null) {
            return failWithReason("Invalid WireGuard config: the PresharedKey is not valid base64 (32 bytes).")
        }
        conf = parsed
        endpointIp = address
        tunnelAddress = ProbePackets.ipv4(parsed.tunnelSettings().address) ?: ByteArray(4)
        ConnectionLog.m("WireGuard: connecting to ${parsed.endpointHost} ($address) port ${parsed.endpointPort} over UDP, keepalive " +
            "${if (parsed.keepalive > 0) "${parsed.keepalive} s" else "off"}, preshared key ${if (parsed.presharedKey.isNotEmpty()) "yes" else "no"}")
        WireGuardNative.setVerbose(logLevel >= 2)
        if (!turnOn()) return
        ConnectionLog.m("WireGuard: device up")
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
        val settings = config.uapi(endpointIp, keepaliveSeconds = 0) ?: run {
            failWithReason("Invalid WireGuard config: a key is not valid base64 (32 bytes).")
            return false
        }
        var started = -1
        val error = host.applyTunnelSettings(config.tunnelSettings()) { fd -> started = WireGuardNative.turnOn(settings, fd) }
        if (error != null) {
            failWithReason("The VPN interface could not be set up: $error")
            return false
        }
        if (started < 0) {
            failWithReason("WireGuard: the engine refused the configuration (see log).")
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
        val keepalive = if (config.keepalive > 0) config.keepalive else 25
        if (peerFresh) {
            peerFresh = false
            WireGuardNative.setConfig(handle, "public_key=${WireGuardConf.base64ToHex(config.peerPublicKey)}\nupdate_only=true\npersistent_keepalive_interval=$keepalive\n")
        } else {
            config.peer(endpointIp, keepalive)?.let { WireGuardNative.setConfig(handle, it) }
        }
        keepaliveTemp = config.keepalive == 0
        handshakeBefore = state()?.first ?: 0L
        if (attempts > 1 || up) ConnectionLog.m("WireGuard: handshake attempt $attempts")
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
                ConnectionLog.m("WireGuard: session established: handshake with ${config.endpointHost}:${config.endpointPort} after ${"%.1f".format(waited / 1000.0)} s")
                host.onConnected()
            } else {
                ConnectionLog.m("WireGuard: the server answers again: handshake after ${"%.1f".format(waited / 1000.0)} s (attempt $attempts)")
            }
            reconnecting = false
            attempts = 0
            startMonitor()
            return
        }
        if (waited < ATTEMPT_MS) return
        stopPolling()
        ConnectionLog.m("WireGuard: no handshake in ${ATTEMPT_MS / 1000} seconds (attempt $attempts)")
        if (attempts < attemptBudget() && !closed) {
            refreshEndpoint()
            startAttempt()
            return
        }
        restoreKeepalive()
        val reason = when {
            attempts > 1 -> "Could not ${if (up) "reconnect" else "connect"} after $attempts attempt${if (attempts == 1) "" else "s"}. (The server did not answer the WireGuard handshake.)"
            up -> "Could not reconnect: the server did not answer the WireGuard handshake."
            else -> wireGuardNoHandshakeMessage(config.endpointPort)
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
        samples.addLast(longArrayOf(now, rx, tx))
        while (samples.isNotEmpty() && now - samples.first()[0] > 60_000) samples.removeFirst()
        if (logLevel >= 1 && now - lastCounterLine >= 30_000) {
            lastCounterLine = now
            val age = if (handshake > 0) System.currentTimeMillis() / 1000 - handshake else -1
            ConnectionLog.m("WireGuard: last handshake $age s ago, received $rx bytes, sent $tx bytes")
        }
        val base = samples.lastOrNull { now - it[0] >= SILENCE_MS } ?: return
        if (rx == base[1] && tx - base[2] >= SILENCE_SENT_BYTES) peerLost()
    }

    private fun peerLost() {
        val reason = "The server stopped answering: nothing came back for ${SILENCE_MS / 1000} seconds"
        ConnectionLog.m("WireGuard: $reason")
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
            ConnectionLog.m("WireGuard: ${config.endpointHost} is now $address")
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
                ConnectionLog.m("WireGuard: network changed ($kind): the sockets move to it")
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
        ConnectionLog.m("WireGuard: closing with reason: $reason")
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
                    ConnectionLog.m("[wg] ${line.substring(2)}")
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
        private const val SILENCE_SENT_BYTES = 296L
        private const val PROBE_ADDRESS = "1.1.1.1"
        private const val PING_TIMEOUT_MS = 15_000L
    }
}
