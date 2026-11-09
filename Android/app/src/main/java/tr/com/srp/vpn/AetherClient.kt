package tr.com.srp.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import org.json.JSONObject
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/** The Aether engine of our fork (libaether.so) with hev, the stderr lines and the test connection (aether_jni.c), in libsrpaether.so. */
internal object AetherNative {
    init {
        System.loadLibrary("srpaether")
    }

    const val VERSION = 0
    const val IDENTITY_OPEN = 1
    const val VERIFY_START = 2
    const val SCAN_START = 3
    const val TUNNEL_START = 4
    const val JOB_POLL = 5
    const val JOB_CANCEL = 6
    const val JOB_FREE = 7

    /** One engine call: its JSON reply */
    @JvmStatic external fun call(fn: Int, id: Long, payload: String?): String?

    /** The engine's settings (AETHER_*, RUST_LOG); null unsets */
    @JvmStatic external fun setenv(key: String, value: String?)

    /** The engine and hev log to stderr: from now on its lines wait for [nextLog] */
    @JvmStatic external fun captureStderr()

    @JvmStatic external fun nextLog(timeoutMs: Int): String?

    /** hev on its own copy of the VPN's TUN fd: 0 when started */
    @JvmStatic external fun hevStart(conf: String, tunFd: Int): Int

    @JvmStatic external fun hevStop()

    /** {bytes from the phone, bytes to the phone} through hev since it started */
    @JvmStatic external fun hevBytes(): LongArray

    /** A SOCKS5 CONNECT to 1.1.1.1:443 through 127.0.0.1:port: 1 passed, 0 the far end closed it, -1 timeout or error */
    @JvmStatic external fun socksProbe(port: Int, timeoutSec: Int): Int
}

/**
 * Aether (SRPAetherClient.m and the Aether start of PacketTunnelProvider.m): Cloudflare WARP through the engine of our fork
 * (MASQUE over HTTP/3 or HTTP/2, or WARP's WireGuard through [WireGuardClient]), Tor through it, or Private mode: WireGuard to
 * the user's server (a relay in libwg-go.so) and that server's Aether proxy to WARP. hev carries the phone's traffic from the
 * TUN to the engine's (or the relay's) SOCKS5 port. Connected once a test connection through the tunnel went through; a test
 * connection every 20 seconds (and one at once after a network change) notices a session that stopped working, and Auto
 * Reconnect and Retry Times set up a new one, as on iPhone.
 */
class AetherClient(
    private val context: Context,
    private val profile: Profile,
    private val connectivity: ConnectivityManager,
    private val host: TunnelHost,
) : TunnelClient {
    private val autoReconnect = profile.autoReconnect
    private val retryTimes = profile.retryTimes.coerceAtLeast(0)
    private val onSleep = profile.onSleep
    private val logLevel = profile.logLevel
    private val privateMode = profile.isAetherPrivate
    private val torMode = if (privateMode) "off" else profile.aetherTor
    private var transport = profile.aetherTransport
    private val identityDir = File(context.filesDir, "aether")
    private val lastGood = context.getSharedPreferences("aether", Context.MODE_PRIVATE)

    @Volatile private var closed = false
    /** Set by close() at once: an attempt holding the worker (a scan waits up to 4 minutes) stops waiting */
    @Volatile private var closing = false
    private var paused = false
    private var up = false
    private var attempts = 0
    private var identityId = 0L
    private var tunnelJob = 0L
    private var relay = -1
    private var socksPort = SOCKS_PORT
    private var socksClosed = false
    private var probeFailures = 0
    private var bytesAtLastProbe = 0L   // hev's bytes to the phone at the last test connection
    private var probing = false
    private var sessionStart = 0L
    private var pathName: String? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var wgClient: WireGuardClient? = null
    /** Bumped by every session start and stop: a timer of an older session changes nothing */
    private var generation = 0

    fun start() {
        logThread
        worker.post {
            AetherNative.setenv("AETHER_PERF_PROFILE", "low")
            // The SOCKS5 requests' destinations only at Debug
            AetherNative.setenv("RUST_LOG", if (logLevel >= 2) "trace" else "info,aether::socks=warn")
            AetherNative.setenv("AETHER_TLS_VERIFY", "1")
            // Tor (Arti) refuses a state directory with a parent others may write, and Android's /data/user/0 (system, 0771) is
            // one; the directory itself is in the app's own storage, which only the app can open
            AetherNative.setenv("ARTI_FS_DISABLE_PERMISSION_CHECKS", "true")
            listOf("AETHER_UPSTREAM", "AETHER_MASQUE_HTTP2", "AETHER_MASQUE_H2_FRAGMENT", "AETHER_MASQUE_H2_FRAGMENT_SIZE",
                "AETHER_MASQUE_H2_FRAGMENT_SNI").forEach { AetherNative.setenv(it, null) }
            ConnectionLog.m("Aether: ${if (privateMode) "private mode via ${profile.server.trim()}" else "transport=$transport scan=${profile.aetherScan} tor=$torMode fragMode=${profile.tlsFragMode}"}")
            ConnectionLog.m("Aether: auto reconnect ${if (autoReconnect) "on" else "off"}, retry times ${if (retryTimes > 0) "$retryTimes" else "no limit"}, " +
                "on sleep ${listOf("off", "pause", "stay")[onSleep.coerceIn(0, 2)]}")
            startPathMonitor()
            startAttempt()
        }
    }

    override fun close() {
        closing = true
        worker.post {
            if (closed) return@post
            ConnectionLog.m("Aether: disconnecting")
            closeNow()
        }
    }

    /** Off and Pause close the session while the device sleeps (the tunnel and hev stay); the WireGuard transport does its own */
    override fun pauseForSleep() {
        worker.post {
            wgClient?.let { it.pauseForSleep(); return@post }
            if (onSleep == 2 || closed || !up || paused) return@post
            paused = true
            ConnectionLog.m("Aether: the device sleeps: the session is closed until it wakes")
            stopSession()
        }
    }

    /** Pause, and Off with Auto Reconnect, connect again at wake; Off without it ends the VPN */
    override fun wakeFromSleep() {
        worker.post {
            wgClient?.let { it.wakeFromSleep(); return@post }
            if (closed || !paused) return@post
            paused = false
            if (onSleep == 0 && !autoReconnect) {
                fail("The connection was closed while the device slept.")
                return@post
            }
            ConnectionLog.m("Aether: the device is awake: connecting again")
            attempts = 0
            startAttempt()
        }
    }

    /** One HTTP request to 1.1.1.1 through the engine's (or the relay's) SOCKS5 port: this app stays outside its own tunnel */
    override fun measurePing(result: (Long) -> Unit) {
        wgClient?.let { it.measurePing(result); return }
        val port = socksPort
        if (closed || !up) {
            result(-1)
            return
        }
        Thread({
            val started = SystemClock.elapsedRealtime()
            val value = runCatching {
                Socket().use { socket ->
                    socket.soTimeout = PING_TIMEOUT_MS
                    socket.connect(InetSocketAddress("127.0.0.1", port), PING_TIMEOUT_MS)
                    val output = socket.getOutputStream()
                    val input = socket.getInputStream()
                    output.write(byteArrayOf(5, 1, 0))
                    val greeting = ByteArray(2).also { readFully(input, it) }
                    if (greeting[0].toInt() != 5 || greeting[1].toInt() != 0) return@use -1L
                    output.write(byteArrayOf(5, 1, 0, 1, 1, 1, 1, 1, 0, 80))
                    val reply = ByteArray(10).also { readFully(input, it) }
                    if (reply[1].toInt() != 0) return@use -1L
                    output.write("HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n".toByteArray())
                    if (input.read() < 0) -1L else SystemClock.elapsedRealtime() - started
                }
            }.getOrElse { if (it is java.net.SocketTimeoutException) -2L else -1L }
            result(value)
        }, "srp.aether.ping").start()
    }

    private fun readFully(input: java.io.InputStream, buffer: ByteArray) {
        var got = 0
        while (got < buffer.size) {
            val n = input.read(buffer, got, buffer.size - got)
            if (n < 0) throw java.io.EOFException()
            got += n
        }
    }

    // --- engine calls -------------------------------------------------------------------------------------------------

    private fun call(fn: Int, id: Long = 0, payload: String? = null): JSONObject =
        runCatching { JSONObject(AetherNative.call(fn, id, payload) ?: "{}") }.getOrElse { JSONObject().put("ok", false).put("error", "bad engine reply") }

    private fun startJob(fn: Int, id: Long, payload: String): Long {
        val reply = call(fn, id, payload)
        if (!reply.optBoolean("ok")) {
            ConnectionLog.m("Aether: job start failed: ${reply.optString("error", "unknown")}")
            return 0
        }
        return reply.optLong("job")
    }

    /** A job's result once it is done, or null on its error, after timeoutSec, or when the connection closes */
    private fun waitJob(job: Long, timeoutSec: Int): JSONObject? {
        val deadline = SystemClock.elapsedRealtime() + timeoutSec * 1000L
        while (true) {
            if (closed || closing) {
                call(AetherNative.JOB_CANCEL, job)
                return null
            }
            val poll = call(AetherNative.JOB_POLL, job)
            if (poll.optString("state") == "done") {
                val result = poll.optJSONObject("result")
                call(AetherNative.JOB_FREE, job)
                if (result != null && result.optBoolean("ok")) return result
                ConnectionLog.m("Aether: job $job failed: ${result?.optString("error", "unknown") ?: "unknown"}")
                return null
            }
            if (SystemClock.elapsedRealtime() > deadline) {
                ConnectionLog.m("Aether: job $job timed out")
                call(AetherNative.JOB_CANCEL, job)
                call(AetherNative.JOB_FREE, job)
                return null
            }
            Thread.sleep(150)
        }
    }

    // --- attempts -------------------------------------------------------------------------------------------------------

    /** One connection attempt: a new session under the tunnel (the first one also brings up hev and the tunnel) */
    private fun startAttempt() {
        if (closed || paused) return
        attempts++
        if (attempts > 1 || up) ConnectionLog.m("Aether: connection attempt $attempts")
        when {
            privateMode -> startPrivate()
            torMode == "only" -> startTorOnly()
            else -> startWarp()
        }
    }

    /** Retry Times: before the first connection 1 attempt, or 1 + Retry Times with Auto Reconnect; after a drop Retry Times
     *  attempts (0 = no limit), one without Auto Reconnect (a wake from Pause) */
    private fun attemptBudget(): Int = when {
        !up -> if (autoReconnect && retryTimes > 0) 1 + retryTimes else 1
        !autoReconnect -> 1
        else -> if (retryTimes > 0) retryTimes else Int.MAX_VALUE
    }

    private fun attemptFailed(reason: String) {
        if (closed) return
        stopSession()
        if (paused) return
        if (attempts < attemptBudget()) {
            ConnectionLog.m("Aether: attempt $attempts failed: $reason; trying again in $RETRY_DELAY_S seconds")
            val number = generation
            worker.postDelayed({ if (number == generation) startAttempt() }, RETRY_DELAY_S * 1000L)
            return
        }
        fail(if (attempts > 1) "Could not ${if (up) "reconnect" else "connect"} after $attempts attempts. ($reason)" else reason)
    }

    /** A working session stopped working: Auto Reconnect sets up a new one, otherwise the VPN ends with the reason */
    private fun sessionLost(reason: String) {
        if (closed || paused || !up) return
        ConnectionLog.m("Aether: $reason")
        stopSession()
        if (!autoReconnect) {
            fail("$reason (auto reconnect is off).")
            return
        }
        attempts = 0
        startAttempt()
    }

    /** A new session works: the first one brings up hev and the tunnel, later ones take over */
    private fun sessionWorks(what: String): Boolean {
        if (!up) {
            val conf = hevConfig()
            var started = -1
            val problem = host.applyTunnelSettings(if (privateMode || torMode == "only") MAPPED_DNS_SETTINGS else WARP_SETTINGS) { fd ->
                started = AetherNative.hevStart(conf, fd)
            }
            if (problem != null || started != 0) {
                fail(if (problem != null) "The tunnel could not be set up: $problem" else "Aether: the packet bridge failed to start")
                return false
            }
            ConnectionLog.m("Aether: session established ($what)")
            host.onConnected()
        } else {
            ConnectionLog.m("Aether: connected again (attempt $attempts)")
        }
        up = true
        attempts = 0
        sessionStart = SystemClock.elapsedRealtime()
        startMonitor()
        startProbe()
        return true
    }

    /** Ends the session under the tunnel (the engine's job, or the relay to the user's server) and its checks */
    private fun stopSession() {
        generation++
        probeFailures = 0
        if (tunnelJob != 0L) {
            val job = tunnelJob
            tunnelJob = 0
            call(AetherNative.JOB_CANCEL, job)
            val deadline = SystemClock.elapsedRealtime() + 15000
            while (call(AetherNative.JOB_POLL, job).optString("state") != "done" && SystemClock.elapsedRealtime() < deadline) Thread.sleep(100)
            call(AetherNative.JOB_FREE, job)
        }
        if (relay >= 0) {
            WireGuardNative.netstackStop(relay)
            relay = -1
        }
    }

    // --- WARP (MASQUE or WireGuard), Tor ------------------------------------------------------------------------------

    private fun startWarp() {
        if (torMode == "reverse") {
            File(identityDir, "tor").mkdirs()
            AetherNative.setenv("AETHER_TOR_DIR", File(identityDir, "tor").path)
            if (!transport.startsWith("masque")) ConnectionLog.m("Aether: tor-reverse needs MASQUE H2 — overriding the selected transport")
            transport = "masque-h2"
        }
        val wireGuard = transport == "wg"
        val engineTransport = if (wireGuard) "wg" else "masque"
        if (!wireGuard) configureCarrier(transport != "masque")
        if (identityId == 0L) {
            identityDir.mkdirs()
            val payload = JSONObject().put("path", File(identityDir, "identity.toml").path).put("transport", engineTransport)
                .put("model", "PC").put("locale", "en").toString()
            val job = startJob(AetherNative.IDENTITY_OPEN, 0, payload)
            val opened = if (job != 0L) waitJob(job, 120) else null
            if (opened == null) {
                attemptFailed("Aether: identity provisioning failed (network unreachable?)")
                return
            }
            identityId = opened.optLong("identity")
            ConnectionLog.m("Aether: identity ready (id $identityId)")
            if (profile.aetherLicense.isNotBlank()) applyWarpLicense(profile.aetherLicense.trim(), engineTransport)
        }
        if (wireGuard) {
            val endpoint = findEndpoint(false)
            if (endpoint == null) {
                attemptFailed("Aether: no reachable WireGuard endpoint found")
                return
            }
            startWireGuard(endpoint)
            return
        }
        val carriers = if (torMode == "reverse" || transport == "masque-h2") listOf(true) else if (transport == "masque-both") listOf(false, true) else listOf(false)
        for (h2 in carriers) {
            if (closed) return
            configureCarrier(h2)
            val endpoint = findEndpoint(h2)
            if (endpoint != null && startMasque(endpoint, h2)) return
            stopSession()
            if (h2 != carriers.last() && !closed) ConnectionLog.m("Aether: MASQUE H3 unavailable — falling back to H2")
        }
        attemptFailed("Aether: no reachable MASQUE endpoint or the tunnel data-plane did not come up")
    }

    private fun configureCarrier(h2: Boolean) {
        AetherNative.setenv("AETHER_MASQUE_HTTP2", if (h2) "1" else null)
        val fragment = h2 && profile.tlsFragMode > 0
        AetherNative.setenv("AETHER_MASQUE_H2_FRAGMENT", if (fragment) "1" else null)
        val manual = fragment && profile.tlsFragMode == 2 && profile.tlsFragFirst > 0 && profile.tlsFragFollowing >= profile.tlsFragFirst
        AetherNative.setenv("AETHER_MASQUE_H2_FRAGMENT_SIZE", if (manual) "${profile.tlsFragFirst}-${profile.tlsFragFollowing}" else null)
        AetherNative.setenv("AETHER_MASQUE_H2_FRAGMENT_SNI", if (fragment && !manual) "1" else null)
    }

    /** The last good endpoint and Cloudflare's two known ones are checked first; otherwise the engine scans */
    private fun findEndpoint(h2: Boolean): String? {
        if (torMode == "reverse") return "162.159.198.2:443"
        val wireGuard = transport == "wg"
        val engineTransport = if (wireGuard) "wg" else "masque"
        val key = if (wireGuard) "lastGoodWG" else if (h2) "lastGoodH2" else "lastGoodH3"
        val candidates = mutableListOf("162.159.198.2:443", "162.159.198.1:443")
        lastGood.getString(key, null)?.takeIf { it.isNotEmpty() && it !in candidates }?.let { candidates.add(0, it) }
        val verifySeconds = if (transport == "masque-both" && !h2) 10 else 20
        for (candidate in candidates) {
            if (closed) return null
            val job = startJob(AetherNative.VERIFY_START, identityId, JSONObject().put("peer", candidate).put("transport", engineTransport).toString())
            val verified = if (job != 0L) waitJob(job, verifySeconds) else null
            if (verified?.optBoolean("reachable") == true) {
                ConnectionLog.m("Aether: verified ${if (h2) "H2" else if (wireGuard) "WG" else "H3"} endpoint $candidate (fast path)")
                lastGood.edit().putString(key, candidate).apply()
                return candidate
            }
        }
        val mode = profile.aetherScan.ifEmpty { "balanced" }
        val job = startJob(AetherNative.SCAN_START, identityId, JSONObject().put("transport", engineTransport).put("mode", mode).toString())
        val scanned = if (job != 0L) waitJob(job, if (mode == "turbo") 90 else 240) else null
        val endpoint = when (val found = scanned?.opt("endpoint")) {
            is String -> found
            is JSONObject -> "${found.optString("ip")}:${found.optInt("port")}"
            else -> null
        }?.takeIf { it.isNotEmpty() } ?: return null
        ConnectionLog.m("Aether: ${if (h2) "H2" else if (wireGuard) "WG" else "H3"} endpoint $endpoint ($mode scan)")
        lastGood.edit().putString(key, endpoint).apply()
        return endpoint
    }

    private fun startMasque(endpoint: String, h2: Boolean): Boolean {
        val payload = JSONObject().put("peer", endpoint).put("transport", "masque").put("socks", "127.0.0.1:$SOCKS_PORT")
        if (torMode == "reverse") payload.put("tor", "reverse")
        tunnelJob = startJob(AetherNative.TUNNEL_START, identityId, payload.toString())
        if (tunnelJob == 0L) return false
        socksPort = SOCKS_PORT
        if (!waitSocksReady(if (torMode == "reverse") 180 else 60)) return false
        if (!sessionWorks("MASQUE ${if (h2) "H2" else "H3"}")) return false
        return true
    }

    private fun startTorOnly() {
        File(identityDir, "tor").mkdirs()
        AetherNative.setenv("AETHER_TOR_DIR", File(identityDir, "tor").path)
        val payload = JSONObject().put("peer", "127.0.0.1:443").put("transport", "masque").put("socks", "127.0.0.1:$SOCKS_PORT").put("tor", "only")
        tunnelJob = startJob(AetherNative.TUNNEL_START, 0, payload.toString())
        if (tunnelJob == 0L) {
            attemptFailed("Aether: the Tor job did not start")
            return
        }
        socksPort = SOCKS_PORT
        ConnectionLog.m("Aether: tor-only — bootstrapping Tor (can take a minute on first run)")
        if (!waitSocksReady(180)) {
            attemptFailed("Aether: Tor did not come up in time")
            return
        }
        sessionWorks("tor-only")
    }

    /** WARP's WireGuard: the identity file holds its keys and addresses, and the WireGuard client drives the tunnel with the
     *  profile's options (its own handshake check, reconnects and sleep handling) */
    private fun startWireGuard(endpoint: String) {
        val toml = runCatching { File(identityDir, "identity.toml").readText() }.getOrDefault("")
        fun value(key: String) = Regex("^\\s*$key\\s*=\\s*\"?([^\"\\n]*)\"?\\s*$", RegexOption.MULTILINE).find(toml)?.groupValues?.get(1)?.trim().orEmpty()
        val privateKey = value("wg_private_key")
        val peerKey = value("wg_peer_public_key")
        val ipv4 = value("ipv4")
        val ipv6 = value("ipv6")
        if (privateKey.isEmpty() || peerKey.isEmpty() || ipv4.isEmpty()) {
            fail("Aether: the identity file is missing the WireGuard keys")
            return
        }
        val conf = "[Interface]\nPrivateKey = $privateKey\nAddress = $ipv4/32${if (ipv6.isNotEmpty()) ", $ipv6/128" else ""}\nDNS = 1.1.1.1, 1.0.0.1\n\n" +
            "[Peer]\nPublicKey = $peerKey\nEndpoint = $endpoint\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
        val warp = Profile(protocolType = "wireguard", desc = profile.desc, server = "", port = "", wgConfig = conf,
            autoReconnect = autoReconnect, retryTimes = retryTimes, onSleep = onSleep, logLevel = logLevel)
        val client = WireGuardClient(warp, connectivity, host)
        wgClient = client
        client.start()
    }

    // --- Private mode -------------------------------------------------------------------------------------------------

    private fun startPrivate() {
        val text = profile.wgEffectiveConfig()
        if (text.isNullOrEmpty()) {
            fail("Aether private mode needs a WireGuard configuration (Server, Port and the keys under Manual Configuration).")
            return
        }
        val (conf, error) = WireGuardConf.parse(text)
        if (conf == null) {
            fail("Aether private: ${error ?: "invalid WireGuard config"}")
            return
        }
        val address = conf.addresses.map { it.substringBefore('/') }.firstOrNull { ProbePackets.ipv4(it) != null }
        if (address == null) {
            fail("Aether private: the interface address must be IPv4")
            return
        }
        val endpointIp = runCatching { InetAddress.getAllByName(conf.endpointHost).firstOrNull { it is Inet4Address }?.hostAddress }.getOrNull()
        if (endpointIp == null) {
            attemptFailed("Aether private: The WireGuard endpoint ${conf.endpointHost} could not be resolved.")
            return
        }
        // The same checks and words as the iPhone's (SRPWireGuardClient netstackParametersFromConfig)
        if (WireGuardConf.base64ToHex(conf.privateKey) == null || WireGuardConf.base64ToHex(conf.peerPublicKey) == null) {
            fail("Aether private: Invalid WireGuard config: a key is not valid base64 (32 bytes).")
            return
        }
        if (conf.presharedKey.isNotEmpty() && WireGuardConf.base64ToHex(conf.presharedKey) == null) {
            fail("Aether private: Invalid WireGuard config: the PresharedKey is not valid base64 (32 bytes).")
            return
        }
        val uapi = conf.uapi(endpointIp)
        if (uapi == null) {
            fail("Aether private: invalid WireGuard config")
            return
        }
        val target = address.substringBeforeLast('.') + ".1:$SOCKS_PORT"
        relayLogThread
        relay = WireGuardNative.netstackStart(uapi, address, "127.0.0.1:$RELAY_PORT", target)
        if (relay < 0) {
            fail("Aether private: the WireGuard relay failed to start")
            return
        }
        socksPort = RELAY_PORT
        ConnectionLog.m("Aether private: WG relay up — $target via $endpointIp")
        // Through a WireGuard that gets no handshake the relay's connection to the proxy never completes (a timeout); a server
        // that answers but has no proxy on the port refuses it at once, and the relay closes the test connection
        if (!waitSocksReady(30)) {
            attemptFailed(if (socksClosed) "Aether private: the server answers over WireGuard, but its Aether proxy (port $SOCKS_PORT on " +
                "${target.substringBefore(':')}) refused the connection: is the aether container running?"
                else "Aether private: the server did not answer the WireGuard handshake: the server's public key or the preshared key may " +
                "not match, the server may not have this profile's public key as a peer, or UDP port ${conf.endpointPort} may be closed.")
            return
        }
        sessionWorks("private")
    }

    /** End-to-end readiness: test connections through the SOCKS5 port until one goes through, the job ends or time runs out */
    private fun waitSocksReady(timeoutSec: Int): Boolean {
        socksClosed = false
        val deadline = SystemClock.elapsedRealtime() + timeoutSec * 1000L
        while (!closed && !closing) {
            if (tunnelJob != 0L && call(AetherNative.JOB_POLL, tunnelJob).optString("state") == "done") {
                ConnectionLog.m("Aether: tunnel ended while waiting for SOCKS5")
                return false
            }
            when (AetherNative.socksProbe(socksPort, 10)) {
                1 -> {
                    ConnectionLog.m("Aether: socks5 end-to-end connect test succeeded")
                    return true
                }
                0 -> socksClosed = true
            }
            if (SystemClock.elapsedRealtime() > deadline) return false
            Thread.sleep(300)
        }
        return false
    }

    // --- the engine's job, test connections, the network ----------------------------------------------------------------

    private fun startMonitor() {
        val number = generation
        worker.postDelayed(object : Runnable {
            override fun run() {
                if (number != generation || closed || tunnelJob == 0L) return
                val job = tunnelJob
                if (call(AetherNative.JOB_POLL, job).optString("state") == "done") {
                    tunnelJob = 0
                    call(AetherNative.JOB_FREE, job)
                    sessionLost(if (torMode == "only") "The Tor session ended" else "The WARP session ended")
                    return
                }
                worker.postDelayed(this, 5000)
            }
        }, 5000)
    }

    private fun startProbe() {
        val number = generation
        probeFailures = 0
        bytesAtLastProbe = AetherNative.hevBytes().getOrElse(1) { 0 }
        worker.postDelayed(object : Runnable {
            override fun run() {
                if (number != generation || closed || paused) return
                probe()
                worker.postDelayed(this, PROBE_SECONDS * 1000L)
            }
        }, PROBE_SECONDS * 1000L)
    }

    /** A test connection through the tunnel, waited for on its own thread (the worker keeps serving the rest) */
    private fun probe() {
        if (probing || closed || paused || !up) return
        probing = true
        val number = generation
        val port = socksPort
        val timeout = if (torMode == "off") PROBE_TIMEOUT_S else 30
        Thread({
            val ok = AetherNative.socksProbe(port, timeout) == 1
            worker.post {
                probing = false
                if (number == generation) probeResult(ok)
            }
        }, "srp.aether.probe").start()
    }

    private fun probeResult(ok: Boolean) {
        if (closed || paused) return
        val toPhone = AetherNative.hevBytes().getOrElse(1) { 0 }
        val cameBack = toPhone - bytesAtLastProbe
        bytesAtLastProbe = toPhone
        if (!ok && cameBack >= BUSY_BYTES) {
            // A busy tunnel can fail a test connection (Tor gives a new stream up after 10 seconds on a full circuit); one that
            // brought this much to the phone since the last test still carries traffic
            ConnectionLog.m("Aether: a test connection through the tunnel failed, but ${cameBack / 1024} KB came through it since the last one: not counted")
            return
        }
        if (ok) {
            if (probeFailures > 0) ConnectionLog.m("Aether: the test connection passes again")
            probeFailures = 0
            if (logLevel >= 1) {
                val bytes = AetherNative.hevBytes()
                ConnectionLog.m("Aether: test connection passed; session up ${(SystemClock.elapsedRealtime() - sessionStart) / 1000} s; " +
                    "received ${bytes.getOrElse(1) { 0 }} bytes, sent ${bytes.getOrElse(0) { 0 }} bytes in all")
            }
            return
        }
        probeFailures++
        ConnectionLog.m("Aether: a test connection through the tunnel failed ($probeFailures in a row)")
        if (probeFailures >= 2) {
            sessionLost(when {
                privateMode -> "The server stopped carrying traffic: two test connections through it failed"
                torMode == "only" -> "Tor stopped carrying traffic: two test connections through it failed"
                else -> "Cloudflare WARP stopped carrying traffic: two test connections through it failed"
            })
            return
        }
        val number = generation
        worker.postDelayed({ if (number == generation) probe() }, 3000)
    }

    /** The phone's network: on a change the session is tested at once, so a session the old network carried and the new one
     *  does not is noticed in seconds and set up again on the new network (the WireGuard transport moves its own sockets) */
    private fun startPathMonitor() {
        if (networkCallback != null || closed) return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                val name = if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) "Wi-Fi"
                           else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) "cellular" else "other"
                val previous = pathName
                pathName = name
                if (previous != null && previous != name) networkChanged(name)
            }

            override fun onLost(network: Network) {
                if (pathName != null && pathName != "none") {
                    pathName = "none"
                    networkChanged("none")
                }
            }
        }
        networkCallback = callback
        // The best network that is not a VPN is the one this app's sockets use (its default network is its own VPN)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val request = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
            connectivity.registerBestMatchingNetworkCallback(request, callback, worker)
        } else {
            connectivity.registerDefaultNetworkCallback(callback, worker)
        }
    }

    private fun networkChanged(name: String) {
        if (closed || paused || !up || wgClient != null) return
        ConnectionLog.m("Aether: network changed ($name): testing the session")
        if (name == "none") return   // nothing to test on; the next network brings a test
        probeFailures = 0
        probe()
    }

    private fun stopPathMonitor() {
        networkCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        networkCallback = null
    }

    /** What the tests' path switch does: the same test a network change brings */
    fun switchNetworkPath() {
        worker.post { networkChanged(pathName ?: "other") }
    }

    /** Ends the engine's session (or the relay) as if WARP or the server had closed it: the lifecycle tests */
    fun debugDropSession() {
        worker.post {
            if (tunnelJob != 0L) {
                ConnectionLog.m("Aether: debug: ending the engine's session")
                call(AetherNative.JOB_CANCEL, tunnelJob)
            } else if (relay >= 0) {
                ConnectionLog.m("Aether: debug: ending the WireGuard relay")
                WireGuardNative.netstackStop(relay)
                relay = -1
            }
        }
    }

    // --- WARP+ ------------------------------------------------------------------------------------------------------------

    /** The WARP+ license, best effort (SRPAetherClient applyWarpLicense): PATCH the registration's account with it, then read
     *  the registration back; the applied key is remembered next to the identity, so later connects skip the call */
    private fun applyWarpLicense(license: String, engineTransport: String) {
        Thread({
            runCatching {
                ConnectionLog.m("Aether: WARP+ license apply starting (transport $engineTransport)")
                val names = if (engineTransport == "masque") listOf("identity-masque.toml", "identity.toml") else listOf("identity.toml", "identity-masque.toml")
                val toml = names.map { File(identityDir, it) }.firstOrNull { it.exists() && "device_id" in it.readText() }?.readText().orEmpty()
                fun value(key: String) = Regex("^\\s*$key\\s*=\\s*\"?([^\"\\n]*)\"?\\s*$", RegexOption.MULTILINE).find(toml)?.groupValues?.get(1)?.trim().orEmpty()
                val device = value("device_id")
                val token = value("access_token")
                ConnectionLog.m("Aether: WARP+ apply: identity read, device=${device.ifEmpty { "none" }}")
                if (device.isEmpty() || token.isEmpty()) {
                    ConnectionLog.m("Aether: WARP+ license skipped (identity file has no device_id)")
                    return@runCatching
                }
                val marker = File(identityDir, ".license-$device")
                if (marker.exists() && marker.readText() == license) return@runCatching
                ConnectionLog.m("Aether: WARP+ apply: device $device, patching /account…")
                fun request(method: String, path: String, body: String?): Pair<Int, String> {
                    val connection = java.net.URL("https://api.cloudflareclient.com/v0a4471/reg/$device$path").openConnection() as java.net.HttpURLConnection
                    // HttpURLConnection has no PATCH of its own: its method field takes it
                    if (method == "PATCH") java.net.HttpURLConnection::class.java.getDeclaredField("method").apply { isAccessible = true }.set(connection, method)
                    else connection.requestMethod = method
                    connection.setRequestProperty("Authorization", "Bearer $token")
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.connectTimeout = 15000
                    connection.readTimeout = 15000
                    if (body != null) {
                        connection.doOutput = true
                        connection.outputStream.use { it.write(body.toByteArray()) }
                    }
                    val status = runCatching { connection.responseCode }.getOrDefault(0)
                    val text = runCatching { (if (status in 200..299) connection.inputStream else connection.errorStream)?.bufferedReader()?.readText() }.getOrNull().orEmpty()
                    ConnectionLog.m("Aether: WARP+ $method $path -> http=$status")
                    return status to text
                }
                val (status, _) = request("PATCH", "/account", JSONObject().put("license", license).toString())
                if (status != 200) {
                    ConnectionLog.m("Aether: WARP+ license bind failed (HTTP $status) — continuing with free WARP")
                    return@runCatching
                }
                val (_, body) = request("GET", "", null)
                val type = runCatching { JSONObject(body).getJSONObject("account").optString("account_type") }.getOrDefault("")
                if (type != "unlimited" && type != "plus") {
                    ConnectionLog.m("Aether: WARP+ license not applied (account_type=${type.ifEmpty { "unknown" }}) — continuing with free WARP")
                    return@runCatching
                }
                marker.writeText(license)
                ConnectionLog.m("Aether: WARP+ license bound — account_type=$type")
            }.onFailure { ConnectionLog.m("Aether: WARP+ license bind failed (${it.javaClass.simpleName}) — continuing with free WARP") }
        }, "srp.aether.license").start()
    }

    // --- the end ----------------------------------------------------------------------------------------------------------

    private fun hevConfig(): String {
        val level = if (logLevel >= 2) "debug" else "warn"   // hev names every connection's destination at info
        return if (privateMode || torMode == "only") {
            // Private mode and Tor carry TCP only: DNS is answered by hev's mapped DNS (fake addresses; connections carry the name).
            // The fake addresses come from 198.19.0.0/16: hev hands them out from the network's first address on, and from
            // 198.18.0.0/16 the second name got 198.18.0.1, the tunnel's own address, which Android keeps local (refused)
            "tunnel:\n  mtu: 1400\n  ipv4: 198.18.0.1\nsocks5:\n  port: $socksPort\n  address: '127.0.0.1'\n  udp: 'tcp'\n  pipeline: true\n" +
                "mapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 198.19.0.0\n  netmask: 255.255.0.0\n  cache-size: 2048\n" +
                "misc:\n  log-file: stderr\n  log-level: $level\n"
        } else {
            "tunnel:\n  mtu: 1400\n  ipv4: 10.89.0.1\nsocks5:\n  port: $socksPort\n  address: '127.0.0.1'\n  udp: 'udp'\n  pipeline: true\n" +
                "misc:\n  log-file: stderr\n  log-level: $level\n"
        }
    }

    private fun fail(reason: String) {
        if (closed) return
        ConnectionLog.m("Aether: closing with reason: $reason")
        closeNow()
        host.onFailure(reason)
    }

    private fun closeNow() {
        if (closed) return
        closed = true
        stopPathMonitor()
        if (current === this) current = null
        wgClient?.let {
            // The WireGuard client ends the tunnel and tells the host itself
            wgClient = null
            it.close()
            return
        }
        stopSession()
        AetherNative.hevStop()
        if (current === this) current = null
        host.onClosed()
    }

    init {
        current = this
    }

    companion object {
        private val worker by lazy { Handler(HandlerThread("srp.aether").apply { start() }.looper) }

        @Volatile private var current: AetherClient? = null

        /** The engine's and hev's stderr lines to the connection log */
        private val logThread by lazy {
            AetherNative.captureStderr()
            Thread({
                while (true) {
                    val line = AetherNative.nextLog(1000) ?: continue
                    ConnectionLog.m(line)
                }
            }, "srp.aether.log").apply {
                isDaemon = true
                start()
            }
        }

        /** Private mode's relay lines (libwg-go.so's queue); a WireGuard session of this process reads the same queue */
        private val relayLogThread by lazy {
            Thread({
                while (true) {
                    val line = WireGuardNative.nextLog(1000) ?: continue
                    ConnectionLog.m("[wg-ns] ${line.substring(2)}")
                }
            }, "srp.aether.relay").apply {
                isDaemon = true
                start()
            }
        }

        private const val SOCKS_PORT = 1819
        private const val RELAY_PORT = 18191
        private const val PROBE_SECONDS = 20
        private const val PROBE_TIMEOUT_S = 10
        private const val BUSY_BYTES = 64 * 1024L   // what a working tunnel brings to the phone between two tests while it is busy
        private const val RETRY_DELAY_S = 2
        private const val PING_TIMEOUT_MS = 15000

        // The engine's tunnel address and DNS through WARP, or the mapped-DNS layout of Private mode and Tor (SRPAetherClient buildSettings)
        private val WARP_SETTINGS = TunnelSettings("10.89.0.1", listOf("1.1.1.1", "1.0.0.1"), listOf("0.0.0.0" to 0), 1400)
        private val MAPPED_DNS_SETTINGS = TunnelSettings("198.18.0.1", listOf("198.18.0.2"), listOf("0.0.0.0" to 0), 1400, addressPrefix = 32)

        /** The running client, for the tests' commands */
        fun running(): AetherClient? = current
    }
}
