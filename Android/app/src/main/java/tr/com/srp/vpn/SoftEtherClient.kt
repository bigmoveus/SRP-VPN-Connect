package tr.com.srp.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import java.io.File
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * SRPSoftEtherClient.m and the SoftEther start of PacketTunnelProvider.m on one worker thread: one session at a time in the
 * native core, reconnects as Auto Reconnect and Retry Times allow, the PAC file's entries one after the other, the move to a
 * new Wi-Fi network and the On Sleep modes. A failure that ends the connection goes to the host with the iOS app's message.
 */
class SoftEtherClient(
    private val context: android.content.Context,
    private val profile: Profile,
    private val allowInsecure: Boolean,
    private val certificate: Pair<ByteArray, String>?,
    private val cellular: () -> Boolean,
    private val connectivity: ConnectivityManager,
    private val host: TunnelHost,
) : TunnelClient {
    private val autoReconnect = profile.autoReconnect
    private val maxRetries = profile.retryTimes
    private val onSleep = profile.onSleep

    private var closed = false
    private var started = false
    private var sleepPaused = false
    private var pathSwitching = false
    private var tunnelUp = false
    private var established = false
    /** A session of this connection was up once: from then on reconnects follow Auto Reconnect and Retry Times */
    private var everEstablished = false
    private var failedAttempts = 0
    private var session = 0
    private var generation = 0
    private var tunnelAddress = ""
    private var pacHops: List<SstpConnector.Hop>? = null
    private var pacIndex = 0
    private var lastPathHadWifi = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private var pingCallback: ((Long) -> Unit)? = null
    private var pingPort = 0
    private var pingStarted = 0L
    private var pingHttpStarted = false
    private var pingEpoch = 0

    private val startTimeout = Runnable {
        if (!closed && !started) failWithReason("Connection timed out. The server did not respond.")
    }

    fun start() {
        current = this
        eventThread
        worker.post {
            SoftEther.init(File(context.filesDir, "softether").apply { mkdirs() }.path, true)   // as iOS: the core's progress lines reach the log
            worker.postDelayed(startTimeout, START_TIMEOUT_MS)
            startPathMonitor()
            connect()
        }
    }

    override fun close() {
        worker.post {
            if (closed) return@post
            ConnectionLog.m("SoftEther: disconnecting")
            closeNow()
        }
    }

    override fun pauseForSleep() {
        worker.post {
            if (onSleep == 2 || closed) return@post
            ConnectionLog.m("device sleep: ${if (onSleep == 1) "pausing" else "closing"} the SoftEther connection")
            sleepPaused = true
            endSession()
        }
    }

    override fun wakeFromSleep() {
        worker.post {
            if (!sleepPaused || closed) return@post
            sleepPaused = false
            if (onSleep == 1 || autoReconnect) {
                failedAttempts = 0
                pacHops = null
                ConnectionLog.m("device wake: reconnecting the SoftEther connection")
                connect()
            } else {
                // Off without Auto Reconnect leaves no connection; end the tunnel instead of keeping a VPN that drops every packet.
                failWithReason("The connection was closed while the device slept.")
            }
        }
    }

    /** Times one HTTP request to 1.1.1.1 through the tunnel, as SstpClient does: this app stays outside its own tunnel. */
    override fun measurePing(result: (Long) -> Unit) {
        worker.post {
            if (closed || !started || !established || tunnelAddress.isEmpty()) {
                result(-1)
                return@post
            }
            pingCallback?.invoke(-1)
            pingCallback = result
            pingPort = Random.nextInt(40000) + 20000
            pingHttpStarted = false
            pingStarted = SystemClock.elapsedRealtime()
            val epoch = ++pingEpoch
            SoftEther.setProbeFlows(intArrayOf(ProbePackets.PROTOCOL_TCP, ProbePackets.ipv4Int(PROBE_ADDRESS), pingPort))
            sendPingSyn(epoch)
            worker.postDelayed({ if (epoch == pingEpoch) finishPing(-2) }, PING_TIMEOUT_MS)
        }
    }

    private fun sendPingSyn(epoch: Int) {
        if (epoch != pingEpoch || pingCallback == null || pingHttpStarted || closed) return
        SoftEther.submit(ProbePackets.syn(address(tunnelAddress), address(PROBE_ADDRESS), pingPort))
        worker.postDelayed({ sendPingSyn(epoch) }, 1000)
    }

    private fun finishPing(value: Long) {
        val callback = pingCallback ?: return
        pingCallback = null
        pingEpoch++
        SoftEther.setProbeFlows(IntArray(0))
        callback(value)
    }

    private fun address(text: String) = ProbePackets.ipv4(text) ?: ByteArray(4)

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
        if (flags and 0x12 == 0x12) {
            pingHttpStarted = true
            SoftEther.submit(ProbePackets.httpRequest(address(tunnelAddress), address(PROBE_ADDRESS), pingPort, u32(packet, ihl + 4) + 1))
        }
    }

    private fun u16(bytes: ByteArray, offset: Int) = ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun u32(bytes: ByteArray, offset: Int) = (u16(bytes, offset) shl 16) or u16(bytes, offset + 2)

    // A new session; with Auto proxy the PAC file is read first, on its own thread (it takes the network)
    private fun connect() {
        if (closed || sleepPaused) return
        val attempt = ++session
        established = false
        if (profile.proxyMode == 2 && pacHops == null) {
            ConnectionLog.m("SoftEther: evaluating the PAC file for ${profile.server.trim()}")
            thread(name = "srp.softether.pac") {
                val result = runCatching { SstpConnector.pacHops(profile, profile.server.trim(), context) }
                worker.post {
                    if (attempt != session || closed || sleepPaused) return@post
                    result.onSuccess {
                        pacHops = it
                        pacIndex = 0
                        connect()
                    }.onFailure { failWithReason(it.message ?: "No usable proxy returned by PAC") }
                }
            }
            return
        }
        startEngine()
    }

    private fun startEngine() {
        val authType = when (profile.seAuthMethod) {
            "anonymous" -> 0
            "radiusNT" -> 2
            "certificate" -> 3
            else -> 1
        }
        // TLS write splitting of the ClientHello, SRPSoftEtherClient.m's policy: Auto takes 43-byte first writes and
        // 256-byte following ones 3 ms apart (128 bytes, 10 ms on cellular); Manual the profile's sizes (32 and 256 when empty)
        var first = 0
        var following = 0
        var gap = 0
        when (profile.tlsFragMode) {
            1 -> {
                val onCellular = cellular()
                first = 43
                following = if (onCellular) 128 else 256
                gap = if (onCellular) 10 else 3
                ConnectionLog.m("SoftEther: TLS fragmentation auto (first=$first following=$following gap=$gap ms)")
            }
            2 -> {
                first = profile.tlsFragFirst.takeIf { it > 0 } ?: 32
                following = profile.tlsFragFollowing.takeIf { it > 0 } ?: 256
                gap = 3
                ConnectionLog.m("SoftEther: TLS fragmentation manual (first=$first following=$following gap=$gap ms)")
            }
        }
        // Proxy: 0 none, 1 HTTP CONNECT, 3 SOCKS5 (SRPSEProxyType)
        var proxyType = 0
        var proxyHost = ""
        var proxyPort = 0
        when (profile.proxyMode) {
            1 -> if (profile.proxyAddress.isNotBlank()) {
                proxyType = if (profile.proxyType == "socks5") 3 else 1
                proxyHost = profile.proxyAddress.trim()
                proxyPort = profile.proxyPort.trim().toIntOrNull() ?: 0
            }
            2 -> pacHops?.getOrNull(pacIndex)?.let { hop ->
                if (hop.socks == null) {
                    ConnectionLog.m("SoftEther: PAC entry ${pacIndex + 1} of ${pacHops!!.size}: DIRECT")
                } else {
                    proxyType = if (hop.socks) 3 else 1
                    proxyHost = hop.host
                    proxyPort = hop.port
                    ConnectionLog.m("SoftEther: PAC entry ${pacIndex + 1} of ${pacHops!!.size}: ${if (hop.socks) "SOCKS5" else "HTTP CONNECT"} ${hop.host}:${hop.port}")
                }
            }
        }
        val server = profile.server.trim()
        val port = profile.effectivePort.toIntOrNull() ?: 443
        val hub = profile.hubName.trim().ifEmpty { "DEFAULT" }
        val connections = profile.seConnections.coerceIn(1, 32)
        fun flag(value: Boolean) = if (value) "1" else "0"
        // softether_jni.c's order
        val settings = arrayOf(
            server, port.toString(), hub, profile.hostnameOverride.trim(), profile.username.trim(), profile.password,
            authType.toString(), flag(!allowInsecure), connections.toString(), flag(profile.seUdpAcceleration),
            flag(profile.seNatTraversal), profile.seNatTHint.trim(), proxyType.toString(), proxyHost, proxyPort.toString(),
            profile.proxyUsername, profile.proxyPassword, first.toString(), following.toString(), gap.toString(),
        )
        ConnectionLog.m("SoftEther connecting to $server:$port hub=$hub user=${profile.username.trim()} auth=$authType conns=$connections " +
            "udpAccel=${flag(profile.seUdpAcceleration)} natT=${flag(profile.seNatTraversal)} verify=${flag(!allowInsecure)}")
        SoftEther.setLog(ConnectionLog.path, profile.logLevel)
        val certificateLogin = authType == 3
        val result = SoftEther.start(settings, if (certificateLogin) certificate?.first else null, if (certificateLogin) certificate?.second else null)
        when {
            result == -2 -> failWithReason("The client certificate could not be read. Re-import it in the profile.")
            result <= 0 -> failWithReason("Internal error starting the SoftEther session")
            else -> generation = result
        }
    }

    private fun handleEvent(event: ByteArray) {
        if (event.size < 5 || closed) return
        val eventGeneration = (event[1].toInt() and 0xff) or (event[2].toInt() and 0xff shl 8) or (event[3].toInt() and 0xff shl 16) or (event[4].toInt() and 0xff shl 24)
        if (eventGeneration != generation) return
        val payload = event.copyOfRange(5, event.size)
        when (event[0].toInt()) {
            SoftEther.EVENT_STATE -> strings(payload).let { values -> handleState(values.getOrNull(0)?.toIntOrNull() ?: -1, values.getOrNull(1)?.toIntOrNull() ?: 0) }
            SoftEther.EVENT_CONFIG -> networkUp(strings(payload))
            SoftEther.EVENT_CONFIG6 -> ConnectionLog.m("SoftEther: the hub offered IPv6 (${strings(payload).firstOrNull().orEmpty()}); the Android app routes IPv4 only")
            SoftEther.EVENT_PROBE_PACKET -> handlePingPacket(payload)
        }
    }

    private fun strings(payload: ByteArray): List<String> {
        val texts = ArrayList<String>()
        var start = 0
        for (index in payload.indices) {
            if (payload[index].toInt() == 0) {
                texts += String(payload, start, index - start)
                start = index + 1
            }
        }
        return texts
    }

    // Cedar's CLIENT_STATUS_*: 0 connecting, 1 negotiation, 2 auth, 3 established, 4 retry, 5 the session thread ended
    private fun handleState(status: Int, error: Int) {
        when (status) {
            0 -> info("SoftEther: connecting")
            1 -> info("SoftEther: negotiation")
            2 -> info("SoftEther: authenticating")
            3 -> {
                ConnectionLog.m("SoftEther: session established")
                established = true
                everEstablished = true
                failedAttempts = 0
                reportConnected()
            }
            4 -> info("SoftEther: retry wait")
            5 -> sessionEnded(error)
        }
    }

    private fun networkUp(values: List<String>) {
        if (values.size < 4) return
        tunnelAddress = values[0]
        val dns = values[3].split(',').map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { listOf("1.1.1.1", "8.8.8.8") }
        ConnectionLog.m("SoftEther: network settings ip=${values[0]} mask=${values[1]} gw=${values[2]} dns=${dns.joinToString(", ")}")
        val problem = host.applyTunnelSettings(TunnelSettings(values[0], dns, listOf("0.0.0.0" to 0), MTU)) { SoftEther.attachTun(it) }
        if (problem != null) {
            failWithReason("SoftEther network settings failed: $problem")
            return
        }
        tunnelUp = true
        reportConnected()
    }

    private fun reportConnected() {
        if (!tunnelUp || !established) return
        if (!started) {
            started = true
            worker.removeCallbacks(startTimeout)
            ConnectionLog.m("SoftEther: connected")
        }
        host.onConnected()
    }

    /** The end of a session (SRPSoftEtherClient.m handleState: 5): the next PAC entry, a reconnect, or the end. */
    private fun sessionEnded(error: Int) {
        val wasUp = tunnelUp
        established = false
        if (closed || sleepPaused || pathSwitching) return
        tunnelUp = false
        if (profile.proxyMode == 2) {
            // A PAC entry that could not be reached moves on to the next one, as browsers do; a session that was up evaluates
            // the PAC file again on its next connection
            val unreachable = error == 1 || error == 13 || error == 17 || error == 18
            val hops = pacHops
            if (!wasUp && unreachable && hops != null && pacIndex + 1 < hops.size) {
                pacIndex++
                ConnectionLog.m("SoftEther: ${describe(error)}; trying the next PAC entry")
                connect()
                return
            }
            if (wasUp) pacHops = null
        }
        // Authentication and certificate errors are never retried: the profile must be fixed first
        val fatal = error == 9 || error == 7 || error == 8 || error == 85 || error == 106 || error == 149
        if (!wasUp && fatal) {
            failWithReason(describe(error))
            return
        }
        if (!autoReconnect) {
            failWithReason(if (wasUp) "Connection lost (auto reconnect is off)." else describe(error))
            return
        }
        if (!wasUp && !everEstablished) {
            // Never up (DNS, TCP or TLS failed): fail at once unless Retry Times allows more attempts
            if (!(maxRetries > 0 && attemptAllowed(failedAttempts, maxRetries))) {
                failWithReason(describe(error))
                return
            }
        } else if (!attemptAllowed(failedAttempts, maxRetries)) {
            failWithReason("Could not reconnect after $maxRetries attempts. (${describe(error)})")
            return
        }
        failedAttempts++
        ConnectionLog.m("SoftEther: connection ended (${describe(error)}); reconnecting in 2s (attempt $failedAttempts${if (maxRetries > 0) " of $maxRetries" else ""})")
        val attempt = session
        worker.postDelayed({ if (attempt == session && !closed && !sleepPaused) connect() }, 2000)
    }

    /** SRPSoftEtherClient.m describeError: */
    private fun describe(error: Int) = when (error) {
        9 -> "Authentication failed. Check the username, password and authentication method."
        8 -> "Virtual Hub not found. Check the Virtual Hub field."
        85 -> "The server certificate is not trusted. Enable verification only with a valid certificate, or check the Hostname field."
        106 -> "The server certificate has expired."
        149 -> "The server certificate name does not match the server. Check the Hostname field."
        1 -> "Cannot reach the server (DNS lookup or TCP connection failed). Check the Server field for typos and the network connection."
        2 -> "The server did not answer as a SoftEther VPN server. Check the Server and Port fields."
        3 -> "The connection to the server was closed."
        150 -> "The server and the app have no TLS version in common."
        151 -> "The server and the app have no TLS cipher in common."
        152 -> "The TLS handshake with the server failed. Check the Server and Port fields."
        13 -> "Connection timed out."
        17 -> "Cannot connect to the proxy server."
        19 -> "Proxy authentication failed."
        else -> "SoftEther error $error: ${SoftEther.errorName(error)}"
    }

    private fun attemptAllowed(failed: Int, limit: Int) = limit <= 0 || failed < limit

    /** A step that the iOS app logs at Info level: Expert and Debug show it. */
    private fun info(message: String) {
        if (profile.logLevel >= 1) ConnectionLog.m(message)
    }

    /** Ends the running session; its end event no longer counts. */
    private fun endSession() {
        session++
        generation = 0
        established = false
        tunnelUp = false
        finishPing(-1)
        SoftEther.stop()
    }

    private fun startPathMonitor() {
        if (!profile.switchToWifi || closed) return
        lastPathHadWifi = false
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                val hasWifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                val hadWifi = lastPathHadWifi
                lastPathHadWifi = hasWifi
                // Only an established tunnel moves, and only when Wi-Fi newly appeared (SSShouldReconnectForPathChange)
                if (!hadWifi && hasWifi && tunnelUp && !closed && !sleepPaused && !pathSwitching) {
                    ConnectionLog.m("Wi-Fi became available; switching the SoftEther connection to the new path")
                    // A migration, not a failure: it is not governed by Auto Reconnect
                    pathSwitching = true
                    failedAttempts = 0
                    pacHops = null   // the new network may get another answer from the PAC file
                    endSession()
                    pathSwitching = false
                    connect()
                }
            }
        }
        networkCallback = callback
        // This app stays outside its own tunnel, so its default network is the real one.
        connectivity.registerDefaultNetworkCallback(callback, worker)
    }

    private fun stopPathMonitor() {
        networkCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        networkCallback = null
    }

    private fun failWithReason(reason: String) {
        ConnectionLog.m("SoftEther: closing with reason: $reason")
        closeNow()
        host.onFailure(reason)
    }

    private fun closeNow() {
        if (closed) return
        closed = true
        worker.removeCallbacks(startTimeout)
        stopPathMonitor()
        endSession()
        SoftEther.attachTun(-1)
        if (current === this) current = null
        host.onClosed()
    }

    companion object {
        private val worker by lazy { Handler(HandlerThread("srp.softether").apply { start() }.looper) }

        @Volatile private var current: SoftEtherClient? = null

        private val eventThread by lazy {
            Thread({
                while (true) {
                    val event = SoftEther.nextEvent(1000) ?: continue
                    current?.let { client -> worker.post { client.handleEvent(event) } }
                }
            }, "srp.softether.events").apply {
                isDaemon = true
                start()
            }
        }

        /** The virtual Ethernet's IP MTU, as on iOS */
        const val MTU = 1500
        private const val PROBE_ADDRESS = "1.1.1.1"
        private const val START_TIMEOUT_MS = 30000L
        private const val PING_TIMEOUT_MS = 15000L
    }
}
