package tr.com.srp.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import java.net.Socket
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * The connection logic of lwIP.m and the SSTP start of PacketTunnelProvider.m on one worker thread: one SSTP session at a
 * time in the native engine, reconnects as Auto Reconnect and Retry Times allow, the TLS 1.2 retry for NPS, the move to a
 * new Wi-Fi network and the On Sleep modes. A failure that ends the connection goes to the host with the iOS app's message.
 */
class SstpClient(
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
    private var authFailed = false
    private var eapTls13Fallback = false
    // Windows and FreeRADIUS hash an MS-CHAP password as UTF-16, SoftEther and pppd byte by byte: a password with
    // characters outside ASCII that a server refused as UTF-16 gets one more attempt the other way (srp_utf16le.h)
    private var mschapBytewise = false
    private var linkEverEstablished = false
    private var connectionEstablished = false
    private var networkReady = false
    private var failedAttempts = 0
    private var session = 0
    private var generation = 0
    private var connecting: Socket? = null
    private var tunnelAddress = ""
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
            ConnectionLog.m("SSTP: connecting to ${profile.server.trim()}:${profile.effectivePort}")
            worker.postDelayed(startTimeout, START_TIMEOUT_MS)
            startPathMonitor()
            connect()
        }
    }

    override fun close() {
        worker.post {
            if (closed) return@post
            ConnectionLog.m("SSTP: disconnecting")
            closeNow()
        }
    }

    /** close the SSTP session on sleep; pause reconnects on wake, off drops the connection (reconnect on wake only with Auto Reconnect) */
    override fun pauseForSleep() {
        worker.post {
            if (onSleep == 2 || closed) return@post
            ConnectionLog.m("device sleep: ${if (onSleep == 1) "pausing" else "closing"} the SSTP connection")
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
                ConnectionLog.m("device wake: reconnecting the SSTP connection")
                connect()
            } else {
                // Off without Auto Reconnect leaves no connection; end the tunnel instead of keeping a VPN that silently drops every packet.
                failWithReason("The connection was closed while the device slept.")
            }
        }
    }

    /** Times one HTTP request to 1.1.1.1 through the tunnel, as WaterWallClient does: this app stays outside its own tunnel. */
    override fun measurePing(result: (Long) -> Unit) {
        worker.post {
            if (closed || !started || !connectionEstablished || tunnelAddress.isEmpty()) {
                result(-1)
                return@post
            }
            pingCallback?.invoke(-1)
            pingCallback = result
            pingPort = Random.nextInt(40000) + 20000
            pingHttpStarted = false
            pingStarted = SystemClock.elapsedRealtime()
            val epoch = ++pingEpoch
            Sstp.setProbeFlows(intArrayOf(ProbePackets.PROTOCOL_TCP, ProbePackets.ipv4Int(PROBE_ADDRESS), pingPort))
            sendPingSyn(epoch)
            worker.postDelayed({ if (epoch == pingEpoch) finishPing(-2) }, PING_TIMEOUT_MS)
        }
    }

    private fun sendPingSyn(epoch: Int) {
        if (epoch != pingEpoch || pingCallback == null || pingHttpStarted || closed) return
        Sstp.submit(ProbePackets.syn(address(tunnelAddress), address(PROBE_ADDRESS), pingPort))
        worker.postDelayed({ sendPingSyn(epoch) }, 1000)
    }

    private fun finishPing(value: Long) {
        val callback = pingCallback ?: return
        pingCallback = null
        pingEpoch++
        Sstp.setProbeFlows(IntArray(0))
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
            Sstp.submit(ProbePackets.httpRequest(address(tunnelAddress), address(PROBE_ADDRESS), pingPort, u32(packet, ihl + 4) + 1))
        }
    }

    private fun u16(bytes: ByteArray, offset: Int) = ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun u32(bytes: ByteArray, offset: Int) = (u16(bytes, offset) shl 16) or u16(bytes, offset + 2)

    // A new session: the outer connection on the connect thread (proxy and DNS take the network), then the engine
    private fun connect() {
        if (closed || sleepPaused) return
        val attempt = ++session
        connectionEstablished = false
        networkReady = false
        val serverHost = profile.server.trim()
        val port = profile.effectivePort.toIntOrNull() ?: 443
        thread(name = "srp.sstp.connect") {
            val socket = try {
                SstpConnector.connect(profile, serverHost, port, context) { closed || attempt != session }
            } catch (failure: SstpConnectFailure) {
                worker.post { if (attempt == session && !closed) sessionEnded(attempt, connectFailure = failure.message) }
                return@thread
            }
            worker.post {
                if (attempt != session || closed || sleepPaused) {
                    runCatching { socket.close() }
                    return@post
                }
                startEngine(attempt, socket)
            }
        }
    }

    private fun startEngine(attempt: Int, socket: Socket) {
        val fd = ParcelFileDescriptor.fromSocket(socket).detachFd()
        runCatching { socket.close() }
        val sni = if (profile.customSniEnabled && profile.customSni.trim().isNotEmpty()) profile.customSni.trim() else profile.server.trim()
        val eap = profile.eap
        fun flag(value: Boolean) = if (value) "1" else "0"
        // SstpClient's order, the keys of sstp_jni.c
        val settings = arrayOf(
            profile.server.trim(), sni, profile.username, profile.password,
            flag(profile.allowLegacyPapChap), flag(profile.allowLegacyPapChap), flag(profile.mschap2),
            flag(eap.eapMschapv2Enabled), flag(eap.peapEnabled), flag(eap.peapRequireCryptoBinding), flag(eap.ttlsInnerMethod != 0),
            ttlsInnerName(eap.ttlsInnerMethod), flag(eap.teapEnabled), flag(eap.identityPrivacyEnabled), eap.anonymousIdentity,
            flag(eap.eapTls13Enabled && !eapTls13Fallback), flag(eap.disableLegacyEapTls), flag(allowInsecure), flag(profile.disableLegacyOuterTls),
            profile.tlsFragMode.toString(), profile.tlsFragFirst.toString(), profile.tlsFragFollowing.toString(), flag(cellular()),
            flag(mschapBytewise), flag(mschapRetryArmed()),
        )
        Sstp.setLog(ConnectionLog.path, profile.logLevel)
        val started = Sstp.start(fd, settings, if (profile.certificateMode) certificate?.first else null, if (profile.certificateMode) certificate?.second else null)
        if (started == 0) {
            sessionEnded(attempt, connectFailure = "The SSTP engine could not start.")
            return
        }
        generation = started
    }

    private fun handleEvent(event: ByteArray) {
        if (event.size < 5 || closed) return
        val eventGeneration = (event[1].toInt() and 0xff) or (event[2].toInt() and 0xff shl 8) or (event[3].toInt() and 0xff shl 16) or (event[4].toInt() and 0xff shl 24)
        if (eventGeneration != generation) return
        val payload = event.copyOfRange(5, event.size)
        when (event[0].toInt()) {
            Sstp.EVENT_ESTABLISHED -> {
                failedAttempts = 0   // a working connection resets the retry budget
                linkEverEstablished = true
                connectionEstablished = true
                reportConnected()
            }
            Sstp.EVENT_NETWORK_UP -> networkUp(strings(payload))
            Sstp.EVENT_LINK_FAILURE -> if (!sleepPaused && !pathSwitching) linkFailure(strings(payload).firstOrNull().orEmpty())
            Sstp.EVENT_SESSION_END -> sessionEnded(session, report = strings(payload))
            Sstp.EVENT_PROBE_PACKET -> handlePingPacket(payload)
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

    private fun networkUp(values: List<String>) {
        if (values.size < 4) return
        tunnelAddress = values[0]
        val dns = listOf(values[2], values[3]).filter { it.isNotEmpty() }.ifEmpty { listOf("1.1.1.1") }
        ConnectionLog.m("SSTP: tunnel address ${values[0]}, DNS ${dns.joinToString(", ")}")
        // PPP MRU is typically 1500 — larger frames are dropped by the server
        val problem = host.applyTunnelSettings(TunnelSettings(values[0], dns, listOf("0.0.0.0" to 0), MTU)) { Sstp.attachTun(it) }
        if (problem != null) {
            failWithReason("SSTP network settings failed: $problem")
            return
        }
        networkReady = true
        reportConnected()
    }

    private fun reportConnected() {
        if (!networkReady || !connectionEstablished) return
        if (!started) {
            started = true
            worker.removeCallbacks(startTimeout)
            ConnectionLog.m("SSTP: connected")
        }
        host.onConnected()
    }

    // The server refused the credentials or PPP failed before the link came up: lwIP.m's failure callback ends the VPN
    /** A refusal now gets one more attempt with the password hashed byte by byte (not after the link was up once) */
    private fun mschapRetryArmed() = !mschapBytewise && !linkEverEstablished && !profile.certificateMode && profile.password.any { it.code > 127 }

    private fun linkFailure(reason: String) {
        if (reason.isEmpty() || closed) return
        if (reason.startsWith("Authentication failed") || reason.startsWith("The EAP server")) authFailed = true
        failWithReason(reason)
    }

    /**
     * The end of a session (lwIP.m tcpClient:didChangeState: with a disconnect). [report] is the engine's: flags (was the
     * call up, did PPP start, authentication failed, TLS 1.3 refused, furthest phase), connection error, link failure,
     * certificate refusal, authentication message and SSTP reason; [connectFailure] means the outer connection never came up.
     */
    private fun sessionEnded(attempt: Int, report: List<String>? = null, connectFailure: String? = null) {
        if (attempt != session || closed) return
        val flags = report?.getOrNull(0).orEmpty()
        val wasEstablished = flags.getOrNull(0) == '1'
        val pppStarted = flags.getOrNull(1) == '1'
        val authFail = flags.getOrNull(2) == '1'
        val tls13Refused = flags.getOrNull(3) == '1'
        val pppPhase = flags.drop(4).toIntOrNull() ?: 0
        val connectionError = connectFailure ?: report?.getOrNull(1).orEmpty()
        val certificateRefusal = report?.getOrNull(3).orEmpty().ifEmpty { null }
        val authMessage = report?.getOrNull(4).orEmpty()
        report?.getOrNull(5)?.takeIf { it.isNotEmpty() }?.let { ConnectionLog.m("SSTP: the call ended: $it") }
        if (connectionError.isNotEmpty()) ConnectionLog.m("SSTP: $connectionError")
        connectionEstablished = false
        networkReady = false
        if (pathSwitching || sleepPaused) return
        if (tls13Refused && !eapTls13Fallback && !wasEstablished) {
            // Microsoft NPS has no TLS 1.3 for EAP and ends the exchange on a TLS 1.3 offer before any credential is
            // checked; the same server takes a TLS 1.2 offer
            eapTls13Fallback = true
            authFailed = false
            ConnectionLog.m("EAP: the server ended the TLS handshake of a TLS 1.3 offer; retrying with TLS 1.2")
            worker.postDelayed({ if (attempt == session) connect() }, 1000)
            return
        }
        val authFailure = if (pppStarted && authFail) certificateRefusal ?: authMessage.ifEmpty { "Authentication failed. The server rejected the username or password." } else null
        if (authFailure != null && !authFailed && certificateRefusal == null && mschapRetryArmed()) {
            mschapBytewise = true
            ConnectionLog.m("MS-CHAP: the server refused the password hashed as UTF-16; retrying with it hashed byte by byte")
            worker.postDelayed({ if (attempt == session) connect() }, 1000)
            return
        }
        if (authFailure != null && !authFailed) {
            // Do not retry: the credentials or the certificate must be fixed first
            authFailed = true
            failWithReason(authFailure)
            return
        }
        if (authFailed) {
            ConnectionLog.m("skipping reconnect after authentication failure")
            return
        }
        if (!wasEstablished && !linkEverEstablished) {
            if (pppStarted) {
                // The server ended PPP before the first link came up, which a retry does not change
                failWithReason(certificateRefusal ?: reasonForServerClose(pppPhase))
                return
            }
            // Never reached PPP: with a retry limit, retry up to Retry Times before giving up; otherwise fail at once
            if (autoReconnect && maxRetries > 0 && attemptAllowed(failedAttempts, maxRetries)) {
                failedAttempts++
                ConnectionLog.m("connect failed; retry $failedAttempts of $maxRetries in 2s")
                worker.postDelayed({ if (attempt == session) connect() }, 2000)
                return
            }
            failWithReason(when {
                // Proxy and TLS failures carry their own reason
                connectionError.isNotEmpty() && connectionError != DIRECT_FAILURE -> connectionError
                failedAttempts > 0 -> "Cannot reach the server after ${failedAttempts + 1} attempts. Check the host, port and certificate settings."
                else -> DIRECT_FAILURE
            })
            return
        }
        // The tunnel was up (now or before a reconnect): Auto Reconnect and Retry Times decide
        if (!autoReconnect) {
            failWithReason("Connection lost (auto reconnect is off).")
            return
        }
        if (!attemptAllowed(failedAttempts, maxRetries)) {
            failWithReason("Could not reconnect after $maxRetries attempts. Giving up.")
            return
        }
        failedAttempts++
        if (maxRetries > 0) ConnectionLog.m("connection dropped; retry $failedAttempts of $maxRetries in 2s")
        worker.postDelayed({ if (attempt == session) connect() }, 2000)
    }

    /** What the server turned down when it ended PPP before the first link came up, by the PPP phase the link had reached. */
    private fun reasonForServerClose(phase: Int) = when (phase) {
        PHASE_AUTHENTICATE -> "The server closed the connection during authentication. Check the username and password."
        PHASE_NETWORK, PHASE_RUNNING -> "The server closed the connection while assigning the tunnel address. Check the server's address pool."
        else -> "The server closed the connection during PPP negotiation. Check that it accepts one of the authentication methods enabled in this profile."
    }

    private fun attemptAllowed(failed: Int, limit: Int) = limit <= 0 || failed < limit

    /** Ends the running session; its end report no longer counts. */
    private fun endSession() {
        session++
        connectionEstablished = false
        networkReady = false
        finishPing(-1)
        Sstp.stop()
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
                if (!hadWifi && hasWifi && connectionEstablished && !closed && !sleepPaused && !pathSwitching) {
                    ConnectionLog.m("Wi-Fi became available; switching the SSTP connection to the new path")
                    // A migration, not a failure: it is not governed by Auto Reconnect
                    pathSwitching = true
                    failedAttempts = 0
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
        ConnectionLog.m("SSTP: closing with reason: $reason")
        closeNow()
        host.onFailure(reason)
    }

    private fun closeNow() {
        if (closed) return
        closed = true
        worker.removeCallbacks(startTimeout)
        stopPathMonitor()
        endSession()
        Sstp.attachTun(-1)
        if (current === this) current = null
        host.onClosed()
    }

    companion object {
        private val worker by lazy { Handler(HandlerThread("srp.sstp").apply { start() }.looper) }

        @Volatile private var current: SstpClient? = null

        private val eventThread by lazy {
            Thread({
                while (true) {
                    val event = Sstp.nextEvent(1000) ?: continue
                    current?.let { client -> worker.post { client.handleEvent(event) } }
                }
            }, "srp.sstp.events").apply {
                isDaemon = true
                start()
            }
        }

        const val MTU = 1400
        private const val PROBE_ADDRESS = "1.1.1.1"
        private const val START_TIMEOUT_MS = 30000L
        private const val PING_TIMEOUT_MS = 15000L
        private const val PHASE_AUTHENTICATE = 7
        private const val PHASE_NETWORK = 9
        private const val PHASE_RUNNING = 10
        private const val DIRECT_FAILURE = "Cannot reach the server (DNS/TCP/TLS failed). Check the host, port and certificate settings."
    }
}
