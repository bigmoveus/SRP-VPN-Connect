package tr.com.srp.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import kotlin.random.Random

/** The SSH bridge of the iOS app (SRPSSHBridge.c) with its packet channel and events (ssh_jni.c), in libsrpssh.so. */
internal object SshNative {
    init {
        System.loadLibrary("srpssh")
    }

    /** A new session (the previous one stops first); its events carry [session]. 0 when started. */
    @JvmStatic external fun start(session: Int, host: String, port: Int, username: String, password: String, hostKey: String,
                                  udp: Boolean, logLevel: Int): Int

    /** Ends the session; no event of it comes after this returns. */
    @JvmStatic external fun stop()

    /** The tunnel's fd (-1: none); the previous one can close once this returns. */
    @JvmStatic external fun attachTun(fd: Int)

    /** A probe packet into the tunnel: 0 when sent, a negative errno otherwise. */
    @JvmStatic external fun submit(packet: ByteArray): Int

    /** Answers of these flows come back through [nextProbe]: triples of protocol, source IPv4, destination port. */
    @JvmStatic external fun setProbeFlows(flows: IntArray)

    @JvmStatic external fun nextProbe(timeoutMs: Int): ByteArray?

    /** The bridge's next event, "session|type|code|text" (type L log, R ready, F failure, G session ended), or null. */
    @JvmStatic external fun nextEvent(timeoutMs: Int): String?
}

/**
 * SRPSSHClient.m and the SSH start of PacketTunnelProvider.m: one SSH session at a time, a new one for every reconnect (an
 * SSH session cannot resume), as Auto Reconnect and Retry Times allow, the move to a new Wi-Fi network and the On Sleep
 * modes. A failure that ends the connection goes to the host with the iOS app's message.
 */
class SshClient(
    private val profile: Profile,
    private val connectivity: ConnectivityManager,
    private val host: TunnelHost,
) : TunnelClient {
    private val autoReconnect = profile.autoReconnect
    private val maxRetries = profile.retryTimes
    private val onSleep = profile.onSleep
    private val port = profile.effectivePort.toIntOrNull() ?: 22

    private var closed = false
    private var started = false
    private var sleepPaused = false
    /** The current session carries packets */
    private var up = false
    /** A session of this connection was up once: what follows obeys Auto Reconnect and Retry Times */
    private var everEstablished = false
    private var settingsApplied = false
    private var failedAttempts = 0
    /** Bumped by every session start; an older session's events change nothing */
    private var generation = 0
    private var running = false
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
        probeThread
        worker.post {
            worker.postDelayed(startTimeout, START_TIMEOUT_MS)
            startPathMonitor()
            startSession()
        }
    }

    override fun close() {
        worker.post {
            if (closed) return@post
            ConnectionLog.m("SSH: disconnecting")
            closeNow()
        }
    }

    override fun pauseForSleep() {
        worker.post {
            if (onSleep == 2 || closed) return@post
            ConnectionLog.m("device sleep: ${if (onSleep == 1) "pausing" else "closing"} the SSH connection")
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
                ConnectionLog.m("device wake: reconnecting the SSH connection")
                startSession()
            } else {
                // Off without Auto Reconnect leaves no connection; end the tunnel instead of keeping a VPN that drops every packet.
                failWithReason("The connection was closed while the device slept.")
            }
        }
    }

    // A new session; the previous one ends first
    private fun startSession() {
        if (closed || sleepPaused) return
        endSession()
        val number = ++generation
        ConnectionLog.m("SSH connecting to ${profile.server.trim()}:$port (user ${profile.username.trim()}, UDP relay ${if (profile.sshUdpRelay) "on" else "off"})")
        if (SshNative.start(number, profile.server.trim(), port, profile.username.trim(), profile.password, profile.sshHostKey.trim(),
                            profile.sshUdpRelay, profile.logLevel) != 0) {
            failWithReason("Internal error starting the SSH engine")
            return
        }
        running = true
    }

    /** Ends the running session; its events no longer count. */
    private fun endSession() {
        if (!running) return
        running = false
        up = false
        generation++
        finishPing(-1)
        SshNative.stop()
    }

    private fun moveToNewPath() {
        if (!up) return
        failedAttempts = 0
        startSession()
    }

    /** An event of the bridge, on the worker */
    private fun handleEvent(number: Int, type: Char, code: Int, text: String) {
        if (number != generation || closed) return
        when (type) {
            // The bridge sends only the lines of the profile's log level: milestones, expert and debug lines
            'L' -> ConnectionLog.m("[ssh] $text")
            'R' -> sessionReady()
            'F' -> sessionFailed(code, text)
            'G' -> sessionEnded(text)
        }
    }

    private fun sessionReady() {
        if (sleepPaused) return
        val again = everEstablished
        up = true
        everEstablished = true
        failedAttempts = 0
        if (!settingsApplied) {
            val problem = host.applyTunnelSettings(SETTINGS) { SshNative.attachTun(it) }
            if (problem != null) {
                failWithReason("The tunnel could not be set up: $problem")
                return
            }
            settingsApplied = true
        }
        ConnectionLog.m("SSH: session established${if (again) " again" else ""}")
        if (!started) {
            started = true
            worker.removeCallbacks(startTimeout)
            ConnectionLog.m("SSH: connected")
        }
        host.onConnected()
    }

    /**
     * A connect or login that failed (SRPSSHClient.m sessionFailed). A refused login, host key, forwarding or relay never gets
     * better by trying again; before the tunnel was ever up only an explicit Retry Times budget retries (as SSTP, SoftEther and
     * SSL VPN).
     */
    private fun sessionFailed(error: Int, detail: String) {
        endSession()
        if (sleepPaused) return
        val message = sshFailureMessage(error, detail, port)
        val final = error in setOf(SSH_ERR_AUTH, SSH_ERR_AUTH_METHOD, SSH_ERR_HOSTKEY, SSH_ERR_FORWARDING, SSH_ERR_RELAY)
        if (final || !autoReconnect || (!everEstablished && maxRetries == 0)) {
            failWithReason(message)
            return
        }
        if (!attemptAllowed(failedAttempts, maxRetries)) {
            failWithReason("Could not ${if (everEstablished) "reconnect" else "connect"} after $maxRetries attempts. ($message)")
            return
        }
        scheduleReconnect(message)
    }

    /** A session that was up has ended: the server closed it, the connection broke, or keepalives went unanswered. */
    private fun sessionEnded(why: String) {
        endSession()
        if (sleepPaused) return
        if (!autoReconnect) {
            failWithReason("${why.replaceFirstChar { it.uppercase() }} (auto reconnect is off).")
            return
        }
        scheduleReconnect(why)
    }

    private fun scheduleReconnect(why: String) {
        failedAttempts++
        ConnectionLog.m("SSH: $why; reconnecting in 2s (attempt $failedAttempts${if (maxRetries > 0) " of $maxRetries" else ""})")
        val number = generation
        // A wake or a network switch may have started a session meanwhile
        worker.postDelayed({ if (number == generation && !closed && !sleepPaused) startSession() }, 2000)
    }

    private fun attemptAllowed(failed: Int, limit: Int) = limit <= 0 || failed < limit

    /** Times one HTTP request to 1.1.1.1 through the tunnel, as SslVpnClient does: this app stays outside its own tunnel. */
    override fun measurePing(result: (Long) -> Unit) {
        worker.post {
            if (closed || !started || !up) {
                result(-1)
                return@post
            }
            pingCallback?.invoke(-1)
            pingCallback = result
            pingPort = Random.nextInt(40000) + 20000
            pingHttpStarted = false
            pingStarted = SystemClock.elapsedRealtime()
            val epoch = ++pingEpoch
            SshNative.setProbeFlows(intArrayOf(ProbePackets.PROTOCOL_TCP, ProbePackets.ipv4Int(PROBE_ADDRESS), pingPort))
            sendPingSyn(epoch)
            worker.postDelayed({ if (epoch == pingEpoch) finishPing(-2) }, PING_TIMEOUT_MS)
        }
    }

    private fun sendPingSyn(epoch: Int) {
        if (epoch != pingEpoch || pingCallback == null || pingHttpStarted || closed) return
        SshNative.submit(ProbePackets.syn(TUNNEL_ADDRESS, ipv4(PROBE_ADDRESS), pingPort))
        worker.postDelayed({ sendPingSyn(epoch) }, 1000)
    }

    private fun finishPing(value: Long) {
        val callback = pingCallback ?: return
        pingCallback = null
        pingEpoch++
        SshNative.setProbeFlows(IntArray(0))
        callback(value)
    }

    private fun ipv4(text: String) = ProbePackets.ipv4(text) ?: ByteArray(4)

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
            SshNative.submit(ProbePackets.httpRequest(TUNNEL_ADDRESS, ipv4(PROBE_ADDRESS), pingPort, u32(packet, ihl + 4) + 1))
        }
    }

    private fun u16(bytes: ByteArray, offset: Int) = ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun u32(bytes: ByteArray, offset: Int) = (u16(bytes, offset) shl 16) or u16(bytes, offset + 2)

    private fun startPathMonitor() {
        if (!profile.switchToWifi || closed) return
        lastPathHadWifi = false
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                val hasWifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                val hadWifi = lastPathHadWifi
                lastPathHadWifi = hasWifi
                // Only an established tunnel moves, and only when Wi-Fi newly appeared (SSShouldReconnectForPathChange)
                if (!hadWifi && hasWifi && up && !closed && !sleepPaused) {
                    ConnectionLog.m("Wi-Fi became available; moving the SSH connection to it")
                    moveToNewPath()
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
        ConnectionLog.m("SSH: closing with reason: $reason")
        closeNow()
        host.onFailure(reason)
    }

    private fun closeNow() {
        if (closed) return
        closed = true
        worker.removeCallbacks(startTimeout)
        stopPathMonitor()
        endSession()
        SshNative.attachTun(-1)
        if (current === this) current = null
        host.onClosed()
    }

    companion object {
        private val worker by lazy { Handler(HandlerThread("srp.ssh").apply { start() }.looper) }

        @Volatile private var current: SshClient? = null

        private val eventThread by lazy {
            Thread({
                while (true) {
                    val event = SshNative.nextEvent(1000) ?: continue
                    val parts = event.split('|', limit = 4)
                    val number = parts.getOrNull(0)?.toIntOrNull() ?: continue
                    val type = parts.getOrNull(1)?.firstOrNull() ?: continue
                    val code = parts.getOrNull(2)?.toIntOrNull() ?: 0
                    val text = parts.getOrNull(3).orEmpty()
                    current?.let { client -> worker.post { client.handleEvent(number, type, code, text) } }
                }
            }, "srp.ssh.events").apply {
                isDaemon = true
                start()
            }
        }

        private val probeThread by lazy {
            Thread({
                while (true) {
                    val packet = SshNative.nextProbe(1000) ?: continue
                    current?.let { client -> worker.post { client.handlePingPacket(packet) } }
                }
            }, "srp.ssh.probes").apply {
                isDaemon = true
                start()
            }
        }

        // The engine's tunnel address and its mapped DNS, as on iOS (SRPSSHClient.m buildSettings)
        private val SETTINGS = TunnelSettings("198.18.0.1", listOf("198.18.0.2"), listOf("0.0.0.0" to 0), 1400)
        private val TUNNEL_ADDRESS = byteArrayOf(198.toByte(), 18, 0, 1)
        private const val PROBE_ADDRESS = "1.1.1.1"
        private const val START_TIMEOUT_MS = 30000L
        private const val PING_TIMEOUT_MS = 15000L
    }
}

// SRPSSHError (SRPSSHBridge.h)
internal const val SSH_ERR_CONNECT = 1
internal const val SSH_ERR_HANDSHAKE = 2
internal const val SSH_ERR_HOSTKEY = 3
internal const val SSH_ERR_AUTH = 4
internal const val SSH_ERR_AUTH_METHOD = 5
internal const val SSH_ERR_FORWARDING = 6
internal const val SSH_ERR_RELAY = 7

/** The message the app shows for a bridge failure, in the iOS app's words (SRPSSHClient messageForError). */
internal fun sshFailureMessage(error: Int, detail: String, port: Int): String = when (error) {
    SSH_ERR_CONNECT -> when (detail) {
        "resolve" -> "Cannot find the server. Check the Server field and the network."
        "refused" -> "The server refused the connection on port $port. Check the Port field."
        "timeout" -> "The server did not answer on port $port. Check the Server and Port fields and the network."
        else -> "Cannot reach the SSH server. Check the Server field and the network."
    }
    SSH_ERR_HANDSHAKE -> when {
        detail == "timeout" -> "The SSH handshake did not finish in time. Check that Port is the server's SSH port."
        detail.isNotEmpty() -> "SSH handshake failed ($detail). Check that Port is the server's SSH port."
        else -> "SSH handshake failed. Check that Port is the server's SSH port."
    }
    SSH_ERR_HOSTKEY -> "The server's host key does not match Host Key. The server presented ${detail.ifEmpty { "another key" }}."
    SSH_ERR_AUTH -> "Authentication failed. Check the username and password."
    SSH_ERR_AUTH_METHOD -> "The server does not take a password for this user (it offers: ${detail.ifEmpty { "other methods" }})."
    SSH_ERR_FORWARDING -> "The server does not let this user forward TCP connections (AllowTcpForwarding or PermitOpen on the server)."
    SSH_ERR_RELAY -> "The UDP relay (HEV) is unavailable on the server. Turn UDP Relay off, or ask the administrator to install or start it."
    else -> detail.ifEmpty { "SSH connection failed." }
}
