package tr.com.srp.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import java.io.File
import java.net.InetAddress
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.random.Random
import org.infradead.libopenconnect.LibOpenConnect
import org.infradead.libopenconnect.LibOpenConnect.AuthForm
import org.infradead.libopenconnect.LibOpenConnect.IPInfo

/** The packet channel between libopenconnect and the tunnel (openconnect_tun_jni.c), in libsrpopenconnect.so with libopenconnect. */
internal object OpenConnectTun {
    init {
        System.loadLibrary("srpopenconnect")
    }

    /** Loads the library, which upstream's LibOpenConnect class needs before its first use. */
    fun load() = Unit

    /** A new channel for a session: libopenconnect's end for setupTunFD, or -1. */
    @JvmStatic external fun open(): Int

    /** Stops the pump and closes the channel: after libopenconnect's main loop has returned. */
    @JvmStatic external fun close()

    /** The tunnel's fd (-1: none); the previous one can close once this returns. */
    @JvmStatic external fun attachTun(fd: Int)

    /** A probe packet into the tunnel: 0 when sent, a negative errno otherwise. */
    @JvmStatic external fun submit(packet: ByteArray): Int

    /** Answers of these flows come back through [nextProbe]: triples of protocol, source IPv4, destination port. */
    @JvmStatic external fun setProbeFlows(flows: IntArray)

    @JvmStatic external fun nextProbe(timeoutMs: Int): ByteArray?
}

/**
 * SRPOpenConnectClient.m and the SSL VPN start of PacketTunnelProvider.m: one session at a time, each on its own thread with
 * upstream's binding of libopenconnect (it uses the JNI environment of the thread that made it, so everything of a session
 * happens there), reconnects as Auto Reconnect and Retry Times allow, the move to a new Wi-Fi network and the On Sleep
 * modes. A failure that ends the connection goes to the host with the iOS app's message.
 */
class SslVpnClient(
    private val context: Context,
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
    private val protocol = profile.ocProtocol.ifEmpty { "anyconnect" }

    private var closed = false
    private var started = false
    private var sleepPaused = false
    private var tunnelUp = false
    private var established = false
    /** A session of this connection was up once: what follows obeys Auto Reconnect and Retry Times */
    private var everEstablished = false
    private var failedAttempts = 0
    /** Bumped by every session start; the end of an older session's thread changes nothing */
    private var generation = 0
    private var session: Session? = null
    @Volatile private var appliedSettings: TunnelSettings? = null
    /** The session is being moved to a new network path on purpose (not a lost connection) */
    private var movingPath = false
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
        OpenConnectTun.load()
        current = this
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
            ConnectionLog.m("OpenConnect: disconnecting")
            closeNow()
        }
    }

    override fun pauseForSleep() {
        worker.post {
            if (onSleep == 2 || closed) return@post
            ConnectionLog.m("device sleep: ${if (onSleep == 1) "pausing" else "closing"} the OpenConnect connection")
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
                ConnectionLog.m("device wake: reconnecting the OpenConnect connection")
                startSession()
            } else {
                // Off without Auto Reconnect leaves no connection; end the tunnel instead of keeping a VPN that drops every packet.
                failWithReason("The connection was closed while the device slept.")
            }
        }
    }

    /** What Switch to Wi-Fi does when Wi-Fi appears: the running session moves to the current network path. */
    fun switchNetworkPath() {
        worker.post {
            ConnectionLog.m("OpenConnect: network path switch requested")
            moveToNewPath()
        }
    }

    // A session on its own thread; `lib` is made there and every call of it happens there, cancel() and pause() excepted
    private inner class Session(val number: Int) : Thread("srp.openconnect.session") {
        @Volatile var lib: LibOpenConnect? = null
        @Volatile var cancelled = false
        var authFailed = false
        var certFailed = false
        var authRounds = 0
        /** libopenconnect's error lines, for the failure message */
        val errors = ArrayList<String>()
        /** libopenconnect's end of the packet channel */
        var tunFd = -1
        private var certificateFile: File? = null

        fun cancel() {
            cancelled = true
            lib?.cancel()
        }

        fun pause() {
            lib?.pause()
        }

        override fun run() {
            val lib = Library(this)
            this.lib = lib
            var tunOpen = false
            try {
                if (cancelled) return
                configure(lib) ?: return
                ConnectionLog.m("OpenConnect connecting to ${maskSecret(sslVpnUrl(profile.server.trim(), port().toString(), profile.ocPath))} (protocol $protocol, user ${profile.username.trim()}, verify=${if (allowInsecure) 0 else 1})")
                val untrusted = "The server's certificate is not trusted. Check the Server field, or turn off TLS Server Verification in the profile."
                if (lib.obtainCookie() != 0) {
                    sessionFailed(if (certFailed) untrusted else if (authFailed) "Authentication failed. Check the username and password."
                                  else reasonFromErrors(errors, protocol) ?: "Cannot reach the server (DNS/TCP/TLS failed). Check the Server field and the network.")
                    return
                }
                if (lib.makeCSTPConnection() != 0) {
                    sessionFailed(if (certFailed) untrusted else "TLS tunnel setup failed. Check the server and certificate settings.")
                    return
                }
                // UDP transport (DTLS) is best-effort; GlobalProtect's ESP is off (see configure)
                if (protocol != "gp" && lib.setupDTLS(60) == 0) ConnectionLog.m("OpenConnect: DTLS (UDP) transport set up")
                else info("OpenConnect: DTLS/ESP unavailable — TLS only")
                if (cancelled) return
                tunFd = OpenConnectTun.open()
                if (tunFd < 0) {
                    sessionFailed("Internal error creating the packet channel")
                    return
                }
                tunOpen = true
                // AnyConnect and GlobalProtect know the addresses now: the tunnel comes up at once, as on iOS. Left to the main
                // loop, it would wait for DTLS to connect or give up first (some 15 s more where UDP is blocked); F5's PPP
                // gets its addresses inside the main loop, which then asks for the tunnel (onSetupTun)
                if (lib.getIPInfo()?.addr != null) lib.setUpTunnel()
                worker.post {
                    if (number != generation) return@post
                    established = true
                    everEstablished = true
                    failedAttempts = 0
                    ConnectionLog.m("OpenConnect: session established")
                }
                // libopenconnect resumes a broken connection with its cookie (same session, same address). Auto Reconnect off:
                // one immediate attempt, then the VPN ends. On: Retry Times attempts in all (0 = until the server no longer
                // knows the session), 2 s apart and then each wait 2 s longer.
                val interval = 2
                val timeout = if (!autoReconnect) 0 else if (maxRetries > 0) interval * maxRetries * (maxRetries - 1) / 2 else 86400
                var result: Int
                // A paused main loop is a move to a new network path: running it again resumes the session over that path
                while (true) {
                    result = lib.mainloop(timeout, interval)
                    if (result != 0 || cancelled || number != generation) break
                    ConnectionLog.m("OpenConnect: resuming the session over the new network path")
                }
                ConnectionLog.m("OpenConnect: mainloop exited ($result)")
                sessionEnded(result)
            } finally {
                lib.destroy()
                if (tunOpen) OpenConnectTun.close()
                certificateFile?.delete()
            }
        }

        /** The profile's settings on a new session; null after a failure was reported. */
        private fun configure(lib: LibOpenConnect): Unit? {
            lib.setLogLevel(when (profile.logLevel) { 2 -> LibOpenConnect.PRG_DEBUG; 1 -> LibOpenConnect.PRG_INFO; else -> LibOpenConnect.PRG_ERR })
            // TLS write splitting of the ClientHello, as on iOS: Auto takes 43-byte first writes and 256-byte following ones 3 ms
            // apart (128 bytes, 10 ms on cellular); Manual the profile's sizes (32 and 256 when empty)
            when (profile.tlsFragMode) {
                1 -> {
                    val onCellular = cellular()
                    val following = if (onCellular) 128 else 256
                    val gap = if (onCellular) 10 else 3
                    lib.setTLSFragmentation(43, following, gap)
                    ConnectionLog.m("OpenConnect: TLS fragmentation auto (first=43 following=$following gap=$gap ms)")
                }
                2 -> {
                    val first = profile.tlsFragFirst.takeIf { it > 0 } ?: 32
                    val following = profile.tlsFragFollowing.takeIf { it > 0 } ?: 256
                    lib.setTLSFragmentation(first, following, 3)
                    ConnectionLog.m("OpenConnect: TLS fragmentation manual (first=$first following=$following gap=3 ms)")
                }
            }
            if (lib.setProtocol(protocol) != 0) ConnectionLog.m("OpenConnect: unsupported protocol $protocol")
            // GlobalProtect waits for ESP (UDP) before its HTTPS tunnel; with ESP off the tunnel comes up at once, as on iOS
            if (protocol == "gp") lib.disableDTLS()
            lib.setReportedOS("android")
            lib.setMobileInfo(null, "Android", null)
            if (profile.certificateMode) {
                val (p12, passphrase) = certificate ?: run {
                    sessionFailed("The client certificate could not be read. Re-import it in the profile.")
                    return null
                }
                // libopenconnect reads a PKCS#12 file; it exists only while the session does, readable by this app alone
                val file = File(context.noBackupFilesDir, "srp_oc_client.p12")
                file.writeBytes(p12)
                certificateFile = file
                if (lib.setClientCert(file.path, null) != 0) ConnectionLog.m("OpenConnect: client certificate rejected")
                lib.setKeyPassword(passphrase)
            }
            if (lib.parseURL(sslVpnUrl(profile.server.trim(), port().toString(), profile.ocPath)) != 0) {
                sessionFailed("Invalid server address")
                return null
            }
            return Unit
        }

        private fun sessionFailed(reason: String) = worker.post { this@SslVpnClient.sessionFailed(number, reason, authFailed, certFailed) }

        private fun sessionEnded(result: Int) = worker.post { this@SslVpnClient.sessionEnded(number, result) }
    }

    /** libopenconnect's callbacks; they run on the session's thread. */
    private inner class Library(private val session: Session) : LibOpenConnect("SRP VPN Connect") {
        override fun onProgress(level: Int, message: String) {
            // libopenconnect logs each request's URL, the Path with it
            val line = maskSecret(maskCookies(message.trim()))
            if (line.isEmpty()) return
            when (level) {
                LibOpenConnect.PRG_ERR -> {
                    if (session.errors.size < 16) session.errors += line
                    ConnectionLog.m("[oc] $line")   // errors explain a failure at every log level
                }
                LibOpenConnect.PRG_INFO -> if (profile.logLevel >= 1) ConnectionLog.m("[oc] $line")
                else -> if (profile.logLevel >= 2) ConnectionLog.m("[oc] $line")
            }
        }

        override fun onValidatePeerCert(reason: String?): Int {
            if (allowInsecure) {
                ConnectionLog.m("OpenConnect TLS: verification disabled — accepting (${reason.orEmpty()})")
                return 0
            }
            // The server's chain against the device's trusted roots and the Server name, as SecTrust does on iOS
            val name = profile.server.trim()
            val chain: Array<ByteArray> = getPeerCertChain() ?: emptyArray()
            val leaf = chain.firstOrNull()?.let {
                runCatching { CertificateFactory.getInstance("X.509").generateCertificate(it.inputStream()) as X509Certificate }.getOrNull()
            }
            val problem = when {
                leaf == null -> "the server sent no certificate"
                !namesMatchHost(leaf.subjectAlternativeNames, name) -> "the certificate is not for $name"
                else -> PlatformTrust.check(chain)
            }
            if (problem != null) {
                ConnectionLog.m("OpenConnect TLS: certificate not trusted for $name: $problem")
                session.certFailed = true
                return 1
            }
            info("OpenConnect TLS: server certificate trusted for $name")
            return 0
        }

        override fun onProcessAuthForm(form: AuthForm): Int {
            if (form.error != null) {
                ConnectionLog.m("OpenConnect: authentication failed: ${form.error}")
                session.authFailed = true
                return LibOpenConnect.OC_FORM_RESULT_CANCELLED   // do not resubmit wrong credentials
            }
            session.authRounds++
            if (session.authRounds > 3) {
                ConnectionLog.m("OpenConnect: authentication failed (server keeps rejecting the credentials)")
                session.authFailed = true
                return LibOpenConnect.OC_FORM_RESULT_CANCELLED
            }
            info("OpenConnect: auth form ${form.authID.orEmpty()} (round ${session.authRounds})")
            for (option in form.opts) {
                when {
                    option.type == LibOpenConnect.OC_FORM_OPT_TEXT && (option.name == "username" || option.name == "user") -> option.value = profile.username.trim()
                    option.type == LibOpenConnect.OC_FORM_OPT_PASSWORD -> option.value = profile.password
                    option.type == LibOpenConnect.OC_FORM_OPT_TEXT && option.label?.contains("user", ignoreCase = true) == true && option.value == null ->
                        option.value = profile.username.trim()
                }
            }
            return LibOpenConnect.OC_FORM_RESULT_OK
        }

        // The tunnel comes up when libopenconnect knows the addresses (for F5's PPP, inside the main loop)
        override fun onSetupTun() = setUpTunnel()

        fun setUpTunnel() {
            val info = getIPInfo() ?: return
            val settings = settingsFrom(info) ?: run {
                ConnectionLog.m("OpenConnect: the server assigned no IPv4 address; the Android app routes IPv4 only")
                session.cancel()
                return
            }
            val problem = applySettings(settings)
            if (problem != null) {
                worker.post { if (session.number == generation) failWithReason("OpenConnect network settings failed: $problem") }
                session.cancel()
                return
            }
            setupTunFD(session.tunFd)
            worker.post {
                if (session.number != generation) return@post
                tunnelUp = true
                reportConnected()
            }
        }

        override fun onReconnected() {
            ConnectionLog.m("OpenConnect: session resumed")
            val info = getIPInfo()
            worker.post {
                if (session.number != generation) return@post
                val moved = movingPath
                movingPath = false
                if (!moved && !autoReconnect) {
                    // libopenconnect always tries one resume of a broken connection; with Auto Reconnect off a lost connection
                    // still ends the VPN, as in the other protocols
                    session.cancel()
                    return@post
                }
                failedAttempts = 0
                // The system keeps its settings unless the server gave another address
                val settings = info?.let { settingsFrom(it) } ?: return@post
                if (settings.address != appliedSettings?.address) {
                    ConnectionLog.m("OpenConnect: the resumed session has another address (${settings.address}); applying it")
                    applySettings(settings)?.let { failWithReason("OpenConnect network settings failed: $it") }
                }
            }
        }
    }

    private fun port() = profile.effectivePort.toIntOrNull() ?: 443

    /** The Path's secret (after "?"): a camouflage secret is a password of sorts, so the log shows only its length */
    private val pathSecret = profile.ocPath.substringAfter('?', "").trim()

    private fun maskSecret(line: String) = if (pathSecret.isEmpty()) line else line.replace("?$pathSecret", "?<${pathSecret.length} characters>")

    /** The server's addresses, DNS servers and routes as the tunnel's settings; null without an IPv4 address. */
    private fun settingsFrom(info: IPInfo): TunnelSettings? {
        val address = info.addr ?: return null
        if (info.addr6 != null) ConnectionLog.m("OpenConnect: the server offered IPv6 (${info.addr6}); the Android app routes IPv4 only")
        // Some servers send several DNS servers in one entry
        val dns = info.DNS.flatMap { it.split(' ', ',', ';') }.map { it.trim() }.filter { ProbePackets.ipv4(it) != null || ':' in it }
        val routes = info.splitIncludes.mapNotNull { cidr(it) }.ifEmpty { listOf("0.0.0.0" to 0) }
        val excluded = info.splitExcludes.mapNotNull { cidr(it) }
        info("OpenConnect: routes through the tunnel: ${if (info.splitIncludes.isEmpty()) "all" else info.splitIncludes.joinToString(", ")}; " +
            "excluded: ${if (excluded.isEmpty()) "none" else info.splitExcludes.joinToString(", ")}")
        ConnectionLog.m("OpenConnect: got settings addr=$address mask=${info.netmask ?: "-"} dns=${dns.firstOrNull() ?: "-"} mtu=${info.MTU}")
        return TunnelSettings(address, dns.ifEmpty { listOf("1.1.1.1") }, routes, if (info.MTU > 0) info.MTU else MTU, excluded)
    }

    private fun cidr(text: String): Pair<String, Int>? {
        val parts = text.split('/')
        if (parts.size != 2 || ProbePackets.ipv4(parts[0]) == null) return null
        // ocserv writes the mask either as a prefix or as a dotted netmask
        val prefix = parts[1].toIntOrNull() ?: ProbePackets.ipv4(parts[1])?.let { mask -> mask.sumOf { Integer.bitCount(it.toInt() and 0xff) } }
        return if (prefix != null && prefix in 0..32) parts[0] to prefix else null
    }

    private fun applySettings(settings: TunnelSettings): String? {
        val problem = host.applyTunnelSettings(settings) { OpenConnectTun.attachTun(it) }
        if (problem == null) appliedSettings = settings
        return problem
    }

    // A new session; the previous one ends first
    private fun startSession() {
        if (closed || sleepPaused) return
        endSession()
        val number = ++generation
        val next = Session(number)
        session = next
        next.start()
    }

    /** Ends the running session, or waits for one that ended on its own to finish; its end no longer counts. */
    private fun endSession() {
        val running = session ?: return
        session = null
        generation++
        established = false
        tunnelUp = false
        finishPing(-1)
        running.cancel()
        // libopenconnect leaves its main loop at once on the cancel; a DNS lookup in progress can take longer
        running.join(30000)
    }

    private fun moveToNewPath() {
        val running = session ?: return
        if (!established) return
        failedAttempts = 0
        movingPath = true
        running.pause()
    }

    /** A login or tunnel setup that failed (SRPOpenConnectClient.m sessionFailed). */
    private fun sessionFailed(number: Int, reason: String, authFailed: Boolean, certFailed: Boolean) {
        if (number != generation || closed || sleepPaused) return
        // A refused login or certificate is never retried: the profile or the server must change first. Before the tunnel was
        // ever up only an explicit Retry Times budget retries (as SSTP and SoftEther).
        if (authFailed || certFailed || !autoReconnect || (!everEstablished && maxRetries == 0)) {
            failWithReason(reason)
            return
        }
        if (!attemptAllowed(failedAttempts, maxRetries)) {
            failWithReason("Could not ${if (everEstablished) "reconnect" else "connect"} after $maxRetries attempts. ($reason)")
            return
        }
        scheduleReconnect(reason)
    }

    /** The main loop of a session that was up has ended; libopenconnect has already tried to resume it (SRPOpenConnectClient.m). */
    private fun sessionEnded(number: Int, result: Int) {
        if (number != generation || closed || sleepPaused) return
        established = false
        tunnelUp = false
        // -EPIPE: the server ended the session; -EPERM: it no longer knows the session
        val serverEnded = result == -EPIPE || result == -EPERM
        if (!autoReconnect) {
            failWithReason(if (serverEnded) "The server ended the session (auto reconnect is off)." else "Connection lost (auto reconnect is off).")
            return
        }
        if (!serverEnded && maxRetries > 0) {
            failWithReason("Could not reconnect after $maxRetries attempts.")
            return
        }
        scheduleReconnect(if (serverEnded) "the server ended the session" else "connection lost")
    }

    private fun scheduleReconnect(why: String) {
        failedAttempts++
        ConnectionLog.m("OpenConnect: $why; reconnecting in 2s (attempt $failedAttempts${if (maxRetries > 0) " of $maxRetries" else ""})")
        val number = generation
        // A wake or a network switch may have started a session meanwhile
        worker.postDelayed({ if (number == generation && !closed && !sleepPaused) startSession() }, 2000)
    }

    private fun attemptAllowed(failed: Int, limit: Int) = limit <= 0 || failed < limit

    private fun reportConnected() {
        if (!tunnelUp) return
        if (!started) {
            started = true
            worker.removeCallbacks(startTimeout)
            ConnectionLog.m("OpenConnect: connected")
        }
        host.onConnected()
    }

    /** A step that the iOS app logs at Info level: Expert and Debug show it. */
    private fun info(message: String) {
        if (profile.logLevel >= 1) ConnectionLog.m(message)
    }

    /** Times one HTTP request to 1.1.1.1 through the tunnel, as SoftEtherClient does: this app stays outside its own tunnel. */
    override fun measurePing(result: (Long) -> Unit) {
        worker.post {
            val address = appliedSettings?.address
            if (closed || !started || !tunnelUp || address == null) {
                result(-1)
                return@post
            }
            pingCallback?.invoke(-1)
            pingCallback = result
            pingPort = Random.nextInt(40000) + 20000
            pingHttpStarted = false
            pingStarted = SystemClock.elapsedRealtime()
            val epoch = ++pingEpoch
            OpenConnectTun.setProbeFlows(intArrayOf(ProbePackets.PROTOCOL_TCP, ProbePackets.ipv4Int(PROBE_ADDRESS), pingPort))
            sendPingSyn(epoch, address)
            worker.postDelayed({ if (epoch == pingEpoch) finishPing(-2) }, PING_TIMEOUT_MS)
        }
    }

    private fun sendPingSyn(epoch: Int, address: String) {
        if (epoch != pingEpoch || pingCallback == null || pingHttpStarted || closed) return
        OpenConnectTun.submit(ProbePackets.syn(ipv4(address), ipv4(PROBE_ADDRESS), pingPort))
        worker.postDelayed({ sendPingSyn(epoch, address) }, 1000)
    }

    private fun finishPing(value: Long) {
        val callback = pingCallback ?: return
        pingCallback = null
        pingEpoch++
        OpenConnectTun.setProbeFlows(IntArray(0))
        callback(value)
    }

    private fun ipv4(text: String) = ProbePackets.ipv4(text) ?: ByteArray(4)

    private fun handlePingPacket(packet: ByteArray) {
        val address = appliedSettings?.address ?: return
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
            OpenConnectTun.submit(ProbePackets.httpRequest(ipv4(address), ipv4(PROBE_ADDRESS), pingPort, u32(packet, ihl + 4) + 1))
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
                if (!hadWifi && hasWifi && tunnelUp && !closed && !sleepPaused) {
                    ConnectionLog.m("Wi-Fi became available; switching the OpenConnect connection to the new path")
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
        ConnectionLog.m("OpenConnect: closing with reason: $reason")
        closeNow()
        host.onFailure(reason)
    }

    private fun closeNow() {
        if (closed) return
        closed = true
        worker.removeCallbacks(startTimeout)
        stopPathMonitor()
        endSession()
        OpenConnectTun.attachTun(-1)
        if (current === this) current = null
        host.onClosed()
    }

    companion object {
        private val worker by lazy { Handler(HandlerThread("srp.openconnect").apply { start() }.looper) }

        @Volatile private var current: SslVpnClient? = null

        private val probeThread by lazy {
            Thread({
                while (true) {
                    val packet = OpenConnectTun.nextProbe(1000) ?: continue
                    current?.let { client -> worker.post { client.handlePingPacket(packet) } }
                }
            }, "srp.openconnect.probes").apply {
                isDaemon = true
                start()
            }
        }

        private const val MTU = 1400
        private const val PROBE_ADDRESS = "1.1.1.1"
        private const val START_TIMEOUT_MS = 30000L
        private const val PING_TIMEOUT_MS = 15000L
        private const val EPIPE = 32
        private const val EPERM = 1
    }
}

/**
 * A server certificate's subject alternative names (X509Certificate.getSubjectAlternativeNames) cover [host]: a DNS name, with
 * at most one wildcard as the whole leftmost label, or the IP address of an IP host.
 */
internal fun namesMatchHost(names: Collection<List<*>>?, host: String): Boolean {
    val target = host.trim().lowercase().trimEnd('.')
    if (ProbePackets.ipv4(target) != null || ':' in target) {
        val wanted = runCatching { InetAddress.getByName(target).address }.getOrNull() ?: return false
        return names.orEmpty().any { it.getOrNull(0) == 7 && runCatching { InetAddress.getByName(it[1] as String).address }.getOrNull()?.contentEquals(wanted) == true }
    }
    return names.orEmpty().filter { it.getOrNull(0) == 2 }.mapNotNull { (it[1] as? String)?.lowercase()?.trimEnd('.') }.any { pattern ->
        if (pattern.startsWith("*.")) {
            val suffix = pattern.substring(1)
            target.endsWith(suffix) && target.length > suffix.length && target.indexOf('.') == target.length - suffix.length
        } else {
            pattern == target
        }
    }
}

/**
 * libopenconnect's Debug lines print the server's cookies; it hides only the session cookie, while others (ocserv's
 * webvpncontext) are session tokens too. A shared log keeps their names and loses their values (SRPOCMaskCookies on iOS).
 */
internal fun maskCookies(line: String): String {
    if ("ookie" !in line) return line
    return line.replace(Regex("""(Set-Cookie: [^=;]+=)[^;<\s][^;]*"""), "$1<elided>")
        .replace(Regex("""(Invalid cookie ')[^']*"""), "$1<elided>")
}

/** Why a login failed, from libopenconnect's own error lines, in the profile's terms (SRPOpenConnectClient.m); null when they do not say. */
internal fun reasonFromErrors(errors: List<String>, protocol: String): String? {
    val all = errors.joinToString("\n")
    return when {
        "getaddrinfo failed" in all -> "The server name could not be found. Check the Server field."
        "Failed to connect to host" in all -> "Cannot connect to the server on this port. Check the Server and Port fields and the network."
        "wrong version number" in all -> "The server did not answer with TLS on this port. Check the Port field."
        // TLS 1.0 and 1.1 sign with MD5+SHA1, which OpenSSL refuses ("legacy sigalg"), when the version itself got through
        "unsupported protocol" in all || "protocol version" in all || "no protocols available" in all || "legacy sigalg" in all ->
            "The server offers only TLS 1.1 or older; the app needs TLS 1.2 or later."
        "SSL connection failure" in all ->
            "The TLS handshake with the server failed. The server may refuse the client certificate, or block this address for a while after wrong passwords."
        "Unexpected 404 result" in all || "Unknown form ID" in all -> {
            val type = when (protocol) { "f5" -> "an F5 BIG-IP"; "gp" -> "a GlobalProtect"; else -> "an AnyConnect" }
            "The server did not answer as $type server. Check the Server Type and the Server field."
        }
        else -> null
    }
}
