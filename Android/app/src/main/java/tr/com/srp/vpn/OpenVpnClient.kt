package tr.com.srp.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import kotlin.random.Random

/** OpenVPN 3 Core with the packet channel and events of openvpn_jni.cpp, in libsrpopenvpn.so. */
internal object OpenVpnNative {
    init {
        System.loadLibrary("srpopenvpn")
    }

    /**
     * A new core (the previous one stops first); its events carry [session]. Returns "OK\thost\tport\tproto" when it runs,
     * "ERR\tmessage" for a profile the core refuses, "CREDS" when the profile needs a username.
     */
    @JvmStatic external fun start(session: Int, profile: String, username: String, password: String, server: String, port: String,
                                  proto: String, disableClientCert: Boolean): String

    /** Ends the core; no event of it counts after this returns. */
    @JvmStatic external fun stop()

    /** The core moves its connection to the current network path. */
    @JvmStatic external fun reconnect()

    /** The tunnel's fd for settings request [request] (-1: none); the previous fd can close once this returns. */
    @JvmStatic external fun attachTun(fd: Int, request: Int)

    /** A probe packet into the tunnel: 0 when sent, a negative errno otherwise. */
    @JvmStatic external fun submit(packet: ByteArray): Int

    /** Answers of these flows come back through [nextProbe]: triples of protocol, source IPv4, destination port. */
    @JvmStatic external fun setProbeFlows(flows: IntArray)

    @JvmStatic external fun nextProbe(timeoutMs: Int): ByteArray?

    /** The next event as UTF-8, "session|type|text" (type L log, E core event, S settings, X core stopped), or null. */
    @JvmStatic external fun nextEvent(timeoutMs: Int): ByteArray?
}

/** What an .ovpn says about itself (SRPOpenVPNClient firstRemoteOfProfile and remoteCountOfProfile on iOS). */
object OpenVpnProfileText {
    data class Remote(val host: String, val port: String, val proto: String)

    private fun directives(profile: String, name: String): List<List<String>> = profile.lineSequence()
        .map { line -> line.trim().split(Regex("[ \t]+")).filter { it.isNotEmpty() } }
        .filter { it.firstOrNull() == name }
        .toList()

    fun firstRemote(profile: String): Remote {
        val remote = directives(profile, "remote").firstOrNull()
        val port = directives(profile, "port").firstOrNull()?.getOrNull(1)
        val proto = directives(profile, "proto").firstOrNull()?.getOrNull(1)
        return Remote(remote?.getOrNull(1) ?: "", remote?.getOrNull(2) ?: port ?: "1194", remote?.getOrNull(3) ?: proto ?: "udp")
    }

    fun remoteCount(profile: String) = directives(profile, "remote").size.coerceAtLeast(1)

    /** An auth-user-pass line that is not commented out: the profile asks for a username and password */
    fun needsAuth(profile: String) = Regex("(?m)^[ \t]*auth-user-pass\\b").containsMatchIn(profile)

    fun hasClientCertificate(profile: String) = "<cert>" in profile || directives(profile, "cert").isNotEmpty()

    fun hasEncryptedKey(profile: String) = "ENCRYPTED PRIVATE KEY" in profile || "Proc-Type: 4,ENCRYPTED" in profile

    fun usesStaticKey(profile: String) = "<secret>" in profile || directives(profile, "secret").isNotEmpty()

    /** The profile turned to one transport protocol (stunnel carries TCP; the core's override only picks TCP remotes) */
    fun withProtocol(profile: String, protocol: String): String {
        var sawProto = false
        val lines = profile.split('\n').map { line ->
            val words = line.trim().split(Regex("[ \t]+")).filter { it.isNotEmpty() }
            when {
                words.firstOrNull() == "proto" -> {
                    sawProto = true
                    "proto $protocol"
                }
                words.size >= 4 && words[0] == "remote" -> "remote ${words[1]} ${words[2]} $protocol"
                else -> line
            }
        }
        val text = lines.joinToString("\n")
        return if (sawProto) text else "proto $protocol\n$text"
    }
}

/** The tunnel for the options a server pushed (SRPOpenVPNClient settingsForPushedOptions on iOS). */
object OpenVpnSettings {
    /** "1.1.1.1", "1.1.1.1:53", "[2620:fe::fe]:53" or "2620:fe::fe" as the bare address */
    fun dnsAddress(value: String): String {
        if (value.startsWith("[")) return value.substringAfter('[').substringBefore(']')
        return if (value.count { it == ':' } == 1) value.substringBefore(':') else value
    }

    private fun prefixOf(mask: String): Int? {
        val bytes = ProbePackets.ipv4(mask) ?: return null
        val bits = bytes.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
        val prefix = java.lang.Long.bitCount(bits)
        // a netmask's ones come first
        return if (bits == ((0xffffffffL shl (32 - prefix)) and 0xffffffffL)) prefix else null
    }

    /** The network of an address for a prefix: Android refuses routes with host bits */
    private fun network(address: String, prefix: Int): String {
        val bytes = ProbePackets.ipv4(address) ?: return address
        val value = bytes.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
        val masked = if (prefix == 0) 0L else value and ((0xffffffffL shl (32 - prefix)) and 0xffffffffL)
        return "${masked shr 24 and 0xff}.${masked shr 16 and 0xff}.${masked shr 8 and 0xff}.${masked and 0xff}"
    }

    /** Null when the server assigned no IPv4 address. */
    fun tunnelSettings(options: List<List<String>>): TunnelSettings? {
        var local4: String? = null
        var peer4: String? = null
        var topology: String? = null
        val dns = ArrayList<String>()
        val domains = ArrayList<String>()
        val includes = ArrayList<Pair<String, Int>>()
        val excludes = ArrayList<Pair<String, Int>>()
        var fullTunnel = false
        var mtu = 1400
        for (parts in options) {
            when (parts.firstOrNull()) {
                "ifconfig" -> {
                    local4 = parts.getOrNull(1)
                    peer4 = parts.getOrNull(2)
                }
                "topology" -> topology = parts.getOrNull(1)
                "dhcp-option" -> when (parts.getOrNull(1)) {
                    "DNS", "DNS6" -> parts.getOrNull(2)?.let { dns += it }
                    "DOMAIN", "DOMAIN-SEARCH", "ADAPTER_DOMAIN_SUFFIX" -> parts.getOrNull(2)?.let { domains += it }
                }
                // OpenVPN 2.6's "dns server N address ADDR [ADDR...]"
                "dns" -> if (parts.size >= 5 && parts[1] == "server" && parts[3] == "address") parts.drop(4).forEach { dns += dnsAddress(it) }
                "redirect-gateway" -> fullTunnel = true
                // route NETWORK [MASK] [GATEWAY]; net_gateway sends the network around the tunnel
                "route" -> {
                    val target = parts.getOrNull(1) ?: continue
                    val prefix = prefixOf(parts.getOrNull(2)?.takeIf { it != "default" } ?: "255.255.255.255") ?: continue
                    if (ProbePackets.ipv4(target) == null) continue
                    val route = network(target, prefix) to prefix
                    if (parts.getOrNull(3) == "net_gateway") excludes += route else includes += route
                }
                "tun-mtu" -> mtu = parts.getOrNull(1)?.toIntOrNull() ?: mtu
            }
        }
        val address = local4 ?: return null
        var prefix = 24
        val peer = peer4
        if (peer != null) {
            // topology subnet: "ifconfig LOCAL NETMASK"; net30 and p2p (OpenVPN 2.6's default): "ifconfig LOCAL PEER"
            if (topology == "subnet") {
                prefix = prefixOf(peer) ?: 24
            } else {
                prefix = 32
                includes += peer to 32
            }
        }
        if (dns.isEmpty()) dns += "1.1.1.1"
        if (mtu !in 576..9000) mtu = 1400
        val routes = if (fullTunnel || includes.isEmpty()) listOf("0.0.0.0" to 0) else includes.distinct()
        // the service takes names that are not addresses as search domains
        return TunnelSettings(address, dns + domains, routes, mtu, excludes, prefix)
    }
}

/** The core's transport errors: DNS, refused or unreachable connections, closed streams (SRPOpenVPNClient messageForTransportError) */
fun openVpnTransportMessage(text: String): String = when {
    text.startsWith("stunnel: ") -> text.removePrefix("stunnel: ")
    "DNS resolve error" in text || "Host not found" in text || "HOST_NOT_FOUND" in text || "nodename nor servname" in text ->
        Regex("on '([^']*)'").find(text)?.let { "The server name ${it.groupValues[1]} could not be resolved." } ?: "The server name could not be resolved."
    "refused" in text || "ECONNREFUSED" in text || "NETWORK_RECV_ERROR" in text -> "The server refused the connection: no OpenVPN server answers on that port."
    "timed out" in text -> "The server did not answer."
    "unreachable" in text || "No route" in text -> "The server cannot be reached from this network."
    "NETWORK_EOF_ERROR" in text || "End of file" in text || "reset by peer" in text -> "The server closed the connection."
    else -> "The connection to the server failed ($text)."
}

/** A core log line that explains a failed attempt, as the user's message; null for any other line (SRPOpenVPNClient messageForLogLine) */
fun openVpnLogMessage(line: String): String? {
    if ("KEEPALIVE_TIMEOUT" in line) return "The server stopped answering (keepalive timeout)."
    if ("Server poll timeout" in line) return "The server did not answer."
    line.indexOf("Transport Error: ").takeIf { it >= 0 }?.let { return openVpnTransportMessage(line.substring(it + 17)) }
    val exception = line.indexOf("Client exception in ")
    if (exception >= 0) {
        var detail = line.substring(exception + 20)
        detail.indexOf(": ").takeIf { it >= 0 }?.let { detail = detail.substring(it + 2) }
        Regex("pushed compressor '([^']*)'").find(detail)?.let {
            return "The server pushes compression (${it.groupValues[1]}), which this app does not take: compression inside a VPN can leak data (VORACLE). Turn it off on the server (remove compress/comp-lzo from its configuration)."
        }
        if ("option_error" in detail || "ERR_PROFILE_OPTION" in detail) return "The server pushed a setting this app cannot use ($detail)."
        return "The OpenVPN session failed ($detail)."
    }
    return null
}

/** What a core event means for the user (SRPOpenVPNClient messageForEvent on iOS). */
fun openVpnEventMessage(name: String, info: String): String {
    val detail = if (info.isNotEmpty()) " ($info)" else ""
    return when {
        name == "AUTH_FAILED" && "cipher" in info.lowercase() -> "The server and this app have no data-channel cipher in common ($info)."
        name == "AUTH_FAILED" -> "The server refused the login$detail. Check the username and password."
        name == "CERT_VERIFY_FAIL" -> "The server's certificate could not be verified with the profile's CA$detail."
        name.startsWith("TLS_ALERT_") || name == "TLS_SIGALG_DISALLOWED_OR_UNSUPPORTED" -> {
            val what = name.removePrefix("TLS_ALERT_").lowercase().replace('_', ' ')
            "The server refused the TLS handshake ($what). Check the profile's client certificate and key."
        }
        name == "TLS_VERSION_MIN" -> "The server does not offer the TLS version the profile asks for (tls-version-min)."
        name == "CLIENT_HALT" -> "The server ended the session$detail."
        name == "CLIENT_RESTART" -> "The server restarted the session."
        name == "CONNECTION_TIMEOUT" -> "Connection timed out. The server did not respond."
        name == "INACTIVE_TIMEOUT" -> "The session ended after the profile's inactivity timeout."
        name == "COMPRESS_ERROR" -> "The server uses compression that this app does not support$detail."
        name == "DYNAMIC_CHALLENGE" || name == "NEED_CREDS" -> "The server asked for another login step (a challenge or one-time code), which this app does not support."
        name == "SESSION_EXPIRED" -> "The server ended the session: the login expired."
        name == "EPKI_ERROR" || name == "EPKI_INVALID_ALIAS" -> "The profile's client certificate or key could not be used$detail."
        name == "TRANSPORT_ERROR" -> openVpnTransportMessage(info)
        name == "TUN_ERROR" -> "The VPN interface failed$detail."
        else -> "$name$detail"
    }
}

fun openVpnInvalidProfileMessage(message: String, profile: String): String =
    if (OpenVpnProfileText.usesStaticKey(profile) || "static key" in message.lowercase()) {
        "This profile uses an OpenVPN static key (secret), which OpenVPN 3 does not support. Ask for a profile with certificates (TLS mode)."
    } else {
        "Invalid OpenVPN profile: $message"
    }

/**
 * SRPOpenVPNClient.mm and the OpenVPN start of PacketTunnelProvider.m: the core reconnects by itself after a lost connection;
 * this class decides from its events whether it may (Auto Reconnect, Retry Times), moves the session to a new Wi-Fi network
 * and applies On Sleep. A failure that ends the connection goes to the host with the iOS app's message.
 */
class OpenVpnClient(
    private val profile: Profile,
    private val connectivity: ConnectivityManager,
    private val cellular: () -> Boolean,
    private val host: TunnelHost,
) : TunnelClient {
    private val autoReconnect = profile.autoReconnect
    private val retryTimes = profile.retryTimes
    private val onSleep = profile.onSleep
    private val expert = profile.logLevel >= 1

    private var closed = false
    private var failed = false
    private var started = false
    private var sleepPaused = false
    private var up = false
    private var everEstablished = false
    /** A reconnect this class asked for (Wi-Fi appeared), not a lost connection */
    private var pathSwitching = false
    private var attempts = 0
    private var remoteCount = 1
    /** What the core (or the stunnel layer) last reported; it ends the session when no attempt is left */
    private var lastReason: String? = null
    private var stunnelError: String? = null
    /** Bumped by every core start; an older core's events change nothing */
    private var generation = 0
    private var running = false
    private var relay: StunnelRelay? = null
    private var lastPathHadWifi = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private var pingCallback: ((Long) -> Unit)? = null
    private var pingPort = 0
    private var pingStarted = 0L
    private var pingHttpStarted = false
    private var pingEpoch = 0
    @Volatile private var tunnelAddress = ByteArray(4)

    private val startTimeout = Runnable {
        if (!closed && !started) failWithReason(lastReason ?: "Connection timed out. The server did not respond.")
    }

    fun start() {
        current = this
        eventThread
        probeThread
        worker.post {
            worker.postDelayed(startTimeout, START_TIMEOUT_MS)
            startPathMonitor()
            startCore()
        }
    }

    override fun close() {
        worker.post {
            if (closed) return@post
            ConnectionLog.m("OpenVPN: disconnecting")
            closeNow()
        }
    }

    override fun pauseForSleep() {
        worker.post {
            if (onSleep == 2 || closed || failed) return@post
            ConnectionLog.m("device sleep: ${if (onSleep == 1) "pausing" else "closing"} the OpenVPN connection")
            sleepPaused = true
            endCore()
        }
    }

    override fun wakeFromSleep() {
        worker.post {
            if (!sleepPaused || closed || failed) return@post
            sleepPaused = false
            if (onSleep == 1 || autoReconnect) {
                attempts = 0
                ConnectionLog.m("device wake: reconnecting the OpenVPN connection")
                startCore()
            } else {
                // Off without Auto Reconnect leaves no connection; end the tunnel instead of keeping a VPN that drops every packet
                failWithReason("The connection was closed while the device slept.")
            }
        }
    }

    /** What Switch to Wi-Fi does when Wi-Fi appears (also the tests' path switch) */
    fun switchNetworkPath() {
        worker.post {
            ConnectionLog.m("OpenVPN: network path switch requested")
            moveToNewPath()
        }
    }

    // A new core; the previous one ends first
    private fun startCore() {
        if (closed || failed || sleepPaused) return
        endCore()
        val number = ++generation
        val text = profile.ovpnProfile
        if (text.isBlank()) return failWithReason("The OpenVPN profile is empty. Import an .ovpn file.")
        if (OpenVpnProfileText.usesStaticKey(text)) {
            return failWithReason("This profile uses an OpenVPN static key (secret), which OpenVPN 3 does not support. Ask for a profile with certificates (TLS mode).")
        }
        if (OpenVpnProfileText.hasEncryptedKey(text)) {
            return failWithReason("The profile's private key is protected with a passphrase, which this app cannot enter. Export the key without a passphrase (for example: openssl pkey -in client.key -out client-plain.key) and import the profile again.")
        }
        val remote = OpenVpnProfileText.firstRemote(text)
        val server = profile.server.trim()
        val port = profile.port.trim()
        // The Server and Port fields start as the first remote line; changed, they replace the profile's remotes
        var serverOverride = if (server.isNotEmpty() && !server.equals(remote.host, ignoreCase = true)) server else ""
        var portOverride = if ((port.toIntOrNull() ?: 0) > 0 && port.toIntOrNull() != remote.port.toIntOrNull()) port else ""
        remoteCount = if (serverOverride.isEmpty() && portOverride.isEmpty()) OpenVpnProfileText.remoteCount(text) else 1
        var proto = ""
        var via = remote.proto.uppercase()
        if (profile.ovpnStunnelEnabled) {
            val stunnelHost = profile.ovpnStunnelHost.trim().ifEmpty { server.ifEmpty { remote.host } }
            if (stunnelHost.isEmpty()) return failWithReason("stunnel is on, but neither stunnel Host nor Server is set.")
            val stunnelPort = profile.ovpnStunnelPort.trim().toIntOrNull()?.takeIf { it in 1..65535 } ?: 443
            val created = try {
                StunnelRelay(stunnelHost, stunnelPort, profile.ovpnStunnelSni.trim().ifEmpty { stunnelHost }, profile.ovpnStunnelCa,
                    profile.tlsFragMode, profile.tlsFragFirst, profile.tlsFragFollowing, cellular,
                    log = { line -> ConnectionLog.m(line) },
                    onError = { message -> worker.post { if (number == generation) stunnelError = message } })
            } catch (error: Exception) {
                return failWithReason("The stunnel layer could not start: ${error.message}")
            }
            relay = created
            created.start()
            // stunnel carries TCP: a UDP profile goes inside it as TCP instead of bypassing it
            serverOverride = "127.0.0.1"
            portOverride = created.localPort.toString()
            proto = "tcp"
            remoteCount = 1
            via = "TCP inside stunnel TLS to $stunnelHost:$stunnelPort"
        }
        stunnelError = null
        // stunnel carries TCP: a UDP profile is turned into TCP itself
        val content = if (profile.ovpnStunnelEnabled) OpenVpnProfileText.withProtocol(text, "tcp") else text
        val result = OpenVpnNative.start(number, content, profile.username.trim(), profile.password, serverOverride, portOverride, proto,
            !OpenVpnProfileText.hasClientCertificate(text))
        when {
            result.startsWith("ERR\t") -> return failWithReason(openVpnInvalidProfileMessage(result.removePrefix("ERR\t"), text))
            result == "CREDS" -> return failWithReason("This profile requires a username and password (auth-user-pass). Enter them in the profile editor.")
        }
        running = true
        val parts = result.split('\t')
        val shownHost = if (profile.ovpnStunnelEnabled) remote.host else serverOverride.ifEmpty { parts.getOrNull(1).orEmpty() }
        val shownPort = if (profile.ovpnStunnelEnabled) remote.port else portOverride.ifEmpty { parts.getOrNull(2).orEmpty() }
        ConnectionLog.m("OpenVPN: connecting to $shownHost:$shownPort over $via ($remoteCount remote${if (remoteCount == 1) "" else "s"}, " +
            "auto reconnect ${if (autoReconnect) "on" else "off"}, retry times $retryTimes)")
    }

    /** Ends the running core; its events no longer count. */
    private fun endCore() {
        if (running) {
            running = false
            up = false
            generation++
            finishPing(-1)
            OpenVpnNative.stop()
        }
        relay?.close()
        relay = null
    }

    private fun moveToNewPath() {
        if (!up || closed || failed) return
        pathSwitching = true
        attempts = 0
        OpenVpnNative.reconnect()
    }

    /** An event of the core, on the worker */
    private fun handleEvent(number: Int, type: Char, text: String) {
        if (number != generation || closed || failed || sleepPaused) return
        when (type) {
            'L' -> coreLog(text)
            'S' -> applySettings(text)
            'E' -> {
                val parts = text.split('|', limit = 4)
                coreEvent(parts.getOrNull(0).orEmpty(), parts.getOrNull(1) == "1", parts.getOrNull(2) == "1", parts.getOrNull(3).orEmpty())
            }
            'X' -> {
                running = false
                up = false
                failWithReason(lastReason ?: text.ifEmpty { "The OpenVPN session ended." })
            }
        }
    }

    private fun coreLog(line: String) {
        if (expert) ConnectionLog.m("OpenVPN core: $line")
        // What the core reports only in its log: lost connections, failed connects, refused pushed settings
        val reason = openVpnLogMessage(line) ?: return
        if (pathSwitching) return
        // Before the tunnel was up, a silence after the TLS handshake usually means the server refused this client
        lastReason = if (!everEstablished && "KEEPALIVE_TIMEOUT" in line) {
            "The server stopped answering after the TLS handshake. It may have refused the client certificate (revoked, from another CA or expired); the server's log names the reason."
        } else {
            stunnelError ?: reason
        }
    }

    private fun applySettings(text: String) {
        val lines = text.split('\n')
        val request = lines.firstOrNull()?.toIntOrNull() ?: return
        val options = lines.drop(2).filter { it.isNotEmpty() }.map { it.split('\t') }
        val settings = OpenVpnSettings.tunnelSettings(options)
        if (settings == null) {
            OpenVpnNative.attachTun(-1, request)
            return failWithReason("The server assigned no IPv4 address; this app needs one.")
        }
        tunnelAddress = ProbePackets.ipv4(settings.address) ?: ByteArray(4)
        ConnectionLog.m("OpenVPN: applying settings addr=${settings.address}/${settings.addressPrefix} " +
            "routes=${if (settings.routes == listOf("0.0.0.0" to 0)) "default" else settings.routes.size} dns=${settings.dnsServers} mtu=${settings.mtu}")
        val problem = host.applyTunnelSettings(settings) { fd -> OpenVpnNative.attachTun(fd, request) }
        if (problem != null) {
            OpenVpnNative.attachTun(-1, request)
            failWithReason("The tunnel could not be set up: $problem")
        }
    }

    private fun coreEvent(name: String, error: Boolean, fatal: Boolean, info: String) {
        if (error || expert) ConnectionLog.m("OpenVPN event $name${if (info.isNotEmpty()) ": $info" else ""}")
        when {
            name == "CONNECTED" -> {
                val again = everEstablished
                up = true
                everEstablished = true
                attempts = 0
                pathSwitching = false
                lastReason = null
                stunnelError = null
                ConnectionLog.m("OpenVPN: session established${if (again) " again" else ""}${if (info.isNotEmpty()) ": $info" else ""}")
                if (!started) {
                    started = true
                    worker.removeCallbacks(startTimeout)
                }
                host.onConnected()
            }
            name == "RECONNECTING" -> coreReconnecting()
            fatal -> failWithReason(openVpnEventMessage(name, info))
            error -> {
                // TRANSPORT_ERROR, TUN_ERROR, CLIENT_RESTART: the core tries again in 5 seconds unless no attempt is left
                lastReason = stunnelError ?: openVpnEventMessage(name, info)
                up = false
                if (!pathSwitching && !mayTryAgain()) failWithReason(finalMessage())
            }
        }
    }

    private fun coreReconnecting() {
        if (pathSwitching) {
            pathSwitching = false
            ConnectionLog.m("OpenVPN: moving the connection to the current network path")
            return
        }
        up = false
        if (lastReason == null) lastReason = stunnelError ?: if (everEstablished) "The server stopped answering." else "The server did not answer."
        if (!mayTryAgain()) return failWithReason(finalMessage())
        attempts++
        ConnectionLog.m("OpenVPN: $lastReason Reconnecting (attempt $attempts${if (retryTimes > 0) " of $retryTimes" else ""}).")
    }

    /**
     * Whether the core may make another attempt now that one failed. Before the tunnel was ever up, an attempt goes to every
     * remote line of the profile once, again only for an explicit Retry Times budget (as SSTP, SoftEther, SSL VPN and SSH);
     * after it was up, Auto Reconnect and Retry Times decide.
     */
    private fun mayTryAgain(): Boolean {
        if (everEstablished) return autoReconnect && (retryTimes <= 0 || attempts < retryTimes)
        val budget = remoteCount * (if (autoReconnect) 1 + retryTimes.coerceAtLeast(0) else 1)
        return attempts + 1 < budget
    }

    private fun finalMessage(): String {
        val reason = lastReason ?: "The connection to the server was lost."
        val bare = reason.removeSuffix(".")
        if (everEstablished && !autoReconnect) return "$bare (auto reconnect is off)."
        if (retryTimes > 0 && autoReconnect) return "Could not ${if (everEstablished) "reconnect" else "connect"} after $retryTimes attempts. ($bare)"
        return reason
    }

    /** Times one HTTP request to 1.1.1.1 through the tunnel, as SshClient does: this app stays outside its own tunnel. */
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
            OpenVpnNative.setProbeFlows(intArrayOf(ProbePackets.PROTOCOL_TCP, ProbePackets.ipv4Int(PROBE_ADDRESS), pingPort))
            sendPingSyn(epoch)
            worker.postDelayed({ if (epoch == pingEpoch) finishPing(-2) }, PING_TIMEOUT_MS)
        }
    }

    private fun sendPingSyn(epoch: Int) {
        if (epoch != pingEpoch || pingCallback == null || pingHttpStarted || closed) return
        OpenVpnNative.submit(ProbePackets.syn(tunnelAddress, ipv4(PROBE_ADDRESS), pingPort))
        worker.postDelayed({ sendPingSyn(epoch) }, 1000)
    }

    private fun finishPing(value: Long) {
        val callback = pingCallback ?: return
        pingCallback = null
        pingEpoch++
        OpenVpnNative.setProbeFlows(IntArray(0))
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
            OpenVpnNative.submit(ProbePackets.httpRequest(tunnelAddress, ipv4(PROBE_ADDRESS), pingPort, u32(packet, ihl + 4) + 1))
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
                    ConnectionLog.m("Wi-Fi became available; moving the OpenVPN connection to it")
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
        if (closed || failed) return
        failed = true
        ConnectionLog.m("OpenVPN: closing with reason: $reason")
        closeNow()
        host.onFailure(reason)
    }

    private fun closeNow() {
        if (closed) return
        closed = true
        worker.removeCallbacks(startTimeout)
        stopPathMonitor()
        endCore()
        OpenVpnNative.attachTun(-1, 0)
        if (current === this) current = null
        host.onClosed()
    }

    companion object {
        private val worker by lazy { Handler(HandlerThread("srp.openvpn").apply { start() }.looper) }

        @Volatile private var current: OpenVpnClient? = null

        private val eventThread by lazy {
            Thread({
                while (true) {
                    val bytes = OpenVpnNative.nextEvent(1000) ?: continue
                    val event = String(bytes, Charsets.UTF_8)
                    val parts = event.split('|', limit = 3)
                    val number = parts.getOrNull(0)?.toIntOrNull() ?: continue
                    val type = parts.getOrNull(1)?.firstOrNull() ?: continue
                    val text = parts.getOrNull(2).orEmpty()
                    current?.let { client -> worker.post { client.handleEvent(number, type, text) } }
                }
            }, "srp.openvpn.events").apply {
                isDaemon = true
                start()
            }
        }

        private val probeThread by lazy {
            Thread({
                while (true) {
                    val packet = OpenVpnNative.nextProbe(1000) ?: continue
                    current?.let { client -> worker.post { client.handlePingPacket(packet) } }
                }
            }, "srp.openvpn.probes").apply {
                isDaemon = true
                start()
            }
        }

        private const val PROBE_ADDRESS = "1.1.1.1"
        private const val START_TIMEOUT_MS = 45000L
        private const val PING_TIMEOUT_MS = 15000L
    }
}
