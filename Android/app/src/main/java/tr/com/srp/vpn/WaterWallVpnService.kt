package tr.com.srp.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import java.net.Inet4Address
import java.net.InetAddress
import kotlin.concurrent.thread

/** What the home screen follows, the counterpart of PDVPNManager's status on iOS. */
object VpnState {
    enum class Status { Disconnected, Connecting, Connected }

    val status = MutableStateFlow(Status.Disconnected)

    @Volatile var connectedProfileId: String? = null

    /** The reason of the last failure and when it happened. */
    @Volatile var lastError: Pair<String, Long>? = null

    @Volatile var client: TunnelClient? = null
}

/** The counterpart of the iOS packet tunnel provider: turns profiles into candidates and owns the tunnel. */
class WaterWallVpnService : VpnService(), WaterWallClient.Host {
    private val main = Handler(Looper.getMainLooper())
    private var client: TunnelClient? = null
    private var tun: ParcelFileDescriptor? = null
    private var tunSettings: TunnelSettings? = null
    private var logLevel = 0
    private var connecting = false
    private var connectRequest = 0
    private var freshNetwork = false

    private val sleepReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                Intent.ACTION_SCREEN_OFF -> client?.pauseForSleep()
                Intent.ACTION_SCREEN_ON -> client?.wakeFromSleep()
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> disconnect()
            ACTION_CONNECT -> connect(intent.getStringExtra(EXTRA_PROFILE), intent.getBooleanExtra(EXTRA_ALLOW_UNTRUSTED, false))
            // Android starts the service itself for an always-on VPN.
            else -> if (client == null && !connecting) connect(getSharedPreferences(PREFERENCES, MODE_PRIVATE).getString(KEY_LAST_PROFILE, null))
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        disconnect()
    }

    override fun onDestroy() {
        connectRequest++
        finishTunnel()
        super.onDestroy()
    }

    private fun connect(profileId: String?, allowUntrusted: Boolean = false) {
        if (client != null || connecting) return
        connecting = true
        val request = ++connectRequest
        VpnState.status.value = VpnState.Status.Connecting
        VpnState.connectedProfileId = profileId
        VpnState.lastError = null
        getSharedPreferences(PREFERENCES, MODE_PRIVATE).edit().putString(KEY_LAST_PROFILE, profileId).apply()
        goForeground("Connecting…")
        // Looking up the server takes the network, so it stays off the main thread.
        thread(name = "waterwall-connect") {
            ConnectionLog.open(this)
            val profiles = ProfileStore(this).load()
            val profile = profiles.firstOrNull { it.nodeId == profileId }
            if (profile != null && (profile.isSstp || profile.isSoftEther || profile.isOpenConnect || profile.isSsh || profile.isOpenVpn)) {
                // Certificate login reads the PKCS#12 from the store here, off the main thread
                val certificate = if (profile.certificateMode) CertificateStore(this).load(profile.certKey) else null
                main.post {
                    if (request != connectRequest) return@post
                    connecting = false
                    if (profile.certificateMode && certificate == null) fail("The client certificate could not be read. Re-import it in the profile.")
                    else startSstp(profile, profile.allowInsecure || allowUntrusted, certificate)
                }
                return@thread
            }
            var failure: String? = null
            val selected = if (profile == null) null else candidateFor(profile) { failure = it }
            val fallbacks = if (selected == null || !profile!!.autoSwitch) emptyList() else fallbackProfiles(profile, profiles).mapNotNull { other ->
                var reason: String? = null
                candidateFor(other) { reason = it }.also {
                    if (it == null) ConnectionLog.m("WaterWall: Auto Switch skips ${other.desc.ifEmpty { "a profile" }}: $reason")
                }
            }
            main.post {
                // Disconnected meanwhile, and perhaps connecting again with a request of its own.
                if (request != connectRequest) return@post
                connecting = false
                if (selected == null) fail(failure ?: "Add a profile first (tap +)") else start(profile!!, selected, fallbacks)
            }
        }
    }

    private fun start(profile: Profile, selected: WaterWallCandidate, fallbacks: List<WaterWallCandidate>) {
        logLevel = profile.logLevel
        WaterWall.setLog(ConnectionLog.file(this).path, logLevel)
        val started = WaterWallClient(selected, fallbacks, profile.autoReconnect, profile.retryTimes, profile.switchToWifi, profile.onSleep,
            getSystemService(ConnectivityManager::class.java), this)
        client = started
        VpnState.client = started
        registerReceiver(sleepReceiver, IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        })
        ConnectionLog.m("WaterWall: starting client")
        started.start()
    }

    private fun startSstp(profile: Profile, allowInsecure: Boolean, certificate: Pair<ByteArray, String>?) {
        logLevel = profile.logLevel
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val cellular = {
            connectivity.getNetworkCapabilities(connectivity.activeNetwork)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) == true
        }
        val started = if (profile.isSsh) SshClient(profile, connectivity, this)
                      else if (profile.isOpenVpn) OpenVpnClient(profile, connectivity, cellular, this)
                      else if (profile.isSoftEther) SoftEtherClient(applicationContext, profile, allowInsecure, certificate, cellular, connectivity, this)
                      else if (profile.isOpenConnect) SslVpnClient(applicationContext, profile, allowInsecure, certificate, cellular, connectivity, this)
                      else SstpClient(applicationContext, profile, allowInsecure, certificate, cellular, connectivity, this)
        client = started
        VpnState.client = started
        registerReceiver(sleepReceiver, IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        })
        when (started) {
            is SoftEtherClient -> started.start()
            is SslVpnClient -> started.start()
            is SshClient -> started.start()
            is OpenVpnClient -> started.start()
            else -> (started as SstpClient).start()
        }
    }

    private fun disconnect() {
        if (client !is SstpClient && client !is SoftEtherClient && client !is SslVpnClient && client !is SshClient && client !is OpenVpnClient) ConnectionLog.m("WaterWall: disconnecting")
        connecting = false
        connectRequest++
        finishTunnel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun finishTunnel() {
        val closing = client
        client = null
        VpnState.client = null
        if (closing != null) {
            runCatching { unregisterReceiver(sleepReceiver) }
            closing.close()
        }
        VpnState.status.value = VpnState.Status.Disconnected
    }

    private fun fail(reason: String) {
        VpnState.lastError = reason to System.currentTimeMillis()
        finishTunnel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun coreJson(): String {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        // This app is outside the tunnel, so activeNetwork is the real network even while the tunnel is up.
        val dns = connectivity.getLinkProperties(connectivity.activeNetwork)?.dnsServers.orEmpty().mapNotNull { it.hostAddress }
        return ChainConfig.coreJson(logLevel, cacheDir.path, dns)
    }

    override fun applyTunnelSettings(settings: TunnelSettings, attach: (Int) -> Unit): String? {
        // An SSTP reconnect that gets the same address and DNS keeps the tunnel the system already has
        val existing = tun
        if (existing != null && (client is SstpClient || client is SoftEtherClient || client is SslVpnClient || client is SshClient || client is OpenVpnClient) && settings == tunSettings) {
            attach(existing.fd)
            return null
        }
        val established = try {
            val builder = Builder()
                .setSession("SRP VPN Connect")
                .setMtu(settings.mtu)
                .addAddress(settings.address, settings.addressPrefix)
                // WaterWall's own sockets would loop into the tunnel without this, and upstream has no protect() hook.
                .addDisallowedApplication(packageName)
            // The new runtime never gave out the placeholder addresses in the system's DNS cache, and may give them to other names.
            // Applying settings drops that cache on iOS. Android keeps the network, and its cache, unless the list of apps differs;
            // naming the same app twice changes the list and nothing else.
            freshNetwork = !freshNetwork
            if (freshNetwork) builder.addDisallowedApplication(packageName)
            // Otherwise Android counts the VPN as metered on any network, and apps hold back on Wi-Fi.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
            settings.routes.forEach { (address, prefix) -> builder.addRoute(address, prefix) }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                settings.excludedRoutes.forEach { (address, prefix) -> builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName(address), prefix)) }
            }
            // A DNS line of a wg-quick file may hold search domains too.
            settings.dnsServers.forEach { if (ProbePackets.ipv4(it) != null || ':' in it) builder.addDnsServer(it) else builder.addSearchDomain(it) }
            builder.establish()
        } catch (error: Exception) {
            return error.message ?: "the system refused the settings"
        } ?: return "VPN permission was withdrawn"
        val previous = tun
        tun = established
        tunSettings = settings
        attach(established.fd)
        previous?.close()
        return null
    }

    override fun onConnected() {
        main.post {
            if (client == null) return@post
            VpnState.status.value = VpnState.Status.Connected
            goForeground("Connected")
        }
    }

    override fun onFailure(reason: String) {
        main.post { fail(reason) }
    }

    override fun onClosed() {
        tun?.close()
        tun = null
        tunSettings = null
    }

    private fun goForeground(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "VPN connection", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("SRP VPN Connect")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION, notification)
        }
    }

    /** Turns one profile into its node graph and tunnel settings; [failure] gets the reason when the profile is unusable. */
    private fun candidateFor(profile: Profile, failure: (String) -> Unit): WaterWallCandidate? {
        val configuration = ChainConfig.configurationWithJson(profile.configJson)
        if (configuration == null) {
            failure("The WaterWall configuration is invalid.")
            return null
        }
        @Suppress("UNCHECKED_CAST")
        val geoIp = configuration["geoip"] as? Map<String, Any?>
        val options = linkedMapOf<String, Any?>(
            "username" to profile.username, "ww_fake_dns" to profile.fakeDns, "ww_smart_routing" to profile.smartRouting,
            "log_level" to listOf("normal", "expert", "debug")[profile.logLevel], "tls_frag" to profile.tlsFragMode.toLong(),
            "tls_frag_first" to profile.tlsFragFirst.toLong(), "tls_frag_following" to profile.tlsFragFollowing.toLong(),
        )
        if (geoIp?.get("iran-direct") == true || (geoIp?.get("countries") as? List<*>).orEmpty().isNotEmpty()) {
            val database = GeoIpDatabase(this)
            val problem = database.currentFile?.let { database.validationError(it) } ?: if (database.currentFile == null) "A valid GeoIP country database is required." else null
            if (problem != null) {
                failure("GeoIP is enabled but its database is unavailable: $problem")
                return null
            }
            options["ww_geoip_db_path"] = database.currentFile!!.path
        }
        val wireGuardMode = ChainConfig.isWireGuard(configuration)
        val direct = ChainConfig.isDirect(configuration)
        var probeTcp = true
        var probeUdp = true
        if (configuration["mode"] == "chain") {
            @Suppress("UNCHECKED_CAST")
            val application = (configuration["node-options"] as? Map<String, Any?>)?.get("application") as? Map<String, Any?>
            val protocol = application?.get("protocol") ?: application?.get("proto")
            if (configuration["application"] == "http-proxy") probeUdp = false
            if (protocol == "tcp" || protocol == "connect") probeUdp = false
            else if (protocol == "udp" || protocol == "udp-associate") probeTcp = false
        }
        var tunnelAddress = if (configuration["input"] == "raw-ipv4" || configuration["outer"] == "aead") "10.44.0.4" else "10.89.0.1"
        val serverAddress = profile.server.ifEmpty { "127.0.0.1" }
        var endpointAddress: String? = null
        if (!wireGuardMode && !direct) {
            endpointAddress = resolvedAddress(serverAddress)
            if (endpointAddress == null) {
                failure("The WaterWall server address could not be resolved.")
                return null
            }
        }
        var dnsServers = listOf("1.1.1.1", "1.0.0.1")
        var allowedIps: String? = null
        val nodesJson: String?
        if (wireGuardMode) {
            val config = profile.wgEffectiveConfig().orEmpty()
            val wireGuard = if (config.isNotEmpty()) ChainConfig.wireGuardWithConfig(config)
            else ChainConfig.wireGuardWithKeys(profile.wgPrivateKey, profile.wgPeerPublicKey, profile.server, profile.effectivePort.toLongOrNull() ?: 0, profile.wgAddress, profile.wgKeepalive.toLong())
            nodesJson = wireGuard?.nodesJson
            if (wireGuard != null) {
                tunnelAddress = wireGuard.tunnelAddress
                dnsServers = wireGuard.dnsServers
                allowedIps = wireGuard.allowedIps
            }
        } else {
            // The SNI field applies to outer TLS, Reality and QUIC only. Left empty it means the server name, except for
            // Reality, where the builder uses its www.cloudflare.com cover; the server argument is a resolved address.
            val typedSni = if (ChainConfig.usesTls(configuration)) profile.customSni else ""
            val sni = typedSni.ifEmpty { if (configuration["outer"] == "reality") "" else serverAddress }
            nodesJson = ChainConfig.nodesJson(configuration, endpointAddress ?: serverAddress, profile.effectivePort.toLongOrNull() ?: 0, sni,
                !profile.allowInsecure, profile.password, profile.outerSecret, options)
        }
        if (nodesJson.isNullOrEmpty()) {
            failure("The WaterWall profile is incomplete or invalid.")
            return null
        }
        if (!wireGuardMode) {
            val nodes = (Json.parse(nodesJson) as Map<*, *>)["nodes"] as List<*>
            probeUdp = probeUdp && (nodes.last() as Map<*, *>)["type"] == "TcpUdpConnector"
        }
        val probeAddress = profile.probeIp.ifEmpty { "1.1.1.1" }
        val fakeDns = profile.fakeDns && ChainConfig.allowsRouting(configuration)
        val dnsProbeAddress = if (fakeDns) "198.18.0.2" else profile.dnsProbeIp.ifEmpty { probeAddress }
        if (fakeDns) dnsServers = listOf("198.18.0.2")
        if (wireGuardMode) {
            probeTcp = probeTcp && probeAddressAllowed(probeAddress, allowedIps)
            probeUdp = probeUdp && probeAddressAllowed(dnsProbeAddress, allowedIps)
        }
        return WaterWallCandidate(
            name = profile.desc.ifEmpty { ChainConfig.summary(configuration) },
            nodesJson = nodesJson,
            remoteAddress = serverAddress,
            tunnelAddress = tunnelAddress,
            probeAddress = probeAddress,
            dnsProbeAddress = dnsProbeAddress,
            probeTcp = probeTcp,
            probeUdp = probeUdp,
            dnsServers = dnsServers,
            allowedIps = allowedIps,
            udpCarrier = ChainConfig.usesUdpCarrier(configuration),
        )
    }

    private fun resolvedAddress(host: String): String? {
        if (ProbePackets.ipv4(host) != null) return host
        return runCatching { InetAddress.getAllByName(host).firstOrNull { it is Inet4Address }?.hostAddress }.getOrNull()
    }

    private fun probeAddressAllowed(address: String, allowedIps: String?): Boolean {
        if (allowedIps.isNullOrEmpty()) return true
        if (ProbePackets.ipv4(address) == null) return false
        val ip = ProbePackets.ipv4Int(address)
        return allowedIps.split(',').any { entry ->
            val parts = entry.trim().split('/')
            val prefix = parts.getOrNull(1)?.toIntOrNull() ?: -1
            if (parts.size != 2 || prefix !in 0..32 || ProbePackets.ipv4(parts[0]) == null) return@any false
            val mask = if (prefix == 0) 0 else -1 shl (32 - prefix)
            ip and mask == ProbePackets.ipv4Int(parts[0]) and mask
        }
    }

    companion object {
        const val ACTION_CONNECT = "tr.com.srp.vpn.CONNECT"
        const val ACTION_DISCONNECT = "tr.com.srp.vpn.DISCONNECT"
        const val EXTRA_PROFILE = "profile"
        /** The user chose Continue on the certificate warning: this connection skips verification, the profile stays as it is. */
        const val EXTRA_ALLOW_UNTRUSTED = "allowUntrusted"
        private const val PREFERENCES = "vpn"
        private const val KEY_LAST_PROFILE = "lastProfile"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION = 1
        private const val FALLBACK_LIMIT = 8

        /** The other chain profiles of the same server that a failing or lossy connection can move to, other carrier first. */
        fun fallbackProfiles(profile: Profile, profiles: List<Profile>): List<Profile> {
            val server = profile.server.trim().lowercase()
            val own = profile.configuration
            fun switchable(configuration: Map<String, Any?>) = !ChainConfig.isWireGuard(configuration) && !ChainConfig.isDirect(configuration)
            if (!profile.autoSwitch || server.isEmpty() || !switchable(own)) return emptyList()
            val udp = ChainConfig.usesUdpCarrier(own)
            val others = profiles.filter { other ->
                other.nodeId != profile.nodeId && other.server.trim().lowercase() == server && switchable(other.configuration) &&
                    // A copy of the selected profile connects the same way, so it cannot take over.
                    !(other.configJson == profile.configJson && other.effectivePort == profile.effectivePort)
            }
            return others.sortedBy { if (ChainConfig.usesUdpCarrier(it.configuration) != udp) 0 else 1 }.take(FALLBACK_LIMIT)
        }
    }
}
