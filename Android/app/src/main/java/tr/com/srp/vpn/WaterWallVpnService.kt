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

    /** The lifecycle tests' commands (debuggable builds only, `am broadcast -a tr.com.srp.vpn.TEST --es command ...`): Aether's
     *  session ends as if WARP had closed it, or the test a network change brings runs at once */
    private val testReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.getStringExtra("command")) {
                "aether-drop" -> (client as? AetherClient)?.debugDropSession()
                "path-switch" -> (client as? AetherClient)?.switchNetworkPath()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        if (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            if (android.os.Build.VERSION.SDK_INT >= 33) registerReceiver(testReceiver, IntentFilter(ACTION_TEST), Context.RECEIVER_EXPORTED)
            else registerReceiver(testReceiver, IntentFilter(ACTION_TEST))
        }
    }

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
        runCatching { unregisterReceiver(testReceiver) }
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
            if (profile != null && (profile.isSstp || profile.isSoftEther || profile.isOpenConnect || profile.isSsh || profile.isOpenVpn || profile.isWireGuard || profile.isAether)) {
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
            getSystemService(ConnectivityManager::class.java), this, profile.logLevel)
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
                      else if (profile.isWireGuard) WireGuardClient(profile, connectivity, this)
                      else if (profile.isAether) AetherClient(applicationContext, profile, connectivity, this)
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
            is WireGuardClient -> started.start()
            is AetherClient -> started.start()
            else -> (started as SstpClient).start()
        }
    }

    private fun disconnect() {
        if (client !is SstpClient && client !is SoftEtherClient && client !is SslVpnClient && client !is SshClient && client !is OpenVpnClient && client !is WireGuardClient && client !is AetherClient) ConnectionLog.m("WaterWall: disconnecting")
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
        if (existing != null && (client is SstpClient || client is SoftEtherClient || client is SslVpnClient || client is SshClient || client is OpenVpnClient || client is WireGuardClient) && settings == tunSettings) {
            attach(existing.fd)
            return null
        }
        val established = try {
            val builder = Builder()
                .setSession("SRP VPN Connect")
                .setMtu(settings.mtu)
                .addAddress(settings.address, settings.addressPrefix)
                .apply { settings.extraAddresses.forEach { (address, prefix) -> addAddress(address, prefix) } }
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

    /**
     * Turns one WaterWall profile into what WaterWall runs and the tunnel's settings (PacketTunnelProvider
     * waterWallChainCandidateWithOptions): its input hint becomes the input Settings → WaterWall Input chooses, and the fixed server
     * names of its connectors are resolved here. [failure] gets the reason when the profile cannot connect.
     */
    private fun candidateFor(profile: Profile, failure: (String) -> Unit): WaterWallCandidate? {
        if (profile.chainJson.isEmpty()) {
            failure("The WaterWall profile is missing from the app's secret store; open it in the app and save it again.")
            return null
        }
        val (document, invalid) = NodeChain.documentWithJson(profile.chainJson)
        if (document == null) {
            failure("The WaterWall profile is invalid: $invalid")
            return null
        }
        var geoIpPath: String? = null
        if (NodeChain.usesGeoIp(document)) {
            val database = GeoIpDatabase(this)
            val current = database.currentFile
            val problem = if (current == null) "A valid GeoIP country database is required." else database.validationError(current)
            if (problem != null) {
                failure("GeoIP is enabled but its database is unavailable: $problem")
                return null
            }
            geoIpPath = current!!.path
        }
        val input = AppSettings(this).waterWallInput
        val endpoints = NodeChain.endpoints(document)
        val addresses = LinkedHashMap<String, String>()
        for ((host, _) in endpoints) {
            if (host in addresses) continue
            addresses[host] = resolvedAddress(host) ?: run {
                failure("The WaterWall server address $host could not be resolved.")
                return null
            }
        }
        val connections = NodeChain.hint(document)?.get("type") == NodeChain.HINT_CONNECTION
        val fakeDns = profile.fakeDns && connections && input == NodeChain.INPUT_TUN
        val (runtime, problem) = NodeChain.runtimeDocument(document, input, fakeDns, geoIpPath, addresses)
        if (runtime == null) {
            failure(problem!!)
            return null
        }
        val chain = NodeChain.chain(document)
        var probeTcp = true
        var probeUdp = true
        var tunnelAddress = "10.89.0.1"
        val applications = setOf("VlessClient", "VmessClient", "TrojanClient", "Socks5Client", "HttpProxyClient")
        for (node in chain) {
            // An HTTP CONNECT proxy carries TCP only, and an application with a fixed protocol carries that one
            val settings = node["settings"] as? Map<*, *>
            val protocol = settings?.get("protocol") ?: settings?.get("proto")
            if (node["type"] == "HttpProxyClient") probeUdp = false
            if (node["type"] in applications && (protocol == "tcp" || protocol == "connect")) probeUdp = false
            if (node["type"] in applications && (protocol == "udp" || protocol == "udp-associate")) probeTcp = false
            if (node["type"] == "EncryptionClient") tunnelAddress = "10.44.0.4"
        }
        probeUdp = probeUdp && chain.lastOrNull()?.get("type") == "TcpUdpConnector"
        // Packets reach the far end with this source address, which our packet servers expect
        if (!connections) tunnelAddress = "10.44.0.4"
        val localProxy = input.takeIf { it != NodeChain.INPUT_TUN }
        val localProxyPort = NodeChain.portForInput(input)
        if (localProxy != null && !localPortIsFree(localProxyPort)) {
            failure("127.0.0.1:$localProxyPort is in use by another app, so the local ${if (localProxy == NodeChain.INPUT_SOCKS5) "SOCKS5" else "HTTP"} proxy cannot listen there. " +
                "Stop that app's proxy or choose another input in Settings → WaterWall Input.")
            return null
        }
        val probeAddress = profile.probeIp.ifEmpty { "1.1.1.1" }
        return WaterWallCandidate(
            name = profile.desc.ifEmpty { NodeChain.summary(document) },
            nodesJson = NodeChain.json(runtime),
            remoteAddress = endpoints.firstOrNull()?.first ?: "127.0.0.1",
            tunnelAddress = tunnelAddress,
            probeAddress = probeAddress,
            dnsProbeAddress = if (fakeDns) "198.18.0.2" else profile.dnsProbeIp.ifEmpty { probeAddress },
            probeTcp = probeTcp,
            // The probe asks a local proxy over TCP; what apps send over SOCKS5 UDP is theirs to check
            probeUdp = probeUdp && localProxy == null,
            dnsServers = if (fakeDns) listOf("198.18.0.2") else listOf("1.1.1.1", "1.0.0.1"),
            allowedIps = null,
            udpCarrier = NodeChain.usesUdpCarrier(document),
            localProxy = localProxy,
            localProxyPort = localProxyPort,
        )
    }

    private fun resolvedAddress(host: String): String? {
        if (ProbePackets.ipv4(host) != null) return host
        return runCatching { InetAddress.getAllByName(host).firstOrNull { it is Inet4Address }?.hostAddress }.getOrNull()
    }

    companion object {
        const val ACTION_CONNECT = "tr.com.srp.vpn.CONNECT"
        const val ACTION_DISCONNECT = "tr.com.srp.vpn.DISCONNECT"
        const val ACTION_TEST = "tr.com.srp.vpn.TEST"
        const val EXTRA_PROFILE = "profile"
        /** The user chose Continue on the certificate warning: this connection skips verification, the profile stays as it is. */
        const val EXTRA_ALLOW_UNTRUSTED = "allowUntrusted"
        private const val PREFERENCES = "vpn"
        private const val KEY_LAST_PROFILE = "lastProfile"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION = 1
        private const val FALLBACK_LIMIT = 8

        /** The other WaterWall profiles of the same server that a failing or lossy connection can move to, the other carrier first
         *  (CheckConnectData waterWallFallbacksForProfile). Empty when Auto Switch is off. */
        fun fallbackProfiles(profile: Profile, profiles: List<Profile>): List<Profile> {
            val server = profile.server.trim().lowercase()
            // The chain of a profile, or null when it is invalid or has no server of its own to share (a direct chain)
            fun switchable(candidate: Profile) = NodeChain.documentWithJson(candidate.chainJson).first?.takeIf { NodeChain.endpoints(it).isNotEmpty() }
            if (!profile.isWaterWall || !profile.autoSwitch || server.isEmpty()) return emptyList()
            val udp = NodeChain.usesUdpCarrier(switchable(profile) ?: return emptyList())
            val others = profiles.mapNotNull { other ->
                if (other.nodeId == profile.nodeId || !other.isWaterWall || other.server.trim().lowercase() != server) return@mapNotNull null
                val document = switchable(other)
                // A copy of the selected profile connects the same way, so it cannot take over.
                if (document == null || other.chainJson == profile.chainJson) null else other to NodeChain.usesUdpCarrier(document)
            }
            return others.sortedBy { if (it.second != udp) 0 else 1 }.map { it.first }.take(FALLBACK_LIMIT)
        }
    }
}
