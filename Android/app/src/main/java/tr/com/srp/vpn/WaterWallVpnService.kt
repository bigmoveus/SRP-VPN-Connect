package tr.com.srp.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONException
import java.io.File
import kotlin.concurrent.thread

// shortcut: stays alive only while the system holds the VPN, with no foreground notification,
// reconnect or network-change handling; those come with the lifecycle port.
class WaterWallVpnService : VpnService() {
    private var connected = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> if (!connected) connect()
            ACTION_DISCONNECT -> if (connected) WaterWall.stop()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        if (connected) WaterWall.stop()
    }

    override fun onDestroy() {
        if (connected) WaterWall.stop()
        super.onDestroy()
    }

    private fun connect() {
        val log = logFile(this)
        val nodes = nodesFile(this).readText()
        val appDns = try {
            tunnelDnsServers(nodes)
        } catch (error: JSONException) {
            log.writeText("Invalid nodes JSON: ${error.message}\n")
            stopSelf()
            return
        }
        val connectivity = getSystemService(ConnectivityManager::class.java)
        // This app is outside the tunnel, so activeNetwork is the real network even after the tunnel is up.
        val networkDns = connectivity.getLinkProperties(connectivity.activeNetwork)?.dnsServers.orEmpty()
            .mapNotNull { it.hostAddress }
        val builder = Builder()
            .setSession("SRP VPN")
            .setMtu(TUNNEL_MTU)
            // shortcut: raw IPv4 and AEAD chains need 10.44.0.4 like on iOS, upgrade with the chain builder port.
            .addAddress("10.89.0.1", 24)
            .addRoute("0.0.0.0", 0)
            // WaterWall's own sockets would loop into the tunnel without this, and upstream has no protect() hook.
            .addDisallowedApplication(packageName)
        appDns.forEach { builder.addDnsServer(it) }
        val tun = builder.establish()
        if (tun == null) {
            log.writeText("Android refused the VPN: permission was withdrawn\n")
            stopSelf()
            return
        }
        if (!WaterWall.start(tun.fd, coreJson(cacheDir.path, networkDns), nodes, log.path)) {
            log.appendText("WaterWall did not start\n")
            tun.close()
            stopSelf()
            return
        }
        log.appendText("Tunnel up, network DNS $networkDns, apps' DNS $appDns\n")
        connected = true
        running.value = true
        thread(name = "waterwall-await") {
            val code = WaterWall.await()
            Handler(Looper.getMainLooper()).post {
                log.appendText("Tunnel down, exit code $code\n")
                tun.close()
                connected = false
                running.value = false
                stopSelf()
            }
        }
    }

    companion object {
        const val ACTION_CONNECT = "tr.com.srp.vpn.CONNECT"
        const val ACTION_DISCONNECT = "tr.com.srp.vpn.DISCONNECT"
        val running = MutableStateFlow(false)

        fun nodesFile(context: Context) = File(context.filesDir, "nodes.json")
        fun logFile(context: Context) = File(context.cacheDir, "waterwall.log")
    }
}
