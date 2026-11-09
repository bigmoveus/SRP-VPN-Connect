package tr.com.srp.vpn

import android.os.Handler
import android.os.Looper
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.math.max

/** The TCP handshake time to a profile's server. This app stays outside its own tunnel, so the sockets reach the real network even while connected. */
class TcpPinger {
    private val main = Handler(Looper.getMainLooper())
    private val pool = Executors.newFixedThreadPool(CONCURRENCY)
    private val lookups = Executors.newCachedThreadPool()
    private var run = 0

    /** [result] gets the profile id, the milliseconds or -1, and whether it timed out; all callbacks run on the main thread. */
    fun ping(profiles: List<Profile>, result: (String, Int, Boolean) -> Unit, progress: (Int, Int) -> Unit, finished: () -> Unit) {
        val runId = ++run
        val targets = profiles.mapNotNull { profile -> endpoint(profile)?.let { Triple(profile.nodeId, it.first, it.second) } }
        var completed = 0
        if (targets.isEmpty()) {
            finished()
            return
        }
        for ((id, host, port) in targets) {
            pool.execute {
                val outcome = if (runId != run) null else measure(host, port)
                main.post {
                    if (runId != run) return@post
                    completed++
                    if (outcome != null) result(id, outcome.first, outcome.second)
                    progress(completed, targets.size)
                    if (completed == targets.size) finished()
                }
            }
        }
    }

    private fun measure(host: String, port: Int): Pair<Int, Boolean> {
        val started = System.nanoTime()
        fun left() = max(1, TIMEOUT_MS - ((System.nanoTime() - started) / 1_000_000).toInt())
        return try {
            val address = lookups.submit(Callable { InetAddress.getByName(host) }).get(TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)
            // The TCP handshake time leaves out name resolution.
            val handshake = System.nanoTime()
            Socket().use { it.connect(InetSocketAddress(address, port), left()) }
            ((System.nanoTime() - handshake) / 1_000_000).toInt() to false
        } catch (_: SocketTimeoutException) {
            -1 to true
        } catch (_: TimeoutException) {
            -1 to true
        } catch (_: Exception) {
            -1 to false
        }
    }

    companion object {
        private const val CONCURRENCY = 16
        private const val TIMEOUT_MS = 2500

        /** Host and port of a profile that reaches its server over TCP, or null for one without a TCP server. */
        fun endpoint(profile: Profile): Pair<String, Int>? {
            // WireGuard has no TCP server (SRPProfileLatencyTester on iOS)
            // Aether's Public mode has no server of its own, and Private mode reaches its server over WireGuard
            if (profile.isWireGuard || profile.isAether) return null
            var host = profile.server.trim()
            var port = profile.effectivePort.trim().toIntOrNull() ?: return null
            if (profile.isOpenVpn) {
                // OpenVPN reaches its server over TCP only through stunnel or with a TCP profile (SRPProfileLatencyTester on iOS)
                if (profile.ovpnStunnelEnabled) {
                    host = profile.ovpnStunnelHost.trim().ifEmpty { host }
                    port = profile.ovpnStunnelPort.trim().toIntOrNull() ?: 443
                } else if (!OpenVpnProfileText.firstRemote(profile.ovpnProfile).proto.lowercase().startsWith("tcp")) {
                    return null
                }
            } else if (!profile.isTlsVpn && !profile.isSsh) {
                val configuration = profile.configuration
                if (ChainConfig.isDirect(configuration) || ChainConfig.usesUdpCarrier(configuration)) return null
            }
            return if (host.isEmpty() || port !in 1..65535) null else host to port
        }

        fun text(milliseconds: Int, timedOut: Boolean) = when {
            milliseconds >= 0 -> "TCP: $milliseconds ms"
            timedOut -> "TCP: Timeout"
            else -> "TCP: Failed"
        }
    }
}
