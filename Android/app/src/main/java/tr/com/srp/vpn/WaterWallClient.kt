package tr.com.srp.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import kotlin.math.max
import kotlin.math.roundToInt
import kotlin.random.Random

/** One WaterWall profile the client can run: its node graph and the tunnel settings it needs. */
class WaterWallCandidate(
    val name: String,
    val nodesJson: String,
    val remoteAddress: String,
    val tunnelAddress: String,
    val probeAddress: String,
    val dnsProbeAddress: String,
    val probeTcp: Boolean,
    val probeUdp: Boolean,
    val dnsServers: List<String>,
    val allowedIps: String?,
    /** Reaches the server over UDP (KCP or QUIC datagrams) instead of a TCP connection. */
    val udpCarrier: Boolean,
)

data class TunnelSettings(val address: String, val dnsServers: List<String>, val routes: List<Pair<String, Int>>, val mtu: Int,
                          /** Ranges that stay outside the tunnel (an SSL VPN server's no-route lines); Android 13 and later */
                          val excludedRoutes: List<Pair<String, Int>> = emptyList(),
                          /** The address's prefix length (an OpenVPN server's netmask; 32 for its net30 topology) */
                          val addressPrefix: Int = 24)

/** What the VPN service does for a protocol's client. */
interface TunnelHost {
    /** Brings the tunnel to these settings and gives its fd to [attach]. Null means done, a text is why it failed. */
    fun applyTunnelSettings(settings: TunnelSettings, attach: (Int) -> Unit): String?

    fun onConnected()

    fun onFailure(reason: String)

    /** The protocol has stopped and the tunnel can close. */
    fun onClosed()
}

/** What the service and the home screen ask of a running protocol client. */
interface TunnelClient {
    fun close()

    fun pauseForSleep()

    fun wakeFromSleep()

    /** Milliseconds of one request through the tunnel, -1 for a failure or -2 for a timeout. */
    fun measurePing(result: (Long) -> Unit)
}

/**
 * The connection logic of SRPWaterWallClient.m on one worker thread: it proves the data plane before the tunnel takes traffic,
 * watches its health, reconnects, moves between the other profiles of a server and follows network changes and sleep.
 */
class WaterWallClient(
    selected: WaterWallCandidate,
    private val fallbacks: List<WaterWallCandidate>,
    private val autoReconnect: Boolean,
    private val retryTimes: Int,
    private val switchToWifi: Boolean,
    private val onSleep: Int,
    private val connectivity: ConnectivityManager,
    private val host: Host,
) : TunnelClient {
    interface Host : TunnelHost {
        /** The core settings for the next runtime start, with the DNS servers of the network at that moment. */
        fun coreJson(): String
    }

    private val candidates = listOf(selected) + fallbacks
    private var candidateIndex = 0
    private val lossyCandidates = HashSet<Int>()
    private var candidate = selected

    private var closed = false
    private var up = false
    private var sleepPaused = false
    private var reconnectPending = false
    private var failedAttempts = 0
    private var generation = 0
    private var started = false

    // 0 idle, 1 start TCP, 2 start DNS, 3 up and watching, 4 health TCP, 5 health DNS, 6 applying the tunnel settings, -1 failed.
    private var probeStage = 0
    private var probeAttempts = 0
    private var probeDnsId = 0
    private var probeTcpPort = 0
    private var probeHttpStarted = false
    private var probeResponseSequence = 0
    private var probeResponseHeader = ByteArray(0)
    private var probeEpoch = 0

    private var pingCallback: ((Long) -> Unit)? = null
    private var pingPort = 0
    private var pingStarted = 0L
    private var pingHttpStarted = false
    private var pingEpoch = 0

    private val linkQuality = LinkQuality()
    private var qualityReadings = 0
    private var lossHandled = false
    private var lastPathHadWifi = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private val startupTimeout = Runnable {
        if (!closed && !sleepPaused && !up) handleRuntimeFailure("WaterWall data-plane validation timed out")
    }
    private val probeTimeout = Runnable { probeFailed("WaterWall data-plane probe timed out") }
    private val healthTick = object : Runnable {
        override fun run() {
            worker.postDelayed(this, HEALTH_INTERVAL_MS)
            checkHealth()
        }
    }
    private val qualityTick = object : Runnable {
        override fun run() {
            worker.postDelayed(this, QUALITY_INTERVAL_MS)
            readLinkQuality()
        }
    }

    val profileName get() = candidate.name

    fun start() {
        current = this
        eventThread
        if (fallbacks.isNotEmpty()) ConnectionLog.m("WaterWall: Auto Switch can move ${candidate.name} to ${fallbacks.size} other profiles of the same server")
        worker.post {
            startRuntime()
            startPathMonitor()
        }
    }

    override fun close() {
        worker.post { closeNow() }
    }

    override fun pauseForSleep() {
        worker.post {
            if (onSleep == 2 || closed) return@post
            ConnectionLog.m("WaterWall: device sleep: ${if (onSleep == 1) "pausing" else "closing"} the connection")
            sleepPaused = true
            reconnectPending = false
            up = false
            stopRuntime()
        }
    }

    override fun wakeFromSleep() {
        worker.post {
            if (!sleepPaused || closed) return@post
            sleepPaused = false
            if (onSleep == 1 || autoReconnect) {
                failedAttempts = 0
                ConnectionLog.m("WaterWall: device wake: reconnecting the connection")
                startRuntime()
            } else {
                // Off without Auto Reconnect leaves no data plane; end the tunnel
                // instead of keeping a VPN that silently drops every packet.
                failWithReason("The connection was closed while the device slept.")
            }
        }
    }

    /**
     * Times one HTTP request through the tunnel to the probe address. This app stays outside its own tunnel, so unlike iOS it cannot
     * send a normal request through it. [result] runs on the worker thread with the milliseconds, -1 for a failure or -2 for a timeout.
     */
    override fun measurePing(result: (Long) -> Unit) {
        worker.post {
            if (closed || !up || !candidate.probeTcp) {
                result(-1)
                return@post
            }
            pingCallback?.invoke(-1)
            pingCallback = result
            pingPort = Random.nextInt(40000) + 20000
            pingHttpStarted = false
            pingStarted = SystemClock.elapsedRealtime()
            val epoch = ++pingEpoch
            updateProbeFlows()
            sendPingSyn(epoch, 0)
            worker.postDelayed({
                if (epoch == pingEpoch) finishPing(-2)
            }, PING_TIMEOUT_MS)
        }
    }

    private fun sendPingSyn(epoch: Int, attempt: Int) {
        if (epoch != pingEpoch || pingCallback == null || pingHttpStarted) return
        submitProbe(ProbePackets.syn(ipv4(candidate.tunnelAddress), ipv4(candidate.probeAddress), pingPort))
        worker.postDelayed({ sendPingSyn(epoch, attempt + 1) }, 1000)
    }

    private fun finishPing(value: Long) {
        val callback = pingCallback ?: return
        pingCallback = null
        pingEpoch++
        updateProbeFlows()
        callback(value)
    }

    private fun handleEvent(event: ByteArray) {
        val eventGeneration = (event[1].toInt() and 0xff) or (event[2].toInt() and 0xff shl 8) or (event[3].toInt() and 0xff shl 16) or (event[4].toInt() and 0xff shl 24)
        if (eventGeneration != generation || closed) return
        val code = (event[5].toInt() and 0xff) or (event[6].toInt() and 0xff shl 8) or (event[7].toInt() and 0xff shl 16) or (event[8].toInt() and 0xff shl 24)
        val payload = event.copyOfRange(9, event.size)
        when (event[0].toInt()) {
            WaterWall.EVENT_READY -> if (!sleepPaused && !up && probeStage == 0) beginDataPlaneProbe()
            WaterWall.EVENT_FAILURE -> if (!sleepPaused) handleRuntimeFailure("${String(payload)} ($code)")
            WaterWall.EVENT_CHANNEL_STOPPED -> if (up) handleRuntimeFailure("WaterWall packet channel stopped ($code)")
            WaterWall.EVENT_PROBE_PACKET -> handleProbePacket(payload)
        }
    }

    private fun ipv4(address: String) = ProbePackets.ipv4(address) ?: ByteArray(4)

    private fun updateProbeFlows() {
        val flows = ArrayList<Int>()
        if (probeStage == 1 || probeStage == 4) {
            flows += listOf(ProbePackets.PROTOCOL_TCP, ProbePackets.ipv4Int(candidate.probeAddress), probeTcpPort)
        } else if (probeStage == 2 || probeStage == 5) {
            flows += listOf(ProbePackets.PROTOCOL_UDP, ProbePackets.ipv4Int(candidate.dnsProbeAddress), ProbePackets.DNS_SOURCE_PORT)
        }
        if (pingCallback != null) flows += listOf(ProbePackets.PROTOCOL_TCP, ProbePackets.ipv4Int(candidate.probeAddress), pingPort)
        WaterWall.setProbeFlows(flows.toIntArray())
    }

    private fun submitProbe(packet: ByteArray, attempt: Int = 0) {
        if (closed) return
        val result = WaterWall.submit(packet)
        when {
            result == 0 -> Unit
            result == -EAGAIN && attempt < 1000 -> worker.postDelayed({ submitProbe(packet, attempt + 1) }, 1)
            probeStage >= 4 -> healthProbeFailed("WaterWall health probe submission failed")
            probeStage in 1..2 -> probeFailed("WaterWall probe submission failed ($result)")
        }
    }

    private fun sendSynProbe() {
        if (closed || (probeStage != 1 && probeStage != 4)) return
        probeAttempts++
        // A request already out keeps waiting: the chain may still be connecting on a slow network, and lwIP answers a
        // second SYN on this port without a SYN-ACK, which would leave no request to take the coming answer.
        if (!probeHttpStarted) submitProbe(ProbePackets.syn(ipv4(candidate.tunnelAddress), ipv4(candidate.probeAddress), probeTcpPort))
        val epoch = probeEpoch
        worker.postDelayed({
            if (epoch != probeEpoch || (probeStage != 1 && probeStage != 4) || closed) return@postDelayed
            if (probeAttempts >= if (probeStage == 1) 15 else 3) {
                if (probeStage == 1) probeFailed("WaterWall TCP probe failed after fifteen attempts")
                else healthProbeFailed("WaterWall TCP health probe failed")
            } else {
                sendSynProbe()
            }
        }, if (probeStage == 1) 1000 else 5000)
    }

    private fun sendDnsProbe() {
        if (closed || (probeStage != 2 && probeStage != 5)) return
        probeAttempts++
        submitProbe(ProbePackets.dnsQuery(ipv4(candidate.tunnelAddress), probeDnsId, ipv4(candidate.dnsProbeAddress)))
        val epoch = probeEpoch
        worker.postDelayed({
            if (epoch != probeEpoch || (probeStage != 2 && probeStage != 5) || closed) return@postDelayed
            if (probeAttempts >= if (probeStage == 2) 5 else 3) {
                if (probeStage == 2) probeFailed("WaterWall UDP/DNS probe failed after five attempts")
                else healthProbeFailed("WaterWall UDP/DNS health probe failed")
            } else {
                sendDnsProbe()
            }
        }, 1000)
    }

    private fun checkHealth() {
        if (closed || sleepPaused || !up || probeStage != 3) return
        val age = WaterWall.lastPayloadAgeMs()
        if (age in 0 until HEALTH_SILENCE_MS) return
        probeStage = if (candidate.probeTcp) 4 else 5
        probeAttempts = 0
        probeTcpPort = Random.nextInt(40000) + 20000
        probeHttpStarted = false
        probeEpoch++
        updateProbeFlows()
        if (candidate.probeTcp) sendSynProbe() else sendDnsProbe()
    }

    private fun finishHealthCheck() {
        if (closed || sleepPaused) return
        probeStage = 3
        probeAttempts = 0
        probeEpoch++
        updateProbeFlows()
    }

    private fun healthProbeFailed(reason: String) {
        if (closed || sleepPaused || probeStage < 4) return
        val age = WaterWall.lastPayloadAgeMs()
        if (age in 0 until HEALTH_SILENCE_MS) {
            finishHealthCheck()
            return
        }
        probeStage = -1
        handleRuntimeFailure(reason)
    }

    private fun beginDataPlaneProbe() {
        probeStage = if (candidate.probeTcp) 1 else 2
        probeAttempts = 0
        probeDnsId = Random.nextInt(65535) + 1
        probeTcpPort = Random.nextInt(40000) + 20000
        probeHttpStarted = false
        probeEpoch++
        updateProbeFlows()
        worker.postDelayed(probeTimeout, 20000)
        when {
            candidate.probeTcp -> sendSynProbe()
            candidate.probeUdp -> sendDnsProbe()
            else -> finishProbe()
        }
    }

    private fun finishProbe() {
        if (closed || sleepPaused) return
        worker.removeCallbacks(probeTimeout)
        probeStage = 6
        probeEpoch++
        failedAttempts = 0
        updateProbeFlows()
        ConnectionLog.m(
            when {
                candidate.probeTcp && candidate.probeUdp -> "WaterWall: TCP and UDP/DNS data-plane probes passed"
                candidate.probeTcp -> "WaterWall: TCP data-plane probe passed"
                candidate.probeUdp -> "WaterWall: UDP/DNS data-plane probe passed"
                else -> "WaterWall: no external data-plane probe required"
            },
        )
        val error = host.applyTunnelSettings(buildSettings()) { WaterWall.attachTun(it) }
        if (closed || sleepPaused || probeStage != 6) return
        if (error != null) {
            handleRuntimeFailure("WaterWall network settings failed: $error")
            return
        }
        worker.removeCallbacks(startupTimeout)
        probeStage = 3
        up = true
        WaterWall.setAccepting(true)
        host.onConnected()
        startHealthMonitor()
        startQualityMonitor()
    }

    private fun probeFailed(reason: String) {
        if (closed || sleepPaused || up || probeStage < 0) return
        probeStage = -1
        worker.removeCallbacks(probeTimeout)
        handleRuntimeFailure(reason)
    }

    private fun stopProbe() {
        worker.removeCallbacks(probeTimeout)
        worker.removeCallbacks(healthTick)
        worker.removeCallbacks(qualityTick)
        probeStage = 0
        probeHttpStarted = false
        probeResponseHeader = ByteArray(0)
        probeEpoch++
        finishPing(-1)
        WaterWall.setProbeFlows(IntArray(0))
    }

    private fun handleProbePacket(packet: ByteArray) {
        if (closed || packet.size < 28 || (packet[0].toInt() and 0xff) shr 4 != 4) return
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || packet.size < ihl + 8) return
        val protocol = packet[9].toInt() and 0xff
        if (protocol == ProbePackets.PROTOCOL_TCP && packet.size >= ihl + 20) {
            val destinationPort = u16(packet, ihl + 2)
            if (pingCallback != null && destinationPort == pingPort) {
                handlePingPacket(packet, ihl)
                return
            }
            if ((probeStage == 1 || probeStage == 4) && destinationPort == probeTcpPort) handleTcpProbePacket(packet, ihl)
        } else if ((probeStage == 2 || probeStage == 5) && protocol == ProbePackets.PROTOCOL_UDP && packet.size >= ihl + 20) {
            val sourcePort = u16(packet, ihl)
            val destinationPort = u16(packet, ihl + 2)
            val identifier = u16(packet, ihl + 8)
            val flags = u16(packet, ihl + 10)
            val answers = u16(packet, ihl + 14)
            if (sourcePort == 53 && destinationPort == ProbePackets.DNS_SOURCE_PORT && identifier == probeDnsId &&
                flags and 0x8000 != 0 && flags and 0x000f == 0 && answers > 0) {
                if (probeStage == 5) finishHealthCheck() else finishProbe()
            }
        }
    }

    private fun handleTcpProbePacket(packet: ByteArray, ihl: Int) {
        val headerLength = ((packet[ihl + 12].toInt() and 0xff) shr 4) * 4
        if (headerLength < 20 || packet.size < ihl + headerLength || u16(packet, ihl) != 80) return
        val flags = packet[ihl + 13].toInt() and 0xff
        val peerSequence = u32(packet, ihl + 4)
        if (probeHttpStarted) {
            val payloadLength = packet.size - ihl - headerLength
            if (payloadLength == 0 && flags and 0x05 != 0) {
                // The chain closed this flow unanswered, so the next attempt opens a new one.
                probeHttpStarted = false
                probeTcpPort = Random.nextInt(40000) + 20000
                updateProbeFlows()
                return
            }
            if (payloadLength == 0 || peerSequence != probeResponseSequence) return
            probeResponseSequence += payloadLength
            if (probeResponseHeader.size < 64) {
                probeResponseHeader += packet.copyOfRange(ihl + headerLength, minOf(packet.size, ihl + headerLength + 64 - probeResponseHeader.size))
            }
            if (probeResponseHeader.size >= 5 && String(probeResponseHeader, 0, 5) == "HTTP/") {
                if (candidate.probeUdp) {
                    probeStage = if (probeStage == 4) 5 else 2
                    probeAttempts = 0
                    probeEpoch++
                    updateProbeFlows()
                    sendDnsProbe()
                } else if (probeStage == 4) {
                    finishHealthCheck()
                } else {
                    finishProbe()
                }
            }
            return
        }
        if (flags and 0x12 == 0x12) {
            probeHttpStarted = true
            probeResponseSequence = peerSequence + 1
            probeResponseHeader = ByteArray(0)
            submitProbe(ProbePackets.httpRequest(ipv4(candidate.tunnelAddress), ipv4(candidate.probeAddress), probeTcpPort, peerSequence + 1))
        }
    }

    private fun handlePingPacket(packet: ByteArray, ihl: Int) {
        val headerLength = ((packet[ihl + 12].toInt() and 0xff) shr 4) * 4
        if (headerLength < 20 || packet.size < ihl + headerLength || u16(packet, ihl) != 80) return
        val flags = packet[ihl + 13].toInt() and 0xff
        if (pingHttpStarted) {
            val payloadLength = packet.size - ihl - headerLength
            if (payloadLength >= 5 && String(packet, ihl + headerLength, 5) == "HTTP/") finishPing(SystemClock.elapsedRealtime() - pingStarted)
            else if (payloadLength == 0 && flags and 0x05 != 0) finishPing(-1)
            return
        }
        if (flags and 0x12 == 0x12) {
            pingHttpStarted = true
            submitProbe(ProbePackets.httpRequest(ipv4(candidate.tunnelAddress), ipv4(candidate.probeAddress), pingPort, u32(packet, ihl + 4) + 1))
        }
    }

    private fun u16(bytes: ByteArray, offset: Int) = ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun u32(bytes: ByteArray, offset: Int) = (u16(bytes, offset) shl 16) or u16(bytes, offset + 2)

    private fun startHealthMonitor() {
        worker.removeCallbacks(healthTick)
        if (!candidate.probeTcp && !candidate.probeUdp) return
        // Check often, but probe only after 15 seconds without relayed payload.
        worker.postDelayed(healthTick, HEALTH_INTERVAL_MS)
    }

    private fun readTotals(): LinkQuality.Totals {
        val values = WaterWall.readLinkCounters()
        return LinkQuality.Totals(values[0], values[1], values[2], values[3], values[4], values[5])
    }

    private fun startQualityMonitor() {
        linkQuality.interval = QUALITY_INTERVAL_MS / 1000.0
        linkQuality.clear()
        linkQuality.add(readTotals())
        qualityReadings = 0
        lossHandled = false
        worker.removeCallbacks(qualityTick)
        worker.postDelayed(qualityTick, QUALITY_INTERVAL_MS)
    }

    private fun readLinkQuality() {
        if (closed || sleepPaused || !up) return
        linkQuality.add(readTotals())
        val perMinute = max(1, (60000.0 / QUALITY_INTERVAL_MS).roundToInt())
        if (++qualityReadings % perMinute == 0) {
            linkQuality.summary(perMinute)?.let { ConnectionLog.m("WaterWall: last minute on ${candidate.name}: $it") }
        }
        val reason = linkQuality.lossReason()
        if (reason == null || lossHandled) return
        lossHandled = true
        lossyCandidates.add(candidateIndex)
        val next = candidateAfterLoss()
        if (next == null) {
            val outcome = if (candidates.size > 1) "the other profiles of this server lost packets on this network too, so it stays"
            else "no other profile of this server can take over"
            ConnectionLog.m("WaterWall: $reason on ${candidate.name}; $outcome")
            return
        }
        ConnectionLog.m("WaterWall: $reason on ${candidate.name}; switching to ${candidates[next].name}")
        switchToCandidate(next)
        failedAttempts = 0
        startRuntime()
    }

    private fun switchToCandidate(index: Int) {
        candidateIndex = index
        candidate = candidates[index]
    }

    // After heavy loss: the next profile with the other carrier, else the next one,
    // skipping every profile that already lost packets on this network.
    private fun candidateAfterLoss(): Int? {
        var sameCarrier: Int? = null
        for (step in 1 until candidates.size) {
            val index = (candidateIndex + step) % candidates.size
            if (index in lossyCandidates) continue
            if (candidates[index].udpCarrier != candidate.udpCarrier) return index
            if (sameCarrier == null) sameCarrier = index
        }
        return sameCarrier
    }

    private fun stopRuntime() {
        stopProbe()
        worker.removeCallbacks(startupTimeout)
        WaterWall.setAccepting(false)
        if (started) {
            WaterWall.stop()
            started = false
        }
    }

    private fun startRuntime() {
        if (closed || sleepPaused) return
        stopRuntime()
        up = false
        generation = WaterWall.start(host.coreJson().toByteArray(), candidate.nodesJson.toByteArray())
        if (generation == 0) {
            failWithReason("WaterWall could not start (invalid configuration or another session is active)")
            return
        }
        started = true
        worker.postDelayed(startupTimeout, 30000)
    }

    private fun handleRuntimeFailure(reason: String) {
        if (closed || sleepPaused || reconnectPending) return
        ConnectionLog.m("WaterWall: handling runtime failure: $reason")
        up = false
        stopRuntime()
        if (!autoReconnect || !(retryTimes <= 0 || failedAttempts < retryTimes)) {
            failWithReason(if (autoReconnect && retryTimes > 0) "Could not reconnect after $retryTimes attempts. ($reason)" else reason)
            return
        }
        failedAttempts++
        reconnectPending = true
        val limit = if (retryTimes > 0) " of $retryTimes" else ""
        ConnectionLog.m("WaterWall: $reason; reconnecting in 2s (attempt $failedAttempts$limit)")
        if (candidates.size > 1) {
            switchToCandidate((candidateIndex + 1) % candidates.size)
            ConnectionLog.m("WaterWall: the next attempt uses ${candidate.name}")
        }
        worker.postDelayed({
            reconnectPending = false
            if (!closed && !sleepPaused) startRuntime()
        }, 2000)
    }

    private fun failWithReason(reason: String) {
        ConnectionLog.m("WaterWall: closing with reason: $reason")
        closeNow()
        host.onFailure(reason)
    }

    private fun closeNow() {
        if (closed) return
        closed = true
        up = false
        stopPathMonitor()
        stopRuntime()
        WaterWall.detachTun()
        host.onClosed()
    }

    private fun startPathMonitor() {
        if (!switchToWifi || closed || sleepPaused) return
        lastPathHadWifi = false
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                val hasWifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                val hadWifi = lastPathHadWifi
                lastPathHadWifi = hasWifi
                if (hadWifi != hasWifi && up && !closed && !sleepPaused) {
                    ConnectionLog.m("WaterWall: ${if (hasWifi) "Wi-Fi became available" else "Wi-Fi became unavailable"}; migrating the connection to the new path")
                    failedAttempts = 0
                    // What failed or lost packets on the previous network says nothing about this one.
                    lossyCandidates.clear()
                    if (candidateIndex != 0) {
                        switchToCandidate(0)
                        ConnectionLog.m("WaterWall: returning to ${candidate.name} on the new network")
                    }
                    startRuntime()
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

    private fun buildSettings(): TunnelSettings {
        val routes = ArrayList<Pair<String, Int>>()
        for (entry in candidate.allowedIps.orEmpty().split(',')) {
            val parts = entry.trim().split('/')
            val prefix = parts.getOrNull(1)?.toIntOrNull() ?: -1
            if (parts.size == 2 && prefix in 0..32 && ProbePackets.ipv4(parts[0]) != null) {
                // Android refuses a route with host bits set; iOS takes it as the whole network.
                val network = ProbePackets.ipv4Int(parts[0]) and (if (prefix == 0) 0 else -1 shl (32 - prefix))
                routes.add("${network ushr 24}.${network ushr 16 and 255}.${network ushr 8 and 255}.${network and 255}" to prefix)
            }
        }
        return TunnelSettings(
            address = candidate.tunnelAddress,
            dnsServers = candidate.dnsServers,
            routes = if (candidate.allowedIps.isNullOrEmpty()) listOf("0.0.0.0" to 0) else routes,
            mtu = MTU,
        )
    }

    companion object {
        // One worker for the process, like the runtime: a client that closes finishes before the next one starts.
        private val worker by lazy { Handler(HandlerThread("srp.waterwall").apply { start() }.looper) }

        @Volatile private var current: WaterWallClient? = null

        // One thread for the process: the runtime is one too, and generations sort out whose an event is.
        private val eventThread by lazy {
            Thread({
                while (true) {
                    val event = WaterWall.nextEvent()
                    current?.let { client -> worker.post { client.handleEvent(event) } }
                }
            }, "srp.waterwall.events").apply {
                isDaemon = true
                start()
            }
        }

        const val MTU = 1420
        private const val EAGAIN = 11
        private const val HEALTH_INTERVAL_MS = 5000L
        private const val HEALTH_SILENCE_MS = 15000L
        private const val QUALITY_INTERVAL_MS = 5000L
        private const val PING_TIMEOUT_MS = 15000L
    }
}
