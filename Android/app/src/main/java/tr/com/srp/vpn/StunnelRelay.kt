package tr.com.srp.vpn

import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.Collections
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.thread

/** How the TLS handshake is split (SSFragTLSConfig on iOS): every write of the handshake as a first chunk, then following chunks. */
data class StunnelFragPlan(val first: Int, val following: Int, val gapMs: Long = 2) {
    companion object {
        /** TLS Fragmentation as the profile stores it: 0 Off, 1 Auto (43, then 256 on Wi-Fi or 128 on cellular), 2 Manual. */
        fun of(mode: Int, first: Int, following: Int, cellular: Boolean): StunnelFragPlan? = when (mode) {
            1 -> StunnelFragPlan(43, if (cellular) 128 else 256)
            2 -> StunnelFragPlan(if (first > 0) first.coerceAtMost(4096) else 32, if (following > 0) following.coerceAtMost(16384) else 256)
            else -> null
        }
    }

    /** The sizes one handshake write of [length] bytes goes out in */
    fun chunks(length: Int): List<Int> {
        val sizes = ArrayList<Int>()
        var left = length
        var size = first
        while (left > 0) {
            val take = minOf(size, left)
            sizes += take
            left -= take
            size = following
        }
        return sizes
    }
}

internal class StunnelFailure(message: String) : IOException(message)

/**
 * The stunnel transport of an OpenVPN profile (SRPStunnelTransport on iOS): OpenVPN's TCP stream inside TLS to the server's
 * stunnel listener. OpenVPN 3 Core connects over TCP to this relay's local port; each of its connections gets its own TLS
 * connection to the server, through SSLEngine so that the handshake can be split as TLS Fragmentation says. The app stays
 * outside its own tunnel, so the connection to the server needs no protect(). A failure is reported through [onError] in
 * the iOS app's words before the local connection closes, so OpenVpnClient.kt can name it.
 */
class StunnelRelay(
    private val host: String,
    private val port: Int,
    private val sni: String,
    private val caPem: String,
    private val fragMode: Int,
    private val fragFirst: Int,
    private val fragFollowing: Int,
    private val cellular: () -> Boolean,
    private val log: (String) -> Unit,
    private val onError: (String) -> Unit,
) {
    private val server = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
    @Volatile private var closed = false
    private val open = Collections.synchronizedSet(HashSet<Closeable>())

    val localPort: Int get() = server.localPort

    fun start() {
        val plan = StunnelFragPlan.of(fragMode, fragFirst, fragFollowing, cellular())
        val frag = when (fragMode) {
            1 -> "auto"
            2 -> "manual ${plan?.first}/${plan?.following}"
            else -> "off"
        }
        log("stunnel: connecting to $host:$port (SNI $sni, CA ${if (caPem.isBlank()) "system trust" else "imported"}, TLS fragmentation $frag)")
        thread(name = "srp.stunnel.accept", isDaemon = true) {
            while (!closed) {
                val local = try {
                    server.accept()
                } catch (error: IOException) {
                    break
                }
                thread(name = "srp.stunnel.up", isDaemon = true) { relay(local, plan) }
            }
        }
    }

    fun close() {
        closed = true
        runCatching { server.close() }
        synchronized(open) { open.toList() }.forEach { runCatching { it.close() } }
    }

    private fun relay(local: Socket, plan: StunnelFragPlan?) {
        open += local
        var tls: StunnelTls? = null
        try {
            local.tcpNoDelay = true
            tls = StunnelTls.open(host, port, sni, caPem, plan)
            open += tls
            log("stunnel: TLS ready to $host:$port (${tls.peerAddress}, ${tls.protocol})")
            val connection = tls
            // the server -> the core
            thread(name = "srp.stunnel.down", isDaemon = true) {
                val buffer = ByteArray(64 * 1024)
                val output = local.getOutputStream()
                try {
                    while (true) {
                        val count = connection.read(buffer)
                        if (count < 0) break
                        output.write(buffer, 0, count)
                    }
                    if (!closed) onError("The stunnel server closed the connection.")
                } catch (error: IOException) {
                    if (!closed) onError("The stunnel connection broke.")
                } finally {
                    runCatching { local.close() }
                }
            }
            // the core -> the server
            val input = local.getInputStream()
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                connection.write(buffer, 0, count)
            }
        } catch (failure: StunnelFailure) {
            if (!closed) {
                log("stunnel: ${failure.message}")
                onError(failure.message!!)
            }
        } catch (error: IOException) {
            // the core closed its side, or the relay is closing
        } finally {
            tls?.let { runCatching { it.close() }; open -= it }
            runCatching { local.close() }
            open -= local
        }
    }
}

/** A TLS client connection on SSLEngine: the certificate is checked for the SNI name, against the system's trust or the imported CA alone. */
internal class StunnelTls private constructor(private val socket: Socket, private val engine: SSLEngine) : Closeable {
    private val input: InputStream = socket.getInputStream()
    private val output: OutputStream = socket.getOutputStream()
    private var netIn: ByteBuffer = ByteBuffer.allocate(engine.session.packetBufferSize).apply { flip() }   // read mode
    private var appIn: ByteBuffer = ByteBuffer.allocate(engine.session.applicationBufferSize)            // write mode
    private var netOut: ByteBuffer = ByteBuffer.allocate(engine.session.packetBufferSize)
    private val readLock = Any()
    private val writeLock = Any()

    val peerAddress: String get() = socket.inetAddress?.hostAddress.orEmpty()
    val protocol: String get() = engine.session.protocol

    companion object {
        fun open(host: String, port: Int, sni: String, caPem: String, plan: StunnelFragPlan?): StunnelTls {
            val where = "$host:$port"
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(host, port), 10000)
            } catch (error: UnknownHostException) {
                throw StunnelFailure("The stunnel server name $host could not be resolved.")
            } catch (error: SocketTimeoutException) {
                throw StunnelFailure("The stunnel server $where did not answer.")
            } catch (error: ConnectException) {
                throw StunnelFailure(if ("ECONNREFUSED" in error.message.orEmpty() || "refused" in error.message.orEmpty().lowercase())
                    "The stunnel server $where refused the connection: nothing listens on that port."
                    else "The stunnel server $where cannot be reached from this network.")
            } catch (error: NoRouteToHostException) {
                throw StunnelFailure("The stunnel server $where cannot be reached from this network.")
            } catch (error: IOException) {
                throw StunnelFailure("The stunnel connection to $where failed (${error.message}).")
            }
            try {
                socket.tcpNoDelay = true
                socket.soTimeout = 20000
                val context = SSLContext.getInstance("TLS")
                context.init(null, trustManagers(caPem), null)
                val engine = context.createSSLEngine(sni, port)
                engine.useClientMode = true
                engine.sslParameters = engine.sslParameters.apply {
                    if (ProbePackets.ipv4(sni) == null && ':' !in sni) serverNames = listOf(SNIHostName(sni))
                    endpointIdentificationAlgorithm = "HTTPS"
                    protocols = engine.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
                }
                val tls = StunnelTls(socket, engine)
                tls.handshake(plan, where, sni, caPem.isNotBlank())
                socket.soTimeout = 0
                return tls
            } catch (failure: StunnelFailure) {
                runCatching { socket.close() }
                throw failure
            } catch (error: Exception) {
                runCatching { socket.close() }
                throw StunnelFailure("The TLS handshake with the stunnel server $where failed (${error.message}).")
            }
        }

        /** The imported CA alone, or null for the system's trust store */
        private fun trustManagers(caPem: String): Array<javax.net.ssl.TrustManager>? {
            if (caPem.isBlank()) return null
            val factory = CertificateFactory.getInstance("X.509")
            val certificates = factory.generateCertificates(caPem.byteInputStream())
            if (certificates.isEmpty()) throw StunnelFailure("The imported CA Certificate holds no certificate.")
            val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
            certificates.forEachIndexed { index, certificate -> store.setCertificateEntry("ca$index", certificate) }
            return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }.trustManagers
        }

        private fun certificateProblem(error: Throwable): Boolean {
            var cause: Throwable? = error
            while (cause != null) {
                if (cause is java.security.cert.CertificateException || cause is java.security.cert.CertPathValidatorException) return true
                cause = cause.cause
            }
            return false
        }
    }

    private fun handshake(plan: StunnelFragPlan?, where: String, sni: String, pinned: Boolean) {
        try {
            engine.beginHandshake()
            var status = engine.handshakeStatus
            while (true) {
                status = when (status) {
                    SSLEngineResult.HandshakeStatus.NEED_WRAP -> wrapHandshake(plan)
                    SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> unwrapHandshake()
                    SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                        while (true) engine.delegatedTask?.run() ?: break
                        engine.handshakeStatus
                    }
                    else -> return
                }
            }
        } catch (failure: StunnelFailure) {
            throw failure
        } catch (error: SSLException) {
            if (certificateProblem(error)) {
                throw StunnelFailure(if (!pinned)
                    "The stunnel server's certificate is not trusted for $sni (another name, expired, or not from a public certificate authority; import its CA Certificate if the server has its own CA)."
                    else "The stunnel server's certificate is not signed by the imported CA Certificate, or not issued for $sni.")
            }
            throw StunnelFailure("The TLS handshake with the stunnel server $where failed (${error.message}): it may require a TLS version or cipher this app does not offer.")
        } catch (error: SocketTimeoutException) {
            throw StunnelFailure("The stunnel server $where did not finish the TLS handshake.")
        }
    }

    private fun wrapHandshake(plan: StunnelFragPlan?): SSLEngineResult.HandshakeStatus {
        netOut.clear()
        val result = engine.wrap(ByteBuffer.allocate(0), netOut)
        if (result.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
            netOut = ByteBuffer.allocate(netOut.capacity() * 2)
            return SSLEngineResult.HandshakeStatus.NEED_WRAP
        }
        if (result.status == SSLEngineResult.Status.CLOSED) throw StunnelFailure("The stunnel server closed the connection during the TLS handshake.")
        netOut.flip()
        val bytes = ByteArray(netOut.remaining()).also { netOut.get(it) }
        if (plan == null) {
            output.write(bytes)
            output.flush()
        } else {
            // each piece its own TCP segment (no Nagle); a short gap keeps them apart
            var offset = 0
            for ((index, size) in plan.chunks(bytes.size).withIndex()) {
                if (index > 0 && plan.gapMs > 0) Thread.sleep(plan.gapMs)
                output.write(bytes, offset, size)
                output.flush()
                offset += size
            }
        }
        return result.handshakeStatus
    }

    private fun unwrapHandshake(): SSLEngineResult.HandshakeStatus {
        while (true) {
            val result = engine.unwrap(netIn, appIn)
            when (result.status) {
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> if (!fill()) throw StunnelFailure("The stunnel server closed the connection during the TLS handshake.")
                SSLEngineResult.Status.BUFFER_OVERFLOW -> appIn = grow(appIn, engine.session.applicationBufferSize)
                SSLEngineResult.Status.CLOSED -> throw StunnelFailure("The stunnel server closed the connection during the TLS handshake.")
                else -> return result.handshakeStatus
            }
        }
    }

    /** More bytes from the server into netIn (kept in read mode); false at its end */
    private fun fill(): Boolean {
        if (netIn.limit() == netIn.capacity() && netIn.position() == 0) {
            netIn = ByteBuffer.allocate(netIn.capacity() * 2).put(netIn).apply { flip() }
        }
        netIn.compact()
        val count = input.read(netIn.array(), netIn.arrayOffset() + netIn.position(), netIn.remaining())
        if (count > 0) netIn.position(netIn.position() + count)
        netIn.flip()
        return count > 0
    }

    private fun grow(buffer: ByteBuffer, at: Int): ByteBuffer =
        ByteBuffer.allocate(maxOf(at, buffer.capacity() * 2)).apply { buffer.flip(); put(buffer) }

    /** Plaintext from the server, -1 at its end */
    fun read(into: ByteArray): Int = synchronized(readLock) { readLocked(into) }

    private fun readLocked(into: ByteArray): Int {
        while (true) {
            if (appIn.position() > 0) {
                appIn.flip()
                val count = minOf(appIn.remaining(), into.size)
                appIn.get(into, 0, count)
                appIn.compact()
                return count
            }
            val result = engine.unwrap(netIn, appIn)
            when (result.status) {
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> if (!fill()) return -1
                SSLEngineResult.Status.BUFFER_OVERFLOW -> appIn = grow(appIn, engine.session.applicationBufferSize)
                SSLEngineResult.Status.CLOSED -> return -1
                else -> {}
            }
            // TLS 1.3 tickets and key updates after the handshake
            if (result.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                while (true) engine.delegatedTask?.run() ?: break
            }
            if (engine.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) synchronized(writeLock) { writeRecords(ByteBuffer.allocate(0)) }
        }
    }

    /** Plaintext to the server */
    fun write(data: ByteArray, offset: Int, length: Int) = synchronized(writeLock) {
        writeRecords(ByteBuffer.wrap(data, offset, length))
    }

    private fun writeRecords(source: ByteBuffer) {
        do {
            netOut.clear()
            val result = engine.wrap(source, netOut)
            when (result.status) {
                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                    netOut = ByteBuffer.allocate(netOut.capacity() * 2)
                    continue
                }
                SSLEngineResult.Status.CLOSED -> throw IOException("TLS closed")
                else -> {}
            }
            netOut.flip()
            output.write(netOut.array(), netOut.arrayOffset() + netOut.position(), netOut.remaining())
        } while (source.hasRemaining())
        output.flush()
    }

    override fun close() {
        runCatching { engine.closeOutbound() }
        runCatching { socket.close() }
    }
}
