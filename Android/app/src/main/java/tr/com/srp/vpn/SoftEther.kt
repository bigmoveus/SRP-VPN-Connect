package tr.com.srp.vpn

import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** The SoftEther client core in libsrpse.so; softether_jni.c has the threading rules. One session runs at a time. */
internal object SoftEther {
    const val EVENT_CONFIG = 1
    const val EVENT_STATE = 2
    const val EVENT_PROBE_PACKET = 3
    const val EVENT_CONFIG6 = 4

    init {
        System.loadLibrary("srpse")
    }

    /** Once per process: a writable directory for the core and whether it prints its debug output. */
    @JvmStatic external fun init(directory: String, debug: Boolean)

    /**
     * Starts a session with the settings in SoftEtherClient's order; a client certificate comes as its PKCS#12 and
     * passphrase. Returns the generation that tags its events, 0 when it did not start, -2 for an unreadable certificate.
     */
    @JvmStatic external fun start(settings: Array<String>, p12: ByteArray?, passphrase: String?): Int

    /** Ends the session and blocks until its threads have ended. */
    @JvmStatic external fun stop()

    /** The tunnel's fd (-1: none); the previous one can close once this returns. */
    @JvmStatic external fun attachTun(fd: Int)

    /** The next event, type, generation (4 bytes) and payload, or null after [timeoutMs] without one. */
    @JvmStatic external fun nextEvent(timeoutMs: Int): ByteArray?

    /** Sends a probe packet into the tunnel: 0 when sent, a negative errno otherwise. */
    @JvmStatic external fun submit(packet: ByteArray): Int

    /** Answers of these flows come back as probe events instead of reaching the tunnel: triples of protocol, source IPv4, destination port. */
    @JvmStatic external fun setProbeFlows(flows: IntArray)

    @JvmStatic external fun setLog(path: String, level: Int)

    /** SoftEther's name for an error code (SRPSEErrorName). */
    @JvmStatic external fun errorName(code: Int): String

    /** Called by the core with the server's chain, leaf first: null when the device trusts it, otherwise why not. */
    @JvmStatic
    fun trustChain(chain: Array<ByteArray>): String? = PlatformTrust.check(chain)
}

/** A server chain against the device's trusted roots, as SecTrust does on iOS: null when trusted, otherwise why not. */
internal object PlatformTrust {
    private val trustManager: X509TrustManager by lazy {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        factory.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    fun check(chain: Array<ByteArray>): String? = runCatching {
        val factory = CertificateFactory.getInstance("X.509")
        val certificates = chain.map { factory.generateCertificate(it.inputStream()) as X509Certificate }.toTypedArray()
        if (certificates.isEmpty()) return "the server sent no certificate"
        trustManager.checkServerTrusted(certificates, if (certificates[0].publicKey.algorithm == "EC") "ECDHE_ECDSA" else "ECDHE_RSA")
        null
    }.getOrElse { error -> error.message ?: "not trusted" }
}
