package tr.com.srp.vpn

/** The SSTP engine in libsrpsstp.so; sstp_jni.c has the threading rules. One session runs at a time. */
internal object Sstp {
    const val EVENT_NETWORK_UP = 1
    const val EVENT_LINK_FAILURE = 2
    const val EVENT_SESSION_END = 3
    const val EVENT_ESTABLISHED = 4
    const val EVENT_PROBE_PACKET = 5

    init {
        System.loadLibrary("srpsstp")
    }

    /**
     * Starts a session on [fd], a connected TCP socket the engine now owns, with the settings in SstpClient's order. A
     * client certificate comes as its PKCS#12 and passphrase. Returns the generation that tags its events, 0 when it did not start.
     */
    @JvmStatic external fun start(fd: Int, settings: Array<String>, p12: ByteArray?, passphrase: String?): Int

    /** Ends the session and blocks until its thread has ended. */
    @JvmStatic external fun stop()

    /** The tunnel's fd; returns once the engine uses it, so the previous one can close. */
    @JvmStatic external fun attachTun(fd: Int)

    /** The next event, type, generation (4 bytes) and payload, or null after [timeoutMs] without one. */
    @JvmStatic external fun nextEvent(timeoutMs: Int): ByteArray?

    @JvmStatic external fun setLog(path: String, level: Int)

    /** Sends a probe packet into PPP: 0 when queued, a negative errno otherwise (-EAGAIN for a full queue). */
    @JvmStatic external fun submit(packet: ByteArray): Int

    /** Answers of these flows come back as probe events instead of reaching the tunnel: triples of protocol, source IPv4, destination port. */
    @JvmStatic external fun setProbeFlows(flows: IntArray)

    /** The certificate's name and expiry in seconds since 1970, or null when the file or the passphrase is wrong. */
    @JvmStatic external fun p12Info(p12: ByteArray, passphrase: String): Array<String>?

    /** Called by the engine with a server's chain, leaf first: null when the device trusts it, otherwise why not. */
    @JvmStatic
    fun trustChain(chain: Array<ByteArray>): String? = PlatformTrust.check(chain)
}
