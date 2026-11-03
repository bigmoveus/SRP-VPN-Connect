package tr.com.srp.vpn

/** The WaterWall runtime in libwaterwall.so; waterwall_jni.c has the threading rules. */
internal object WaterWall {
    const val EVENT_READY = 1
    const val EVENT_FAILURE = 2
    const val EVENT_PROBE_PACKET = 3
    const val EVENT_CHANNEL_STOPPED = 4

    init {
        System.loadLibrary("waterwall")
    }

    /** The generation that tags this runtime's events, or 0 when it did not start. The settings are UTF-8, as a password may hold any character. */
    @JvmStatic external fun start(coreJson: ByteArray, nodesJson: ByteArray): Int

    /** Blocks until the runtime's threads have ended. */
    @JvmStatic external fun stop()

    @JvmStatic external fun attachTun(fd: Int)

    @JvmStatic external fun detachTun()

    /** Whether packets from the tunnel go to the runtime; while false they wait in the kernel. */
    @JvmStatic external fun setAccepting(value: Boolean)

    /** 0 when accepted, a negative errno otherwise: -EAGAIN for a full queue, -ENOTCONN while not running. */
    @JvmStatic external fun submit(packet: ByteArray): Int

    /** Blocks for the next event: type, generation (4 bytes), code (4 bytes), payload. */
    @JvmStatic external fun nextEvent(): ByteArray

    /** Packets of these flows come back as events instead of going to the tunnel: triples of protocol, source IPv4, destination port. */
    @JvmStatic external fun setProbeFlows(flows: IntArray)

    /** Milliseconds since relayed payload last arrived, or -1 when none has since the runtime started. */
    @JvmStatic external fun lastPayloadAgeMs(): Long

    @JvmStatic external fun setLog(path: String, level: Int)

    /** Sent packets, retransmitted packets, received bytes, timed out connections, max RTT and max RTO since the previous reading. */
    @JvmStatic external fun readLinkCounters(): LongArray

    /** Why the file is not a usable country database, or null when it is. */
    @JvmStatic external fun geoIpError(path: String): String?

    /** The database's type and file size in bytes, or null. */
    @JvmStatic external fun geoIpInfo(path: String): Array<String>?

    @JvmStatic external fun x25519PublicKey(privateKey: ByteArray): ByteArray?
}
