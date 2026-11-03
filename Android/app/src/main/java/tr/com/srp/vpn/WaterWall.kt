package tr.com.srp.vpn

/** The WaterWall runtime in libwaterwall.so; waterwall_jni.c has the threading rules. */
internal object WaterWall {
    init {
        System.loadLibrary("waterwall")
    }

    @JvmStatic
    external fun start(tunFd: Int, coreJson: String, nodesJson: String, logPath: String): Boolean

    /** Blocks until [stop] or a runtime failure, and returns the exit code. */
    @JvmStatic
    external fun await(): Int

    @JvmStatic
    external fun stop()
}
