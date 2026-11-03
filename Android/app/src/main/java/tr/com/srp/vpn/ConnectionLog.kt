package tr.com.srp.vpn

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** srptunnel.log, the file the Connection Log screen shows. The runtime's own lines reach it through WaterWall.setLog. */
object ConnectionLog {
    private const val CAP_BYTES = 2 * 1024 * 1024L
    private const val KEEP_BYTES = 512 * 1024

    private lateinit var logFile: File
    private val time = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    fun file(context: Context) = File(context.filesDir, "srptunnel.log")

    fun open(context: Context) {
        logFile = file(context)
        cap()
    }

    /** A milestone: errors and connect or disconnect steps, printed at every log level. */
    @Synchronized
    fun m(message: String) {
        if (!::logFile.isInitialized) return
        val line = "${time.format(Date())} [Y] $message\n"
        runCatching { FileOutputStream(logFile, true).use { it.write(line.toByteArray()) } }
    }

    /** When the log exceeds 2 MB, keep its last 512 KB: the tail is what looking back needs. */
    @Synchronized
    private fun cap() {
        if (logFile.length() <= CAP_BYTES) return
        runCatching {
            val tail = ByteArray(KEEP_BYTES)
            RandomAccessFile(logFile, "r").use {
                it.seek(it.length() - KEEP_BYTES)
                it.readFully(tail)
            }
            logFile.writeBytes(tail)
        }
    }
}
