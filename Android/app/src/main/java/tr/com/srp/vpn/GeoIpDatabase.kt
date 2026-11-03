package tr.com.srp.vpn

import android.content.Context
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID

/** The country database of GeoIP routing: the bundled file, or the one the user uploaded or downloaded, checked before it replaces the old one. */
class GeoIpDatabase(private val context: Context) {
    class Failure(message: String) : Exception(message)

    class Info(val type: String, val source: String, val bytes: Long)

    private val directory = File(context.filesDir, "GeoIP")
    private val installed = File(directory, "GeoLite2-Country.mmdb")
    private val updatedMarker = File(directory, "updated")

    /** The file WaterWall should open, once one is installed. */
    val currentFile: File? get() = installed.takeIf { it.exists() }

    fun validationError(file: File): String? {
        if (!file.isFile || file.length() <= 0 || file.length() > MAXIMUM_BYTES) return "Choose a nonempty MaxMind Country MMDB file no larger than 128 MB."
        return WaterWall.geoIpError(file.path)
    }

    private fun bundledCopy(): File {
        val copy = File(context.cacheDir, "GeoLite2-Country-bundled.mmdb")
        if (!copy.exists()) context.assets.open(BUNDLED).use { input -> copy.outputStream().use { input.copyTo(it) } }
        return copy
    }

    /** @throws Failure when no valid database can be installed */
    @Synchronized
    fun installBundledIfNeeded() {
        if (installed.exists()) {
            validationError(installed)?.let { throw Failure(it) }
            return
        }
        install(bundledCopy(), updated = false)
    }

    @Synchronized
    private fun install(source: File, updated: Boolean) {
        validationError(source)?.let { throw Failure(it) }
        directory.mkdirs()
        val temporary = File(directory, ".${UUID.randomUUID()}.tmp")
        try {
            source.copyTo(temporary)
            validationError(temporary)?.let { throw Failure(it) }
            if (!temporary.renameTo(installed)) throw Failure("The validated GeoIP database could not be installed. The previous file was kept.")
            if (updated) updatedMarker.writeText("1") else updatedMarker.delete()
        } finally {
            temporary.delete()
        }
    }

    fun info(): Info? {
        val file = currentFile ?: bundledCopy()
        if (validationError(file) != null) return null
        val values = WaterWall.geoIpInfo(file.path) ?: return null
        return Info(values[0], if (updatedMarker.exists()) "Updated" else "Bundled", values[1].toLong())
    }

    /** @throws Failure when the file is not a valid database */
    fun installFrom(input: InputStream) {
        val temporary = File(context.cacheDir, "geoip-${UUID.randomUUID()}")
        try {
            temporary.outputStream().use { output -> copyLimited(input, output) }
            install(temporary, updated = true)
        } finally {
            temporary.delete()
        }
    }

    /** @throws Failure when the link, the download or the file is not good */
    fun download(link: String) {
        if (!ChainConfig.isValidHttpsLink(link)) throw Failure("Enter a valid HTTPS link without embedded credentials. The file must be a MaxMind Country MMDB.")
        var current = link
        repeat(MAXIMUM_REDIRECTS) {
            val connection = try {
                (URL(current).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 30000
                    readTimeout = 30000
                    instanceFollowRedirects = false
                    connect()
                }
            } catch (_: Exception) {
                throw Failure("The GeoIP download failed. Check the HTTPS link and network connection.")
            }
            try {
                val code = connection.responseCode
                if (code in 300..399) {
                    val location = connection.getHeaderField("Location")?.let { URL(URL(current), it).toString() }
                    if (location == null || !ChainConfig.isValidHttpsLink(location)) throw Failure("GeoIP redirects must remain on HTTPS without embedded credentials.")
                    current = location
                    return@repeat
                }
                if (code !in 200..299) throw Failure("The GeoIP download link did not return a successful HTTPS response.")
                if (connection.contentLengthLong > MAXIMUM_BYTES) throw Failure("The GeoIP database exceeds the 128 MB limit.")
                try {
                    connection.inputStream.use { installFrom(it) }
                } catch (error: Failure) {
                    throw error
                } catch (_: Exception) {
                    throw Failure("The GeoIP download failed. Check the HTTPS link and network connection.")
                }
                return
            } finally {
                connection.disconnect()
            }
        }
        throw Failure("The GeoIP download failed. Check the HTTPS link and network connection.")
    }

    private fun copyLimited(input: InputStream, output: java.io.OutputStream) {
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val count = input.read(buffer)
            if (count < 0) return
            total += count
            if (total > MAXIMUM_BYTES) throw Failure("The GeoIP database exceeds the 128 MB limit.")
            output.write(buffer, 0, count)
        }
    }

    private companion object {
        const val BUNDLED = "GeoLite2-Country.mmdb"
        const val MAXIMUM_BYTES = 128L * 1024 * 1024
        const val MAXIMUM_REDIRECTS = 8
    }
}
