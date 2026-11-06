package tr.com.srp.vpn

import android.content.Context
import android.util.Base64
import java.io.File
import java.util.UUID

/** One imported client certificate: the reference profiles keep, its subject name and when it expires (seconds since 1970). */
data class ClientCertificate(val ref: String, val name: String, val expiry: Long)

/**
 * Client certificates for SSTP certificate login, as SRPCertificateStore on iOS: the PKCS#12 file and its passphrase stay in
 * the SecretStore, and certificates.json lists them without any secret.
 */
class CertificateStore(context: Context) {
    private val index = File(context.filesDir, "certificates.json")
    private val secrets = SecretStore(context)

    fun list(): List<ClientCertificate> {
        val stored = (Json.parseOrNull(if (index.exists()) index.readText() else null) as? List<*>).orEmpty().filterIsInstance<Map<*, *>>()
        return stored.mapNotNull { item ->
            val ref = item["ref"] as? String ?: return@mapNotNull null
            ClientCertificate(ref, item["name"] as? String ?: "Client Certificate", (item["expiry"] as? Number)?.toLong() ?: 0)
        }
    }

    /** Imports a .p12 or .pfx file; returns the certificate, or why it was refused. */
    fun import(p12: ByteArray, passphrase: String): Result<ClientCertificate> {
        val info = Sstp.p12Info(p12, passphrase)
            ?: return Result.failure(IllegalArgumentException("The file is not a PKCS#12 certificate with its private key, or the passphrase is wrong."))
        val certificate = ClientCertificate(UUID.randomUUID().toString(), info[0], info[1].toLongOrNull() ?: 0)
        secrets.set(secretName(certificate.ref), Base64.encodeToString(p12, Base64.NO_WRAP))
        secrets.set(passphraseName(certificate.ref), passphrase)
        save(list() + certificate)
        return Result.success(certificate)
    }

    /** The PKCS#12 bytes and passphrase of a certificate, or null when it is gone or the Keystore cannot read it. */
    fun load(ref: String): Pair<ByteArray, String>? {
        val p12 = secrets.get(secretName(ref))?.let { runCatching { Base64.decode(it, Base64.NO_WRAP) }.getOrNull() } ?: return null
        return p12 to (secrets.get(passphraseName(ref)) ?: return null)
    }

    fun delete(ref: String) {
        secrets.delete(secretName(ref))
        secrets.delete(passphraseName(ref))
        save(list().filter { it.ref != ref })
    }

    private fun save(certificates: List<ClientCertificate>) {
        val temporary = File(index.path + ".tmp")
        temporary.writeText(Json.write(certificates.map { mapOf("ref" to it.ref, "name" to it.name, "expiry" to it.expiry) }, pretty = true, sortedKeys = true))
        temporary.renameTo(index)
    }

    private fun secretName(ref: String) = "cert:$ref"

    private fun passphraseName(ref: String) = "cert-passphrase:$ref"
}
