package tr.com.srp.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** One saved connection, with the same fields and defaults as a WaterWall NodeModel on iOS. Secrets stay out of the stored profile. */
data class Profile(
    val nodeId: String = UUID.randomUUID().toString().uppercase(),
    val desc: String = "",
    val username: String = "",
    val password: String = "",
    val passwordKey: String = "",
    val server: String = "",
    val port: String = "443",
    val allowInsecure: Boolean = false,
    val configJson: String = ChainConfig.jsonWithConfiguration(ChainConfig.defaultConfiguration())!!,
    val outerSecret: String = "",
    val outerSecretRef: String = "",
    val probeIp: String = "",
    val dnsProbeIp: String = "",
    val fakeDns: Boolean = true,
    val smartRouting: Boolean = false,
    val autoSwitch: Boolean = true,
    val tlsFragMode: Int = 0,
    val tlsFragFirst: Int = 0,
    val tlsFragFollowing: Int = 0,
    val autoReconnect: Boolean = true,
    val retryTimes: Int = 0,
    val switchToWifi: Boolean = true,
    val onSleep: Int = 2,
    val logLevel: Int = 0,
    val customSni: String = "",
    val wgConfig: String = "",
    val wgPrivateKey: String = "",
    val wgPeerPublicKey: String = "",
    val wgPresharedKey: String = "",
    val wgAddress: String = "",
    val wgDns: String = "",
    val wgAllowedIps: String = "",
    val wgKeepalive: Int = 0,
    val wgSecretRef: String = "",
) {
    val configuration: Map<String, Any?>
        get() = ChainConfig.configurationWithJson(configJson) ?: ChainConfig.defaultConfiguration()

    /** An empty port means 443, or 51820 in WireGuard mode. */
    val effectivePort: String
        get() = port.ifEmpty { if (ChainConfig.isWireGuard(configuration)) "51820" else "443" }

    val nodeName get() = "WaterWall VPN"

    /** The imported config, or one generated from the manual fields. */
    fun wgEffectiveConfig(): String? {
        if (wgConfig.isNotEmpty()) return wgConfig
        if (wgPrivateKey.isEmpty() || wgPeerPublicKey.isEmpty() || wgAddress.isEmpty() || server.isEmpty()) return null
        return buildString {
            append("[Interface]\nPrivateKey = $wgPrivateKey\nAddress = $wgAddress\n")
            if (wgDns.isNotEmpty()) append("DNS = $wgDns\n")
            append("\n[Peer]\nPublicKey = $wgPeerPublicKey\n")
            if (wgPresharedKey.isNotEmpty()) append("PresharedKey = $wgPresharedKey\n")
            append("Endpoint = $server:$effectivePort\n")
            append("AllowedIPs = ${wgAllowedIps.ifEmpty { "0.0.0.0/0" }}\n")
            if (wgKeepalive > 0) append("PersistentKeepalive = $wgKeepalive\n")
        }
    }
}

/** The app's secrets, encrypted with a key that the Android Keystore holds; the counterpart of the iOS Keychain. */
class SecretStore(context: Context) {
    private val preferences = context.getSharedPreferences("secrets", Context.MODE_PRIVATE)

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    fun set(name: String, value: String) {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val sealed = cipher.iv + cipher.doFinal(value.toByteArray())
        preferences.edit().putString(name, Base64.encodeToString(sealed, Base64.NO_WRAP)).apply()
    }

    fun get(name: String): String? {
        val sealed = Base64.decode(preferences.getString(name, null) ?: return null, Base64.NO_WRAP)
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, IV_BYTES))
            String(cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES))
        }.getOrNull()
    }

    fun delete(name: String) {
        preferences.edit().remove(name).apply()
    }

    private companion object {
        const val ALIAS = "srp-secrets"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
    }
}

/** Saved profiles, in the same parameter names as iOS: profiles.json holds no secret, the SecretStore holds the rest. */
class ProfileStore(context: Context) {
    private val file = File(context.filesDir, "profiles.json")
    private val secrets = SecretStore(context)

    fun load(): List<Profile> {
        val stored = (Json.parseOrNull(if (file.exists()) file.readText() else null) as? List<*>).orEmpty().filterIsInstance<Map<*, *>>()
        val profiles = stored.map { fromStored(it) }
        // Re-save profiles that still contain a plaintext credential or WireGuard key.
        if (stored.any { item -> listOf("password", "ww_outer_secret", "wg_conf", "wg_private_key", "wg_preshared_key").any { it in item } }) save(profiles)
        return profiles
    }

    fun save(profiles: List<Profile>) {
        val stored = profiles.map { toStored(it) }
        val temporary = File(file.path + ".tmp")
        temporary.writeText(Json.write(stored, pretty = true, sortedKeys = true))
        temporary.renameTo(file)
    }

    fun deleteSecrets(profile: Profile) {
        listOf(profile.passwordKey, profile.outerSecretRef, profile.wgSecretRef).filter { it.isNotEmpty() }.forEach { secrets.delete(it) }
    }

    private fun toStored(profile: Profile): Map<String, Any?> {
        var saved = profile
        if (saved.password.isNotEmpty()) {
            if (saved.passwordKey.isEmpty()) saved = saved.copy(passwordKey = UUID.randomUUID().toString())
            secrets.set(saved.passwordKey, saved.password)
        } else if (saved.passwordKey.isNotEmpty() && secrets.get(saved.passwordKey) != null) {
            // A secret the Keystore cannot read now also loads as empty, so only one that reads was really cleared.
            secrets.delete(saved.passwordKey)
        }
        if (saved.outerSecret.isNotEmpty()) {
            if (saved.outerSecretRef.isEmpty()) saved = saved.copy(outerSecretRef = UUID.randomUUID().toString())
            secrets.set(saved.outerSecretRef, saved.outerSecret)
        }
        val keys = LinkedHashMap<String, Any?>()
        if (saved.wgConfig.isNotEmpty()) keys["conf"] = saved.wgConfig
        if (saved.wgPrivateKey.isNotEmpty()) keys["private_key"] = saved.wgPrivateKey
        if (saved.wgPresharedKey.isNotEmpty()) keys["preshared_key"] = saved.wgPresharedKey
        if (keys.isNotEmpty()) {
            if (saved.wgSecretRef.isEmpty()) saved = saved.copy(wgSecretRef = UUID.randomUUID().toString())
            secrets.set(saved.wgSecretRef, Json.write(keys))
        } else if (saved.wgSecretRef.isNotEmpty() && secrets.get(saved.wgSecretRef) != null) {
            secrets.delete(saved.wgSecretRef)
            saved = saved.copy(wgSecretRef = "")
        }
        return linkedMapOf(
            "type" to "waterwall", "desc" to saved.desc, "node_id" to saved.nodeId, "username" to saved.username, "address" to saved.server,
            "port" to saved.effectivePort, "allowInsecure" to saved.allowInsecure, "ww_config" to saved.configJson, "password_key" to saved.passwordKey,
            "ww_outer_secret_ref" to saved.outerSecretRef, "ww_probe_ip" to saved.probeIp, "ww_dns_probe_ip" to saved.dnsProbeIp,
            "ww_fake_dns" to saved.fakeDns, "ww_smart_routing" to saved.smartRouting, "ww_auto_switch" to saved.autoSwitch,
            "tls_frag" to saved.tlsFragMode.toLong(), "tls_frag_first" to saved.tlsFragFirst.toLong(), "tls_frag_following" to saved.tlsFragFollowing.toLong(),
            "auto_reconnect" to saved.autoReconnect, "retry_times" to saved.retryTimes.toLong(), "switch_to_wifi" to saved.switchToWifi,
            "on_sleep" to listOf("off", "pause", "stay")[saved.onSleep], "log_level" to listOf("normal", "expert", "debug")[saved.logLevel],
            "sni" to saved.customSni, "wg_peer_public_key" to saved.wgPeerPublicKey, "wg_address" to saved.wgAddress, "wg_dns" to saved.wgDns,
            "wg_allowed_ips" to saved.wgAllowedIps, "wg_keepalive" to saved.wgKeepalive.toLong(), "wg_secret_ref" to saved.wgSecretRef,
        )
    }

    private fun fromStored(item: Map<*, *>): Profile {
        fun text(key: String) = item[key] as? String ?: ""
        fun flag(key: String, default: Boolean) = item[key] as? Boolean ?: default
        fun number(key: String) = (item[key] as? Number)?.toInt() ?: 0
        val defaults = Profile()
        val configJson = text("ww_config").takeIf { ChainConfig.configurationWithJson(it) != null && it.isNotEmpty() } ?: defaults.configJson
        // Password: prefer the store through password_key; a plaintext one moves there on the next save.
        val passwordKey = text("password_key")
        val outerRef = text("ww_outer_secret_ref")
        val wgRef = text("wg_secret_ref")
        val wg = (if (wgRef.isNotEmpty()) secrets.get(wgRef) else null)?.let { Json.parseOrNull(it) as? Map<*, *> }
        return Profile(
            nodeId = text("node_id").ifEmpty { defaults.nodeId },
            desc = text("desc"),
            username = text("username"),
            password = text("password").ifEmpty { if (passwordKey.isNotEmpty()) secrets.get(passwordKey).orEmpty() else "" },
            passwordKey = passwordKey,
            server = text("address"),
            port = text("port"),
            allowInsecure = flag("allowInsecure", false),
            configJson = configJson,
            outerSecret = text("ww_outer_secret").ifEmpty { if (outerRef.isNotEmpty()) secrets.get(outerRef).orEmpty() else "" },
            outerSecretRef = outerRef,
            probeIp = text("ww_probe_ip"),
            dnsProbeIp = text("ww_dns_probe_ip"),
            fakeDns = flag("ww_fake_dns", true),
            smartRouting = flag("ww_smart_routing", false),
            autoSwitch = flag("ww_auto_switch", true),
            tlsFragMode = number("tls_frag"),
            tlsFragFirst = number("tls_frag_first"),
            tlsFragFollowing = number("tls_frag_following"),
            autoReconnect = flag("auto_reconnect", true),
            retryTimes = number("retry_times"),
            switchToWifi = flag("switch_to_wifi", true),
            onSleep = when (item["on_sleep"]) { "off" -> 0; "pause" -> 1; else -> 2 },
            logLevel = when (item["log_level"]) { "debug" -> 2; "expert" -> 1; else -> 0 },
            customSni = text("sni"),
            wgConfig = (wg?.get("conf") as? String) ?: text("wg_conf"),
            wgPrivateKey = (wg?.get("private_key") as? String) ?: text("wg_private_key"),
            wgPeerPublicKey = text("wg_peer_public_key"),
            wgPresharedKey = (wg?.get("preshared_key") as? String) ?: text("wg_preshared_key"),
            wgAddress = text("wg_address"),
            wgDns = text("wg_dns"),
            wgAllowedIps = text("wg_allowed_ips"),
            wgKeepalive = number("wg_keepalive"),
            wgSecretRef = wgRef,
        )
    }
}

/** WireGuard keys as base64, as in wg-quick files. */
object WireGuardKeys {
    fun generatePrivateKey(): String {
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        key[0] = (key[0].toInt() and 248).toByte()
        key[31] = ((key[31].toInt() and 127) or 64).toByte()
        return Base64.encodeToString(key, Base64.NO_WRAP)
    }

    fun publicKey(privateKey: String): String? {
        val key = runCatching { Base64.decode(privateKey, Base64.DEFAULT) }.getOrNull()?.takeIf { it.size == 32 } ?: return null
        return WaterWall.x25519PublicKey(key)?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
    }
}
