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

/** The EAP settings of an SSTP profile, as SRPEapConfig on iOS: ttlsInnerMethod 0 = off, 1 = EAP, 2 = PAP, 3 = CHAP, 4 = MSCHAPv2. */
data class EapConfig(
    val eapMschapv2Enabled: Boolean = false,
    val peapEnabled: Boolean = false,
    val peapRequireCryptoBinding: Boolean = false,
    val ttlsInnerMethod: Int = 0,
    val teapEnabled: Boolean = false,
    val identityPrivacyEnabled: Boolean = false,
    val anonymousIdentity: String = "anonymous",
    val eapTls13Enabled: Boolean = true,
    val disableLegacyEapTls: Boolean = true,
) {
    val anyMethod get() = eapMschapv2Enabled || peapEnabled || teapEnabled || ttlsInnerMethod != 0

    fun toMap(): Map<String, Any?> = linkedMapOf(
        "eap_mschapv2_enabled" to eapMschapv2Enabled, "peap_enabled" to peapEnabled, "peap_require_crypto_binding" to peapRequireCryptoBinding,
        "ttls_inner_method" to ttlsInnerMethod.toLong(), "teap_enabled" to teapEnabled, "teap_secondary_method" to 0L,
        "identity_privacy_enabled" to identityPrivacyEnabled, "anonymous_identity" to anonymousIdentity,
        "eap_tls13_enabled" to eapTls13Enabled, "disable_legacy_eap_tls" to disableLegacyEapTls,
    )

    companion object {
        fun fromMap(item: Map<*, *>?): EapConfig {
            val defaults = EapConfig()
            if (item == null) return defaults
            fun flag(key: String, default: Boolean) = item[key] as? Boolean ?: default
            return EapConfig(
                eapMschapv2Enabled = flag("eap_mschapv2_enabled", defaults.eapMschapv2Enabled),
                peapEnabled = flag("peap_enabled", defaults.peapEnabled),
                peapRequireCryptoBinding = flag("peap_require_crypto_binding", defaults.peapRequireCryptoBinding),
                ttlsInnerMethod = (item["ttls_inner_method"] as? Number)?.toInt()?.takeIf { it in 0..4 } ?: defaults.ttlsInnerMethod,
                teapEnabled = flag("teap_enabled", defaults.teapEnabled),
                identityPrivacyEnabled = flag("identity_privacy_enabled", defaults.identityPrivacyEnabled),
                anonymousIdentity = item["anonymous_identity"] as? String ?: defaults.anonymousIdentity,
                eapTls13Enabled = flag("eap_tls13_enabled", defaults.eapTls13Enabled),
                disableLegacyEapTls = flag("disable_legacy_eap_tls", defaults.disableLegacyEapTls),
            )
        }
    }
}

/** One saved connection, with the same fields and defaults as a NodeModel on iOS. Secrets stay out of the stored profile. */
data class Profile(
    val nodeId: String = UUID.randomUUID().toString().uppercase(),
    /** "waterwall", "sstp", "softether", "openconnect" (SSL VPN), "ssh" or "openvpn" */
    val protocolType: String = "waterwall",
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
    // AmneziaWG's manual settings (NodeModel's wgJc … wgDisableCookies; 0 or empty = unset). S1-S4, H1-H4, the header protection key
    // and Random Trailers must match the server; the rest is this device's own.
    val wgJc: Int = 0,
    val wgJmin: Int = 0,
    val wgJmax: Int = 0,
    val wgS1: Int = 0,
    val wgS2: Int = 0,
    val wgS3: Int = 0,
    val wgS4: Int = 0,
    /** H1-H4: a number or a range ("1100000000-1199999999") */
    val wgH1: String = "",
    val wgH2: String = "",
    val wgH3: String = "",
    val wgH4: String = "",
    val wgI1: String = "",
    val wgI2: String = "",
    val wgI3: String = "",
    val wgI4: String = "",
    val wgI5: String = "",
    /** A secret like the keys: kept in the SecretStore with them */
    val wgHeaderProtectionKey: String = "",
    /** The content padding and the timings: a number or a range ("4-6") */
    val wgContentPaddingAddition: String = "",
    val wgRekeyAfterTime: String = "",
    val wgRekeyTimeout: String = "",
    val wgRejectAfterTime: String = "",
    val wgKeepaliveTimeout: String = "",
    val wgMaxHandshakeAttempts: String = "",
    val wgRandomTrailers: Boolean = false,
    val wgDisableCookies: Boolean = false,
    // SSTP, with the defaults the iOS editor gives a new SSTP profile
    val mschap2: Boolean = true,
    val allowLegacyPapChap: Boolean = false,
    /** "password" or "certificate" */
    val authMethod: String = "password",
    val certKey: String = "",
    val certName: String = "",
    val eap: EapConfig = EapConfig(),
    /** 0 = none, 1 = manual, 2 = auto (PAC) */
    val proxyMode: Int = 0,
    val proxyAddress: String = "",
    val proxyPort: String = "",
    val proxyUsername: String = "",
    val proxyPassword: String = "",
    val proxyPasswordRef: String = "",
    val pacUrl: String = "",
    val disableLegacyOuterTls: Boolean = false,
    val customSniEnabled: Boolean = false,
    // SoftEther (NodeModel's se* fields): standardPassword, radiusNT, certificate or anonymous
    val seAuthMethod: String = "standardPassword",
    val hubName: String = "DEFAULT",
    /** TLS SNI and certificate-verification name; empty = the server field */
    val hostnameOverride: String = "",
    val seConnections: Int = 1,
    val seUdpAcceleration: Boolean = false,
    val seNatTraversal: Boolean = false,
    val seNatTHint: String = "",
    /** The manual proxy's protocol: "http" or "socks5" (SSTP finds it by negotiation instead) */
    val proxyType: String = "http",
    /** SSL VPN server type: "anyconnect", "f5" (F5 BIG-IP) or "gp" (Palo Alto GlobalProtect) */
    val ocProtocol: String = "anyconnect",
    /** SSL VPN: what follows the server in its URL, such as ocserv camouflage's "?secret"; empty for none */
    val ocPath: String = "",
    /** SSH: the server's host key fingerprint ("SHA256:..." or the line ssh-keygen -lf prints); empty accepts any key */
    val sshHostKey: String = "",
    /** SSH: UDP through the HEV relay on the server (off by default, as on iOS) */
    val sshUdpRelay: Boolean = false,
    /** OpenVPN: the imported .ovpn with its keys inline; it holds the client's private key, so it is kept in the SecretStore */
    val ovpnProfile: String = "",
    val ovpnProfileRef: String = "",
    /** OpenVPN inside TLS to the server's stunnel listener (TCP; also for a UDP profile) */
    val ovpnStunnelEnabled: Boolean = false,
    /** Empty = the Server field */
    val ovpnStunnelHost: String = "",
    /** Empty = 443 */
    val ovpnStunnelPort: String = "",
    /** The outer TLS's SNI and certificate name; empty = the stunnel host */
    val ovpnStunnelSni: String = "",
    /** PEM of the CA that signs the stunnel certificate; empty = the system's trust */
    val ovpnStunnelCa: String = "",
) {
    val isSstp get() = protocolType == "sstp"
    val isSoftEther get() = protocolType == "softether"
    val isOpenConnect get() = protocolType == "openconnect"
    val isSsh get() = protocolType == "ssh"
    val isOpenVpn get() = protocolType == "openvpn"
    /** WireGuard or AmneziaWG: the same client, editor and options (AmneziaWG adds its obfuscation settings) */
    val isWireGuard get() = protocolType == "wireguard" || protocolType == "amnezia"
    val isAmnezia get() = protocolType == "amnezia"
    val isPlainWireGuard get() = protocolType == "wireguard"
    /** SSTP, SoftEther and SSL VPN: TLS protocols with a server, a port and the same OPTIONS (not WaterWall) */
    val isTlsVpn get() = isSstp || isSoftEther || isOpenConnect

    val certificateMode get() = ((isSstp || isOpenConnect) && authMethod == "certificate") || (isSoftEther && seAuthMethod == "certificate")

    val configuration: Map<String, Any?>
        get() = ChainConfig.configurationWithJson(configJson) ?: ChainConfig.defaultConfiguration()

    /** An empty port means 443, 22 for SSH, 1194 for OpenVPN, or 51820 in WireGuard mode. */
    val effectivePort: String
        get() = port.ifEmpty { if (isSsh) "22" else if (isOpenVpn) "1194" else if (isWireGuard || (!isTlsVpn && ChainConfig.isWireGuard(configuration))) "51820" else "443" }

    val nodeName get() = if (isSstp) "SSTP VPN" else if (isSoftEther) "SoftEther VPN" else if (isOpenConnect) "SSL VPN" else if (isSsh) "SSH VPN" else if (isOpenVpn) "OpenVPN" else if (isAmnezia) "AmneziaWG VPN" else if (isWireGuard) "WireGuard VPN" else "WaterWall VPN"

    /** The imported config, or one generated from the manual fields. */
    fun wgEffectiveConfig(): String? {
        if (wgConfig.isNotEmpty()) return if (isWireGuard) wgConfigWithEndpointFromFields(wgConfig) else wgConfig
        if (wgPrivateKey.isEmpty() || wgPeerPublicKey.isEmpty() || wgAddress.isEmpty() || server.isEmpty()) return null
        return buildString {
            append("[Interface]\nPrivateKey = $wgPrivateKey\nAddress = $wgAddress\n")
            if (wgDns.isNotEmpty()) append("DNS = $wgDns\n")
            if (isAmnezia) {
                listOf("Jc" to wgJc, "Jmin" to wgJmin, "Jmax" to wgJmax, "S1" to wgS1, "S2" to wgS2, "S3" to wgS3, "S4" to wgS4)
                    .filter { it.second > 0 }.forEach { append("${it.first} = ${it.second}\n") }
                listOf("H1" to wgH1, "H2" to wgH2, "H3" to wgH3, "H4" to wgH4, "I1" to wgI1, "I2" to wgI2, "I3" to wgI3, "I4" to wgI4,
                    "I5" to wgI5, "HeaderProtectionKey" to wgHeaderProtectionKey, "ContentPaddingAddition" to wgContentPaddingAddition,
                    "RekeyAfterTime" to wgRekeyAfterTime, "RekeyTimeout" to wgRekeyTimeout, "RejectAfterTime" to wgRejectAfterTime,
                    "KeepaliveTimeout" to wgKeepaliveTimeout, "MaxHandshakeAttempts" to wgMaxHandshakeAttempts)
                    .filter { it.second.trim().isNotEmpty() }.forEach { append("${it.first} = ${it.second.trim()}\n") }
                if (wgRandomTrailers) append("RandomTrailers = on\n")
                if (wgDisableCookies) append("DisableCookies = on\n")
            }
            append("\n[Peer]\nPublicKey = $wgPeerPublicKey\n")
            if (wgPresharedKey.isNotEmpty()) append("PresharedKey = $wgPresharedKey\n")
            append("Endpoint = $server:$effectivePort\n")
            append("AllowedIPs = ${wgAllowedIps.ifEmpty { "0.0.0.0/0" }}\n")
            if (wgKeepalive > 0) append("PersistentKeepalive = $wgKeepalive\n")
        }
    }
}

/**
 * An imported WireGuard config with the editor's Server and Port as its Endpoint (NodeModel wgConfigWithEndpointFromFields): the
 * import fills them from the Endpoint line, so they differ only when changed. An empty field keeps the file's value.
 */
internal fun Profile.wgConfigWithEndpointFromFields(config: String): String {
    val host = server.trim()
    val number = port.trim()
    if (host.isEmpty() && number.isEmpty()) return config
    val endpoint = Regex("""^([ \t]*Endpoint[ \t]*=[ \t]*)(\[[^\]]*\]|[^\s#;]*?)(?::(\d+))?[ \t]*$""", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE))
    val match = endpoint.find(config) ?: return config
    var name = host.ifEmpty { match.groupValues[2] }
    if (':' in name && !name.startsWith("[")) name = "[$name]"
    val value = number.ifEmpty { match.groups[3]?.value ?: "51820" }
    return config.replaceRange(match.range, "${match.groupValues[1]}$name:$value")
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
    private val certificates = CertificateStore(context)

    fun load(): List<Profile> {
        val stored = (Json.parseOrNull(if (file.exists()) file.readText() else null) as? List<*>).orEmpty().filterIsInstance<Map<*, *>>()
        val profiles = stored.map { fromStored(it) }
        // Re-save profiles that still contain a plaintext credential or WireGuard key.
        if (stored.any { item -> listOf("password", "ww_outer_secret", "wg_conf", "wg_private_key", "wg_preshared_key", "wg_header_protection_key", "proxy_password", "cert_p12", "ovpn_profile").any { it in item } }) save(profiles)
        return profiles
    }

    fun save(profiles: List<Profile>) {
        val stored = profiles.map { toStored(it) }
        val temporary = File(file.path + ".tmp")
        temporary.writeText(Json.write(stored, pretty = true, sortedKeys = true))
        temporary.renameTo(file)
    }

    fun deleteSecrets(profile: Profile) {
        listOf(profile.passwordKey, profile.outerSecretRef, profile.wgSecretRef, profile.proxyPasswordRef, profile.ovpnProfileRef).filter { it.isNotEmpty() }.forEach { secrets.delete(it) }
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
        if (saved.isTlsVpn || saved.isSsh || saved.isOpenVpn) return sstpStored(saved)
        val keys = LinkedHashMap<String, Any?>()
        if (saved.wgConfig.isNotEmpty()) keys["conf"] = saved.wgConfig
        if (saved.wgPrivateKey.isNotEmpty()) keys["private_key"] = saved.wgPrivateKey
        if (saved.wgPresharedKey.isNotEmpty()) keys["preshared_key"] = saved.wgPresharedKey
        if (saved.wgHeaderProtectionKey.isNotEmpty()) keys["header_protection_key"] = saved.wgHeaderProtectionKey
        if (keys.isNotEmpty()) {
            if (saved.wgSecretRef.isEmpty()) saved = saved.copy(wgSecretRef = UUID.randomUUID().toString())
            secrets.set(saved.wgSecretRef, Json.write(keys))
        } else if (saved.wgSecretRef.isNotEmpty() && secrets.get(saved.wgSecretRef) != null) {
            secrets.delete(saved.wgSecretRef)
            saved = saved.copy(wgSecretRef = "")
        }
        if (saved.isWireGuard) {
            // CheckConnectData's keys for a WireGuard or AmneziaWG profile; the keys and the imported file went to the store above
            val stored = linkedMapOf<String, Any?>(
                "type" to saved.protocolType, "desc" to saved.desc, "node_id" to saved.nodeId, "address" to saved.server, "port" to saved.port,
                "auto_reconnect" to saved.autoReconnect, "retry_times" to saved.retryTimes.toLong(),
                "on_sleep" to listOf("off", "pause", "stay")[saved.onSleep], "log_level" to listOf("normal", "expert", "debug")[saved.logLevel],
                "wg_peer_public_key" to saved.wgPeerPublicKey, "wg_address" to saved.wgAddress, "wg_dns" to saved.wgDns,
                "wg_allowed_ips" to saved.wgAllowedIps, "wg_keepalive" to saved.wgKeepalive.toLong(), "wg_secret_ref" to saved.wgSecretRef,
            )
            if (saved.isAmnezia) {
                // The AmneziaWG fields under CheckConnectData's keys (the header protection key went to the store with the keys)
                listOf("wg_jc" to saved.wgJc, "wg_jmin" to saved.wgJmin, "wg_jmax" to saved.wgJmax, "wg_s1" to saved.wgS1, "wg_s2" to saved.wgS2,
                    "wg_s3" to saved.wgS3, "wg_s4" to saved.wgS4).filter { it.second > 0 }.forEach { stored[it.first] = it.second.toLong() }
                listOf("wg_h1" to saved.wgH1, "wg_h2" to saved.wgH2, "wg_h3" to saved.wgH3, "wg_h4" to saved.wgH4, "wg_i1" to saved.wgI1,
                    "wg_i2" to saved.wgI2, "wg_i3" to saved.wgI3, "wg_i4" to saved.wgI4, "wg_i5" to saved.wgI5,
                    "wg_content_padding" to saved.wgContentPaddingAddition, "wg_rekey_after_time" to saved.wgRekeyAfterTime,
                    "wg_rekey_timeout" to saved.wgRekeyTimeout, "wg_reject_after_time" to saved.wgRejectAfterTime,
                    "wg_keepalive_timeout" to saved.wgKeepaliveTimeout, "wg_max_handshake_attempts" to saved.wgMaxHandshakeAttempts)
                    .filter { it.second.isNotEmpty() }.forEach { stored[it.first] = it.second }
                if (saved.wgRandomTrailers) stored["wg_random_trailers"] = true
                if (saved.wgDisableCookies) stored["wg_disable_cookies"] = true
            }
            return stored
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

    /** CheckConnectData's keys for an SSTP, SoftEther, SSL VPN, SSH or OpenVPN profile; the proxy password and the .ovpn go to the store like the main one. */
    private fun sstpStored(profile: Profile): Map<String, Any?> {
        var saved = profile
        // A profile moved from WaterWall has no WireGuard keys left to keep
        if (saved.wgSecretRef.isNotEmpty()) {
            secrets.delete(saved.wgSecretRef)
            saved = saved.copy(wgSecretRef = "")
        }
        if (saved.proxyPassword.isNotEmpty()) {
            if (saved.proxyPasswordRef.isEmpty()) saved = saved.copy(proxyPasswordRef = UUID.randomUUID().toString())
            secrets.set(saved.proxyPasswordRef, saved.proxyPassword)
        } else if (saved.proxyPasswordRef.isNotEmpty() && secrets.get(saved.proxyPasswordRef) != null) {
            secrets.delete(saved.proxyPasswordRef)
            saved = saved.copy(proxyPasswordRef = "")
        }
        val eap = saved.eap
        val stored = linkedMapOf<String, Any?>(
            "type" to saved.protocolType, "desc" to saved.desc, "node_id" to saved.nodeId, "username" to saved.username, "address" to saved.server,
            "port" to saved.effectivePort, "password_key" to saved.passwordKey,
            "chap_enable" to saved.allowLegacyPapChap, "mschap2_enable" to saved.mschap2, "pap_enable" to saved.allowLegacyPapChap,
            "allowInsecure" to saved.allowInsecure, "allow_legacy_papchap" to saved.allowLegacyPapChap, "auth_method" to saved.authMethod,
            "eapmschapv2_enable" to eap.eapMschapv2Enabled, "peap_enable" to eap.peapEnabled, "peap_require_cb" to eap.peapRequireCryptoBinding,
            "eapttls_enable" to (eap.ttlsInnerMethod != 0), "eapttls_inner" to ttlsInnerName(eap.ttlsInnerMethod), "eapteap_enable" to eap.teapEnabled,
            "eap_identity_privacy" to eap.identityPrivacyEnabled, "eap_anonymous_identity" to eap.anonymousIdentity,
            "eap_tls13" to eap.eapTls13Enabled, "eap_disable_legacy_tls" to eap.disableLegacyEapTls, "eap_config" to eap.toMap(),
            "cert_auth" to (saved.certificateMode && saved.certKey.isNotEmpty()),
            "proxy_mode" to listOf("none", "manual", "auto")[saved.proxyMode.coerceIn(0, 2)],
            "disable_legacy_outer_tls" to saved.disableLegacyOuterTls, "tls_frag" to saved.tlsFragMode.toLong(),
            "auto_reconnect" to saved.autoReconnect, "retry_times" to saved.retryTimes.toLong(), "switch_to_wifi" to saved.switchToWifi,
            "on_sleep" to listOf("off", "pause", "stay")[saved.onSleep], "log_level" to listOf("normal", "expert", "debug")[saved.logLevel],
            "custom_sni_enabled" to saved.customSniEnabled,
        )
        if (saved.certKey.isNotEmpty()) stored["cert_key"] = saved.certKey
        if (saved.certName.isNotEmpty()) stored["cert_name"] = saved.certName
        if (saved.proxyAddress.isNotEmpty()) stored["proxy_host"] = saved.proxyAddress
        if (saved.proxyPort.isNotEmpty()) stored["proxy_port"] = saved.proxyPort
        if (saved.proxyUsername.isNotEmpty()) stored["proxy_user"] = saved.proxyUsername
        if (saved.proxyPasswordRef.isNotEmpty()) stored["proxy_pass_ref"] = saved.proxyPasswordRef
        if (saved.pacUrl.isNotEmpty()) stored["pac_url"] = saved.pacUrl
        if (saved.tlsFragFirst > 0) stored["tls_frag_first"] = saved.tlsFragFirst.toLong()
        if (saved.tlsFragFollowing > 0) stored["tls_frag_following"] = saved.tlsFragFollowing.toLong()
        if (saved.customSni.isNotEmpty()) stored["sni"] = saved.customSni
        if (saved.isSoftEther) {
            stored["se_auth_method"] = saved.seAuthMethod
            stored["hub"] = saved.hubName.ifEmpty { "DEFAULT" }
            stored["se_connections"] = saved.seConnections.coerceIn(1, 32).toLong()
            stored["se_udp_accel"] = saved.seUdpAcceleration
            stored["se_natt"] = saved.seNatTraversal
            if (saved.seNatTHint.isNotEmpty()) stored["se_natt_hint"] = saved.seNatTHint
            if (saved.hostnameOverride.isNotEmpty()) stored["hostname_override"] = saved.hostnameOverride
            stored["proxy_type"] = saved.proxyType
        }
        if (saved.isOpenConnect) {
            stored["oc_protocol"] = saved.ocProtocol.ifEmpty { "anyconnect" }
            if (saved.ocPath.isNotEmpty()) stored["oc_path"] = saved.ocPath
        }
        if (saved.isSsh) {
            // CheckConnectData's keys for an SSH profile
            stored["ssh_udp"] = saved.sshUdpRelay
            if (saved.sshHostKey.isNotEmpty()) stored["hostkey"] = saved.sshHostKey
        }
        if (saved.isOpenVpn) {
            // CheckConnectData's keys for an OpenVPN profile; the .ovpn itself goes to the store (it holds the private key)
            if (saved.ovpnProfile.isNotEmpty()) {
                if (saved.ovpnProfileRef.isEmpty()) saved = saved.copy(ovpnProfileRef = UUID.randomUUID().toString())
                secrets.set(saved.ovpnProfileRef, saved.ovpnProfile)
                stored["ovpn_profile_ref"] = saved.ovpnProfileRef
            }
            stored["stunnel"] = saved.ovpnStunnelEnabled
            if (saved.ovpnStunnelHost.isNotEmpty()) stored["stunnel_host"] = saved.ovpnStunnelHost
            if (saved.ovpnStunnelPort.isNotEmpty()) stored["stunnel_port"] = saved.ovpnStunnelPort
            if (saved.ovpnStunnelSni.isNotEmpty()) stored["stunnel_sni"] = saved.ovpnStunnelSni
            if (saved.ovpnStunnelCa.isNotEmpty()) stored["stunnel_ca"] = saved.ovpnStunnelCa
        }
        return stored
    }

    private fun fromStored(item: Map<*, *>): Profile {
        fun text(key: String) = item[key] as? String ?: ""
        fun flag(key: String, default: Boolean) = item[key] as? Boolean ?: default
        fun number(key: String) = (item[key] as? Number)?.toInt() ?: 0
        fun header(key: String) = when (val value = item[key]) {
            is Number -> if (value.toLong() > 0) value.toLong().toString() else ""
            is String -> value
            else -> ""
        }
        val defaults = Profile()
        val configJson = text("ww_config").takeIf { ChainConfig.configurationWithJson(it) != null && it.isNotEmpty() } ?: defaults.configJson
        // Password: prefer the store through password_key; a plaintext one moves there on the next save.
        val passwordKey = text("password_key")
        val outerRef = text("ww_outer_secret_ref")
        val wgRef = text("wg_secret_ref")
        val wg = (if (wgRef.isNotEmpty()) secrets.get(wgRef) else null)?.let { Json.parseOrNull(it) as? Map<*, *> }
        // A certificate written into the file as a PKCS#12 moves to the certificate store, as plaintext secrets move to theirs
        val imported = text("cert_p12").takeIf { it.isNotEmpty() }?.let { p12 ->
            runCatching { Base64.decode(p12, Base64.NO_WRAP) }.getOrNull()?.let { certificates.import(it, text("cert_passphrase")).getOrNull() }
        }
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
            wgJc = number("wg_jc"),
            wgJmin = number("wg_jmin"),
            wgJmax = number("wg_jmax"),
            wgS1 = number("wg_s1"),
            wgS2 = number("wg_s2"),
            wgS3 = number("wg_s3"),
            wgS4 = number("wg_s4"),
            // H1-H4 were numbers on iPhone before ranges were possible
            wgH1 = header("wg_h1"),
            wgH2 = header("wg_h2"),
            wgH3 = header("wg_h3"),
            wgH4 = header("wg_h4"),
            wgI1 = text("wg_i1"),
            wgI2 = text("wg_i2"),
            wgI3 = text("wg_i3"),
            wgI4 = text("wg_i4"),
            wgI5 = text("wg_i5"),
            wgHeaderProtectionKey = (wg?.get("header_protection_key") as? String) ?: text("wg_header_protection_key"),
            wgContentPaddingAddition = text("wg_content_padding"),
            wgRekeyAfterTime = text("wg_rekey_after_time"),
            wgRekeyTimeout = text("wg_rekey_timeout"),
            wgRejectAfterTime = text("wg_reject_after_time"),
            wgKeepaliveTimeout = text("wg_keepalive_timeout"),
            wgMaxHandshakeAttempts = text("wg_max_handshake_attempts"),
            wgRandomTrailers = flag("wg_random_trailers", false),
            wgDisableCookies = flag("wg_disable_cookies", false),
            protocolType = text("type").takeIf { it == "sstp" || it == "softether" || it == "openconnect" || it == "ssh" || it == "openvpn" || it == "wireguard" || it == "amnezia" } ?: "waterwall",
            mschap2 = flag("mschap2_enable", true),
            allowLegacyPapChap = flag("allow_legacy_papchap", false),
            authMethod = text("auth_method").ifEmpty { "password" },
            certKey = imported?.ref ?: text("cert_key"),
            certName = imported?.name ?: text("cert_name"),
            eap = EapConfig.fromMap(item["eap_config"] as? Map<*, *>),
            proxyMode = when (item["proxy_mode"]) { "manual" -> 1; "auto" -> 2; else -> 0 },
            proxyAddress = text("proxy_host"),
            proxyPort = text("proxy_port"),
            proxyUsername = text("proxy_user"),
            proxyPassword = text("proxy_password").ifEmpty { text("proxy_pass_ref").let { if (it.isNotEmpty()) secrets.get(it).orEmpty() else "" } },
            proxyPasswordRef = text("proxy_pass_ref"),
            pacUrl = text("pac_url"),
            disableLegacyOuterTls = flag("disable_legacy_outer_tls", false),
            customSniEnabled = flag("custom_sni_enabled", false),
            seAuthMethod = text("se_auth_method").ifEmpty { "standardPassword" },
            hubName = text("hub").ifEmpty { "DEFAULT" },
            hostnameOverride = text("hostname_override"),
            seConnections = number("se_connections").coerceIn(1, 32),
            seUdpAcceleration = flag("se_udp_accel", false),
            seNatTraversal = flag("se_natt", false),
            seNatTHint = text("se_natt_hint"),
            proxyType = if (text("proxy_type") == "socks5") "socks5" else "http",
            ocProtocol = text("oc_protocol").takeIf { it == "f5" || it == "gp" } ?: "anyconnect",
            ocPath = text("oc_path"),
            sshHostKey = text("hostkey"),
            sshUdpRelay = flag("ssh_udp", false),
            // a plaintext .ovpn (written by an older build or a test) moves to the store on the next save
            ovpnProfile = text("ovpn_profile").ifEmpty { text("ovpn_profile_ref").let { if (it.isNotEmpty()) secrets.get(it).orEmpty() else "" } },
            ovpnProfileRef = text("ovpn_profile_ref"),
            ovpnStunnelEnabled = flag("stunnel", false),
            ovpnStunnelHost = text("stunnel_host"),
            ovpnStunnelPort = text("stunnel_port"),
            ovpnStunnelSni = text("stunnel_sni"),
            ovpnStunnelCa = text("stunnel_ca"),
        )
    }
}

/** The tunnel's name for a TTLS inner method, as CheckConnectData sends it: MSCHAPv2 runs as inner EAP. */
fun ttlsInnerName(method: Int) = when (method) {
    2 -> "pap"
    3 -> "chap"
    else -> "eap"
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
