package tr.com.srp.vpn

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType

// The iOS editor's footers (CreateVC.m) for an SSL VPN profile
private const val SSL_VPN_SERVER_FOOTER = "AnyConnect (for example ocserv), F5 BIG-IP or Palo Alto GlobalProtect. Path is what follows the server in its address, such as ?secret for an ocserv with camouflage; an address pasted whole into Server is split on Save. With TLS Server Verification on, the server certificate must be valid for the Server name."

private const val SSL_VPN_OPTIONS_FOOTER = "Auto Reconnect resumes the same session when the connection breaks; Retry Times limits the attempts (empty = as long as the server keeps the session, then new logins). Off: the VPN disconnects with the reason. OpenConnect always uses TLS 1.2 or later; DTLS (UDP) is used when the server supports it."

/** The first reason an SSL VPN profile cannot be saved yet, in the iOS editor's words (CreateVC validationMessage). */
fun sslVpnValidationMessage(profile: Profile): String? {
    if (profile.server.isEmpty()) return "Enter the server address."
    if (profile.username.isEmpty()) return "Enter the username."
    if (profile.certificateMode) {
        if (profile.certKey.isEmpty()) return "Import a client certificate."
    } else if (profile.password.isEmpty()) {
        return "Enter the password."
    }
    return null
}

/**
 * An address pasted whole into Server, such as `https://vpn.example.com:8443/?secret`, as Server, Port and Path (null when the
 * text has none of them); the server's address as typed otherwise. Mirrors SRPOCSplitServerAddress on iOS.
 */
fun splitSslVpnAddress(text: String): Triple<String, String?, String?> {
    var rest = text.trim()
    Regex("^https?://", RegexOption.IGNORE_CASE).find(rest)?.let { rest = rest.substring(it.range.last + 1) }
    val cut = rest.indexOfFirst { it == '/' || it == '?' }
    val hostPort = if (cut >= 0) rest.substring(0, cut) else rest
    val path = if (cut >= 0) rest.substring(cut).takeIf { it != "/" } else null
    // host:port, or [IPv6]:port; a bare IPv6 address has more than one colon and no port
    val port = Regex("^(\\[[^\\]]+\\]|[^:]+):(\\d{1,5})$").find(hostPort)
    return if (port != null) Triple(port.groupValues[1], port.groupValues[2], path) else Triple(hostPort, null, path)
}

/** The URL libopenconnect is given: the path starts with a slash, as it splits the host from the path at the first one. */
fun sslVpnUrl(server: String, port: String, path: String): String {
    val tail = path.trim().let { if (it.isEmpty()) "/" else if (it.startsWith("/")) it else "/$it" }
    return "https://$server:$port$tail"
}

/** SRPOCServerTypeViewController's names */
fun sslVpnServerTypeTitle(type: String) = when (type) {
    "f5" -> "F5 BIG-IP"
    "gp" -> "Palo Alto GP"
    else -> "AnyConnect"
}

/** SERVER, AUTHENTICATION and OPTIONS of an SSL VPN profile, row for row as CreateVC.m shows them (no proxy, as on iOS). */
@Composable
fun SslVpnSections(draft: Profile, onChange: (Profile) -> Unit, push: (EditorPage) -> Unit) {
    Section("SERVER", SSL_VPN_SERVER_FOOTER) {
        row { ValueRow("Server Type", sslVpnServerTypeTitle(draft.ocProtocol)) { push(EditorPage.SslVpnServerType) } }
        row { TextFieldRow("Server", draft.server, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(server = it)) } }
        row { TextFieldRow("Port", draft.port, "443", keyboardType = KeyboardType.Number) { onChange(draft.copy(port = it)) } }
        row { TextFieldRow("Path", draft.ocPath, "Optional", keyboardType = KeyboardType.Uri) { onChange(draft.copy(ocPath = it)) } }
        row { SwitchRow("TLS Server Verification", !draft.allowInsecure) { onChange(draft.copy(allowInsecure = !it)) } }
    }
    Section("AUTHENTICATION") {
        row { ValueRow("Method", if (draft.certificateMode) "Certificate" else "Password") { push(EditorPage.SstpMethod) } }
        row { TextFieldRow("Username", draft.username, "Required") { onChange(draft.copy(username = it)) } }
        if (draft.certificateMode) {
            row { ValueRow("Certificate", draft.certName.ifEmpty { "None" }) { push(EditorPage.SstpCertificate) } }
        } else {
            row { TextFieldRow("Password", draft.password, "Required", secure = true) { onChange(draft.copy(password = it)) } }
        }
    }
    Section("OPTIONS", SSL_VPN_OPTIONS_FOOTER) {
        row { SwitchRow("Auto Reconnect", draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) } }
        if (draft.autoReconnect) row { CountRow("Retry Times", draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) } }
        row { SwitchRow("Switch to Wi-Fi When Available", draft.switchToWifi) { onChange(draft.copy(switchToWifi = it)) } }
        row { SegmentRow("On Sleep", listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) } }
        row { SegmentRow("Log Level", listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) } }
        row { SegmentRow("TLS Fragmentation", listOf("Off", "Auto", "Manual"), draft.tlsFragMode) { onChange(draft.copy(tlsFragMode = it)) } }
        if (draft.tlsFragMode == 2) {
            row { CountRow("First Chunk (bytes)", draft.tlsFragFirst, "32") { onChange(draft.copy(tlsFragFirst = it)) } }
            row { CountRow("Following Chunks (bytes)", draft.tlsFragFollowing, "256") { onChange(draft.copy(tlsFragFollowing = it)) } }
        }
    }
}

/** A number field where empty means zero and zero shows as empty. */
@Composable
private fun CountRow(title: String, value: Int, placeholder: String, onChange: (Int) -> Unit) {
    TextFieldRow(title, if (value > 0) value.toString() else "", placeholder, keyboardType = KeyboardType.Number) { text ->
        onChange(text.filter { it in '0'..'9' }.take(9).toIntOrNull() ?: 0)
    }
}

/** Server Type (SRPOCServerTypeViewController), in its order. */
@Composable
fun SslVpnServerTypePage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().background(LocalIosColors.current.groupedBackground)) {
        NavBar("Server Type", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Section {
            for (type in listOf("anyconnect", "f5", "gp")) {
                row {
                    CheckRow(sslVpnServerTypeTitle(type), checked = draft.ocProtocol.ifEmpty { "anyconnect" } == type) {
                        onChange(draft.copy(ocProtocol = type))
                        onBack()
                    }
                }
            }
        }
    }
}
