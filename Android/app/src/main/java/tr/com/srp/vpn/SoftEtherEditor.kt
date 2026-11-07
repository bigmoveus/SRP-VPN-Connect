package tr.com.srp.vpn

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType

private const val SOFTETHER_SERVER_FOOTER = "Hostname overrides the TLS server name (SNI) and certificate verification; the TCP destination stays the Server field. When Hostname differs from the server certificate name, turn off TLS Server Verification. More Connections may improve throughput but use more memory. NAT-T asks the NAT-T server of SoftEther Corporation for the VPN server's UDP port, which sends it the connection's details; NAT-T Hint is the server's private IP address when several VPN servers share one public address."

private const val SOFTETHER_OPTIONS_FOOTER = "SoftEther always requires TLS 1.2 or later. TLS Fragmentation splits the handshake's outgoing bytes into smaller TCP writes (the TLS stream itself is unchanged); Auto picks the chunking from the access network, Manual sets the write sizes by hand."

/** The first reason a SoftEther profile cannot be saved yet, in the iOS editor's words (CreateVC validationMessage). */
fun softEtherValidationMessage(profile: Profile): String? {
    if (profile.server.isEmpty()) return "Enter the server address."
    if (profile.username.isEmpty()) return "Enter the username."
    if (profile.seAuthMethod == "certificate") {
        if (profile.certKey.isEmpty()) return "Import a client certificate."
    } else if (profile.seAuthMethod != "anonymous" && profile.password.isEmpty()) {
        return "Enter the password."
    }
    if (profile.seConnections !in 1..32) return "Use between 1 and 32 connections."
    when (profile.proxyMode) {
        1 -> if (profile.proxyAddress.isEmpty() || profile.proxyPort.isEmpty()) return "Enter the proxy address and port."
        2 -> {
            val url = runCatching { java.net.URI(profile.pacUrl) }.getOrNull()
            if (url == null || (url.scheme != "http" && url.scheme != "https") || url.host.isNullOrEmpty()) return "Enter an http or https PAC URL."
        }
    }
    return null
}

fun softEtherMethodTitle(method: String) = when (method) {
    "radiusNT" -> "RADIUS / NT Domain"
    "certificate" -> "Certificate"
    "anonymous" -> "Anonymous"
    else -> "Standard Password"
}

/** SERVER, AUTHENTICATION, PROXY and OPTIONS of a SoftEther profile, row for row as CreateVC.m shows them. */
@Composable
fun SoftEtherSections(draft: Profile, onChange: (Profile) -> Unit, push: (EditorPage) -> Unit) {
    Section("SERVER", SOFTETHER_SERVER_FOOTER) {
        row { TextFieldRow("Server", draft.server, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(server = it)) } }
        row { TextFieldRow("Port", draft.port, "443", keyboardType = KeyboardType.Number) { onChange(draft.copy(port = it)) } }
        row { TextFieldRow("Hostname", draft.hostnameOverride, "Optional", keyboardType = KeyboardType.Uri) { onChange(draft.copy(hostnameOverride = it)) } }
        row { SwitchRow("TLS Server Verification", !draft.allowInsecure) { onChange(draft.copy(allowInsecure = !it)) } }
        row { TextFieldRow("Virtual Hub", draft.hubName, "DEFAULT") { onChange(draft.copy(hubName = it)) } }
        row {
            TextFieldRow("Connections", if (draft.seConnections > 0) draft.seConnections.toString() else "", "1 – 32", keyboardType = KeyboardType.Number) { text ->
                onChange(draft.copy(seConnections = text.filter { it in '0'..'9' }.take(2).toIntOrNull() ?: 0))
            }
        }
        row { SwitchRow("Enable UDP Acceleration", draft.seUdpAcceleration) { onChange(draft.copy(seUdpAcceleration = it)) } }
        row { SwitchRow("Enable NAT Traversal (NAT-T)", draft.seNatTraversal) { onChange(draft.copy(seNatTraversal = it)) } }
        if (draft.seNatTraversal) {
            row { TextFieldRow("NAT-T Hint", draft.seNatTHint, "Optional", keyboardType = KeyboardType.Uri) { onChange(draft.copy(seNatTHint = it)) } }
        }
    }
    Section("AUTHENTICATION") {
        row { ValueRow("Method", softEtherMethodTitle(draft.seAuthMethod)) { push(EditorPage.SoftEtherMethod) } }
        row { TextFieldRow("Username", draft.username, "Required") { onChange(draft.copy(username = it)) } }
        when (draft.seAuthMethod) {
            "anonymous" -> Unit
            "certificate" -> row { ValueRow("Certificate", draft.certName.ifEmpty { "None" }) { push(EditorPage.SstpCertificate) } }
            else -> row { TextFieldRow("Password", draft.password, "Required", secure = true) { onChange(draft.copy(password = it)) } }
        }
    }
    val proxyFooter = when (draft.proxyMode) {
        1 -> "SoftEther supports HTTP CONNECT and SOCKS5 proxies. The proxy is only used for the connection to the VPN server."
        2 -> "The PAC script picks the proxy for the connection to the VPN server: PROXY is used as HTTP CONNECT, SOCKS and SOCKS5 as SOCKS5, and the next entry is tried when one cannot be reached. The username and password go to that proxy."
        else -> null
    }
    Section("PROXY", proxyFooter) {
        row { SegmentRow("Mode", listOf("None", "Manual", "Auto"), draft.proxyMode) { onChange(draft.copy(proxyMode = it)) } }
        if (draft.proxyMode == 1) {
            row { TextFieldRow("Address", draft.proxyAddress, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(proxyAddress = it)) } }
            row { TextFieldRow("Port", draft.proxyPort, "Required", keyboardType = KeyboardType.Number) { onChange(draft.copy(proxyPort = it)) } }
            row { SegmentRow("Type", listOf("HTTP", "SOCKS5"), if (draft.proxyType == "socks5") 1 else 0) { onChange(draft.copy(proxyType = if (it == 1) "socks5" else "http")) } }
        }
        if (draft.proxyMode == 2) {
            row { TextFieldRow("PAC URL", draft.pacUrl, "https://example.com/proxy.pac", keyboardType = KeyboardType.Uri) { onChange(draft.copy(pacUrl = it)) } }
        }
        if (draft.proxyMode != 0) {
            row { TextFieldRow("Username", draft.proxyUsername, "Optional") { onChange(draft.copy(proxyUsername = it)) } }
            row { TextFieldRow("Password", draft.proxyPassword, "Optional", secure = true) { onChange(draft.copy(proxyPassword = it)) } }
        }
    }
    Section("OPTIONS", SOFTETHER_OPTIONS_FOOTER) {
        row { SwitchRow("Auto Reconnect", draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) } }
        if (draft.autoReconnect) row { NumberRow("Retry Times", draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) } }
        row { SwitchRow("Switch to Wi-Fi When Available", draft.switchToWifi) { onChange(draft.copy(switchToWifi = it)) } }
        row { SegmentRow("On Sleep", listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) } }
        row { SegmentRow("Log Level", listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) } }
        row { SegmentRow("TLS Fragmentation", listOf("Off", "Auto", "Manual"), draft.tlsFragMode) { onChange(draft.copy(tlsFragMode = it)) } }
        if (draft.tlsFragMode == 2) {
            row { NumberRow("First Chunk (bytes)", draft.tlsFragFirst, "32") { onChange(draft.copy(tlsFragFirst = it)) } }
            row { NumberRow("Following Chunks (bytes)", draft.tlsFragFollowing, "256") { onChange(draft.copy(tlsFragFollowing = it)) } }
        }
    }
}

/** A number field where empty means zero and zero shows as empty. */
@Composable
private fun NumberRow(title: String, value: Int, placeholder: String, onChange: (Int) -> Unit) {
    TextFieldRow(title, if (value > 0) value.toString() else "", placeholder, keyboardType = KeyboardType.Number) { text ->
        onChange(text.filter { it in '0'..'9' }.take(9).toIntOrNull() ?: 0)
    }
}

/** Authentication: the SoftEther login methods (SRPSEMethodViewController), in its order. */
@Composable
fun SoftEtherMethodPage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().background(LocalIosColors.current.groupedBackground)) {
        NavBar("Authentication", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Section {
            for (method in listOf("standardPassword", "radiusNT", "certificate", "anonymous")) {
                row {
                    CheckRow(softEtherMethodTitle(method), checked = draft.seAuthMethod == method) {
                        onChange(draft.copy(seAuthMethod = method))
                        onBack()
                    }
                }
            }
        }
    }
}
