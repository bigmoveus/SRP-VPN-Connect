package tr.com.srp.vpn

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlin.concurrent.thread

// The iOS editor's footers (CreateVC.m) for an OpenVPN profile
private const val OPENVPN_SERVER_FOOTER = "The .ovpn profile supplies the OpenVPN configuration and credentials (client certificate or auth-user-pass). Server and Port are filled from the profile's first remote line on import; change them to connect to another address or port. Enable stunnel to wrap OpenVPN TCP in an outer TLS connection."

private const val OPENVPN_STUNNEL_FOOTER = "The .ovpn profile supplies the OpenVPN configuration and credentials. With stunnel on, OpenVPN runs over TCP (also for a UDP profile) inside a TLS connection to the server's stunnel listener; CA Certificate pins the CA that signs the stunnel certificate (empty = system trust)."

private const val OPENVPN_AUTH_FOOTER = "This .ovpn profile requires username/password authentication (auth-user-pass). Enter the credentials from your administrator."

private const val OPENVPN_OPTIONS_FOOTER = "Auto Reconnect lets OpenVPN connect again when the connection breaks or the server stops answering its keepalives; Retry Times limits the attempts (empty = no limit). Off: the VPN disconnects with the reason. OpenVPN uses the TLS parameters negotiated with the server (tls-crypt, data-channel ciphers). With stunnel on, the outer TLS connection requires TLS 1.2 or later, and TLS Fragmentation splits its handshake."

/** The first reason an OpenVPN profile cannot be saved yet, in the iOS editor's words (CreateVC validationMessage). */
fun openVpnValidationMessage(profile: Profile): String? {
    if (profile.server.isEmpty()) return "Enter the server address."
    if (profile.ovpnProfile.isEmpty()) return "Import an OpenVPN profile."
    if (OpenVpnProfileText.needsAuth(profile.ovpnProfile) && (profile.username.isEmpty() || profile.password.isEmpty())) {
        return "This OpenVPN profile needs a username and password."
    }
    if (profile.ovpnStunnelEnabled && profile.ovpnStunnelPort.isNotEmpty() && (profile.ovpnStunnelPort.toIntOrNull() ?: 0) !in 1..65535) {
        return "Enter a stunnel port between 1 and 65535."
    }
    if (profile.ovpnStunnelEnabled && profile.tlsFragMode == 2) {
        if (profile.tlsFragFirst > 4096) return "First Chunk can be at most 4096 bytes."
        if (profile.tlsFragFollowing > 16384) return "Following Chunks can be at most 16384 bytes."
    }
    return null
}

/** Every PEM certificate block must have base64 that decodes (CreateVC pemCertificatesAreValid): chat apps mangle them. */
fun pemCertificatesAreValid(text: String): Boolean {
    val blocks = Regex("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", RegexOption.DOT_MATCHES_ALL).findAll(text).toList()
    if (blocks.isEmpty()) return false
    return blocks.all { block ->
        val base64 = block.groupValues[1].filterNot { it.isWhitespace() }
        base64.isNotEmpty() && runCatching { java.util.Base64.getDecoder().decode(base64) }.isSuccess
    }
}

/** An imported text as the iOS editor takes it (CreateVC handleImportedText): mode "ovpn" or "ca". A problem's message, or the new profile. */
fun importedOpenVpnText(text: String, mode: String, profile: Profile): Pair<Profile?, String?> {
    if (mode == "ca") {
        if ("BEGIN CERTIFICATE" !in text) return null to "The file does not look like a PEM certificate (no BEGIN CERTIFICATE block)."
        if (!pemCertificatesAreValid(text)) {
            return null to "The certificate is damaged — the base64 inside the PEM block does not decode. This usually happens when the file is copied through a chat app. Import the original file, or use \"From URL\"."
        }
        return profile.copy(ovpnStunnelCa = text) to null
    }
    if ("remote" !in text || "dev" !in text) return null to "The file does not look like an OpenVPN profile (.ovpn)."
    if ("BEGIN CERTIFICATE" in text && !pemCertificatesAreValid(text)) {
        return null to "A certificate embedded in this profile is damaged — the base64 inside a PEM block does not decode. This usually happens when the file is copied through a chat app. Import the original file, or use \"From URL\"."
    }
    // Server and Port from the first remote line
    val remote = Regex("(?m)^[ \t]*remote[ \t]+(\\S+)(?:[ \t]+(\\d+))?").find(text)
    var imported = profile.copy(ovpnProfile = text)
    if (remote != null) {
        imported = imported.copy(server = remote.groupValues[1])
        if (remote.groupValues[2].isNotEmpty()) imported = imported.copy(port = remote.groupValues[2])
    }
    return imported to null
}

/** SERVER, AUTHENTICATION (when the profile asks for it) and OPTIONS of an OpenVPN profile, row for row as CreateVC.m shows them. */
@Composable
fun OpenVpnSections(draft: Profile, onChange: (Profile) -> Unit) {
    val ui = LocalUi.current
    val context = LocalContext.current
    var importMode by remember { mutableStateOf("ovpn") }
    val handle = { text: String?, mode: String ->
        if (text.isNullOrEmpty()) {
            ui.showAlert("Import Failed", "The file could not be read as UTF-8 text.")
        } else {
            val (imported, problem) = importedOpenVpnText(text, mode, draft)
            if (imported != null) onChange(imported) else ui.showAlert("Import Failed", problem)
        }
    }
    val importFile = rememberLauncherForActivityResult(OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val text = runCatching {
            val bytes = context.contentResolver.openInputStream(uri)!!.use { it.readBytes() }
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        }.getOrNull()
        handle(text, importMode)
    }
    // Import from Files or from URL (a URL avoids the copy-and-paste damage long files suffer), as the iOS action sheet offers
    val offerImport = { title: String, mode: String ->
        ui.choice = UiHost.Choice(title, null, listOf("From Files", "From URL", "Cancel"), emptySet()) { index ->
            when (index) {
                0 -> {
                    importMode = mode
                    importFile.launch(arrayOf("*/*"))
                }
                1 -> ui.prompt = UiHost.Prompt("Import from URL", null, "https://...", false, "Import") { address ->
                    val url = address?.trim().orEmpty()
                    if (address == null) return@Prompt
                    if (!url.startsWith("http://") && !url.startsWith("https://") || runCatching { URL(url).host }.getOrNull().isNullOrEmpty()) {
                        ui.showAlert("Invalid URL", "Enter a full URL (https://...).")
                        return@Prompt
                    }
                    thread(name = "srp.ovpn.import") {
                        val result = runCatching {
                            val connection = URL(url).openConnection() as HttpURLConnection
                            connection.connectTimeout = 15000
                            connection.readTimeout = 15000
                            connection.inputStream.use { String(it.readBytes(), Charsets.UTF_8) }
                        }
                        android.os.Handler(android.os.Looper.getMainLooper()).post {
                            val text = result.getOrNull()
                            if (text.isNullOrEmpty()) ui.showAlert("Download Failed", result.exceptionOrNull()?.message ?: "The file could not be downloaded.")
                            else handle(text, mode)
                        }
                    }
                }
            }
        }
    }
    Section("SERVER", if (draft.ovpnStunnelEnabled) OPENVPN_STUNNEL_FOOTER else OPENVPN_SERVER_FOOTER) {
        row { ValueRow("Profile (.ovpn)", if (draft.ovpnProfile.isNotEmpty()) "Imported" else "None") { offerImport("OpenVPN Profile", "ovpn") } }
        row { TextFieldRow("Server", draft.server, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(server = it)) } }
        row { TextFieldRow("Port", draft.port, "1194", keyboardType = KeyboardType.Number) { onChange(draft.copy(port = it)) } }
        row { SwitchRow("Enable stunnel (TLS)", draft.ovpnStunnelEnabled) { onChange(draft.copy(ovpnStunnelEnabled = it)) } }
        if (draft.ovpnStunnelEnabled) {
            row { TextFieldRow("stunnel Host", draft.ovpnStunnelHost, "Optional — default: Server", keyboardType = KeyboardType.Uri) { onChange(draft.copy(ovpnStunnelHost = it)) } }
            row { TextFieldRow("stunnel Port", draft.ovpnStunnelPort, "443", keyboardType = KeyboardType.Number) { onChange(draft.copy(ovpnStunnelPort = it)) } }
            row { TextFieldRow("stunnel SNI", draft.ovpnStunnelSni, "Optional — default: stunnel Host", keyboardType = KeyboardType.Uri) { onChange(draft.copy(ovpnStunnelSni = it)) } }
            row { ValueRow("CA Certificate", if (draft.ovpnStunnelCa.isNotEmpty()) "Imported" else "System Trust") { offerImport("CA Certificate", "ca") } }
        }
    }
    if (OpenVpnProfileText.needsAuth(draft.ovpnProfile)) {
        Section("AUTHENTICATION", OPENVPN_AUTH_FOOTER) {
            row { TextFieldRow("Username", draft.username, "Required") { onChange(draft.copy(username = it)) } }
            row { TextFieldRow("Password", draft.password, "Required", secure = true) { onChange(draft.copy(password = it)) } }
        }
    }
    Section("OPTIONS", OPENVPN_OPTIONS_FOOTER) {
        row { SwitchRow("Auto Reconnect", draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) } }
        if (draft.autoReconnect) row { CountRow("Retry Times", draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) } }
        row { SwitchRow("Switch to Wi-Fi When Available", draft.switchToWifi) { onChange(draft.copy(switchToWifi = it)) } }
        row { SegmentRow("On Sleep", listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) } }
        row { SegmentRow("Log Level", listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) } }
        if (draft.ovpnStunnelEnabled) {
            row { SegmentRow("TLS Fragmentation", listOf("Off", "Auto", "Manual"), draft.tlsFragMode) { onChange(draft.copy(tlsFragMode = it)) } }
            if (draft.tlsFragMode == 2) {
                row { CountRow("First Chunk (bytes)", draft.tlsFragFirst, "32") { onChange(draft.copy(tlsFragFirst = it)) } }
                row { CountRow("Following Chunks (bytes)", draft.tlsFragFollowing, "256") { onChange(draft.copy(tlsFragFollowing = it)) } }
            }
        }
    }
}
