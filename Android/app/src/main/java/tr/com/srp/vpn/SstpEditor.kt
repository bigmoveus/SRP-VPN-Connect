package tr.com.srp.vpn

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date

const val SSTP_MAX_FIRST_CHUNK = 4096
const val SSTP_MAX_FOLLOWING_CHUNK = 16384

private const val SSTP_OPTIONS_FOOTER = "Disable TLS 1.0 & 1.1 applies to the outer SSTP connection only; the EAP tunnel versions are configured in EAP Configuration. Custom SNI is sent in the TLS ClientHello and used for certificate verification; the TCP destination stays the Host field. TLS Fragmentation splits the handshake's outgoing bytes into smaller TCP writes (the TLS stream itself is unchanged) — experimental, may help on networks with DPI. Auto picks the chunking from the access network; Manual sets the write sizes by hand."

/** A bare DNS hostname: no scheme, port, path or whitespace (NodeModel isValidCustomSni). */
fun isValidCustomSni(sni: String): Boolean {
    if (sni.isEmpty() || "://" in sni || ':' in sni || '/' in sni || sni.any { it.isWhitespace() }) return false
    return Regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$").matches(sni)
}

/** The first reason an SSTP profile cannot be saved yet, in the iOS editor's words. */
fun sstpValidationMessage(profile: Profile): String? {
    if (profile.certificateMode) {
        if (profile.server.isEmpty()) return "Enter the server address."
        if (profile.certKey.isEmpty()) return "Import a client certificate."
    } else {
        if (profile.server.isEmpty()) return "Enter the server address."
        if (profile.username.isEmpty()) return "Enter the username."
        if (profile.password.isEmpty()) return "Enter the password."
        if (!(profile.mschap2 || profile.allowLegacyPapChap || profile.eap.anyMethod)) return "Enable at least one authentication method."
    }
    when (profile.proxyMode) {
        1 -> if (profile.proxyAddress.isEmpty() || profile.proxyPort.isEmpty()) return "Enter the proxy address and port."
        2 -> {
            val url = runCatching { java.net.URI(profile.pacUrl) }.getOrNull()
            if (url == null || (url.scheme != "http" && url.scheme != "https") || url.host.isNullOrEmpty()) return "Enter an http or https PAC URL."
        }
    }
    if (profile.customSniEnabled && !isValidCustomSni(profile.customSni)) return "Custom SNI must be a bare hostname, without a scheme, port, path or spaces."
    // Empty sizes mean the placeholders; larger ones would only be refused when connecting
    if (profile.tlsFragMode == 2) {
        if (profile.tlsFragFirst > SSTP_MAX_FIRST_CHUNK) return "First Chunk can be at most $SSTP_MAX_FIRST_CHUNK bytes."
        if (profile.tlsFragFollowing > SSTP_MAX_FOLLOWING_CHUNK) return "Following Chunks can be at most $SSTP_MAX_FOLLOWING_CHUNK bytes."
    }
    return null
}

/** SERVER, AUTHENTICATION, PROXY and OPTIONS of an SSTP profile, row for row as CreateVC.m shows them. */
@Composable
fun SstpSections(draft: Profile, onChange: (Profile) -> Unit, push: (EditorPage) -> Unit) {
    Section("SERVER") {
        row { TextFieldRow("Host", draft.server, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(server = it)) } }
        row { TextFieldRow("Port", draft.port, "443", keyboardType = KeyboardType.Number) { onChange(draft.copy(port = it)) } }
        row { SwitchRow("Allow Untrusted Certificate", draft.allowInsecure) { onChange(draft.copy(allowInsecure = it)) } }
    }
    Section("AUTHENTICATION") {
        row { ValueRow("Method", if (draft.certificateMode) "Certificate" else "Password") { push(EditorPage.SstpMethod) } }
        if (draft.certificateMode) {
            // Optional: used as the identity hint / outer EAP identity
            row { TextFieldRow("Username", draft.username, "Optional") { onChange(draft.copy(username = it)) } }
            row { ValueRow("Certificate", draft.certName.ifEmpty { "None" }) { push(EditorPage.SstpCertificate) } }
            row { ValueRow("EAP Configuration") { push(EditorPage.SstpEap) } }
        } else {
            row { TextFieldRow("Username", draft.username, "Required") { onChange(draft.copy(username = it)) } }
            row { TextFieldRow("Password", draft.password, "Required", secure = true) { onChange(draft.copy(password = it)) } }
            row { ValueRow("EAP Configuration") { push(EditorPage.SstpEap) } }
            row { SwitchRow("Enable MS-CHAPv2", draft.mschap2) { onChange(draft.copy(mschap2 = it)) } }
            row { SwitchRow("Enable PAP / CHAP (Less Secure)", draft.allowLegacyPapChap) { onChange(draft.copy(allowLegacyPapChap = it)) } }
        }
    }
    val proxyFooter = when (draft.proxyMode) {
        1 -> "The proxy protocol (SOCKS5 or HTTP CONNECT) is detected automatically by negotiation."
        2 -> "The PAC script picks the proxy for the connection to the VPN server; the username and password go to that proxy when it asks for them."
        else -> null
    }
    Section("PROXY", proxyFooter) {
        row { SegmentRow("Mode", listOf("None", "Manual", "Auto"), draft.proxyMode) { onChange(draft.copy(proxyMode = it)) } }
        if (draft.proxyMode == 1) {
            row { TextFieldRow("Address", draft.proxyAddress, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(proxyAddress = it)) } }
            row { TextFieldRow("Port", draft.proxyPort, "Required", keyboardType = KeyboardType.Number) { onChange(draft.copy(proxyPort = it)) } }
        }
        if (draft.proxyMode == 2) {
            row { TextFieldRow("PAC URL", draft.pacUrl, "https://example.com/proxy.pac", keyboardType = KeyboardType.Uri) { onChange(draft.copy(pacUrl = it)) } }
        }
        if (draft.proxyMode != 0) {
            // The proxy the PAC script picks may ask for a password too
            row { TextFieldRow("Username", draft.proxyUsername, "Optional") { onChange(draft.copy(proxyUsername = it)) } }
            row { TextFieldRow("Password", draft.proxyPassword, "Optional", secure = true) { onChange(draft.copy(proxyPassword = it)) } }
        }
    }
    val optionsFooter = SSTP_OPTIONS_FOOTER + if (draft.customSniEnabled) " Note: when the SNI hostname differs from the server's certificate name, enable \"Allow Untrusted Certificate\" to connect." else ""
    Section("OPTIONS", optionsFooter) {
        row { SwitchRow("Disable TLS 1.0 & 1.1", draft.disableLegacyOuterTls) { onChange(draft.copy(disableLegacyOuterTls = it)) } }
        row { SwitchRow("Auto Reconnect", draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) } }
        if (draft.autoReconnect) row { SstpNumberRow("Retry Times", draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) } }
        row { SwitchRow("Switch to Wi-Fi When Available", draft.switchToWifi) { onChange(draft.copy(switchToWifi = it)) } }
        row { SegmentRow("On Sleep", listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) } }
        row { SegmentRow("Log Level", listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) } }
        row { SwitchRow("Enable Custom SNI", draft.customSniEnabled) { onChange(draft.copy(customSniEnabled = it)) } }
        if (draft.customSniEnabled) {
            // A bare DNS name only (checked on save); the TCP destination always stays the Host field
            row { TextFieldRow("SNI Hostname", draft.customSni, "vpn.example.com", keyboardType = KeyboardType.Uri) { onChange(draft.copy(customSni = it)) } }
        }
        row { SegmentRow("TLS Fragmentation", listOf("Off", "Auto", "Manual"), draft.tlsFragMode) { onChange(draft.copy(tlsFragMode = it)) } }
        if (draft.tlsFragMode == 2) {
            row { SstpNumberRow("First Chunk (bytes)", draft.tlsFragFirst, "32") { onChange(draft.copy(tlsFragFirst = it)) } }
            row { SstpNumberRow("Following Chunks (bytes)", draft.tlsFragFollowing, "256") { onChange(draft.copy(tlsFragFollowing = it)) } }
        }
    }
}

/** A number field where empty means zero and zero shows as empty. */
@Composable
private fun SstpNumberRow(title: String, value: Int, placeholder: String, onChange: (Int) -> Unit) {
    TextFieldRow(title, if (value > 0) value.toString() else "", placeholder, keyboardType = KeyboardType.Number) { text ->
        onChange(text.filter { it in '0'..'9' }.take(9).toIntOrNull() ?: 0)
    }
}

/** Method: Password or Certificate (SRPMethodViewController). */
@Composable
fun SstpMethodPage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().background(LocalIosColors.current.groupedBackground)) {
        NavBar("Method", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Section {
            row { CheckRow("Password", checked = !draft.certificateMode) { onChange(draft.copy(authMethod = "password")); onBack() } }
            row { CheckRow("Certificate", checked = draft.certificateMode) { onChange(draft.copy(authMethod = "certificate")); onBack() } }
        }
    }
}

/** Select Certificate: the imported client certificates, and Import for a new .p12 or .pfx file (SRPCertificateViewController). */
@Composable
fun SstpCertificatePage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val context = LocalContext.current
    val store = remember { CertificateStore(context) }
    var certificates by remember { mutableStateOf(store.list()) }
    val picker = rememberLauncherForActivityResult(OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val name = uri.lastPathSegment?.substringAfterLast('/') ?: "the certificate"
        val bytes = runCatching { context.contentResolver.openInputStream(uri)!!.use { it.readBytes() } }.getOrNull()
        if (bytes == null || bytes.isEmpty()) {
            ui.showAlert("Import Failed", "Could not read the selected file.")
            return@rememberLauncherForActivityResult
        }
        ui.prompt = UiHost.Prompt("Certificate Passphrase", "Enter the passphrase for $name", "Passphrase", true, "Import") { passphrase ->
            if (passphrase == null) return@Prompt
            store.import(bytes, passphrase).onSuccess { certificate ->
                certificates = store.list()
                onChange(draft.copy(certKey = certificate.ref, certName = certificate.name))
            }.onFailure { ui.showAlert("Import Failed", it.message ?: "Import failed.") }
        }
    }
    Column(Modifier.fillMaxSize().background(colors.groupedBackground)) {
        NavBar(
            "Select Certificate",
            left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) },
            right = {
                Label("Import", IosText.body.copy(fontWeight = FontWeight.SemiBold), colors.blue,
                    Modifier.clickable(onClickLabel = "Import a client certificate") { picker.launch(arrayOf("application/x-pkcs12", "application/octet-stream", "*/*")) }.padding(8.dp))
            },
        )
        Column(Modifier.weight(1f).navigationBarsPadding().verticalScroll(rememberScrollState())) {
            val footer = if (certificates.isEmpty()) "No certificates imported yet. Tap Import to add a .p12/.pfx client certificate."
            else "Import a client certificate as a .p12 or .pfx file (PKCS#12). The file must contain the certificate and its private key. You will be asked for the export passphrase."
            Section(footer = footer) {
                for (certificate in certificates) {
                    val expiry = if (certificate.expiry > 0) "Expires ${DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(certificate.expiry * 1000))}" else null
                    row {
                        CheckRow(certificate.name, expiry, checked = certificate.ref == draft.certKey) {
                            onChange(draft.copy(certKey = certificate.ref, certName = certificate.name))
                            onBack()
                        }
                    }
                }
            }
        }
    }
}

/** EAP Configuration (SRPEapConfigViewController): every method the lwIP backend has, and the EAP tunnel's TLS options. */
@Composable
fun SstpEapPage(draft: Profile, onChange: (Profile) -> Unit, push: (EditorPage) -> Unit, onBack: () -> Unit) {
    val eap = draft.eap
    fun update(value: EapConfig) = onChange(draft.copy(eap = value))
    Column(Modifier.fillMaxSize().background(LocalIosColors.current.groupedBackground)) {
        NavBar("EAP Configuration", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Column(Modifier.weight(1f).navigationBarsPadding().imePadding().verticalScroll(rememberScrollState())) {
            Section("EAP", "TEAP secondary authentication is not supported") {
                row { SwitchRow("Enable EAP-MSCHAPv2", eap.eapMschapv2Enabled) { update(eap.copy(eapMschapv2Enabled = it)) } }
            }
            Section("PEAP") {
                row { SwitchRow("Enable PEAP", eap.peapEnabled) { update(eap.copy(peapEnabled = it, peapRequireCryptoBinding = it && eap.peapRequireCryptoBinding)) } }
                if (eap.peapEnabled) row { SwitchRow("Require Crypto Binding", eap.peapRequireCryptoBinding) { update(eap.copy(peapRequireCryptoBinding = it)) } }
            }
            Section("EAP-TTLS") {
                row { ValueRow("EAP-TTLS Method", ttlsMethodTitle(eap.ttlsInnerMethod)) { push(EditorPage.SstpTtls) } }
            }
            Section("TEAP") {
                row { SwitchRow("Enable TEAP", eap.teapEnabled) { update(eap.copy(teapEnabled = it)) } }
            }
            Section("OPTIONS", "TEAP secondary authentication is not supported") {
                row { SwitchRow("Enable Identity Privacy", eap.identityPrivacyEnabled) { update(eap.copy(identityPrivacyEnabled = it)) } }
                row { TextFieldRow("Identity", eap.anonymousIdentity, "anonymous") { update(eap.copy(anonymousIdentity = it)) } }
                row { SwitchRow("Enable TLS 1.3", eap.eapTls13Enabled) { update(eap.copy(eapTls13Enabled = it)) } }
                row { SwitchRow("Disable TLS 1.0 & 1.1", eap.disableLegacyEapTls) { update(eap.copy(disableLegacyEapTls = it)) } }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

fun ttlsMethodTitle(method: Int) = when (method) {
    1 -> "EAP"
    2 -> "PAP"
    3 -> "CHAP"
    4 -> "MSCHAPv2"
    else -> "Disabled"
}

/** EAP-TTLS Method (SRPTtlsMethodViewController). */
@Composable
fun SstpTtlsPage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().background(LocalIosColors.current.groupedBackground)) {
        NavBar("EAP-TTLS Method", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Section {
            for (method in listOf(0, 1, 2, 3, 4)) {
                row {
                    CheckRow(ttlsMethodTitle(method), checked = draft.eap.ttlsInnerMethod == method) {
                        onChange(draft.copy(eap = draft.eap.copy(ttlsInnerMethod = method)))
                        onBack()
                    }
                }
            }
        }
    }
}
