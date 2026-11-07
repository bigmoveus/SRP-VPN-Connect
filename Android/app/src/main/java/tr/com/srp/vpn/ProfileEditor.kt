package tr.com.srp.vpn

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

private const val SERVER_FOOTER = "Configuration independently combines the input, application protocol, MUX and outer transport. SOCKS5 supports TCP and UDP Association directly; HTTP CONNECT supports TCP. Proxy username and password are optional as a pair. Advanced Node Settings provides per-node JSON overrides. Reality defaults to the www.cloudflare.com cover and uses a separate password. AEAD has no TLS handshake. Raw IPv4 uses PacketsToStream. TLS Server Verification validates TLS, Reality and QUIC certificates. Optional SNI must match the server's cover configuration."

/** The screens of the editor, which open one over the other as in the iOS navigation stack. */
sealed interface EditorPage {
    data object Main : EditorPage

    data object Protocol : EditorPage

    data object WireGuardManual : EditorPage

    data object WaterWall : EditorPage

    data class Choice(val row: String) : EditorPage

    data class NodeOptions(val layer: String) : EditorPage

    data object Countries : EditorPage

    data object SstpMethod : EditorPage

    data object SstpCertificate : EditorPage

    data object SstpEap : EditorPage

    data object SstpTtls : EditorPage

    data object SoftEtherMethod : EditorPage

    data object SslVpnServerType : EditorPage
}

/** Add Profile and Edit Profile. Nothing reaches the saved profile until Save. */
@Composable
fun ProfileEditor(profile: Profile?, onClose: () -> Unit, onSave: (Profile) -> Unit) {
    var draft by remember { mutableStateOf(profile ?: Profile()) }
    var pages by remember { mutableStateOf(listOf<EditorPage>(EditorPage.Main)) }
    // What a page remembers, such as how far it was scrolled, stays while a sub-screen is on top and goes when the page closes.
    val pageStates = rememberSaveableStateHolder()
    val push: (EditorPage) -> Unit = { pages = pages + it }
    val pop: () -> Unit = {
        pageStates.removeState(pages.last().toString())
        pages = pages.dropLast(1)
    }
    BackHandler(pages.size > 1, onBack = pop)
    var depth by remember { mutableStateOf(1) }
    val forward = pages.size >= depth
    depth = pages.size
    AnimatedContent(
        targetState = pages.last(),
        transitionSpec = {
            if (forward) slideInHorizontally(tween(280)) { it } togetherWith slideOutHorizontally(tween(280)) { -it / 3 }
            else slideInHorizontally(tween(280)) { -it / 3 } togetherWith slideOutHorizontally(tween(280)) { it }
        },
        label = "editor",
    ) { page ->
        pageStates.SaveableStateProvider(page.toString()) {
            when (page) {
                EditorPage.Main -> ProfileEditPage(draft, profile != null, { draft = it }, push, onClose, onSave)
                EditorPage.Protocol -> ProtocolPage(draft, { draft = it }, pop)
                EditorPage.WireGuardManual -> WireGuardManualPage(draft, { draft = it }, pop)
                EditorPage.WaterWall -> WaterWallConfigPage(draft, { draft = it }, push, pop)
                is EditorPage.Choice -> WaterWallChoicePage(page.row, draft, { draft = it }, pop)
                is EditorPage.NodeOptions -> NodeOptionsPage(page.layer, draft, { draft = it }, pop)
                EditorPage.Countries -> GeoIpCountriesPage(draft, { draft = it }, pop)
                EditorPage.SstpMethod -> SstpMethodPage(draft, { draft = it }, pop)
                EditorPage.SstpCertificate -> SstpCertificatePage(draft, { draft = it }, pop)
                EditorPage.SstpEap -> SstpEapPage(draft, { draft = it }, push, pop)
                EditorPage.SstpTtls -> SstpTtlsPage(draft, { draft = it }, pop)
                EditorPage.SoftEtherMethod -> SoftEtherMethodPage(draft, { draft = it }, pop)
                EditorPage.SslVpnServerType -> SslVpnServerTypePage(draft, { draft = it }, pop)
            }
        }
    }
}

/** The first problem of a profile about to be saved, in the iOS app's words. */
fun validationMessage(profile: Profile): String? {
    if (profile.isSstp) return sstpValidationMessage(profile)
    if (profile.isSoftEther) return softEtherValidationMessage(profile)
    if (profile.isOpenConnect) return sslVpnValidationMessage(profile)
    val configuration = profile.configuration
    ChainConfig.validationError(configuration)?.let { return it }
    if (ChainConfig.isDirect(configuration)) return null
    if (ChainConfig.isWireGuard(configuration)) {
        return if (ChainConfig.wireGuardWithConfig(profile.wgEffectiveConfig()) == null) "Import or enter a complete, valid WireGuard configuration." else null
    }
    if (profile.server.isEmpty()) return "Enter the WaterWall server."
    if ((profile.effectivePort.toIntOrNull() ?: 0) !in 1..65535) return "Enter a WaterWall port between 1 and 65535."
    ChainConfig.applicationSecretError(profile.password, configuration)?.let { return it }
    ChainConfig.applicationUsernameError(profile.username, profile.password, configuration)?.let { return it }
    ChainConfig.outerSecretError(profile.outerSecret, configuration)?.let { return it }
    // The ClientHello is cut only below 16384 bytes, so a larger first chunk would send it whole
    if (profile.tlsFragMode == 2 && profile.tlsFragFirst >= 16384 && ChainConfig.allowsFragmentation(configuration)) {
        return "First Chunk must be smaller than 16384 bytes."
    }
    return null
}

private fun trimmedForSave(profile: Profile): Profile {
    // Pasted values often carry a trailing space or newline, and none of these fields can start or end with one
    if (profile.isOpenConnect) {
        // An address pasted whole, such as vpn.example.com/?secret, goes to Server, Port and Path
        val (server, port, path) = splitSslVpnAddress(profile.server)
        return profile.copy(server = server, port = port ?: profile.port.trim(), ocPath = path ?: profile.ocPath.trim())
    }
    if (profile.isTlsVpn) {
        return profile.copy(server = profile.server.trim(), port = profile.port.trim(), customSni = profile.customSni.trim(),
            proxyAddress = profile.proxyAddress.trim(), proxyPort = profile.proxyPort.trim(), hostnameOverride = profile.hostnameOverride.trim(),
            hubName = profile.hubName.trim(), seNatTHint = profile.seNatTHint.trim(), pacUrl = profile.pacUrl.trim())
    }
    val application = profile.configuration["application"]
    return profile.copy(
        server = profile.server.trim(),
        port = profile.port.trim(),
        customSni = profile.customSni.trim(),
        password = if (application == "vless" || application == "vmess") profile.password.trim() else profile.password,
    )
}

/** Server and Port from a wg-quick file's Endpoint line, once it looks like a WireGuard file. */
private fun importedWireGuard(text: String, profile: Profile): Profile? {
    if ("[Interface]" !in text || "[Peer]" !in text) return null
    var imported = profile.copy(wgConfig = text)
    val endpoint = text.lineSequence().map { it.trim() }.firstOrNull { it.lowercase().startsWith("endpoint") }
    val value = endpoint?.substringAfterLast('=')?.trim()
    val colon = value?.lastIndexOf(':') ?: -1
    if (value != null && colon >= 0) imported = imported.copy(server = value.substring(0, colon), port = value.substring(colon + 1))
    return imported
}

@Composable
private fun ProfileEditPage(
    draft: Profile,
    editing: Boolean,
    onChange: (Profile) -> Unit,
    push: (EditorPage) -> Unit,
    onClose: () -> Unit,
    onSave: (Profile) -> Unit,
) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val context = LocalContext.current
    val configuration = draft.configuration
    val wireGuard = ChainConfig.isWireGuard(configuration)
    val application = configuration["application"]
    val proxy = application == "socks5" || application == "http-proxy"
    val importFile = rememberLauncherForActivityResult(OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val text = runCatching {
            val bytes = context.contentResolver.openInputStream(uri)!!.use { it.readBytes() }
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        }.getOrNull()
        if (text.isNullOrEmpty()) {
            ui.showAlert("Import Failed", "The file could not be read as UTF-8 text.")
            return@rememberLauncherForActivityResult
        }
        val imported = importedWireGuard(text, draft)
        if (imported == null) ui.showAlert("Import Failed", "The file does not look like a WireGuard config (no [Interface]/[Peer] sections).")
        else onChange(imported)
    }

    Column(Modifier.fillMaxSize().background(colors.groupedBackground)) {
        NavBar(
            if (editing) "Edit Profile" else "Add Profile",
            left = { RoundBarButton(Glyph.Close, "Cancel", onClick = onClose) },
            right = {
                SaveButton {
                    val trimmed = trimmedForSave(draft)
                    onChange(trimmed)
                    val message = validationMessage(trimmed)
                    if (message != null) ui.showAlert(if (trimmed.isTlsVpn) "Profile Incomplete" else "Invalid WaterWall Configuration", message) else onSave(trimmed)
                }
            },
        )
        Column(Modifier.weight(1f).navigationBarsPadding().imePadding().verticalScroll(rememberScrollState())) {
            Section {
                row { ValueRow("Protocol", draft.nodeName) { push(EditorPage.Protocol) } }
                row { TextFieldRow("Description", draft.desc, "Optional", keyboardType = KeyboardType.Text) { onChange(draft.copy(desc = it)) } }
            }
            if (draft.isSstp) {
                SstpSections(draft, onChange, push)
                Spacer(Modifier.height(32.dp))
                return@Column
            }
            if (draft.isSoftEther) {
                SoftEtherSections(draft, onChange, push)
                Spacer(Modifier.height(32.dp))
                return@Column
            }
            if (draft.isOpenConnect) {
                SslVpnSections(draft, onChange, push)
                Spacer(Modifier.height(32.dp))
                return@Column
            }
            Section("SERVER", SERVER_FOOTER) {
                if (wireGuard) {
                    row { ValueRow("Configuration", ChainConfig.summary(configuration)) { push(EditorPage.WaterWall) } }
                    row { ValueRow("Import Config (.conf)", if (draft.wgConfig.isNotEmpty()) "Imported" else "None") { importFile.launch(arrayOf("*/*")) } }
                    row { ValueRow("Manual Configuration", if (draft.wgPrivateKey.isNotEmpty()) "Configured" else "None") { push(EditorPage.WireGuardManual) } }
                    row { TextFieldRow("Server", draft.server, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(server = it)) } }
                    row { TextFieldRow("Port", draft.port, "51820", keyboardType = KeyboardType.Number) { onChange(draft.copy(port = it)) } }
                } else {
                    row { ValueRow("Configuration", if (ChainConfig.isDirect(configuration)) "Direct (diagnostics)" else "Custom Chain") { push(EditorPage.WaterWall) } }
                    row { TextFieldRow("Server", draft.server, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(server = it)) } }
                    row { TextFieldRow("Port", draft.port, "443", keyboardType = KeyboardType.Number) { onChange(draft.copy(port = it)) } }
                    if (ChainConfig.usesTls(configuration)) {
                        row { TextFieldRow("SNI (optional)", draft.customSni, "Server hostname", keyboardType = KeyboardType.Uri) { onChange(draft.copy(customSni = it)) } }
                        row { SwitchRow("TLS Server Verification", !draft.allowInsecure) { onChange(draft.copy(allowInsecure = !it)) } }
                    }
                }
            }
            if (ChainConfig.needsApplicationSecret(configuration) || ChainConfig.needsOuterSecret(configuration)) {
                Section("AUTHENTICATION") {
                    if (ChainConfig.needsApplicationSecret(configuration)) {
                        if (proxy) row { TextFieldRow("Username", draft.username, "Optional") { onChange(draft.copy(username = it)) } }
                        val title = when {
                            application == "trojan" || proxy -> "Password"
                            application == "vmess" -> "UUID / ID"
                            else -> "UUID"
                        }
                        row { TextFieldRow(title, draft.password, if (proxy) "Optional" else "Required", secure = true) { onChange(draft.copy(password = it)) } }
                    }
                    if (ChainConfig.needsOuterSecret(configuration)) {
                        val title = if (configuration["packet-encryption"] == true) "Packet Password" else if (configuration["outer"] == "aead") "AEAD Password" else "Reality Password"
                        row { TextFieldRow(title, draft.outerSecret, "Required", secure = true) { onChange(draft.copy(outerSecret = it)) } }
                    }
                }
            }
            OptionsSection(draft, configuration, onChange)
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun OptionsSection(draft: Profile, configuration: Map<String, Any?>, onChange: (Profile) -> Unit) {
    val autoSwitch = !ChainConfig.isWireGuard(configuration) && !ChainConfig.isDirect(configuration)
    val fragmentation = ChainConfig.allowsFragmentation(configuration)
    val routing = ChainConfig.allowsRouting(configuration)
    val footer = buildString {
        append("Auto Reconnect restarts WaterWall 2 seconds after the connection fails; Retry Times limits the consecutive attempts (empty = unlimited) before the VPN disconnects with an error.")
        if (autoSwitch) append(" Auto Switch uses the other WaterWall profiles of the same server: each reconnect tries the next one, and when the network loses too many packets the connection moves to a profile with the other carrier (TCP or UDP); when Switch to Wi-Fi When Available moves the connection to a new network, it returns to this profile.")
        append(" Switch to Wi-Fi When Available moves the connection to Wi-Fi as soon as it appears, and back to cellular when Wi-Fi is lost. On Sleep: Off closes the connection while the device sleeps; on wake it reconnects with Auto Reconnect, otherwise the VPN disconnects. Pause closes it and always reconnects on wake; Stay keeps it open.")
        if (fragmentation) append(" TLS Fragmentation splits the outer TLS ClientHello into smaller writes.")
        if (routing) append(" Remote DNS answers lookups with placeholder addresses so the server resolves the real names; Direct LAN Routing connects private addresses (10/8, 172.16/12, 192.168/16) directly instead of through the server.")
    }
    Section("OPTIONS", footer) {
        row { SwitchRow("Auto Reconnect", draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) } }
        if (draft.autoReconnect) {
            row { NumberRow("Retry Times", draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) } }
        }
        if (autoSwitch) row { SwitchRow("Auto Switch", draft.autoSwitch) { onChange(draft.copy(autoSwitch = it)) } }
        row { SwitchRow("Switch to Wi-Fi When Available", draft.switchToWifi) { onChange(draft.copy(switchToWifi = it)) } }
        row { SegmentRow("On Sleep", listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) } }
        row { SegmentRow("Log Level", listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) } }
        if (fragmentation) {
            row { SegmentRow("TLS Fragmentation", listOf("Off", "Auto", "Manual"), draft.tlsFragMode) { onChange(draft.copy(tlsFragMode = it)) } }
            if (draft.tlsFragMode == 2) {
                row { NumberRow("First Chunk (bytes)", draft.tlsFragFirst, "32") { onChange(draft.copy(tlsFragFirst = it)) } }
                row { NumberRow("Following Chunks (bytes)", draft.tlsFragFollowing, "256") { onChange(draft.copy(tlsFragFollowing = it)) } }
            }
        }
        if (routing) {
            row { SwitchRow("Remote DNS (Fake IP)", draft.fakeDns) { onChange(draft.copy(fakeDns = it)) } }
            row { SwitchRow("Direct LAN Routing", draft.smartRouting) { onChange(draft.copy(smartRouting = it)) } }
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

/** The Protocol screen: the protocols of the Android app so far, named and described as on iOS. */
@Composable
private fun ProtocolPage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    fun choose(type: String) {
        if (type != draft.protocolType) {
            // Each protocol keeps its own WireGuard keys and settings; a profile moved to another protocol starts without them.
            onChange(draft.copy(protocolType = type, wgConfig = "", wgPrivateKey = "", wgPeerPublicKey = "", wgPresharedKey = "", wgAddress = "",
                wgDns = "", wgAllowedIps = "", wgKeepalive = 0, port = if (type == "waterwall") "443" else draft.port))
        }
        onBack()
    }
    Column(Modifier.fillMaxSize().background(LocalIosColors.current.groupedBackground)) {
        NavBar("Protocol", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Section {
            row { CheckRow("WaterWall VPN", "VLESS, VMess, Trojan, BGP4 and packet tunnels", checked = draft.protocolType == "waterwall") { choose("waterwall") } }
            row { CheckRow("SSTP VPN", "Microsoft SSTP over TLS", checked = draft.isSstp) { choose("sstp") } }
            row { CheckRow("SoftEther VPN", "SoftEther over TLS", checked = draft.isSoftEther) { choose("softether") } }
            row { CheckRow("SSL VPN", "AnyConnect, F5 BIG-IP, Palo Alto GlobalProtect", checked = draft.isOpenConnect) { choose("openconnect") } }
        }
    }
}

@Composable
private fun WireGuardManualPage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val context = LocalContext.current
    val publicKey = remember(draft.wgPrivateKey) { if (draft.wgPrivateKey.isNotEmpty()) WireGuardKeys.publicKey(draft.wgPrivateKey) else null }
    Column(Modifier.fillMaxSize().background(colors.groupedBackground)) {
        NavBar("Manual Configuration", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Column(Modifier.weight(1f).navigationBarsPadding().imePadding().verticalScroll(rememberScrollState())) {
            Section("THIS DEVICE") {
                row {
                    TextFieldRow("Private Key", draft.wgPrivateKey, "Required", trailing = {
                        Label(
                            "Gen",
                            IosText.caption.copy(fontWeight = FontWeight.SemiBold),
                            colors.blue,
                            Modifier.clickable(onClickLabel = "Generate a key pair") { onChange(draft.copy(wgPrivateKey = WireGuardKeys.generatePrivateKey())) }.padding(6.dp),
                        )
                    }) { onChange(draft.copy(wgPrivateKey = it)) }
                }
                row {
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 52.dp)
                            .clickable(enabled = publicKey != null) {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("WireGuard public key", publicKey))
                                ui.showAlert("Public Key Copied", "Register this key as a peer on the WireGuard server.")
                            }
                            .padding(horizontal = 16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Label("Public Key")
                        Spacer(Modifier.width(12.dp))
                        Box(Modifier.weight(1f), contentAlignment = Alignment.CenterEnd) {
                            androidx.compose.foundation.text.BasicText(
                                publicKey ?: "—",
                                style = IosText.caption.copy(fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = colors.secondaryLabel),
                                maxLines = 1,
                                overflow = TextOverflow.MiddleEllipsis,
                            )
                        }
                    }
                }
                row { TextFieldRow("Address", draft.wgAddress, "e.g. 10.88.0.2/24") { onChange(draft.copy(wgAddress = it)) } }
                row { TextFieldRow("DNS", draft.wgDns, "Optional — e.g. 1.1.1.1") { onChange(draft.copy(wgDns = it)) } }
            }
            Section("SERVER (PEER)", "The endpoint (host:port) comes from the Server and Port fields of the profile. AllowedIPs 0.0.0.0/0 routes everything through the tunnel.") {
                row { TextFieldRow("Server Public Key", draft.wgPeerPublicKey, "Required") { onChange(draft.copy(wgPeerPublicKey = it)) } }
                row { TextFieldRow("Preshared Key", draft.wgPresharedKey, "Optional") { onChange(draft.copy(wgPresharedKey = it)) } }
                row { TextFieldRow("AllowedIPs", draft.wgAllowedIps, "Default: 0.0.0.0/0") { onChange(draft.copy(wgAllowedIps = it)) } }
                row { NumberRow("Keepalive", draft.wgKeepalive, "Optional — seconds") { onChange(draft.copy(wgKeepalive = it)) } }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}
