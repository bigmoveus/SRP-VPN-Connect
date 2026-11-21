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

private const val WATERWALL_FOOTER = "The profile is a chain of WaterWall nodes that starts with an input hint. Open it to read the chain from top to bottom, edit a node, or import a WaterWall JSON file. The node settings hold the server, its credentials and every other setting of the chain."

/** The screens of the editor, which open one over the other as in the iOS navigation stack. */
sealed interface EditorPage {
    data object Main : EditorPage

    data object Protocol : EditorPage

    data object WireGuardManual : EditorPage

    /** The WaterWall chain */
    data object WaterWall : EditorPage

    /** Edit Node for [name], or Insert Node after [after] */
    data class WaterWallNode(val name: String?, val after: String?) : EditorPage

    data object WaterWallImport : EditorPage

    data object SstpMethod : EditorPage

    data object SstpCertificate : EditorPage

    data object SstpEap : EditorPage

    data object SstpTtls : EditorPage

    data object SoftEtherMethod : EditorPage

    data object SslVpnServerType : EditorPage

    data object AetherTransport : EditorPage
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
                EditorPage.WaterWall -> WaterWallChainPage(draft, { draft = it }, push, pop)
                is EditorPage.WaterWallNode -> WaterWallNodePage(draft, page.name, page.after, { draft = it }, pop)
                EditorPage.WaterWallImport -> WaterWallImportPage(draft, { draft = it }, pop)
                EditorPage.SstpMethod -> SstpMethodPage(draft, { draft = it }, pop)
                EditorPage.SstpCertificate -> SstpCertificatePage(draft, { draft = it }, pop)
                EditorPage.SstpEap -> SstpEapPage(draft, { draft = it }, push, pop)
                EditorPage.SstpTtls -> SstpTtlsPage(draft, { draft = it }, pop)
                EditorPage.SoftEtherMethod -> SoftEtherMethodPage(draft, { draft = it }, pop)
                EditorPage.SslVpnServerType -> SslVpnServerTypePage(draft, { draft = it }, pop)
                EditorPage.AetherTransport -> AetherTransportPage(draft, { draft = it }, pop)
            }
        }
    }
}

/** The first problem of a profile about to be saved, in the iOS app's words. */
fun validationMessage(profile: Profile): String? {
    if (profile.isSstp) return sstpValidationMessage(profile)
    if (profile.isSoftEther) return softEtherValidationMessage(profile)
    if (profile.isOpenConnect) return sslVpnValidationMessage(profile)
    if (profile.isSsh) return sshValidationMessage(profile)
    if (profile.isOpenVpn) return openVpnValidationMessage(profile)
    if (profile.isWireGuard) return wireGuardValidationMessage(profile)
    // Aether needs nothing entered: it connects to Cloudflare WARP by itself
    if (profile.isAether) return null
    // WaterWall: the chain's own checks, as on import
    return NodeChain.validationError(documentOf(profile))
}

private fun trimmedForSave(profile: Profile): Profile {
    // Pasted values often carry a trailing space or newline, and none of these fields can start or end with one
    if (profile.isOpenConnect) {
        // An address pasted whole, such as vpn.example.com/?secret, goes to Server, Port and Path
        val (server, port, path) = splitSslVpnAddress(profile.server)
        return profile.copy(server = server, port = port ?: profile.port.trim(), ocPath = path ?: profile.ocPath.trim())
    }
    if (profile.isOpenVpn) {
        // The password stays as typed: it may begin or end with a space
        return profile.copy(server = profile.server.trim(), port = profile.port.trim(), username = profile.username.trim(),
            ovpnStunnelHost = profile.ovpnStunnelHost.trim(), ovpnStunnelPort = profile.ovpnStunnelPort.trim(),
            ovpnStunnelSni = profile.ovpnStunnelSni.trim())
    }
    if (profile.isWireGuard) {
        // Keys, addresses, the endpoint and AmneziaWG's numbers and ranges cannot start or end with a space (the I1-I5 chains stay as typed)
        return profile.copy(server = profile.server.trim(), port = profile.port.trim(), wgPrivateKey = profile.wgPrivateKey.trim(),
            wgPeerPublicKey = profile.wgPeerPublicKey.trim(), wgPresharedKey = profile.wgPresharedKey.trim(), wgAddress = profile.wgAddress.trim(),
            wgDns = profile.wgDns.trim(), wgAllowedIps = profile.wgAllowedIps.trim(), wgH1 = profile.wgH1.trim(), wgH2 = profile.wgH2.trim(),
            wgH3 = profile.wgH3.trim(), wgH4 = profile.wgH4.trim(), wgHeaderProtectionKey = profile.wgHeaderProtectionKey.trim(),
            wgContentPaddingAddition = profile.wgContentPaddingAddition.trim(), wgRekeyAfterTime = profile.wgRekeyAfterTime.trim(),
            wgRekeyTimeout = profile.wgRekeyTimeout.trim(), wgRejectAfterTime = profile.wgRejectAfterTime.trim(),
            wgKeepaliveTimeout = profile.wgKeepaliveTimeout.trim(), wgMaxHandshakeAttempts = profile.wgMaxHandshakeAttempts.trim())
    }
    if (profile.isSsh) {
        // The password stays as typed: an SSH password may begin or end with a space
        return profile.copy(server = profile.server.trim(), port = profile.port.trim(), username = profile.username.trim(),
            sshHostKey = profile.sshHostKey.trim())
    }
    if (profile.isTlsVpn) {
        return profile.copy(server = profile.server.trim(), port = profile.port.trim(), customSni = profile.customSni.trim(),
            proxyAddress = profile.proxyAddress.trim(), proxyPort = profile.proxyPort.trim(), hostnameOverride = profile.hostnameOverride.trim(),
            hubName = profile.hubName.trim(), seNatTHint = profile.seNatTHint.trim(), pacUrl = profile.pacUrl.trim())
    }
    // WaterWall's server, port and credentials are node settings, which the node editor checks as JSON
    if (profile.isWaterWall) return profile
    return profile.copy(server = profile.server.trim(), port = profile.port.trim(), customSni = profile.customSni.trim())
}

/** Server and Port from a wg-quick file's Endpoint line, once it looks like a WireGuard file. */
internal fun importedWireGuard(text: String, profile: Profile): Profile? {
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
        val amneziaSetting = amneziaSettingIn(text)
        if (imported == null) ui.showAlert("Import Failed", "The file does not look like a WireGuard config (no [Interface]/[Peer] sections).")
        // WireGuard takes none of AmneziaWG's settings: such a file needs an AmneziaWG profile
        else if (draft.isPlainWireGuard && amneziaSetting != null) {
            ui.showAlert("AmneziaWG Configuration", "This file has AmneziaWG settings ($amneziaSetting and others). Choose AmneziaWG VPN as the protocol to use it.")
        }
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
                    if (message != null) ui.showAlert(if (trimmed.isTlsVpn || trimmed.isOpenVpn || trimmed.isWireGuard) "Profile Incomplete" else "Invalid WaterWall Configuration", message) else onSave(trimmed)
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
            if (draft.isSsh) {
                SshSections(draft, onChange)
                Spacer(Modifier.height(32.dp))
                return@Column
            }
            if (draft.isOpenVpn) {
                OpenVpnSections(draft, onChange)
                Spacer(Modifier.height(32.dp))
                return@Column
            }
            if (draft.isAether) {
                AetherSections(draft, onChange, push)
                Spacer(Modifier.height(32.dp))
                return@Column
            }
            if (draft.isWireGuard) {
                Section("SERVER", if (draft.isAmnezia) AMNEZIAWG_SERVER_FOOTER else WIREGUARD_SERVER_FOOTER) {
                    row { ValueRow("Import Config (.conf)", if (draft.wgConfig.isNotEmpty()) "Imported" else "None") { importFile.launch(arrayOf("*/*")) } }
                    row { ValueRow("Manual Configuration", wireGuardConfigState(draft)) { push(EditorPage.WireGuardManual) } }
                    row { TextFieldRow("Server", draft.server, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(server = it)) } }
                    row { TextFieldRow("Port", draft.port, "51820", keyboardType = KeyboardType.Number) { onChange(draft.copy(port = it)) } }
                }
                WireGuardOptionsSection(draft, onChange)
                Spacer(Modifier.height(32.dp))
                return@Column
            }
            val document = documentOf(draft)
            Section("SERVER", WATERWALL_FOOTER) {
                row { ValueRow("WaterWall", NodeChain.summary(document)) { push(EditorPage.WaterWall) } }
            }
            WaterWallOptionsSection(draft, document, onChange)
            Spacer(Modifier.height(32.dp))
        }
    }
}

internal const val REMOTE_DNS_OFF_WARNING = "WaterWall will no longer receive site names: apps look each name up with a DNS server through the tunnel and connect to an IP address. Domain routing and DNS routing in the chain stop working, even when they are enabled. Only a Router with sniffing still reads the name, from the traffic itself."

/** The WaterWall rows of OPTIONS: Auto Switch needs a chain with a server of its own, Remote DNS a chain that takes connections */
internal fun waterWallOptionTitles(profile: Profile, document: Map<String, Any?>): List<String> = buildList {
    add("Auto Reconnect")
    if (profile.autoReconnect) add("Retry Times")
    if (NodeChain.endpoints(document).isNotEmpty()) add("Auto Switch")
    addAll(listOf("Switch to Wi-Fi When Available", "On Sleep", "Log Level"))
    if (NodeChain.hint(document)?.get("type") == NodeChain.HINT_CONNECTION) add("Remote DNS (Fake IP)")
}

internal fun waterWallOptionsFooter(document: Map<String, Any?>) = buildString {
    append("Auto Reconnect restarts WaterWall 2 seconds after the connection fails; Retry Times limits the consecutive attempts (empty = unlimited) before the VPN disconnects with an error.")
    if (NodeChain.endpoints(document).isNotEmpty()) {
        append(" Auto Switch uses the other WaterWall profiles of the same server: each reconnect tries the next one, and when the network loses too many packets the connection moves to a profile that reaches the server the other way (TCP or UDP).")
    }
    append(" Switch to Wi-Fi When Available moves the connection to Wi-Fi as soon as it appears, and back to cellular when Wi-Fi is lost. On Sleep: Off closes the connection while the device sleeps, Pause closes it and connects again at wake, Stay keeps it.")
    if (NodeChain.hint(document)?.get("type") == NodeChain.HINT_CONNECTION) {
        append(" With System VPN (TUN) as the WaterWall input in Settings, Remote DNS answers lookups with placeholder addresses, so each connection carries the name to the chain and the server resolves it.")
    }
}

@Composable
private fun WaterWallOptionsSection(draft: Profile, document: Map<String, Any?>, onChange: (Profile) -> Unit) {
    val ui = LocalUi.current
    Section("OPTIONS", waterWallOptionsFooter(document)) {
        for (title in waterWallOptionTitles(draft, document)) {
            row {
                when (title) {
                    "Auto Reconnect" -> SwitchRow(title, draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) }
                    "Retry Times" -> NumberRow(title, draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) }
                    "Auto Switch" -> SwitchRow(title, draft.autoSwitch) { onChange(draft.copy(autoSwitch = it)) }
                    "Switch to Wi-Fi When Available" -> SwitchRow(title, draft.switchToWifi) { onChange(draft.copy(switchToWifi = it)) }
                    "On Sleep" -> SegmentRow(title, listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) }
                    "Log Level" -> SegmentRow(title, listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) }
                    // Remote DNS stays on until the user accepts what turning it off costs
                    else -> SwitchRow(title, draft.fakeDns) { on ->
                        if (on) onChange(draft.copy(fakeDns = true))
                        else ui.choice = UiHost.Choice("Turn Off Remote DNS?", REMOTE_DNS_OFF_WARNING, listOf("Turn Off", "Cancel"), setOf(0)) { index ->
                            if (index == 0) onChange(draft.copy(fakeDns = false))
                        }
                    }
                }
            }
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
            val chosen = draft.copy(protocolType = type, wgConfig = "", wgPrivateKey = "", wgPeerPublicKey = "", wgPresharedKey = "", wgAddress = "",
                wgDns = "", wgAllowedIps = "", wgKeepalive = 0, wgJc = 0, wgJmin = 0, wgJmax = 0, wgS1 = 0, wgS2 = 0, wgS3 = 0, wgS4 = 0,
                wgH1 = "", wgH2 = "", wgH3 = "", wgH4 = "", wgI1 = "", wgI2 = "", wgI3 = "", wgI4 = "", wgI5 = "", wgHeaderProtectionKey = "",
                wgContentPaddingAddition = "", wgRekeyAfterTime = "", wgRekeyTimeout = "", wgRejectAfterTime = "", wgKeepaliveTimeout = "",
                wgMaxHandshakeAttempts = "", wgRandomTrailers = false, wgDisableCookies = false,
                port = if (type == "ssh") "22" else if (type == "openvpn") "1194"
                       else if (type == "wireguard" || type == "amnezia") "51820" else if (type == "aether") "" else draft.port,
                // A new Aether profile as the iOS editor makes it (SRPProtocolViewController applyProtocol)
                aetherTransport = "masque-both", aetherScan = "balanced", aetherTor = "off")
            // WaterWall starts with the input hint alone, until a file is imported or nodes are inserted
            onChange(if (type == "waterwall") chosen.copy(configJson = "", chainJson = NodeChain.emptyJson).withWaterWallServer() else chosen)
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
            row { CheckRow("SSH VPN", "SSH tunnel with optional UDP relay", checked = draft.isSsh) { choose("ssh") } }
            row { CheckRow("OpenVPN", "OpenVPN 3 — UDP/TCP, optional stunnel (TLS 1.3)", checked = draft.isOpenVpn) { choose("openvpn") } }
            row { CheckRow("WireGuard VPN", "WireGuard — fast modern UDP", checked = draft.isPlainWireGuard) { choose("wireguard") } }
            row { CheckRow("AmneziaWG VPN", "AmneziaWG — obfuscated for strict firewalls", checked = draft.isAmnezia) { choose("amnezia") } }
            row { CheckRow("Aether VPN", "Cloudflare WARP — no server needed, automatic", checked = draft.isAether) { choose("aether") } }
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
            if (draft.isAmnezia) {
                Section("AMNEZIAWG: SAME AS THE SERVER", AMNEZIAWG_MATCH_FOOTER) {
                    row { NumberRow("S1", draft.wgS1, "Init padding") { onChange(draft.copy(wgS1 = it)) } }
                    row { NumberRow("S2", draft.wgS2, "Response padding") { onChange(draft.copy(wgS2 = it)) } }
                    row { NumberRow("S3", draft.wgS3, "Cookie padding") { onChange(draft.copy(wgS3 = it)) } }
                    row { NumberRow("S4", draft.wgS4, "Data padding") { onChange(draft.copy(wgS4 = it)) } }
                    row { TextFieldRow("H1", draft.wgH1, "Init header") { onChange(draft.copy(wgH1 = it)) } }
                    row { TextFieldRow("H2", draft.wgH2, "Response header") { onChange(draft.copy(wgH2 = it)) } }
                    row { TextFieldRow("H3", draft.wgH3, "Cookie header") { onChange(draft.copy(wgH3 = it)) } }
                    row { TextFieldRow("H4", draft.wgH4, "Data header") { onChange(draft.copy(wgH4 = it)) } }
                    row { TextFieldRow("Header Protection Key", draft.wgHeaderProtectionKey, "Optional") { onChange(draft.copy(wgHeaderProtectionKey = it)) } }
                    row { SwitchRow("Random Trailers", draft.wgRandomTrailers) { onChange(draft.copy(wgRandomTrailers = it)) } }
                }
                Section("AMNEZIAWG: THIS DEVICE ONLY", AMNEZIAWG_DEVICE_FOOTER) {
                    row { NumberRow("Jc", draft.wgJc, "Junk packet count") { onChange(draft.copy(wgJc = it)) } }
                    row { NumberRow("Jmin", draft.wgJmin, "Junk packet min size") { onChange(draft.copy(wgJmin = it)) } }
                    row { NumberRow("Jmax", draft.wgJmax, "Junk packet max size") { onChange(draft.copy(wgJmax = it)) } }
                    row { TextFieldRow("I1", draft.wgI1, "Optional signature chain") { onChange(draft.copy(wgI1 = it)) } }
                    row { TextFieldRow("I2", draft.wgI2, "Optional") { onChange(draft.copy(wgI2 = it)) } }
                    row { TextFieldRow("I3", draft.wgI3, "Optional") { onChange(draft.copy(wgI3 = it)) } }
                    row { TextFieldRow("I4", draft.wgI4, "Optional") { onChange(draft.copy(wgI4 = it)) } }
                    row { TextFieldRow("I5", draft.wgI5, "Optional") { onChange(draft.copy(wgI5 = it)) } }
                    row { TextFieldRow("Content Padding", draft.wgContentPaddingAddition, "Optional — bytes") { onChange(draft.copy(wgContentPaddingAddition = it)) } }
                    row { TextFieldRow("Rekey After Time", draft.wgRekeyAfterTime, "Default 120") { onChange(draft.copy(wgRekeyAfterTime = it)) } }
                    row { TextFieldRow("Rekey Timeout", draft.wgRekeyTimeout, "Default 5") { onChange(draft.copy(wgRekeyTimeout = it)) } }
                    row { TextFieldRow("Reject After Time", draft.wgRejectAfterTime, "Default 180") { onChange(draft.copy(wgRejectAfterTime = it)) } }
                    row { TextFieldRow("Keepalive Timeout", draft.wgKeepaliveTimeout, "Default 10") { onChange(draft.copy(wgKeepaliveTimeout = it)) } }
                    row { TextFieldRow("Max Handshake Attempts", draft.wgMaxHandshakeAttempts, "Default 18") { onChange(draft.copy(wgMaxHandshakeAttempts = it)) } }
                    row { SwitchRow("Disable Cookies", draft.wgDisableCookies) { onChange(draft.copy(wgDisableCookies = it)) } }
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}
