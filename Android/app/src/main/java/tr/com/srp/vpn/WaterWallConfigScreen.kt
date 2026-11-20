package tr.com.srp.vpn

import android.content.Context
import android.provider.OpenableColumns
import android.text.format.Formatter
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.OffsetMapping
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.TransformedText
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

// The WaterWall screens of SRPWaterWallConfigViewController.m: the profile's chain of nodes from the input hint along each next, Edit
// Node and Insert Node, Import JSON, and the app's Settings with WaterWall Input and the GeoIP database. Changes go to the profile
// being edited; its Save keeps them.

/** The profile's document as the editor has it: a new profile's lacks nodes yet, so it is read, not checked */
@Suppress("UNCHECKED_CAST")
internal fun documentOf(profile: Profile): Map<String, Any?> = Json.parseOrNull(profile.chainJson) as? Map<String, Any?> ?: NodeChain.emptyDocument()

/** A checked document kept in the profile being edited; the profile's Save puts it in the secret store */
private fun kept(profile: Profile, document: Map<String, Any?>, context: Context): Profile {
    // A Router that routes by country needs the database before the tunnel starts
    if (NodeChain.usesGeoIp(document)) runCatching { GeoIpDatabase(context.applicationContext).installBundledIfNeeded() }
    // A chain saved over a profile that could not be converted replaces its former settings
    return profile.copy(chainJson = NodeChain.json(document), configJson = "").withWaterWallServer()
}

internal fun chainFooter(document: Map<String, Any?>): String {
    val all = (document["nodes"] as? List<*>)?.size ?: 0
    val others = all - NodeChain.chain(document).size
    if (others <= 0) return "Order follows each node's next field."
    val one = others == 1
    return "Order follows each node's next field. The profile has $others more ${if (one) "node" else "nodes"} off the chain, such as a Router's targets, " +
        "which ${if (one) "is" else "are"} kept as ${if (one) "it is" else "they are"}."
}

/** The large title the WaterWall screens show under the navigation bar */
@Composable
private fun LargeTitle(text: String) {
    Label(text, TextStyle(fontSize = 34.sp, lineHeight = 41.sp, fontWeight = FontWeight.Bold), modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 4.dp).semantics { heading() })
}

/** A row that acts, like a table cell in the tint color: Edit node, Import JSON… */
@Composable
private fun ActionRow(glyph: Glyph?, title: String, color: Color, detail: String? = null, enabled: Boolean = true, onClick: () -> Unit) {
    val colors = LocalIosColors.current
    PressableRow(if (enabled) onClick else null) {
        if (glyph != null) {
            GlyphIcon(glyph, color, 20.dp)
            Spacer(Modifier.width(14.dp))
        }
        Label(title, color = if (enabled) color else colors.secondaryLabel, modifier = Modifier.weight(1f), maxLines = 2)
        if (detail != null) Label(detail, color = colors.secondaryLabel, maxLines = 1)
    }
}

/** A title with its detail below, like a subtitle cell */
@Composable
private fun DetailRow(title: String, detail: String, style: TextStyle = IosText.headline, color: Color = LocalIosColors.current.label,
                      detailColor: Color = LocalIosColors.current.secondaryLabel) {
    PressableRow(null) {
        Column(Modifier.weight(1f).padding(vertical = 4.dp)) {
            Label(title, style, color)
            Label(detail, IosText.subheadline, detailColor)
        }
    }
}

@Composable
private fun NextRow(title: String, next: String) {
    PressableRow(null) {
        Label(title, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(8.dp))
        Label(next, IosText.body.copy(fontFamily = FontFamily.Monospace), maxLines = 2)
    }
}

/** The screen titled WaterWall behind the profile's WaterWall row: one row per node from the hint along next, the last marked End */
@Composable
fun WaterWallChainPage(draft: Profile, onChange: (Profile) -> Unit, push: (EditorPage) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val context = LocalContext.current
    val document = documentOf(draft)
    val chain = NodeChain.chain(document)
    // The node whose next and actions show
    var expanded by rememberSaveable { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().background(colors.groupedBackground)) {
        NavBar("", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) },
            right = { RoundBarButton(Glyph.ImportDoc, "Import JSON") { push(EditorPage.WaterWallImport) } })
        Column(Modifier.weight(1f).navigationBarsPadding().verticalScroll(rememberScrollState())) {
            LargeTitle("WaterWall")
            Section("NODE CHAIN", chainFooter(document)) {
                chain.forEachIndexed { index, node ->
                    val name = node["name"] as? String ?: ""
                    val open = node["name"] == expanded
                    row { NodeRow(index + 1, node, index == chain.lastIndex, open) { expanded = if (open) null else name } }
                    if (!open) return@forEachIndexed
                    (node["next"] as? String)?.let { next -> row { NextRow("next", next) } }
                    row { ActionRow(Glyph.Pencil, "Edit node", colors.blue) { push(EditorPage.WaterWallNode(name, null)) } }
                    row { ActionRow(Glyph.Plus, "Insert node after", colors.blue) { push(EditorPage.WaterWallNode(null, name)) } }
                    if (!NodeChain.isHint(node["type"])) {
                        row {
                            ActionRow(Glyph.Trash, "Delete node", colors.red) {
                                val changed = NodeChain.deletingNode(document, name)
                                val problem = NodeChain.validationError(changed)
                                if (problem != null) {
                                    ui.showAlert("Node Not Deleted", problem)
                                } else {
                                    onChange(kept(draft, changed, context))
                                    expanded = null
                                }
                            }
                        }
                    }
                }
            }
            Section { row { ActionRow(Glyph.Doc, "Import JSON…", colors.blue) { push(EditorPage.WaterWallImport) } } }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun NodeRow(number: Int, node: Map<String, Any?>, end: Boolean, expanded: Boolean, onToggle: () -> Unit) {
    val colors = LocalIosColors.current
    val type = node["type"] as? String ?: ""
    val name = node["name"] as? String ?: ""
    val hint = if (expanded) "Hides the node's actions" else "Shows the node's next and actions"
    PressableRow(onToggle, Modifier.clearAndSetSemantics {
        contentDescription = "$number, $type, $name${if (end) ", End" else ""}"
        onClick(hint) {
            onToggle()
            true
        }
    }) {
        Box(Modifier.size(28.dp).border(1.5.dp, colors.secondaryLabel, CircleShape), contentAlignment = Alignment.Center) {
            Label("$number", IosText.subheadline.copy(fontWeight = FontWeight.SemiBold), colors.secondaryLabel)
        }
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f).padding(vertical = 4.dp)) {
            Label(type, IosText.headline, maxLines = 2)
            Label(name, IosText.subheadline, colors.secondaryLabel, maxLines = 2)
        }
        if (end) {
            Spacer(Modifier.width(8.dp))
            Label("End", color = colors.secondaryLabel)
        }
        Spacer(Modifier.width(12.dp))
        GlyphIcon(Glyph.Chevron, colors.tertiaryLabel, 13.dp, Modifier.rotate(if (expanded) 90f else 0f))
    }
}

@Composable
private fun NodeFieldRow(title: String, value: String, placeholder: String, onChange: (String) -> Unit) {
    PressableRow(null) {
        Label(title, modifier = Modifier.width(72.dp))
        Spacer(Modifier.width(16.dp))
        InlineField(value, placeholder, false, KeyboardType.Ascii, true, TextAlign.Start, Modifier.weight(1f), title, null, onChange)
    }
}

/** Edit Node, or Insert Node after [after] when [name] is null: Name, Type, Next when there is one, and the settings as JSON */
@Composable
fun WaterWallNodePage(draft: Profile, name: String?, after: String?, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val context = LocalContext.current
    val node = remember {
        @Suppress("UNCHECKED_CAST")
        val found = (documentOf(draft)["nodes"] as? List<*>).orEmpty().filterIsInstance<Map<String, Any?>>().lastOrNull { it["name"] == (name ?: after) }
        // The new node takes over the successor of the one it follows
        if (name != null) found ?: mapOf("name" to name, "type" to "")
        else linkedMapOf<String, Any?>("name" to "", "type" to "").apply { found?.get("next")?.let { put("next", it) } }
    }
    val hint = NodeChain.isHint(node["type"])
    var nameText by rememberSaveable { mutableStateOf(node["name"] as? String ?: "") }
    var typeText by rememberSaveable { mutableStateOf(node["type"] as? String ?: "") }
    var settings by rememberSaveable(stateSaver = TextFieldValue.Saver) { mutableStateOf(TextFieldValue(nodeSettingsText(node["settings"] as? Map<*, *> ?: emptyMap<String, Any?>()))) }
    val parsed = remember(settings.text) { parseNodeSettings(settings.text) }
    val dark = isSystemInDarkTheme()
    val highlight = remember(dark) {
        if (dark) JsonHighlight(Color(0xFFFF7366), Color(0xFF73BFFF)) else JsonHighlight(Color(0xFFC41A17), Color(0xFF1C00CF))
    }
    val focus = LocalFocusManager.current

    fun save() {
        focus.clearFocus()
        val changed = LinkedHashMap(node)
        changed["name"] = nameText.trim()
        changed["type"] = typeText.trim()
        if (!hint) {
            val values = parsed.settings
            if (values == null) {
                ui.showAlert("Invalid Node Settings", parsed.error)
                return
            }
            // A node the file wrote without settings keeps it so when none were added
            if (values.isEmpty() && node["settings"] == null) changed.remove("settings") else changed["settings"] = values
        }
        val document = documentOf(draft)
        val edited = if (name != null) NodeChain.replacingNode(document, name, changed) else NodeChain.insertingNode(document, changed, after ?: "")
        val problem = NodeChain.validationError(edited)
        if (problem != null) {
            ui.showAlert("Invalid Node", problem)
            return
        }
        onChange(kept(draft, edited, context))
        onBack()
    }

    Column(Modifier.fillMaxSize().background(colors.groupedBackground)) {
        NavBar(if (name != null) "Edit Node" else "Insert Node", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) }, right = { SaveButton { save() } })
        Column(Modifier.weight(1f).navigationBarsPadding().imePadding().verticalScroll(rememberScrollState())) {
            LargeTitle(typeText.ifEmpty { "New Node" })
            val next = node["next"] as? String
            val footer = when {
                hint -> "An input hint has no settings: SRP puts the input chosen in Settings → WaterWall Input in its place when it connects. Its type says what the chain takes: HintConnectionIN connections, HintPacketIN IP packets."
                name == null && next != null -> "The new node goes between \"$after\" and \"$next\"."
                name == null -> "The new node goes after \"$after\" and ends the chain."
                else -> null
            }
            Section("NODE", footer) {
                row { NodeFieldRow("Name", nameText, "Required") { nameText = it } }
                row { NodeFieldRow("Type", typeText, "Required, such as TlsClient") { typeText = it } }
                if (next != null) row { NextRow("Next", next) }
            }
            if (!hint) {
                Section("SETTINGS") {
                    row {
                        BasicTextField(
                            value = settings,
                            onValueChange = { settings = withIndentedNewline(settings, it) },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 220.dp).editedField().semantics { contentDescription = "Settings" }
                                .padding(horizontal = 16.dp, vertical = 10.dp),
                            textStyle = IosText.body.copy(fontSize = 15.sp, fontFamily = FontFamily.Monospace, color = colors.label),
                            cursorBrush = SolidColor(colors.blue),
                            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii),
                            visualTransformation = highlight,
                        )
                    }
                }
                Label(parsed.error ?: "Valid JSON", IosText.footnote.copy(fontSize = 14.sp, lineHeight = 19.sp), if (parsed.error != null) colors.red else colors.secondaryLabel,
                    Modifier.padding(start = 16.dp, end = 16.dp, top = 8.dp))
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

/** What a chosen file holds: the checked document, or null and why nothing of it can be imported */
internal fun importedDocument(bytes: ByteArray?): Pair<Map<String, Any?>?, String?> {
    if (bytes != null && bytes.size > MAXIMUM_IMPORT_BYTES) return null to "The file is larger than 1 MB."
    if (bytes == null) return null to "The file could not be read."
    val text = runCatching {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    }.getOrNull() ?: return null to "The file is not UTF-8 text."
    return NodeChain.documentWithJson(text)
}

internal fun importFooter(document: Map<String, Any?>) =
    "${NodeChain.summary(document)}: ${NodeChain.chain(document).size} nodes on the chain. Import replaces the profile's chain."

private const val MAXIMUM_IMPORT_BYTES = 1048576

/** Up to one byte more than an import may have, so that a larger file shows as one */
private fun readForImport(input: InputStream): ByteArray {
    val buffer = ByteArray(MAXIMUM_IMPORT_BYTES + 1)
    var length = 0
    while (length < buffer.size) {
        val count = input.read(buffer, length, buffer.size - length)
        if (count < 0) break
        length += count
    }
    return buffer.copyOf(length)
}

private val ImportRules = listOf(
    "Input hint" to "Start with HintConnectionIN or HintPacketIN.",
    "App-managed input" to "Leave TunDevice and PacketsToConnection out of the file.",
    "Raw sockets" to "Raw socket nodes cannot be imported.",
)

/** Import JSON: a plain WaterWall .json file replaces the profile's chain, or shows why it is blocked and leaves the profile as it is */
@Composable
fun WaterWallImportPage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val context = LocalContext.current
    // Not saved with the activity's state: a file of up to 1 MB would not fit there
    var fileName by remember { mutableStateOf<String?>(null) }
    var document by remember { mutableStateOf<Map<String, Any?>?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    val choose = rememberLauncherForActivityResult(OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val resolver = context.contentResolver
        fileName = runCatching {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { if (it.moveToFirst()) it.getString(0) else null }
        }.getOrNull() ?: uri.lastPathSegment
        val (checked, reason) = importedDocument(runCatching { resolver.openInputStream(uri)?.use { readForImport(it) } }.getOrNull())
        // An invalid file leaves the profile as it is: nothing of it is imported
        document = checked
        problem = reason
    }
    Column(Modifier.fillMaxSize().background(colors.groupedBackground)) {
        NavBar("", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Column(Modifier.weight(1f).navigationBarsPadding().verticalScroll(rememberScrollState())) {
            LargeTitle("Import JSON")
            Section(footer = document?.let { importFooter(it) }) {
                row {
                    PressableRow(null) {
                        GlyphIcon(Glyph.Doc, colors.blue, 22.dp)
                        Spacer(Modifier.width(14.dp))
                        Label(fileName ?: "No file chosen", color = if (fileName != null) colors.label else colors.secondaryLabel, modifier = Modifier.weight(1f), maxLines = 2)
                        Spacer(Modifier.width(8.dp))
                        Label("Choose File", color = colors.blue, modifier = Modifier.clickable(role = Role.Button) { choose.launch(arrayOf("*/*")) }.padding(6.dp))
                    }
                }
            }
            Section("IMPORT RULES") {
                for ((title, detail) in ImportRules) row { DetailRow(title, detail) }
            }
            problem?.let { reason ->
                Section {
                    row {
                        Row(
                            Modifier.fillMaxWidth().background(colors.red.copy(alpha = 0.12f)).padding(horizontal = 16.dp, vertical = 12.dp)
                                .semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            GlyphIcon(Glyph.Alert, colors.red, 26.dp)
                            Spacer(Modifier.width(14.dp))
                            Column(Modifier.weight(1f)) {
                                Label("Import blocked", IosText.headline, colors.red)
                                Label(reason, IosText.subheadline, colors.red)
                            }
                        }
                    }
                }
            }
            val chosen = document
            Box(
                Modifier.padding(start = 16.dp, end = 16.dp, top = 24.dp).fillMaxWidth().heightIn(min = 50.dp).clip(RoundedCornerShape(12.dp))
                    .background(if (chosen != null) colors.blue else colors.fill)
                    .clickable(enabled = chosen != null, role = Role.Button) {
                        if (chosen == null) return@clickable
                        onChange(kept(draft, chosen, context))
                        onBack()
                    },
                contentAlignment = Alignment.Center,
            ) {
                Label("Import", IosText.headline, if (chosen != null) Color.White else colors.tertiaryLabel)
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

private val Inputs = listOf(NodeChain.INPUT_TUN to "System VPN (TUN)", NodeChain.INPUT_SOCKS5 to "Local SOCKS5 proxy", NodeChain.INPUT_HTTP to "Local HTTP proxy")

internal fun inputTitle(input: String) = Inputs.firstOrNull { it.first == input }?.second ?: Inputs[0].second

/** The app's settings behind the home screen's gear: WaterWall Input, one choice for every WaterWall profile, and the GeoIP database
 *  that WaterWall Routers use to route by country */
@Composable
fun SettingsScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    val settings = remember { AppSettings(context.applicationContext) }
    var input by remember { mutableStateOf(settings.waterWallInput) }
    var showingInput by rememberSaveable { mutableStateOf(false) }
    BackHandler(showingInput) { showingInput = false }
    AnimatedContent(
        targetState = showingInput,
        transitionSpec = {
            if (targetState) slideInHorizontally(tween(280)) { it } togetherWith slideOutHorizontally(tween(280)) { -it / 3 }
            else slideInHorizontally(tween(280)) { -it / 3 } togetherWith slideOutHorizontally(tween(280)) { it }
        },
        label = "settings",
    ) { inputPage ->
        if (inputPage) {
            WaterWallInputPage(input, { chosen ->
                settings.waterWallInput = chosen
                input = chosen
            }) { showingInput = false }
        } else {
            SettingsPage(settings, input, { showingInput = true }, onClose)
        }
    }
}

@Composable
private fun SettingsPage(settings: AppSettings, input: String, openInput: () -> Unit, onClose: () -> Unit) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val context = LocalContext.current
    val focus = LocalFocusManager.current
    val database = remember { GeoIpDatabase(context.applicationContext) }
    var databaseInfo by remember { mutableStateOf(database.info()) }
    var urlDraft by rememberSaveable { mutableStateOf(settings.geoIpUpdateUrl) }
    val busy = AppModel.geoIpUpdating

    fun commitUrl() {
        urlDraft = urlDraft.trim()
        settings.geoIpUpdateUrl = urlDraft
    }

    fun updateGeoIp(work: () -> Unit) = AppModel.updateGeoIp(work) { failure ->
        databaseInfo = database.info()
        ui.showAlert("GeoIP", failure ?: "The country database was validated and installed. Reconnect WaterWall to use the new file.")
    }

    val upload = rememberLauncherForActivityResult(OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val resolver = context.contentResolver
        updateGeoIp { resolver.openInputStream(uri)!!.use { database.installFrom(it) } }
    }

    Column(Modifier.fillMaxSize().background(colors.groupedBackground)) {
        NavBar("Settings", left = {
            RoundBarButton(Glyph.Close, "Done") {
                focus.clearFocus()
                commitUrl()
                onClose()
            }
        })
        Column(Modifier.weight(1f).navigationBarsPadding().imePadding().verticalScroll(rememberScrollState())) {
            Section("WATERWALL", "What SRP puts in place of a WaterWall profile's input hint when it connects, for every profile.") {
                row { ValueRow("WaterWall Input", inputTitle(input), onClick = openInput) }
            }
            Section("GEOIP DATABASE", "WaterWall Routers that route by country (rules with geoip: destinations) use this country database. Download & Replace fetches a GeoIP2 or GeoLite2 Country MMDB file from the HTTPS link; Upload takes one from your files.") {
                row {
                    val info = databaseInfo
                    DetailRow("Country Database", if (info != null) "${info.type} · ${info.source} · ${Formatter.formatFileSize(context, info.bytes)}" else "No valid database", IosText.body)
                }
                row { GeoIpUrlRow(urlDraft, busy, { urlDraft = it }) { commitUrl() } }
                row {
                    ActionRow(null, "Download & Replace", colors.blue, if (busy) "Validating…" else null, enabled = !busy) {
                        focus.clearFocus()
                        commitUrl()
                        val link = settings.geoIpUpdateUrl
                        if (link.isEmpty()) ui.showAlert("GeoIP", "Enter the HTTPS link to a GeoIP2 or GeoLite2 Country MMDB file first.")
                        else updateGeoIp { database.download(link) }
                    }
                }
                row { ActionRow(null, "Upload MMDB…", colors.blue, if (busy) "Validating…" else null, enabled = !busy) { upload.launch(arrayOf("*/*")) } }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun WaterWallInputPage(input: String, onChoose: (String) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val socks = input == NodeChain.INPUT_SOCKS5
    val port = NodeChain.portForInput(input)
    Column(Modifier.fillMaxSize().background(colors.groupedBackground)) {
        NavBar("", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Column(Modifier.weight(1f).navigationBarsPadding().verticalScroll(rememberScrollState())) {
            LargeTitle("WaterWall Input")
            Section("INPUT FOR ALL PROFILES", "Every WaterWall profile uses this input. A change applies the next time a profile connects.") {
                for ((value, title) in Inputs) row { CheckRow(title, checked = value == input) { onChoose(value) } }
            }
            val tun = input == NodeChain.INPUT_TUN
            Section(
                if (socks) "LOCAL SOCKS5 INPUT" else if (tun) "SYSTEM VPN INPUT" else "LOCAL HTTP INPUT",
                if (tun) "SRP adds these nodes when it builds the runtime configuration."
                else "SRP adds these nodes when it builds the runtime configuration. Apps on this device that you set to use the proxy at 127.0.0.1:$port go through WaterWall; the VPN carries no other traffic.",
            ) {
                row {
                    DetailRow(NodeChain.HINT_PACKET, if (tun) "TunDevice" else "Not available: a profile that takes IP packets needs System VPN (TUN).")
                }
                row {
                    DetailRow(NodeChain.HINT_CONNECTION, if (tun) "TunDevice → PacketsToConnection"
                    else "${if (socks) "TcpUdpListener" else "TcpListener"} 127.0.0.1:$port → ${if (socks) "Socks5Server" else "HttpProxyServer"}")
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun GeoIpUrlRow(text: String, inFlight: Boolean, onChange: (String) -> Unit, commit: () -> Unit) {
    val colors = LocalIosColors.current
    var focused by remember { mutableStateOf(false) }
    Row(Modifier.fillMaxWidth().heightIn(min = 52.dp).padding(horizontal = 16.dp), verticalAlignment = Alignment.CenterVertically) {
        Label("Update URL")
        Spacer(Modifier.width(12.dp))
        InlineField(
            text, "https://…/GeoLite2-Country.mmdb", false, KeyboardType.Uri, !inFlight, TextAlign.Start,
            Modifier.weight(1f).onFocusChanged {
                if (focused && !it.isFocused) commit()
                focused = it.isFocused
            },
            "Update URL", commit, onChange,
        )
        if (text.isNotEmpty() && !inFlight) {
            Spacer(Modifier.width(6.dp))
            // The clear button of a UITextField.
            Box(
                Modifier.size(18.dp).clip(CircleShape).background(colors.gray.copy(alpha = 0.6f)).semantics { contentDescription = "Clear Update URL" }.clickable(role = Role.Button) { onChange("") },
                contentAlignment = Alignment.Center,
            ) {
                GlyphIcon(Glyph.ClearMark, Color.White, 16.dp)
            }
        }
    }
}

internal class NodeSettingsText(val settings: Map<String, Any?>?, val error: String?)

/** Empty text means no settings. Otherwise the error says why the text is not a JSON object, with the line and column of a syntax error. */
internal fun parseNodeSettings(text: String): NodeSettingsText {
    if (text.isBlank()) return NodeSettingsText(emptyMap(), null)
    return try {
        @Suppress("UNCHECKED_CAST")
        val settings = Json.parse(text) as? Map<String, Any?>
        if (settings != null) NodeSettingsText(settings, null) else NodeSettingsText(null, "The settings must be a JSON object.")
    } catch (error: Json.SyntaxError) {
        // The line and column count characters as the editor shows them
        val lines = text.substring(0, minOf(error.offset, text.length)).split("\n")
        NodeSettingsText(null, "Line ${lines.size}, column ${lines.last().length + 1}: ${error.reason}")
    }
}

internal fun nodeSettingsText(settings: Map<*, *>) = Json.write(settings, pretty = true, sortedKeys = true)

/** A new line keeps the indentation of the line it breaks, one level deeper after { or [. */
internal fun withIndentedNewline(old: TextFieldValue, new: TextFieldValue): TextFieldValue {
    val cursor = new.selection.start
    val typedNewline = new.text.length == old.text.length + 1 && cursor > 0 && new.text[cursor - 1] == '\n' &&
        new.text.removeRange(cursor - 1, cursor) == old.text
    if (!typedNewline) return new
    val head = old.text.substring(old.text.lastIndexOf('\n', cursor - 2) + 1, cursor - 1)
    val indent = head.takeWhile { it == ' ' || it == '\t' }
    val code = head.trim()
    val insert = "\n" + indent + if (code.endsWith("{") || code.endsWith("[")) "  " else ""
    val text = old.text.substring(0, cursor - 1) + insert + old.text.substring(cursor - 1)
    return TextFieldValue(text, TextRange(cursor - 1 + insert.length))
}

private val JsonStrings = Regex("\"(?:[^\"\\\\\\n]|\\\\.)*\"(\\s*:)?")
private val JsonLiterals = Regex("\\b(?:true|false|null)\\b|-?\\b\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b")

/** Keys in red, values in blue, as the editor's mockup shows them */
internal class JsonHighlight(private val key: Color, private val value: Color) : VisualTransformation {
    override fun filter(text: AnnotatedString): TransformedText {
        val colors = arrayOfNulls<Color>(text.length)
        for (match in JsonLiterals.findAll(text.text)) for (index in match.range) colors[index] = value
        // A string followed by a colon is a key; the colon keeps the text color
        for (match in JsonStrings.findAll(text.text)) {
            val colon = match.groups[1]
            for (index in match.range.first until (colon?.range?.first ?: (match.range.last + 1))) colors[index] = if (colon != null) key else value
        }
        val styled = buildAnnotatedString {
            append(text.text)
            var start = 0
            while (start < colors.size) {
                var end = start
                while (end < colors.size && colors[end] == colors[start]) end++
                colors[start]?.let { addStyle(SpanStyle(color = it), start, end) }
                start = end
            }
        }
        return TransformedText(styled, OffsetMapping.Identity)
    }
}
