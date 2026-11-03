package tr.com.srp.vpn

import android.text.format.Formatter
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.Collator
import java.util.Locale

private val OuterChoices = listOf("none" to "None", "tls" to "TLS", "reality" to "Reality", "aead" to "AEAD", "quic" to "QUIC", "bgp4" to "BGP4")
private val ApplicationChoices = listOf("vless" to "VLESS", "vmess" to "VMess", "trojan" to "Trojan", "socks5" to "SOCKS5", "http-proxy" to "HTTP CONNECT")

private fun Map<String, Any?>.optionsOf(): LinkedHashMap<String, Any?> {
    @Suppress("UNCHECKED_CAST")
    return LinkedHashMap((this["node-options"] as? Map<String, Any?>).orEmpty())
}

private fun Map<String, Any?>.geoIpOf(): LinkedHashMap<String, Any?> {
    @Suppress("UNCHECKED_CAST")
    return LinkedHashMap((this["geoip"] as? Map<String, Any?>).orEmpty())
}

private fun countriesOf(configuration: Map<String, Any?>): List<String> =
    (configuration.geoIpOf()["countries"] as? List<*>).orEmpty().filterIsInstance<String>()

/** Checks a changed configuration and keeps it, or says why it is not allowed. True when it was kept. */
private fun applyConfiguration(configuration: Map<String, Any?>, draft: Profile, ui: UiHost, onChange: (Profile) -> Unit): Boolean {
    val error = ChainConfig.validationError(configuration)
    val json = if (error == null) ChainConfig.jsonWithConfiguration(configuration) else null
    if (json.isNullOrEmpty()) {
        ui.showAlert("Invalid WaterWall Configuration", error ?: "The configuration could not be serialized.")
        return false
    }
    onChange(draft.copy(configJson = json))
    return true
}

private fun changedApplication(configuration: Map<String, Any?>, application: String): Map<String, Any?> {
    val changed = LinkedHashMap(configuration)
    val options = configuration.optionsOf()
    options.remove("application")
    changed["application"] = application
    if (application == "socks5") {
        changed["mux"] = false
        changed["outer"] = "none"
        changed["http"] = "off"
        changed["obfuscator"] = false
        changed["carrier"] = "tcp"
        changed["bgp4"] = false
        listOf("mux", "outer", "http", "obfuscator", "kcp").forEach { options.remove(it) }
    } else if (application == "http-proxy") {
        changed["mux"] = false
        changed["http"] = "off"
        changed["carrier"] = "tcp"
        listOf("mux", "http", "kcp").forEach { options.remove(it) }
    }
    changed["node-options"] = options
    return changed
}

private fun changedOuter(configuration: Map<String, Any?>, outer: String): Map<String, Any?> {
    val changed = LinkedHashMap(configuration)
    val options = configuration.optionsOf()
    options.remove("outer")
    changed["outer"] = outer
    if (outer == "quic") {
        changed["http"] = "off"
        changed["carrier"] = "tcp"
        changed["quic-carrier"] = if (configuration["application"] == "http-proxy") "stream" else "datagram"
        changed["mux"] = false
        listOf("http", "kcp", "mux").forEach { options.remove(it) }
    }
    changed["node-options"] = options
    return changed
}

/** The screen titled WaterWall behind the Configuration row. */
@Composable
fun WaterWallConfigPage(draft: Profile, onChange: (Profile) -> Unit, push: (EditorPage) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val context = LocalContext.current
    val database = remember { GeoIpDatabase(context.applicationContext) }
    val configuration = draft.configuration
    val isChain = configuration["mode"] == "chain"
    val usesConnections = configuration["input"] == "connections"
    val usesQuic = configuration["outer"] == "quic"
    val http = configuration["http"] as? String ?: "off"
    val httpEnabled = http != "off"
    val carrier = configuration["carrier"] as? String ?: "tcp"
    val quicCarrier = configuration["quic-carrier"] as? String ?: "datagram"
    val application = configuration["application"] as? String
    val httpProxy = application == "http-proxy"
    val wireGuard = ChainConfig.isWireGuard(configuration)
    val showsMux = isChain && usesConnections && application != "socks5" && !httpProxy && (!usesQuic || quicCarrier == "stream")
    val countries = countriesOf(configuration)
    val geoIpInFlight = AppModel.geoIpUpdating
    var databaseInfo by remember { mutableStateOf(database.info()) }

    fun apply(changed: Map<String, Any?>) = applyConfiguration(changed, draft, ui, onChange)

    var urlDraft by rememberSaveable { mutableStateOf(configuration.geoIpOf()["update-url"] as? String ?: "") }

    /** Saves the link as typed. A link that is not allowed stays in the field, so that it can be corrected. */
    fun commitUrl(): Boolean {
        val url = urlDraft.trim()
        urlDraft = url
        if (url == (configuration.geoIpOf()["update-url"] as? String ?: "")) return true
        val changed = LinkedHashMap(configuration)
        val geoIp = configuration.geoIpOf()
        if (url.isEmpty()) geoIp.remove("update-url") else geoIp["update-url"] = url
        if (geoIp.isEmpty()) changed.remove("geoip") else changed["geoip"] = geoIp
        val error = ChainConfig.validationError(changed)
        if (error != null) {
            ui.showAlert("GeoIP", error)
            return false
        }
        return apply(changed)
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
        NavBar("WaterWall", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Column(Modifier.weight(1f).navigationBarsPadding().imePadding().verticalScroll(rememberScrollState())) {
            val footer = when {
                configuration["bgp4"] == true || configuration["outer"] == "bgp4" -> "BGP4 is framing, not encryption. Combine it with a separate outer transport when needed; QUIC requires stream mode."
                isChain && application == "vmess" && configuration["obfuscator"] == true -> "VMess uses modern AEAD. WaterWall MUX is not Mux.Cool/XUDP; XOR is obfuscation, not encryption."
                isChain && application == "vmess" -> "VMess uses modern AEAD. WaterWall MUX is not VMess Mux.Cool or XUDP."
                isChain && configuration["obfuscator"] == true -> "Build each layer independently. XOR is obfuscation, not encryption."
                else -> "Build the connection chain by selecting each layer independently."
            }
            Section("CONFIGURATION", footer) {
                row {
                    val selected = when (configuration["mode"]) { "wireguard" -> 1; "direct" -> 2; else -> 0 }
                    SegmentRow("Mode", listOf("Chain", "WireGuard", "Direct"), selected) { index ->
                        val mode = listOf("chain", "wireguard", "direct")[index]
                        val changed = LinkedHashMap(configuration)
                        changed["mode"] = mode
                        changed["node-options"] = LinkedHashMap<String, Any?>()
                        if (mode == "chain") {
                            changed.putAll(mapOf("input" to "connections", "application" to "vless", "mux" to false, "outer" to "tls", "http" to "off", "http-version" to 1L,
                                "obfuscator" to false, "carrier" to "tcp", "quic-carrier" to "datagram", "bgp4" to false))
                        } else {
                            listOf("input", "application", "mux", "outer", "http", "http-version", "obfuscator", "carrier", "quic-carrier", "geoip", "bgp4").forEach { changed.remove(it) }
                        }
                        apply(changed)
                    }
                }
                if (isChain && application != "socks5") {
                    row { InputRow(usesConnections, configuration, ::apply) }
                    if (usesConnections) {
                        row { ValueRow("Application", ChainConfig.applicationNames[application]) { push(EditorPage.Choice("application")) } }
                        if (showsMux) {
                            row {
                                SwitchRow("MUX", configuration["mux"] == true) { on ->
                                    val changed = LinkedHashMap(configuration)
                                    changed["mux"] = on
                                    if (!on) changed["node-options"] = configuration.optionsOf().apply { remove("mux") }
                                    apply(changed)
                                }
                            }
                        }
                    }
                    row {
                        SwitchRow("Obfuscator", configuration["obfuscator"] == true) { on ->
                            val changed = LinkedHashMap(configuration)
                            changed["obfuscator"] = on
                            if (!on) changed["node-options"] = configuration.optionsOf().apply { remove("obfuscator") }
                            apply(changed)
                        }
                    }
                    if (!usesQuic && !httpProxy) {
                        row {
                            SegmentRow("HTTP", listOf("Off", "HTTP", "WebSocket"), listOf("off", "http", "websocket").indexOf(http)) { index ->
                                val changed = LinkedHashMap(configuration)
                                changed["http"] = listOf("off", "http", "websocket")[index]
                                if (index == 0) changed["node-options"] = configuration.optionsOf().apply { remove("http") }
                                apply(changed)
                            }
                        }
                        if (httpEnabled) {
                            row {
                                SegmentRow("HTTP Version", listOf("1", "2"), if ((configuration["http-version"] as? Number)?.toInt() == 2) 1 else 0) { index ->
                                    apply(LinkedHashMap(configuration).apply { put("http-version", if (index == 1) 2L else 1L) })
                                }
                            }
                        }
                    }
                    row {
                        SwitchRow("BGP4 Framing", configuration["bgp4"] == true || configuration["outer"] == "bgp4") { on ->
                            val changed = LinkedHashMap(configuration)
                            changed["bgp4"] = on
                            if (!on && configuration["outer"] == "bgp4") {
                                changed["outer"] = "none"
                                changed["node-options"] = configuration.optionsOf().apply { remove("outer") }
                            }
                            apply(changed)
                        }
                    }
                    row { ValueRow("Outer", OuterChoices.firstOrNull { it.first == configuration["outer"] }?.second ?: "BGP4") { push(EditorPage.Choice("outer")) } }
                    if (!httpProxy) {
                        if (usesQuic) {
                            row {
                                SegmentRow("QUIC Carrier", listOf("Datagram", "Stream"), if (quicCarrier == "stream") 1 else 0) { index ->
                                    val changed = LinkedHashMap(configuration)
                                    changed["quic-carrier"] = if (index == 1) "stream" else "datagram"
                                    if (index == 0) {
                                        changed["mux"] = false
                                        changed["node-options"] = configuration.optionsOf().apply { remove("mux") }
                                    }
                                    apply(changed)
                                }
                            }
                        } else {
                            row {
                                SegmentRow("Carrier", listOf("TCP", "KCP"), if (carrier == "kcp") 1 else 0) { index ->
                                    val changed = LinkedHashMap(configuration)
                                    changed["carrier"] = if (index == 1) "kcp" else "tcp"
                                    if (index == 0) changed["node-options"] = configuration.optionsOf().apply { remove("kcp") }
                                    apply(changed)
                                }
                            }
                        }
                    }
                } else if (isChain) {
                    row { InputRow(usesConnections, configuration, ::apply) }
                    row { ValueRow("Application", ChainConfig.applicationNames[application]) { push(EditorPage.Choice("application")) } }
                }
            }
            if (!wireGuard) {
                val layers = buildList {
                    add("packet")
                    if (isChain) {
                        if (usesConnections) {
                            add("application")
                            if (configuration["mux"] == true) add("mux")
                        }
                        if (configuration["obfuscator"] == true) add("obfuscator")
                        if (!usesQuic && httpEnabled) add("http")
                        if (configuration["outer"] != "none") add("outer")
                        if (!usesQuic && carrier == "kcp") add("kcp")
                    }
                }
                Section("ADVANCED NODE SETTINGS", "Optional per-node JSON objects. Leave them empty to use WaterWall defaults.") {
                    for (layer in layers) {
                        row {
                            val count = (configuration.optionsOf()[layer] as? Map<*, *>)?.size ?: 0
                            ValueRow(layerTitle(layer), if (count > 0) "$count ${if (count == 1) "setting" else "settings"}" else "Default") { push(EditorPage.NodeOptions(layer)) }
                        }
                    }
                }
            }
            if (isChain && usesConnections) {
                Section("GEOIP ROUTING", "GeoLite2 Country data by MaxMind. Uploaded and downloaded files are validated before atomic replacement. Selected-country matches use a direct TCP/UDP connector; other destinations use the proxy chain. Fake-IP resolution happens before routing.") {
                    row {
                        SwitchRow("GeoIP Routing", countries.isNotEmpty()) { on ->
                            geoIpEnabledChanged(on, configuration, database, draft, ui, onChange)
                            databaseInfo = database.info()
                        }
                    }
                    row { ValueRow("Countries", "${countries.size} ${if (countries.size == 1) "country" else "countries"}") { push(EditorPage.Countries) } }
                    row {
                        val info = databaseInfo
                        ValueRow("Country Database", if (info != null) "${info.type} · ${info.source} · ${Formatter.formatFileSize(context, info.bytes)}" else "No valid database", disclosure = false)
                    }
                    row { GeoIpUrlRow(urlDraft, geoIpInFlight, { urlDraft = it }) { commitUrl() } }
                    row {
                        ValueRow("Upload MMDB…", if (geoIpInFlight) "Validating…" else "Choose a country database", enabled = !geoIpInFlight) { upload.launch(arrayOf("*/*")) }
                    }
                    row {
                        ValueRow("Download & Replace", if (geoIpInFlight) "Validating…" else "Use the HTTPS link", enabled = !geoIpInFlight) {
                            if (commitUrl()) {
                                val link = urlDraft
                                if (link.isEmpty()) {
                                    ui.showAlert("GeoIP", "Enter the HTTPS link to a GeoIP2 or GeoLite2 Country MMDB file first.")
                                } else {
                                    updateGeoIp { database.download(link) }
                                }
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun InputRow(usesConnections: Boolean, configuration: Map<String, Any?>, apply: (Map<String, Any?>) -> Boolean) {
    SegmentRow("Input", listOf("Connections", "Raw IPv4"), if (usesConnections) 0 else 1) { index ->
        val raw = index == 1
        val changed = LinkedHashMap(configuration)
        changed["node-options"] = configuration.optionsOf().apply { listOf("packet", "application", "mux").forEach { remove(it) } }
        changed["input"] = if (raw) "raw-ipv4" else "connections"
        if (raw) changed.remove("geoip")
        changed["application"] = if (raw) "" else (configuration["application"] as? String)?.takeIf { it.isNotEmpty() } ?: "vless"
        changed["mux"] = if (raw) false else configuration["mux"] ?: false
        apply(changed)
    }
}

private fun layerTitle(layer: String) = when (layer) {
    "application" -> "Application"
    "mux" -> "MUX"
    "obfuscator" -> "Obfuscator"
    "http" -> "HTTP"
    "outer" -> "Outer"
    "kcp" -> "KCP"
    else -> "Packet"
}

private fun geoIpEnabledChanged(enabled: Boolean, configuration: Map<String, Any?>, database: GeoIpDatabase, draft: Profile, ui: UiHost, onChange: (Profile) -> Unit): Boolean {
    if (enabled) {
        try {
            database.installBundledIfNeeded()
        } catch (error: GeoIpDatabase.Failure) {
            ui.showAlert("GeoIP", error.message ?: "Upload or download a valid Country MMDB before enabling GeoIP routing.")
            return false
        }
    }
    val changed = LinkedHashMap(configuration)
    val geoIp = configuration.geoIpOf()
    if (enabled) geoIp["countries"] = countriesOf(configuration).ifEmpty { listOf("IR") } else geoIp.remove("countries")
    if (geoIp.isEmpty()) changed.remove("geoip") else changed["geoip"] = geoIp
    return applyConfiguration(changed, draft, ui, onChange)
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

/** The list behind the Application and Outer rows. */
@Composable
fun WaterWallChoicePage(row: String, draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val configuration = draft.configuration
    val application = row == "application"
    Column(Modifier.fillMaxSize().background(colors.groupedBackground)) {
        NavBar(if (application) "Application" else "Outer", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Column(Modifier.weight(1f).navigationBarsPadding().verticalScroll(rememberScrollState())) {
            Section {
                for ((value, title) in if (application) ApplicationChoices else OuterChoices) {
                    row {
                        CheckRow(title, checked = configuration[row] == value) {
                            if (application) {
                                // Picking the current application again keeps its UUID or password
                                if (value != configuration["application"]) {
                                    applyConfiguration(changedApplication(configuration, value), draft.copy(username = "", password = ""), ui, onChange)
                                }
                            } else {
                                applyConfiguration(changedOuter(configuration, value), draft, ui, onChange)
                            }
                            onBack()
                        }
                    }
                }
            }
        }
    }
}

/** The JSON editor of one layer's advanced settings. */
@Composable
fun NodeOptionsPage(layer: String, draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val configuration = draft.configuration
    val initial = remember { nodeSettingsText((configuration.optionsOf()[layer] as? Map<*, *>).orEmpty()) }
    var value by remember { mutableStateOf(TextFieldValue(initial)) }
    val focus = remember { FocusRequester() }
    val parsed = remember(value.text) { parseNodeSettings(value.text) }
    val status = when {
        parsed.error != null -> parsed.error
        parsed.settings!!.isEmpty() -> "No settings: WaterWall defaults"
        else -> "Valid JSON"
    }
    LaunchedEffect(Unit) { focus.requestFocus() }
    Column(Modifier.fillMaxSize().background(colors.plainBackground)) {
        NavBar(
            layerTitle(layer),
            colors.plainBackground,
            left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) },
            right = {
                RoundBarButton(Glyph.Check, "Done", prominent = true) {
                    val settings = parsed.settings
                    if (settings == null) {
                        ui.showAlert("Invalid Node Settings", parsed.error)
                        return@RoundBarButton
                    }
                    val changed = LinkedHashMap(configuration)
                    changed["node-options"] = configuration.optionsOf().apply { put(layer, settings) }
                    val error = ChainConfig.validationError(changed)
                    if (error != null) {
                        ui.showAlert("Invalid Node Settings", error)
                    } else if (applyConfiguration(changed, draft, ui, onChange)) {
                        onBack()
                    }
                }
            },
        )
        BasicTextField(
            value = value,
            onValueChange = { new -> value = withIndentedNewline(value, new) },
            modifier = Modifier.weight(1f).fillMaxWidth().editedField().focusRequester(focus).padding(horizontal = 16.dp, vertical = 8.dp),
            textStyle = IosText.subheadline.copy(fontSize = 14.sp, fontFamily = FontFamily.Monospace, color = colors.label),
            cursorBrush = SolidColor(colors.blue),
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii),
        )
        Row(Modifier.fillMaxWidth().imePadding().navigationBarsPadding().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Label(status ?: "", IosText.footnote, if (parsed.error != null) colors.red else colors.secondaryLabel, Modifier.weight(1f))
            Spacer(Modifier.width(8.dp))
            Label(
                "Format",
                IosText.callout,
                if (parsed.settings != null) colors.blue else colors.tertiaryLabel,
                Modifier.clickable(enabled = parsed.settings != null) {
                    val text = nodeSettingsText(parsed.settings!!)
                    value = TextFieldValue(text, TextRange(text.length))
                }.padding(4.dp),
            )
        }
    }
}

internal class NodeSettingsText(val settings: Map<String, Any?>?, val error: String?)

/** Empty text keeps the WaterWall defaults. Otherwise the error says why the text is not a JSON object, with the line and column of a syntax error. */
internal fun parseNodeSettings(text: String): NodeSettingsText {
    if (text.isBlank()) return NodeSettingsText(emptyMap(), null)
    return try {
        @Suppress("UNCHECKED_CAST")
        val settings = Json.parse(text) as? Map<String, Any?>
        if (settings != null) NodeSettingsText(settings, null) else NodeSettingsText(null, "Advanced node settings must be a JSON object.")
    } catch (error: Json.SyntaxError) {
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

/** The GeoIP Countries screen: a searchable list where the ticked countries go direct. */
@Composable
fun GeoIpCountriesPage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val context = LocalContext.current
    val database = remember { GeoIpDatabase(context.applicationContext) }
    val configuration = draft.configuration
    val selected = countriesOf(configuration).toSet()
    var query by remember { mutableStateOf("") }
    val countries = remember {
        val collator = Collator.getInstance(Locale.US)
        Locale.getISOCountries().map { it to Locale.Builder().setRegion(it).build().getDisplayCountry(Locale.US) }
            .filter { it.second.isNotEmpty() }
            .sortedWith { left, right -> collator.compare(left.second, right.second) }
    }
    val visible = remember(query) {
        val wanted = query.trim()
        if (wanted.isEmpty()) countries else countries.filter { it.second.contains(wanted, ignoreCase = true) || it.first.contains(wanted, ignoreCase = true) }
    }

    fun setCountries(codes: Set<String>) {
        // Choosing a country turns routing on, so it needs the database the GeoIP Routing switch installs
        if (codes.isNotEmpty()) {
            try {
                database.installBundledIfNeeded()
            } catch (error: GeoIpDatabase.Failure) {
                ui.showAlert("GeoIP", error.message ?: "Upload or download a valid Country MMDB before enabling GeoIP routing.")
                return
            }
        }
        val changed = LinkedHashMap(configuration)
        val geoIp = configuration.geoIpOf()
        if (codes.isNotEmpty()) geoIp["countries"] = codes.sorted() else geoIp.remove("countries")
        if (geoIp.isEmpty()) changed.remove("geoip") else changed["geoip"] = geoIp
        applyConfiguration(changed, draft, ui, onChange)
    }

    Box(Modifier.fillMaxSize().background(colors.plainBackground)) {
        Column(Modifier.fillMaxSize()) {
            NavBar("GeoIP Countries", colors.plainBackground, left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) }, right = { RoundBarButton(Glyph.Check, "Done", prominent = true, onClick = onBack) })
            LazyColumn(Modifier.weight(1f)) {
                item {
                    Section {
                        row {
                            SwitchRow("GeoIP Routing", selected.isNotEmpty()) { on ->
                                setCountries(if (on) selected.ifEmpty { setOf("IR") } else emptySet())
                            }
                        }
                    }
                    Label("COUNTRIES", IosText.subheadline.copy(fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold), colors.secondaryLabel, Modifier.padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 8.dp))
                }
                items(visible, key = { it.first }) { (code, name) ->
                    CheckRow("$name ($code)", checked = code in selected) {
                        setCountries(if (code in selected) selected - code else selected + code)
                    }
                    Box(Modifier.fillMaxWidth().padding(start = 16.dp).height(0.5.dp).background(colors.separator))
                }
                item {
                    Label("${selected.size} selected. Selected countries use direct routing.", IosText.footnote.copy(fontSize = 14.sp), colors.secondaryLabel, Modifier.padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 96.dp))
                }
            }
        }
        // The search bar floats at the bottom, as on current iOS.
        Row(
            Modifier
                .align(Alignment.BottomCenter)
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp, vertical = 12.dp)
                .fillMaxWidth()
                .height(48.dp)
                .shadow(3.dp, RoundedCornerShape(24.dp))
                .clip(RoundedCornerShape(24.dp))
                .background(colors.barButton)
                .padding(horizontal = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            GlyphIcon(Glyph.Search, colors.label, 18.dp)
            Spacer(Modifier.width(8.dp))
            InlineField(query, "Country or ISO code", false, KeyboardType.Text, true, TextAlign.Start, Modifier.weight(1f), "Search countries", null) { query = it }
        }
    }
}
