package tr.com.srp.vpn

import java.net.URI
import kotlin.math.floor
import kotlin.math.max

private typealias Obj = Map<String, Any?>

private val UTF8 = Charsets.UTF_8

@Suppress("UNCHECKED_CAST")
private fun Any?.asObj(): Obj? = this as? Map<String, Any?>

private fun String.utf8Size() = toByteArray(UTF8).size

private fun isInteger(value: Any?): Boolean = when (value) {
    is Long, is Int -> true
    is Double -> value == floor(value)
    else -> false
}

private fun longOf(value: Any?): Long = (value as? Number)?.toLong() ?: 0L

private fun boolOf(value: Any?): Boolean = when (value) {
    is Boolean -> value
    is Number -> value.toDouble() != 0.0
    else -> false
}

private fun lengthOf(value: Any?): Int = (value as? String)?.length ?: 0

private fun inRange(settings: Obj, key: String, minimum: Long, maximum: Long): Boolean {
    val value = settings[key]
    return isInteger(value) && longOf(value) in minimum..maximum
}

private fun booleans(settings: Obj, keys: Set<String>): Boolean = keys.all { settings[it] == null || settings[it] is Boolean }

private fun alpnError(value: Any?): String? {
    val list = value as? List<*> ?: return "alpns must be an array of unique nonempty strings."
    val seen = HashSet<String>()
    var totalBytes = 0
    for (item in list) {
        val text = item as? String
        if (text == null || text.utf8Size() == 0 || text.utf8Size() > 255 || text in seen) {
            return "Each alpns entry must be a unique nonempty string of at most 255 UTF-8 bytes."
        }
        seen.add(text)
        totalBytes += text.utf8Size() + 1
        if (totalBytes > 65533) return "alpns exceeds the encoded 65533-byte limit."
    }
    return null
}

private fun fakeDnsError(key: String, value: Any?): String? {
    if (value is Boolean) return null
    val settings = value.asObj() ?: return "$key must be a boolean or an object."
    val allowed = setOf("enabled", "address", "network", "netmask", "port", "cache-size", "ttl")
    for (nested in settings.keys) if (nested !in allowed) return "Unsupported $key setting: $nested"
    if (settings["enabled"] != null && settings["enabled"] !is Boolean) return "$key.enabled must be a boolean."
    for (nested in listOf("address", "network", "netmask")) {
        if (settings[nested] != null && settings[nested] !is String) return "$key.$nested must be a string."
    }
    val ranges = listOf(Triple("port", 1L, 65535L), Triple("cache-size", 1L, 262144L), Triple("ttl", 0L, 2147483647L))
    for ((nested, minimum, maximum) in ranges) {
        if (settings[nested] != null && !inRange(settings, nested, minimum, maximum)) return "$key.$nested has an invalid value or range."
    }
    return null
}

private fun fragmentError(value: Any?): String? {
    val settings = value.asObj()
    if (settings == null || settings.isEmpty()) return "fragment must be a nonempty object."
    val allowed = setOf("mode", "count", "duration-ms", "bypass_chance", "wait-for-est", "tls-hello-fragment", "tls-hello-timeout-ms", "cuts")
    for (key in settings.keys) if (key !in allowed) return "Unsupported fragment setting: $key"
    val mode = settings["mode"]
    if (mode != "counter" && mode != "timed") return "fragment.mode must be counter or timed."
    val counter = mode == "counter"
    val counterKey = if (counter) "count" else "duration-ms"
    val forbiddenKey = if (counter) "duration-ms" else "count"
    if (settings[counterKey] == null || !inRange(settings, counterKey, 0, 4294967295L)) return "fragment.$counterKey has an invalid value or range."
    if (settings[forbiddenKey] != null) return "fragment.$forbiddenKey is not valid in $mode mode."
    if (settings["bypass_chance"] != null && !inRange(settings, "bypass_chance", 0, 100)) return "fragment.bypass_chance has an invalid value or range."
    for (key in listOf("wait-for-est", "tls-hello-fragment")) {
        if (settings[key] != null && settings[key] !is Boolean) return "fragment.$key must be a boolean."
    }
    if (settings["tls-hello-timeout-ms"] != null &&
        (!boolOf(settings["tls-hello-fragment"]) || !inRange(settings, "tls-hello-timeout-ms", 1, 4294967295L))) {
        return "fragment.tls-hello-timeout-ms requires TLS fragmentation and an integer from 1 to 4294967295."
    }
    val cuts = settings["cuts"] as? List<*>
    if (cuts == null || cuts.size > 64) return "fragment.cuts must be an array of at most 64 entries."
    var previousOffset = 0L
    for (cut in cuts) {
        val parts = cut as? List<*>
        if (parts == null || parts.size != 3 || !parts.all { isInteger(it) }) {
            return "Each fragment cut must be [offset, delay_ms, chance_percent] with integer values."
        }
        val offset = longOf(parts[0])
        val delay = longOf(parts[1])
        val chance = longOf(parts[2])
        if (offset <= previousOffset || offset < 1 || offset > 4294967295L) return "fragment cut offsets must be strictly increasing integers from 1 to 4294967295."
        if (delay < 0 || delay > 4294967295L) return "fragment cut delays must be integers from 0 to 4294967295."
        if (chance < 0 || chance > 100) return "fragment cut chances must be integers from 0 to 100."
        previousOffset = offset
    }
    return null
}

private fun isUuid(value: Any?): Boolean {
    val text = value as? String ?: return false
    var hex = text
    if (text.length == 36) {
        for (position in listOf(8, 13, 18, 23)) if (text[position] != '-') return false
        hex = text.replace("-", "")
    }
    return hex.length == 32 && hex.all { it in "0123456789abcdefABCDEF" }
}

private fun integerOrRange(value: Any?, minimum: Long, maximum: Long): Boolean {
    if (isInteger(value)) return longOf(value) in minimum..maximum
    val parts = value as? List<*>
    if (parts == null || parts.size != 2 || !isInteger(parts[0]) || !isInteger(parts[1])) return false
    val lower = longOf(parts[0])
    val upper = longOf(parts[1])
    return lower >= minimum && upper <= maximum && lower <= upper
}

private fun stringMapError(value: Any?, field: String): String? {
    val map = value.asObj() ?: return "$field must be an object with string values."
    return if (map.values.all { it is String }) null else "$field values must be strings."
}

/** The HTTP version a setting names: 1, 2, 0 for automatic, or null when it names none. */
private fun httpVersionOf(value: Any?): Int? {
    if (isInteger(value) && (longOf(value) == 1L || longOf(value) == 2L)) return longOf(value).toInt()
    return when (value) {
        "1", "1.1", "http1", "http1.1" -> 1
        "2", "2.0", "http2", "h2" -> 2
        "both", "any", "auto", "1.1+2" -> 0
        else -> null
    }
}

private fun httpError(settings: Obj, usesTls: Boolean, httpMode: String?, configuredVersion: Any?): String? {
    for (key in listOf("path", "scheme", "method", "user-agent", "upgrade-protocol", "content-type",
        "websocket-origin", "websocket-subprotocol", "websocket-extensions", "http1-mode")) {
        if (settings[key] != null && settings[key] !is String) return "http.$key must be a string."
    }
    if (settings["scheme"] != null && settings["scheme"] != "http" && settings["scheme"] != "https") return "http.scheme must be http or https."
    if (settings["http1-mode"] != null && settings["http1-mode"] != "single" && settings["http1-mode"] != "split") return "http.http1-mode must be single or split."
    if (!booleans(settings, setOf("upgrade", "verbose"))) return "An HTTP boolean setting has the wrong type."
    var effectiveVersion = httpVersionOf(configuredVersion) ?: 0
    if (settings["http-version"] != null) {
        effectiveVersion = httpVersionOf(settings["http-version"]) ?: return "http.http-version is invalid."
        if (usesTls && effectiveVersion == 0) return "Automatic HTTP upgrade cannot be used with TLS ALPN."
    }
    if (settings["http1-mode"] == "split" && (effectiveVersion != 1 || httpMode == "websocket")) {
        return "HTTP split mode requires HTTP version 1 and cannot be used with WebSocket."
    }
    for (key in listOf("upgrade-request-headers", "upgrade-response-headers", "headers")) {
        if (settings[key] != null) stringMapError(settings[key], "http.$key")?.let { return it }
    }
    if (settings["split"] != null && settings["split"].asObj() == null) return "http.split must be an object."
    if (lengthOf(settings["websocket-extensions"]) > 0) return "http.websocket-extensions is unsupported because negotiated extensions are not implemented."
    return null
}

private fun obfuscatorError(settings: Obj): String? {
    if (settings["method"] != null && settings["method"] != "xor") return "obfuscator.method must be xor."
    if (settings["xor_key"] != null && !inRange(settings, "xor_key", 0, 255)) return "obfuscator.xor_key must be an integer from 0 to 255."
    if (settings["skip"] != null && settings["skip"] !in listOf("none", "ipv4", "transport")) return "obfuscator.skip must be none, ipv4 or transport."
    if (!booleans(settings, setOf("tls_record_header", "tls_header"))) return "Obfuscator TLS header flags must be booleans."
    return null
}

private fun kcpError(settings: Obj): String? {
    if (!booleans(settings, setOf("fec", "kcp-nodelay", "kcp-no-congestion-control"))) return "A KCP boolean setting has the wrong type."
    val minimumMtu = if (boolOf(settings["fec"])) 126L else 118L
    if (settings["send-mtu"] != null && !inRange(settings, "send-mtu", minimumMtu, 65535)) return "kcp.send-mtu has an invalid value or range."
    val ranges = listOf(
        Triple("fec-data-shards", 1L, 255L), Triple("fec-parity-shards", 1L, 255L), Triple("kcp-interval-ms", 10L, 5000L),
        Triple("kcp-resend", 0L, 2147483647L), Triple("kcp-send-window", 1L, 4294967295L), Triple("kcp-recv-window", 1L, 4294967295L),
        Triple("kcp-rx-minrto-ms", 1L, 2147483647L), Triple("kcp-send-buffer-limit", 0L, 2147483647L),
        Triple("ping-interval-ms", 1L, 2147483647L), Triple("no-recv-timeout-ms", 1L, 2147483647L),
    )
    for ((key, minimum, maximum) in ranges) {
        if (settings[key] != null && !inRange(settings, key, minimum, maximum)) return "kcp.$key has an invalid value or range."
    }
    val dataShards = if (settings["fec-data-shards"] != null) longOf(settings["fec-data-shards"]) else 10
    val parityShards = if (settings["fec-parity-shards"] != null) longOf(settings["fec-parity-shards"]) else 3
    if (dataShards + parityShards > 255) return "KCP FEC data and parity shards cannot exceed 255 in total."
    val sendWindow = if (settings["kcp-send-window"] != null) longOf(settings["kcp-send-window"]) else 128 // the builder's default
    if (settings["kcp-initial-cwnd"] != null && !inRange(settings, "kcp-initial-cwnd", 1, sendWindow)) return "kcp.kcp-initial-cwnd must be positive and no greater than kcp-send-window."
    val ping = if (settings["ping-interval-ms"] != null) longOf(settings["ping-interval-ms"]) else 10000
    val timeout = if (settings["no-recv-timeout-ms"] != null) longOf(settings["no-recv-timeout-ms"]) else 30000
    if (timeout <= ping) return "kcp.no-recv-timeout-ms must be greater than kcp.ping-interval-ms."
    return null
}

private fun tls13Error(value: Any?, reality: Boolean): String? {
    val settings = value.asObj()
    if (settings == null || settings.isEmpty()) return "tls13-record-shaping must be a nonempty object."
    for (key in settings.keys) if (key != "scope" && key != "outcomes") return "Unsupported tls13-record-shaping setting: $key"
    val scope = settings["scope"].asObj()
    if (scope == null || scope["first-application-records"] == null || scope.size != 1 || !inRange(scope, "first-application-records", 1, 1024)) {
        return "tls13-record-shaping.scope requires first-application-records from 1 to 1024."
    }
    val outcomes = settings["outcomes"] as? List<*>
    if (outcomes == null || outcomes.size !in 1..16) return "tls13-record-shaping.outcomes must contain 1 to 16 entries."
    var cumulativeProbability = 0L
    for (item in outcomes) {
        val outcome = item.asObj() ?: return "Each TLS 1.3 shaping outcome must be an object."
        for (key in outcome.keys) if (key !in setOf("probability", "padding-bytes", "delay")) return "Unsupported TLS shaping outcome setting: $key"
        if (!inRange(outcome, "probability", 1, 100)) return "TLS shaping outcome probability must be an integer from 1 to 100."
        cumulativeProbability += longOf(outcome["probability"])
        if (cumulativeProbability > 100) return "TLS shaping cumulative probability cannot exceed 100."
        if (outcome["padding-bytes"] != null && !integerOrRange(outcome["padding-bytes"], 1, 4096)) return "TLS shaping padding-bytes must be in the range 1 to 4096."
        var meaningfulDelay = false
        if (outcome["delay"] != null) {
            if (reality) return "Reality TLS shaping cannot contain delay settings."
            val delay = outcome["delay"].asObj() ?: return "TLS shaping delay must be an object."
            for (key in delay.keys) if (key != "probability" && key != "ms") return "Unsupported TLS shaping delay setting: $key"
            if (!inRange(delay, "probability", 0, 100)) return "TLS shaping delay probability must be an integer from 0 to 100."
            if (!integerOrRange(delay["ms"], 0, 1000)) return "TLS shaping delay ms must be in the range 0 to 1000."
            val maximumDelay = if (isInteger(delay["ms"])) longOf(delay["ms"]) else longOf((delay["ms"] as List<*>)[1])
            meaningfulDelay = longOf(delay["probability"]) > 0 && maximumDelay > 0
        }
        if (outcome["padding-bytes"] == null && !meaningfulDelay) return "Each TLS shaping outcome requires padding or a nonzero-probability, nonzero delay."
    }
    return null
}

private fun geoIpCountries(value: Any?): List<String>? {
    if (value == null) return emptyList()
    val list = value as? List<*> ?: return null
    val countries = sortedSetOf<String>()
    for (item in list) {
        val code = (item as? String ?: return null).uppercase()
        if (code.length != 2 || code[0] !in 'A'..'Z' || code[1] !in 'A'..'Z') return null
        countries.add(code)
    }
    return countries.toList()
}

/** Host and port of a WireGuard Endpoint value, or null. */
private fun endpointOf(value: Any?): Pair<String, Long>? {
    val text = value as? String ?: return null
    val colon = text.lastIndexOf(':')
    if (colon <= 0 || colon + 1 >= text.length) return null
    val port = text.substring(colon + 1).toLongOrNull() ?: return null
    if (port !in 1..65535) return null
    var server = text.substring(0, colon)
    if (server.startsWith("[") && server.endsWith("]") && server.length > 2) server = server.substring(1, server.length - 1)
    return if (server.isEmpty()) null else server to port
}

private fun nonnegativeIntegerString(value: Any?): Long? {
    val parsed = (value as? String)?.takeIf { it.isNotEmpty() }?.toLongOrNull() ?: return null
    return if (parsed in 0..65535) parsed else null
}

private fun migrate(configuration: Obj): Obj {
    var migrated = configuration
    if (migrated["version"].let { isInteger(it) && longOf(it) == 2L }) {
        val versioned = LinkedHashMap(migrated)
        versioned["version"] = 3L
        if (versioned["mode"] == "chain") {
            val defaults = mapOf("http" to "off", "http-version" to 1L, "obfuscator" to false, "carrier" to "tcp", "quic-carrier" to "datagram")
            for ((key, value) in defaults) if (versioned[key] == null) versioned[key] = value
        }
        migrated = versioned
    }
    val nodeOptions = migrated["node-options"].asObj()
    val kcpOptions = nodeOptions?.get("kcp").asObj()
    if (nodeOptions != null && kcpOptions != null && kcpOptions["mtu"] != null) {
        // WaterWall 1.5.3 renamed this setting.
        val renamed = LinkedHashMap(kcpOptions)
        if (renamed["send-mtu"] == null) renamed["send-mtu"] = renamed["mtu"]
        renamed.remove("mtu")
        val options = LinkedHashMap(nodeOptions)
        options["kcp"] = renamed
        val result = LinkedHashMap(migrated)
        result["node-options"] = options
        migrated = result
    }
    val stored = migrated["geoip"].asObj() ?: return migrated
    val result = LinkedHashMap(migrated)
    val geoIp = LinkedHashMap(stored)
    val legacy = geoIp["iran-direct"]
    if (legacy is Boolean) {
        if (geoIp["countries"] == null && legacy) geoIp["countries"] = arrayListOf("IR")
        geoIp.remove("iran-direct")
    }
    val countries = geoIpCountries(geoIp["countries"])
    if (countries != null && geoIp["countries"] != null) geoIp["countries"] = ArrayList(countries)
    if (geoIp.isEmpty()) result.remove("geoip") else result["geoip"] = geoIp
    return result
}

/** The chain builder and validator of SRPWaterWallChainConfig.m. Every message and rule matches iOS; ChainConfigParityTest compares them. */
object ChainConfig {
    data class WireGuard(
        val nodesJson: String,
        val tunnelAddress: String,
        val allowedIps: String,
        val dnsServers: List<String>,
        val endpointIp: String,
        val endpointIps: List<String>?,
    )

    fun defaultConfiguration(): Map<String, Any?> = linkedMapOf(
        "version" to 3L, "mode" to "chain", "input" to "connections", "application" to "vless", "mux" to false, "outer" to "tls",
        "http" to "off", "http-version" to 1L, "obfuscator" to false, "carrier" to "tcp", "quic-carrier" to "datagram",
        "node-options" to LinkedHashMap<String, Any?>(),
    )

    fun configurationWithJson(json: String?): Map<String, Any?>? {
        if (json.isNullOrEmpty()) return defaultConfiguration()
        val configuration = Json.parseOrNull(json).asObj()?.let { migrate(it) } ?: return null
        return if (validationError(configuration) == null) configuration else null
    }

    fun jsonWithConfiguration(configuration: Map<String, Any?>): String? {
        val migrated = migrate(configuration)
        return if (validationError(migrated) == null) Json.write(migrated, sortedKeys = true) else null
    }

    /** The same core settings as iOS, apart from the log folder and DNS that Android cannot find by itself. */
    fun coreJson(logLevel: Int, logFolder: String, dnsServers: List<String>): String {
        val name = if (logLevel >= 2) "DEBUG" else if (logLevel == 1) "INFO" else "WARN"
        val logger = { file: String -> linkedMapOf("loglevel" to name, "file" to file, "console" to true) }
        // c-ares finds no DNS servers on Android by itself.
        val dns = linkedMapOf<String, Any?>("domain-strategy" to "prefer-ipv4")
        if (dnsServers.isNotEmpty()) dns["servers"] = dnsServers
        return Json.write(linkedMapOf(
            "log" to linkedMapOf("path" to "$logFolder/", "core" to logger("ww-core.log"), "network" to logger("ww-network.log"),
                "dns" to logger("ww-dns.log"), "internal" to logger("ww-internal.log")),
            "misc" to linkedMapOf("workers" to 1L, "ram-profile" to "minimal", "mtu" to 1420L, "splice" to false, "try-enabling-bbr" to false, "tcp-tune" to false,
                // lwIP's receive windows may hold this much in total, the same as iOS.
                "tcp-stack-receive-budget" to 16777216L),
            "dns" to dns,
            "configs" to listOf("hosted-nodes.json"),
        ))
    }

    fun isWireGuard(configuration: Map<String, Any?>) = configuration["mode"] == "wireguard"

    fun isDirect(configuration: Map<String, Any?>) = configuration["mode"] == "direct"

    fun needsApplicationSecret(configuration: Map<String, Any?>) = configuration["mode"] == "chain" && configuration["input"] == "connections"

    fun needsOuterSecret(configuration: Map<String, Any?>) =
        configuration["mode"] == "chain" &&
            (configuration["outer"] == "reality" || configuration["outer"] == "aead" || boolOf(configuration["packet-encryption"]))

    fun usesTls(configuration: Map<String, Any?>) =
        configuration["mode"] == "chain" && configuration["outer"] in listOf("tls", "reality", "quic")

    fun allowsFragmentation(configuration: Map<String, Any?>) =
        configuration["mode"] == "chain" && (configuration["outer"] == "tls" || configuration["outer"] == "reality")

    fun allowsRouting(configuration: Map<String, Any?>) = configuration["mode"] == "chain" && configuration["input"] == "connections"

    /** Reaches the server over UDP (WireGuard, KCP or QUIC datagrams) rather than over TCP. */
    fun usesUdpCarrier(configuration: Map<String, Any?>): Boolean {
        if (isWireGuard(configuration)) return true
        if (configuration["mode"] != "chain") return false
        // QUIC's stream carrier runs over a TCP connection, like the chain's default carrier.
        return configuration["carrier"] == "kcp" || (configuration["outer"] == "quic" && configuration["quic-carrier"] != "stream")
    }

    fun summary(configuration: Map<String, Any?>): String {
        if (isWireGuard(configuration)) return "WireGuard"
        if (isDirect(configuration)) return "Direct (diagnostics)"
        val parts = ArrayList<String>()
        if (configuration["input"] == "raw-ipv4") {
            parts.add("Raw IPv4")
            if (boolOf(configuration["packet-encryption"])) parts.add("Packet encryption")
        } else parts.add(applicationNames[configuration["application"]] ?: "VLESS")
        if (boolOf(configuration["mux"])) parts.add("MUX")
        if (boolOf(configuration["obfuscator"])) parts.add("XOR")
        if (configuration["http"] == "websocket") parts.add("WebSocket")
        else if (configuration["http"] == "http") parts.add("HTTP")
        if (boolOf(configuration["bgp4"]) && configuration["outer"] != "bgp4") parts.add("BGP4")
        val outer = configuration["outer"] as? String ?: ""
        if (outer == "quic" && configuration["quic-carrier"] == "stream") parts.add("QUIC Stream")
        else parts.add(if (outer == "aead") "AEAD" else if (outer == "none") "none" else outer.uppercase())
        if (configuration["carrier"] == "kcp") parts.add("KCP")
        return parts.joinToString(" + ")
    }

    val applicationNames = mapOf("vless" to "VLESS", "vmess" to "VMess", "trojan" to "Trojan", "socks5" to "SOCKS5", "http-proxy" to "HTTP CONNECT")

    fun validationError(input: Map<String, Any?>): String? {
        val configuration = migrate(input)
        val topKeys = setOf("version", "mode", "input", "application", "mux", "outer", "http", "http-version", "obfuscator", "carrier", "quic-carrier", "node-options", "geoip", "bgp4", "packet-encryption")
        for (key in configuration.keys) if (key !in topKeys) return "Unknown configuration key: $key"
        if (configuration["version"].let { !isInteger(it) || longOf(it) != 3L }) return "Unsupported WaterWall configuration version."
        for (key in listOf("mode", "input", "application", "outer", "http", "carrier", "quic-carrier")) {
            if (configuration[key] != null && configuration[key] !is String) return "WaterWall $key must be a string."
        }
        val mode = configuration["mode"] as? String ?: return "WaterWall mode must be a string."
        if (mode !in listOf("chain", "direct", "wireguard")) return "WaterWall mode is invalid."
        val direct = mode == "direct"
        val wireGuard = mode == "wireguard"
        var raw = false
        var application: String? = null
        var outer: String? = null
        var http: String? = null
        var carrier: String? = null
        var quicCarrier: String? = null
        val mux = configuration["mux"]
        val bgp4 = configuration["bgp4"]
        val geoIp = configuration["geoip"]
        if (geoIp != null) {
            val settings = geoIp.asObj() ?: return "geoip must be an object."
            for (key in settings.keys) if (key !in setOf("iran-direct", "countries", "update-url")) return "Unsupported geoip setting: $key"
            if (mode != "chain" || configuration["input"] != "connections") return "GeoIP routing requires Chain mode with Connections input."
            if (settings["iran-direct"] != null && settings["iran-direct"] !is Boolean) return "geoip.iran-direct must be a boolean."
            if (settings["countries"] != null && geoIpCountries(settings["countries"]) == null) return "geoip.countries must be an array of two-letter country codes."
            val updateUrl = settings["update-url"]
            if (updateUrl != null) {
                if (updateUrl !is String || updateUrl.isEmpty() || updateUrl.length > 2048 || updateUrl != updateUrl.trim()) {
                    return "geoip.update-url must be a nonempty HTTPS link of at most 2048 characters."
                }
                if (!isPlainHttps(updateUrl)) return "geoip.update-url must use HTTPS and cannot contain embedded credentials or a fragment."
            }
        }
        if (bgp4 != null && bgp4 !is Boolean) return "BGP4 must be a boolean."
        if ((direct || wireGuard) && boolOf(bgp4)) return "BGP4 framing requires Chain mode."
        val packetEncryption = configuration["packet-encryption"]
        if (packetEncryption != null && packetEncryption !is Boolean) return "Packet encryption must be a boolean."
        if (boolOf(packetEncryption)) {
            if (direct || wireGuard || configuration["input"] != "raw-ipv4") return "Packet encryption requires Raw IPv4."
            if (configuration["outer"] == "reality" || configuration["outer"] == "aead") return "Packet encryption cannot be combined with Reality or AEAD."
        }
        if (!direct && !wireGuard) {
            val input = configuration["input"] as? String ?: return "WaterWall input must be a string."
            raw = input == "raw-ipv4"
            if (!raw && input != "connections") return "WaterWall input is invalid."
            application = configuration["application"] as? String ?: return "WaterWall application must be a string."
            if (!raw && application !in listOf("vless", "vmess", "trojan", "socks5", "http-proxy")) return "Select VLESS, VMess, Trojan, SOCKS5 or HTTP CONNECT."
            if (raw && application.isNotEmpty()) return "Raw IPv4 cannot be combined with an application protocol."
            outer = configuration["outer"] as? String ?: return "WaterWall outer must be a string."
            if (outer !in listOf("none", "tls", "reality", "aead", "quic", "bgp4")) return "Select none, TLS, Reality, AEAD, QUIC or BGP4."
            http = configuration["http"] as? String
            carrier = configuration["carrier"] as? String
            quicCarrier = configuration["quic-carrier"] as? String
            if (http == null || http !in listOf("off", "http", "websocket")) return "WaterWall http must be off, http or websocket."
            if (carrier == null || carrier !in listOf("tcp", "kcp")) return "WaterWall carrier must be tcp or kcp."
            if (quicCarrier == null || quicCarrier !in listOf("datagram", "stream")) return "WaterWall quic-carrier must be datagram or stream."
            if (mux !is Boolean) return "MUX must be a boolean."
            if (configuration["obfuscator"] !is Boolean) return "Obfuscator must be a boolean."
            val httpVersion = configuration["http-version"]
            if (!isInteger(httpVersion) || (longOf(httpVersion) != 1L && longOf(httpVersion) != 2L)) return "http-version must be integer 1 or 2."
            if (raw && mux) return "MUX requires an application protocol, not Raw IPv4."
            if (outer == "quic" && carrier == "kcp") return "QUIC cannot be combined with the KCP carrier."
            if (outer == "quic" && http != "off") return "HTTP cannot run over QUIC."
            if (outer == "quic" && mux && quicCarrier != "stream") return "MUX over QUIC requires the stream carrier."
            if (outer == "quic" && boolOf(bgp4) && quicCarrier != "stream") return "BGP4 over QUIC requires the stream carrier."
            if (application == "socks5" && (outer != "none" || http != "off" || mux || boolOf(configuration["obfuscator"]) || boolOf(bgp4) || carrier == "kcp")) {
                return "SOCKS5 TCP and UDP require the TCP carrier with no MUX, outer transport, HTTP or obfuscation."
            }
            if (application == "http-proxy" && (mux || http != "off" || carrier == "kcp")) {
                return "HTTP CONNECT cannot be combined with MUX, another HTTP layer or KCP."
            }
            if (application == "http-proxy" && outer == "quic" && quicCarrier != "stream") {
                return "HTTP CONNECT over QUIC requires the stream carrier."
            }
        }

        val nodeOptions = configuration["node-options"].asObj() ?: return "Advanced Node Settings must be a JSON object."
        if (wireGuard) {
            return if (nodeOptions.isNotEmpty()) "WireGuard mode does not consume node-options; leave it empty." else null
        }
        val layers = hashSetOf("packet")
        if (!direct) {
            if (!raw) layers.add("application")
            if (boolOf(mux)) layers.add("mux")
            if (outer != "none") layers.add("outer")
            if (http != "off") layers.add("http")
            if (boolOf(configuration["obfuscator"])) layers.add("obfuscator")
            if (carrier == "kcp") layers.add("kcp")
        }
        for ((layer, settings) in nodeOptions) {
            if (layer !in layers || settings.asObj() == null) {
                return if (direct) "Direct mode permits only packet node-options objects."
                else "Advanced node setting $layer is unavailable or is not an object."
            }
        }
        val connectionPacketKeys = listOf("mtu", "udp-idle-timeout-ms", "max-pending-bytes", "max-total-pending-bytes", "fake-dns", "mapdns", "fake_dns")
        val applicationKeys = when (application) {
            "vmess" -> listOf("protocol", "proto", "first-payload-timeout-ms", "verbose", "domain-strategy", "security", "chunk-masking",
                "global-padding", "authenticated-length", "encrypted-counter-policy", "send-termination", "packet-encoding")
            "socks5" -> listOf("protocol", "proto", "verbose", "domain-strategy")
            "http-proxy" -> listOf("verbose", "domain-strategy", "headers", "max-header-bytes", "header-timeout-ms", "connect-response-timeout-ms", "idle-timeout-ms")
            else -> listOf("protocol", "proto", "first-payload-timeout-ms", "verbose", "domain-strategy")
        }
        val tlsKeys = listOf("alpns", "x25519mlkem768", "fragment", "tls13-record-shaping", "ech-config-list", "ech-sni-trick", "verbose")
        val schemas = mapOf(
            "packet" to if (raw) listOf("sensitive-mode", "interval-ms", "tolerance-ms", "packet-validation-level") else connectionPacketKeys,
            "application" to applicationKeys,
            "mux" to listOf("mode", "connection-duration-ms", "connection-capacity", "per-worker-connections-count", "keepalive", "ping-interval", "tolerance-ms",
                "parent-write-buffer-pause-threshold", "parent-write-buffer-resume-threshold", "parent-write-buffer-limit",
                "max-children", "child-buffer-limit", "child-buffer-resume-threshold", "parent-buffer-limit",
                "detached-buffer-limit", "detached-child-limit", "log-main-line-stats"),
            "http" to listOf("path", "scheme", "method", "user-agent", "http-version", "upgrade", "upgrade-protocol",
                "upgrade-request-headers", "upgrade-response-headers", "headers", "content-type",
                "websocket-origin", "websocket-subprotocol", "websocket-extensions", "http1-mode", "split", "verbose"),
            "obfuscator" to listOf("method", "xor_key", "skip", "tls_record_header", "tls_header"),
            "kcp" to listOf("send-mtu", "fec", "fec-data-shards", "fec-parity-shards", "kcp-nodelay", "kcp-interval-ms", "kcp-resend",
                "kcp-no-congestion-control", "kcp-send-window", "kcp-recv-window", "kcp-initial-cwnd", "kcp-rx-minrto-ms",
                "kcp-send-buffer-limit", "ping-interval-ms", "no-recv-timeout-ms"),
            "outer" to when (outer) {
                "tls" -> tlsKeys
                "reality" -> tlsKeys + listOf("algorithm", "method", "salt", "kdf-iterations")
                "aead" -> listOf("algorithm", "method", "salt", "kdf-iterations", "max-frame-size")
                "quic" -> listOf("ca-file", "protocol", "handshake-timeout-ms", "idle-timeout-ms", "max-packet-size", "max-buffered-bytes", "max-buffered-buffers", "receive-window-bytes", "verbose")
                else -> emptyList()
            },
        )
        for ((layer, settings) in nodeOptions) {
            val allowed = schemas[layer].orEmpty()
            for (key in settings.asObj()!!.keys) if (key !in allowed) return "Unsupported $layer setting: $key"
        }
        val packet = nodeOptions["packet"].asObj() ?: emptyMap()
        val app = nodeOptions["application"].asObj() ?: emptyMap()
        val muxOptions = nodeOptions["mux"].asObj() ?: emptyMap()
        val outerOptions = nodeOptions["outer"].asObj() ?: emptyMap()
        if (!booleans(packet, setOf("sensitive-mode", "enabled")) ||
            !booleans(app, setOf("verbose", "chunk-masking", "global-padding", "authenticated-length", "send-termination")) ||
            !booleans(muxOptions, setOf("log-main-line-stats", "keepalive")) ||
            !booleans(outerOptions, setOf("x25519mlkem768", "verbose"))) return "A boolean node setting has the wrong type."
        val ranges = listOf(
            Triple(packet, "mtu", 68L to 65535L), Triple(packet, "udp-idle-timeout-ms", 1L to 4294967295L),
            Triple(packet, "max-pending-bytes", 1024L to 67108864L), Triple(packet, "max-total-pending-bytes", 65536L to 67108864L),
            Triple(packet, "interval-ms", 1L to 4294967295L), Triple(packet, "tolerance-ms", 1L to 4294967295L),
            Triple(app, "first-payload-timeout-ms", 0L to 4294967295L),
            Triple(app, "max-header-bytes", 1024L to 65536L), Triple(app, "header-timeout-ms", 1L to 2147483647L),
            Triple(app, "connect-response-timeout-ms", 1L to 2147483647L), Triple(app, "idle-timeout-ms", 1L to 2147483647L),
            Triple(muxOptions, "connection-duration-ms", 61L to 4294967295L), Triple(muxOptions, "connection-capacity", 1L to 4294967295L),
            Triple(muxOptions, "per-worker-connections-count", 1L to 4294967295L), Triple(muxOptions, "max-children", 1L to 4294967295L),
            Triple(muxOptions, "ping-interval", 1L to 2147483647L), Triple(muxOptions, "tolerance-ms", 1L to 2147483647L),
            Triple(muxOptions, "parent-write-buffer-pause-threshold", 1L to 2147483647L), Triple(muxOptions, "parent-write-buffer-resume-threshold", 0L to 2147483647L),
            Triple(muxOptions, "parent-write-buffer-limit", 1L to 2147483647L), Triple(muxOptions, "child-buffer-limit", 1L to 2147483647L),
            Triple(muxOptions, "child-buffer-resume-threshold", 1L to 2147483647L), Triple(muxOptions, "parent-buffer-limit", 0L to 2147483647L),
            Triple(muxOptions, "detached-buffer-limit", 0L to 2147483647L), Triple(muxOptions, "detached-child-limit", 0L to 2147483647L),
            Triple(outerOptions, "kdf-iterations", 1L to 1000000L), Triple(outerOptions, "max-frame-size", 1L to 16356L),
            Triple(outerOptions, "handshake-timeout-ms", 1L to 86400000L), Triple(outerOptions, "idle-timeout-ms", 1L to 86400000L),
            Triple(outerOptions, "max-packet-size", 1200L to 1452L), Triple(outerOptions, "max-buffered-bytes", 65536L to 67108864L),
            Triple(outerOptions, "max-buffered-buffers", 1L to 65536L), Triple(outerOptions, "receive-window-bytes", 16384L to 16777216L),
        )
        for ((settings, key, limits) in ranges) {
            if (settings[key] != null && !inRange(settings, key, limits.first, limits.second)) return "$key has an invalid value or range."
        }
        val muxMode = muxOptions["mode"]
        if (muxMode != null && muxMode !is String) return "MUX mode must be a string."
        if (lengthOf(muxMode) > 0 && muxMode !in listOf("timer", "counter", "fixed-connections-count")) return "MUX mode is invalid."
        val effectiveMuxMode = if (lengthOf(muxMode) > 0) muxMode as String else "counter"
        if (effectiveMuxMode == "timer") {
            if (muxOptions["connection-duration-ms"] == null) return "MUX timer mode requires connection-duration-ms."
            if (muxOptions["connection-capacity"] != null || muxOptions["per-worker-connections-count"] != null) return "MUX timer mode accepts duration only, not capacity or fixed-count settings."
        } else if (effectiveMuxMode == "fixed-connections-count") {
            if (muxOptions["per-worker-connections-count"] == null) return "MUX fixed-connections-count mode requires per-worker-connections-count."
            if (muxOptions["connection-duration-ms"] != null || muxOptions["connection-capacity"] != null) return "MUX fixed mode accepts fixed-count settings only."
        } else if (muxOptions["connection-duration-ms"] != null || muxOptions["per-worker-connections-count"] != null) {
            return "MUX counter mode accepts capacity only, not duration or fixed-count settings."
        }
        val resume = longOf(muxOptions["parent-write-buffer-resume-threshold"]).takeIf { it != 0L } ?: 1048576L
        val pause = longOf(muxOptions["parent-write-buffer-pause-threshold"]).takeIf { it != 0L } ?: 8388608L
        val limit = longOf(muxOptions["parent-write-buffer-limit"]).takeIf { it != 0L } ?: 16777216L
        if (!(resume < pause && pause < limit)) return "MUX buffer thresholds must satisfy resume < pause < limit."

        val validationLevel = packet["packet-validation-level"]
        if (validationLevel != null) {
            if (validationLevel !is String) return "packet-validation-level must be a string."
            if (validationLevel !in listOf("none", "loose", "hard")) return "packet-validation-level must be none, loose or hard."
        }
        var fakeDnsCount = 0
        for (key in listOf("fake-dns", "mapdns", "fake_dns")) {
            if (packet[key] == null) continue
            fakeDnsCount += 1
            fakeDnsError(key, packet[key])?.let { return it }
        }
        if (fakeDnsCount > 1) return "fake-dns, mapdns and fake_dns are mutually exclusive aliases."
        val applicationProtocols = listOf("tcp", "connect", "udp", "udp-associate", "dest_context->protocol", "line->dest_ctx->protocol")
        for (key in listOf("protocol", "proto")) {
            if (app[key] == null) continue
            if (app[key] !is String) return "application.$key must be a string."
            if (app[key] !in applicationProtocols) return "application.$key has an unsupported protocol."
        }
        val strategy = app["domain-strategy"]
        if (strategy != null) {
            if (strategy !is String) return "application.domain-strategy must be a string."
            val strategies = listOf("do-not-resolve-domains", "resolve-domains-and-prefer-ipv4", "resolve-domains-and-prefer-ipv6",
                "resolve-domains-with-core-settings", "resolve-domains-and-accept-dns-returned-order",
                "resolve-domains-and-use-only-ipv4", "resolve-domains-and-use-only-ipv6")
            if (strategy !in strategies) return "application.domain-strategy is invalid."
        }
        if (app["headers"] != null) {
            stringMapError(app["headers"], "application.headers")?.let { return it }
            val forbidden = setOf("host", "proxy-authorization", "content-length", "transfer-encoding", "connection", "proxy-connection", "keep-alive", "te", "trailer", "upgrade", "expect")
            val token = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            for ((name, value) in app["headers"].asObj()!!) {
                if (name.isEmpty() || name.lowercase() in forbidden || name.any { it !in token }) return "HTTP proxy contains an invalid or reserved header name."
                if ((value as String).any { (it.code < 32 && it.code != 9) || it.code == 127 }) return "HTTP proxy header values cannot contain control characters."
            }
        }
        if (application == "vmess") {
            val security = if (app["security"] != null) app["security"] else "aes-128-gcm"
            if (security !is String || security !in listOf("aes-128-gcm", "chacha20-poly1305", "auto", "none", "zero")) {
                return "VMess security must be aes-128-gcm, chacha20-poly1305, auto, none or zero."
            }
            if (app["encrypted-counter-policy"] != null && app["encrypted-counter-policy"] !in listOf("wrap", "strict")) {
                return "VMess encrypted-counter-policy must be wrap or strict."
            }
            if (app["packet-encoding"] != null && app["packet-encoding"] !in listOf("none", "packetaddr")) {
                return "VMess packet-encoding must be none or packetaddr."
            }
            val protocol = app["protocol"] ?: app["proto"] ?: "dest_context->protocol"
            if (security == "zero" && protocol != "tcp" && protocol != "connect") {
                return "VMess zero supports TCP only; select a fixed TCP protocol or an encrypted security mode."
            }
            if (boolOf(app["global-padding"]) && app["chunk-masking"] != null && !boolOf(app["chunk-masking"])) {
                return "VMess global-padding requires chunk-masking."
            }
            if (boolOf(app["authenticated-length"]) && (security == "none" || security == "zero")) {
                return "VMess authenticated-length requires an encrypted security mode."
            }
            if (security == "zero" && (boolOf(app["chunk-masking"]) || boolOf(app["global-padding"]) || boolOf(app["authenticated-length"]))) {
                return "VMess zero cannot enable masking, padding or authenticated lengths."
            }
            if (app["packet-encoding"] == "packetaddr" && (app["domain-strategy"] == null || app["domain-strategy"] == "do-not-resolve-domains")) {
                return "VMess packetaddr requires local DNS resolution so the target is an IP address."
            }
        }
        for (key in listOf("algorithm", "method", "salt", "ech-config-list", "ech-sni-trick", "ca-file")) {
            if (outerOptions[key] != null && (outerOptions[key] !is String || lengthOf(outerOptions[key]) == 0)) return "$key must be a nonempty string."
        }
        if (outerOptions["salt"] != null && (outerOptions["salt"] as String).utf8Size() > 32) return "salt must contain 1 to 32 UTF-8 bytes."
        if (outer == "reality" || outer == "aead") {
            val algorithms = if (outer == "reality") listOf("chacha20-poly1305", "chacha20poly1305", "aes-gcm", "aes-256-gcm", "aes256gcm")
            else listOf("chacha20-poly1305", "chacha20poly1305", "chacha20", "chacha", "aes-gcm", "aes256gcm", "aes-256-gcm", "aes256-gcm")
            for (key in listOf("algorithm", "method")) {
                if (outerOptions[key] != null && outerOptions[key] !in algorithms) return "$outer.$key is unsupported."
            }
        }
        if (outerOptions["ech-config-list"] != null && outerOptions["ech-sni-trick"] != null) return "ech-config-list and ech-sni-trick cannot be used together."
        if (http != "off" && (outer == "tls" || outer == "reality") && outerOptions["alpns"] != null) {
            return "outer.alpns is builder-owned when HTTP is enabled with TLS or Reality."
        }
        if (outerOptions["alpns"] != null) alpnError(outerOptions["alpns"])?.let { return it }
        if (outerOptions["fragment"] != null) fragmentError(outerOptions["fragment"])?.let { return it }
        if (outerOptions["tls13-record-shaping"] != null) tls13Error(outerOptions["tls13-record-shaping"], outer == "reality")?.let { return it }
        if (outerOptions["protocol"] != null && outerOptions["protocol"] !is String) return "QUIC protocol must be a string."
        if (outerOptions["protocol"] != null && lengthOf(outerOptions["protocol"]) == 0) return "QUIC protocol cannot be empty."
        if (outer == "quic") {
            val quicByteBudget = if (outerOptions["max-buffered-bytes"] != null) longOf(outerOptions["max-buffered-bytes"]) else 2097152
            val quicBufferCount = if (outerOptions["max-buffered-buffers"] != null) longOf(outerOptions["max-buffered-buffers"]) else 1024
            val receiveWindow = if (outerOptions["receive-window-bytes"] != null) longOf(outerOptions["receive-window-bytes"]) else 1048576
            if (receiveWindow > quicByteBudget) return "QUIC receive-window-bytes cannot exceed max-buffered-bytes."
            if ((quicBufferCount + 1) * 24 > quicByteBudget) return "QUIC buffer entry count does not fit its byte budget."
        }
        nodeOptions["http"].asObj()?.let { settings ->
            httpError(settings, outer == "tls" || outer == "reality", http, configuration["http-version"])?.let { return it }
        }
        nodeOptions["obfuscator"].asObj()?.let { settings ->
            obfuscatorError(settings)?.let { return it }
            // The server re-derives each skip from its own buffer boundaries, which a connection stream does not keep.
            val skip = settings["skip"]
            if (!raw && skip != null && skip != "none") return "obfuscator.skip must be none for connection input."
        }
        nodeOptions["kcp"].asObj()?.let { settings -> kcpError(settings)?.let { return it } }
        return null
    }

    private fun isPlainHttps(value: String): Boolean = try {
        val uri = URI(value)
        uri.scheme?.lowercase() == "https" && !uri.host.isNullOrEmpty() && uri.userInfo == null && uri.fragment == null
    } catch (_: Exception) {
        false
    }

    /** The checks of an HTTPS link for a database update, used by the GeoIP downloader too. */
    fun isValidHttpsLink(value: String): Boolean =
        value.isNotEmpty() && value.length <= 2048 && value == value.trim() && isPlainHttps(value)

    fun applicationSecretError(secret: Any?, configuration: Map<String, Any?>): String? {
        if (!needsApplicationSecret(configuration)) return null
        val application = configuration["application"]
        if (application == "socks5" || application == "http-proxy") return null
        val vless = application == "vless"
        val vmess = application == "vmess"
        val name = if (vless) "VLESS UUID" else if (vmess) "VMess UUID or ID" else "Trojan password"
        if (secret !is String) return "$name must be a string."
        if (vless && !isUuid(secret)) return "Enter a valid VLESS UUID as dashed RFC4122 or 32 hexadecimal characters."
        if (vmess && !isUuid(secret) && secret.utf8Size() !in 1..30) return "Enter a VMess UUID or a short string ID of 1 to 30 UTF-8 bytes."
        if (!vless && !vmess && secret.isEmpty()) return "Enter the Trojan password."
        return null
    }

    fun applicationUsernameError(username: String?, secret: String?, configuration: Map<String, Any?>): String? {
        val application = configuration["application"]
        val socks = application == "socks5"
        val httpProxy = application == "http-proxy"
        if (!socks && !httpProxy) return null
        if (username.isNullOrEmpty() && secret.isNullOrEmpty()) return null
        if (username.isNullOrEmpty() || secret.isNullOrEmpty()) return "Proxy username and password must be supplied together, or both left empty."
        if (username.utf8Size() > 255 || secret.utf8Size() > 255) return "Proxy username and password must each contain at most 255 UTF-8 bytes."
        if (httpProxy) {
            if (':' in username) return "HTTP proxy username cannot contain a colon."
            if ((username + secret).any { it.code < 32 || it.code == 127 }) return "HTTP proxy credentials cannot contain control characters."
        }
        return null
    }

    fun outerSecretError(secret: Any?, configuration: Map<String, Any?>): String? {
        if (!needsOuterSecret(configuration)) return null
        val reality = configuration["outer"] == "reality"
        val packet = boolOf(configuration["packet-encryption"])
        val name = if (reality) "Reality password" else if (packet) "Packet encryption password" else "AEAD password"
        if (secret !is String) return "$name must be a string."
        if (reality && secret.utf8Size() !in 1..32) return "Reality password must contain 1 to 32 UTF-8 bytes."
        if (!reality && secret.isEmpty()) return if (packet) "Enter the packet encryption password." else "Enter the AEAD password."
        return null
    }

    private fun merged(defaults: Map<String, Any?>, overrides: Obj?, required: Map<String, Any?>): LinkedHashMap<String, Any?> =
        LinkedHashMap(defaults).apply {
            putAll(overrides.orEmpty())
            putAll(required)
        }

    /** The node graph of a chain or direct profile, or null when the profile is not usable. */
    fun nodesJson(
        input: Map<String, Any?>,
        server: String?,
        port: Long,
        sni: String?,
        verifyTls: Boolean,
        secret: String?,
        outerSecret: String?,
        options: Map<String, Any?>?,
    ): String? {
        val configuration = migrate(input)
        if (validationError(configuration) != null || isWireGuard(configuration) || port !in 1..65535) return null
        if (!isDirect(configuration) && server.isNullOrEmpty()) return null
        if (applicationSecretError(secret, configuration) != null) return null
        if (applicationUsernameError(options?.get("username") as? String, secret, configuration) != null) return null
        if (outerSecretError(outerSecret, configuration) != null) return null
        val direct = isDirect(configuration)
        val raw = configuration["input"] == "raw-ipv4"
        val mux = boolOf(configuration["mux"])
        val outer = configuration["outer"] as? String
        val quic = outer == "quic"
        val hasOuter = outer != "none"
        val hasHttp = configuration["http"] != "off"
        val obfuscator = boolOf(configuration["obfuscator"])
        val kcp = configuration["carrier"] == "kcp"
        val application = configuration["application"] as? String
        // An empty SNI means the server, except for Reality, whose default cover is www.cloudflare.com
        val effectiveSni = if (!sni.isNullOrEmpty()) sni else if (outer == "reality") "www.cloudflare.com" else server
        val advanced = configuration["node-options"].asObj() ?: emptyMap()
        fun advancedOf(layer: String) = advanced[layer].asObj()
        val bgp4 = boolOf(configuration["bgp4"]) && outer != "bgp4"
        val afterBgp4 = if (hasOuter) outer else if (kcp) "kcp" else "connector"
        val afterHttp = if (bgp4) "bgp4" else afterBgp4
        val afterObfuscator = if (hasHttp) "http" else afterHttp
        val afterApplication = if (obfuscator) "obfuscator" else afterObfuscator
        val afterInput = if (raw) afterApplication else application
        fun node(name: String?, type: String, settings: Map<String, Any?>, next: String? = null): Map<String, Any?> =
            linkedMapOf<String, Any?>("name" to name, "type" to type, "settings" to settings).apply { if (next != null) put("next", next) }

        val packetEncryption = boolOf(configuration["packet-encryption"])
        val nodes = arrayListOf(node("ne", "NEPacketDevice", emptyMap(), if (direct || !raw) "ptc" else if (packetEncryption) "packet-encryption" else "pts"))
        if (direct || !raw) {
            val required = LinkedHashMap<String, Any?>()
            val fakeDnsOption = options?.get("ww_fake_dns")
            if ((fakeDnsOption == null || boolOf(fakeDnsOption)) && !direct) {
                required["fake-dns"] = linkedMapOf("enabled" to true, "address" to "198.18.0.2", "port" to 53L, "network" to "100.64.0.0",
                    "netmask" to "255.192.0.0", "cache-size" to 10000L, "ttl" to 60L)
            }
            val settings = merged(mapOf("mtu" to 1420L, "max-pending-bytes" to 65536L, "max-total-pending-bytes" to 16777216L), advancedOf("packet"), required)
            if (required["fake-dns"] != null) {
                settings.remove("mapdns")
                settings.remove("fake_dns")
            }
            nodes.add(node("ptc", "PacketsToConnection", settings, if (direct) "connector" else if (raw) afterInput else "router"))
        }
        if (direct) {
            nodes.add(node("connector", "TcpUdpConnector", mapOf("address" to "dest_context->address", "port" to "dest_context->port", "nodelay" to true)))
        } else {
            if (!raw) {
                val vmess = application == "vmess"
                val socks = application == "socks5"
                val httpProxy = application == "http-proxy"
                val defaults = linkedMapOf<String, Any?>("domain-strategy" to "do-not-resolve-domains")
                if (!httpProxy) defaults["protocol"] = "dest_context->protocol"
                if (vmess) defaults["security"] = "aes-128-gcm"
                if (httpProxy) defaults["mode"] = "connect"
                val required = linkedMapOf<String, Any?>((if (httpProxy) "target-address" else "address") to "dest_context->address", "port" to "dest_context->port")
                if (!socks && !httpProxy) required[if (application == "trojan") "password" else "uuid"] = secret
                val applicationSettings = merged(defaults, advancedOf("application"), required)
                val username = options?.get("username") as? String
                if ((socks || httpProxy) && !username.isNullOrEmpty()) {
                    applicationSettings[if (socks) "user" else "username"] = username
                    applicationSettings[if (socks) "pass" else "password"] = secret
                }
                if (advancedOf("application")?.get("protocol") == null && advancedOf("application")?.get("proto") != null) {
                    applicationSettings["protocol"] = advancedOf("application")!!["proto"]
                }
                val applicationType = when (application) {
                    "vless" -> "VlessClient"
                    "vmess" -> "VmessClient"
                    "trojan" -> "TrojanClient"
                    "socks5" -> "Socks5Client"
                    else -> "HttpProxyClient"
                }
                nodes.add(node(application, applicationType, applicationSettings, if (mux) "mux" else afterApplication))
                val directCountries = geoIpCountries(configuration["geoip"].asObj()?.get("countries")).orEmpty()
                val geoIpPath = options?.get("ww_geoip_db_path") as? String
                if (directCountries.isNotEmpty() && geoIpPath.isNullOrEmpty()) return null
                val routerSettings = linkedMapOf<String, Any?>("resolve-domains" to directCountries.isNotEmpty())
                val rules = ArrayList<Any?>()
                if (boolOf(options?.get("ww_smart_routing"))) {
                    rules.add(mapOf("destination-ip" to listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"), "target" to "direct-local"))
                }
                if (directCountries.isNotEmpty()) {
                    routerSettings["geoip-db-path"] = geoIpPath
                    for (country in directCountries) {
                        rules.add(mapOf("destination-ip" to listOf("geoip:" + country.lowercase()), "target" to "direct-local"))
                    }
                }
                if (rules.isNotEmpty()) routerSettings["rules"] = rules
                nodes.add(node("router", "Router", routerSettings, application))
                if (rules.isNotEmpty()) {
                    nodes.add(node("direct-local", "TcpUdpConnector", mapOf("address" to "dest_context->address", "port" to "dest_context->port",
                        "domain-strategy" to "prefer-ipv4", "nodelay" to true)))
                }
            } else {
                if (packetEncryption) {
                    nodes.add(node("packet-encryption", "EncryptionClient", linkedMapOf("packet-mode" to true, "algorithm" to "xchacha20-poly1305",
                        "password" to outerSecret, "salt" to "waterwall-packet", "kdf-iterations" to 12000L), "pts"))
                }
                nodes.add(node("pts", "PacketsToStream", merged(mapOf("packet-validation-level" to "hard"), advancedOf("packet"), emptyMap()), afterApplication))
            }
            if (mux) {
                val muxMode = (advancedOf("mux")?.get("mode") as? String)?.takeIf { it.isNotEmpty() } ?: "counter"
                val defaults = linkedMapOf<String, Any?>("mode" to muxMode, "max-children" to 256L,
                    "parent-write-buffer-pause-threshold" to 8388608L, "parent-write-buffer-resume-threshold" to 1048576L,
                    "parent-write-buffer-limit" to 16777216L, "child-buffer-limit" to 4194304L, "parent-buffer-limit" to 16777216L,
                    "detached-buffer-limit" to 4194304L, "detached-child-limit" to 128L)
                if (muxMode == "counter") defaults["connection-capacity"] = 128L
                nodes.add(node("mux", "MuxClient", merged(defaults, advancedOf("mux"), emptyMap()), afterApplication))
            }
            if (obfuscator) {
                nodes.add(node("obfuscator", "ObfuscatorClient", merged(mapOf("method" to "xor", "xor_key" to 90L, "skip" to "none"), advancedOf("obfuscator"), emptyMap()), afterObfuscator))
            }
            var httpVersion = 0
            val httpVersionValue = advancedOf("http")?.get("http-version") ?: configuration["http-version"]
            if (hasHttp) {
                httpVersion = httpVersionOf(httpVersionValue) ?: 0
                val scheme = if (outer == "tls" || outer == "reality") "https" else "http"
                val websocket = configuration["http"] == "websocket"
                val settings = merged(
                    mapOf("host" to effectiveSni, "path" to "/", "scheme" to scheme, "port" to port, "http-version" to httpVersionValue, "websocket" to websocket),
                    advancedOf("http"),
                    mapOf("host" to effectiveSni, "port" to port, "http-version" to httpVersionValue, "websocket" to websocket),
                )
                nodes.add(node("http", "HttpClient", settings, afterHttp))
            }
            if (bgp4) nodes.add(node("bgp4", "Bgp4Client", emptyMap(), afterBgp4))
            if (hasOuter) {
                var outerSettings = LinkedHashMap<String, Any?>()
                val tlsLike = outer == "tls" || outer == "reality" || quic
                if (tlsLike) {
                    outerSettings["sni"] = effectiveSni
                    outerSettings["verify"] = verifyTls
                }
                if (outer == "tls") outerSettings["alpns"] = listOf("http/1.1")
                if (outer == "reality") {
                    outerSettings["password"] = outerSecret
                    outerSettings["algorithm"] = "chacha20-poly1305"
                    outerSettings["salt"] = "waterwall-reality"
                    outerSettings["kdf-iterations"] = 12000L
                    outerSettings["verbose"] = options?.get("log_level") == "debug"
                } else if (outer == "aead") {
                    outerSettings["password"] = outerSecret
                    outerSettings["algorithm"] = "chacha20-poly1305"
                    outerSettings["salt"] = "waterwall-aead"
                    outerSettings["kdf-iterations"] = 12000L
                    outerSettings["max-frame-size"] = 16356L
                } else if (quic) {
                    outerSettings["protocol"] = "h3"
                    outerSettings["carrier-mode"] = configuration["quic-carrier"]
                }
                val tlsFragment = longOf(options?.get("tls_frag"))
                if (tlsFragment > 0 && allowsFragmentation(configuration)) {
                    // Auto uses the default sizes; only Manual takes the profile's
                    val manual = tlsFragment == 2L
                    val firstCut = if (manual) max(1L, longOf(options?.get("tls_frag_first")).takeIf { it != 0L } ?: 32L) else 32L
                    val following = if (manual) max(1L, longOf(options?.get("tls_frag_following")).takeIf { it != 0L } ?: 256L) else 256L
                    val cuts = ArrayList<Any?>()
                    var offset = firstCut
                    while (offset < 16384 && cuts.size < 64) {
                        cuts.add(listOf(offset, 0L, 100L))
                        offset += following
                    }
                    outerSettings["fragment"] = linkedMapOf("mode" to "counter", "count" to 1L, "tls-hello-fragment" to true, "tls-hello-timeout-ms" to 1000L, "cuts" to cuts)
                }
                outerSettings = merged(outerSettings, advancedOf("outer"), emptyMap())
                if (advancedOf("outer")?.get("algorithm") == null && advancedOf("outer")?.get("method") != null) {
                    outerSettings["algorithm"] = advancedOf("outer")!!["method"]
                }
                if (tlsLike) {
                    outerSettings["sni"] = effectiveSni
                    outerSettings["verify"] = verifyTls
                }
                if (hasHttp && httpVersion > 0 && (outer == "tls" || outer == "reality")) {
                    outerSettings["alpns"] = listOf(if (httpVersion == 1) "http/1.1" else "h2")
                }
                if (outer == "reality" || outer == "aead") outerSettings["password"] = outerSecret
                if (quic) outerSettings["carrier-mode"] = configuration["quic-carrier"]
                val outerType = when (outer) {
                    "tls" -> "TlsClient"
                    "reality" -> "RealityClient"
                    "aead" -> "EncryptionClient"
                    "bgp4" -> "Bgp4Client"
                    else -> "QuicClient"
                }
                nodes.add(node(outer, outerType, outerSettings, if (kcp) "kcp" else "connector"))
            }
            if (kcp) {
                val defaults = mapOf("kcp-send-window" to 128L, "kcp-recv-window" to 128L, "kcp-initial-cwnd" to 16L, "kcp-send-buffer-limit" to 512L)
                nodes.add(node("kcp", "TcpOverUdpClient", merged(defaults, advancedOf("kcp"), emptyMap()), "connector"))
            }
            val applicationProtocol = advancedOf("application")?.get("protocol") ?: advancedOf("application")?.get("proto")
            val fixedApplicationProtocol = applicationProtocol in listOf("tcp", "connect", "udp", "udp-associate")
            val dynamicTcpUdp = !raw && !mux && !hasHttp && outer == "tls" && application != "http-proxy" && !fixedApplicationProtocol
            val connectorType = when {
                application == "socks5" -> "TcpUdpConnector"
                kcp -> "UdpConnector"
                quic -> if (configuration["quic-carrier"] == "stream") "TcpConnector" else "UdpConnector"
                dynamicTcpUdp -> "TcpUdpConnector"
                else -> "TcpConnector"
            }
            nodes.add(node("connector", connectorType, mapOf("address" to server, "port" to port, "nodelay" to true)))
        }
        return Json.write(linkedMapOf("name" to summary(configuration), "nodes" to nodes))
    }

    /** The node graph and tunnel settings of a wg-quick configuration, or null when it is not usable. */
    fun wireGuardWithConfig(config: String?): WireGuard? {
        if (config.isNullOrEmpty()) return null
        var section: LinkedHashMap<String, String>? = null
        var iface: LinkedHashMap<String, String>? = null
        val peerValues = ArrayList<LinkedHashMap<String, String>>()
        for (line in config.split(Regex("[\\n\\r\\u000B\\u000C\\u0085\\u2028\\u2029]"))) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith(";")) continue
            if (trimmed.startsWith("[")) {
                if (!trimmed.endsWith("]")) return null
                when (trimmed.substring(1, trimmed.length - 1).lowercase()) {
                    "interface" -> {
                        if (iface != null) return null
                        iface = LinkedHashMap()
                        section = iface
                    }
                    "peer" -> {
                        if (peerValues.size >= 32) return null
                        section = LinkedHashMap()
                        peerValues.add(section)
                    }
                    else -> return null
                }
                continue
            }
            val separator = trimmed.indexOf('=')
            if (section == null || separator < 0) return null
            val key = trimmed.substring(0, separator).trim().lowercase()
            if (key.isEmpty()) return null
            section[key] = trimmed.substring(separator + 1).trim()
        }
        val privateKey = iface?.get("privatekey")
        val address = iface?.get("address")
        if (privateKey.isNullOrEmpty() || address.isNullOrEmpty() || peerValues.isEmpty()) return null
        val peers = ArrayList<Any?>()
        val allowedIpParts = ArrayList<String>()
        val endpointIps = ArrayList<String>()
        for (values in peerValues) {
            val publicKey = values["publickey"]
            val (server, _) = (if (publicKey.isNullOrEmpty()) null else endpointOf(values["endpoint"])) ?: return null
            var keepalive = 0L
            if (values["persistentkeepalive"] != null) keepalive = nonnegativeIntegerString(values["persistentkeepalive"]) ?: return null
            val allowedIps = values["allowedips"]?.takeIf { it.isNotEmpty() } ?: "0.0.0.0/0"
            val peer = linkedMapOf<String, Any?>("publickey" to publicKey, "allowedips" to allowedIps, "endpoint" to values["endpoint"], "persistentkeepalive" to keepalive)
            if (!values["presharedkey"].isNullOrEmpty()) peer["presharedkey"] = values["presharedkey"]
            peers.add(peer)
            allowedIpParts.add(allowedIps)
            endpointIps.add(server)
        }
        val nodes = listOf(
            linkedMapOf("name" to "udp", "type" to "UdpStatelessSocket", "settings" to mapOf("listen-address" to "0.0.0.0", "listen-port" to 0L, "verbose" to true), "next" to "wg"),
            linkedMapOf("name" to "wg", "type" to "WireGuardDevice", "settings" to mapOf("privatekey" to privateKey, "peers" to peers), "next" to "ne"),
            linkedMapOf("name" to "ne", "type" to "NEPacketDevice", "settings" to emptyMap<String, Any?>()),
        )
        val dnsServers = iface?.get("dns").orEmpty().split(",").map { it.trim() }.filter { it.isNotEmpty() }
        return WireGuard(
            nodesJson = Json.write(linkedMapOf("name" to "wireguard", "nodes" to nodes)),
            tunnelAddress = address.substringBefore('/'),
            allowedIps = allowedIpParts.joinToString(", "),
            dnsServers = dnsServers.ifEmpty { listOf("1.1.1.1", "1.0.0.1") },
            endpointIp = endpointIps.first(),
            endpointIps = endpointIps,
        )
    }

    /** Manual fields without a generated config, the way iOS keeps this builder for profiles missing an effective config. */
    fun wireGuardWithKeys(privateKey: String, serverPublicKey: String, server: String, port: Long, clientAddress: String, keepalive: Long): WireGuard? {
        if (privateKey.isEmpty() || serverPublicKey.isEmpty() || server.isEmpty() || clientAddress.isEmpty() ||
            port !in 1..65535 || keepalive !in 0..65535) return null
        val nodes = listOf(
            linkedMapOf("name" to "udp", "type" to "UdpStatelessSocket", "settings" to mapOf("listen-address" to "0.0.0.0", "listen-port" to 0L, "verbose" to true), "next" to "wg"),
            linkedMapOf("name" to "wg", "type" to "WireGuardDevice", "settings" to mapOf("privatekey" to privateKey,
                "peers" to listOf(mapOf("publickey" to serverPublicKey, "allowedips" to "0.0.0.0/0", "endpoint" to "$server:$port", "persistentkeepalive" to max(0L, keepalive)))), "next" to "ne"),
            linkedMapOf("name" to "ne", "type" to "NEPacketDevice", "settings" to emptyMap<String, Any?>()),
        )
        return WireGuard(
            nodesJson = Json.write(linkedMapOf("name" to "wireguard", "nodes" to nodes)),
            tunnelAddress = clientAddress.substringBefore('/'),
            allowedIps = "0.0.0.0/0",
            dnsServers = listOf("1.1.1.1", "1.0.0.1"),
            endpointIp = server,
            endpointIps = null,
        )
    }
}
