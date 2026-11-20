package tr.com.srp.vpn

private typealias Node = Map<String, Any?>

/**
 * A WaterWall profile as the node editor keeps it, SRPWaterWallNodeChain of SRPWaterWallChainConfig.m: a WaterWall JSON document
 * ({"name", "nodes"}) whose chain starts with an input hint, HintConnectionIN or HintPacketIN, in place of the input SRP supplies
 * when it connects. Every message and rule matches iOS; ChainConfigParityTest compares them.
 */
object NodeChain {
    /** Settings → WaterWall Input, one choice for every profile */
    const val INPUT_TUN = "tun"
    const val INPUT_SOCKS5 = "socks5"
    const val INPUT_HTTP = "http"
    const val HINT_CONNECTION = "HintConnectionIN"
    const val HINT_PACKET = "HintPacketIN"

    /** The node types WaterWall/CMakeLists.txt builds into the app, apart from the input SRP supplies itself */
    private val INCLUDED = setOf(
        "AuthenticationClient", "Bgp4Client", "DomainResolver", "EncryptionClient", "HttpClient", "HttpProxyClient", "HttpProxyServer",
        "KcpClient", "MuxClient", "ObfuscatorClient", "PacketsToStream", "QuicClient", "RealityClient", "Router", "Socks5Client",
        "Socks5Server", "StreamFragmenter", "TcpConnector", "TcpListener", "TcpUdpConnector", "TcpUdpListener", "TlsClient", "TrojanClient",
        "UdpConnector", "UdpListener", "UdpStatelessSocket", "UserController", "VlessClient", "VmessClient", "WireGuardDevice",
    )
    private val CONNECTORS = setOf("TcpConnector", "UdpConnector", "TcpUdpConnector")

    /** The stored input: anything but the two local proxies reads as System VPN */
    fun inputOf(stored: String?): String = if (stored == INPUT_SOCKS5 || stored == INPUT_HTTP) stored else INPUT_TUN

    /** The 127.0.0.1 port of a local proxy input, 0 for System VPN */
    fun portForInput(input: String) = when (input) {
        INPUT_SOCKS5 -> 1080
        INPUT_HTTP -> 8080
        else -> 0
    }

    fun isHint(type: Any?) = type == HINT_CONNECTION || type == HINT_PACKET

    @Suppress("UNCHECKED_CAST")
    private fun nodesOf(document: Any?): List<Node> =
        ((document as? Map<*, *>)?.get("nodes") as? List<*>).orEmpty().filterIsInstance<Map<*, *>>() as List<Node>

    private fun withNodes(document: Map<String, Any?>, nodes: List<Node>): Map<String, Any?> = LinkedHashMap(document).apply { put("nodes", nodes) }

    /** The node with this next, or without one when [next] is null, as an NSMutableDictionary takes a nil value */
    private fun withNext(node: Node, next: Any?): Node = LinkedHashMap(node).apply { if (next == null) remove("next") else put("next", next) }

    /** A file or saved profile, checked as an import is: the document, or null and the reason naming the node or reference at fault */
    fun documentWithJson(json: String?): Pair<Map<String, Any?>?, String?> {
        // NSJSONSerialization reads an object or an array, never a bare value
        val document = Json.parseOrNull(json)?.takeIf { it is Map<*, *> || it is List<*> }
        val problem = if (document == null) "The file is not valid JSON." else validationError(document)
        @Suppress("UNCHECKED_CAST")
        return if (problem != null) null to problem else document as Map<String, Any?> to null
    }

    /** The checks of an import, on a document an edit made; null when it may be kept */
    fun validationError(document: Any?): String? {
        val nodes = (document as? Map<*, *>)?.get("nodes") as? List<*> ?: return "The file is not a WaterWall profile: it has no \"nodes\" list."
        // A node SRP does not run blocks the file whatever else is in it, wherever it is
        for ((index, item) in nodes.withIndex()) {
            val node = item as? Map<*, *> ?: continue
            val type = node["type"] as? String ?: continue
            val name = node["name"] as? String
            val label = if (!name.isNullOrEmpty()) "Node \"$name\"" else "Node ${index + 1}"
            if (type == "RawSocket") return "$label is a RawSocket node: raw socket nodes cannot be imported."
            if (type == "TunDevice" || type == "PacketsToConnection" || type == "NEPacketDevice") {
                return "$label is a $type node: SRP supplies TunDevice and PacketsToConnection itself when it connects, so leave them out of the profile."
            }
        }
        val byName = HashMap<String, Map<*, *>>()
        val hints = ArrayList<Map<*, *>>()
        for ((index, item) in nodes.withIndex()) {
            val node = item as? Map<*, *> ?: return "Node ${index + 1} is not a JSON object."
            val name = (node["name"] as? String)?.takeIf { it.isNotEmpty() } ?: return "Node ${index + 1} has no name."
            if ((node["type"] as? String).isNullOrEmpty()) return "Node \"$name\" has no type."
            if (node["settings"] != null && node["settings"] !is Map<*, *>) return "The settings of node \"$name\" are not a JSON object."
            val next = node["next"]
            if (next != null && (next !is String || next.isEmpty())) return "The next of node \"$name\" is not a node name."
            if (name in byName) return "Two nodes are named \"$name\": every node needs a name of its own."
            byName[name] = node
            if (isHint(node["type"])) hints.add(node)
        }
        if (hints.isEmpty()) return "The chain must start with an input hint: HintConnectionIN or HintPacketIN."
        if (hints.size > 1) return "The profile has more than one input hint (\"${hints[0]["name"]}\" and \"${hints[1]["name"]}\"); it needs exactly one."
        val hint = hints[0]
        val hintName = hint["name"] as String
        if ((hint["settings"] as? Map<*, *>).orEmpty().isNotEmpty()) return "The input hint \"$hintName\" has settings, but a hint takes none."
        for (item in nodes) {
            val node = item as Map<*, *>
            if (node["next"] == hintName) return "Node \"${node["name"]}\" points to the input hint \"$hintName\", which must start the chain."
        }
        if (hint["next"] == null) return "The input hint \"$hintName\" has no next node: import a WaterWall profile or insert a node after it."
        val seen = hashSetOf(hintName)
        var node = hint
        while (node["next"] != null) {
            val next = node["next"] as String
            val successor = byName[next] ?: return "Node \"${node["name"]}\" names \"$next\" as next, but no node has that name."
            if (!seen.add(next)) return "Following next from \"${node["name"]}\" comes back to \"$next\": the chain has a cycle."
            node = successor
        }
        return null
    }

    fun json(document: Map<String, Any?>): String = Json.write(document, sortedKeys = true)

    /** A new profile's document: the connection hint alone, until a file is imported or nodes are inserted */
    fun emptyDocument(): Map<String, Any?> =
        linkedMapOf("nodes" to listOf(linkedMapOf("name" to "input", "type" to HINT_CONNECTION, "settings" to LinkedHashMap<String, Any?>())))

    val emptyJson: String get() = json(emptyDocument())

    fun hint(document: Any?): Node? = nodesOf(document).firstOrNull { isHint(it["type"]) }

    /** The nodes from the hint along each next, in the order the chain runs (a missing node or a cycle ends the list) */
    fun chain(document: Any?): List<Node> {
        val nodes = nodesOf(document)
        // Nothing to follow: the file's order
        val hint = nodes.firstOrNull { isHint(it["type"]) } ?: return nodes
        val byName = HashMap<String, Node>()
        for (node in nodes) (node["name"] as? String)?.let { byName.putIfAbsent(it, node) }
        val chain = arrayListOf(hint)
        val seen = hashSetOf(hint["name"] ?: "")
        var node = hint
        while (true) {
            val next = node["next"] as? String ?: break
            val successor = byName[next]
            if (successor == null || !seen.add(next)) break
            chain.add(successor)
            node = successor
        }
        return chain
    }

    /** The document's name, or the node types along the chain */
    fun summary(document: Any?): String {
        ((document as? Map<*, *>)?.get("name") as? String)?.takeIf { it.isNotEmpty() }?.let { return it }
        val types = chain(document).mapNotNull { node -> (node["type"] as? String)?.takeIf { !isHint(it) } }
        return if (types.isNotEmpty()) types.joinToString(" → ") else "No nodes"
    }

    /** The editor's changes; each returns the new document, which the caller checks before keeping it */
    fun replacingNode(document: Map<String, Any?>, name: String, node: Node): Map<String, Any?> {
        val newName = node["name"]
        return withNodes(document, nodesOf(document).map { item ->
            when {
                item["name"] == name -> node
                // A rename keeps the link that pointed to the old name
                newName != name && item["next"] == name -> withNext(item, newName)
                else -> item
            }
        })
    }

    fun insertingNode(document: Map<String, Any?>, node: Node, after: String): Map<String, Any?> {
        val nodes = ArrayList<Node>()
        for (item in nodesOf(document)) {
            if (item["name"] != after) {
                nodes.add(item)
                continue
            }
            // The new node takes over the former successor; after the last node it becomes the last one
            val inserted = withNext(node, item["next"])
            nodes.add(withNext(item, inserted["name"]))
            nodes.add(inserted)
        }
        return withNodes(document, nodes)
    }

    fun deletingNode(document: Map<String, Any?>, name: String): Map<String, Any?> {
        val deleted = nodesOf(document).lastOrNull { it["name"] == name }
        // The predecessor links to the successor, or becomes the last node
        return withNodes(document, nodesOf(document).filter { it["name"] != name }.map { if (it["next"] == name) withNext(it, deleted?.get("next")) else it })
    }

    /** A connector's own server, not the destination of the connection it carries */
    private fun fixedAddress(node: Node): String? {
        val address = (node["settings"] as? Map<*, *>)?.get("address") as? String
        return if (node["type"] !in CONNECTORS || address.isNullOrEmpty() || address.startsWith("dest_context")) null else address
    }

    /** NSString and NSNumber integerValue: a number truncated, true as 1, a string's leading decimal digits after spaces and tabs */
    private fun integerValue(value: Any?): Long = when (value) {
        is Boolean -> if (value) 1 else 0
        is Number -> value.toLong()
        is String -> {
            val text = value.trimStart(' ', '\t')
            val negative = text.startsWith("-")
            var number = 0L
            // Beyond any port, so a longer number stays out of range instead of wrapping around
            for (character in text.drop(if (negative || text.startsWith("+")) 1 else 0)) {
                if (character !in '0'..'9' || number > 1_000_000_000_000L) break
                number = number * 10 + (character - '0')
            }
            if (negative) -number else number
        }
        else -> 0
    }

    /** The fixed server endpoints of the profile's connectors as host and port, the chain's last node first */
    fun endpoints(document: Any?): List<Pair<String, Int>> {
        val ordered = ArrayList(chain(document).asReversed())
        for (node in nodesOf(document)) if (node !in ordered) ordered.add(node)
        return ordered.mapNotNull { node ->
            val host = fixedAddress(node)
            val port = integerValue((node["settings"] as? Map<*, *>)?.get("port"))
            if (host == null || port !in 1..65535) null else host to port.toInt()
        }
    }

    private fun routerUsesGeoIp(node: Node): Boolean {
        if (node["type"] != "Router") return false
        val rules = (node["settings"] as? Map<*, *>)?.get("rules") as? List<*> ?: return false
        return rules.any { rule ->
            val destinations = (rule as? Map<*, *>)?.get("destination-ip")
            (destinations as? List<*> ?: listOfNotNull(destinations)).any { it is String && it.lowercase().startsWith("geoip:") }
        }
    }

    fun usesGeoIp(document: Any?) = nodesOf(document).any { routerUsesGeoIp(it) }

    /** The chain reaches its server over UDP (it ends in a UDP connector) */
    fun usesUdpCarrier(document: Any?) = chain(document).lastOrNull()?.get("type").let { it == "UdpConnector" || it == "UdpStatelessSocket" }

    private fun node(name: String, type: String, settings: Map<String, Any?>, next: Any?): Node =
        linkedMapOf("name" to name, "type" to type, "settings" to settings, "next" to next)

    /**
     * What WaterWall runs: the hint replaced by the input SRP supplies, linked to the hint's successor; the GeoIP database set on the
     * Routers that need it; each fixed server name of a connector replaced by its address from [addresses]. Null and the reason when
     * the profile cannot run with this input.
     */
    fun runtimeDocument(document: Map<String, Any?>, input: String, fakeDns: Boolean, geoIpDatabasePath: String?,
                        addresses: Map<String, String>): Pair<Map<String, Any?>?, String?> {
        val hint = hint(document)
        val packets = hint?.get("type") == HINT_PACKET
        val unknown = nodesOf(document).firstOrNull { it !== hint && it["type"] !in INCLUDED }
        val problem = validationError(document)
            ?: (if (packets && input != INPUT_TUN) "This profile starts with HintPacketIN, which takes IP packets, but the local SOCKS5 and HTTP proxies supply connections. Choose System VPN (TUN) in Settings → WaterWall Input to use it." else null)
            // Another type would only fail and be retried when the runtime starts
            ?: unknown?.let { "Node \"${it["name"]}\" is a ${it["type"]} node, which the app's WaterWall does not include." }
            ?: (if (usesGeoIp(document) && geoIpDatabasePath.isNullOrEmpty()) "The profile routes by country, but the GeoIP database is not available." else null)
        if (problem != null) return null to problem
        val names = nodesOf(document).map { it["name"] }.toHashSet<Any?>()
        fun unique(base: String): String {
            var name = base
            var suffix = 2
            while (name in names) name = "$base-${suffix++}"
            names.add(name)
            return name
        }
        val successor = hint!!["next"]
        val nodes = ArrayList<Node>()
        when {
            input == INPUT_SOCKS5 -> {
                val server = unique("srp-socks5")
                nodes.add(node(unique("srp-socks5-listener"), "TcpUdpListener", linkedMapOf("address" to "127.0.0.1", "port" to 1080L, "nodelay" to true), server))
                nodes.add(node(server, "Socks5Server", linkedMapOf("no-auth" to true, "connect" to true, "udp" to true, "ipv4" to "127.0.0.1"), successor))
            }
            input == INPUT_HTTP -> {
                val server = unique("srp-http-proxy")
                nodes.add(node(unique("srp-http-listener"), "TcpListener", linkedMapOf("address" to "127.0.0.1", "port" to 8080L, "nodelay" to true), server))
                nodes.add(node(server, "HttpProxyServer", linkedMapOf("no-auth" to true), successor))
            }
            packets -> nodes.add(node(unique("srp-device"), "NEPacketDevice", LinkedHashMap(), successor))
            else -> {
                val connections = unique("srp-connections")
                nodes.add(node(unique("srp-device"), "NEPacketDevice", LinkedHashMap(), connections))
                val settings = linkedMapOf<String, Any?>("mtu" to 1420L, "max-pending-bytes" to 65536L, "max-total-pending-bytes" to 16777216L)
                if (fakeDns) settings["fake-dns"] = ChainConfig.fakeDnsSettings()
                nodes.add(node(connections, "PacketsToConnection", settings, successor))
            }
        }
        for (node in nodesOf(document)) {
            if (node === hint) continue
            val address = fixedAddress(node)?.let { addresses[it] }
            val geoIp = routerUsesGeoIp(node)
            if (address == null && !geoIp) {
                nodes.add(node)
                continue
            }
            @Suppress("UNCHECKED_CAST")
            val settings = LinkedHashMap(node["settings"] as Map<String, Any?>)
            // The connector uses the address resolved before the tunnel came up
            if (address != null) settings["address"] = address
            // A path in the file belongs to another machine; on the phone the app's database is the one there is
            if (geoIp) settings["geoip-db-path"] = geoIpDatabasePath
            nodes.add(LinkedHashMap(node).apply { put("settings", settings) })
        }
        val name = (document["name"] as? String)?.takeIf { it.isNotEmpty() } ?: "WaterWall"
        return linkedMapOf<String, Any?>("name" to name, "nodes" to nodes) to null
    }

    /**
     * The document of a profile made with the former WaterWall form: the nodes the app built for it when it connected, with the input
     * hint in place of NEPacketDevice and PacketsToConnection. Null for WireGuard mode and incomplete profiles.
     */
    fun documentForConfiguration(configuration: Map<String, Any?>?, server: String?, port: Long, sni: String?, verifyTls: Boolean,
                                 secret: String?, outerSecret: String?, options: Map<String, Any?>?): Map<String, Any?>? {
        if (configuration == null || ChainConfig.isWireGuard(configuration)) return null
        // The builder wants the database to route by country; the runtime sets the phone's own path again
        val builderOptions = LinkedHashMap(options.orEmpty()).apply { put("ww_geoip_db_path", "geoip.mmdb") }
        val built = ChainConfig.nodesJson(configuration, server, port, sni, verifyTls, secret, outerSecret, builderOptions)?.let { Json.parse(it) as? Map<*, *> }
        val nodes = nodesOf(built)
        val device = nodes.lastOrNull { it["type"] == "NEPacketDevice" } ?: return null
        val connections = nodes.lastOrNull { it["name"] == device["next"] && it["type"] == "PacketsToConnection" }
        val result = arrayListOf<Node>(linkedMapOf("name" to "input", "type" to if (connections != null) HINT_CONNECTION else HINT_PACKET,
            "settings" to LinkedHashMap<String, Any?>(), "next" to (connections ?: device)["next"]))
        for (node in nodes) {
            if (node === device || node === connections) continue
            val settings = node["settings"] as? Map<*, *>
            if (node["type"] == "Router" && settings?.get("geoip-db-path") != null) {
                result.add(LinkedHashMap(node).apply { put("settings", LinkedHashMap(settings).apply { remove("geoip-db-path") }) })
            } else {
                result.add(node)
            }
        }
        val document = linkedMapOf<String, Any?>("name" to (built?.get("name") ?: "WaterWall"), "nodes" to result)
        return if (validationError(document) == null) document else null
    }
}
