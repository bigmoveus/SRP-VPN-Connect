package tr.com.srp.vpn

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.lang.reflect.Proxy
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

/** The WaterWall node editor as the iPhone app has it (SRPWaterWallNodeChain, CheckConnectData, SROptionsTests' WaterWall node tests). */
class WaterWallNodeChainTest {
    @get:Rule
    val folder = TemporaryFolder()

    // The example profile of the node editor's specification: its array puts uplink before tls
    private val exampleJson = """{"name": "Example TLS chain", "nodes": [
        {"name": "input", "type": "HintConnectionIN", "settings": {}, "next": "tls"},
        {"name": "uplink", "type": "TcpConnector", "settings": {"address": "vpn.example.com", "port": 443}},
        {"name": "tls", "type": "TlsClient", "settings": {"sni": "vpn.example.com", "verify": true}, "next": "uplink"}]}"""
    private val uuid = "00112233-4455-6677-8899-aabbccddeeff"

    // WaterWall's "striped RTMP and Reality" example with the hint in place of its listener and SOCKS5 server: the chain ends at the
    // HalfDuplexClient, whose settings name the upload and the download branch
    private val branchedJson = """{"name": "Test", "nodes": [
        {"name": "input", "type": "HintConnectionIN", "settings": {}, "next": "trojan"},
        {"name": "reality-connector", "type": "TcpConnector", "settings": {"address": "203.0.113.20", "port": 443, "nodelay": true, "fastopen": false}},
        {"name": "trojan", "type": "TrojanClient", "next": "mux", "settings": {"password": "trojan-secret", "address": "dest_context->address",
            "port": "dest_context->port", "protocol": "dest_context->protocol"}},
        {"name": "mux", "type": "MuxClient", "next": "half-duplex", "settings": {"mode": "fixed-connections-count", "per-worker-connections-count": 1}},
        {"name": "half-duplex", "type": "HalfDuplexClient", "settings": {"upload": "up", "download": "down"}},
        {"name": "up", "type": "ConnectionStripeClient", "settings": {"connections": 8}, "next": "obfuscator"},
        {"name": "obfuscator", "type": "ObfuscatorClient", "settings": {"method": "xor", "xor_key": 90}, "next": "rtmp"},
        {"name": "rtmp", "type": "RtmpClient", "settings": {"tc-url": "rtmp://203.0.113.20:1935/waterwall"}, "next": "rtmp-connector"},
        {"name": "rtmp-connector", "type": "TcpConnector", "settings": {"address": "203.0.113.20", "port": 1935, "nodelay": true, "fastopen": false}},
        {"name": "down", "type": "RealityClient", "next": "reality-connector", "settings": {"sni": "example.com", "password": "reality-secret", "verify": true}}]}"""

    private fun example() = NodeChain.documentWithJson(exampleJson).first!!

    private fun branched() = NodeChain.documentWithJson(branchedJson).first!!

    private fun documentWith(vararg nodes: Map<String, Any?>): Map<String, Any?> = mapOf("name" to "Test", "nodes" to nodes.toList())

    @Suppress("UNCHECKED_CAST")
    private fun nodesOf(document: Map<String, Any?>) = document["nodes"] as List<Map<String, Any?>>

    /** The rows of a section of the chain screen, as a screen reader says them */
    private fun descriptions(section: ChainSection) = section.rows.map { (node, number, end) -> nodeRowDescription(number, node["type"] as String, node["name"] as String, end) }

    private fun importProblem(vararg nodes: Map<String, Any?>) = NodeChain.documentWithJson(Json.write(documentWith(*nodes))).second

    private fun names(document: Map<String, Any?>) = NodeChain.chain(document).map { it["name"] }

    private fun chainConfiguration(input: String, application: String, mux: Boolean, outer: String): Map<String, Any?> = linkedMapOf(
        "version" to 3L, "mode" to "chain", "input" to input, "application" to application, "mux" to mux, "outer" to outer, "http" to "off",
        "http-version" to 1L, "obfuscator" to false, "carrier" to "tcp", "quic-carrier" to "datagram", "node-options" to LinkedHashMap<String, Any?>())

    private fun mode(mode: String): Map<String, Any?> = linkedMapOf("version" to 3L, "mode" to mode, "node-options" to LinkedHashMap<String, Any?>())

    /** The presets of the former form, as the iOS tests define them */
    private val legacyCases = listOf(
        "direct" to mode("direct"),
        "vless-tls" to chainConfiguration("connections", "vless", false, "tls"), "trojan-tls" to chainConfiguration("connections", "trojan", false, "tls"),
        "vless-mux-tls" to chainConfiguration("connections", "vless", true, "tls"), "trojan-mux-tls" to chainConfiguration("connections", "trojan", true, "tls"),
        "vless-reality" to chainConfiguration("connections", "vless", false, "reality"), "trojan-reality" to chainConfiguration("connections", "trojan", false, "reality"),
        "vless-mux-reality" to chainConfiguration("connections", "vless", true, "reality"), "trojan-mux-reality" to chainConfiguration("connections", "trojan", true, "reality"),
        "vless-aead" to chainConfiguration("connections", "vless", false, "aead"), "vless-mux-aead" to chainConfiguration("connections", "vless", true, "aead"),
        "trojan-aead" to chainConfiguration("connections", "trojan", false, "aead"), "trojan-mux-aead" to chainConfiguration("connections", "trojan", true, "aead"),
        "rawip-tls" to chainConfiguration("raw-ipv4", "", false, "tls"), "rawip-reality" to chainConfiguration("raw-ipv4", "", false, "reality"),
        "rawip-aead" to chainConfiguration("raw-ipv4", "", false, "aead"), "vless-quic" to chainConfiguration("connections", "vless", false, "quic"),
        "trojan-quic" to chainConfiguration("connections", "trojan", false, "quic"), "rawip-quic" to chainConfiguration("raw-ipv4", "", false, "quic"),
        "wireguard" to mode("wireguard"),
    )

    private fun legacyProfile(configuration: Map<String, Any?>, server: String = "waterwall.example.com", desc: String = "") = Profile(
        protocolType = "waterwall", desc = desc, server = server, port = "443", password = uuid, configJson = ChainConfig.jsonWithConfiguration(configuration)!!)

    // SharedPreferences and the Keystore are not on the JVM: these keep their values in memory.
    private class MemoryPreferences {
        val values = HashMap<String, Any?>()
        val preferences = Proxy.newProxyInstance(javaClass.classLoader, arrayOf(SharedPreferences::class.java, SharedPreferences.Editor::class.java)) { proxy, method, arguments ->
            when (method.name) {
                "getString" -> values[arguments[0] as String] as? String ?: arguments[1]
                "contains" -> arguments[0] in values
                "putString" -> proxy.also { values[arguments[0] as String] = arguments[1] }
                "remove" -> proxy.also { values.remove(arguments[0]) }
                "commit" -> true
                "edit" -> proxy
                else -> null
            }
        } as SharedPreferences
    }

    private class MemorySecrets(context: Context) : SecretStore(context) {
        val values = LinkedHashMap<String, String>()

        override fun set(name: String, value: String) {
            values[name] = value
        }

        override fun get(name: String) = values[name]

        override fun delete(name: String) {
            values.remove(name)
        }
    }

    private val preferences = HashMap<String, MemoryPreferences>()
    private val context: Context by lazy {
        object : ContextWrapper(null) {
            override fun getFilesDir() = folder.root
            override fun getSharedPreferences(name: String?, mode: Int) = preferences.getOrPut(name.orEmpty()) { MemoryPreferences() }.preferences
        }
    }
    private val secrets by lazy { MemorySecrets(context) }
    private val profilesFile get() = File(folder.root, "profiles.json")

    private fun store() = ProfileStore(context, secrets)

    /** What an older build wrote for a profile of the former WaterWall form, with its secrets in the store */
    private fun storedLegacy(configuration: Map<String, Any?>, id: String, secret: String? = uuid, outerSecret: String? = null): Map<String, Any?> {
        val stored = linkedMapOf<String, Any?>("type" to "waterwall", "desc" to id, "node_id" to id, "username" to "", "address" to "waterwall.example.com",
            "port" to "8443", "allowInsecure" to false, "ww_config" to ChainConfig.jsonWithConfiguration(configuration), "ww_probe_ip" to "1.1.1.1",
            "ww_dns_probe_ip" to "192.0.2.1", "ww_fake_dns" to true, "ww_smart_routing" to true, "ww_auto_switch" to true, "tls_frag" to 0L,
            "auto_reconnect" to true, "retry_times" to 0L, "switch_to_wifi" to true, "on_sleep" to "stay", "log_level" to "normal", "sni" to "")
        if (secret != null) {
            stored["password_key"] = "$id-secret"
            secrets.set("$id-secret", secret)
        }
        if (outerSecret != null) {
            stored["ww_outer_secret_ref"] = "$id-outer"
            secrets.set("$id-outer", outerSecret)
        }
        return stored
    }

    private fun writeProfiles(vararg stored: Map<String, Any?>) = profilesFile.writeText(Json.write(stored.toList()))

    @Suppress("UNCHECKED_CAST")
    private fun savedProfiles() = Json.parse(profilesFile.readText()) as List<Map<String, Any?>>

    @Test
    fun exampleImportFollowsNextAndEndsAtTheTerminalNode() {
        val (document, problem) = NodeChain.documentWithJson(exampleJson)
        assertNull(problem)
        val chain = NodeChain.chain(document)
        assertEquals(listOf("HintConnectionIN", "TlsClient", "TcpConnector"), chain.map { it["type"] })
        assertEquals(listOf("input", "tls", "uplink"), chain.map { it["name"] })
        assertEquals("uplink", chain[1]["next"])
        assertFalse("The terminal node has no next key", "next" in chain.last())
        assertEquals(mapOf("sni" to "vpn.example.com", "verify" to true), chain[1]["settings"])
        assertEquals("Example TLS chain", NodeChain.summary(document))
        assertEquals(listOf("vpn.example.com" to 443), NodeChain.endpoints(document))
        assertEquals("TlsClient → TcpConnector", NodeChain.summary(document!!.filterKeys { it != "name" }))
        assertEquals("No nodes", NodeChain.summary(Json.parseOrNull("not JSON")))
    }

    @Test
    fun editInsertDeleteAndRenameKeepTheChain() {
        val document = example()
        // Edit: a new SNI; verify and next stay as they were
        val tls = LinkedHashMap(NodeChain.chain(document)[1]).apply { put("settings", mapOf("sni" to "edge.example.net", "verify" to true)) }
        val edited = NodeChain.replacingNode(document, "tls", tls)
        assertNull(NodeChain.validationError(edited))
        val reopened = NodeChain.documentWithJson(NodeChain.json(edited)).first!!
        val saved = NodeChain.chain(reopened)[1]
        assertEquals(mapOf("sni" to "edge.example.net", "verify" to true), saved["settings"])
        assertEquals("uplink", saved["next"])
        assertEquals(NodeChain.chain(document).last(), NodeChain.chain(reopened).last())

        // Insert after tls, then delete: the link comes back
        val inserted = NodeChain.insertingNode(document, mapOf("name" to "split", "type" to "StreamFragmenter", "settings" to emptyMap<String, Any?>(), "next" to "uplink"), "tls")
        assertNull(NodeChain.validationError(inserted))
        assertEquals(listOf("input", "tls", "split", "uplink"), names(inserted))
        val deleted = NodeChain.deletingNode(inserted, "split")
        assertEquals("uplink", NodeChain.chain(deleted)[1]["next"])
        assertEquals(listOf("input", "tls", "uplink"), names(deleted))

        // After the terminal node a new node ends the chain; deleting the terminal node ends it at its predecessor
        val tail = NodeChain.insertingNode(document, mapOf("name" to "last", "type" to "StreamFragmenter", "settings" to emptyMap<String, Any?>()), "uplink")
        assertEquals("last", NodeChain.chain(tail).last()["name"])
        assertEquals("last", NodeChain.chain(tail)[2]["next"])
        val shortened = NodeChain.deletingNode(document, "uplink")
        assertFalse("next" in NodeChain.chain(shortened).last())
        assertEquals("tls", NodeChain.chain(shortened).last()["name"])

        // Rename: the next that named the node follows the new name
        val afterRename = NodeChain.replacingNode(document, "tls", LinkedHashMap(tls).apply { put("name", "outer-tls") })
        assertEquals("outer-tls", NodeChain.chain(afterRename)[0]["next"])
        assertNull(NodeChain.validationError(afterRename))

        // An edit that leaves no leading hint cannot be saved
        val noHint = NodeChain.replacingNode(document, "input", mapOf("name" to "input", "type" to "TlsClient", "settings" to emptyMap<String, Any?>(), "next" to "tls"))
        assertEquals("The chain must start with an input hint: HintConnectionIN or HintPacketIN.", NodeChain.validationError(noHint))
    }

    @Test
    fun importBlocksForbiddenAndBrokenFilesWithTheirReason() {
        val hint = mapOf("name" to "input", "type" to "HintConnectionIN", "settings" to emptyMap<String, Any?>(), "next" to "out")
        val out = mapOf("name" to "out", "type" to "TcpConnector", "settings" to mapOf("address" to "vpn.example.com", "port" to 443L))
        assertNull(importProblem(hint, out))
        assertEquals("The chain must start with an input hint: HintConnectionIN or HintPacketIN.", importProblem(out))
        // A raw socket anywhere, on the chain or off it
        assertEquals("Node \"raw\" is a RawSocket node: raw socket nodes cannot be imported.",
            importProblem(hint, out, mapOf("name" to "raw", "type" to "RawSocket", "settings" to emptyMap<String, Any?>())))
        val tun = importProblem(hint, out, mapOf("name" to "tun", "type" to "TunDevice", "settings" to emptyMap<String, Any?>(), "next" to "input"))!!
        assertTrue(tun, tun.startsWith("Node \"tun\" is a TunDevice node: SRP supplies TunDevice and PacketsToConnection itself"))
        val ptc = importProblem(hint, out, mapOf("name" to "ptc", "type" to "PacketsToConnection", "settings" to emptyMap<String, Any?>()))!!
        assertTrue(ptc, ptc.startsWith("Node \"ptc\" is a PacketsToConnection node"))
        val missing = importProblem(hint)!!
        assertTrue("The missing target is named: $missing", "\"out\"" in missing)
        assertNotNull(importProblem(hint, mapOf("name" to "out", "type" to "TlsClient", "settings" to emptyMap<String, Any?>(), "next" to "input")))
        val twice = importProblem(hint, out, mapOf("name" to "out", "type" to "TlsClient", "settings" to emptyMap<String, Any?>()))!!
        assertTrue(twice, "\"out\"" in twice)
        assertNotNull("A hint has no settings", importProblem(LinkedHashMap(hint).apply { put("settings", mapOf("mtu" to 1400L)) }, out))
        assertNotNull(importProblem(hint, out, mapOf("name" to "second", "type" to "HintPacketIN", "settings" to emptyMap<String, Any?>())))
        assertEquals("The file is not valid JSON.", NodeChain.documentWithJson("{\"nodes\": [").second)

        // The file itself: nothing of a bad one is imported
        assertEquals("The file could not be read.", importedDocument(null).second)
        assertEquals("The file is larger than 1 MB.", importedDocument(ByteArray(1048577) { ' '.code.toByte() }).second)
        assertEquals("The file is not UTF-8 text.", importedDocument(byteArrayOf(0x7b, 0xff.toByte(), 0x7d)).second)
        assertEquals(example(), importedDocument(exampleJson.toByteArray()).first)
        // A byte order mark is not part of the JSON
        assertEquals(example(), importedDocument(byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + exampleJson.toByteArray()).first)
        // A number no double can hold could not be written back; a key written twice keeps its first value, as WaterWall reads it
        for (number in listOf("1e999", "-1e999")) {
            assertEquals(number, "The file is not valid JSON.", importedDocument(exampleJson.replaceFirst("{", "{\"limit\": $number, ").toByteArray()).second)
        }
        assertEquals(example(), importedDocument(exampleJson.replaceFirst(Regex("\\}\\s*$"), ", \"nodes\": []}").toByteArray()).first)
        // One comma after the last member or element is accepted, as the iPhone's reader accepts it; any other stray comma is not
        assertEquals(example(), importedDocument(exampleJson.replaceFirst(Regex("\\}\\s*$"), ",\n}").toByteArray()).first)
        assertEquals(mapOf("a" to listOf(1L, 2L), "b" to mapOf("c" to true)), Json.parse("{\"a\": [1, 2 , ], \"b\": {\"c\": true,},}"))
        for (stray in listOf("[1,,]", "[,]", "[,1]", "{\"a\": 1,,}", "{,}", "{,\"a\": 1}", "[1,]]", "[1,")) {
            assertEquals(stray, "The file is not valid JSON.", NodeChain.documentWithJson(stray).second)
        }
    }

    // The saved profile keeps its hint; what WaterWall runs starts with the input Settings → WaterWall Input chooses
    @Test
    fun runtimeInputPrefixFollowsTheHintAndTheInputSetting() {
        val document = example()
        fun runtime(profile: Map<String, Any?>, input: String) = NodeChain.runtimeDocument(profile, input, true, null, mapOf("vpn.example.com" to "192.0.2.10"))
        @Suppress("UNCHECKED_CAST")
        fun nodes(result: Pair<Map<String, Any?>?, String?>) = result.first!!["nodes"] as List<Map<String, Any?>>

        val tun = runtime(document, NodeChain.INPUT_TUN)
        assertNull(tun.second)
        val tunNodes = nodes(tun)
        assertEquals(listOf("NEPacketDevice", "PacketsToConnection", "TcpConnector", "TlsClient"), tunNodes.map { it["type"] })
        assertEquals(tunNodes[1]["name"], tunNodes[0]["next"])
        assertEquals("PacketsToConnection takes over the hint's successor", "tls", tunNodes[1]["next"])
        assertNotNull((tunNodes[1]["settings"] as Map<*, *>)["fake-dns"])
        assertEquals("The address resolved before the tunnel", "192.0.2.10", (tunNodes[2]["settings"] as Map<*, *>)["address"])
        assertEquals("The profile keeps its hint", "HintConnectionIN", NodeChain.chain(document).first()["type"])

        @Suppress("UNCHECKED_CAST")
        val packets = documentWith(*((document["nodes"] as List<Map<String, Any?>>).toMutableList().apply {
            set(0, mapOf("name" to "input", "type" to "HintPacketIN", "settings" to emptyMap<String, Any?>(), "next" to "tls"))
        }.toTypedArray()))
        val packetRuntime = nodes(runtime(packets, NodeChain.INPUT_TUN))
        assertEquals(listOf("NEPacketDevice", "TcpConnector", "TlsClient"), packetRuntime.map { it["type"] })
        assertEquals("tls", packetRuntime[0]["next"])

        val socks = nodes(runtime(document, NodeChain.INPUT_SOCKS5))
        assertEquals(listOf("TcpUdpListener", "Socks5Server"), socks.take(2).map { it["type"] })
        assertEquals("127.0.0.1", (socks[0]["settings"] as Map<*, *>)["address"])
        assertEquals(1080L, (socks[0]["settings"] as Map<*, *>)["port"])
        assertEquals(mapOf("no-auth" to true, "connect" to true, "udp" to true, "ipv4" to "127.0.0.1"), socks[1]["settings"])
        assertEquals("tls", socks[1]["next"])
        val http = nodes(runtime(document, NodeChain.INPUT_HTTP))
        assertEquals(listOf("TcpListener", "HttpProxyServer"), http.take(2).map { it["type"] })
        assertEquals(8080L, (http[0]["settings"] as Map<*, *>)["port"])
        assertEquals(mapOf("no-auth" to true), http[1]["settings"])
        assertEquals("tls", http[1]["next"])

        // A packet hint never becomes a connection input, and never falls back to the system VPN
        for (input in listOf(NodeChain.INPUT_SOCKS5, NodeChain.INPUT_HTTP)) {
            val (refused, error) = runtime(packets, input)
            assertNull(refused)
            assertTrue(error, error!!.startsWith("This profile starts with HintPacketIN, which takes IP packets"))
        }

        // A node type the app's WaterWall does not include stops the connection at once, naming the node
        @Suppress("UNCHECKED_CAST")
        val nodesOfExample = document["nodes"] as List<Map<String, Any?>>
        val unknown = runtime(documentWith(*(nodesOfExample + mapOf("name" to "meter", "type" to "SpeedTestClient", "settings" to emptyMap<String, Any?>())).toTypedArray()), NodeChain.INPUT_TUN)
        assertNull(unknown.first)
        assertEquals("Node \"meter\" is a SpeedTestClient node, which the app's WaterWall does not include.", unknown.second)

        // A generated name never takes one the profile already uses
        val clash = runtime(documentWith(*(nodesOfExample + mapOf("name" to "srp-device", "type" to "StreamFragmenter", "settings" to emptyMap<String, Any?>())).toTypedArray()), NodeChain.INPUT_TUN)
        assertEquals("srp-device-2", nodes(clash)[0]["name"])

        // A Router that routes by country takes the phone's database, and cannot run without one
        val geoIp = documentWith(mapOf("name" to "input", "type" to "HintConnectionIN", "settings" to emptyMap<String, Any?>(), "next" to "router"),
            mapOf("name" to "router", "type" to "Router", "settings" to mapOf("rules" to listOf(mapOf("destination-ip" to listOf("geoip:ir"), "target" to "out")),
                "geoip-db-path" to "/elsewhere.mmdb"), "next" to "out"),
            mapOf("name" to "out", "type" to "TcpUdpConnector", "settings" to mapOf("address" to "dest_context->address", "port" to "dest_context->port")))
        assertEquals("The profile routes by country, but the GeoIP database is not available.", NodeChain.runtimeDocument(geoIp, NodeChain.INPUT_TUN, true, null, emptyMap()).second)
        val routed = nodes(NodeChain.runtimeDocument(geoIp, NodeChain.INPUT_TUN, false, "/data/GeoLite2-Country.mmdb", emptyMap()))
        assertEquals("/data/GeoLite2-Country.mmdb", (routed.first { it["type"] == "Router" }["settings"] as Map<*, *>)["geoip-db-path"])
        assertNull("Remote DNS off", (routed[1]["settings"] as Map<*, *>)["fake-dns"])
    }

    // WaterWall 1.6 refuses QuicClient's carrier-mode: a profile saved for 1.5 loses it, and QUIC over TCP gets the UdpOverTcp framing
    @Test
    fun quicProfilesOfVersion15TakeTheFormOfVersion16() {
        fun profile(mode: String, connector: String) = documentWith(
            mapOf("name" to "input", "type" to "HintConnectionIN", "settings" to emptyMap<String, Any?>(), "next" to "vless"),
            mapOf("name" to "vless", "type" to "VlessClient", "settings" to mapOf("uuid" to "id"), "next" to "quic"),
            mapOf("name" to "quic", "type" to "QuicClient", "next" to "connector", "settings" to mapOf("sni" to "vpn.example.com", "protocol" to "h3", "carrier-mode" to mode)),
            mapOf("name" to "connector", "type" to connector, "settings" to mapOf("address" to "vpn.example.com", "port" to 443L)))
        val datagram = NodeChain.chain(NodeChain.currentDocument(profile("datagram", "UdpConnector")))
        assertEquals(listOf("HintConnectionIN", "VlessClient", "QuicClient", "UdpConnector"), datagram.map { it["type"] })
        assertEquals(mapOf("sni" to "vpn.example.com", "protocol" to "h3"), datagram[2]["settings"])

        val taken = nodesOf(profile("stream", "TcpConnector")) + mapOf("name" to "udp-over-tcp", "type" to "StreamFragmenter", "settings" to emptyMap<String, Any?>())
        val stream = NodeChain.currentDocument(documentWith(*taken.toTypedArray()))
        val chain = NodeChain.chain(stream)
        assertEquals(listOf("HintConnectionIN", "VlessClient", "QuicClient", "UdpOverTcpClient", "TcpConnector"), chain.map { it["type"] })
        assertFalse("carrier-mode" in chain[2]["settings"] as Map<*, *>)
        assertEquals("The profile already has a node of the plain name", "udp-over-tcp-2", chain[3]["name"])
        assertEquals(emptyMap<String, Any?>(), chain[3]["settings"])
        assertNull(NodeChain.validationError(stream))

        // A profile of the present form is returned as it is, and reading a saved one or starting it brings the form up to date
        assertSame(stream, NodeChain.currentDocument(stream))
        val saved = NodeChain.json(profile("stream", "TcpConnector"))
        assertEquals(5, nodesOf(NodeChain.documentWithJson(saved).first!!).size)
        val runtime = NodeChain.runtimeDocument(profile("stream", "TcpConnector"), NodeChain.INPUT_TUN, true, null, emptyMap()).first!!
        assertEquals(listOf("NEPacketDevice", "PacketsToConnection", "VlessClient", "QuicClient", "UdpOverTcpClient", "TcpConnector"), nodesOf(runtime).map { it["type"] })
        assertFalse("carrier-mode" in NodeChain.json(runtime))
    }

    // A file in WaterWall's own config syntax: // comments go, and each $name$ takes its value from the "variables" block
    @Test
    fun importTakesCommentsAndVariables() {
        val file = "{\n  // the values to change\n  \"variables\": {\"server_address\": \"203.0.113.20\", \"port\": 8443," +
            " \"tls\": {\"sni\": \"vpn.example.com\", \"verify\": true}},\n  \"name\": \"price \$5 // not a comment\",\n  \"nodes\": [\n" +
            "    {\"name\": \"input\", \"type\": \"HintConnectionIN\", \"next\": \"tls\"}, // the app's input\n" +
            "    {\"name\": \"tls\", \"type\": \"TlsClient\", \"settings\": \$tls\$, \"next\": \"out\"},\n" +
            "    {\"name\": \"out\", \"type\": \"TcpConnector\", \"settings\": {\"address\": \$server_address\$, \"port\": \$port\$}}\n  ]\n}\n"
        val (document, problem) = NodeChain.documentWithJson(file)
        assertNull(problem)
        assertFalse("The values are in the nodes now", "variables" in document!!)
        assertEquals("price \$5 // not a comment", document["name"])
        val chain = NodeChain.chain(document)
        assertEquals(mapOf("sni" to "vpn.example.com", "verify" to true), chain[1]["settings"])
        assertEquals(mapOf("address" to "203.0.113.20", "port" to 8443L), chain[2]["settings"])

        assertEquals(null to "The file uses the variable \$missing\$, but its \"variables\" block does not define it.",
            NodeChain.documentWithJson(file.replace("\$port\$", "\$missing\$")))
        // Of several undefined variables the message names the first by name, whatever their order in the file
        assertEquals(null to "The file uses the variable \$alpha\$, but its \"variables\" block does not define it.",
            NodeChain.documentWithJson(file.replace("\$tls\$", "\$zeta\$").replace("\$port\$", "\$alpha\$")))
        // A value named many times must not grow the profile past what a file may hold: 1,048,576 characters of values
        fun repeated(count: Int) = "{\"variables\": {\"big\": \"${"x".repeat(1024)}\"}, \"nodes\": [" +
            "{\"name\": \"input\", \"type\": \"HintConnectionIN\", \"next\": \"out\"}, " +
            "{\"name\": \"out\", \"type\": \"TcpConnector\", \"settings\": {\"address\": \"203.0.113.20\", \"port\": 443, \"notes\": [${List(count) { "\$big\$" }.joinToString(",")}]}}]}"
        assertNull(NodeChain.documentWithJson(repeated(1024)).second)
        assertEquals(null to "The file is larger than 1 MB with its variables filled in.", NodeChain.documentWithJson(repeated(1025)))
        for (broken in listOf("\$port", "\$\$")) {
            assertEquals(broken, null to "The file is not valid JSON.", NodeChain.documentWithJson(file.replace("\$port\$", broken)))
        }
    }

    // Nodes that are not on the path from the hint, such as the ones another node names in its settings, follow the chain branch by branch
    @Test
    fun branchesFollowTheChain() {
        val document = branched()
        assertEquals(listOf("input", "trojan", "mux", "half-duplex"), names(document))
        assertEquals(listOf("up", "obfuscator", "rtmp", "rtmp-connector", "down", "reality-connector"), NodeChain.branchNodes(document).map { it["name"] })
        assertEquals(emptyList<Any>(), NodeChain.branchNodes(example()))
        assertEquals(setOf("203.0.113.20" to 1935, "203.0.113.20" to 443), NodeChain.endpoints(document).toSet())

        val (runtime, problem) = NodeChain.runtimeDocument(document, NodeChain.INPUT_SOCKS5, false, null, mapOf("203.0.113.20" to "198.51.100.7"))
        assertNull(problem)
        assertEquals("The two input nodes and the nine nodes after the hint", 11, nodesOf(runtime!!).size)
        for (node in nodesOf(runtime).filter { it["type"] == "TcpConnector" }) {
            assertEquals("${node["name"]}", "198.51.100.7", (node["settings"] as Map<*, *>)["address"])
        }
        // A cycle among the other nodes still lists each of them once
        val cycle = nodesOf(example()) + mapOf("name" to "a", "type" to "BlackHole", "settings" to emptyMap<String, Any?>(), "next" to "b") +
            mapOf("name" to "b", "type" to "BlackHole", "settings" to emptyMap<String, Any?>(), "next" to "a")
        assertEquals(listOf("a", "b"), NodeChain.branchNodes(documentWith(*cycle.toTypedArray())).map { it["name"] })
    }

    // A WaterWall client config for a computer starts at its own listener and proxy server: without a hint, SRP's input takes their
    // place, as it does when it adds the same pair for its local SOCKS5 input
    @Test
    fun importReplacesTheFilesOwnLocalProxyWithTheHint() {
        val rest = arrayOf(mapOf("name" to "trojan", "type" to "TrojanClient", "settings" to mapOf("password" to "secret"), "next" to "out"),
            mapOf("name" to "out", "type" to "TcpConnector", "settings" to mapOf("address" to "vpn.example.com", "port" to 443L)))
        fun imported(vararg head: Map<String, Any?>) = NodeChain.documentWithJson(NodeChain.json(documentWith(*head, *rest)))
        val listener = mapOf("name" to "socks-listener", "type" to "TcpUdpListener", "next" to "socks", "settings" to mapOf("address" to "127.0.0.1", "port" to 1080L))
        val socks = mapOf("name" to "socks", "type" to "Socks5Server", "settings" to mapOf("no-auth" to true), "next" to "trojan")
        val (document, problem) = imported(listener, socks)
        assertNull(problem)
        assertEquals(listOf("input", "trojan", "out"), names(document!!))
        assertEquals(mapOf("name" to "input", "type" to "HintConnectionIN", "settings" to emptyMap<String, Any?>(), "next" to "trojan"), NodeChain.hint(document))
        val http = socks + ("type" to "HttpProxyServer")
        assertEquals(3, nodesOf(imported(listener + ("type" to "TcpListener"), http).first!!).size)

        // A listener that forwards to one fixed service is no proxy input, and a second proxy head leaves the choice to the file
        val noHint = null to "The chain must start with an input hint: HintConnectionIN or HintPacketIN."
        assertEquals(noHint, imported(listener + ("next" to "trojan")))
        val secondListener = mapOf("name" to "http-listener", "type" to "TcpListener", "settings" to emptyMap<String, Any?>(), "next" to "http")
        assertEquals(noHint, imported(listener, socks, secondListener, http + ("name" to "http")))
        // A listener without a next leads nowhere, so a proxy server without a name is not its pair
        assertEquals(null to "The next of node \"socks-listener\" is not a node name.", imported(listener + ("next" to null), socks + ("name" to null)))
        // A file that has a hint keeps its other nodes as they are
        val hint = mapOf("name" to "start", "type" to "HintConnectionIN", "settings" to emptyMap<String, Any?>(), "next" to "trojan")
        assertEquals(5, nodesOf(imported(hint, listener, socks).first!!).size)
    }

    // The names a node holds in its settings are links too: a missing one blocks the file, a rename follows, a delete is refused
    @Test
    fun settingsThatNameANodeAreKeptWhole() {
        val document = branched()
        assertEquals("Node \"half-duplex\" names \"down\" as its download, but no node has that name.", NodeChain.validationError(NodeChain.deletingNode(document, "down")))
        assertNull("next closes the gap", NodeChain.validationError(NodeChain.deletingNode(document, "obfuscator")))

        val renamed = NodeChain.replacingNode(document, "up", NodeChain.branchNodes(document)[0] + ("name" to "striped"))
        assertNull(NodeChain.validationError(renamed))
        assertEquals(mapOf("upload" to "striped", "download" to "down"), NodeChain.chain(renamed).last()["settings"])

        fun routed(vararg rules: Any?) = documentWith(
            mapOf("name" to "input", "type" to "HintConnectionIN", "settings" to emptyMap<String, Any?>(), "next" to "router"),
            mapOf("name" to "router", "type" to "Router", "next" to "proxy", "settings" to mapOf("rules" to rules.toList())),
            mapOf("name" to "proxy", "type" to "TcpConnector", "settings" to mapOf("address" to "vpn.example.com", "port" to 443L,
                "dns-behaviour" to mapOf("resolve" to true, "dns-next" to "dns"))),
            mapOf("name" to "direct", "type" to "TcpUdpConnector", "settings" to mapOf("address" to "dest_context->address", "port" to "dest_context->port")),
            mapOf("name" to "dns", "type" to "TcpUdpConnector", "settings" to mapOf("address" to "1.1.1.1", "port" to 53L)))
        val lan = routed(mapOf("destination-ip" to listOf("10.0.0.0/8"), "target" to "direct"))
        assertNull(NodeChain.validationError(lan))
        assertEquals("Node \"router\" names \"direct\" as its rules target, but no node has that name.", NodeChain.validationError(NodeChain.deletingNode(lan, "direct")))
        assertEquals("Node \"proxy\" names \"dns\" as its dns-next, but no node has that name.", NodeChain.validationError(NodeChain.deletingNode(lan, "dns")))
        // A rule that is not an object names no node: the file is read, and WaterWall is the one to refuse the rule
        val oddRule = routed(5L, mapOf("target" to "direct"))
        assertNull(NodeChain.validationError(oddRule))
        assertEquals(oddRule to null, NodeChain.documentWithJson(NodeChain.json(oddRule)))
        assertEquals("Node \"router\" names the input hint \"input\" as its rules target, but the hint must start the chain.",
            NodeChain.validationError(routed(mapOf("target" to "input"))))

        // Only an IPv4 host of the profile's own is a server to look up; country rules count by source and when negated too
        val others = listOf("src_context->address", "2001:db8::1", "203.0.113.0/24").map {
            mapOf("name" to it, "type" to "TcpConnector", "settings" to mapOf("address" to it, "port" to 443L))
        }
        assertEquals(listOf("vpn.example.com", "1.1.1.1"), NodeChain.endpoints(documentWith(*(nodesOf(lan) + others).toTypedArray())).map { it.first })
        assertFalse(NodeChain.usesGeoIp(lan))
        for (rule in listOf(mapOf("source-ips" to listOf("geoip:ir"), "target" to "direct"), mapOf("destination-ip" to listOf("!GeoIP:IR"), "target" to "direct"))) {
            assertTrue("$rule", NodeChain.usesGeoIp(routed(rule)))
        }
    }

    // A profile is checked against the node types WaterWall/CMakeLists.txt builds into the app
    @Test
    fun nodeTypesAreTheOnesOfTheBuild() {
        // Gradle runs the tests in the app module's folder
        val list = File("../../WaterWall/CMakeLists.txt").readText().substringAfter("set(SRP_NODES", "").substringBefore("\n)")
        val built = Regex("""^\s+[A-Z0-9_]+:([A-Za-z0-9]+)$""", RegexOption.MULTILINE).findAll(list).map { it.groupValues[1] }.toSet()
        assertTrue("$built", built.size > 40)
        // SRP supplies these two itself, so a profile may not hold them
        assertEquals(built - setOf("NEPacketDevice", "PacketsToConnection"), NodeChain.includedNodeTypes)
    }

    // One choice for all WaterWall profiles: the profiles hold no input of their own
    @Test
    fun inputIsOneAppWideSetting() {
        val settings = AppSettings(context)
        assertEquals(NodeChain.INPUT_TUN, settings.waterWallInput)
        val first = Profile(protocolType = "waterwall", chainJson = exampleJson).withWaterWallServer()
        val second = Profile(protocolType = "waterwall", chainJson = NodeChain.emptyJson)
        store().save(listOf(first, second))
        val before = profilesFile.readText()
        for (input in listOf(NodeChain.INPUT_SOCKS5, NodeChain.INPUT_HTTP, NodeChain.INPUT_TUN)) {
            settings.waterWallInput = input
            assertEquals(input, settings.waterWallInput)
            assertEquals(input, preferences["settings"]!!.values["SRPWaterWallInput"])
            store().save(store().load())
            assertEquals("Changing the input changes no profile", before, profilesFile.readText())
            for (stored in savedProfiles()) for (key in stored.keys) assertFalse(key, "input" in key)
        }
        assertEquals(1080, NodeChain.portForInput(NodeChain.INPUT_SOCKS5))
        assertEquals(8080, NodeChain.portForInput(NodeChain.INPUT_HTTP))
        assertEquals(0, NodeChain.portForInput(NodeChain.INPUT_TUN))
        preferences["settings"]!!.values["SRPWaterWallInput"] = "something-else"
        assertEquals(NodeChain.INPUT_TUN, settings.waterWallInput)
        assertEquals(listOf("System VPN (TUN)", "Local SOCKS5 proxy", "Local HTTP proxy"),
            listOf(NodeChain.INPUT_TUN, NodeChain.INPUT_SOCKS5, NodeChain.INPUT_HTTP).map { inputTitle(it) })
    }

    // A profile from the former WaterWall form becomes the chain the app built for it, once, when it is first read
    @Test
    fun legacyProfileBecomesItsNodeChain() {
        writeProfiles(storedLegacy(chainConfiguration("connections", "vless", true, "reality"), "LEGACY", outerSecret = "outer-secret"))
        val profile = store().load().single()
        val chain = NodeChain.chain(NodeChain.documentWithJson(profile.chainJson).first)
        assertEquals(NodeChain.HINT_CONNECTION, chain.first()["type"])
        val byType = chain.associateBy { it["type"] }
        assertEquals(uuid, (byType["VlessClient"]!!["settings"] as Map<*, *>)["uuid"])
        assertNotNull(byType["MuxClient"])
        assertEquals("outer-secret", (byType["RealityClient"]!!["settings"] as Map<*, *>)["password"])
        assertNotNull("Direct LAN Routing stays a Router on the chain", byType["Router"])
        assertNull(byType["NEPacketDevice"])
        assertNull(byType["PacketsToConnection"])
        assertEquals("waterwall.example.com", (chain.last()["settings"] as Map<*, *>)["address"])
        assertEquals("waterwall.example.com" to "8443", profile.server to profile.port)
        // The secrets are in the chain now, which the store keeps as a whole; the form's fields and entries are gone
        assertEquals("" to "", profile.configJson to profile.password)
        assertEquals("" to "", profile.passwordKey to profile.outerSecretRef)
        assertEquals(mapOf(profile.chainRef to profile.chainJson), secrets.values)
        val saved = savedProfiles().single()
        assertEquals(profile.chainRef, saved["ww_chain_ref"])
        for (key in listOf("ww_config", "password", "password_key", "ww_outer_secret_ref", "ww_outer_secret", "ww_smart_routing")) assertFalse(key, key in saved)
        assertFalse("The UUID travels in the chain only", uuid in profilesFile.readText())
        assertFalse("A profile is converted once", profile.hasLegacyWaterWallSettings)

        val file = profilesFile.readText()
        val reloaded = store().load().single()
        assertEquals(profile, reloaded)
        assertEquals("1.1.1.1" to "192.0.2.1", reloaded.probeIp to reloaded.dnsProbeIp)
        assertTrue(reloaded.fakeDns)
        assertEquals("Nothing to convert or save again", file, profilesFile.readText())
    }

    // WaterWall's WireGuard mode cannot start with an input hint: such a profile becomes a WireGuard profile
    @Test
    fun wireGuardModeProfileBecomesAWireGuardProfile() {
        val config = "[Interface]\nPrivateKey = aW1wb3J0ZWQ=\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = cGVlcg==\nEndpoint = wg.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
        val profile = Profile(protocolType = "waterwall", server = "edited.example.com", port = "443", configJson = ChainConfig.jsonWithConfiguration(mode("wireguard"))!!,
            wgConfig = config).convertedFromLegacyWaterWall()!!
        assertEquals("wireguard", profile.protocolType)
        assertEquals("WireGuard VPN", profile.nodeName)
        assertEquals("The imported file's Endpoint, as WaterWall used it", "wg.example.com" to "51820", profile.server to profile.port)
        assertEquals("" to "", profile.configJson to profile.chainJson)
        assertEquals(config, profile.wgConfig)
        assertEquals(config, profile.wgEffectiveConfig())
    }

    // The GeoIP update link moved from each profile to the app's settings: a converted profile gives it once
    @Test
    fun conversionMovesTheGeoIPUpdateLinkToTheSettings() {
        fun geoIp(url: String) = LinkedHashMap(chainConfiguration("connections", "vless", false, "tls")).apply {
            put("geoip", mapOf("countries" to listOf("IR"), "update-url" to url))
        }
        writeProfiles(storedLegacy(geoIp("https://example.com/first.mmdb"), "FIRST"), storedLegacy(geoIp("https://example.com/second.mmdb"), "SECOND"))
        val profiles = store().load()
        assertEquals("https://example.com/first.mmdb", AppSettings(context).geoIpUpdateUrl)
        val document = NodeChain.documentWithJson(profiles[0].chainJson).first
        assertTrue(NodeChain.usesGeoIp(document))
        assertFalse("The phone's own database path is set when it connects", "geoip-db-path" in profiles[0].chainJson)
    }

    @Test
    fun migrationDefaultsAndLegacyConfigurations() {
        // Stored without settings or a UUID, the form could not connect it either: it starts as an empty chain
        writeProfiles(mapOf("type" to "waterwall", "node_id" to "EMPTY"))
        val file = profilesFile.readText()
        val empty = store().load().single()
        assertTrue(empty.fakeDns)
        assertEquals(NodeChain.emptyJson, empty.chainJson)
        assertEquals("Nothing was converted, so nothing was saved", file, profilesFile.readText())
        assertFalse(empty.hasLegacyWaterWallSettings)
        assertEquals("The input hint \"input\" has no next node: import a WaterWall profile or insert a node after it.", validationMessage(empty))

        for ((name, configuration) in legacyCases) {
            val converted = legacyProfile(configuration).copy(outerSecret = "outer-secret").convertedFromLegacyWaterWall()
            assertNotNull(name, converted)
            if (ChainConfig.isWireGuard(configuration)) {
                assertEquals(name, "wireguard", converted!!.protocolType)
            } else {
                assertNull(name, NodeChain.validationError(NodeChain.documentWithJson(converted!!.chainJson).first))
                assertEquals(name, "" to "", converted.configJson to converted.password)
                // Direct chains have no server of their own; the others name the one the form had
                assertEquals(name, if (ChainConfig.isDirect(configuration)) "" else "waterwall.example.com", converted.server)
                assertEquals(name, !ChainConfig.isDirect(configuration), converted.fakeDns)
            }
        }
        // One that cannot be converted keeps its former settings beside the empty chain, until a chain is saved for it
        writeProfiles(storedLegacy(chainConfiguration("connections", "vless", false, "tls"), "NO-UUID", secret = null),
            storedLegacy(chainConfiguration("connections", "vless", false, "tls"), "CONVERTS"))
        val (kept, converted) = store().load()
        assertEquals(NodeChain.emptyJson, kept.chainJson)
        assertTrue(kept.configJson.isNotEmpty())
        assertTrue(kept.hasLegacyWaterWallSettings)
        assertTrue(converted.configJson.isEmpty())
        val saved = savedProfiles().associateBy { it["node_id"] }
        assertEquals(kept.configJson, saved["NO-UUID"]!!["ww_config"])
        assertEquals(NodeChain.emptyJson, secrets.values[saved["NO-UUID"]!!["ww_chain_ref"]])
        assertFalse("ww_config" in saved["CONVERTS"]!!)
    }

    @Test
    fun chainLeavesWithItsProfileOrProtocol() {
        val waterWall = Profile(protocolType = "waterwall", chainJson = exampleJson).withWaterWallServer()
        store().save(listOf(waterWall))
        val saved = store().load().single()
        assertEquals(exampleJson, secrets.values[saved.chainRef])
        // A profile moved to another protocol leaves its chain
        store().save(listOf(saved.copy(protocolType = "sstp", server = "vpn.example.com")))
        assertFalse(saved.chainRef in secrets.values)
        assertFalse("ww_chain_ref" in savedProfiles().single())
        // Deleting a profile deletes its chain
        store().save(listOf(saved))
        val again = store().load().single()
        store().deleteSecrets(again)
        assertFalse(again.chainRef in secrets.values)
    }

    @Test
    fun autoSwitchOffersTheOtherCarrierOfTheSameServerFirst() {
        val tcp = LinkedHashMap(chainConfiguration("connections", "vmess", false, "none")).apply { put("bgp4", false) }
        val kcp = LinkedHashMap(tcp).apply { put("carrier", "kcp") }
        val quicStream = LinkedHashMap(tcp).apply {
            put("outer", "quic")
            put("quic-carrier", "stream")
        }
        fun profile(name: String, server: String, configuration: Map<String, Any?>) = legacyProfile(configuration, server, name).convertedFromLegacyWaterWall()!!
        val selected = profile("TCP", "waterwall.example", tcp)
        val sameCarrier = profile("QUIC stream", "WaterWall.Example ", quicStream)
        val otherCarrier = profile("KCP", "waterwall.example", kcp)
        val otherServer = profile("Elsewhere", "other.example", kcp)
        val direct = profile("Direct", "waterwall.example", mode("direct"))
        val copy = profile("Copy", "waterwall.example", tcp).copy(nodeId = "COPY")
        val sstp = Profile(protocolType = "sstp", server = "waterwall.example")
        val profiles = listOf(selected, sameCarrier, sstp, otherServer, otherCarrier, direct, copy)

        assertEquals(listOf("KCP", "QUIC stream"), WaterWallVpnService.fallbackProfiles(selected, profiles).map { it.desc })
        assertTrue(NodeChain.usesUdpCarrier(NodeChain.documentWithJson(otherCarrier.chainJson).first))
        assertFalse(NodeChain.usesUdpCarrier(NodeChain.documentWithJson(sameCarrier.chainJson).first))
        assertEquals(0, WaterWallVpnService.fallbackProfiles(selected.copy(autoSwitch = false), profiles).size)
    }

    @Test
    fun tcpPingFollowsTheChainsLastConnector() {
        val configuration = LinkedHashMap(chainConfiguration("connections", "vmess", false, "none")).apply { put("bgp4", false) }
        fun converted() = Profile(protocolType = "waterwall", server = "203.0.113.8", port = "2083", password = uuid,
            configJson = ChainConfig.jsonWithConfiguration(configuration)!!).convertedFromLegacyWaterWall()!!
        assertEquals("203.0.113.8" to 2083, TcpPinger.endpoint(converted()))
        // The chain the former form built for each carrier: one that ends in UDP has no TCP server to time
        configuration["carrier"] = "kcp"
        assertNull(TcpPinger.endpoint(converted()))
        configuration["carrier"] = "tcp"
        configuration["outer"] = "quic"
        assertNull(TcpPinger.endpoint(converted()))
        // QUIC's stream carrier runs over a TCP connection to the same port.
        configuration["quic-carrier"] = "stream"
        assertEquals("203.0.113.8" to 2083, TcpPinger.endpoint(converted()))
        assertEquals("vpn.example.com" to 443, TcpPinger.endpoint(Profile(protocolType = "waterwall", chainJson = exampleJson).withWaterWallServer()))
    }

    @Test
    fun profileOffersConnectionOptions() {
        val document = example()
        val profile = Profile(protocolType = "waterwall", chainJson = exampleJson)
        assertEquals(listOf("Auto Reconnect", "Retry Times", "Auto Switch", "Switch to Wi-Fi When Available", "On Sleep", "Log Level", "Remote DNS (Fake IP)"),
            waterWallOptionTitles(profile, document))
        val footer = waterWallOptionsFooter(document)
        assertTrue(footer.contains("Auto Reconnect restarts WaterWall"))
        assertTrue(footer.contains("Auto Switch uses the other WaterWall profiles of the same server"))
        assertFalse(footer.contains("SSTP"))
        assertEquals(waterWallOptionTitles(profile, document) - "Retry Times", waterWallOptionTitles(profile.copy(autoReconnect = false), document))

        val edited = profile.copy(retryTimes = 3, switchToWifi = false, autoSwitch = false, onSleep = 1)
        store().save(listOf(edited))
        val stored = savedProfiles().single()
        assertEquals(true, stored["auto_reconnect"])
        assertEquals(3L, stored["retry_times"])
        assertEquals(false, stored["switch_to_wifi"])
        assertEquals(false, stored["ww_auto_switch"])
        assertEquals("pause", stored["on_sleep"])
        val result = store().load().single()
        assertEquals(listOf(true, false, false), listOf(result.autoReconnect, result.switchToWifi, result.autoSwitch))
        assertEquals(3 to 1, result.retryTimes to result.onSleep)
        writeProfiles(stored.filterKeys { it != "ww_auto_switch" })
        assertTrue("Profiles saved before Auto Switch get it on", store().load().single().autoSwitch)
    }

    // The chain decides two rows: Auto Switch needs a server of its own, Remote DNS a chain that takes connections
    @Test
    fun optionRowsFollowTheChain() {
        @Suppress("UNCHECKED_CAST")
        val packetNodes = (example()["nodes"] as List<Map<String, Any?>>).toMutableList().apply {
            set(0, mapOf("name" to "input", "type" to "HintPacketIN", "settings" to emptyMap<String, Any?>(), "next" to "tls"))
        }
        val direct = documentWith(mapOf("name" to "input", "type" to "HintConnectionIN", "settings" to emptyMap<String, Any?>(), "next" to "out"),
            mapOf("name" to "out", "type" to "TcpUdpConnector", "settings" to mapOf("address" to "dest_context->address", "port" to "dest_context->port")))
        val cases = mapOf(
            example() to listOf("Auto Reconnect", "Auto Switch", "Switch to Wi-Fi When Available", "On Sleep", "Log Level", "Remote DNS (Fake IP)"),
            documentWith(*packetNodes.toTypedArray()) to listOf("Auto Reconnect", "Auto Switch", "Switch to Wi-Fi When Available", "On Sleep", "Log Level"),
            direct to listOf("Auto Reconnect", "Switch to Wi-Fi When Available", "On Sleep", "Log Level", "Remote DNS (Fake IP)"),
        )
        for ((document, rows) in cases) {
            val profile = Profile(protocolType = "waterwall", autoReconnect = false, chainJson = NodeChain.json(document))
            assertEquals(rows, waterWallOptionTitles(profile, documentOf(profile)))
            val footer = waterWallOptionsFooter(document)
            assertEquals("Auto Switch" in rows, footer.contains("Auto Switch"))
            assertEquals("Remote DNS (Fake IP)" in rows, footer.contains("Remote DNS"))
        }
    }

    @Test
    fun chainScreenFollowsTheLinkedOrder() {
        val section = chainSections(example()).single()
        assertEquals("NODE CHAIN" to "Order follows each node's next field.", section.title to section.footer)
        assertEquals(listOf("1, HintConnectionIN, input", "2, TlsClient, tls", "3, TcpConnector, uplink, End"), descriptions(section))
        // A profile without a readable chain is read as the hint alone
        assertEquals(NodeChain.emptyDocument(), documentOf(Profile(chainJson = "")))
    }

    // A profile with nodes off the chain shows them in a section of their own
    @Test
    fun chainScreenShowsTheOtherNodes() {
        val sections = chainSections(branched())
        assertEquals(listOf("NODE CHAIN", "OTHER NODES"), sections.map { it.title })
        assertEquals("Order follows each node's next field.", sections[0].footer)
        assertEquals("Nodes off the chain above, such as a Router's targets or a HalfDuplexClient's upload and download paths.", sections[1].footer)
        assertEquals(listOf("1, HintConnectionIN, input", "2, TrojanClient, trojan", "3, MuxClient, mux", "4, HalfDuplexClient, half-duplex, End"), descriptions(sections[0]))
        assertEquals(listOf("Branch, ConnectionStripeClient, up", "Branch, ObfuscatorClient, obfuscator", "Branch, RtmpClient, rtmp", "Branch, TcpConnector, rtmp-connector, End",
            "Branch, RealityClient, down", "Branch, TcpConnector, reality-connector, End"), descriptions(sections[1]))
        // Deleting the only other node leaves the chain's section alone
        val spare = documentWith(*(nodesOf(example()) + mapOf("name" to "spare", "type" to "BlackHole", "settings" to emptyMap<String, Any?>())).toTypedArray())
        assertEquals(listOf("Branch, BlackHole, spare, End"), descriptions(chainSections(spare)[1]))
        assertEquals(listOf("NODE CHAIN"), chainSections(NodeChain.deletingNode(spare, "spare")).map { it.title })
    }

    @Test
    fun nodeEditorSavesSettingsAndKeepsTheRest() {
        val tls = NodeChain.chain(example())[1]
        assertEquals("{\n  \"sni\" : \"vpn.example.com\",\n  \"verify\" : true\n}", nodeSettingsText(tls["settings"] as Map<*, *>))
        assertNull(parseNodeSettings(nodeSettingsText(tls["settings"] as Map<*, *>)).error)
        assertEquals(emptyMap<String, Any?>(), parseNodeSettings("  \n").settings)
        // Columns count characters, not UTF-8 bytes
        val errors = mapOf("{\n  \"sni\": \"a\"\n  \"verify\": true\n}" to "Line 3, column 3: ", "{\"éé\": tru}" to "Line 1, column 8: ",
            "[1500]" to "The settings must be a JSON object.")
        for ((text, prefix) in errors) {
            val error = parseNodeSettings(text).error!!
            assertTrue("$text -> $error", error.startsWith(prefix))
        }
        val newlines = mapOf("{\n  \"a\": [" to "{\n  \"a\": [\n    ", "{\n  \"a\": 1," to "{\n  \"a\": 1,\n  ")
        for ((text, expected) in newlines) {
            val typed = withIndentedNewline(TextFieldValue(text, TextRange(text.length)), TextFieldValue(text + "\n", TextRange(text.length + 1)))
            assertEquals(expected, typed.text)
            assertEquals(expected.length, typed.selection.start)
        }
        // Keys red, values blue, the colon in the text color
        val key = androidx.compose.ui.graphics.Color.Red
        val value = androidx.compose.ui.graphics.Color.Blue
        val styled = JsonHighlight(key, value).filter(androidx.compose.ui.text.AnnotatedString("{\"sni\": \"a\", \"n\": 15, \"ok\": true}")).text
        val colors = styled.spanStyles.associate { styled.text.substring(it.start, it.end) to it.item.color }
        assertEquals(mapOf("\"sni\"" to key, "\"a\"" to value, "\"n\"" to key, "15" to value, "\"ok\"" to key, "true" to value), colors)
    }

    @Test
    fun importKeepsTheChainAndItsServer() {
        val raw = """{"nodes": [{"name": "input", "type": "HintPacketIN", "settings": {}, "next": "sock"}, {"name": "sock", "type": "RawSocket", "settings": {}}]}"""
        val (blocked, problem) = importedDocument(raw.toByteArray())
        assertNull(blocked)
        assertEquals("Node \"sock\" is a RawSocket node: raw socket nodes cannot be imported.", problem)
        val document = importedDocument(exampleJson.toByteArray()).first!!
        assertEquals("Example TLS chain: 3 nodes on the chain. Import replaces the profile's chain.", importFooter(document))
        val imported = Profile(protocolType = "waterwall", chainJson = NodeChain.json(document)).withWaterWallServer()
        assertEquals("vpn.example.com" to "443", imported.server to imported.port)
        assertEquals("" to "", Profile(protocolType = "waterwall").withWaterWallServer().let { it.server to it.port })
    }

    // A chain WaterWall refuses when it builds it ends the VPN with WaterWall's reason instead of being retried for ever
    @Test
    fun refusedProfileEndsWithWaterWallsReason() {
        val fatal = fatalText("2026-11-20 09:25:40.146 FATAL JSON Error: VlessClient->settings->target-address (string field) is required\n")
        assertEquals("JSON Error: VlessClient->settings->target-address (string field) is required", fatal)
        val next = fatalText("2026-11-20 09:25:40.147 FATAL NodeManager: node startup failure: node (\"<restricted>\") create() returned NULL handle")
        assertEquals("NodeManager: node startup failure: node (\"<restricted>\") create() returned NULL handle", next)
        assertNull(fatalText("2026-11-20 09:25:40.146 ERROR TcpConnector: connection refused"))
        assertEquals("WaterWall refused the profile: JSON Error: VlessClient->settings->target-address (string field) is required",
            refusedProfileReason(fatal, runtimeReady = false))
        // Whatever the fatal line says: before the runtime is ready it is WaterWall refusing the profile
        for (problem in listOf(next, "NodeManager: node creation failure: VlessClient", "Restricted config: node TunDevice")) {
            assertEquals("WaterWall refused the profile: $problem", refusedProfileReason(problem, runtimeReady = false))
        }
        // Once the runtime was ready, or without a fatal line, a failure is retried as before
        assertNull(refusedProfileReason(fatal, runtimeReady = true))
        assertNull(refusedProfileReason(null, runtimeReady = false))
        assertNull(refusedProfileReason("", runtimeReady = false))
    }

    @Test
    fun screenGlyphsAreValidPaths() {
        // The gear, document, pencil and alert symbols of these screens are drawn from these paths
        for (glyph in Glyph.entries) {
            assertTrue(glyph.name, androidx.compose.ui.graphics.vector.PathParser().parsePathString(glyph.path).toNodes().size > 1)
        }
    }

    // Behind a local proxy the probe asks the proxy as an app would; the tunnel then routes nothing and leaves DNS alone
    @Test
    fun localProxyProbeAndTunnelSettings() {
        for (proxy in listOf(NodeChain.INPUT_SOCKS5, NodeChain.INPUT_HTTP)) {
            ServerSocket(0, 4, InetAddress.getByName("127.0.0.1")).use { listener ->
                var request: String? = null
                var get: String? = null
                val server = thread {
                    listener.accept().use { socket ->
                        val input = java.io.DataInputStream(socket.getInputStream())
                        val output = socket.getOutputStream()
                        if (proxy == NodeChain.INPUT_SOCKS5) {
                            input.readFully(ByteArray(3))
                            output.write(byteArrayOf(5, 0))
                            val connect = ByteArray(10).also { input.readFully(it) }
                            request = "${connect[1]} ${(4..7).joinToString(".") { (connect[it].toInt() and 0xff).toString() }}:${(connect[8].toInt() and 0xff shl 8) or (connect[9].toInt() and 0xff)}"
                            output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 4, 0x38))
                        } else {
                            val header = StringBuilder()
                            while (!header.endsWith("\r\n\r\n")) header.append(input.read().toChar())
                            request = header.toString()
                            output.write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
                        }
                        val buffer = ByteArray(512)
                        val count = input.read(buffer)
                        get = if (count > 0) String(buffer, 0, count) else null
                        output.write("HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\n\r\n".toByteArray())
                    }
                }
                assertNull(localProxyProbe(proxy, listener.localPort, "1.1.1.1"))
                server.join(5000)
                if (proxy == NodeChain.INPUT_SOCKS5) assertEquals("1 1.1.1.1:80", request) else assertEquals("CONNECT 1.1.1.1:80 HTTP/1.1\r\nHost: 1.1.1.1:80\r\n\r\n", request)
                assertTrue(get, get!!.startsWith("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n"))
                // A port another app listens on cannot take WaterWall's listener
                assertFalse(localPortIsFree(listener.localPort))
            }
        }
        val closed = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        assertEquals("127.0.0.1:$closed accepts no connection", localProxyProbe(NodeChain.INPUT_HTTP, closed, "1.1.1.1"))
        assertTrue(localPortIsFree(closed))
        assertEquals("the probe address is not an IPv4 address", localProxyProbe(NodeChain.INPUT_SOCKS5, closed, "example.com"))

        fun candidate(proxy: String?) = WaterWallCandidate("WaterWall", "{}", "127.0.0.1", "10.89.0.1", "1.1.1.1", "1.1.1.1", true, false,
            listOf("198.18.0.2"), null, false, proxy, NodeChain.portForInput(proxy ?: NodeChain.INPUT_TUN))
        val system = WaterWallClient.settingsFor(candidate(null))
        assertEquals(listOf("0.0.0.0" to 0), system.routes)
        assertEquals(listOf("198.18.0.2"), system.dnsServers)
    }
}
