package tr.com.srp.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.zip.GZIPInputStream

/** The Kotlin chain builder and node chain against what iOS's answered for the same inputs; see Android/tools/chain_parity. */
class ChainConfigParityTest {
    private fun cases(): List<Map<String, Any?>> {
        val stream = checkNotNull(javaClass.classLoader!!.getResourceAsStream("chain_config_parity.json.gz"))
        val text = GZIPInputStream(stream).bufferedReader().use { it.readText() }
        @Suppress("UNCHECKED_CAST")
        return Json.parse(text) as List<Map<String, Any?>>
    }

    /** Numbers compare by value, so that 10.0 and 10 are the same setting. */
    private fun normal(value: Any?): Any? = when (value) {
        is Map<*, *> -> value.entries.associate { it.key to normal(it.value) }
        is List<*> -> value.map { normal(it) }
        is Number -> value.toDouble()
        Json.Null -> null
        else -> value
    }

    private fun nullable(value: Any?): String? = if (value == null || value == Json.Null) null else value as String

    /** An answer that raised an exception on iOS, which the Kotlin port need not copy */
    private fun raised(value: Any?) = value is Map<*, *> && value.containsKey("__exception__")

    @Test
    fun answersMatchIos() {
        val failures = ArrayList<String>()
        var compared = 0
        var documents = 0
        for (item in cases()) {
            val check = { what: String, expected: Any?, actual: Any? ->
                if (!raised(expected) && normal(expected) != normal(actual)) failures.add("$what\n  case: ${Json.write(item.filterKeys { it !in setOf("nodes", "json", "legacyDocument") })}\n  iOS: ${Json.write(normal(expected))}\n  Kotlin: ${Json.write(normal(actual))}")
            }
            val exception = item["exception"] != null
            when (item["kind"]) {
                // nodeChainAnswersMatchIos compares these
                "node-chain", "node-json", "node-edit", "node-runtime" -> continue
                "wg-conf" -> {
                    if (exception) continue
                    val result = ChainConfig.wireGuardWithConfig(item["config"] as String)
                    check("wireguard config", item["result"], result?.let(::wireGuardMap))
                }
                "wg-keys" -> {
                    if (exception) continue
                    val result = ChainConfig.wireGuardWithKeys(item["privateKey"] as String, item["serverPublicKey"] as String, item["server"] as String,
                        (item["port"] as Number).toLong(), item["clientAddress"] as String, (item["keepalive"] as Number).toLong())
                    check("wireguard keys", item["result"], result?.let(::wireGuardMap))
                }
                else -> {
                    if (item["skipped"] != null) continue
                    @Suppress("UNCHECKED_CAST")
                    val configuration = item["configuration"] as Map<String, Any?>
                    // iOS raises an exception on some wrong types; here it is enough that they do not pass.
                    if (exception) {
                        runCatching { ChainConfig.validationError(configuration) }
                        continue
                    }
                    compared++
                    val error = ChainConfig.validationError(configuration)
                    check("validation", item["error"], error)
                    if (error == null && nullable(item["error"]) == null) {
                        check("json", item["json"], ChainConfig.jsonWithConfiguration(configuration)?.let { Json.parse(it) })
                        check("summary", item["summary"], ChainConfig.summary(configuration))
                        check("flags", item["flags"], listOf(ChainConfig.isWireGuard(configuration), ChainConfig.isDirect(configuration),
                            ChainConfig.needsApplicationSecret(configuration), ChainConfig.needsOuterSecret(configuration), ChainConfig.usesTls(configuration),
                            ChainConfig.allowsFragmentation(configuration), ChainConfig.allowsRouting(configuration), ChainConfig.usesUdpCarrier(configuration)))
                    }
                    val secret = item["secret"].takeIf { it != Json.Null } as String?
                    val outerSecret = item["outerSecret"].takeIf { it != Json.Null } as String?
                    @Suppress("UNCHECKED_CAST")
                    val options = item["options"].takeIf { it != Json.Null } as Map<String, Any?>?
                    check("secret", item["secretError"], ChainConfig.applicationSecretError(secret, configuration))
                    check("username", item["usernameError"], ChainConfig.applicationUsernameError(options?.get("username") as String?, secret, configuration))
                    check("outer secret", item["outerError"], ChainConfig.outerSecretError(outerSecret, configuration))
                    val server = item["server"].takeIf { it != Json.Null } as String?
                    val sni = item["sni"].takeIf { it != Json.Null } as String?
                    val nodes = ChainConfig.nodesJson(configuration, server, (item["port"] as Number).toLong(), sni, item["verifyTLS"] as Boolean, secret, outerSecret, options)
                    check("nodes", item["nodes"], nodes?.let { Json.parse(it) })
                    // The node chain a profile of the former form becomes
                    val document = NodeChain.documentForConfiguration(configuration, server, (item["port"] as Number).toLong(), sni, item["verifyTLS"] as Boolean,
                        secret, outerSecret, options)
                    check("legacy document", item["legacyDocument"], document)
                    if (document != null) documents++
                }
            }
            if (failures.size >= 15) break
        }
        assertTrue(failures.take(15).joinToString("\n"), failures.isEmpty())
        assertTrue("The corpus should cover thousands of chains, compared $compared", compared > 5000)
        assertTrue("Thousands of chains should convert to node documents, converted $documents", documents > 2000)
    }

    @Test
    fun nodeChainAnswersMatchIos() {
        val failures = ArrayList<String>()
        val compared = HashMap<String, Int>()
        for (item in cases()) {
            val kind = item["kind"] as? String ?: continue
            if (!kind.startsWith("node-") || item["exception"] != null) continue
            val check = { what: String, expected: Any?, actual: Any? ->
                if (!raised(expected) && normal(expected) != normal(actual)) failures.add("$what\n  case: ${Json.write(item)}\n  iOS: ${Json.write(normal(expected))}\n  Kotlin: ${Json.write(normal(actual))}")
            }
            compared[kind] = (compared[kind] ?: 0) + 1
            val document = item["document"]
            @Suppress("UNCHECKED_CAST")
            when (kind) {
                "node-chain" -> {
                    check("validation", item["error"], NodeChain.validationError(document))
                    if (document is Map<*, *>) {
                        check("chain", item["chain"], NodeChain.chain(document))
                        check("hint", item["hint"], NodeChain.hint(document))
                        check("summary", item["summary"], NodeChain.summary(document))
                        check("endpoints", item["endpoints"], NodeChain.endpoints(document).map { (host, port) -> mapOf("host" to host, "port" to port) })
                        check("flags", item["flags"], listOf(NodeChain.usesGeoIp(document), NodeChain.usesUdpCarrier(document)))
                    }
                }
                "node-json" -> {
                    val (parsed, error) = NodeChain.documentWithJson(item["json"] as? String)
                    check("parsed", item["parsed"], parsed)
                    check("parse error", item["error"], error)
                }
                "node-edit" -> {
                    val name = item["name"] as String
                    val node = item["node"] as Map<String, Any?>?
                    val result = when (item["operation"]) {
                        "replace" -> NodeChain.replacingNode(document as Map<String, Any?>, name, node!!)
                        "insert" -> NodeChain.insertingNode(document as Map<String, Any?>, node!!, name)
                        else -> NodeChain.deletingNode(document as Map<String, Any?>, name)
                    }
                    check("edit", item["result"], result)
                    check("edit validation", item["resultError"], NodeChain.validationError(result))
                }
                "node-runtime" -> {
                    val (runtime, error) = NodeChain.runtimeDocument(document as Map<String, Any?>, item["input"] as String, item["fakeDNS"] as Boolean,
                        nullable(item["geoIPDatabasePath"]), item["addresses"] as Map<String, String>)
                    check("runtime", item["runtime"], runtime)
                    check("runtime error", item["runtimeError"], error)
                }
            }
            if (failures.size >= 15) break
        }
        assertTrue(failures.take(15).joinToString("\n"), failures.isEmpty())
        assertTrue("The corpus should cover the node editor, compared $compared",
            (compared["node-chain"] ?: 0) > 2000 && (compared["node-edit"] ?: 0) > 500 && (compared["node-runtime"] ?: 0) > 500 && (compared["node-json"] ?: 0) >= 10)
    }

    private fun wireGuardMap(result: ChainConfig.WireGuard): Map<String, Any?> = mapOf(
        "nodes" to Json.parse(result.nodesJson), "tunnelAddress" to result.tunnelAddress, "allowedIPs" to result.allowedIps,
        "dnsServers" to result.dnsServers, "endpointIP" to result.endpointIp, "endpointIPs" to result.endpointIps,
    )

    @Test
    fun syntaxErrorsCarryTheirOffset() {
        val error = runCatching { Json.parse("{\n  \"a\": 1,\n}") }.exceptionOrNull() as Json.SyntaxError
        assertEquals(12, error.offset)
    }
}
