package tr.com.srp.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.zip.GZIPInputStream

/** The Kotlin chain builder against what iOS's answered for the same inputs; see Android/tools/chain_parity. */
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

    @Test
    fun answersMatchIos() {
        val failures = ArrayList<String>()
        var compared = 0
        for (item in cases()) {
            val check = { what: String, expected: Any?, actual: Any? ->
                if (normal(expected) != normal(actual)) failures.add("$what\n  case: ${Json.write(item.filterKeys { it !in setOf("nodes", "json") })}\n  iOS: ${Json.write(normal(expected))}\n  Kotlin: ${Json.write(normal(actual))}")
            }
            val exception = item["exception"] != null
            when (item["kind"]) {
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
                    val nodes = ChainConfig.nodesJson(configuration, item["server"].takeIf { it != Json.Null } as String?, (item["port"] as Number).toLong(),
                        item["sni"].takeIf { it != Json.Null } as String?, item["verifyTLS"] as Boolean, secret, outerSecret, options)
                    check("nodes", item["nodes"], nodes?.let { Json.parse(it) })
                }
            }
            if (failures.size >= 15) break
        }
        assertTrue(failures.take(15).joinToString("\n"), failures.isEmpty())
        assertTrue("The corpus should cover thousands of chains, compared $compared", compared > 5000)
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
