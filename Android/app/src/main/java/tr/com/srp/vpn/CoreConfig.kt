package tr.com.srp.vpn

import org.json.JSONArray
import org.json.JSONObject

/** The same core settings as iOS, apart from the log folder and DNS that Android cannot find by itself. */
internal fun coreJson(logFolder: String, dnsServers: List<String>): String {
    // shortcut: always DEBUG because the log is all this screen has, a level setting comes with the editor port.
    val logger = { file: String -> JSONObject().put("loglevel", "DEBUG").put("file", file).put("console", true) }
    val dns = JSONObject().put("domain-strategy", "prefer-ipv4").put("tries", 5)
    // c-ares finds no DNS servers on Android by itself, and a slow answer needs more than its 2 default tries.
    if (dnsServers.isNotEmpty()) dns.put("servers", JSONArray(dnsServers))
    return JSONObject()
        .put(
            "log",
            JSONObject()
                .put("path", "$logFolder/")
                .put("core", logger("ww-core.log"))
                .put("network", logger("ww-network.log"))
                .put("dns", logger("ww-dns.log"))
                .put("internal", logger("ww-internal.log")),
        )
        .put(
            "misc",
            JSONObject()
                .put("workers", 1)
                .put("ram-profile", "minimal")
                .put("mtu", TUNNEL_MTU)
                .put("splice", false)
                .put("try-enabling-bbr", false)
                .put("tcp-tune", false),
        )
        .put("dns", dns)
        .put("configs", JSONArray(listOf("hosted-nodes.json")))
        .toString()
}

/** What the tunnel offers apps as DNS: the chain's fake DNS when it has one, as on iOS. Throws on invalid JSON. */
internal fun tunnelDnsServers(nodesJson: String): List<String> {
    val nodes = JSONObject(nodesJson).getJSONArray("nodes")
    for (index in 0 until nodes.length()) {
        val fakeDns = nodes.getJSONObject(index).optJSONObject("settings")?.optJSONObject("fake-dns") ?: continue
        if (fakeDns.optBoolean("enabled")) return listOf(fakeDns.getString("address"))
    }
    return listOf("1.1.1.1", "1.0.0.1")
}

internal const val TUNNEL_MTU = 1420
