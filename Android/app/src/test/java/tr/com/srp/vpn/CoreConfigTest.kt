package tr.com.srp.vpn

import org.json.JSONException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class CoreConfigTest {
    @Test
    fun coreJsonCarriesNetworkDnsTriesAndLogFolder() {
        val core = JSONObject(coreJson("/data/cache", listOf("10.0.2.3", "fe80::1%wlan0")))
        val dns = core.getJSONObject("dns")
        assertEquals("""["10.0.2.3","fe80::1%wlan0"]""", dns.getJSONArray("servers").toString())
        assertEquals(5, dns.getInt("tries"))
        assertEquals("/data/cache/", core.getJSONObject("log").getString("path"))
    }

    @Test
    fun coreJsonWithoutNetworkDnsLeavesServersOut() {
        assertFalse(JSONObject(coreJson("/data/cache", emptyList())).getJSONObject("dns").has("servers"))
    }

    @Test
    fun appsGetTheFakeDnsOfTheChain() {
        val nodes = """{"nodes":[{"type":"NEPacketDevice"},
            {"type":"PacketsToConnection","settings":{"fake-dns":{"enabled":true,"address":"198.18.0.2"}}}]}"""
        assertEquals(listOf("198.18.0.2"), tunnelDnsServers(nodes))
    }

    @Test
    fun appsGetPublicDnsWhenFakeDnsIsOff() {
        val nodes = """{"nodes":[{"settings":{"fake-dns":{"enabled":false,"address":"198.18.0.2"}}}]}"""
        assertEquals(listOf("1.1.1.1", "1.0.0.1"), tunnelDnsServers(nodes))
    }

    @Test(expected = JSONException::class)
    fun invalidJsonIsRefused() {
        tunnelDnsServers("{not json")
    }
}
