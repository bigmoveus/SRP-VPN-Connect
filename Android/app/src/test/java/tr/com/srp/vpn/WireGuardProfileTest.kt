package tr.com.srp.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The WireGuard protocol as the iPhone app reads and runs it (SRPWireGuardClient.m, NodeModel, CreateVC). */
class WireGuardProfileTest {
    private val key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="   // bytes 0..31
    private val conf = """
        [Interface]
        PrivateKey = $key
        Address = 10.66.66.3/32, fd66::3/128
        DNS = 1.1.1.1, 8.8.8.8
        MTU = 1280

        [Peer]
        PublicKey = $key
        PresharedKey = $key
        Endpoint = vpn.example.com:51821
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
    """.trimIndent()

    @Test
    fun readsAConfigAsTheIosClientDoes() {
        val (parsed, problem) = WireGuardConf.parse(conf)
        assertNull(problem)
        parsed!!
        assertEquals("vpn.example.com" to 51821, parsed.endpointHost to parsed.endpointPort)
        assertEquals(listOf("10.66.66.3/32", "fd66::3/128"), parsed.addresses)
        assertEquals(25, parsed.keepalive)
        assertEquals("The config has no [Interface] PrivateKey.", WireGuardConf.parse("[Interface]\nthis is not a WireGuard config\n[Peer]\n").second)
        assertEquals("The config has no [Interface] Address.", WireGuardConf.parse(conf.lines().filter { !it.startsWith("Address") }.joinToString("\n")).second)
        assertEquals("[2001:db8::7]".removeSurrounding("[", "]") to 51820, WireGuardConf.endpointParts("[2001:db8::7]:51820"))
    }

    @Test
    fun givesTheEngineHexKeysAndAFreshPeer() {
        val hex = (0 until 32).joinToString("") { "%02x".format(it) }
        assertEquals(hex, WireGuardConf.base64ToHex(key))
        assertNull(WireGuardConf.base64ToHex("not-a-key"))
        val parsed = WireGuardConf.parse(conf).first!!
        val uapi = parsed.uapi("192.0.2.7")!!
        assertTrue(uapi.startsWith("private_key=$hex\nlisten_port=0\nreplace_peers=true\npublic_key=$hex\npreshared_key=$hex\n"))
        assertTrue("endpoint=192.0.2.7:51821\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n" in uapi)
        assertTrue("endpoint=[2001:db8::7]:51821\n" in parsed.peer("2001:db8::7", 25)!!)
    }

    @Test
    fun readsTheEnginesPeerState() {
        val uapi = "private_key=0011\nlisten_port=51000\npublic_key=aabb\nendpoint=192.0.2.7:51820\nlast_handshake_time_sec=1794170000\n" +
            "last_handshake_time_nsec=12\ntx_bytes=1480\nrx_bytes=92\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\nerrno=0\n"
        assertEquals(Triple(1794170000L, 92L, 1480L), WireGuardConf.peerState(uapi))
        assertNull(WireGuardConf.peerState("private_key=0011\nlisten_port=51000\nerrno=0\n"))
    }

    @Test
    fun makesTheVpnInterfaceTheConfigAsksFor() {
        val settings = WireGuardConf.parse(conf).first!!.tunnelSettings()
        assertEquals("10.66.66.3", settings.address)
        assertEquals(32, settings.addressPrefix)
        assertEquals(listOf("fd66::3" to 128), settings.extraAddresses)
        assertEquals(listOf("0.0.0.0" to 0, "::" to 0), settings.routes)
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), settings.dnsServers)
        assertEquals(1280, settings.mtu)
        assertEquals(1420, WireGuardConf.parse(conf.replace("MTU = 1280\n", "")).first!!.tunnelSettings().mtu)
    }

    @Test
    fun serverAndPortReplaceTheImportedEndpoint() {
        var profile = Profile(protocolType = "wireguard", wgConfig = conf, server = "vpn.example.com", port = "51821")
        assertEquals(conf, profile.wgEffectiveConfig())
        profile = profile.copy(port = "51822")
        assertTrue("\nEndpoint = vpn.example.com:51822\n" in profile.wgEffectiveConfig()!!)
        profile = profile.copy(server = "2001:db8::7")
        assertTrue("\nEndpoint = [2001:db8::7]:51822\n" in profile.wgEffectiveConfig()!!)
        // Empty fields keep the file's endpoint; WaterWall's WireGuard mode keeps its file as it is
        assertEquals(conf, profile.copy(server = "", port = "").wgEffectiveConfig())
        assertEquals(conf, profile.copy(protocolType = "waterwall").wgEffectiveConfig())
        // Manual configuration without a Port: WireGuard's own port, as the field's hint says
        val manual = Profile(protocolType = "wireguard", server = "vpn.example.com", port = "", wgPrivateKey = key, wgPeerPublicKey = key, wgAddress = "10.66.66.3/32")
        assertTrue("\nEndpoint = vpn.example.com:51820\n" in manual.wgEffectiveConfig()!!)
    }

    @Test
    fun importsAsTheIosEditorDoes() {
        val imported = importedWireGuard(conf, Profile(protocolType = "wireguard"))!!
        assertEquals(conf, imported.wgConfig)
        assertEquals("vpn.example.com" to "51821", imported.server to imported.port)
        assertNull(importedWireGuard("[Interface]\nPrivateKey = x\n", Profile(protocolType = "wireguard")))
    }

    @Test
    fun savesWhatTheIosEditorSaves() {
        val profile = Profile(protocolType = "wireguard", server = "", wgConfig = conf)
        assertEquals("Enter the server address.", validationMessage(profile))
        assertEquals("Import or enter a WireGuard configuration.", validationMessage(Profile(protocolType = "wireguard", server = "vpn.example.com")))
        assertNull(validationMessage(profile.copy(server = "vpn.example.com")))
        assertEquals("WireGuard VPN", profile.nodeName)
        assertEquals("51820", profile.copy(port = "").effectivePort)
        assertEquals("Overridden by import", wireGuardConfigState(profile))
        assertTrue("no Switch to Wi-Fi option" in WIREGUARD_OPTIONS_FOOTER)
        assertTrue(wireGuardNoHandshakeMessage(51821).endsWith("or UDP port 51821 may be closed."))
    }
}
