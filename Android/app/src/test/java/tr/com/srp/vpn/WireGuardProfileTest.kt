package tr.com.srp.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
        assertTrue("endpoint=[2001:db8::7]:51821\n" in parsed.peer("2001:db8::7", "25")!!)
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

    private val awgPrivate = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    private val awgPublic = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    private val awgHead = "[Interface]\nPrivateKey = $awgPrivate\nAddress = 10.67.3.3/32\n"
    private val awgPeer = "\n[Peer]\nPublicKey = $awgPublic\nEndpoint = 192.0.2.7:51833\nAllowedIPs = 0.0.0.0/0\n"

    /** AmneziaWG's settings as the engine gets them (SROptionsTests testAmneziaWGEngineSettings): every key of the awg tool's files */
    @Test
    fun givesAmneziaWGItsSettings() {
        val text = awgHead + "Jc = 4\njmin = 40\nJmax = 120\nS1 = 48\nS2 = 40\nS3 = 28\nS4 = 16\nH1 = 2100000000-2199999999\n" +
            "H2 = 2200000000 - 2299999999\nH3 = 2300000000\nH4 = 2400000000-2499999999\nI1 = <b 0xc700000001><r 8><rc 8><t><rd 4>\n" +
            "HeaderProtectionKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\nContentPaddingAddition = 8-64\nRekeyAfterTime = 110-125\n" +
            "RekeyTimeout = 4-6\nRejectAfterTime = 170-185\nKeepaliveTimeout = 9-11\nMaxHandshakeAttempts = 18-22\nRandomTrailers = on\n" +
            "DisableCookies = 1\n" + awgPeer + "PersistentKeepalive = 20-30\n"
        val (parsed, problem) = WireGuardConf.parse(text)
        assertNull(problem)
        val uapi = parsed!!.uapi("192.0.2.7", amnezia = true)!!
        val lines = listOf("jc=4", "jmin=40", "jmax=120", "s1=48", "s2=40", "s3=28", "s4=16", "h1=2100000000-2199999999", "h2=2200000000-2299999999",
            "h3=2300000000", "h4=2400000000-2499999999", "i1=<b 0xc700000001><r 8><rc 8><t><rd 4>", "header_protection_key=" + "03".repeat(32),
            "content_padding_addition=8-64", "rekey_after_time=110-125", "rekey_timeout=4-6", "reject_after_time=170-185", "keepalive_timeout=9-11",
            "max_handshake_attempts=18-22", "random_trailers=true", "disable_cookies=true", "endpoint=192.0.2.7:51833", "persistent_keepalive_interval=20-30")
        lines.forEach { assertTrue(it, "$it\n" in uapi) }
        assertTrue(uapi.indexOf("random_trailers=") < uapi.indexOf("public_key="))
        assertEquals(1404, parsed.tunnelMtu(true))
        assertEquals(4L * (16 + 32 + 1404), parsed.silenceBytes(true))
        // The note on RandomTrailers with ranges: only without a header protection key (the fork's engine covers the rest)
        assertFalse(parsed.trailersWithRanges)
        assertTrue(WireGuardConf.parse(text.replace(Regex("HeaderProtectionKey = .*\n"), "")).first!!.trailersWithRanges)
        assertFalse(WireGuardConf.parse(text.replace(Regex("HeaderProtectionKey = .*\n"), "").replace(Regex("(H[12] = )(\\d+) ?- ?\\d+"), "$1$2"))
            .first!!.trailersWithRanges)
        // WireGuard's engine gets none of them, and the same file with WireGuard is refused by name
        assertTrue("jc=" !in parsed.uapi("192.0.2.7", amnezia = false)!!)
        assertEquals("This configuration has AmneziaWG settings (Jc, Jmin, Jmax, S1, …): use the AmneziaWG VPN protocol for it.",
            amneziaKeysMessage(parsed.amneziaKeys))
        // An MTU in the file wins; without padding a keepalive is S4 + 32 bytes and the bound stays WireGuard's
        val simple = WireGuardConf.parse(awgHead + "MTU = 1380\nS1 = 64\nS2 = 58\nS3 = 30\nS4 = 24\n" + awgPeer + "PersistentKeepalive = 25\n").first!!
        assertEquals(1380, simple.tunnelMtu(true))
        assertEquals(296L, simple.silenceBytes(true))
        val none = WireGuardConf.parse(awgHead + awgPeer + "PersistentKeepalive = off\n").first!!
        assertEquals(1420, none.tunnelMtu(true))
        assertTrue("persistent_keepalive_interval" !in none.uapi("192.0.2.7", amnezia = true)!!)
    }

    /** What AmneziaWG refuses before connecting, with the setting named (SROptionsTests testAmneziaWGRefusesInvalidSettings) */
    @Test
    fun refusesInvalidAmneziaWGSettings() {
        mapOf(
            "S1 = 70000" to "S1 must be a whole number from 0 to 65535.",
            "Jc = -1" to "Jc must be a whole number from 0 to 65535.",
            "H1 = abc" to "H1 must be a number or a range such as 1000000-1999999.",
            "H2 = 300-200" to "H2 must be a number or a range such as 1000000-1999999.",
            "H3 = 4294967296" to "H3 must be a number or a range such as 1000000-1999999.",
            "RekeyTimeout = 1-2-3" to "RekeyTimeout must be a number or a range such as 10-20.",
            "ContentPaddingAddition = 70000" to "ContentPaddingAddition must be a number or a range such as 10-20.",
            "RandomTrailers = maybe" to "RandomTrailers must be on or off.",
            "HeaderProtectionKey = not-a-key" to "the HeaderProtectionKey is not valid base64 (32 bytes).",
        ).forEach { (line, message) -> assertEquals(line, message, WireGuardConf.parse("$awgHead$line\n$awgPeer").second) }
        val range = WireGuardConf.parse(awgHead + awgPeer + "PersistentKeepalive = 20-30\n").first!!
        assertEquals(listOf("a PersistentKeepalive range"), range.amneziaKeys)
        assertEquals("AmneziaWG refused the configuration: failed to parse I1: unknown tag <x>",
            engineRefusedMessage("AmneziaWG", "Unable to set the configuration: IPC error -22: failed to parse I1: unknown tag <x>"))
        assertEquals("AmneziaWG: the engine refused the configuration (see log).", engineRefusedMessage("AmneziaWG", null))
    }

    /** AmneziaWG's profile: manual fields, the editor's texts, the protocol's name and port (SROptionsTests testAmneziaWGManualFieldsAndStorage) */
    @Test
    fun amneziaWGProfilesAsTheIosEditorMakesThem() {
        val profile = Profile(protocolType = "amnezia", server = "vpn.example.com", port = "", wgPrivateKey = awgPrivate, wgPeerPublicKey = awgPublic,
            wgAddress = "10.67.0.3/32", wgS1 = 64, wgS4 = 24, wgH1 = "1100000000-1199999999", wgH4 = " 1400000000 ",
            wgHeaderProtectionKey = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=", wgContentPaddingAddition = "8-64", wgRekeyTimeout = "4-6",
            wgMaxHandshakeAttempts = "18-22", wgRandomTrailers = true)
        val effective = profile.wgEffectiveConfig()!!
        listOf("S1 = 64", "S4 = 24", "H1 = 1100000000-1199999999", "H4 = 1400000000", "HeaderProtectionKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
            "ContentPaddingAddition = 8-64", "RekeyTimeout = 4-6", "MaxHandshakeAttempts = 18-22", "RandomTrailers = on",
            "Endpoint = vpn.example.com:51820").forEach { assertTrue(it, "$it\n" in effective) }
        assertTrue("DisableCookies" !in effective)
        assertNull(WireGuardConf.parse(effective.replace("vpn.example.com", "192.0.2.7")).second)
        // The same fields with WireGuard: no AmneziaWG lines
        assertTrue("S1 =" !in profile.copy(protocolType = "wireguard").wgEffectiveConfig()!!)
        assertEquals("AmneziaWG VPN", profile.nodeName)
        assertEquals("51820", profile.effectivePort)
        assertTrue(profile.isWireGuard && profile.isAmnezia && !profile.isPlainWireGuard)
        assertEquals("Import or enter an AmneziaWG configuration.", validationMessage(Profile(protocolType = "amnezia", server = "vpn.example.com")))
        // An imported file: the editor's Server and Port replace its Endpoint as for WireGuard
        val imported = Profile(protocolType = "amnezia", wgConfig = "$awgHead${awgPeer}", server = "192.0.2.7", port = "51830")
        assertTrue("\nEndpoint = 192.0.2.7:51830\n" in imported.wgEffectiveConfig()!!)
        assertTrue("no Switch to Wi-Fi option" in AMNEZIAWG_OPTIONS_FOOTER)
        assertTrue(wireGuardNoHandshakeMessage(51830, amnezia = true).contains("obfuscation settings (S1-S4, H1-H4, HeaderProtectionKey, RandomTrailers)"))
        assertEquals("S1", amneziaSettingIn("[Interface]\nPrivateKey = x\n  S1 = 64\n"))
        assertNull(amneziaSettingIn(conf))
    }
}
