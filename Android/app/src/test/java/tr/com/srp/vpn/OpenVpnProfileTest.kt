package tr.com.srp.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The OpenVPN editor's save and import rules (CreateVC.m), the tunnel the pushed options make, the stunnel TCP profile, the
 * split handshake and the messages (SRPOpenVPNClient.mm), as testOpenVPNPushedSettingsAndProfileRemotes checks them on iOS.
 */
class OpenVpnProfileTest {
    private val ovpn = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\n<ca>\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n</ca>\n"
    private val complete = Profile(protocolType = "openvpn", server = "vpn.example.com", port = "1194", ovpnProfile = ovpn)

    @Test
    fun savesWhatTheIosEditorSaves() {
        assertNull(openVpnValidationMessage(complete))
        assertEquals("Enter the server address.", openVpnValidationMessage(complete.copy(server = "")))
        assertEquals("Import an OpenVPN profile.", openVpnValidationMessage(complete.copy(ovpnProfile = "")))
        val withLogin = complete.copy(ovpnProfile = ovpn + "auth-user-pass\n")
        assertEquals("This OpenVPN profile needs a username and password.", openVpnValidationMessage(withLogin))
        assertNull(openVpnValidationMessage(withLogin.copy(username = "user", password = "secret")))
        // a commented line asks for nothing
        assertFalse(OpenVpnProfileText.needsAuth(ovpn + "# auth-user-pass\n"))
        assertEquals("Enter a stunnel port between 1 and 65535.", openVpnValidationMessage(complete.copy(ovpnStunnelEnabled = true, ovpnStunnelPort = "70000")))
        assertEquals("First Chunk can be at most 4096 bytes.",
            openVpnValidationMessage(complete.copy(ovpnStunnelEnabled = true, tlsFragMode = 2, tlsFragFirst = 5000)))
        assertTrue(complete.isOpenVpn)
        assertEquals("OpenVPN", complete.nodeName)
        assertEquals("1194", complete.copy(port = "").effectivePort)
    }

    @Test
    fun importsAsTheIosEditorDoes() {
        val (imported, problem) = importedOpenVpnText(ovpn.replace("remote vpn.example.com 1194", "remote other.example.com 443"), "ovpn", Profile(protocolType = "openvpn"))
        assertNull(problem)
        assertEquals("other.example.com", imported!!.server)
        assertEquals("443", imported.port)
        assertEquals("The file does not look like an OpenVPN profile (.ovpn).", importedOpenVpnText("hello", "ovpn", complete).second)
        assertTrue(importedOpenVpnText(ovpn.replace("AAAA", "A!A"), "ovpn", complete).second!!.startsWith("A certificate embedded in this profile is damaged"))
        assertEquals("The file does not look like a PEM certificate (no BEGIN CERTIFICATE block).", importedOpenVpnText("x", "ca", complete).second)
        assertEquals("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
            importedOpenVpnText("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "ca", complete).first!!.ovpnStunnelCa)
    }

    @Test
    fun makesTheTunnelThePushedOptionsAskFor() {
        val subnet = OpenVpnSettings.tunnelSettings(listOf(
            listOf("redirect-gateway", "def1", "bypass-dhcp"), listOf("dhcp-option", "DNS", "1.1.1.1"), listOf("topology", "subnet"),
            listOf("ifconfig", "10.8.0.2", "255.255.255.0"), listOf("route", "192.0.2.0", "255.255.255.0", "net_gateway"), listOf("tun-mtu", "1500")))!!
        assertEquals("10.8.0.2", subnet.address)
        assertEquals(24, subnet.addressPrefix)
        assertEquals(listOf("0.0.0.0" to 0), subnet.routes)
        assertEquals(listOf("192.0.2.0" to 24), subnet.excludedRoutes)
        assertEquals(listOf("1.1.1.1"), subnet.dnsServers)
        assertEquals(1500, subnet.mtu)
        // net30 (OpenVPN 2.6's default topology): the second ifconfig word is the peer, not a netmask
        val net30 = OpenVpnSettings.tunnelSettings(listOf(
            listOf("route", "10.8.6.1"), listOf("topology", "net30"), listOf("ifconfig", "10.8.6.6", "10.8.6.5"),
            listOf("dns", "server", "0", "address", "9.9.9.9", "[2620:fe::fe]:53"), listOf("dhcp-option", "DOMAIN", "corp.example")))!!
        assertEquals(32, net30.addressPrefix)
        assertEquals(listOf("10.8.6.1" to 32, "10.8.6.5" to 32), net30.routes)
        assertEquals(listOf("9.9.9.9", "2620:fe::fe", "corp.example"), net30.dnsServers)
        // routes lose their host bits, as Android requires
        assertEquals(listOf("10.20.0.0" to 16), OpenVpnSettings.tunnelSettings(listOf(listOf("ifconfig", "10.8.0.2", "255.255.255.0"),
            listOf("topology", "subnet"), listOf("route", "10.20.30.40", "255.255.0.0")))!!.routes)
        assertNull(OpenVpnSettings.tunnelSettings(listOf(listOf("ifconfig-ipv6", "fd00::2/64", "fd00::1"))))
    }

    @Test
    fun readsTheProfilesRemotesAndTurnsItToTcpForStunnel() {
        val profile = "client\nproto tcp\nport 1195\n# remote commented.example 1\nremote a.example\nremote b.example 443 udp\n"
        assertEquals(OpenVpnProfileText.Remote("a.example", "1195", "tcp"), OpenVpnProfileText.firstRemote(profile))
        assertEquals(2, OpenVpnProfileText.remoteCount(profile))
        assertEquals(1, OpenVpnProfileText.remoteCount("client\n"))
        assertEquals("client\nproto tcp\nremote a.example 1194 tcp\n<ca>\nx\n</ca>",
            OpenVpnProfileText.withProtocol("client\nproto udp\nremote a.example 1194 udp\n<ca>\nx\n</ca>", "tcp"))
        assertEquals("proto tcp\nremote a.example 1194", OpenVpnProfileText.withProtocol("remote a.example 1194", "tcp"))
        assertTrue(OpenVpnProfileText.usesStaticKey("dev tun\n<secret>\nx\n</secret>"))
        assertTrue(OpenVpnProfileText.hasEncryptedKey("<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\n"))
        assertFalse(OpenVpnProfileText.hasClientCertificate(ovpn))
    }

    @Test
    fun splitsTheHandshakeAsTlsFragmentationSays() {
        assertNull(StunnelFragPlan.of(0, 0, 0, cellular = false))
        assertEquals(listOf(43, 256, 256, 62), StunnelFragPlan.of(1, 0, 0, cellular = false)!!.chunks(617))
        assertEquals(128, StunnelFragPlan.of(1, 0, 0, cellular = true)!!.following)
        assertEquals(listOf(10, 40, 40, 10), StunnelFragPlan.of(2, 10, 40, cellular = false)!!.chunks(100))
        assertEquals(listOf(32, 256), StunnelFragPlan.of(2, 0, 0, cellular = false)!!.chunks(288))
    }

    @Test
    fun explainsWhatTheCoreReports() {
        assertEquals("The server refused the connection: no OpenVPN server answers on that port.",
            openVpnLogMessage("Transport Error: TCPv4 connect error on 'vpn.example:1199' (192.0.2.1:1199): Connection refused"))
        assertEquals("The server name no.example could not be resolved.",
            openVpnLogMessage("Transport Error: DNS resolve error on 'no.example' for UDP session: Host not found"))
        assertTrue(openVpnLogMessage("Client exception in transport_recv: ERR_PROFILE_OPTION: option_error: Problem accepting server-pushed compressor 'lz4-v2': compressor_unavailable")!!
            .contains("compression (lz4-v2)"))
        assertNull(openVpnLogMessage("Contacting 192.0.2.1:1194 via UDP"))
        assertEquals("The server refused the login. Check the username and password.", openVpnEventMessage("AUTH_FAILED", ""))
        assertTrue(openVpnEventMessage("AUTH_FAILED", "Data channel cipher negotiation failed (no shared cipher)").startsWith("The server and this app have no data-channel cipher in common"))
        assertEquals("The stunnel server closed the connection.", openVpnEventMessage("TRANSPORT_ERROR", "stunnel: The stunnel server closed the connection."))
        assertNotNull(openVpnInvalidProfileMessage("ssl_context_error", "dev tun\n<secret>\nx\n</secret>"))
    }
}
