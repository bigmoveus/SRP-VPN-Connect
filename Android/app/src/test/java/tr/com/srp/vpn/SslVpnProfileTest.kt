package tr.com.srp.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The SSL VPN editor's save rules (CreateVC.m) and the server certificate's name check of SslVpnClient. */
class SslVpnProfileTest {
    private val complete = Profile(protocolType = "openconnect", server = "vpn.example.com", username = "user", password = "secret")

    @Test
    fun namesTheFirstMissingField() {
        assertNull(sslVpnValidationMessage(complete))
        assertEquals("Enter the server address.", sslVpnValidationMessage(complete.copy(server = "")))
        assertEquals("Enter the username.", sslVpnValidationMessage(complete.copy(username = "")))
        assertEquals("Enter the password.", sslVpnValidationMessage(complete.copy(password = "")))
        val certificate = complete.copy(authMethod = "certificate", password = "")
        assertTrue(certificate.certificateMode)
        assertEquals("Import a client certificate.", sslVpnValidationMessage(certificate))
        assertNull(sslVpnValidationMessage(certificate.copy(certKey = "ref")))
    }

    @Test
    fun isATlsVpnWithItsOwnName() {
        assertTrue(complete.isOpenConnect && complete.isTlsVpn)
        assertEquals("SSL VPN", complete.nodeName)
        assertEquals("443", complete.copy(port = "").effectivePort)
        assertEquals("AnyConnect", sslVpnServerTypeTitle(complete.ocProtocol))
        assertEquals("F5 BIG-IP", sslVpnServerTypeTitle("f5"))
        assertEquals("Palo Alto GP", sslVpnServerTypeTitle("gp"))
    }

    @Test
    fun matchesTheServerNameAgainstTheCertificate() {
        val names = listOf(listOf(2, "vpn.example.com"), listOf(2, "*.example.net"), listOf(7, "192.0.2.7"))
        assertTrue(namesMatchHost(names, "vpn.example.com"))
        assertTrue(namesMatchHost(names, "VPN.Example.com."))
        assertTrue(namesMatchHost(names, "a.example.net"))
        // A wildcard covers exactly one label, never the bare domain
        assertFalse(namesMatchHost(names, "a.b.example.net"))
        assertFalse(namesMatchHost(names, "example.net"))
        assertFalse(namesMatchHost(names, "other.example.com"))
        // An IP host needs the address itself, not a DNS name that looks like one
        assertTrue(namesMatchHost(names, "192.0.2.7"))
        assertFalse(namesMatchHost(names, "192.0.2.8"))
        assertFalse(namesMatchHost(listOf(listOf(2, "192.0.2.7")), "192.0.2.7"))
        assertFalse(namesMatchHost(null, "vpn.example.com"))
    }

    @Test
    fun hidesTheServersCookieValuesInTheLog() {
        assertEquals("Set-Cookie: webvpncontext=<elided>; Secure; HttpOnly",
            maskCookies("Set-Cookie: webvpncontext=ZmFrZS1jb250ZXh0LXZhbHVl; Secure; HttpOnly"))
        // libopenconnect's own elision and an emptied cookie stay as they are
        assertEquals("Set-Cookie: webvpn=<elided>; Secure; HttpOnly", maskCookies("Set-Cookie: webvpn=<elided>; Secure; HttpOnly"))
        assertEquals("Set-Cookie: webvpnc=; expires=Thu, 01 Jan 1970", maskCookies("Set-Cookie: webvpnc=; expires=Thu, 01 Jan 1970"))
        assertEquals("Invalid cookie '<elided>'", maskCookies("Invalid cookie 'abc=def'"))
        assertEquals("Got CONNECT response: HTTP/1.1 200 CONNECTED", maskCookies("Got CONNECT response: HTTP/1.1 200 CONNECTED"))
    }

    @Test
    fun namesTheCauseOfAFailedLogin() {
        assertEquals("The server name could not be found. Check the Server field.",
            reasonFromErrors(listOf("getaddrinfo failed for host 'x.example': nodename nor servname provided"), "anyconnect"))
        assertEquals("The server did not answer with TLS on this port. Check the Port field.",
            reasonFromErrors(listOf("SSL connection failure", "error:0A00010B:SSL routines::wrong version number"), "anyconnect"))
        assertEquals("The server did not answer as a GlobalProtect server. Check the Server Type and the Server field.",
            reasonFromErrors(listOf("Unexpected 404 result from server"), "gp"))
        assertEquals("The server did not answer as an F5 BIG-IP server. Check the Server Type and the Server field.",
            reasonFromErrors(listOf("Unknown form ID '(null)' (expected 'auth_form')"), "f5"))
        assertEquals("The server offers only TLS 1.1 or older; the app needs TLS 1.2 or later.",
            reasonFromErrors(listOf("SSL connection failure", "error:0A00014D:SSL routines::legacy sigalg disallowed or unsupported"), "anyconnect"))
        assertNull(reasonFromErrors(emptyList(), "anyconnect"))
    }
}
