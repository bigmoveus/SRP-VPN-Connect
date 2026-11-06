package tr.com.srp.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The SSTP editor's save rules and stored EAP settings, which must match CreateVC.m and SRPEapConfig.m. */
class SstpProfileTest {
    private val complete = Profile(protocolType = "sstp", server = "vpn.example.com", username = "user", password = "secret")

    @Test
    fun savesAProfileWithAnyOneAuthenticationMethod() {
        assertNull(sstpValidationMessage(complete))
        assertNull(sstpValidationMessage(complete.copy(mschap2 = false, eap = EapConfig(peapEnabled = true))))
        assertNull(sstpValidationMessage(complete.copy(mschap2 = false, eap = EapConfig(ttlsInnerMethod = 2))))
        assertEquals("Enable at least one authentication method.", sstpValidationMessage(complete.copy(mschap2 = false)))
    }

    @Test
    fun namesTheFirstMissingField() {
        assertEquals("Enter the server address.", sstpValidationMessage(complete.copy(server = "")))
        assertEquals("Enter the username.", sstpValidationMessage(complete.copy(username = "")))
        assertEquals("Enter the password.", sstpValidationMessage(complete.copy(password = "")))
        val certificate = complete.copy(authMethod = "certificate", username = "", password = "")
        assertEquals("Import a client certificate.", sstpValidationMessage(certificate))
        assertNull(sstpValidationMessage(certificate.copy(certKey = "ref")))
    }

    @Test
    fun checksProxyCustomSniAndChunkLimits() {
        assertEquals("Enter the proxy address and port.", sstpValidationMessage(complete.copy(proxyMode = 1, proxyAddress = "10.0.0.1")))
        assertEquals("Enter an http or https PAC URL.", sstpValidationMessage(complete.copy(proxyMode = 2, pacUrl = "ftp://example.com/x.pac")))
        assertNull(sstpValidationMessage(complete.copy(proxyMode = 2, pacUrl = "http://10.0.0.1:8090/proxy.pac")))
        assertEquals("Custom SNI must be a bare hostname, without a scheme, port, path or spaces.",
            sstpValidationMessage(complete.copy(customSniEnabled = true, customSni = "vpn.example.com:443")))
        // A switched-off Custom SNI keeps its text without being checked
        assertNull(sstpValidationMessage(complete.copy(customSniEnabled = false, customSni = "https://x")))
        assertEquals("First Chunk can be at most 4096 bytes.", sstpValidationMessage(complete.copy(tlsFragMode = 2, tlsFragFirst = 5000)))
        assertEquals("Following Chunks can be at most 16384 bytes.", sstpValidationMessage(complete.copy(tlsFragMode = 2, tlsFragFollowing = 20000)))
        assertTrue(isValidCustomSni("a-b.example.com"))
        assertFalse(isValidCustomSni("bad host"))
    }

    @Test
    fun storesEapSettingsWithTheIosKeys() {
        val eap = EapConfig(eapMschapv2Enabled = true, peapEnabled = true, peapRequireCryptoBinding = true, ttlsInnerMethod = 3,
            identityPrivacyEnabled = true, anonymousIdentity = "anon", eapTls13Enabled = false, disableLegacyEapTls = false)
        assertEquals(eap, EapConfig.fromMap(eap.toMap()))
        assertEquals(EapConfig(), EapConfig.fromMap(null))
        assertEquals(listOf("eap", "eap", "pap", "chap", "eap"), (0..4).map { ttlsInnerName(it) })
    }
}
