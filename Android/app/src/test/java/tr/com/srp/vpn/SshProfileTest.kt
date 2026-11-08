package tr.com.srp.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The SSH editor's save rules (CreateVC.m), the profile's port and name, and the bridge failures' messages (SRPSSHClient.m). */
class SshProfileTest {
    private val complete = Profile(protocolType = "ssh", server = "ssh.example.com", port = "", username = "user", password = "secret")

    @Test
    fun namesTheFirstMissingField() {
        assertNull(sshValidationMessage(complete))
        assertEquals("Enter the server address.", sshValidationMessage(complete.copy(server = "")))
        assertEquals("Enter the username.", sshValidationMessage(complete.copy(username = "")))
        assertEquals("Enter the password.", sshValidationMessage(complete.copy(password = "")))
    }

    @Test
    fun isSshWithItsOwnPortAndName() {
        assertTrue(complete.isSsh)
        assertFalse(complete.isTlsVpn)
        assertEquals("SSH VPN", complete.nodeName)
        assertEquals("22", complete.effectivePort)
        assertEquals("2222", complete.copy(port = "2222").effectivePort)
        assertFalse(complete.sshUdpRelay)
    }

    @Test
    fun explainsTheBridgeFailures() {
        assertEquals("The server refused the connection on port 2222. Check the Port field.", sshFailureMessage(SSH_ERR_CONNECT, "refused", 2222))
        assertEquals("Cannot find the server. Check the Server field and the network.", sshFailureMessage(SSH_ERR_CONNECT, "resolve", 22))
        assertEquals("The server did not answer on port 22. Check the Server and Port fields and the network.", sshFailureMessage(SSH_ERR_CONNECT, "timeout", 22))
        assertEquals("Authentication failed. Check the username and password.", sshFailureMessage(SSH_ERR_AUTH, "", 22))
        assertEquals("The server does not take a password for this user (it offers: publickey).", sshFailureMessage(SSH_ERR_AUTH_METHOD, "publickey", 22))
        assertTrue(sshFailureMessage(SSH_ERR_HOSTKEY, "ED25519 SHA256:abc", 22).endsWith("The server presented ED25519 SHA256:abc."))
        assertTrue(sshFailureMessage(SSH_ERR_FORWARDING, "", 22).startsWith("The server does not let this user forward TCP connections"))
        assertEquals("SSH handshake failed (Failed getting banner). Check that Port is the server's SSH port.",
            sshFailureMessage(SSH_ERR_HANDSHAKE, "Failed getting banner", 22))
    }
}
