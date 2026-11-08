package tr.com.srp.vpn

import androidx.compose.runtime.Composable
import androidx.compose.ui.text.input.KeyboardType

// The iOS editor's footers (CreateVC.m) for an SSH profile
private const val SSH_SERVER_FOOTER = "Every connection travels through the SSH session as TCP forwarding, which the server must allow for the user. Host Key: the SHA256 fingerprint of the server's key, as ssh-keygen -lf prints it (the ED25519 key on current servers; the connection log names the key the server presented). Empty accepts any key. UDP Relay carries UDP through the HEV relay the administrator installs on the server."

private const val SSH_OPTIONS_FOOTER = "Auto Reconnect opens a new SSH session when the connection breaks or the server stops answering keepalives; connections that were open start again. Retry Times limits the attempts (empty = no limit). Off: the VPN disconnects with the reason. UDP through the relay travels inside the SSH session's TCP stream, so calls and games are only as smooth as that stream."

/** The first reason an SSH profile cannot be saved yet, in the iOS editor's words (CreateVC validationMessage). */
fun sshValidationMessage(profile: Profile): String? {
    if (profile.server.isEmpty()) return "Enter the server address."
    if (profile.username.isEmpty()) return "Enter the username."
    if (profile.password.isEmpty()) return "Enter the password."
    return null
}

/** SERVER, AUTHENTICATION and OPTIONS of an SSH profile, row for row as CreateVC.m shows them (no proxy, as on iOS). */
@Composable
fun SshSections(draft: Profile, onChange: (Profile) -> Unit) {
    Section("SERVER", SSH_SERVER_FOOTER) {
        row { TextFieldRow("Server", draft.server, "Required", keyboardType = KeyboardType.Uri) { onChange(draft.copy(server = it)) } }
        row { TextFieldRow("Port", draft.port, "22", keyboardType = KeyboardType.Number) { onChange(draft.copy(port = it)) } }
        row { TextFieldRow("Host Key (SHA256)", draft.sshHostKey, "Optional — SHA256:...") { onChange(draft.copy(sshHostKey = it)) } }
        row { SwitchRow("UDP Relay (HEV)", draft.sshUdpRelay) { onChange(draft.copy(sshUdpRelay = it)) } }
    }
    Section("AUTHENTICATION") {
        row { TextFieldRow("Username", draft.username, "Required") { onChange(draft.copy(username = it)) } }
        row { TextFieldRow("Password", draft.password, "Required", secure = true) { onChange(draft.copy(password = it)) } }
    }
    Section("OPTIONS", SSH_OPTIONS_FOOTER) {
        row { SwitchRow("Auto Reconnect", draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) } }
        if (draft.autoReconnect) row { CountRow("Retry Times", draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) } }
        row { SwitchRow("Switch to Wi-Fi When Available", draft.switchToWifi) { onChange(draft.copy(switchToWifi = it)) } }
        row { SegmentRow("On Sleep", listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) } }
        row { SegmentRow("Log Level", listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) } }
    }
}
