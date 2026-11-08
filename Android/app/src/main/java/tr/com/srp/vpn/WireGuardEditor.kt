package tr.com.srp.vpn

import androidx.compose.runtime.Composable

/** The WireGuard protocol's parts of the profile editor, in the iOS editor's words (CreateVC, isPlainWireGuard). */
internal const val WIREGUARD_SERVER_FOOTER =
    "Import a .conf file (wg-quick format) or enter the keys manually under Manual Configuration. Server and Port are filled from the " +
        "Endpoint line on import; changed, they replace it. WireGuard runs over UDP."

internal const val WIREGUARD_OPTIONS_FOOTER =
    "WireGuard counts as connected once the server answered its handshake. When nothing comes back for 30 seconds while the phone sends, " +
        "the server stopped answering: Auto Reconnect starts new handshakes, 10 seconds each, and Retry Times limits them (empty = no limit); " +
        "before the first connection, Retry Times adds attempts. Off: the VPN disconnects with the reason. On Sleep: Off closes the connection " +
        "while the device sleeps and connects again at wake only with Auto Reconnect; Pause closes it and connects again at wake; Stay keeps it. " +
        "WireGuard always uses the network the phone uses: when Wi-Fi appears, its packets go over Wi-Fi by themselves, so there is no Switch to " +
        "Wi-Fi option."

/** The first problem of a WireGuard profile about to be saved (CreateVC validationMessage). */
internal fun wireGuardValidationMessage(profile: Profile): String? {
    if (profile.server.isEmpty()) return "Enter the server address."
    if (profile.wgEffectiveConfig().isNullOrEmpty()) return "Import or enter a WireGuard configuration."
    return null
}

/** The Manual Configuration row's value: what the tunnel uses (an imported file wins) */
internal fun wireGuardConfigState(profile: Profile) =
    if (profile.wgConfig.isNotEmpty()) "Overridden by import" else if (profile.wgPrivateKey.isNotEmpty()) "Manual" else "None"

/** Auto Reconnect (+Retry Times when on), On Sleep and Log Level: WireGuard always follows the phone's network */
@Composable
internal fun WireGuardOptionsSection(draft: Profile, onChange: (Profile) -> Unit) {
    Section("OPTIONS", WIREGUARD_OPTIONS_FOOTER) {
        row { SwitchRow("Auto Reconnect", draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) } }
        if (draft.autoReconnect) {
            row { CountRow("Retry Times", draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) } }
        }
        row { SegmentRow("On Sleep", listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) } }
        row { SegmentRow("Log Level", listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) } }
    }
}
