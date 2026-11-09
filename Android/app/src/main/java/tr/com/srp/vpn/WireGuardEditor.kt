package tr.com.srp.vpn

import androidx.compose.runtime.Composable

/** The WireGuard and AmneziaWG protocols' parts of the profile editor, in the iOS editor's words (CreateVC, isPlainWireGuard). */
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

internal const val AMNEZIAWG_SERVER_FOOTER =
    "Import a .conf file (the awg-quick format of AmneziaWG servers, or WireGuard's own) or enter the keys and the obfuscation settings under " +
        "Manual Configuration. Server and Port are filled from the Endpoint line on import; changed, they replace it. AmneziaWG runs over UDP."

internal const val AMNEZIAWG_OPTIONS_FOOTER =
    "AmneziaWG counts as connected once the server answered its handshake. When nothing comes back for 30 seconds while the phone sends, " +
        "the server stopped answering: Auto Reconnect starts new handshakes, 10 seconds each, and Retry Times limits them (empty = no limit); " +
        "before the first connection, Retry Times adds attempts. Off: the VPN disconnects with the reason. When the server answers its handshakes " +
        "but none of the traffic (S3, S4 or H4 differ from the server's), the VPN disconnects with that reason. On Sleep: Off closes the " +
        "connection while the device sleeps and connects again at wake only with Auto Reconnect; Pause closes " +
        "it and connects again at wake; Stay keeps it. AmneziaWG always uses the network the phone uses: when Wi-Fi appears, its packets go over " +
        "Wi-Fi by themselves, so there is no Switch to Wi-Fi option."

internal const val AMNEZIAWG_MATCH_FOOTER =
    "These must be the server's values. With another S1, S2, H1, H2, Header Protection Key or Random Trailers the server does not answer; with " +
        "another S3, S4 or H4 the handshake works but no traffic does. H1-H4 take a number or a range such as 1100000000-1199999999. Leave all " +
        "empty for a server without obfuscation."

internal const val AMNEZIAWG_DEVICE_FOOTER =
    "This device's own, not needed on the server: Jc junk packets of Jmin to Jmax bytes and the I1-I5 chains go before every handshake; " +
        "Content Padding adds bytes to data packets; the timings are seconds (Max Handshake Attempts a count). Each takes a number or a range " +
        "such as 4-6, picked anew each time."

/** The first problem of a WireGuard or AmneziaWG profile about to be saved (CreateVC validationMessage). */
internal fun wireGuardValidationMessage(profile: Profile): String? {
    if (profile.server.isEmpty()) return "Enter the server address."
    if (profile.wgEffectiveConfig().isNullOrEmpty()) {
        return if (profile.isAmnezia) "Import or enter an AmneziaWG configuration." else "Import or enter a WireGuard configuration."
    }
    return null
}

/** An AmneziaWG setting in a file (the first one's name), which a WireGuard profile cannot use (CreateVC handleImportedText:mode:) */
internal fun amneziaSettingIn(text: String): String? =
    Regex("""^[ \t]*(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies)[ \t]*=""",
        setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE)).find(text)?.groupValues?.get(1)

/** The Manual Configuration row's value: what the tunnel uses (an imported file wins) */
internal fun wireGuardConfigState(profile: Profile) =
    if (profile.wgConfig.isNotEmpty()) "Overridden by import" else if (profile.wgPrivateKey.isNotEmpty()) "Manual" else "None"

/** Auto Reconnect (+Retry Times when on), On Sleep and Log Level: WireGuard and AmneziaWG always follow the phone's network */
@Composable
internal fun WireGuardOptionsSection(draft: Profile, onChange: (Profile) -> Unit) {
    Section("OPTIONS", if (draft.isAmnezia) AMNEZIAWG_OPTIONS_FOOTER else WIREGUARD_OPTIONS_FOOTER) {
        row { SwitchRow("Auto Reconnect", draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) } }
        if (draft.autoReconnect) {
            row { CountRow("Retry Times", draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) } }
        }
        row { SegmentRow("On Sleep", listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) } }
        row { SegmentRow("Log Level", listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) } }
    }
}
