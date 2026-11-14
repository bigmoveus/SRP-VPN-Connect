package tr.com.srp.vpn

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType

/** The Aether protocol's parts of the profile editor, in the iOS editor's words (CreateVC, isAether). */
internal const val AETHER_FOOTER =
    "Aether connects to Cloudflare WARP automatically. H3 uses QUIC; H2 uses TCP+TLS and supports TLS Fragmentation; Both tries H3 " +
        "first and falls back to H2. Endpoint Scan: Turbo takes the first verified endpoint, Balanced compares more candidates. WireGuard is " +
        "the classic WARP transport. A WARP+ License is bound at connect time. Tor can carry WARP or provide a Tor-only exit."

internal const val AETHER_OPTIONS_FOOTER =
    "Aether counts as connected once a test connection through the tunnel went through. When the session ends, or two test connections " +
        "through it fail (one every 20 seconds, and one at once after a network change), it stopped working: Auto Reconnect sets up a new " +
        "session and Retry Times limits the attempts (empty = no limit); before the first connection, Retry Times adds attempts. Off: the VPN " +
        "disconnects with the reason. On Sleep: Off closes the session while the device sleeps and connects again at wake only with Auto " +
        "Reconnect; Pause closes it and connects again at wake; Stay keeps it. Aether always uses the network the phone uses, so there is no " +
        "Switch to Wi-Fi option."

internal const val AETHER_OPTIONS_LEAD =
    "Aether connects to Cloudflare WARP; no server or account is needed. Tor Only exits through the Tor network (no WARP); WARP via Tor " +
        "dials the tunnel through Tor (slow to connect). "

internal const val AETHER_FRAGMENT_NOTE =
    " MASQUE H2 runs over TCP+TLS (useful where QUIC/UDP is filtered); TLS Fragmentation splits the handshake's ClientHello into smaller " +
        "writes — Auto picks safe sizes and splits at the SNI, Manual sets the byte range."

private val AETHER_TRANSPORTS = listOf(
    Triple("masque", "MASQUE (HTTP/3)", "Fast MASQUE transport over QUIC/UDP"),
    Triple("masque-h2", "MASQUE (HTTP/2)", "TCP+TLS, with optional TLS Fragmentation"),
    Triple("masque-both", "Both (H3 → H2)", "Try HTTP/3 first, then fall back to HTTP/2"),
    Triple("wg", "WireGuard", "Classic Cloudflare WARP over UDP"),
)

internal fun aetherTransportTitle(transport: String) = AETHER_TRANSPORTS.firstOrNull { it.first == transport }?.second ?: "MASQUE (HTTP/3)"

/** TLS Fragmentation acts on the MASQUE-H2 carrier's TLS handshake: with H2, or H3 then H2, not Tor Only */
internal fun aetherOffersFragmentation(profile: Profile) =
    profile.isAether && profile.aetherTor != "only" &&
        (profile.aetherTransport == "masque-h2" || profile.aetherTransport == "masque-both")

@Composable
internal fun AetherSections(draft: Profile, onChange: (Profile) -> Unit, push: (EditorPage) -> Unit) {
    // No header: the rows name no server (CreateVC hides this section's header for Aether)
    Section(footer = AETHER_FOOTER) {
        val torOnly = draft.aetherTor == "only"
        if (!torOnly) {
            row { ValueRow("Transport", aetherTransportTitle(draft.aetherTransport)) { push(EditorPage.AetherTransport) } }
            row {
                SegmentRow("Endpoint Scan", listOf("Balanced", "Turbo"), if (draft.aetherScan == "turbo") 1 else 0) {
                    onChange(draft.copy(aetherScan = if (it == 1) "turbo" else "balanced"))
                }
            }
            row { TextFieldRow("WARP+ License", draft.aetherLicense, "Optional", keyboardType = KeyboardType.Ascii) { onChange(draft.copy(aetherLicense = it)) } }
        }
        row {
            SegmentRow("Tor", listOf("Off", "WARP via Tor", "Tor Only"), when (draft.aetherTor) { "only" -> 2; "reverse" -> 1; else -> 0 }) {
                onChange(draft.copy(aetherTor = when (it) { 2 -> "only"; 1 -> "reverse"; else -> "off" }))
            }
        }
    }
    val fragment = aetherOffersFragmentation(draft)
    val footer = AETHER_OPTIONS_LEAD + AETHER_OPTIONS_FOOTER + if (fragment) AETHER_FRAGMENT_NOTE else ""
    Section("OPTIONS", footer) {
        row { SwitchRow("Auto Reconnect", draft.autoReconnect) { onChange(draft.copy(autoReconnect = it)) } }
        if (draft.autoReconnect) {
            row { CountRow("Retry Times", draft.retryTimes, "Unlimited") { onChange(draft.copy(retryTimes = it)) } }
        }
        row { SegmentRow("On Sleep", listOf("Off", "Pause", "Stay"), draft.onSleep) { onChange(draft.copy(onSleep = it)) } }
        row { SegmentRow("Log Level", listOf("Normal", "Expert", "Debug"), draft.logLevel) { onChange(draft.copy(logLevel = it)) } }
        if (fragment) {
            row { SegmentRow("TLS Fragmentation", listOf("Off", "Auto", "Manual"), draft.tlsFragMode) { onChange(draft.copy(tlsFragMode = it)) } }
            if (draft.tlsFragMode == 2) {
                row { CountRow("Min Chunk (bytes)", draft.tlsFragFirst, "32") { onChange(draft.copy(tlsFragFirst = it)) } }
                row { CountRow("Max Chunk (bytes)", draft.tlsFragFollowing, "256") { onChange(draft.copy(tlsFragFollowing = it)) } }
            }
        }
    }
}

/** The Transport screen (SRPAetherTransportViewController) */
@Composable
internal fun AetherTransportPage(draft: Profile, onChange: (Profile) -> Unit, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().background(LocalIosColors.current.groupedBackground)) {
        NavBar("Transport", left = { RoundBarButton(Glyph.Back, "Back", onClick = onBack) })
        Section {
            AETHER_TRANSPORTS.forEach { (value, title, subtitle) ->
                row {
                    CheckRow(title, subtitle, checked = draft.aetherTransport == value) {
                        onChange(draft.copy(aetherTransport = value))
                        onBack()
                    }
                }
            }
        }
    }
}
