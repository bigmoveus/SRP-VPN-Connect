# Changelog

All notable changes to SRP VPN Connect are recorded here. Every commit adds its entry under **Unreleased**; a TestFlight or App Store build moves those entries under its version and build number.

## Unreleased

### Added
- SSTP profiles with Proxy set to Auto (PAC) take a username and password for the proxy the PAC script picks; before, a PAC proxy that asks for a password could not be used.
- The WaterWall Advanced Node Settings editors (Packet, Application and the other layers) work as a JSON editor. A line under the text says whether the JSON is valid or names the line and column of the first error, as the save alert now does too; a new line keeps the indentation, one level deeper after `{` or `[`; and Format pretty-prints valid JSON.

### Fixed
- SSTP crashed the VPN extension as soon as a connection started, because WaterWall's lwIP network stack had replaced the one SSTP uses. WaterWall's copy now has its own symbol names, so each protocol keeps its own stack.
- SSTP could crash the VPN extension under heavy traffic: every batch of packets read from the device replaced the callback that was writing received packets back. It is now set once, and a reconnect no longer starts another read loop.
- An SSTP upload faster than the path to the server made the VPN extension exceed its memory limit within seconds. The tunnel now stops reading from the device while 1 MB waits for PPP framing or for the network, with or without TLS Fragmentation.
- Under upload, every finished SSTP send processed the PPP buffers again on the network queue while the tunnel was filling them, which could corrupt frames.
- With TLS Fragmentation, SSTP kept a copy of every encrypted chunk it sent, so an upload ran the VPN extension out of memory within seconds.
- Heavy SSTP traffic, such as eight downloads at once or any download with TLS Fragmentation, could run the VPN extension out of memory. The objects each packet left for release piled up while the packet queues never went idle, and with TLS Fragmentation every read took everything the network had buffered. Each batch of packets now releases its objects, and TLS Fragmentation reads at most 64 KB at a time.
- SSTP could crash the VPN extension when a connection closed with sends still in flight, as when the device slept with On Sleep set to Pause or Off, or on a reconnect.
- After the server ended an SSTP session, Auto Reconnect gave up instead of reconnecting when Retry Times was unlimited, because the drop was taken for a connection that never came up. Late events from a replaced connection no longer reach the new one.
- When an SSTP connection ended for good after it was up (Auto Reconnect off, Retry Times used up, or On Sleep set to Off without Auto Reconnect after the device woke), the VPN stayed connected without a working tunnel; it now disconnects with a message.
- SSTP sent a Custom SNI that was switched off when the profile still held its hostname.
- With Custom SNI on, the certificate check before an SSTP connection ignored it and reported an untrusted certificate when the Host field is an IP address; it now checks the certificate against the Custom SNI, as the connection does.
- When an SSTP server ended PPP before the first link came up, for example because it accepts none of the profile's authentication methods, the error read "Connection lost (auto reconnect is off)."; it now says the server closed the connection during PPP negotiation.
- An SSTP profile that uses only PEAP, EAP-TTLS or TEAP could not be saved.
- SSTP ran the TLS Fragmentation mode that was not chosen: Manual ignored the chunk sizes and used the automatic ones, and Auto used fixed 32- and 256-byte chunks. Each mode now runs as chosen.
- The SSTP profile editor accepted Manual TLS Fragmentation chunks above 4096 and 16384 bytes, which failed only when connecting; it now names the limit on save.
- An SSTP proxy that cannot be reached was reported as an unsupported proxy protocol after about 20 seconds; the error now names the proxy address and the reason, at once when the connection is refused.
- A wrong password on an SSTP server that ends the call together with its refusal, as MikroTik does with RADIUS, was reported as a failed negotiation of the authentication methods; it is now reported as a rejected username or password. A server that ends PPP without a refusal gets a message naming the phase it ended: negotiation, authentication or the tunnel address.
- When an SSTP server ended the call but kept its TCP connection open, as SoftEther does when it accepts none of the profile's authentication methods, the connection waited 30 seconds and then said the server did not respond; it now ends at once with the reason.
- SSTP answered an EAP-MD5 challenge with the password whichever EAP methods the profile allowed. FreeRADIUS offers EAP-MD5 first, so PEAP, EAP-MSCHAPv2 and certificate profiles behind it logged in with EAP-MD5 instead and passed no traffic (EAP-MD5 gives no keys for the crypto binding), and any server could obtain a hash of the password to guess at. The profile's own method is now asked for, and unknown methods are refused the same way.
- With Identity Privacy on, a server that refuses the anonymous outer identity, as Windows RRAS does with local accounts, was reported as a wrong username or password only; the message now names Identity Privacy too. A refused client certificate is reported as such instead of as a wrong password.
- With EAP TLS 1.3 on (the default), PEAP and the other TLS-based EAP methods failed against Windows Server NPS, which has no TLS 1.3 for EAP and drops the offer. When a server ends EAP during the TLS handshake of a TLS 1.3 offer, SSTP now connects again once, offering TLS 1.2.
- In the WaterWall Advanced Node Settings editors and the Psiphon Server Entries editor, opening the keyboard moved the whole screen up, so the back and save buttons sat under the status bar. The screen now stays in place; the text still ends above the keyboard.
- A WaterWall Reality profile with the SNI left empty sent the server's name instead of the www.cloudflare.com cover the profile editor describes. An empty SNI means www.cloudflare.com for Reality again, as before the tunnel started connecting to the resolved server address.
- WaterWall TLS Fragmentation set to Auto used the Manual chunk sizes stored in the profile. Auto now always cuts at 32 and then every 256 bytes; only Manual uses the profile's sizes.
- With BGP4 Framing and an HTTP or WebSocket layer both on, WaterWall left the HTTP layer out of the chain. HTTP now sits inside the BGP4 framing, in the order the configuration screen lists them.
- A WaterWall SNI hidden because the outer layer has no TLS (None, AEAD or BGP4) was still sent as the HTTP Host; it is now ignored and the Host is the Server field.
- Ticking countries for WaterWall GeoIP routing while the GeoIP Routing switch was off turned routing on without installing the country database, so the connection failed; ticking a country now installs it as the switch does.
- Tapping the protocol a profile already has in the Protocol list reset the profile to that protocol's defaults, and tapping the current WaterWall Application cleared its UUID or password. Both now leave the profile as it is.
- An empty Port in WaterWall's WireGuard mode connected to 443 although the field showed 51820; it now means 51820.
- The WaterWall KCP settings check measured kcp-initial-cwnd against a send window of 8192, while the chain uses 128 unless kcp-send-window is set.
- The WaterWall profile editor accepted a Manual TLS Fragmentation First Chunk of 16384 bytes or more, which leaves the ClientHello whole; it now names the limit on save.
- A profile kept its WireGuard keys and settings when its protocol changed, so a WaterWall profile in WireGuard mode could connect with keys entered for the WireGuard, AmneziaWG or Aether protocol, and the other way round. A profile moved to another protocol now starts without them.
- WireGuard private keys, preshared keys and imported configs were saved in the app's settings file. They are now kept in the Keychain and the profile keeps only a reference; saved profiles move their keys there when the app first loads them.
- A saved WireGuard profile that had both an imported config and manual keys lost the import when the app loaded it. Only a config generated from the manual fields is now dropped on load.
- Deleting a profile left its passwords and WireGuard keys in the Keychain; they are now removed with the profile.

### Changed
- New profiles start as WaterWall VPN with its default configuration on port 443 instead of SSTP; existing profiles keep their protocol.
- The SSTP tunnel log records the extension's memory when the link comes up and, near the memory limit, how much data waits for PPP framing and for the network.
- SSTP accepted any certificate from an EAP server on another host than the SSTP server, as when RRAS relays PEAP, EAP-TTLS, TEAP or EAP-TLS to a RADIUS server. That certificate must now chain to a root the device trusts, as the outer connection's does, unless Allow Insecure is on; a RADIUS server with a private CA needs that CA installed and trusted on the device. A refused certificate is named in the error.
- WaterWall's Auto Switch option is shown only in Chain mode, because WireGuard and Direct have no other profiles to switch to. Its note now says that a network change returns to the chosen profile when Switch to Wi-Fi When Available moves the connection.

### Development
- The WaterWall runtime build fails when one of WaterWall's lwIP symbols keeps a name the other protocols' lwIP uses (`WaterWall/tests/lwip_prefix_contract.py`); `WaterWall/generate_lwip_prefix.py` regenerates `srp_lwip_prefix.h` after an lwIP upgrade.
- Live device tests for a profile of any protocol: `testProfileLiveConnectionAndThroughputWhenConfigured` runs downloads, uploads or both, or expects a refusal, and `testProfileLiveLifecycleWhenConfigured` checks the sleep modes, a session the server ends and the retry limit. The profile comes as JSON in `SRP_LIVE_PROFILE_JSON` and its password in `SRP_LIVE_PASSWORD`; `SRP_ACCEPT_UNTRUSTED` answers the untrusted-certificate prompt.
- A live connection that does not come up no longer fails the test on its own timeout, so a test that expects a refusal can pass.
- The live profile tests can log in with a client certificate: `SRP_LIVE_CERT_P12_BASE64` carries the PKCS#12 and `SRP_LIVE_CERT_PASSPHRASE` its passphrase. The test imports it as the profile editor does and removes it afterwards.
- The unit tests link in Release builds again. Tests added since 31 October referred to app classes directly, which the Release app does not export; they now reach them through `NSClassFromString`, as the other tests do.
- `testDocumentationScreenshotsWhenRequested` renders the WaterWall screens with example values for the documentation when `TEST_RUNNER_SRP_DOCS_SCREENSHOTS=1` is set.
- The device matrix's server side no longer requires an HTTP Host, because the generated client and the app may send different names by design.
- The device matrix builds its BGP4 framing cases with the `bgp4` configuration switch. It put the flag in node-options, which the app refuses, so none of those combinations ever ran.
- The device matrix's GeoIP cases check the routing: the reference server's log shows whether each download came straight from the phone or through WaterWall. Before, they only measured traffic.
- The live tests' sustained UDP check waits up to 60 seconds past its duration instead of 20, and its log line counts the datagrams it sent again. Each lost datagram costs a 5-second retry, so paths that lose a few in 90 seconds ran out of time although UDP worked. The TCP ping test logs the state its default-route check ends in.

## 1.2.0 (29) - 2026-10-31

### Added
- Auto Switch for WaterWall profiles, on by default under Options: when the connection fails, Auto Reconnect tries the next WaterWall profile of the same server, and when the network loses too many packets (15% of the packets sent within 30 seconds, or two connections dropped within two minutes) the connection moves to a profile with the other carrier (TCP or UDP) that has not lost packets on that network yet. A network change returns to the selected profile.
- WaterWall measures its TCP connections to the server (packets sent and retransmitted, data received, round-trip time, retransmission timeout and connections the network dropped) and writes a summary to the log every minute while traffic flows.
- The measurement also covers the UDP carriers: KCP segments sent again, QUIC packets declared lost, and KCP or QUIC sessions that stopped hearing from the server. Auto Switch therefore moves a lossy KCP or QUIC connection to a TCP profile as well.

### Fixed
- TCP ping skipped WaterWall profiles that carry QUIC over a TCP stream; they are pinged like the other TCP transports now.

### Changed
- WaterWall VPN comes first in the protocol list of the profile editor.

### Development
- The `--lifecycle` device run checks that Auto Switch connects through another profile of the same server when the selected one cannot reach it, and that the outer TCP connections are measured.

## 1.2.0 (28) - 2026-10-31

### Added
- WaterWall profiles offer Auto Reconnect, Retry Times, Switch to Wi-Fi When Available and On Sleep under Options, like the other protocols.
- Pull down the profile list to TCP-ping every profile's server, or swipe a profile right to ping only that one. The handshake is timed over the physical network even while the VPN is connected, progress is shown during the run, and profiles without a TCP server (UDP transports, WARP, server entries) are skipped; the connected profile keeps its delay measured through the tunnel.
- Ping results are colored (green below 200 ms, orange below 500 ms, red from 500 ms or on failure) and kept across launches.

### Fixed
- WaterWall Options showed the SSTP description; it now describes the WaterWall options.
- WaterWall did not notice a stopped server, so Auto Reconnect and Retry Times never started. Only data relayed from the server now counts as live traffic, and the server is probed once it has been silent for 15 seconds (checked every 5 seconds).
- With On Sleep set to Off and Auto Reconnect disabled, WaterWall kept the VPN connected without a working connection after the device woke; it now disconnects with a message.

### Development
- The device test matrix gains `--lifecycle`, which checks the sleep modes, reconnects and the retry limit against a real peer that it stops and restarts, and `SRP_TEST_WW_UPLOAD_ONLY` for upload-only runs; it now always builds the shipped Release runtime.
- The `--lifecycle` device run also checks that TCP ping measures the physical network while the VPN is connected.
- `SRP_TEST_ALLOWED_SOURCE` accepts a comma-separated list of client addresses, so a device on cellular can reach the isolated test peer alongside the harness host.

## 1.2.0 (27) - 2026-10-31

### Fixed
- VMess over TLS or Reality, including TLS with ALPN, never finished connecting.
- The VPN extension could crash when a QUIC session closed or the tunnel stopped.
- HTTP/2 uploads could queue without limit until iOS ended the VPN extension for memory.
- KCP and QUIC dropped incoming data, including acknowledgements, while an app paused reading.
- QUIC stream uploads could overrun their queue while the carrier was paused.
- The VPN extension could crash when the packet budget refused a new TCP flow.
- Uploads under heavy load could be reset; the iOS TCP receive window is now bounded.

### Changed
- WaterWall applies tighter backpressure between its nodes and records more detailed diagnostics.
- Profile Save stays tappable and names the missing value instead of staying disabled.
- Obfuscator skip modes are rejected for connection input, where they corrupt data.

### Development
- The device test matrix supports key-based SSH, client-limited ports and re-executed WaterWall peers, treats UDP as not applicable in full-duplex runs, and keeps tunnel stderr and debug lines in test diagnostics.
- OpenSSL builds without assembly on fresh iOS configures.
- Added the upload stability report.
