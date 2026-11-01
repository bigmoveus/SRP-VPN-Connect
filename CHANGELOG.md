# Changelog

All notable changes to SRP VPN Connect are recorded here. Every commit adds its entry under **Unreleased**; a TestFlight or App Store build moves those entries under its version and build number.

## Unreleased

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

### Changed
- New profiles start as WaterWall VPN with its default configuration on port 443 instead of SSTP; existing profiles keep their protocol.
- The SSTP tunnel log records the extension's memory when the link comes up and, near the memory limit, how much data waits for PPP framing and for the network.

### Development
- The WaterWall runtime build fails when one of WaterWall's lwIP symbols keeps a name the other protocols' lwIP uses (`WaterWall/tests/lwip_prefix_contract.py`); `WaterWall/generate_lwip_prefix.py` regenerates `srp_lwip_prefix.h` after an lwIP upgrade.

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
