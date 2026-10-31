# Changelog

All notable changes to SRP VPN Connect are recorded here. Every commit adds its entry under **Unreleased**; a TestFlight or App Store build moves those entries under its version and build number.

## Unreleased

### Added
- WaterWall profiles offer Auto Reconnect, Retry Times, Switch to Wi-Fi When Available and On Sleep under Options, like the other protocols.

### Fixed
- WaterWall Options showed the SSTP description; it now describes the WaterWall options.
- WaterWall did not notice a stopped server, so Auto Reconnect and Retry Times never started. Only data relayed from the server now counts as live traffic, and the server is probed once it has been silent for 15 seconds (checked every 5 seconds).
- With On Sleep set to Off and Auto Reconnect disabled, WaterWall kept the VPN connected without a working connection after the device woke; it now disconnects with a message.

### Development
- The device test matrix gains `--lifecycle`, which checks the sleep modes, reconnects and the retry limit against a real peer that it stops and restarts, and `SRP_TEST_WW_UPLOAD_ONLY` for upload-only runs; it now always builds the shipped Release runtime.

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
