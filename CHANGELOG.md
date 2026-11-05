# Changelog

All notable changes to SRP VPN Connect are recorded here. Every commit adds its entry under **Unreleased**; a TestFlight or App Store build moves those entries under its version and build number.

## Unreleased

### Added
- The Android app's release build can now be signed: Gradle signs `assembleRelease` when `SRP_ANDROID_KEYSTORE` and `SRP_ANDROID_KEYSTORE_PASSWORD` are set. The key and its password stay outside the repository, and a build without them needs neither.
- An early Android app in `Android/`, WaterWall only: Kotlin and Jetpack Compose, minSdk 26, targetSdk 36, arm64. One screen takes a client node graph, connects through a `VpnService` that keeps the app's own sockets outside the tunnel, and shows the log. Tested on an Android 16 emulator with the production `vless-tls` chain and its TLS check on: downloads and uploads finish through the tunnel with matching SHA-256, and a server with a self-signed certificate is refused.
- The Android app now has everything the iOS app has for WaterWall: the same home screen, profile editor, WaterWall configuration screen, GeoIP routing, WireGuard and Direct modes, options, messages and log, in light and dark, and the same connection logic (start-up and health checks, Auto Reconnect, Retry Times, Auto Switch, Switch to Wi-Fi, On Sleep). A unit test checks the Kotlin chain builder against answers recorded from the iOS one on 37,977 configurations.

### Changed
- WaterWall moved to the official 1.5.3. The server now runs the official release as published, and both apps build 1.5.3 with only their own client changes on top: the packet device, link quality counters, the connection budget, memory limits for phones, and holding QUIC and KCP delivery instead of pausing their carriers. KCP's wire format changed in 1.5.3, so a KCP chain needs a client and a server of the same version.
- The public GitHub repository's history no longer holds the test phone's id, the team id or the test servers' names and address. Its commits from 2026-10-30 on have new hashes and the same authors, dates and messages, so an earlier clone must be cloned again, and the WaterWall guide's build step now checks out `6e5134d4`, whose `WaterWall/upstream` is the same source as before.
- The test programs no longer hold the test phone's id, the team id or the test servers' names: `device_matrix.py` needs `SRP_DEVICE_ID` and `DEVELOPMENT_TEAM`, OCTest reads `OC_URL`, OVPNTest's stunnel mode `OVPN_STUNNEL_HOST` and SETest `SE_HOST`, and each stops with a clear message without its value.
- The WaterWall test matrix no longer names the test server: the direct GeoIP check takes its address from `SRP_MATRIX_DIRECT_IP` and stops with a clear message without it, and the device matrix takes the server name from `SRP_TEST_HTTP_URL`.
- WaterWall's shared build now works for Android: OpenSSL uses the app's minimum API level and finds the NDK compiler in its prefix step, Android links a shared library instead of Apple's packed archive, and it keeps the lwIP limits tested on iOS. On Android its log lines now go through the logger like on other platforms, instead of straight to logcat at every level, and it no longer runs `iptables` at start, which held up the tunnel for 10 seconds. The iOS runtime archive is unchanged apart from OpenSSL's build date.
- The repository now keeps each platform in its own folder: the iOS app moved from the top level into `iOS/`, leaving room for `Android/` beside it. `WaterWall/` stays at the top because both apps build it, the C bridge over it moved from `Core/SRPCore` into `WaterWall/native`, and the WaterWall examples moved into `WaterWall/examples`. The iOS app itself is unchanged: the same files in the bundle, the same symbols and segment sizes, and all unit tests pass.
- The WaterWall documentation now describes only the current state: TestFlight build 33 against our own server program, WaterWall 1.5.2 plus the repository's changes, from new test runs of all 163 scenarios. Troubleshooting explains what the server's DNS timeout and the packet budget's refusal mean, and the installation page builds the server program from source and sets `"tries": 5` in `core.json`.
- The country database moved from the iOS app's folder to `WaterWall/GeoIP`, beside the rest of WaterWall, because both apps ship it. The iOS app bundles it in the same place as before.
- WaterWall's shared code now fits an Android process. It no longer samples CPU and memory load there, where SELinux denies the files it reads and the failed reads counted as being under load. It leaves signals to Android, whose request for a stack dump would have stopped the tunnel. It reads its TCP link counters with `TCP_INFO`, which the rule for moving to another carrier on packet loss needs. Other systems compile the same code as before.
- The WaterWall documentation now covers Android: the guides apply to both systems, each screenshot of the UI guide stands next to its Android twin, and a new Android page lists what differs and what we tested on a Samsung Galaxy A55 and the Android emulator.
- The WaterWall server's TCP receive window is now 2 MiB instead of 4 MiB, so four long uploads on a raw IPv4 chain fit in the Android app's read-ahead and none of their packets are lost: four uploads of 16 MiB at once take about 15 seconds, against 14 on a Connections chain, and less waits in front of the tunnel. One raw IPv4 upload can now have at most 2 MiB on its way per round trip. The apps keep their own 256 KiB.
- The WaterWall documentation names the server program that now runs, builds it from that commit, gives the Android chain results measured on it, and no longer lists many long uploads as a limit of Raw IPv4 chains on Android.
- The evidence inventory records the build steps as run from a fresh clone at the commit the guide now names.
- The WaterWall documentation names the server program that now runs and builds it from that commit, gives the Android chain results measured on it, and says how many TCP connections a Raw IPv4 chain on the server holds and where a refusal is logged.
- The evidence inventory records the build from a fresh clone of the commit the guide now names for the server program with 1024 connections.
- The iPhone device tests send the traffic of a raw IPv4 or WireGuard case through the tunnel, to an address of the server other than its public one, and a case fails if the test server saw its transfers come from outside the tunnel.
- The iPhone's Raw IPv4 and WireGuard scenario pages give results measured through the tunnel. Their earlier transfer figures had left outside it, because iOS keeps the server's own address out of the tunnel on these inputs; the FAQ and the Android page now say so.

### Fixed
- WaterWall's device tests failed now and then when the test server's DNS answered slowly: with WaterWall's default of two tries, a lookup through a fast local resolver gives up within 0.75 seconds and closes the line. The test server now uses five tries, about six seconds.
- WaterWall's packet budget test allowed 8 TCP connections at once while the test opens about 10, so two were refused every run. It now allows 32.
- The description of WaterWall's QUIC server still said its final drain lasts five seconds; it now describes the 30 second limit and the stream FIN.
- WaterWall's speed test server could crash at the end of a test over KCP: it kept reading its own state after finishing, because KCP keeps the line alive while it delivers queued data.
- Uploads through a raw IPv4 chain lost packets each time the outer connection paused: WaterWall's packet device kept delivering what it had queued, and `PacketsToStream` drops what arrives while it is paused. The packets now wait in the queue until it resumes. On the Android test phone two uploads of 16 MiB at once went from 30 to 40 seconds to 7.5, with almost nothing sent twice.
- The iOS unit tests on a device stopped building when WaterWall's bridge header moved to `WaterWall/native`; their target now searches that folder.
- The Android build steps now name the SDK folder: a fresh clone has no `local.properties`, so Gradle could not find it.
- The ✕ in the iOS profile editor now discards what was changed. The editor changed the saved profile directly, so the changes stayed after ✕: the list showed them, Connect used them, and the next save of any profile stored them. It now works on a copy, for every protocol and all of its screens, and Save puts that copy in place of the profile with the same Keychain entries.
- WaterWall's `StreamToPackets` threw away whole reads of good packets on a raw IPv4 chain: it compared what it had buffered with a 128 KiB limit before taking any packet out, so a read of that size was lost with everything in it, and a chain with no outer layer reads that much whenever the line is busy. It now takes every complete packet out of each read, which leaves at most one incomplete packet buffered, so the limit is gone.
- Uploads through a raw IPv4 chain crawled after losing a stretch of packets, as Android's queue in front of the tunnel does when many long uploads run at once: without selective acknowledgements from WaterWall's lwIP a sender repairs one segment per round trip, and lwIP keeps only 32 packets out of order, so nearly a whole window had to be sent again that way. lwIP now sends SACK as upstream's c9113786 does, with upstream's fix for a segment it could not keep. Four uploads of 16 MiB at once took 43 seconds on Android and now take about 20.
- A raw IPv4 chain on a WaterWall server stopped taking new TCP connections at 16 open: one web page could reach that, and so could about seven reconnects, because a client that vanishes keeps its connections' share for about 11 minutes. Each connection reserves `max-pending-bytes` of `max-total-pending-bytes`, and the default total of 16 MiB suited a phone's memory, not a server. Without the key the total is now 1 GiB, which is 1024 connections at the server's 1 MiB each. A reservation allocates nothing: 1024 flooded connections cost the program 270 MiB. The apps still send their own 16 MiB, and the core now accepts up to 1 GiB.

## 1.2.0 (33) - 2026-11-03

### Fixed
- A WaterWall connection over MUX could now and then fail with a TLS error: when a carrier read boundary fell inside the first bytes of a new connection, VLESS and Trojan servers took it for a probe and rejected the connection.
- A finished WaterWall QUIC line disappeared without telling the other side, which kept the line open until its idle timeout and kept sending packets that opened new associations on the server. The side that finishes now sends a stream FIN after its last byte, and the other side closes the connection once it has read everything.
- A QUIC line closing with data still queued gave up after 5 seconds and checked every millisecond while it waited; it now waits up to 30 seconds and wakes only when something can have changed.
- WaterWall's HTTP server let queued HTTP/2 response data grow without limit, and releasing it overflowed the TCP write queue and reset the connection. It now pauses the service above 1 MiB of queued data, as the HTTP client already does.
- A WaterWall profile failed to start with "TCP probe failed after fifteen attempts" whenever the first answer took over a second: the next probe attempt reset the wait for it and could never succeed on the same port.
- WaterWall MUX downloads lost their connection while uploads filled the same parent: the client closed a child whose queue reached 4 MiB, because the pause request reached the server too late. Reads on the parent now stop until the queues drain, for at most 5 seconds at a time.
- A KCP download could stop partway and time out after 120 seconds: WaterWall's loop clock could step back a millisecond, a server line then looked silent for ages and was destroyed with the rest of the response still queued.

## 1.2.0 (32) - 2026-11-02

### Fixed
- A WaterWall upload could crawl at about three TCP segments a second for up to a minute, on any chain, and sometimes hit the 180 second limit of a request. When the start of an upload overflowed the queue in front of the tunnel, iOS retransmitted the lost stretch, and WaterWall's TCP stack acknowledged each retransmission within a millisecond. Without TCP timestamps iOS took that for proof the retransmission was needless and repaired one segment per retransmission timeout. WaterWall's TCP stack now negotiates timestamps.
- Repairing a lost stretch of a WaterWall upload could still move only four TCP segments a second, because WaterWall's TCP stack held the acknowledgement of a lone segment for its 250 ms timer. Packets from iOS now enter the stack in batches, and each batch's acknowledgements go out when it ends.

## 1.2.0 (31) - 2026-11-02

### Fixed
- `WaterWall/UPSTREAM_VERSION` and the documentation site said the app's WaterWall was based on upstream 1.5.0, although its code has been based on 1.5.2 since 2026-10-27. Both now say 1.5.2, and the last six files of that release (PingClient and PingServer, which the app does not build) are in place. The WaterWall compiled into the app does not change.
- WaterWall could stop all traffic for about half a minute until the health check closed the tunnel. A lock in its event loop could miss a wakeup on the phone's ARM processor, and the worker thread then slept until the tunnel was stopped.
- After each WaterWall KCP connection the app kept the line for up to 30 seconds, retransmitting its close frame and waiting for an acknowledgement servers never send, and each retransmission opened a useless line on the server. It now waits only until its data is acknowledged, sends the close frame once and releases the line, and sends nothing more once it reads the server's close frame. Uploads of many small requests went about twice as fast in our tests.
- A new WaterWall KCP connection could get a UDP port a recent connection had used and reach what the server still kept for that port. It then received nothing, and a TLS connection through it failed after hanging for a minute. A UDP port now stays out of use for 60 seconds after it is released.

## 1.2.0 (30) - 2026-11-02

### Added
- A documentation site in `tutorial/`: static HTML guides for WaterWall (installation, getting started, configuration, the app's screens, troubleshooting and FAQ) and one page for each of the 163 scenarios tested on the phone against WaterWall 1.5.2, with its server file, app settings, procedure and result. `tutorial/tools/waterwall_scenarios.py` turns a device test run into sanitized evidence files and renders the scenario pages from them; it refuses to write a file that still holds a public address or a local path. SSTP follows later.
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
- The runtime recovery test waits for WaterWall to stop before it waits for the restart. It checked for the restart while the old runtime still reported itself up, so its second round of downloads and UDP began before the restart.

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
