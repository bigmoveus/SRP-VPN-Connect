# Upstream patches (SoftEtherVPN 5.02.5187)

Applied to `upstream/` (vendored copy). Keep this list current when patching.

1. `Mayaqua/Mayaqua.c` — `CheckUnixTempDir()`: early `return` under `SRP_IOS`
   (/tmp is not writable in an app extension; nothing in the client core uses it).
2. `Mayaqua/Unix.c` — legacy shadow `struct statfs` disabled under `SRP_IOS`
   (conflicts with the SDK); `system()` call in the service-stop path compiled
   out under `SRP_IOS` (service code never runs in the extension).
3. `Cedar/NativeStack.c` — `system()` calls remapped to a stub under `SRP_IOS`
   (Linux SecureNAT helper; never used by the client core).
4. `Cedar/Connection.h` — `CLIENT_OPTION` gained `char SniOverride[...]`
   (TLS SNI/verification hostname override; the app UI "Hostname" field).
5. `Cedar/Protocol.c` — `ClientConnectToServer`: SNI override honored for the
   TLS handshake, and the `SRPSETrustCheck()` hook (implemented in
   `bridge/SRPSEClient.c`) is invoked right after the TLS handshake so the
   app can verify the server chain with SecTrust.
6. `Cedar/Session.c` — debug prints in `NewClientSessionEx` (cert auth path).

7. `Mayaqua/Network.c` — `SecureRecv` SSL-error debug print now includes
   remote IP/port and socket type (root-causing the benign QoS close alert).
8. `Cedar/Protocol.c` — client cert-auth debug prints + a `MaxConnection/QoS`
   debug line after the Welcome pack (all Debug-level only).
9. `Cedar/Protocol.c` — `ClientConnect`: UDP acceleration starts without NAT-T (`no_nat_t`)
   when the hint is `tcp`, which `bridge/SRPSEClient.c` sets when the profile's NAT-T switch is off,
   so that switch stops every query to the NAT-T servers (the connect path already honors `tcp`).
10. `Mayaqua/DNS.c` — `DnsResolver` thread: on Android (`__ANDROID__`) the IPv6 case asks `getaddrinfo` for
    `AF_UNSPEC` with `AI_ADDRCONFIG`, because Bionic refuses `AI_ALL | AI_V4MAPPED` with `EAI_BADFLAGS` and no server
    name resolved; each result is read by its own family (unchanged on iOS, where the results are IPv6 or v4-mapped).
11. `Mayaqua/Network.c` — UNIX `connect_timeout`: on Apple platforms (`SRP_IOS` and `__APPLE__`) an `EISCONN` answer
    counts as connected only when `getpeername` finds a peer, because Darwin answers `EISCONN` to the repeated `connect()`
    after the first one was refused; without it a closed port looked connected and failed later as "not a VPN server"
    (Linux and Android answer `ECONNREFUSED` and never reach the check).
12. `Mayaqua/Network.c` — `NewSSLCtx`: no `SSL_CTX_set_keylog_callback` under `SRP_IOS` (iOS and Android). Upstream
    prints every TLS session secret through `Debug()`, and both apps send the core's `Debug()` lines to the user's log.
