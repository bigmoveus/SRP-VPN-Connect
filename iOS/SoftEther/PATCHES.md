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
