# SoftEther VPN Protocol core (native)

Native SoftEther VPN client protocol for the SRPTunnel network extension.

- `upstream/` — vendored SoftEther VPN 5.02.5187 (Apache-2.0) sources
  (`Mayaqua/`, `Cedar/`, `libhamcore/`, `GlobalConst.h`) with minimal iOS
  patches (see PATCHES.md).
- `bridge/` — SRPSEAdapter (L2/L3: Ethernet<->IPv4, ARP, DHCPv4 client),
  SRPSEClient (session driver C API), SRPSEStubs (server-only symbol stubs).
- `openssl/` — OpenSSL 3.0.15 static builds with all symbols prefixed
  `srpse_` so they coexist with the BoringSSL libs used by the SSTP core.
  Rebuild with `./build_openssl.sh` (runs on macOS, outputs iphoneos+macosx).
- `build_secore.sh` — compiles `build/<platform>/libSECore.a`
  (iphoneos + macosx slices) from upstream + bridge sources.
- `SETest/` — macOS E2E harness (connects to a real SoftEther server,
  does DHCP/ARP/ICMP/DNS through the tunnel). Build: `SETest/build.sh`.
- `shim/sodium.h` — libsodium stub (only WireGuard server code needs the
  real library; it is excluded).

The extension-side Objective-C wrapper is `Core/SRPCore/SRPSoftEtherClient.*`.
