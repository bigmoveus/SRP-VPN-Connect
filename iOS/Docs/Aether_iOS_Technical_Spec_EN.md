# Aether for iOS — Full Technical Specification

**Architecture, C/Rust integration, zero-configuration WARP, bring-your-own-server WireGuard, UDP/TCP data paths, adaptive censorship resilience for Iranian networks, deployment, security, validation, and implementation backlog**

> **Document type:** Technical Specification / Architecture Decision Record (ADR) / Implementation Backlog  
> **Version:** 1.2 — 2026-10-08  
> **Language:** English  
> **Status:** Engineering kickoff baseline; items marked `SPIKE`, `BLOCKER`, or `P0` require evidence before release commitments.  
> **Android reference:** https://github.com/MrMatin0/Aether  
> **Upstream engine:** https://github.com/CluvexStudio/Aether  
> **Audience:** iOS, C/native, Rust, networking, server/DevOps, security, QA, and product engineers.

---

## Executive engineering directive: implement Phase 0 and Phase 1 first

**The team MUST begin with Phase 0 (source audit and native feasibility) and Phase 1 (iOS VPN framework and packet bridge), before investing in the full graphical interface.** The first milestone is a **working proof on a physical iPhone** showing real packet transfer—not a mockup, a successful handshake alone, a green Connect indicator, or an app that exposes a SOCKS port without handling device traffic.

**Required early evidence:**

1. A signed `NEPacketTunnelProvider` starts and stops correctly on a physical iPhone.
2. The existing C code is inventoried, built for Apple targets, and connected through a well-defined C ABI.
3. The required Rust Aether functionality is demonstrated on iOS or a documented alternative is approved.
4. At least one actual bidirectional **TCP** test and one actual bidirectional **UDP** test pass through the intended packet path, with server-side confirmation.
5. DNS, route/underlay behavior, memory ownership, cancellation, TLS certificate verification, and leakage risks are understood.
6. Any unproven prerequisite is recorded as a `BLOCKER` or `SPIKE`; it must not be represented as complete.

**Go/no-go rule:** Do not start full-scale SwiftUI design or promise a release date until Phase 0 and Phase 1 pass their exit criteria. A minimal debug interface is sufficient during these phases.

**Adaptive-resilience sequencing:** The Iran-oriented network diagnosis, protocol prioritization, and automatic fallback architecture in **Section 14A** is a post-proof engineering workstream. It MUST NOT replace or delay the physical-iPhone Phase 0/Phase 1 TCP + UDP proof gates; the team may write tests/designs in parallel, but must not treat unproven transports or obfuscation as working features.

---

## 0. Executive summary and architecture decision

The objective is a production-capable iOS VPN app with a simple **Connect** button and two connection modes:

1. **Auto WARP / Direct:** no user-owned VPS and no manually imported configuration. The client discovers a reachable Cloudflare endpoint and establishes an encrypted WARP tunnel using an adapted Aether engine.
2. **Personal Server / BYOS:** the user imports a standard WireGuard configuration or scans a QR code; the iPhone connects to the user's own VPS through a normal WireGuard tunnel, carrying both TCP and UDP IP traffic.

A future optional feature is **Personal Server + Aether Egress**: the iPhone enters a user-owned VPS over WireGuard, and the VPS subsequently routes traffic through an Aether/WARP-based egress path. This is a **separate networking project**, not a feature automatically enabled by installing Aether on the VPS.

**Architecture decision:** use one iOS application, one `NEPacketTunnelProvider` extension, and two independent VPN backends behind a stable internal API. Preserve the team's existing C networking implementation as a **C adapter / C core**. For direct WARP, reuse the upstream Aether **Rust** functionality through its documented C interface where feasible. Do not rewrite the whole Rust protocol stack in Swift without an explicit technical reason.

**Important technical distinctions:**

- Upstream Aether is fundamentally a **WARP client/local SOCKS5 engine**, not a generic personal VPN server.
- **UDP as transport is not the same as UDP support for application traffic.** Validate carrier, encapsulated datagrams, and packet bridge independently.
- The source repositories indicate **AGPL licensing**. Confirm exact licenses, transitive dependencies, and distribution obligations before commercial release.
- Upstream documentation contains a warning that **TLS certificates are not checked** in at least one documented path, while other release notes discuss pinning. This discrepancy requires source-level audit. **Unverified TLS = P0 RELEASE BLOCKER.**

### MVP feature scope

| Feature | MVP | After MVP |
|---|---|---|
| Real iPhone direct WARP connection | Required | Reliability enhancements |
| Automatic endpoint discovery and reconnect | Required | Scan tuning and caching |
| Basic policy-driven failover (last-good endpoint and H3/H2 where proven) | P1 after Phase 0/1 proofs | Wider multi-backend policy engine, field tuning |
| Iran network diagnostics / reproducible impairment test harness | P1 engineering acceptance | Carrier/ASN-specific tuning with opt-in field evidence |
| MASQUE HTTP/3 | Primary feasibility target | Optimization |
| MASQUE HTTP/2 fallback | Only after proven compatible | Fine tuning |
| WARP-over-WireGuard mode | Feasibility-dependent | Advanced mode |
| Personal WireGuard server | Required | Managed provisioning |
| TCP, UDP, and DNS on both modes | Required acceptance criteria | Richer protocol coverage |
| Auto / Personal mode selection | Required | Multi-profile policies |
| Basic English/localizable user interface | Required | RTL and accessibility polish |
| Psiphon, Tor, and protocol chaining | Out of MVP | Independent phase |
| Aether egress on a VPS | Out of MVP | Separate proof of concept |
| Absolute kill switch / universal per-app VPN | Do not promise | Platform/entitlement research |

---

## 1. Existing source code and reuse boundaries

### 1.1 Android repository: MrMatin0/Aether

The Android fork is described as using Kotlin/Compose, Android `VpnService`, vendored Aether code under `native/aether`, and `hev-socks5-tunnel`. Android native-build scripts produce libraries such as `libaether.so`, `libhev-socks5-tunnel.so`, and a JNI/bridge artifact such as `libaethertun.so`.

**Those Android binaries cannot be linked directly into an iOS extension.** Review the source, dependency graph, and data flow instead. Replace JNI, Android-specific VpnService calls, and process assumptions with supported Apple APIs.

Inspect before implementing:

- `README.md`, `README.fa.md`, `THIRD_PARTY_NOTICES.md`, `MODIFICATIONS.md`, `SECURITY.md`.
- Vendored `native/aether/` and the native bridge entry points.
- `scripts/fetch-natives.sh`, `scripts/build-natives.sh`.
- Connection, reconnect, DNS, packet forwarding, and cleanup paths in `app/`.

### 1.2 Rust upstream: CluvexStudio/Aether

Upstream documents C-facing functions including `aether_core_start`, `aether_job_poll`, `aether_job_cancel`, and `aether_string_free`. Its manifest indicates library output suitable for native linking. **Extract exact signatures, ownership, error handling, packet-channel interfaces, and thread safety from the pinned header/source; do not guess FFI signatures from names.**

Reported capabilities include endpoint scanning, MASQUE H3/H2, WARP WireGuard transport, a local SOCKS5 service, and channel-oriented integration. Their existence in upstream documentation does **not** establish that they run unmodified inside an iOS Packet Tunnel extension.

Audit Apple target support for dependencies including `quiche`, `boring`/BoringSSL, `tokio`, `smoltcp`, and `boringtun`. Confirm whether build scripts, crypto, runtime, entropy, threads, and socket usage are compatible with the extension sandbox.

**Version policy:** pin exact commit SHAs of both repositories and dependency lockfiles in `third_party/versions.lock`. Never build releases from floating `main` or mutable `latest` container tags.

### 1.3 Existing C code: day-one inventory

| Question | Evidence required |
|---|---|
| Input boundary | IP packet, TCP byte stream, UDP datagram, SOCKS request, or configuration? |
| Output boundary | IP packet, transport socket, datagram, or local listener? |
| OS dependencies | Portable POSIX, or Linux/Android-specific `epoll`, `/dev/net/tun`, JNI? |
| Concurrency model | Single-thread, worker pool, callback, event loop, polling? |
| Memory ownership | Allocate/free rules, temporary buffers, copy vs. zero-copy? |
| UDP support | Bidirectional datagrams, mapping, timeouts, fragmentation? |
| Address families | IPv4, IPv6, MTU/ICMP behavior? |
| Licensing | External libraries, cryptography, permitted redistribution? |

**Deliverable:** `docs/CORE_INVENTORY.md`, a call graph of native entry points, and a reproducible Apple SDK compile/link report. Do not assume the C program can be launched as a separate long-running process on iOS.

---

## 2. End-to-end network architecture

### 2.1 Auto WARP: no personal server

```text
+---------------------------+
| iOS App / SwiftUI         |
| Connect, profiles, status |
+-------------+-------------+
              | NETunnelProviderManager
              v
+---------------------------------------------+
| Packet Tunnel Extension                     |
| NEPacketTunnelProvider                       |
| NEPacketTunnelFlow (virtual IP packets)      |
+------------------+--------------------------+
                   | packet bridge / C ABI
                   v
+---------------------------------------------+
| C adapter + Aether Rust core                |
| identity -> scan -> verify -> dial           |
| IP packets / TCP / UDP <-> WARP session      |
+------------------+--------------------------+
                   | encrypted MASQUE or WG
                   v
           Cloudflare WARP edge
                   |
                   v
                 Internet
```

The **Connect** button activates the OS-level VPN, not just a local SOCKS5 socket. The interface must reflect `NETunnelProviderSession` and the actual working data path, rather than internal engine state alone.

### 2.2 Personal Server: user's own WireGuard VPS

```text
 iOS UI: imported WG profile + Keychain references
                       |
                       v
             NEPacketTunnelProvider
                       |
                       v
    Personal WireGuard backend (audited C OR WireGuardKit)
                       |
                 Encrypted UDP
                       |
                       v
 User-owned VPS: wg0 -> IP forwarding / NAT -> Internet
```

The VPS is a **real WireGuard server** here. Upstream Aether is **not** a prerequisite. The official [WireGuard Apple repository](https://github.com/WireGuard/wireguard-apple) is an implementation reference. An audited C-based WireGuard backend may be used if the project mandates a C network core, as long as it passes the same tests.

### 2.3 Optional Personal Server + Aether egress

```text
 iPhone ---- WireGuard ----> VPS wg0
                              |
                      ingress routing policy
                              |
                     IP/flow adapter: TCP + UDP
                              |
                    local Aether API / SOCKS5
                              |
                        Cloudflare WARP
                              |
                           Internet
```

Routing `wg0 -> Aether` is **not automatic**. Engineers must implement policy routing, TCP and UDP flow adaptation, connection/NAT state, DNS, IPv6 behavior, routing-loop prevention, health checks, failure handling, and safe isolation. Never expose an unauthenticated SOCKS listener publicly on `0.0.0.0`.

---

## 3. Product and functional requirements

| ID | Requirement | Priority | Acceptance evidence |
|---|---|---|---|
| FR-01 | One-tap Auto WARP | P0 | Working data path without VPS or imported profile |
| FR-02 | System VPN permission flow | P0 | Correct prompt, denial handling, recovery |
| FR-03 | Endpoint discovery and verification | P0 | Selection based on real data-plane health |
| FR-04 | TCP, UDP, DNS in/out | P0 | Independent HTTPS, UDP echo, QUIC, DNS tests |
| FR-05 | Import WireGuard profile / QR | P0 | Validated import and VPS connection |
| FR-06 | Switch Auto / Personal | P0 | One active tunnel and correct mode switching |
| FR-07 | Reliable disconnect/cancel | P0 | No leaked sockets, listeners, tasks or handles |
| FR-08 | Wi-Fi / cellular transitions | P0 | Recovery without false Connected indication |
| FR-09 | Secure credentials | P0 | Keychain, no secret logging |
| FR-10 | DNS, MTU, IPv4 controls | P1 | Correct route/DNS behavior |
| FR-11 | State, stats and error codes | P1 | Genuine counters and redacted diagnostics |
| FR-12 | MASQUE H3 -> H2 fallback | P1 | Tested transport and inner-UDP behavior |
| FR-13 | Controlled IPv6 support | P1 | Dual stack or proven leak prevention |
| FR-14 | Multiple saved profiles | P1 | Secure edit/delete/import/export |
| FR-15 | VPS Aether egress | P2 | Independent TCP/UDP prototype |

### Non-functional requirements

- Establish memory, CPU, battery, and throughput budgets only after baselining on physical iPhones.
- Never block the main thread for discovery, cryptography, socket I/O, or poll loops.
- Implement cancellation, explicit deadlines, bounded queues, and backpressure.
- Do not collect packet payloads, private keys, visited URLs, destination IPs, or DNS queries by default.
- Test offline mode, captive portals, packet loss, endpoint failure, DNS failure, and network transitions.
- Clearly communicate dependence on third-party Cloudflare infrastructure and its availability policies.

---

## 4. iOS components and repository organization

### 4.1 Targets and language boundaries

| Target / Module | Language | Responsibility |
|---|---|---|
| `AetherApp` | SwiftUI | UI, onboarding, mode selection, profiles |
| `PacketTunnel` | Swift with C/Obj-C boundary | NetworkExtension and packet flow lifecycle |
| `TunnelOrchestrator` | Swift | Shared state machine and backend selection |
| `NativeBridge` | C ABI | Stable memory and packet contract |
| `CNetworkCore` | C | Existing team networking code / packet adapter |
| `AetherCore` | Rust static library | WARP discovery/transport functionality |
| `PersonalWGBackend` | C or WireGuardKit | Personal VPN transport |
| `SharedModels` | Swift/C structs | Versioned config and error models |

### 4.2 Ownership by process

**App target:** stores VPN configurations through `NETunnelProviderManager`, securely imports profiles, stores secrets in Keychain, selects a mode, and renders state. `providerConfiguration` should contain only a profile identifier and non-sensitive metadata.

**Extension target:** implements `startTunnel(options:completionHandler:)` and `stopTunnel(with:completionHandler:)`, retrieves an authorized profile, initializes the proper backend, calls `setTunnelNetworkSettings`, pumps packets through `packetFlow`, publishes status, and performs cleanup.

**Native bridge:** gives both backends a common lifecycle and packet API, maps native errors to stable codes, and prevents Rust panics/abort paths from crossing the FFI boundary.

**Important:** an iOS Network Extension runs in its own sandboxed, resource-limited process. Link C/Rust code into the **signed extension binary**. Do not rely on shelling out to background daemons or downloading and executing native binaries.

### 4.3 Suggested monorepo

```text
Aether-iOS/
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CORE_INVENTORY.md
│   ├── SECURITY_THREAT_MODEL.md
│   ├── UDP_TEST_PLAN.md
│   ├── PHASE_0_1_EXIT_CRITERIA.md
│   ├── NETWORK_RESILIENCE_POLICY.md
│   ├── IRAN_NETWORK_TEST_MATRIX.md
│   └── RELEASE_CHECKLIST.md
├── ios/
│   ├── Aether.xcodeproj
│   ├── AetherApp/
│   │   ├── App.swift
│   │   ├── UI/{Connect,Profiles,Settings,Diagnostics}/
│   │   └── Services/{VPNProfileManager,KeychainStore}.swift
│   ├── PacketTunnel/
│   │   ├── PacketTunnelProvider.swift
│   │   ├── TunnelOrchestrator.swift
│   │   ├── NetworkResilienceCoordinator.swift
│   │   ├── PacketFlowAdapter.swift
│   │   └── Backends/{WarpBackend,PersonalWGBackend}.swift
│   ├── Shared/{ConnectionProfile,TunnelError,ConfigVersion}.swift
│   └── Entitlements/
├── native/
│   ├── include/tunnel_core.h
│   ├── c_adapter/
│   ├── aether_rust/        # fixed commit / vendor / submodule
│   └── build-ios.sh
├── server/
│   ├── wireguard/         # public templates; NEVER commit secrets
│   └── optional-egress/   # independent prototype
├── tests/{integration,network-matrix,impairment-harness,fixtures}/
├── third_party/{versions.lock,NOTICES.md,SBOM.md}
└── .github/workflows/
```

---

## 5. Apple NetworkExtension integration

### 5.1 Prerequisites

- A supported macOS + Xcode environment and **real iPhone** for functional Packet Tunnel testing.
- Apple Developer team, valid app IDs, provisioning, and signing for both app and extension.
- `Network Extensions` entitlement including `packet-tunnel-provider`, according to current Apple provisioning requirements.
- App Group / Keychain Sharing only where needed; configure access groups explicitly.
- Extension point `com.apple.networkextension.packet-tunnel`.

### 5.2 Correct lifecycle

```text
Idle -> LoadingProfile -> StartingBackend -> Scanning / Handshaking
     -> ConfiguringInterface -> Connected
     -> Reconnecting / Stopping -> Idle
                    \-------> Failed(reason)
```

- Create/save a `NETunnelProviderManager` configuration, then use `connection.startVPNTunnel()` to start the extension.
- Call `startTunnel`'s completion handler with success **only after** tunnel settings and an operational data path are established. Report all failure paths exactly once.
- Discovery and startup must be asynchronous, cancellable, and protected against concurrent Connect/Disconnect races.
- Drive `packetFlow.readPackets` as a repeatable callback/batch loop; feed inbound IP packets back via `writePackets` with `AF_INET`/`AF_INET6` family metadata.
- Control packet batch size, queue limits, MTU, buffer ownership, and path changes.
- Ensure WARP bootstrap, endpoint DNS, and transport sockets use the proper **underlying network** and do not recursively enter their own tunnel. Verify this on a device.

### 5.3 Conceptual Swift skeleton — NOT production-ready

```swift
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var coordinator: TunnelCoordinator?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // 1. Load validated profile by ID; no secrets in providerConfiguration.
        // 2. Obtain private keys from an authorized Keychain access group.
        // 3. Instantiate Auto WARP or Personal WireGuard backend.
        // 4. Establish underlay transport with cancellation and timeouts.
        // 5. Derive assigned addresses, DNS, MTU and routes from backend.
        // 6. Call setTunnelNetworkSettings(settings).
        // 7. Start bidirectional packetFlow <-> backend packet pumps.
        // 8. Complete successfully only after verified readiness.
        //    Every failure must invoke completionHandler(error) exactly once.
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        // Cancel discovery, stop pumps, close sockets, destroy native handles.
        // Always complete, even if some cleanup step reports an error.
        completionHandler()
    }
}
```

Compute `ipv4Settings`, `ipv6Settings`, included/excluded routes, DNS settings, and MTU from validated backend configuration and explicit policy. **Do not hard-code fictional tunnel addresses** as final production settings.

### 5.4 Platform constraints

- Do not assume Linux `/dev/net/tun`, Linux `epoll`, JNI, or a freely accessible system TUN file descriptor on iOS.
- `NEPacketTunnelFlow` is the supported public packet interface. Avoid undocumented file-descriptor hacks.
- Do not promise a universal kill switch, unrestricted per-app VPN, or unlimited background execution before verifying Apple capabilities.
- Account for other VPN configurations and OS-driven session changes.

---

## 6. Proposed C-to-iOS bridge contract

Upstream Aether has **its own C API**. The following header is an **internal adapter design proposal**, not a transcription of Aether's upstream header.

```c
/* native/include/tunnel_core.h — DESIGN PROPOSAL, NOT UPSTREAM API */
#ifndef TUNNEL_CORE_H
#define TUNNEL_CORE_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vpn_engine vpn_engine_t;

typedef enum {
    VPN_MODE_WARP = 1,
    VPN_MODE_PERSONAL_WG = 2
} vpn_mode_t;

typedef enum {
    VPN_OK = 0,
    VPN_ERR_CONFIG = -1,
    VPN_ERR_NETWORK = -2,
    VPN_ERR_CANCELLED = -3,
    VPN_ERR_UNSUPPORTED = -4,
    VPN_ERR_INTERNAL = -5
} vpn_result_t;

typedef void (*vpn_packet_callback_t)(
    void *user_context,
    const uint8_t *packet,
    size_t packet_length,
    int address_family /* AF_INET or AF_INET6 */
);

/* Non-blocking start: readiness arrives through the state/event API. */
vpn_result_t vpn_create(const char *config_json,
                        vpn_packet_callback_t on_packet,
                        void *user_context,
                        vpn_engine_t **out_engine);
vpn_result_t vpn_start(vpn_engine_t *engine);
vpn_result_t vpn_send_ip_packet(vpn_engine_t *engine,
                                const uint8_t *bytes, size_t count,
                                int address_family);
vpn_result_t vpn_get_state_json(vpn_engine_t *engine,
                                char *buffer, size_t *inout_size);
vpn_result_t vpn_cancel(vpn_engine_t *engine);
void vpn_destroy(vpn_engine_t *engine);

#ifdef __cplusplus
}
#endif
#endif
```

### Non-negotiable ABI conditions

- `vpn_engine_t` must be opaque; version APIs, configs, and return codes.
- Document all input/output buffer lifetimes. A caller-owned packet or string is valid only during its call/callback unless explicitly copied.
- Packet callbacks may run on native worker threads. Never call SwiftUI directly from such callbacks.
- No callback to deallocated objects, double free, use-after-free, or unsafe re-entrancy. `cancel` must be idempotent; `destroy` must safely follow stop.
- Formalize the two-call size-query contract for `vpn_get_state_json`, plus buffer-too-small behavior.
- Add `WOULD_BLOCK`, backpressure and/or explicit packet-drop behavior to the final API; avoid unbounded buffering.
- Prefer a C module map or narrow Objective-C shim for Swift integration.
- Release strings returned by upstream APIs using the allocator/free function documented by that upstream version (e.g. `aether_string_free` where applicable).
- Poll native control handles on a dedicated queue; do not confuse control polling with the actual IP-packet interface.

---

## 7. Direct WARP implementation and automatic scanning

### 7.1 Connection sequence

1. Choose the `auto-warp` profile.
2. Retrieve previously authorized identity credentials securely or create/register a new supported identity.
3. Bootstrap registration/endpoints over the **underlay**. Surface a clear error when required APIs are inaccessible.
4. Reuse the core's cached-endpoint/scanning logic; start with a balanced policy.
5. Verify candidate endpoints using **actual data-plane traffic**, not a successful TCP/QUIC handshake alone.
6. Create a MASQUE H3 session and obtain/derive validated tunnel network parameters.
7. Connect `NEPacketTunnelFlow` to the engine's real IP-packet API in both directions.
8. Enter Connected state only after successful TCP, UDP, and DNS checks appropriate to the declared capabilities.
9. On failure, retry a cached known-good endpoint with cooldown; escalate to wider scanning when necessary.

### 7.2 Initial selection policy (project proposal)

```text
if pinned_endpoint:
    attempt_connect_and_data_plane_verify()
else:
    try_cached_last_good_and_verify()
    if failed: scan_balanced_and_verify()
    if failed: scan_thorough_and_report_diagnostic()

transport_preference:
    MASQUE_H3
    -> MASQUE_H2 (only if inner UDP behavior is supported and tested)
    -> WARP_WG (optional and only with a verified packet bridge)
```

This is a proposed product policy; it is **not a claim** about exact upstream scan ranking or fallback implementation. Tune deadlines and scans through measured iPhone/network results.

### 7.3 iOS/Rust compatibility notes

- `cargo build --release` on macOS is not equivalent to building for iOS. Compile explicitly for Apple target triples and SDKs, with correct crypto/linker flags.
- Build Rust static libraries for the real iOS architecture and each **actually supported** simulator architecture. Create an `.xcframework` only from successfully built slices (for example with `xcodebuild -create-xcframework`).
- Remove interactive CLI prompts and child-process requirements from embedded library mode.
- Audit platform-specific TLS, DNS, entropy, and socket assumptions; maintain a small documented upstream patch set if needed.
- `aether_job_poll` and similar methods represent control-plane behavior: find and test the **actual packet channel** in source before designing the packet pump.

---

## 8. Personal Server protocol and imported profile contract

### 8.1 Protocol choice

The MVP personal-server backend MUST use standard **WireGuard over UDP**. Do not invent a new client/server transport without an explicit compatibility requirement. Users should be able to connect to their own VPS or a compatible standard WireGuard server.

Aether's WARP-oriented MASQUE client must **not** be marketed as supporting arbitrary self-hosted MASQUE servers without separate server-side implementation and compatibility testing.

### 8.2 Minimum profile fields

| Field | Required | Description |
|---|---|---|
| `profile_id`, `name`, `mode` | Yes | `personal-wireguard` |
| `interface_private_key_ref` | Yes | Keychain reference, never plaintext defaults |
| `interface_address` | Yes | Assigned IPv4 and/or IPv6 addresses |
| `dns_servers` | Recommended | Route through the intended tunnel |
| `mtu` | Optional | Prefer auto/path-tested value |
| `peer_public_key` | Yes | Server public key |
| `preshared_key_ref` | Optional | Stored in Keychain |
| `endpoint_host`, `endpoint_port` | Yes | IP/FQDN; default UDP 51820 is configurable |
| `allowed_ips` | Yes | Full tunnel typically `0.0.0.0/0` plus IPv6 only when safely supported |
| `persistent_keepalive` | Optional | Often 25s for NAT use cases |
| `last_connected_at` | Optional | Avoid sensitive data |

### 8.3 Import and validation

- Parse and semantically validate `wg-quick` text: base64 keys, CIDRs, ports, size limits, peer count, duplicates, and allowed ranges.
- A QR code must encode a valid profile; remove temporary plaintext after storing secrets in Keychain.
- Export should be **redacted by default**. Explicit private-key export requires a prominent warning and user action.
- If remote profile import is added, require authentic HTTPS and/or a signed profile format; never put credentials in URL query strings or analytics.
- Acceptance requires a successful real-device connection using an imported configuration.

---

## 9. Personal WireGuard VPS deployment — Ubuntu example

**This installs a real WireGuard server, not an Aether upstream VPN server.** Adapt rules to the Linux distribution, current firewall stack, and cloud provider. The following is an illustrative starting point, not a hardened production appliance.

### 9.1 Prerequisites

- Supported Ubuntu VPS with public IPv4 and sudo access.
- UDP port `51820` (or a chosen port) allowed by the cloud firewall and host firewall.
- Identify the egress interface with `ip route get 1.1.1.1`. `eth0` below is only a **placeholder**.
- This sample is IPv4-only; the iOS implementation must address potential IPv6 leakage separately.

### 9.2 Install and generate server credentials

```bash
sudo apt update
sudo apt install -y wireguard iptables
sudo install -d -m 700 /etc/wireguard
sudo sh -c 'umask 077; wg genkey > /etc/wireguard/server.key; wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub'
sudo chmod 600 /etc/wireguard/server.key
sudo cat /etc/wireguard/server.pub
```

Never place the **server private key** in Git, tickets, chat, or logs. Ideally generate the **client private key on the device** and send only its public key to the server administrator.

### 9.3 Enable IPv4 forwarding

```bash
printf 'net.ipv4.ip_forward=1\n' | sudo tee /etc/sysctl.d/99-aether-wireguard.conf
sudo sysctl --system
```

### 9.4 Example `/etc/wireguard/wg0.conf`

Replace `<SERVER_PRIVATE_KEY>` from secure server storage, `<IPHONE_PUBLIC_KEY>` with the client-generated public key, and **`eth0` with your real egress interface**.

```ini
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY>
SaveConfig = false
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE

[Peer]
PublicKey = <IPHONE_PUBLIC_KEY>
AllowedIPs = 10.66.66.2/32
```

**Production caution:** use a default-deny firewall and scoped `wg0` forwarding rules, idempotent firewall configuration, key rotation, access audits, and observability. If the host uses `nftables`, UFW, container-managed rules, or cloud network policy, integrate deliberately—do not paste incompatible iptables rules indiscriminately.

```bash
sudo chmod 600 /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
sudo systemctl status wg-quick@wg0 --no-pager
sudo wg show
```

Permit UDP/51820 through both relevant firewalls while retaining secure SSH management access.

### 9.5 Example iPhone WireGuard profile

```ini
[Interface]
PrivateKey = <IPHONE_PRIVATE_KEY_CREATED_LOCALLY>
Address = 10.66.66.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <YOUR_VPS_PUBLIC_IP_OR_DOMAIN>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`1.1.1.1` is an illustrative DNS choice, not a privacy/security guarantee. IPv6 routing must be explicit: simply omitting `::/0` is **not an IPv6 leak-prevention strategy**.

### 9.6 VPS smoke tests

```bash
sudo wg show
sudo ss -lunp | grep 51820
sysctl net.ipv4.ip_forward
sudo journalctl -u wg-quick@wg0 -n 60 --no-pager
```

After connecting from a real iPhone, verify handshake, VPS public egress IP, HTTPS downloads, two-way UDP echo, DNS resolution, reconnection, and negative leak tests.

---

## 10. UDP, TCP, QUIC, DNS, IPv6: definitive engineering policy

### 10.1 Transport versus inner traffic

| Mode | Underlying carrier | Expected inner traffic | Release evidence |
|---|---|---|---|
| WARP MASQUE H3 | QUIC over UDP | IP traffic: TCP and UDP | UDP echo + real QUIC from iPhone |
| WARP MASQUE H2 | HTTP/2 over TCP | Encapsulated UDP **only if implemented** | Inner-UDP pass + latency/HOL measurements |
| WARP WireGuard | UDP | IP traffic: TCP and UDP | Independent UDP + DNS tests |
| Personal WireGuard | UDP to VPS | IP traffic: TCP and UDP | Bidirectional datagrams and NAT proof |
| Android fork Psiphon/Tor chains | Depends on chain | General UDP not supported in some documented chains | Out of MVP |
| VPS + Aether SOCKS5 | Local TCP listener; UDP support requires verification | Requires compatible relay/packet adapter | No assumptions without end-to-end tests |

**Never equate "QUIC uses UDP" with "iPhone app UDP packets are forwarded correctly."** These are different properties at different layers.

### 10.2 Packet data path and backpressure

`NEPacketTunnelFlow` provides raw IP packets. If the native backend consumes/emits IP packets, bridge them directly. If the backend only offers a SOCKS5 listener, add an iOS-compatible **TUN-to-SOCKS adapter** with verified UDP handling. A local SOCKS socket is an implementation detail, not proof of VPN completeness.

Required behavior:

- TCP connect, half-close, reset, socket pooling and reconnect.
- UDP 5-tuple/session mapping, TTL/expiry, address/port preservation, simultaneous flows, and reverse datagrams.
- UDP fragmentation/reassembly, MTU, PMTU, oversized packets, and ICMP considerations.
- Real-world QUIC/HTTP3, UDP DNS, and optional UDP-to-TCP DNS fallback when policy permits.
- Underlay routing-loop protection for engine-controlled sockets.
- Bounded input/output queues, rate controls, packet-drop/timeout counters, and nonblocking teardown.

### 10.3 DNS

- Apply DNS settings via `NEDNSSettings` on the VPN interface.
- Define and test secure underlay DNS for WARP enrollment, endpoint bootstrapping, and personal VPN endpoint resolution.
- Tunnel-targeted DNS should be routed through the selected tunnel. Test for leaks and silent downgrades.
- DoH/DoT are optional future work after TLS trust and performance analysis.
- Never silently fall back to an insecure off-tunnel resolver contrary to explicit user policy.

### 10.4 IPv6

The MVP must **prove** one of two options:

1. **Full dual stack:** IPv4/IPv6 addresses, routes, DNS, underlying endpoint resolution, and egress work safely; or
2. **Validated IPv4-only policy:** IPv6 traffic is reliably blocked/contained within the capabilities iOS permits, with Wi-Fi and cellular leak tests.

"Only add an IPv4 default route and hope IPv6 does not leak" is unacceptable. If the OS or entitlements prevent a safe guarantee, the limitation is a release decision and must be disclosed.

---

## 11. Shared configuration/data models

The following are **proposed app-level schemas**, not upstream Aether's source formats. They intentionally store **references to secrets**, not private keys.

### 11.1 Auto WARP example

```json
{
  "schemaVersion": 1,
  "id": "default-auto",
  "name": "Auto WARP",
  "mode": "autoWarp",
  "warp": {
    "transport": "masque-h3",
    "scanMode": "balanced",
    "endpoint": null,
    "fallbackToH2": true
  },
  "network": {
    "ipv6Policy": "blockUntilSupported",
    "dnsPolicy": "insideTunnel",
    "mtu": "auto"
  },
  "secretRefs": {}
}
```

### 11.2 Personal WireGuard example

```json
{
  "schemaVersion": 1,
  "id": "office-vps",
  "name": "My VPS",
  "mode": "personalWireGuard",
  "wireguard": {
    "address": ["10.66.66.2/32"],
    "dns": ["1.1.1.1"],
    "endpoint": "vpn.example.org:51820",
    "peerPublicKey": "BASE64_SERVER_PUBLIC_KEY",
    "allowedIPs": ["0.0.0.0/0"],
    "persistentKeepalive": 25
  },
  "secretRefs": { "interfacePrivateKey": "keychain:wg:office-vps" }
}
```

All example names, endpoints, and public-key text are **placeholders**. Make configuration versioned, migratable, strictly validated, and length-bounded. Never deserialize arbitrary input directly into C structs/Rust FFI without validation.

---

## 12. Connection state, errors, and observability

### 12.1 State machine

```text
DISCONNECTED
  +-- Connect --> PREPARING
                   +-- WARP --> SCANNING --> VERIFYING --> HANDSHAKING
                   +-- WG   --> RESOLVING --------------> HANDSHAKING
                                                         |
                                                    CONFIGURING_TUN
                                                         |
                                                     CONNECTED
                                                   /           \
                                            RECONNECTING   DISCONNECTING
                                                 |               |
                                         CONNECTED / FAILED  DISCONNECTED
```

One orchestrator owns the authoritative state. `CONNECTED` means a **usable IP data path**, not merely an allocated object, local listener, tunnel interface, or successful handshake.

### 12.2 Stable error taxonomy

```text
ERR_NO_PERMISSION
ERR_PROFILE_INVALID
ERR_ENDPOINT_UNREACHABLE
ERR_SCAN_TIMEOUT
ERR_TLS_VALIDATION
ERR_IDENTITY_REGISTER
ERR_WG_HANDSHAKE
ERR_UDP_UNSUPPORTED
ERR_DNS
ERR_PACKET_BRIDGE
ERR_TUN_SETTINGS
ERR_NETWORK_CHANGED
ERR_CANCELLED
ERR_NATIVE_CRASH
```

For each code define user-facing messaging, retry policy, transient/permanent category, sensitive-data redaction, and unit-test coverage.

### 12.3 Privacy-preserving diagnostics

**Allowed by default:** connection timing, reconnect counts, candidate count, error class, bytes sent/received, packet drops, handshake latency, and aggregate device performance.

**Disallowed without explicit, separate consent:** raw packet payload, full URLs, private keys, registration tokens, raw DNS queries, destination history, or general packet capture.

Debug-only packet capture requires an explicit development/testing flow, strict access, and redaction.

---

## 13. Security, privacy, terms, and open-source licensing

### 13.1 P0 BLOCKER: upstream TLS certificate behavior

Public upstream documentation reportedly includes the statement **"Certificates are not checked"** for TLS behavior, while some upstream release notes describe SPKI pinning. Neither statement establishes the exact security state of all current code paths. The security team must inspect the **pinned source revision** and each relevant TLS path: WARP registration/API, MASQUE H3/H2, upstream proxies, any DNS/ECH requests, and Zero Trust functions if used.

**Release=BLOCKED** until certificate-chain validation, hostname verification, intended pinning where applicable, and negative MITM tests are confirmed. Do not bypass certificate validation merely to make connections work in restricted networks. Nonstandard endpoint IP discovery must still authenticate the intended peer correctly.

### 13.2 Threat model and required controls

| Threat | Control |
|---|---|
| TLS/API/edge MITM | Chain, hostname, trust/pinning policy, negative tests |
| WG key or WARP identity theft | Keychain, minimal access, no plaintext log |
| Unauthorized VPS SOCKS access | Loopback-only listener, authenticated WG ingress |
| DNS/IPv6 leaks | Explicit routes, resolver policy, negative tests |
| Traffic escape / tunnel loop | Underlay isolation, fail-closed tests |
| Resource exhaustion | Bounded queues, socket limits, cancellation |
| Vulnerable/malicious upstream code | Commit pins, SBOM, dependency and code review |
| Malformed config / QR injection | Strict parser, size limits, fuzzing |
| Sensitive telemetry | Privacy minimization, security review |

### 13.3 License diligence

- `CluvexStudio/Aether`: check the pinned Cargo manifest's **AGPL-3.0-only** declaration.
- `MrMatin0/Aether`: check the fork's **AGPL-3.0-or-later** license and vendored component notices.
- Review `hev-socks5-tunnel`'s own license.
- Review the components, notices, and distribution conditions for `wireguard-apple` / WireGuardKit.

**Legal decision required:** Will the distributed iOS app satisfy applicable AGPL obligations? If the business needs a closed-source proprietary binary, resolve alternate licensing or architecture **before building the product around AGPL core code**. This document is not legal advice.

### 13.4 Cloudflare dependency and branding

WARP is third-party infrastructure. Review Terms of Service, acceptable use, enrollment behavior, API limits, rate limits, account requirements, changes to endpoints, and brand/trademark usage. Zero-configuration availability is not guaranteed indefinitely. Do not represent the application as an official Cloudflare product.

### 13.5 App Store and signing

Apple's **App Review Guideline 5.4** imposes VPN-specific requirements, including considerations around developer organization accounts, user data disclosure, and privacy policies. The release/legal team must verify current classification and eligibility for the specific distribution model, and confirm signing and entitlements for development, TestFlight, and App Store distribution separately.

---

## 14. Practical testing plan

### 14.1 Network/device test matrix

| Test | Home Wi-Fi | LTE/5G | UDP/443 blocked | TCP/443 available | IPv6-only/NAT64 | Network switch |
|---|---|---|---|---|---|---|
| Auto WARP H3 | Test | Test | Expect fail/fallback | Test | Test | Test |
| Auto WARP H2 | Test | Test | Test | Test | Test | Test |
| Personal WG | Test | Test | Depends on WG port | WG needs UDP | Test | Test |
| TCP/UDP/DNS and leak tests | Test | Test | Test | Test | Test | Test |

Run on multiple **physical** iPhone models and targeted iOS versions. Determine the minimum supported iOS version only after checking dependencies, SDK behavior, and actual build results; record it in `README.md`.

### 14.2 Mandatory protocol/security tests

- **TCP:** HTTPS 200, large download, redirect, long-running stream, reset and half-close.
- **UDP:** bidirectional echo, UDP DNS, controlled NTP/test endpoint, multiple datagram sizes.
- **QUIC:** real HTTP/3 or controlled QUIC test endpoint, with evidence at the server.
- **Routing:** correct external exit IP per mode, DNS/IPv6 leak tests, route consistency.
- **Lifecycle:** 10 repeated connect/disconnect cycles, airplane mode, Wi-Fi/cellular switch, suspend/resume, app termination/background, OS extension restart.
- **Security:** invalid certificate/MITM simulation, invalid WG credentials, malformed QR/config, inadvertent public SOCKS exposure, incomplete socket teardown.
- **Native:** memory ownership checks, fuzzers, Rust panic boundaries, ASan/TSan where target/tooling supports them.
- **Performance:** latency, sustained throughput, peak memory, CPU, battery behavior and dropped packets compared with baseline.

### 14.3 Formal definition: "UDP works"

A **PASS** requires an app or test harness running on a real iPhone to send a UDP datagram with known payload through the selected VPN, receive the actual UDP reply, and obtain independent endpoint/server-side evidence confirming that route. A QUIC handshake or WireGuard handshake alone does **not** qualify.

### 14.4 Formal definition: "Connected"

1. The system VPN session reports an active tunnel.
2. A real TCP probe succeeds, and a real UDP probe succeeds for any mode advertised as full TCP/UDP VPN.
3. DNS and observed egress IP match the selected policy.
4. TLS, identity, or endpoint failures do not leave the UI in a false Connected state.

---

## 14A. Iran-specific network resilience: detection, priority, automatic fallback (NEW IN v1.2)

> **Status:** Proposed engineering design, not a verified property of Aether+ and not evidence that any transport currently works on a particular Iranian ISP. Deploy only after Phase 0 and Phase 1 pass, and calibrate on consent-based measurements from physical devices. "Iran-specific" here refers to a **test environment and threat model**, not a hard-coded assumption about every Iranian network.
>
> **Non-goals:** No guarantees of connectivity during a national/near-total international shutdown, no claims of undetectability, no remote access to users' packet contents, no covert network testing, no automatic use of an unapproved personal server, and no downgrade of TLS/identity checks to improve apparent success.

### 14A.1 Objectives, assumptions, and release gates

**Outcome:** A user presses **Connect** once. A local policy engine selects a backend, verifies *real* data transfer, diagnoses observed failure classes, and changes endpoint/carrier/backend when doing so is both technically feasible and authorized. The UI reports *what was verified* rather than making untestable censorship claims.

Mandatory principles:

1. **Availability first, but never at the expense of confidentiality:** preserve TLS verification, identity checks, VPN routing, and fail-closed behavior during all retries.
2. **Observable symptoms ≠ confirmed cause:** a failed UDP handshake suggests UDP reachability trouble; it does not prove ISP DPI or intentional blocking. Report `suspected_udp_impairment`, not `government_blocked_udp`.
3. **No single universal route priority:** start with a documented baseline, then rank using successful **on-device** validation, per-underlay recent evidence, and constrained energy/traffic budgets.
4. **Scope-sensitive verification:** measure both outer transport (UDP QUIC/TCP TLS/WireGuard) and inner application traffic (TCP, UDP, DNS); do not treat an H3 handshake as proof that UDP application traffic works.
5. **Respect explicit user selection:** `auto_warp`, `personal_only`, or `auto_with_authorized_personal_fallback`. Never import keys, switch exit jurisdictions, or transfer traffic to a different operator without the user's opt-in.
6. **No false positives:** an ICMP/PING, DNS lookup, `CONNECT 200`, or successful WireGuard handshake alone is insufficient to label an IP route as usable.
7. **Gracefully unavailable:** if no authorized route works, show `NO_VALIDATED_ROUTE`, retain strict routing/leak protections where OS permits, and offer a retry/manual diagnostic action.
8. **Source-specific documentation:** upstream Aether currently documents H3/H2, scanning, noise, H2 fragmentation, and data-plane checking. It does not guarantee their functionality on iOS; source/audit/physical-device tests are required.

**Prerequisite:** Phase 0/1 must first demonstrate a real iOS Packet Tunnel, correct underlay sockets, and bidirectional TCP + UDP through the intended packet path. The resilience controller cannot compensate for an unimplemented data plane.

### 14A.2 Threat model and failure-class decision table

| Observed condition / possible interference | Local evidence required | Candidate recovery | What it cannot establish |
|---|---|---|---|
| Some Cloudflare endpoints unavailable | Repeated endpoint-level connect timeouts, other endpoints healthy | Retry last-good alternative; bounded scan and ranking | Does not prove deliberate IP blocking |
| UDP/QUIC path unreachable or consistently degraded | H3 attempts fail while independent TCP/443 control and/or H2 path succeed, across multiple candidates | MASQUE H3 → verified MASQUE H2; avoid aggressive UDP scans temporarily | Cannot infer all UDP ports fail from UDP/443 alone |
| MASQUE handshake succeeds, data stalls | Handshake accepted but end-to-end in-tunnel TCP/UDP control replies absent | Reject candidate, classify `DATA_PLANE_BLACKHOLE`, try different endpoint/carrier | Cannot declare success from handshake alone |
| DNS bootstrap poisoned, failing, or unavailable | Resolver divergence/errors; direct endpoint or authenticated resolver succeeds where permitted | Reuse signed/cached endpoint metadata; trusted bootstrap path; H2 underlay if appropriate | DNS results alone are not proof of DPI |
| TCP/443 handshake interfered with | TLS timeout/reset after reproducible baseline; validation failure tracked separately | Alternate healthy endpoint; optionally audit-tested upstream H2 fragmentation/noise profile | Never ignore certificate failure or auto-enable unverified hacks |
| WireGuard handshake fails | No authenticated handshake + underlay UDP path checks; clock/key/route preflight | Try alternate UDP endpoint for that WG profile; if user authorized, select independently configured transport | Standard WG has no native TCP fallback |
| Fragmentation, PMTU, MTU black-hole | Small payload works, larger payload consistently fails; retransmissions/ICMP evidence if available | Adjust tunnel MTU within verified safe range; validate UDP sizes | Small datagram success alone does not imply all traffic works |
| Wi-Fi ↔ cellular / IPv4 ↔ IPv6 / NAT64 transition | `NWPathMonitor` change, interface/path capabilities, old socket invalidation | Cancel stale attempts; re-evaluate tunnel/underlay; rerun minimal validation | Do not assume the new carrier preserves old reachability |
| Captive portal / no usable underlay | Path attached but approved internet controls fail | Pause scans; explain sign-in/network issue; retry after path changes | VPN cannot fix an unestablished upstream link |
| Broad external connectivity failure | Several independent allowed controls fail, all available modes exhaust bounded budget | Display unavailable; no busy loop and no fake Connected state | A client cannot promise operation during a near-total shutdown |
| WARP identity/API denied or TLS trust failure | Identity enrollment failure/rate limit OR certificate-chain/hostname/pin failure | Identity-specific backoff; explain; authorized personal route may be tried only if policy allows | **Never** disable TLS verification or mint identities repeatedly |

**Diagnostics classification must attach evidence and confidence:** `observed` (deterministic local error), `suspected` (multiple correlated probes), or `unknown` (ambiguous). No public UI text should present ISP attribution as a fact without independent evidence.

### 14A.3 Target architecture and ownership boundaries

```text
 Main iOS App (SwiftUI; settings/profile consent, *not* active packet owner)
    |  configured mode, opt-ins, nonsecret policy version
    v
 NETunnelProviderManager / NEPacketTunnelProvider [one active tunnel]
    |
    +-- NetworkResilienceCoordinator (Swift control; can call C policy engine)
    |       +-- UnderlayObserver (NWPathMonitor / NWPath; constrained/expensive)
    |       +-- DiagnosticProbeScheduler (bounded, privacy-preserving)
    |       +-- FailureClassifier (confidence + reason codes)
    |       +-- CandidateRegistry (validated WARP endpoints / user WG profiles)
    |       +-- PolicyEvaluator (rank, select, cooldown, hysteresis)
    |       +-- SessionSupervisor (start, verify, swap, stop, cleanup)
    |
    +-- C ABI: transport lifecycle, packet I/O, metrics, typed events
    |       +-- Aether Rust MASQUE H3 / H2 / WG (ONLY audited iOS-supported paths)
    |       +-- Personal WireGuard backend (user-imported, consented config)
    |       +-- Future plugin: audited independently provisioned circumvention backend
    |
    +-- NEPacketTunnelFlow <--> packet bridge <--> selected tunnel backend
    |
    +-- Redacted, local-only diagnostics and bounded per-underlay cache
```

**Separation of concerns:** a C networking core may implement packet transport and candidate scoring, but lifecycle, entitlements, OS route settings, and policy authorization stay in the signed iOS extension. The app target edits persistent policies; the extension decides during live sessions using an immutable snapshot/versioned update. Do not attempt to launch external binaries or arbitrary background daemons.

**Control plane versus data plane:** all candidate probes must be isolated from the active user traffic path, must not accidentally route through the candidate itself, and must not invalidate the current session until a safe transition is available. Use underlay-aware socket handling and explicitly test the absence of VPN feedback loops.

### 14A.4 Candidate types and protocol preference graph

**Baseline candidate order for *Auto WARP*, subject to tests and policy:**

```text
 [Recent valid last-good WARP endpoint for this underlay and mode]
               |
     +---------+----------+
     |                    |
 MASQUE H3 / QUIC      MASQUE H2 / TCP
 UDP 443 (default)     TCP 443 (when H3 fails or measured unsuitable)
     |                    |
     +---------+----------+
               |
   WARP WireGuard / UDP (OPTIONAL: only if compiled, supported, audited)
               |
   Bounded alternate endpoint scan and validation
               |
   No validated Auto WARP candidate -> error or authorized profile fallback
               |
 [Personal WG, only if user has opted into automatic personal fallback]
               |
   No authorized/working route -> FAILED / NO_VALIDATED_ROUTE
```

- A valid cached candidate is **reverified**, not blindly trusted. Cache must be invalidated after transport/security changes, severe path changes, and reasonable TTL expiry.
- H2 on TCP is a **fallback carrier**, not a guarantee of same latency/throughput. A developer MUST verify whether Aether's embedded H2 implementation actually carries inner UDP end-to-end through the iOS bridge; a carrier using TCP may still transport UDP application packets *if the implementation supports it*.
- H2 TLS ClientHello fragmentation and documented noise profiles are optional **audited experiments**. Never enable as a universal default on unmeasured networks; they may introduce extra fingerprinting, latency, instability or incompatibility.
- Nested modes (`gool`, `mim`), Psiphon/Tor, and custom transport over a personal VPS are **Phase-5+ candidates** requiring separate source, iOS runtime, security, licensing, UDP, and egress tests. They are **not** the MVP's automatic fallback promise.
- Standard personal WireGuard is **UDP-only as an outer transport**. It does not magically work where every needed UDP path is blocked. TCP-capable personal server fallback requires a separately deployed and audited compatible server and client transport (future ADR).
- No option silently repurposes public Cloudflare IPs to reach a user-owned personal server; treat them as separate products/backends.

**Mode-specific policy:**

| User-selected mode | Allowed candidates | Automatic exit/IP change | Consent required |
|---|---|---|---|
| `AUTO_WARP_ONLY` | WARP H3/H2, optional audited WARP WG | Between validated WARP routes | Standard initial VPN permission/terms |
| `PERSONAL_ONLY` | Selected user WG profile; its explicitly authorized endpoints | Only within that profile's allowed endpoints | Profile import and selection |
| `AUTO_WITH_PERSONAL_FALLBACK` | WARP, then explicitly nominated personal profile(s) | Yes, when already authorized and displayed in UI | **Separate opt-in** explaining exit provider change |
| `MANUAL_PROTOCOL` | Chosen backend/protocol | Retry allowed within defined pinned profile; no cross-protocol jump unless consented | Explicit user selection |

### 14A.5 Signal collection and privacy-preserving measurements

| Signal | Source | Use | Retention policy |
|---|---|---|---|
| Path viability, Wi-Fi/cellular, IPv4/IPv6, constrained/expensive | `NWPathMonitor` + `NWPath` and validated underlay API | Reset candidate assumptions and scan budgets | In-memory; no raw SSID/BSSID |
| Candidate transport connect outcome | Aether/WG backend typed result | Classify timeout/refusal/verification failure | Redacted aggregate, bounded local TTL |
| Tunnel/data-plane health | In-tunnel HTTPS/TCP probe, authorized UDP echo and DNS resolution | Confirm real functional tunnel | Success/failure + latency only; no payload logs |
| UDP loss and jitter, RTT, throughput sample | Controlled echo and test endpoint | Rank viable candidates | Coarse/aggregate values only |
| Keychain identity status | Registration/Keychain layer | Separate identity errors from filtering | Error class only; no identity token in logs |
| Battery/thermal/expensive path | OS indications where available | Reduce scan/probe work | Volatile |
| Reconnect attempts / cancellation | Coordinator | Prevent reconnect storms | Local counters and cooldowns |

**Privacy and safety:** avoid collecting SSIDs, BSSIDs, IMSI, phone identifiers, device fingerprinting, user location, browsed sites, raw destination IP lists, URLs or DNS histories. Network-scoped last-good cache should use an ephemeral/rotating *local-only* coarse network key with no exportable persistent identifier. If the network cannot be recognized safely, use a coarse per-interface profile (Wi-Fi vs cellular) and revalidate; do not manufacture a tracking ID.

No background upload of measurements by default. Opt-in support bundles must be scrubbed, human reviewable and user initiated. In sensitive environments, disable remote diagnostics entirely unless the user explicitly enables them. Never actively scan arbitrary third-party hosts: use approved endpoints and the minimum number of consented control probes.

### 14A.6 Diagnostic probes: order, data-plane verification, energy budget

**Algorithmic probe stages:**

1. Check local ability to run (`NWPath` viable, no explicit user disconnect, secrets/permission available).
2. Check cache validity and local identity state without network when possible; never create new WARP identity on every reconnect.
3. Test a *small* pool of known-good endpoints using the selected carrier and a bounded timeout.
4. Require authenticated session *and* real in-tunnel end-to-end TCP; for a claimed full-IP VPN, also require bidirectional UDP and DNS under release acceptance criteria.
5. Only if these fail, run incremental scanner groups (e.g. balanced before thorough); stop early on first validated good route with stable health.
6. For suspected UDP impairment, try verified H2/TCP or other authorized carriers; record each result separately.
7. Deprioritize failed candidates with exponential cooldown, including a jittered delay; reset selectively after an underlying interface transition.
8. If all allowable candidates fail or safety conditions trigger, stop and surface a typed error; do not burn battery in a permanent loop.

**Illustrative starting parameters (NOT empirical Iran settings; tune with real data):**

| Parameter | Engineering starting value | Notes |
|---|---|---|
| Transport connect timeout | 4–8 seconds per trial | Shorter only with evidence; distinguish TLS and transport phases |
| Data-plane verification timeout | 3–6 seconds per approved probe | Avoid conflating probe endpoint outage with carrier failure |
| Concurrent new candidate probes | At most 2 on Wi-Fi; 1 on cellular | Conserve energy and avoid rate limiting; confirm extension limits |
| First-connect scan budget | 20–30 seconds before surfacing progress/error | User-configurable retry afterward; no arbitrary unbounded scan |
| Candidate cooldown | Start 15–30 seconds, exponential up to 10 minutes | Jitter; reset based on evidence rather than purely on elapsed time |
| Stable session dwell | Minimum ~30–60 seconds before performance-driven change | Never delay urgent failure recovery |
| Probe health cadence | Sparse and path/state adaptive; e.g. 30–60s while active | Timer execution is best-effort under iOS scheduling; avoid wake guarantees |
| Cached success lifetime | 6–24 hours, with immediate revalidation after path change | Treat as heuristic; not a hard-coded trust assertion |
| Attempt cap | e.g. 8–12 new endpoints / local retry cycle | Prevent battery abuse, flooding and registration limits |
| Low Data Mode / constrained path | Reduce or pause broad scans; ask user before high data cost | Honor OS hints and user override preferences |

**Probe design requirements:** make test URLs/endpoints operator-controlled or trusted and transparent; report response types rather than merely any HTTP status. Where the probe relies on a remote UDP echo service, deploy an authenticated/limited test instance under team control, do not use open reflectors, and document payload/loss policy. Limit response sizes, enforce per-device budgets and include abuse controls.

### 14A.7 Data-plane state machine and safe transitions

```text
 IDLE --user connect--> PRECHECK
 PRECHECK --path missing--> WAIT_UNDERLAY
 PRECHECK --eligible------> PICK_CANDIDATE
 PICK_CANDIDATE ---------> CONNECTING
 CONNECTING --TLS/identity error--> HARD_FAIL (or explicit authorized alternate mode)
 CONNECTING --timeout-----> CLASSIFY -> COOLDOWN -> PICK_CANDIDATE
 CONNECTING --success-----> VERIFY_DATA_PLANE
 VERIFY_DATA_PLANE --bad--> CLASSIFY -> COOLDOWN -> PICK_CANDIDATE
 VERIFY_DATA_PLANE --good-> ONLINE
 ONLINE --path changed----> REVALIDATE / RECONNECT (invalidate old sockets)
 ONLINE --health degraded-> SUSPECT -> limited probe -> SWITCH_OR_RETAIN
 SWITCH_OR_RETAIN --candidate validated--> ATOMIC_SWITCH_OR_RESTART -> ONLINE
 SWITCH_OR_RETAIN --no safe candidate----> RETAIN_IF_STILL_HEALTHY / FAIL_CLOSED
 ANY --user disconnect----> STOPPING -> IDLE
 ANY --extension fatal-----> FAIL_CLOSED -> report without false Connected state
```

**Required switch invariants:**

- A single authoritative coordinator controls the one Packet Tunnel extension and owns cancellation tokens, current/next session handles, route settings, and resources.
- Never release secrets, start a new underlay socket through the current tunnel, or reorder routes while stale packet pumps remain active.
- A cross-backend swap (WARP ↔ personal WG) may require a controlled interruption of live sessions; do not promise seamless make-before-break until state/routing and Apple extension constraints are empirically proven.
- Before switching, apply **hysteresis**: prefer the current functioning route unless the new route passes full validation and provides an objective reliability advantage, or the old route is actually dead.
- On failure while full tunnel is expected, favor fail-closed behavior; document Apple-specific exceptions and do not claim an absolute OS-wide kill switch without validation.
- Prevent cycles: no A→B→A loops inside a cooldown, and a user disconnect always cancels outstanding probes and wins over automation.

### 14A.8 Policy engine: deterministic scoring and C ABI sketch

Start with a deterministic rule engine, not machine-learning inference. A scoring function can rank *already acceptable* candidates; it must never override security, consent or required packet-capability gates.

**Eligibility =** authenticated/trusted transport AND allowed by user mode AND protocol supported by signed app AND required test traffic validated AND non-expired authorization AND non-blocked cooldown. **Then rank eligible candidates** by freshness of actual data-plane success, connection reliability, recent handshake cost, latency, measured loss and estimated energy/overhead. Use monotonic clocks; do not let wall-clock adjustment alter cooldown logic.

Example score for a candidate that passed all hard gates (all components normalized 0..1; tunable only after field tests):

```text
 score = 0.35 * recent_end_to_end_success
       + 0.25 * reconnect_reliability
       + 0.20 * latency_score
       + 0.10 * packet_loss_score
       + 0.10 * battery_and_setup_cost_score

 A candidate that FAILS authentication, route safety, DNS policy,
 user authorization or required UDP/TCP acceptance is INELIGIBLE,
 even if a computed score would otherwise be high.
```

An illustrative, versioned C header (API proposal, **not** upstream Aether's current ABI):

```c
/* native/include/resilience_policy.h — proposed product-owned interface */
#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    RP_WARP_MASQUE_H3 = 1,
    RP_WARP_MASQUE_H2 = 2,
    RP_WARP_WG = 3,
    RP_PERSONAL_WG = 4
} rp_transport_t;

typedef enum {
    RP_OK = 0,
    RP_TIMEOUT,
    RP_UDP_IMPAIRMENT_SUSPECTED,
    RP_DATA_PLANE_BLACKHOLE,
    RP_DNS_FAILURE,
    RP_AUTH_FAILURE,
    RP_TLS_VERIFICATION_FAILURE,
    RP_PATH_CHANGED,
    RP_NO_VALIDATED_ROUTE,
    RP_USER_CANCELLED
} rp_reason_t;

typedef struct {
    uint32_t api_version;               /* must equal documented version */
    rp_transport_t transport;
    uint32_t candidate_id;              /* local opaque ID, no keys */
    bool permission_to_use_personal;    /* supplied by iOS consent policy */
    bool authenticated_and_trusted;
    bool tcp_ok;                        /* end-to-end probe */
    bool udp_ok;                        /* end-to-end echo */
    bool dns_ok;                        /* observed DNS policy */
    uint32_t rtt_ms;
    uint32_t packet_loss_permille;
    uint64_t monotonic_observed_ms;
} rp_observation_t;

typedef struct {
    uint32_t api_version;
    rp_transport_t target_transport;
    uint32_t target_candidate_id;
    rp_reason_t reason;
    bool should_switch;
    uint32_t minimum_backoff_ms;
} rp_decision_t;

/* Pure decision step; caller owns all pointers and handles all socket actions. */
bool rp_evaluate(const rp_observation_t *observations,
                 uint32_t count,
                 uint32_t user_policy_flags,
                 uint64_t now_monotonic_ms,
                 rp_decision_t *out_decision);
```

**ABI engineering notes:** real implementation needs explicit struct sizes, alignment checks, count bounds, 32-/64-bit safety, immutable input snapshots, no pointers persisted across calls, stable enum and error mapping, and fuzz/unit tests. `permission_to_use_personal` is **not** sufficient security authority by itself: the Swift extension must also validate an explicit authorized profile ID from trusted storage. A `rp_evaluate` result is advisory; the iOS coordinator enforces consent and route safety before executing it.

### 14A.9 Adaptation pseudocode (implementation contract)

```text
on Connect(requested_mode):
    policy = load_user_authorized_policy_and_profile_snapshot()
    path = snapshot_underlay_path()
    if !path.satisfied: return WAIT_UNDERLAY

    candidates = permitted_candidates_only(policy, path)
    candidates = recent_verified_cache_first(candidates)

    for candidate in candidates within attempt/time/energy budgets:
        if canceled_by_user or !same_underlay_generation(): abort
        if !security_and_consent_preconditions(candidate): continue
        session = connect_with_timeout(candidate, underlay_socket_policy)
        if session.failed:
            classify_with_evidence(session.failure)
            apply_bounded_cooldown(candidate)
            continue
        proof = validate_real_TCP_UDP_DNS_over_tunnel(session)
        if !proof.meets_required_capabilities:
            close(session)
            record_DATA_PLANE_FAILURE(candidate, proof)
            continue
        install_packet_path_and_routes_only_when_safe(session)
        mark_ONLINE(candidate, proof)
        return

    if policy.allows_personal_fallback:
        retry_only_user_nominated_personal_profiles()
    return NO_VALIDATED_ROUTE

on SessionHealthEvent(event):
    if changed_underlay_or_proven_dead:
        invalidate_stale_socket_and_probe_generation()
        reconnect_with_appropriate_budget_and_fail_closed_policy()
    else if degraded_and_still_usable:
        run_limited_non_disruptive_validation()
        switch_only_if_candidate_is_verified_and_hysteresis_passes()

on UserDisconnect:
    cancel_every_probe_and_reconnect_task()
    stop_packet_pump_and_native_backends()
    close_underlay_sockets_and_release_buffers()
    remove_session_state_safely()
```

**Implementer warning:** `install_packet_path_and_routes_only_when_safe` is conceptual; in real `NEPacketTunnelProvider` implementations, extension startup/network-settings ordering may require an established interface before data-plane checks. Engineers must document the actual Apple lifecycle and use a controlled verification path, avoiding recursion and leaks. Do **not** literally block `setTunnelNetworkSettings` waiting for traffic that cannot flow until those settings exist.

### 14A.10 Operator/network-aware strategy without brittle fingerprints

| Field environment (test grouping only) | What QA records | Policy implications |
|---|---|---|
| MCI/Hamrah-e Aval mobile | iOS version, anonymized interface class, measured H3/H2/WG outcomes | Tune from repeated device evidence only |
| Irancell mobile | Same matrix | No globally baked-in assumptions |
| Fixed broadband from multiple ISPs | IPv4/IPv6 availability, DNS behavior, endpoint success | Separate observed network failures from app bugs |
| Wi-Fi hotspot or enterprise/campus link | Captive portal, constrained path, UDP policy | Avoid broad scans, display path limitations |
| Roaming / network handover | Old/new interface and session generation | Cancel/restart and reverify underlay sockets |
| IPv6-only/NAT64 | DNS64, endpoint address family, IPv6 leak reports | Do not disable IPv6 blindly or silently expose routes |

Use only coarse, **opt-in** field metadata; never require a carrier identity, exact location, or user tracking for baseline operation. Treat a carrier's measured outcome as time-bounded and contingent on network configuration. Maintain reproducible remote-fixture captures instead of generalizing individual user experiences.

### 14A.11 Controlled impairment lab and acceptance matrix

Before expensive field testing, build a Linux/macOS-controlled network fixture for the **server/transport path** (with iPhones on a controlled hotspot/router for live tests). Use `tc netem`, `nftables` / approved packet filters, a DNS fault fixture and synthetic response delay; maintain deterministic reproducible scripts. Do not perform bulk scans against third parties.

| Test ID | Injection / simulated condition | Expected result / proof |
|---|---|---|
| IR-01 | Clean UDP/443 and TCP/443 | Prefer a validated healthy H3 candidate; TCP/UDP/DNS genuinely pass |
| IR-02 | Drop UDP/443 only | Stop repeated unproductive H3 attempts; try verified H2; inner UDP test still required |
| IR-03 | Drop TCP/443 only | H2 not usable; H3 may work if independent UDP underlay survives |
| IR-04 | All WARP candidate endpoints blackholed | Exhaust bounded scans; no false Connected; report lack of validated WARP route |
| IR-05 | Endpoint handshake succeeds, downstream packets silently dropped | Reject candidate from real data-plane validation, not just handshake |
| IR-06 | Loss 5–10%, high RTT, jitter and intermittent resets | Avoid flapping; only switch after hysteresis and validated superiority |
| IR-07 | DNS bootstrap timeout/poison simulation | Surface DNS/bootstrap classification; do not bypass certificate checks |
| IR-08 | Wrong TLS cert / expired credentials | Hard fail route; never weaken trust; separate security failure from network block |
| IR-09 | UDP fragmentation / low effective MTU | Correct MTU/packet handling, controlled failure and recovery |
| IR-10 | Wi-Fi → cellular → Wi-Fi in a session | Cancel old probes and sockets, re-evaluate candidates, no routing loop |
| IR-11 | IPv6-only and NAT64 underlay | Valid endpoint resolution or explicit unsupported error; no IPv6 leakage |
| IR-12 | Personal WG endpoint reachable/unreachable | Retry only authorized personal profile; no unauthorized mode switching |
| IR-13 | All international connectivity unavailable | Bounded failed state, clear UI, no battery-burning retries |
| IR-14 | Low Data Mode, low battery / backgrounded extension | Respect budgets and iOS scheduling; no foreground-service assumptions |
| IR-15 | Cancel mid-scan / repeated Connect presses | No orphan workers, leaked sockets, duplicate TUN callbacks or secrets |
| IR-16 | TLS H2 fragmentation/noise enabled vs disabled | Measure connection rate/latency with A/B fixture; no assumed DPI immunity |

**For each test capture:** OS/version, signed binary build/commit, mode, carrier, endpoint class (not raw user browsing), packet-level remote control-server evidence, inner TCP/UDP/DNS results, route/DNS/IPv6 leak test, power/CPU budget, typed reason code, trace ID local to session, and signed QA verdict. Keep private network metadata out of shared tickets.

### 14A.12 Success metrics, guardrails, and experiment protocol

Track **separately** for each authorized backend and controlled network scenario:

- `connect_success_rate`: proportion of attempts with verified inner TCP, UDP and DNS (not handshake-only).
- `time_to_usable_tunnel_p50/p95`: measured from user's Connect action to real verified data-plane readiness.
- `stable_session_10min_rate`: sessions delivering usable traffic without a fatal stall for ten minutes.
- `fallback_effectiveness`: percentage of original-route failures recovered by an *authorized* alternate candidate, with control group.
- `false_connected_rate`: **target 0** in the test suite; any event is a release blocker.
- `leak_failures`: **target 0** in defined supported configurations; document unpreventable OS exceptions precisely.
- `transport_coverage`: independent outer carrier and inner TCP/UDP/DNS proof per mode.
- `scan_cost`: bytes, candidate attempts, CPU, peak memory, battery proxy, and time spent per successful connection.
- `flap_count`: backend changes per stable hour and frequency of A→B→A loops.

Do not claim numerical real-world success rates without representative measurement data and methodology. Set product service-level targets **only after** an initial field baseline, explicitly segmented by time, operator, access type and iOS version. A/B experiments must compare a bounded policy change and be opt-in for any telemetry upload.

### 14A.13 User interface and transparency requirements

Expose only actionable, evidence-backed states: `Connecting`, `Scanning gateways`, `Verifying traffic`, `Connected (WARP)`, `Connected (Personal Server)`, `Limited connectivity`, `Reconnecting`, `No validated route`, and `Network sign-in required`. Provide manual protocol/profile selection and **Stop auto-switching**. Show meaningful failure reason where possible without naming a purported censor.

- In the main UI, explain clearly that `Auto WARP` uses Cloudflare's infrastructure, not a server operated by the app developer.
- If switching to a user-owned server changes exit IP/provider, show profile name and require that the user previously opted in.
- A mode that cannot pass UDP must not advertise generic "full UDP supported" solely because QUIC or WireGuard was the outer transport.
- If a fallback violates a user-enforced privacy/jurisdiction setting, reject it rather than trading privacy for availability.
- Do not show green VPN success on incomplete verification; display which test failed in optional Advanced Diagnostics.
- Enroll WARP identity once per valid device lifecycle; preserve securely and honor API limits/terms. Provide recoverable errors instead of forced mass re-registration.

### 14A.14 Engineering phases and ship/no-ship checks

**Workstream PR-0: diagnostics design (can be designed during Phase 0/1, must not distract from proof gates).** Decide probe endpoints, threat model, typed error taxonomy, local-only diagnostics, candidate cache policy and test fixtures.

**Workstream PR-1: resilience MVP (after Phase 0 + Phase 1 pass).** Integrate `NWPathMonitor`, retry last-good/alternate verified WARP candidate, H3→H2 where tested, bounded scanning, actual data-plane health checks, failed-route cooldown and user-visible failure handling.

**Workstream PR-2: authorized personal fallback (after Personal WG Phase 3 proof).** Implement explicit user opt-in, profile allowlist, WG health gate, deterministic policy switch and reconnect verification. No auto-switch to arbitrary servers.

**Workstream PR-3: further circumvention experiments (not in core MVP).** Evaluate optional upstream noize/H2 TLS fragmentation, nested modes and separately provisioned TCP-capable personal-server transport through individual ADRs and controlled field/lab tests; avoid shipping unverified obfuscation defaults.

**Ship blockers:** unverified TLS; missing physical iPhone TCP/UDP evidence for claimed modes; silent backend/exit changes without authorization; persistent reconnect storms; DNS/IPv6 leaks within promised scope; false Connected state; identity churn / registration abuse; and unbounded remote probes.

**Field-test completion gate:** validate at least two different iOS hardware models, Wi-Fi and mobile access, repeatable impairment scenarios IR-01..IR-15, and at least two distinct provider environments where volunteers explicitly consent. Treat any single-carrier result as **scenario-specific**, not as a country-wide success guarantee.

### 14A.15 Evidence and references specific to this resilience design

- [Aether upstream English guide](https://github.com/CluvexStudio/Aether/blob/main/Docs/GUIDE.en.md): the project describes MASQUE H3/H2, WARP endpoint discovery, obfuscation profiles, H2 ClientHello fragmentation, and data-plane acceptance checks. Verify source and pinned revision rather than assuming flags are exposed to iOS FFI.
- [Aether core documentation](https://github.com/CluvexStudio/Aether/blob/main/Docs/DOCS.en.md): documented protocols and user-space proxy design; distinguish the SOCKS proxy from an iOS IP packet tunnel.
- [Apple `NEPacketTunnelProvider`](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider): iOS virtual interface, route, DNS and tunnel configuration.
- [Apple `NWPath` / `NWPathMonitor`](https://developer.apple.com/documentation/network/nwpath), [monitor](https://developer.apple.com/documentation/network/nwpathmonitor/): path status, interface family and constrained/expensive properties; monitoring is not a censorship-detection oracle.
- [OONI Iran disruption case study (2025)](https://explorer.ooni.org/findings/2025-iran-blocked-whatsapp-amid-war-with-israel): illustrates variability and gaps in observational coverage during disruptions; **historical case study, not a prediction or 2026 success measurement**.
- [OONI Explorer](https://explorer.ooni.org/) and [Cloudflare Radar Iran](https://radar.cloudflare.com/ir): external contextual measurement sources; not a substitute for the team's controlled per-carrier validation.

---

## 15. Implementation roadmap and engineering epics

### Priority policy

**Execute Phase 0 and Phase 1 before full UI implementation.** These two phases are an explicit *proof gate* for connection feasibility, iOS signing/entitlements, real TUN packet flow, and bidirectional TCP/UDP on an iPhone. Only after both phases pass should the team invest in production-quality SwiftUI screens and broader product polish. Implement minimal test controls during these phases, not a decorative VPN UI.

### Phase 0 — Discovery and feasibility (mandatory first gate)

**E-00 / AUDIT — Source, C code, security, and licensing**

- [ ] Pin exact source commits and cryptographic checksums for fork and upstream.
- [ ] Inventory all dependencies and their licenses.
- [ ] Review existing C code for Apple portability, ABI, ownership and real UDP/IP capabilities.
- [ ] Audit every used TLS trust/verification path; file P0 fixes.
- [ ] Validate Apple entitlement, provisioning, TestFlight/App Store distribution strategy.
- [ ] Review Cloudflare/WARP registration policy, rate limits and allowed usage.

**E-01 / POC — Rust/C engine linked on a physical iPhone**

- [ ] Build an actual Aether Rust static library for an iOS device target.
- [ ] Add simulator slices / XCFramework only where proven possible and needed.
- [ ] Extract the real exported C header and test buffer ownership/threading.
- [ ] Exercise identity, endpoint discovery, and session creation in an extension or supported harness.
- [ ] Identify and exercise actual packet send/receive channels on-device.

**Phase 0 exit criteria:** known signed binary can invoke native core on iPhone; no unidentified critical C/FFI/runtime dependency; TLS handling has an approved remediation plan; realistic scope estimate recorded. If the Rust core cannot be securely embedded or its packet channel cannot be used, **NO-GO** for the planned Auto WARP backend pending upstream patch/fork/rearchitecture.

### Phase 1 — iOS VPN framework and packet-transport proof (mandatory second gate)

**E-02 / iOS shell and OS VPN session**

- [ ] Configure app and Packet Tunnel extension targets, bundle identifiers, signing, and capabilities.
- [ ] Implement permission, manager save/load/start/stop using `NETunnelProviderManager`.
- [ ] Implement `TunnelOrchestrator` state machine and accurate status propagation.
- [ ] Create minimal test UI or diagnostic controls (not the production design system).

**E-03 / IP packet bridge and on-device TCP/UDP proof**

- [ ] Bidirectional IPv4 packet pump between `NEPacketTunnelFlow` and native C backend.
- [ ] Demonstrate **TCP request/response** over the intended test tunnel.
- [ ] Demonstrate **UDP request/response** with independent remote echo verification.
- [ ] Add backpressure, queue caps, clean cancellation and packet-drop metrics.
- [ ] Configure DNS and MTU, handle failures and path changes.
- [ ] Prove no transport socket routing loop; document underlay bootstrapping.
- [ ] Run DNS/IPv6 leakage tests and document any release-impacting gaps.

**Phase 1 exit criteria:** signed VPN connects/disconnects repeatedly on a real iPhone; verified packets travel in both directions; actual TCP and UDP tests pass; DNS/routing behavior is measured; no significant leak, hang, ownership or cancellation blocker is unresolved. **A green Connect button or WireGuard/QUIC handshake alone is insufficient.**

### Phase 2 — Direct WARP product

**E-04 / Auto WARP**

- [ ] WARP identity lifecycle and secure persistence.
- [ ] Balanced scanning, data-plane verification, last-good endpoint cache.
- [ ] MASQUE H3 session, retry, reconnect and verified H2 fallback where feasible.
- [ ] UI-visible state, diagnostics, and stable error taxonomy.
- [ ] Wi-Fi/cellular/network-switch and no-leak test matrix.
- [ ] Implement **Section 14A PR-1**: basic network-state signals, bounded probes, verified H3→H2 or endpoint fallback, cooldown, and real data-plane health gating.
- [ ] Produce controlled impairment fixtures IR-01..IR-15 before any general reliability claims.

### Phase 3 — Personal Server product

**E-05 / WireGuard server and client**

- [ ] Reproducible and hardened Ubuntu WireGuard deployment.
- [ ] WireGuard profile parser, model, and Keychain secret storage.
- [ ] Integrate WireGuardKit or an audited C backend with the common packet API.
- [ ] Full-tunnel IPv4 TCP/UDP/DNS verification on real hardware.
- [ ] Reconnect, key rotation, profile deletion, and user documentation.
- [ ] Implement **Section 14A PR-2**: user-authorized personal fallback and cross-backend policy checks.

### Phase 4 — Release-quality application

**Before production UI sign-off:** demonstrate the Phase 0/1 connection proof and implement/test the approved Section 14A resilience MVP, including explicit consent for personal fallback and truthful failure states.

**E-06 / Security, QA, UX, release**

- [ ] Resolve all P0 security/FFI/routing blockers.
- [ ] CI builds, native/unit/integration tests, SBOM and dependency scanning.
- [ ] Privacy labels/policy, AGPL obligations and third-party notices.
- [ ] TestFlight validation under real networks.
- [ ] **Now finish full SwiftUI design and polish**, accessibility, English/RTL localization, crash triage, diagnostics.

### Phase 5 — Optional VPS Aether egress

**E-07 / Independent BYOS egress research**

- [ ] Establish WireGuard ingress separately from Aether.
- [ ] Engineer TCP/UDP-to-Aether channel/SOCKS policy routing.
- [ ] Solve routing loops, DNS, IPv6, authorization and resource isolation.
- [ ] Study failures, load, capacity, health checks and safe fail-closed behavior.
- [ ] Pass independent UDP/QUIC/load test and security gate.

---

## 16. Assignable implementation backlog

| Ticket | Owner | Deliverable | Definition of Done |
|---|---|---|---|
| IOS-001 | Tech lead | ADRs, pinned source/dependency versions | Reviewed and merged |
| IOS-002 | Rust/native | iOS static library build | Linked and executed on iPhone |
| IOS-003 | C/native | `tunnel_core.h` and adapter | Ownership/threading tests pass |
| IOS-004 | iOS | Packet Tunnel extension | Real system VPN start/stop |
| IOS-005 | iOS/native/network | IP packet pump | Confirmed TCP and UDP echo |
| IOS-006 | Rust/network | WARP bootstrap/discovery | Valid endpoint + data-plane proof |
| IOS-007 | iOS/native | WARP H3 driver | Real traffic exits through Cloudflare |
| IOS-008 | DevOps | Ubuntu WireGuard server | Reproducible documented deployment |
| IOS-009 | iOS | WG import + Keychain | Import/connect/delete tests |
| IOS-010 | Network | Personal WG backend | Real-device bidirectional TCP/UDP |
| IOS-011 | QA/network | Leak test harness | DNS, IPv6, no-loop reports |
| IOS-012 | Security | TLS, FFI, secrets audit | Zero unresolved P0 security issues |
| IOS-013 | Product/iOS | Production SwiftUI MVP | Usable, accessible, localizable UX |
| IOS-014 | Release | Signing, CI, privacy, licenses | TestFlight-ready candidate |
| IOS-015 | Network/server | Optional Aether egress POC | Separate decision and test report |
| IOS-016 | iOS/network | Underlay observer and signal taxonomy (14A.2, 14A.5) | Deterministic path-change and failure classification tests |
| IOS-017 | C/native + iOS | Policy evaluator, cache, budgets and cooldown (14A.6–14A.9) | No loops, no unauthorized candidate, fuzzed bounded inputs |
| IOS-018 | QA/network | Reproducible network impairment harness (IR-01..IR-16) | Device + server-side evidence and repeatable fixtures |
| IOS-019 | Rust/iOS | Verified H3/H2 and endpoint fallback orchestration | TCP + UDP + DNS pass, no false Connected states |
| IOS-020 | Security/product/iOS | Authorized Personal Server fallback policy | Profile consent, no silent exit change, fail-closed tests |
| IOS-021 | QA/product | Iran-oriented field test protocol and redacted diagnostics | Consent-based multi-network measurements with no sensitive uploads |

**Every pull request** should include change rationale, risk analysis, automated tests, on-device tests when touching network transport, memory/security review, and a rollback strategy.

### Recommended work order

```text
FIRST:   IOS-001 -> IOS-002 / IOS-003 / IOS-004 (parallel)
THEN:    IOS-005 + IOS-011 + IOS-012 (proof and security gates)
AFTER:   IOS-006 -> IOS-007 (Auto WARP) + IOS-016 -> IOS-017 / IOS-018
THEN:    IOS-019 (verified endpoint / H3-H2 fallback, after backend proof)
PARALLEL AFTER GATE: IOS-008 -> IOS-009 -> IOS-010 (Personal Server)
AFTER PERSONAL PROOF: IOS-020 (explicit opt-in fallback) + IOS-021 (field QA)
LAST:    IOS-013 + IOS-014 (complete UX/release work)
OPTIONAL: IOS-015 (separate future scope)
```

---

## 17. MVP definition of done

- [ ] Installs on a real iPhone with valid entitlements and VPN permission workflow.
- [ ] **Auto WARP:** no VPS or imported profile; at least one demonstrably functioning tunnel with verified TLS trust, TCP, UDP, and DNS.
- [ ] **Personal WireGuard:** imported profile, connection to a test VPS, correct public egress IP, verified TCP, UDP, and DNS.
- [ ] Seamless mode selection, connect/disconnect/reconnect with no crashes, unintended leaks, or orphan native processes.
- [ ] Private keys are absent from ordinary files, logs, analytics, and controllable crash reports.
- [ ] IPv6 handling is clearly documented, tested, and free from unintended exposure within the supported guarantee.
- [ ] Network transitions, sleep/wake, errors and cleanup are tested and recorded.
- [ ] UI Connected state matches real data-plane behavior.
- [ ] Section 14A verified last-good selection, bounded retries, H3/H2 transport fallback where supported, and local diagnostics pass controlled impairment tests; no user traffic switches to Personal Server without explicit authorization.
- [ ] Suspected censorship diagnoses are reported as evidence-backed possibilities, not asserted facts; scanning remains bounded and private.
- [ ] Reproducible builds, onboarding, server setup/recovery docs, and third-party notices are complete.
- [ ] Legal/product sign-off on AGPL, Cloudflare policies, and Apple's current requirements.
- [ ] No unresolved P0 security blockers; threat model signed off.

---

## 18. Assumptions, open questions, and risk register

| Topic | Current state | Mandatory action |
|---|---|---|
| Rust engine on iOS | Library interface documented; device success not established | Build/link/run SPIKE |
| Embedded packet API | Upstream discusses channel integration | Extract exact source/header and test |
| Team's C source | Not yet provided for audit | Inventory and Apple build proof |
| UDP completeness | UDP carrier does not guarantee inner UDP | Layered packet-level tests |
| TLS trust | Upstream documentation raises validation concerns | P0 audit/remediation |
| Zero-config WARP identity/API | Externally controlled service | Terms, limits, availability review |
| iOS kill-switch semantics | Depends on OS and entitlements | Do not make blanket promises |
| IPv6 containment | Requires measured platform policy | Leak tests and release gate |
| AGPL versus closed-source goals | Potential licensing constraint | Legal decision early |
| VPS Aether egress | SOCKS listener alone is insufficient | Independent POC |
| Network filtering variability in Iran | Carrier/time-specific and not reliably predictable | Section 14A consent-based field measurements and bounded fallback |
| H2 fallback inner UDP | H2 uses TCP outer transport, inner UDP support still unverified on iOS | Packet-level UDP echo and negative tests for selected implementation |
| Automated personal mode switching | Changes exit owner/network trust boundary | Separate user authorization and strict profile allowlist |
| App Store VPN eligibility | May depend on current Apple rules and distribution model | Verify before distribution |

---

## 19. Team day-one kickoff plan

1. Create the monorepo in Section 4 and record the initial architecture as an ADR.
2. Pin both upstream repositories, capture SHA/lockfiles, start dependency/license inventory.
3. On a Mac and physical iPhone, sign and start/stop the smallest possible Packet Tunnel extension.
4. In parallel, native engineers demonstrate C portability, Rust static-library build and usable packet-channel ABI on iOS.
5. The server team deploys a standard WireGuard VPS and validates its TCP/UDP behavior using the **official WireGuard iOS client** before debugging a custom client.
6. Security provides a source-based TLS trust audit and resolves P0 objections before any public connection promises.
7. The first internal demo must show evidence for **real Auto WARP** and **real Personal Server**, including UDP tests. If one backend remains blocked, report it transparently; a polished screen does not substitute for a successful network test.

### Explicit rejection criteria

Do **not** accept:

- A green Connect label when no actual IP packets can traverse the tunnel.
- Secrets embedded in source, Git, URLs, telemetry or `providerConfiguration`.
- Publicly reachable unauthenticated SOCKS5 on a VPS.
- UDP support inferred solely from QUIC/WireGuard's outer UDP carrier.
- Linux `/dev/net/tun`, external daemon, or unsupported process assumptions in an iOS extension.
- Disabled certificate verification as a workaround.
- Closed-source distribution without addressing upstream AGPL obligations.
- Starting full UI production before the Phase 0 + Phase 1 connection and TCP/UDP proofs.

---

## 20. Primary references

### Source code and protocol projects

1. [MrMatin0/Aether Android fork](https://github.com/MrMatin0/Aether) — Android architecture, VPN service, native libraries, documented chain/UDP limits.
2. [CluvexStudio/Aether](https://github.com/CluvexStudio/Aether) — upstream Rust WARP implementation.
3. [Upstream English documentation](https://github.com/CluvexStudio/Aether/blob/main/Docs/DOCS.en.md) — transport, scanner, C API, packet-channel claims, TCP/UDP, and TLS warning. Verify against pinned revision.
4. [Aether Cargo manifest](https://github.com/CluvexStudio/Aether/blob/main/aether/Cargo.toml) — library types, dependencies and license declaration.
5. [Android fork license](https://github.com/MrMatin0/Aether/blob/main/LICENSE) — AGPL licensing.
6. [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) — TUN-to-SOCKS implementation and UDP-related features; iOS portability remains a task.
7. [WireGuard for Apple platforms](https://github.com/WireGuard/wireguard-apple) — canonical iOS implementation reference.

### Apple documentation

8. [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider) — packet tunnel provider lifecycle.
9. [NEPacketTunnelFlow](https://developer.apple.com/documentation/networkextension/nepackettunnelflow) — reading/writing IP packets.
10. [NETunnelProviderManager](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager) — configuring, starting and managing tunnel sessions.
11. [Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension) — `packet-tunnel-provider` entitlement.
12. [Apple App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/) — Section 5.4 VPN requirements and related privacy policies.

**Source validity note:** the references reflect the documented upstream architecture used to prepare this specification. Repository contents and policies can change. Revalidate every source-level API, license, and platform rule against pinned versions and current requirements before implementation and release. Code labeled *example*, *skeleton*, or *proposal* is intentionally not production-ready.

---

## Appendix A — Architecture Decision Record summary

| ADR | Decision | Rationale |
|---|---|---|
| ADR-001 | One Packet Tunnel extension, multiple backends | Consistent UX and protocol separation |
| ADR-002 | Direct WARP runs on the device; no VPS | Mirrors Aether's primary client model |
| ADR-003 | Personal Server uses standard WireGuard | Interoperability, UDP and deployability |
| ADR-004 | Stable C ABI at native boundary | Reuses team's C code and Rust engine API |
| ADR-005 | Keys stored in Keychain | Minimizes secret exposure |
| ADR-006 | Unvalidated certificates are a release blocker | Auditable transport identity |
| ADR-007 | VPS Aether egress excluded from MVP | Requires separate flow/routing engineering |
| ADR-008 | Redacted diagnostics, no default packet logs | Privacy by default |
| ADR-009 | IPv6 needs a separate validation gate | Avoid false leak-prevention claims |
| ADR-010 | Phase 0 + Phase 1 precede production UI | Prove real iPhone TCP/UDP path first |
| ADR-011 | Adaptive fallback is local, bounded, evidence-driven | No false-positive connectivity or reconnect storms |
| ADR-012 | Personal exit fallback requires explicit opt-in | Prevent silent changes to network trust and exit provider |
| ADR-013 | No country-wide censorship resilience guarantee | Carrier/time-specific validation is essential |

## Appendix B — Outcomes required from the first engineering meeting

- [ ] Engineering owner assigned for every epic and P0 risk.
- [ ] Existing C source acquired; packet boundary, dependencies and ABI identified.
- [ ] Repository, build Mac, Apple signing team, physical test iPhone and test VPS available.
- [ ] Security owner assigned to TLS certificate verification and licensing review.
- [ ] Personal WG backend choice (WireGuardKit or audited C) recorded as an ADR.
- [ ] Test endpoints and success criteria for UDP, TCP, DNS, IPv6 and no-leak behavior approved.
- [ ] **Written agreement: finish Phase 0 and Phase 1 device-level connectivity proof before full UI development.**
- [ ] Assign owner for Section 14A diagnostics, H3/H2 fallback, privacy budgets, and IR-01..IR-16 controlled network fixture.
- [ ] Approve explicit user-consent policy for any fallback to a personal server, plus a kill/revert switch.
