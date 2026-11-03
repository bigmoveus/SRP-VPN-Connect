// SRPSEAdapter.h — Layer-2/Layer-3 adapter between the SoftEther session
// (Ethernet frames) and an L3 IP packet flow (NEPacketTunnelFlow on iOS).
//
// Implements the SoftEther PACKET_ADAPTER contract (full Ethernet frames),
// plus: ARP responder/resolver, minimal DHCPv4 client (SecureNAT), and IPv6
// support: NDP (RS/RA/NS/NA) + SLAAC address configuration.
#ifndef SRP_SE_ADAPTER_H
#define SRP_SE_ADAPTER_H

#include <stdint.h>
#include <stdbool.h>

#include "Cedar/Cedar.h"
#include "Cedar/Session.h"

typedef struct SRPSEAdapter SRPSEAdapter;

// Deliver an IP packet (no Ethernet header) up to the tunnel flow.
// family: 4 (IPv4) or 6 (IPv6).
typedef void (*SRPSEAdapterPacketFn)(void *ctx, const uint8_t *pkt, uint32_t len, int family);

// IPv4 configuration acquired via DHCP. All strings are dotted-quad; dnsCsv is
// a comma-separated list (may be empty). leaseSec is the DHCP lease time.
typedef void (*SRPSEAdapterConfigFn)(void *ctx, const char *ip, const char *mask,
                                     const char *gw, const char *dnsCsv, uint32_t leaseSec);

// IPv6 configuration acquired via RA/SLAAC. addr6 is the full global address,
// gw6 the router's link-local address, dns6Csv comma-separated (may be empty).
typedef void (*SRPSEAdapterConfig6Fn)(void *ctx, const char *addr6, int prefixLen,
                                      const char *gw6, const char *dns6Csv, uint32_t lifetimeSec);

// Log line callback (may be NULL).
typedef void (*SRPSEAdapterLogFn)(void *ctx, const char *line);

SRPSEAdapter *SRPSEAdapterCreate(void *ctx, SRPSEAdapterPacketFn packetFn,
                                 SRPSEAdapterConfigFn configFn,
                                 SRPSEAdapterConfig6Fn config6Fn,
                                 SRPSEAdapterLogFn logFn);

// Packet adapter to hand to NewClientSessionEx. Owned by the adapter.
PACKET_ADAPTER *SRPSEAdapterGetPacketAdapter(SRPSEAdapter *a);

// Inject an IP packet coming from the tunnel flow (TUN -> VPN). family: 4|6.
void SRPSEAdapterInjectPacket(SRPSEAdapter *a, const uint8_t *pkt, uint32_t len, int family);

// Stop DHCP/NDP thread and wake the session. Idempotent.
void SRPSEAdapterStop(SRPSEAdapter *a);

// Free (after the session has been released).
void SRPSEAdapterFree(SRPSEAdapter *a);

// Current config state.
bool SRPSEAdapterHasConfig(SRPSEAdapter *a);
bool SRPSEAdapterHasV6Config(SRPSEAdapter *a);

#endif
