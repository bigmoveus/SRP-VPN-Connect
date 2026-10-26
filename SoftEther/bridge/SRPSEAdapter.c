// SRPSEAdapter.c — see SRPSEAdapter.h
//
// The adapter is the entire L2 peer of the SoftEther session:
//  - outbound: IPv4 packets from the tunnel flow are wrapped in Ethernet frames
//    (dst = gateway MAC, learned via ARP) and queued for the session.
//  - inbound: Ethernet frames from the session are classified: IPv4/IPv6 ->
//    tunnel flow, ARP/NDP -> answered locally, DHCP -> embedded DHCP client.
//  - DHCPv4 client: DISCOVER/REQUEST/ACK with retransmit + T1 renew, which is
//    how SecureNAT assigns address/gateway/DNS.
//  - IPv6: Router Solicitation on connect, SLAAC from Router Advertisements
//    (prefix + RDNSS), Neighbor Solicitation answers; EUI-64 identifiers.

#include "SRPSEAdapter.h"

#include "Cedar/Connection.h"

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPV6 0x86DD

#define DHCP_STATE_INIT       0
#define DHCP_STATE_SELECTING  1
#define DHCP_STATE_REQUESTING 2
#define DHCP_STATE_BOUND      3
#define DHCP_STATE_RENEWING   4

#define ICMP6_RS  133
#define ICMP6_RA  134
#define ICMP6_NS  135
#define ICMP6_NA  136

#define DHCP_RETRANSMIT_MS   4000
#define ARP_REFRESH_MS       2000
#define DHCP_MAX_RETRIES     8

struct SRPSEAdapter
{
    SESSION *Session;
    QUEUE *ToSessionQ;          // BLOCKs: full Ethernet frames towards the session
    CANCEL *Cancel;
    LOCK *Lock;
    THREAD *DhcpThread;
    EVENT *DhcpEvent;
    volatile bool Halt;
    volatile bool Stopped;

    uint8_t Mac[6];

    // DHCP / IPv4 config (host byte order)
    int DhcpState;
    uint32_t Xid;
    uint64_t NextDhcpActionTick;
    int DhcpRetries;
    bool HasConfig;
    uint32_t Ip, Mask, Gw;
    uint32_t Dns[8];
    int DnsCount;
    uint32_t DhcpServer;
    uint32_t OfferedIp;
    uint32_t LeaseSec;
    uint64_t LeaseBoundTick;
    uint64_t RenewTick;

    uint8_t GwMac[6];
    bool GwMacKnown;
    uint64_t NextArpTick;

    // IPv6 (NDP/SLAAC) state
    uint8_t LinkLocal6[16];
    uint8_t Global6[16];
    int Prefix6Len;
    uint32_t V6LifetimeSec;
    uint64_t V6BoundTick;
    bool HasV6;
    bool V6Announced;
    uint8_t Gw6[16];            // router link-local
    uint8_t Gw6Mac[6];
    bool Gw6MacKnown;
    uint8_t Dns6[2][16];
    int Dns6Count;
    int RsRetries;
    uint64_t NextRsTick;

    void *CbCtx;
    SRPSEAdapterPacketFn PacketCb;
    SRPSEAdapterConfigFn ConfigCb;
    SRPSEAdapterConfig6Fn Config6Cb;
    SRPSEAdapterLogFn LogCb;
};

#pragma pack(push, 1)
typedef struct {
    uint8_t dst[6], src[6];
    uint16_t type;
} ETH_HDR;

typedef struct {
    uint16_t htype, ptype;
    uint8_t hlen, plen;
    uint16_t op;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
} ARP_PKT;

typedef struct {
    uint8_t op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64], file[128];
    uint32_t cookie;
    uint8_t options[312];
} DHCP_PKT;
#pragma pack(pop)

// ---- helpers ----------------------------------------------------------------

static void se_log(SRPSEAdapter *a, const char *fmt, ...)
{
    if (a->LogCb == NULL) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    a->LogCb(a->CbCtx, buf);
}

static uint16_t ip_checksum(const void *data, uint32_t len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static void ip_to_str(uint32_t ip, char *dst, uint32_t size)  // host order -> dotted
{
    snprintf(dst, size, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

static void ip6_to_str(const uint8_t *ip, char *dst, uint32_t size)
{
    snprintf(dst, size, "%x:%x:%x:%x:%x:%x:%x:%x",
             (ip[0] << 8) | ip[1], (ip[2] << 8) | ip[3], (ip[4] << 8) | ip[5], (ip[6] << 8) | ip[7],
             (ip[8] << 8) | ip[9], (ip[10] << 8) | ip[11], (ip[12] << 8) | ip[13], (ip[14] << 8) | ip[15]);
}

// ICMPv6 checksum (mandatory): pseudo-header + payload.
static uint16_t icmpv6_checksum(const uint8_t *src16, const uint8_t *dst16,
                                const uint8_t *payload, uint32_t len)
{
    uint32_t s = 0;
    for (int i = 0; i + 1 < 16; i += 2) s += (src16[i] << 8) | src16[i + 1];
    for (int i = 0; i + 1 < 16; i += 2) s += (dst16[i] << 8) | dst16[i + 1];
    s += (len >> 16) & 0xFFFF; s += len & 0xFFFF;
    s += 58;
    for (uint32_t i = 0; i + 1 < len; i += 2) s += (payload[i] << 8) | payload[i + 1];
    if (len & 1) s += payload[len - 1] << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    uint16_t c = (uint16_t)~s;
    return c == 0 ? 0xFFFF : c;
}

static bool ip6_is_multicast(const uint8_t *ip) { return ip[0] == 0xFF; }

// ff02::1 (all-nodes) and ff02::2 (all-routers)
static const uint8_t SE_IP6_ALL_NODES[16]   = {0xFF,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
static const uint8_t SE_IP6_ALL_ROUTERS[16] = {0xFF,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2};

// Solicited-node multicast for an address (ff02::1:ffXX:XXXX)
static void se_ip6_solicited_node(const uint8_t *addr, uint8_t *out)
{
    memcpy(out, SE_IP6_ALL_NODES, 16);
    out[11] = 0x01; out[12] = 0xFF;
    out[13] = addr[13]; out[14] = addr[14]; out[15] = addr[15];
}

// Multicast MAC for an IPv6 multicast address (33:33:xx:xx:xx:xx)
static void se_ip6_mcast_mac(const uint8_t *ip, uint8_t *mac)
{
    mac[0] = 0x33; mac[1] = 0x33;
    mac[2] = ip[12]; mac[3] = ip[13]; mac[4] = ip[14]; mac[5] = ip[15];
}

static uint32_t rd32(const void *p) { uint32_t v; memcpy(&v, p, 4); return ntohl(v); }
static uint16_t rd16(const void *p) { uint16_t v; memcpy(&v, p, 2); return ntohs(v); }
static void wr32(void *p, uint32_t v) { v = htonl(v); memcpy(p, &v, 4); }
static void wr16(void *p, uint16_t v) { v = htons(v); memcpy(p, &v, 2); }

// Enqueue an Ethernet frame towards the session (takes ownership of `frame`).
static void se_enqueue(SRPSEAdapter *a, void *frame, uint32_t size)
{
    LockQueue(a->ToSessionQ);
    {
        BLOCK *b = NewBlock(frame, size, 0);
        InsertQueue(a->ToSessionQ, b);
    }
    UnlockQueue(a->ToSessionQ);
    Cancel(a->Cancel);
}

// ---- DHCP -------------------------------------------------------------------

// Build a DHCP packet (DISCOVER/REQUEST) into a full Ethernet broadcast frame.
static void *se_build_dhcp(SRPSEAdapter *a, uint8_t msgType, uint32_t reqIp, uint32_t serverId, uint32_t *outSize)
{
    uint32_t udpLen = 8 + sizeof(DHCP_PKT);
    uint32_t ipLen = 20 + udpLen;
    uint32_t frameLen = sizeof(ETH_HDR) + ipLen;
    uint8_t *f = ZeroMalloc(frameLen);

    ETH_HDR *eth = (ETH_HDR *)f;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, a->Mac, 6);
    wr16(&eth->type, ETH_TYPE_IPV4);

    uint8_t *ip = f + sizeof(ETH_HDR);
    ip[0] = 0x45;
    wr16(ip + 2, (uint16_t)ipLen);
    wr16(ip + 4, (uint16_t)(Rand32() & 0xFFFF));
    wr16(ip + 6, 0);                    // flags/frag
    ip[8] = 64;                         // TTL
    ip[9] = 17;                         // UDP
    wr16(ip + 10, 0);
    // src IP: 0.0.0.0 unless we are renewing a bound lease
    wr32(ip + 12, (msgType == 3 && a->DhcpState == DHCP_STATE_RENEWING) ? a->Ip : 0);
    wr32(ip + 16, 0xFFFFFFFF);
    wr16(ip + 10, ip_checksum(ip, 20));

    uint8_t *udp = ip + 20;
    wr16(udp + 0, 68);
    wr16(udp + 2, 67);
    wr16(udp + 4, (uint16_t)udpLen);
    wr16(udp + 6, 0);                   // no UDP checksum

    DHCP_PKT *d = (DHCP_PKT *)(udp + 8);
    d->op = 1; d->htype = 1; d->hlen = 6;
    wr32(&d->xid, a->Xid);
    wr16(&d->flags, 0x8000);            // broadcast flag
    memcpy(d->chaddr, a->Mac, 6);
    wr32(&d->cookie, 0x63825363u);      // 99.130.83.99

    uint8_t *o = d->options;
    *o++ = 53; *o++ = 1; *o++ = msgType;
    *o++ = 55; *o++ = 4; *o++ = 1; *o++ = 3; *o++ = 6; *o++ = 51;   // param request list
    *o++ = 57; *o++ = 2; *o++ = 0x05; *o++ = 0xDC;                  // max msg size 1500
    const char *hn = "srpvpn-ios";
    *o++ = 12; *o++ = (uint8_t)strlen(hn); memcpy(o, hn, strlen(hn)); o += strlen(hn);
    if (msgType == 3) {                 // REQUEST
        if (reqIp) { *o++ = 50; *o++ = 4; wr32(o, reqIp); o += 4; }
        if (serverId) { *o++ = 54; *o++ = 4; wr32(o, serverId); o += 4; }
    }
    *o++ = 255;

    *outSize = frameLen;
    return f;
}

// Parse a DHCP packet from the server. Returns msg type (2=offer,5=ack,6=nak,0=invalid).
static uint8_t se_parse_dhcp(SRPSEAdapter *a, const uint8_t *p, uint32_t len)
{
    if (len < sizeof(ETH_HDR) + 20 + 8 + 240) return 0;
    const uint8_t *ip = p + sizeof(ETH_HDR);
    uint32_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || len < sizeof(ETH_HDR) + ihl + 8 + 240) return 0;
    const uint8_t *udp = ip + ihl;
    if (rd16(udp + 0) != 67 || rd16(udp + 2) != 68) return 0;

    const DHCP_PKT *d = (const DHCP_PKT *)(udp + 8);
    if (rd32(&d->cookie) != 0x63825363u) return 0;
    if (rd32(&d->xid) != a->Xid) return 0;
    if (d->op != 2) return 0;

    a->OfferedIp = rd32(&d->yiaddr);

    uint8_t msg = 0;
    uint32_t mask = 0, gw = 0, server = 0, lease = 0;
    uint32_t dns[8]; int dnsCount = 0;
    const uint8_t *o = d->options;
    const uint8_t *end = p + len;
    while (o < end && *o != 255) {
        if (*o == 0) { o++; continue; }
        if (o + 2 > end || o + 2 + o[1] > end) break;
        uint8_t code = o[0], l = o[1];
        const uint8_t *v = o + 2;
        switch (code) {
        case 53: if (l >= 1) msg = v[0]; break;
        case 54: if (l >= 4) server = rd32(v); break;
        case 51: if (l >= 4) lease = rd32(v); break;
        case 1:  if (l >= 4) mask = rd32(v); break;
        case 3:  if (l >= 4) gw = rd32(v); break;
        case 6:
            for (int i = 0; i + 4 <= l && dnsCount < 8; i += 4) dns[dnsCount++] = rd32(v + i);
            break;
        }
        o += 2 + l;
    }

    if (msg == 2 && (a->DhcpState == DHCP_STATE_SELECTING)) {
        // OFFER
        a->DhcpServer = server;
        a->DhcpState = DHCP_STATE_REQUESTING;
        a->DhcpRetries = 0;
        a->NextDhcpActionTick = 0;      // send REQUEST immediately
        char ips[32]; ip_to_str(a->OfferedIp, ips, sizeof(ips));
        se_log(a, "DHCP offer: %s", ips);
    }
    else if (msg == 5 && (a->DhcpState == DHCP_STATE_REQUESTING || a->DhcpState == DHCP_STATE_RENEWING)) {
        // ACK
        a->Ip = rd32(&d->yiaddr);
        a->Mask = mask ? mask : 0xFFFFFF00;
        a->Gw = gw;
        memcpy(a->Dns, dns, sizeof(dns));
        a->DnsCount = dnsCount;
        a->LeaseSec = lease ? lease : 3600;
        a->LeaseBoundTick = Tick64();
        a->RenewTick = a->LeaseBoundTick + (uint64_t)(a->LeaseSec / 2) * 1000;
        a->DhcpState = DHCP_STATE_BOUND;
        bool first = !a->HasConfig;
        a->HasConfig = true;
        char ips[32], ms[32], gs[32], ds[256];
        ip_to_str(a->Ip, ips, sizeof(ips));
        ip_to_str(a->Mask, ms, sizeof(ms));
        ip_to_str(a->Gw, gs, sizeof(gs));
        ds[0] = 0;
        for (int i = 0; i < a->DnsCount; i++) {
            char t[32]; ip_to_str(a->Dns[i], t, sizeof(t));
            if (i) strncat(ds, ",", sizeof(ds) - strlen(ds) - 1);
            strncat(ds, t, sizeof(ds) - strlen(ds) - 1);
        }
        se_log(a, "DHCP bound: ip=%s mask=%s gw=%s dns=%s lease=%us", ips, ms, gs, ds, a->LeaseSec);
        if (first && a->ConfigCb != NULL) {
            a->ConfigCb(a->CbCtx, ips, ms, gs, ds, a->LeaseSec);
        }
    }
    else if (msg == 6) {
        // NAK — restart
        se_log(a, "DHCP NAK — restarting discovery");
        a->HasConfig = false;
        a->DhcpState = DHCP_STATE_INIT;
        a->DhcpRetries = 0;
        a->NextDhcpActionTick = 0;
    }
    return msg;
}

static void se_arp_request(SRPSEAdapter *a, uint32_t targetIp)
{
    uint32_t frameLen = sizeof(ETH_HDR) + sizeof(ARP_PKT);
    uint8_t *f = ZeroMalloc(frameLen);
    ETH_HDR *eth = (ETH_HDR *)f;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, a->Mac, 6);
    wr16(&eth->type, ETH_TYPE_ARP);

    ARP_PKT *arp = (ARP_PKT *)(f + sizeof(ETH_HDR));
    wr16(&arp->htype, 1);
    wr16(&arp->ptype, ETH_TYPE_IPV4);
    arp->hlen = 6; arp->plen = 4;
    wr16(&arp->op, 1);
    memcpy(arp->sha, a->Mac, 6);
    wr32(&arp->spa, a->Ip);
    memset(arp->tha, 0, 6);
    wr32(&arp->tpa, targetIp);
    se_enqueue(a, f, frameLen);
}

static void se_handle_arp(SRPSEAdapter *a, const uint8_t *p, uint32_t len)
{
    if (len < sizeof(ETH_HDR) + sizeof(ARP_PKT)) return;
    const ARP_PKT *arp = (const ARP_PKT *)(p + sizeof(ETH_HDR));
    if (rd16(&arp->htype) != 1 || rd16(&arp->ptype) != ETH_TYPE_IPV4 || arp->hlen != 6 || arp->plen != 4) return;
    uint32_t spa = rd32(&arp->spa);
    uint32_t tpa = rd32(&arp->tpa);
    uint16_t op = rd16(&arp->op);

    // Learn the gateway MAC from its ARP packets
    if (a->HasConfig && spa == a->Gw && !a->GwMacKnown) {
        memcpy(a->GwMac, arp->sha, 6);
        a->GwMacKnown = true;
        se_log(a, "ARP: gateway MAC learned %02X:%02X:%02X:%02X:%02X:%02X",
               arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);
    }

    if (op == 1 && a->HasConfig && tpa == a->Ip) {
        // ARP request for us — reply
        uint32_t frameLen = sizeof(ETH_HDR) + sizeof(ARP_PKT);
        uint8_t *f = ZeroMalloc(frameLen);
        ETH_HDR *eth = (ETH_HDR *)f;
        memcpy(eth->dst, arp->sha, 6);
        memcpy(eth->src, a->Mac, 6);
        wr16(&eth->type, ETH_TYPE_ARP);
        ARP_PKT *r = (ARP_PKT *)(f + sizeof(ETH_HDR));
        wr16(&r->htype, 1);
        wr16(&r->ptype, ETH_TYPE_IPV4);
        r->hlen = 6; r->plen = 4;
        wr16(&r->op, 2);
        memcpy(r->sha, a->Mac, 6);
        wr32(&r->spa, a->Ip);
        memcpy(r->tha, arp->sha, 6);
        wr32(&r->tpa, spa);
        se_enqueue(a, f, frameLen);
    }
}


// ---- NDP (IPv6) ---------------------------------------------------------------

// Build a full Ethernet frame carrying an ICMPv6 message. dstIp may be
// multicast (MAC derived). Returns Malloc'd frame, sets *outSize.
static void *se_build_icmpv6(SRPSEAdapter *a, const uint8_t *dstIp, bool dstMcast,
                             uint8_t *icmpPayload, uint32_t icmpLen, uint32_t *outSize)
{
    uint32_t ipLen = 40 + icmpLen;
    uint32_t frameLen = sizeof(ETH_HDR) + ipLen;
    uint8_t *f = ZeroMalloc(frameLen);

    ETH_HDR *eth = (ETH_HDR *)f;
    if (dstMcast) {
        se_ip6_mcast_mac(dstIp, eth->dst);
    } else {
        memcpy(eth->dst, a->Gw6Mac, 6);
    }
    memcpy(eth->src, a->Mac, 6);
    wr16(&eth->type, ETH_TYPE_IPV6);

    uint8_t *ip = f + sizeof(ETH_HDR);
    ip[0] = 0x60;
    wr16(ip + 4, (uint16_t)icmpLen);        // payload length
    ip[6] = 58;                             // ICMPv6
    ip[7] = 255;                            // hop limit (mandatory for NDP)
    memcpy(ip + 8, a->LinkLocal6, 16);      // src
    memcpy(ip + 24, dstIp, 16);             // dst

    uint8_t *icmp = ip + 40;
    memcpy(icmp, icmpPayload, icmpLen);
    wr16(icmp + 2, icmpv6_checksum(a->LinkLocal6, dstIp, icmp, icmpLen));

    *outSize = frameLen;
    return f;
}

// Send Router Solicitation (ICMPv6 133) to ff02::2 with our SLLA.
static void se_send_rs(SRPSEAdapter *a)
{
    // full ICMPv6 message: type, code, checksum(filled by builder), reserved, options
    uint8_t pl[8 + 8];
    memset(pl, 0, sizeof(pl));
    pl[0] = ICMP6_RS;                       // type 133
    pl[1] = 0;                              // code
    pl[8] = 1; pl[9] = 1;                   // option: source link-layer address
    memcpy(pl + 10, a->Mac, 6);
    uint32_t sz;
    void *f = se_build_icmpv6(a, SE_IP6_ALL_ROUTERS, true, pl, sizeof(pl), &sz);
    se_enqueue(a, f, sz);
    se_log(a, "NDP: router solicitation sent");
}

// Answer a Neighbor Solicitation targeting one of our addresses.
static void se_send_na(SRPSEAdapter *a, const uint8_t *target,
                       const uint8_t *nsSrcIp, const uint8_t *nsSrcMac, bool solicited)
{
    bool dad = true;                        // NS from :: = DAD probe
    for (int i = 0; i < 16; i++) if (nsSrcIp[i]) { dad = false; break; }

    uint8_t pl[4 + 16 + 8];
    memset(pl, 0, 4);
    pl[0] = solicited ? 0x60 : 0x20;        // R=0 S=solicited O=1(override) -> bits: 0x40=S,0x20=O
    memcpy(pl + 4, target, 16);
    pl[20] = 2; pl[21] = 1;                 // option: target link-layer address
    memcpy(pl + 22, a->Mac, 6);

    uint8_t dstIp[16];
    uint8_t dstMac[6];
    if (dad) {
        memcpy(dstIp, SE_IP6_ALL_NODES, 16);
        se_ip6_mcast_mac(dstIp, dstMac);
    } else {
        memcpy(dstIp, nsSrcIp, 16);
        memcpy(dstMac, nsSrcMac, 6);
    }

    // build manually (src = target of the NS, not link-local)
    uint32_t icmpLen = 4 + sizeof(pl);      // type/code/cksum + flags + target + options
    uint32_t frameLen = sizeof(ETH_HDR) + 40 + icmpLen;
    uint8_t *f = ZeroMalloc(frameLen);
    ETH_HDR *eth = (ETH_HDR *)f;
    memcpy(eth->dst, dstMac, 6);
    memcpy(eth->src, a->Mac, 6);
    wr16(&eth->type, ETH_TYPE_IPV6);
    uint8_t *ip = f + sizeof(ETH_HDR);
    ip[0] = 0x60;
    wr16(ip + 4, (uint16_t)icmpLen);
    ip[6] = 58; ip[7] = 255;
    memcpy(ip + 8, target, 16);             // src = our address
    memcpy(ip + 24, dstIp, 16);
    uint8_t *icmp = ip + 40;
    icmp[0] = ICMP6_NA; icmp[1] = 0;
    memcpy(icmp + 4, pl, sizeof(pl));    // flags + target + options
    wr16(icmp + 2, 0);
    wr16(icmp + 2, icmpv6_checksum(target, dstIp, icmp, icmpLen));
    se_enqueue(a, f, frameLen);
}

// Parse a Router Advertisement: prefix (PIO), RDNSS, router = src link-local.
static void se_handle_ra(SRPSEAdapter *a, const uint8_t *frame, uint32_t len)
{
    const ETH_HDR *eth = (const ETH_HDR *)frame;
    const uint8_t *ip = frame + sizeof(ETH_HDR);
    const uint8_t *icmp = ip + 40;
    uint32_t plen = rd16(ip + 4);
    if (len < sizeof(ETH_HDR) + 40 + 12 || plen < 12) return;

    // Router = RA source (link-local); learn its MAC
    memcpy(a->Gw6, ip + 8, 16);
    memcpy(a->Gw6Mac, eth->src, 6);
    a->Gw6MacKnown = true;
    a->RsRetries = 99;                      // stop RS retries

    uint32_t routerLifetime = rd16(icmp + 6);

    // options walk (RA header = 16 bytes: type/code/cksum + curHop/flags + lifetime + reachable + retrans)
    const uint8_t *o = icmp + 16;
    const uint8_t *end = icmp + plen;
    uint8_t pfx[16]; int pfxLen = -1; uint32_t validLt = 0;
    while (o + 2 <= end && o + o[1] * 8 <= end && o[1] > 0) {
        uint8_t type = o[0], units = o[1];
        if (type == 3 && units >= 4) {      // Prefix Information
            uint8_t flags = o[3];
            if (flags & 0x40) {             // A (autonomous) — SLAAC allowed
                pfxLen = o[2];
                validLt = rd32(o + 4);
                memcpy(pfx, o + 16, 16);
            }
        }
        else if (type == 25 && units >= 3) { // RDNSS
            int n = (units * 8 - 8) / 16;
            a->Dns6Count = 0;
            for (int i = 0; i < n && i < 2; i++) {
                memcpy(a->Dns6[a->Dns6Count++], o + 8 + i * 16, 16);
            }
        }
        o += units * 8;
    }

    if (pfxLen > 0 && pfxLen <= 64 && !a->HasV6) {
        // SLAAC: prefix/64 + EUI-64 IID from our MAC
        memcpy(a->Global6, pfx, 16);
        a->Global6[8]  = a->Mac[0] ^ 0x02;
        a->Global6[9]  = a->Mac[1];
        a->Global6[10] = a->Mac[2];
        a->Global6[11] = 0xFF;
        a->Global6[12] = 0xFE;
        a->Global6[13] = a->Mac[3];
        a->Global6[14] = a->Mac[4];
        a->Global6[15] = a->Mac[5];
        a->Prefix6Len = pfxLen;
        a->V6LifetimeSec = validLt;
        a->V6BoundTick = Tick64();
        a->HasV6 = true;

        char a6[64], g6[64], d6[160];
        ip6_to_str(a->Global6, a6, sizeof(a6));
        ip6_to_str(a->Gw6, g6, sizeof(g6));
        d6[0] = 0;
        for (int i = 0; i < a->Dns6Count; i++) {
            char t[64]; ip6_to_str(a->Dns6[i], t, sizeof(t));
            if (i) strncat(d6, ",", sizeof(d6) - strlen(d6) - 1);
            strncat(d6, t, sizeof(d6) - strlen(d6) - 1);
        }
        se_log(a, "NDP: RA — prefix len=%d addr=%s gw=%s dns=%s lifetime=%us",
               pfxLen, a6, g6, d6, validLt ? validLt : routerLifetime);
        if (!a->V6Announced && a->Config6Cb != NULL) {
            a->V6Announced = true;
            a->Config6Cb(a->CbCtx, a6, pfxLen, g6, d6,
                         validLt ? validLt : routerLifetime);
        }
    }
}

// Handle inbound ICMPv6 (NDP). Returns true if consumed locally.
static bool se_handle_icmpv6(SRPSEAdapter *a, const uint8_t *frame, uint32_t len)
{
    if (len < sizeof(ETH_HDR) + 40 + 4) return false;
    const uint8_t *ip = frame + sizeof(ETH_HDR);
    uint32_t plen = rd16(ip + 4);
    if (sizeof(ETH_HDR) + 40 + plen > len) return false;
    const uint8_t *icmp = ip + 40;
    uint8_t type = icmp[0];

    if (type == ICMP6_RA && plen >= 12) {
        se_handle_ra(a, frame, len);
        return true;
    }
    if (type == ICMP6_NS && plen >= 24) {
        const uint8_t *target = icmp + 8;
        bool ours = memcmp(target, a->LinkLocal6, 16) == 0 ||
                    (a->HasV6 && memcmp(target, a->Global6, 16) == 0);
        if (ours) {
            const uint8_t *srcIp = ip + 8;
            uint8_t srcMac[6] = {0};
            // SLLA option if present
            const uint8_t *o = icmp + 24;
            const uint8_t *end = icmp + plen;
            if (o + 8 <= end && o[0] == 1 && o[1] == 1) memcpy(srcMac, o + 2, 6);
            else memcpy(srcMac, ((const ETH_HDR *)frame)->src, 6);
            se_send_na(a, target, srcIp, srcMac, true);
            se_log(a, "NDP: answered neighbor solicitation for our address");
        }
        return true;
    }
    if (type == ICMP6_NA && plen >= 24) {
        // Learn router MAC from its NA
        const uint8_t *srcIp = ip + 8;
        if (a->Gw6MacKnown == false || memcmp(srcIp, a->Gw6, 16) == 0) {
            if (a->Gw6MacKnown == false) {
                memcpy(a->Gw6, srcIp, 16);
            }
            const uint8_t *o = icmp + 24;
            if (o + 8 <= icmp + plen && o[0] == 2 && o[1] == 1) {
                memcpy(a->Gw6Mac, o + 2, 6);
            } else {
                memcpy(a->Gw6Mac, ((const ETH_HDR *)frame)->src, 6);
            }
            a->Gw6MacKnown = true;
        }
        return true;
    }
    return false;   // echo replies etc. go up to the tunnel flow
}

// ---- DHCP timer thread-------------------------------------------------------

static void se_dhcp_thread(THREAD *t, void *param)
{
    SRPSEAdapter *a = (SRPSEAdapter *)param;
    (void)t;
    while (a->Halt == false)
    {
        uint64_t now = Tick64();
        uint32_t waitMs = 1000;
        Lock(a->Lock);
        {
            if (a->NextDhcpActionTick == 0) {
                // action due now
                if (a->DhcpState == DHCP_STATE_INIT || a->DhcpState == DHCP_STATE_SELECTING) {
                    a->Xid = Rand32();
                    uint32_t sz;
                    void *f = se_build_dhcp(a, 1, 0, 0, &sz);   // DISCOVER
                    se_enqueue(a, f, sz);
                    a->DhcpState = DHCP_STATE_SELECTING;
                    a->DhcpRetries++;
                    a->NextDhcpActionTick = now + DHCP_RETRANSMIT_MS;
                    se_log(a, "DHCP discover sent (try %d)", a->DhcpRetries);
                }
                else if (a->DhcpState == DHCP_STATE_REQUESTING) {
                    uint32_t sz;
                    void *f = se_build_dhcp(a, 3, a->OfferedIp, a->DhcpServer, &sz);
                    se_enqueue(a, f, sz);
                    a->DhcpRetries++;
                    a->NextDhcpActionTick = now + DHCP_RETRANSMIT_MS;
                }
                else if (a->DhcpState == DHCP_STATE_RENEWING) {
                    uint32_t sz;
                    void *f = se_build_dhcp(a, 3, 0, 0, &sz);   // renew: ciaddr set, broadcast
                    se_enqueue(a, f, sz);
                    a->NextDhcpActionTick = now + DHCP_RETRANSMIT_MS;
                }
            }
            else if (now >= a->NextDhcpActionTick) {
                // timeout waiting for reply
                if (a->DhcpState == DHCP_STATE_SELECTING || a->DhcpState == DHCP_STATE_REQUESTING) {
                    if (a->DhcpRetries >= DHCP_MAX_RETRIES) {
                        a->DhcpState = DHCP_STATE_INIT;
                        a->DhcpRetries = 0;
                        se_log(a, "DHCP retry limit — restarting");
                    }
                    a->NextDhcpActionTick = 0;  // act next loop
                }
                else if (a->DhcpState == DHCP_STATE_RENEWING) {
                    if (now >= a->LeaseBoundTick + (uint64_t)a->LeaseSec * 1000) {
                        se_log(a, "DHCP lease expired — rebinding");
                        a->HasConfig = false;
                        a->DhcpState = DHCP_STATE_INIT;
                        a->DhcpRetries = 0;
                    }
                    a->NextDhcpActionTick = 0;
                }
            }
            if (a->DhcpState == DHCP_STATE_BOUND && now >= a->RenewTick) {
                a->DhcpState = DHCP_STATE_RENEWING;
                a->NextDhcpActionTick = 0;
            }
            // ARP for gateway once bound
            if (a->HasConfig && !a->GwMacKnown && now >= a->NextArpTick) {
                se_arp_request(a, a->Gw);
                a->NextArpTick = now + ARP_REFRESH_MS;
            }
            // IPv6: router solicitations until an RA arrives (4 tries)
            if (!a->HasV6 && a->RsRetries < 4 && now >= a->NextRsTick) {
                se_send_rs(a);
                a->RsRetries++;
                a->NextRsTick = now + (uint64_t)(4 << a->RsRetries) * 1000;
            }
            // compute next wait
            now = Tick64();
            uint64_t next = now + 1000;
            if (a->NextDhcpActionTick == 0) next = now;
            else if (a->NextDhcpActionTick < next) next = a->NextDhcpActionTick;
            if (a->NextArpTick && a->NextArpTick < next) next = a->NextArpTick;
            waitMs = (next > now) ? (uint32_t)(next - now) : 0;
        }
        Unlock(a->Lock);
        if (a->Halt) break;
        Wait(a->DhcpEvent, waitMs);
    }
}

// ---- PACKET_ADAPTER contract --------------------------------------------------

static bool se_pa_init(SESSION *s)
{
    SRPSEAdapter *a = (SRPSEAdapter *)s->PacketAdapter->Param;
    a->Session = s;
    return true;
}

static CANCEL *se_pa_get_cancel(SESSION *s)
{
    SRPSEAdapter *a = (SRPSEAdapter *)s->PacketAdapter->Param;
    AddRef(a->Cancel->ref);
    return a->Cancel;
}

static UINT se_pa_get_next_packet(SESSION *s, void **data)
{
    SRPSEAdapter *a = (SRPSEAdapter *)s->PacketAdapter->Param;
    UINT size = 0;
    LockQueue(a->ToSessionQ);
    {
        BLOCK *b = GetNext(a->ToSessionQ);
        if (b != NULL)
        {
            *data = b->Buf;
            size = b->Size;
            Free(b);
        }
    }
    UnlockQueue(a->ToSessionQ);
    return size;
}

static bool se_pa_put_packet(SESSION *s, void *data, UINT size)
{
    SRPSEAdapter *a = (SRPSEAdapter *)s->PacketAdapter->Param;
    if (data == NULL) return true;
    if (size < sizeof(ETH_HDR)) { Free(data); return true; }

    uint8_t *p = (uint8_t *)data;
    uint16_t type = rd16(&((ETH_HDR *)p)->type);

    switch (type)
    {
    case ETH_TYPE_IPV4:
    {
        const uint8_t *ip = p + sizeof(ETH_HDR);
        uint32_t iplen = size - sizeof(ETH_HDR);
        if (iplen >= 20) {
            // Trim Ethernet padding using the IP total length
            uint32_t iplenReal = rd16(ip + 2);
            if (iplenReal >= 20 && iplenReal < iplen) iplen = iplenReal;
            // Learn gateway MAC from inbound frames
            if (a->HasConfig && !a->GwMacKnown && rd32(ip + 12) == a->Gw) {
                memcpy(a->GwMac, ((ETH_HDR *)p)->src, 6);
                a->GwMacKnown = true;
                se_log(a, "Gateway MAC learned from inbound IP frame");
            }
            if (ip[9] == 17) {  // UDP — DHCP reply?
                uint32_t ihl = (ip[0] & 0x0F) * 4;
                if (iplen >= ihl + 8 && rd16(ip + ihl + 0) == 67 && rd16(ip + ihl + 2) == 68) {
                    Lock(a->Lock);
                    se_parse_dhcp(a, p, size);
                    Unlock(a->Lock);
                    Free(data);
                    return true;
                }
            }
            if (a->PacketCb != NULL) {
                a->PacketCb(a->CbCtx, ip, iplen, 4);
            }
        }
        break;
    }
    case ETH_TYPE_IPV6:
    {
        const uint8_t *ip = p + sizeof(ETH_HDR);
        uint32_t ip6len = size - sizeof(ETH_HDR);
        if (ip6len >= 40 && (ip[0] >> 4) == 6) {
            uint32_t realLen = 40 + rd16(ip + 4);    // payload length
            if (realLen < ip6len) ip6len = realLen;
            {   static int v6dbg; if (v6dbg < 20) { v6dbg++;
                const ETH_HDR *e6 = (const ETH_HDR *)p;
                se_log(a, "v6 rx: len=%u nexthdr=%u srcmac=%02X:%02X:%02X:%02X:%02X:%02X icmptype=%u",
                       ip6len, ip[6], e6->src[0], e6->src[1], e6->src[2], e6->src[3], e6->src[4], e6->src[5],
                       ip[6] == 58 && ip6len > 40 ? ip[40] : 0);
            } }
            Lock(a->Lock);
            bool consumed = (ip[6] == 58) ? se_handle_icmpv6(a, p, sizeof(ETH_HDR) + ip6len) : false;
            Unlock(a->Lock);
            if (!consumed && a->PacketCb != NULL) {
                a->PacketCb(a->CbCtx, ip, ip6len, 6);
            }
        }
        break;
    }
    case ETH_TYPE_ARP:
        Lock(a->Lock);
        se_handle_arp(a, p, size);
        Unlock(a->Lock);
        break;
    default:
        break;
    }

    Free(data);
    return true;
}

static void se_pa_free(SESSION *s)
{
    SRPSEAdapter *a = (SRPSEAdapter *)s->PacketAdapter->Param;
    (void)a;
}

// ---- public API ---------------------------------------------------------------

SRPSEAdapter *SRPSEAdapterCreate(void *ctx, SRPSEAdapterPacketFn packetFn,
                                 SRPSEAdapterConfigFn configFn,
                                 SRPSEAdapterConfig6Fn config6Fn,
                                 SRPSEAdapterLogFn logFn)
{
    SRPSEAdapter *a = ZeroMalloc(sizeof(SRPSEAdapter));
    a->ToSessionQ = NewQueue();
    a->Cancel = NewCancel();
    a->Lock = NewLock();
    a->DhcpEvent = NewEvent();
    a->CbCtx = ctx;
    a->PacketCb = packetFn;
    a->ConfigCb = configFn;
    a->Config6Cb = config6Fn;
    a->LogCb = logFn;
    a->DhcpState = DHCP_STATE_INIT;
    a->Xid = Rand32();

    // Locally administered MAC: 02:53:52 ("SR") + random
    a->Mac[0] = 0x02; a->Mac[1] = 0x53; a->Mac[2] = 0x52;
    a->Mac[3] = Rand32() & 0xFF; a->Mac[4] = Rand32() & 0xFF; a->Mac[5] = Rand32() & 0xFF;

    // IPv6 link-local (EUI-64 from MAC)
    a->LinkLocal6[0] = 0xFE; a->LinkLocal6[1] = 0x80;
    a->LinkLocal6[8]  = a->Mac[0] ^ 0x02;
    a->LinkLocal6[9]  = a->Mac[1];
    a->LinkLocal6[10] = a->Mac[2];
    a->LinkLocal6[11] = 0xFF;
    a->LinkLocal6[12] = 0xFE;
    a->LinkLocal6[13] = a->Mac[3];
    a->LinkLocal6[14] = a->Mac[4];
    a->LinkLocal6[15] = a->Mac[5];

    a->DhcpThread = NewThread(se_dhcp_thread, a);
    return a;
}

PACKET_ADAPTER *SRPSEAdapterGetPacketAdapter(SRPSEAdapter *a)
{
    PACKET_ADAPTER *pa = NewPacketAdapter(se_pa_init, se_pa_get_cancel,
                                          se_pa_get_next_packet, se_pa_put_packet, se_pa_free);
    pa->Param = a;
    return pa;
}

void SRPSEAdapterInjectPacket(SRPSEAdapter *a, const uint8_t *pkt, uint32_t len, int family)
{
    if (a == NULL || a->Stopped || len < 20 || len > 1600) return;
    int version = pkt[0] >> 4;
    if (version != family || (family != 4 && family != 6)) return;

    Lock(a->Lock);
    const uint8_t *dstMac;
    uint16_t ethType;
    if (family == 4) {
        if (!a->HasConfig) { Unlock(a->Lock); return; }   // drop until DHCP bound
        if (!a->GwMacKnown) {
            se_arp_request(a, a->Gw);
            Unlock(a->Lock);
            return;                                        // drop; TCP/UDP will retransmit
        }
        dstMac = a->GwMac;
        ethType = ETH_TYPE_IPV4;
    } else {
        if (!a->HasV6) { Unlock(a->Lock); return; }       // drop until RA/SLAAC
        const uint8_t *dst6 = pkt + 24;
        static uint8_t mcastMac[6];
        if (ip6_is_multicast(dst6)) {
            se_ip6_mcast_mac(dst6, mcastMac);
            dstMac = mcastMac;
        } else {
            if (!a->Gw6MacKnown) {
                // router MAC unknown yet — nudge with an RS and drop
                if (a->RsRetries >= 4) { a->RsRetries = 0; a->NextRsTick = 0; }
                Unlock(a->Lock);
                return;
            }
            dstMac = a->Gw6Mac;
        }
        ethType = ETH_TYPE_IPV6;
    }

    uint32_t frameLen = sizeof(ETH_HDR) + len;
    uint8_t *f = Malloc(frameLen);
    ETH_HDR *eth = (ETH_HDR *)f;
    memcpy(eth->dst, dstMac, 6);
    memcpy(eth->src, a->Mac, 6);
    wr16(&eth->type, ethType);
    memcpy(f + sizeof(ETH_HDR), pkt, len);
    Unlock(a->Lock);

    {   // Ethernet minimum payload padding (60 bytes total, without FCS)
        uint32_t padded = frameLen;
        if (padded < 60) padded = 60;
        if (padded != frameLen) {
            uint8_t *nf = Malloc(padded);
            memcpy(nf, f, frameLen);
            memset(nf + frameLen, 0, padded - frameLen);
            Free(f);
            f = nf;
            frameLen = padded;
        }
    }
    {   static int dbgN; if (dbgN < 10) { dbgN++;
        char sip[32], dip[32];
        ip_to_str(rd32(pkt + 12), sip, sizeof(sip));
        ip_to_str(rd32(pkt + 16), dip, sizeof(dip));
        se_log(a, "inject: %s -> %s proto=%u iplen=%u framelen=%u", sip, dip, pkt[9], len, frameLen);
    } }
    se_enqueue(a, f, frameLen);
}

void SRPSEAdapterStop(SRPSEAdapter *a)
{
    if (a == NULL || a->Stopped) return;
    a->Stopped = true;
    a->Halt = true;
    Set(a->DhcpEvent);
    Cancel(a->Cancel);
}

void SRPSEAdapterFree(SRPSEAdapter *a)
{
    if (a == NULL) return;
    SRPSEAdapterStop(a);
    WaitThread(a->DhcpThread, INFINITE);
    ReleaseThread(a->DhcpThread);
    BLOCK *b;
    LockQueue(a->ToSessionQ);
    while ((b = GetNext(a->ToSessionQ)) != NULL) FreeBlock(b);
    UnlockQueue(a->ToSessionQ);
    ReleaseQueue(a->ToSessionQ);
    ReleaseCancel(a->Cancel);
    DeleteLock(a->Lock);
    ReleaseEvent(a->DhcpEvent);
    Free(a);
}

bool SRPSEAdapterHasConfig(SRPSEAdapter *a)
{
    return a != NULL && a->HasConfig;
}

bool SRPSEAdapterHasV6Config(SRPSEAdapter *a)
{
    return a != NULL && a->HasV6;
}
