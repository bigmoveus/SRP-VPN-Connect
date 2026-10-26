// SRPSEClient.c — see SRPSEClient.h

#include "SRPSEClient.h"
#include "SRPFragBio.h"
#include "SRPSEAdapter.h"

#include "Cedar/Cedar.h"
#include "Cedar/Client.h"
#include "Cedar/Connection.h"
#include "Cedar/Protocol.h"
#include "Cedar/Session.h"
#include "Cedar/Account.h"

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Tick64.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

struct SRPSEClient
{
    SRPSEClientConfig Cfg;
    SRPSEAdapter *Adapter;
    PACKET_ADAPTER *PA;
    CEDAR *Cedar;
    SESSION *Session;             // owned ref (AddRef) until Stop
    ACCOUNT Account;              // minimal account object (session stores a pointer)
    LOCK *StatusLock;
    bool Started;
    bool Stopped;
    int LastReportedStatus;
    THREAD *MonitorThread;
    EVENT *MonitorEvent;
    volatile bool MonitorHalt;

    void *CbCtx;
    SRPSEClientPacketFn PacketFn;
    SRPSEClientConfigFn ConfigFn;
    SRPSEClientConfig6Fn Config6Fn;
    SRPSEClientStateFn StateFn;
    SRPSEClientLogFn LogFn;
};

// ---- global init ---------------------------------------------------------------

static bool g_inited = false;

int SRPSEGlobalInit(const char *writableDir, bool debugLog)
{
    // Single-threaded entry on both harness and extension; Mayaqua locks cannot
    // be used here because the kernel is not initialized yet.
    if (!g_inited)
    {
        MayaquaMinimalMode();   // no hamcore.se2 requirement

        // argv[0] must resolve to an existing file (GetExeDir derives from it)
        static char fake[1024];
        snprintf(fake, sizeof(fake), "%s/secore", writableDir);
        {   // plain POSIX — FileIO is not safe before InitMayaqua
            int fd = open(fake, O_CREAT | O_WRONLY, 0644);
            if (fd >= 0) close(fd);
        }
        char *argv[1];
        argv[0] = fake;

        InitMayaqua(false, debugLog, 1, argv);
        InitCedar();
        g_inited = true;
    }
    return 0;
}

// ---- trust hook ------------------------------------------------------------------

static void *g_trustCtx = NULL;
static SRPSETrustFn g_trustFn = NULL;

void SRPSESetTrustHook(void *ctx, SRPSETrustFn fn)
{
    g_trustCtx = ctx;
    g_trustFn = fn;
}

// Called from patched Cedar/Protocol.c right after the TLS handshake.
// TLS write splitting: configured per session start; the Network.c patch
// calls SRPSEFragWrap right after SSL_set_fd on client sockets.
static uint32_t g_fragFirst, g_fragFollowing, g_fragGapMs;

BIO *SRPSEFragWrap(BIO *raw)
{
    if (g_fragFirst == 0 || raw == NULL)
        return NULL;
    BIO *f = srp_frag_bio_new(g_fragFirst, g_fragFollowing, g_fragGapMs);
    if (f == NULL)
        return NULL;
    return BIO_push(f, raw);
}

UINT SRPSETrustCheck(CONNECTION *c)
{
    if (g_trustFn == NULL) return ERR_NO_ERROR;
    if (c == NULL || c->FirstSock == NULL || c->FirstSock->ssl == NULL) return ERR_CERT_NOT_TRUSTED;

    SSL *ssl = (SSL *)c->FirstSock->ssl;
    const char *hostname = c->ServerName;
    if (c->Session != NULL && c->Session->ClientOption != NULL &&
        StrLen(c->Session->ClientOption->SniOverride) != 0)
    {
        hostname = c->Session->ClientOption->SniOverride;
    }

    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    if (chain == NULL || sk_X509_num(chain) <= 0) return ERR_CERT_NOT_TRUSTED;

    int count = sk_X509_num(chain);
    const uint8_t *ders[32];
    size_t lens[32];
    uint8_t *bufs[32];
    if (count > 32) count = 32;
    for (int i = 0; i < count; i++)
    {
        X509 *x = sk_X509_value(chain, i);
        int n = i2d_X509(x, NULL);
        if (n <= 0 || n > 65536) { for (int j = 0; j < i; j++) free(bufs[j]); return ERR_CERT_NOT_TRUSTED; }
        bufs[i] = malloc(n);
        uint8_t *p = bufs[i];
        i2d_X509(x, &p);
        ders[i] = bufs[i];
        lens[i] = (size_t)n;
    }
    uint32_t r = g_trustFn(g_trustCtx, ders, lens, count, hostname);
    for (int i = 0; i < count; i++) free(bufs[i]);
    return r;
}

// ---- status monitor ---------------------------------------------------------------

static void se_status_thread(THREAD *t, void *param)
{
    SRPSEClient *c = (SRPSEClient *)param;
    (void)t;
    printf("[se] monitor thread started\n");
    while (!c->MonitorHalt)
    {
        int st = -1; uint32_t err = 0;
        SRPSEClientGetStatus(c, &st, &err);
        if (st != c->LastReportedStatus)
        {
            c->LastReportedStatus = st;
            if (c->StateFn) c->StateFn(c->CbCtx, st, err);
        }
        if (st == 5 /* CLIENT_STATUS_IDLE */) break;   // session thread ended
        Wait(c->MonitorEvent, 200);
    }
    if (!c->MonitorHalt)
    {
        int st = -1; uint32_t err = 0;
        SRPSEClientGetStatus(c, &st, &err);
        if (c->StateFn) c->StateFn(c->CbCtx, 5, err);   // final: ended with error code
    }
}

// ---- callbacks from adapter --------------------------------------------------------

static void se_client_packet_cb(void *ctx, const uint8_t *pkt, uint32_t len, int family)
{
    SRPSEClient *c = (SRPSEClient *)ctx;
    if (c->PacketFn) c->PacketFn(c->CbCtx, pkt, len, family);
}

static void se_client_config6_cb(void *ctx, const char *addr6, int prefixLen,
                                 const char *gw6, const char *dns6Csv, uint32_t lifetimeSec)
{
    SRPSEClient *c = (SRPSEClient *)ctx;
    if (c->Config6Fn) c->Config6Fn(c->CbCtx, addr6, prefixLen, gw6, dns6Csv, lifetimeSec);
}

static void se_client_config_cb(void *ctx, const char *ip, const char *mask,
                                const char *gw, const char *dnsCsv, uint32_t leaseSec)
{
    SRPSEClient *c = (SRPSEClient *)ctx;
    if (c->ConfigFn) c->ConfigFn(c->CbCtx, ip, mask, gw, dnsCsv, leaseSec);
}

static void se_client_log_cb(void *ctx, const char *line)
{
    SRPSEClient *c = (SRPSEClient *)ctx;
    if (c->LogFn) c->LogFn(c->CbCtx, line);
}

// ---- lifecycle -----------------------------------------------------------------------

SRPSEClient *SRPSEClientCreate(const SRPSEClientConfig *cfg, void *ctx,
                               SRPSEClientPacketFn packetFn, SRPSEClientConfigFn configFn,
                               SRPSEClientConfig6Fn config6Fn,
                               SRPSEClientStateFn stateFn, SRPSEClientLogFn logFn)
{
    if (cfg == NULL || !g_inited) return NULL;
    SRPSEClient *c = ZeroMalloc(sizeof(SRPSEClient));
    memcpy(&c->Cfg, cfg, sizeof(SRPSEClientConfig));
    c->CbCtx = ctx;
    c->PacketFn = packetFn;
    c->ConfigFn = configFn;
    c->Config6Fn = config6Fn;
    c->StateFn = stateFn;
    c->LogFn = logFn;
    c->StatusLock = NewLock();
    c->LastReportedStatus = -1;
    return c;
}

int SRPSEClientStart(SRPSEClient *c)
{
    // TLS write splitting config for this session (read by SRPSEFragWrap)
    g_fragFirst = c->Cfg.tlsFragFirst;
    g_fragFollowing = c->Cfg.tlsFragFollowing;
    g_fragGapMs = c->Cfg.tlsFragGapMs;
    if (c == NULL || c->Started) return -1;

    c->Adapter = SRPSEAdapterCreate(c, se_client_packet_cb, se_client_config_cb,
                                    se_client_config6_cb, se_client_log_cb);
    c->PA = SRPSEAdapterGetPacketAdapter(c->Adapter);

    c->Cedar = NewCedar(NULL, NULL);

    CLIENT_OPTION o;
    Zero(&o, sizeof(o));
    StrCpy(o.Hostname, sizeof(o.Hostname), c->Cfg.hostname);
    o.Port = c->Cfg.port;
    StrCpy(o.HubName, sizeof(o.HubName), c->Cfg.hub);
    UniStrCpy(o.AccountName, sizeof(o.AccountName), L"SRP VPN Connect");
    o.MaxConnection = MAKESURE(c->Cfg.maxConnections, 1, 32);
    o.UseEncrypt = true;
    o.UseCompress = c->Cfg.useCompress;
    o.HalfConnection = false;
    o.NoRoutingTracking = false;
    o.NumRetry = 0;                       // reconnect is owned by the outer layer
    o.RetryInterval = c->Cfg.retryIntervalSec ? c->Cfg.retryIntervalSec : 5;
    o.AdditionalConnectionInterval = 1;
    o.PortUDP = 0;
    StrCpy(o.DeviceName, sizeof(o.DeviceName), "vpn");   // non-empty: use our PA, not virtual-host mode
    // UDP acceleration and NAT-T are independent switches
    o.NoUdpAcceleration = !c->Cfg.udpAcceleration;
    StrCpy(o.HintStr, sizeof(o.HintStr), c->Cfg.natTHint);
    StrCpy(o.SniOverride, sizeof(o.SniOverride), c->Cfg.sniOverride);

    o.ProxyType = (UINT)c->Cfg.proxyType;
    if (c->Cfg.proxyType != SRPSEProxyNone)
    {
        StrCpy(o.ProxyName, sizeof(o.ProxyName), c->Cfg.proxyHost);
        o.ProxyPort = c->Cfg.proxyPort;
        StrCpy(o.ProxyUsername, sizeof(o.ProxyUsername), c->Cfg.proxyUsername);
        StrCpy(o.ProxyPassword, sizeof(o.ProxyPassword), c->Cfg.proxyPassword);
    }

    CLIENT_AUTH a;
    Zero(&a, sizeof(a));
    a.AuthType = (UINT)c->Cfg.authType;
    StrCpy(a.Username, sizeof(a.Username), c->Cfg.username);

    X *certX = NULL;
    K *certK = NULL;
    switch (c->Cfg.authType)
    {
    case SRPSEAuthPassword:
        HashPassword(a.HashedPassword, a.Username, c->Cfg.password);
        break;
    case SRPSEAuthPlainPassword:
        StrCpy(a.PlainPassword, sizeof(a.PlainPassword), c->Cfg.password);
        break;
    case SRPSEAuthCertificate:
    {
        if (c->Cfg.p12 == NULL || c->Cfg.p12Len == 0) return -2;
        BIO *bio = BIO_new_mem_buf(c->Cfg.p12, (int)c->Cfg.p12Len);
        PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
        BIO_free(bio);
        if (p12 == NULL) return -2;
        EVP_PKEY *pkey = NULL;
        X509 *x509 = NULL;
        if (PKCS12_parse(p12, c->Cfg.p12Passphrase, &pkey, &x509, NULL) != 1 || x509 == NULL || pkey == NULL)
        {
            PKCS12_free(p12);
            return -2;
        }
        PKCS12_free(p12);
        certX = X509ToX(x509);
        // Export key to PKCS#8 DER and load as K
        BUF *kb = NewBuf();
        {
            BIO *kbio = BIO_new(BIO_s_mem());
            if (i2d_PKCS8PrivateKey_bio(kbio, pkey, NULL, NULL, 0, NULL, NULL) == 1)
            {
                char *kdata = NULL;
                long klen = BIO_get_mem_data(kbio, &kdata);
                if (klen > 0 && kdata != NULL) WriteBuf(kb, kdata, (UINT)klen);
            }
            BIO_free(kbio);
        }
        EVP_PKEY_free(pkey);
        // NB: ownership of x509 moved into certX (X509ToX stores the pointer)
        certK = BufToK(kb, true, false, NULL);
        FreeBuf(kb);
        if (certX == NULL || certK == NULL)
        {
            if (certX) FreeX(certX);
            if (certK) FreeK(certK);
            return -2;
        }
        printf("[se] cert parsed: bits=%u compatible=%u\n", certX->bits, certX->is_compatible_bit);
        a.ClientX = certX;
        a.ClientK = certK;
        break;
    }
    default:
        break;
    }

    Zero(&c->Account, sizeof(c->Account));
    c->Account.CheckServerCert = false;     // verification is done by our trust hook
    c->Account.ClientOption = NULL;
    c->Account.ClientAuth = NULL;

    SESSION *s = NewClientSessionEx(c->Cedar, &o, &a, c->PA, &c->Account);

    if (certX) FreeX(certX);
    if (certK) FreeK(certK);

    if (s == NULL) return -3;

    // Keep our own reference so status can be read after the session thread exits
    AddRef(s->ref);
    c->Session = s;
    c->Account.ClientSession = s;
    c->Started = true;

    c->MonitorEvent = NewEvent();
    c->MonitorHalt = false;
    c->MonitorThread = NewThread(se_status_thread, c);
    return 0;
}

void SRPSEClientInjectPacket(SRPSEClient *c, const uint8_t *pkt, uint32_t len, int family)
{
    if (c == NULL || c->Adapter == NULL || c->Stopped) return;
    SRPSEAdapterInjectPacket(c->Adapter, pkt, len, family);
}

void SRPSEClientGetStatus(SRPSEClient *c, int *clientStatus, uint32_t *err)
{
    if (clientStatus) *clientStatus = -1;
    if (err) *err = 0;
    if (c == NULL || c->Session == NULL) return;
    SESSION *s = c->Session;
    Lock(s->lock);
    {
        if (clientStatus) *clientStatus = (int)s->ClientStatus;
        if (err) *err = s->Err;
    }
    Unlock(s->lock);
}

void SRPSEClientStop(SRPSEClient *c)
{
    if (c == NULL || c->Stopped) return;
    c->Stopped = true;

    if (c->MonitorThread != NULL)
    {
        c->MonitorHalt = true;
        Set(c->MonitorEvent);
        WaitThread(c->MonitorThread, INFINITE);
        ReleaseThread(c->MonitorThread);
        c->MonitorThread = NULL;
    }
    if (c->MonitorEvent != NULL)
    {
        ReleaseEvent(c->MonitorEvent);
        c->MonitorEvent = NULL;
    }
    if (c->Session != NULL)
    {
        StopSession(c->Session);
        SRPSEAdapterStop(c->Adapter);
        ReleaseSession(c->Session);   // our ref
        c->Session = NULL;
    }
}

void SRPSEClientFree(SRPSEClient *c)
{
    if (c == NULL) return;
    SRPSEClientStop(c);
    if (c->Adapter != NULL)
    {
        SRPSEAdapterFree(c->Adapter);
        c->Adapter = NULL;
    }
    if (c->Cedar != NULL)
    {
        ReleaseCedar(c->Cedar);
        c->Cedar = NULL;
    }
    DeleteLock(c->StatusLock);
    Free(c);
}

const char *SRPSEErrorName(uint32_t err)
{
    switch (err)
    {
    case 0: return "no error";
    case 1: return "connect failed";
    case 2: return "server is not a VPN server";
    case 3: return "disconnected";
    case 4: return "protocol error";
    case 5: return "client is not a VPN client";
    case 6: return "user cancel";
    case 7: return "auth type not supported";
    case 8: return "hub not found";
    case 9: return "authentication failed";
    case 10: return "hub stopping";
    case 11: return "session removed";
    case 12: return "access denied";
    case 13: return "session timeout";
    case 14: return "invalid protocol";
    case 15: return "too many connections";
    case 16: return "hub is busy";
    case 17: return "proxy connect failed";
    case 18: return "proxy error";
    case 19: return "proxy auth failed";
    case 20: return "too many user sessions";
    case 33: return "hub not found (online hubs only)";
    case 85: return "certificate not trusted";
    case 106: return "server certificate expired";
    case 149: return "certificate hostname mismatch";
    default: return "unknown";
    }
}
