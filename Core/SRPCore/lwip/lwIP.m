
#import "lwIP.h"

#ifndef SSTP_PPPD_DEBUG
#define SSTP_PPPD_DEBUG 0
#endif
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <lwip/stats.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <netdb.h>
#import <NetworkExtension/NetworkExtension.h>
#include "x_lwip.h"
#include "x_utils.h"
#import "UDPHandler.h"
#import "TCPHandler.h"
#import "SSTCPClient.h"
#import "NWRunLoop.h"
#import "SSData.h"
#import "SSBuffer.h"
#import "SSSSTPClient.h"
#import "SSLog.h"
#import "SSNetOptions.h"
#include "netif/ppp/pppos.h"
#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/eap-ttls.h"
#include "lwip/dns.h"

static long long __m_timeout_ms__;
static const char *__WorkQueueKey__ = "com.x.worker.queue";
static int8_t __memory__[2048];

@interface lwIP ()<UDPHandlerDelegate, TCPHandlerDelegate, SSSSTPClientDelegate>

/// SSTP client; this is what implements the Microsoft SSTP protocol
@property (nonatomic, strong, readonly)SSSSTPClient *sstpClient;

/// Write data to the tunnel
/// - Parameters:
///   - packet: IP packet
///   - family: IP protocol version
-(void)WriteOut:(NSData *)packet family:(int)family;

/// Set up the network interface
/// - Parameters:
///   - interface: interface IP
///   - mask: subnet mask
///   - remote: server-assigned remote IP
///   - dns: server-assigned DNS
-(void)SetupNetworkInterface:(NSString *)interface mask:(NSString *)mask remote:(NSString *)remote dns:(NSArray <NSString *> *)dns;
@end

@implementation lwIP {
    dispatch_source_t _timer;
    lwIPOutputCallback _mOutputCallback;
    lwSetupNetworkSettingsCallback _mSettingCallback;
    lwFailureCallback _mFailureCallback;
    
    NSMutableDictionary <NSString *, UDPHandler *>*__m_udp_map__;
    NSMutableDictionary <NSString *, TCPHandler *>*__m_tcp_map__;
    
    struct tcp_pcb *__tcp_stack__;
    struct udp_pcb *__udp_stack__;
    
    ppp_pcb *__ppp__;
    struct netif __pppos_netif__;
    
    SSTPPPPState _pppState;
    BOOL _closedManually;
    BOOL _authFailed;
    NSData *_eapTlsCertPem;	/* EAP-TLS client credentials, retained for the session */
    NSData *_eapTlsKeyPem;

    // OPTIONS section state
    BOOL _autoReconnect;          // default YES
    NSInteger _maxRetries;        // 0 = unlimited
    NSInteger _failedAttempts;    // consecutive failed (re)connect attempts
    BOOL _switchToWifi;           // default YES
    NSInteger _onSleep;           // 0=off 1=pause 2=stay
    nw_path_monitor_t _pathMonitor;
    BOOL _lastPathHadWifi;
    BOOL _sleepPaused;            // client closed due to sleep (pause mode)
    BOOL _pathSwitchInProgress;   // deliberate close for a path migration
    NSString *_serverHost;        // SSTP server host/IP — excluded from tunnel routes
}

static void netif_ppp_print_function(const char *buf) {
    NSLog(@"[Y] PPP => %s", buf);   // level-gated upstream in ppp_log_write
}

static err_t netif_output_callback(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    if (p->tot_len == p->len) {
        // Avoid an extra memory copy
        NSData *ipPacket = [[NSData alloc] initWithBytesNoCopy:p->payload length:p->tot_len freeWhenDone:NO];
        [[lwIP shared] WriteOut:ipPacket family:AF_INET];
    }
    else {
        if (p->tot_len <= 2048) {
            pbuf_copy_partial(p, __memory__, p->tot_len, 0);
            NSData *ipPacket = [[NSData alloc] initWithBytesNoCopy:__memory__ length:p->tot_len freeWhenDone:NO];
            [[lwIP shared] WriteOut:ipPacket family:AF_INET];
        }
        else {
            NSMutableData *ipPacket = [NSMutableData dataWithLength:p->tot_len];
            pbuf_copy_partial(p, ipPacket.mutableBytes, p->tot_len, 0);
            [[lwIP shared] WriteOut:ipPacket family:AF_INET];
        }
    }
    return ERR_OK;
}

static err_t netif_output_ip6_callback(struct netif *netif, struct pbuf *p,
                                       const ip6_addr_t *ipaddr) {
    if (p->tot_len == p->len) {
        // Avoid an extra memory copy
        NSData *ipPacket = [[NSData alloc] initWithBytesNoCopy:p->payload length:p->tot_len freeWhenDone:NO];
        [[lwIP shared] WriteOut:ipPacket family:AF_INET6];
    }
    else {
        if (p->tot_len <= 2048) {
            pbuf_copy_partial(p, __memory__, p->tot_len, 0);
            NSData *ipPacket = [[NSData alloc] initWithBytesNoCopy:__memory__ length:p->tot_len freeWhenDone:NO];
            [[lwIP shared] WriteOut:ipPacket family:AF_INET6];
        }
        else {
            NSMutableData *ipPacket = [NSMutableData dataWithLength:p->tot_len];
            pbuf_copy_partial(p, ipPacket.mutableBytes, p->tot_len, 0);
            [[lwIP shared] WriteOut:ipPacket family:AF_INET6];
        }
    }
    return ERR_OK;
}

static void netif_ppp_link_status_cb_fn(ppp_pcb *pcb, int err_code, void *ctx) {
    struct netif *pppif = ppp_netif(pcb);
    switch(err_code) {
      case PPPERR_NONE:               /* No error. */
          {
  #if LWIP_DNS
          const ip_addr_t *ns;
  #endif /* LWIP_DNS */
          fprintf(stderr, "ppp_link_status_cb: PPPERR_NONE\n\r");
  #if LWIP_IPV4
          fprintf(stderr, "   our_ip4addr = %s\n\r", ip4addr_ntoa(netif_ip4_addr(pppif)));
          fprintf(stderr, "   his_ipaddr  = %s\n\r", ip4addr_ntoa(netif_ip4_gw(pppif)));
          fprintf(stderr, "   netmask     = %s\n\r", ip4addr_ntoa(netif_ip4_netmask(pppif)));
  #endif /* LWIP_IPV4 */
  #if LWIP_IPV6
          fprintf(stderr, "   our_ip6addr = %s\n\r", ip6addr_ntoa(netif_ip6_addr(pppif, 0)));
  #endif /* LWIP_IPV6 */

  #if LWIP_DNS
          ns = dns_getserver(0);
          fprintf(stderr, "   dns1        = %s\n\r", ipaddr_ntoa(ns));
          ns = dns_getserver(1);
          fprintf(stderr, "   dns2        = %s\n\r", ipaddr_ntoa(ns));
  #endif /* LWIP_DNS */
  #if PPP_IPV6_SUPPORT
          fprintf(stderr, "   our6_ipaddr = %s\n\r", ip6addr_ntoa(netif_ip6_addr(pppif, 0)));
  #endif /* PPP_IPV6_SUPPORT */
          }
          break;

      case PPPERR_PARAM:             /* Invalid parameter. */
          SSLogM(@"ppp_link_status_cb: PPPERR_PARAM\n");
          break;

      case PPPERR_OPEN:              /* Unable to open PPP session. */
          SSLogM(@"ppp_link_status_cb: PPPERR_OPEN\n");
          break;

      case PPPERR_DEVICE:            /* Invalid I/O device for PPP. */
          SSLogM(@"ppp_link_status_cb: PPPERR_DEVICE\n");
          break;

      case PPPERR_ALLOC:             /* Unable to allocate resources. */
          SSLogM(@"ppp_link_status_cb: PPPERR_ALLOC\n");
          break;

      case PPPERR_USER:              /* User interrupt. */
          SSLogM(@"ppp_link_status_cb: PPPERR_USER\n");
          break;

      case PPPERR_CONNECT:           /* Connection lost. */
          SSLogM(@"ppp_link_status_cb: PPPERR_CONNECT\n");
          break;

      case PPPERR_AUTHFAIL:          /* Failed authentication challenge. */
          SSLogM(@"ppp_link_status_cb: PPPERR_AUTHFAIL\n");
          break;

      case PPPERR_PROTOCOL:          /* Failed to meet protocol. */
          SSLogM(@"ppp_link_status_cb: PPPERR_PROTOCOL\n");
          break;

      case PPPERR_PEERDEAD:          /* Connection timeout. */
          SSLogM(@"ppp_link_status_cb: PPPERR_PEERDEAD\n");
          break;

      case PPPERR_IDLETIMEOUT:       /* Idle Timeout. */
          SSLogM(@"ppp_link_status_cb: PPPERR_IDLETIMEOUT\n");
          break;

      case PPPERR_CONNECTTIME:       /* PPPERR_CONNECTTIME. */
          SSLogM(@"ppp_link_status_cb: PPPERR_CONNECTTIME\n");
          break;

      case PPPERR_LOOPBACK:          /* Connection timeout. */
          SSLogM(@"ppp_link_status_cb: PPPERR_LOOPBACK\n");
          break;

      default:
          SSLogM(@"ppp_link_status_cb: unknown errCode %d\n", err_code);
          break;
      }

    // Surface negotiation failures to the UI (only before the link is up,
    // and never after a user-initiated close). Auth failure must not
    // trigger the auto-reconnect loop.
    lwIP *ip = [lwIP shared];
    NSString *reason = nil;
    switch (err_code) {
        case PPPERR_AUTHFAIL:
            ip->_authFailed = YES;
            reason = @"Authentication failed. The server rejected the username or password.";
            break;
        case PPPERR_CONNECT:
            reason = @"Connection lost during PPP negotiation.";
            break;
        case PPPERR_PEERDEAD:
            reason = @"Server stopped responding.";
            break;
        default:
            break;
    }
    if (reason != nil && ip->_pppState != SSTPPPPState_ESTABLISHED && !ip->_closedManually && ip->_mFailureCallback) {
        ip->_mFailureCallback(reason);
    }
}

static void netif_ppp_notify_phase_cb_fn(ppp_pcb *pcb, u8_t phase, void *ctx) {
    switch (phase) {
        case PPP_PHASE_DEAD:
            SSLogI(@"phase: DEAD");
            break;
        case PPP_PHASE_MASTER:
            SSLogI(@"phase: MASTER");
            break;
        case PPP_PHASE_HOLDOFF:
            SSLogI(@"phase: HOLDOFF");
            break;
        case PPP_PHASE_INITIALIZE:
            SSLogI(@"phase: INITIALIZE");
            break;
        case PPP_PHASE_SERIALCONN:
            SSLogI(@"phase: SERIALCONN");
            break;
        case PPP_PHASE_DORMANT:
            SSLogI(@"phase: DORMANT");
            break;
        case PPP_PHASE_ESTABLISH:
            SSLogI(@"phase: ESTABLISH");
            break;
        case PPP_PHASE_AUTHENTICATE:
            SSLogI(@"phase: AUTHENTICATE");
            break;
        case PPP_PHASE_CALLBACK:
            SSLogI(@"phase: CALLBACK");
            break;
        case PPP_PHASE_NETWORK: {
            SSLogI(@"phase: NETWORK");
            /* Tunneled EAP (PEAP/TTLS/TEAP): the engine derived the MPPE
             * session keys; feed them to the SSTP Call Connected crypto
             * binding before the first IPCP frame triggers it. */
#if EAP_SUPPORT
            if (pcb->settings.eap_mppe_keys_ok && lwIP.shared.sstpClient) {
                NSData *skey = [NSData dataWithBytes:pcb->settings.eap_mppe_send_key length:32];
                NSData *rkey = [NSData dataWithBytes:pcb->settings.eap_mppe_recv_key length:32];
                [lwIP.shared.sstpClient setMppeKeys:skey recv:rkey];
            }
#endif
            break;
        }
        case PPP_PHASE_RUNNING: {
            SSLogI(@"phase: RUNNING");
            ip4_addr_t addr;
            ppp_pcb *ppp = lwIP.shared->__ppp__;
            struct ipcp_options *wo = &ppp->ipcp_wantoptions;
            char our_ip[32] = {0};
            addr.addr = wo->ouraddr;
            ip4addr_ntoa_r((const ip4_addr_t *)&addr, our_ip, 32);
            
            ipcp_options *ho = &ppp->ipcp_hisoptions;
            char his_ip[32] = {0};
            addr.addr = ho->hisaddr;
            ip4addr_ntoa_r((const ip4_addr_t *)&addr, his_ip, 32);
            
            struct ipcp_options *go = &ppp->ipcp_gotoptions;
            NSString *primary_dns = @"1.1.1.1";
            NSString *second_dns = @"";
            if (go->dnsaddr[0] != 0) {
                ip4_addr_t dns_addr;
                dns_addr.addr = go->dnsaddr[0];
                char dns_ip[32] = {0};
                ip4addr_ntoa_r(&dns_addr, dns_ip, 32);
                primary_dns = [NSString stringWithUTF8String:dns_ip];
            }
            if (go->dnsaddr[1] != 0) {
                ip4_addr_t dns_addr;
                dns_addr.addr = go->dnsaddr[1];
                char dns_ip[32] = {0};
                ip4addr_ntoa_r(&dns_addr, dns_ip, 32);
                second_dns = [NSString stringWithUTF8String:dns_ip];
            }
            NSMutableArray *dns = [NSMutableArray new];
            if (primary_dns.length > 0) {
                [dns addObject:primary_dns];
            }
            if (second_dns.length > 0) {
                [dns addObject:second_dns];
            }
            NSString *remote = @"1.0.0.1";
            if (ho->hisaddr != 0) {
                remote = [NSString stringWithUTF8String:his_ip];
            }
            [lwIP.shared SetupNetworkInterface:[NSString stringWithUTF8String:our_ip] mask:[NSString stringWithUTF8String:"255.255.255.0"] remote:remote dns:dns];
        }
            break;
        case PPP_PHASE_TERMINATE:
            SSLogI(@"phase: TERMINATE");
            break;
        default:
            SSLogI(@"phase: DISCONNECT");
            break;
    }
}

static u32_t netif_pppos_output_cb_fn(ppp_pcb *pcb, u8_t *data, u32_t len, void *ctx) {
#if SSTP_PPPD_DEBUG
    {
        char hex[256]; int o = 0;
        for (u32_t i = 0; i < len && i < 80; i++) o += snprintf(hex + o, sizeof(hex) - o, "%02x", data[i]);
        SSLogI(@"pppos_output_cb: %u bytes: %s", (unsigned)len, hex);
    }
#endif
    [lwIP.shared.sstpClient sendMessage:data length:len];
    return len;
}

+(instancetype)shared {
    static lwIP *__lwip__ = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        __lwip__ = [[self alloc] init];
        [__lwip__ configure];
    });
    return __lwip__;
}

-(void)setup:(SSProtocol *)protocol {
    dispatch_async(self.worker, ^{
        [self setupInQueue:protocol];
    });
}

-(void)setupInQueue:(SSProtocol *)protocol{
    [[NWRunLoop currentRunLoop] setup:protocol];
    if ([protocol isKindOfClass:SSSstp.class]) {
        SSSstp *sstp = (SSSstp *)protocol;
        // OPTIONS section
        SSLogSetLevel((SSLogLevel)sstp.logLevel);
        _autoReconnect = sstp.autoReconnect;
        _maxRetries = sstp.retryTimes;
        _failedAttempts = 0;
        _switchToWifi = sstp.switchToWifi;
        _onSleep = sstp.onSleep;
        _sleepPaused = NO;
        [self startPathMonitor];
        _closedManually = NO;
        _authFailed = NO;
        _serverHost = sstp.host;
        _sstpClient = [[SSSSTPClient alloc] initWithTarget:protocol.host port:protocol.port proto:(SSProtocolTypeTCP) family:AF_INET];
        _sstpClient.delegate = self;
        _sstpClient.tag = @"sstp client";
        [_sstpClient connect];
    }
    else {
        if (__ppp__) {
            ppp_close(__ppp__, 0);
            ppp_free(__ppp__);
            __ppp__ = NULL;
        }
        [_sstpClient close];
        _sstpClient = nil;
    }
}

#pragma mark - Switch to Wi-Fi when available

-(void)startPathMonitor {
    [self stopPathMonitor];
    if (!_switchToWifi) {
        return;
    }
    _lastPathHadWifi = NO;
    _pathMonitor = nw_path_monitor_create();
    __weak lwIP *weakSelf = self;
    nw_path_monitor_set_queue(_pathMonitor, self.worker);
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
        lwIP *strongSelf = weakSelf;
        if (!strongSelf) return;
        BOOL satisfied = nw_path_get_status(path) == nw_path_status_satisfied;
        BOOL hasWifi = satisfied && nw_path_uses_interface_type(path, nw_interface_type_wifi);
        BOOL hadWifi = strongSelf->_lastPathHadWifi;
        strongSelf->_lastPathHadWifi = hasWifi;
        if (SSShouldReconnectForPathChange(hadWifi, hasWifi, satisfied,
                                           strongSelf->_pppState == SSTPPPPState_ESTABLISHED)) {
            SSLogM(@"Wi-Fi became available; switching the SSTP connection to the new path");
            [strongSelf reconnectForPathSwitch];
        }
    });
    nw_path_monitor_start(_pathMonitor);
}

-(void)stopPathMonitor {
    if (_pathMonitor != nil) {
        nw_path_monitor_cancel(_pathMonitor);
        _pathMonitor = nil;
    }
}

/// Migrate the established tunnel to the new network path: tear down the
/// current transport and immediately reconnect. This is a migration, not a
/// failure — it is not governed by Auto Reconnect.
-(void)reconnectForPathSwitch {
    if (_pathSwitchInProgress || _closedManually || _sleepPaused) {
        return;
    }
    _pathSwitchInProgress = YES;
    _failedAttempts = 0;
    if (__ppp__) {
        netif_remove(&__pppos_netif__);
        ppp_close(__ppp__, 0);
        ppp_free(__ppp__);
        __ppp__ = NULL;
    }
    _pppState = SSTPPPPState_CLOSE;
    _sstpClient.delegate = nil;   // deliberate close: suppress the drop path
    [_sstpClient close];
    _sstpClient = nil;
    [self reconnect];
    _pathSwitchInProgress = NO;
}

#pragma mark - On Sleep

/// close the SSTP client on sleep; pause reconnects on wake, off drops the
/// connection (reconnect on wake only with Auto Reconnect)
-(void)pauseForSleep {
    if (_onSleep == 2 || _closedManually) {
        return;   // stay: keep the connection up
    }
    SSLogM(@"device sleep: %@ the SSTP connection", _onSleep == 1 ? @"pausing" : @"closing");
    _sleepPaused = YES;
    if (__ppp__) {
        netif_remove(&__pppos_netif__);
        ppp_close(__ppp__, 0);
        ppp_free(__ppp__);
        __ppp__ = NULL;
    }
    _pppState = SSTPPPPState_CLOSE;
    _sstpClient.delegate = nil;
    [_sstpClient close];
    _sstpClient = nil;
}

-(void)wakeFromSleep {
    if (!_sleepPaused || _closedManually) {
        return;
    }
    _sleepPaused = NO;
    if (_onSleep == 1 || _autoReconnect) {
        // pause always reconnects; off only with Auto Reconnect
        _failedAttempts = 0;
        SSLogM(@"device wake: reconnecting the SSTP connection");
        [self reconnect];
    }
}

-(void)SetupNetworkInterface:(NSString *)interface mask:(NSString *)mask remote:(NSString *)remote dns:(NSArray <NSString *> *)dns{
    _mSettingCallback([self createNetworkSetting:interface mask:mask remote:remote dns:dns]);
}

+(void)setup:(NSString *)geoip {
    [NWRunLoop setup:geoip];
}

-(void)configure {
    lwip_init();
    
    netif_list->mtu = 1500;
    netif_list->output = netif_output_callback;
    netif_list->output_ip6 = netif_output_ip6_callback;
    
    struct tcp_pcb *t_pcb = tcp_new();
    tcp_bind(t_pcb, &ip_addr_any, 0);
    t_pcb = tcp_listen_with_backlog(t_pcb, TCP_DEFAULT_LISTEN_BACKLOG);
    tcp_accept(t_pcb, netif_tcp_accept_callback);
    
    struct udp_pcb *u_pcb = udp_new();
    udp_bind(u_pcb, &ip_addr_any, 0);
    udp_recv(u_pcb, netif_udp_receive_callback, NULL);
    
    ppp_set_print_func(netif_ppp_print_function);
    
    _worker = dispatch_queue_create_with_target("com.x.tcp.ip.queue",
                                                DISPATCH_QUEUE_SERIAL,
                                                dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));
    dispatch_queue_set_specific(_worker, __WorkQueueKey__, &__WorkQueueKey__, NULL);
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _worker);
    

    sys_restart_timeouts();
    dispatch_time_t start = dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC);
    
    // Timer interval
    dispatch_source_set_timer(_timer, start, 200 * NSEC_PER_MSEC, 0);
    dispatch_source_set_event_handler(_timer, ^{
        sys_check_timeouts();
        long long now = x_system_time_mills();
        if (now - __m_timeout_ms__ >= 10000) {
            __m_timeout_ms__ = now;
            [self checkTimeout];
        }
    });
    // Start the timer
    dispatch_resume(_timer);
    
    __tcp_stack__ = t_pcb;
    __udp_stack__ = u_pcb;
    
    __m_udp_map__ = [NSMutableDictionary new];
    __m_tcp_map__ = [NSMutableDictionary new];
    
    [NWRunLoop currentRunLoop].worker = _worker;
}

+(BOOL)InQueue {
    return [lwIP.shared InQueue];
}

-(BOOL)InQueue {
#if DEBUG
    return dispatch_get_specific(__WorkQueueKey__) == (&__WorkQueueKey__);
#else
    return true;
#endif
}

#if LWIP_STATS
void
x_stats_display_mem(struct stats_mem *mem, const char *name)
{
    SSLogI(@"MEM %s, avail: %ld, used: %ld, max: %ld, err: %d", name, mem->avail, mem->used, mem->max, mem->err);
}

void
x_stats_display_memp(struct stats_mem *mem, int idx)
{
  if (idx < MEMP_MAX) {
    x_stats_display_mem(mem, mem->name);
  }
}
#endif

-(void)checkTimeout {
    NSMutableArray *allUDPKeys = @[].mutableCopy;
    
    [__m_udp_map__ enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, UDPHandler * _Nonnull handler, BOOL * _Nonnull stop) {
        if (x_system_time_mills() - handler.activeTime >= 30000) {
            [handler close:YES];
            [allUDPKeys addObject:key];
        }
    }];
    [__m_udp_map__ removeObjectsForKeys:allUDPKeys];
    
    NSMutableArray *allTCPKeys = @[].mutableCopy;
    [__m_tcp_map__ enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, TCPHandler * _Nonnull handler, BOOL * _Nonnull stop) {
        BOOL timeout = [handler checkTimeout];
        if (timeout) {
            [handler close];
            [allTCPKeys addObject:handler];
        }
    }];
    [__m_tcp_map__ removeObjectsForKeys:allTCPKeys];
    SSLogI(@"TCPHandler: %lld, UDPHandler: %lld, TCPClient: %lld, SSBuffer.flow: %lld, SSData.refCount: %lld, SSData.flow: %lld", TCPHandler.refCount, UDPHandler.refCount, SSTCPClient.refCount, SSBuffer.flow, SSData.refCount, SSData.flow);
    
#if LWIP_STATS
    struct stats_mem *mem = &lwip_stats.mem;
    x_stats_display_mem(mem, "HEAP");
    for (int i = 0; i < MEMP_MAX; i++) {
        x_stats_display_memp(lwip_stats.memp[i], i);
    }
#endif
}

-(void)SetlwSetupNetworkSettingsCallback:(lwSetupNetworkSettingsCallback)callback {
    _mSettingCallback = callback;
}

-(void)SetlwFailureCallback:(lwFailureCallback)callback {
    _mFailureCallback = callback;
}

-(void)SetlwIPOutputCallback:(lwIPOutputCallback)callback {
    _mOutputCallback = callback;
}

-(void)WriteOut:(NSData *)packet family:(int)family{
    if (_mOutputCallback == nil) {
        return;
    }
    _mOutputCallback(packet, family);
}

+(NSArray *)GetDNS {
    return @[@"8.8.4.4", @"8.8.8.8", @"1.1.1.1", @"1.0.0.1"];
}

+ (NSArray<NSString *> *)GetSystemDNS {
    NSMutableArray *dnsList = [NSMutableArray array];
    res_state x = malloc(sizeof(struct __res_state));
    if (res_ninit(x) == 0) {
        for (int i = 0; i < x->nscount; i++) {
            NSString *s = [NSString stringWithUTF8String:inet_ntoa(x->nsaddr_list[i].sin_addr)];
            [dnsList addObject:s];
        }
    }
    res_nclose(x);
    res_ndestroy(x);
    free(x);
    return dnsList;
}


- (NEPacketTunnelNetworkSettings *)createNetworkSetting:(NSString *)ip mask:(NSString *)mask remote:(NSString *)remote dns:(NSArray <NSString *> *)dns{
    NEPacketTunnelNetworkSettings *networkSettings = [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:remote];
    SSLogI(@"createNetworkSetting DNS: %@, IP: %@, MASK: %@", dns, ip, mask);
    networkSettings.DNSSettings = [[NEDNSSettings alloc] initWithServers:dns];
    // PPP MRU is typically 1500 — larger frames are dropped by the server
    networkSettings.MTU = @(1400);
    
    // This creates a virtual IP address; routes must be added separately
    NEIPv4Settings *ipv4Settings = [[NEIPv4Settings alloc] initWithAddresses:@[ip] subnetMasks:@[mask]];
    ipv4Settings.includedRoutes = @[[NEIPv4Route defaultRoute]];
    // The VPN server itself must stay on the physical path — otherwise the
    // tunnel's own TLS transport gets routed into the utun and blackholed.
    NSString *serverIP = _serverHost;
    struct in_addr sa;
    if (serverIP && inet_pton(AF_INET, serverIP.UTF8String, &sa) != 1) {
        struct hostent *he = gethostbyname(serverIP.UTF8String);
        if (he && he->h_length == 4) {
            char buf[INET_ADDRSTRLEN];
            serverIP = inet_ntop(AF_INET, he->h_addr_list[0], buf, sizeof(buf)) ? @(buf) : nil;
        } else {
            serverIP = nil;
        }
    }
    if (serverIP) {
        ipv4Settings.excludedRoutes = @[[[NEIPv4Route alloc] initWithDestinationAddress:serverIP
                                                                             subnetMask:@"255.255.255.255"]];
    } else {
        ipv4Settings.excludedRoutes = @[];
    }
    networkSettings.IPv4Settings = ipv4Settings;
    return networkSettings;
}

-(void)WriteIPPacket:(NSData *)packet family:(int)family {
    dispatch_async(self.worker, ^{
        int ret = [self WriteIPPacketInQueue:packet family:family];
        if (ret != 0) {
            SSLogI(@"WriteIPPacketInQueue: %d", ret);
        }
    });
}

-(int)WriteIPPacketInQueue:(NSData *)packet family:(int)family {
    if (packet.length <= 2) {
        return -1;
    }
    uint8_t *pkt = (uint8_t *)packet.bytes;
    u16_t length = (u16_t)packet.length;
#if SSTP_PPPD_DEBUG
    SSLogI(@"WriteIPPacketInQueue: len=%d pppState=%d sstpClient=%@", (int)length, (int)_pppState, _sstpClient ? @"set" : @"nil");
#endif
    
    x_ipver ipv = x_ip_version(pkt);
    if (ipv != x_ipv4 && ipv != x_ipv6) {
        return -2;
    }
    x_proto next_proto = x_tcp_stack_version(ipv, pkt, length);
    if (next_proto == x_proto_unknown) return -3;
    
    struct pbuf *buf = NULL;
    if (next_proto == x_proto_udp && !(x_more_fragments(ipv, pkt) || x_fragment_offset(ipv, pkt) > 0)) {
        buf = pbuf_alloc_reference(pkt, length, PBUF_REF);
    }
    else {
        buf = pbuf_alloc(PBUF_RAW, length, PBUF_POOL);
        pbuf_take(buf, pkt, length);
    }
    
    if (_sstpClient) {
        err_t err = ERR_OK;
        if (_pppState == SSTPPPPState_ESTABLISHED) {
            if (ipv == x_ipv4) {
                struct ip_hdr *ip = (struct ip_hdr *)pkt;
                ip4_addr_t ipaddr;
                ipaddr.addr = ip->dest.addr;
                err = __pppos_netif__.output(&__pppos_netif__, buf, &ipaddr);
            }
            else {
                struct ip6_hdr *ip = (struct ip6_hdr *)pkt;
                ip6_addr_t addr;
                addr.addr[0] = ip->ip6_dst.__u6_addr.__u6_addr32[0];
                addr.addr[1] = ip->ip6_dst.__u6_addr.__u6_addr32[1];
                addr.addr[2] = ip->ip6_dst.__u6_addr.__u6_addr32[2];
                addr.addr[3] = ip->ip6_dst.__u6_addr.__u6_addr32[3];
                err = __pppos_netif__.output_ip6(&__pppos_netif__, buf, &addr);
            }
        }
        pbuf_free(buf);
        if (err != ERR_OK) {
            return -6;
        }
        return 0;
    }
    err_t err = netif_list->input(buf, netif_list);
    if (err != ERR_OK) {
        pbuf_free(buf);
        return -5;
    }
    return 0;
}


-(TCPHandler *)GetTCPHander:(void *)argument newpcb:(struct tcp_pcb *)newpcb {
    char src_ip[32] = {0};
    char dst_ip[32] = {0};
    
    ip_addr_t local_addr = newpcb->remote_ip;
    ip_addr_t dest_addr = newpcb->local_ip;
    
    u16_t local_port = newpcb->remote_port;
    u16_t dest_port = newpcb->local_port;
    
    ip4addr_ntoa_r((const ip4_addr_t *)&local_addr, src_ip, 32);
    ip4addr_ntoa_r((const ip4_addr_t *)&dest_addr, dst_ip, 32);
    
    NSString *identifier = [NSString stringWithFormat:@"%s:%d->%s:%d", src_ip, local_port, dst_ip, dest_port];
    TCPHandler *handler = __m_tcp_map__[identifier];
    if (!handler) {
        handler = [[TCPHandler alloc] initWithPCB:newpcb identifier:identifier];
        handler.delegate = self;
        __m_tcp_map__[identifier] = handler;
    }
    return handler;
}

-(void)handler:(TCPHandler *)handler onTcpStateDidChanged:(TCPState)state {
    if (state >= TCPStateClosing) {
        [handler close];
        [__m_tcp_map__ removeObjectForKey:handler.identifier];
    }
}

-(void)handler:(UDPHandler *)handler onUdpStateDidChanged:(UDPState)state {
    if (state == UDPStateDisconnected) {
        [handler close:NO];
        [__m_udp_map__ removeObjectForKey:handler.identifier];
    }
}

-(UDPHandler *)GetUDPHandler:(void *)argument pcb:(struct udp_pcb *)pcb addr:(const ip_addr_t *)addr port:(u16_t)port dest_addr:(const ip_addr_t *)dest_addr dest_port:(u16_t)dest_port {
    
    char src_ip[64] = {0};
    char dst_ip[64] = {0};
    
    ip4addr_ntoa_r((const ip4_addr_t *)addr, src_ip, 64);
    ip4addr_ntoa_r((const ip4_addr_t *)dest_addr, dst_ip, 64);
    
    NSString *identifier = [NSString stringWithFormat:@"%s:%d->%s:%d", src_ip, port, dst_ip, dest_port];
    UDPHandler *handler = __m_udp_map__[identifier];
    if (!handler) {
        handler = [[UDPHandler alloc] initWithArgument:argument pcb:pcb addr:addr port:port dest_addr:dest_addr dest_port:dest_port identifier:identifier];
        handler.delegate = self;
        __m_udp_map__[identifier] = handler;
    }
    return handler;
}

#pragma mark pppd
- (void)tcpClient:(SSTCPClient *)client didChangeState:(SSClientState)state {
    if (state == SSClientStateDisconnected) {
        BOOL wasEstablished = (_pppState == SSTPPPPState_ESTABLISHED);
        _pppState = SSTPPPPState_CLOSE;
        if (__ppp__ == NULL) {
            if (!wasEstablished && !_closedManually && !_pathSwitchInProgress) {
                // Never established: with a retry limit, retry up to
                // retryTimes before giving up; otherwise fail immediately
                // (historic behavior). Auto Reconnect off = fail at once.
                if (_autoReconnect && _maxRetries > 0 && SSReconnectAttemptAllowed(_failedAttempts, _maxRetries)) {
                    _failedAttempts++;
                    SSLogM(@"connect failed; retry %ld of %ld in 2s",
                           (long)_failedAttempts, (long)_maxRetries);
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), self.worker, ^{
                        [self reconnect];
                    });
                    return;
                }
                if (_mFailureCallback) {
                    // Proxy failures carry their own reason (detection /
                    // negotiation / PAC); keep them distinct from TLS errors
                    NSString *reason = client.connectionError.length > 0
                        ? client.connectionError
                        : _failedAttempts > 0
                            ? [NSString stringWithFormat:@"Cannot reach the server after %ld attempts. Check the host, port and certificate settings.", (long)(_failedAttempts + 1)]
                            : @"Cannot reach the server (DNS/TCP/TLS failed). Check the host, port and certificate settings.";
                    _mFailureCallback(reason);
                }
            }
            return;
        }
        netif_remove(&__pppos_netif__);
        ppp_close(__ppp__, 0);
        ppp_free(__ppp__);
        __ppp__ = NULL;
        if (_closedManually || _pathSwitchInProgress || _sleepPaused) {
            return;
        }
        if (_authFailed) {
            // Authentication failure: do not retry, the user must fix credentials
            SSLogM(@"skipping reconnect after authentication failure");
            return;
        }
        if (!_autoReconnect) {
            // Auto Reconnect off: surface the drop instead of reconnecting
            if (_mFailureCallback) {
                _mFailureCallback(@"Connection lost (auto reconnect is off).");
            }
            return;
        }
        if (!SSReconnectAttemptAllowed(_failedAttempts + 1, _maxRetries)) {
            if (_mFailureCallback) {
                _mFailureCallback([NSString stringWithFormat:
                    @"Could not reconnect after %ld attempts. Giving up.", (long)_maxRetries]);
            }
            return;
        }
        _failedAttempts++;
        if (_maxRetries > 0) {
            SSLogM(@"connection dropped; retry %ld of %ld in 2s",
                   (long)_failedAttempts, (long)_maxRetries);
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), self.worker, ^{
            [self reconnect];
        });
    }
}

-(void)reconnect {
    SSProtocol *protocol = NWRunLoop.currentRunLoop.protocol;
    _sstpClient = [[SSSSTPClient alloc] initWithTarget:protocol.host port:protocol.port proto:(SSProtocolTypeTCP) family:AF_INET];
    _sstpClient.delegate = self;
    _sstpClient.tag = @"sstp client";
    [_sstpClient connect];
}

- (void)tcpClient:(SSTCPClient *)client didReceiveMessage:(uint8_t *)pkt length:(int)length {
    pppos_input(__ppp__, pkt, length);
}

-(void)tcpClient:(SSTCPClient *)client didReceiveIPPacket:(uint8_t *)packet length:(int)length {
    NSData *ipPacket = [[NSData alloc] initWithBytesNoCopy:packet length:length freeWhenDone:NO];
    [[lwIP shared] WriteOut:ipPacket family:AF_INET];
}

- (void)tcpClient:(SSTCPClient *)client didChangeSSTPState:(SSTPPPPState)state {
    if (state == SSTPPPPState_OPEN) {
        SSSstp *sstp = (SSSstp *)NWRunLoop.currentRunLoop.protocol;
        __ppp__ = pppos_create(&__pppos_netif__, netif_pppos_output_cb_fn, netif_ppp_link_status_cb_fn, NULL);
        ppp_set_notify_phase_callback(__ppp__, netif_ppp_notify_phase_cb_fn);
        uint8_t at = 0;
        if (sstp.PAP_ENABLE) {
            at |= PPPAUTHTYPE_PAP;
        }
        if (sstp.CHAP_ENABLE) {
            at |= PPPAUTHTYPE_CHAP;
        }
        if (sstp.MS_CHAP_ENABLE) {
            at |= PPPAUTHTYPE_MSCHAP;
        }
        if (sstp.MS2_CHAP_ENABLE) {
            at |= PPPAUTHTYPE_MSCHAP_V2;
        }
        if (sstp.eapMschapv2Enabled || sstp.peapEnabled || sstp.ttlsEnabled || sstp.teapEnabled ||
            sstp.eapTlsCertPem.length > 0) {
            at |= PPPAUTHTYPE_EAP;
        }
        // Safe auth logging — never log credentials
        SSLogI(@"PPP auth: PAP %@, CHAP %@, MSCHAPv1 %@, MSCHAPv2 %@, EAP-MSCHAPv2 %@, PEAP %@, TTLS %@, TEAP %@",
              sstp.PAP_ENABLE ? @"enabled" : @"disabled",
              sstp.CHAP_ENABLE ? @"enabled" : @"disabled",
              sstp.MS_CHAP_ENABLE ? @"enabled" : @"disabled",
              sstp.MS2_CHAP_ENABLE ? @"enabled" : @"disabled",
              sstp.eapMschapv2Enabled ? @"enabled" : @"disabled",
              sstp.peapEnabled ? @"enabled" : @"disabled",
              sstp.ttlsEnabled ? @"enabled" : @"disabled",
              sstp.teapEnabled ? @"enabled" : @"disabled");
        if ([sstp respondsToSelector:NSSelectorFromString(@"eapConfig")] ||
            [sstp respondsToSelector:NSSelectorFromString(@"eap_config")]) {
            SSLogI(@"PPP auth: EAP requested but unsupported by lwIP PPP backend");
        }
        ppp_set_auth(__ppp__, at, sstp.username.UTF8String, sstp.password.UTF8String);
        ppp_set_usepeerdns(__ppp__, true);
#if EAP_SUPPORT
        __ppp__->settings.eap_mschapv2_enable = sstp.eapMschapv2Enabled ? 1 : 0;
        __ppp__->settings.eap_peap_enable = sstp.peapEnabled ? 1 : 0;
        __ppp__->settings.peap_require_cb = sstp.peapRequireCryptoBinding ? 1 : 0;
        __ppp__->settings.eap_ttls_enable = sstp.ttlsEnabled ? 1 : 0;
        /* TTLS inner method: "eap" = inner EAP-MSCHAPv2 via EAP-Message
         * AVPs; "pap"/"chap" = AVP-based (RFC 5281 11.2). */
        __ppp__->settings.eap_ttls_inner = EAP_TTLS_INNER_EAP;
        if ([sstp.ttlsInnerMethod isEqualToString:@"pap"]) {
            __ppp__->settings.eap_ttls_inner = EAP_TTLS_INNER_PAP;
        } else if ([sstp.ttlsInnerMethod isEqualToString:@"chap"]) {
            __ppp__->settings.eap_ttls_inner = EAP_TTLS_INNER_CHAP;
        }
        __ppp__->settings.eap_teap_enable = sstp.teapEnabled ? 1 : 0;
        /* EAP-TLS client credentials (PEM blobs; borrowed pointers — the
         * NSData is retained on self for the whole session). */
        _eapTlsCertPem = sstp.eapTlsCertPem;
        _eapTlsKeyPem = sstp.eapTlsKeyPem;
        __ppp__->settings.eap_tls_cert_pem = (const u_char *)_eapTlsCertPem.bytes;
        __ppp__->settings.eap_tls_cert_pem_len = (int)_eapTlsCertPem.length;
        __ppp__->settings.eap_tls_key_pem = (const u_char *)_eapTlsKeyPem.bytes;
        __ppp__->settings.eap_tls_key_pem_len = (int)_eapTlsKeyPem.length;
        if (sstp.peapEnabled || sstp.ttlsEnabled || sstp.teapEnabled || sstp.eapTlsCertPem.length > 0) {
            /* PEAP/TTLS need many more EAP requests than the default budget of
             * 10: TLS fragment acks + inner identity + capabilities +
             * inner MSCHAPv2 easily exceed it. */
            __ppp__->settings.eap_allow_req = 40;
        }
        __ppp__->settings.eap_identity_privacy = sstp.eapIdentityPrivacy ? 1 : 0;
        __ppp__->settings.eap_anonymous_identity = sstp.eapAnonymousIdentity.length > 0 ? sstp.eapAnonymousIdentity.UTF8String : "anonymous";
        __ppp__->settings.eap_tls13_enabled = sstp.eapTls13Enabled ? 1 : 0;
        __ppp__->settings.eap_disable_legacy_tls = sstp.eapDisableLegacyTls ? 1 : 0;
        __ppp__->settings.peap_cert_check = sstp.allowInsecure ? 0 : 1;
        if (__ppp__->settings.peap_cert_check) {
            /* Pin the inner TLS certificate to the outer connection's leaf
             * certificate: the SSTP TLS layer already verified the server at
             * the system level, and RRAS/NPS normally presents the same
             * certificate inside PEAP.  A mismatch fails authentication. */
            u_char certHash[32] = {0};
            int certHashLen = 0;
            [_sstpClient getCertificate:certHash length:&certHashLen evp:1];
            if (certHashLen == 32) {
                MEMCPY(__ppp__->settings.peap_cert_sha256, certHash, 32);
            }
            else {
                SSLogI(@"PPP: no outer certificate hash available, inner cert check will fail closed");
                memset(__ppp__->settings.peap_cert_sha256, 0, 32);
            }
        }
#endif /* EAP_SUPPORT */
        ppp_connect(__ppp__, 0);
    }
    if (state == SSTPPPPState_ESTABLISHED) {
        _failedAttempts = 0;   // a working connection resets the retry budget
    }
    _pppState = state;
    SSLogM(@"tcpClient: %@ didChangeSSTPState: %@", client.tag, [lwIP GetState:state]);
}

+(NSString *)GetState:(SSTPPPPState)state {
    switch (state) {
        case SSTPPPPState_OPEN:
            return @"Open";
            
        case SSTPPPPState_CLOSE:
            return @"Close";
            
        case SSTPPPPState_ESTABLISHED:
            return @"ESTABLISHED";
        default:
            break;
    }
}
- (BOOL)close {
    _closedManually = YES;
    [self stopPathMonitor];
    [_sstpClient close];
    return YES;
}

@end
