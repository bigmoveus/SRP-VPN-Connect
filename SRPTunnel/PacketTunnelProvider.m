
#import "PacketTunnelProvider.h"
#import <SRPCore/SRPCore.h>
#import <SRPCore/SRPGeoIPDatabase.h>
#import <SRPParser/SRPParser.h>
#import "SRPKeychain.h"
#import <arpa/inet.h>

@interface PacketTunnelProvider ()
@property (nonatomic) NSInteger onSleepMode;   // 0=off 1=pause 2=stay (from the profile)
@property (nonatomic) BOOL sstpActive;
@property (nonatomic, strong) SRPSoftEtherClient *seClient;   // non-nil while a SoftEther session is active
@property (nonatomic, strong) SRPOpenConnectClient *ocClient;  // non-nil while an OpenConnect session is active
@property (nonatomic, strong) SRPSSHClient *sshClient;  // non-nil while an SSH session is active
@property (nonatomic, strong) SRPOpenVPNClient *ovpnClient;  // non-nil while an OpenVPN session is active
@property (nonatomic, strong) SRPWireGuardClient *wgClient;  // non-nil while a WireGuard session is active
@property (nonatomic, strong) SRPAetherClient *aeClient;    // non-nil while an Aether session is active
@property (nonatomic, strong) SRPPsiphonClient *psiClient;  // non-nil while a Psiphon session is active
@property (nonatomic, strong) SRPWaterWallClient *wwClient;
@property (nonatomic) NSInteger wwReadGeneration;
@property (nonatomic) BOOL wwReadInFlight;
@property (nonatomic) NSUInteger wwReadRequestID;

@end

@implementation PacketTunnelProvider{
    NWTCPConnection *_TCPConnection;
    NWUDPSession *_UDPSession;
}

// OpenConnect data-plane counters (dumped by logIPv4, declared at 347)
static long g_ocInPackets = 0, g_ocOutPackets = 0;
static long g_sshInPackets = 0, g_sshOutPackets = 0;
static long g_ovpnInPackets = 0, g_ovpnOutPackets = 0;
static long g_aeInPackets = 0, g_aeOutPackets = 0;
static long g_wwInPackets = 0, g_wwOutPackets = 0;
static void logIPv4(NSString *dir, NSData *pkt, long n);

-(instancetype)init {
    self = [super init];
    if (self) {
        [PDVPNManager setGroupID:@"group.tr.com.srp.vpn"];
    }
    return self;
}

-(void)startSSTPWithOptions:(NSDictionary *)v completionHandler:(void (^)(NSError *))completionHandler {

    SSSstp *p = [[SSSstp alloc] init];
    p.username = v[@"username"];
    p.password = v[@"password"];
    p.tls = YES;
    p.host = v[@"address"];
    p.port = [v[@"port"] intValue];
    p.allowInsecure = [v[@"allowInsecure"] boolValue];
    p.PAP_ENABLE = v[@"pap_enable"] ? [v[@"pap_enable"] boolValue] : NO;
    p.CHAP_ENABLE = v[@"chap_enable"] ? [v[@"chap_enable"] boolValue] : NO;
    p.MS_CHAP_ENABLE = v[@"mschap_enable"] ? [v[@"mschap_enable"] boolValue] : NO;
    p.MS2_CHAP_ENABLE = v[@"mschap2_enable"] ? [v[@"mschap2_enable"] boolValue] : YES;
    p.eapMschapv2Enabled = v[@"eapmschapv2_enable"] ? [v[@"eapmschapv2_enable"] boolValue] : NO;
    p.peapEnabled = v[@"peap_enable"] ? [v[@"peap_enable"] boolValue] : NO;
    p.peapRequireCryptoBinding = v[@"peap_require_cb"] ? [v[@"peap_require_cb"] boolValue] : NO;
    p.ttlsEnabled = v[@"eapttls_enable"] ? [v[@"eapttls_enable"] boolValue] : NO;
    if ([v[@"eapttls_inner"] length] > 0) {
        p.ttlsInnerMethod = v[@"eapttls_inner"];
    }
    p.teapEnabled = v[@"eapteap_enable"] ? [v[@"eapteap_enable"] boolValue] : NO;
    p.eapIdentityPrivacy = v[@"eap_identity_privacy"] ? [v[@"eap_identity_privacy"] boolValue] : NO;
    if ([v[@"eap_anonymous_identity"] length] > 0) {
        p.eapAnonymousIdentity = [v[@"eap_anonymous_identity"] stringByRemovingPercentEncoding];
    }
    p.eapTls13Enabled = v[@"eap_tls13"] ? [v[@"eap_tls13"] boolValue] : YES;
    p.eapDisableLegacyTls = v[@"eap_disable_legacy_tls"] ? [v[@"eap_disable_legacy_tls"] boolValue] : YES;
    p.domain = v[@"sni"];

    // Certificate authentication: unwrap the client .p12 from the shared
    // Keychain (only the cert_ref UUID crosses the profile -> tunnel boundary)
    if ([v[@"cert_auth"] boolValue] && [v[@"cert_ref"] length] > 0) {
        NSString *certPass = nil;
        NSData *p12 = [SRPKeychain certificateForKey:v[@"cert_ref"] passphrase:&certPass];
        if (p12 == nil || ![p setEapTlsP12:p12 passphrase:certPass ?: @""]) {
            NSLog(@"[SRP] certificate authentication requested but the certificate could not be read");
            completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"The client certificate could not be read. Re-import it in the profile."}]);
            return;
        }
    }

    // Proxy for the outer TCP path (never the SSTP destination / TLS SNI)
    NSString *proxyMode = v[@"proxy_mode"];
    p.proxyMode = [proxyMode isEqualToString:@"manual"] ? 1
                : [proxyMode isEqualToString:@"auto"] ? 2 : 0;
    p.proxyHost = [v[@"proxy_host"] stringByRemovingPercentEncoding];
    p.proxyPort = [v[@"proxy_port"] integerValue];
    p.proxyUsername = [v[@"proxy_user"] stringByRemovingPercentEncoding];
    p.pacURL = [v[@"pac_url"] stringByRemovingPercentEncoding];
    if ([v[@"proxy_pass_ref"] length] > 0) {
        // The proxy password lives in the shared Keychain under this ref
        p.proxyPassword = [SRPKeychain passwordForKey:v[@"proxy_pass_ref"]];
    }

    // OPTIONS section
    p.disableLegacyOuterTls = [v[@"disable_legacy_outer_tls"] boolValue];
    p.tlsFragMode = [v[@"tls_frag"] integerValue];
    p.tlsFragFirst = [v[@"tls_frag_first"] integerValue];
    p.tlsFragFollowing = [v[@"tls_frag_following"] integerValue];
    p.autoReconnect = v[@"auto_reconnect"] ? [v[@"auto_reconnect"] boolValue] : YES;
    p.retryTimes = [v[@"retry_times"] integerValue];
    p.switchToWifi = v[@"switch_to_wifi"] ? [v[@"switch_to_wifi"] boolValue] : YES;
    NSString *onSleep = v[@"on_sleep"];
    p.onSleep = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
    self.onSleepMode = p.onSleep;
    NSString *logLevel = v[@"log_level"];
    p.logLevel = [logLevel isEqualToString:@"expert"] ? 1 : [logLevel isEqualToString:@"debug"] ? 2 : 0;

    self.sstpActive = YES;
    [[lwIP shared] setup:p];

    __weak PacketTunnelProvider *weakSelf = self;
    __block BOOL finished = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    void (^finish)(NSError *) = ^(NSError *e) {
        if (finished) {
            return;
        }
        finished = YES;
        if (e) {
            // Publish the failure reason for the app UI
            NSString *reason = e.localizedDescription ?: @"SSTP connection failed";
            [shared setObject:@{@"message": reason, @"date": [NSDate date]} forKey:@"SRPLastError"];
        }
        else {
            [shared removeObjectForKey:@"SRPLastError"];
        }
        [shared synchronize];
        completionHandler(e);
    };

    [[lwIP shared] SetlwFailureCallback:^(NSString *reason) {
        finish([NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: reason ?: @"SSTP connection failed"}]);
    }];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        finish([NSError errorWithDomain:@"SRPVPN" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"Connection timed out. The server did not respond."}]);
    });

    [[lwIP shared] SetlwSetupNetworkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting) {
        [self setTunnelNetworkSettings:setting completionHandler:^(NSError * _Nullable e) {
            if (e) {
                return finish(e);
            }
            __strong PacketTunnelProvider *strongSelf = weakSelf;
            [strongSelf readPackets];
            finish(nil);
        }];
    }];
}

#pragma mark - SoftEther VPN Protocol

-(void)startSoftEtherWithOptions:(NSDictionary *)v completionHandler:(void (^)(NSError *))completionHandler {
    // Writable dir for the SoftEther core (also where the tunnel log lives)
    NSString *dir = [SRPTunnelLogPath() stringByDeletingLastPathComponent];
    [SRPSoftEtherClient initializeCoreInDirectory:dir debugLog:YES];

    SRPSoftEtherClient *se = [[SRPSoftEtherClient alloc] init];
    se.host = v[@"address"];
    se.port = [v[@"port"] intValue] ?: 443;
    se.hubName = [v[@"hub"] length] > 0 ? [v[@"hub"] stringByRemovingPercentEncoding] : @"DEFAULT";
    se.hostnameOverride = [v[@"sni"] length] > 0 ? [v[@"sni"] stringByRemovingPercentEncoding] : nil;
    se.username = v[@"username"];
    se.password = [v[@"password"] length] > 0 ? v[@"password"] : nil;

    NSString *auth = v[@"auth"];
    se.authMethod = [auth isEqualToString:@"plain"] ? SRPSoftEtherAuthRadiusNTDomain
                  : [auth isEqualToString:@"cert"] ? SRPSoftEtherAuthCertificate
                  : [auth isEqualToString:@"anonymous"] ? SRPSoftEtherAuthAnonymous
                  : SRPSoftEtherAuthStandardPassword;
    se.tlsServerVerification = ![v[@"allowInsecure"] boolValue];
    se.tlsFragMode = [v[@"tls_frag"] integerValue];
    se.tlsFragFirst = [v[@"tls_frag_first"] integerValue];
    se.tlsFragFollowing = [v[@"tls_frag_following"] integerValue];
    se.connections = MAX(1, MIN(32, [v[@"conns"] integerValue] ?: 1));
    se.udpAcceleration = [v[@"udp_accel"] boolValue];
    se.natTraversal = [v[@"natt"] boolValue];
    se.natTHint = [v[@"natt_hint"] stringByRemovingPercentEncoding];
    se.useCompress = YES;

    // Certificate authentication: unwrap the client .p12 from the shared Keychain
    if (se.authMethod == SRPSoftEtherAuthCertificate) {
        if ([v[@"cert_ref"] length] == 0) {
            completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"Certificate authentication requires a client certificate in the profile."}]);
            return;
        }
        NSString *certPass = nil;
        NSData *p12 = [SRPKeychain certificateForKey:v[@"cert_ref"] passphrase:&certPass];
        if (p12 == nil) {
            completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"The client certificate could not be read. Re-import it in the profile."}]);
            return;
        }
        se.clientCertP12 = p12;
        se.clientCertPassphrase = certPass;
    }

    // Proxy (manual HTTP/SOCKS5; auto/PAC falls back to direct with a log note)
    NSString *proxyMode = v[@"proxy_mode"];
    se.proxyMode = [proxyMode isEqualToString:@"manual"] ? 1
                 : [proxyMode isEqualToString:@"auto"] ? 2 : 0;
    se.proxyType = [v[@"proxy_type"] isEqualToString:@"socks5"] ? @"socks5" : @"http";
    se.proxyHost = [v[@"proxy_host"] stringByRemovingPercentEncoding];
    se.proxyPort = [v[@"proxy_port"] integerValue];
    se.proxyUsername = [v[@"proxy_user"] stringByRemovingPercentEncoding];
    if ([v[@"proxy_pass_ref"] length] > 0) {
        se.proxyPassword = [SRPKeychain passwordForKey:v[@"proxy_pass_ref"]];
    }

    // OPTIONS section
    se.autoReconnect = v[@"auto_reconnect"] ? [v[@"auto_reconnect"] boolValue] : YES;
    se.retryTimes = [v[@"retry_times"] integerValue];
    se.switchToWifi = v[@"switch_to_wifi"] ? [v[@"switch_to_wifi"] boolValue] : YES;
    NSString *onSleep = v[@"on_sleep"];
    se.onSleep = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
    self.onSleepMode = se.onSleep;
    NSString *logLevel = v[@"log_level"];
    se.logLevel = [logLevel isEqualToString:@"expert"] ? 1 : [logLevel isEqualToString:@"debug"] ? 2 : 0;

    self.seClient = se;

    __weak PacketTunnelProvider *weakSelf = self;
    __block BOOL finished = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    void (^finish)(NSError *) = ^(NSError *e) {
        if (finished) {
            return;
        }
        finished = YES;
        if (e) {
            [shared setObject:@{@"message": e.localizedDescription ?: @"SoftEther connection failed",
                                @"date": [NSDate date]} forKey:@"SRPLastError"];
        }
        else {
            [shared removeObjectForKey:@"SRPLastError"];
        }
        [shared synchronize];
        completionHandler(e);
    };

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        finish([NSError errorWithDomain:@"SRPVPN" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"Connection timed out. The server did not respond."}]);
    });

    [se startWithOutputCallback:^(NSData *ipPacket, int family) {
        [weakSelf.packetFlow writePackets:@[ipPacket] withProtocols:@[@(family)]];
    } networkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting) {
        // IPv6 settings may arrive later (RA); re-apply and keep reading
        if (finished) {
            [weakSelf setTunnelNetworkSettings:setting completionHandler:nil];
            return;
        }
        [weakSelf setTunnelNetworkSettings:setting completionHandler:^(NSError * _Nullable e) {
            if (e) {
                return finish(e);
            }
            [weakSelf readPacketsSE];
            finish(nil);
        }];
    } connectedCallback:nil disconnectedCallback:nil failureCallback:^(NSString *reason) {
        finish([NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: reason ?: @"SoftEther connection failed"}]);
    }];
}

-(void)readPacketsSE {
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> * _Nonnull packets, NSArray<NSNumber *> * _Nonnull protocols) {
        for (NSInteger i = 0; i < packets.count; i ++) {
            int fam = protocols[i].intValue;
            if (fam != AF_INET && fam != AF_INET6) {
                continue;
            }
            [self.seClient injectPacket:packets[i] family:fam];
        }
        [self readPacketsSE];
    }];
}

#pragma mark - OpenConnect (AnyConnect) VPN Protocol

-(void)startOpenConnectWithOptions:(NSDictionary *)v completionHandler:(void (^)(NSError *))completionHandler {
    [SRPOpenConnectClient initializeCore];

    SRPOpenConnectClient *oc = [[SRPOpenConnectClient alloc] init];
    oc.host = v[@"address"];
    oc.port = [v[@"port"] intValue] ?: 443;
    oc.ocProtocol = [v[@"ocproto"] length] > 0 ? v[@"ocproto"] : @"anyconnect";
    oc.username = v[@"username"];
    oc.password = [v[@"password"] length] > 0 ? v[@"password"] : nil;
    oc.tlsServerVerification = ![v[@"allowInsecure"] boolValue];
    oc.tlsFragMode = [v[@"tls_frag"] integerValue];
    oc.tlsFragFirst = [v[@"tls_frag_first"] integerValue];
    oc.tlsFragFollowing = [v[@"tls_frag_following"] integerValue];

    // Client certificate (optional): unwrap the .p12 from the shared Keychain
    if ([v[@"cert_auth"] boolValue] && [v[@"cert_ref"] length] > 0) {
        NSString *certPass = nil;
        NSData *p12 = [SRPKeychain certificateForKey:v[@"cert_ref"] passphrase:&certPass];
        if (p12 == nil) {
            completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"The client certificate could not be read. Re-import it in the profile."}]);
            return;
        }
        oc.clientCertP12 = p12;
        oc.clientCertPassphrase = certPass;
    }

    // OPTIONS section
    oc.autoReconnect = v[@"auto_reconnect"] ? [v[@"auto_reconnect"] boolValue] : YES;
    oc.retryTimes = [v[@"retry_times"] integerValue];
    oc.switchToWifi = v[@"switch_to_wifi"] ? [v[@"switch_to_wifi"] boolValue] : YES;
    NSString *onSleep = v[@"on_sleep"];
    oc.onSleep = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
    self.onSleepMode = oc.onSleep;
    NSString *logLevel = v[@"log_level"];
    oc.logLevel = [logLevel isEqualToString:@"expert"] ? 1 : [logLevel isEqualToString:@"debug"] ? 2 : 0;

    self.ocClient = oc;

    __weak PacketTunnelProvider *weakSelf = self;
    __block BOOL finished = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    void (^finish)(NSError *) = ^(NSError *e) {
        if (finished) {
            return;
        }
        finished = YES;
        if (e) {
            [shared setObject:@{@"message": e.localizedDescription ?: @"OpenConnect connection failed",
                                @"date": [NSDate date]} forKey:@"SRPLastError"];
        }
        else {
            [shared removeObjectForKey:@"SRPLastError"];
        }
        [shared synchronize];
        completionHandler(e);
    };

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        finish([NSError errorWithDomain:@"SRPVPN" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"Connection timed out. The server did not respond."}]);
    });

    [oc startWithOutputCallback:^(NSData *ipPacket, int family) {
        g_ocOutPackets++;
        if (g_ocOutPackets <= 20 || g_ocOutPackets % 100 == 0) {
            logIPv4(@"oc-to-phone", ipPacket, g_ocOutPackets);
        }
        [weakSelf.packetFlow writePackets:@[ipPacket] withProtocols:@[@(family)]];
    } networkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting) {
        SSLogM(@"OpenConnect: applying settings addr=%@ dns=%@ mtu=%@",
               setting.IPv4Settings.addresses, setting.DNSSettings.servers, setting.MTU);
        [weakSelf setTunnelNetworkSettings:setting completionHandler:^(NSError * _Nullable e) {
            if (e) {
                SSLogE(@"OpenConnect: setTunnelNetworkSettings failed: %@", e);
                return finish(e);
            }
            SSLogM(@"OpenConnect: settings applied, starting readPacketsOC");
            [weakSelf readPacketsOC];
            finish(nil);
        }];
    } connectedCallback:nil disconnectedCallback:nil failureCallback:^(NSString *reason) {
        finish([NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: reason ?: @"OpenConnect connection failed"}]);
    }];
}

-(void)readPacketsOC {
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> * _Nonnull packets, NSArray<NSNumber *> * _Nonnull protocols) {
        for (NSInteger i = 0; i < packets.count; i ++) {
            int fam = protocols[i].intValue;
            if (fam != AF_INET && fam != AF_INET6) {
                continue;
            }
            g_ocInPackets++;
            if (g_ocInPackets <= 20 || g_ocInPackets % 100 == 0) {
                logIPv4(@"oc-from-phone", packets[i], g_ocInPackets);
            }
            [self.ocClient injectPacket:packets[i] family:fam];
        }
        [self readPacketsOC];
    }];
}

#pragma mark - SSH VPN Protocol

-(void)startSSHWithOptions:(NSDictionary *)v completionHandler:(void (^)(NSError *))completionHandler {
    SRPSSHClient *ssh = [[SRPSSHClient alloc] init];
    ssh.host = v[@"address"];
    ssh.port = [v[@"port"] intValue] ?: 22;
    ssh.username = v[@"username"];
    ssh.password = [v[@"password"] length] > 0 ? v[@"password"] : nil;
    ssh.hostKeySHA256 = [v[@"hostkey"] length] > 0 ? [v[@"hostkey"] stringByRemovingPercentEncoding] : nil;

    ssh.udpEnabled = [v[@"ssh_udp"] boolValue];

    // OPTIONS section
    ssh.autoReconnect = v[@"auto_reconnect"] ? [v[@"auto_reconnect"] boolValue] : YES;
    ssh.retryTimes = [v[@"retry_times"] integerValue];
    ssh.switchToWifi = v[@"switch_to_wifi"] ? [v[@"switch_to_wifi"] boolValue] : YES;
    NSString *onSleep = v[@"on_sleep"];
    ssh.onSleep = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
    self.onSleepMode = ssh.onSleep;
    NSString *logLevel = v[@"log_level"];
    ssh.logLevel = [logLevel isEqualToString:@"expert"] ? 1 : [logLevel isEqualToString:@"debug"] ? 2 : 0;

    self.sshClient = ssh;

    __weak PacketTunnelProvider *weakSelf = self;
    __block BOOL finished = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    void (^finish)(NSError *) = ^(NSError *e) {
        if (finished) {
            return;
        }
        finished = YES;
        if (e) {
            [shared setObject:@{@"message": e.localizedDescription ?: @"SSH connection failed",
                                @"date": [NSDate date]} forKey:@"SRPLastError"];
        }
        else {
            [shared removeObjectForKey:@"SRPLastError"];
        }
        [shared synchronize];
        completionHandler(e);
    };

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        finish([NSError errorWithDomain:@"SRPVPN" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"Connection timed out. The server did not respond."}]);
    });

    [ssh startWithOutputCallback:^(NSData *ipPacket, int family) {
        g_sshOutPackets++;
        if (g_sshOutPackets <= 20 || g_sshOutPackets % 100 == 0) {
            logIPv4(@"ssh-to-phone", ipPacket, g_sshOutPackets);
        }
        [weakSelf.packetFlow writePackets:@[ipPacket] withProtocols:@[@(family)]];
    } networkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting) {
        [weakSelf setTunnelNetworkSettings:setting completionHandler:^(NSError * _Nullable e) {
            if (e) {
                SSLogE(@"SSH: setTunnelNetworkSettings failed: %@", e);
                return finish(e);
            }
            SSLogM(@"SSH: settings applied, starting readPacketsSSH");
            [weakSelf readPacketsSSH];
            finish(nil);
        }];
    } connectedCallback:nil disconnectedCallback:nil failureCallback:^(NSString *reason) {
        finish([NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: reason ?: @"SSH connection failed"}]);
    }];
}

-(void)readPacketsSSH {
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> * _Nonnull packets, NSArray<NSNumber *> * _Nonnull protocols) {
        for (NSInteger i = 0; i < packets.count; i ++) {
            int fam = protocols[i].intValue;
            if (fam != AF_INET && fam != AF_INET6) {
                continue;
            }
            g_sshInPackets++;
            if (g_sshInPackets <= 20 || g_sshInPackets % 100 == 0) {
                logIPv4(@"ssh-from-phone", packets[i], g_sshInPackets);
            }
            [self.sshClient injectPacket:packets[i] family:fam];
        }
        [self readPacketsSSH];
    }];
}


#pragma mark - OpenVPN Protocol

-(void)startOpenVPNWithOptions:(NSDictionary *)v completionHandler:(void (^)(NSError *))completionHandler {
    SRPOpenVPNClient *ovpn = [[SRPOpenVPNClient alloc] init];
    ovpn.profileText = [v[@"profile"] stringByRemovingPercentEncoding];
    if (ovpn.profileText.length == 0) {
        completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"No .ovpn profile is stored in this VPN profile. Import one in the profile editor."}]);
        return;
    }
    ovpn.stunnelEnabled = [v[@"stunnel"] boolValue];
    ovpn.tlsFragMode = [v[@"tls_frag"] integerValue];
    ovpn.tlsFragFirst = [v[@"tls_frag_first"] integerValue];
    ovpn.tlsFragFollowing = [v[@"tls_frag_following"] integerValue];
    ovpn.username = [v[@"username"] length] > 0 ? v[@"username"] : nil;
    ovpn.password = [v[@"password"] length] > 0 ? v[@"password"] : nil;
    if (ovpn.stunnelEnabled) {
        NSString *stHost = [v[@"stunnel_host"] stringByRemovingPercentEncoding];
        ovpn.stunnelHost = stHost.length > 0 ? stHost : v[@"address"];
        ovpn.stunnelPort = [v[@"stunnel_port"] intValue] ?: 443;
        ovpn.stunnelSNI = [v[@"stunnel_sni"] stringByRemovingPercentEncoding];
        ovpn.outerCAPEM = [v[@"stunnel_ca"] stringByRemovingPercentEncoding];
    }

    // OPTIONS section
    ovpn.autoReconnect = v[@"auto_reconnect"] ? [v[@"auto_reconnect"] boolValue] : YES;
    ovpn.retryTimes = [v[@"retry_times"] integerValue];
    ovpn.switchToWifi = v[@"switch_to_wifi"] ? [v[@"switch_to_wifi"] boolValue] : YES;
    NSString *onSleep = v[@"on_sleep"];
    ovpn.onSleep = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
    self.onSleepMode = ovpn.onSleep;
    NSString *logLevel = v[@"log_level"];
    ovpn.logLevel = [logLevel isEqualToString:@"expert"] ? 1 : [logLevel isEqualToString:@"debug"] ? 2 : 0;

    // The extension applies NEPacketTunnelNetworkSettings itself; the core
    // waits for tunApplied before declaring the tunnel up.
    [ovpn setProviderManaged:YES];
    self.ovpnClient = ovpn;

    __weak PacketTunnelProvider *weakSelf = self;
    __block BOOL finished = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    void (^finish)(NSError *) = ^(NSError *e) {
        if (finished) {
            return;
        }
        finished = YES;
        if (e) {
            [shared setObject:@{@"message": e.localizedDescription ?: @"OpenVPN connection failed",
                                @"date": [NSDate date]} forKey:@"SRPLastError"];
        }
        else {
            [shared removeObjectForKey:@"SRPLastError"];
        }
        [shared synchronize];
        completionHandler(e);
    };

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(45 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        finish([NSError errorWithDomain:@"SRPVPN" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"Connection timed out. The server did not respond."}]);
    });

    [ovpn startWithOutputCallback:^(NSData *ipPacket, int family) {
        g_ovpnOutPackets++;
        if (g_ovpnOutPackets <= 20 || g_ovpnOutPackets % 100 == 0) {
            logIPv4(@"ovpn-to-phone", ipPacket, g_ovpnOutPackets);
        }
        [weakSelf.packetFlow writePackets:@[ipPacket] withProtocols:@[@(family)]];
    } networkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting) {
        [weakSelf setTunnelNetworkSettings:setting completionHandler:^(NSError * _Nullable e) {
            if (e) {
                SSLogE(@"OpenVPN: setTunnelNetworkSettings failed: %@", e);
                return finish(e);
            }
            SSLogM(@"OpenVPN: settings applied, starting readPacketsOVPN");
            [ovpn tunApplied];
            [weakSelf readPacketsOVPN];
            finish(nil);
        }];
    } connectedCallback:nil disconnectedCallback:nil failureCallback:^(NSString *reason) {
        finish([NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: reason ?: @"OpenVPN connection failed"}]);
    }];
}

-(void)readPacketsOVPN {
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> * _Nonnull packets, NSArray<NSNumber *> * _Nonnull protocols) {
        for (NSInteger i = 0; i < packets.count; i ++) {
            int fam = protocols[i].intValue;
            if (fam != AF_INET && fam != AF_INET6) {
                continue;
            }
            g_ovpnInPackets++;
            if (g_ovpnInPackets <= 20 || g_ovpnInPackets % 100 == 0) {
                logIPv4(@"ovpn-from-phone", packets[i], g_ovpnInPackets);
            }
            [self.ovpnClient injectPacket:packets[i] family:fam];
        }
        [self readPacketsOVPN];
    }];
}


#pragma mark - WireGuard Protocol

-(void)startWireGuardWithOptions:(NSDictionary *)v completionHandler:(void (^)(NSError *))completionHandler {
    SRPWireGuardClient *wg = [[SRPWireGuardClient alloc] init];
    wg.amnezia = [v[@"xx"] isEqualToString:@"amnezia"];
    wg.configText = [v[@"wg_conf"] stringByRemovingPercentEncoding];
    if (wg.configText.length == 0) {
        completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"No WireGuard/AmneziaWG config is stored in this VPN profile. Import a .conf file or use Manual Configuration."}]);
        return;
    }
    NSString *logLevel = v[@"log_level"];
    wg.logLevel = [logLevel isEqualToString:@"expert"] ? 1 : [logLevel isEqualToString:@"debug"] ? 2 : 0;
    NSString *onSleep = v[@"on_sleep"];
    self.onSleepMode = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
    self.wgClient = wg;

    __weak PacketTunnelProvider *weakSelf = self;
    __block BOOL finished = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    void (^finish)(NSError *) = ^(NSError *e) {
        if (finished) {
            return;
        }
        finished = YES;
        if (e) {
            [shared setObject:@{@"message": e.localizedDescription ?: @"WireGuard connection failed",
                                @"date": [NSDate date]} forKey:@"SRPLastError"];
        }
        else {
            [shared removeObjectForKey:@"SRPLastError"];
        }
        [shared synchronize];
        completionHandler(e);
    };

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        finish([NSError errorWithDomain:@"SRPVPN" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"Connection timed out. The server did not respond."}]);
    });

    [wg startWithNetworkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting) {
        [weakSelf setTunnelNetworkSettings:setting completionHandler:^(NSError * _Nullable e) {
            if (e) {
                SSLogE(@"WireGuard: setTunnelNetworkSettings failed: %@", e);
                return finish(e);
            }
            // The utun fd exists only after the settings are applied
            NSError *actErr = nil;
            if (![wg activateWithError:&actErr]) {
                return finish(actErr);
            }
            SSLogM(@"WireGuard: session established");
            finish(nil);
        }];
    } failureCallback:^(NSString *reason) {
        finish([NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: reason ?: @"WireGuard connection failed"}]);
    }];
}


#pragma mark - Psiphon Protocol

-(void)startPsiphonWithOptions:(NSDictionary *)v completionHandler:(void (^)(NSError *))completionHandler {
    SRPPsiphonClient *psi = [[SRPPsiphonClient alloc] init];
    psi.serverEntry = [v[@"psi_entry"] stringByRemovingPercentEncoding];
    psi.serverIP = v[@"address"];
    psi.limitProtocols = v[@"psi_protos"];
    NSString *logLevel = v[@"log_level"];
    psi.logLevel = [logLevel isEqualToString:@"expert"] ? 1 : [logLevel isEqualToString:@"debug"] ? 2 : 0;
    NSString *onSleep = v[@"on_sleep"];
    self.onSleepMode = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
    self.psiClient = psi;

    __weak PacketTunnelProvider *weakSelf = self;
    __block BOOL finished = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    void (^finish)(NSError *) = ^(NSError *e) {
        if (finished) {
            return;
        }
        finished = YES;
        if (e) {
            [shared setObject:@{@"message": e.localizedDescription ?: @"Psiphon connection failed",
                                @"date": [NSDate date]} forKey:@"SRPLastError"];
        }
        else {
            [shared removeObjectForKey:@"SRPLastError"];
        }
        [shared synchronize];
        completionHandler(e);
    };

    // Psiphon can take a while on slow networks; the client retries once
    // with a wiped tactics database after a failed establishment (60s each),
    // so the budget must cover both attempts plus settings
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(200 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        finish([NSError errorWithDomain:@"SRPVPN" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"Connection timed out. The server did not respond."}]);
    });

    [psi startWithOutputCallback:^(NSData *ipPacket, int family) {
        [weakSelf.packetFlow writePackets:@[ipPacket] withProtocols:@[@(family)]];
    } networkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting) {
        [weakSelf setTunnelNetworkSettings:setting completionHandler:^(NSError * _Nullable e) {
            if (e) {
                SSLogE(@"Psiphon: setTunnelNetworkSettings failed: %@", e);
                return finish(e);
            }
            [weakSelf readPacketsPSI];
            finish(nil);
        }];
    } connectedCallback:nil failureCallback:^(NSString *reason) {
        finish([NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: reason ?: @"Psiphon connection failed"}]);
    }];
}

-(void)readPacketsPSI {
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> * _Nonnull packets, NSArray<NSNumber *> * _Nonnull protocols) {
        for (NSInteger i = 0; i < packets.count; i ++) {
            int fam = protocols[i].intValue;
            if (fam != AF_INET && fam != AF_INET6) {
                continue;
            }
            [self.psiClient injectPacket:packets[i] family:fam];
        }
        [self readPacketsPSI];
    }];
}

#pragma mark - Aether Protocol

-(void)startAetherWithOptions:(NSDictionary *)v completionHandler:(void (^)(NSError *))completionHandler {
#if DEBUG
    [self debugTlsProbe:@"162.159.198.2"];   // raw BSD TLS probe, engine-free
#endif
    SRPAetherClient *ae = [[SRPAetherClient alloc] init];
    // Private mode: the user's own server runs the Aether SOCKS5 proxy; the
    // device chains hev -> WireGuard (netstack relay) -> that proxy -> WARP
    if ([v[@"ae_mode"] isEqualToString:@"private"]) {
        ae.privateConfig = [v[@"wg_conf"] stringByRemovingPercentEncoding];
        if (ae.privateConfig.length == 0) {
            completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"Aether private mode needs a WireGuard configuration (Server, Port and the keys under Manual Configuration)."}]);
            return;
        }
    }
    // The engine keeps its identity/last-good endpoint in the shared
    // app-group container so a reconnect reuses them
    NSURL *container = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
    NSString *dir = [container.path stringByAppendingPathComponent:@"Library/aether"];
    ae.identityDir = dir;
    ae.transport = [v[@"ae_transport"] length] > 0 ? v[@"ae_transport"] : @"masque";
    ae.scanProfile = [v[@"ae_scan"] length] > 0 ? v[@"ae_scan"] : @"balanced";
    ae.licenseKey = [v[@"ae_license"] stringByRemovingPercentEncoding];
    ae.torMode = v[@"ae_tor"];
    ae.fragMode = [v[@"tls_frag"] integerValue];
    ae.fragMin = [v[@"tls_frag_first"] integerValue];
    ae.fragMax = [v[@"tls_frag_following"] integerValue];
    NSString *logLevel = v[@"log_level"];
    ae.logLevel = [logLevel isEqualToString:@"expert"] ? 1 : [logLevel isEqualToString:@"debug"] ? 2 : 0;
    NSString *onSleep = v[@"on_sleep"];
    self.onSleepMode = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
    self.aeClient = ae;

    __weak PacketTunnelProvider *weakSelf = self;
    __block BOOL finished = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    void (^finish)(NSError *) = ^(NSError *e) {
        if (finished) {
            return;
        }
        finished = YES;
        if (e) {
            [shared setObject:@{@"message": e.localizedDescription ?: @"Aether connection failed",
                                @"date": [NSDate date]} forKey:@"SRPLastError"];
        }
        else {
            [shared removeObjectForKey:@"SRPLastError"];
        }
        [shared synchronize];
        completionHandler(e);
    };

    [ae startWithOutputCallback:^(NSData *ipPacket, int family) {
        g_aeOutPackets++;
        if (g_aeOutPackets <= 20 || g_aeOutPackets % 100 == 0) {
            logIPv4(@"ae-to-phone", ipPacket, g_aeOutPackets);
        }
        [weakSelf.packetFlow writePackets:@[ipPacket] withProtocols:@[@(family)]];
    } networkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting) {
        SSLogM(@"Aether: applying settings: %@", setting);
        [weakSelf setTunnelNetworkSettings:setting completionHandler:^(NSError * _Nullable e) {
            if (e) {
                SSLogE(@"Aether: setTunnelNetworkSettings failed: %@", e);
                return finish(e);
            }
            [weakSelf.aeClient tunApplied];
            if ([weakSelf.aeClient usingWireGuardEngine]) {
                SSLogM(@"Aether: settings applied (WireGuard engine owns the utun)");
            } else {
                SSLogM(@"Aether: settings applied, starting readPacketsAE");
                [weakSelf readPacketsAE];
            }
            finish(nil);
        }];
    } connectedCallback:nil failureCallback:^(NSString *reason) {
        NSError *error = [NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: reason ?: @"Aether connection failed"}];
        if (finished) {
            [shared setObject:@{@"message": error.localizedDescription, @"date": NSDate.date} forKey:@"SRPLastError"];
            [weakSelf cancelTunnelWithError:error];
        } else {
            finish(error);
        }
    }];
}

-(void)readPacketsAE {
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> * _Nonnull packets, NSArray<NSNumber *> * _Nonnull protocols) {
        NSMutableArray<NSData *> *validPackets = [NSMutableArray arrayWithCapacity:packets.count];
        for (NSInteger i = 0; i < packets.count; i ++) {
            int fam = protocols[i].intValue;
            if (fam != AF_INET && fam != AF_INET6) continue;
            g_aeInPackets++;
            if (g_aeInPackets <= 20 || g_aeInPackets % 100 == 0) {
                logIPv4(@"ae-from-phone", packets[i], g_aeInPackets);
            }
            [validPackets addObject:packets[i]];
        }
        [self.aeClient injectPackets:validPackets completion:^{
            [self readPacketsAE];
        }];
    }];
}


#pragma mark - WaterWall Protocol

static BOOL SRPWWProbeAddressAllowed(NSString *address, NSString *allowedIPs) {
    if (allowedIPs.length == 0) return YES;
    struct in_addr probe;
    if (inet_pton(AF_INET, address.UTF8String, &probe) != 1) return NO;
    uint32_t ip = ntohl(probe.s_addr);
    for (NSString *entry in [allowedIPs componentsSeparatedByString:@","]) {
        NSString *cidr = [entry stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSArray<NSString *> *parts = [cidr componentsSeparatedByString:@"/"];
        struct in_addr network;
        NSInteger prefix = parts.count == 2 ? parts[1].integerValue : -1;
        if (parts.count != 2 || prefix < 0 || prefix > 32 || inet_pton(AF_INET, parts[0].UTF8String, &network) != 1) continue;
        uint32_t mask = prefix == 0 ? 0 : UINT32_MAX << (32 - prefix);
        if ((ip & mask) == (ntohl(network.s_addr) & mask)) return YES;
    }
    return NO;
}

- (void)startWaterWallWithOptions:(NSDictionary *)v completionHandler:(void (^)(NSError *))completionHandler {
    NSDictionary *configuration = [SRPWaterWallChainConfig configurationWithJSON:v[@"ww_config"]];
    if (configuration == nil) {
        completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"The WaterWall configuration is invalid."}]);
        return;
    }
    BOOL requiresGeoIP = [configuration[@"geoip"][@"iran-direct"] boolValue] ||
                         [configuration[@"geoip"][@"countries"] count] > 0;
    if (requiresGeoIP) {
        NSURL *databaseURL = SRPGeoIPDatabase.sharedDatabase.currentDatabaseURL;
        NSError *databaseError = nil;
        if (databaseURL == nil || ![SRPGeoIPDatabase.sharedDatabase validateDatabaseAtURL:databaseURL error:&databaseError]) {
            NSString *message = databaseError.localizedDescription ?: @"A valid GeoIP country database is required.";
            completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{
                NSLocalizedDescriptionKey: [@"GeoIP is enabled but its database is unavailable: " stringByAppendingString:message]
            }]);
            return;
        }
        NSMutableDictionary *options = [v mutableCopy];
        options[@"ww_geoip_db_path"] = databaseURL.path;
        v = options;
    }
#if DEBUG
    if ([v[@"ww_test_id"] length] > 0) {
        NSURL *container = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
        NSString *base = container ? container.path : NSHomeDirectory();
        NSString *path = [base stringByAppendingPathComponent:@"Library/ww-native-current.log"];
        if ([NSFileManager.defaultManager fileExistsAtPath:path]) {
            NSString *backup = [path stringByAppendingFormat:@".%.0f.previous", NSDate.date.timeIntervalSince1970];
            [NSFileManager.defaultManager moveItemAtPath:path toPath:backup error:nil];
        }
        NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
        NSString *message = [NSString stringWithFormat:@"WaterWall test profile: %@\n", v[@"ww_test_id"]];
        [handle seekToEndOfFile];
        [handle writeData:[message dataUsingEncoding:NSUTF8StringEncoding]];
        [handle closeFile];
    }
#endif
    NSString *secret = [v[@"ww_secret_ref"] length] > 0 ? [SRPKeychain passwordForKey:v[@"ww_secret_ref"]] : v[@"password"];
    SRPWaterWallClient *client = [SRPWaterWallClient new];
    if ([configuration[@"mode"] isEqualToString:@"chain"]) {
        NSDictionary *application = configuration[@"node-options"][@"application"];
        NSString *protocol = application[@"protocol"] ?: application[@"proto"];
        if ([configuration[@"application"] isEqualToString:@"http-proxy"]) client.probeUDP = NO;
        if ([protocol isEqualToString:@"tcp"] || [protocol isEqualToString:@"connect"]) {
            client.probeUDP = NO;
        } else if ([protocol isEqualToString:@"udp"] || [protocol isEqualToString:@"udp-associate"]) {
            client.probeTCP = NO;
        }
    }
    if ([configuration[@"input"] isEqualToString:@"raw-ipv4"] || [configuration[@"outer"] isEqualToString:@"aead"]) client.tunnelAddress = @"10.44.0.4";
    NSString *serverAddress = [v[@"address"] length] > 0 ? v[@"address"] : @"127.0.0.1";
    NSString *endpointAddress = v[@"endpoint_ip"];
    if (![SRPWaterWallChainConfig isWireGuardConfiguration:configuration] &&
        ![SRPWaterWallChainConfig isDirectConfiguration:configuration]) {
        endpointAddress = [client resolvedAddressForHost:endpointAddress.length > 0 ? endpointAddress : serverAddress];
        if (endpointAddress.length == 0) {
            completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{
                NSLocalizedDescriptionKey: @"The WaterWall server address could not be resolved."
            }]);
            return;
        }
        client.endpointIP = endpointAddress;
        client.endpointIPs = @[endpointAddress];
    }
    NSString *nodesJSON;
    if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration]) {
        NSDictionary *wg;
        NSString *wgConfig = v[@"wg_conf"];
        if (wgConfig.length > 0) {
            wg = [SRPWaterWallChainConfig wireGuardConfigurationWithConfig:wgConfig];
        } else {
            wg = [SRPWaterWallChainConfig wireGuardConfigurationWithPrivateKey:v[@"wg_private_key"] ?: @""
                                                                  serverPublicKey:v[@"wg_peer_public_key"] ?: @""
                                                                           server:v[@"address"] ?: @""
                                                                             port:[v[@"port"] integerValue]
                                                                     clientAddress:v[@"wg_address"] ?: @""
                                                                         keepalive:[v[@"wg_keepalive"] integerValue]];
        }
        nodesJSON = wg[@"nodesJSON"];
        client.tunnelAddress = wg[@"tunnelAddress"];
        client.dnsServers = wg[@"dnsServers"];
        client.allowedIPs = wg[@"allowedIPs"];
        client.endpointIP = wg[@"endpointIP"];
        client.endpointIPs = wg[@"endpointIPs"];
    } else {
        NSString *outerSecret = v[@"ww_outer_secret"];
        if ([v[@"ww_outer_secret_ref"] length] > 0) {
            outerSecret = [SRPKeychain passwordForKey:v[@"ww_outer_secret_ref"]] ?: outerSecret;
        }
        nodesJSON = [SRPWaterWallChainConfig nodesJSONForConfiguration:configuration
                                                                server:endpointAddress.length > 0 ? endpointAddress : serverAddress
                                                                  port:[v[@"port"] integerValue]
                                                                   sni:[v[@"sni"] length] > 0 ? v[@"sni"] : serverAddress
                                                             verifyTLS:![v[@"allowInsecure"] boolValue]
                                                                secret:secret
                                                           outerSecret:outerSecret
                                                               options:v];
    }
    if (nodesJSON.length == 0) {
        completionHandler([NSError errorWithDomain:@"SRPVPN" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"The WaterWall profile is incomplete or invalid."}]);
        return;
    }
    if (![SRPWaterWallChainConfig isWireGuardConfiguration:configuration]) {
        NSDictionary *graph = [NSJSONSerialization JSONObjectWithData:[nodesJSON dataUsingEncoding:NSUTF8StringEncoding]
                                                               options:0
                                                                 error:nil];
        NSArray<NSDictionary *> *nodes = graph[@"nodes"];
        client.probeUDP = client.probeUDP && [nodes.lastObject[@"type"] isEqualToString:@"TcpUdpConnector"];
    }
    client.logLevel = [v[@"log_level"] isEqualToString:@"debug"] ? 2 : [v[@"log_level"] isEqualToString:@"expert"] ? 1 : 0;
    client.autoReconnect = v[@"auto_reconnect"] ? [v[@"auto_reconnect"] boolValue] : YES;
    client.retryTimes = [v[@"retry_times"] integerValue];
    client.switchToWifi = v[@"switch_to_wifi"] ? [v[@"switch_to_wifi"] boolValue] : YES;
    NSString *onSleep = v[@"on_sleep"];
    client.onSleep = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
    self.onSleepMode = client.onSleep;
    client.coreJSON = [SRPWaterWallChainConfig coreJSONWithLogLevel:client.logLevel];
    client.nodesJSON = nodesJSON;
    client.remoteAddress = [v[@"address"] length] > 0 ? v[@"address"] : @"127.0.0.1";
    client.probeAddress = [v[@"ww_probe_ip"] length] > 0 ? v[@"ww_probe_ip"] : @"1.1.1.1";
    BOOL fakeDNS = (v[@"ww_fake_dns"] == nil || [v[@"ww_fake_dns"] boolValue]) &&
                   [SRPWaterWallChainConfig configurationAllowsRouting:configuration];
    client.dnsProbeAddress = fakeDNS ? @"198.18.0.2" :
                             [v[@"ww_dns_probe_ip"] length] > 0 ? v[@"ww_dns_probe_ip"] : client.probeAddress;
    if (fakeDNS) client.dnsServers = @[@"198.18.0.2"];
    if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration]) {
        client.probeTCP = client.probeTCP && SRPWWProbeAddressAllowed(client.probeAddress, client.allowedIPs);
        client.probeUDP = client.probeUDP && SRPWWProbeAddressAllowed(client.dnsProbeAddress, client.allowedIPs);
    }
    if (client.endpointIP.length == 0) client.endpointIP = v[@"endpoint_ip"];
    self.wwClient = client;

    __block BOOL finished = NO;
    NSUserDefaults *shared = [[NSUserDefaults alloc] initWithSuiteName:@"group.tr.com.srp.vpn"];
    void (^finish)(NSError *) = ^(NSError *error) {
        if (finished) return;
        finished = YES;
        if (error) {
            [shared setObject:@{@"message": error.localizedDescription, @"date": [NSDate date]} forKey:@"SRPLastError"];
        } else {
            [shared removeObjectForKey:@"SRPLastError"];
        }
        completionHandler(error);
    };
    __weak PacketTunnelProvider *weakSelf = self;
    [client startWithOutputCallback:^(NSData *packet, int family) {
        g_wwOutPackets++;
        if (g_wwOutPackets <= 20 || g_wwOutPackets % 100 == 0) logIPv4(@"ww-to-phone", packet, g_wwOutPackets);
        [weakSelf.packetFlow writePackets:@[packet] withProtocols:@[@(family)]];
    } networkSettingsCallback:^(NEPacketTunnelNetworkSettings *setting, void (^applied)(NSError *error)) {
        [weakSelf setTunnelNetworkSettings:setting completionHandler:^(NSError *error) {
            if (error) SSLogE(@"WaterWall: setTunnelNetworkSettings failed: %@", error);
            applied(error);
            if (error) return finish(error);
            weakSelf.wwReadGeneration++;
            SSLogM(@"WaterWall read generation advanced to %ld", (long)weakSelf.wwReadGeneration);
            [weakSelf readPacketsWWForGeneration:weakSelf.wwReadGeneration];
            finish(nil);
        }];
    } connectedCallback:nil failureCallback:^(NSString *reason) {
        NSError *error = [NSError errorWithDomain:@"SRPVPN" code:-1 userInfo:@{NSLocalizedDescriptionKey: reason}];
        if (finished) {
            [shared setObject:@{@"message": error.localizedDescription, @"date": NSDate.date} forKey:@"SRPLastError"];
            [weakSelf cancelTunnelWithError:error];
        } else {
            finish(error);
        }
    }];
}

- (void)finishWWReadRequest:(NSUInteger)requestID {
    @synchronized (self) {
        if (self.wwReadRequestID != requestID) return;
        self.wwReadInFlight = NO;
    }
    [self readPacketsWWForGeneration:self.wwReadGeneration];
}

- (void)readPacketsWWForGeneration:(NSInteger)generation {
    if (generation != self.wwReadGeneration) return;
    SRPWaterWallClient *client = self.wwClient;
    if (client == nil) return;
    NSUInteger requestID;
    @synchronized (self) {
        if (self.wwReadInFlight) return;
        self.wwReadInFlight = YES;
        requestID = ++self.wwReadRequestID;
    }
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        if (generation != self.wwReadGeneration || client != self.wwClient) {
            SSLogM(@"WaterWall read generation changed from %ld to %ld", (long)generation, (long)self.wwReadGeneration);
            [self finishWWReadRequest:requestID];
            return;
        }
        NSMutableArray<NSData *> *validPackets = [NSMutableArray arrayWithCapacity:packets.count];
        for (NSInteger i = 0; i < packets.count; i++) {
            int family = protocols[i].intValue;
            if (family != AF_INET) continue;
            g_wwInPackets++;
            if (g_wwInPackets <= 20 || g_wwInPackets % 100 == 0) logIPv4(@"ww-from-phone", packets[i], g_wwInPackets);
            [validPackets addObject:packets[i]];
        }
        [client injectPackets:validPackets completion:^{
            [self finishWWReadRequest:requestID];
        }];
    }];
}


// Data-plane instrumentation: counters are free; packet dumps are Debug builds only.
static long g_inPackets = 0, g_inV6 = 0, g_outPackets = 0;

static void logIPv4(NSString *dir, NSData *pkt, long n) {
#if DEBUG
    if (!SSLogEnabled(SSLogLevelDebug)) {
        return;   // [SRP-PKT] packet counters are Debug-level only
    }
    const uint8_t *b = pkt.bytes;
    if (pkt.length >= 20 && (b[0] >> 4) == 4) {
        NSLog(@"[SRP-PKT] %@ #%ld %d.%d.%d.%d -> %d.%d.%d.%d proto=%d len=%lu",
              dir, n, b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19], b[9], (unsigned long)pkt.length);
    }
#endif
}

-(void)readPackets {
    [[lwIP shared] SetlwIPOutputCallback:^(NSData *ipPacket, int family) {
        g_outPackets++;
        if (g_outPackets <= 20 || g_outPackets % 100 == 0) {
            logIPv4(@"to-phone", ipPacket, g_outPackets);
        }
        [self.packetFlow writePackets:@[ipPacket] withProtocols:@[@(family)]];
    }];
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> * _Nonnull packets, NSArray<NSNumber *> * _Nonnull protocols) {
        for (NSInteger i = 0; i < packets.count; i ++) {
            // Only IPv4 is supported for now; skip IPv6 packets without killing the read loop
            if (protocols[i].intValue == AF_INET6) {
                g_inV6++;
#if DEBUG
                NSLog(@"[SRP-PKT] skipped IPv6 packet (total v6: %ld)", g_inV6);
#endif
                continue;
            }
            g_inPackets++;
            if (g_inPackets <= 20 || g_inPackets % 100 == 0) {
                logIPv4(@"from-phone", packets[i], g_inPackets);
            }
            [[lwIP shared] WriteIPPacket:packets[i] family:protocols[i].intValue];
        }
        [self readPackets];
    }];
}

-(nullable NSDictionary *)parse:(NSString *)uri {
    NSURL *url = [NSURL URLWithString:uri];
    NSArray *nodes = [uri componentsSeparatedByString:@"#"];
    NSString *remark = nodes.count >= 2 ? nodes.lastObject : @"sstp";
    NSArray <NSString *>*parameters = [url.query componentsSeparatedByString:@"&"];
    NSString *username = url.user;
    NSString *password = url.password;
    if (password == nil) {
        NSArray *up = [[PDBase64 decode:username] componentsSeparatedByString:@":"];
        if (up.count != 2) {
            return nil;
        }
        username = up[0];
        password = up[1];

        username = [username stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        password = [password stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    }
    NSMutableDictionary *body = @{@"username":username, @"password":password, @"port":url.port, @"xx":url.scheme, @"address":url.host, @"remark":remark}.mutableCopy;
    [parameters enumerateObjectsUsingBlock:^(NSString * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSArray *t = [obj componentsSeparatedByString:@"="];
        if (t.count == 2) {
            body[t[0]] = t[1];
        }
    }];
    // EAP variants supported by the lwIP backend: bare EAP-MSCHAPv2, PEAP, EAP-TTLS, TEAP
    // (plus PEAP TLS options and identity privacy). Warn only on genuinely unknown EAP keys.
    static NSSet *supportedEapKeys = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        supportedEapKeys = [NSSet setWithArray:@[
            @"eapmschapv2_enable", @"peap_enable", @"eapttls_enable", @"eapteap_enable",
            @"eapttls_inner", @"peap_require_cb",
            @"eap_identity_privacy", @"eap_anonymous_identity", @"eap_tls13", @"eap_disable_legacy_tls"
        ]];
    });
    for (NSString *key in body.allKeys) {
        if ([supportedEapKeys containsObject:key]) {
            continue;
        }
        if ([key hasPrefix:@"eap"] || [key hasPrefix:@"peap"] || [key hasPrefix:@"ttls"] || [key hasPrefix:@"teap"]) {
            NSLog(@"[SRP] EAP config present in URI (%@) but unsupported by backend", key);
        }
    }
    return body;
}

// Log file lives in the shared app-group container so the app's log viewer
// can read it. Truncated on every tunnel start (fresh log per connection);
// never wiped on stop (the user reads it after a failure) — only capped.
static NSString *SRPTunnelLogPath(void) {
    NSURL *container = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
    // Keep the log under Library/ so it stays within the app-group's
    // readable directories (devicectl allows Library/Documents/tmp only).
    NSString *base = container ? container.path : NSHomeDirectory();
    NSString *dir = [base stringByAppendingPathComponent:@"Library"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return [dir stringByAppendingPathComponent:@"srptunnel.log"];
}

/// Cap growth: when the log exceeds ~2MB, keep its last 512KB (the tail is
/// what post-mortem debugging needs; wiping it loses exactly that)
static void SRPTunnelLogCap(NSString *path) {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    if (attrs.fileSize > 2 * 1024 * 1024) {
        NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
        if (!fh) return;
        [fh seekToFileOffset:attrs.fileSize - 512 * 1024];
        NSData *tail = [fh readDataToEndOfFile];
        [fh closeFile];
        [tail writeToFile:path atomically:YES];
    }
}

- (void)startTunnelWithOptions:(NSDictionary *)options completionHandler:(void (^)(NSError *))completionHandler {

#if DEBUG
    // Debug builds only: release builds never write logs to disk.
    NSString *logFilePath = SRPTunnelLogPath();
    [[NSFileManager defaultManager] removeItemAtPath:logFilePath error:nil];
    [[NSFileManager defaultManager] createFileAtPath:logFilePath contents:nil attributes:nil];
    freopen([logFilePath cStringUsingEncoding:NSUTF8StringEncoding], "w+", stdout);
    freopen([logFilePath cStringUsingEncoding:NSUTF8StringEncoding], "w+", stderr);
    // A file-backed stdout is fully buffered; a stopped extension loses the
    // tail (or all) of the log. Line-buffer both streams instead.
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
#endif
    // Never log credentials: mask the URI userinfo before logging
    NSString* (^maskURI)(NSString *) = ^NSString *(NSString *uri) {
        if (!uri) {
            return uri;
        }
        NSRange schemeEnd = [uri rangeOfString:@"//"];
        NSRange atSign = [uri rangeOfString:@"@"];
        if (schemeEnd.location != NSNotFound && atSign.location != NSNotFound && atSign.location > schemeEnd.location + 1) {
            return [uri stringByReplacingCharactersInRange:NSMakeRange(schemeEnd.location + 2, atSign.location - schemeEnd.location - 2) withString:@"***"];
        }
        return uri;
    };
    NSMutableDictionary *safeOptions = options.mutableCopy;
    safeOptions[@"uri"] = maskURI(safeOptions[@"uri"]);
    if (safeOptions[@"waterwall"]) safeOptions[@"waterwall"] = @"<redacted>";
    NSDictionary *vendorData = safeOptions[@"VendorData"];
    NSDictionary *vendorConf = vendorData[@"configuration"];
    if (vendorConf) {
        NSMutableDictionary *safeConf = vendorConf.mutableCopy;
        safeConf[@"uri"] = maskURI(safeConf[@"uri"]);
        if (safeConf[@"waterwall"]) safeConf[@"waterwall"] = @"<redacted>";
        NSMutableDictionary *safeVendor = vendorData.mutableCopy;
        safeVendor[@"configuration"] = safeConf;
        safeOptions[@"VendorData"] = safeVendor;
    }
#if DEBUG
    NSLog(@"[SRP] startTunnel options: %@", safeOptions);
#endif

    if (!options) {
        NETunnelProviderProtocol *protocolConfiguration = (NETunnelProviderProtocol *)self.protocolConfiguration;
        NSMutableDictionary *copy = protocolConfiguration.providerConfiguration.mutableCopy;
        options = copy[@"configuration"];
    }
    NSDictionary *ss;
    NSString *uri = options[@"uri"];
    BOOL global = [options[@"global"] boolValue];
    if (!global) {
        [NWRunLoop setup:PDVPNManager.mmdb];
    }
    else {
        [NWRunLoop setup:nil];
    }

    NSDictionary *waterwall = options[@"waterwall"];
    if ([waterwall isKindOfClass:NSDictionary.class]) {
        return [self startWaterWallWithOptions:waterwall completionHandler:completionHandler];
    }

    ss = [self parse:uri];
    NSString *scheme = ss[@"xx"];
    if ([scheme isEqualToString:@"sstp"]) {
        return [self startSSTPWithOptions:ss completionHandler:completionHandler];
    }
    if ([scheme isEqualToString:@"softether"]) {
        return [self startSoftEtherWithOptions:ss completionHandler:completionHandler];
    }
    if ([scheme isEqualToString:@"openconnect"]) {
        return [self startOpenConnectWithOptions:ss completionHandler:completionHandler];
    }
    if ([scheme isEqualToString:@"ssh"]) {
        return [self startSSHWithOptions:ss completionHandler:completionHandler];
    }
    if ([scheme isEqualToString:@"openvpn"]) {
        return [self startOpenVPNWithOptions:ss completionHandler:completionHandler];
    }
    if ([scheme isEqualToString:@"aether"]) {
        return [self startAetherWithOptions:ss completionHandler:completionHandler];
    }
    if ([scheme isEqualToString:@"psiphon"]) {
        return [self startPsiphonWithOptions:ss completionHandler:completionHandler];
    }
    if ([scheme isEqualToString:@"wireguard"] || [scheme isEqualToString:@"amnezia"]) {
        return [self startWireGuardWithOptions:ss completionHandler:completionHandler];
    }

    completionHandler([NSError errorWithDomain:@"Not Found" code:404 userInfo:nil]);
}

- (void)stopTunnelWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    NSLog(@"[Y] stop tunnel in orb:%@", @(reason));
    [self.seClient closeAndWait];   // wait for the SoftEther session thread to exit
    self.seClient = nil;
    [self.ocClient closeAndWait];   // wait for the OpenConnect mainloop to exit
    self.ocClient = nil;
    [self.sshClient closeAndWait];  // wait for the SSH session/engine to exit
    self.sshClient = nil;
    [self.ovpnClient closeAndWait]; // wait for the OpenVPN core thread to exit
    self.ovpnClient = nil;
    [self.wgClient closeAndWait];   // stop the WireGuard device
    self.wgClient = nil;
    [self.aeClient closeAndWait];   // stop the Aether engine and bridge
    self.aeClient = nil;
    [self.psiClient closeAndWait];  // stop the Psiphon core and bridge
    self.psiClient = nil;
    self.wwReadGeneration++;
    @synchronized (self) {
        self.wwReadRequestID++;
        self.wwReadInFlight = NO;
    }
    [self.wwClient closeAndWait];
    self.wwClient = nil;
    BOOL v = self.sstpActive && [[lwIP shared] close];
    self.sstpActive = NO;
    if (v) {
        sleep(1);
    }
    // Keep the log for post-mortem reading; only cap its size
    fflush(stdout);
    fflush(stderr);
    SRPTunnelLogCap(SRPTunnelLogPath());
    completionHandler();
}

- (void)handleAppMessage:(NSData *)messageData completionHandler:(void (^)(NSData *))completionHandler {
    NSDictionary *app = [NSJSONSerialization JSONObjectWithData:messageData options:NSJSONReadingMutableContainers error:nil];
    NSInteger type = [app[@"type"] integerValue];
    if (type == 5) {
        BOOL global = [app[@"global"] boolValue];
        if (global) {
            [NWRunLoop setup:nil];
        }
        else {
            [NWRunLoop setup:PDVPNManager.mmdb];
        }
    }
#if DEBUG
    if (type == 100) {
        NSString *command = app[@"command"];
        if ([command isEqualToString:@"sleep"]) {
            [self sleepWithCompletionHandler:^{ completionHandler(messageData); }];
            return;
        }
        if ([command isEqualToString:@"wake"]) {
            [self wake];
            completionHandler(messageData);
            return;
        }
        if ([command isEqualToString:@"state"]) {
            NSDictionary *state = @{
                @"up": @([self.wwClient valueForKey:@"up"] != nil && [[self.wwClient valueForKey:@"up"] boolValue]),
                @"sleepPaused": @([[self.wwClient valueForKey:@"sleepPaused"] boolValue]),
                @"reconnectPending": @([[self.wwClient valueForKey:@"reconnectPending"] boolValue]),
                @"failedAttempts": [self.wwClient valueForKey:@"failedAttempts"] ?: @0,
                @"pendingPacketIndex": [self.wwClient valueForKey:@"pendingPacketIndex"] ?: @0,
                @"pendingPacketCount": @([[self.wwClient valueForKey:@"pendingPackets"] count]),
                @"retryScheduled": @([[self.wwClient valueForKey:@"retryScheduled"] boolValue]),
                @"probeStage": [self.wwClient valueForKey:@"probeStage"] ?: @0,
                @"settingsGeneration": @(self.wwReadGeneration),
            };
            completionHandler([NSJSONSerialization dataWithJSONObject:state options:0 error:nil]);
            return;
        }
        if ([command isEqualToString:@"native-log"] || [command isEqualToString:@"tunnel-log"]) {
            NSURL *container = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:@"group.tr.com.srp.vpn"];
            NSString *name = [command isEqualToString:@"native-log"] ? @"ww-native-current.log" : @"srptunnel.log";
            NSString *base = container ? container.path : NSHomeDirectory();
            NSString *path = [base stringByAppendingPathComponent:[@"Library/" stringByAppendingString:name]];
            NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:path];
            unsigned long long size = file ? [file seekToEndOfFile] : 0;
            [file seekToFileOffset:size > 262144 ? size - 262144 : 0];
            NSData *data = file ? [file readDataToEndOfFile] : [NSData data];
            [file closeFile];
            completionHandler(data);
            return;
        }
        if ([command isEqualToString:@"fail-runtime"]) {
            extern int requestProgramShutdown(int);
            requestProgramShutdown(0);
            completionHandler(messageData);
            return;
        }
    }
#endif

    completionHandler(messageData);
}

- (void)sleepWithCompletionHandler:(void (^)(void))completionHandler {
    NSLog(@"[SRP] sleepWithCompletionHandler called (onSleepMode=%ld)", (long)self.onSleepMode);
    if (self.onSleepMode != 2) {
        [self.seClient pauseForSleep];
        [self.ocClient pauseForSleep];
        [self.sshClient pauseForSleep];
        [self.ovpnClient pauseForSleep];
        [self.wgClient pauseForSleep];
        [self.aeClient pauseForSleep];
        [self.wwClient pauseForSleep];
        if (self.sstpActive) [[lwIP shared] pauseForSleep];
    }
    completionHandler();
}

- (void)wake {
    NSLog(@"[SRP] wake called (onSleepMode=%ld)", (long)self.onSleepMode);
    [self.seClient wakeFromSleep];
    [self.ocClient wakeFromSleep];
    [self.sshClient wakeFromSleep];
    [self.ovpnClient wakeFromSleep];
    [self.wgClient wakeFromSleep];
    [self.aeClient wakeFromSleep];
    [self.wwClient wakeFromSleep];
    if (self.sstpActive) [[lwIP shared] wakeFromSleep];
}

- (void) setupUDPSession: (NEPacketTunnelNetworkSettings *) setting{
    self.reasserting = false;
    if(_TCPConnection != nil){
        self.reasserting = true;
        _TCPConnection = nil;
    }
    if(_UDPSession != nil){
        self.reasserting = true;
        _UDPSession = nil;
    }
    __weak PacketTunnelProvider *weakSelf  = self;
    [self setTunnelNetworkSettings:nil completionHandler:^(NSError * _Nullable error){
        if(error != nil){
            NSLog(@"[Y] Error set TunnelNetwork %@", error);
        }
        NSLog(@"[Y] setTunnelNetworkSettings %@", setting);
        __strong PacketTunnelProvider *strongSelf = weakSelf;
        [strongSelf setTunnelNetworkSettings:setting completionHandler:^(NSError * _Nullable error){
            if(error != nil){
                NSLog(@"[Y] %@", error);
            }
        }];
    }];
}

#if DEBUG
/// DEBUG: raw TLS probe from the EXTENSION process (no engine involved) to
/// isolate where cert interception happens (app vs extension path).
- (void)debugTlsProbe:(NSString *)ip {
    nw_parameters_t params = nw_parameters_create_secure_tcp(
        ^(nw_protocol_options_t tls) {
            sec_protocol_options_t sec = nw_tls_copy_sec_protocol_options(tls);
            sec_protocol_options_set_tls_server_name(sec, "consumer-masque.cloudflareclient.com");
            sec_protocol_options_set_verify_block(sec, ^(sec_protocol_metadata_t meta, sec_trust_t trust, sec_protocol_verify_complete_t complete) {
                SecTrustRef st = sec_trust_copy_ref(trust);
                NSMutableString *names = [NSMutableString new];
                if (st) {
                    CFArrayRef chain = SecTrustCopyCertificateChain(st);
                    for (id certObj in (__bridge NSArray *)chain) {
                        NSString *summary = (__bridge_transfer NSString *)SecCertificateCopySubjectSummary((__bridge SecCertificateRef)certObj);
                        [names appendFormat:@"<%@> ", summary ?: @"?"];
                    }
                    if (chain) CFRelease(chain);
                    CFRelease(st);
                }
                NSLog(@"[Y] ext-cert-probe %@ -> %@", ip, names);
                complete(true);
            }, dispatch_get_main_queue());
        },
        NW_PARAMETERS_DEFAULT_CONFIGURATION);
    nw_endpoint_t ep = nw_endpoint_create_host(ip.UTF8String, "443");
    nw_connection_t conn = nw_connection_create(ep, params);
    nw_connection_set_state_changed_handler(conn, ^(nw_connection_state_t state, nw_error_t error) {
        if (state == nw_connection_state_failed) {
            NSLog(@"[Y] ext-cert-probe %@ failed: %@", ip, error);
        }
    });
    nw_connection_set_queue(conn, dispatch_get_main_queue());
    nw_connection_start(conn);
}
#endif

@end
