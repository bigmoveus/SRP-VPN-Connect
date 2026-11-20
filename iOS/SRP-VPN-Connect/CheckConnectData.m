
#import "CheckConnectData.h"
#import "NodeModel.h"
#import "SRPEapConfig.h"
#import "SRPKeychain.h"
#import "../Core/SRPCore/SRPWaterWallChainConfig.h"

@implementation CheckConnectData

+(NSDictionary*)checkConnectParmer:(NodeModel*)modal {
    // A WaterWall profile from before the node editor (the live tests still describe one so) becomes its chain first:
    // its secrets move into the chain, and WaterWall's WireGuard mode becomes a WireGuard profile
    [self convertLegacyWaterWallProfile:modal];
    // Sync the secret into Keychain; the dict keeps the in-memory password
    // under @"password" because connectDirectly needs it for the sstp:// URI.
    if (modal.password.length > 0) {
        if (modal.passwordKey.length == 0) {
            modal.passwordKey = NSUUID.UUID.UUIDString;
        }
        [SRPKeychain setPassword:modal.password forKey:modal.passwordKey];
    }
    NSMutableDictionary *d = [@{@"type":modal.protocolType ?: @"sstp",
             @"desc":modal.desc ?: @"",
             @"node_id":modal.nodeId ?: @"",
             @"username":modal.username ?: @"",
             @"password":modal.password ?: @"",
             @"address":modal.server ?: @"",
             @"port":modal.port ?: @"443",
             @"chap_enable":@(modal.allowLegacyPapChap),
             @"mschap2_enable":@(modal.MSCHAP2),
             @"pap_enable":@(modal.allowLegacyPapChap),
             @"allowInsecure":@(modal.TLS),
             @"allow_legacy_papchap":@(modal.allowLegacyPapChap),
             @"auth_method":modal.authMethod,
             @"eapmschapv2_enable":@(modal.eapConfig.eapMschapv2Enabled),
             @"peap_enable":@(modal.eapConfig.peapEnabled),
             @"peap_require_cb":@(modal.eapConfig.peapRequireCryptoBinding),
             @"eapttls_enable":@(modal.eapConfig.ttlsInnerMethod != SRPTtlsInnerMethodDisabled),
             @"eapttls_inner":(modal.eapConfig.ttlsInnerMethod == SRPTtlsInnerMethodPAP) ? @"pap"
                 : (modal.eapConfig.ttlsInnerMethod == SRPTtlsInnerMethodCHAP) ? @"chap"
                 : @"eap",
             @"eapteap_enable":@(modal.eapConfig.teapEnabled),
             @"eap_identity_privacy":@(modal.eapConfig.identityPrivacyEnabled),
             @"eap_anonymous_identity":modal.eapConfig.anonymousIdentity ?: @"anonymous",
             @"eap_tls13":@(modal.eapConfig.eapTls13Enabled),
             @"eap_disable_legacy_tls":@(modal.eapConfig.disableLegacyEapTls),
             @"eap_config":[modal.eapConfig toDictionary],
            } mutableCopy];
    // SoftEther-specific fields
    if ([modal.protocolType isEqualToString:@"softether"]) {
        d[@"se_auth_method"] = modal.seAuthMethod ?: @"standardPassword";
        d[@"hub"] = modal.hubName.length > 0 ? modal.hubName : @"DEFAULT";
        d[@"se_connections"] = @(MAX(1, MIN(32, modal.seConnections)));
        d[@"se_udp_accel"] = @(modal.seUdpAcceleration);
        d[@"se_natt"] = @(modal.seNatTraversal);
        if (modal.seNatTHint.length > 0) {
            d[@"se_natt_hint"] = modal.seNatTHint;
        }
        if (modal.hostnameOverride.length > 0) {
            d[@"hostname_override"] = modal.hostnameOverride;
        }
        if (modal.proxyType.length > 0) {
            d[@"proxy_type"] = modal.proxyType;
        }
    }
    if ([modal.protocolType isEqualToString:@"openconnect"]) {
        d[@"oc_protocol"] = modal.ocProtocol.length > 0 ? modal.ocProtocol : @"anyconnect";
        if (modal.ocPath.length > 0) d[@"oc_path"] = modal.ocPath;
    }
    if ([modal.protocolType isEqualToString:@"ssh"]) {
        d[@"ssh_udp"] = @(modal.sshUdpRelay);
        if (modal.sshHostKey.length > 0) d[@"hostkey"] = modal.sshHostKey;
    }
    if ([modal.protocolType isEqualToString:@"openvpn"]) {
        d[@"ovpn_profile"] = modal.ovpnProfile ?: @"";
        d[@"stunnel"] = @(modal.ovpnStunnelEnabled);
        if (modal.ovpnStunnelHost.length > 0) d[@"stunnel_host"] = modal.ovpnStunnelHost;
        if (modal.ovpnStunnelPort.length > 0) d[@"stunnel_port"] = modal.ovpnStunnelPort;
        if (modal.ovpnStunnelSNI.length > 0) d[@"stunnel_sni"] = modal.ovpnStunnelSNI;
        if (modal.ovpnStunnelCA.length > 0) d[@"stunnel_ca"] = modal.ovpnStunnelCA;
    }
    if ([modal.protocolType isEqualToString:@"aether"]) {
        if (modal.aetherTransport.length > 0) d[@"ae_transport"] = modal.aetherTransport;
        if (modal.aetherScan.length > 0) d[@"ae_scan"] = modal.aetherScan;
        if (modal.aetherLicense.length > 0) d[@"ae_license"] = modal.aetherLicense;
        if (modal.aetherTor.length > 0) d[@"ae_tor"] = modal.aetherTor;
    }
    if ([modal.protocolType isEqualToString:@"waterwall"]) {
        if (modal.waterwallChainJSON.length == 0) {
            modal.waterwallChainJSON = [SRPWaterWallNodeChain JSONWithDocument:[SRPWaterWallNodeChain emptyDocument]];
        }
        // The chain holds UUIDs and passwords: the tunnel reads it from the Keychain, as it reads the other secrets
        if (modal.waterwallChainRef.length == 0) modal.waterwallChainRef = NSUUID.UUID.UUIDString;
        [SRPKeychain setPassword:modal.waterwallChainJSON forKey:modal.waterwallChainRef];
        d[@"ww_chain_ref"] = modal.waterwallChainRef;
        if (modal.waterwallProbeIP.length > 0) d[@"ww_probe_ip"] = modal.waterwallProbeIP;
        if (modal.waterwallDNSProbeIP.length > 0) d[@"ww_dns_probe_ip"] = modal.waterwallDNSProbeIP;
        d[@"ww_fake_dns"] = @(modal.waterwallFakeDNS);
        d[@"ww_auto_switch"] = @(modal.waterwallAutoSwitch);
    }
    if ([modal.protocolType isEqualToString:@"wireguard"] || [modal.protocolType isEqualToString:@"amnezia"]) {
        d[@"wg_conf"] = [modal wgEffectiveConfig] ?: @"";
        if (modal.wgPrivateKey.length > 0) d[@"wg_private_key"] = modal.wgPrivateKey;
        if (modal.wgPeerPublicKey.length > 0) d[@"wg_peer_public_key"] = modal.wgPeerPublicKey;
        if (modal.wgPresharedKey.length > 0) d[@"wg_preshared_key"] = modal.wgPresharedKey;
        if (modal.wgAddress.length > 0) d[@"wg_address"] = modal.wgAddress;
        if (modal.wgDNS.length > 0) d[@"wg_dns"] = modal.wgDNS;
        if (modal.wgAllowedIPs.length > 0) d[@"wg_allowed_ips"] = modal.wgAllowedIPs;
        if (modal.wgKeepalive > 0) d[@"wg_keepalive"] = @(modal.wgKeepalive);
        if (modal.wgJc > 0) d[@"wg_jc"] = @(modal.wgJc);
        if (modal.wgJmin > 0) d[@"wg_jmin"] = @(modal.wgJmin);
        if (modal.wgJmax > 0) d[@"wg_jmax"] = @(modal.wgJmax);
        if (modal.wgS1 > 0) d[@"wg_s1"] = @(modal.wgS1);
        if (modal.wgS2 > 0) d[@"wg_s2"] = @(modal.wgS2);
        if (modal.wgS3 > 0) d[@"wg_s3"] = @(modal.wgS3);
        if (modal.wgS4 > 0) d[@"wg_s4"] = @(modal.wgS4);
        if (modal.wgI1.length > 0) d[@"wg_i1"] = modal.wgI1;
        if (modal.wgI2.length > 0) d[@"wg_i2"] = modal.wgI2;
        if (modal.wgI3.length > 0) d[@"wg_i3"] = modal.wgI3;
        if (modal.wgI4.length > 0) d[@"wg_i4"] = modal.wgI4;
        if (modal.wgI5.length > 0) d[@"wg_i5"] = modal.wgI5;
        if (modal.wgH1.length > 0) d[@"wg_h1"] = modal.wgH1;
        if (modal.wgH2.length > 0) d[@"wg_h2"] = modal.wgH2;
        if (modal.wgH3.length > 0) d[@"wg_h3"] = modal.wgH3;
        if (modal.wgH4.length > 0) d[@"wg_h4"] = modal.wgH4;
        if (modal.wgContentPaddingAddition.length > 0) d[@"wg_content_padding"] = modal.wgContentPaddingAddition;
        if (modal.wgRekeyAfterTime.length > 0) d[@"wg_rekey_after_time"] = modal.wgRekeyAfterTime;
        if (modal.wgRekeyTimeout.length > 0) d[@"wg_rekey_timeout"] = modal.wgRekeyTimeout;
        if (modal.wgRejectAfterTime.length > 0) d[@"wg_reject_after_time"] = modal.wgRejectAfterTime;
        if (modal.wgKeepaliveTimeout.length > 0) d[@"wg_keepalive_timeout"] = modal.wgKeepaliveTimeout;
        if (modal.wgMaxHandshakeAttempts.length > 0) d[@"wg_max_handshake_attempts"] = modal.wgMaxHandshakeAttempts;
        if (modal.wgRandomTrailers) d[@"wg_random_trailers"] = @YES;
        if (modal.wgDisableCookies) d[@"wg_disable_cookies"] = @YES;
    }
    if (modal.passwordKey.length > 0) {
        d[@"password_key"] = modal.passwordKey;
    }
    // Certificate authentication: only the Keychain reference crosses into
    // the profile/tunnel configuration — never the .p12 blob itself.
    BOOL certAuth = ([modal.authMethod isEqualToString:@"certificate"] ||
                     ([modal.protocolType isEqualToString:@"softether"] &&
                      [modal.seAuthMethod isEqualToString:@"certificate"]))
                    && modal.certKey.length > 0;
    d[@"cert_auth"] = @(certAuth);
    if (modal.certKey.length > 0) {
        d[@"cert_key"] = modal.certKey;
    }
    if (modal.certName.length > 0) {
        d[@"cert_name"] = modal.certName;
    }
    // Proxy settings (outer TCP path). The proxy password is synced into the
    // Keychain like the main password; only its reference is persisted.
    if (modal.proxyPassword.length > 0) {
        if (modal.proxyPasswordRef.length == 0) {
            modal.proxyPasswordRef = NSUUID.UUID.UUIDString;
        }
        [SRPKeychain setPassword:modal.proxyPassword forKey:modal.proxyPasswordRef];
    }
    NSString *proxyMode = modal.proxyMode == 1 ? @"manual" : modal.proxyMode == 2 ? @"auto" : @"none";
    d[@"proxy_mode"] = proxyMode;
    if (modal.proxyAddress.length > 0) d[@"proxy_host"] = modal.proxyAddress;
    if (modal.proxyPort.length > 0) d[@"proxy_port"] = modal.proxyPort;
    if (modal.proxyUsername.length > 0) d[@"proxy_user"] = modal.proxyUsername;
    if (modal.proxyPasswordRef.length > 0) d[@"proxy_pass_ref"] = modal.proxyPasswordRef;
    if (modal.pacURL.length > 0) d[@"pac_url"] = modal.pacURL;
    // OPTIONS section
    d[@"disable_legacy_outer_tls"] = @(modal.disableLegacyOuterTls);
    d[@"tls_frag"] = @(modal.tlsFragMode);
    if (modal.tlsFragFirst > 0) d[@"tls_frag_first"] = @(modal.tlsFragFirst);
    if (modal.tlsFragFollowing > 0) d[@"tls_frag_following"] = @(modal.tlsFragFollowing);
    d[@"auto_reconnect"] = @(modal.autoReconnect);
    d[@"retry_times"] = @(modal.retryTimes);
    d[@"switch_to_wifi"] = @(modal.switchToWifi);
    d[@"on_sleep"] = modal.onSleep == 0 ? @"off" : modal.onSleep == 1 ? @"pause" : @"stay";
    d[@"log_level"] = modal.logLevel == 2 ? @"debug" : modal.logLevel == 1 ? @"expert" : @"normal";
    // Custom SNI
    d[@"custom_sni_enabled"] = @(modal.customSniEnabled);
    if (modal.customSni.length > 0) {
        d[@"sni"] = modal.customSni;
    }
    return d;
}

static NSString *SRPServerKey(NSString *server) {
    return [server stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].lowercaseString ?: @"";
}

// The chain of a WaterWall profile, or nil when it is invalid or has no server of its own to share (a direct chain).
static NSDictionary *SRPSwitchableDocument(NodeModel *profile) {
    NSDictionary *document = [SRPWaterWallNodeChain documentWithJSON:profile.waterwallChainJSON error:nil];
    return document != nil && [SRPWaterWallNodeChain endpointsOfDocument:document].count > 0 ? document : nil;
}

+(NSArray<NSDictionary*>*)waterWallFallbacksForProfile:(NodeModel*)profile amongProfiles:(NSArray<NodeModel*>*)profiles {
    static const NSUInteger limit = 8;
    NSString *server = SRPServerKey(profile.server);
    if (![profile.protocolType isEqualToString:@"waterwall"] || !profile.waterwallAutoSwitch || server.length == 0) return @[];
    [self checkConnectParmer:profile];
    NSDictionary *ownDocument = SRPSwitchableDocument(profile);
    if (ownDocument == nil) return @[];
    BOOL udp = [SRPWaterWallNodeChain documentUsesUDPCarrier:ownDocument];
    NSMutableArray<NSDictionary*> *otherCarrier = [NSMutableArray new];
    NSMutableArray<NSDictionary*> *sameCarrier = [NSMutableArray new];
    for (NodeModel *candidate in profiles) {
        if (candidate == profile || [candidate.nodeId isEqualToString:profile.nodeId]) continue;
        if (![candidate.protocolType isEqualToString:@"waterwall"] || ![SRPServerKey(candidate.server) isEqualToString:server]) continue;
        // Fallbacks travel with Keychain references only, never a plaintext secret.
        NSMutableDictionary *parameters = [[self checkConnectParmer:candidate] mutableCopy];
        [parameters removeObjectsForKeys:@[@"password", @"ww_outer_secret"]];
        NSDictionary *document = SRPSwitchableDocument(candidate);
        // A copy of the selected profile connects the same way, so it cannot take over.
        if (document == nil || [candidate.waterwallChainJSON isEqualToString:profile.waterwallChainJSON]) continue;
        [([SRPWaterWallNodeChain documentUsesUDPCarrier:document] != udp ? otherCarrier : sameCarrier) addObject:parameters];
    }
    NSArray<NSDictionary*> *ordered = [otherCarrier arrayByAddingObjectsFromArray:sameCarrier];
    return ordered.count > limit ? [ordered subarrayWithRange:NSMakeRange(0, limit)] : ordered;
}

+(NSDictionary*)connectParametersForProfile:(NodeModel*)profile amongProfiles:(NSArray<NodeModel*>*)profiles {
    NSMutableDictionary *parameters = [[self checkConnectParmer:profile] mutableCopy];
    NSArray<NSDictionary*> *fallbacks = [self waterWallFallbacksForProfile:profile amongProfiles:profiles];
    if (fallbacks.count > 0) parameters[@"ww_fallbacks"] = fallbacks;
    return parameters;
}

+(NodeModel*)getModalForDic:(NSDictionary*)selectDic {
    NSString *type = selectDic[@"type"];
    if([type isEqualToString:@"sstp"] || [type isEqualToString:@"softether"] || [type isEqualToString:@"openconnect"] || [type isEqualToString:@"ssh"] || [type isEqualToString:@"openvpn"] || [type isEqualToString:@"wireguard"] || [type isEqualToString:@"amnezia"] || [type isEqualToString:@"aether"] || [type isEqualToString:@"waterwall"]) {
        NodeModel * modal = [NodeModel new];
        modal.protocolType = type;
        modal.nodeName = [type isEqualToString:@"softether"] ? @"SoftEther VPN"
                       : [type isEqualToString:@"openconnect"] ? @"SSL VPN"
                       : [type isEqualToString:@"ssh"] ? @"SSH VPN"
                       : [type isEqualToString:@"openvpn"] ? @"OpenVPN"
                       : [type isEqualToString:@"wireguard"] ? @"WireGuard VPN"
                       : [type isEqualToString:@"amnezia"] ? @"AmneziaWG VPN"
                       : [type isEqualToString:@"aether"] ? @"Aether VPN"
                       : [type isEqualToString:@"waterwall"] ? @"WaterWall VPN" : @"SSTP VPN";
        // SoftEther-specific fields (migration-safe defaults)
        if (selectDic[@"se_auth_method"] != nil) {
            modal.seAuthMethod = selectDic[@"se_auth_method"];
        }
        modal.hubName = selectDic[@"hub"];
        modal.hostnameOverride = selectDic[@"hostname_override"];
        if (selectDic[@"se_connections"] != nil) {
            modal.seConnections = [selectDic[@"se_connections"] integerValue];
        }
        if (selectDic[@"se_udp_accel"] != nil) {
            modal.seUdpAcceleration = [selectDic[@"se_udp_accel"] boolValue];
        }
        if (selectDic[@"se_natt"] != nil) {
            modal.seNatTraversal = [selectDic[@"se_natt"] boolValue];
        }
        modal.seNatTHint = selectDic[@"se_natt_hint"];
        modal.proxyType = selectDic[@"proxy_type"];
        modal.ocProtocol = selectDic[@"oc_protocol"];
        modal.ocPath = selectDic[@"oc_path"];
        // SSH engine fields (migration-safe: absent = relay off, no pinned key)
        if (selectDic[@"ssh_udp"] != nil) {
            modal.sshUdpRelay = [selectDic[@"ssh_udp"] boolValue];
        }
        modal.sshHostKey = selectDic[@"hostkey"];
        // OpenVPN engine fields (migration-safe: absent = no profile, stunnel off)
        modal.ovpnProfile = selectDic[@"ovpn_profile"];
        if (selectDic[@"stunnel"] != nil) {
            modal.ovpnStunnelEnabled = [selectDic[@"stunnel"] boolValue];
        }
        modal.ovpnStunnelHost = selectDic[@"stunnel_host"];
        modal.ovpnStunnelPort = selectDic[@"stunnel_port"];
        modal.ovpnStunnelSNI = selectDic[@"stunnel_sni"];
        modal.ovpnStunnelCA = selectDic[@"stunnel_ca"];
        // WireGuard: imported wg-quick config (migration-safe: absent = none)
        modal.wgConfig = selectDic[@"wg_conf"];
        modal.wgPrivateKey = selectDic[@"wg_private_key"];
        modal.wgPeerPublicKey = selectDic[@"wg_peer_public_key"];
        modal.wgPresharedKey = selectDic[@"wg_preshared_key"];
        modal.wgAddress = selectDic[@"wg_address"];
        modal.wgDNS = selectDic[@"wg_dns"];
        modal.wgAllowedIPs = selectDic[@"wg_allowed_ips"];
        if (selectDic[@"wg_keepalive"] != nil) {
            modal.wgKeepalive = [selectDic[@"wg_keepalive"] integerValue];
        }
        modal.wgJc = [selectDic[@"wg_jc"] integerValue];
        modal.wgJmin = [selectDic[@"wg_jmin"] integerValue];
        modal.wgJmax = [selectDic[@"wg_jmax"] integerValue];
        modal.wgS1 = [selectDic[@"wg_s1"] integerValue];
        modal.wgS2 = [selectDic[@"wg_s2"] integerValue];
        modal.wgS3 = [selectDic[@"wg_s3"] integerValue];
        modal.wgS4 = [selectDic[@"wg_s4"] integerValue];
        modal.wgI1 = selectDic[@"wg_i1"];
        modal.wgI2 = selectDic[@"wg_i2"];
        modal.wgI3 = selectDic[@"wg_i3"];
        modal.wgI4 = selectDic[@"wg_i4"];
        modal.wgI5 = selectDic[@"wg_i5"];
        modal.aetherTransport = selectDic[@"ae_transport"];
        modal.aetherScan = selectDic[@"ae_scan"];
        // The WARP+ license comes from the Keychain; older saves kept it in the profile
        modal.aetherLicense = selectDic[@"ae_license"];
        modal.aetherLicenseRef = selectDic[@"ae_license_ref"];
        if (modal.aetherLicenseRef.length > 0) modal.aetherLicense = [SRPKeychain passwordForKey:modal.aetherLicenseRef];
        modal.aetherTor = selectDic[@"ae_tor"];
        modal.waterwallChainRef = selectDic[@"ww_chain_ref"];
        if (modal.waterwallChainRef.length > 0) modal.waterwallChainJSON = [SRPKeychain passwordForKey:modal.waterwallChainRef];
        // The former form's settings, read only to convert a profile made before the node editor
        modal.waterwallPreset = selectDic[@"ww_preset"];
        modal.waterwallConfigJSON = selectDic[@"ww_config"];
        modal.waterwallSecretRef = selectDic[@"ww_secret_ref"];
        modal.waterwallOuterSecretRef = selectDic[@"ww_outer_secret_ref"];
        modal.waterwallOuterSecret = selectDic[@"ww_outer_secret"];
        if (modal.waterwallOuterSecret.length == 0 && modal.waterwallOuterSecretRef.length > 0) {
            modal.waterwallOuterSecret = [SRPKeychain passwordForKey:modal.waterwallOuterSecretRef];
        }
        modal.waterwallProbeIP = selectDic[@"ww_probe_ip"];
        modal.waterwallDNSProbeIP = selectDic[@"ww_dns_probe_ip"];
        modal.waterwallFakeDNS = selectDic[@"ww_fake_dns"] != nil ? [selectDic[@"ww_fake_dns"] boolValue] : YES;
        modal.waterwallSmartRouting = [selectDic[@"ww_smart_routing"] boolValue];
        modal.waterwallAutoSwitch = selectDic[@"ww_auto_switch"] != nil ? [selectDic[@"ww_auto_switch"] boolValue] : YES;
        // H1-H4 were numbers before ranges were possible
        NSString* (^headerValue)(id) = ^NSString *(id value) {
            if ([value isKindOfClass:NSNumber.class]) return [value integerValue] > 0 ? [value stringValue] : nil;
            return [value isKindOfClass:NSString.class] && [value length] > 0 ? value : nil;
        };
        modal.wgH1 = headerValue(selectDic[@"wg_h1"]);
        modal.wgH2 = headerValue(selectDic[@"wg_h2"]);
        modal.wgH3 = headerValue(selectDic[@"wg_h3"]);
        modal.wgH4 = headerValue(selectDic[@"wg_h4"]);
        modal.wgContentPaddingAddition = selectDic[@"wg_content_padding"];
        modal.wgRekeyAfterTime = selectDic[@"wg_rekey_after_time"];
        modal.wgRekeyTimeout = selectDic[@"wg_rekey_timeout"];
        modal.wgRejectAfterTime = selectDic[@"wg_reject_after_time"];
        modal.wgKeepaliveTimeout = selectDic[@"wg_keepalive_timeout"];
        modal.wgMaxHandshakeAttempts = selectDic[@"wg_max_handshake_attempts"];
        modal.wgRandomTrailers = [selectDic[@"wg_random_trailers"] boolValue];
        modal.wgDisableCookies = [selectDic[@"wg_disable_cookies"] boolValue];
        modal.desc = selectDic[@"desc"];
        // Stable identity; legacy profiles without one get a fresh id (migration
        // persists it on the next save).
        if ([selectDic[@"node_id"] length] > 0) {
            modal.nodeId = selectDic[@"node_id"];
        }
        modal.username =selectDic[@"username"];
        modal.server =selectDic[@"address"];
        modal.port =selectDic[@"port"];
        modal.TLS =[selectDic[@"allowInsecure"] boolValue];
        modal.MSCHAP2 =[selectDic[@"mschap2_enable"] boolValue];
        // Legacy PAP/CHAP properties kept for migration only
        modal.PAP =[selectDic[@"pap_enable"] boolValue];
        modal.CHAP =[selectDic[@"chap_enable"] boolValue];
        // Migration: absent allow_legacy_papchap -> old pap_enable || chap_enable
        if (selectDic[@"allow_legacy_papchap"] != nil) {
            modal.allowLegacyPapChap = [selectDic[@"allow_legacy_papchap"] boolValue];
        }
        else {
            modal.allowLegacyPapChap = modal.PAP || modal.CHAP;
        }
        if (selectDic[@"auth_method"] != nil) {
            modal.authMethod = selectDic[@"auth_method"];
        }
        modal.certKey = selectDic[@"cert_key"];
        modal.certName = selectDic[@"cert_name"];
        // Proxy settings; migration-safe default is "none" when absent
        NSString *pm = selectDic[@"proxy_mode"];
        modal.proxyMode = [pm isEqualToString:@"manual"] ? 1 : [pm isEqualToString:@"auto"] ? 2 : 0;
        modal.proxyAddress = selectDic[@"proxy_host"];
        modal.proxyPort = selectDic[@"proxy_port"];
        modal.proxyUsername = selectDic[@"proxy_user"];
        modal.pacURL = selectDic[@"pac_url"];
        modal.proxyPasswordRef = selectDic[@"proxy_pass_ref"];
        if (modal.proxyPasswordRef.length > 0) {
            modal.proxyPassword = [SRPKeychain passwordForKey:modal.proxyPasswordRef];
        }
        // OPTIONS section; migration-safe defaults match a fresh profile
        if (selectDic[@"disable_legacy_outer_tls"] != nil) {
            modal.disableLegacyOuterTls = [selectDic[@"disable_legacy_outer_tls"] boolValue];
        }
        // Migration: old builds stored a boolean (1 -> manual)
        modal.tlsFragMode = [selectDic[@"tls_frag"] integerValue];
        modal.tlsFragFirst = [selectDic[@"tls_frag_first"] integerValue];
        modal.tlsFragFollowing = [selectDic[@"tls_frag_following"] integerValue];
        if (selectDic[@"auto_reconnect"] != nil) {
            modal.autoReconnect = [selectDic[@"auto_reconnect"] boolValue];
        }
        if (selectDic[@"retry_times"] != nil) {
            modal.retryTimes = [selectDic[@"retry_times"] integerValue];
        }
        if (selectDic[@"switch_to_wifi"] != nil) {
            modal.switchToWifi = [selectDic[@"switch_to_wifi"] boolValue];
        }
        NSString *onSleep = selectDic[@"on_sleep"];
        if (onSleep != nil) {
            modal.onSleep = [onSleep isEqualToString:@"off"] ? 0 : [onSleep isEqualToString:@"pause"] ? 1 : 2;
        }
        NSString *logLevel = selectDic[@"log_level"];
        if (logLevel != nil) {
            modal.logLevel = [logLevel isEqualToString:@"debug"] ? 2 : [logLevel isEqualToString:@"expert"] ? 1 : 0;
        }
        // Custom SNI; migration-safe default is disabled
        if (selectDic[@"custom_sni_enabled"] != nil) {
            modal.customSniEnabled = [selectDic[@"custom_sni_enabled"] boolValue];
        }
        modal.customSni = selectDic[@"sni"];
        // Migration: absent eap_config -> defaults
        modal.eapConfig = [SRPEapConfig fromDictionary:selectDic[@"eap_config"]];
        // Password: prefer Keychain via password_key; migrate plaintext if present
        modal.passwordKey = selectDic[@"password_key"];
        if ([type isEqualToString:@"waterwall"] && modal.passwordKey.length == 0 && modal.waterwallSecretRef.length > 0) {
            modal.passwordKey = modal.waterwallSecretRef;
        }
        if (modal.passwordKey.length > 0) {
            modal.password = [SRPKeychain passwordForKey:modal.passwordKey];
        }
        else if ([selectDic[@"password"] length] > 0) {
            // Legacy plaintext password -> move to Keychain, keep in memory
            modal.password = selectDic[@"password"];
            modal.passwordKey = NSUUID.UUID.UUIDString;
            [SRPKeychain setPassword:modal.password forKey:modal.passwordKey];
        }
        else {
            modal.password = @"";
        }
        // WireGuard keys come from the Keychain. Older saves kept them in the profile, together with the
        // config generated from the manual fields as if it had been imported.
        modal.wgSecretRef = selectDic[@"wg_secret_ref"];
        NSString *storedKeys = modal.wgSecretRef.length > 0 ? [SRPKeychain passwordForKey:modal.wgSecretRef] : nil;
        NSDictionary *wireGuard = storedKeys.length > 0 ?
            [NSJSONSerialization JSONObjectWithData:[storedKeys dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] : nil;
        if ([wireGuard isKindOfClass:NSDictionary.class]) {
            modal.wgConfig = wireGuard[@"conf"];
            modal.wgPrivateKey = wireGuard[@"private_key"];
            modal.wgPresharedKey = wireGuard[@"preshared_key"];
            modal.wgHeaderProtectionKey = wireGuard[@"header_protection_key"];
        } else if (modal.wgConfig.length > 0) {
            NSString *saved = modal.wgConfig;
            modal.wgConfig = nil;
            if (![saved isEqualToString:[modal wgEffectiveConfig]]) modal.wgConfig = saved;
        }
        return modal;

    }
    return nil;
}

// The Endpoint of a WireGuard file, as host and port
static BOOL SRPWireGuardEndpoint(NSString *config, NSString **host, NSString **port) {
    for (NSString *line in [config componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSRange equals = [line rangeOfString:@"="];
        if (equals.location == NSNotFound) continue;
        NSString *key = [[line substringToIndex:equals.location] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if ([key caseInsensitiveCompare:@"Endpoint"] != NSOrderedSame) continue;
        NSString *value = [[line substringFromIndex:equals.location + 1] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        NSRange colon = [value rangeOfString:@":" options:NSBackwardsSearch];
        if (colon.location == NSNotFound || colon.location == 0) return NO;
        *host = [[value substringToIndex:colon.location] stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"[]"]];
        *port = [value substringFromIndex:colon.location + 1];
        return YES;
    }
    return NO;
}

+(BOOL)convertLegacyWaterWallProfile:(NodeModel*)modal {
    if (![modal.protocolType isEqualToString:@"waterwall"]) return NO;
    BOOL legacy = modal.waterwallConfigJSON.length > 0 || modal.waterwallPreset.length > 0 ||
                  (modal.waterwallChainJSON.length == 0 && modal.waterwallChainRef.length == 0);
    if (!legacy) return NO;
    // An empty config reads as the default one, so a stored preset is asked first; an invalid config converts to nothing
    NSDictionary *configuration = modal.waterwallConfigJSON.length > 0 ? [SRPWaterWallChainConfig configurationWithJSON:modal.waterwallConfigJSON] :
        modal.waterwallPreset.length > 0 ? [SRPWaterWallChainConfig configurationFromLegacyPreset:modal.waterwallPreset] :
        [SRPWaterWallChainConfig defaultConfiguration];
    if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration]) {
        // WaterWall's WireGuard mode ends its chain in the packet device, which a leading input hint cannot express: the
        // profile becomes a WireGuard profile with the same keys, and with the Endpoint its imported file had
        NSString *host = nil, *port = nil;
        if (modal.wgConfig.length > 0 && SRPWireGuardEndpoint(modal.wgConfig, &host, &port)) {
            modal.server = host;
            modal.port = port;
        }
        modal.protocolType = @"wireguard";
        modal.nodeName = nil;
        [self clearLegacyWaterWallSettingsOfProfile:modal];
        return YES;
    }
    NSDictionary *options = @{@"ww_fake_dns": @(modal.waterwallFakeDNS), @"ww_smart_routing": @(modal.waterwallSmartRouting),
                              @"tls_frag": @(modal.tlsFragMode), @"tls_frag_first": @(modal.tlsFragFirst),
                              @"tls_frag_following": @(modal.tlsFragFollowing), @"username": modal.username ?: @"",
                              @"log_level": modal.logLevel == 2 ? @"debug" : modal.logLevel == 1 ? @"expert" : @"normal"};
    NSDictionary *document = [SRPWaterWallNodeChain documentForConfiguration:configuration
                                                                      server:modal.server ?: @""
                                                                        port:modal.port.integerValue
                                                                         sni:modal.customSniEnabled ? modal.customSni : nil
                                                                   verifyTLS:!modal.TLS
                                                                      secret:modal.password
                                                                 outerSecret:modal.waterwallOuterSecret
                                                                     options:options];
    if (document == nil) {
        // A profile the form could not connect either keeps its former settings until a chain is saved for it
        if (modal.waterwallChainJSON.length == 0) {
            modal.waterwallChainJSON = [SRPWaterWallNodeChain JSONWithDocument:[SRPWaterWallNodeChain emptyDocument]];
        }
        return NO;
    }
    modal.waterwallChainJSON = [SRPWaterWallNodeChain JSONWithDocument:document];
    // The GeoIP update link is app-wide now (Settings → GeoIP Database): the first profile that had one gives it
    NSDictionary *geoIP = [configuration[@"geoip"] isKindOfClass:NSDictionary.class] ? configuration[@"geoip"] : nil;
    if ([geoIP[@"update-url"] isKindOfClass:NSString.class] && [geoIP[@"update-url"] length] > 0 &&
        [NSUserDefaults.standardUserDefaults stringForKey:@"SRPGeoIPUpdateURL"].length == 0) {
        [NSUserDefaults.standardUserDefaults setObject:geoIP[@"update-url"] forKey:@"SRPGeoIPUpdateURL"];
    }
    // A direct chain had no fake DNS; the option now shapes only the input SRP supplies
    if ([SRPWaterWallChainConfig isDirectConfiguration:configuration]) modal.waterwallFakeDNS = NO;
    [self clearLegacyWaterWallSettingsOfProfile:modal];
    [modal syncWaterWallServer];
    return YES;
}

+(void)clearLegacyWaterWallSettingsOfProfile:(NodeModel*)modal {
    // The UUID, password and outer secret are in the chain now, which the Keychain keeps as a whole
    for (NSString *key in @[modal.passwordKey ?: @"", modal.waterwallSecretRef ?: @"", modal.waterwallOuterSecretRef ?: @""]) {
        if (key.length > 0) [SRPKeychain deletePasswordForKey:key];
    }
    modal.password = nil;
    modal.passwordKey = nil;
    modal.waterwallSecretRef = nil;
    modal.waterwallOuterSecret = nil;
    modal.waterwallOuterSecretRef = nil;
    modal.waterwallConfigJSON = nil;
    modal.waterwallPreset = nil;
    modal.waterwallSmartRouting = NO;
    modal.tlsFragMode = 0;
    modal.tlsFragFirst = 0;
    modal.tlsFragFollowing = 0;
    modal.customSniEnabled = NO;
    modal.customSni = nil;
    modal.username = nil;
}

+(NSDictionary*)storedParametersForProfile:(NodeModel*)modal {
    NSMutableDictionary *d = [[self checkConnectParmer:modal] mutableCopy];
    BOOL wireGuard = d[@"wg_conf"] != nil;
    // Never persist plaintext credentials — they live in the Keychain.
    [d removeObjectsForKeys:@[@"password", @"ww_outer_secret", @"wg_conf", @"wg_private_key", @"wg_preshared_key", @"ae_license"]];
    NSMutableDictionary *keys = [NSMutableDictionary new];
    if (wireGuard) {
        // wg_conf above is the effective config; only an imported one is kept, so manual fields stay editable
        if (modal.wgConfig.length > 0) keys[@"conf"] = modal.wgConfig;
        if (modal.wgPrivateKey.length > 0) keys[@"private_key"] = modal.wgPrivateKey;
        if (modal.wgPresharedKey.length > 0) keys[@"preshared_key"] = modal.wgPresharedKey;
        if (modal.wgHeaderProtectionKey.length > 0) keys[@"header_protection_key"] = modal.wgHeaderProtectionKey;
    }
    if (keys.count > 0) {
        if (modal.wgSecretRef.length == 0) modal.wgSecretRef = NSUUID.UUID.UUIDString;
        NSData *json = [NSJSONSerialization dataWithJSONObject:keys options:0 error:nil];
        [SRPKeychain setPassword:[[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] forKey:modal.wgSecretRef];
        d[@"wg_secret_ref"] = modal.wgSecretRef;
    } else if (modal.wgSecretRef.length > 0) {
        [SRPKeychain deletePasswordForKey:modal.wgSecretRef];
        modal.wgSecretRef = nil;
    }
    // An Aether profile's WARP+ license: the Keychain has it, the list only its key
    if ([modal.protocolType isEqualToString:@"aether"] && modal.aetherLicense.length > 0) {
        if (modal.aetherLicenseRef.length == 0) modal.aetherLicenseRef = NSUUID.UUID.UUIDString;
        [SRPKeychain setPassword:modal.aetherLicense forKey:modal.aetherLicenseRef];
        d[@"ae_license_ref"] = modal.aetherLicenseRef;
    } else if (modal.aetherLicenseRef.length > 0) {
        [SRPKeychain deletePasswordForKey:modal.aetherLicenseRef];
        modal.aetherLicenseRef = nil;
    }
    if (![modal.protocolType isEqualToString:@"waterwall"] && modal.waterwallChainRef.length > 0) {
        // A profile moved to another protocol leaves its chain
        [SRPKeychain deletePasswordForKey:modal.waterwallChainRef];
        modal.waterwallChainRef = nil;
        modal.waterwallChainJSON = nil;
    }
    if ([modal.protocolType isEqualToString:@"waterwall"] && (modal.waterwallConfigJSON.length > 0 || modal.waterwallPreset.length > 0)) {
        // A profile whose conversion failed keeps its former settings until a chain is saved for it
        if (modal.waterwallConfigJSON.length > 0) d[@"ww_config"] = modal.waterwallConfigJSON;
        if (modal.waterwallPreset.length > 0) d[@"ww_preset"] = modal.waterwallPreset;
        if (modal.passwordKey.length > 0) d[@"ww_secret_ref"] = modal.passwordKey;
        if (modal.waterwallOuterSecretRef.length > 0) d[@"ww_outer_secret_ref"] = modal.waterwallOuterSecretRef;
        d[@"ww_smart_routing"] = @(modal.waterwallSmartRouting);
    }
    return d;
}

+(void)deleteStoredSecretsOfProfile:(NodeModel*)modal {
    for (NSString *key in @[modal.passwordKey ?: @"", modal.waterwallSecretRef ?: @"", modal.waterwallOuterSecretRef ?: @"", modal.waterwallChainRef ?: @"",
                            modal.proxyPasswordRef ?: @"", modal.wgSecretRef ?: @"", modal.aetherLicenseRef ?: @""]) {
        if (key.length > 0) [SRPKeychain deletePasswordForKey:key];
    }
}

+(NSDictionary<NSString*, NSString*>*)splitSslVpnAddress:(NSString*)text {
    NSString *rest = [text ?: @"" stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSRange scheme = [rest rangeOfString:@"^https?://" options:NSRegularExpressionSearch | NSCaseInsensitiveSearch];
    if (scheme.location != NSNotFound) rest = [rest substringFromIndex:NSMaxRange(scheme)];
    NSMutableDictionary *parts = [NSMutableDictionary dictionary];
    NSString *hostPort = rest;
    NSRange cut = [rest rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"/?"]];
    if (cut.location != NSNotFound) {
        hostPort = [rest substringToIndex:cut.location];
        NSString *path = [rest substringFromIndex:cut.location];
        if (![path isEqualToString:@"/"]) parts[@"path"] = path;
    }
    // host:port, or [IPv6]:port; a bare IPv6 address has more than one colon and no port
    static NSRegularExpression *hostAndPort;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        hostAndPort = [NSRegularExpression regularExpressionWithPattern:@"^(\\[[^\\]]+\\]|[^:]+):(\\d{1,5})$" options:0 error:nil];
    });
    NSTextCheckingResult *match = [hostAndPort firstMatchInString:hostPort options:0 range:NSMakeRange(0, hostPort.length)];
    parts[@"server"] = match ? [hostPort substringWithRange:[match rangeAtIndex:1]] : hostPort;
    if (match) parts[@"port"] = [hostPort substringWithRange:[match rangeAtIndex:2]];
    return parts;
}

@end
