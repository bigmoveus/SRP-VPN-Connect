
#import "NodeModel.h"
#import "CheckConnectData.h"
#import "SRPEapConfig.h"

@implementation NodeModel
static NodeModel * modal = nil;

- (instancetype)init {
    self = [super init];
    if (self) {
        // OPTIONS defaults
        _autoReconnect = YES;
        _switchToWifi = YES;
        _onSleep = 2;    // stay
        _logLevel = 0;   // normal
        _protocolType = @"sstp";
        _seAuthMethod = @"standardPassword";
        _seConnections = 1;
        _ocProtocol = @"anyconnect";
        _nodeId = NSUUID.UUID.UUIDString;
    }
    return self;
}

+(instancetype)shareInstance {
    @synchronized (self) {
        if(!modal) {
            modal = [[self alloc] init];
            modal.selectNode = [NodeModel new];
        }
        return modal;
    }
}

+(BOOL)isValidCustomSni:(NSString*)sni {
    if (sni.length == 0) {
        return NO;
    }
    if ([sni containsString:@"://"] || [sni containsString:@"/"] ||
        [sni containsString:@":"] ||
        [sni rangeOfCharacterFromSet:NSCharacterSet.whitespaceCharacterSet].location != NSNotFound) {
        return NO;
    }
    return YES;
}

-(SRPEapConfig*)eapConfig {
    if (!_eapConfig) {
        _eapConfig = [SRPEapConfig initWithDefaults];
    }
    return _eapConfig;
}

-(NSString*)authMethod {
    if(_authMethod.length==0) {
        return @"password";
    }
    return _authMethod;
}

-(NSString*)nodeName {
    if(_nodeName.length==0) {
        return [_protocolType isEqualToString:@"softether"] ? @"SoftEther VPN"
             : [_protocolType isEqualToString:@"openconnect"] ? @"SSL VPN"
             : [_protocolType isEqualToString:@"ssh"] ? @"SSH VPN"
             : [_protocolType isEqualToString:@"openvpn"] ? @"OpenVPN"
             : [_protocolType isEqualToString:@"wireguard"] ? @"WireGuard VPN"
             : [_protocolType isEqualToString:@"amnezia"] ? @"AmneziaWG VPN"
             : [_protocolType isEqualToString:@"aether"] ? @"Aether VPN"
             : [_protocolType isEqualToString:@"waterwall"] ? @"WaterWall VPN"
             : [_protocolType isEqualToString:@"psiphon"] ? @"Psiphon VPN" : @"SSTP VPN";
    }
    return _nodeName;
}


-(NSString*)port {
    if(_port.length==0) {
        return @"443";
    }
    return _port;
}

-(NSString*)udpgw_port {
    if(_udpgw_port.length==0) {
        return @"7300";
    }
    return _udpgw_port;
}

-(NSString*)wgEffectiveConfig {
    if (_wgConfig.length > 0) {
        return _wgConfig;
    }
    if (_wgPrivateKey.length == 0 || _wgPeerPublicKey.length == 0 ||
        _wgAddress.length == 0 || self.server.length == 0) {
        return nil;
    }
    NSMutableString *c = [NSMutableString new];
    [c appendString:@"[Interface]\n"];
    [c appendFormat:@"PrivateKey = %@\n", _wgPrivateKey];
    [c appendFormat:@"Address = %@\n", _wgAddress];
    if (_wgDNS.length > 0) {
        [c appendFormat:@"DNS = %@\n", _wgDNS];
    }
    if ([_protocolType isEqualToString:@"amnezia"]) {
        if (_wgJc > 0)   [c appendFormat:@"Jc = %ld\n", (long)_wgJc];
        if (_wgJmin > 0) [c appendFormat:@"Jmin = %ld\n", (long)_wgJmin];
        if (_wgJmax > 0) [c appendFormat:@"Jmax = %ld\n", (long)_wgJmax];
        if (_wgS1 > 0)   [c appendFormat:@"S1 = %ld\n", (long)_wgS1];
        if (_wgS2 > 0)   [c appendFormat:@"S2 = %ld\n", (long)_wgS2];
        if (_wgS3 > 0)   [c appendFormat:@"S3 = %ld\n", (long)_wgS3];
        if (_wgS4 > 0)   [c appendFormat:@"S4 = %ld\n", (long)_wgS4];
        if (_wgH1 > 0)   [c appendFormat:@"H1 = %ld\n", (long)_wgH1];
        if (_wgH2 > 0)   [c appendFormat:@"H2 = %ld\n", (long)_wgH2];
        if (_wgH3 > 0)   [c appendFormat:@"H3 = %ld\n", (long)_wgH3];
        if (_wgH4 > 0)   [c appendFormat:@"H4 = %ld\n", (long)_wgH4];
        if (_wgI1.length > 0) [c appendFormat:@"I1 = %@\n", _wgI1];
        if (_wgI2.length > 0) [c appendFormat:@"I2 = %@\n", _wgI2];
        if (_wgI3.length > 0) [c appendFormat:@"I3 = %@\n", _wgI3];
        if (_wgI4.length > 0) [c appendFormat:@"I4 = %@\n", _wgI4];
        if (_wgI5.length > 0) [c appendFormat:@"I5 = %@\n", _wgI5];
    }
    [c appendString:@"\n[Peer]\n"];
    [c appendFormat:@"PublicKey = %@\n", _wgPeerPublicKey];
    if (_wgPresharedKey.length > 0) {
        [c appendFormat:@"PresharedKey = %@\n", _wgPresharedKey];
    }
    [c appendFormat:@"Endpoint = %@:%@\n", self.server, self.port];
    [c appendFormat:@"AllowedIPs = %@\n", _wgAllowedIPs.length > 0 ? _wgAllowedIPs : @"0.0.0.0/0"];
    if (_wgKeepalive > 0) {
        [c appendFormat:@"PersistentKeepalive = %ld\n", (long)_wgKeepalive];
    }
    return c;
}


@end
