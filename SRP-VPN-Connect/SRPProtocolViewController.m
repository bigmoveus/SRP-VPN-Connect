//
//  SRPProtocolViewController.m
//  SRP-VPN-Connect
//

#import "SRPProtocolViewController.h"
#import "NodeModel.h"
#import <SRPCore/SRPWaterWallChainConfig.h>

@interface SRPProtocolViewController ()
@property (nonatomic, strong) NodeModel *model;
@end

@implementation SRPProtocolViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Protocol";
}

- (NSArray<NSString *> *)types {
    return @[@"waterwall", @"sstp", @"softether", @"openconnect", @"ssh", @"openvpn", @"wireguard", @"amnezia", @"aether", @"psiphon"];
}

+ (NSString *)titleForType:(NSString *)type {
    if ([type isEqualToString:@"softether"]) return @"SoftEther VPN";
    if ([type isEqualToString:@"openconnect"]) return @"SSL VPN";
    if ([type isEqualToString:@"ssh"]) return @"SSH VPN";
    if ([type isEqualToString:@"openvpn"]) return @"OpenVPN";
    if ([type isEqualToString:@"wireguard"]) return @"WireGuard VPN";
    if ([type isEqualToString:@"amnezia"]) return @"AmneziaWG VPN";
    if ([type isEqualToString:@"aether"]) return @"Aether VPN";
    if ([type isEqualToString:@"waterwall"]) return @"WaterWall VPN";
    if ([type isEqualToString:@"psiphon"]) return @"Psiphon VPN";
    return @"SSTP VPN";
}

+ (NSString *)subtitleForType:(NSString *)type {
    if ([type isEqualToString:@"softether"]) return @"SoftEther over TLS";
    if ([type isEqualToString:@"openconnect"]) return @"AnyConnect, F5 BIG-IP, Palo Alto GlobalProtect";
    if ([type isEqualToString:@"ssh"]) return @"SSH tunnel with optional UDP relay";
    if ([type isEqualToString:@"openvpn"]) return @"OpenVPN 3 — UDP/TCP, optional stunnel (TLS 1.3)";
    if ([type isEqualToString:@"wireguard"]) return @"WireGuard — fast modern UDP";
    if ([type isEqualToString:@"amnezia"]) return @"AmneziaWG — obfuscated for strict firewalls";
    if ([type isEqualToString:@"aether"]) return @"Cloudflare WARP — no server needed, automatic";
    if ([type isEqualToString:@"waterwall"]) return @"VLESS, VMess, Trojan, BGP4 and packet tunnels";
    if ([type isEqualToString:@"psiphon"]) return @"Censorship-resistant network (multi-transport)";
    return @"Microsoft SSTP over TLS";
}

+ (void)applyProtocol:(NSString *)type toModel:(NodeModel *)model {
    // Each protocol keeps its own WireGuard keys and settings; a profile moved to another protocol starts without them.
    if (![type isEqualToString:model.protocolType]) [model clearWireGuardSettings];
    model.protocolType = type;
    model.nodeName = nil;   // the getter derives the name from the protocol
    // Protocol-specific defaults (same as the old action sheet)
    if ([type isEqualToString:@"ssh"]) {
        model.port = @"22";
        model.sshUdpRelay = NO;   // relay off by default — enable only when the server has the HEV relay
    } else if ([type isEqualToString:@"openvpn"]) {
        model.port = @"1194";
    } else if ([type isEqualToString:@"wireguard"]) {
        model.port = @"51820";
    } else if ([type isEqualToString:@"amnezia"]) {
        model.port = @"51821";
    } else if ([type isEqualToString:@"aether"]) {
        model.aetherTransport = @"masque-both";
        model.aetherScan = @"balanced";
    } else if ([type isEqualToString:@"waterwall"]) {
        model.waterwallConfigJSON = [SRPWaterWallChainConfig JSONWithConfiguration:[SRPWaterWallChainConfig defaultConfiguration]];
        model.port = @"443";
    } else if ([type isEqualToString:@"softether"] && model.hubName.length == 0) {
        model.hubName = @"DEFAULT";
    }
}

#pragma mark - Table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.types.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellID = @"protocolType";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cellID];
        cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    }
    NSString *type = self.types[indexPath.row];
    cell.textLabel.text = [SRPProtocolViewController titleForType:type];
    cell.detailTextLabel.text = [SRPProtocolViewController subtitleForType:type];
    NSString *current = self.model.protocolType.length > 0 ? self.model.protocolType : @"sstp";
    cell.accessoryType = [current isEqualToString:type] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    // Tapping the protocol the profile already has keeps its settings
    NSString *type = self.types[indexPath.row];
    if (![type isEqualToString:self.model.protocolType]) [SRPProtocolViewController applyProtocol:type toModel:self.model];
    [self.navigationController popViewControllerAnimated:YES];
}

@end
