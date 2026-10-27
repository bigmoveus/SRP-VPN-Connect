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
    return @[@"sstp", @"softether", @"openconnect", @"ssh", @"openvpn", @"wireguard", @"amnezia", @"aether", @"waterwall", @"psiphon"];
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
    NSString *type = self.types[indexPath.row];
    self.model.protocolType = type;
    self.model.nodeName = nil;   // the getter derives the name from the protocol
    // Protocol-specific defaults (same as the old action sheet)
    if ([type isEqualToString:@"ssh"]) {
        self.model.port = @"22";
        self.model.sshUdpRelay = NO;   // relay off by default — enable only when the server has the HEV relay
    } else if ([type isEqualToString:@"openvpn"]) {
        self.model.port = @"1194";
    } else if ([type isEqualToString:@"wireguard"]) {
        self.model.port = @"51820";
    } else if ([type isEqualToString:@"amnezia"]) {
        self.model.port = @"51821";
    } else if ([type isEqualToString:@"aether"]) {
        self.model.aetherTransport = @"masque-both";
        self.model.aetherScan = @"balanced";
    } else if ([type isEqualToString:@"waterwall"]) {
        self.model.waterwallConfigJSON = [SRPWaterWallChainConfig JSONWithConfiguration:[SRPWaterWallChainConfig defaultConfiguration]];
        self.model.port = @"443";
    } else if ([type isEqualToString:@"softether"] && self.model.hubName.length == 0) {
        self.model.hubName = @"DEFAULT";
    }
    [self.navigationController popViewControllerAnimated:YES];
}

@end
