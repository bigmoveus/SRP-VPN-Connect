//  Rewritten: code-only grouped settings UI (iOS Settings style).
//  Public API unchanged: t_modal / backModal / createNodeBackResult:.

#import "CreateVC.h"
#import "NodeModel.h"
#import "SRPEapConfig.h"
#import "SRPEapConfigViewController.h"
#import "SRPMethodViewController.h"
#import "SRPSEMethodViewController.h"
#import "SRPCertificateViewController.h"
#import "SRPOCServerTypeViewController.h"
#import "SRPProtocolViewController.h"
#import "SRPWGConfigViewController.h"
#import "SRPPsiphonEntriesViewController.h"
#import "SRPWaterWallConfigViewController.h"
#import <SRPCore/SSAuthCapabilities.h>
#import <SRPCore/SRPWaterWallChainConfig.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <objc/runtime.h>

@interface CreateVC ()

@property (nonatomic,strong) NodeModel * modal;
@property (nonatomic,readonly) BOOL isEditingExisting;

-(void)saveNode;
-(void)onCancel;

@end

#pragma mark - Screen A: profile edit table

// Text field tags
static const NSInteger kFieldDesc = 1;
static const NSInteger kFieldHost = 2;
static const NSInteger kFieldPort = 3;
static const NSInteger kFieldUsername = 4;
static const NSInteger kFieldPassword = 5;
static const NSInteger kFieldProxyAddress = 6;
static const NSInteger kFieldProxyPort = 7;
static const NSInteger kFieldProxyUsername = 8;
static const NSInteger kFieldProxyPassword = 9;
static const NSInteger kFieldPacURL = 10;

// Switch tags
static const NSInteger kSwitchAllowUntrusted = 10;
static const NSInteger kSwitchLegacyPapChap = 11;
static const NSInteger kSwitchMschapv2 = 12;
static const NSInteger kSwitchDisableLegacyOuterTls = 13;
static const NSInteger kSwitchAutoReconnect = 14;
static const NSInteger kSwitchSwitchToWifi = 15;
static const NSInteger kSwitchCustomSni = 16;

// Segmented control tags
static const NSInteger kSegmentProxyMode = 20;
static const NSInteger kSegmentOnSleep = 21;
static const NSInteger kSegmentLogLevel = 22;

// Text field tags (OPTIONS)
static const NSInteger kFieldRetryTimes = 11;
static const NSInteger kFieldCustomSni = 12;

// SoftEther field tags
static const NSInteger kFieldSEHostname = 13;   // optional TLS SNI/verify override
static const NSInteger kFieldSEHub = 14;
static const NSInteger kFieldSENatTHint = 15;
static const NSInteger kFieldSEConnections = 16;

// SoftEther switch tags
static const NSInteger kSwitchSETLSVerify = 17;
static const NSInteger kSwitchSEUdpAccel = 18;
static const NSInteger kSwitchSENatT = 19;
static const NSInteger kSwitchWWFakeDNS = 40;
static const NSInteger kSwitchWWSmartRouting = 41;
static const NSInteger kFieldWWOuterSecret = 42;

// SoftEther segmented control tags
static const NSInteger kSegmentSEProxyType = 23;
// SSH field/switch tags
static const NSInteger kFieldSSHHostKey = 24;    // pinned server host key (optional)
static const NSInteger kSwitchSSHRelay = 27;     // HEV UDP relay on/off

// OpenVPN field/switch tags
static const NSInteger kSwitchOVPNStunnel = 28;  // stunnel (outer TLS) on/off
static const NSInteger kFieldOVPNStunnelHost = 28;
static const NSInteger kFieldOVPNStunnelPort = 29;
static const NSInteger kFieldOVPNStunnelSNI = 30;

// SSTP TLS fragmentation (OPTIONS)
static const NSInteger kSegmentTLSFrag = 29;
static const NSInteger kFieldTLSFragFirst = 31;
static const NSInteger kFieldTLSFragFollowing = 32;
static const NSInteger kFieldAetherLicense = 33;
static const NSInteger kFieldPsiphonEntry = 34;

@class SRPProfileEditViewController;

@interface SRPProfileEditViewController : UITableViewController <UIDocumentPickerDelegate>
@property (nonatomic, weak) CreateVC *owner;
@end

@interface SRPProfileEditViewController ()
@property (nonatomic, strong) UIBarButtonItem *saveItem;
// Text-field cells are kept stable across layout/reload passes — recreating a
// UITextField mid-edit kills first-responder and visibly flickers the field.
@property (nonatomic, strong) NSMutableDictionary<NSIndexPath *, UITableViewCell *> *textCellCache;
@end

@interface SRPAetherTransportViewController : UITableViewController
@property (nonatomic, strong) NodeModel *model;
- (instancetype)initWithNodeModel:(NodeModel *)model;
+ (NSString *)titleForTransport:(NSString *)transport;
@end

@implementation SRPAetherTransportViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Transport";
}

- (NSArray<NSString *> *)transports {
    return @[@"masque", @"masque-h2", @"masque-both", @"wg"];
}

+ (NSString *)titleForTransport:(NSString *)transport {
    if ([transport isEqualToString:@"masque-h2"]) return @"MASQUE (HTTP/2)";
    if ([transport isEqualToString:@"masque-both"]) return @"Both (H3 → H2)";
    if ([transport isEqualToString:@"wg"]) return @"WireGuard";
    return @"MASQUE (HTTP/3)";
}

- (NSString *)subtitleForTransport:(NSString *)transport {
    if ([transport isEqualToString:@"masque-h2"]) return @"TCP+TLS, with optional TLS Fragmentation";
    if ([transport isEqualToString:@"masque-both"]) return @"Try HTTP/3 first, then fall back to HTTP/2";
    if ([transport isEqualToString:@"wg"]) return @"Classic Cloudflare WARP over UDP";
    return @"Fast MASQUE transport over QUIC/UDP";
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.transports.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellID = @"aetherTransport";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cellID];
        cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
        cell.detailTextLabel.numberOfLines = 0;
    }
    NSString *transport = self.transports[indexPath.row];
    cell.textLabel.text = [SRPAetherTransportViewController titleForTransport:transport];
    cell.detailTextLabel.text = [self subtitleForTransport:transport];
    NSString *current = self.model.aetherTransport.length > 0 ? self.model.aetherTransport : @"masque";
    cell.accessoryType = [current isEqualToString:transport] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    self.model.aetherTransport = self.transports[indexPath.row];
    [self.navigationController popViewControllerAnimated:YES];
}

@end

@implementation SRPProfileEditViewController

- (NodeModel *)modal {
    return self.owner.modal;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = self.owner.isEditingExisting ? @"Edit Profile" : @"Add Profile";
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    self.textCellCache = [NSMutableDictionary new];

    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                                                          target:self
                                                                                          action:@selector(onCancel)];
    self.saveItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemSave
                                                                  target:self
                                                                  action:@selector(onSave)];
    self.navigationItem.rightBarButtonItem = self.saveItem;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    // Sub-screens may have changed the mode/method — rebuild; field text lives in the model.
    [self.textCellCache removeAllObjects];
    [self.tableView reloadData];
}

#pragma mark - validation / actions

- (BOOL)isSoftEther {
    return [self.modal.protocolType isEqualToString:@"softether"];
}

- (BOOL)isOpenConnect {
    return [self.modal.protocolType isEqualToString:@"openconnect"];
}

- (BOOL)isSSH {
    return [self.modal.protocolType isEqualToString:@"ssh"];
}

- (BOOL)isOpenVPN {
    return [self.modal.protocolType isEqualToString:@"openvpn"];
}

- (BOOL)isWireGuard {
    return [self.modal.protocolType isEqualToString:@"wireguard"] || [self.modal.protocolType isEqualToString:@"amnezia"];
}

- (BOOL)isAether {
    return [self.modal.protocolType isEqualToString:@"aether"];
}

- (BOOL)isWaterWall {
    return [self.modal.protocolType isEqualToString:@"waterwall"];
}

- (NSDictionary *)waterWallConfiguration {
    NSDictionary *configuration = self.modal.waterwallConfigJSON.length > 0 ?
        [SRPWaterWallChainConfig configurationWithJSON:self.modal.waterwallConfigJSON] : nil;
    if (configuration == nil) {
        configuration = self.modal.waterwallPreset.length > 0 ?
            [SRPWaterWallChainConfig configurationFromLegacyPreset:self.modal.waterwallPreset] : nil;
        configuration = configuration ?: [SRPWaterWallChainConfig defaultConfiguration];
        self.modal.waterwallConfigJSON = [SRPWaterWallChainConfig JSONWithConfiguration:configuration];
    }
    return configuration;
}

- (BOOL)waterWallNeedsOuterSecret {
    return [SRPWaterWallChainConfig configurationNeedsOuterSecret:[self waterWallConfiguration]];
}

- (NSString *)waterWallValidationError {
    NSDictionary *configuration = [self waterWallConfiguration];
    NSString *error = [SRPWaterWallChainConfig validationErrorForConfiguration:configuration];
    if (error != nil) return error;
    if ([SRPWaterWallChainConfig isDirectConfiguration:configuration]) return nil;
    if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration]) {
        return [SRPWaterWallChainConfig wireGuardConfigurationWithConfig:[self.modal wgEffectiveConfig]] == nil ?
            @"Import or enter a complete, valid WireGuard configuration." : nil;
    }
    if (self.modal.server.length == 0) return @"Enter the WaterWall server.";
    NSInteger port = self.modal.port.integerValue;
    if (port < 1 || port > 65535) return @"Enter a WaterWall port between 1 and 65535.";
    // An untouched field is nil; validate it as empty so the message names the missing value.
    error = [SRPWaterWallChainConfig validationErrorForApplicationSecret:self.modal.password ?: @""
                                                        forConfiguration:configuration];
    if (error != nil) return error;
    error = [SRPWaterWallChainConfig validationErrorForApplicationUsername:self.modal.username
                                                                    secret:self.modal.password
                                                           forConfiguration:configuration];
    if (error != nil) return error;
    error = [SRPWaterWallChainConfig validationErrorForOuterSecret:self.modal.waterwallOuterSecret ?: @""
                                                  forConfiguration:configuration];
    if (error != nil) return error;
    return nil;
}

- (BOOL)isPsiphon {
    return [self.modal.protocolType isEqualToString:@"psiphon"];
}

// Psiphon transport presets: Auto = all (tactics pick), Speed drops the
// request-cycled meek carriers, Stealth keeps the web-like ones only
static NSString * const kPsiProtosFast = @"OSSH,QUIC-OSSH,TLS-OSSH,SHADOWSOCKS-OSSH";
static NSString * const kPsiProtosStealth = @"UNFRONTED-MEEK-HTTPS-OSSH,UNFRONTED-MEEK-OSSH,TLS-OSSH";

- (NSInteger)psiTransportIndex {
    NSString *v = self.modal.psiphonLimitProtocols;
    if (v.length == 0) return 0;
    if ([v isEqualToString:kPsiProtosFast]) return 1;
    if ([v isEqualToString:kPsiProtosStealth]) return 2;
    return 0;
}

- (void)psiphonTransportsChanged:(UISegmentedControl *)seg {
    self.modal.psiphonLimitProtocols = seg.selectedSegmentIndex == 1 ? kPsiProtosFast
                                   : seg.selectedSegmentIndex == 2 ? kPsiProtosStealth : nil;
}

/// OpenVPN: the imported profile asks for interactive credentials
- (BOOL)ovpnNeedsAuth {
    return [self isOpenVPN] && [self.modal.ovpnProfile containsString:@"auth-user-pass"];
}

- (BOOL)isCertificateMode {
    if ([self isSoftEther]) {
        return [self.modal.seAuthMethod isEqualToString:@"certificate"];
    }
    return [self.modal.authMethod isEqualToString:@"certificate"];
}

- (BOOL)isSEAnonymousMode {
    return [self isSoftEther] && [self.modal.seAuthMethod isEqualToString:@"anonymous"];
}

/// The first reason the profile cannot be saved yet, or nil once it is complete.
/// Save stays tappable: a disabled button gave no hint about which field was wrong.
- (NSString *)validationMessage {
    BOOL hasServer = self.modal.server.length > 0;
    if ([self isSoftEther]) {
        // SoftEther: username is always required; password unless anonymous /
        // certificate; a certificate must be imported for certificate auth.
        if (!hasServer) return @"Enter the server address.";
        if (self.modal.username.length == 0) return @"Enter the username.";
        if ([self.modal.seAuthMethod isEqualToString:@"certificate"]) {
            if (self.modal.certKey.length == 0) return @"Import a client certificate.";
        } else if (![self isSEAnonymousMode] && self.modal.password.length == 0) {
            return @"Enter the password.";
        }
        NSInteger c = self.modal.seConnections;
        if (c < 1 || c > 32) return @"Use between 1 and 32 connections.";
    }
    else if ([self isOpenConnect]) {
        // OpenConnect (AnyConnect): server + username; password or certificate
        if (!hasServer) return @"Enter the server address.";
        if (self.modal.username.length == 0) return @"Enter the username.";
        if ([self isCertificateMode]) {
            if (self.modal.certKey.length == 0) return @"Import a client certificate.";
        } else if (self.modal.password.length == 0) {
            return @"Enter the password.";
        }
    }
    else if ([self isSSH]) {
        // SSH: server + username + password (v1 is password auth). The relay
        // credentials are optional — only needed when the server-side relay
        // enforces its own authentication.
        if (!hasServer) return @"Enter the server address.";
        if (self.modal.username.length == 0) return @"Enter the username.";
        if (self.modal.password.length == 0) return @"Enter the password.";
    }
    else if ([self isOpenVPN]) {
        // OpenVPN: server + an imported .ovpn profile (credentials live in the
        // profile: client certificate / auth-user-pass).
        if (!hasServer) return @"Enter the server address.";
        if (self.modal.ovpnProfile.length == 0) return @"Import an OpenVPN profile.";
        if ([self ovpnNeedsAuth] && (self.modal.username.length == 0 || self.modal.password.length == 0)) {
            return @"This OpenVPN profile needs a username and password.";
        }
        if (self.modal.ovpnStunnelEnabled && self.modal.ovpnStunnelPort.length > 0) {
            NSInteger sp = self.modal.ovpnStunnelPort.integerValue;
            if (sp < 1 || sp > 65535) return @"Enter a stunnel port between 1 and 65535.";
        }
    }
    else if ([self isWireGuard]) {
        // WireGuard: server + a config — imported .conf or complete manual entry
        if (!hasServer) return @"Enter the server address.";
        if ([self.modal wgEffectiveConfig].length == 0) return @"Import or enter a WireGuard configuration.";
    }
    else if ([self isAether]) {
        // Private: own WireGuard server — a complete config is required.
        // Public: zero-config (Cloudflare WARP) — nothing is required.
        if ([self isAetherPrivate]) {
            if (!hasServer) return @"Enter the server address.";
            if ([self.modal wgEffectiveConfig].length == 0) return @"Import or enter a WireGuard configuration.";
        }
    }
    else if ([self isWaterWall]) {
        NSString *error = [self waterWallValidationError];
        if (error != nil) return error;
    }
    else if ([self isPsiphon]) {
        // Psiphon: at least one server entry is required
        if (self.modal.psiphonServerEntry.length == 0) return @"Add a Psiphon server entry.";
    }
    else if ([self isCertificateMode]) {
        // Certificate authentication: host + an imported client certificate;
        // the username is optional (identity hint / outer identity) and no
        // password is required.
        if (!hasServer) return @"Enter the server address.";
        if (self.modal.certKey.length == 0) return @"Import a client certificate.";
    } else {
        if (!hasServer) return @"Enter the server address.";
        if (self.modal.username.length == 0) return @"Enter the username.";
        if (self.modal.password.length == 0) return @"Enter the password.";
        if (!(self.modal.MSCHAP2 || self.modal.allowLegacyPapChap || self.modal.eapConfig.eapMschapv2Enabled)) {
            return @"Enable at least one authentication method.";
        }
    }
    switch (self.modal.proxyMode) {
        case 1: // Manual: proxy address + port required
            if (self.modal.proxyAddress.length == 0 || self.modal.proxyPort.length == 0) {
                return @"Enter the proxy address and port.";
            }
            break;
        case 2: { // Auto: a valid http(s) PAC URL required
            NSURL *pac = [NSURL URLWithString:self.modal.pacURL ?: @""];
            if (pac == nil || !([pac.scheme isEqualToString:@"http"] || [pac.scheme isEqualToString:@"https"]) ||
                pac.host.length == 0) {
                return @"Enter an http or https PAC URL.";
            }
            break;
        }
        default:
            break;
    }
    if (![self isSoftEther] && self.modal.customSniEnabled && ![NodeModel isValidCustomSni:self.modal.customSni]) {
        return @"Custom SNI must be a bare hostname, without a scheme, port, path or spaces.";
    }
    return nil;
}

/// Pasted values often carry a trailing space or newline, and the secure UUID
/// field hides it; none of these fields can legitimately start or end with one.
- (void)trimEdgeWhitespace {
    NSCharacterSet *edges = NSCharacterSet.whitespaceAndNewlineCharacterSet;
    self.modal.server = [self.modal.server stringByTrimmingCharactersInSet:edges];
    self.modal.port = [self.modal.port stringByTrimmingCharactersInSet:edges];
    self.modal.customSni = [self.modal.customSni stringByTrimmingCharactersInSet:edges];
    self.modal.proxyAddress = [self.modal.proxyAddress stringByTrimmingCharactersInSet:edges];
    self.modal.proxyPort = [self.modal.proxyPort stringByTrimmingCharactersInSet:edges];
    if ([self isWaterWall]) {
        NSString *application = [self waterWallConfiguration][@"application"];
        if ([application isEqualToString:@"vless"] || [application isEqualToString:@"vmess"]) {
            self.modal.password = [self.modal.password stringByTrimmingCharactersInSet:edges];
        }
    }
}

- (void)onSave {
    [self.view endEditing:YES];
    [self trimEdgeWhitespace];
    NSString *message = [self validationMessage];
    if (message != nil) {
        [self showInfoAlertWithTitle:[self isWaterWall] ? @"Invalid WaterWall Configuration" : @"Profile Incomplete"
                             message:message];
        return;
    }
    [self.owner saveNode];
}

- (void)onCancel {
    [self.owner onCancel];
}

#pragma mark - cell builders

- (UITableViewCell *)textCellWithTitle:(NSString *)title
                                  text:(NSString *)text
                           placeholder:(NSString *)placeholder
                                   tag:(NSInteger)tag
                          keyboardType:(UIKeyboardType)keyboardType
                                secure:(BOOL)secure {
    // Keep one stable cell per field: recreating the UITextField on a layout
    // pass resigns first responder and flickers the field mid-typing.
    NSNumber *cacheKey = @(tag);
    UITableViewCell *cached = self.textCellCache[cacheKey];
    if (cached) {
        return cached;
    }
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.textLabel.text = title;
    UITextField *field = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 190, 30)];
    field.text = text;
    field.placeholder = placeholder;
    field.textAlignment = NSTextAlignmentRight;
    field.keyboardType = keyboardType;
    field.secureTextEntry = secure;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.clearButtonMode = UITextFieldViewModeNever;
    field.tag = tag;
    [field addTarget:self action:@selector(fieldChanged:) forControlEvents:UIControlEventEditingChanged];
    cell.accessoryView = field;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    self.textCellCache[cacheKey] = cell;
    return cell;
}

- (UITableViewCell *)switchCellWithTitle:(NSString *)title on:(BOOL)on tag:(NSInteger)tag {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.textLabel.text = title;
    UISwitch *sw = [[UISwitch alloc] init];
    sw.on = on;
    sw.tag = tag;
    [sw addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = sw;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (UITableViewCell *)valueCellWithTitle:(NSString *)title value:(NSString *)value disclosure:(BOOL)disclosure {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.textLabel.text = title;
    cell.detailTextLabel.text = value;
    if (disclosure) {
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    return cell;
}

- (UITableViewCell *)segmentCellWithTitle:(NSString *)title items:(NSArray<NSString *> *)items
                                 selected:(NSInteger)selected action:(SEL)action tag:(NSInteger)tag {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.textLabel.text = title;
    UISegmentedControl *seg = [[UISegmentedControl alloc] initWithItems:items];
    seg.selectedSegmentIndex = selected;
    seg.tag = tag;
    [seg addTarget:self action:action forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = seg;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

#pragma mark - change handlers

- (void)fieldChanged:(UITextField *)field {
    switch (field.tag) {
        case kFieldDesc: self.modal.desc = field.text; break;
        case kFieldHost: self.modal.server = field.text; break;
        case kFieldPort: self.modal.port = field.text; break;
        case kFieldUsername: self.modal.username = field.text; break;
        case kFieldPassword: self.modal.password = field.text; break;
        case kFieldProxyAddress: self.modal.proxyAddress = field.text; break;
        case kFieldProxyPort: self.modal.proxyPort = field.text; break;
        case kFieldProxyUsername: self.modal.proxyUsername = field.text; break;
        case kFieldProxyPassword: self.modal.proxyPassword = field.text; break;
        case kFieldPacURL: self.modal.pacURL = field.text; break;
        case kFieldRetryTimes: self.modal.retryTimes = field.text.integerValue; break;
        case kFieldCustomSni: self.modal.customSni = field.text; break;
        case kFieldAetherLicense: self.modal.aetherLicense = field.text; break;
        case kFieldPsiphonEntry: self.modal.psiphonServerEntry = field.text; break;
        case kFieldSEHostname: self.modal.hostnameOverride = field.text; break;
        case kFieldSEHub: self.modal.hubName = field.text; break;
        case kFieldSENatTHint: self.modal.seNatTHint = field.text; break;
        case kFieldSEConnections: {
            NSInteger v = field.text.integerValue;
            self.modal.seConnections = MAX(1, MIN(32, v));
            break;
        }
        case kFieldSSHHostKey: self.modal.sshHostKey = field.text; break;
        case kFieldOVPNStunnelHost: self.modal.ovpnStunnelHost = field.text; break;
        case kFieldOVPNStunnelPort: self.modal.ovpnStunnelPort = field.text; break;
        case kFieldOVPNStunnelSNI: self.modal.ovpnStunnelSNI = field.text; break;
        case kFieldTLSFragFirst: self.modal.tlsFragFirst = field.text.integerValue; break;
        case kFieldTLSFragFollowing: self.modal.tlsFragFollowing = field.text.integerValue; break;
        case kFieldWWOuterSecret: self.modal.waterwallOuterSecret = field.text; break;
        default: break;
    }
}

- (void)proxyModeChanged:(UISegmentedControl *)seg {
    self.modal.proxyMode = seg.selectedSegmentIndex;
    [self.tableView reloadData];
}

- (void)onSleepChanged:(UISegmentedControl *)seg {
    self.modal.onSleep = seg.selectedSegmentIndex;   // 0=Off 1=Pause 2=Stay
}

- (void)aetherScanChanged:(UISegmentedControl *)seg {
    self.modal.aetherScan = seg.selectedSegmentIndex == 1 ? @"turbo" : @"balanced";
}

- (BOOL)isAetherPrivate {
    return [self isAether] && [self.modal.aetherMode isEqualToString:@"private"];
}

- (void)aetherModeChanged:(UISegmentedControl *)seg {
    self.modal.aetherMode = seg.selectedSegmentIndex == 1 ? @"private" : @"public";
    if ([self isAetherPrivate] && self.modal.port.length == 0) {
        self.modal.port = @"51820";
    }
    [self.tableView reloadData];
}

- (void)aetherTorChanged:(UISegmentedControl *)seg {
    self.modal.aetherTor = seg.selectedSegmentIndex == 2 ? @"only"
                         : seg.selectedSegmentIndex == 1 ? @"reverse" : @"off";
    // Tor-only hides the WARP-specific rows (Transport, WARP+ License)
    [self.tableView reloadData];
}

- (void)tlsFragChanged:(UISegmentedControl *)seg {
    self.modal.tlsFragMode = seg.selectedSegmentIndex;   // 0=Off 1=Auto 2=Manual
    [self.tableView reloadData];
}

- (void)logLevelChanged:(UISegmentedControl *)seg {
    self.modal.logLevel = seg.selectedSegmentIndex;  // 0=Normal 1=Expert 2=Debug
}

- (void)seProxyTypeChanged:(UISegmentedControl *)seg {
    self.modal.proxyType = seg.selectedSegmentIndex == 1 ? @"socks5" : @"http";
}

- (void)showInfoAlertWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)protocolTapped {
    // Dedicated picker screen (the protocol list outgrew the action sheet).
    // The edit screen rebuilds itself in viewWillAppear on return.
    SRPProtocolViewController *vc = [[SRPProtocolViewController alloc] initWithNodeModel:self.modal];
    [self.navigationController pushViewController:vc animated:YES];
}

/// Text field cell with an (i) info button next to the field.
- (UITableViewCell *)textInfoCellWithTitle:(NSString *)title
                                      text:(NSString *)text
                               placeholder:(NSString *)placeholder
                                       tag:(NSInteger)tag
                              keyboardType:(UIKeyboardType)keyboardType
                                infoTitle:(NSString *)infoTitle
                             infoMessage:(NSString *)infoMessage {
    NSNumber *cacheKey = @(tag);
    UITableViewCell *cached = self.textCellCache[cacheKey];
    if (cached) {
        return cached;
    }
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.textLabel.text = title;

    UIView *container = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 224, 30)];
    UITextField *field = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 190, 30)];
    field.text = text;
    field.placeholder = placeholder;
    field.textAlignment = NSTextAlignmentRight;
    field.keyboardType = keyboardType;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.clearButtonMode = UITextFieldViewModeNever;
    field.tag = tag;
    [field addTarget:self action:@selector(fieldChanged:) forControlEvents:UIControlEventEditingChanged];
    [container addSubview:field];

    UIButton *info = [UIButton buttonWithType:UIButtonTypeInfoLight];
    info.frame = CGRectMake(198, 3, 24, 24);
    info.accessibilityLabel = infoTitle;
    objc_setAssociatedObject(info, "infoTitle", infoTitle, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(info, "infoMessage", infoMessage, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [info addTarget:self action:@selector(infoButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    [container addSubview:info];

    cell.accessoryView = container;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    self.textCellCache[cacheKey] = cell;
    return cell;
}

- (void)infoButtonTapped:(UIButton *)button {
    NSString *title = objc_getAssociatedObject(button, "infoTitle");
    NSString *message = objc_getAssociatedObject(button, "infoMessage");
    [self showInfoAlertWithTitle:title message:message];
}

- (void)switchChanged:(UISwitch *)sw {
    switch (sw.tag) {
        case kSwitchAllowUntrusted: self.modal.TLS = sw.isOn; break;
        case kSwitchLegacyPapChap: self.modal.allowLegacyPapChap = sw.isOn; break;
        case kSwitchMschapv2: self.modal.MSCHAP2 = sw.isOn; break;
        case kSwitchDisableLegacyOuterTls: self.modal.disableLegacyOuterTls = sw.isOn; break;
        case kSwitchAutoReconnect:
            self.modal.autoReconnect = sw.isOn;
            [self.tableView reloadData];
            break;
        case kSwitchSwitchToWifi: self.modal.switchToWifi = sw.isOn; break;
        case kSwitchCustomSni:
            self.modal.customSniEnabled = sw.isOn;
            [self.tableView reloadData];
            break;
        case kSwitchSETLSVerify: self.modal.TLS = !sw.isOn; break;   // TLS field = allowUntrusted (inverted)
        case kSwitchWWFakeDNS: self.modal.waterwallFakeDNS = sw.isOn; break;
        case kSwitchWWSmartRouting: self.modal.waterwallSmartRouting = sw.isOn; break;
        case kSwitchSEUdpAccel: self.modal.seUdpAcceleration = sw.isOn; break;
        case kSwitchSENatT:
            self.modal.seNatTraversal = sw.isOn;
            [self.tableView reloadData];
            break;
        case kSwitchSSHRelay:
            self.modal.sshUdpRelay = sw.isOn;
            [self.tableView reloadData];
            break;
        case kSwitchOVPNStunnel:
            self.modal.ovpnStunnelEnabled = sw.isOn;
            [self.tableView reloadData];
            break;

        default: break;
    }
}

#pragma mark - table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 5;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case 1: return @"SERVER";
        case 2: return ([self isAether] || [self isPsiphon] || ([self isWaterWall] &&
            ![SRPWaterWallChainConfig configurationNeedsApplicationSecret:[self waterWallConfiguration]] &&
            ![self waterWallNeedsOuterSecret])) ? nil : ([self isOpenVPN] && ![self ovpnNeedsAuth] ? nil : ([self isWireGuard] ? nil : @"AUTHENTICATION"));  // OpenVPN/WireGuard: credentials live in the imported file
        case 3: return ([self isSSH] || [self isOpenVPN] || [self isWireGuard] || [self isOpenConnect] || [self isAether] || [self isWaterWall] || [self isPsiphon]) ? nil : @"PROXY";  // hidden where unsupported
        case 4: return @"OPTIONS";
        default: return nil;
    }
}

// The SSH/OpenVPN/WireGuard proxy section (unsupported) collapses fully
- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section {
    if (([self isSSH] || [self isOpenVPN] || [self isWireGuard] || [self isOpenConnect] || [self isAether] || [self isWaterWall]) && section == 3) {
        return CGFLOAT_MIN;
    }
    if (([self isAether] && (section == 1 || section == 2)) ||
        ([self isWaterWall] && section == 2 &&
         ![SRPWaterWallChainConfig configurationNeedsApplicationSecret:[self waterWallConfiguration]] &&
         ![self waterWallNeedsOuterSecret]) ||
        (([self isOpenVPN] && ![self ovpnNeedsAuth] && section == 2) || ([self isWireGuard] && section == 2))) {
        return CGFLOAT_MIN;
    }
    return UITableViewAutomaticDimension;
}

- (CGFloat)tableView:(UITableView *)tableView heightForFooterInSection:(NSInteger)section {
    if (([self isSSH] || [self isOpenVPN] || [self isWireGuard] || [self isOpenConnect] || [self isAether] || [self isWaterWall]) && section == 3) {
        return CGFLOAT_MIN;
    }
    if (([self isAether] && (section == 1 || section == 2)) ||
        ([self isWaterWall] && section == 2 &&
         ![SRPWaterWallChainConfig configurationNeedsApplicationSecret:[self waterWallConfiguration]] &&
         ![self waterWallNeedsOuterSecret]) ||
        (([self isOpenVPN] && ![self ovpnNeedsAuth] && section == 2) || ([self isWireGuard] && section == 2))) {
        return CGFLOAT_MIN;
    }
    return UITableViewAutomaticDimension;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 1 && [self isOpenConnect]) {
        return @"AnyConnect (e.g. ocserv) or F5 BIG-IP APM. The server certificate is verified against the Server hostname. F5 BIG-IP is supported on firmware with the classic login flow.";
    }
    if (section == 1 && [self isSSH]) {
        return @"SSH tunnel (direct TCP forwarding). Host Key pins the server's SSH fingerprint (OpenSSH \"SHA256:...\" form); leave empty to accept any key. UDP Relay uses the administrator-installed HEV service on the server (no extra credentials).";
    }
    if (section == 1 && [self isOpenVPN]) {
        if (self.modal.ovpnStunnelEnabled) {
            return @"The .ovpn profile supplies the OpenVPN configuration and credentials. With stunnel on, the OpenVPN TCP connection is wrapped in a TLS connection to the server's stunnel listener; CA Certificate pins the CA that signs the stunnel certificate (empty = system trust).";
        }
        return @"The .ovpn profile supplies the OpenVPN configuration and credentials (client certificate or auth-user-pass). Server and Port are filled from the profile's remote line on import. Enable stunnel to wrap OpenVPN TCP in an outer TLS connection.";
    }
    if (section == 1 && [self isPsiphon]) {
        return @"Psiphon connects to your own psiphond server(s) — paste the hex server entry produced by 'psiphond generate'; several entries (space- or newline-separated) rotate automatically. Transports: Auto tries everything; Speed skips the slower web-shaped carriers; Stealth keeps only web-like traffic.";
    }
    if (section == 1 && [self isWaterWall]) {
        return @"Configuration independently combines the input, application protocol, MUX and outer transport. SOCKS5 supports TCP and UDP Association directly; HTTP CONNECT supports TCP. Proxy username and password are optional as a pair. Advanced Node Settings provides per-node JSON overrides. Reality defaults to the www.cloudflare.com cover and uses a separate password. AEAD has no TLS handshake. Raw IPv4 uses PacketsToStream. TLS Server Verification validates TLS, Reality and QUIC certificates. Optional SNI must match the server's cover configuration.";
    }
    if (section == 1 && [self isAether]) {
        if ([self isAetherPrivate]) {
            return @"Server and Port are the WireGuard endpoint of your own server. Keys, address and DNS are entered under Manual Configuration.";
        }
        return @"Public mode connects to Cloudflare WARP automatically. H3 uses QUIC; H2 uses TCP+TLS and supports TLS Fragmentation; Both tries H3 first and falls back to H2. Endpoint Scan: Turbo takes the first verified endpoint, Balanced compares more candidates. WireGuard is the classic WARP transport. A WARP+ License is bound at connect time. Tor can carry WARP or provide a Tor-only exit.";
    }
    if (section == 1 && [self isWireGuard]) {
        return @"Import a .conf file (wg-quick format) or enter the keys manually under Manual Configuration. Server and Port are filled from the Endpoint line on import. WireGuard runs over UDP.";
    }
    if (section == 1 && [self isSoftEther]) {
        return @"Hostname overrides the TLS server name (SNI) and certificate verification; the TCP destination stays the Server field. When Hostname differs from the server certificate name, turn off TLS Server Verification.";
    }
    if (section == 2 && [self ovpnNeedsAuth]) {
        return @"This .ovpn profile requires username/password authentication (auth-user-pass). Enter the credentials from your administrator.";
    }
    if (section == 3 && self.modal.proxyMode != 0 &&
        ![SSAuthCapabilities sharedCapabilities].supportsProxy) {
        return @"Proxy connections require iOS 17 or later.";
    }
    if (section == 3 && self.modal.proxyMode == 1) {
        if ([self isSoftEther]) {
            return @"SoftEther supports HTTP CONNECT and SOCKS5 proxies. The proxy is only used for the connection to the VPN server.";
        }
        return @"The proxy protocol (SOCKS5 or HTTP CONNECT) is detected automatically by negotiation.";
    }
    if (section == 3 && self.modal.proxyMode == 2 && [self isSoftEther]) {
        return @"Auto (PAC) proxy is not supported for SoftEther profiles yet; the connection will be made directly.";
    }
    if (section == 4 && [self isWaterWall]) {
        NSString *base = @"Auto Reconnect restarts WaterWall 2 seconds after the connection fails; Retry Times limits the consecutive attempts (empty = unlimited) before the VPN disconnects with an error. Switch to Wi-Fi When Available moves the connection to Wi-Fi as soon as it appears, and back to cellular when Wi-Fi is lost. On Sleep: Off closes the connection while the device sleeps; on wake it reconnects with Auto Reconnect, otherwise the VPN disconnects. Pause closes it and always reconnects on wake; Stay keeps it open.";
        NSDictionary *configuration = [self waterWallConfiguration];
        if ([SRPWaterWallChainConfig configurationAllowsFragmentation:configuration]) {
            base = [base stringByAppendingString:@" TLS Fragmentation splits the outer TLS ClientHello into smaller writes."];
        }
        if ([SRPWaterWallChainConfig configurationAllowsRouting:configuration]) {
            base = [base stringByAppendingString:@" Remote DNS answers lookups with placeholder addresses so the server resolves the real names; Direct LAN Routing connects private addresses (10/8, 172.16/12, 192.168/16) directly instead of through the server."];
        }
        return base;
    }
    if (section == 4 && [self isSoftEther]) {
        return @"SoftEther always requires TLS 1.2 or later.";
    }
    if (section == 4 && [self isOpenConnect]) {
        return @"OpenConnect always uses TLS 1.2 or later; DTLS (UDP) is used when the server supports it.";
    }
    if (section == 4 && [self isSSH]) {
        return @"SSH transport is encrypted by the SSH session itself. UDP uses the HEV relay over an SSH channel (reliable stream — media quality depends on the network).";
    }
    if (section == 4 && [self isOpenVPN]) {
        return @"OpenVPN uses the TLS parameters negotiated with the server (tls-crypt, data-channel ciphers). With stunnel on, the outer TLS connection requires TLS 1.2 or later. TLS Fragmentation applies to the outer stunnel TLS handshake.";
    }
    if (section == 4 && [self isPsiphon]) {
        return @"Psiphon carries TCP only; DNS is answered inside the tunnel and names are resolved by the server.";
    }
    if (section == 4 && [self isAether]) {
        if ([self isAetherPrivate]) {
            return @"Private mode connects to your own WireGuard server (standard WireGuard over UDP) — the Aether engine and Cloudflare WARP are not involved. Enter the keys under Manual Configuration; the client keypair can be generated there.";
        }
        NSString *base = @"Aether connects to Cloudflare WARP automatically — no server or account is needed. The engine re-establishes the session itself on network changes; only Log Level and, where H2 is used, TLS Fragmentation apply here. Tor Only exits via the Tor network (no WARP); WARP via Tor dials the tunnel through Tor (experimental — slow to connect).";
        if (([self.modal.aetherTransport isEqualToString:@"masque-h2"] || [self.modal.aetherTransport isEqualToString:@"masque-both"])) {
            return [base stringByAppendingString:@" MASQUE H2 runs over TCP+TLS (useful where QUIC/UDP is filtered); TLS Fragmentation splits the handshake's ClientHello into smaller writes — Auto picks safe sizes and splits at the SNI, Manual sets the byte range."];
        }
        return base;
    }
    if (section == 4 && [self isWireGuard]) {
        return @"WireGuard is stateless over UDP: roaming, retries and sleep/wake are built into the protocol — only Log Level applies.";
    }
    if (section == 4) {
        NSString *base = @"Disable TLS 1.0 & 1.1 applies to the outer SSTP connection only; the EAP tunnel versions are configured in EAP Configuration. Custom SNI is sent in the TLS ClientHello and used for certificate verification; the TCP destination stays the Host field. TLS Fragmentation splits the handshake's outgoing bytes into smaller TCP writes (the TLS stream itself is unchanged) — experimental, may help on networks with DPI. Auto picks the chunking from the access network; Manual sets the write sizes by hand.";
        if (self.modal.customSniEnabled) {
            return [base stringByAppendingString:@" Note: when the SNI hostname differs from the server's certificate name, enable \"Allow Untrusted Certificate\" to connect."];
        }
        return base;
    }
    return nil;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case 0: return 2; // Protocol, Description
        case 1:
            if ([self isPsiphon]) {
                // Server Entries + Transports
                return 2;
            }
            if ([self isWaterWall]) {
                NSDictionary *configuration = [self waterWallConfiguration];
                if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration]) return 5;
                return [SRPWaterWallChainConfig configurationUsesTLS:configuration] ? 5 : 3;
            }
            if ([self isAether]) {
                if ([self isAetherPrivate]) return 4;
                return [self.modal.aetherTor isEqualToString:@"only"] ? 2 : 5;
            }
            if ([self isOpenConnect]) {
                return 4;   // Server Type, Server, Port, TLS Server Verification
            }
            if ([self isWireGuard]) {
                return 4;   // Import, Manual, Server, Port
            }
            if ([self isOpenVPN]) {
                // Profile, Server, Port, stunnel (+ Host, Port, SNI, CA when on)
                return self.modal.ovpnStunnelEnabled ? 8 : 4;
            }
            if ([self isSSH]) {
                // Server, Port, Host Key, UDP Relay
                return 4;
            }
            if ([self isSoftEther]) {
                // Host, Port, Hostname, TLS Verification, Virtual Hub,
                // Connections, UDP Accel, NAT-T (+ NAT-T Hint when on)
                return self.modal.seNatTraversal ? 9 : 8;
            }
            return 3; // Host, Port, Allow Untrusted
        case 2:
            if ([self isWaterWall]) {
                NSDictionary *configuration = [self waterWallConfiguration];
                NSString *application = configuration[@"application"];
                BOOL proxy = [application isEqualToString:@"socks5"] || [application isEqualToString:@"http-proxy"];
                return ([SRPWaterWallChainConfig configurationNeedsApplicationSecret:configuration] ? (proxy ? 2 : 1) : 0) +
                       ([self waterWallNeedsOuterSecret] ? 1 : 0);
            }
            if ([self isAether] || [self isPsiphon]) {
                return 0;
            }
            if ([self isWireGuard]) {
                return 0;   // keys live in the .conf
            }
            if ([self isOpenVPN]) {
                return [self ovpnNeedsAuth] ? 2 : 0;   // Username, Password when the profile has auth-user-pass
            }
            if ([self isSSH]) {
                return 2;   // Username, Password
            }
            if ([self isSoftEther]) {
                // Method, Username, (Password | Certificate)
                return [self isSEAnonymousMode] ? 2 : 3;
            }
            if ([self isOpenConnect]) {
                // Method, Username, Password|Certificate
                return 3;
            }
            return [self isCertificateMode] ? 4 : 6;
        case 3: // PROXY: Mode (+ fields per mode)
            if ([self isOpenConnect] || [self isSSH] || [self isOpenVPN] || [self isWireGuard] || [self isAether] || [self isWaterWall] || [self isPsiphon]) {
                return 0;   // libopenconnect proxy support is not wired yet; SSH/OpenVPN/WireGuard/Psiphon likewise
            }
            if ([self isSoftEther]) {
                switch (self.modal.proxyMode) {
                    case 1: return 6; // Mode, Address, Port, Type, Username, Password
                    case 2: return 2; // Mode, PAC URL
                    default: return 1;
                }
            }
            switch (self.modal.proxyMode) {
                case 1: return 5; // Mode, Address, Port, Username, Password
                case 2: return 2; // Mode, PAC URL
                default: return 1; // Mode
            }
        case 4: // OPTIONS
            if ([self isWaterWall]) {
                // Auto Reconnect (+Retry Times when on), Switch to Wi-Fi,
                // On Sleep, Log Level (+ TLS Fragmentation where the chain
                // has an outer TLS handshake, + the two routing switches)
                NSDictionary *configuration = [self waterWallConfiguration];
                BOOL fragmentation = [SRPWaterWallChainConfig configurationAllowsFragmentation:configuration];
                BOOL routing = [SRPWaterWallChainConfig configurationAllowsRouting:configuration];
                return (self.modal.autoReconnect ? 5 : 4) + (fragmentation ? 1 + (self.modal.tlsFragMode == 2 ? 2 : 0) : 0) +
                       (routing ? 2 : 0);
            }
            if ([self isWireGuard] || [self isPsiphon]) {
                // Log Level only — WireGuard/AmneziaWG roam and retry by
                // design (stateless UDP), and the Psiphon core redials
                // internally; nothing else in this section acts on them.
                return 1;
            }
            if ([self isAether]) {
                // Log Level (+ TLS Fragmentation on the MASQUE-H2 carrier);
                // the engine keeps its own quick-reconnect, so the generic
                // reconnect/wi-fi/sleep switches do not apply
                BOOL fragOK = ([self.modal.aetherTransport isEqualToString:@"masque-h2"] || [self.modal.aetherTransport isEqualToString:@"masque-both"]);
                return 1 + (fragOK ? 1 + (self.modal.tlsFragMode == 2 ? 2 : 0) : 0);
            }
            if ([self isOpenConnect] || [self isSSH] || [self isOpenVPN]) {
                // Auto Reconnect (+Retry Times when on), Switch to Wi-Fi,
                // On Sleep, Log Level (+ TLS Fragmentation for
                // OpenConnect and OpenVPN-stunnel)
                BOOL fragOK = [self isOpenConnect] ||
                              ([self isOpenVPN] && self.modal.ovpnStunnelEnabled);
                NSInteger extra = fragOK ? 1 + (self.modal.tlsFragMode == 2 ? 2 : 0) : 0;
                return (self.modal.autoReconnect ? 5 : 4) + extra;
            }
            if ([self isSoftEther]) {
                // Auto Reconnect (+Retry Times when on), Switch to Wi-Fi,
                // On Sleep, Log Level, TLS Fragmentation (+2 rows in Manual)
                return (self.modal.autoReconnect ? 5 : 4) + 1 + (self.modal.tlsFragMode == 2 ? 2 : 0);
            }
            // Disable legacy TLS, Auto Reconnect (+Retry Times when on),
            // Switch to Wi-Fi, On Sleep, Log Level, Custom SNI (+hostname
            // row when enabled), TLS Fragmentation (+2 size rows when on)
            return (self.modal.autoReconnect ? 6 : 5) + 1 + (self.modal.customSniEnabled ? 1 : 0)
                 + 1 + (self.modal.tlsFragMode == 2 ? 2 : 0);
        default: return 0;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 0) {
        if (indexPath.row == 0) {
            NSString *pt = self.modal.nodeName;   // derives from the protocol
            return [self valueCellWithTitle:@"Protocol" value:pt disclosure:YES];
        }
        return [self textCellWithTitle:@"Description" text:self.modal.desc placeholder:@"Optional"
                                   tag:kFieldDesc keyboardType:UIKeyboardTypeDefault secure:NO];
    }
    if (indexPath.section == 1) {
        if ([self isPsiphon]) {
            if (indexPath.row == 0) {
                NSUInteger n = 0;
                if (self.modal.psiphonServerEntry.length > 0) {
                    for (NSString *p in [self.modal.psiphonServerEntry componentsSeparatedByCharactersInSet:
                                         [NSCharacterSet characterSetWithCharactersInString:@" \t\r\n,"]]) {
                        if (p.length > 0) n++;
                    }
                }
                NSString *v = n > 0 ? [NSString stringWithFormat:@"%lu %@", (unsigned long)n, n == 1 ? @"entry" : @"entries"] : @"None";
                return [self valueCellWithTitle:@"Server Entries" value:v disclosure:YES];
            }
            return [self segmentCellWithTitle:@"Transports"
                                        items:@[@"Auto", @"Speed", @"Stealth"]
                                     selected:[self psiTransportIndex]
                                       action:@selector(psiphonTransportsChanged:) tag:kSegmentOnSleep + 104];
        }
        if ([self isWaterWall]) {
            NSDictionary *configuration = [self waterWallConfiguration];
            if ([SRPWaterWallChainConfig isWireGuardConfiguration:configuration]) {
                switch (indexPath.row) {
                    case 0:
                        return [self valueCellWithTitle:@"Configuration"
                                                  value:[SRPWaterWallChainConfig summaryForConfiguration:configuration] disclosure:YES];
                    case 1:
                        return [self valueCellWithTitle:@"Import Config (.conf)" value:(self.modal.wgConfig.length > 0 ? @"Imported" : @"None") disclosure:YES];
                    case 2:
                        return [self valueCellWithTitle:@"Manual Configuration" value:(self.modal.wgPrivateKey.length > 0 ? @"Configured" : @"None") disclosure:YES];
                    case 3:
                        return [self textCellWithTitle:@"Server" text:self.modal.server placeholder:@"Required"
                                                   tag:kFieldHost keyboardType:UIKeyboardTypeURL secure:NO];
                    default:
                        return [self textCellWithTitle:@"Port" text:self.modal.port placeholder:@"51820"
                                                   tag:kFieldPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                }
            }
            switch (indexPath.row) {
                case 0:
                    return [self valueCellWithTitle:@"Configuration"
                                              value:[SRPWaterWallChainConfig isDirectConfiguration:configuration] ? @"Direct (diagnostics)" : @"Custom Chain"
                                       disclosure:YES];
                case 1:
                    return [self textCellWithTitle:@"Server" text:self.modal.server placeholder:@"Required"
                                               tag:kFieldHost keyboardType:UIKeyboardTypeURL secure:NO];
                case 2:
                    return [self textCellWithTitle:@"Port" text:self.modal.port placeholder:@"443"
                                               tag:kFieldPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                case 3:
                    return [self textCellWithTitle:@"SNI (optional)" text:self.modal.customSni placeholder:@"Server hostname"
                                               tag:kFieldCustomSni keyboardType:UIKeyboardTypeURL secure:NO];
                default:
                    return [self switchCellWithTitle:@"TLS Server Verification" on:!self.modal.TLS tag:kSwitchSETLSVerify];
            }
        }
        if ([self isAether]) {
            if (indexPath.row == 0) {
                return [self segmentCellWithTitle:@"Server"
                                            items:@[@"Public (WARP)", @"Private"]
                                         selected:[self isAetherPrivate] ? 1 : 0
                                           action:@selector(aetherModeChanged:) tag:kSegmentOnSleep + 101];
            }
            if (![self isAetherPrivate]) {
                BOOL torOnly = [self.modal.aetherTor isEqualToString:@"only"];
                if (indexPath.row == 1 && !torOnly) {
                    return [self valueCellWithTitle:@"Transport"
                                              value:[SRPAetherTransportViewController titleForTransport:self.modal.aetherTransport]
                                         disclosure:YES];
                }
                if (indexPath.row == 2 && !torOnly) {
                    return [self segmentCellWithTitle:@"Endpoint Scan"
                                                items:@[@"Balanced", @"Turbo"]
                                             selected:[self.modal.aetherScan isEqualToString:@"turbo"] ? 1 : 0
                                               action:@selector(aetherScanChanged:) tag:kSegmentOnSleep + 105];
                }
                if (indexPath.row == 3 && !torOnly) {
                    return [self textCellWithTitle:@"WARP+ License" text:self.modal.aetherLicense placeholder:@"Optional"
                                               tag:kFieldAetherLicense keyboardType:UIKeyboardTypeASCIICapable secure:NO];
                }
                NSInteger torSel = [self.modal.aetherTor isEqualToString:@"only"] ? 2
                                 : [self.modal.aetherTor isEqualToString:@"reverse"] ? 1 : 0;
                return [self segmentCellWithTitle:@"Tor"
                                            items:@[@"Off", @"WARP via Tor", @"Tor Only"]
                                         selected:torSel
                                           action:@selector(aetherTorChanged:) tag:kSegmentOnSleep + 102];
            }
            switch (indexPath.row) {
                case 1:
                    return [self textCellWithTitle:@"Server" text:self.modal.server placeholder:@"Required"
                                               tag:kFieldHost keyboardType:UIKeyboardTypeURL secure:NO];
                case 2:
                    return [self textCellWithTitle:@"Port" text:self.modal.port placeholder:@"51820"
                                               tag:kFieldPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                default: {
                    NSString *configState = self.modal.wgPrivateKey.length > 0 ? @"Configured" : @"None";
                    return [self valueCellWithTitle:@"Manual Configuration" value:configState disclosure:YES];
                }
            }
        }
        if ([self isWireGuard]) {
            NSString *configState = self.modal.wgConfig.length > 0 ? @"Imported"
                                  : (self.modal.wgPrivateKey.length > 0 ? @"Manual" : @"None");
            switch (indexPath.row) {
                case 0:
                    return [self valueCellWithTitle:@"Import Config (.conf)"
                                              value:(self.modal.wgConfig.length > 0 ? @"Imported" : @"None")
                                         disclosure:YES];
                case 1:
                    return [self valueCellWithTitle:@"Manual Configuration"
                                              value:(self.modal.wgConfig.length > 0 ? @"Overridden by import" : configState)
                                         disclosure:YES];
                case 2:
                    return [self textCellWithTitle:@"Server" text:self.modal.server placeholder:@"Required"
                                               tag:kFieldHost keyboardType:UIKeyboardTypeURL secure:NO];
                case 3:
                    return [self textCellWithTitle:@"Port" text:self.modal.port placeholder:@"51820"
                                               tag:kFieldPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                default: break;
            }
        }
        if ([self isOpenVPN]) {
            switch (indexPath.row) {
                case 0:
                    return [self valueCellWithTitle:@"Profile (.ovpn)"
                                              value:(self.modal.ovpnProfile.length > 0 ? @"Imported" : @"None")
                                         disclosure:YES];
                case 1:
                    return [self textCellWithTitle:@"Server" text:self.modal.server placeholder:@"Required"
                                               tag:kFieldHost keyboardType:UIKeyboardTypeURL secure:NO];
                case 2:
                    return [self textCellWithTitle:@"Port" text:self.modal.port placeholder:@"1194"
                                               tag:kFieldPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                case 3:
                    return [self switchCellWithTitle:@"Enable stunnel (TLS)" on:self.modal.ovpnStunnelEnabled tag:kSwitchOVPNStunnel];
                case 4:
                    return [self textCellWithTitle:@"stunnel Host" text:self.modal.ovpnStunnelHost placeholder:@"Optional — default: Server"
                                               tag:kFieldOVPNStunnelHost keyboardType:UIKeyboardTypeURL secure:NO];
                case 5:
                    return [self textCellWithTitle:@"stunnel Port" text:self.modal.ovpnStunnelPort placeholder:@"443"
                                               tag:kFieldOVPNStunnelPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                case 6:
                    return [self textCellWithTitle:@"stunnel SNI" text:self.modal.ovpnStunnelSNI placeholder:@"Optional — default: stunnel Host"
                                               tag:kFieldOVPNStunnelSNI keyboardType:UIKeyboardTypeURL secure:NO];
                case 7:
                    return [self valueCellWithTitle:@"CA Certificate"
                                              value:(self.modal.ovpnStunnelCA.length > 0 ? @"Imported" : @"System Trust")
                                         disclosure:YES];
                default: break;
            }
        }
        if ([self isSSH]) {
            switch (indexPath.row) {
                case 0:
                    return [self textCellWithTitle:@"Server" text:self.modal.server placeholder:@"Required"
                                               tag:kFieldHost keyboardType:UIKeyboardTypeURL secure:NO];
                case 1:
                    return [self textCellWithTitle:@"Port" text:self.modal.port placeholder:@"22"
                                               tag:kFieldPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                case 2:
                    return [self textCellWithTitle:@"Host Key (SHA256)" text:self.modal.sshHostKey placeholder:@"Optional — SHA256:..."
                                                   tag:kFieldSSHHostKey keyboardType:UIKeyboardTypeDefault secure:NO];
                case 3:
                    return [self switchCellWithTitle:@"UDP Relay (HEV)" on:self.modal.sshUdpRelay tag:kSwitchSSHRelay];
                default: break;
            }
        }
        if ([self isOpenConnect]) {
            switch (indexPath.row) {
                case 0:
                    return [self valueCellWithTitle:@"Server Type"
                                              value:[SRPOCServerTypeViewController titleForType:self.modal.ocProtocol]
                                         disclosure:YES];
                case 1:
                    return [self textCellWithTitle:@"Server" text:self.modal.server placeholder:@"Required"
                                               tag:kFieldHost keyboardType:UIKeyboardTypeURL secure:NO];
                case 2:
                    return [self textCellWithTitle:@"Port" text:self.modal.port placeholder:@"443"
                                               tag:kFieldPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                case 3:
                    return [self switchCellWithTitle:@"TLS Server Verification" on:!self.modal.TLS tag:kSwitchSETLSVerify];
                default: break;
            }
        }
        if ([self isSoftEther]) {
            switch (indexPath.row) {
                case 0:
                    return [self textCellWithTitle:@"Server" text:self.modal.server placeholder:@"Required"
                                               tag:kFieldHost keyboardType:UIKeyboardTypeURL secure:NO];
                case 1:
                    return [self textCellWithTitle:@"Port" text:self.modal.port placeholder:@"443"
                                               tag:kFieldPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                case 2:
                    return [self textCellWithTitle:@"Hostname" text:self.modal.hostnameOverride placeholder:@"Optional"
                                               tag:kFieldSEHostname keyboardType:UIKeyboardTypeURL secure:NO];
                case 3:
                    return [self switchCellWithTitle:@"TLS Server Verification" on:!self.modal.TLS tag:kSwitchSETLSVerify];
                case 4:
                    return [self textCellWithTitle:@"Virtual Hub" text:self.modal.hubName placeholder:@"DEFAULT"
                                               tag:kFieldSEHub keyboardType:UIKeyboardTypeDefault secure:NO];
                case 5:
                    return [self textInfoCellWithTitle:@"Connections"
                                                  text:(self.modal.seConnections > 0 ? @(self.modal.seConnections).stringValue : @"1")
                                             placeholder:@"1 – 32"
                                                     tag:kFieldSEConnections
                                            keyboardType:UIKeyboardTypeNumberPad
                                              infoTitle:@"Connections"
                                           infoMessage:@"Multiple connections may improve stability but also consume more memory. Please do not use under heavy load as the VPN may get killed for excessive memory usage."];
                case 6:
                    return [self switchCellWithTitle:@"Enable UDP Acceleration" on:self.modal.seUdpAcceleration tag:kSwitchSEUdpAccel];
                case 7:
                    return [self switchCellWithTitle:@"Enable NAT Traversal (NAT-T)" on:self.modal.seNatTraversal tag:kSwitchSENatT];
                case 8:
                    return [self textInfoCellWithTitle:@"NAT-T Hint"
                                                  text:self.modal.seNatTHint
                                           placeholder:@"Optional"
                                                     tag:kFieldSENatTHint
                                            keyboardType:UIKeyboardTypeURL
                                              infoTitle:@"NAT-T Hint"
                                           infoMessage:@"To connect over NAT-T, the app needs to look up the UDP port of the VPN server by sending connection information to the NAT-T server managed by SoftEther Corporation. In case there are multiple VPN servers on the same public IP address, enter its private IP address here."];
                default: break;
            }
        }
        switch (indexPath.row) {
            case 0:
                return [self textCellWithTitle:@"Host" text:self.modal.server placeholder:@"Required"
                                           tag:kFieldHost keyboardType:UIKeyboardTypeURL secure:NO];
            case 1:
                return [self textCellWithTitle:@"Port" text:self.modal.port placeholder:@"443"
                                           tag:kFieldPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
            case 2:
                return [self switchCellWithTitle:@"Allow Untrusted Certificate" on:self.modal.TLS tag:kSwitchAllowUntrusted];
            default: break;
        }
    }
    if (indexPath.section == 2 && [self isWaterWall]) {
        NSDictionary *configuration = [self waterWallConfiguration];
        BOOL needsApplicationSecret = [SRPWaterWallChainConfig configurationNeedsApplicationSecret:configuration];
        NSString *application = configuration[@"application"];
        BOOL proxy = [application isEqualToString:@"socks5"] || [application isEqualToString:@"http-proxy"];
        NSInteger applicationRows = needsApplicationSecret ? (proxy ? 2 : 1) : 0;
        BOOL isOuterSecretRow = [self waterWallNeedsOuterSecret] && indexPath.row == applicationRows;
        if (isOuterSecretRow) {
            NSString *title = [configuration[@"outer"] isEqualToString:@"aead"] ? @"AEAD Password" : @"Reality Password";
            return [self textCellWithTitle:title text:self.modal.waterwallOuterSecret placeholder:@"Required"
                                       tag:kFieldWWOuterSecret keyboardType:UIKeyboardTypeASCIICapable secure:YES];
        }
        if (proxy && indexPath.row == 0) {
            return [self textCellWithTitle:@"Username" text:self.modal.username placeholder:@"Optional"
                                       tag:kFieldUsername keyboardType:UIKeyboardTypeASCIICapable secure:NO];
        }
        NSString *title = [application isEqualToString:@"trojan"] ? @"Password" :
                          [application isEqualToString:@"vmess"] ? @"UUID / ID" : proxy ? @"Password" : @"UUID";
        return [self textCellWithTitle:title text:self.modal.password placeholder:proxy ? @"Optional" : @"Required"
                                   tag:kFieldPassword keyboardType:UIKeyboardTypeASCIICapable secure:YES];
    }
    if (indexPath.section == 2 && [self isOpenVPN]) {
        if (![self ovpnNeedsAuth]) {
            return [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        }
        switch (indexPath.row) {
            case 0:
                return [self textCellWithTitle:@"Username" text:self.modal.username placeholder:@"Required"
                                           tag:kFieldUsername keyboardType:UIKeyboardTypeDefault secure:NO];
            case 1:
                return [self textCellWithTitle:@"Password" text:self.modal.password placeholder:@"Required"
                                           tag:kFieldPassword keyboardType:UIKeyboardTypeDefault secure:YES];
            default: break;
        }
    }
    if (indexPath.section == 2 && [self isOpenConnect]) {
        if (indexPath.row == 0) {
            NSString *methodTitle = [self isCertificateMode] ? @"Certificate" : @"Password";
            return [self valueCellWithTitle:@"Method" value:methodTitle disclosure:YES];
        }
        if (indexPath.row == 1) {
            return [self textCellWithTitle:@"Username" text:self.modal.username placeholder:@"Required"
                                       tag:kFieldUsername keyboardType:UIKeyboardTypeDefault secure:NO];
        }
        if ([self isCertificateMode]) {
            return [self valueCellWithTitle:@"Certificate"
                                      value:(self.modal.certName.length > 0 ? self.modal.certName : @"None")
                                 disclosure:YES];
        }
        return [self textCellWithTitle:@"Password" text:self.modal.password placeholder:@"Required"
                                   tag:kFieldPassword keyboardType:UIKeyboardTypeDefault secure:YES];
    }
    if (indexPath.section == 2 && [self isSoftEther]) {
        if (indexPath.row == 0) {
            return [self valueCellWithTitle:@"Method"
                                      value:[SRPSEMethodViewController titleForMethod:self.modal.seAuthMethod]
                                 disclosure:YES];
        }
        if (indexPath.row == 1) {
            return [self textCellWithTitle:@"Username" text:self.modal.username placeholder:@"Required"
                                       tag:kFieldUsername keyboardType:UIKeyboardTypeDefault secure:NO];
        }
        if (indexPath.row == 2) {
            if ([self isCertificateMode]) {
                return [self valueCellWithTitle:@"Certificate"
                                          value:(self.modal.certName.length > 0 ? self.modal.certName : @"None")
                                     disclosure:YES];
            }
            return [self textCellWithTitle:@"Password" text:self.modal.password placeholder:@"Required"
                                       tag:kFieldPassword keyboardType:UIKeyboardTypeDefault secure:YES];
        }
    }
    if (indexPath.section == 2) {
        if ([self isSSH]) {
            switch (indexPath.row) {
                case 0:
                    return [self textCellWithTitle:@"Username" text:self.modal.username placeholder:@"Required"
                                               tag:kFieldUsername keyboardType:UIKeyboardTypeDefault secure:NO];
                case 1:
                    return [self textCellWithTitle:@"Password" text:self.modal.password placeholder:@"Required"
                                               tag:kFieldPassword keyboardType:UIKeyboardTypeDefault secure:YES];
                default: break;
            }
        }
        if (indexPath.row == 0) {
            NSString *methodTitle = [self isCertificateMode] ? @"Certificate" : @"Password";
            return [self valueCellWithTitle:@"Method" value:methodTitle disclosure:YES];
        }
        if ([self isCertificateMode]) {
            switch (indexPath.row) {
                case 1:
                    // Optional: used as the identity hint / outer EAP identity
                    return [self textCellWithTitle:@"Username" text:self.modal.username placeholder:@"Optional"
                                               tag:kFieldUsername keyboardType:UIKeyboardTypeDefault secure:NO];
                case 2:
                    return [self valueCellWithTitle:@"Certificate"
                                              value:(self.modal.certName.length > 0 ? self.modal.certName : @"None")
                                         disclosure:YES];
                case 3:
                    return [self valueCellWithTitle:@"EAP Configuration" value:nil disclosure:YES];
                default: break;
            }
        }
        switch (indexPath.row) {
            case 1:
                return [self textCellWithTitle:@"Username" text:self.modal.username placeholder:@"Required"
                                           tag:kFieldUsername keyboardType:UIKeyboardTypeDefault secure:NO];
            case 2:
                return [self textCellWithTitle:@"Password" text:self.modal.password placeholder:@"Required"
                                           tag:kFieldPassword keyboardType:UIKeyboardTypeDefault secure:YES];
            case 3:
                return [self valueCellWithTitle:@"EAP Configuration" value:nil disclosure:YES];
            case 4:
                return [self switchCellWithTitle:@"Enable MS-CHAPv2" on:self.modal.MSCHAP2 tag:kSwitchMschapv2];
            case 5:
                return [self switchCellWithTitle:@"Enable PAP / CHAP (Less Secure)" on:self.modal.allowLegacyPapChap tag:kSwitchLegacyPapChap];
            default: break;
        }
    }
    if (indexPath.section == 3) {
        if (indexPath.row == 0) {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
            cell.textLabel.text = @"Mode";
            UISegmentedControl *seg = [[UISegmentedControl alloc] initWithItems:@[@"None", @"Manual", @"Auto"]];
            seg.selectedSegmentIndex = self.modal.proxyMode;
            seg.tag = kSegmentProxyMode;
            [seg addTarget:self action:@selector(proxyModeChanged:) forControlEvents:UIControlEventValueChanged];
            cell.accessoryView = seg;
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            return cell;
        }
        if (self.modal.proxyMode == 1) {
            if ([self isSoftEther] && indexPath.row == 3) {
                return [self segmentCellWithTitle:@"Type" items:@[@"HTTP", @"SOCKS5"]
                                         selected:[self.modal.proxyType isEqualToString:@"socks5"] ? 1 : 0
                                           action:@selector(seProxyTypeChanged:) tag:kSegmentSEProxyType];
            }
            NSInteger fieldRow = [self isSoftEther] && indexPath.row > 3 ? indexPath.row - 1 : indexPath.row;
            switch (fieldRow) {
                case 1:
                    return [self textCellWithTitle:@"Address" text:self.modal.proxyAddress placeholder:@"Required"
                                               tag:kFieldProxyAddress keyboardType:UIKeyboardTypeURL secure:NO];
                case 2:
                    return [self textCellWithTitle:@"Port" text:self.modal.proxyPort placeholder:@"Required"
                                               tag:kFieldProxyPort keyboardType:UIKeyboardTypeNumberPad secure:NO];
                case 3:
                    return [self textCellWithTitle:@"Username" text:self.modal.proxyUsername placeholder:@"Optional"
                                               tag:kFieldProxyUsername keyboardType:UIKeyboardTypeDefault secure:NO];
                case 4:
                    return [self textCellWithTitle:@"Password" text:self.modal.proxyPassword placeholder:@"Optional"
                                               tag:kFieldProxyPassword keyboardType:UIKeyboardTypeDefault secure:YES];
                default: break;
            }
        }
        if (self.modal.proxyMode == 2 && indexPath.row == 1) {
            return [self textCellWithTitle:@"PAC URL" text:self.modal.pacURL placeholder:@"https://example.com/proxy.pac"
                                       tag:kFieldPacURL keyboardType:UIKeyboardTypeURL secure:NO];
        }
    }
    if (indexPath.section == 4) {
        if ([self isWaterWall]) {
            // Same reconnect, Wi-Fi and sleep rows as the other engines; rows
            // shift when Auto Reconnect hides Retry Times
            BOOL ar = self.modal.autoReconnect;
            NSInteger row = indexPath.row;
            if (row == 0) {
                return [self switchCellWithTitle:@"Auto Reconnect" on:self.modal.autoReconnect tag:kSwitchAutoReconnect];
            }
            if (ar && row == 1) {
                return [self textCellWithTitle:@"Retry Times"
                                          text:(self.modal.retryTimes > 0 ? @(self.modal.retryTimes).stringValue : nil)
                                   placeholder:@"Unlimited"
                                           tag:kFieldRetryTimes keyboardType:UIKeyboardTypeNumberPad secure:NO];
            }
            NSInteger shifted = ar ? row : row + 1;   // align rows after Retry Times
            if (shifted == 2) {
                return [self switchCellWithTitle:@"Switch to Wi-Fi When Available" on:self.modal.switchToWifi tag:kSwitchSwitchToWifi];
            }
            if (shifted == 3) {
                return [self segmentCellWithTitle:@"On Sleep" items:@[@"Off", @"Pause", @"Stay"]
                                         selected:self.modal.onSleep action:@selector(onSleepChanged:) tag:kSegmentOnSleep];
            }
            if (shifted == 4) {
                return [self segmentCellWithTitle:@"Log Level" items:@[@"Normal", @"Expert", @"Debug"]
                                         selected:self.modal.logLevel action:@selector(logLevelChanged:) tag:kSegmentLogLevel];
            }
            NSDictionary *configuration = [self waterWallConfiguration];
            BOOL fragmentation = [SRPWaterWallChainConfig configurationAllowsFragmentation:configuration];
            BOOL routing = [SRPWaterWallChainConfig configurationAllowsRouting:configuration];
            if (fragmentation && shifted == 5) {
                return [self segmentCellWithTitle:@"TLS Fragmentation" items:@[@"Off", @"Auto", @"Manual"]
                                         selected:self.modal.tlsFragMode action:@selector(tlsFragChanged:) tag:kSegmentTLSFrag];
            }
            if (fragmentation && self.modal.tlsFragMode == 2 && shifted == 6) {
                return [self textCellWithTitle:@"First Chunk (bytes)"
                                          text:(self.modal.tlsFragFirst > 0 ? @(self.modal.tlsFragFirst).stringValue : nil)
                                   placeholder:@"32" tag:kFieldTLSFragFirst keyboardType:UIKeyboardTypeNumberPad secure:NO];
            }
            if (fragmentation && self.modal.tlsFragMode == 2 && shifted == 7) {
                return [self textCellWithTitle:@"Following Chunks (bytes)"
                                          text:(self.modal.tlsFragFollowing > 0 ? @(self.modal.tlsFragFollowing).stringValue : nil)
                                   placeholder:@"256" tag:kFieldTLSFragFollowing keyboardType:UIKeyboardTypeNumberPad secure:NO];
            }
            NSInteger routingRow = 5 + (fragmentation ? 1 + (self.modal.tlsFragMode == 2 ? 2 : 0) : 0);
            if (routing && shifted == routingRow) {
                return [self switchCellWithTitle:@"Remote DNS (Fake IP)" on:self.modal.waterwallFakeDNS tag:kSwitchWWFakeDNS];
            }
            if (routing && shifted == routingRow + 1) {
                return [self switchCellWithTitle:@"Direct LAN Routing" on:self.modal.waterwallSmartRouting tag:kSwitchWWSmartRouting];
            }
            return [UITableViewCell new];
        }
        if ([self isWireGuard] || [self isPsiphon] || [self isAether]) {
            // Log Level; Aether-H2 adds TLS Fragmentation below it
            if (indexPath.row == 0) {
                return [self segmentCellWithTitle:@"Log Level" items:@[@"Normal", @"Expert", @"Debug"]
                                         selected:self.modal.logLevel action:@selector(logLevelChanged:) tag:kSegmentLogLevel];
            }
            BOOL fragOK = [self isAether] && ([self.modal.aetherTransport isEqualToString:@"masque-h2"] || [self.modal.aetherTransport isEqualToString:@"masque-both"]);
            if (fragOK && indexPath.row == 1) {
                return [self segmentCellWithTitle:@"TLS Fragmentation" items:@[@"Off", @"Auto", @"Manual"]
                                         selected:self.modal.tlsFragMode action:@selector(tlsFragChanged:) tag:kSegmentTLSFrag];
            }
            if (fragOK && self.modal.tlsFragMode == 2 && indexPath.row == 2) {
                return [self textCellWithTitle:@"Min Chunk (bytes)"
                                          text:(self.modal.tlsFragFirst > 0 ? @(self.modal.tlsFragFirst).stringValue : nil)
                                   placeholder:@"32" tag:kFieldTLSFragFirst keyboardType:UIKeyboardTypeNumberPad secure:NO];
            }
            if (fragOK && self.modal.tlsFragMode == 2 && indexPath.row == 3) {
                return [self textCellWithTitle:@"Max Chunk (bytes)"
                                          text:(self.modal.tlsFragFollowing > 0 ? @(self.modal.tlsFragFollowing).stringValue : nil)
                                   placeholder:@"256" tag:kFieldTLSFragFollowing keyboardType:UIKeyboardTypeNumberPad secure:NO];
            }
            return [UITableViewCell new];
        }
        if ([self isOpenConnect] || [self isSoftEther] || [self isSSH] || [self isOpenVPN]) {
            // OPTIONS for the non-SSTP engines: Auto Reconnect (+Retry),
            // Switch to Wi-Fi, On Sleep, Log Level (+ TLS Fragmentation
            // only where an outer TLS handshake exists: OpenConnect,
            // SoftEther, OpenVPN-stunnel). Aether has neither an outer TLS
            // handshake nor SNI — "Disable TLS 1.0" does not apply to it.
            BOOL ar = self.modal.autoReconnect;
            NSInteger row = indexPath.row;
            if (row == 0) {
                return [self switchCellWithTitle:@"Auto Reconnect" on:self.modal.autoReconnect tag:kSwitchAutoReconnect];
            }
            if (ar && row == 1) {
                return [self textCellWithTitle:@"Retry Times"
                                          text:(self.modal.retryTimes > 0 ? @(self.modal.retryTimes).stringValue : nil)
                                   placeholder:@"Unlimited"
                                           tag:kFieldRetryTimes keyboardType:UIKeyboardTypeNumberPad secure:NO];
            }
            NSInteger shifted = ar ? row : row + 1;
            if (shifted == 2) {
                return [self switchCellWithTitle:@"Switch to Wi-Fi When Available" on:self.modal.switchToWifi tag:kSwitchSwitchToWifi];
            }
            if (shifted == 3) {
                return [self segmentCellWithTitle:@"On Sleep" items:@[@"Off", @"Pause", @"Stay"]
                                         selected:self.modal.onSleep action:@selector(onSleepChanged:) tag:kSegmentOnSleep];
            }
            if (shifted == 4) {
                return [self segmentCellWithTitle:@"Log Level" items:@[@"Normal", @"Expert", @"Debug"]
                                         selected:self.modal.logLevel action:@selector(logLevelChanged:) tag:kSegmentLogLevel];
            }
            BOOL fragOK = [self isOpenConnect] || [self isSoftEther] ||
                          ([self isOpenVPN] && self.modal.ovpnStunnelEnabled) ||
                          ([self isAether] && ([self.modal.aetherTransport isEqualToString:@"masque-h2"] || [self.modal.aetherTransport isEqualToString:@"masque-both"]));
            if (fragOK && shifted == 5) {
                return [self segmentCellWithTitle:@"TLS Fragmentation" items:@[@"Off", @"Auto", @"Manual"]
                                         selected:self.modal.tlsFragMode action:@selector(tlsFragChanged:) tag:kSegmentTLSFrag];
            }
            if (fragOK && self.modal.tlsFragMode == 2 && shifted == 6) {
                return [self textCellWithTitle:[self isAether] ? @"Min Chunk (bytes)" : @"First Chunk (bytes)"
                                          text:(self.modal.tlsFragFirst > 0 ? @(self.modal.tlsFragFirst).stringValue : nil)
                                   placeholder:@"32" tag:kFieldTLSFragFirst keyboardType:UIKeyboardTypeNumberPad secure:NO];
            }
            if (fragOK && self.modal.tlsFragMode == 2 && shifted == 7) {
                return [self textCellWithTitle:[self isAether] ? @"Max Chunk (bytes)" : @"Following Chunks (bytes)"
                                          text:(self.modal.tlsFragFollowing > 0 ? @(self.modal.tlsFragFollowing).stringValue : nil)
                                   placeholder:@"256" tag:kFieldTLSFragFollowing keyboardType:UIKeyboardTypeNumberPad secure:NO];
            }
        }
        // OPTIONS: rows shift when Auto Reconnect hides Retry Times
        BOOL ar = self.modal.autoReconnect;
        NSInteger row = indexPath.row;
        if (row == 0) {
            return [self switchCellWithTitle:@"Disable TLS 1.0 & 1.1" on:self.modal.disableLegacyOuterTls tag:kSwitchDisableLegacyOuterTls];
        }
        if (row == 1) {
            return [self switchCellWithTitle:@"Auto Reconnect" on:self.modal.autoReconnect tag:kSwitchAutoReconnect];
        }
        if (ar && row == 2) {
            return [self textCellWithTitle:@"Retry Times"
                                      text:(self.modal.retryTimes > 0 ? @(self.modal.retryTimes).stringValue : nil)
                               placeholder:@"Unlimited"
                                       tag:kFieldRetryTimes keyboardType:UIKeyboardTypeNumberPad secure:NO];
        }
        NSInteger shifted = ar ? row : row + 1;   // align rows after Retry Times
        if (shifted == 3) {
            return [self switchCellWithTitle:@"Switch to Wi-Fi When Available" on:self.modal.switchToWifi tag:kSwitchSwitchToWifi];
        }
        if (shifted == 4) {
            return [self segmentCellWithTitle:@"On Sleep" items:@[@"Off", @"Pause", @"Stay"]
                                     selected:self.modal.onSleep action:@selector(onSleepChanged:) tag:kSegmentOnSleep];
        }
        if (shifted == 5) {
            return [self segmentCellWithTitle:@"Log Level" items:@[@"Normal", @"Expert", @"Debug"]
                                     selected:self.modal.logLevel action:@selector(logLevelChanged:) tag:kSegmentLogLevel];
        }
        if (shifted == 6) {
            return [self switchCellWithTitle:@"Enable Custom SNI" on:self.modal.customSniEnabled tag:kSwitchCustomSni];
        }
        // The SNI hostname row exists only when Custom SNI is on — the
        // fragmentation rows must not depend on it.
        NSInteger fragBase = self.modal.customSniEnabled ? 8 : 7;
        if (self.modal.customSniEnabled && shifted == 7) {
            // SNI hostname: bare DNS name only (validated on save); the TCP
            // destination always stays the Host field
            return [self textCellWithTitle:@"SNI Hostname" text:self.modal.customSni placeholder:@"vpn.example.com"
                                       tag:kFieldCustomSni keyboardType:UIKeyboardTypeURL secure:NO];
        }
        if (shifted == fragBase) {
            return [self segmentCellWithTitle:@"TLS Fragmentation" items:@[@"Off", @"Auto", @"Manual"]
                                     selected:self.modal.tlsFragMode action:@selector(tlsFragChanged:) tag:kSegmentTLSFrag];
        }
        if (self.modal.tlsFragMode == 2 && shifted == fragBase + 1) {
            return [self textCellWithTitle:@"First Chunk (bytes)"
                                      text:(self.modal.tlsFragFirst > 0 ? @(self.modal.tlsFragFirst).stringValue : nil)
                               placeholder:@"32" tag:kFieldTLSFragFirst keyboardType:UIKeyboardTypeNumberPad secure:NO];
        }
        if (self.modal.tlsFragMode == 2 && shifted == fragBase + 2) {
            return [self textCellWithTitle:@"Following Chunks (bytes)"
                                      text:(self.modal.tlsFragFollowing > 0 ? @(self.modal.tlsFragFollowing).stringValue : nil)
                               placeholder:@"256" tag:kFieldTLSFragFollowing keyboardType:UIKeyboardTypeNumberPad secure:NO];
        }
    }
    return [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == 0 && indexPath.row == 0) {
        [self protocolTapped];
        return;
    }
    if ([self isPsiphon] && indexPath.section == 1 && indexPath.row == 0) {
        SRPPsiphonEntriesViewController *vc = [[SRPPsiphonEntriesViewController alloc] initWithNodeModel:self.modal];
        [self.navigationController pushViewController:vc animated:YES];
        return;
    }
    if ([self isWaterWall] && indexPath.section == 1) {
        if (indexPath.row == 0) {
            SRPWaterWallConfigViewController *vc = [[SRPWaterWallConfigViewController alloc] initWithNodeModel:self.modal];
            [self.navigationController pushViewController:vc animated:YES];
        } else if ([SRPWaterWallChainConfig isWireGuardConfiguration:[self waterWallConfiguration]]) {
            if (indexPath.row == 1) {
                [self importWGConfig];
            } else if (indexPath.row == 2) {
                SRPWGConfigViewController *vc = [[SRPWGConfigViewController alloc] initWithNodeModel:self.modal];
                [self.navigationController pushViewController:vc animated:YES];
            }
        }
        return;
    }
    if ([self isAether]) {
        if (![self isAetherPrivate] && indexPath.section == 1 && indexPath.row == 1 &&
            ![self.modal.aetherTor isEqualToString:@"only"]) {
            SRPAetherTransportViewController *vc = [[SRPAetherTransportViewController alloc] initWithNodeModel:self.modal];
            [self.navigationController pushViewController:vc animated:YES];
            return;
        }
        if ([self isAetherPrivate] && indexPath.section == 1 && indexPath.row == 3) {
            SRPWGConfigViewController *vc = [[SRPWGConfigViewController alloc] initWithNodeModel:self.modal];
            [self.navigationController pushViewController:vc animated:YES];
        }
        return;
    }
    if ([self isOpenVPN]) {
        if (indexPath.section == 1 && indexPath.row == 0) {
            [self importOvpnProfile];
            return;
        }
        if (indexPath.section == 1 && indexPath.row == 7 && self.modal.ovpnStunnelEnabled) {
            [self importStunnelCA];
            return;
        }
        return;
    }
    if ([self isWireGuard]) {
        if (indexPath.section == 1 && indexPath.row == 0) {
            [self importWGConfig];
        }
        else if (indexPath.section == 1 && indexPath.row == 1) {
            SRPWGConfigViewController *vc = [[SRPWGConfigViewController alloc] initWithNodeModel:self.modal];
            [self.navigationController pushViewController:vc animated:YES];
        }
        return;
    }
    if ([self isOpenConnect]) {
        if (indexPath.section == 1 && indexPath.row == 0) {
            SRPOCServerTypeViewController *vc = [[SRPOCServerTypeViewController alloc] initWithNodeModel:self.modal];
            [self.navigationController pushViewController:vc animated:YES];
            return;
        }
        if (indexPath.section == 2 && indexPath.row == 0) {
            SRPMethodViewController *vc = [[SRPMethodViewController alloc] initWithNodeModel:self.modal];
            [self.navigationController pushViewController:vc animated:YES];
        }
        else if (indexPath.section == 2 && indexPath.row == 2 && [self isCertificateMode]) {
            SRPCertificateViewController *vc = [[SRPCertificateViewController alloc] initWithNodeModel:self.modal];
            [self.navigationController pushViewController:vc animated:YES];
        }
        return;
    }
    if ([self isSoftEther]) {
        if (indexPath.section == 2 && indexPath.row == 0) {
            SRPSEMethodViewController *vc = [[SRPSEMethodViewController alloc] initWithNodeModel:self.modal];
            [self.navigationController pushViewController:vc animated:YES];
        }
        else if (indexPath.section == 2 && indexPath.row == 2 && [self isCertificateMode]) {
            SRPCertificateViewController *vc = [[SRPCertificateViewController alloc] initWithNodeModel:self.modal];
            [self.navigationController pushViewController:vc animated:YES];
        }
        return;
    }
    if (indexPath.section == 2 && indexPath.row == 0) {
        SRPMethodViewController *vc = [[SRPMethodViewController alloc] initWithNodeModel:self.modal];
        [self.navigationController pushViewController:vc animated:YES];
    }
    else if (indexPath.section == 2 && [self isCertificateMode] && indexPath.row == 2) {
        SRPCertificateViewController *vc = [[SRPCertificateViewController alloc] initWithNodeModel:self.modal];
        [self.navigationController pushViewController:vc animated:YES];
    }
    else if (indexPath.section == 2 && indexPath.row == 3) {
        // EAP Configuration is available in both password and certificate mode
        SRPEapConfigViewController *vc = [[SRPEapConfigViewController alloc] initWithNodeModel:self.modal];
        [self.navigationController pushViewController:vc animated:YES];
    }
}

#pragma mark - OpenVPN file import

- (void)importOvpnProfile {
    [self offerImportModeForTitle:@"OpenVPN Profile" mode:@"ovpn"];
}

- (void)importStunnelCA {
    [self offerImportModeForTitle:@"CA Certificate" mode:@"ca"];
}

- (void)importWGConfig {
    objc_setAssociatedObject(self, "importMode", @"wg", OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    UIDocumentPickerViewController *picker =
        [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeText, UTTypeData] asCopy:YES];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

/// Action sheet: import from Files or from URL (the .ovpn and CA files are
/// long; a URL import avoids copy/paste corruption entirely)
- (void)offerImportModeForTitle:(NSString *)title mode:(NSString *)mode {
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:title
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    [sheet addAction:[UIAlertAction actionWithTitle:@"From Files" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        objc_setAssociatedObject(self, "importMode", mode, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        UIDocumentPickerViewController *picker =
            [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeText, UTTypeData] asCopy:YES];
        picker.delegate = self;
        picker.allowsMultipleSelection = NO;
        [self presentViewController:picker animated:YES completion:nil];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"From URL" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Import from URL"
                                                                       message:nil
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *f) {
            f.placeholder = @"https://...";
            f.keyboardType = UIKeyboardTypeURL;
            f.autocorrectionType = UITextAutocorrectionTypeNo;
            f.autocapitalizationType = UITextAutocapitalizationTypeNone;
        }];
        [alert addAction:[UIAlertAction actionWithTitle:@"Import" style:UIAlertActionStyleDefault handler:^(UIAlertAction *act) {
            NSString *u = alert.textFields.firstObject.text;
            [self downloadImportURL:u mode:mode];
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    // iPad: action sheets need a popover anchor
    sheet.popoverPresentationController.sourceView = self.tableView;
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)downloadImportURL:(NSString *)urlString mode:(NSString *)mode {
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url || url.host.length == 0) {
        [self showInfoAlertWithTitle:@"Invalid URL" message:@"Enter a full URL (https://...)."];
        return;
    }
    [[[NSURLSession sharedSession] dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        NSString *text = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            if (text.length == 0) {
                [self showInfoAlertWithTitle:@"Download Failed"
                                     message:err.localizedDescription ?: @"The file could not be downloaded."];
                return;
            }
            [self handleImportedText:text mode:mode];
        });
    }] resume];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) {
        return;
    }
    NSString *mode = objc_getAssociatedObject(self, "importMode");
    NSString *text = [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:nil];
    if (text.length == 0) {
        [self showInfoAlertWithTitle:@"Import Failed" message:@"The file could not be read as UTF-8 text."];
        return;
    }
    [self handleImportedText:text mode:mode];
}

/// Every PEM CERTIFICATE block in the text must have a base64 body that
/// actually decodes. A certificate copied through a chat app often survives
/// with mangled base64 — it still contains "BEGIN CERTIFICATE" but the
/// OpenVPN core later rejects it with "parse_cert_crl_error ... bad base64
/// decode". Catch that here, at import time, with an actionable message.
- (BOOL)pemCertificatesAreValid:(NSString *)text {
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:
        @"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
        options:NSRegularExpressionDotMatchesLineSeparators error:nil];
    NSArray<NSTextCheckingResult *> *blocks = [re matchesInString:text options:0 range:NSMakeRange(0, text.length)];
    if (blocks.count == 0) {
        return NO;
    }
    for (NSTextCheckingResult *block in blocks) {
        NSString *body = [text substringWithRange:[block rangeAtIndex:1]];
        NSString *b64 = [[body componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]
                         componentsJoinedByString:@""];
        if (b64.length == 0 || ![[NSData alloc] initWithBase64EncodedString:b64 options:0]) {
            return NO;
        }
    }
    return YES;
}

/// Shared import processing for file and URL imports (mode: ovpn | ca | wg)
- (void)handleImportedText:(NSString *)text mode:(NSString *)mode {
    if ([mode isEqualToString:@"ca"]) {
        if (![text containsString:@"BEGIN CERTIFICATE"]) {
            [self showInfoAlertWithTitle:@"Import Failed" message:@"The file does not look like a PEM certificate (no BEGIN CERTIFICATE block)."];
            return;
        }
        if (![self pemCertificatesAreValid:text]) {
            [self showInfoAlertWithTitle:@"Import Failed"
                                 message:@"The certificate is damaged — the base64 inside the PEM block does not decode. This usually happens when the file is copied through a chat app. Import the original file, or use \"From URL\"."];
            return;
        }
        self.modal.ovpnStunnelCA = text;
    }
    else if ([mode isEqualToString:@"wg"]) {
        if (![text containsString:@"[Interface]"] || ![text containsString:@"[Peer]"]) {
            [self showInfoAlertWithTitle:@"Import Failed" message:@"The file does not look like a WireGuard config (no [Interface]/[Peer] sections)."];
            return;
        }
        self.modal.wgConfig = text;
        // Prefill Server/Port from the [Peer] Endpoint line
        for (NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
            NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
            if ([trimmed.lowercaseString hasPrefix:@"endpoint"]) {
                NSString *value = [[trimmed componentsSeparatedByString:@"="].lastObject stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
                NSRange colon = [value rangeOfString:@":" options:NSBackwardsSearch];
                if (colon.location != NSNotFound) {
                    self.modal.server = [value substringToIndex:colon.location];
                    self.modal.port = [value substringFromIndex:colon.location + 1];
                }
                break;
            }
        }
    }
    else {
        if (![text containsString:@"remote"] || ![text containsString:@"dev"]) {
            [self showInfoAlertWithTitle:@"Import Failed" message:@"The file does not look like an OpenVPN profile (.ovpn)."];
            return;
        }
        // Embedded <ca>/<cert> PEM blocks must decode, or the core fails at
        // connect time with parse_cert_crl_error
        if ([text containsString:@"BEGIN CERTIFICATE"] && ![self pemCertificatesAreValid:text]) {
            [self showInfoAlertWithTitle:@"Import Failed"
                                 message:@"A certificate embedded in this profile is damaged — the base64 inside a PEM block does not decode. This usually happens when the file is copied through a chat app. Import the original file, or use \"From URL\"."];
            return;
        }
        self.modal.ovpnProfile = text;
        // Prefill Server/Port from the first "remote" line
        for (NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
            NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
            if ([trimmed hasPrefix:@"remote "]) {
                NSArray<NSString *> *parts = [trimmed componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
                parts = [parts filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
                if (parts.count >= 2) {
                    self.modal.server = parts[1];
                }
                if (parts.count >= 3) {
                    self.modal.port = parts[2];
                }
                break;
            }
        }
    }
    // The text-cell cache still holds cells built with the pre-import values —
    // refresh the fields the import just prefilled (Server/Port), or the form
    // would display the old value while the model already has the new one
    for (NSNumber *tag in @[@(kFieldHost), @(kFieldPort)]) {
        UITableViewCell *cell = self.textCellCache[tag];
        UITextField *f = [cell.accessoryView isKindOfClass:UITextField.class]
                         ? (UITextField *)cell.accessoryView : nil;
        if (f) {
            f.text = tag.integerValue == kFieldHost ? self.modal.server : self.modal.port;
        }
    }
    [self.tableView reloadData];
}

@end

#pragma mark - CreateVC (container, public API unchanged)

@interface CreateVC ()

@property (nonatomic,strong) SRPProfileEditViewController * tableVC;

@end

@implementation CreateVC

- (BOOL)isEditingExisting {
    return self.t_modal != nil;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    if(_t_modal) {
        self.modal = _t_modal;
    }else{
        self.modal = [NodeModel new];
        self.modal.MSCHAP2 = TRUE;
        self.modal.protocolType = @"sstp";
        self.modal.authMethod = @"password";
    }
    // nodeName defaults to the protocol name (SSTP / SoftEther) via the getter

    self.tableVC = [[SRPProfileEditViewController alloc] initWithStyle:UITableViewStyleGrouped];
    self.tableVC.owner = self;

    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:self.tableVC];
    [self addChildViewController:nav];
    nav.view.frame = self.view.bounds;
    nav.view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:nav.view];
    [nav didMoveToParentViewController:self];

    self.view.backgroundColor = UIColor.systemBackgroundColor;
}

-(void)saveNode {
    if(!self.modal.desc) {
        self.modal.desc = @"";
    }
    if(!self.modal.port) {
        self.modal.port = @"443";
    }
    // Password is pushed to Keychain by CheckConnectData/userNodeData on persist.
    if (self.backModal) {
        self.backModal(self.modal);
    }
    [self onCancel];
}

-(void)createNodeBackResult:(backNodeModal)modal {
    self.backModal = modal;
}

-(void)onCancel {
    [self dismissViewControllerAnimated:YES completion:nil];
}

@end
