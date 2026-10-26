#import "SRPWaterWallConfigViewController.h"
#import "NodeModel.h"
#import <SRPCore/SRPWaterWallChainConfig.h>

@interface SRPWaterWallNodeOptionsViewController : UIViewController

- (instancetype)initWithConfiguration:(NSDictionary *)configuration
                                layer:(NSString *)layer
                                title:(NSString *)title
                           completion:(void (^)(NSDictionary *configuration))completion;

@end

@interface SRPWaterWallConfigViewController ()

@property (nonatomic, strong) NodeModel *model;
@property (nonatomic, copy) NSDictionary *configuration;

@end

@implementation SRPWaterWallNodeOptionsViewController {
    NSDictionary *_configuration;
    NSString *_layer;
    void (^_completion)(NSDictionary *configuration);
    UITextView *_textView;
}

- (instancetype)initWithConfiguration:(NSDictionary *)configuration
                                layer:(NSString *)layer
                                title:(NSString *)title
                           completion:(void (^)(NSDictionary *configuration))completion {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _configuration = [configuration copy];
        _layer = [layer copy];
        _completion = [completion copy];
        self.title = title;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                                                          target:self
                                                                                          action:@selector(done)];

    NSDictionary *settings = _configuration[@"node-options"][_layer] ?: @{};
    NSData *data = [NSJSONSerialization dataWithJSONObject:settings
                                                   options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
                                                     error:nil];
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"{}";

    _textView = [[UITextView alloc] initWithFrame:CGRectZero];
    _textView.translatesAutoresizingMaskIntoConstraints = NO;
    _textView.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
    _textView.text = text;
    _textView.autocorrectionType = UITextAutocorrectionTypeNo;
    _textView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _textView.smartQuotesType = UITextSmartQuotesTypeNo;
    _textView.smartDashesType = UITextSmartDashesTypeNo;
    _textView.keyboardType = UIKeyboardTypeASCIICapable;
    _textView.alwaysBounceVertical = YES;
    [self.view addSubview:_textView];

    UILayoutGuide *guide = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [_textView.leadingAnchor constraintEqualToAnchor:guide.leadingAnchor],
        [_textView.trailingAnchor constraintEqualToAnchor:guide.trailingAnchor],
        [_textView.topAnchor constraintEqualToAnchor:guide.topAnchor],
        [_textView.bottomAnchor constraintEqualToAnchor:self.view.keyboardLayoutGuide.topAnchor]
    ]];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [_textView becomeFirstResponder];
}

- (void)showError:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Invalid Node Settings"
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)done {
    NSString *text = [_textView.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    id settings = @{};
    if (text.length > 0) {
        NSError *error = nil;
        settings = [NSJSONSerialization JSONObjectWithData:[text dataUsingEncoding:NSUTF8StringEncoding]
                                                   options:0
                                                     error:&error];
        if (settings == nil) {
            [self showError:error.localizedDescription ?: @"Enter a valid JSON object, or leave the editor empty for defaults."];
            return;
        }
    }
    if (![settings isKindOfClass:NSDictionary.class]) {
        [self showError:@"Advanced node settings must be a JSON object."];
        return;
    }

    NSMutableDictionary *configuration = [_configuration mutableCopy];
    NSMutableDictionary *options = [_configuration[@"node-options"] mutableCopy] ?: [NSMutableDictionary new];
    options[_layer] = settings;
    configuration[@"node-options"] = options;
    NSString *validationError = [SRPWaterWallChainConfig validationErrorForConfiguration:configuration];
    if (validationError != nil) {
        [self showError:validationError];
        return;
    }

    _completion(configuration);
    [self.navigationController popViewControllerAnimated:YES];
}

@end

@interface SRPWaterWallChoiceViewController : UITableViewController

- (instancetype)initWithTitle:(NSString *)title
                      choices:(NSArray<NSArray<NSString *> *> *)choices
                     selected:(NSString *)selected
                   completion:(void (^)(NSString *value))completion;

@end

@implementation SRPWaterWallChoiceViewController {
    NSArray<NSArray<NSString *> *> *_choices;
    NSString *_selected;
    void (^_completion)(NSString *value);
}

- (instancetype)initWithTitle:(NSString *)title
                      choices:(NSArray<NSArray<NSString *> *> *)choices
                     selected:(NSString *)selected
                   completion:(void (^)(NSString *value))completion {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        self.title = title;
        _choices = [choices copy];
        _selected = [selected copy];
        _completion = [completion copy];
    }
    return self;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return _choices.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    NSString *value = _choices[indexPath.row][0];
    cell.textLabel.text = _choices[indexPath.row][1];
    cell.accessibilityIdentifier = [@"WWChoice." stringByAppendingString:value];
    cell.accessoryType = [value isEqualToString:_selected] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    _completion(_choices[indexPath.row][0]);
    [self.navigationController popViewControllerAnimated:YES];
}

@end

@implementation SRPWaterWallConfigViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
        NSDictionary *stored = model.waterwallConfigJSON.length > 0 ?
            [SRPWaterWallChainConfig configurationWithJSON:model.waterwallConfigJSON] : nil;
        NSDictionary *legacy = stored == nil && model.waterwallPreset.length > 0 ?
            [SRPWaterWallChainConfig configurationFromLegacyPreset:model.waterwallPreset] : nil;
        NSDictionary *configuration = stored ?: legacy ?: [SRPWaterWallChainConfig defaultConfiguration];
        NSString *json = [SRPWaterWallChainConfig JSONWithConfiguration:configuration];
        _configuration = [([SRPWaterWallChainConfig configurationWithJSON:json] ?: configuration) copy];
        _model.waterwallConfigJSON = json;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"WaterWall";
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.tableView reloadData];
}

- (BOOL)isChain {
    return [self.configuration[@"mode"] isEqualToString:@"chain"];
}

- (BOOL)usesConnections {
    return [self.configuration[@"input"] isEqualToString:@"connections"];
}

- (BOOL)usesQUIC {
    return [self.configuration[@"outer"] isEqualToString:@"quic"];
}

- (NSString *)http {
    return self.configuration[@"http"] ?: @"off";
}

- (BOOL)httpEnabled {
    return ![self.http isEqualToString:@"off"];
}

- (NSString *)carrier {
    return self.configuration[@"carrier"] ?: @"tcp";
}

- (NSString *)quicCarrier {
    return self.configuration[@"quic-carrier"] ?: @"datagram";
}

- (BOOL)showsMux {
    return [self isChain] && [self usesConnections] &&
        ![self.configuration[@"application"] isEqualToString:@"socks5"] &&
        ![self.configuration[@"application"] isEqualToString:@"http-proxy"] &&
        (![self usesQUIC] || [self.quicCarrier isEqualToString:@"stream"]);
}

- (NSMutableDictionary *)mutableNodeOptions {
    return [self.configuration[@"node-options"] mutableCopy] ?: [NSMutableDictionary new];
}

- (void)applyConfiguration:(NSDictionary *)configuration {
    NSString *validationError = [SRPWaterWallChainConfig validationErrorForConfiguration:configuration];
    NSString *json = validationError == nil ? [SRPWaterWallChainConfig JSONWithConfiguration:configuration] : nil;
    if (validationError != nil || json.length == 0) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Invalid WaterWall Configuration"
                                                                       message:validationError ?: @"The configuration could not be serialized."
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    self.configuration = [SRPWaterWallChainConfig configurationWithJSON:json] ?: configuration;
    self.model.waterwallConfigJSON = json;
}

- (UITableViewCell *)segmentedCellWithTitle:(NSString *)title
                                      items:(NSArray<NSString *> *)items
                                   selected:(NSInteger)selected
                                     action:(SEL)action
                     accessibilityIdentifier:(NSString *)accessibilityIdentifier {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.textLabel.text = title;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    UISegmentedControl *control = [[UISegmentedControl alloc] initWithItems:items];
    control.selectedSegmentIndex = selected;
    control.accessibilityIdentifier = accessibilityIdentifier;
    [control addTarget:self action:action forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = control;
    return cell;
}

- (UITableViewCell *)switchCellWithTitle:(NSString *)title
                                     on:(BOOL)on
                                 action:(SEL)action
                  accessibilityIdentifier:(NSString *)accessibilityIdentifier {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    cell.textLabel.text = title;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    UISwitch *control = [[UISwitch alloc] init];
    control.on = on;
    control.accessibilityIdentifier = accessibilityIdentifier;
    [control addTarget:self action:action forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = control;
    return cell;
}

- (void)modeChanged:(UISegmentedControl *)sender {
    NSString *mode = sender.selectedSegmentIndex == 1 ? @"wireguard" :
        sender.selectedSegmentIndex == 2 ? @"direct" : @"chain";
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    configuration[@"mode"] = mode;
    configuration[@"node-options"] = @{};
    if ([mode isEqualToString:@"chain"]) {
        configuration[@"input"] = @"connections";
        configuration[@"application"] = @"vless";
        configuration[@"mux"] = @NO;
        configuration[@"outer"] = @"tls";
        configuration[@"http"] = @"off";
        configuration[@"http-version"] = @1;
        configuration[@"obfuscator"] = @NO;
        configuration[@"carrier"] = @"tcp";
        configuration[@"quic-carrier"] = @"datagram";
    } else {
        [configuration removeObjectsForKeys:@[@"input", @"application", @"mux", @"outer", @"http",
                                               @"http-version", @"obfuscator", @"carrier", @"quic-carrier"]];
    }
    [self applyConfiguration:configuration];
    [self.tableView reloadData];
}

- (void)inputChanged:(UISegmentedControl *)sender {
    BOOL raw = sender.selectedSegmentIndex == 1;
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    NSMutableDictionary *options = [self mutableNodeOptions];
    [options removeObjectsForKeys:@[@"packet", @"application", @"mux"]];
    configuration[@"node-options"] = options;
    configuration[@"input"] = raw ? @"raw-ipv4" : @"connections";
    configuration[@"application"] = raw ? @"" :
        ([configuration[@"application"] length] > 0 ? configuration[@"application"] : @"vless");
    configuration[@"mux"] = raw ? @NO : configuration[@"mux"] ?: @NO;
    [self applyConfiguration:configuration];
    [self.tableView reloadData];
}

- (void)applicationChanged:(NSString *)application {
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    NSMutableDictionary *options = [self mutableNodeOptions];
    [options removeObjectForKey:@"application"];
    configuration[@"application"] = application;
    self.model.username = nil;
    self.model.password = nil;
    if ([application isEqualToString:@"socks5"]) {
        configuration[@"mux"] = @NO;
        configuration[@"outer"] = @"none";
        configuration[@"http"] = @"off";
        configuration[@"obfuscator"] = @NO;
        configuration[@"carrier"] = @"tcp";
        [options removeObjectsForKeys:@[@"mux", @"outer", @"http", @"obfuscator", @"kcp"]];
    } else if ([application isEqualToString:@"http-proxy"]) {
        configuration[@"mux"] = @NO;
        configuration[@"http"] = @"off";
        configuration[@"carrier"] = @"tcp";
        [options removeObjectsForKeys:@[@"mux", @"http", @"kcp"]];
    }
    configuration[@"node-options"] = options;
    [self applyConfiguration:configuration];
    [self.tableView reloadData];
}

- (void)outerChanged:(NSString *)outer {
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    NSMutableDictionary *options = [self mutableNodeOptions];
    [options removeObjectForKey:@"outer"];
    configuration[@"outer"] = outer;
    if ([outer isEqualToString:@"quic"]) {
        configuration[@"http"] = @"off";
        configuration[@"carrier"] = @"tcp";
        configuration[@"quic-carrier"] = [configuration[@"application"] isEqualToString:@"http-proxy"] ? @"stream" : @"datagram";
        configuration[@"mux"] = @NO;
        [options removeObjectsForKeys:@[@"http", @"kcp", @"mux"]];
    }
    configuration[@"node-options"] = options;
    [self applyConfiguration:configuration];
    [self.tableView reloadData];
}

- (void)muxChanged:(UISwitch *)sender {
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    NSMutableDictionary *options = [self mutableNodeOptions];
    configuration[@"mux"] = @(sender.isOn);
    if (!sender.isOn) {
        [options removeObjectForKey:@"mux"];
        configuration[@"node-options"] = options;
    }
    [self applyConfiguration:configuration];
    [self.tableView reloadData];
}

- (void)httpChanged:(UISegmentedControl *)sender {
    NSArray<NSString *> *values = @[@"off", @"http", @"websocket"];
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    configuration[@"http"] = values[sender.selectedSegmentIndex];
    if (sender.selectedSegmentIndex == 0) {
        NSMutableDictionary *options = [self mutableNodeOptions];
        [options removeObjectForKey:@"http"];
        configuration[@"node-options"] = options;
    }
    [self applyConfiguration:configuration];
    [self.tableView reloadData];
}

- (void)httpVersionChanged:(UISegmentedControl *)sender {
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    configuration[@"http-version"] = @(sender.selectedSegmentIndex == 1 ? 2 : 1);
    [self applyConfiguration:configuration];
}

- (void)obfuscatorChanged:(UISwitch *)sender {
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    NSMutableDictionary *options = [self mutableNodeOptions];
    configuration[@"obfuscator"] = @(sender.isOn);
    if (!sender.isOn) {
        [options removeObjectForKey:@"obfuscator"];
        configuration[@"node-options"] = options;
    }
    [self applyConfiguration:configuration];
    [self.tableView reloadData];
}

- (void)carrierChanged:(UISegmentedControl *)sender {
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    configuration[@"carrier"] = sender.selectedSegmentIndex == 1 ? @"kcp" : @"tcp";
    if (sender.selectedSegmentIndex == 0) {
        NSMutableDictionary *options = [self mutableNodeOptions];
        [options removeObjectForKey:@"kcp"];
        configuration[@"node-options"] = options;
    }
    [self applyConfiguration:configuration];
    [self.tableView reloadData];
}

- (void)quicCarrierChanged:(UISegmentedControl *)sender {
    BOOL stream = sender.selectedSegmentIndex == 1;
    NSMutableDictionary *configuration = [self.configuration mutableCopy];
    NSMutableDictionary *options = [self mutableNodeOptions];
    configuration[@"quic-carrier"] = stream ? @"stream" : @"datagram";
    if (!stream) {
        configuration[@"mux"] = @NO;
        [options removeObjectForKey:@"mux"];
        configuration[@"node-options"] = options;
    }
    [self applyConfiguration:configuration];
    [self.tableView reloadData];
}

- (NSArray<NSString *> *)configurationRows {
    if (![self isChain]) return @[@"mode"];
    NSString *application = self.configuration[@"application"];
    if ([application isEqualToString:@"socks5"]) return @[@"mode", @"input", @"application"];
    BOOL httpProxy = [application isEqualToString:@"http-proxy"];
    NSMutableArray<NSString *> *rows = [NSMutableArray arrayWithObjects:@"mode", @"input", nil];
    if ([self usesConnections]) {
        [rows addObject:@"application"];
        if ([self showsMux]) [rows addObject:@"mux"];
    }
    [rows addObject:@"obfuscator"];
    if (![self usesQUIC] && !httpProxy) {
        [rows addObject:@"http"];
        if ([self httpEnabled]) [rows addObject:@"http-version"];
    }
    [rows addObject:@"outer"];
    if (!httpProxy) [rows addObject:[self usesQUIC] ? @"quic-carrier" : @"carrier"];
    return rows;
}

- (NSArray<NSString *> *)advancedLayers {
    if ([SRPWaterWallChainConfig isWireGuardConfiguration:self.configuration]) return @[];
    NSMutableArray<NSString *> *layers = [NSMutableArray arrayWithObject:@"packet"];
    if ([self isChain]) {
        if ([self usesConnections]) {
            [layers addObject:@"application"];
            if ([self.configuration[@"mux"] boolValue]) [layers addObject:@"mux"];
        }
        if ([self.configuration[@"obfuscator"] boolValue]) [layers addObject:@"obfuscator"];
        if (![self usesQUIC] && [self httpEnabled]) [layers addObject:@"http"];
        if (![self.configuration[@"outer"] isEqualToString:@"none"]) [layers addObject:@"outer"];
        if (![self usesQUIC] && [self.carrier isEqualToString:@"kcp"]) [layers addObject:@"kcp"];
    }
    return layers;
}

- (NSString *)titleForLayer:(NSString *)layer {
    if ([layer isEqualToString:@"application"]) return @"Application";
    if ([layer isEqualToString:@"mux"]) return @"MUX";
    if ([layer isEqualToString:@"obfuscator"]) return @"Obfuscator";
    if ([layer isEqualToString:@"http"]) return @"HTTP";
    if ([layer isEqualToString:@"outer"]) return @"Outer";
    if ([layer isEqualToString:@"kcp"]) return @"KCP";
    return @"Packet";
}

- (NSString *)accessibilityIdentifierForLayer:(NSString *)layer {
    if ([layer isEqualToString:@"application"]) return @"WWAdvancedApplication";
    if ([layer isEqualToString:@"mux"]) return @"WWAdvancedMux";
    if ([layer isEqualToString:@"obfuscator"]) return @"WWAdvancedObfuscator";
    if ([layer isEqualToString:@"http"]) return @"WWAdvancedHTTP";
    if ([layer isEqualToString:@"outer"]) return @"WWAdvancedOuter";
    if ([layer isEqualToString:@"kcp"]) return @"WWAdvancedKCP";
    return @"WWAdvancedPacket";
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return [SRPWaterWallChainConfig isWireGuardConfiguration:self.configuration] ? 1 : 2;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section == 0 ? @"CONFIGURATION" : @"ADVANCED NODE SETTINGS";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0) {
        BOOL vmess = [self isChain] && [self.configuration[@"application"] isEqualToString:@"vmess"];
        BOOL xor = [self isChain] && [self.configuration[@"obfuscator"] boolValue];
        if (vmess && xor) return @"VMess uses modern AEAD. WaterWall MUX is not Mux.Cool/XUDP; XOR is obfuscation, not encryption.";
        if (vmess) return @"VMess uses modern AEAD. WaterWall MUX is not VMess Mux.Cool or XUDP.";
        if (xor) return @"Build each layer independently. XOR is obfuscation, not encryption.";
        return @"Build the connection chain by selecting each layer independently.";
    }
    return @"Optional per-node JSON objects. Leave them empty to use WaterWall defaults.";
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section == 0 ? [self configurationRows].count : [self advancedLayers].count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 1) {
        NSString *layer = [self advancedLayers][indexPath.row];
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
        cell.textLabel.text = [self titleForLayer:layer];
        NSDictionary *settings = self.configuration[@"node-options"][layer];
        cell.detailTextLabel.text = settings.count > 0 ?
            [NSString stringWithFormat:@"%lu %@", (unsigned long)settings.count, settings.count == 1 ? @"setting" : @"settings"] : @"Default";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.accessibilityIdentifier = [self accessibilityIdentifierForLayer:layer];
        return cell;
    }

    NSString *row = [self configurationRows][indexPath.row];
    if ([row isEqualToString:@"mode"]) {
        NSString *mode = self.configuration[@"mode"];
        NSInteger selected = [mode isEqualToString:@"wireguard"] ? 1 : [mode isEqualToString:@"direct"] ? 2 : 0;
        return [self segmentedCellWithTitle:@"Mode"
                                      items:@[@"Chain", @"WireGuard", @"Direct"]
                                   selected:selected
                                     action:@selector(modeChanged:)
                       accessibilityIdentifier:@"WWMode"];
    }
    if ([row isEqualToString:@"input"]) {
        return [self segmentedCellWithTitle:@"Input"
                                      items:@[@"Connections", @"Raw IPv4"]
                                   selected:[self usesConnections] ? 0 : 1
                                     action:@selector(inputChanged:)
                       accessibilityIdentifier:@"WWInput"];
    }
    if ([row isEqualToString:@"application"]) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
        NSDictionary *names = @{@"vless": @"VLESS", @"vmess": @"VMess", @"trojan": @"Trojan",
                                @"socks5": @"SOCKS5", @"http-proxy": @"HTTP CONNECT"};
        cell.textLabel.text = @"Application";
        cell.detailTextLabel.text = names[self.configuration[@"application"]];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.accessibilityIdentifier = @"WWApplication";
        return cell;
    }
    if ([row isEqualToString:@"mux"]) {
        return [self switchCellWithTitle:@"MUX"
                                     on:[self.configuration[@"mux"] boolValue]
                                 action:@selector(muxChanged:)
                   accessibilityIdentifier:@"WWMux"];
    }
    if ([row isEqualToString:@"obfuscator"]) {
        return [self switchCellWithTitle:@"Obfuscator"
                                     on:[self.configuration[@"obfuscator"] boolValue]
                                 action:@selector(obfuscatorChanged:)
                   accessibilityIdentifier:@"WWObfuscator"];
    }
    if ([row isEqualToString:@"http"]) {
        NSInteger selected = [self.http isEqualToString:@"http"] ? 1 : [self.http isEqualToString:@"websocket"] ? 2 : 0;
        return [self segmentedCellWithTitle:@"HTTP"
                                      items:@[@"Off", @"HTTP", @"WebSocket"]
                                   selected:selected
                                     action:@selector(httpChanged:)
                       accessibilityIdentifier:@"WWHTTP"];
    }
    if ([row isEqualToString:@"http-version"]) {
        return [self segmentedCellWithTitle:@"HTTP Version"
                                      items:@[@"1", @"2"]
                                   selected:[self.configuration[@"http-version"] integerValue] == 2 ? 1 : 0
                                     action:@selector(httpVersionChanged:)
                       accessibilityIdentifier:@"WWHTTPVersion"];
    }
    if ([row isEqualToString:@"outer"]) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
        NSString *outer = self.configuration[@"outer"];
        cell.textLabel.text = @"Outer";
        cell.detailTextLabel.text = [outer isEqualToString:@"none"] ? @"None" :
            [outer isEqualToString:@"tls"] ? @"TLS" :
            [outer isEqualToString:@"reality"] ? @"Reality" :
            [outer isEqualToString:@"aead"] ? @"AEAD" : @"QUIC";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.accessibilityIdentifier = @"WWOuter";
        return cell;
    }
    if ([row isEqualToString:@"quic-carrier"]) {
        return [self segmentedCellWithTitle:@"QUIC Carrier"
                                      items:@[@"Datagram", @"Stream"]
                                   selected:[self.quicCarrier isEqualToString:@"stream"] ? 1 : 0
                                     action:@selector(quicCarrierChanged:)
                       accessibilityIdentifier:@"WWQuicCarrier"];
    }
    return [self segmentedCellWithTitle:@"Carrier"
                                  items:@[@"TCP", @"KCP"]
                               selected:[self.carrier isEqualToString:@"kcp"] ? 1 : 0
                                 action:@selector(carrierChanged:)
                   accessibilityIdentifier:@"WWCarrier"];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == 0) {
        NSString *row = [self configurationRows][indexPath.row];
        if (![row isEqualToString:@"outer"] && ![row isEqualToString:@"application"]) return;
        __weak SRPWaterWallConfigViewController *weakSelf = self;
        BOOL application = [row isEqualToString:@"application"];
        NSArray *choices = application ?
            @[@[@"vless", @"VLESS"], @[@"vmess", @"VMess"], @[@"trojan", @"Trojan"],
              @[@"socks5", @"SOCKS5"], @[@"http-proxy", @"HTTP CONNECT"]] :
            @[@[@"none", @"None"], @[@"tls", @"TLS"], @[@"reality", @"Reality"], @[@"aead", @"AEAD"], @[@"quic", @"QUIC"]];
        NSString *selected = self.configuration[row];
        SRPWaterWallChoiceViewController *choice =
            [[SRPWaterWallChoiceViewController alloc] initWithTitle:application ? @"Application" : @"Outer"
                                                            choices:choices
                                                           selected:selected
                                                         completion:^(NSString *value) {
            if (application) [weakSelf applicationChanged:value];
            else [weakSelf outerChanged:value];
        }];
        [self.navigationController pushViewController:choice animated:YES];
        return;
    }

    NSString *layer = [self advancedLayers][indexPath.row];
    __weak SRPWaterWallConfigViewController *weakSelf = self;
    SRPWaterWallNodeOptionsViewController *editor =
        [[SRPWaterWallNodeOptionsViewController alloc] initWithConfiguration:self.configuration
                                                                       layer:layer
                                                                       title:[self titleForLayer:layer]
                                                                  completion:^(NSDictionary *configuration) {
        SRPWaterWallConfigViewController *strongSelf = weakSelf;
        [strongSelf applyConfiguration:configuration];
        [strongSelf.tableView reloadData];
    }];
    [self.navigationController pushViewController:editor animated:YES];
}

@end
