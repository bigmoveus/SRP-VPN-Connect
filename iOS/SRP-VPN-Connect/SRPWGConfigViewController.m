//
//  SRPWGConfigViewController.m
//  SRP-VPN-Connect
//

#import "SRPWGConfigViewController.h"
#import "NodeModel.h"
#import <SRPCore/SRPWGKeys.h>

typedef NS_ENUM(NSInteger, SRPWGField) {
    SRPWGFieldPrivateKey = 1,
    SRPWGFieldPeerPublicKey,
    SRPWGFieldPresharedKey,
    SRPWGFieldAddress,
    SRPWGFieldDNS,
    SRPWGFieldAllowedIPs,
    SRPWGFieldKeepalive,
    SRPWGFieldJc, SRPWGFieldJmin, SRPWGFieldJmax,
    SRPWGFieldS1, SRPWGFieldS2, SRPWGFieldS3, SRPWGFieldS4,
    SRPWGFieldH1, SRPWGFieldH2, SRPWGFieldH3, SRPWGFieldH4,
    SRPWGFieldI1, SRPWGFieldI2, SRPWGFieldI3, SRPWGFieldI4, SRPWGFieldI5,
};

@interface SRPWGConfigViewController () <UITextFieldDelegate>
@property (nonatomic, strong) NodeModel *model;
@end

@implementation SRPWGConfigViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Manual Configuration";
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
}

#pragma mark - cell builder

/// Private-key cell with a Generate button next to the field.
- (UITableViewCell *)privateKeyCell {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.textLabel.text = @"Private Key";

    UIView *container = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 234, 30)];
    UITextField *field = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 190, 30)];
    field.text = self.model.wgPrivateKey;
    field.placeholder = @"Required";
    field.textAlignment = NSTextAlignmentRight;
    field.keyboardType = UIKeyboardTypeASCIICapable;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.clearButtonMode = UITextFieldViewModeNever;
    field.tag = SRPWGFieldPrivateKey;
    [field addTarget:self action:@selector(fieldChanged:) forControlEvents:UIControlEventEditingChanged];
    [container addSubview:field];

    UIButton *gen = [UIButton buttonWithType:UIButtonTypeSystem];
    gen.frame = CGRectMake(196, 0, 38, 30);
    gen.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    [gen setTitle:@"Gen" forState:UIControlStateNormal];
    [gen addTarget:self action:@selector(generateTapped:) forControlEvents:UIControlEventTouchUpInside];
    [container addSubview:gen];

    cell.accessoryView = container;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (void)generateTapped:(UIButton *)button {
    self.model.wgPrivateKey = [SRPWGKeys generatePrivateKeyBase64];
    [self.tableView reloadData];
}

/// Read-only derived public key; tap to copy (it must be registered as a
/// peer on the server).
- (UITableViewCell *)publicKeyCell {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.textLabel.text = @"Public Key";
    NSString *pub = self.model.wgPrivateKey.length > 0
        ? [SRPWGKeys publicKeyBase64ForPrivateKeyBase64:self.model.wgPrivateKey] : nil;
    cell.detailTextLabel.text = pub.length > 0 ? pub : @"—";
    cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    cell.detailTextLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
    cell.selectionStyle = pub.length > 0 ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
    return cell;
}

- (UITableViewCell *)fieldCellWithTitle:(NSString *)title
                                   text:(NSString *)text
                            placeholder:(NSString *)placeholder
                                    tag:(NSInteger)tag {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.textLabel.text = title;
    UITextField *field = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 190, 30)];
    field.text = text;
    field.placeholder = placeholder;
    field.textAlignment = NSTextAlignmentRight;
    field.keyboardType = UIKeyboardTypeASCIICapable;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.clearButtonMode = UITextFieldViewModeNever;
    field.tag = tag;
    [field addTarget:self action:@selector(fieldChanged:) forControlEvents:UIControlEventEditingChanged];
    cell.accessoryView = field;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (void)fieldChanged:(UITextField *)field {
    switch (field.tag) {
        case SRPWGFieldPrivateKey: self.model.wgPrivateKey = field.text; break;
        case SRPWGFieldPeerPublicKey: self.model.wgPeerPublicKey = field.text; break;
        case SRPWGFieldPresharedKey: self.model.wgPresharedKey = field.text; break;
        case SRPWGFieldAddress: self.model.wgAddress = field.text; break;
        case SRPWGFieldDNS: self.model.wgDNS = field.text; break;
        case SRPWGFieldAllowedIPs: self.model.wgAllowedIPs = field.text; break;
        case SRPWGFieldKeepalive: self.model.wgKeepalive = field.text.integerValue; break;
        case SRPWGFieldJc: self.model.wgJc = field.text.integerValue; break;
        case SRPWGFieldJmin: self.model.wgJmin = field.text.integerValue; break;
        case SRPWGFieldJmax: self.model.wgJmax = field.text.integerValue; break;
        case SRPWGFieldS1: self.model.wgS1 = field.text.integerValue; break;
        case SRPWGFieldS2: self.model.wgS2 = field.text.integerValue; break;
        case SRPWGFieldH1: self.model.wgH1 = field.text.integerValue; break;
        case SRPWGFieldH2: self.model.wgH2 = field.text.integerValue; break;
        case SRPWGFieldH3: self.model.wgH3 = field.text.integerValue; break;
        case SRPWGFieldH4: self.model.wgH4 = field.text.integerValue; break;
        case SRPWGFieldS3: self.model.wgS3 = field.text.integerValue; break;
        case SRPWGFieldS4: self.model.wgS4 = field.text.integerValue; break;
        case SRPWGFieldI1: self.model.wgI1 = field.text; break;
        case SRPWGFieldI2: self.model.wgI2 = field.text; break;
        case SRPWGFieldI3: self.model.wgI3 = field.text; break;
        case SRPWGFieldI4: self.model.wgI4 = field.text; break;
        case SRPWGFieldI5: self.model.wgI5 = field.text; break;
        default: break;
    }
}

#pragma mark - table view

static NSString *SRPWGIntOrNil(NSInteger v) { return v > 0 ? @(v).stringValue : nil; }

- (BOOL)isAmnezia {
    return [self.model.protocolType isEqualToString:@"amnezia"];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return [self isAmnezia] ? 3 : 2;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"THIS DEVICE";
    if (section == 1) return @"SERVER (PEER)";
    return @"AMNEZIAWG OBFUSCATION";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 2) {
        return @"These values must match the server exactly. Leave empty only if the server runs without obfuscation.";
    }
    if (section == 1) {
        return @"The endpoint (host:port) comes from the Server and Port fields of the profile. AllowedIPs 0.0.0.0/0 routes everything through the tunnel.";
    }
    return nil;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 2) return 16;  // Jc, Jmin, Jmax, S1-S4, H1-H4, I1-I5
    return 4;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 0) {
        switch (indexPath.row) {
            case 0:
                return [self privateKeyCell];
            case 1:
                return [self publicKeyCell];
            case 2:
                return [self fieldCellWithTitle:@"Address" text:self.model.wgAddress
                                    placeholder:@"e.g. 10.88.0.2/24" tag:SRPWGFieldAddress];
            case 3:
                return [self fieldCellWithTitle:@"DNS" text:self.model.wgDNS
                                    placeholder:@"Optional — e.g. 1.1.1.1" tag:SRPWGFieldDNS];
        }
    }
    switch (indexPath.row) {
        case 0:
            return [self fieldCellWithTitle:@"Server Public Key" text:self.model.wgPeerPublicKey
                                placeholder:@"Required" tag:SRPWGFieldPeerPublicKey];
        case 1:
            return [self fieldCellWithTitle:@"Preshared Key" text:self.model.wgPresharedKey
                                placeholder:@"Optional" tag:SRPWGFieldPresharedKey];
        case 2:
            return [self fieldCellWithTitle:@"AllowedIPs" text:self.model.wgAllowedIPs
                                placeholder:@"Default: 0.0.0.0/0" tag:SRPWGFieldAllowedIPs];
        case 3:
            return [self fieldCellWithTitle:@"Keepalive" text:(self.model.wgKeepalive > 0 ? @(self.model.wgKeepalive).stringValue : nil)
                                placeholder:@"Optional — seconds" tag:SRPWGFieldKeepalive];
    }
    if (indexPath.section == 2) {
        switch (indexPath.row) {
            case 0: return [self fieldCellWithTitle:@"Jc" text:SRPWGIntOrNil(self.model.wgJc) placeholder:@"Junk packet count" tag:SRPWGFieldJc];
            case 1: return [self fieldCellWithTitle:@"Jmin" text:SRPWGIntOrNil(self.model.wgJmin) placeholder:@"Junk packet min size" tag:SRPWGFieldJmin];
            case 2: return [self fieldCellWithTitle:@"Jmax" text:SRPWGIntOrNil(self.model.wgJmax) placeholder:@"Junk packet max size" tag:SRPWGFieldJmax];
            case 3: return [self fieldCellWithTitle:@"S1" text:SRPWGIntOrNil(self.model.wgS1) placeholder:@"Init junk padding" tag:SRPWGFieldS1];
            case 4: return [self fieldCellWithTitle:@"S2" text:SRPWGIntOrNil(self.model.wgS2) placeholder:@"Response junk padding" tag:SRPWGFieldS2];
            case 5: return [self fieldCellWithTitle:@"S3" text:SRPWGIntOrNil(self.model.wgS3) placeholder:@"Cookie junk padding" tag:SRPWGFieldS3];
            case 6: return [self fieldCellWithTitle:@"S4" text:SRPWGIntOrNil(self.model.wgS4) placeholder:@"Transport junk padding" tag:SRPWGFieldS4];
            case 7: return [self fieldCellWithTitle:@"H1" text:SRPWGIntOrNil(self.model.wgH1) placeholder:@"Init header type" tag:SRPWGFieldH1];
            case 8: return [self fieldCellWithTitle:@"H2" text:SRPWGIntOrNil(self.model.wgH2) placeholder:@"Response header type" tag:SRPWGFieldH2];
            case 9: return [self fieldCellWithTitle:@"H3" text:SRPWGIntOrNil(self.model.wgH3) placeholder:@"Cookie header type" tag:SRPWGFieldH3];
            case 10: return [self fieldCellWithTitle:@"H4" text:SRPWGIntOrNil(self.model.wgH4) placeholder:@"Data header type" tag:SRPWGFieldH4];
            case 11: return [self fieldCellWithTitle:@"I1" text:self.model.wgI1 placeholder:@"Optional signature chain" tag:SRPWGFieldI1];
            case 12: return [self fieldCellWithTitle:@"I2" text:self.model.wgI2 placeholder:@"Optional" tag:SRPWGFieldI2];
            case 13: return [self fieldCellWithTitle:@"I3" text:self.model.wgI3 placeholder:@"Optional" tag:SRPWGFieldI3];
            case 14: return [self fieldCellWithTitle:@"I4" text:self.model.wgI4 placeholder:@"Optional" tag:SRPWGFieldI4];
            case 15: return [self fieldCellWithTitle:@"I5" text:self.model.wgI5 placeholder:@"Optional" tag:SRPWGFieldI5];
        }
    }
    return [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    // Tap the derived public key -> copy it (it must be registered as a peer
    // on the server)
    if (indexPath.section == 0 && indexPath.row == 1 && self.model.wgPrivateKey.length > 0) {
        NSString *pub = [SRPWGKeys publicKeyBase64ForPrivateKeyBase64:self.model.wgPrivateKey];
        if (pub.length > 0) {
            UIPasteboard.generalPasteboard.string = pub;
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Public Key Copied"
                                                                           message:@"Register this key as a peer on the WireGuard server."
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        }
    }
}

@end
