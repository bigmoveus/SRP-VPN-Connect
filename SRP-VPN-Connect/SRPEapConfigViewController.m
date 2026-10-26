//
//  SRPEapConfigViewController.m
//  SRP-VPN-Connect
//

#import "SRPEapConfigViewController.h"
#import "SRPTtlsMethodViewController.h"
#import "NodeModel.h"
#import "SRPEapConfig.h"
#import <SRPCore/SSAuthCapabilities.h>

typedef NS_ENUM(NSInteger, SRPEapSection) {
    SRPEapSectionEAP = 0,
    SRPEapSectionPEAP,
    SRPEapSectionTTLS,
    SRPEapSectionTEAP,
    SRPEapSectionOptions,
    SRPEapSectionCount,
};

// Switch tags
static const NSInteger kTagEapMschapv2 = 1;
static const NSInteger kTagPeap = 2;
static const NSInteger kTagPeapCryptoBinding = 3;
static const NSInteger kTagTeap = 4;
static const NSInteger kTagIdentityPrivacy = 5;
static const NSInteger kTagTls13 = 6;
static const NSInteger kTagDisableLegacyTls = 7;

@interface SRPEapConfigViewController ()
@property (nonatomic, strong) NodeModel *model;
@end

@implementation SRPEapConfigViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"EAP Configuration";
}

- (SRPEapConfig *)eap {
    return self.model.eapConfig;
}

- (NSString *)unsupportedReason {
    return [SSAuthCapabilities sharedCapabilities].eapUnsupportedReason;
}

- (NSString *)ttlsMethodTitle {
    switch (self.eap.ttlsInnerMethod) {
        case SRPTtlsInnerMethodEAP: return @"EAP";
        case SRPTtlsInnerMethodPAP: return @"PAP";
        case SRPTtlsInnerMethodCHAP: return @"CHAP";
        case SRPTtlsInnerMethodMSCHAPv2: return @"MSCHAPv2";
        case SRPTtlsInnerMethodDisabled: default: return @"Disabled";
    }
}

#pragma mark - Cells

- (UITableViewCell *)switchCell:(NSString *)title on:(BOOL)on enabled:(BOOL)enabled tag:(NSInteger)tag {
    static NSString *cellID = @"switch";
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cellID];
    cell.textLabel.text = title;
    UISwitch *sw = [[UISwitch alloc] init];
    sw.on = on;
    sw.enabled = enabled;
    sw.tag = tag;
    [sw addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = sw;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.textLabel.enabled = enabled;
    return cell;
}

- (UITableViewCell *)identityCell {
    static NSString *cellID = @"identity";
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:cellID];
    cell.textLabel.text = @"Identity";
    BOOL enabled = self.eap.identityPrivacyEnabled &&
                   ([SSAuthCapabilities sharedCapabilities].supportsPeap ||
                    [SSAuthCapabilities sharedCapabilities].supportsEapTtls); // NO today
    cell.textLabel.enabled = enabled;
    UITextField *field = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 180, 30)];
    field.text = self.eap.anonymousIdentity;
    field.placeholder = @"anonymous";
    field.textAlignment = NSTextAlignmentRight;
    field.enabled = enabled;
    field.textColor = enabled ? UIColor.secondaryLabelColor : UIColor.tertiaryLabelColor;
    [field addTarget:self action:@selector(identityChanged:) forControlEvents:UIControlEventEditingChanged];
    cell.accessoryView = field;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

#pragma mark - Actions

- (void)switchChanged:(UISwitch *)sw {
    // Switches are disabled in the UI (backend has no EAP); these setters exist
    // so programmatic configuration still lands in the model.
    switch (sw.tag) {
        case kTagEapMschapv2: self.eap.eapMschapv2Enabled = sw.isOn; break;
        case kTagPeap: self.eap.peapEnabled = sw.isOn; break;
        case kTagPeapCryptoBinding: self.eap.peapRequireCryptoBinding = sw.isOn; break;
        case kTagTeap: self.eap.teapEnabled = sw.isOn; break;
        case kTagIdentityPrivacy: self.eap.identityPrivacyEnabled = sw.isOn; break;
        case kTagTls13: self.eap.eapTls13Enabled = sw.isOn; break;
        case kTagDisableLegacyTls: self.eap.disableLegacyEapTls = sw.isOn; break;
        default: break;
    }
    [self.tableView reloadData];
}

- (void)identityChanged:(UITextField *)field {
    self.eap.anonymousIdentity = field.text.length > 0 ? field.text : @"anonymous";
}

#pragma mark - Table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return SRPEapSectionCount;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case SRPEapSectionEAP: return @"EAP";
        case SRPEapSectionPEAP: return @"PEAP";
        case SRPEapSectionTTLS: return @"EAP-TTLS";
        case SRPEapSectionTEAP: return @"TEAP";
        case SRPEapSectionOptions: return @"OPTIONS";
        default: return nil;
    }
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    switch (section) {
        case SRPEapSectionEAP:
        case SRPEapSectionOptions:
            return [self unsupportedReason];
        default:
            return nil;
    }
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case SRPEapSectionEAP: return 1;
        case SRPEapSectionPEAP: return 2;
        case SRPEapSectionTTLS: return 1;
        case SRPEapSectionTEAP: return 1;
        case SRPEapSectionOptions: return 4;
        default: return 0;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    SSAuthCapabilities *caps = [SSAuthCapabilities sharedCapabilities];
    switch (indexPath.section) {
        case SRPEapSectionEAP:
            return [self switchCell:@"Enable EAP-MSCHAPv2" on:self.eap.eapMschapv2Enabled
                            enabled:caps.supportsEapMschapv2 tag:kTagEapMschapv2];
        case SRPEapSectionPEAP:
            if (indexPath.row == 0) {
                return [self switchCell:@"Enable PEAP" on:self.eap.peapEnabled
                                enabled:caps.supportsPeap tag:kTagPeap];
            }
            return [self switchCell:@"Require Crypto Binding" on:self.eap.peapRequireCryptoBinding
                            enabled:caps.supportsPeapCryptoBinding && self.eap.peapEnabled tag:kTagPeapCryptoBinding];
        case SRPEapSectionTTLS: {
            static NSString *cellID = @"ttls";
            UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
            if (!cell) {
                cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:cellID];
            }
            cell.textLabel.text = @"EAP-TTLS Method";
            cell.detailTextLabel.text = [self ttlsMethodTitle];
            cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
            return cell;
        }
        case SRPEapSectionTEAP:
            return [self switchCell:@"Enable TEAP" on:self.eap.teapEnabled
                            enabled:caps.supportsTeap tag:kTagTeap];
        case SRPEapSectionOptions:
            switch (indexPath.row) {
                case 0:
                    return [self switchCell:@"Enable Identity Privacy" on:self.eap.identityPrivacyEnabled
                                    enabled:caps.supportsPeap || caps.supportsEapTtls tag:kTagIdentityPrivacy];
                case 1:
                    return [self identityCell];
                case 2:
                    return [self switchCell:@"Enable TLS 1.3" on:self.eap.eapTls13Enabled
                                    enabled:caps.supportsEapTls13 tag:kTagTls13];
                case 3:
                    return [self switchCell:@"Disable TLS 1.0 & 1.1" on:self.eap.disableLegacyEapTls
                                    enabled:caps.supportsEapTls13 tag:kTagDisableLegacyTls];
                default: break;
            }
            break;
        default:
            break;
    }
    return [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == SRPEapSectionTTLS && indexPath.row == 0) {
        SRPTtlsMethodViewController *vc = [[SRPTtlsMethodViewController alloc] initWithNodeModel:self.model];
        [self.navigationController pushViewController:vc animated:YES];
    }
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.tableView reloadData];
}

@end
