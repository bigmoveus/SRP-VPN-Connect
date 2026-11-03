//
//  SRPTtlsMethodViewController.m
//  SRP-VPN-Connect
//

#import "SRPTtlsMethodViewController.h"
#import "NodeModel.h"
#import "SRPEapConfig.h"
#import <SRPCore/SSAuthCapabilities.h>

@interface SRPTtlsMethodViewController ()
@property (nonatomic, strong) NodeModel *model;
@end

@implementation SRPTtlsMethodViewController

- (instancetype)initWithNodeModel:(NodeModel *)model {
    self = [super initWithStyle:UITableViewStyleGrouped];
    if (self) {
        _model = model;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"EAP-TTLS Method";
}

- (NSArray<NSNumber *> *)methods {
    return @[@(SRPTtlsInnerMethodDisabled), @(SRPTtlsInnerMethodEAP),
             @(SRPTtlsInnerMethodPAP), @(SRPTtlsInnerMethodCHAP),
             @(SRPTtlsInnerMethodMSCHAPv2)];
}

- (NSString *)titleForMethod:(SRPTtlsInnerMethod)method {
    switch (method) {
        case SRPTtlsInnerMethodEAP: return @"EAP";
        case SRPTtlsInnerMethodPAP: return @"PAP";
        case SRPTtlsInnerMethodCHAP: return @"CHAP";
        case SRPTtlsInnerMethodMSCHAPv2: return @"MSCHAPv2";
        case SRPTtlsInnerMethodDisabled: default: return @"Disabled";
    }
}

#pragma mark - Table view

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.methods.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return [SSAuthCapabilities sharedCapabilities].eapUnsupportedReason;
}

- (BOOL)methodSelectable:(SRPTtlsInnerMethod)method {
    SSAuthCapabilities *caps = [SSAuthCapabilities sharedCapabilities];
    switch (method) {
        case SRPTtlsInnerMethodDisabled: return YES;
        case SRPTtlsInnerMethodMSCHAPv2: return caps.supportsTtlsMschapv2;
        case SRPTtlsInnerMethodPAP: return caps.supportsTtlsPap;
        case SRPTtlsInnerMethodCHAP: return caps.supportsTtlsChap;
        // Inner "EAP" runs the server's inner EAP method (EAP-MSCHAPv2 via
        // EAP-Message AVPs on our FreeRADIUS) — selectable when that works
        case SRPTtlsInnerMethodEAP: default:
            return caps.supportsEapTtls && caps.supportsTtlsMschapv2;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellID = @"method";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cellID];
    }
    SRPTtlsInnerMethod method = (SRPTtlsInnerMethod)self.methods[indexPath.row].integerValue;
    cell.textLabel.text = [self titleForMethod:method];
    BOOL selectable = [self methodSelectable:method];
    cell.textLabel.enabled = selectable;
    cell.selectionStyle = selectable ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
    cell.accessoryType = (self.model.eapConfig.ttlsInnerMethod == method) ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (NSIndexPath *)tableView:(UITableView *)tableView willSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    SRPTtlsInnerMethod method = (SRPTtlsInnerMethod)self.methods[indexPath.row].integerValue;
    if (![self methodSelectable:method]) {
        return nil; // grayed rows do nothing
    }
    return indexPath;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    SRPTtlsInnerMethod method = (SRPTtlsInnerMethod)self.methods[indexPath.row].integerValue;
    self.model.eapConfig.ttlsInnerMethod = method;
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    [self.navigationController popViewControllerAnimated:YES];
}

@end
