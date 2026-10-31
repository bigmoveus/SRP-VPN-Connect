//
//  SRPProtocolViewController.h
//  SRP-VPN-Connect
//
//  Protocol picker pushed from the profile editor (replaces the action
//  sheet — the list outgrew it).
//

#import <UIKit/UIKit.h>

@class NodeModel;

@interface SRPProtocolViewController : UITableViewController
- (instancetype)initWithNodeModel:(NodeModel *)model;
/// Sets the protocol and its defaults, as picking it in the list does.
+ (void)applyProtocol:(NSString *)type toModel:(NodeModel *)model;
@end
