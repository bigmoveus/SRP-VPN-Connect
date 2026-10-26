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
@end
