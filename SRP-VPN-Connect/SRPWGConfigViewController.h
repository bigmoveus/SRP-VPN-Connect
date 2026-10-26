//
//  SRPWGConfigViewController.h
//  SRP-VPN-Connect
//
//  WireGuard manual entry: keys, address, DNS, allowed IPs — the fields a
//  .conf file would carry, for profiles entered by hand.
//

#import <UIKit/UIKit.h>

@class NodeModel;

@interface SRPWGConfigViewController : UITableViewController
- (instancetype)initWithNodeModel:(NodeModel *)model;
@end
