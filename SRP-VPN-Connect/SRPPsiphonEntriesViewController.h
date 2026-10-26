//
//  SRPPsiphonEntriesViewController.h
//  SRP-VPN-Connect
//
//  Full-screen editor for Psiphon server entries: the hex blobs from
//  'psiphond generate' are several KB long, which makes a single-line text
//  field unusable. Supports multiple entries (space/newline separated),
//  paste-from-clipboard and file import.
//

#import <UIKit/UIKit.h>

@class NodeModel;

NS_ASSUME_NONNULL_BEGIN

@interface SRPPsiphonEntriesViewController : UIViewController

- (instancetype)initWithNodeModel:(NodeModel *)model;

@end

NS_ASSUME_NONNULL_END
