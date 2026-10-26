//
//  HomeHeaderView.h
//  SRP-VPN-Connect
//
//  Home screen status cell (code-only): app title, large round connect
//  button with a power symbol, status text, and toolbar buttons for
//  editing, help and adding a profile.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SRPHomeStatus) {
    SRPHomeStatusDisconnected = 0,
    SRPHomeStatusConnecting,
    SRPHomeStatusConnected,
};

@interface HomeHeaderView : UITableViewCell

@property (nonatomic, strong, readonly) UIButton *connectButton;
@property (nonatomic, strong, readonly) UILabel *statusLabel;
@property (nonatomic, strong, readonly) UIButton *editButton;
@property (nonatomic, strong, readonly) UIButton *helpButton;
@property (nonatomic, strong, readonly) UIButton *addButton;

/// Fired when the status text ("Connected"/… ) is tapped — opens the log
/// viewer. The power button itself keeps its connect/disconnect meaning.
@property (nonatomic, copy, nullable) void (^onStatusTap)(void);

/// Update the status area (colors + light pulse animation while connecting).
- (void)showStatus:(SRPHomeStatus)status animated:(BOOL)animated;

@end

NS_ASSUME_NONNULL_END
