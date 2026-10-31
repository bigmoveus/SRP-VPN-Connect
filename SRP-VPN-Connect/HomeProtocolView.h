//
//  HomeProtocolView.h
//  SRP-VPN-Connect
//
//  Home screen server row (code-only): rounded card with the profile name,
//  server address, a protocol badge, latency, and a selection checkmark.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface HomeProtocolView : UITableViewCell

/// Card content: profile title, "host:port" subtitle, selection marker.
- (void)configureWithTitle:(NSString *)title subtitle:(NSString *)subtitle selected:(BOOL)selected;
- (void)configureWithTitle:(NSString *)title subtitle:(NSString *)subtitle badge:(NSString *)badge selected:(BOOL)selected;
- (void)configureWithTitle:(NSString *)title
                  subtitle:(NSString *)subtitle
                     badge:(NSString *)badge
                   latency:(nullable NSString *)latency
                  selected:(BOOL)selected;
/// latencyColor tints the latency text; nil keeps the secondary label color.
- (void)configureWithTitle:(NSString *)title
                  subtitle:(NSString *)subtitle
                     badge:(NSString *)badge
                   latency:(nullable NSString *)latency
              latencyColor:(nullable UIColor *)latencyColor
                  selected:(BOOL)selected;

@end

NS_ASSUME_NONNULL_END
