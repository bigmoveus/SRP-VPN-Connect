//
//  SSNetOptions.h
//  SRPCore
//
//  Pure decision helpers for the profile OPTIONS section (unit-testable
//  without a network).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Whether a default-path change should trigger an SSTP reconnect
/// ("Switch to Wi-Fi When Available"): the tunnel must be up, the new path
/// usable, and Wi-Fi must have newly become available (e.g. the connection
/// was running over cellular).
BOOL SSShouldReconnectForPathChange(BOOL oldHadWifi, BOOL newHadWifi,
                                    BOOL newPathSatisfied, BOOL tunnelUp);

/// Retry accounting for Auto Reconnect: given the number of consecutive
/// failed attempts and the configured retry limit (0 = unlimited), decide
/// whether another attempt is allowed.
BOOL SSReconnectAttemptAllowed(NSInteger failedAttempts, NSInteger retryLimit);

NS_ASSUME_NONNULL_END
