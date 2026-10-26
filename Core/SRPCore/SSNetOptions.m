//
//  SSNetOptions.m
//  SRPCore
//

#import "SSNetOptions.h"

BOOL SSShouldReconnectForPathChange(BOOL oldHadWifi, BOOL newHadWifi,
                                    BOOL newPathSatisfied, BOOL tunnelUp) {
    // Only migrate an established tunnel to Wi-Fi when Wi-Fi newly appeared
    return tunnelUp && newPathSatisfied && !oldHadWifi && newHadWifi;
}

BOOL SSReconnectAttemptAllowed(NSInteger failedAttempts, NSInteger retryLimit) {
    // retryLimit 0 = unlimited
    return retryLimit <= 0 || failedAttempts < retryLimit;
}
