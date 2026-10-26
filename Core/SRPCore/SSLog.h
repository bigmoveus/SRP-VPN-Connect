//
//  SSLog.h
//  SRPCore
//
//  Global log level gate. Normal prints only errors and connect/disconnect
//  milestones; Expert adds the phase/auth detail (the historical [Y] NSLog
//  volume); Debug adds packet counters and sstp-core x_debug output.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SSLogLevel) {
    SSLogLevelNormal = 0,   // errors + milestones only
    SSLogLevelExpert = 1,   // historical [Y] detail level
    SSLogLevelDebug  = 2,   // everything + packet counters + x_debug
};

void SSLogSetLevel(SSLogLevel level);
SSLogLevel SSLogGetLevel(void);
BOOL SSLogEnabled(SSLogLevel level);
/// C entry point for the sstp core (utils.c x_debug)
int ss_log_debug_enabled(void);
/// C entry point for the lwIP ppp logger (raw level as int)
int ss_log_level_value(void);

/// Error — always printed
#define SSLogE(fmt, ...) NSLog(@"[Y] " fmt, ##__VA_ARGS__)
/// Milestone (connect/disconnect/auth verdict) — always printed
#define SSLogM(fmt, ...) NSLog(@"[Y] " fmt, ##__VA_ARGS__)
/// Info — Expert and above
#define SSLogI(fmt, ...) do { if (SSLogEnabled(SSLogLevelExpert)) NSLog(@"[Y] " fmt, ##__VA_ARGS__); } while (0)
/// Debug — Debug level only
#define SSLogD(fmt, ...) do { if (SSLogEnabled(SSLogLevelDebug)) NSLog(@"[Y] " fmt, ##__VA_ARGS__); } while (0)

NS_ASSUME_NONNULL_END
