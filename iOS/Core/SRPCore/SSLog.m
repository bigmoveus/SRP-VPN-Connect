//
//  SSLog.m
//  SRPCore
//

#import "SSLog.h"

static SSLogLevel g_level = SSLogLevelNormal;   // profile default is Normal

void SSLogSetLevel(SSLogLevel level) {
    g_level = level;
}

SSLogLevel SSLogGetLevel(void) {
    return g_level;
}

BOOL SSLogEnabled(SSLogLevel level) {
    return g_level >= level;
}

int ss_log_debug_enabled(void) {
    return g_level >= SSLogLevelDebug;
}

int ss_log_level_value(void) {
    return (int)g_level;
}
