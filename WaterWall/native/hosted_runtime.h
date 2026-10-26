#pragma once

#include "loggers/core_logger.h"

typedef void (*SRPWaterWallHostedReady)(void);
typedef bool (*SRPWaterWallHostedStopRequested)(void);

int srpWaterWallHostedRun(const char *core_json, const char *nodes_json, SRPWaterWallHostedReady ready,
                          SRPWaterWallHostedStopRequested stop_requested, logger_handler log_handler);
