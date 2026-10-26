/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef AWG_H
#define AWG_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void awgSetLogger(void *context, logger_fn_t logger_fn);
extern int awgTurnOn(const char *settings, int32_t tun_fd);
extern void awgTurnOff(int handle);
extern int64_t awgSetConfig(int handle, const char *settings);
extern char *awgGetConfig(int handle);
extern void awgBumpSockets(int handle);
extern void awgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *awgVersion();

#endif
