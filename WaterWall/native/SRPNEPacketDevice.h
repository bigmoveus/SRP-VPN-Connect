#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void (*SRPNEPacketWriteCallback)(void *context, const uint8_t *packet, size_t length);
typedef void (*SRPNEPacketLogCallback)(void *context, int level, const char *message, size_t length);

bool srpNEPacketDeviceConfigure(SRPNEPacketWriteCallback packet, SRPNEPacketLogCallback log, void *context);
int  srpNEPacketDeviceSubmit(const void *packet, size_t length);
void srpNEPacketDeviceClose(void);
