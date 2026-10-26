#pragma once

#include "wwapi.h"

WW_EXPORT node_t    nodeNEPacketDeviceGet(void);
WW_EXPORT tunnel_t *nepacketdeviceTunnelCreate(node_t *node);

void nepacketdeviceTunnelOnStart(tunnel_t *t);
void nepacketdeviceTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void nepacketdeviceTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void nepacketdeviceTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);
void nepacketdeviceTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
void nepacketdeviceTunnelWritePayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void nepacketdeviceTunnelDownstreamPause(tunnel_t *t, line_t *line);
void nepacketdeviceTunnelDownstreamResume(tunnel_t *t, line_t *line);
