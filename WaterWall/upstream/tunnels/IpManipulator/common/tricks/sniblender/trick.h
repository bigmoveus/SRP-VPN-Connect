#pragma once
#include "structure.h"


bool sniblendertrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void sniblendertrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
