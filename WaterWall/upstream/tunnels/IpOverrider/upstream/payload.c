#include "structure.h"

#include "loggers/network_logger.h"

void ipoverriderUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipoverriderApplyUpStreamPayload(t, l, buf);
}
