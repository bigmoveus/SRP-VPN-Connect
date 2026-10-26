#include "structure.h"

#include "loggers/network_logger.h"

void pingclientDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingclientDecapsulatePacket(t, l, buf);
}
