#include "structure.h"

#include "loggers/network_logger.h"

void pingclientUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingclientEncapsulatePacket(t, l, buf);
}
