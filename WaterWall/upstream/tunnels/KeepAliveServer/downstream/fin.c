#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    keepaliveserverCloseLineFromDownstream(t, l);
}
