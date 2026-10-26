#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    keepaliveserverCloseLineFromUpstream(t, l);
}
