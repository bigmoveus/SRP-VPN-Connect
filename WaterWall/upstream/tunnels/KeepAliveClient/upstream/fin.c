#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    keepaliveclientCloseLineFromUpstream(t, l);
}
