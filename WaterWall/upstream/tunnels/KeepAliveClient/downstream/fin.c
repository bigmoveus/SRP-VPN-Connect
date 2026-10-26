#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    keepaliveclientCloseLineFromDownstream(t, l);
}
