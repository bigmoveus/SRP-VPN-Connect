#include "structure.h"

#include "loggers/network_logger.h"

void speedlimitTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    speedlimit_lstate_t *ls = lineGetState(l, t);
    speedlimitLinestateInitialize(ls, t, l);

    tunnelNextUpStreamInit(t, l);
}
