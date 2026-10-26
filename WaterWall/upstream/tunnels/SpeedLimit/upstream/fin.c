#include "structure.h"

#include "loggers/network_logger.h"

void speedlimitTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    speedlimit_lstate_t *ls = lineGetState(l, t);
    speedlimitLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
