#include "structure.h"

#include "loggers/network_logger.h"

void speedlimitTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    speedlimit_lstate_t *ls = lineGetState(l, t);
    speedlimitLinestateDestroy(ls);

    tunnelPrevDownStreamFinish(t, l);
}
