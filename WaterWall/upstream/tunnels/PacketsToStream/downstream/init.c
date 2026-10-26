#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    
    discard t;
    discard l;

    LOGF("PacketsToStream: not supposed to receive init downstream, your chain is incorrectly designed");
    // we operate left to right, no reason to pass init downside
}
