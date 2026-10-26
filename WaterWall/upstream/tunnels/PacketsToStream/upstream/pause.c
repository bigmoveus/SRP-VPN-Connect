#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;

    LOGW("PacketsToStream: not supposed to receive upstream pause");
}
