#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;

    LOGW("StreamToPackets: not supposed to receive upstream pause");
}
