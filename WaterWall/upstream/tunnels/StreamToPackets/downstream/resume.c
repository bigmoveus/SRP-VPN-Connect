#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;

    LOGW("StreamToPackets: not supposed to receive dowstream Resume");
}
