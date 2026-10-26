#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    encryptionserver_lstate_t *ls = lineGetState(l, t);
    encryptionserverLinestateInitialize(ls, lineGetBufferPool(l));

    tunnelNextUpStreamInit(t, l);
}
