#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamResume(tunnel_t *t, line_t *child_l)
{
    muxclient_tstate_t *ts_shutdown = tunnelGetState(t);
    if (ts_shutdown->worker_states[lineGetWID(child_l)].quiescing)
    {
        return;
    }

    muxclient_lstate_t *child_ls = lineGetState(child_l, t);

    assert(child_ls->is_child);

    child_ls->paused = false;

    if (child_ls->close_state == kMuxClientChildCloseParentGoneDraining)
    {
        muxclient_child_drain_result_t result = muxclientDrainDetachedChild(t, child_l, child_ls);
        if (result == kMuxClientChildDrainReadyToFinish)
        {
            muxclientFinalizeDetachedChild(t, child_l, child_ls);
        }
        return;
    }

    muxclient_lstate_t *parent_ls = child_ls->parent;
    if (parent_ls->parent_finishing || ! child_ls->open_frame_submitted)
    {
        return;
    }

    line_t *parent_l = parent_ls->l;
    lineRef(parent_l);
    muxclient_child_drain_result_t result = muxclientDrainAttachedChild(t, parent_l, parent_ls, child_l, child_ls);
    if (result == kMuxClientChildDrainReadyToFinish && child_ls->close_state == kMuxClientChildClosePeerDraining)
    {
        discard muxclientFinalizeAttachedPeerClose(t, parent_l, tunnelGetState(t), parent_ls, child_ls);
    }
    else if (result == kMuxClientChildDrainReadyToFinish)
    {
        muxclientDeliverKeptChildData(t, parent_l, child_ls);
    }
    muxclientSyncParentInput(t, parent_l);
    lineUnref(parent_l);
}
