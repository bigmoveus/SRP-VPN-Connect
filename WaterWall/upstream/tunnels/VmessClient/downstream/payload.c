#include "internal.h"

#include "loggers/network_logger.h"

void vmessclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVmessClientPhaseClosed || ls->closing || ls->kind == kVmessClientLineKindUdpApplication ||
        sbufGetLength(buf) == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    vmessclient_tstate_t *ts = tunnelGetState(t);
    atomicAddU64Explicit(&ts->stats.rx_wire_bytes, sbufGetLength(buf), memory_order_relaxed);
    assert(! sbufIsSplice(buf));
    buf = vmessclientCompactInput(l, buf);
    if (! ls->request_sent || ! bufferqueueTryPushBack(&ls->pending_down, &buf))
    {
        const buffer_budget_cost_t usage = bufferbudgetGetUsage(&ls->downstream_budget);
        LOGE("VmessClient: downstream input rejected: request_sent=%u bytes=%zu charge=%zu entries=%zu input_bytes=%zu "
             "input_charge=%zu paused=%u",
             ls->request_sent ? 1U : 0U,
             usage.bytes,
             usage.charge,
             usage.entries,
             sbufGetLength(buf),
             sbufGetAllocationCharge(buf),
             ls->downstream_pause_sent ? 1U : 0U);
        lineReuseBuffer(l, buf);
        vmessclientSetReason(ls, kVmessClientReasonRetainedInput);
        vmessclientCloseLine(t, l, kVmessClientCloseInternal);
        return;
    }
    vmessclientRefreshDownstreamPause(t, l);
    vmessclientReceive(t, l);
}
