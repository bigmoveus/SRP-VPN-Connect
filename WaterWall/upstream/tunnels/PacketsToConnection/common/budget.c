#include "structure.h"

#include "loggers/network_logger.h"

bool ptcTcpBudgetReserve(ptc_tstate_t *ts)
{
    uint32_t current = atomic_load_explicit(&ts->tcp_reserved_bytes, memory_order_relaxed);
    for (;;)
    {
        if (ts->max_pending_bytes > ts->max_total_pending_bytes ||
            current > ts->max_total_pending_bytes - ts->max_pending_bytes)
        {
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(&ts->tcp_reserved_bytes, &current,
                                                  current + ts->max_pending_bytes,
                                                  memory_order_acq_rel, memory_order_relaxed))
        {
            return true;
        }
    }
}

void ptcTcpBudgetRelease(ptc_tstate_t *ts, bool *reserved)
{
    if (reserved == NULL || ! *reserved)
    {
        return;
    }
    *reserved = false;
    const uint32_t previous = atomic_fetch_sub_explicit(&ts->tcp_reserved_bytes,
                                                        ts->max_pending_bytes,
                                                        memory_order_acq_rel);
    if (UNLIKELY(previous < ts->max_pending_bytes))
    {
        LOGF("PacketsToConnection: TCP aggregate budget reservation underflow");
        abortProgramNow(1);
    }
}

void ptcTcpBudgetTransfer(bool *from, bool *to)
{
    assert(from != NULL && to != NULL && *from && ! *to);
    *to   = *from;
    *from = false;
}
