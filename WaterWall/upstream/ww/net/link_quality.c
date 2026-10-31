#include "link_quality.h"

enum
{
    kLinkQualitySampleIntervalMs = 1000
};

static atomic_ullong tx_packets_total;
static atomic_ullong retransmitted_packets_total;
static atomic_ullong rx_bytes_total;
static atomic_ullong rx_out_of_order_bytes_total;
static atomic_ullong closed_connections_total;
static atomic_ullong failed_connections_total;
static atomic_ullong timed_out_connections_total;
static atomic_ullong max_srtt_ms_seen;
static atomic_ullong max_rto_ms_seen;

static void addGrowth(atomic_ullong *total, uint64_t current, uint64_t *last)
{
    if (current > *last)
    {
        atomicAddU64Explicit(total, current - *last, memory_order_relaxed);
    }
    *last = current;
}

static void raiseMaximum(atomic_ullong *maximum, uint64_t value)
{
    uint64_t seen = atomicLoadU64Explicit(maximum, memory_order_relaxed);
    while (value > seen &&
           ! atomicCompareExchangeWeakU64Explicit(maximum, &seen, value, memory_order_relaxed, memory_order_relaxed))
    {
    }
}

static uint32_t takeMaximum(atomic_ullong *maximum)
{
    const uint64_t value = atomicExchangeU64Explicit(maximum, 0, memory_order_relaxed);
    return value > UINT32_MAX ? UINT32_MAX : (uint32_t) value;
}

#if defined(TCP_CONNECTION_INFO)

static void sampleTcpNow(link_quality_tcp_state_t *state, wio_t *io, uint64_t now_ms)
{
    struct tcp_connection_info info;
    socklen_t                  length = sizeof(info);
    if (getsockopt(wioGetFD(io), IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &length) != 0)
    {
        return;
    }
    state->sampled_at_ms = now_ms;
    addGrowth(&tx_packets_total, info.tcpi_txpackets, &state->tx_packets);
    addGrowth(&retransmitted_packets_total, info.tcpi_txretransmitpackets, &state->retransmitted_packets);
    addGrowth(&rx_bytes_total, info.tcpi_rxbytes, &state->rx_bytes);
    addGrowth(&rx_out_of_order_bytes_total, info.tcpi_rxoutoforderbytes, &state->rx_out_of_order_bytes);
    raiseMaximum(&max_srtt_ms_seen, info.tcpi_srtt);
    raiseMaximum(&max_rto_ms_seen, info.tcpi_rto);
}

void linkqualitySampleTcp(link_quality_tcp_state_t *state, wio_t *io)
{
    const uint64_t now_ms = wloopNowMS(weventGetLoop(io));
    if (state->sampled_at_ms != 0 && now_ms - state->sampled_at_ms < kLinkQualitySampleIntervalMs)
    {
        return;
    }
    sampleTcpNow(state, io, now_ms);
}

void linkqualityRecordTcpClose(link_quality_tcp_state_t *state, wio_t *io, int error)
{
    sampleTcpNow(state, io, wloopNowMS(weventGetLoop(io)));
    atomicAddU64Explicit(&closed_connections_total, 1, memory_order_relaxed);
    if (error != 0)
    {
        atomicAddU64Explicit(&failed_connections_total, 1, memory_order_relaxed);
    }
    // A reset can come from the server itself; these errors mean the path stopped delivering.
    if (error == ETIMEDOUT || error == EHOSTUNREACH || error == ENETUNREACH || error == ENETDOWN)
    {
        atomicAddU64Explicit(&timed_out_connections_total, 1, memory_order_relaxed);
    }
}

#else

void linkqualitySampleTcp(link_quality_tcp_state_t *state, wio_t *io)
{
    discard state;
    discard io;
}

void linkqualityRecordTcpClose(link_quality_tcp_state_t *state, wio_t *io, int error)
{
    discard state;
    discard io;
    discard error;
}

#endif

void linkqualityRecordCarrier(link_quality_carrier_state_t *state, uint64_t now_ms, bool final, uint64_t sent_packets,
                              uint64_t resent_packets, uint64_t received_bytes, uint32_t srtt_ms, uint32_t rto_ms)
{
    if (! final && state->sampled_at_ms != 0 && now_ms - state->sampled_at_ms < kLinkQualitySampleIntervalMs)
    {
        return;
    }
    state->sampled_at_ms = now_ms;
    addGrowth(&tx_packets_total, sent_packets, &state->sent_packets);
    addGrowth(&retransmitted_packets_total, resent_packets, &state->resent_packets);
    addGrowth(&rx_bytes_total, received_bytes, &state->received_bytes);
    raiseMaximum(&max_srtt_ms_seen, srtt_ms);
    raiseMaximum(&max_rto_ms_seen, rto_ms);
}

void linkqualityRecordCarrierEnd(bool timed_out)
{
    atomicAddU64Explicit(&closed_connections_total, 1, memory_order_relaxed);
    if (timed_out)
    {
        atomicAddU64Explicit(&timed_out_connections_total, 1, memory_order_relaxed);
    }
}

void linkqualityReadTotals(link_quality_totals_t *totals)
{
    totals->tx_packets            = atomicLoadU64Explicit(&tx_packets_total, memory_order_relaxed);
    totals->retransmitted_packets = atomicLoadU64Explicit(&retransmitted_packets_total, memory_order_relaxed);
    totals->rx_bytes              = atomicLoadU64Explicit(&rx_bytes_total, memory_order_relaxed);
    totals->rx_out_of_order_bytes = atomicLoadU64Explicit(&rx_out_of_order_bytes_total, memory_order_relaxed);
    totals->closed_connections    = atomicLoadU64Explicit(&closed_connections_total, memory_order_relaxed);
    totals->failed_connections    = atomicLoadU64Explicit(&failed_connections_total, memory_order_relaxed);
    totals->timed_out_connections = atomicLoadU64Explicit(&timed_out_connections_total, memory_order_relaxed);
    totals->max_srtt_ms           = takeMaximum(&max_srtt_ms_seen);
    totals->max_rto_ms            = takeMaximum(&max_rto_ms_seen);
}
