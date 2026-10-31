#pragma once

#include "wlibc.h"

#include "wloop.h"

/*
 * Outbound TCP connection quality. TcpConnector samples the kernel counters of
 * each socket (Apple's TCP_CONNECTION_INFO) while data moves and once more when
 * the connection ends, and folds their growth into process-wide totals that an
 * embedding application polls. Platforms without those counters report zeros.
 */

typedef struct tcp_quality_state_s
{
    uint64_t sampled_at_ms;
    uint64_t tx_packets;
    uint64_t retransmitted_packets;
    uint64_t rx_bytes;
    uint64_t rx_out_of_order_bytes;
} tcp_quality_state_t;

typedef struct tcp_quality_totals_s
{
    uint64_t tx_packets;            // segments sent, retransmissions included
    uint64_t retransmitted_packets; // segments sent again
    uint64_t rx_bytes;
    uint64_t rx_out_of_order_bytes; // bytes that arrived while an earlier segment was missing
    uint64_t closed_connections;
    uint64_t failed_connections;    // ended by any socket error
    uint64_t timed_out_connections; // given up by the network: retransmission timeout or no route
    uint32_t max_srtt_ms;           // highest smoothed RTT sampled since the previous read
    uint32_t max_rto_ms;            // highest retransmission timeout sampled since the previous read
} tcp_quality_totals_t;

// Samples at most once per second per connection; call it whenever the socket moves data.
void tcpqualitySample(tcp_quality_state_t *state, wio_t *io);

// Takes the final sample; call it before the socket is closed. error is the socket error, or zero.
void tcpqualityRecordClose(tcp_quality_state_t *state, wio_t *io, int error);

// Counters are cumulative for the process; the two maxima restart after every read.
void tcpqualityReadTotals(tcp_quality_totals_t *totals);
