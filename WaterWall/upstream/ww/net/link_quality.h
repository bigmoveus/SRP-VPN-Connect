#pragma once

#include "wlibc.h"

#include "wloop.h"

/*
 * Quality of the connections that carry traffic to the server. TcpConnector
 * samples the kernel counters of each socket (Apple's TCP_CONNECTION_INFO; other
 * platforms report no TCP traffic), while the UDP carriers KCP and QUIC report
 * the counters of their own sessions. Both fold their growth into process-wide
 * totals that an embedding application polls.
 */

typedef struct link_quality_tcp_state_s
{
    uint64_t sampled_at_ms;
    uint64_t tx_packets;
    uint64_t retransmitted_packets;
    uint64_t rx_bytes;
    uint64_t rx_out_of_order_bytes;
} link_quality_tcp_state_t;

typedef struct link_quality_carrier_state_s
{
    uint64_t sampled_at_ms;
    uint64_t sent_packets;
    uint64_t resent_packets;
    uint64_t received_bytes;
} link_quality_carrier_state_t;

typedef struct link_quality_totals_s
{
    uint64_t tx_packets;            // TCP and KCP segments and QUIC packets sent, retransmissions included
    uint64_t retransmitted_packets; // TCP and KCP segments sent again, QUIC packets declared lost
    uint64_t rx_bytes;
    uint64_t rx_out_of_order_bytes; // TCP bytes that arrived while an earlier segment was missing
    uint64_t closed_connections;
    uint64_t failed_connections;    // TCP connections ended by any socket error
    uint64_t timed_out_connections; // given up on the network: timeout, no route, or a silent carrier session
    uint32_t max_srtt_ms;           // highest smoothed RTT sampled since the previous read
    uint32_t max_rto_ms;            // highest retransmission timeout sampled since the previous read
} link_quality_totals_t;

// Samples at most once per second per connection; call it whenever the socket moves data.
void linkqualitySampleTcp(link_quality_tcp_state_t *state, wio_t *io);

// Takes the final sample; call it before the socket is closed. error is the socket error, or zero.
void linkqualityRecordTcpClose(link_quality_tcp_state_t *state, wio_t *io, int error);

// Folds a carrier session's cumulative counters, at most once per second unless final is set.
void linkqualityRecordCarrier(link_quality_carrier_state_t *state, uint64_t now_ms, bool final, uint64_t sent_packets,
                              uint64_t resent_packets, uint64_t received_bytes, uint32_t srtt_ms, uint32_t rto_ms);

// Counts an ended carrier session; timed_out means the network stopped delivering it.
void linkqualityRecordCarrierEnd(bool timed_out);

// Counters are cumulative for the process; the two maxima restart after every read.
void linkqualityReadTotals(link_quality_totals_t *totals);
