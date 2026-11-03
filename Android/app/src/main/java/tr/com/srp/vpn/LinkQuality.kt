package tr.com.srp.vpn

import kotlin.math.max
import kotlin.math.min

/** Rates WaterWall's connections to the server from counters read at a fixed interval, as on iOS. */
class LinkQuality(var interval: Double = 5.0) {
    class Totals(val sent: Long, val retransmitted: Long, val received: Long, val timedOut: Long, val rtt: Long, val rto: Long)

    private class Sample(val sent: Long, val retransmitted: Long, val received: Long, val timedOut: Long, val rtt: Long, val rto: Long)

    private var last: Totals? = null
    private val samples = arrayOfNulls<Sample>(HISTORY)
    private var count = 0
    private var next = 0

    /** The growth since the previous reading becomes one sample; the first reading is the baseline. */
    fun add(totals: Totals) {
        last?.let { previous ->
            samples[next] = Sample(
                growth(totals.sent, previous.sent), growth(totals.retransmitted, previous.retransmitted),
                growth(totals.received, previous.received), growth(totals.timedOut, previous.timedOut), totals.rtt, totals.rto,
            )
            next = (next + 1) % HISTORY
            count = min(count + 1, HISTORY)
        }
        last = totals
    }

    fun clear() {
        last = null
        count = 0
        next = 0
    }

    private fun sum(wanted: Int): Sample {
        var sent = 0L
        var retransmitted = 0L
        var received = 0L
        var timedOut = 0L
        var rtt = 0L
        var rto = 0L
        for (index in 0 until min(wanted, count)) {
            val sample = samples[(next + HISTORY - 1 - index) % HISTORY]!!
            sent += sample.sent
            retransmitted += sample.retransmitted
            received += sample.received
            timedOut += sample.timedOut
            rtt = max(rtt, sample.rtt)
            rto = max(rto, sample.rto)
        }
        return Sample(sent, retransmitted, received, timedOut, rtt, rto)
    }

    /** Why the recent samples count as lossy, or null. */
    fun lossReason(): String? {
        val recent = sum(LOSS_SAMPLES)
        if (count >= LOSS_SAMPLES && recent.sent >= LOSS_MINIMUM_PACKETS && recent.retransmitted * 100 >= recent.sent * LOSS_PERCENT) {
            return "${recent.retransmitted * 100 / recent.sent}% of the packets sent to the server were retransmitted in the last ${"%.0f".format(LOSS_SAMPLES * interval)} seconds"
        }
        val history = sum(HISTORY)
        if (history.timedOut >= TIMEOUT_LIMIT) {
            return "the network dropped ${history.timedOut} connections to the server in the last ${"%.0f".format(min(count, HISTORY) * interval)} seconds"
        }
        return null
    }

    /** Traffic of the most recent samples for the log, or null when there was none. */
    fun summary(wanted: Int): String? {
        val total = sum(wanted)
        if (total.sent == 0L && total.received == 0L && total.timedOut == 0L) return null
        // QUIC reports no retransmission timeout, so the RTO appears only when a TCP or KCP connection had one.
        val percent = if (total.sent > 0) 100.0 * total.retransmitted / total.sent else 0.0
        val rto = if (total.rto > 0) ", RTO up to ${total.rto} ms" else ""
        return "${total.sent} packets sent, ${"%.1f".format(percent)}% retransmitted, ${total.received / 1024} KB received, " +
            "${total.timedOut} connections dropped by the network, RTT up to ${total.rtt} ms$rto"
    }

    private fun growth(now: Long, before: Long) = if (now > before) now - before else 0

    private companion object {
        const val HISTORY = 24 // samples kept: two minutes at the default interval
        const val LOSS_SAMPLES = 6 // samples judged for retransmissions: 30 seconds
        const val LOSS_MINIMUM_PACKETS = 500L
        const val LOSS_PERCENT = 15L
        const val TIMEOUT_LIMIT = 2L
    }
}
