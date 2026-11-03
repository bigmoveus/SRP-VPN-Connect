package tr.com.srp.vpn

/** The IPv4 packets of the data-plane probes, the same bytes iOS sends. */
internal object ProbePackets {
    const val DNS_SOURCE_PORT = 12353
    const val PROTOCOL_TCP = 6
    const val PROTOCOL_UDP = 17

    private val HEALTH_REQUEST = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n".toByteArray()
    private val DNS_QUERY = byteArrayOf(
        0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
        3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0, 0x00, 0x01, 0x00, 0x01,
    )

    /** The four bytes of a dotted IPv4 address, or null. */
    fun ipv4(address: String): ByteArray? {
        val parts = address.split('.')
        if (parts.size != 4) return null
        return ByteArray(4) { index ->
            val value = parts[index].toIntOrNull()
            if (value == null || value !in 0..255 || parts[index].isEmpty()) return null
            value.toByte()
        }
    }

    fun ipv4Int(address: String): Int {
        val bytes = ipv4(address) ?: return 0
        return (bytes[0].toInt() and 0xff shl 24) or (bytes[1].toInt() and 0xff shl 16) or (bytes[2].toInt() and 0xff shl 8) or (bytes[3].toInt() and 0xff)
    }

    private fun put16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value shr 8).toByte()
        packet[offset + 1] = value.toByte()
    }

    private fun put32(packet: ByteArray, offset: Int, value: Int) {
        put16(packet, offset, value ushr 16)
        put16(packet, offset + 2, value and 0xffff)
    }

    private fun sum(bytes: ByteArray, offset: Int, length: Int, start: Int): Int {
        var total = start
        var index = 0
        while (index + 1 < length) {
            total += ((bytes[offset + index].toInt() and 0xff) shl 8) or (bytes[offset + index + 1].toInt() and 0xff)
            index += 2
        }
        if (length and 1 != 0) total += (bytes[offset + length - 1].toInt() and 0xff) shl 8
        return total
    }

    private fun checksum(start: Int): Int {
        var total = start
        while (total ushr 16 != 0) total = (total and 0xffff) + (total ushr 16)
        return total.inv() and 0xffff
    }

    private fun ipHeader(packet: ByteArray, protocol: Int, source: ByteArray, destination: ByteArray) {
        packet[0] = 0x45
        put16(packet, 2, packet.size)
        put16(packet, 4, 0x4242)
        packet[8] = 64
        packet[9] = protocol.toByte()
        source.copyInto(packet, 12)
        destination.copyInto(packet, 16)
        put16(packet, 10, checksum(sum(packet, 0, 20, 0)))
    }

    private fun tcp(source: ByteArray, destination: ByteArray, sourcePort: Int, flags: Int, sequence: Int, acknowledgement: Int, payload: ByteArray): ByteArray {
        val packet = ByteArray(40 + payload.size)
        ipHeader(packet, PROTOCOL_TCP, source, destination)
        put16(packet, 20, sourcePort)
        put16(packet, 22, 80)
        put32(packet, 24, sequence)
        put32(packet, 28, acknowledgement)
        packet[32] = (5 shl 4).toByte()
        packet[33] = flags.toByte()
        put16(packet, 34, 0xffff)
        payload.copyInto(packet, 40)
        val pseudo = sum(packet, 12, 8, PROTOCOL_TCP + 20 + payload.size)
        put16(packet, 36, checksum(sum(packet, 20, 20 + payload.size, pseudo)))
        return packet
    }

    fun syn(source: ByteArray, destination: ByteArray, sourcePort: Int) = tcp(source, destination, sourcePort, 0x02, 1, 0, ByteArray(0))

    fun httpRequest(source: ByteArray, destination: ByteArray, sourcePort: Int, acknowledgement: Int) =
        tcp(source, destination, sourcePort, 0x18, 2, acknowledgement, HEALTH_REQUEST)

    fun dnsQuery(source: ByteArray, identifier: Int, destination: ByteArray): ByteArray {
        val packet = ByteArray(20 + 8 + DNS_QUERY.size)
        ipHeader(packet, PROTOCOL_UDP, source, destination)
        put16(packet, 20, DNS_SOURCE_PORT)
        put16(packet, 22, 53)
        put16(packet, 24, 8 + DNS_QUERY.size)
        DNS_QUERY.copyInto(packet, 28)
        put16(packet, 28, identifier)
        return packet
    }
}
