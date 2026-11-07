package io.github.shdavlatbek.mlbblock.net

import java.util.concurrent.atomic.AtomicInteger

object Tcp {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

internal fun ByteArray.u8(i: Int): Int = this[i].toInt() and 0xFF
internal fun ByteArray.u16(i: Int): Int = (u8(i) shl 8) or u8(i + 1)
internal fun ByteArray.i32(i: Int): Int = (u8(i) shl 24) or (u8(i + 1) shl 16) or (u8(i + 2) shl 8) or u8(i + 3)
internal fun ByteArray.put16(i: Int, v: Int) {
    this[i] = (v ushr 8).toByte(); this[i + 1] = v.toByte()
}
internal fun ByteArray.put32(i: Int, v: Int) {
    this[i] = (v ushr 24).toByte(); this[i + 1] = (v ushr 16).toByte()
    this[i + 2] = (v ushr 8).toByte(); this[i + 3] = v.toByte()
}

/** A parsed IPv4 packet read from the TUN device. Offsets point into [buf]. */
class Ipv4(val buf: ByteArray, length: Int) {
    val headerLen = (buf[0].toInt() and 0x0F) * 4
    val totalLen = minOf(buf.u16(2), length)
    val proto = buf.u8(9)
    val src = buf.i32(12)
    val dst = buf.i32(16)
    val isFragment = (buf.u16(6) and 0x3FFF) != 0 // MF flag or non-zero offset
    val payloadOff get() = headerLen
    val payloadLen get() = totalLen - headerLen

    val valid get() = headerLen >= 20 && totalLen >= headerLen && totalLen <= buf.size

    // UDP / TCP common
    val srcPort get() = buf.u16(headerLen)
    val dstPort get() = buf.u16(headerLen + 2)

    // UDP
    val udpDataOff get() = headerLen + 8
    val udpDataLen get() = minOf(buf.u16(headerLen + 4) - 8, totalLen - headerLen - 8)

    // TCP
    val tcpSeq get() = buf.i32(headerLen + 4)
    val tcpAck get() = buf.i32(headerLen + 8)
    val tcpHeaderLen get() = (buf.u8(headerLen + 12) ushr 4) * 4
    val tcpFlags get() = buf.u8(headerLen + 13)
    val tcpWindow get() = buf.u16(headerLen + 14)
    val tcpDataOff get() = headerLen + tcpHeaderLen
    val tcpDataLen get() = totalLen - headerLen - tcpHeaderLen

    /** MSS option from a SYN, or 0. */
    fun tcpMss(): Int {
        var i = headerLen + 20
        val end = headerLen + tcpHeaderLen
        while (i < end) {
            when (val kind = buf.u8(i)) {
                0 -> return 0
                1 -> i++
                else -> {
                    if (i + 1 >= end) return 0
                    val len = buf.u8(i + 1)
                    if (len < 2) return 0
                    if (kind == 2 && len == 4 && i + 3 < end) return buf.u16(i + 2)
                    i += len
                }
            }
        }
        return 0
    }
}

object Packets {
    private val ipId = AtomicInteger(1)

    fun checksum(buf: ByteArray, off: Int, len: Int, initial: Long = 0): Int {
        var sum = initial
        var i = off
        val end = off + len
        while (i < end - 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun pseudo4(src: Int, dst: Int, proto: Int, len: Int): Long =
        (src ushr 16).toLong() + (src and 0xFFFF) + (dst ushr 16) + (dst and 0xFFFF) + proto + len

    private fun writeIpv4Header(p: ByteArray, total: Int, proto: Int, src: Int, dst: Int) {
        p[0] = 0x45
        p[1] = 0
        p.put16(2, total)
        p.put16(4, ipId.getAndIncrement() and 0xFFFF)
        p.put16(6, 0x4000) // don't fragment
        p[8] = 64
        p[9] = proto.toByte()
        p.put16(10, 0)
        p.put32(12, src)
        p.put32(16, dst)
        p.put16(10, checksum(p, 0, 20))
    }

    fun udp(src: Int, srcPort: Int, dst: Int, dstPort: Int, data: ByteArray, off: Int, len: Int): ByteArray {
        val total = 28 + len
        val p = ByteArray(total)
        writeIpv4Header(p, total, PROTO_UDP, src, dst)
        p.put16(20, srcPort)
        p.put16(22, dstPort)
        p.put16(24, 8 + len)
        p.put16(26, 0)
        System.arraycopy(data, off, p, 28, len)
        var c = checksum(p, 20, 8 + len, pseudo4(src, dst, PROTO_UDP, 8 + len))
        if (c == 0) c = 0xFFFF
        p.put16(26, c)
        return p
    }

    fun tcp(
        src: Int, srcPort: Int, dst: Int, dstPort: Int,
        seq: Int, ack: Int, flags: Int, window: Int,
        data: ByteArray? = null, off: Int = 0, len: Int = 0,
        mss: Int = 0,
    ): ByteArray {
        val optLen = if (mss > 0) 4 else 0
        val tcpLen = 20 + optLen + len
        val total = 20 + tcpLen
        val p = ByteArray(total)
        writeIpv4Header(p, total, PROTO_TCP, src, dst)
        p.put16(20, srcPort)
        p.put16(22, dstPort)
        p.put32(24, seq)
        p.put32(28, ack)
        p[32] = (((20 + optLen) / 4) shl 4).toByte()
        p[33] = flags.toByte()
        p.put16(34, window.coerceIn(0, 0xFFFF))
        p.put16(36, 0)
        p.put16(38, 0)
        if (mss > 0) {
            p[40] = 2; p[41] = 4; p.put16(42, mss)
        }
        if (len > 0 && data != null) System.arraycopy(data, off, p, 20 + 20 + optLen, len)
        p.put16(36, checksum(p, 20, tcpLen, pseudo4(src, dst, PROTO_TCP, tcpLen)))
        return p
    }

    /** Wraps a raw ICMP message (header + data) into an IPv4 packet, fixing the ICMP checksum. */
    fun icmp(src: Int, dst: Int, icmp: ByteArray, off: Int, len: Int): ByteArray {
        val total = 20 + len
        val p = ByteArray(total)
        writeIpv4Header(p, total, PROTO_ICMP, src, dst)
        System.arraycopy(icmp, off, p, 20, len)
        p.put16(22, 0)
        p.put16(22, checksum(p, 20, len))
        return p
    }

    /**
     * Splits an IPv4 packet that is bigger than [mtu] into fragments (needed when a server
     * sends a UDP datagram larger than the tunnel MTU).
     */
    fun fragment(packet: ByteArray, mtu: Int): List<ByteArray> {
        if (packet.size <= mtu) return listOf(packet)
        val hl = 20
        val payload = packet.size - hl
        val chunk = ((mtu - hl) / 8) * 8
        val out = ArrayList<ByteArray>((payload + chunk - 1) / chunk)
        val id = packet.u16(4)
        var off = 0
        while (off < payload) {
            val n = minOf(chunk, payload - off)
            val more = off + n < payload
            val f = ByteArray(hl + n)
            System.arraycopy(packet, 0, f, 0, hl)
            System.arraycopy(packet, hl + off, f, hl, n)
            f.put16(2, hl + n)
            f.put16(4, id)
            f.put16(6, (if (more) 0x2000 else 0) or (off / 8))
            f.put16(10, 0)
            f.put16(10, checksum(f, 0, hl))
            out.add(f)
            off += n
        }
        return out
    }
}
