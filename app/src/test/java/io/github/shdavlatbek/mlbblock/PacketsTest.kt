package io.github.shdavlatbek.mlbblock

import io.github.shdavlatbek.mlbblock.net.Ip
import io.github.shdavlatbek.mlbblock.net.Ipv4
import io.github.shdavlatbek.mlbblock.net.PROTO_TCP
import io.github.shdavlatbek.mlbblock.net.PROTO_UDP
import io.github.shdavlatbek.mlbblock.net.Packets
import io.github.shdavlatbek.mlbblock.net.Tcp
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketsTest {
    private val a = Ip.parse("10.88.0.2")!!
    private val b = Ip.parse("213.230.64.1")!!

    private fun pseudo(p: Ipv4): Long {
        val len = p.totalLen - p.headerLen
        return (p.src ushr 16).toLong() + (p.src and 0xFFFF) + (p.dst ushr 16) + (p.dst and 0xFFFF) + p.proto + len
    }

    @Test
    fun udpRoundTrip() {
        val data = "hello mlbb".toByteArray()
        val raw = Packets.udp(b, 5501, a, 40000, data, 0, data.size)
        val p = Ipv4(raw, raw.size)
        assertTrue(p.valid)
        assertEquals(PROTO_UDP, p.proto)
        assertEquals(b, p.src)
        assertEquals(a, p.dst)
        assertEquals(5501, p.srcPort)
        assertEquals(40000, p.dstPort)
        assertEquals(data.size, p.udpDataLen)
        assertArrayEquals(data, raw.copyOfRange(p.udpDataOff, p.udpDataOff + p.udpDataLen))
        assertEquals(0, Packets.checksum(raw, 0, 20)) // IP header checksum verifies
        assertEquals(0, Packets.checksum(raw, 20, raw.size - 20, pseudo(p))) // UDP checksum verifies
    }

    @Test
    fun tcpWithMss() {
        val payload = ByteArray(100) { it.toByte() }
        val raw = Packets.tcp(a, 40001, b, 10001, 1234, 5678, Tcp.SYN, 65535, payload, 0, 100, mss = 1360)
        val p = Ipv4(raw, raw.size)
        assertEquals(PROTO_TCP, p.proto)
        assertEquals(1234, p.tcpSeq)
        assertEquals(5678, p.tcpAck)
        assertEquals(Tcp.SYN, p.tcpFlags)
        assertEquals(24, p.tcpHeaderLen)
        assertEquals(1360, p.tcpMss())
        assertEquals(100, p.tcpDataLen)
        assertEquals(65535, p.tcpWindow)
        assertEquals(0, Packets.checksum(raw, 20, raw.size - 20, pseudo(p)))
        assertFalse(p.isFragment)
    }

    @Test
    fun fragmentsReassemble() {
        val data = ByteArray(4000) { (it * 7).toByte() }
        val raw = Packets.udp(b, 5501, a, 40000, data, 0, data.size)
        val frags = Packets.fragment(raw, 1500)
        assertEquals(3, frags.size)
        val joined = java.io.ByteArrayOutputStream()
        var expectOff = 0
        for ((i, f) in frags.withIndex()) {
            assertTrue(f.size <= 1500)
            assertEquals(0, Packets.checksum(f, 0, 20))
            val flags = ((f[6].toInt() and 0xFF) shl 8) or (f[7].toInt() and 0xFF)
            assertEquals(expectOff / 8, flags and 0x1FFF)
            assertEquals(i < frags.size - 1, flags and 0x2000 != 0)
            joined.write(f, 20, f.size - 20)
            expectOff += f.size - 20
        }
        assertArrayEquals(raw.copyOfRange(20, raw.size), joined.toByteArray())
    }

    @Test
    fun ipParsing() {
        assertEquals("213.230.64.1", Ip.str(Ip.parse("213.230.64.1")!!))
        assertEquals(null, Ip.parse("256.1.1.1"))
        assertEquals(null, Ip.parse("1.2.3"))
        assertEquals(Ip.parse("10.1.2.0")!! to 24, Ip.parseCidr("10.1.2.77/24"))
        assertTrue(Ip.isPrivate(Ip.parse("192.168.1.1")!!))
        assertTrue(Ip.isPrivate(Ip.parse("100.64.0.1")!!))
        assertFalse(Ip.isPrivate(Ip.parse("8.8.8.8")!!))
    }
}
