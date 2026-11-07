package io.github.shdavlatbek.mlbblock

import io.github.shdavlatbek.mlbblock.net.Cidr
import io.github.shdavlatbek.mlbblock.net.FilterConfig
import io.github.shdavlatbek.mlbblock.net.GeoIp
import io.github.shdavlatbek.mlbblock.net.Ip
import io.github.shdavlatbek.mlbblock.net.Ipv4
import io.github.shdavlatbek.mlbblock.net.Mode
import io.github.shdavlatbek.mlbblock.net.PROTO_TCP
import io.github.shdavlatbek.mlbblock.net.PROTO_UDP
import io.github.shdavlatbek.mlbblock.net.Packets
import io.github.shdavlatbek.mlbblock.net.Tcp
import io.github.shdavlatbek.mlbblock.vpn.Engine
import io.github.shdavlatbek.mlbblock.vpn.Monitor
import io.github.shdavlatbek.mlbblock.vpn.Protector
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileDescriptor
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class EngineTest {
    private val app = Ip.parse("10.88.0.2")!!
    private val local = Ip.parse("127.0.0.1")!!
    private val loopback = InetAddress.getByName("127.0.0.1")

    @Volatile private var cfg = FilterConfig(countries = setOf("UZ"), mode = Mode.STRICT, revision = 1)
    private val out = LinkedBlockingQueue<ByteArray>()
    private lateinit var engine: Engine
    private lateinit var loop: Thread

    private object NoProtect : Protector {
        override fun protect(socket: Socket) = true
        override fun protect(socket: DatagramSocket) = true
        override fun protect(fd: FileDescriptor) = true
    }

    @Before
    fun setUp() {
        val geo = File("src/main/assets/geoip-v4.bin").inputStream().use { GeoIp.load(it) }
        engine = Engine(geo, { cfg }, NoProtect, { out.add(it) })
        loop = thread(isDaemon = true) { engine.run() }
    }

    @After
    fun tearDown() {
        engine.stop()
        loop.join(2000)
    }

    private fun next(timeoutMs: Long = 3000): Ipv4? = out.poll(timeoutMs, TimeUnit.MILLISECONDS)?.let { Ipv4(it, it.size) }

    private fun nextTcp(timeoutMs: Long = 3000): Ipv4 {
        val p = next(timeoutMs)
        assertNotNull("expected a TCP packet from the engine", p)
        assertEquals(PROTO_TCP, p!!.proto)
        return p
    }

    private fun tcp(srcPort: Int, dst: Int, dstPort: Int, seq: Int, ack: Int, flags: Int, data: ByteArray? = null, window: Int = 65535) =
        Packets.tcp(app, srcPort, dst, dstPort, seq, ack, flags, window, data, 0, data?.size ?: 0, mss = if (flags and Tcp.SYN != 0) 1360 else 0)

    private fun waitFor(timeoutMs: Long = 3000, cond: () -> Boolean): Boolean {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) {
            if (cond()) return true
            Thread.sleep(20)
        }
        return cond()
    }

    // ---------------- UDP ----------------

    @Test
    fun udpIsForwardedBothWays() {
        val server = DatagramSocket(0, loopback)
        thread(isDaemon = true) {
            val buf = ByteArray(2000)
            val p = DatagramPacket(buf, buf.size)
            server.receive(p)
            val reply = ("pong:" + String(buf, 0, p.length)).toByteArray()
            server.send(DatagramPacket(reply, reply.size, p.socketAddress))
        }
        val data = "ping".toByteArray()
        engine.submit(Packets.udp(app, 40000, local, server.localPort, data, 0, data.size))
        val r = next()
        assertNotNull(r)
        assertEquals(PROTO_UDP, r!!.proto)
        assertEquals(local, r.src)
        assertEquals(server.localPort, r.srcPort)
        assertEquals(app, r.dst)
        assertEquals(40000, r.dstPort)
        assertEquals("pong:ping", String(r.buf, r.udpDataOff, r.udpDataLen))
        server.close()
    }

    @Test
    fun udpToForeignGameServerIsDropped() {
        val de = Ip.parse("3.120.0.1")!! // DE in DB-IP
        val data = ByteArray(40)
        repeat(3) { engine.submit(Packets.udp(app, 40001, de, 5501, data, 0, data.size)) }
        assertNull(next(500))
        assertTrue(waitFor { (Monitor.snapshot().firstOrNull { it.ip == de }?.dropped ?: 0) >= 3 })
    }

    // ---------------- TCP ----------------

    @Test
    fun tcpToForeignGameServerGetsReset() {
        val de = Ip.parse("3.120.0.1")!!
        engine.submit(tcp(41000, de, 10003, 5000, 0, Tcp.SYN))
        val r = nextTcp()
        assertTrue(r.tcpFlags and Tcp.RST != 0)
        assertEquals(5001, r.tcpAck)
    }

    @Test
    fun tcpEchoAndGracefulClose() {
        val server = ServerSocket(0, 5, loopback)
        thread(isDaemon = true) {
            server.accept().use { s ->
                val buf = ByteArray(1024)
                while (true) {
                    val n = s.getInputStream().read(buf)
                    if (n < 0) break
                    s.getOutputStream().write(buf, 0, n)
                }
            }
        }
        val port = server.localPort
        engine.submit(tcp(42000, local, port, 1000, 0, Tcp.SYN))
        val synAck = nextTcp()
        assertEquals(Tcp.SYN or Tcp.ACK, synAck.tcpFlags)
        assertEquals(1001, synAck.tcpAck)
        val isn = synAck.tcpSeq

        engine.submit(tcp(42000, local, port, 1001, isn + 1, Tcp.ACK))
        engine.submit(tcp(42000, local, port, 1001, isn + 1, Tcp.ACK or Tcp.PSH, "hello".toByteArray()))

        var gotAck = false
        var echoed: String? = null
        while (echoed == null) {
            val p = nextTcp()
            if (p.tcpDataLen == 0 && p.tcpAck == 1006) gotAck = true
            if (p.tcpDataLen > 0) {
                assertEquals(isn + 1, p.tcpSeq)
                echoed = String(p.buf, p.tcpDataOff, p.tcpDataLen)
            }
        }
        assertTrue(gotAck)
        assertEquals("hello", echoed)

        // app acks the echo and closes
        engine.submit(tcp(42000, local, port, 1006, isn + 6, Tcp.ACK))
        engine.submit(tcp(42000, local, port, 1006, isn + 6, Tcp.FIN or Tcp.ACK))
        var finSeq: Int? = null
        while (finSeq == null) {
            val p = nextTcp()
            if (p.tcpFlags and Tcp.FIN != 0) finSeq = p.tcpSeq
        }
        assertEquals(isn + 6, finSeq)
        engine.submit(tcp(42000, local, port, 1007, isn + 7, Tcp.ACK))
        assertTrue("flow should be gone", waitFor { engine.tcpCount == 0 })
        server.close()
    }

    /** Server sends 1 MB; the app has a small window and "loses" one segment, so retransmit must work. */
    @Test
    fun tcpBulkDownloadWithSmallWindowAndLoss() {
        val total = 1 shl 20
        val payload = ByteArray(total) { (it * 31 + 7).toByte() }
        val server = ServerSocket(0, 5, loopback)
        thread(isDaemon = true) {
            server.accept().use { s -> s.getOutputStream().write(payload); s.shutdownOutput(); Thread.sleep(3000) }
        }
        val port = server.localPort
        val window = 8192
        engine.submit(tcp(43000, local, port, 1, 0, Tcp.SYN, window = window))
        val synAck = nextTcp()
        val isn = synAck.tcpSeq
        engine.submit(tcp(43000, local, port, 2, isn + 1, Tcp.ACK, window = window))

        val got = ByteArrayOutputStream()
        var expected = isn + 1
        var dropped = false
        var maxInFlight = 0
        var lastAck = isn + 1
        var fin = false
        val deadline = System.currentTimeMillis() + 30_000
        while (!fin && System.currentTimeMillis() < deadline) {
            val p = nextTcp(5000)
            if (p.tcpFlags and Tcp.RST != 0) throw AssertionError("unexpected reset")
            if (p.tcpDataLen > 0) {
                maxInFlight = maxOf(maxInFlight, p.tcpSeq + p.tcpDataLen - lastAck)
                if (!dropped && got.size() > 100_000) {
                    dropped = true // pretend this segment was lost
                    continue
                }
                if (p.tcpSeq == expected) {
                    got.write(p.buf, p.tcpDataOff, p.tcpDataLen)
                    expected += p.tcpDataLen
                }
                lastAck = expected
                engine.submit(tcp(43000, local, port, 2, expected, Tcp.ACK, window = window))
            }
            if (p.tcpFlags and Tcp.FIN != 0 && p.tcpSeq == expected) {
                fin = true
                engine.submit(tcp(43000, local, port, 2, expected + 1, Tcp.ACK or Tcp.FIN, window = window))
            }
        }
        assertTrue("did not finish", fin)
        assertTrue("segment loss was not simulated", dropped)
        assertTrue("window not respected: $maxInFlight", maxInFlight <= window)
        assertEquals(total, got.size())
        assertArrayEquals(payload, got.toByteArray())
        server.close()
    }

    @Test
    fun changingRulesKillsLiveConnection() {
        val server = ServerSocket(0, 5, loopback)
        thread(isDaemon = true) { server.accept().use { Thread.sleep(5000) } }
        val port = server.localPort
        // TCP to a game port on our "server"
        engine.submit(tcp(44000, local, port, 1, 0, Tcp.SYN))
        val synAck = nextTcp()
        engine.submit(tcp(44000, local, port, 2, synAck.tcpSeq + 1, Tcp.ACK))
        assertTrue(waitFor { engine.tcpCount == 1 })
        cfg = cfg.copy(block = listOf(Cidr(local, 32)), revision = cfg.revision + 1)
        var reset = false
        val end = System.currentTimeMillis() + 3000
        while (!reset && System.currentTimeMillis() < end) {
            val p = next(500) ?: continue
            if (p.proto == PROTO_TCP && p.tcpFlags and Tcp.RST != 0) reset = true
        }
        assertTrue("live connection was not reset", reset)
        assertTrue(waitFor { engine.tcpCount == 0 })
        server.close()
    }
}
