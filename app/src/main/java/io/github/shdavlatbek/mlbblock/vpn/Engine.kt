package io.github.shdavlatbek.mlbblock.vpn

import io.github.shdavlatbek.mlbblock.net.FilterConfig
import io.github.shdavlatbek.mlbblock.net.GeoLookup
import io.github.shdavlatbek.mlbblock.net.Ipv4
import io.github.shdavlatbek.mlbblock.net.PROTO_ICMP
import io.github.shdavlatbek.mlbblock.net.PROTO_TCP
import io.github.shdavlatbek.mlbblock.net.PROTO_UDP
import io.github.shdavlatbek.mlbblock.net.Packets
import io.github.shdavlatbek.mlbblock.net.Policy
import io.github.shdavlatbek.mlbblock.net.Tcp
import java.io.FileDescriptor
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.PortUnreachableException
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentLinkedQueue

/** Keeps our own sockets out of the VPN (VpnService.protect). */
interface Protector {
    fun protect(socket: Socket): Boolean
    fun protect(socket: DatagramSocket): Boolean
    fun protect(fd: FileDescriptor): Boolean
}

/** Forwards ICMP echo (ping) for allowed servers. Optional: not every phone allows ping sockets. */
interface IcmpHandler {
    fun echo(p: Ipv4, entry: ServerEntry)
    fun tick(now: Long)
    fun close()
}

internal class UdpFlow(
    val key: Long,
    val appIp: Int,
    val appPort: Int,
    val dstIp: Int,
    val dstPort: Int,
    val entry: ServerEntry,
) {
    var channel: DatagramChannel? = null
    var blocked = false
    var dead = false
    var revision = 0
    var lastActive = 0L
}

/**
 * The packet engine. One thread ([run]) owns every socket; packets from the TUN device are
 * handed over with [submit]. Nothing here depends on Android, so it is tested on the JVM.
 */
class Engine(
    private val geo: GeoLookup,
    private val config: () -> FilterConfig,
    internal val protector: Protector,
    private val tunOut: (ByteArray) -> Unit,
    var icmp: IcmpHandler? = null,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    companion object {
        const val MTU = 1500
        private const val UDP_IDLE = 120_000L
        private const val DNS_IDLE = 20_000L
        private const val MAX_UDP = 2048
        private const val MAX_TCP = 1024
        private const val TICK = 200L

        fun inet(ip: Int): InetAddress = InetAddress.getByAddress(
            byteArrayOf((ip ushr 24).toByte(), (ip ushr 16).toByte(), (ip ushr 8).toByte(), ip.toByte())
        )

        fun flowKey(srcPort: Int, dstIp: Int, dstPort: Int): Long =
            (srcPort.toLong() shl 48) or ((dstIp.toLong() and 0xFFFFFFFFL) shl 16) or dstPort.toLong()
    }

    internal val selector: Selector = Selector.open()
    internal val readBuffer: ByteBuffer = ByteBuffer.allocate(65536)
    private val inbox = ConcurrentLinkedQueue<ByteArray>()
    private val udp = HashMap<Long, UdpFlow>()
    private val tcp = HashMap<Long, TcpFlow>()
    private var lastTick = 0L
    private var lastRevision = -1

    @Volatile private var running = true

    @Volatile var droppedFragments = 0L
        private set

    val udpCount get() = udp.size
    val tcpCount get() = tcp.size

    internal fun now() = clock()

    internal fun tunWrite(p: ByteArray) {
        try {
            if (p.size > MTU) Packets.fragment(p, MTU).forEach(tunOut) else tunOut(p)
        } catch (_: Exception) {
        }
    }

    /** Thread-safe: a raw IP packet read from the TUN device. */
    fun submit(packet: ByteArray) {
        inbox.add(packet)
        selector.wakeup()
    }

    fun stop() {
        running = false
        selector.wakeup()
    }

    fun run() {
        try {
            while (running) {
                drainInbox()
                selector.select(TICK)
                if (!running) break
                val it = selector.selectedKeys().iterator()
                while (it.hasNext()) {
                    val k = it.next()
                    it.remove()
                    if (!k.isValid) continue
                    when (val a = k.attachment()) {
                        is UdpFlow -> onUdpReadable(a)
                        is TcpFlow -> a.onKey(k)
                    }
                }
                drainInbox()
                val now = clock()
                if (now - lastTick >= TICK) {
                    lastTick = now
                    housekeeping(now)
                }
            }
        } finally {
            shutdown()
        }
    }

    private fun drainInbox() {
        while (true) {
            val p = inbox.poll() ?: return
            try {
                handle(p)
            } catch (_: Exception) {
            }
        }
    }

    internal fun handle(buf: ByteArray) {
        if (buf.size < 20 || (buf[0].toInt() ushr 4) != 4) return // IPv6 is not routed to us
        val p = Ipv4(buf, buf.size)
        if (!p.valid) return
        if (p.isFragment) {
            droppedFragments++
            return
        }
        when (p.proto) {
            PROTO_UDP -> if (p.payloadLen >= 8) onUdp(p)
            PROTO_TCP -> if (p.payloadLen >= 20 && p.tcpHeaderLen >= 20) onTcp(p)
            PROTO_ICMP -> if (p.payloadLen >= 8) onIcmp(p)
        }
    }

    // ---------------- UDP ----------------

    private fun onUdp(p: Ipv4) {
        val dst = p.dst
        if ((dst ushr 24 and 255) >= 224) return // multicast / broadcast
        val key = flowKey(p.srcPort, dst, p.dstPort)
        val cfg = config()
        var f = udp[key]
        if (f == null) {
            if (udp.size >= MAX_UDP) evictUdp()
            val country = geo.country(dst)
            val city = geo.city(dst, country)
            val v = Policy.decide(cfg, PROTO_UDP, dst, p.dstPort, country, city)
            val entry = Monitor.flowStarted(dst, country, city, PROTO_UDP, p.dstPort, Policy.classify(PROTO_UDP, p.dstPort), v)
            f = UdpFlow(key, p.src, p.srcPort, dst, p.dstPort, entry)
            f.blocked = v.blocked
            f.revision = cfg.revision
            udp[key] = f
            if (!f.blocked) openUdp(f)
        } else if (f.revision != cfg.revision) {
            recheckUdp(f, cfg)
        }
        f.lastActive = clock()
        if (f.blocked) {
            Monitor.drop(f.entry)
            return
        }
        val ch = f.channel ?: return
        val len = p.udpDataLen
        if (len < 0) return
        try {
            ch.write(ByteBuffer.wrap(p.buf, p.udpDataOff, len))
            Monitor.out(f.entry)
        } catch (_: PortUnreachableException) {
        } catch (_: IOException) {
            closeUdp(f)
        }
    }

    private fun openUdp(f: UdpFlow) {
        try {
            val ch = DatagramChannel.open()
            protector.protect(ch.socket())
            ch.configureBlocking(false)
            ch.connect(InetSocketAddress(inet(f.dstIp), f.dstPort))
            ch.register(selector, SelectionKey.OP_READ, f)
            f.channel = ch
        } catch (_: Exception) {
            f.dead = true
        }
    }

    private fun recheckUdp(f: UdpFlow, cfg: FilterConfig) {
        f.revision = cfg.revision
        val v = Policy.decide(cfg, PROTO_UDP, f.dstIp, f.dstPort, f.entry.country, cityOf(f.entry))
        if (v.blocked == f.blocked) return
        Monitor.flowStarted(f.dstIp, f.entry.country, f.entry.city, PROTO_UDP, f.dstPort, Policy.classify(PROTO_UDP, f.dstPort), v)
        f.blocked = v.blocked
        if (f.blocked) {
            f.channel?.let { ch -> try { ch.close() } catch (_: Exception) {} }
            f.channel = null
        } else if (f.channel == null) {
            openUdp(f)
        }
    }

    private fun onUdpReadable(f: UdpFlow) {
        val ch = f.channel ?: return
        try {
            repeat(32) {
                readBuffer.clear()
                val n = ch.read(readBuffer)
                if (n <= 0) return
                tunWrite(Packets.udp(f.dstIp, f.dstPort, f.appIp, f.appPort, readBuffer.array(), 0, n))
                Monitor.inbound(f.entry)
                f.lastActive = clock()
            }
        } catch (_: PortUnreachableException) {
        } catch (_: IOException) {
            closeUdp(f)
        }
    }

    private fun closeUdp(f: UdpFlow) {
        f.channel?.let { ch -> try { ch.close() } catch (_: Exception) {} }
        f.channel = null
        udp.remove(f.key)
    }

    private fun evictUdp() {
        udp.values.minByOrNull { it.lastActive }?.let { closeUdp(it) }
    }

    // ---------------- TCP ----------------

    private fun onTcp(p: Ipv4) {
        val key = flowKey(p.srcPort, p.dst, p.dstPort)
        val f = tcp[key]
        val flags = p.tcpFlags
        if (f != null) {
            f.onAppPacket(p)
            return
        }
        if (flags and Tcp.SYN != 0 && flags and Tcp.ACK == 0) {
            val cfg = config()
            val country = geo.country(p.dst)
            val city = geo.city(p.dst, country)
            val v = Policy.decide(cfg, PROTO_TCP, p.dst, p.dstPort, country, city)
            val entry = Monitor.flowStarted(p.dst, country, city, PROTO_TCP, p.dstPort, Policy.classify(PROTO_TCP, p.dstPort), v)
            if (v.blocked || tcp.size >= MAX_TCP) {
                if (v.blocked) Monitor.drop(entry)
                tunWrite(Packets.tcp(p.dst, p.dstPort, p.src, p.srcPort, 0, p.tcpSeq + 1, Tcp.RST or Tcp.ACK, 0))
                return
            }
            val flow = TcpFlow(this, key, p.src, p.srcPort, p.dst, p.dstPort, entry)
            flow.revision = cfg.revision
            tcp[key] = flow
            flow.start(p)
            return
        }
        // a segment for a connection we do not know: reset it
        if (flags and Tcp.RST != 0) return
        if (flags and Tcp.ACK != 0) {
            tunWrite(Packets.tcp(p.dst, p.dstPort, p.src, p.srcPort, p.tcpAck, 0, Tcp.RST, 0))
        } else {
            val ack = p.tcpSeq + p.tcpDataLen + (if (flags and Tcp.FIN != 0) 1 else 0)
            tunWrite(Packets.tcp(p.dst, p.dstPort, p.src, p.srcPort, 0, ack, Tcp.RST or Tcp.ACK, 0))
        }
    }

    internal fun tcpClosed(f: TcpFlow) {
        if (tcp[f.key] === f) tcp.remove(f.key)
    }

    // ---------------- ICMP ----------------

    private fun onIcmp(p: Ipv4) {
        val type = p.buf[p.payloadOff].toInt() and 0xFF
        if (type != 8) return // only echo requests
        val dst = p.dst
        val cfg = config()
        val country = geo.country(dst)
        val city = geo.city(dst, country)
        val v = Policy.decide(cfg, PROTO_ICMP, dst, 0, country, city)
        val entry = Monitor.flowStarted(dst, country, city, PROTO_ICMP, 0, Policy.classify(PROTO_ICMP, 0), v)
        if (v.blocked) {
            Monitor.drop(entry)
            return
        }
        icmp?.echo(p, entry)
    }

    /** The entry's city, looked up again if the city table was not ready when the flow began. */
    private fun cityOf(e: ServerEntry): String? =
        e.city ?: geo.city(e.ip, e.country)?.also { e.city = it }

    // ---------------- timers ----------------

    private fun housekeeping(now: Long) {
        val cfg = config()
        val changed = cfg.revision != lastRevision
        lastRevision = cfg.revision
        if (changed) {
            for (f in tcp.values.toList()) {
                if (f.revision == cfg.revision) continue
                f.revision = cfg.revision
                val v = Policy.decide(cfg, PROTO_TCP, f.dstIp, f.dstPort, f.entry.country, cityOf(f.entry))
                if (v.blocked) {
                    Monitor.flowStarted(f.dstIp, f.entry.country, f.entry.city, PROTO_TCP, f.dstPort, Policy.classify(PROTO_TCP, f.dstPort), v)
                    f.kill()
                }
            }
            for (f in udp.values.toList()) if (f.revision != cfg.revision) recheckUdp(f, cfg)
        }
        for (f in tcp.values.toList()) f.tick(now)
        val it = udp.values.iterator()
        while (it.hasNext()) {
            val f = it.next()
            val idle = if (f.dstPort == 53) DNS_IDLE else UDP_IDLE
            if (f.dead || now - f.lastActive > idle) {
                f.channel?.let { ch -> try { ch.close() } catch (_: Exception) {} }
                it.remove()
            }
        }
        icmp?.tick(now)
    }

    private fun shutdown() {
        for (f in tcp.values.toList()) f.kill()
        tcp.clear()
        for (f in udp.values) f.channel?.let { ch -> try { ch.close() } catch (_: Exception) {} }
        udp.clear()
        try { icmp?.close() } catch (_: Exception) {}
        try { selector.close() } catch (_: Exception) {}
    }
}
