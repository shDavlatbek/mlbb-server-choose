package io.github.shdavlatbek.mlbblock.vpn

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import io.github.shdavlatbek.mlbblock.net.Ipv4
import io.github.shdavlatbek.mlbblock.net.Packets
import java.io.FileDescriptor
import java.util.concurrent.ConcurrentHashMap

/**
 * Forwards ping (ICMP echo) to allowed servers through unprivileged "ping sockets", so the game
 * still sees a ping for the servers we keep open. Blocked servers never get here.
 */
class IcmpForwarder(
    private val protector: Protector,
    private val write: (ByteArray) -> Unit,
) : IcmpHandler {

    private class Flow(val key: Long, val dst: Int, val appIp: Int, val id: Int, val fd: FileDescriptor, val entry: ServerEntry) {
        @Volatile var lastActive = System.currentTimeMillis()
        val sentAt = ConcurrentHashMap<Int, Long>()
    }

    private val flows = ConcurrentHashMap<Long, Flow>()
    private var wakeRead: FileDescriptor? = null
    private var wakeWrite: FileDescriptor? = null
    @Volatile private var running = true
    @Volatile private var unavailable = false
    private val thread: Thread

    init {
        try {
            val p = Os.pipe()
            wakeRead = p[0]
            wakeWrite = p[1]
        } catch (_: Exception) {
        }
        thread = Thread({ loop() }, "icmp").apply { isDaemon = true; start() }
    }

    override fun echo(p: Ipv4, entry: ServerEntry) {
        if (unavailable || !running) return
        val off = p.payloadOff
        val len = p.payloadLen
        val b = p.buf
        val id = ((b[off + 4].toInt() and 0xFF) shl 8) or (b[off + 5].toInt() and 0xFF)
        val seq = ((b[off + 6].toInt() and 0xFF) shl 8) or (b[off + 7].toInt() and 0xFF)
        val key = ((p.dst.toLong() and 0xFFFFFFFFL) shl 16) or id.toLong()
        var f = flows[key]
        if (f == null) {
            val fd = try {
                Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_ICMP)
            } catch (e: Exception) {
                unavailable = true
                Monitor.event("ICMP (пинг) недоступен на этом телефоне: ${e.message}")
                return
            }
            try {
                protector.protect(fd)
                Os.connect(fd, Engine.inet(p.dst), 0)
            } catch (_: Exception) {
                closeFd(fd)
                return
            }
            f = Flow(key, p.dst, p.src, id, fd, entry)
            flows[key] = f
            wake()
        }
        f.lastActive = System.currentTimeMillis()
        f.sentAt[seq] = System.nanoTime()
        if (f.sentAt.size > 64) f.sentAt.clear()
        try {
            Os.write(f.fd, b, off, len)
            Monitor.out(entry)
        } catch (_: Exception) {
        }
    }

    private fun loop() {
        val buf = ByteArray(65536)
        while (running) {
            val list = flows.values.toList()
            val wr = wakeRead
            val base = if (wr != null) 1 else 0
            val fds = Array(list.size + base) { StructPollfd() }
            if (wr != null) {
                fds[0].fd = wr
                fds[0].events = OsConstants.POLLIN.toShort()
            }
            for (i in list.indices) {
                fds[i + base].fd = list[i].fd
                fds[i + base].events = OsConstants.POLLIN.toShort()
            }
            try {
                if (fds.isEmpty()) {
                    sleepQuietly()
                    continue
                }
                Os.poll(fds, if (wr != null) 1000 else 100)
            } catch (e: ErrnoException) {
                if (e.errno != OsConstants.EINTR) sleepQuietly()
                continue
            } catch (_: Exception) {
                sleepQuietly()
                continue
            }
            if (!running) break
            if (wr != null && fds[0].revents.toInt() and OsConstants.POLLIN != 0) {
                try { Os.read(wr, ByteArray(64), 0, 64) } catch (_: Exception) {}
            }
            for (i in list.indices) {
                if (fds[i + base].revents.toInt() and OsConstants.POLLIN == 0) continue
                val f = list[i]
                try {
                    val n = Os.read(f.fd, buf, 0, buf.size)
                    if (n < 8 || buf[0].toInt() != 0) continue // only echo replies
                    val seq = ((buf[6].toInt() and 0xFF) shl 8) or (buf[7].toInt() and 0xFF)
                    buf[4] = (f.id ushr 8).toByte()
                    buf[5] = f.id.toByte()
                    write(Packets.icmp(f.dst, f.appIp, buf, 0, n))
                    Monitor.inbound(f.entry)
                    f.sentAt.remove(seq)?.let { t -> Monitor.rtt(f.entry, ((System.nanoTime() - t) / 1_000_000).toInt()) }
                } catch (_: Exception) {
                }
            }
        }
    }

    override fun tick(now: Long) {
        for (f in flows.values) {
            if (now - f.lastActive > 30_000) {
                flows.remove(f.key)
                closeFd(f.fd)
            }
        }
    }

    override fun close() {
        running = false
        wake()
        try { thread.join(1500) } catch (_: Exception) {}
        for (f in flows.values) closeFd(f.fd)
        flows.clear()
        wakeRead?.let { closeFd(it) }
        wakeWrite?.let { closeFd(it) }
    }

    private fun wake() {
        val w = wakeWrite ?: return
        try { Os.write(w, byteArrayOf(1), 0, 1) } catch (_: Exception) {}
    }

    private fun closeFd(fd: FileDescriptor) {
        try { Os.close(fd) } catch (_: Exception) {}
    }

    private fun sleepQuietly() {
        try { Thread.sleep(50) } catch (_: InterruptedException) {}
    }
}
