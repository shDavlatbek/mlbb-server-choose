package io.github.shdavlatbek.mlbblock.vpn

import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import io.github.shdavlatbek.mlbblock.net.Ip
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Measures ping to game servers: 3 ICMP echoes over an unprivileged ping socket
 * (falls back to /system/bin/ping). Our app is outside the VPN, so blocked servers
 * can be pinged too — handy for comparing countries and cities.
 */
object Pinger {
    private const val SAMPLES = 3
    private const val TIMEOUT_MS = 1000
    private const val FRESH_MS = 30_000L
    private val TIME = Regex("time[=<]\\s*([\\d.]+)")

    private val pool = Executors.newFixedThreadPool(4) { r -> Thread(r, "ping").apply { isDaemon = true } }
    private val busy = ConcurrentHashMap.newKeySet<Int>()
    @Volatile private var socketsWork: Boolean? = null

    val isBusy get() = busy.isNotEmpty()

    /** Queues a ping for every entry that was not measured recently. Returns how many were queued. */
    fun pingAll(entries: Collection<ServerEntry>, force: Boolean = false): Int {
        val now = System.currentTimeMillis()
        var queued = 0
        for (e in entries) {
            if (Ip.isPrivate(e.ip)) continue
            if (!force && now - e.pingAt < FRESH_MS) continue
            if (!busy.add(e.ip)) continue
            queued++
            pool.execute {
                try {
                    Monitor.ping(e, measure(e.ip))
                } catch (_: Exception) {
                    Monitor.ping(e, ServerEntry.PING_LOST)
                } finally {
                    busy.remove(e.ip)
                }
            }
        }
        return queued
    }

    /** Median round trip in ms, or [ServerEntry.PING_LOST]. Blocking. */
    fun measure(ip: Int): Int {
        val samples = (if (socketsWork != false) icmp(ip) else null) ?: binary(ip)
        if (samples.isEmpty()) return ServerEntry.PING_LOST
        return samples.sorted()[samples.size / 2]
    }

    private fun icmp(ip: Int): List<Int>? {
        val fd = try {
            Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_ICMP)
        } catch (_: Exception) {
            socketsWork = false
            return null
        }
        socketsWork = true
        try {
            Os.connect(fd, Engine.inet(ip), 0)
            val out = ArrayList<Int>(SAMPLES)
            val req = ByteArray(8 + 32)
            req[0] = 8 // echo request; the kernel fills in id and checksum
            val buf = ByteArray(256)
            for (seq in 1..SAMPLES) {
                req[6] = (seq ushr 8).toByte()
                req[7] = seq.toByte()
                val t0 = System.nanoTime()
                Os.write(fd, req, 0, req.size)
                val deadline = t0 + TimeUnit.MILLISECONDS.toNanos(TIMEOUT_MS.toLong())
                while (true) {
                    val left = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()).toInt()
                    if (left <= 0) break
                    val p = StructPollfd().apply { this.fd = fd; events = OsConstants.POLLIN.toShort() }
                    if (Os.poll(arrayOf(p), left) <= 0) break
                    val n = Os.read(fd, buf, 0, buf.size)
                    val gotSeq = ((buf[6].toInt() and 0xFF) shl 8) or (buf[7].toInt() and 0xFF)
                    if (n >= 8 && buf[0].toInt() == 0 && gotSeq == seq) {
                        out.add(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0).toInt())
                        break
                    }
                }
                if (seq < SAMPLES) Thread.sleep(150)
            }
            return out
        } catch (_: Exception) {
            return emptyList()
        } finally {
            try { Os.close(fd) } catch (_: Exception) {}
        }
    }

    private fun binary(ip: Int): List<Int> = try {
        val p = ProcessBuilder("/system/bin/ping", "-c", "$SAMPLES", "-i", "0.2", "-W", "1", "-n", Ip.str(ip))
            .redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readLines()
        p.waitFor(5, TimeUnit.SECONDS)
        p.destroy()
        out.mapNotNull { line -> TIME.find(line)?.groupValues?.get(1)?.toDoubleOrNull()?.toInt() }
    } catch (_: Exception) {
        emptyList()
    }
}
