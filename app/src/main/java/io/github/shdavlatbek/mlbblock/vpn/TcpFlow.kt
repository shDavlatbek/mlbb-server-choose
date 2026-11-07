package io.github.shdavlatbek.mlbblock.vpn

import io.github.shdavlatbek.mlbblock.net.Ipv4
import io.github.shdavlatbek.mlbblock.net.Packets
import io.github.shdavlatbek.mlbblock.net.Tcp
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import kotlin.random.Random

/** Fixed-size FIFO of bytes: data sent to the app that it has not acknowledged yet. */
internal class ByteRing(capacity: Int) {
    private val buf = ByteArray(capacity)
    private var head = 0
    var size = 0
        private set
    val free get() = buf.size - size

    fun append(src: ByteArray, off: Int, len: Int) {
        require(len <= free)
        var tail = (head + size) % buf.size
        var o = off
        var n = len
        while (n > 0) {
            val c = minOf(n, buf.size - tail)
            System.arraycopy(src, o, buf, tail, c)
            tail = (tail + c) % buf.size
            o += c
            n -= c
        }
        size += len
    }

    fun drop(n: Int) {
        val k = minOf(n, size)
        head = (head + k) % buf.size
        size -= k
    }

    fun copy(from: Int, len: Int, dst: ByteArray, dstOff: Int) {
        var p = (head + from) % buf.size
        var o = dstOff
        var n = len
        while (n > 0) {
            val c = minOf(n, buf.size - p)
            System.arraycopy(buf, p, dst, o, c)
            p = (p + c) % buf.size
            o += c
            n -= c
        }
    }
}

/**
 * One TCP connection of the game. The game's TCP stack talks to us through the TUN device;
 * we talk to the real server through a normal (protected) socket and copy bytes between them.
 */
internal class TcpFlow(
    private val engine: Engine,
    val key: Long,
    val appIp: Int,
    val appPort: Int,
    val dstIp: Int,
    val dstPort: Int,
    val entry: ServerEntry,
) {
    enum class State { CONNECTING, SYN_RCVD, ESTABLISHED, CLOSED }

    companion object {
        const val MSS = 1360
        const val WINDOW = 65535
        private const val INITIAL_RTO = 600L
        private const val MAX_RTO = 8000L
        private const val MAX_RETRIES = 8
        private const val CONNECT_TIMEOUT = 15_000L
        private const val IDLE_TIMEOUT = 20 * 60_000L
        private const val HALF_CLOSED_TIMEOUT = 90_000L

        private fun seqGt(a: Int, b: Int) = a - b > 0
        private fun seqLt(a: Int, b: Int) = a - b < 0
    }

    var state = State.CONNECTING
        private set
    var revision = 0

    private var channel: SocketChannel? = null
    private var selKey: SelectionKey? = null

    private val isn = Random.nextInt()
    private var sndUna = isn
    private var sndNxt = isn
    private var rcvNxt = 0
    private var sndWnd = 0
    private var mss = MSS

    private val unacked = ByteRing(WINDOW + 1)
    private val toRemote = ArrayDeque<ByteBuffer>()
    private var toRemoteBytes = 0

    private var appFin = false
    private var remoteEof = false
    private var finSent = false
    private var finAcked = false
    private var outShutdown = false
    private var lastAdvWnd = WINDOW

    private val created = engine.now()
    private var lastActivity = created
    private var lastSend = 0L
    private var rto = INITIAL_RTO
    private var retries = 0

    // ---- setup ----

    fun start(syn: Ipv4) {
        rcvNxt = syn.tcpSeq + 1
        sndWnd = syn.tcpWindow
        val m = syn.tcpMss()
        mss = if (m > 0) minOf(m, MSS) else 536
        try {
            val ch = SocketChannel.open()
            channel = ch
            engine.protector.protect(ch.socket())
            ch.configureBlocking(false)
            try { ch.socket().tcpNoDelay = true } catch (_: Exception) {}
            val done = ch.connect(InetSocketAddress(Engine.inet(dstIp), dstPort))
            selKey = ch.register(engine.selector, if (done) 0 else SelectionKey.OP_CONNECT, this)
            if (done) onConnected()
        } catch (e: Exception) {
            abort()
        }
    }

    private fun onConnected() {
        state = State.SYN_RCVD
        sndUna = isn
        sndNxt = isn + 1
        sendSynAck()
        lastSend = engine.now()
        updateInterest()
    }

    // ---- packets from the game ----

    fun onAppPacket(p: Ipv4) {
        if (state == State.CLOSED) return
        val flags = p.tcpFlags
        lastActivity = engine.now()
        if (flags and Tcp.RST != 0) {
            close()
            return
        }
        if (flags and Tcp.SYN != 0) {
            // retransmitted SYN: answer again if we already did
            if (state == State.SYN_RCVD) sendSynAck()
            return
        }
        if (state == State.CONNECTING) return

        if (flags and Tcp.ACK != 0) onAck(p)
        if (state == State.CLOSED) return

        val len = p.tcpDataLen
        if (len > 0 && state == State.ESTABLISHED) onData(p, len)

        if (flags and Tcp.FIN != 0 && state == State.ESTABLISHED) {
            if (!appFin && p.tcpSeq + len == rcvNxt) {
                rcvNxt += 1
                appFin = true
                sendAck()
                maybeShutdownOutput()
            } else if (appFin) {
                sendAck() // FIN retransmission
            }
        }
        checkDone()
        updateInterest()
    }

    private fun onAck(p: Ipv4) {
        val ack = p.tcpAck
        if (seqGt(ack, sndUna) && !seqGt(ack, sndNxt)) {
            var acked = ack - sndUna
            if (state == State.SYN_RCVD) {
                state = State.ESTABLISHED
                acked -= 1
            }
            if (finSent && !finAcked && ack == sndNxt) {
                finAcked = true
                acked -= 1
            }
            if (acked > 0) unacked.drop(acked)
            sndUna = ack
            retries = 0
            rto = INITIAL_RTO
            lastSend = engine.now()
        }
        sndWnd = p.tcpWindow
    }

    private fun onData(p: Ipv4, len: Int) {
        if (appFin) return
        var off = p.tcpDataOff
        var n = len
        val seq = p.tcpSeq
        if (seq != rcvNxt) {
            if (seqLt(seq, rcvNxt)) {
                val skip = rcvNxt - seq
                if (skip >= n) {
                    sendAck() // pure duplicate
                    return
                }
                off += skip
                n -= skip
            } else {
                sendAck() // a hole: ask for the missing bytes
                return
            }
        }
        n = minOf(n, rcvWindow())
        if (n <= 0) {
            sendAck()
            return
        }
        toRemote.addLast(ByteBuffer.wrap(p.buf.copyOfRange(off, off + n)))
        toRemoteBytes += n
        rcvNxt += n
        Monitor.out(entry)
        try {
            flushToRemote()
        } catch (e: IOException) {
            abort()
            return
        }
        sendAck()
    }

    // ---- socket events ----

    fun onKey(k: SelectionKey) {
        try {
            if (k.isConnectable) {
                if (channel!!.finishConnect()) onConnected()
                return
            }
            if (k.isValid && k.isWritable) {
                flushToRemote()
            }
            if (k.isValid && k.isReadable && state == State.ESTABLISHED) {
                readRemote()
            }
            updateInterest()
        } catch (e: Exception) {
            abort()
        }
    }

    private fun flushToRemote() {
        val ch = channel ?: return
        while (toRemote.isNotEmpty()) {
            val b = toRemote.first()
            val w = ch.write(b)
            toRemoteBytes -= w
            if (b.hasRemaining()) break
            toRemote.removeFirst()
        }
        maybeShutdownOutput()
        // the game may have stopped sending because our window was small: tell it there is room
        val wnd = rcvWindow()
        if (lastAdvWnd < 2 * mss && wnd >= lastAdvWnd + mss && state == State.ESTABLISHED) sendAck()
    }

    private fun readRemote() {
        if (remoteEof) return
        val ch = channel ?: return
        val inFlight = sndNxt - sndUna
        val canSend = minOf(sndWnd - inFlight, unacked.free)
        if (canSend <= 0) return
        val buf = engine.readBuffer
        buf.clear()
        buf.limit(minOf(canSend, buf.capacity()))
        val n = ch.read(buf)
        if (n < 0) {
            remoteEof = true
            sendFin()
            checkDone()
            return
        }
        if (n == 0) return
        lastActivity = engine.now()
        if (inFlight == 0) lastSend = engine.now()
        val data = buf.array()
        var off = 0
        while (off < n) {
            val seg = minOf(mss, n - off)
            val flags = if (off + seg == n) Tcp.ACK or Tcp.PSH else Tcp.ACK
            engine.tunWrite(Packets.tcp(dstIp, dstPort, appIp, appPort, sndNxt, rcvNxt, flags, rcvWindow(), data, off, seg))
            unacked.append(data, off, seg)
            sndNxt += seg
            off += seg
        }
        lastAdvWnd = rcvWindow()
        Monitor.inbound(entry)
    }

    private fun maybeShutdownOutput() {
        if (appFin && !outShutdown && toRemote.isEmpty()) {
            outShutdown = true
            try { channel?.shutdownOutput() } catch (_: Exception) {}
        }
    }

    private fun updateInterest() {
        val k = selKey ?: return
        if (!k.isValid) return
        var ops = 0
        when (state) {
            State.CONNECTING -> ops = SelectionKey.OP_CONNECT
            State.ESTABLISHED -> {
                val inFlight = sndNxt - sndUna
                if (!remoteEof && sndWnd - inFlight > 0 && unacked.free > 0) ops = ops or SelectionKey.OP_READ
                if (toRemote.isNotEmpty()) ops = ops or SelectionKey.OP_WRITE
            }
            else -> if (toRemote.isNotEmpty()) ops = SelectionKey.OP_WRITE
        }
        if (k.interestOps() != ops) k.interestOps(ops)
    }

    // ---- timers ----

    fun tick(now: Long) {
        when (state) {
            State.CLOSED -> return
            State.CONNECTING -> if (now - created > CONNECT_TIMEOUT) abort()
            State.SYN_RCVD -> if (now - lastSend > rto) {
                if (++retries > 5) abort() else {
                    sendSynAck(); lastSend = now; rto = minOf(rto * 2, MAX_RTO)
                }
            }
            State.ESTABLISHED -> {
                if (sndNxt != sndUna && now - lastSend > rto) {
                    if (++retries > MAX_RETRIES) {
                        abort(); return
                    }
                    retransmit()
                    lastSend = now
                    rto = minOf(rto * 2, MAX_RTO)
                }
                val idle = if (appFin || remoteEof) HALF_CLOSED_TIMEOUT else IDLE_TIMEOUT
                if (now - lastActivity > idle) abort()
            }
        }
    }

    private fun retransmit() {
        val dataLen = unacked.size
        val limit = maxOf(minOf(dataLen, sndWnd), minOf(dataLen, mss))
        var off = 0
        while (off < limit) {
            val n = minOf(mss, limit - off)
            val tmp = ByteArray(n)
            unacked.copy(off, n, tmp, 0)
            engine.tunWrite(Packets.tcp(dstIp, dstPort, appIp, appPort, sndUna + off, rcvNxt, Tcp.ACK or Tcp.PSH, rcvWindow(), tmp, 0, n))
            off += n
        }
        if (finSent && !finAcked && off >= dataLen) {
            engine.tunWrite(Packets.tcp(dstIp, dstPort, appIp, appPort, sndNxt - 1, rcvNxt, Tcp.FIN or Tcp.ACK, rcvWindow()))
        }
    }

    // ---- helpers ----

    private fun rcvWindow() = maxOf(0, WINDOW - toRemoteBytes)

    private fun sendSynAck() {
        engine.tunWrite(Packets.tcp(dstIp, dstPort, appIp, appPort, isn, rcvNxt, Tcp.SYN or Tcp.ACK, rcvWindow(), mss = MSS))
    }

    private fun sendAck() {
        val w = rcvWindow()
        lastAdvWnd = w
        engine.tunWrite(Packets.tcp(dstIp, dstPort, appIp, appPort, sndNxt, rcvNxt, Tcp.ACK, w))
    }

    private fun sendFin() {
        if (finSent) return
        engine.tunWrite(Packets.tcp(dstIp, dstPort, appIp, appPort, sndNxt, rcvNxt, Tcp.FIN or Tcp.ACK, rcvWindow()))
        finSent = true
        if (sndNxt == sndUna) lastSend = engine.now()
        sndNxt += 1
    }

    private fun checkDone() {
        if (appFin && finSent && finAcked) close()
    }

    /** Re-checks the policy for a live connection (the user changed the country). */
    fun kill() = abort()

    private fun abort() {
        if (state == State.CLOSED) return
        engine.tunWrite(Packets.tcp(dstIp, dstPort, appIp, appPort, sndNxt, rcvNxt, Tcp.RST or Tcp.ACK, 0))
        close()
    }

    fun close() {
        if (state == State.CLOSED) return
        state = State.CLOSED
        try { selKey?.cancel() } catch (_: Exception) {}
        try { channel?.close() } catch (_: Exception) {}
        engine.tcpClosed(this)
    }
}
