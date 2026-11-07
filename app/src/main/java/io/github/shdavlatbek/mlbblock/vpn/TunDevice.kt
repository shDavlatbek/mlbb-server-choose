package io.github.shdavlatbek.mlbblock.vpn

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd

/** Reads packets from the (non-blocking) TUN file descriptor and writes replies back. */
class TunDevice(pfd: ParcelFileDescriptor, private val sink: (ByteArray) -> Unit) {
    private val fd = pfd.fileDescriptor
    @Volatile private var running = true
    private val reader = Thread({ readLoop() }, "tun-reader")
    private val writeLock = Any()

    fun start() = reader.start()

    fun stop() {
        running = false
        try { reader.join(1500) } catch (_: InterruptedException) {}
    }

    private fun readLoop() {
        val buf = ByteArray(32768)
        val pfds = arrayOf(StructPollfd().apply {
            fd = this@TunDevice.fd
            events = OsConstants.POLLIN.toShort()
        })
        val bad = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
        while (running) {
            try {
                pfds[0].revents = 0
                if (Os.poll(pfds, 500) <= 0) continue
                if (pfds[0].revents.toInt() and bad != 0) break
                while (running) {
                    val n = try {
                        Os.read(fd, buf, 0, buf.size)
                    } catch (e: ErrnoException) {
                        if (e.errno == OsConstants.EAGAIN) break else throw e
                    }
                    if (n <= 0) break
                    sink(buf.copyOf(n))
                }
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EINTR) continue
                break
            } catch (_: Exception) {
                break
            }
        }
    }

    fun write(packet: ByteArray) {
        synchronized(writeLock) {
            var tries = 0
            while (running) {
                try {
                    Os.write(fd, packet, 0, packet.size)
                    return
                } catch (e: ErrnoException) {
                    if (e.errno != OsConstants.EAGAIN || ++tries > 50) return
                    try { Thread.sleep(1) } catch (_: InterruptedException) { return }
                } catch (_: Exception) {
                    return
                }
            }
        }
    }
}
