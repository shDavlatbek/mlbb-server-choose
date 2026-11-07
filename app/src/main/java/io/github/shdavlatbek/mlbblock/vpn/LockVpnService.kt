package io.github.shdavlatbek.mlbblock.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import io.github.shdavlatbek.mlbblock.R
import io.github.shdavlatbek.mlbblock.net.Countries
import io.github.shdavlatbek.mlbblock.net.GeoIp
import io.github.shdavlatbek.mlbblock.net.Ip
import io.github.shdavlatbek.mlbblock.ui.MainActivity
import java.io.FileDescriptor
import java.net.DatagramSocket
import java.net.Socket

object Geo {
    @Volatile private var geo: GeoIp? = null

    fun get(context: Context): GeoIp = geo ?: synchronized(this) {
        geo ?: context.assets.open("geoip-v4.bin").use { GeoIp.load(it) }.also { geo = it }
    }
}

class LockVpnService : VpnService() {
    companion object {
        const val ACTION_START = "io.github.shdavlatbek.mlbblock.START"
        const val ACTION_STOP = "io.github.shdavlatbek.mlbblock.STOP"
        private const val CHANNEL = "filter"
        private const val NOTIFY_ID = 1
        private const val TUN_ADDRESS = "10.88.0.2"

        val GAME_PACKAGES = listOf("com.mobile.legends", "com.mobilelegends.hwag", "com.mobilelegends.mi")

        @Volatile var running = false
            private set
        @Volatile var lastError: String? = null
            private set
        @Volatile var engine: Engine? = null
            private set

        fun installedGames(context: Context): List<String> = GAME_PACKAGES.filter {
            try {
                context.packageManager.getPackageInfo(it, 0); true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }

        fun start(context: Context) {
            val i = Intent(context, LockVpnService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(i) else context.startService(i)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, LockVpnService::class.java).setAction(ACTION_STOP))
        }
    }

    private var pfd: ParcelFileDescriptor? = null
    private var tun: TunDevice? = null
    private var engineThread: Thread? = null
    private val main = Handler(Looper.getMainLooper())
    private var ticks = 0

    private val updater = object : Runnable {
        override fun run() {
            if (!running) return
            notifyStatus()
            if (++ticks % 20 == 0) Monitor.saveHistory(applicationContext)
            main.postDelayed(this, 3000)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopFilter()
            return START_NOT_STICKY
        }
        goForeground(getString(R.string.notif_starting))
        if (!running) startFilter()
        return START_STICKY
    }

    private fun startFilter() {
        try {
            Prefs.load(this)
            val geo = Geo.get(this)
            val games = installedGames(this)
            if (games.isEmpty()) throw IllegalStateException(getString(R.string.err_no_game))

            val b = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(Engine.MTU)
                .addAddress(TUN_ADDRESS, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .setBlocking(false)
                .setConfigureIntent(
                    PendingIntent.getActivity(
                        this, 0, Intent(this, MainActivity::class.java),
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                    )
                )
            for (g in games) b.addAllowedApplication(g)
            val fd = b.establish() ?: throw IllegalStateException(getString(R.string.err_no_permission))
            pfd = fd

            val service = this
            val protector = object : Protector {
                override fun protect(socket: Socket) = service.protect(socket)
                override fun protect(socket: DatagramSocket) = service.protect(socket)
                override fun protect(fd: FileDescriptor): Boolean = try {
                    ParcelFileDescriptor.dup(fd).use { service.protect(it.fd) }
                } catch (_: Exception) {
                    false
                }
            }

            lateinit var device: TunDevice
            val eng = Engine(geo, { Prefs.current }, protector, { p -> device.write(p) })
            device = TunDevice(fd) { p -> eng.submit(p) }
            eng.icmp = IcmpForwarder(protector) { p -> device.write(p) }
            tun = device
            engine = eng

            Monitor.loadHistory(this)
            Monitor.startSession()
            engineThread = Thread({ eng.run() }, "engine").apply { start() }
            device.start()

            running = true
            lastError = null
            val cfg = Prefs.current
            Monitor.event(
                if (cfg.countries.isEmpty()) getString(R.string.event_started_watch)
                else getString(R.string.event_started, cfg.countries.joinToString(", ") { Countries.label(it) })
            )
            main.post(updater)
        } catch (e: Exception) {
            lastError = e.message ?: e.toString()
            Monitor.event("⚠️ " + lastError)
            stopFilter()
        }
    }

    private fun stopFilter() {
        val wasRunning = running
        running = false
        main.removeCallbacks(updater)
        tun?.stop()
        engine?.stop()
        try { engineThread?.join(2000) } catch (_: InterruptedException) {}
        try { pfd?.close() } catch (_: Exception) {}
        tun = null
        engine = null
        engineThread = null
        pfd = null
        if (wasRunning) {
            Monitor.event(getString(R.string.event_stopped))
            Monitor.saveHistory(applicationContext)
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        stopFilter()
        super.onRevoke()
    }

    override fun onDestroy() {
        if (running) stopFilter()
        super.onDestroy()
    }

    // ---------------- notification ----------------

    private fun goForeground(text: String) {
        val n = buildNotification(text)
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFY_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(NOTIFY_ID, n)
            }
        } catch (_: Exception) {
            // The system keeps an active VPN service alive anyway; just show the notification.
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFY_ID, n)
        }
    }

    private fun notifyStatus() {
        val cfg = Prefs.current
        val allowed = if (cfg.countries.isEmpty()) getString(R.string.notif_watch)
        else cfg.countries.joinToString(", ") { Countries.label(it) }
        val match = Monitor.currentMatch()
        val text = buildString {
            append(allowed)
            append(" • ").append(getString(R.string.notif_blocked, Monitor.blockedTotal))
            if (match != null) append(" • ").append(getString(R.string.notif_match, Ip.str(match.ip), Countries.flag(match.country)))
        }
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFY_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, LockVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL)
        else @Suppress("DEPRECATION") Notification.Builder(this)
        return b.setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(null, getString(R.string.stop), stop).build())
            .build()
    }
}
