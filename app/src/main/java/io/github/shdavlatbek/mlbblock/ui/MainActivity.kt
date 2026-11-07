package io.github.shdavlatbek.mlbblock.ui

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import io.github.shdavlatbek.mlbblock.R
import io.github.shdavlatbek.mlbblock.net.Cidr
import io.github.shdavlatbek.mlbblock.net.Countries
import io.github.shdavlatbek.mlbblock.net.FilterConfig
import io.github.shdavlatbek.mlbblock.net.Ip
import io.github.shdavlatbek.mlbblock.net.Mode
import io.github.shdavlatbek.mlbblock.net.PROTO_ICMP
import io.github.shdavlatbek.mlbblock.net.PROTO_TCP
import io.github.shdavlatbek.mlbblock.net.PROTO_UDP
import io.github.shdavlatbek.mlbblock.net.Policy
import io.github.shdavlatbek.mlbblock.net.Verdict
import io.github.shdavlatbek.mlbblock.vpn.Geo
import io.github.shdavlatbek.mlbblock.vpn.LockVpnService
import io.github.shdavlatbek.mlbblock.vpn.Monitor
import io.github.shdavlatbek.mlbblock.vpn.Prefs
import io.github.shdavlatbek.mlbblock.vpn.ServerEntry
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private companion object {
        const val REQ_VPN = 1
        const val REQ_NOTIFY = 2
        const val MAX_ROWS = 80
    }

    private lateinit var countries: TextView
    private lateinit var toggle: Button
    private lateinit var status: TextView
    private lateinit var match: TextView
    private lateinit var servers: LinearLayout
    private lateinit var serversEmpty: TextView
    private lateinit var log: TextView
    private lateinit var showBtn: Button
    private lateinit var modeGroup: RadioGroup

    private var showAll = false
    private val handler = Handler(Looper.getMainLooper())
    private val rows = ArrayList<View>()
    private val dateFmt = SimpleDateFormat("dd.MM HH:mm", Locale.getDefault())

    private val refresher = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        Prefs.load(this)
        Monitor.loadHistory(this)

        countries = findViewById(R.id.countries)
        toggle = findViewById(R.id.btn_toggle)
        status = findViewById(R.id.status)
        match = findViewById(R.id.match)
        servers = findViewById(R.id.servers)
        serversEmpty = findViewById(R.id.servers_empty)
        log = findViewById(R.id.log)
        showBtn = findViewById(R.id.btn_show)
        modeGroup = findViewById(R.id.mode)

        findViewById<Button>(R.id.btn_country).setOnClickListener {
            startActivity(Intent(this, CountryActivity::class.java))
        }
        toggle.setOnClickListener { onToggle() }
        showBtn.setOnClickListener {
            showAll = !showAll
            showBtn.setText(if (showAll) R.string.show_game else R.string.show_all)
            refresh()
        }
        findViewById<Button>(R.id.btn_clear).setOnClickListener {
            Monitor.clear(this)
            refresh()
        }
        findViewById<Button>(R.id.btn_rules).setOnClickListener { showRulesDialog() }

        modeGroup.check(if (Prefs.current.mode == Mode.STRICT) R.id.mode_strict else R.id.mode_ports)
        modeGroup.setOnCheckedChangeListener { _, id ->
            val mode = if (id == R.id.mode_ports) Mode.PORTS else Mode.STRICT
            if (mode != Prefs.current.mode) changeConfig { it.copy(mode = mode) }
        }

        val version = try {
            Geo.get(this).version.toString().let { "${it.substring(0, 4)}-${it.substring(4, 6)}" }
        } catch (_: Exception) {
            "?"
        }
        findViewById<TextView>(R.id.footer).text = getString(R.string.footer, version)

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFY)
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresher)
    }

    override fun onPause() {
        handler.removeCallbacks(refresher)
        super.onPause()
    }

    // ---------------- start / stop ----------------

    private fun onToggle() {
        if (LockVpnService.running) {
            LockVpnService.stop(this)
            handler.postDelayed({ refresh() }, 300)
            return
        }
        if (LockVpnService.installedGames(this).isEmpty()) {
            AlertDialog.Builder(this).setMessage(R.string.warn_no_game).setPositiveButton(android.R.string.ok, null).show()
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            startActivityForResult(prepare, REQ_VPN)
        } else {
            startFilter()
        }
    }

    @Deprecated("framework Activity API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) startFilter()
    }

    private fun startFilter() {
        LockVpnService.start(this)
        handler.postDelayed({ refresh() }, 400)
        if (Prefs.current.countries.isNotEmpty()) Toast.makeText(this, R.string.tip_restart, Toast.LENGTH_LONG).show()
    }

    private fun changeConfig(change: (FilterConfig) -> FilterConfig) {
        Prefs.update(this, change)
        if (LockVpnService.running) Monitor.event(getString(R.string.event_rules))
        refresh()
    }

    // ---------------- UI refresh ----------------

    private fun refresh() {
        val cfg = Prefs.current
        countries.text = if (cfg.countries.isEmpty()) getString(R.string.no_country)
        else cfg.countries.sortedBy { Countries.name(it) }.joinToString("\n") { Countries.label(it) }
        countries.textSize = if (cfg.countries.isEmpty()) 15f else 20f

        val running = LockVpnService.running
        toggle.setText(if (running) R.string.stop else R.string.start)
        toggle.setBackgroundResource(if (running) R.drawable.btn_stop else R.drawable.btn_filled)

        val sb = StringBuilder()
        if (running) {
            sb.append(getString(if (cfg.countries.isEmpty()) R.string.status_watch else R.string.status_on))
            sb.append('\n').append(getString(R.string.status_blocked, Monitor.blockedTotal))
            LockVpnService.engine?.let { sb.append('\n').append(getString(R.string.status_flows, it.udpCount, it.tcpCount)) }
        } else {
            sb.append(getString(R.string.status_off))
            LockVpnService.lastError?.let { sb.append('\n').append(getString(R.string.error_prefix, it)) }
        }
        status.text = sb

        val m = if (running) Monitor.currentMatch() else null
        match.text = if (m != null) getString(R.string.match_now, Ip.str(m.ip), Countries.label(m.country))
        else if (running) getString(R.string.match_none) else ""

        renderServers(cfg)

        val ev = Monitor.events()
        log.text = if (ev.isEmpty()) getString(R.string.log_empty) else ev.take(40).joinToString("\n")
    }

    private fun displayVerdict(cfg: FilterConfig, e: ServerEntry): Verdict {
        val proto = when {
            e.protoMask and 1 != 0 -> PROTO_UDP
            e.protoMask and 2 != 0 -> PROTO_TCP
            else -> PROTO_ICMP
        }
        val ports = synchronized(e.ports) { e.ports.toList() }
        val port = when (proto) {
            PROTO_UDP -> ports.firstOrNull { Policy.isGameUdpPort(it) } ?: ports.firstOrNull() ?: 0
            PROTO_TCP -> ports.firstOrNull { Policy.isGameTcpPort(it) } ?: ports.firstOrNull() ?: 0
            else -> 0
        }
        return Policy.decide(cfg, proto, e.ip, port, e.country)
    }

    private fun renderServers(cfg: FilterConfig) {
        val list = Monitor.snapshot()
            .filter { showAll || it.isGame }
            .sortedWith(compareBy<ServerEntry> { it.fromHistory }.thenByDescending { it.lastSeen })
            .take(MAX_ROWS)
        serversEmpty.visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
        while (rows.size < list.size) {
            val v = LayoutInflater.from(this).inflate(R.layout.item_server, servers, false)
            servers.addView(v)
            rows.add(v)
        }
        for (i in rows.indices) rows[i].visibility = if (i < list.size) View.VISIBLE else View.GONE
        for ((i, e) in list.withIndex()) bindRow(rows[i], e, displayVerdict(cfg, e))
    }

    private fun bindRow(v: View, e: ServerEntry, verdict: Verdict) {
        v.findViewById<TextView>(R.id.flag).text = Countries.flag(e.country)
        v.findViewById<TextView>(R.id.line1).text = "${Ip.str(e.ip)}  ·  ${Countries.name(e.country)}"
        val parts = ArrayList<String>()
        val ports = e.portsText()
        parts.add(e.protoText() + if (ports.isNotEmpty()) " $ports" else "")
        if (e.fromHistory) {
            parts.add(getString(R.string.seen_before, dateFmt.format(Date(e.lastSeen))))
        } else {
            parts.add("↑${e.pktOut} ↓${e.pktIn}")
            if (e.dropped > 0) parts.add("⛔ ${e.dropped}")
            if (e.rttMs >= 0) parts.add(getString(R.string.ping_ms, e.rttMs))
        }
        v.findViewById<TextView>(R.id.line2).text = parts.joinToString("  ·  ")

        val chip = v.findViewById<TextView>(R.id.verdict)
        val (text, color) = when (verdict) {
            Verdict.BLOCK_COUNTRY, Verdict.BLOCK_MANUAL -> R.string.v_blocked to R.color.bad
            Verdict.ALLOW_COUNTRY -> R.string.v_open to R.color.ok
            Verdict.ALLOW_MANUAL -> R.string.v_manual to R.color.ok
            Verdict.ALLOW_NORMAL, Verdict.ALLOW_LOCAL -> R.string.v_normal to R.color.neutral
            Verdict.ALLOW_FILTER_OFF -> R.string.v_watch to R.color.neutral
        }
        chip.setText(text)
        chip.setTextColor(getColor(color))
        v.setOnClickListener { showServerDialog(e) }
    }

    // ---------------- dialogs ----------------

    private fun showServerDialog(e: ServerEntry) {
        val ip = Ip.str(e.ip)
        val single = Cidr(e.ip, 32)
        val cfg = Prefs.current
        val items = ArrayList<Pair<String, () -> Unit>>()
        items.add(getString(R.string.server_allow) to {
            changeConfig { c -> c.copy(allow = (c.allow + single).distinct(), block = c.block - single) }
        })
        items.add(getString(R.string.server_block) to {
            changeConfig { c -> c.copy(block = (c.block + single).distinct(), allow = c.allow - single) }
        })
        if (e.country.length == 2 && e.country !in cfg.countries && e.country != "--") {
            items.add(getString(R.string.server_allow_country, Countries.label(e.country)) to {
                changeConfig { c -> c.copy(countries = c.countries + e.country) }
            })
        }
        if (single in cfg.allow || single in cfg.block) {
            items.add(getString(R.string.server_unrule) to {
                changeConfig { c -> c.copy(allow = c.allow - single, block = c.block - single) }
            })
        }
        items.add(getString(R.string.server_copy) to {
            (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("ip", ip))
            Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show()
        })
        AlertDialog.Builder(this)
            .setTitle("${Countries.flag(e.country)} $ip")
            .setItems(items.map { it.first }.toTypedArray()) { _, which -> items[which].second() }
            .show()
    }

    private fun showRulesDialog() {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_rules, null)
        val allow = view.findViewById<EditText>(R.id.allow)
        val block = view.findViewById<EditText>(R.id.block)
        val cfg = Prefs.current
        allow.setText(cfg.allow.joinToString("\n"))
        block.setText(cfg.block.joinToString("\n"))
        AlertDialog.Builder(this)
            .setTitle(R.string.rules_title)
            .setView(view)
            .setPositiveButton(R.string.save) { _, _ ->
                changeConfig { c ->
                    c.copy(allow = Prefs.parseList(allow.text.toString()), block = Prefs.parseList(block.text.toString()))
                }
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }
}
