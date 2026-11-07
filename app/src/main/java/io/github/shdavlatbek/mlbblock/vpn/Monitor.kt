package io.github.shdavlatbek.mlbblock.vpn

import android.content.Context
import io.github.shdavlatbek.mlbblock.net.Countries
import io.github.shdavlatbek.mlbblock.net.Ip
import io.github.shdavlatbek.mlbblock.net.PROTO_ICMP
import io.github.shdavlatbek.mlbblock.net.PROTO_TCP
import io.github.shdavlatbek.mlbblock.net.PROTO_UDP
import io.github.shdavlatbek.mlbblock.net.TrafficClass
import io.github.shdavlatbek.mlbblock.net.Verdict
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** One remote address the game talked to. Counters are written by the VPN threads only. */
class ServerEntry(val ip: Int, val country: String) {
    @Volatile var cls: TrafficClass = TrafficClass.NORMAL
    @Volatile var verdict: Verdict = Verdict.ALLOW_NORMAL
    @Volatile var protoMask = 0
    val ports = java.util.TreeSet<Int>()
    @Volatile var pktOut = 0L
    @Volatile var pktIn = 0L
    @Volatile var dropped = 0L
    @Volatile var firstSeen = 0L
    @Volatile var lastSeen = 0L
    @Volatile var lastIn = 0L
    @Volatile var rttMs = -1
    @Volatile var lastEventAt = 0L
    /** Loaded from history, not seen in this session yet. */
    @Volatile var fromHistory = false

    val isGame get() = cls == TrafficClass.GAME || cls == TrafficClass.OTHER_UDP || cls == TrafficClass.ICMP

    fun protoText(): String = buildList {
        if (protoMask and 1 != 0) add("UDP")
        if (protoMask and 2 != 0) add("TCP")
        if (protoMask and 4 != 0) add("ICMP")
    }.joinToString("+")

    fun portsText(): String = synchronized(ports) {
        val list = ports.toList()
        if (list.size <= 4) list.joinToString(",") else list.take(4).joinToString(",") + "…"
    }
}

object Monitor {
    private const val MAX_ENTRIES = 600
    private const val MAX_EVENTS = 150
    private const val HISTORY_FILE = "servers.json"

    private val entries = HashMap<Int, ServerEntry>()
    private val events = ArrayDeque<String>()
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    @Volatile var blockedTotal = 0L
        private set
    @Volatile var sessionStart = 0L
        private set
    @Volatile private var dirty = false

    private fun rank(c: TrafficClass) = when (c) {
        TrafficClass.GAME -> 3
        TrafficClass.OTHER_UDP -> 2
        TrafficClass.ICMP -> 1
        TrafficClass.NORMAL -> 0
    }

    fun startSession() {
        sessionStart = System.currentTimeMillis()
        blockedTotal = 0
        synchronized(this) {
            for (e in entries.values) {
                e.pktOut = 0; e.pktIn = 0; e.dropped = 0; e.lastIn = 0; e.rttMs = -1; e.lastEventAt = 0
            }
            events.clear()
        }
    }

    /** Called once per new flow (not per packet). */
    fun flowStarted(ip: Int, country: String, proto: Int, port: Int, cls: TrafficClass, verdict: Verdict): ServerEntry {
        val now = System.currentTimeMillis()
        val e: ServerEntry
        var isNewForEvents = false
        synchronized(this) {
            e = entries.getOrPut(ip) {
                if (entries.size >= MAX_ENTRIES) trim()
                ServerEntry(ip, country).also { it.firstSeen = now }
            }
            if (e.fromHistory) e.fromHistory = false
            if (rank(cls) >= rank(e.cls)) e.cls = cls
            val oldVerdict = e.verdict
            e.verdict = verdict
            e.protoMask = e.protoMask or when (proto) {
                PROTO_UDP -> 1; PROTO_TCP -> 2; PROTO_ICMP -> 4; else -> 0
            }
            if (proto != PROTO_ICMP) synchronized(e.ports) { if (e.ports.size < 16) e.ports.add(port) }
            e.lastSeen = now
            if (cls != TrafficClass.NORMAL && (oldVerdict != verdict || e.lastEventAt == 0L || now - e.lastEventAt > 30_000)) {
                isNewForEvents = true
                e.lastEventAt = now
            }
            if (e.isGame) dirty = true
        }
        if (isNewForEvents) {
            val p = when (proto) { PROTO_UDP -> "UDP"; PROTO_TCP -> "TCP"; PROTO_ICMP -> "ICMP"; else -> "IP$proto" }
            val where = if (proto == PROTO_ICMP) Ip.str(ip) else "${Ip.str(ip)}:$port"
            val mark = if (verdict.blocked) "⛔" else "✅"
            event("$mark $p $where ${Countries.flag(country)} $country")
        }
        return e
    }

    fun out(e: ServerEntry) {
        e.pktOut++
        e.lastSeen = System.currentTimeMillis()
    }

    fun inbound(e: ServerEntry) {
        e.pktIn++
        e.lastIn = System.currentTimeMillis()
    }

    fun drop(e: ServerEntry) {
        e.dropped++
        e.lastSeen = System.currentTimeMillis()
        blockedTotal++
    }

    fun rtt(e: ServerEntry, ms: Int) {
        e.rttMs = ms
    }

    fun event(text: String) {
        val line = timeFmt.format(Date()) + "  " + text
        synchronized(events) {
            events.addFirst(line)
            while (events.size > MAX_EVENTS) events.removeLast()
        }
    }

    fun events(): List<String> = synchronized(events) { events.toList() }

    fun snapshot(): List<ServerEntry> = synchronized(this) { entries.values.toList() }

    /** The allowed game server that sent us data in the last few seconds. */
    fun currentMatch(): ServerEntry? {
        val now = System.currentTimeMillis()
        return snapshot()
            .filter { it.cls == TrafficClass.GAME && !it.verdict.blocked && now - it.lastIn < 5000 && it.pktIn > 20 }
            .maxByOrNull { it.pktIn }
    }

    fun clear(context: Context) {
        synchronized(this) { entries.clear() }
        synchronized(events) { events.clear() }
        File(context.filesDir, HISTORY_FILE).delete()
    }

    private fun trim() {
        // drop the oldest non-game entries first
        val victims = entries.values.sortedWith(compareBy<ServerEntry> { it.isGame }.thenBy { it.lastSeen }).take(100)
        for (v in victims) entries.remove(v.ip)
    }

    /** Game servers seen before, so the list is not empty after a restart. */
    fun loadHistory(context: Context) {
        val f = File(context.filesDir, HISTORY_FILE)
        if (!f.exists()) return
        try {
            val arr = JSONArray(f.readText())
            synchronized(this) {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    val ip = Ip.parse(o.getString("ip")) ?: continue
                    if (entries.containsKey(ip)) continue
                    val e = ServerEntry(ip, o.optString("cc", "--"))
                    e.cls = runCatching { TrafficClass.valueOf(o.optString("cls", "GAME")) }.getOrDefault(TrafficClass.GAME)
                    e.protoMask = o.optInt("proto", 1)
                    val ports = o.optJSONArray("ports")
                    if (ports != null) for (j in 0 until ports.length()) e.ports.add(ports.getInt(j))
                    e.firstSeen = o.optLong("first", 0)
                    e.lastSeen = o.optLong("last", 0)
                    e.fromHistory = true
                    entries[ip] = e
                }
            }
        } catch (_: Exception) {
        }
    }

    fun saveHistory(context: Context) {
        if (!dirty) return
        dirty = false
        val arr = JSONArray()
        snapshot().filter { it.isGame }.sortedByDescending { it.lastSeen }.take(300).forEach { e ->
            arr.put(JSONObject().apply {
                put("ip", Ip.str(e.ip))
                put("cc", e.country)
                put("cls", e.cls.name)
                put("proto", e.protoMask)
                put("ports", JSONArray(synchronized(e.ports) { e.ports.toList() }))
                put("first", e.firstSeen)
                put("last", e.lastSeen)
            })
        }
        try {
            val tmp = File(context.filesDir, "$HISTORY_FILE.tmp")
            tmp.writeText(arr.toString())
            tmp.renameTo(File(context.filesDir, HISTORY_FILE))
        } catch (_: Exception) {
        }
    }
}
