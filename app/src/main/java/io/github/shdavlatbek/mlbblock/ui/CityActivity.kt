package io.github.shdavlatbek.mlbblock.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import io.github.shdavlatbek.mlbblock.R
import io.github.shdavlatbek.mlbblock.net.Countries
import io.github.shdavlatbek.mlbblock.net.GeoCity
import io.github.shdavlatbek.mlbblock.vpn.GeoStore
import io.github.shdavlatbek.mlbblock.vpn.LockVpnService
import io.github.shdavlatbek.mlbblock.vpn.Monitor
import io.github.shdavlatbek.mlbblock.vpn.Pinger
import io.github.shdavlatbek.mlbblock.vpn.Prefs
import java.text.Collator

/** Pick the cities of one country whose servers stay open (none = whole country). */
class CityActivity : Activity() {
    companion object {
        private const val EXTRA_COUNTRY = "country"

        fun open(context: Context, country: String) {
            context.startActivity(Intent(context, CityActivity::class.java).putExtra(EXTRA_COUNTRY, country))
        }

        fun label(context: Context, city: String): String =
            if (GeoCity.isRegion(city)) context.getString(R.string.city_region, GeoCity.displayName(city))
            else GeoCity.displayName(city)
    }

    private class Item(val key: String, val name: String, val seen: Int, val ping: Int)

    private lateinit var country: String
    private val selected = HashSet<String>()
    private var all: List<Item> = emptyList()
    private var shown: List<Item> = emptyList()
    private var query = ""
    private lateinit var adapter: Adapter
    private lateinit var hint: TextView
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_country)
        country = intent.getStringExtra(EXTRA_COUNTRY) ?: run { finish(); return }
        Prefs.load(this)
        selected.addAll(Prefs.current.cities[country].orEmpty())

        findViewById<TextView>(R.id.title).text = getString(R.string.city_title, Countries.label(country))
        hint = findViewById(R.id.hint)
        hint.visibility = View.VISIBLE
        hint.setText(R.string.city_loading)

        val list = findViewById<ListView>(R.id.list)
        adapter = Adapter()
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ ->
            val key = shown[pos].key
            if (!selected.remove(key)) selected.add(key)
            adapter.notifyDataSetChanged()
        }

        val search = findViewById<EditText>(R.id.search)
        search.setHint(R.string.search_city_hint)
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                query = s?.toString()?.trim()?.lowercase() ?: ""
                applyFilter()
            }
        })

        findViewById<Button>(R.id.btn_reset).apply {
            setText(R.string.whole_country)
            setOnClickListener {
                selected.clear()
                adapter.notifyDataSetChanged()
            }
        }
        findViewById<Button>(R.id.btn_done).setOnClickListener {
            val chosen = selected.toSet()
            if (chosen != Prefs.current.cities[country].orEmpty()) {
                Prefs.update(this) { it.copy(cities = it.cities + (country to chosen)) }
                if (LockVpnService.running) Monitor.event(getString(R.string.event_rules))
            }
            finish()
        }

        // the city table may need unpacking the first time: do it off the main thread
        val app = applicationContext
        Thread({
            val db = GeoStore.cities(app)
            handler.post { if (!isFinishing) build(db) }
        }, "city-load").start()
    }

    private fun build(db: GeoCity?) {
        if (db == null) {
            hint.text = getString(R.string.city_error, GeoStore.cityError ?: "?")
            return
        }
        hint.setText(R.string.city_hint)
        val game = Monitor.snapshot().filter { it.isGame && it.country == country && it.city != null }
        Pinger.pingAll(game)
        val seen = game.groupBy { it.city!! }
        val keys = LinkedHashSet<String>()
        keys.addAll(seen.keys)
        keys.addAll(selected)
        keys.addAll(db.citiesOf(country))
        val collator = Collator.getInstance()
        all = keys.map { k ->
            val entries = seen[k].orEmpty()
            Item(k, label(this, k), entries.size, entries.map { it.latency }.filter { it >= 0 }.minOrNull() ?: -1)
        }.sortedWith { a, b ->
            when {
                (a.seen > 0) != (b.seen > 0) -> if (a.seen > 0) -1 else 1
                a.seen > 0 && a.ping != b.ping -> when {
                    a.ping < 0 -> 1
                    b.ping < 0 -> -1
                    else -> a.ping - b.ping
                }
                GeoCity.isRegion(a.key) != GeoCity.isRegion(b.key) -> if (GeoCity.isRegion(a.key)) 1 else -1
                else -> collator.compare(a.name, b.name)
            }
        }
        applyFilter()
    }

    private fun applyFilter() {
        shown = if (query.isEmpty()) all else all.filter { it.name.lowercase().contains(query) }
        adapter.notifyDataSetChanged()
    }

    private inner class Adapter : BaseAdapter() {
        override fun getCount() = shown.size
        override fun getItem(position: Int) = shown[position]
        override fun getItemId(position: Int) = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val v = convertView ?: LayoutInflater.from(parent.context).inflate(R.layout.item_country, parent, false)
            val item = shown[position]
            v.findViewById<TextView>(R.id.flag).text = if (item.seen > 0) "🎮" else "📍"
            v.findViewById<TextView>(R.id.name).text = item.name
            val note = v.findViewById<TextView>(R.id.note)
            if (item.seen > 0) {
                note.visibility = View.VISIBLE
                note.text = if (item.ping >= 0) getString(R.string.seen_ping, item.seen, item.ping)
                else getString(R.string.seen_in_game, item.seen)
            } else {
                note.visibility = View.GONE
            }
            v.findViewById<CheckBox>(R.id.check).isChecked = item.key in selected
            return v
        }
    }
}
