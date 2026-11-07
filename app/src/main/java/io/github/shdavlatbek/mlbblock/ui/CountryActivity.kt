package io.github.shdavlatbek.mlbblock.ui

import android.app.Activity
import android.os.Bundle
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
import io.github.shdavlatbek.mlbblock.vpn.Geo
import io.github.shdavlatbek.mlbblock.vpn.LockVpnService
import io.github.shdavlatbek.mlbblock.vpn.Monitor
import io.github.shdavlatbek.mlbblock.vpn.Prefs
import java.text.Collator
import java.util.Locale

/** Pick one (or several) countries whose game servers stay open. */
class CountryActivity : Activity() {
    private class Item(val code: String, val name: String, val seen: Int)

    private val selected = HashSet<String>()
    private var all: List<Item> = emptyList()
    private var shown: List<Item> = emptyList()
    private lateinit var adapter: Adapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_country)
        Prefs.load(this)
        selected.addAll(Prefs.current.countries)

        // how many game servers we have seen per country: those go first
        val seen = Monitor.snapshot().filter { it.isGame }.groupingBy { it.country }.eachCount()
        val codes = HashSet<String>()
        codes.addAll(Locale.getISOCountries())
        try { codes.addAll(Geo.get(this).allCountries()) } catch (_: Exception) {}
        val collator = Collator.getInstance()
        all = codes.filter { it.length == 2 }
            .map { Item(it, Countries.name(it), seen[it] ?: 0) }
            .sortedWith { a, b ->
                when {
                    (a.seen > 0) != (b.seen > 0) -> if (a.seen > 0) -1 else 1
                    a.seen != b.seen -> b.seen - a.seen
                    else -> collator.compare(a.name, b.name)
                }
            }
        shown = all

        val list = findViewById<ListView>(R.id.list)
        adapter = Adapter()
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ ->
            val code = shown[pos].code
            if (!selected.remove(code)) selected.add(code)
            adapter.notifyDataSetChanged()
        }

        findViewById<EditText>(R.id.search).addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val q = s?.toString()?.trim()?.lowercase() ?: ""
                shown = if (q.isEmpty()) all else all.filter {
                    it.name.lowercase().contains(q) || it.code.lowercase() == q ||
                        Countries.name(it.code, Locale.ENGLISH).lowercase().contains(q)
                }
                adapter.notifyDataSetChanged()
            }
        })

        findViewById<Button>(R.id.btn_reset).setOnClickListener {
            selected.clear()
            adapter.notifyDataSetChanged()
        }
        findViewById<Button>(R.id.btn_done).setOnClickListener {
            val chosen = selected.toSet()
            if (chosen != Prefs.current.countries) {
                Prefs.update(this) { it.copy(countries = chosen) }
                if (LockVpnService.running) Monitor.event(getString(R.string.event_rules))
            }
            finish()
        }
    }

    private inner class Adapter : BaseAdapter() {
        override fun getCount() = shown.size
        override fun getItem(position: Int) = shown[position]
        override fun getItemId(position: Int) = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val v = convertView ?: LayoutInflater.from(parent.context).inflate(R.layout.item_country, parent, false)
            val item = shown[position]
            v.findViewById<TextView>(R.id.flag).text = Countries.flag(item.code)
            v.findViewById<TextView>(R.id.name).text = item.name
            val note = v.findViewById<TextView>(R.id.note)
            if (item.seen > 0) {
                note.visibility = View.VISIBLE
                note.text = getString(R.string.seen_in_game, item.seen)
            } else {
                note.visibility = View.GONE
            }
            v.findViewById<CheckBox>(R.id.check).isChecked = item.code in selected
            return v
        }
    }
}
