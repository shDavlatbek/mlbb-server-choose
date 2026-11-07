package io.github.shdavlatbek.mlbblock.vpn

import android.content.Context
import io.github.shdavlatbek.mlbblock.net.Cidr
import io.github.shdavlatbek.mlbblock.net.FilterConfig
import io.github.shdavlatbek.mlbblock.net.Mode
import org.json.JSONArray
import org.json.JSONObject

/** User settings. [current] is read by the VPN threads on every new flow. */
object Prefs {
    private const val FILE = "settings"
    private const val K_COUNTRIES = "countries"
    private const val K_MODE = "mode"
    private const val K_ALLOW = "allow"
    private const val K_BLOCK = "block"
    private const val K_CITIES = "cities"

    @Volatile var current: FilterConfig = FilterConfig()
        private set
    private var loaded = false

    @Synchronized
    fun load(context: Context): FilterConfig {
        if (loaded) return current
        val sp = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        current = FilterConfig(
            countries = sp.getString(K_COUNTRIES, "")!!.split(',').filter { it.length == 2 }.toSet(),
            mode = runCatching { Mode.valueOf(sp.getString(K_MODE, Mode.STRICT.name)!!) }.getOrDefault(Mode.STRICT),
            allow = parseList(sp.getString(K_ALLOW, "")!!),
            block = parseList(sp.getString(K_BLOCK, "")!!),
            cities = parseCities(sp.getString(K_CITIES, "")!!),
            revision = 1,
        )
        loaded = true
        return current
    }

    @Synchronized
    fun update(context: Context, change: (FilterConfig) -> FilterConfig) {
        load(context)
        val changed = change(current)
        // forget city choices of countries that are no longer selected
        val next = changed.copy(
            cities = changed.cities.filter { (cc, set) -> cc in changed.countries && set.isNotEmpty() },
            revision = current.revision + 1,
        )
        current = next
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit()
            .putString(K_COUNTRIES, next.countries.sorted().joinToString(","))
            .putString(K_MODE, next.mode.name)
            .putString(K_ALLOW, next.allow.joinToString("\n"))
            .putString(K_BLOCK, next.block.joinToString("\n"))
            .putString(K_CITIES, citiesJson(next.cities))
            .apply()
    }

    private fun citiesJson(cities: Map<String, Set<String>>): String {
        val o = JSONObject()
        for ((cc, set) in cities) o.put(cc, JSONArray(set.sorted()))
        return o.toString()
    }

    private fun parseCities(text: String): Map<String, Set<String>> {
        if (text.isBlank()) return emptyMap()
        return try {
            val o = JSONObject(text)
            o.keys().asSequence().associateWith { cc ->
                val a = o.getJSONArray(cc)
                (0 until a.length()).map { a.getString(it) }.toSet()
            }.filterValues { it.isNotEmpty() }
        } catch (_: Exception) {
            emptyMap()
        }
    }

    /** Parses one IP or CIDR per line (commas and spaces also work); bad lines are skipped. */
    fun parseList(text: String): List<Cidr> =
        text.split('\n', ',', ' ', ';').mapNotNull { Cidr.parse(it) }.distinct()
}
