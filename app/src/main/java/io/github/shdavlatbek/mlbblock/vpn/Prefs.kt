package io.github.shdavlatbek.mlbblock.vpn

import android.content.Context
import io.github.shdavlatbek.mlbblock.net.Cidr
import io.github.shdavlatbek.mlbblock.net.FilterConfig
import io.github.shdavlatbek.mlbblock.net.Mode

/** User settings. [current] is read by the VPN threads on every new flow. */
object Prefs {
    private const val FILE = "settings"
    private const val K_COUNTRIES = "countries"
    private const val K_MODE = "mode"
    private const val K_ALLOW = "allow"
    private const val K_BLOCK = "block"

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
            revision = 1,
        )
        loaded = true
        return current
    }

    @Synchronized
    fun update(context: Context, change: (FilterConfig) -> FilterConfig) {
        load(context)
        val next = change(current).copy(revision = current.revision + 1)
        current = next
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit()
            .putString(K_COUNTRIES, next.countries.sorted().joinToString(","))
            .putString(K_MODE, next.mode.name)
            .putString(K_ALLOW, next.allow.joinToString("\n"))
            .putString(K_BLOCK, next.block.joinToString("\n"))
            .apply()
    }

    /** Parses one IP or CIDR per line (commas and spaces also work); bad lines are skipped. */
    fun parseList(text: String): List<Cidr> =
        text.split('\n', ',', ' ', ';').mapNotNull { Cidr.parse(it) }.distinct()
}
