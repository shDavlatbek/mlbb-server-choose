package io.github.shdavlatbek.mlbblock.net

import java.util.Locale

object Countries {
    fun flag(cc: String): String {
        if (cc.length != 2 || cc[0] !in 'A'..'Z' || cc[1] !in 'A'..'Z') return "🌐"
        val base = 0x1F1E6
        return String(Character.toChars(base + (cc[0] - 'A'))) + String(Character.toChars(base + (cc[1] - 'A')))
    }

    fun name(cc: String, locale: Locale = Locale.getDefault()): String {
        if (cc == GeoIp.UNKNOWN) return "?"
        val n = Locale("", cc).getDisplayCountry(locale)
        return if (n.isNullOrBlank() || n == cc) cc else n
    }

    fun label(cc: String) = "${flag(cc)} ${name(cc)}"
}
