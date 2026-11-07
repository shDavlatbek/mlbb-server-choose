package io.github.shdavlatbek.mlbblock.net

import java.io.DataInputStream
import java.io.InputStream

/**
 * IPv4 -> country lookup over the DB-IP "IP to Country Lite" table
 * (converted by tools/build_geoip.py). "--" means unknown.
 */
class GeoIp private constructor(
    /** Range starts with the sign bit flipped so signed compare == unsigned compare. */
    private val starts: IntArray,
    private val codes: ByteArray,
    val version: Int,
) {
    val size: Int get() = starts.size

    fun country(ip: Int): String {
        val key = ip xor Int.MIN_VALUE
        var lo = 0
        var hi = starts.size - 1
        while (lo < hi) {
            val mid = (lo + hi + 1) ushr 1
            if (starts[mid] <= key) lo = mid else hi = mid - 1
        }
        val c0 = codes[lo * 2].toInt().toChar()
        val c1 = codes[lo * 2 + 1].toInt().toChar()
        return if (c0 == '-') UNKNOWN else "$c0$c1"
    }

    /** All country codes present in the table, for the picker. */
    fun allCountries(): Set<String> {
        val out = HashSet<String>()
        var i = 0
        while (i < codes.size) {
            val c0 = codes[i].toInt().toChar()
            if (c0 != '-') out.add("$c0${codes[i + 1].toInt().toChar()}")
            i += 2
        }
        return out
    }

    companion object {
        const val UNKNOWN = "--"

        fun load(input: InputStream): GeoIp {
            val data = DataInputStream(input.buffered(1 shl 16))
            val magic = ByteArray(4)
            data.readFully(magic)
            require(String(magic, Charsets.US_ASCII) == "GEO4") { "bad GeoIP file" }
            val count = data.readInt()
            val version = data.readInt()
            require(count in 1..10_000_000) { "bad GeoIP size" }
            val starts = IntArray(count)
            for (i in 0 until count) starts[i] = data.readInt() xor Int.MIN_VALUE
            val codes = ByteArray(count * 2)
            data.readFully(codes)
            return GeoIp(starts, codes, version)
        }
    }
}
