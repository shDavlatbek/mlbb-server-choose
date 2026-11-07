package io.github.shdavlatbek.mlbblock.net

import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * IPv4 -> city over DB-IP "IP to City Lite" (built by tools/build_geocity.py).
 * The asset is unpacked once into a fixed-width file and memory-mapped, so it costs no heap.
 * City keys look like "Moscow"; small towns are merged into their region: "Namangan*".
 */
class GeoCity private constructor(
    private val names: Array<String>,
    private val map: ByteBuffer,
    private val count: Int,
    val version: Int,
) {
    private val idsBase = HEADER + count * 4

    /** "CC|City" for the address, or null when unknown. */
    fun lookup(ip: Int): String? {
        val key = ip xor Int.MIN_VALUE
        var lo = 0
        var hi = count - 1
        while (lo < hi) {
            val mid = (lo + hi + 1) ushr 1
            if ((map.getInt(HEADER + mid * 4) xor Int.MIN_VALUE) <= key) lo = mid else hi = mid - 1
        }
        val id = map.getShort(idsBase + lo * 2).toInt() and 0xFFFF
        if (id == 0 || id >= names.size) return null
        return names[id]
    }

    /** City of [ip] if the city data agrees that it is in [country]. */
    fun city(ip: Int, country: String): String? {
        val k = lookup(ip) ?: return null
        return if (k.length > 3 && k[2] == '|' && k.startsWith(country)) k.substring(3) else null
    }

    /** Every city / region key known for a country. */
    fun citiesOf(country: String): List<String> =
        names.filter { it.length > 3 && it[2] == '|' && it.startsWith(country) }.map { it.substring(3) }

    companion object {
        private const val HEADER = 16

        fun isRegion(city: String) = city.endsWith("*")
        fun displayName(city: String) = city.removeSuffix("*")

        /**
         * Opens the city table, unpacking [asset] into [dir] the first time
         * (or when the bundled version changes).
         */
        fun open(asset: () -> InputStream, dir: File): GeoCity {
            asset().use { raw ->
                val input = DataInputStream(raw.buffered(1 shl 16))
                val magic = ByteArray(4)
                input.readFully(magic)
                require(String(magic, Charsets.US_ASCII) == "CTY1") { "bad city file" }
                val count = input.readInt()
                val version = input.readInt()
                val nameCount = input.readInt()
                val namesLen = input.readInt()
                require(count in 1..20_000_000 && nameCount in 1..65535 && namesLen in 1..50_000_000) { "bad city header" }
                val blob = ByteArray(namesLen)
                input.readFully(blob)
                val names = String(blob, Charsets.UTF_8).split('\n').toTypedArray()
                require(names.size == nameCount) { "bad city names" }

                val file = File(dir, "geocity-$version.dat")
                val size = HEADER + count.toLong() * 6
                if (!file.exists() || file.length() != size) {
                    dir.mkdirs()
                    dir.listFiles()?.filter { it.name.startsWith("geocity-") }?.forEach { it.delete() }
                    val tmp = File(dir, "geocity-$version.tmp")
                    DataOutputStream(BufferedOutputStream(tmp.outputStream(), 1 shl 16)).use { out ->
                        out.write("CTYX".toByteArray(Charsets.US_ASCII))
                        out.writeInt(count)
                        out.writeInt(version)
                        out.writeInt(0)
                        var prev = 0L
                        for (i in 0 until count) {
                            var shift = 0
                            var delta = 0L
                            while (true) {
                                val b = input.readUnsignedByte()
                                delta = delta or ((b and 0x7F).toLong() shl shift)
                                if (b and 0x80 == 0) break
                                shift += 7
                            }
                            prev += delta
                            out.writeInt(prev.toInt())
                        }
                        val ids = ByteArray(count * 2)
                        input.readFully(ids)
                        out.write(ids)
                    }
                    require(tmp.renameTo(file)) { "cannot write city table" }
                }
                val map = RandomAccessFile(file, "r").use { f ->
                    f.channel.map(FileChannel.MapMode.READ_ONLY, 0, size)
                }
                return GeoCity(names, map, count, version)
            }
        }
    }
}

/** What the filter needs to know about an address. */
interface GeoLookup {
    fun country(ip: Int): String
    /** City inside [country], or null when unknown. */
    fun city(ip: Int, country: String): String?
}

class Geo(private val countries: GeoIp, private val cities: () -> GeoCity?) : GeoLookup {
    override fun country(ip: Int) = countries.country(ip)
    override fun city(ip: Int, country: String) = cities()?.city(ip, country)
}
