package io.github.shdavlatbek.mlbblock.net

/** IPv4 addresses are kept as plain Ints (network byte order, so 1.2.3.4 == 0x01020304). */
object Ip {
    fun str(ip: Int): String =
        "${ip ushr 24 and 255}.${ip ushr 16 and 255}.${ip ushr 8 and 255}.${ip and 255}"

    fun parse(text: String): Int? {
        val parts = text.trim().split('.')
        if (parts.size != 4) return null
        var ip = 0
        for (p in parts) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
            val v = p.toInt()
            if (v > 255) return null
            ip = (ip shl 8) or v
        }
        return ip
    }

    /** Parses "1.2.3.4" or "1.2.3.0/24" into (network, prefix length). */
    fun parseCidr(text: String): Pair<Int, Int>? {
        val t = text.trim()
        val slash = t.indexOf('/')
        if (slash < 0) return parse(t)?.let { it to 32 }
        val ip = parse(t.substring(0, slash)) ?: return null
        val len = t.substring(slash + 1).toIntOrNull() ?: return null
        if (len !in 0..32) return null
        return (ip and mask(len)) to len
    }

    fun mask(len: Int): Int = if (len == 0) 0 else (-1 shl (32 - len))

    fun inCidr(ip: Int, net: Int, len: Int): Boolean = (ip and mask(len)) == net

    /** Local, private, CGNAT, multicast and other non-routable ranges: never filtered. */
    fun isPrivate(ip: Int): Boolean {
        val a = ip ushr 24 and 255
        val b = ip ushr 16 and 255
        return when {
            a == 0 || a == 10 || a == 127 -> true
            a == 100 && b in 64..127 -> true
            a == 169 && b == 254 -> true
            a == 172 && b in 16..31 -> true
            a == 192 && b == 168 -> true
            a >= 224 -> true // multicast, reserved, broadcast
            else -> false
        }
    }
}
