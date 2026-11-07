package io.github.shdavlatbek.mlbblock.net

const val PROTO_ICMP = 1
const val PROTO_TCP = 6
const val PROTO_UDP = 17

/**
 * STRICT: every UDP flow (except DNS/NTP/QUIC-like service ports), every ICMP ping and every
 *         TCP flow on game ports must go to an allowed country.
 * PORTS:  only known Mobile Legends battle/probe ports (+ ICMP) are checked.
 */
enum class Mode { STRICT, PORTS }

enum class TrafficClass {
    /** Known MLBB battle / probe / match ports. */
    GAME,
    /** Some other UDP port: checked only in STRICT mode. */
    OTHER_UDP,
    /** Echo requests: the game uses them to measure server ping. */
    ICMP,
    /** Lobby, login, CDN, DNS, HTTPS: never blocked, otherwise the game cannot log in. */
    NORMAL,
}

enum class Verdict(val blocked: Boolean) {
    ALLOW_COUNTRY(false),
    ALLOW_MANUAL(false),
    ALLOW_NORMAL(false),
    ALLOW_LOCAL(false),
    ALLOW_FILTER_OFF(false),
    BLOCK_COUNTRY(true),
    BLOCK_CITY(true),
    BLOCK_MANUAL(true),
}

data class Cidr(val net: Int, val len: Int) {
    fun contains(ip: Int) = Ip.inCidr(ip, net, len)
    override fun toString() = if (len == 32) Ip.str(net) else "${Ip.str(net)}/$len"

    companion object {
        fun parse(text: String): Cidr? = Ip.parseCidr(text)?.let { Cidr(it.first, it.second) }
    }
}

data class FilterConfig(
    val countries: Set<String> = emptySet(),
    /** Optional city filter per country (keys from [GeoCity]); missing or empty = whole country. */
    val cities: Map<String, Set<String>> = emptyMap(),
    val mode: Mode = Mode.STRICT,
    val allow: List<Cidr> = emptyList(),
    val block: List<Cidr> = emptyList(),
    /** Bumped on every change so live flows can be re-checked. */
    val revision: Int = 0,
)

object Policy {
    /** UDP ports that are never treated as game traffic. */
    private val SERVICE_UDP = setOf(53, 67, 68, 123, 137, 138, 443, 853, 1900, 3478, 3479, 5349, 5353)

    fun isGameUdpPort(port: Int) = port in 5000..5999 || port in 10000..10199 || port in 30000..30300

    /** TCP game ports. Lobby ports (30021, 30071, 30101, 30102, 30220) are deliberately not here. */
    fun isGameTcpPort(port: Int) = port in 5000..5999 || port in 10000..10199 || port in 30190..30199

    fun classify(proto: Int, port: Int): TrafficClass = when (proto) {
        PROTO_UDP -> when {
            port in SERVICE_UDP -> TrafficClass.NORMAL
            isGameUdpPort(port) -> TrafficClass.GAME
            else -> TrafficClass.OTHER_UDP
        }
        PROTO_TCP -> if (isGameTcpPort(port)) TrafficClass.GAME else TrafficClass.NORMAL
        PROTO_ICMP -> TrafficClass.ICMP
        else -> TrafficClass.NORMAL
    }

    fun decide(cfg: FilterConfig, proto: Int, ip: Int, port: Int, country: String, city: String? = null): Verdict {
        if (cfg.block.any { it.contains(ip) }) return Verdict.BLOCK_MANUAL
        if (Ip.isPrivate(ip)) return Verdict.ALLOW_LOCAL
        if (cfg.allow.any { it.contains(ip) }) return Verdict.ALLOW_MANUAL
        val cls = classify(proto, port)
        if (cls == TrafficClass.NORMAL) return Verdict.ALLOW_NORMAL
        if (cls == TrafficClass.OTHER_UDP && cfg.mode == Mode.PORTS) return Verdict.ALLOW_NORMAL
        if (cfg.countries.isEmpty()) return Verdict.ALLOW_FILTER_OFF
        if (country !in cfg.countries) return Verdict.BLOCK_COUNTRY
        val wanted = cfg.cities[country]
        if (!wanted.isNullOrEmpty() && (city == null || city !in wanted)) return Verdict.BLOCK_CITY
        return Verdict.ALLOW_COUNTRY
    }
}
