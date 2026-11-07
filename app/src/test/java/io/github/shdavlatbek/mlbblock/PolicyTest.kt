package io.github.shdavlatbek.mlbblock

import io.github.shdavlatbek.mlbblock.net.Cidr
import io.github.shdavlatbek.mlbblock.net.FilterConfig
import io.github.shdavlatbek.mlbblock.net.Ip
import io.github.shdavlatbek.mlbblock.net.Mode
import io.github.shdavlatbek.mlbblock.net.PROTO_ICMP
import io.github.shdavlatbek.mlbblock.net.PROTO_TCP
import io.github.shdavlatbek.mlbblock.net.PROTO_UDP
import io.github.shdavlatbek.mlbblock.net.Policy
import io.github.shdavlatbek.mlbblock.net.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

class PolicyTest {
    private val de = Ip.parse("3.120.0.1")!!
    private val uz = Ip.parse("213.230.64.1")!!
    private val strictUz = FilterConfig(countries = setOf("UZ"), mode = Mode.STRICT)
    private val portsUz = FilterConfig(countries = setOf("UZ"), mode = Mode.PORTS)

    @Test
    fun foreignGameServersAreBlockedInBothModes() {
        for (cfg in listOf(strictUz, portsUz)) {
            assertEquals(Verdict.BLOCK_COUNTRY, Policy.decide(cfg, PROTO_UDP, de, 5501, "DE"))
            assertEquals(Verdict.BLOCK_COUNTRY, Policy.decide(cfg, PROTO_UDP, de, 30191, "DE"))
            // the ports the original app forgot
            assertEquals(Verdict.BLOCK_COUNTRY, Policy.decide(cfg, PROTO_UDP, de, 5003, "DE"))
            assertEquals(Verdict.BLOCK_COUNTRY, Policy.decide(cfg, PROTO_UDP, de, 10050, "DE"))
            assertEquals(Verdict.BLOCK_COUNTRY, Policy.decide(cfg, PROTO_TCP, de, 10003, "DE"))
            assertEquals(Verdict.BLOCK_COUNTRY, Policy.decide(cfg, PROTO_ICMP, de, 0, "DE"))
        }
    }

    @Test
    fun chosenCountryIsOpen() {
        assertEquals(Verdict.ALLOW_COUNTRY, Policy.decide(strictUz, PROTO_UDP, uz, 5501, "UZ"))
        assertEquals(Verdict.ALLOW_COUNTRY, Policy.decide(strictUz, PROTO_ICMP, uz, 0, "UZ"))
    }

    @Test
    fun strictBlocksUnknownUdpPortsButSoftDoesNot() {
        assertEquals(Verdict.BLOCK_COUNTRY, Policy.decide(strictUz, PROTO_UDP, de, 8001, "DE"))
        assertEquals(Verdict.ALLOW_NORMAL, Policy.decide(portsUz, PROTO_UDP, de, 8001, "DE"))
    }

    @Test
    fun lobbyAndWebAreNeverBlocked() {
        for (cfg in listOf(strictUz, portsUz)) {
            assertEquals(Verdict.ALLOW_NORMAL, Policy.decide(cfg, PROTO_TCP, de, 443, "DE"))
            assertEquals(Verdict.ALLOW_NORMAL, Policy.decide(cfg, PROTO_TCP, de, 30021, "DE"))
            assertEquals(Verdict.ALLOW_NORMAL, Policy.decide(cfg, PROTO_TCP, de, 30101, "DE"))
            assertEquals(Verdict.ALLOW_NORMAL, Policy.decide(cfg, PROTO_UDP, de, 53, "DE"))
            assertEquals(Verdict.ALLOW_NORMAL, Policy.decide(cfg, PROTO_UDP, de, 443, "DE"))
        }
    }

    @Test
    fun manualRulesWin() {
        val cfg = strictUz.copy(allow = listOf(Cidr.parse("3.120.0.0/16")!!), block = listOf(Cidr.parse("213.230.64.1")!!))
        assertEquals(Verdict.ALLOW_MANUAL, Policy.decide(cfg, PROTO_UDP, de, 5501, "DE"))
        assertEquals(Verdict.BLOCK_MANUAL, Policy.decide(cfg, PROTO_UDP, uz, 5501, "UZ"))
    }

    @Test
    fun cityFilter() {
        val ru = Ip.parse("95.46.1.1")!!
        val cfg = FilterConfig(countries = setOf("RU", "UZ"), cities = mapOf("RU" to setOf("St Petersburg")))
        assertEquals(Verdict.BLOCK_CITY, Policy.decide(cfg, PROTO_UDP, ru, 5501, "RU", "Moscow"))
        assertEquals(Verdict.BLOCK_CITY, Policy.decide(cfg, PROTO_UDP, ru, 5501, "RU", null)) // unknown city
        assertEquals(Verdict.ALLOW_COUNTRY, Policy.decide(cfg, PROTO_UDP, ru, 5501, "RU", "St Petersburg"))
        // no city chosen for UZ: the whole country is open
        assertEquals(Verdict.ALLOW_COUNTRY, Policy.decide(cfg, PROTO_UDP, uz, 5501, "UZ", "Namangan*"))
        // lobby traffic is never touched by the city filter
        assertEquals(Verdict.ALLOW_NORMAL, Policy.decide(cfg, PROTO_TCP, ru, 443, "RU", "Moscow"))
    }

    @Test
    fun noCountryMeansWatchOnly() {
        assertEquals(Verdict.ALLOW_FILTER_OFF, Policy.decide(FilterConfig(), PROTO_UDP, de, 5501, "DE"))
    }

    @Test
    fun localAddressesPass() {
        assertEquals(Verdict.ALLOW_LOCAL, Policy.decide(strictUz, PROTO_UDP, Ip.parse("192.168.1.1")!!, 5501, "--"))
    }
}
