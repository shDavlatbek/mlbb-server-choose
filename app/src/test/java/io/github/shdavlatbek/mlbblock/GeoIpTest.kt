package io.github.shdavlatbek.mlbblock

import io.github.shdavlatbek.mlbblock.net.GeoIp
import io.github.shdavlatbek.mlbblock.net.Ip
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class GeoIpTest {
    private val geo = File("src/main/assets/geoip-v4.bin").inputStream().use { GeoIp.load(it) }

    private fun cc(ip: String) = geo.country(Ip.parse(ip)!!)

    @Test
    fun knownAddresses() {
        // expected values taken from the source CSV
        assertEquals("US", cc("8.8.8.8"))
        assertEquals("RU", cc("77.88.8.8"))
        assertEquals("UZ", cc("213.230.64.1"))
        assertEquals("UZ", cc("84.54.64.1"))
        assertEquals("UZ", cc("195.158.1.1"))
        assertEquals("UZ", cc("217.12.80.1"))
        assertEquals("AU", cc("1.0.0.1"))
        assertEquals("RU", cc("5.255.255.255"))
    }

    @Test
    fun edgesAreUnknown() {
        assertEquals(GeoIp.UNKNOWN, cc("0.0.0.1"))
        assertEquals(GeoIp.UNKNOWN, cc("255.255.255.255"))
    }

    @Test
    fun highAddressesUseUnsignedOrder() {
        // 200.x and 213.x are negative as Ints; lookups must still work
        assertEquals("UZ", cc("213.230.64.1"))
        assertTrue(geo.allCountries().containsAll(listOf("UZ", "KZ", "RU", "DE", "SG", "ID", "PH", "TR")))
    }
}
