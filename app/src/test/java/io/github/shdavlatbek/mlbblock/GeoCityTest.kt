package io.github.shdavlatbek.mlbblock

import io.github.shdavlatbek.mlbblock.net.GeoCity
import io.github.shdavlatbek.mlbblock.net.Ip
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class GeoCityTest {
    companion object {
        /** Unpacked once per test run, shared by the other tests too. */
        val db: GeoCity by lazy {
            val dir = Files.createTempDirectory("geocity").toFile().apply { deleteOnExit() }
            GeoCity.open({ File("src/main/assets/geocity-v4.bin").inputStream() }, dir)
        }
    }

    private fun lookup(ip: String) = db.lookup(Ip.parse(ip)!!)

    @Test
    fun knownCities() {
        // expected values cross-checked against the source CSV
        assertEquals("UZ|Tashkent", lookup("213.230.64.1"))
        assertEquals("RU|St Petersburg", lookup("2.16.21.1"))
        assertEquals("RU|Moscow", lookup("95.46.1.1"))
        assertEquals("RU|Moscow", lookup("77.88.8.8")) // "Moscow (Tsentralnyy ...)" is folded into Moscow
        assertEquals("RU|Samara", lookup("37.29.16.1"))
        assertEquals("US|Mountain View", lookup("8.8.8.8"))
        assertNull(lookup("0.0.0.1"))
        assertNull(lookup("255.255.255.254"))
    }

    @Test
    fun cityIsOnlyGivenForTheMatchingCountry() {
        assertEquals("Moscow", db.city(Ip.parse("95.46.1.1")!!, "RU"))
        assertNull(db.city(Ip.parse("95.46.1.1")!!, "KZ"))
    }

    @Test
    fun citiesOfCountry() {
        val ru = db.citiesOf("RU")
        assertTrue(ru.containsAll(listOf("Moscow", "St Petersburg", "Novosibirsk", "Yekaterinburg")))
        assertTrue(db.citiesOf("UZ").contains("Tashkent"))
        assertTrue(ru.any { GeoCity.isRegion(it) })
    }

    @Test
    fun reopenUsesUnpackedFile() {
        val dir = Files.createTempDirectory("geocity2").toFile()
        val first = GeoCity.open({ File("src/main/assets/geocity-v4.bin").inputStream() }, dir)
        val files = dir.listFiles()!!.map { it.name }
        assertEquals(listOf("geocity-${first.version}.dat"), files)
        val again = GeoCity.open({ File("src/main/assets/geocity-v4.bin").inputStream() }, dir)
        assertEquals("UZ|Tashkent", again.lookup(Ip.parse("213.230.64.1")!!))
        dir.deleteRecursively()
    }
}
