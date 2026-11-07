package io.github.shdavlatbek.mlbblock.vpn

import android.content.Context
import io.github.shdavlatbek.mlbblock.net.Geo
import io.github.shdavlatbek.mlbblock.net.GeoCity
import io.github.shdavlatbek.mlbblock.net.GeoIp

/** Lazily loaded country and city tables, shared by the UI and the VPN service. */
object GeoStore {
    @Volatile private var countries: GeoIp? = null
    @Volatile private var cities: GeoCity? = null
    @Volatile var cityError: String? = null
        private set

    fun countries(context: Context): GeoIp = countries ?: synchronized(this) {
        countries ?: context.assets.open("geoip-v4.bin").use { GeoIp.load(it) }.also { countries = it }
    }

    /** Blocking: the first call unpacks the city table (a second or two), later calls are instant. */
    fun cities(context: Context): GeoCity? = cities ?: synchronized(this) {
        cities ?: try {
            val app = context.applicationContext
            GeoCity.open({ app.assets.open("geocity-v4.bin") }, app.noBackupFilesDir).also {
                cities = it
                cityError = null
                Monitor.fillCities { e -> it.city(e.ip, e.country) }
            }
        } catch (e: Exception) {
            cityError = e.message ?: e.toString()
            null
        }
    }

    fun citiesIfReady(): GeoCity? = cities

    fun lookup(context: Context): Geo {
        val c = countries(context)
        return Geo(c) { cities }
    }

    fun warmUp(context: Context) {
        if (cities != null) return
        val app = context.applicationContext
        Thread({ cities(app) }, "geo-warmup").apply { isDaemon = true; start() }
    }
}
