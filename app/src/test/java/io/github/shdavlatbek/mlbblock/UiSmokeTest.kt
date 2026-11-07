package io.github.shdavlatbek.mlbblock

import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import android.widget.ListView
import android.widget.TextView
import io.github.shdavlatbek.mlbblock.net.Ip
import io.github.shdavlatbek.mlbblock.net.PROTO_UDP
import io.github.shdavlatbek.mlbblock.net.TrafficClass
import io.github.shdavlatbek.mlbblock.net.Verdict
import io.github.shdavlatbek.mlbblock.ui.CountryActivity
import io.github.shdavlatbek.mlbblock.ui.MainActivity
import io.github.shdavlatbek.mlbblock.vpn.Monitor
import io.github.shdavlatbek.mlbblock.vpn.Prefs
import io.github.shdavlatbek.mlbblock.vpn.ServerEntry
import io.github.shdavlatbek.mlbblock.vpn.GeoStore
import io.github.shdavlatbek.mlbblock.ui.CityActivity
import android.content.Intent
import android.os.Looper
import org.robolectric.Shadows.shadowOf
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/** Launches the real screens on the JVM: catches crashes and saves screenshots to build/ui/. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "ru-w411dp-h891dp-xxhdpi")
class UiSmokeTest {

    /** [fullHeight]: draw the whole scrollable content instead of one screen. */
    private fun shot(view: View, name: String, fullHeight: Boolean = true) {
        val dm = view.resources.displayMetrics
        val w = dm.widthPixels
        val hSpec = if (fullHeight) View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
        else View.MeasureSpec.makeMeasureSpec(dm.heightPixels, View.MeasureSpec.EXACTLY)
        view.measure(View.MeasureSpec.makeMeasureSpec(w, View.MeasureSpec.EXACTLY), hSpec)
        val h = view.measuredHeight.coerceIn(1, 6000)
        view.layout(0, 0, w, h)
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        view.draw(Canvas(bmp))
        val dir = File("build/ui").apply { mkdirs() }
        File(dir, "$name.png").outputStream().use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    @Test
    fun mainScreenWithServers() {
        val ctx = RuntimeEnvironment.getApplication()
        Prefs.update(ctx) { it.copy(countries = setOf("UZ", "RU"), cities = mapOf("RU" to setOf("St Petersburg"))) }
        Monitor.flowStarted(Ip.parse("213.230.64.10")!!, "UZ", "Tashkent", PROTO_UDP, 5521, TrafficClass.GAME, Verdict.ALLOW_COUNTRY)
            .also { e -> repeat(120) { Monitor.out(e); Monitor.inbound(e) }; Monitor.ping(e, 18) }
        Monitor.flowStarted(Ip.parse("3.120.0.1")!!, "DE", "Frankfurt am Main", PROTO_UDP, 5003, TrafficClass.GAME, Verdict.BLOCK_COUNTRY)
            .also { e -> repeat(40) { Monitor.drop(e) }; Monitor.ping(e, 96) }
        Monitor.flowStarted(Ip.parse("95.46.1.1")!!, "RU", "Moscow", PROTO_UDP, 30191, TrafficClass.GAME, Verdict.BLOCK_COUNTRY)
            .also { e -> repeat(12) { Monitor.drop(e) }; Monitor.ping(e, ServerEntry.PING_LOST) }
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val root = activity.window.decorView.findViewById<View>(android.R.id.content)
        val text = activity.findViewById<TextView>(R.id.countries).text.toString()
        assertTrue(text, text.contains("Узбекистан"))
        shot(root, "main")
    }

    @Test
    fun countryPicker() {
        Monitor.flowStarted(Ip.parse("213.230.64.11")!!, "UZ", "Tashkent", PROTO_UDP, 5521, TrafficClass.GAME, Verdict.ALLOW_COUNTRY)
        Monitor.flowStarted(Ip.parse("3.120.0.2")!!, "DE", "Frankfurt am Main", PROTO_UDP, 5003, TrafficClass.GAME, Verdict.BLOCK_COUNTRY)
        val activity = Robolectric.buildActivity(CountryActivity::class.java).setup().get()
        val list = activity.findViewById<ListView>(R.id.list)
        assertTrue(list.adapter.count > 200)
        shot(activity.window.decorView.findViewById(android.R.id.content), "countries", fullHeight = false)
    }

    @Test
    fun cityPicker() {
        val ctx = RuntimeEnvironment.getApplication()
        Prefs.update(ctx) { it.copy(countries = setOf("RU"), cities = mapOf("RU" to setOf("St Petersburg"))) }
        Monitor.flowStarted(Ip.parse("95.46.1.2")!!, "RU", "Moscow", PROTO_UDP, 5521, TrafficClass.GAME, Verdict.BLOCK_CITY)
            .also { Monitor.ping(it, 41) }
        Monitor.flowStarted(Ip.parse("2.16.21.2")!!, "RU", "St Petersburg", PROTO_UDP, 5521, TrafficClass.GAME, Verdict.ALLOW_COUNTRY)
            .also { Monitor.ping(it, 23) }
        GeoStore.cities(ctx) // unpack before the screen asks for it
        val intent = Intent(ctx, CityActivity::class.java).putExtra("country", "RU")
        val activity = Robolectric.buildActivity(CityActivity::class.java, intent).setup().get()
        val list = activity.findViewById<ListView>(R.id.list)
        val end = System.currentTimeMillis() + 10_000
        while (list.adapter.count == 0 && System.currentTimeMillis() < end) {
            Thread.sleep(50)
            shadowOf(Looper.getMainLooper()).idle()
        }
        assertTrue(list.adapter.count > 20)
        shot(activity.window.decorView.findViewById(android.R.id.content), "cities", fullHeight = false)
    }
}
