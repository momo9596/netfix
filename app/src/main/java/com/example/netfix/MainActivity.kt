package com.example.netfix

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.net.wifi.WifiManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.webkit.*
import android.webkit.CookieManager
import android.widget.*
import org.json.JSONObject
import java.net.*
import kotlin.concurrent.thread

@Suppress("DEPRECATION")
class MainActivity : Activity() {
    private lateinit var ip: EditText
    private lateinit var usr: EditText
    private lateinit var pw: EditText
    private lateinit var out: TextView
    private lateinit var web: WebView
    private lateinit var fixBtn: Button
    private var bestCh = 6
    private var bestDns = "1.1.1.1"
    private var beforeSpeed = -1.0
    private val ui = Handler(Looper.getMainLooper())

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), 1)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32); layoutDirection = android.view.View.LAYOUT_DIRECTION_RTL }
        fun field(h: String, t: String = "") = EditText(this).apply { hint = h; setText(t); setSingleLine() }
        ip = field("رقم IP للراوتر", gateway()); usr = field("اسم المستخدم", "admin")
        pw = field("كلمة المرور").apply { inputType = 129 }
        val diag = Button(this).apply { text = "🚀 افتح الراوتر وابدأ الفحص والإصلاح التلقائي"; setOnClickListener { openRouter(); diagnose(true) } }
        fixBtn = Button(this).apply { text = "🔁 إعادة محاولة الإصلاح"; isEnabled = false; setOnClickListener { applyFixes() } }
        out = TextView(this).apply { textSize = 15f; setPadding(0, 16, 0, 16) }
        web = WebView(this).apply {
            settings.javaScriptEnabled = true; settings.domStorageEnabled = true
            layoutParams = LinearLayout.LayoutParams(-1, 1400)
        }
        listOf(ip, diag, out, fixBtn, web).forEach { col.addView(it) }
        setContentView(ScrollView(this).apply { addView(col) })
    }

    private fun say(s: String) = runOnUiThread { out.text = s }

    private fun gateway(): String {
        val g = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).dhcpInfo.gateway
        return if (g == 0) "192.168.0.1" else "%d.%d.%d.%d".format(g and 255, g shr 8 and 255, g shr 16 and 255, g shr 24 and 255)
    }

    // ================= أدوات القياس الحقيقية =================
    private fun tcp(host: String, port: Int): Long = try {
        val t = System.nanoTime()
        Socket().use { it.connect(InetSocketAddress(host, port), 1500) }
        (System.nanoTime() - t) / 1_000_000
    } catch (e: Exception) { -1 }

    private fun dnsUdp(server: String): Long = try {
        val q = java.io.ByteArrayOutputStream().apply {
            write(byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            "example.com".split(".").forEach { write(it.length); write(it.toByteArray()) }
            write(byteArrayOf(0, 0, 1, 0, 1))
        }.toByteArray()
        DatagramSocket().use { s ->
            s.soTimeout = 1500
            val t = System.nanoTime()
            s.send(DatagramPacket(q, q.size, InetAddress.getByName(server), 53))
            s.receive(DatagramPacket(ByteArray(512), 512))
            (System.nanoTime() - t) / 1_000_000
        }
    } catch (e: Exception) { -1 }

    private fun stats(f: () -> Long, n: Int = 10): Pair<Double, Int> {
        val ok = (1..n).map { f() }.filter { it >= 0 }
        return Pair(if (ok.isEmpty()) -1.0 else ok.average(), (n - ok.size) * 100 / n)
    }

    private fun speedMbps(): Double = try {
        val c = URL("https://speed.cloudflare.com/__down?bytes=10000000").openConnection()
        c.connectTimeout = 5000; c.readTimeout = 15000
        val t = System.nanoTime(); var n = 0L
        c.getInputStream().use { s -> val buf = ByteArray(65536); while (true) { val r = s.read(buf); if (r < 0) break; n += r } }
        n * 8 / ((System.nanoTime() - t) / 1e9) / 1e6
    } catch (e: Exception) { -1.0 }

    private fun sysDnsMs(): Long {
        val t = System.nanoTime()
        try { InetAddress.getByName("n" + System.nanoTime() + ".example.com") } catch (e: Exception) {}
        return (System.nanoTime() - t) / 1_000_000
    }

    // ================= التشخيص وتحديد السبب =================
    private fun diagnose(auto: Boolean = false) {
        fixBtn.isEnabled = false
        thread {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val gw = ip.text.toString().trim()
            val info = wm.connectionInfo
            val is24 = info.frequency in 2400..2500
            val curCh = if (is24) (info.frequency - 2407) / 5 else (info.frequency - 5000) / 5

            say("⏳ فحص الإشارة والقنوات..."); wm.startScan(); Thread.sleep(3000)
            val aps = wm.scanResults.filter { it.frequency in 2400..2500 }
            fun cong(ch: Int) = aps.sumOf { ap ->
                val d = Math.abs((ap.frequency - 2407) / 5 - ch)
                if (d <= 4) (5 - d) / 5.0 * (100 + ap.level).coerceAtLeast(0) else 0.0
            }
            bestCh = listOf(1, 6, 11).minByOrNull { cong(it) } ?: 6

            say("⏳ فحص الراوتر..."); val (gwMs, gwLoss) = stats({ tcp(gw, 80) })
            say("⏳ فحص الإنترنت..."); val (netMs, netLoss) = stats({ dnsUdp("1.1.1.1") })
            say("⏳ فحص DNS..."); val sysDns = (1..3).map { sysDnsMs() }.average()
            val dnsRes = mapOf("1.1.1.1" to "Cloudflare", "8.8.8.8" to "Google", "9.9.9.9" to "Quad9")
                .map { (k, _) -> k to stats({ dnsUdp(k) }, 4).first }.filter { it.second >= 0 }.sortedBy { it.second }
            bestDns = dnsRes.firstOrNull()?.first ?: "1.1.1.1"
            say("⏳ اختبار السرعة..."); val sp = speedMbps(); beforeSpeed = sp

            val causes = mutableListOf<String>()
            if (info.rssi < -75) causes += "📶 إشارة الواي فاي ضعيفة (${info.rssi}dBm): اقترب من الراوتر أو أزل العوائق."
            if (is24 && cong(curCh) > 150) causes += "📡 تداخل قنوات شديد على القناة $curCh (${aps.size} شبكة قريبة) ← الحل: القناة $bestCh أو استخدم 5GHz."
            if (is24 && aps.size > 8) causes += "🏘 شبكات كثيرة بجوارك على 2.4GHz: يفضّل التحويل إلى 5GHz."
            if (gwLoss > 5 || gwMs > 40) causes += "🔌 اتصالك بالراوتر غير مستقر (فقد $gwLoss%، ${gwMs.toInt()}ms): مشكلة واي فاي أو راوتر مضغوط."
            else if (netLoss > 5 || netMs > 120) causes += "🌐 الراوتر سليم لكن الخط/المزوّد بطيء (${netMs.toInt()}ms، فقد $netLoss%): تواصل مع شركة الإنترنت."
            if (sysDns > 80 && dnsRes.isNotEmpty() && sysDns > dnsRes.first().second * 2) causes += "🧭 DNS الحالي بطيء (${sysDns.toInt()}ms) ← الحل: $bestDns (${dnsRes.first().second.toInt()}ms)."
            if (sp in 0.0..5.0) causes += "🐢 السرعة منخفضة جداً (${"%.1f".format(sp)} Mbps)."
            if (causes.isEmpty()) causes += "✅ لم أجد مشكلة واضحة. الشبكة تبدو سليمة."

            say("📊 النتائج\nإشارة: ${info.rssi}dBm | ${if (is24) "2.4" else "5"}GHz قناة $curCh | وصلة ${info.linkSpeed}Mbps\n" +
                "الراوتر: ${gwMs.toInt()}ms فقد $gwLoss%\nالإنترنت: ${netMs.toInt()}ms فقد $netLoss%\nالسرعة: ${"%.1f".format(sp)} Mbps\n\n" +
                "🔎 أسباب الضعف:\n" + causes.joinToString("\n\n") + "\n\nالحلول المقترحة: قناة $bestCh + DNS $bestDns")
            runOnUiThread { fixBtn.isEnabled = true; if (auto) applyFixes() }
        }
    }

    // ================= تطبيق الحلول فعلياً عبر WebView =================
    private fun js(user: String, pass: String, tryLogin: Boolean) = """
    (function(CH,DNS,U,P,TL){
      var r={login:false,ch:false,dns:false,nav:false};
      function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
      function vis(e){return e.offsetParent!==null}
      function setv(e,v){e.focus();e.value=v;['input','change','keyup'].forEach(function(t){e.dispatchEvent(new Event(t,{bubbles:true}))})}
      function clickSave(d){var c=[].slice.call(d.querySelectorAll('button,input[type=button],input[type=submit],a')).filter(vis);
        for(var i=0;i<c.length;i++){var t=(c[i].innerText||c[i].value||'');if(/save|apply|^ok$|submit|حفظ|تطبيق/i.test(t)){c[i].click();return true}}return false}
      docs(window,[]).forEach(function(d){
        try{
          var p=[].slice.call(d.querySelectorAll('input[type=password]')).filter(vis)[0];
          if(p&&TL){var us=[].slice.call(d.querySelectorAll('input[type=text],input:not([type])')).filter(vis)[0];
            if(us)setv(us,U);setv(p,P);
            var b=[].slice.call(d.querySelectorAll('button,input[type=submit],input[type=button],a')).filter(vis).filter(function(x){return /log\s*in|sign\s*in|login|دخول/i.test((x.innerText||x.value||x.id||x.className))})[0];
            if(b)b.click();else p.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',keyCode:13,bubbles:true}));
            r.login=true;return}
          var sels=[].slice.call(d.querySelectorAll('select')).filter(vis);
          for(var i=0;i<sels.length;i++){var o=[].slice.call(sels[i].options).map(function(x){return x.text.trim()});
            if(o.indexOf('1')>=0&&o.indexOf('6')>=0&&o.indexOf('11')>=0){sels[i].selectedIndex=o.indexOf(String(CH));
              sels[i].dispatchEvent(new Event('change',{bubbles:true}));clickSave(d);r.ch=true}}
          var dn=[].slice.call(d.querySelectorAll('input')).filter(function(x){return vis(x)&&/dns/i.test(x.name+x.id+(x.placeholder||''))});
          if(dn.length){setv(dn[0],DNS);if(dn[1])setv(dn[1],'8.8.8.8');clickSave(d);r.dns=true}
          if(!r.ch&&!r.dns){var m=[].slice.call(d.querySelectorAll('a,li,span,div')).filter(function(x){return vis(x)&&x.children.length==0&&/^(wireless|wi-?fi|wlan|wireless settings|network|internet|wan)$/i.test((x.innerText||'').trim())})[0];
            if(m){m.click();r.nav=true}}
        }catch(e){}
      });
      return JSON.stringify(r)
    })(${bestCh},${JSONObject.quote(bestDns)},${JSONObject.quote(user)},${JSONObject.quote(pass)},$tryLogin)
    """

    private val logoutJs = """
    (function(){function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
    docs(window,[]).forEach(function(d){try{[].slice.call(d.querySelectorAll('a,button,li,span,div,input')).forEach(function(x){
    var t=(x.innerText||x.value||x.id||'').trim();if(t.length<25&&/log\s*out|sign\s*out|logout|خروج/i.test(t)&&x.children.length<3){x.click()}})}catch(e){}})})()
    """

    private fun finish(msg: String) {
        say("$msg\n🚪 جاري تسجيل الخروج من صفحة الراوتر...")
        web.evaluateJavascript(logoutJs, null)
        ui.postDelayed({
            CookieManager.getInstance().removeAllCookies(null)
            web.clearCache(true); web.loadUrl("about:blank")
            thread {
                Thread.sleep(8000)
                val after = speedMbps()
                say("$msg\n✅ تم تسجيل الخروج من الراوتر\n\n📈 السرعة قبل: ${"%.1f".format(beforeSpeed)} Mbps\nالسرعة بعد: ${"%.1f".format(after)} Mbps\n\nإن لم تتحسن أعد تشغيل الراوتر ثم افحص مجدداً.")
            }
        }, 4000)
    }

    private fun openRouter() {
        web.webViewClient = object : WebViewClient() {
            override fun onReceivedHttpAuthRequest(v: WebView, h: HttpAuthHandler, hs: String, r: String) {
                val box = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 20, 40, 0) }
                val u = EditText(this@MainActivity).apply { hint = "اسم المستخدم" }
                val p = EditText(this@MainActivity).apply { hint = "كلمة المرور"; inputType = 129 }
                box.addView(u); box.addView(p)
                AlertDialog.Builder(this@MainActivity).setTitle("دخول الراوتر").setView(box)
                    .setPositiveButton("دخول") { _, _ -> h.proceed(u.text.toString(), p.text.toString()) }
                    .setNegativeButton("إلغاء") { _, _ -> h.cancel() }.show()
            }
        }
        web.loadUrl("http://" + ip.text.toString().trim())
    }

    private fun applyFixes() {
        var chDone = false; var dnsDone = false; var logins = 0; var ticks = 0
        say("✍ اكتب اسم المستخدم وكلمة المرور في صفحة الراوتر بالأسفل، وسأكمل الإصلاح تلقائياً بعد دخولك...")
        val tick = object : Runnable {
            override fun run() {
                ticks++
                web.evaluateJavascript(js("", "", false)) { raw ->
                    try {
                        val r = JSONObject(raw.trim('"').replace("\\\"", "\""))
                        if (r.getBoolean("login")) logins++
                        if (r.getBoolean("ch")) chDone = true
                        if (r.getBoolean("dns")) dnsDone = true
                    } catch (e: Exception) {}
                    say("✍ بانتظار دخولك   📡 القناة $bestCh: ${if (chDone) "✓" else "…"}   🧭 DNS $bestDns: ${if (dnsDone) "✓" else "…"}")
                }
                if (chDone && dnsDone) { finish("✅ تم تطبيق القناة $bestCh و DNS $bestDns"); return }
                if (ticks < 120) ui.postDelayed(this, 2500)
                else finish("⚠ لم تكتمل كل الخطوات تلقائياً (القناة: $chDone، DNS: $dnsDone). واجهة راوترك تحتاج دعماً مخصصاً.")
            }
        }
        ui.postDelayed(tick, 3000)
    }
}
