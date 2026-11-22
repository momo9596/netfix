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
import android.webkit.CookieManager
import android.webkit.HttpAuthHandler
import android.webkit.JsResult
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.*
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import kotlin.concurrent.thread

@Suppress("DEPRECATION")
class MainActivity : Activity() {
    private lateinit var ip: EditText
    private lateinit var out: TextView
    private lateinit var web: WebView
    private lateinit var fixBtn: Button
    private var bestCh = 6
    private var bestDns = "1.1.1.1"
    private var beforeSpeed = -1.0
    private var crowded = false
    private var running = false
    private var changed = false
    private var phase = "dns"
    private var ticks = 0
    private var pt = 0
    private val report = mutableListOf<String>()
    private val ui = Handler(Looper.getMainLooper())

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), 1)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32); layoutDirection = android.view.View.LAYOUT_DIRECTION_RTL }
        ip = EditText(this).apply { hint = "رقم IP للراوتر"; setText(gateway()); setSingleLine() }
        val diag = Button(this).apply { text = "🚀 افتح الراوتر وابدأ الفحص والإصلاح التلقائي"; setOnClickListener { openRouter(); diagnose(true) } }
        fixBtn = Button(this).apply { text = "🔁 إعادة محاولة الإصلاح"; isEnabled = false; setOnClickListener { applyFixes() } }
        out = TextView(this).apply { textSize = 15f; setPadding(0, 16, 0, 16) }
        web = WebView(this).apply {
            settings.javaScriptEnabled = true; settings.domStorageEnabled = true
            layoutParams = LinearLayout.LayoutParams(-1, 1400)
            webChromeClient = object : WebChromeClient() {
                override fun onJsConfirm(v: WebView, url: String, message: String, result: JsResult): Boolean { result.confirm(); return true }
                override fun onJsAlert(v: WebView, url: String, message: String, result: JsResult): Boolean { result.confirm(); return true }
            }
        }
        listOf(ip, diag, out, fixBtn, web).forEach { col.addView(it) }
        setContentView(ScrollView(this).apply { addView(col) })
    }

    private fun say(s: String) = runOnUiThread { out.text = s }

    private fun progress(extra: String) =
        say((listOf("🎯 الخطة: قناة $bestCh + DNS $bestDns") + report + extra).joinToString("\n"))

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
            crowded = is24 && (aps.size > 5 || cong(curCh) > 120)

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

    // ================= سكربت التحكم في صفحة الراوتر =================
    private fun js(ph: String) = """
    (function(PH,CH,DNS,CROWD){
      var r={found:false,changed:false,pw:false,clicked:false,w:false,info:''};
      function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
      function vis(e){return e.offsetParent!==null}
      function setv(e,v){e.focus();e.value=v;['input','change','keyup'].forEach(function(t){e.dispatchEvent(new Event(t,{bubbles:true}))})}
      function norm(x){return (x.innerText||x.value||'').trim().replace(/^[-\s]+/,'').toLowerCase()}
      function save(d){var c=[].slice.call(d.querySelectorAll('button,input[type=button],input[type=submit],a')).filter(vis);
        for(var i=0;i<c.length;i++){if(['save','apply','ok','submit','حفظ','تطبيق'].indexOf(norm(c[i]))>=0){c[i].click();return true}}return false}
      function menu(names){var ds=docs(window,[]);
        for(var k=0;k<names.length;k++){for(var j=0;j<ds.length;j++){
          var al=[].slice.call(ds[j].querySelectorAll('a,li,span,div,td')).filter(function(x){return vis(x)&&x.children.length==0&&norm(x)===names[k]});
          if(al.length){al[0].click();return true}}}return false}
      var ds=docs(window,[]);
      for(var i=0;i<ds.length;i++){try{var p=ds[i].querySelector('input[type=password]');if(p&&vis(p)){r.pw=true;return r}}catch(e){}}
      for(var i=0;i<ds.length;i++){try{var d=ds[i];
        if(PH==='dns'){
          var dn=[].slice.call(d.querySelectorAll('input')).filter(function(x){return vis(x)&&x.type!=='hidden'&&/dns/i.test(x.name+x.id)});
          if(dn.length){r.found=true;r.info=dn[0].value.trim();
            if(r.info!==DNS){setv(dn[0],DNS);if(dn[1])setv(dn[1],DNS==='8.8.8.8'?'1.1.1.1':'8.8.8.8');save(d);r.changed=true}
            return r}
        } else if(PH==='chan'){
          var ss=[].slice.call(d.querySelectorAll('select')).filter(vis),cs=null,ws=null;
          ss.forEach(function(s){var o=[].slice.call(s.options).map(function(x){return x.text.trim()});
            var j=o.join('|').toLowerCase();
            if(o.indexOf('1')>=0&&o.indexOf('6')>=0&&o.indexOf('11')>=0)cs=s;
            else if(j.indexOf('20')>=0&&j.indexOf('40')>=0)ws=s});
          if(cs){r.found=true;var cur=cs.options[cs.selectedIndex].text.trim();r.info=cur;var chg=false;
            if(cur!==String(CH)){for(var q=0;q<cs.options.length;q++){if(cs.options[q].text.trim()===String(CH)){cs.selectedIndex=q;break}}cs.dispatchEvent(new Event('change',{bubbles:true}));chg=true}
            if(CROWD&&ws){for(var q=0;q<ws.options.length;q++){if(/^20/.test(ws.options[q].text.trim())){if(ws.selectedIndex!==q){ws.selectedIndex=q;ws.dispatchEvent(new Event('change',{bubbles:true}));chg=true;r.w=true}break}}}
            if(chg){save(d);r.changed=true}
            return r}
        } else if(PH==='reboot'){
          var bt=[].slice.call(d.querySelectorAll('input[type=button],input[type=submit],button')).filter(vis).filter(function(x){return norm(x)==='reboot'})[0];
          if(bt){bt.click();r.clicked=true;return r}
        }
      }catch(e){}}
      if(PH==='dns')menu(['dhcp settings','dhcp','wan','internet','network']);
      else if(PH==='chan')menu(['wireless settings','wireless','wi-fi','wlan']);
      else if(PH==='reboot')menu(['reboot','system tools']);
      return r
    })(${JSONObject.quote(ph)},${bestCh},${JSONObject.quote(bestDns)},$crowded)
    """

    private val logoutJs = """
    (function(){function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
    docs(window,[]).forEach(function(d){try{[].slice.call(d.querySelectorAll('a,button,li,span,div,input')).forEach(function(x){
    var t=(x.innerText||x.value||x.id||'').trim();if(t.length<25&&/log\s*out|sign\s*out|logout|خروج/i.test(t)&&x.children.length<3){x.click()}})}catch(e){}})})()
    """

    // ================= تسلسل الإصلاح =================
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
        if (running) return
        running = true; phase = "dns"; ticks = 0; pt = 0; changed = false; report.clear()
        progress("✍ سجّل دخولك في صفحة الراوتر بالأسفل وسأبدأ الإصلاح تلقائياً...")
        ui.postDelayed({ step() }, 2000)
    }

    private fun moveTo(p: String) { phase = p; pt = 0 }

    private fun step() {
        ticks++
        if (ticks > 200) { finish("⚠ انتهت المهلة قبل إكمال الخطوات"); return }
        web.evaluateJavascript(js(phase)) { raw ->
            val r = try { JSONObject(raw ?: "") } catch (e: Exception) { null }
            var wait = 2500L
            var stop = false
            if (r != null && r.optBoolean("pw")) {
                progress("✍ بانتظار تسجيل دخولك في صفحة الراوتر...")
            } else if (r != null) {
                pt++
                val found = r.optBoolean("found")
                when (phase) {
                    "dns" -> {
                        if (found) {
                            if (r.optBoolean("changed")) {
                                changed = true; wait = 5000
                                report += "🧭 DNS: كان ${r.optString("info")} ← أصبح $bestDns"
                            } else report += "🧭 DNS ${r.optString("info")} مناسب (بدون تغيير)"
                            moveTo("chan")
                        } else if (pt > 24) {
                            report += "🧭 لم أجد إعدادات DNS في هذا الراوتر (تخطّيت)"
                            moveTo("chan")
                        } else progress("🔎 أبحث عن إعدادات DNS...")
                    }
                    "chan" -> {
                        if (found) {
                            val cur = r.optString("info")
                            if (r.optBoolean("changed")) {
                                changed = true; wait = 5000
                                report += "📡 القناة: كانت $cur ← أصبحت $bestCh"
                                if (r.optBoolean("w")) report += "📶 عرض القناة ← 20MHz (أقل تداخلاً)"
                            } else report += "📡 القناة $cur مناسبة (بدون تغيير)"
                            moveTo(if (changed) "reboot" else "done")
                        } else if (pt > 24) {
                            report += "📡 لم أجد إعدادات القناة (تخطّيت)"
                            moveTo(if (changed) "reboot" else "done")
                        } else progress("🔎 أبحث عن إعدادات الواي فاي...")
                    }
                    "reboot" -> {
                        if (r.optBoolean("clicked")) { stop = true; rebooting() }
                        else if (pt > 24) { stop = true; finish("⚠ لم أجد زر إعادة التشغيل، أعد تشغيل الراوتر يدوياً ليُطبَّق التغيير") }
                        else progress("🔁 أنتقل لصفحة إعادة التشغيل...")
                    }
                }
                if (phase == "done") { stop = true; finish("✅ الراوتر مضبوط بالفعل، لا حاجة لإعادة التشغيل") }
            }
            if (!stop) ui.postDelayed({ step() }, wait)
        }
    }

    private fun rebooting() {
        val gw = ip.text.toString().trim()
        progress("🔄 جاري إعادة تشغيل الراوتر... (حوالي دقيقة ونصف)")
        thread {
            var down = false
            var i = 0
            while (!down && i < 15) { Thread.sleep(3000); if (tcp(gw, 80) < 0) down = true; i++ }
            if (!down) {
                say(report.joinToString("\n") + "\n\n⚠ لم أتأكد أن الراوتر أعاد التشغيل (لم ينقطع). أعد تشغيله يدوياً.")
                running = false
                return@thread
            }
            var up = false
            var n = 0
            while (!up && n < 45) { if (tcp(gw, 80) >= 0) up = true else { Thread.sleep(4000); n++ } }
            if (!up) {
                say(report.joinToString("\n") + "\n\n⚠ الراوتر لم يرجع بعد. أعد توصيل الواي فاي ثم افحص من جديد.")
                running = false
                return@thread
            }
            Thread.sleep(15000)
            val after = speedMbps()
            say(report.joinToString("\n") + "\n\n✅ تمت إعادة تشغيل الراوتر فعلياً (انقطع ثم رجع)\n📈 السرعة قبل: ${"%.1f".format(beforeSpeed)} Mbps\nالسرعة بعد: ${"%.1f".format(after)} Mbps")
            running = false
        }
    }

    private fun finish(msg: String) {
        progress("$msg\n🚪 جاري تسجيل الخروج من صفحة الراوتر...")
        web.evaluateJavascript(logoutJs, null)
        ui.postDelayed({
            CookieManager.getInstance().removeAllCookies(null)
            web.clearCache(true); web.loadUrl("about:blank")
            thread {
                Thread.sleep(5000)
                val after = speedMbps()
                say(report.joinToString("\n") + "\n\n$msg\n✅ تم تسجيل الخروج\n📈 السرعة قبل: ${"%.1f".format(beforeSpeed)} Mbps\nالسرعة بعد: ${"%.1f".format(after)} Mbps")
                running = false
            }
        }, 4000)
    }
}
