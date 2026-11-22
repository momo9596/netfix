package com.example.netfix

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
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
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

data class ChanScan(val best: Int, val count: Int, val curBad: Boolean)

@Suppress("DEPRECATION")
class MainActivity : Activity() {
    private lateinit var ip: EditText
    private lateinit var out: TextView
    private lateinit var web: WebView
    private lateinit var fixBtn: Button
    private lateinit var restoreBtn: Button
    private var bestCh = 6
    private var bestDns = "1.1.1.1"
    private var bestDns2 = "8.8.8.8"
    private var dnsWorth = true
    private var dnsReport = ""
    private var beforeSpeed = -1.0
    private var crowded = false
    private var lowSpeed = false
    private var lineProblem = false
    private var oldUptime = false
    private var running = false
    private var changed = false
    private var restoring = false
    private var restoreWid = ""
    private var dnsDone = false
    private var chanDone = false
    private var devices = -1
    private var phase = "status"
    private var ticks = 0
    private var pt = 0
    private var primary = ""
    private var diagText = ""
    private var lastReport = ""
    private val report = mutableListOf<String>()
    private val audit = mutableListOf<String>()
    private val order = listOf("status", "dns", "clients", "chan")
    private val ui = Handler(Looper.getMainLooper())

    // مرشّحو DNS فقط؛ الاختيار النهائي بالقياس الحي
    private val dnsCandidates = listOf(
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "94.140.14.14", "185.228.168.9"
    )
    private val testDomains = listOf(
        "google.com", "youtube.com", "facebook.com", "wikipedia.org",
        "amazon.com", "instagram.com", "whatsapp.com", "tiktok.com"
    )

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), 1)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32); layoutDirection = android.view.View.LAYOUT_DIRECTION_RTL }
        ip = EditText(this).apply { hint = "رقم IP للراوتر"; setText(gateway()); setSingleLine() }
        val diag = Button(this).apply { text = "🚀 افتح الراوتر وابدأ فحص وإصلاح السرعة"; setOnClickListener { openRouter(); diagnose(true) } }
        fixBtn = Button(this).apply { text = "🔁 إعادة محاولة الإصلاح"; isEnabled = false; setOnClickListener { applyFixes() } }
        restoreBtn = Button(this).apply {
            text = "↩ استرجاع إعدادات الراوتر السابقة"
            isEnabled = hasBackup()
            setOnClickListener { restoreBackup() }
        }
        val copyBtn = Button(this).apply { text = "📋 نسخ التقرير"; setOnClickListener { copyReport() } }
        out = TextView(this).apply { textSize = 15f; setPadding(0, 16, 0, 16) }
        web = WebView(this).apply {
            settings.javaScriptEnabled = true; settings.domStorageEnabled = true
            layoutParams = LinearLayout.LayoutParams(-1, 1400)
            webChromeClient = object : WebChromeClient() {
                // حماية: لا نوافق أبداً على رسائل استرجاع إعدادات المصنع
                private fun risky(m: String) = Regex("factory|default|restore|مصنع|افتراض", RegexOption.IGNORE_CASE).containsMatchIn(m)
                override fun onJsConfirm(v: WebView, url: String, message: String, result: JsResult): Boolean {
                    if (risky(message)) result.cancel() else result.confirm(); return true
                }
                override fun onJsAlert(v: WebView, url: String, message: String, result: JsResult): Boolean { result.confirm(); return true }
            }
        }
        listOf(ip, diag, out, fixBtn, restoreBtn, copyBtn, web).forEach { col.addView(it) }
        setContentView(ScrollView(this).apply { addView(col) })
    }

    private fun say(s: String) = runOnUiThread { out.text = s }

    private fun progress(extra: String) =
        say((listOf("🎯 الخطة: قناة $bestCh + DNS $bestDns") + audit + report + extra).joinToString("\n"))

    private fun copyReport() {
        val text = if (lastReport.isNotEmpty()) lastReport else out.text.toString()
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("report", text))
        Toast.makeText(this, "تم نسخ التقرير", Toast.LENGTH_SHORT).show()
    }

    private fun fmt(x: Double): String = if (x < 0) "فشل القياس" else "%.1f Mbps".format(x)

    private fun gateway(): String {
        val g = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).dhcpInfo.gateway
        return if (g == 0) "192.168.0.1" else "%d.%d.%d.%d".format(g and 255, g shr 8 and 255, g shr 16 and 255, g shr 24 and 255)
    }

    // ================= النسخة الاحتياطية والاسترجاع =================
    private fun hasBackup(): Boolean {
        val sp = getSharedPreferences("nf", 0)
        return sp.contains("bk_ch") || sp.contains("bk_dns1")
    }

    private fun restoreBackup() {
        if (running) return
        val sp = getSharedPreferences("nf", 0)
        if (!hasBackup()) { Toast.makeText(this, "لا توجد نسخة احتياطية", Toast.LENGTH_SHORT).show(); return }
        restoring = true
        dnsWorth = sp.contains("bk_dns1")
        bestDns = sp.getString("bk_dns1", "") ?: ""
        bestDns2 = sp.getString("bk_dns2", "") ?: ""
        bestCh = sp.getInt("bk_ch", 0)
        restoreWid = sp.getString("bk_wd", "") ?: ""
        crowded = false
        openRouter()
        applyFixes()
    }

    // ================= أدوات القياس الحقيقية =================
    private fun tcp(host: String, port: Int): Long = try {
        val t = System.nanoTime()
        Socket().use { it.connect(InetSocketAddress(host, port), 1500) }
        (System.nanoTime() - t) / 1_000_000
    } catch (e: Exception) { -1 }

    // استعلام DNS حقيقي مع التحقق من الرد (نفس الـ ID، بدون خطأ، وفيه إجابة)
    private fun dnsQuery(server: String, host: String, timeout: Int = 1500): Long {
        val id = (Math.random() * 65535).toInt()
        val bo = java.io.ByteArrayOutputStream()
        bo.write(byteArrayOf((id shr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        host.split(".").forEach { bo.write(it.length); bo.write(it.toByteArray()) }
        bo.write(byteArrayOf(0, 0, 1, 0, 1))
        val q = bo.toByteArray()
        return try {
            DatagramSocket().use { s ->
                s.soTimeout = timeout
                val t = System.nanoTime()
                s.send(DatagramPacket(q, q.size, InetAddress.getByName(server), 53))
                val buf = ByteArray(512)
                s.receive(DatagramPacket(buf, 512))
                val ms = (System.nanoTime() - t) / 1_000_000
                val idOk = buf[0] == q[0] && buf[1] == q[1]
                val rcode = buf[3].toInt() and 15
                val answers = ((buf[6].toInt() and 255) shl 8) or (buf[7].toInt() and 255)
                if (idOk && rcode == 0 && answers > 0) ms else -1
            }
        } catch (e: Exception) { -1 }
    }

    private fun dnsUdp(server: String): Long = dnsQuery(server, "example.com")

    // DNS اللي واخدته الشبكة حالياً من المزوّد
    private fun ispDns(): List<String> {
        val d = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).dhcpInfo
        fun ipOf(g: Int) = if (g == 0) null else "%d.%d.%d.%d".format(g and 255, g shr 8 and 255, g shr 16 and 255, g shr 24 and 255)
        return listOfNotNull(ipOf(d.dns1), ipOf(d.dns2))
    }

    // الدرجة = 60% وسيط + 40% متوسط، والفشل بعقوبة 1500ms
    private fun dnsScore(server: String): Double {
        val times = mutableListOf<Long>()
        repeat(2) {
            for (d in testDomains) {
                val x = dnsQuery(server, d)
                times.add(if (x < 0) 1500 else x)
            }
        }
        val sorted = times.sorted()
        val median = sorted[sorted.size / 2].toDouble()
        return median * 0.6 + times.average() * 0.4
    }

    private fun benchmarkDns(): List<Pair<String, Double>> {
        val all = (ispDns() + dnsCandidates).distinct()
        val results = java.util.Collections.synchronizedList(mutableListOf<Pair<String, Double>>())
        val ts = all.map { s -> thread { results.add(s to dnsScore(s)) } }
        ts.forEach { it.join(30000) }
        return ArrayList(results).filter { it.second < 1400 }.sortedBy { it.second }
    }

    private fun chooseDns(ranked: List<Pair<String, Double>>) {
        if (ranked.isEmpty()) { dnsWorth = false; dnsReport = "🧭 تعذّر قياس DNS"; return }
        val cur = ispDns().firstOrNull()
        val curScore = ranked.firstOrNull { it.first == cur }?.second
        val best = ranked[0]
        bestDns = best.first
        bestDns2 = ranked.getOrNull(1)?.first ?: "8.8.8.8"
        dnsWorth = curScore == null || best.second < curScore * 0.8
        if (!dnsWorth) bestDns = cur ?: best.first
        dnsReport = "🧭 أفضل DNS: ${best.first} (${best.second.toInt()}ms)" +
            (if (curScore != null) " | الحالي $cur (${curScore.toInt()}ms)" else "") +
            if (dnsWorth) " ← سيتغيّر" else " ← الحالي مناسب"
    }

    // 3 مسحات + استبعاد شبكتك + حساب التداخل بالقدرة (mW)
    private fun pickChannel(wm: WifiManager, curCh: Int): ChanScan {
        val own = wm.connectionInfo.bssid
        val seen = HashMap<String, Int>()
        val freq = HashMap<String, Int>()
        repeat(3) {
            wm.startScan(); Thread.sleep(2500)
            wm.scanResults.filter { it.frequency in 2400..2500 && it.BSSID != own }.forEach {
                if (it.level > (seen[it.BSSID] ?: -200)) { seen[it.BSSID] = it.level; freq[it.BSSID] = it.frequency }
            }
        }
        fun load(ch: Int): Double = seen.entries.sumOf { e ->
            val apCh = (freq[e.key]!! - 2407) / 5
            val d = Math.abs(apCh - ch)
            if (d > 4) 0.0 else Math.pow(10.0, e.value / 10.0) * (5 - d) / 5.0
        }
        val best = listOf(1, 6, 11).minByOrNull { load(it) } ?: 6
        val curBad = curCh != best && load(curCh) > load(best) * 2 && seen.isNotEmpty()
        return ChanScan(best, seen.size, curBad)
    }

    private fun stats(f: () -> Long, n: Int = 10): Pair<Double, Int> {
        val ok = (1..n).map { f() }.filter { it >= 0 }
        return Pair(if (ok.isEmpty()) -1.0 else ok.average(), (n - ok.size) * 100 / n)
    }

    private fun pingStats(n: Int): Triple<Double, Double, Int> {
        val t = mutableListOf<Long>()
        for (i in 1..n) {
            val x = dnsUdp("1.1.1.1")
            if (x >= 0) t.add(x)
            Thread.sleep(100)
        }
        val avg = if (t.isEmpty()) -1.0 else t.average()
        var j = 0.0
        for (i in 1 until t.size) j += Math.abs(t[i] - t[i - 1]).toDouble()
        return Triple(avg, if (t.size > 1) j / (t.size - 1) else 0.0, (n - t.size) * 100 / n)
    }

    private fun speedLoaded(): Pair<Double, Double> {
        val bytes = AtomicLong(0)
        val stop = AtomicBoolean(false)
        val lat = java.util.Collections.synchronizedList(mutableListOf<Long>())
        val conns = java.util.Collections.synchronizedList(mutableListOf<HttpURLConnection>())
        val start = System.nanoTime()
        val workers = (1..3).map {
            thread {
                try {
                    val c = URL("https://speed.cloudflare.com/__down?bytes=25000000").openConnection() as HttpURLConnection
                    conns.add(c)
                    c.connectTimeout = 5000; c.readTimeout = 10000
                    c.inputStream.use { s ->
                        val buf = ByteArray(65536)
                        while (!stop.get()) {
                            val r = s.read(buf)
                            if (r < 0) break
                            bytes.addAndGet(r.toLong())
                        }
                    }
                } catch (e: Exception) {}
            }
        }
        val pinger = thread {
            try {
                Thread.sleep(1500)
                while (!stop.get()) {
                    val x = dnsUdp("1.1.1.1")
                    if (x >= 0) lat.add(x)
                    Thread.sleep(300)
                }
            } catch (e: Exception) {}
        }
        val deadline = System.nanoTime() + 12_000_000_000L
        while (System.nanoTime() < deadline && workers.any { it.isAlive }) Thread.sleep(200)
        stop.set(true)
        val secs = (System.nanoTime() - start) / 1e9
        val total = bytes.get()
        for (c in ArrayList(conns)) { try { c.disconnect() } catch (e: Exception) {} }
        pinger.join(1500)
        val mbps = if (total > 0) total * 8 / secs / 1e6 else -1.0
        val l = ArrayList(lat)
        return Pair(mbps, if (l.isEmpty()) -1.0 else l.average())
    }

    private fun speedRetry(): Pair<Double, Double> {
        for (i in 1..4) {
            val r = speedLoaded()
            if (r.first > 0) return r
            Thread.sleep(5000)
        }
        return Pair(-1.0, -1.0)
    }

    // ================= التشخيص من جهة الهاتف =================
    private fun diagnose(auto: Boolean = false) {
        fixBtn.isEnabled = false
        thread {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val gw = ip.text.toString().trim()
            val info = wm.connectionInfo
            val is24 = info.frequency in 2400..2500
            val curCh = if (is24) (info.frequency - 2407) / 5 else (info.frequency - 5000) / 5

            say("⏳ فحص الاتصال بالراوتر..."); val (gwMs, gwLoss) = stats({ tcp(gw, 80) })
            say("⏳ فحص استقرار الإنترنت (20 قياساً)..."); val (netMs, jitter, netLoss) = pingStats(20)
            say("⏳ اختبار السرعة (قد يستغرق دقيقة)..."); val (sp, loaded) = speedRetry(); beforeSpeed = sp
            lowSpeed = sp in 0.0..5.0
            lineProblem = netLoss > 5 || netMs > 120
            val bloat = loaded > 0 && netMs > 0 && loaded - netMs > 150

            say("⏳ قياس أسرع DNS فعلياً (8 مواقع × كل سيرفر)...")
            val ranked = benchmarkDns()
            chooseDns(ranked)

            say("⏳ مسح القنوات (3 مرات)...")
            val cs = pickChannel(wm, curCh)
            bestCh = cs.best
            crowded = is24 && (cs.count > 5 || cs.curBad)

            val causes = mutableListOf<String>()
            if (info.rssi < -75) causes += "📶 إشارة الواي فاي ضعيفة (${info.rssi}dBm): اقترب من الراوتر أو أزل العوائق."
            if (info.linkSpeed in 1..20) causes += "🐌 سرعة وصلة الواي فاي بين هاتفك والراوتر منخفضة (${info.linkSpeed}Mbps)."
            if (is24 && cs.curBad) causes += "📡 تداخل قنوات على القناة $curCh (${cs.count} شبكة قريبة) ← الحل: القناة $bestCh."
            if (is24 && cs.count > 8) causes += "🏘 شبكات كثيرة حولك على 2.4GHz."
            if (is24 && info.rssi > -65 && wm.is5GHzBandSupported) causes += "⚡ هاتفك يدعم 5GHz وإشارتك جيدة: اتصل بشبكة 5GHz (إن وُجدت) فهي أسرع وأقل ازدحاماً."
            if (gwLoss > 5 || gwMs > 40) causes += "🔌 اتصالك بالراوتر غير مستقر (فقد $gwLoss%، ${gwMs.toInt()}ms): مشكلة واي فاي أو راوتر مضغوط."
            if (lineProblem) causes += "🌐 الإنترنت نفسه غير مستقر (${netMs.toInt()}ms، فقد $netLoss%، تذبذب ${jitter.toInt()}ms): غالباً الخط أو المزوّد."
            if (bloat) causes += "📉 عند التحميل يرتفع زمن الاستجابة من ${netMs.toInt()} إلى ${loaded.toInt()}ms: أي تحميل يبطّئ باقي الأجهزة."
            if (dnsWorth && ranked.isNotEmpty()) causes += "🧭 يوجد DNS أسرع بشكل واضح من الحالي ← الحل: $bestDns."
            if (sp in 0.0..5.0) causes += "🐢 سرعة التحميل منخفضة جداً (${fmt(sp)})."
            if (causes.isEmpty()) causes += "✅ لم أجد مشكلة واضحة."

            primary = when {
                info.rssi < -75 || gwLoss > 5 || gwMs > 40 -> "المشكلة عندك محلياً: ضعف الواي فاي أو بعدك عن الراوتر أو ازدحام القنوات."
                lineProblem -> "المشكلة في الخط أو شركة الإنترنت (الراوتر سليم)."
                sp in 0.0..10.0 -> "الواي فاي والراوتر سليمان، والسرعة منخفضة: سرعة الباقة أو الخط أو ازدحام الأجهزة."
                bloat -> "الخط يزدحم عند التحميل: قلّل الأجهزة أو فعّل QoS في الراوتر."
                else -> "لا توجد مشكلة واضحة."
            }

            diagText = "📊 نتائج فحص الهاتف\n" +
                "إشارة: ${info.rssi}dBm | ${if (is24) "2.4" else "5"}GHz قناة $curCh | وصلة ${info.linkSpeed}Mbps\n" +
                "الراوتر: ${gwMs.toInt()}ms فقد $gwLoss%\n" +
                "الإنترنت: ${netMs.toInt()}ms تذبذب ${jitter.toInt()}ms فقد $netLoss%\n" +
                "السرعة: ${fmt(sp)} | زمن أثناء التحميل: ${if (loaded > 0) "${loaded.toInt()}ms" else "—"}\n" +
                dnsReport + "\n\n" +
                "🔎 الأسباب:\n" + causes.joinToString("\n")
            say(diagText + "\n\nالحلول المقترحة: قناة $bestCh + DNS $bestDns")
            runOnUiThread { fixBtn.isEnabled = true; if (auto) applyFixes() }
        }
    }

    // ================= سكربت عام لمعظم الرواتر (بحث ذكي بالكلمات المفتاحية) =================
    private fun widParam(): String = if (restoring) restoreWid else if (crowded) "20" else ""

    private fun js(ph: String) = """
    (function(PH,CH,DNS,DNS2,DOCHG,WID,PT){
      var r={found:false,changed:false,pw:false,clicked:false,w:false,info:'',info2:'',cn:-1,wd:'',md:''};
      function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
      function vis(e){return e.offsetParent!==null}
      function setv(e,v){e.focus();e.value=v;['input','change','keyup'].forEach(function(t){e.dispatchEvent(new Event(t,{bubbles:true}))})}
      function norm(x){return (x.innerText||x.value||'').trim().replace(/^[-\s]+/,'').toLowerCase()}
      function g(tx,re){var m=tx.match(re);return m?m[1].trim():''}
      function ok(a,n){return a===n||(n.length>4&&a.indexOf(n)===0&&a.length<=n.length+10)}
      function num(o){var m=(o.text||'').match(/^\s*(?:channel\s*)?(\d{1,2})\b/i);if(m)return parseInt(m[1]);
        var v=(o.value||'');return /^\d{1,2}\b/.test(v)?parseInt(v):-1}
      function save(d){var nm=['save','apply','ok','submit','save changes','apply changes','confirm','حفظ','تطبيق','تأكيد'];
        var c=[].slice.call(d.querySelectorAll('button,input[type=button],input[type=submit],a')).filter(vis);
        for(var i=0;i<c.length;i++){if(nm.indexOf(norm(c[i]))>=0){c[i].click();return true}}return false}
      function menu(names){var ds=docs(window,[]);
        for(var k=0;k<names.length;k++){var n=names[(PT+k)%names.length];
          for(var j=0;j<ds.length;j++){
            var al=[].slice.call(ds[j].querySelectorAll('a,li,span,div,td')).filter(function(x){return vis(x)&&x.children.length<=1&&ok(norm(x),n)});
            if(al.length){al[0].click();return true}}}return false}
      var ds=docs(window,[]);
      for(var i=0;i<ds.length;i++){try{var p=ds[i].querySelector('input[type=password]');if(p&&vis(p)){r.pw=true;return r}}catch(e){}}
      for(var i=0;i<ds.length;i++){try{var d=ds[i];
        var tx='';try{tx=d.body.innerText||''}catch(e){}
        if(PH==='status'){
          if(/firmware version|software version|hardware version|system up ?time|device information/i.test(tx)){
            r.found=true;
            var vm=(tx+' '+(d.title||'')).match(/tp-?link|huawei|zte|d-?link|tenda|netgear|mercusys|asus|xiaomi|totolink|mikrotik|linksys|zyxel/i);
            r.info=JSON.stringify({vendor:vm?vm[0]:'',fw:g(tx,/(?:Firmware|Software) Version\s*:?\s*([^\n\r]+)/i),hw:g(tx,/Hardware Version\s*:?\s*([^\n\r]+)/i),
              up:g(tx,/(?:System Up ?Time|Up ?Time|Time Online)\s*:?\s*([^\n\r]+)/i),
              dns:g(tx,/DNS(?: Server)?\s*:?\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:\s*,?\s*[0-9]{1,3}(?:\.[0-9]{1,3}){3})?)/i)});
            return r}
        } else if(PH==='dns'){
          var dn=[].slice.call(d.querySelectorAll('input')).filter(function(x){
            return vis(x)&&!x.disabled&&!x.readOnly&&x.type!=='hidden'&&x.type!=='checkbox'&&x.type!=='radio'&&/dns/i.test(x.name+x.id+(x.placeholder||''))});
          if(dn.length){r.found=true;r.info=dn[0].value.trim();r.info2=dn[1]?dn[1].value.trim():'';
            if(DOCHG&&r.info!==DNS){setv(dn[0],DNS);if(dn[1])setv(dn[1],DNS2);save(d);r.changed=true}
            return r}
        } else if(PH==='clients'){
          if(/mac/i.test(tx)&&/client|device|host|station|connected|assigned|جهاز/i.test(tx)){
            var m=tx.match(/(?:[0-9a-f]{2}[-:]){5}[0-9a-f]{2}/gi)||[];var u={};m.forEach(function(x){u[x.toLowerCase()]=1});
            if(m.length){r.found=true;r.info=String(Object.keys(u).length);return r}}
        } else if(PH==='chan'){
          var ss=[].slice.call(d.querySelectorAll('select')).filter(function(x){return vis(x)&&!x.disabled}),cs=null,ws=null,ms=null;
          ss.forEach(function(s){var os=[].slice.call(s.options);
            var ns=os.map(num).filter(function(n){return n>=0});
            var j=os.map(function(x){return x.text.trim()}).join('|').toLowerCase();
            if(ns.indexOf(1)>=0&&ns.indexOf(6)>=0&&ns.indexOf(11)>=0&&ns.every(function(n){return n<=14}))cs=s;
            else if(j.indexOf('20')>=0&&j.indexOf('40')>=0)ws=s;
            else if(/11b|11g|11n|bgn/.test(j))ms=s});
          if(cs){r.found=true;var co=cs.options[cs.selectedIndex];r.info=co.text.trim();r.cn=num(co);
            r.wd=ws?ws.options[ws.selectedIndex].text.trim():'';r.md=ms?ms.options[ms.selectedIndex].text.trim():'';
            var chg=false,tq=-1;
            for(var q=0;q<cs.options.length;q++){
              if(CH===0){if(/auto/i.test(cs.options[q].text)){tq=q;break}}
              else if(num(cs.options[q])===CH){tq=q;break}}
            if(tq>=0&&tq!==cs.selectedIndex){cs.selectedIndex=tq;cs.dispatchEvent(new Event('change',{bubbles:true}));chg=true}
            if(WID&&ws){for(var q=0;q<ws.options.length;q++){
              var tt=ws.options[q].text.trim();var t2=tt.replace(/\s/g,'').toLowerCase();
              var hit=(WID==='20')?(t2==='20'||t2==='20mhz'):(tt===WID);
              if(hit){if(ws.selectedIndex!==q){ws.selectedIndex=q;ws.dispatchEvent(new Event('change',{bubbles:true}));chg=true;r.w=true}break}}}
            if(chg){save(d);r.changed=true}
            return r}
        } else if(PH==='reboot'){
          var rn=['reboot','restart','reboot router','restart router','reboot now','restart now','إعادة تشغيل','اعادة تشغيل','إعادة التشغيل'];
          var bt=[].slice.call(d.querySelectorAll('input[type=button],input[type=submit],button')).filter(vis).filter(function(x){return rn.indexOf(norm(x))>=0})[0];
          if(bt){bt.click();r.clicked=true;return r}
        }
      }catch(e){}}
      if(PH==='status')menu(['status','device information','device info','overview','system status','home']);
      else if(PH==='dns')menu(['dhcp settings','dhcp','lan settings','lan','local network','network','internet settings','internet','wan settings','wan']);
      else if(PH==='clients')menu(['dhcp clients list','dhcp clients','client list','connected devices','device list','attached devices','host list','clients']);
      else if(PH==='chan')menu(['wireless settings','wireless','wi-fi','wifi','wlan settings','wlan','2.4g wireless','basic settings']);
      else if(PH==='reboot')menu(['reboot','restart','system tools','system','maintenance','management','administration','tools']);
      return r
    })(${JSONObject.quote(ph)},${bestCh},${JSONObject.quote(bestDns)},${JSONObject.quote(bestDns2)},$dnsWorth,${JSONObject.quote(widParam())},$pt)
    """

    private val logoutJs = """
    (function(){function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
    docs(window,[]).forEach(function(d){try{[].slice.call(d.querySelectorAll('a,button,li,span,div,input')).forEach(function(x){
    var t=(x.innerText||x.value||x.id||'').trim();if(t.length<25&&/log\s*out|sign\s*out|logout|خروج/i.test(t)&&x.children.length<3){x.click()}})}catch(e){}})})()
    """

    // ================= تسلسل الفحص والإصلاح =================
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
        running = true; phase = "status"; ticks = 0; pt = 0; changed = false; oldUptime = false; devices = -1
        dnsDone = false; chanDone = false
        report.clear(); audit.clear()
        progress("✍ سجّل دخولك في صفحة الراوتر بالأسفل وسأبدأ الفحص تلقائياً...")
        ui.postDelayed({ step() }, 2000)
    }

    private fun moveTo(p: String) { phase = p; pt = 0 }

    private fun nextPhase() {
        val i = order.indexOf(phase)
        if (i >= 0 && i < order.size - 1) moveTo(order[i + 1])
        else {
            val needReboot = changed || (!restoring && (oldUptime || (lowSpeed && !lineProblem)))
            moveTo(if (needReboot) "reboot" else "done")
        }
    }

    private fun parseStatus(s: String) {
        val o = try { JSONObject(s) } catch (e: Exception) { return }
        val vendor = o.optString("vendor")
        if (vendor.isNotEmpty()) audit += "🏷 نوع الراوتر: $vendor"
        val fw = o.optString("fw"); val hw = o.optString("hw")
        if (fw.isNotEmpty() || hw.isNotEmpty()) audit += "📋 الراوتر: $hw | فيرموير: $fw"
        val up = o.optString("up")
        if (up.isNotEmpty()) {
            audit += "⏱ مدة التشغيل: $up"
            val d = Regex("(\\d+)\\s*day", RegexOption.IGNORE_CASE).find(up)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            if (d >= 14) { oldUptime = true; audit += "⚠ الراوتر يعمل منذ $d يوماً بلا إعادة تشغيل، وهذا يبطّئه (سأعيد تشغيله)" }
        }
        val dns = o.optString("dns")
        if (dns.isNotEmpty()) audit += "🌐 DNS الحالي في الراوتر: $dns"
    }

    private fun step() {
        ticks++
        if (ticks > 260) { finish("⚠ انتهت المهلة قبل إكمال كل الخطوات"); return }
        web.evaluateJavascript(js(phase)) { raw ->
            val r = try { JSONObject(raw ?: "") } catch (e: Exception) { null }
            var wait = 2500L
            var stop = false
            if (r != null && r.optBoolean("pw")) {
                progress("✍ بانتظار تسجيل دخولك في صفحة الراوتر...")
            } else if (r != null) {
                pt++
                val found = r.optBoolean("found")
                val sp = getSharedPreferences("nf", 0)
                when (phase) {
                    "status" -> {
                        if (found) { parseStatus(r.optString("info")); nextPhase() }
                        else if (pt > 12) { audit += "📋 تعذّر قراءة صفحة الحالة"; nextPhase() }
                        else progress("🔎 أفتح صفحة حالة الراوتر...")
                    }
                    "dns" -> {
                        if (found) {
                            dnsDone = true
                            if (r.optBoolean("changed")) {
                                changed = true; wait = 5000
                                if (!restoring) sp.edit().putString("bk_dns1", r.optString("info")).putString("bk_dns2", r.optString("info2")).apply()
                                report += "🧭 DNS: كان ${r.optString("info")} ← أصبح $bestDns" + (if (bestDns2.isNotEmpty()) " (ثانوي $bestDns2)" else "")
                            } else audit += "🧭 DNS ${r.optString("info")} مناسب (بدون تغيير)"
                            nextPhase()
                        } else if (pt > 30) { audit += "🧭 لم أجد إعدادات DNS (تخطّيت)"; nextPhase() }
                        else progress("🔎 أبحث عن إعدادات DNS...")
                    }
                    "clients" -> {
                        if (found) {
                            devices = r.optString("info").toIntOrNull() ?: -1
                            audit += if (devices > 8) "👥 الأجهزة المتصلة: $devices ⚠ عدد كبير قد يبطّئ الشبكة" else "👥 الأجهزة المتصلة: $devices"
                            nextPhase()
                        } else if (pt > 12) { audit += "👥 تعذّر قراءة الأجهزة المتصلة"; nextPhase() }
                        else progress("🔎 أقرأ الأجهزة المتصلة...")
                    }
                    "chan" -> {
                        if (found) {
                            chanDone = true
                            val cur = r.optString("info"); val md = r.optString("md"); val wd = r.optString("wd")
                            val cn = r.optInt("cn", -1)
                            audit += "📡 القناة الحالية: $cur | العرض: ${if (wd.isEmpty()) "—" else wd} | النمط: ${if (md.isEmpty()) "—" else md}"
                            if (r.optBoolean("changed")) {
                                changed = true; wait = 5000
                                if (!restoring) sp.edit().putInt("bk_ch", cn.coerceAtLeast(0)).putString("bk_wd", wd).apply()
                                if (cn != bestCh) report += "📡 القناة: كانت ${if (cn <= 0) "تلقائي" else cn.toString()} ← أصبحت ${if (bestCh == 0) "تلقائي" else bestCh.toString()}"
                                if (r.optBoolean("w")) report += "📶 عرض القناة ← ${if (restoring) restoreWid else "20MHz (أقل تداخلاً)"}"
                            } else audit += "📡 القناة والعرض مناسبان (بدون تغيير)"
                            nextPhase()
                        } else if (pt > 30) { audit += "📡 لم أجد إعدادات القناة (تخطّيت)"; nextPhase() }
                        else progress("🔎 أبحث عن إعدادات القناة...")
                    }
                    "reboot" -> {
                        if (r.optBoolean("clicked")) {
                            stop = true
                            report += if (changed) "🔄 إعادة تشغيل الراوتر لتطبيق التغييرات"
                                else if (oldUptime) "🔄 إعادة تشغيل الراوتر (يعمل منذ مدة طويلة)"
                                else "🔄 إعادة تشغيل الراوتر لأن السرعة منخفضة (تنظيف الاتصال)"
                            rebooting()
                        } else if (pt > 30) {
                            stop = true
                            finish("⚠ لم أجد زر إعادة التشغيل، أعد تشغيل الراوتر يدوياً")
                        } else progress("🔁 أنتقل لصفحة إعادة التشغيل...")
                    }
                }
                if (phase == "done") { stop = true; finish("✅ إعدادات السرعة سليمة، لا حاجة لإعادة التشغيل") }
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
                lastReport = (audit + report).joinToString("\n") + "\n\n⚠ لم أتأكد أن الراوتر أعاد التشغيل (لم ينقطع). أعد تشغيله يدوياً." + manual()
                say(lastReport); endRun()
                return@thread
            }
            var up = false
            var n = 0
            while (!up && n < 45) { if (tcp(gw, 80) >= 0) up = true else { Thread.sleep(4000); n++ } }
            if (!up) {
                lastReport = (audit + report).joinToString("\n") + "\n\n⚠ الراوتر لم يرجع بعد. أعد توصيل الواي فاي ثم افحص من جديد."
                say(lastReport); endRun()
                return@thread
            }
            say("✅ الراوتر رجع. جاري قياس السرعة بعد الإصلاح...")
            Thread.sleep(15000)
            val (after, _) = speedRetry()
            showFinal("✅ تمت إعادة تشغيل الراوتر فعلياً (انقطع ثم رجع)", after)
        }
    }

    private fun endRun() {
        running = false; restoring = false
        runOnUiThread { restoreBtn.isEnabled = hasBackup() }
    }

    private fun finish(msg: String) {
        progress("$msg\n🚪 جاري تسجيل الخروج من صفحة الراوتر...")
        web.evaluateJavascript(logoutJs, null)
        ui.postDelayed({
            CookieManager.getInstance().removeAllCookies(null)
            web.clearCache(true); web.loadUrl("about:blank")
            thread {
                Thread.sleep(4000)
                val (after, _) = speedRetry()
                showFinal("$msg\n🚪 تم تسجيل الخروج من الراوتر", after)
            }
        }, 4000)
    }

    // خطوات يدوية تُعرض تلقائياً لو واجهة الراوتر لم تُفهم آلياً
    private fun manual(): String {
        if (restoring) return ""
        val s = mutableListOf<String>()
        if (dnsWorth && !dnsDone) s += "• DNS: من إعدادات الراوتر (DHCP أو LAN أو WAN) اجعل الأساسي $bestDns والثانوي $bestDns2"
        if (!chanDone) s += "• القناة: من Wireless ← 2.4GHz اجعل Channel = $bestCh" + (if (crowded) " وعرض القناة 20MHz" else "")
        return if (s.isEmpty()) "" else "\n\n🖐 خطوات يدوية (واجهة راوترك مختلفة عن المتوقع):\n" + s.joinToString("\n")
    }

    private fun advice(after: Double): String = when {
        after in 0.0..5.0 -> "⚠ السرعة ما زالت منخفضة بعد الضبط، يعني السبب خارج الراوتر: خط شركة الإنترنت أو الباقة. اضغط «نسخ التقرير» وأرسله للشركة واطلب فحص الخط."
        beforeSpeed > 0 && after > beforeSpeed * 1.3 -> "✅ تحسّنت السرعة بشكل واضح بعد الإصلاح."
        devices > 8 -> "💡 عدد الأجهزة المتصلة كبير ($devices). افصل غير المستخدم من الراوتر."
        else -> "💡 الشبكة مستقرة. لو ما زلت تشعر بالبطء جرّب الاقتراب من الراوتر أو استخدام كابل."
    }

    private fun showFinal(msg: String, after: Double) {
        val sp = getSharedPreferences("nf", 0)
        val prev = sp.getFloat("last", -1f)
        val sb = StringBuilder()
        sb.append(msg).append("\n\n")
        if (audit.isNotEmpty()) sb.append("🧪 فحص الراوتر:\n").append(audit.joinToString("\n")).append("\n\n")
        if (report.isNotEmpty()) sb.append("🛠 ما تم تنفيذه:\n").append(report.joinToString("\n")).append("\n\n")
        sb.append(diagText).append("\n\n")
        sb.append("📈 السرعة قبل: ${fmt(beforeSpeed)}\n📈 السرعة بعد: ${fmt(after)}\n")
        if (prev > 0) sb.append("🕘 آخر فحص سابق: ${fmt(prev.toDouble())}\n")
        if (after > 0) sp.edit().putFloat("last", after.toFloat()).apply()
        sb.append("\n🎯 التشخيص النهائي: $primary\n").append(advice(after))
        sb.append(manual())
        if (hasBackup()) sb.append("\n\n↩ تقدر ترجّع إعدادات الراوتر السابقة بزر «استرجاع».")
        lastReport = sb.toString()
        say(lastReport)
        endRun()
    }
}
