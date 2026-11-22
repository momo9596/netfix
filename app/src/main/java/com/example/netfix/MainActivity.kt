package com.example.netfix

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.wifi.WifiManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.webkit.CookieManager
import android.webkit.HttpAuthHandler
import android.webkit.JsResult
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

data class ChanScan(val best: Int, val count: Int, val curBad: Boolean)

@Suppress("DEPRECATION")
class MainActivity : Activity() {
    // ---------- ألوان التصميم ----------
    private val cBg = Color.parseColor("#0B1220")
    private val cCard = Color.parseColor("#111B30")
    private val cLine = Color.parseColor("#1F2C48")
    private val cText = Color.parseColor("#E8EEF9")
    private val cMuted = Color.parseColor("#8A9AB8")
    private val cCyan = Color.parseColor("#22D3EE")
    private val cBlue = Color.parseColor("#3B82F6")
    private val cGreen = Color.parseColor("#34D399")
    private val cAmber = Color.parseColor("#FBBF24")
    private val cRed = Color.parseColor("#F87171")

    // ---------- عناصر الواجهة ----------
    private lateinit var ip: EditText
    private lateinit var userEt: EditText
    private lateinit var passEt: EditText
    private lateinit var web: WebView
    private lateinit var dashScroll: ScrollView
    private lateinit var startBtn: Button
    private lateinit var fixBtn: Button
    private lateinit var restoreBtn: Button
    private lateinit var chip: TextView
    private lateinit var bar: ProgressBar
    private lateinit var beforeTv: TextView
    private lateinit var afterTv: TextView
    private lateinit var gainTv: TextView
    private lateinit var logView: TextView
    private lateinit var reportCard: LinearLayout
    private lateinit var reportView: TextView
    private lateinit var liveWeb: TextView
    private lateinit var modeBtn: TextView
    private val stepViews = mutableListOf<TextView>()
    private val stepNames = listOf(
        "فحص الشبكة والسرعة", "قياس أسرع DNS", "مسح القنوات", "الدخول لصفحة الراوتر",
        "تطبيق DNS", "ضبط القناة والعرض", "إعادة تشغيل الراوتر", "قياس السرعة بعد الإصلاح"
    )
    private val stepState = IntArray(8)
    private var webFull = false

    // ---------- الحالة ----------
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
    private var diagBusy = false
    private var changed = false
    private var restoring = false
    private var restoreWid = ""
    private var dnsDone = false
    private var chanDone = false
    private var devices = -1
    private var phase = "status"
    private var ticks = 0
    private var pt = 0
    private var loginTries = 0
    private var rebootTry = 0
    private var gwIp = ""
    private var primary = ""
    private var diagText = ""
    private var lastReport = ""
    private var lastLog = ""
    private val logLines = mutableListOf<String>()
    private val report = mutableListOf<String>()
    private val audit = mutableListOf<String>()
    private val order = listOf("status", "dns", "clients", "chan")
    private val ui = Handler(Looper.getMainLooper())

    private val dnsCandidates = listOf(
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "94.140.14.14", "185.228.168.9"
    )
    private val testDomains = listOf(
        "google.com", "youtube.com", "facebook.com", "wikipedia.org",
        "amazon.com", "instagram.com", "whatsapp.com", "tiktok.com"
    )

    // ================= بناء الواجهة =================
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun bg(color: Int, r: Int = 16, stroke: Int = 0) = GradientDrawable().apply {
        setColor(color); cornerRadius = dp(r).toFloat()
        if (stroke != 0) setStroke(dp(1), stroke)
    }

    private fun label(t: String, size: Float = 14f, color: Int = cText, bold: Boolean = false) = TextView(this).apply {
        text = t; textSize = size; setTextColor(color)
        if (bold) setTypeface(typeface, Typeface.BOLD)
    }

    private fun cardBox() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = bg(cCard, 18, cLine)
        setPadding(dp(14), dp(12), dp(14), dp(12))
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) }
    }

    private fun field(hint: String, pass: Boolean = false) = EditText(this).apply {
        this.hint = hint; setHintTextColor(cMuted); setTextColor(cText); textSize = 14f
        setSingleLine(); background = bg(Color.parseColor("#0D1628"), 12, cLine)
        setPadding(dp(12), dp(10), dp(12), dp(10))
        if (pass) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) }
    }

    private fun gradBtn(t: String, c1: Int, c2: Int) = Button(this).apply {
        text = t; isAllCaps = false; textSize = 16f; setTextColor(Color.WHITE)
        setTypeface(typeface, Typeface.BOLD)
        background = GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, intArrayOf(c1, c2)).apply { cornerRadius = dp(16).toFloat() }
        layoutParams = LinearLayout.LayoutParams(-1, dp(54)).apply { topMargin = dp(12) }
    }

    private fun smallBtn(t: String) = Button(this).apply {
        text = t; isAllCaps = false; textSize = 12f; setTextColor(cText)
        background = bg(Color.parseColor("#17233D"), 12, cLine)
        layoutParams = LinearLayout.LayoutParams(0, dp(44), 1f).apply { marginEnd = dp(6) }
    }

    private fun toolChip(t: String) = TextView(this).apply {
        text = t; textSize = 14f; setTextColor(cText); gravity = Gravity.CENTER
        background = bg(Color.parseColor("#1B2A47"), 10)
        setPadding(dp(12), dp(6), dp(12), dp(6))
        layoutParams = LinearLayout.LayoutParams(-2, -2).apply { marginStart = dp(6) }
    }

    private fun statBox(title: String, color: Int): Pair<LinearLayout, TextView> {
        val v = label("—", 22f, color, true).apply { gravity = Gravity.CENTER }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
            background = bg(Color.parseColor("#0D1628"), 14)
            setPadding(dp(6), dp(10), dp(6), dp(10))
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f).apply { marginEnd = dp(6) }
            addView(label(title, 11f, cMuted).apply { gravity = Gravity.CENTER })
            addView(v)
            addView(label("Mbps", 10f, cMuted).apply { gravity = Gravity.CENTER })
        }
        return Pair(box, v)
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), 1)
        window.statusBarColor = cBg
        window.navigationBarColor = cBg

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setBackgroundColor(cBg)
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        dashScroll = ScrollView(this).apply { layoutParams = LinearLayout.LayoutParams(-1, 0, 1f) }
        val dash = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(36), dp(14), dp(14))
        }

        // رأس الصفحة
        val header = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        val titles = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        titles.addView(label("NetFix Pro", 26f, cText, true))
        titles.addView(label("تشخيص وتسريع الإنترنت تلقائياً", 12f, cMuted))
        chip = label("● جاهز", 12f, cGreen, true).apply {
            setPadding(dp(12), dp(6), dp(12), dp(6)); background = bg(Color.parseColor("#13281F"), 20)
        }
        header.addView(titles); header.addView(chip)
        dash.addView(header)

        // بيانات الراوتر
        val inCard = cardBox()
        inCard.addView(label("🌐 بيانات الراوتر", 13f, cMuted))
        ip = field("عنوان الراوتر (IP)").apply { setText(gateway()) }
        userEt = field("اسم المستخدم (اختياري للدخول التلقائي)")
        passEt = field("كلمة المرور (اختياري، لا تُحفظ)", true)
        inCard.addView(ip); inCard.addView(userEt); inCard.addView(passEt)
        dash.addView(inCard)

        // الأزرار
        startBtn = gradBtn("🚀 ابدأ الفحص والإصلاح", cCyan, cBlue)
        startBtn.setOnClickListener {
            if (running || diagBusy) return@setOnClickListener
            startBtn.isEnabled = false
            openRouter(); diagnose(true)
        }
        dash.addView(startBtn)
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) }
        }
        fixBtn = smallBtn("🔁 إعادة المحاولة").apply { isEnabled = false; setOnClickListener { openRouter(); applyFixes() } }
        restoreBtn = smallBtn("↩ استرجاع").apply { isEnabled = hasBackup(); setOnClickListener { restoreBackup() } }
        val copyBtn = smallBtn("📋 نسخ التقرير").apply { setOnClickListener { copyReport() } }
        row.addView(fixBtn); row.addView(restoreBtn); row.addView(copyBtn)
        dash.addView(row)

        // مراحل العمل
        val stepsCard = cardBox()
        stepsCard.addView(label("📋 مراحل العمل", 13f, cMuted))
        bar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100; progress = 0
            progressTintList = ColorStateList.valueOf(cCyan)
            layoutParams = LinearLayout.LayoutParams(-1, dp(8)).apply { topMargin = dp(8); bottomMargin = dp(6) }
        }
        stepsCard.addView(bar)
        stepNames.forEachIndexed { i, n ->
            val tv = label("⚪  $n", 14f, cMuted).apply { setPadding(0, dp(5), 0, dp(5)) }
            stepViews.add(tv); stepsCard.addView(tv)
            stepState[i] = 0
        }
        dash.addView(stepsCard)

        // مقارنة السرعة
        val spCard = cardBox()
        spCard.addView(label("📈 السرعة", 13f, cMuted))
        val spRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) }
        }
        val (b1, t1) = statBox("قبل", cAmber); beforeTv = t1
        val (b2, t2) = statBox("بعد", cGreen); afterTv = t2
        val (b3, t3) = statBox("التحسّن", cMuted); gainTv = t3
        spRow.addView(b1); spRow.addView(b2); spRow.addView(b3)
        spCard.addView(spRow)
        dash.addView(spCard)

        // السجل المباشر
        val logCard = cardBox()
        logCard.addView(label("🛰 ما يحدث الآن", 13f, cMuted))
        logView = label("بانتظار البدء...", 12f, Color.parseColor("#A7F3D0")).apply {
            typeface = Typeface.MONOSPACE; setPadding(0, dp(8), 0, 0)
        }
        logCard.addView(logView)
        dash.addView(logCard)

        // التقرير النهائي
        reportCard = cardBox().apply { visibility = View.GONE }
        reportCard.addView(label("🧾 التقرير", 13f, cMuted))
        reportView = label("", 13f, cText).apply { setPadding(0, dp(8), 0, 0); setTextIsSelectable(true) }
        reportCard.addView(reportView)
        dash.addView(reportCard)

        dashScroll.addView(dash)

        // شاشة الراوتر المباشرة (قابلة للتكبير والتصغير)
        val webPanel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(cCard)
            layoutParams = LinearLayout.LayoutParams(-1, 0, 1.1f)
        }
        val bar2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(10), dp(6), dp(10), dp(6))
        }
        liveWeb = label("🖥 شاشة الراوتر المباشرة", 12f, cCyan, true).apply {
            setSingleLine(); ellipsize = android.text.TextUtils.TruncateAt.END
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        }
        val zOut = toolChip("➖"); val zIn = toolChip("➕")
        modeBtn = toolChip("⛶ تكبير")
        zOut.setOnClickListener { web.zoomOut() }
        zIn.setOnClickListener { web.zoomIn() }
        modeBtn.setOnClickListener {
            webFull = !webFull
            dashScroll.visibility = if (webFull) View.GONE else View.VISIBLE
            modeBtn.text = if (webFull) "⤓ اللوحة" else "⛶ تكبير"
        }
        bar2.addView(liveWeb); bar2.addView(zOut); bar2.addView(zIn); bar2.addView(modeBtn)
        webPanel.addView(bar2)

        web = WebView(this).apply {
            settings.javaScriptEnabled = true; settings.domStorageEnabled = true
            settings.setSupportZoom(true); settings.builtInZoomControls = true
            settings.displayZoomControls = false
            settings.useWideViewPort = true; settings.loadWithOverviewMode = true
            setBackgroundColor(Color.WHITE)
            layoutParams = LinearLayout.LayoutParams(-1, 0, 1f)
            webChromeClient = object : WebChromeClient() {
                private fun risky(m: String): Boolean {
                    val ic = RegexOption.IGNORE_CASE
                    val rb = Regex("reboot|restart|إعادة تشغيل|اعادة تشغيل", ic).containsMatchIn(m)
                    return Regex("factory|مصنع", ic).containsMatchIn(m) ||
                        (!rb && Regex("default|restore|reset|افتراض", ic).containsMatchIn(m))
                }
                override fun onJsConfirm(v: WebView, url: String, message: String, result: JsResult): Boolean {
                    if (risky(message)) result.cancel() else result.confirm(); return true
                }
                override fun onJsAlert(v: WebView, url: String, message: String, result: JsResult): Boolean { result.confirm(); return true }
            }
        }
        webPanel.addView(web)

        root.addView(dashScroll); root.addView(webPanel)
        setContentView(root)
    }

    // ================= السجل والحالة =================
    private fun log(s: String) {
        if (s == lastLog) return
        lastLog = s
        val t = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        synchronized(logLines) {
            logLines.add("$t  $s")
            while (logLines.size > 200) logLines.removeAt(0)
        }
        val shown = synchronized(logLines) { logLines.takeLast(10).joinToString("\n") }
        runOnUiThread { logView.text = shown; liveWeb.text = "🖥 $s" }
    }

    private fun say(s: String) = log(s)
    private fun progress(extra: String) = log(extra)

    private fun setChip(t: String, color: Int) = runOnUiThread { chip.text = t; chip.setTextColor(color) }

    private fun setStep(i: Int, st: Int) {
        stepState[i] = st
        runOnUiThread {
            val icon = when (st) { 1 -> "⏳"; 2 -> "✅"; 3 -> "⏭"; else -> "⚪" }
            val col = when (st) { 1 -> cAmber; 2 -> cGreen; else -> cMuted }
            stepViews[i].text = "$icon  ${stepNames[i]}"
            stepViews[i].setTextColor(col)
            bar.progress = stepState.count { it == 2 || it == 3 } * 100 / stepState.size
        }
    }

    private fun resetUi() {
        for (i in stepState.indices) setStep(i, 0)
        runOnUiThread {
            beforeTv.text = "—"; afterTv.text = "—"; gainTv.text = "—"; gainTv.setTextColor(cMuted)
            reportCard.visibility = View.GONE
        }
    }

    private fun setReport(t: String) = runOnUiThread { reportView.text = t; reportCard.visibility = View.VISIBLE }

    private fun mb(x: Double) = if (x < 0) "—" else "%.1f".format(x)

    private fun copyReport() {
        val text = if (lastReport.isNotEmpty()) lastReport else synchronized(logLines) { logLines.joinToString("\n") }
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
        if (running || diagBusy) return
        val sp = getSharedPreferences("nf", 0)
        if (!hasBackup()) { Toast.makeText(this, "لا توجد نسخة احتياطية", Toast.LENGTH_SHORT).show(); return }
        restoring = true
        dnsWorth = sp.contains("bk_dns1")
        bestDns = sp.getString("bk_dns1", "") ?: ""
        bestDns2 = sp.getString("bk_dns2", "") ?: ""
        bestCh = sp.getInt("bk_ch", 0)
        restoreWid = sp.getString("bk_wd", "") ?: ""
        crowded = false
        resetUi()
        log("↩ استرجاع الإعدادات السابقة للراوتر")
        openRouter()
        applyFixes()
    }

    // ================= أدوات القياس الحقيقية =================
    private fun tcp(host: String, port: Int): Long = try {
        val t = System.nanoTime()
        Socket().use { it.connect(InetSocketAddress(host, port), 1500) }
        (System.nanoTime() - t) / 1_000_000
    } catch (e: Exception) { -1 }

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

    private fun ispDns(): List<String> {
        val d = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).dhcpInfo
        fun ipOf(g: Int) = if (g == 0) null else "%d.%d.%d.%d".format(g and 255, g shr 8 and 255, g shr 16 and 255, g shr 24 and 255)
        return listOfNotNull(ipOf(d.dns1), ipOf(d.dns2))
    }

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
        diagBusy = true
        gwIp = ip.text.toString().trim()
        fixBtn.isEnabled = false
        resetUi()
        setChip("● جارٍ العمل", cAmber)
        val gw = gwIp
        thread {
            try {
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                val info = wm.connectionInfo
                val is24 = info.frequency in 2400..2500
                val curCh = if (is24) (info.frequency - 2407) / 5 else (info.frequency - 5000) / 5

                setStep(0, 1)
                say("⏳ فحص الاتصال بالراوتر..."); val (gwMs, gwLoss) = stats({ tcp(gw, 80) })
                say("⏳ فحص استقرار الإنترنت (20 قياساً)..."); val (netMs, jitter, netLoss) = pingStats(20)
                say("⏳ اختبار السرعة (قد يستغرق دقيقة)..."); val (sp, loaded) = speedRetry(); beforeSpeed = sp
                runOnUiThread { beforeTv.text = mb(sp) }
                setStep(0, 2)
                lowSpeed = sp in 0.0..5.0
                lineProblem = netLoss > 5 || netMs > 120
                val bloat = loaded > 0 && netMs > 0 && loaded - netMs > 150

                setStep(1, 1)
                say("⏳ قياس أسرع DNS فعلياً (8 مواقع × كل سيرفر)...")
                val ranked = benchmarkDns()
                chooseDns(ranked)
                say(dnsReport)
                setStep(1, 2)

                setStep(2, 1)
                say("⏳ مسح القنوات (3 مرات)...")
                val cs = pickChannel(wm, curCh)
                bestCh = cs.best
                crowded = is24 && (cs.count > 5 || cs.curBad)
                say("📡 أفضل قناة: $bestCh (${cs.count} شبكة مجاورة)")
                setStep(2, 2)

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
                setReport(diagText + "\n\n🎯 الخطة: قناة $bestCh + DNS $bestDns")
                diagBusy = false
                runOnUiThread { fixBtn.isEnabled = true; if (auto) applyFixes() else startBtn.isEnabled = true }
            } catch (e: Exception) {
                diagBusy = false
                log("❌ خطأ أثناء الفحص: ${e.message} (تأكد من تفعيل الموقع وصلاحيات الواي فاي)")
                setChip("● خطأ", cRed)
                runOnUiThread { startBtn.isEnabled = true }
            }
        }
    }

    // ================= سكربت الراوتر (بحث ذكي + تمييز مرئي للعناصر) =================
    private fun widParam(): String = if (restoring) restoreWid else if (crowded) "20" else ""

    private fun q(s: String): String = JSONObject.quote(s)

    private fun js(ph: String): String {
        val user = userEt.text.toString()
        val pass = if (loginTries < 2) passEt.text.toString() else ""
        return """
    (function(PH,CH,DNS,DNS2,DOCHG,WID,PT,USER,PASS){
      var r={found:false,changed:false,pw:false,clicked:false,w:false,info:'',info2:'',cn:-1,wd:'',md:'',dbg:''};
      function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
      function vis(e){return e.offsetParent!==null}
      function hl(e){try{e.style.outline='3px solid #22d3ee';e.style.backgroundColor='#fef9c3';e.scrollIntoView({block:'center'})}catch(x){}}
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
            if(al.length){hl(al[0]);al[0].click();return true}}}return false}
      function login(dd,p){try{
        var us=[].slice.call(dd.querySelectorAll('input')).filter(function(x){return vis(x)&&!x.readOnly&&(x.type==='text'||x.type==='email'||x.type==='')});
        if(us.length&&USER){setv(us[0],USER);hl(us[0])}
        setv(p,PASS);hl(p);
        setTimeout(function(){
          var ln=['login','log in','sign in','ok','submit','enter','دخول','تسجيل الدخول'];
          var bs=[].slice.call(dd.querySelectorAll('button,input[type=button],input[type=submit],a,span,div')).filter(function(x){return vis(x)&&x.children.length<=1&&ln.indexOf(norm(x))>=0});
          if(bs.length){bs[0].click()}else{p.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',keyCode:13,bubbles:true}))}
        },600)}catch(e){}}
      var ds=docs(window,[]);
      for(var i=0;i<ds.length;i++){try{var p=ds[i].querySelector('input[type=password]');
        if(p&&vis(p)){r.pw=true;if(PASS){login(ds[i],p)}return r}}catch(e){}}
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
          if(dn.length){r.found=true;r.info=dn[0].value.trim();r.info2=dn[1]?dn[1].value.trim():'';hl(dn[0]);if(dn[1])hl(dn[1]);
            if(DOCHG&&r.info!==DNS){setv(dn[0],DNS);if(dn[1])setv(dn[1],DNS2);setTimeout(function(){save(d)},700);r.changed=true}
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
            var chg=false,tq=-1;hl(cs);
            for(var q=0;q<cs.options.length;q++){
              if(CH===0){if(/auto/i.test(cs.options[q].text)){tq=q;break}}
              else if(num(cs.options[q])===CH){tq=q;break}}
            if(tq>=0&&tq!==cs.selectedIndex){cs.selectedIndex=tq;cs.dispatchEvent(new Event('change',{bubbles:true}));chg=true}
            if(WID&&ws){for(var q=0;q<ws.options.length;q++){
              var tt=ws.options[q].text.trim();var t2=tt.replace(/\s/g,'').toLowerCase();
              var hit=(WID==='20')?(t2==='20'||t2==='20mhz'):(tt===WID);
              if(hit){hl(ws);if(ws.selectedIndex!==q){ws.selectedIndex=q;ws.dispatchEvent(new Event('change',{bubbles:true}));chg=true;r.w=true}break}}}
            if(chg){setTimeout(function(){save(d)},700);r.changed=true}
            return r}
        } else if(PH==='reboot'){
          var rn=['reboot','restart','reboot router','restart router','reboot now','restart now','إعادة تشغيل','اعادة تشغيل','إعادة التشغيل'];
          var cands=[].slice.call(d.querySelectorAll('input[type=button],input[type=submit],button,a,span,div,td,li')).filter(function(x){return vis(x)&&x.children.length<=1&&rn.indexOf(norm(x))>=0});
          var bt=cands.filter(function(x){return /^(button|input)$/i.test(x.tagName)})[0];
          if(!bt){bt=cands.filter(function(x){return /btn|button/i.test(x.className+'')||x.getAttribute('role')==='button'})[0]}
          if(!bt&&PT>=8&&cands.length){bt=cands[cands.length-1]}
          if(bt){hl(bt);setTimeout(function(){bt.click()},700);r.clicked=true;return r}
          if(PT>=10){r.dbg+=[].slice.call(d.querySelectorAll('a,button,input[type=button],input[type=submit]')).filter(vis).map(function(x){return norm(x)}).filter(function(t){return t&&t.length<30}).slice(0,25).join(' | ')+' || '}
        }
      }catch(e){}}
      if(PH==='status')menu(['status','device information','device info','overview','system status','home']);
      else if(PH==='dns')menu(['dhcp settings','dhcp','lan settings','lan','local network','network','internet settings','internet','wan settings','wan']);
      else if(PH==='clients')menu(['dhcp clients list','dhcp clients','client list','connected devices','device list','attached devices','host list','clients']);
      else if(PH==='chan')menu(['wireless settings','wireless','wi-fi','wifi','wlan settings','wlan','2.4g wireless','basic settings']);
      else if(PH==='reboot')menu(['reboot','restart','system tools','system','maintenance','management','administration','tools']);
      return r
    })(${q(ph)},${bestCh},${q(bestDns)},${q(bestDns2)},$dnsWorth,${q(widParam())},$pt,${q(user)},${q(pass)})
    """
    }

    // نوافذ التأكيد المخصصة (HTML) بعد الضغط على Reboot
    private val confirmJs = """
    (function(){function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
    var ok=['ok','yes','confirm','continue','نعم','موافق','تأكيد','reboot','restart'];
    docs(window,[]).forEach(function(d){try{var c=[].slice.call(d.querySelectorAll('button,input[type=button],input[type=submit],a,span,div')).filter(function(x){
      return x.offsetParent!==null&&x.children.length<=1&&ok.indexOf((x.innerText||x.value||'').trim().toLowerCase())>=0});
      if(c.length){c[c.length-1].click()}}catch(e){}})})()
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
                val u0 = userEt.text.toString(); val p0 = passEt.text.toString()
                if (u0.isNotEmpty() && p0.isNotEmpty() && loginTries < 2) {
                    loginTries++; h.proceed(u0, p0); return
                }
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
        dnsDone = false; chanDone = false; loginTries = 0; rebootTry = 0
        gwIp = ip.text.toString().trim()
        report.clear(); audit.clear()
        setChip("● جارٍ العمل", cAmber)
        runOnUiThread { startBtn.isEnabled = false }
        setStep(3, 1)
        log(if (passEt.text.isNotEmpty()) "🔐 سأسجّل الدخول تلقائياً ثم أبدأ الضبط" else "✍ سجّل دخولك في صفحة الراوتر بالأسفل وسأكمل تلقائياً")
        ui.postDelayed({ step() }, 2000)
    }

    private fun moveTo(p: String) {
        phase = p; pt = 0; loginTries = 0
        when (p) {
            "dns" -> { setStep(3, 2); setStep(4, 1) }
            "clients" -> setStep(4, if (dnsDone) 2 else 3)
            "chan" -> setStep(5, 1)
            "reboot" -> { setStep(5, if (chanDone) 2 else 3); setStep(6, 1) }
            "done" -> { setStep(5, if (chanDone) 2 else 3); setStep(6, 3) }
        }
    }

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
        if (vendor.isNotEmpty()) { audit += "🏷 نوع الراوتر: $vendor"; log("🏷 تم التعرّف على الراوتر: $vendor") }
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
                loginTries++
                log(if (passEt.text.isNotEmpty() && loginTries <= 2) "🔐 أسجّل الدخول تلقائياً..." else "✍ بانتظار تسجيل دخولك في صفحة الراوتر...")
            } else if (r != null) {
                pt++
                val found = r.optBoolean("found")
                val sp = getSharedPreferences("nf", 0)
                when (phase) {
                    "status" -> {
                        if (found) { log("✅ قرأت صفحة حالة الراوتر"); parseStatus(r.optString("info")); nextPhase() }
                        else if (pt > 12) { audit += "📋 تعذّر قراءة صفحة الحالة"; log("⏭ تخطّي صفحة الحالة"); nextPhase() }
                        else log("🔎 أفتح صفحة حالة الراوتر...")
                    }
                    "dns" -> {
                        if (found) {
                            dnsDone = true
                            if (r.optBoolean("changed")) {
                                changed = true; wait = 5000
                                if (!restoring) sp.edit().putString("bk_dns1", r.optString("info")).putString("bk_dns2", r.optString("info2")).apply()
                                val m = "🧭 DNS: كان ${r.optString("info")} ← أصبح $bestDns" + (if (bestDns2.isNotEmpty()) " (ثانوي $bestDns2)" else "")
                                report += m; log(m)
                            } else { audit += "🧭 DNS ${r.optString("info")} مناسب (بدون تغيير)"; log("🧭 DNS الحالي مناسب، لا تغيير") }
                            nextPhase()
                        } else if (pt > 30) { audit += "🧭 لم أجد إعدادات DNS (تخطّيت)"; log("⏭ لم أجد إعدادات DNS"); nextPhase() }
                        else log("🔎 أبحث عن إعدادات DNS...")
                    }
                    "clients" -> {
                        if (found) {
                            devices = r.optString("info").toIntOrNull() ?: -1
                            audit += if (devices > 8) "👥 الأجهزة المتصلة: $devices ⚠ عدد كبير قد يبطّئ الشبكة" else "👥 الأجهزة المتصلة: $devices"
                            log("👥 الأجهزة المتصلة: $devices")
                            nextPhase()
                        } else if (pt > 12) { audit += "👥 تعذّر قراءة الأجهزة المتصلة"; nextPhase() }
                        else log("🔎 أقرأ الأجهزة المتصلة...")
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
                                if (cn != bestCh) {
                                    val m = "📡 القناة: كانت ${if (cn <= 0) "تلقائي" else cn.toString()} ← أصبحت ${if (bestCh == 0) "تلقائي" else bestCh.toString()}"
                                    report += m; log(m)
                                }
                                if (r.optBoolean("w")) { val m = "📶 عرض القناة ← ${if (restoring) restoreWid else "20MHz (أقل تداخلاً)"}"; report += m; log(m) }
                            } else { audit += "📡 القناة والعرض مناسبان (بدون تغيير)"; log("📡 القناة والعرض مناسبان") }
                            nextPhase()
                        } else if (pt > 30) { audit += "📡 لم أجد إعدادات القناة (تخطّيت)"; log("⏭ لم أجد إعدادات القناة"); nextPhase() }
                        else log("🔎 أبحث عن إعدادات القناة...")
                    }
                    "reboot" -> {
                        if (r.optBoolean("clicked")) {
                            stop = true
                            val m = if (changed) "🔄 إعادة تشغيل الراوتر لتطبيق التغييرات"
                                else if (oldUptime) "🔄 إعادة تشغيل الراوتر (يعمل منذ مدة طويلة)"
                                else "🔄 إعادة تشغيل الراوتر لأن السرعة منخفضة (تنظيف الاتصال)"
                            if (!report.contains(m)) report += m
                            rebooting(false)
                        } else if (pt > 30) {
                            stop = true
                            rebooting(true)
                        } else {
                            if (pt == 12) log("🧩 العناصر الظاهرة: ${r.optString("dbg").take(350)}")
                            log("🔁 أبحث عن زر إعادة التشغيل...")
                        }
                    }
                }
                if (phase == "done") { stop = true; finish("✅ إعدادات السرعة سليمة، لا حاجة لإعادة التشغيل") }
            }
            if (!stop) ui.postDelayed({ step() }, wait)
        }
    }

    // مراقبة إعادة التشغيل: ضغط تلقائي + تأكيد + إعادة محاولة + وضع المراقبة اليدوية
    private fun rebooting(manualMode: Boolean) {
        val gw = gwIp
        log(if (manualMode) "🖐 اضغط Reboot بنفسك في صفحة الراوتر (كبّرها بإصبعين)، وأنا أراقب وأكمل تلقائياً" else "🔄 تم الضغط على Reboot، أنتظر انقطاع الراوتر...")
        thread {
            var down = false
            var i = 0
            val limit = if (manualMode) 40 else 12
            while (!down && i < limit) {
                Thread.sleep(3000)
                if (!manualMode && i < 4) runOnUiThread { web.evaluateJavascript(confirmJs, null) }
                if (tcp(gw, 80) < 0) down = true
                i++
            }
            if (!down) {
                if (!manualMode && rebootTry < 2) {
                    rebootTry++
                    log("⚠ الراوتر لم ينقطع، أعيد المحاولة ($rebootTry/2)")
                    runOnUiThread { moveTo("reboot"); ui.postDelayed({ step() }, 800) }
                    return@thread
                }
                if (!manualMode) { runOnUiThread { rebooting(true) }; return@thread }
                setStep(6, 3)
                lastReport = (audit + report).joinToString("\n") + "\n\n⚠ لم أتأكد أن الراوتر أعاد التشغيل. أعد تشغيله يدوياً." + manual()
                setReport(lastReport); setChip("● يحتاج تدخل", cAmber); endRun()
                return@thread
            }
            log("📴 الراوتر انقطع، أنتظر رجوعه...")
            var up = false
            var n = 0
            while (!up && n < 45) { if (tcp(gw, 80) >= 0) up = true else { Thread.sleep(4000); n++ } }
            if (!up) {
                setStep(6, 3)
                lastReport = (audit + report).joinToString("\n") + "\n\n⚠ الراوتر لم يرجع بعد. أعد توصيل الواي فاي ثم افحص من جديد."
                setReport(lastReport); setChip("● يحتاج تدخل", cAmber); endRun()
                return@thread
            }
            setStep(6, 2)
            setStep(7, 1)
            log("✅ الراوتر رجع. أقيس السرعة بعد الإصلاح...")
            Thread.sleep(15000)
            val (after, _) = speedRetry()
            showFinal("✅ تمت إعادة تشغيل الراوتر فعلياً (انقطع ثم رجع)", after)
        }
    }

    private fun endRun() {
        running = false; restoring = false
        runOnUiThread { restoreBtn.isEnabled = hasBackup(); startBtn.isEnabled = true }
    }

    private fun finish(msg: String) {
        log(msg)
        setStep(7, 1)
        log("🚪 جاري تسجيل الخروج من صفحة الراوتر...")
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

        runOnUiThread {
            afterTv.text = mb(after)
            if (beforeSpeed > 0 && after > 0) {
                val pct = (after - beforeSpeed) / beforeSpeed * 100
                gainTv.text = (if (pct >= 0) "+" else "") + "%.0f%%".format(pct)
                gainTv.setTextColor(if (pct >= 0) cGreen else cRed)
            }
        }
        setStep(7, 2)
        setReport(lastReport)
        setChip("● اكتمل", cGreen)
        log("🏁 انتهى. التقرير الكامل في الأعلى")
        endRun()
    }
}
