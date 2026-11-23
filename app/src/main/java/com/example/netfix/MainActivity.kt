package com.example.netfix

import android.Manifest
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.http.SslError
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.HttpAuthHandler
import android.webkit.JsResult
import android.webkit.RenderProcessGoneDetail
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
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
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

// ---------- نماذج البيانات ----------
data class ChanScan(val ok: Boolean, val count: Int, val loads: Map<Int, Double>, val note: String)
data class PingRes(val avg: Double, val jitter: Double, val loss: Int, val method: String)
data class DnsRes(val server: String, val avg: Double, val median: Double, val success: Int, val score: Double)
data class Reach(val gw: Boolean, val tcp: Boolean, val udp: Boolean, val http: Boolean) {
    val internet: Boolean get() = tcp || udp || http
}
data class Speed(val down: Double, val up: Double, val loaded: Double)
data class Snap(val reach: Reach, val gwMs: Double, val gwLoss: Int, val ping: PingRes, val sp: Speed)
class Plan {
    var dns = false; var d1 = ""; var d2 = ""
    var chan = false; var ch = 0
    var wid = ""
}

/** تُرمى عند طلب الإيقاف. ترث Error حتى لا تلتقطها catch (e: Exception) بالخطأ. */
class Cancelled : Error()

@Suppress("DEPRECATION")
class MainActivity : Activity() {

    companion object {
        const val DL_CAP = 30_000_000L      // حد أقصى لتنزيل اختبار واحد
        const val UL_CAP = 8_000_000L       // حد أقصى لرفع اختبار واحد
        const val TOTAL_CAP = 100_000_000L  // حد أقصى لاستهلاك البيانات في التشغيل الواحد
        const val STAGE_TTL = 20 * 60 * 1000L
        const val ROUTER_TICKS = 70
    }

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
    private lateinit var stopBtn: Button
    private lateinit var chip: TextView
    private lateinit var bar: ProgressBar
    private lateinit var beforeTv: TextView
    private lateinit var afterTv: TextView
    private lateinit var gainTv: TextView
    private lateinit var pingTv: TextView
    private lateinit var autoSw: Switch
    private lateinit var logView: TextView
    private lateinit var reportCard: LinearLayout
    private lateinit var reportView: TextView
    private lateinit var liveWeb: TextView
    private lateinit var modeBtn: TextView
    private lateinit var dnsTv: TextView
    private lateinit var resultCard: LinearLayout
    private lateinit var resultPct: TextView
    private lateinit var resultBarV: ProgressBar
    private lateinit var resultSub: TextView
    private lateinit var verdictTv: TextView
    private lateinit var wizard: ScrollView
    private lateinit var wizP1: LinearLayout
    private lateinit var wizP2: LinearLayout
    private lateinit var wizIp: EditText
    private lateinit var wizUser: EditText
    private lateinit var wizPass: EditText
    private lateinit var wizErr: TextView
    private val stepViews = mutableListOf<TextView>()
    private val stepNames = listOf(
        "فحص الشبكة والسرعة", "قياس أسرع DNS", "مسح القنوات", "الدخول لصفحة الراوتر",
        "تطبيق DNS", "ضبط القناة والعرض", "إعادة تشغيل الراوتر", "قياس الجودة والـ Ping بعد الإصلاح", "تسجيل الخروج والنتيجة النهائية"
    )
    private val stepState = IntArray(9)
    private var webFull = false

    // ---------- حالة التشغيل (مشتركة بين الخيوط) ----------
    @Volatile private var busy = false
    @Volatile private var destroyed = false
    private val cancelled = AtomicBoolean(false)
    private val approved = AtomicBoolean(false)   // موافقة المستخدم على الإجراءات (تسمح بتأكيد نوافذ الراوتر)
    private val webDead = AtomicBoolean(false)
    private val dataUsed = AtomicLong(0)
    @Volatile private var restoring = false
    private var locGranted = false

    // بيانات الدخول (تُقرأ من الواجهة قبل بدء الخيط، ولا تُحفظ)
    private var credUser = ""
    private var credPass = ""
    private var authTries = 0
    private var loginTries = 0
    private var loginStuck = false
    private var pt = 0

    // هوية الراوتر والشبكة
    private var gwIp = ""
    private var lockSsid = ""
    private var lockBssid = ""
    private var lockTitle = ""
    private var vendor = ""
    private var unknownUi = false
    private var gwPort = 80

    // قراءات الراوتر (للقراءة فقط قبل أي تعديل)
    private var rDnsOk = false; private var rDns1 = ""; private var rDns2 = ""
    private var rChOk = false; private var rCh = -1; private var rWd = ""; private var rMd = ""
    private var rChOpts: List<Int> = emptyList(); private var rWopts: List<String> = emptyList()
    private var devices = -1
    private var oldUptime = false

    // نتائج القياس
    private var phoneCh = 0
    private var bestDns = ""
    private var bestDns2 = ""
    private var dnsWorth = false
    private var dnsReport = ""
    private var dnsRank: List<DnsRes> = emptyList()
    private var curDnsAtStart = ""
    private var scan = ChanScan(false, 0, emptyMap(), "")
    private var bDown = -1.0; private var bUp = -1.0; private var bLoaded = -1.0
    private var aDown = -1.0; private var aUp = -1.0
    private var pingB = PingRes(-1.0, 0.0, 100, "none")
    private var pingA: PingRes? = null
    private var gwBefore = -1.0
    private var gwAfter = -1.0
    private var scoreB = 0
    private var scoreA = 0
    private var afterValid = false
    private var lowSpeed = false
    private var lineProblem = false
    private var primary = ""
    private var diagText = ""
    private var lastReport = ""
    private var lastLog = ""
    private var plannedCount = 0
    private var verifiedCount = 0
    private var rebootPlanned = false
    private var rebootOk = false
    private var loggedOut = false
    private var changedAny = false

    private val okList = mutableListOf<String>()     // تغييرات تم التحقق منها
    private val failList = mutableListOf<String>()   // تغييرات فشلت وسببها
    private val skipList = mutableListOf<String>()   // عمليات تم تخطيها وسببها
    private val audit = mutableListOf<String>()
    private val logLines = mutableListOf<String>()
    private val ui = Handler(Looper.getMainLooper())

    private val dnsCandidates = listOf(
        "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "94.140.14.140",
        "76.76.2.0", "64.6.64.6", "4.2.2.1", "84.200.69.80", "8.26.56.26"
    )
    private val dnsNames = mapOf(
        "1.1.1.1" to "Cloudflare", "8.8.8.8" to "Google", "9.9.9.9" to "Quad9",
        "208.67.222.222" to "OpenDNS", "94.140.14.140" to "AdGuard", "76.76.2.0" to "Control D",
        "64.6.64.6" to "Verisign", "4.2.2.1" to "Level3", "84.200.69.80" to "DNS.WATCH", "8.26.56.26" to "Comodo"
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
        text = t; setAllCaps(false); textSize = 16f; setTextColor(Color.WHITE)
        setTypeface(typeface, Typeface.BOLD)
        background = GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, intArrayOf(c1, c2)).apply { cornerRadius = dp(16).toFloat() }
        layoutParams = LinearLayout.LayoutParams(-1, dp(54)).apply { topMargin = dp(12) }
    }

    private fun smallBtn(t: String) = Button(this).apply {
        text = t; setAllCaps(false); textSize = 12f; setTextColor(cText)
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
        if (!hasLoc()) requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), 1) else locGranted = true
        window.statusBarColor = cBg
        window.navigationBarColor = cBg
        window.setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)

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
        autoSw = Switch(this).apply {
            text = "⚡ بدء تلقائي عند فتح التطبيق"; setTextColor(cText); textSize = 13f
            isChecked = getSharedPreferences("nf", 0).getBoolean("auto", true)
            setOnCheckedChangeListener { _, c -> getSharedPreferences("nf", 0).edit().putBoolean("auto", c).apply() }
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) }
        }
        inCard.addView(autoSw)
        inCard.visibility = View.GONE
        dash.addView(inCard)

        // الأزرار
        startBtn = gradBtn("🔄 إعادة الفحص والتحسين", cCyan, cBlue)
        startBtn.setOnClickListener { if (!busy) startRun(false) }
        dash.addView(startBtn)

        stopBtn = Button(this).apply {
            text = "⛔ إيقاف العملية"; setAllCaps(false); textSize = 13f; setTextColor(Color.WHITE)
            background = bg(Color.parseColor("#7F1D1D"), 14)
            layoutParams = LinearLayout.LayoutParams(-1, dp(44)).apply { topMargin = dp(8) }
            visibility = View.GONE
            setOnClickListener { if (busy) { cancelled.set(true); log("⛔ طُلب الإيقاف، أُنهي المهام الجارية...") } }
        }
        dash.addView(stopBtn)

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) }
        }
        fixBtn = smallBtn("🔁 إعادة المحاولة").apply { isEnabled = false; setOnClickListener { if (!busy) startRun(false) } }
        restoreBtn = smallBtn("↩ استرجاع").apply { isEnabled = hasBackup(); setOnClickListener { if (!busy) startRun(true) } }
        val copyBtn = smallBtn("📋 نسخ التقرير").apply { setOnClickListener { copyReport() } }
        val settingsBtn = smallBtn("⚙ بيانات الراوتر").apply {
            setOnClickListener { if (!busy) showWizard(1, "") }
        }
        row.addView(fixBtn); row.addView(restoreBtn); row.addView(copyBtn); row.addView(settingsBtn)
        dash.addView(row)

        resultCard = cardBox().apply { visibility = View.GONE }
        resultCard.addView(label("🏆 نتيجة التحسين ونسبة نجاح الاختبار", 13f, cMuted))
        verdictTv = label("", 17f, cText, true).apply { gravity = Gravity.CENTER; setPadding(0, dp(8), 0, 0) }
        resultCard.addView(verdictTv)
        resultPct = label("0%", 46f, cGreen, true).apply { gravity = Gravity.CENTER; setPadding(0, dp(6), 0, 0) }
        resultCard.addView(resultPct)
        resultBarV = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100; progress = 0; progressTintList = ColorStateList.valueOf(cGreen)
            layoutParams = LinearLayout.LayoutParams(-1, dp(10)).apply { topMargin = dp(6) }
        }
        resultCard.addView(resultBarV)
        resultSub = label("", 13f, cText).apply { gravity = Gravity.CENTER; setPadding(0, dp(8), 0, 0) }
        resultCard.addView(resultSub)
        dash.addView(resultCard)

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
        spCard.addView(label("📈 السرعة (تنزيل)", 13f, cMuted))
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

        val pgCard = cardBox()
        pgCard.addView(label("⏱ استقرار الاتصال (Ping) ودرجة صحة الشبكة", 13f, cMuted))
        pingTv = label("بعد الفحص تظهر هنا نتائج الاستجابة والتذبذب وفقد الحزم قبل وبعد الإصلاح", 13f, cText).apply { setPadding(0, dp(8), 0, 0) }
        pgCard.addView(pingTv)
        dash.addView(pgCard)

        val dnsCard = cardBox()
        dnsCard.addView(label("🧭 ترتيب أسرع DNS (قياس حي)", 13f, cMuted))
        dnsTv = label("سيظهر ترتيب أسرع DNS بعد القياس", 12f, cText).apply { typeface = Typeface.MONOSPACE; setPadding(0, dp(8), 0, 0) }
        dnsCard.addView(dnsTv)
        dash.addView(dnsCard)

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
            settings.allowFileAccess = false
            setBackgroundColor(Color.WHITE)
            layoutParams = LinearLayout.LayoutParams(-1, 0, 1f)
            webViewClient = routerClient
            webChromeClient = object : WebChromeClient() {
                private fun risky(m: String): Boolean {
                    val ic = RegexOption.IGNORE_CASE
                    val rb = Regex("reboot|restart|إعادة تشغيل|اعادة تشغيل", ic).containsMatchIn(m)
                    return Regex("factory|مصنع", ic).containsMatchIn(m) ||
                        (!rb && Regex("default|restore|reset|افتراض", ic).containsMatchIn(m))
                }
                // لا يُؤكَّد أي مربع حوار من الراوتر إلا بعد موافقة المستخدم على الإجراء، ولا يُؤكَّد أبداً إن كان فيه إعادة ضبط
                override fun onJsConfirm(v: WebView, url: String, message: String, result: JsResult): Boolean {
                    if (risky(message) || !approved.get()) result.cancel() else result.confirm()
                    return true
                }
                override fun onJsAlert(v: WebView, url: String, message: String, result: JsResult): Boolean { result.confirm(); return true }
            }
        }
        webPanel.addView(web)

        root.addView(dashScroll); root.addView(webPanel)
        val frame = FrameLayout(this)
        frame.addView(root, FrameLayout.LayoutParams(-1, -1))
        buildWizard()
        frame.addView(wizard, FrameLayout.LayoutParams(-1, -1))
        setContentView(frame)
        showWizard(1, "")
        checkResume()
    }

    // ================= دورة الحياة والصلاحيات =================
    private fun hasLoc() = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        locGranted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
        if (!locGranted) Toast.makeText(this, "بدون صلاحية الموقع لن يعمل مسح القنوات وسيُتخطى", Toast.LENGTH_LONG).show()
    }

    override fun onDestroy() {
        destroyed = true
        cancelled.set(true)
        ui.removeCallbacksAndMessages(null)
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.bindProcessToNetwork(null)
        } catch (e: Exception) {}
        try {
            web.stopLoading()
            (web.parent as? ViewGroup)?.removeView(web)
            web.destroy()
        } catch (e: Exception) {}
        super.onDestroy()
    }

    override fun onBackPressed() {
        if (wizard.visibility == View.VISIBLE && wizP2.visibility == View.VISIBLE) { showWizard(1, ""); return }
        if (busy) {
            AlertDialog.Builder(this).setTitle("عملية جارية").setMessage("إيقاف العملية والخروج؟")
                .setPositiveButton("إيقاف وخروج") { _, _ -> cancelled.set(true); super.onBackPressed() }
                .setNegativeButton("استمرار", null).show()
        } else super.onBackPressed()
    }

    // ================= شاشات البداية: IP ← بيانات الدخول ← تشغيل تلقائي =================
    private fun buildWizard() {
        val prefs = getSharedPreferences("nf", 0)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(24), dp(56), dp(24), dp(24))
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        col.addView(label("📡", 56f).apply { gravity = Gravity.CENTER })
        col.addView(label("NetFix Pro", 28f, cText, true).apply { gravity = Gravity.CENTER })
        col.addView(label("تحسين سرعة واستقرار الإنترنت تلقائياً", 13f, cMuted).apply { gravity = Gravity.CENTER; setPadding(0, 0, 0, dp(24)) })

        wizP1 = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        wizP1.addView(label("الخطوة 1 من 2 — عنوان الراوتر", 15f, cCyan, true))
        wizP1.addView(label("اكتب IP الراوتر (غالباً مكتوب خلف الراوتر مثل 192.168.1.1). ملأت عنوان شبكتك الحالية تلقائياً.", 12f, cMuted).apply { setPadding(0, dp(6), 0, 0) })
        wizIp = field("عنوان الراوتر").apply {
            setText(prefs.getString("router_ip", null) ?: gateway())
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        }
        wizP1.addView(wizIp)
        val next1 = gradBtn("التالي ←", cCyan, cBlue)
        next1.setOnClickListener { onIpNext() }
        wizP1.addView(next1)

        wizP2 = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE }
        wizP2.addView(label("الخطوة 2 من 2 — دخول الراوتر", 15f, cCyan, true))
        wizP2.addView(label("اكتب اسم المستخدم وكلمة المرور (غالباً admin أو مكتوبة خلف الراوتر). لو الراوتر بلا كلمة مرور اترك الخانة فارغة. كلمة المرور لا تُحفظ.", 12f, cMuted).apply { setPadding(0, dp(6), 0, 0) })
        wizUser = field("اسم المستخدم").apply { setText(prefs.getString("router_user", "admin")) }
        wizPass = field("كلمة المرور", true)
        wizP2.addView(wizUser); wizP2.addView(wizPass)
        val go = gradBtn("🚀 دخول وبدء التحسين التلقائي", cGreen, cCyan)
        go.setOnClickListener { onGoClicked() }
        wizP2.addView(go)
        val back = toolChip("→ رجوع").apply {
            layoutParams = LinearLayout.LayoutParams(-2, -2).apply { topMargin = dp(14) }
            setOnClickListener { showWizard(1, "") }
        }
        wizP2.addView(back)

        wizErr = label("", 13f, cRed).apply { gravity = Gravity.CENTER; setPadding(0, dp(14), 0, 0) }
        col.addView(wizP1); col.addView(wizP2); col.addView(wizErr)
        wizard = ScrollView(this).apply { setBackgroundColor(cBg); isFillViewport = true; addView(col) }
    }

    private fun showWizard(page: Int, msg: String) {
        runOnUiThread {
            if (destroyed) return@runOnUiThread
            wizP1.visibility = if (page == 1) View.VISIBLE else View.GONE
            wizP2.visibility = if (page == 2) View.VISIBLE else View.GONE
            wizErr.text = msg
            wizard.animate().cancel()
            wizard.alpha = 1f; wizard.visibility = View.VISIBLE
        }
    }

    private fun onIpNext() {
        val v = wizIp.text.toString().trim()
        if (!Regex("[A-Za-z0-9.-]+").matches(v) || !v.contains(".")) { wizErr.text = "اكتب عنواناً صحيحاً مثل 192.168.1.1"; return }
        wizErr.text = "⏳ أتحقق من الاتصال بالراوتر..."
        thread(name = "netfix-ipcheck") {
            bindToWifi()
            val ok = listOf(80, 443, 8080).any { tcp(v, it, 1500) >= 0 }
            runOnUiThread {
                if (destroyed) return@runOnUiThread
                if (ok) {
                    ipFails = 0
                    getSharedPreferences("nf", 0).edit().putString("router_ip", v).apply()
                    showWizard(2, "")
                } else {
                    ipFails++
                    if (ipFails >= 2) {
                        getSharedPreferences("nf", 0).edit().putString("router_ip", v).apply()
                        showWizard(2, "⚠ لم أتحقق من الاتصال بالعنوان، لكن سأجرّب الدخول")
                    } else {
                        wizErr.text = "❌ لا أستطيع الوصول لهذا العنوان. تأكد أنك متصل بواي فاي الراوتر وأن الـ IP صحيح (اضغط التالي مرة أخرى للمتابعة رغم ذلك)."
                    }
                }
            }
        }
    }
    private var ipFails = 0

    private fun onGoClicked() {
        val u = wizUser.text.toString().trim()
        val pw = wizPass.text.toString()
        val v = wizIp.text.toString().trim()
        ip.setText(v); userEt.setText(u); passEt.setText(pw)
        getSharedPreferences("nf", 0).edit().putString("router_ip", v).putString("router_user", u).apply()
        wizErr.text = ""
        wizard.animate().alpha(0f).setDuration(350).withEndAction { wizard.visibility = View.GONE }.start()
        startRun(false)
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
        runOnUiThread { if (!destroyed) { logView.text = shown; liveWeb.text = "🖥 $s" } }
    }

    private fun say(s: String) = log(s)

    private fun setChip(t: String, color: Int) = runOnUiThread { if (!destroyed) { chip.text = t; chip.setTextColor(color) } }

    private fun setStep(i: Int, st: Int) {
        stepState[i] = st
        runOnUiThread {
            if (destroyed) return@runOnUiThread
            val icon = when (st) { 1 -> "⏳"; 2 -> "✅"; 3 -> "⏭"; 4 -> "❌"; else -> "⚪" }
            val col = when (st) { 1 -> cAmber; 2 -> cGreen; 4 -> cRed; else -> cMuted }
            stepViews[i].text = "$icon  ${stepNames[i]}"
            stepViews[i].setTextColor(col)
            ObjectAnimator.ofInt(bar, "progress", stepState.count { it >= 2 } * 100 / stepState.size).setDuration(450).start()
        }
    }

    private fun resetUi() {
        for (i in stepState.indices) setStep(i, 0)
        runOnUiThread {
            if (destroyed) return@runOnUiThread
            beforeTv.text = "—"; afterTv.text = "—"; gainTv.text = "—"; gainTv.setTextColor(cMuted)
            pingTv.text = "جارٍ القياس..."
            dnsTv.text = "جارٍ القياس..."
            resultCard.visibility = View.GONE
            reportCard.visibility = View.GONE
        }
    }

    private fun setReport(t: String) = runOnUiThread {
        if (destroyed) return@runOnUiThread
        reportView.text = t
        if (reportCard.visibility != View.VISIBLE) {
            reportCard.alpha = 0f; reportCard.visibility = View.VISIBLE
            reportCard.animate().alpha(1f).setDuration(450).start()
        }
    }

    private fun mb(x: Double) = if (x < 0) "—" else "%.1f".format(x)
    private fun fmt(x: Double): String = if (x < 0) "فشل القياس" else "%.1f Mbps".format(x)
    private fun ms(x: Double) = if (x < 0) "—" else "${x.toInt()}ms"

    // درجة صحة الشبكة من 100 (استجابة + تذبذب + فقد حزم + سرعة)
    private fun health(p: PingRes, sp: Double): Int {
        var s = 100.0
        s -= if (p.avg < 0) 40.0 else Math.min(25.0, Math.max(0.0, (p.avg - 30) / 4))
        s -= Math.min(25.0, p.jitter * 2.5)
        s -= Math.min(25.0, p.loss * 5.0)
        s -= if (sp < 0) 15.0 else if (sp < 5) 25.0 else if (sp < 15) 15.0 else if (sp < 30) 8.0 else 0.0
        return s.coerceIn(0.0, 100.0).toInt()
    }

    private fun verdict(sc: Int) = if (sc >= 85) "ممتاز 🟢" else if (sc >= 65) "جيد 🟡" else if (sc >= 40) "ضعيف 🟠" else "سيئ 🔴"

    private fun pingLine(p: PingRes) =
        if (p.avg < 0) "فشل القياس (${p.method})" else "${p.avg.toInt()}ms | تذبذب ${p.jitter.toInt()}ms | فقد ${p.loss}% (${p.method})"

    private fun updatePingCard() {
        val a = pingA
        val txt = "قبل: ${pingLine(pingB)}\nدرجة الصحة: $scoreB/100 (${verdict(scoreB)})\n\n" +
            (if (a == null) "بعد: —" else "بعد: ${pingLine(a)}\nدرجة الصحة: $scoreA/100 (${verdict(scoreA)})")
        runOnUiThread { if (!destroyed) pingTv.text = txt }
    }

    private fun copyReport() {
        val text = if (lastReport.isNotEmpty()) lastReport else synchronized(logLines) { logLines.joinToString("\n") }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("report", text))
        Toast.makeText(this, "تم نسخ التقرير", Toast.LENGTH_SHORT).show()
    }

    private fun gatewayRaw(): String = try {
        val g = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).dhcpInfo.gateway
        if (g == 0) "" else "%d.%d.%d.%d".format(g and 255, g shr 8 and 255, g shr 16 and 255, g shr 24 and 255)
    } catch (e: Exception) { "" }

    private fun gateway(): String = gatewayRaw().ifEmpty { "192.168.0.1" }

    private fun isIp(s: String) =
        Regex("\\d{1,3}(\\.\\d{1,3}){3}").matches(s) && s.split(".").all { it.toInt() in 0..255 }

    // ================= التحكم في المهام (إلغاء / انتظار / حوار) =================
    private fun chk() { if (cancelled.get() || destroyed) throw Cancelled() }

    private fun sleepC(totalMs: Long) {
        var left = totalMs
        while (left > 0) { chk(); val s = Math.min(left, 200L); Thread.sleep(s); left -= s }
    }

    /** سؤال المستخدم من خيط العمل (يحجب حتى الرد، ويُلغى عند الإيقاف). */
    private fun askUser(title: String, msg: String, yes: String = "نعم، نفّذ", no: String = "لا"): Boolean {
        val latch = CountDownLatch(1)
        var res = false
        runOnUiThread {
            if (destroyed || isFinishing) { latch.countDown(); return@runOnUiThread }
            AlertDialog.Builder(this).setTitle(title).setMessage(msg).setCancelable(false)
                .setPositiveButton(yes) { _, _ -> res = true; latch.countDown() }
                .setNegativeButton(no) { _, _ -> latch.countDown() }.show()
        }
        while (!latch.await(300, TimeUnit.MILLISECONDS)) chk()
        return res
    }

    // ================= أدوات الشبكة =================
    private fun bindToWifi(): Boolean = try {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val wifis = cm.allNetworks.filter { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true }
        val n = wifis.firstOrNull { cm.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true } ?: wifis.firstOrNull()
        if (n != null) { cm.bindProcessToNetwork(n); true } else false
    } catch (e: Exception) { false }

    private fun wifiInfoSafe(): Triple<String, String, Int> = try {
        val i = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).connectionInfo
        val ss = (i.ssid ?: "").trim('"')
        val bs = i.bssid ?: ""
        Triple(if (ss == "<unknown ssid>") "" else ss, if (bs == "02:00:00:00:00:00") "" else bs, i.frequency)
    } catch (e: Exception) { Triple("", "", 0) }

    /** هل الهاتف متصل فعلاً بشبكة الراوتر المطلوب (واي فاي + نفس البوابة + نفس الاسم إن أمكن قراءته)؟ */
    private fun onTargetNetwork(): Boolean = try {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val hasWifi = cm.allNetworks.any { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true }
        if (!hasWifi) false
        else {
            val g = gatewayRaw()
            val gwOk = !isIp(gwIp) || (g.isNotEmpty() && g == gwIp)
            val ss = wifiInfoSafe().first
            val ssOk = lockSsid.isEmpty() || ss.isEmpty() || ss == lockSsid
            gwOk && ssOk
        }
    } catch (e: Exception) { false }

    private fun nudgeWifi() {
        try {
            if (Build.VERSION.SDK_INT < 29) {
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                if (!wm.isWifiEnabled) wm.isWifiEnabled = true
                wm.reconnect()
            }
        } catch (e: Exception) {}
    }

    private fun tcp(host: String, port: Int, timeout: Int = 1500): Long = try {
        val t = System.nanoTime()
        Socket().use { it.connect(InetSocketAddress(host, port), timeout) }
        (System.nanoTime() - t) / 1_000_000
    } catch (e: Exception) { -1 }

    private fun tcpAny(host: String): Long {
        for (p in listOf(80, 443, 8080, 53)) { val x = tcp(host, p, 1200); if (x >= 0) return x }
        return -1
    }

    private fun httpPing(): Long = try {
        val t = System.nanoTime()
        val c = URL("https://cp.cloudflare.com/generate_204").openConnection() as HttpURLConnection
        c.connectTimeout = 3000; c.readTimeout = 3000; c.instanceFollowRedirects = false
        val code = c.responseCode
        c.disconnect()
        if (code in 200..399) (System.nanoTime() - t) / 1_000_000 else -1
    } catch (e: Exception) { -1 }

    private fun dnsQuery(server: String, host: String, timeout: Int = 1000): Long {
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

    /** يميّز: الراوتر / الإنترنت عبر TCP / عبر UDP / عبر HTTP. حظر UDP وحده لا يعني انقطاع الإنترنت. */
    private fun reach(): Reach {
        val gw = listOf(80, 443, 8080, 53).any { tcp(gwIp, it, 1200) >= 0 }
        val tcpOk = tcp("1.1.1.1", 443, 1500) >= 0 || tcp("8.8.8.8", 443, 1500) >= 0
        val udpOk = dnsQuery("1.1.1.1", "example.com", 1200) >= 0 || dnsQuery("8.8.8.8", "example.com", 1200) >= 0
        val httpOk = if (!tcpOk && !udpOk) httpPing() >= 0 else false
        return Reach(gw, tcpOk, udpOk, httpOk)
    }

    private fun ispDns(): List<String> = try {
        val d = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).dhcpInfo
        fun ipOf(g: Int) = if (g == 0) null else "%d.%d.%d.%d".format(g and 255, g shr 8 and 255, g shr 16 and 255, g shr 24 and 255)
        listOfNotNull(ipOf(d.dns1), ipOf(d.dns2))
    } catch (e: Exception) { emptyList() }

    private fun gwStats(): Pair<Double, Int> {
        var port = -1
        for (p in listOf(80, 443, 8080, 53)) { if (tcp(gwIp, p, 1200) >= 0) { port = p; break } }
        if (port < 0) return Pair(-1.0, 100)
        gwPort = port
        val ok = (1..10).map { tcp(gwIp, port, 1200) }.filter { it >= 0 }
        return Pair(if (ok.isEmpty()) -1.0 else ok.average(), (10 - ok.size) * 10)
    }

    /** Ping/Jitter/Loss: يختار أول وسيلة تعمل (TCP ثم UDP ثم HTTP) بدل الاعتماد على UDP وحده. */
    private fun pingStats(n: Int): PingRes {
        val methods = listOf<Pair<String, () -> Long>>(
            "TCP 1.1.1.1:443" to { tcp("1.1.1.1", 443, 1500) },
            "TCP 8.8.8.8:443" to { tcp("8.8.8.8", 443, 1500) },
            "UDP DNS" to { dnsQuery("1.1.1.1", "example.com", 1200) },
            "HTTP" to { httpPing() }
        )
        for ((name, f) in methods) {
            chk()
            var probe = false
            for (i in 1..3) { if (f() >= 0) { probe = true; break } }
            if (!probe) continue
            val t = mutableListOf<Long>()
            for (i in 1..n) { chk(); val x = f(); if (x >= 0) t.add(x); sleepC(100) }
            val avg = if (t.isEmpty()) -1.0 else t.average()
            var j = 0.0
            for (i in 1 until t.size) j += Math.abs(t[i] - t[i - 1]).toDouble()
            return PingRes(avg, if (t.size > 1) j / (t.size - 1) else 0.0, (n - t.size) * 100 / n, name)
        }
        return PingRes(-1.0, 0.0, 100, "لا توجد وسيلة تعمل")
    }

    /** اختبار تنزيل بحد أقصى للبيانات والمدة، قابل للإيقاف. يرجع (Mbps، زمن الاستجابة أثناء التحميل). */
    private fun downloadTest(): Pair<Double, Double> {
        if (dataUsed.get() + DL_CAP > TOTAL_CAP) { log("⚠ تخطّيت اختبار التنزيل: بلغتُ الحد الأقصى لاستهلاك البيانات"); return Pair(-1.0, -1.0) }
        val bytes = AtomicLong(0)
        val stop = AtomicBoolean(false)
        val lat = java.util.Collections.synchronizedList(mutableListOf<Long>())
        val conns = java.util.Collections.synchronizedList(mutableListOf<HttpURLConnection>())
        val per = DL_CAP / 3
        val start = System.nanoTime()
        val workers = (1..3).map {
            thread(name = "netfix-dl") {
                try {
                    val c = URL("https://speed.cloudflare.com/__down?bytes=$per").openConnection() as HttpURLConnection
                    conns.add(c)
                    c.connectTimeout = 5000; c.readTimeout = 8000
                    c.inputStream.use { s ->
                        val buf = ByteArray(65536)
                        while (!stop.get() && !cancelled.get()) {
                            val r = s.read(buf)
                            if (r < 0) break
                            if (bytes.addAndGet(r.toLong()) >= DL_CAP) break
                        }
                    }
                } catch (e: Exception) {}
            }
        }
        val pinger = thread(name = "netfix-lat") {
            try {
                Thread.sleep(1200)
                while (!stop.get() && !cancelled.get()) {
                    val x = tcp("1.1.1.1", 443, 1500)
                    if (x >= 0) lat.add(x)
                    Thread.sleep(300)
                }
            } catch (e: Exception) {}
        }
        val deadline = System.nanoTime() + 10_000_000_000L
        while (System.nanoTime() < deadline && workers.any { it.isAlive } && !cancelled.get() && bytes.get() < DL_CAP) Thread.sleep(150)
        stop.set(true)
        val secs = (System.nanoTime() - start) / 1e9
        val total = bytes.get()
        for (c in ArrayList(conns)) { try { c.disconnect() } catch (e: Exception) {} }
        pinger.join(1500)
        dataUsed.addAndGet(total)
        chk()
        val mbps = if (total > 0) total * 8 / secs / 1e6 else -1.0
        val l = ArrayList(lat)
        return Pair(mbps, if (l.isEmpty()) -1.0 else l.average())
    }

    private fun speedRetry(): Pair<Double, Double> {
        for (i in 1..2) {
            val r = downloadTest()
            if (r.first > 0) return r
            sleepC(3000)
        }
        return Pair(-1.0, -1.0)
    }

    /** اختبار رفع منفصل ومحدود. القيمة تقريبية (جزء منها قد يكون في ذاكرة المقابس). */
    private fun uploadTest(): Double {
        if (dataUsed.get() + UL_CAP > TOTAL_CAP) { log("⚠ تخطّيت اختبار الرفع: بلغتُ الحد الأقصى لاستهلاك البيانات"); return -1.0 }
        var sent = 0L
        val start = System.nanoTime()
        var end = start
        try {
            val c = URL("https://speed.cloudflare.com/__up").openConnection() as HttpURLConnection
            c.requestMethod = "POST"; c.doOutput = true
            c.connectTimeout = 5000; c.readTimeout = 12000
            c.setFixedLengthStreamingMode(UL_CAP)
            val buf = ByteArray(32768).also { java.util.Random().nextBytes(it) }
            val deadline = start + 8_000_000_000L
            try {
                c.outputStream.use { o ->
                    while (sent < UL_CAP && System.nanoTime() < deadline && !cancelled.get()) {
                        val n = Math.min(buf.size.toLong(), UL_CAP - sent).toInt()
                        o.write(buf, 0, n); sent += n
                    }
                }
                if (sent >= UL_CAP) c.responseCode
            } catch (e: Exception) {}
            end = System.nanoTime()
            try { c.disconnect() } catch (e: Exception) {}
        } catch (e: Exception) {}
        dataUsed.addAndGet(sent)
        chk()
        val secs = (end - start) / 1e9
        return if (sent > 0 && secs > 0) sent * 8 / secs / 1e6 else -1.0
    }

    private fun gwAndNet(tag: String): Snap {
        log("⏳ [$tag] فحص الاتصال بالراوتر والإنترنت...")
        val rc = reach()
        val (gwMs, gwLoss) = gwStats()
        val ping = if (rc.internet) { log("⏳ [$tag] قياس الاستجابة (20 عينة)..."); pingStats(20) } else PingRes(-1.0, 0.0, 100, "لا يوجد إنترنت")
        var sp = Speed(-1.0, -1.0, -1.0)
        if (rc.tcp || rc.http) {
            log("⏳ [$tag] اختبار التنزيل (حتى ${DL_CAP / 1_000_000}MB)...")
            val (d, l) = speedRetry()
            log("⏳ [$tag] اختبار الرفع (حتى ${UL_CAP / 1_000_000}MB)...")
            val u = uploadTest()
            sp = Speed(d, u, l)
        }
        return Snap(rc, gwMs, gwLoss, ping, sp)
    }

    // ================= قياس DNS (مهلة إجمالية + إلغاء غير المكتمل) =================
    private fun dnsScore(server: String, deadline: Long): DnsRes? {
        val times = mutableListOf<Long>()
        var total = 0
        var fails = 0
        for (round in 1..3) {
            for (d in testDomains) {
                if (cancelled.get() || System.currentTimeMillis() > deadline) return null   // غير مكتمل ← يُهمل
                val x = dnsQuery(server, d, 1000)
                total++
                if (x >= 0) times.add(x) else fails++
                if (total == 6 && times.isEmpty()) return DnsRes(server, -1.0, -1.0, 0, 1e9)  // لا يستجيب
            }
        }
        if (times.isEmpty()) return DnsRes(server, -1.0, -1.0, 0, 1e9)
        val sorted = times.sorted()
        val avg = times.average()
        val med = sorted[sorted.size / 2].toDouble()
        val sd = Math.sqrt(times.sumOf { (it - avg) * (it - avg) } / times.size)
        val success = (total - fails) * 100 / total
        val score = med * 0.5 + avg * 0.3 + sd * 0.2 + (100 - success) * 8.0
        return DnsRes(server, avg, med, success, score)
    }

    private fun benchmarkDns(extra: List<String>): List<DnsRes> {
        val all = (extra + ispDns() + dnsCandidates).filter { isIp(it) }.distinct()
        val deadline = System.currentTimeMillis() + 25_000
        val pool = Executors.newFixedThreadPool(4)
        val futures = all.map { s -> pool.submit(Callable<DnsRes?> { dnsScore(s, deadline) }) }
        val out = mutableListOf<DnsRes>()
        try {
            for (f in futures) {
                if (cancelled.get()) break
                val left = deadline - System.currentTimeMillis()
                try {
                    val r = f.get(Math.max(left, 100L), TimeUnit.MILLISECONDS)
                    if (r != null) out.add(r)
                } catch (e: Exception) { f.cancel(true) }
            }
        } finally { pool.shutdownNow() }
        chk()
        return out.sortedBy { it.score }
    }

    private fun chooseDns(ranked: List<DnsRes>, curServer: String) {
        val good = ranked.filter { it.success >= 90 }
        if (good.isEmpty()) { dnsWorth = false; dnsReport = "🧭 تعذّر قياس DNS بشكل موثوق (UDP/53 قد يكون محظوراً)"; return }
        val cur = ranked.firstOrNull { it.server == curServer }
        val best = good[0]
        bestDns = best.server
        bestDns2 = good.firstOrNull { it.server != best.server }?.server ?: ""
        dnsWorth = isIp(best.server) && best.server != curServer &&
            (cur == null || cur.success < 80 || (best.score < cur.score * 0.8 && cur.score - best.score >= 5))
        dnsReport = "🧭 أفضل DNS: ${best.server} (${best.avg.toInt()}ms، نجاح ${best.success}%)" +
            (if (cur != null) " | الحالي $curServer (${if (cur.avg < 0) "لا يستجيب" else "${cur.avg.toInt()}ms"}، نجاح ${cur.success}%)" else "") +
            if (dnsWorth) " ← مرشّح للتغيير" else " ← الحالي مناسب"
    }

    private fun dnsRankText(): String {
        if (dnsRank.isEmpty()) return "لم يتم القياس"
        return dnsRank.take(11).mapIndexed { i, p ->
            val name = (dnsNames[p.server] ?: "DNS آخر") + (if (p.server == curDnsAtStart) " (الحالي)" else "")
            val mark = if (p.server == bestDns) " ⭐" else if (p.server == bestDns2) " ✔" else ""
            val t = if (p.avg < 0) "لا يستجيب" else "${p.avg.toInt()}ms • نجاح ${p.success}%"
            "${i + 1}. $name ${p.server} — $t$mark"
        }.joinToString("\n")
    }

    private fun renderDns() { val t = dnsRankText(); runOnUiThread { if (!destroyed) dnsTv.text = t } }

    // ================= مسح القنوات (2.4GHz، كل القنوات المتاحة) =================
    private fun scanChannels(): ChanScan {
        if (!hasLoc()) return ChanScan(false, 0, emptyMap(), "صلاحية الموقع غير ممنوحة")
        if (Build.VERSION.SDK_INT >= 28) {
            val lm = getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager
            if (!lm.isLocationEnabled) return ChanScan(false, 0, emptyMap(), "خدمة الموقع (GPS) مغلقة")
        }
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val own = try { wm.connectionInfo.bssid } catch (e: Exception) { null }
        val seen = HashMap<String, Int>()
        val freq = HashMap<String, Int>()
        var total = 0
        try {
            repeat(3) {
                chk()
                try { wm.startScan() } catch (e: Exception) {}
                sleepC(3000)
                val res = wm.scanResults
                total = Math.max(total, res.size)
                res.filter { it.frequency in 2400..2500 && it.BSSID != own }.forEach {
                    if (it.level > (seen[it.BSSID] ?: -200)) { seen[it.BSSID] = it.level; freq[it.BSSID] = it.frequency }
                }
            }
        } catch (e: SecurityException) {
            return ChanScan(false, 0, emptyMap(), "رفض النظام نتائج المسح")
        }
        if (total == 0) return ChanScan(false, 0, emptyMap(), "نتائج المسح فارغة (قد يكون النظام قيّد المسح)")
        fun load(ch: Int): Double = seen.entries.sumOf { e ->
            val apCh = if (freq[e.key] == 2484) 14 else (freq[e.key]!! - 2407) / 5
            val d = Math.abs(apCh - ch)
            if (d > 4) 0.0 else Math.pow(10.0, e.value / 10.0) * (5 - d) / 5.0
        }
        val loads = (1..14).associateWith { load(it) }
        return ChanScan(true, seen.size, loads, "")
    }

    /** أفضل قناة من القنوات التي يدعمها الراوتر فعلاً (مقروءة من صفحته). */
    private fun chooseChannel(): Int? {
        if (!rChOk || !scan.ok) return null
        val cands = rChOpts.filter { it in 1..14 }
        if (cands.isEmpty()) return null
        val min = cands.minOf { scan.loads[it] ?: 0.0 }
        val near = cands.filter { (scan.loads[it] ?: 0.0) <= min * 1.05 + 1e-18 }
        return near.firstOrNull { it == 1 || it == 6 || it == 11 } ?: near.first()
    }

    // ================= سكربت الراوتر =================
    private fun q(s: String): String = JSONObject.quote(s)

    private fun routerJs(ph: String, write: Boolean = false, ch: Int = 0, d1: String = "", d2: String = "", wid: String = ""): String {
        val pass = if (loginTries < 3) credPass else ""
        val wr = if (write) "true" else "false"
        return """
    (function(PH,WR,CH,DNS,DNS2,WID,PT,USER,PASS){
      var r={found:false,changed:false,saved:false,pw:false,clicked:false,w:false,info:'',info2:'',cn:-1,wd:'',md:'',opts:'[]',wopts:'[]',hasAuto:false,dbg:''};
      function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
      function vis(e){return e.offsetParent!==null}
      function hl(e){try{e.style.outline='3px solid #22d3ee';e.style.backgroundColor='#fef9c3';e.scrollIntoView({block:'center'})}catch(x){}}
      function setv(e,v){e.focus();e.value=v;['input','change','keyup'].forEach(function(t){e.dispatchEvent(new Event(t,{bubbles:true}))})}
      function norm(x){return (x.innerText||x.value||'').trim().replace(/^[-\s]+/,'').toLowerCase()}
      function g(tx,re){var m=tx.match(re);return m?m[1].trim():''}
      function ok(a,n){return a===n||(n.length>4&&a.indexOf(n)===0&&a.length<=n.length+10)}
      function num(o){var m=(o.text||'').match(/^\s*(?:channel\s*)?(\d{1,2})\b/i);if(m)return parseInt(m[1]);
        var v=(o.value||'');return /^\d{1,2}\b/.test(v)?parseInt(v):-1}
      function findSave(d){var nm=['save','apply','ok','submit','save changes','apply changes','confirm','حفظ','تطبيق','تأكيد'];
        var c=[].slice.call(d.querySelectorAll('button,input[type=button],input[type=submit],a')).filter(vis);
        for(var i=0;i<c.length;i++){if(nm.indexOf(norm(c[i]))>=0){return c[i]}}return null}
      function doSave(d){var b=findSave(d);if(b){r.saved=true;setTimeout(function(){b.click()},700)}}
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
            if(WR&&(r.info!==DNS||(dn[1]&&r.info2!==DNS2))){setv(dn[0],DNS);if(dn[1])setv(dn[1],DNS2);r.changed=true;doSave(d)}
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
            var cso=[].slice.call(cs.options);
            r.opts=JSON.stringify(cso.map(num).filter(function(n){return n>0}));
            r.hasAuto=cso.some(function(x){return /auto/i.test(x.text)});
            r.wd=ws?ws.options[ws.selectedIndex].text.trim():'';r.md=ms?ms.options[ms.selectedIndex].text.trim():'';
            r.wopts=ws?JSON.stringify([].slice.call(ws.options).map(function(x){return x.text.trim()})):'[]';
            hl(cs);
            if(WR){
              var chg=false,tq=-1;
              for(var q=0;q<cs.options.length;q++){
                if(CH===0){if(/auto/i.test(cs.options[q].text)){tq=q;break}}
                else if(num(cs.options[q])===CH){tq=q;break}}
              if(tq>=0&&tq!==cs.selectedIndex){cs.selectedIndex=tq;cs.dispatchEvent(new Event('change',{bubbles:true}));chg=true}
              if(WID&&ws){for(var q=0;q<ws.options.length;q++){
                var tt=ws.options[q].text.trim();var t2=tt.replace(/\s/g,'').toLowerCase();
                var hit=(WID==='20')?(t2==='20'||t2==='20mhz'):(tt===WID);
                if(hit){hl(ws);if(ws.selectedIndex!==q){ws.selectedIndex=q;ws.dispatchEvent(new Event('change',{bubbles:true}));chg=true;r.w=true}break}}}
              if(chg){r.changed=true;doSave(d)}
            }
            return r}
        } else if(PH==='reboot'){
          var rn=['reboot','restart','reboot router','restart router','reboot now','restart now','إعادة تشغيل','اعادة تشغيل','إعادة التشغيل'];
          var cands=[].slice.call(d.querySelectorAll('input[type=button],input[type=submit],button,a,span,div,td,li')).filter(function(x){return vis(x)&&x.children.length<=1&&rn.indexOf(norm(x))>=0});
          var bt=cands.filter(function(x){return /^(button|input)${'$'}/i.test(x.tagName)})[0];
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
    })(${q(ph)},$wr,$ch,${q(d1)},${q(d2)},${q(wid)},$pt,${q(credUser)},${q(pass)})
    """
    }

    // نوافذ التأكيد المخصصة (HTML) بعد الضغط على Reboot: تُنقر فقط داخل عناصر تشبه النوافذ المنبثقة
    private val confirmJs = """
    (function(){function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
    function inModal(x){var p=x;for(var i=0;i<8&&p;i++){if(/modal|dialog|popup|confirm|msgbox|layer|alert/i.test((p.className||'')+' '+(p.id||'')))return true;p=p.parentElement}return false}
    var ok=['ok','yes','confirm','continue','نعم','موافق','تأكيد','reboot','restart'];
    docs(window,[]).forEach(function(d){try{var c=[].slice.call(d.querySelectorAll('button,input[type=button],input[type=submit],a,span,div')).filter(function(x){
      return x.offsetParent!==null&&x.children.length<=1&&ok.indexOf((x.innerText||x.value||'').trim().toLowerCase())>=0&&inModal(x)});
      if(c.length){c[c.length-1].click()}}catch(e){}})})()
    """

    private val logoutJs = """
    (function(){function docs(w,a){a.push(w.document);for(var i=0;i<w.frames.length;i++){try{docs(w.frames[i],a)}catch(e){}}return a}
    docs(window,[]).forEach(function(d){try{[].slice.call(d.querySelectorAll('a,button,li,span,div,input')).forEach(function(x){
    var t=(x.innerText||x.value||x.id||'').trim();if(t.length<25&&/log\s*out|sign\s*out|logout|خروج/i.test(t)&&x.children.length<3){x.click()}})}catch(e){}})})()
    """

    // ================= WebView =================
    private val routerClient = object : WebViewClient() {
        override fun onReceivedHttpAuthRequest(v: WebView, h: HttpAuthHandler, hs: String, r: String) {
            if (credUser.isNotEmpty() && credPass.isNotEmpty() && authTries < 2) {
                authTries++; h.proceed(credUser, credPass); return
            }
            if (destroyed) { h.cancel(); return }
            val box = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 20, 40, 0) }
            val u = EditText(this@MainActivity).apply { hint = "اسم المستخدم" }
            val p = EditText(this@MainActivity).apply { hint = "كلمة المرور"; inputType = 129 }
            box.addView(u); box.addView(p)
            AlertDialog.Builder(this@MainActivity).setTitle("دخول الراوتر").setView(box)
                .setPositiveButton("دخول") { _, _ -> h.proceed(u.text.toString(), p.text.toString()) }
                .setNegativeButton("إلغاء") { _, _ -> h.cancel() }.show()
        }

        // شهادة الراوتر الذاتية: تُقبل فقط لعنوان الراوتر نفسه
        override fun onReceivedSslError(v: WebView, h: SslErrorHandler, e: SslError) {
            val u = e.url ?: ""
            if (gwIp.isNotEmpty() && u.contains(gwIp)) h.proceed() else h.cancel()
        }

        override fun onReceivedError(v: WebView, req: WebResourceRequest, err: WebResourceError) {
            if (req.isForMainFrame) log("⚠ تعذّر تحميل صفحة الراوتر: ${err.description}")
        }

        // منع أي رابط إعادة ضبط المصنع نهائياً
        override fun shouldOverrideUrlLoading(v: WebView, req: WebResourceRequest): Boolean {
            val u = req.url.toString()
            if (Regex("factory|restoredefault|restore_default|resetdefault|reset_default", RegexOption.IGNORE_CASE).containsMatchIn(u)) {
                log("🛑 منعتُ فتح رابط إعادة ضبط المصنع")
                return true
            }
            return false
        }

        override fun onRenderProcessGone(view: WebView?, detail: RenderProcessGoneDetail?): Boolean {
            webDead.set(true); log("❌ توقّفت عملية WebView"); return true
        }
    }

    private fun openRouter() {
        runOnUiThread {
            if (destroyed) return@runOnUiThread
            authTries = 0
            web.webViewClient = routerClient
            web.loadUrl("http://$gwIp")
        }
        sleepC(2500)
    }

    /** تنفيذ سكربت في WebView وانتظار نتيجته (بدون حجب الواجهة). */
    private fun evalJs(script: String, timeoutMs: Long = 8000): JSONObject? {
        chk()
        val latch = CountDownLatch(1)
        var out: String? = null
        runOnUiThread {
            if (destroyed) { latch.countDown(); return@runOnUiThread }
            try { web.evaluateJavascript(script) { v -> out = v; latch.countDown() } } catch (e: Exception) { latch.countDown() }
        }
        latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        val s = out ?: return null
        return try { JSONObject(s) } catch (e: Exception) { null }
    }

    /** يتنقل في قوائم الراوتر ويقرأ/يكتب حتى يتحقق الشرط، أو ينتهي العدد. */
    private fun navRead(
        ph: String, maxTicks: Int, write: Boolean = false, ch: Int = 0, d1: String = "", d2: String = "", wid: String = "",
        until: (JSONObject) -> Boolean = { it.optBoolean("found") }
    ): JSONObject? {
        pt = 0
        var pwSeen = 0
        for (tick in 1..maxTicks) {
            chk()
            if (webDead.get()) throw IllegalStateException("توقّف WebView")
            val r = evalJs(routerJs(ph, write, ch, d1, d2, wid))
            if (r != null) {
                if (r.optBoolean("pw")) {
                    pwSeen++
                    if (credPass.isNotEmpty() && loginTries < 3) { loginTries++; log("🔐 أسجّل الدخول تلقائياً... ($loginTries)") }
                    else if (credPass.isEmpty()) log("✍ سجّل دخولك في صفحة الراوتر بالأسفل وسأكمل تلقائياً")
                    else log("⏳ أنتظر نتيجة تسجيل الدخول...")
                    if (credPass.isNotEmpty() && loginTries >= 3 && pwSeen > 8) { loginStuck = true; return null }
                } else {
                    if (until(r)) { loginStuck = false; loginTries = 0; return r }
                    pt++
                    if (pt % 6 == 1) log(when (ph) {
                        "status" -> "🔎 أفتح صفحة حالة الراوتر..."
                        "dns" -> "🔎 أبحث عن إعدادات DNS..."
                        "clients" -> "🔎 أقرأ الأجهزة المتصلة..."
                        "chan" -> "🔎 أبحث عن إعدادات القناة..."
                        else -> "🔁 أبحث عن زر إعادة التشغيل..."
                    })
                    if (ph == "reboot" && pt == 12) log("🧩 العناصر الظاهرة: ${r.optString("dbg").take(350)}")
                }
            }
            sleepC(2500)
        }
        loginStuck = pwSeen >= 3
        return null
    }

    // ================= النسخة الاحتياطية (مع التحقق من صحتها) =================
    private fun loadBackup(): JSONObject? = try {
        val s = getSharedPreferences("nf", 0).getString("bk", null)
        if (s == null) null else JSONObject(s)
    } catch (e: Exception) { null }

    private fun hasBackup() = loadBackup() != null

    private fun validateBackup(b: JSONObject): Boolean {
        if (b.optInt("v") != 1 || b.optString("gw").isEmpty()) return false
        if (b.optBoolean("hasDns")) {
            val a = b.optString("dns1"); val c = b.optString("dns2")
            if (!(a.isEmpty() || isIp(a)) || !(c.isEmpty() || isIp(c))) return false
        }
        if (b.optBoolean("hasChan")) { if (b.optInt("ch", -1) !in 0..14) return false }
        return b.optBoolean("hasDns") || b.optBoolean("hasChan")
    }

    /** يحفظ الأصل قبل أي تعديل. لا يكتب فوق الأصل إذا كانت القيم الحالية هي نتيجة تعديلنا السابق. */
    private fun saveBackup(): Boolean {
        val sp = getSharedPreferences("nf", 0)
        val old = loadBackup()
        val curCh = if (rCh > 0) rCh else 0
        if (old != null && old.optString("gw") == gwIp && validateBackup(old)) {
            val sameAsOurs = (!old.optBoolean("hasDns") || old.optString("aDns1").isEmpty() || old.optString("aDns1") == rDns1) &&
                (!old.optBoolean("hasChan") || old.optInt("aCh", -2) == -2 || old.optInt("aCh") == curCh)
            val sameAsOriginal = (!old.optBoolean("hasDns") || old.optString("dns1") == rDns1) &&
                (!old.optBoolean("hasChan") || old.optInt("ch") == curCh)
            if (sameAsOurs || sameAsOriginal) return true   // نحتفظ بالأصل القديم
        }
        val b = JSONObject().apply {
            put("v", 1); put("gw", gwIp); put("vendor", vendor); put("ts", System.currentTimeMillis())
            put("hasDns", rDnsOk); put("dns1", rDns1); put("dns2", rDns2)
            put("hasChan", rChOk); put("ch", curCh); put("wd", rWd)
            put("aDns1", ""); put("aCh", -2)
        }
        if (!validateBackup(b)) return false
        sp.edit().putString("bk", b.toString()).commit()
        val back = loadBackup()
        return back != null && validateBackup(back) && back.optString("dns1") == rDns1
    }

    private fun markApplied(dns1: String?, ch: Int?) {
        val b = loadBackup() ?: return
        if (dns1 != null) b.put("aDns1", dns1)
        if (ch != null) b.put("aCh", ch)
        getSharedPreferences("nf", 0).edit().putString("bk", b.toString()).commit()
    }

    // ================= التطبيق مع التحقق الفعلي بعد الحفظ =================
    private fun normW(s: String) = s.replace(" ", "").lowercase(Locale.ROOT)

    /** إعادة تحميل كاملة لصفحة الراوتر ثم قراءة DNS من جديد (لا يُعتمد على القيم المكتوبة في النموذج). */
    private fun verifyDns(d1: String, d2: String): Boolean {
        openRouter()
        val r = navRead("dns", 30) ?: return false
        val a = r.optString("info"); val b = r.optString("info2")
        return a == d1 && (b.isEmpty() || d2.isEmpty() || b == d2 || !r.has("info2"))
    }

    private fun verifyChan(ch: Int, wid: String): Boolean {
        openRouter()
        val r = navRead("chan", 30) ?: return false
        val cn = r.optInt("cn", -1)
        val chOk = if (ch == 0) (cn <= 0 && Regex("auto", RegexOption.IGNORE_CASE).containsMatchIn(r.optString("info"))) else cn == ch
        val wOk = wid.isEmpty() || (if (wid == "20") normW(r.optString("wd")).let { it == "20" || it == "20mhz" } else r.optString("wd") == wid)
        return chOk && wOk
    }

    private fun applyDnsValue(d1: String, d2: String, tag: String): Boolean {
        val r = navRead("dns", 30, write = true, d1 = d1, d2 = d2)
        if (r == null) { failList += "DNS ($tag): لم أجد حقول DNS قابلة للتعديل في واجهة الراوتر"; return false }
        if (r.optBoolean("changed") && !r.optBoolean("saved")) {
            failList += "DNS ($tag): لم أجد زر الحفظ في صفحة الراوتر، لم يُحفظ شيء"; return false
        }
        if (r.optBoolean("changed")) { log("💾 ضغطتُ حفظ DNS، أنتظر التطبيق..."); sleepC(6000); waitRouterBack(90_000) }
        log("🔍 أتحقق من قيمة DNS بعد الحفظ (إعادة تحميل الصفحة)...")
        return verifyDns(d1, d2)
    }

    private fun applyChanValue(ch: Int, wid: String, tag: String): Boolean {
        val r = navRead("chan", 30, write = true, ch = ch, wid = wid)
        if (r == null) { failList += "القناة ($tag): لم أجد إعدادات القناة في واجهة الراوتر"; return false }
        if (r.optBoolean("changed") && !r.optBoolean("saved")) {
            failList += "القناة ($tag): لم أجد زر الحفظ، لم يُحفظ شيء"; return false
        }
        if (r.optBoolean("changed")) { log("💾 ضغطتُ حفظ القناة (قد ينقطع الواي فاي لثوانٍ)..."); sleepC(10_000); waitRouterBack(150_000) }
        log("🔍 أتحقق من القناة بعد الحفظ (إعادة تحميل الصفحة)...")
        return verifyChan(ch, wid)
    }

    // ================= انتظار الراوتر الصحيح والإنترنت (مرحلة مستقلة) =================
    private fun fetchTitle(): String = try {
        val c = URL("http://$gwIp/").openConnection() as HttpURLConnection
        c.connectTimeout = 2500; c.readTimeout = 2500; c.instanceFollowRedirects = true
        val txt = c.inputStream.use { s -> String(s.readBytes().take(8192).toByteArray(), Charsets.ISO_8859_1) }
        c.disconnect()
        Regex("<title[^>]*>([^<]{0,80})", RegexOption.IGNORE_CASE).find(txt)?.groupValues?.get(1)?.trim()?.lowercase(Locale.ROOT) ?: ""
    } catch (e: Exception) { "" }

    /** ينتظر عودة الراوتر المطلوب تحديداً (نفس الشبكة + نفس البوابة + نفس بصمة الصفحة) باستقرار متتالٍ. */
    private fun waitRouterBack(timeoutMs: Long): Boolean {
        val t0 = System.currentTimeMillis()
        var good = 0
        var lastNote = -100L
        while (System.currentTimeMillis() - t0 < timeoutMs) {
            chk(); bindToWifi()
            val net = onTargetNetwork()
            if (net && tcpAny(gwIp) >= 0) {
                val t = if (lockTitle.isNotEmpty()) fetchTitle() else ""
                if (lockTitle.isEmpty() || t.isEmpty() || t == lockTitle) good++
                else { good = 0; log("⚠ الصفحة التي ردّت ليست صفحة الراوتر المطلوب") }
                if (good >= 2) return true
            } else {
                good = 0   // انقطاع مؤقت لا يُعدّ فشلاً، فقط نبدأ العدّ من جديد
                val el = (System.currentTimeMillis() - t0) / 1000
                if (el - lastNote >= 15) {
                    lastNote = el
                    log(if (!net) "⏳ أنتظر اتصال الهاتف بشبكة الراوتر الأصلية... (${el}ث)" else "⏳ أنتظر رجوع صفحة الراوتر... (${el}ث)")
                    nudgeWifi()
                }
                if (el in 100L..115L) log("📶 لو الواي فاي لم يتصل تلقائياً، اتصل بشبكتك يدوياً وسأكمل")
            }
            sleepC(3000)
        }
        return false
    }

    /** ينتظر الإنترنت بشكل مستقل عن صفحة الراوتر (3 نجاحات متتالية). */
    private fun waitInternet(timeoutMs: Long): Boolean {
        val t0 = System.currentTimeMillis()
        var good = 0
        var n = 0
        while (System.currentTimeMillis() - t0 < timeoutMs) {
            chk(); bindToWifi()
            val rc = reach()
            if (rc.internet) good++ else good = 0
            if (good >= 3) { log("🌐 الإنترنت مستقر"); return true }
            if (good == 0 && n % 4 == 0) log("⏳ أنتظر عودة الإنترنت...")
            n++
            sleepC(3000)
        }
        return false
    }

    // ================= حفظ المرحلة (لاستكمال العملية دون البدء من الصفر) =================
    private fun jsonList(a: JSONArray?): List<String> {
        val out = mutableListOf<String>()
        if (a != null) for (i in 0 until a.length()) out.add(a.optString(i))
        return out
    }

    private fun saveStage(stage: String) {
        try {
            val o = JSONObject().apply {
                put("stage", stage); put("ts", System.currentTimeMillis())
                put("gw", gwIp); put("ssid", lockSsid); put("bssid", lockBssid); put("title", lockTitle); put("vendor", vendor)
                put("bDown", bDown); put("bUp", bUp); put("bLoaded", bLoaded); put("gwb", gwBefore)
                put("pb", JSONArray(listOf(pingB.avg, pingB.jitter, pingB.loss.toDouble())))
                put("pbm", pingB.method); put("sb", scoreB)
                put("ok", JSONArray(okList as Collection<*>)); put("fail", JSONArray(failList as Collection<*>))
                put("skip", JSONArray(skipList as Collection<*>)); put("audit", JSONArray(audit as Collection<*>))
                put("diag", diagText); put("primary", primary); put("rank", dnsRankText())
                put("planned", plannedCount); put("verified", verifiedCount); put("devices", devices)
                put("lowSpeed", lowSpeed); put("lineProblem", lineProblem)
            }
            getSharedPreferences("nf", 0).edit().putString("stage", o.toString()).commit()
        } catch (e: Exception) {}
    }

    private fun clearStage() { getSharedPreferences("nf", 0).edit().remove("stage").commit() }

    private fun loadStage(o: JSONObject) {
        gwIp = o.optString("gw", gwIp); lockSsid = o.optString("ssid"); lockBssid = o.optString("bssid")
        lockTitle = o.optString("title"); vendor = o.optString("vendor")
        bDown = o.optDouble("bDown", -1.0); bUp = o.optDouble("bUp", -1.0); bLoaded = o.optDouble("bLoaded", -1.0)
        gwBefore = o.optDouble("gwb", -1.0)
        val p = o.optJSONArray("pb")
        pingB = PingRes(p?.optDouble(0, -1.0) ?: -1.0, p?.optDouble(1, 0.0) ?: 0.0, (p?.optDouble(2, 100.0) ?: 100.0).toInt(), o.optString("pbm"))
        scoreB = o.optInt("sb")
        okList.clear(); okList.addAll(jsonList(o.optJSONArray("ok")))
        failList.clear(); failList.addAll(jsonList(o.optJSONArray("fail")))
        skipList.clear(); skipList.addAll(jsonList(o.optJSONArray("skip")))
        audit.clear(); audit.addAll(jsonList(o.optJSONArray("audit")))
        diagText = o.optString("diag"); primary = o.optString("primary")
        savedRank = o.optString("rank")
        plannedCount = o.optInt("planned"); verifiedCount = o.optInt("verified"); devices = o.optInt("devices", -1)
        lowSpeed = o.optBoolean("lowSpeed"); lineProblem = o.optBoolean("lineProblem")
    }
    private var savedRank = ""

    private fun checkResume() {
        val s = getSharedPreferences("nf", 0).getString("stage", null) ?: return
        val o = try { JSONObject(s) } catch (e: Exception) { clearStage(); return }
        if (System.currentTimeMillis() - o.optLong("ts") > STAGE_TTL) { clearStage(); return }
        AlertDialog.Builder(this).setTitle("عملية سابقة لم تكتمل")
            .setMessage("توجد عملية إعادة تشغيل لم يكتمل قياس نتيجتها. أستكملها (انتظار الراوتر والإنترنت ثم القياس) بدل البدء من الصفر؟")
            .setPositiveButton("استكمال") { _, _ ->
                ip.setText(o.optString("gw")); wizard.visibility = View.GONE
                startRun(false, o)
            }
            .setNegativeButton("تجاهل") { _, _ -> clearStage() }.show()
    }

    // ================= التشغيل =================
    private fun resetState() {
        okList.clear(); failList.clear(); skipList.clear(); audit.clear()
        rDnsOk = false; rDns1 = ""; rDns2 = ""; rChOk = false; rCh = -1; rWd = ""; rMd = ""
        rChOpts = emptyList(); rWopts = emptyList(); devices = -1; oldUptime = false
        bestDns = ""; bestDns2 = ""; dnsWorth = false; dnsReport = ""; dnsRank = emptyList(); curDnsAtStart = ""; savedRank = ""
        scan = ChanScan(false, 0, emptyMap(), "")
        bDown = -1.0; bUp = -1.0; bLoaded = -1.0; aDown = -1.0; aUp = -1.0
        pingB = PingRes(-1.0, 0.0, 100, "none"); pingA = null
        gwBefore = -1.0; gwAfter = -1.0; scoreB = 0; scoreA = 0; afterValid = false
        lowSpeed = false; lineProblem = false; primary = ""; diagText = ""
        plannedCount = 0; verifiedCount = 0; rebootPlanned = false; rebootOk = false; loggedOut = false; changedAny = false
        unknownUi = false; vendor = ""; loginTries = 0; loginStuck = false; pt = 0
        lockSsid = ""; lockBssid = ""; lockTitle = ""
        webDead.set(false)
    }

    private fun startRun(restore: Boolean, resume: JSONObject? = null) {
        if (busy) return
        busy = true
        cancelled.set(false); approved.set(false); dataUsed.set(0)
        restoring = restore
        credUser = userEt.text.toString(); credPass = passEt.text.toString()
        gwIp = ip.text.toString().trim()
        resetState()
        resetUi()
        setChip("● جارٍ العمل", cAmber)
        runOnUiThread {
            startBtn.isEnabled = false; fixBtn.isEnabled = false; restoreBtn.isEnabled = false
            stopBtn.visibility = View.VISIBLE
        }
        thread(name = "netfix-run") { runner(resume) }
    }

    private fun runner(resume: JSONObject?) {
        try {
            bindToWifi()
            when {
                resume != null -> resumePost(resume)
                restoring -> doRestore()
                else -> mainFlow()
            }
        } catch (c: Cancelled) {
            cancelledEnd()
        } catch (e: Exception) {
            log("❌ خطأ غير متوقع: ${e.message}")
            failList += "خطأ غير متوقع: ${e.message}"
            setChip("● خطأ", cRed)
            clearStage()
            setReport("❌ توقّفت العملية بسبب خطأ: ${e.message}\n\n" + resultLists())
            endRun()
        }
    }

    private fun cancelledEnd() {
        log("⛔ تم إيقاف العملية بطلبك")
        clearStage()
        try { doLogout() } catch (e: Throwable) {}
        setChip("● متوقف", cAmber)
        setReport("⛔ تم إيقاف العملية بطلبك.\n\n" + resultLists())
        endRun()
    }

    private fun endRun() {
        busy = false; restoring = false
        runOnUiThread {
            if (destroyed) return@runOnUiThread
            restoreBtn.isEnabled = hasBackup(); startBtn.isEnabled = true; fixBtn.isEnabled = true
            stopBtn.visibility = View.GONE
        }
    }

    private fun loginFailed(msg: String) {
        setStep(3, 4)
        setChip("● تعذّر الدخول", cRed)
        log("❌ $msg")
        failList += msg
        clearStage()
        endRun()
        showWizard(2, "❌ $msg")
    }

    private fun resultLists(): String {
        val sb = StringBuilder()
        if (okList.isNotEmpty()) sb.append("✅ تغييرات تم التحقق منها:\n").append(okList.joinToString("\n") { "• $it" }).append("\n\n")
        if (failList.isNotEmpty()) sb.append("❌ فشلت (مع السبب):\n").append(failList.joinToString("\n") { "• $it" }).append("\n\n")
        if (skipList.isNotEmpty()) sb.append("⏭ تم تخطّيها:\n").append(skipList.joinToString("\n") { "• $it" }).append("\n\n")
        if (sb.isEmpty()) sb.append("لم يتم تنفيذ أي تغيير.\n\n")
        return sb.toString()
    }

    // ================= التدفق الرئيسي =================
    private fun captureIdentity() {
        val (ss, bs, _) = wifiInfoSafe()
        lockSsid = ss; lockBssid = bs
        lockTitle = fetchTitle()
        if (lockSsid.isNotEmpty()) audit += "📶 الشبكة: $lockSsid"
        if (!onTargetNetwork()) {
            log("⚠ لا أتأكد أن الهاتف متصل بواي فاي الراوتر $gwIp")
            audit += "⚠ لم أتأكد أن الهاتف على شبكة هذا الراوتر (الاتصال بواي فاي أو العنوان قد يكون خاطئاً)"
        }
    }

    private fun parseStatus(s: String) {
        val o = try { JSONObject(s) } catch (e: Exception) { return }
        vendor = o.optString("vendor")
        if (vendor.isNotEmpty()) { audit += "🏷 نوع الراوتر: $vendor"; log("🏷 تم التعرّف على الراوتر: $vendor") }
        val fw = o.optString("fw"); val hw = o.optString("hw")
        if (fw.isNotEmpty() || hw.isNotEmpty()) audit += "📋 الراوتر: $hw | فيرموير: $fw"
        val up = o.optString("up")
        if (up.isNotEmpty()) {
            audit += "⏱ مدة التشغيل: $up"
            val d = Regex("(\\d+)\\s*day", RegexOption.IGNORE_CASE).find(up)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            if (d >= 14) { oldUptime = true; audit += "⚠ الراوتر يعمل منذ $d يوماً بلا إعادة تشغيل، وهذا يبطّئه" }
        }
        val dns = o.optString("dns")
        if (dns.isNotEmpty()) audit += "🌐 DNS الحالي في صفحة الحالة: $dns"
    }

    private fun readRouterState() {
        log("🔎 أقرأ إعدادات DNS الحالية (قراءة فقط)...")
        val d = navRead("dns", 30)
        if (d != null) { rDnsOk = true; rDns1 = d.optString("info"); rDns2 = d.optString("info2"); audit += "🧭 DNS في الراوتر: $rDns1 ${if (rDns2.isNotEmpty()) "/ $rDns2" else ""}" }
        else audit += "🧭 لم أجد حقول DNS قابلة للتعديل"
        val c = navRead("clients", 12)
        if (c != null) {
            devices = c.optString("info").toIntOrNull() ?: -1
            audit += if (devices > 8) "👥 الأجهزة المتصلة: $devices ⚠ عدد كبير قد يبطّئ الشبكة" else "👥 الأجهزة المتصلة: $devices"
        }
        log("🔎 أقرأ إعدادات القناة والقنوات المدعومة (قراءة فقط)...")
        val ch = navRead("chan", 30)
        if (ch != null) {
            rChOk = true
            rCh = ch.optInt("cn", -1); rWd = ch.optString("wd"); rMd = ch.optString("md")
            rChOpts = try { val a = JSONArray(ch.optString("opts", "[]")); (0 until a.length()).map { a.getInt(it) } } catch (e: Exception) { emptyList() }
            rWopts = try { jsonList(JSONArray(ch.optString("wopts", "[]"))) } catch (e: Exception) { emptyList() }
            audit += "📡 القناة الحالية: ${ch.optString("info")} | العرض: ${if (rWd.isEmpty()) "—" else rWd} | النمط: ${if (rMd.isEmpty()) "—" else rMd} | القنوات المدعومة: ${rChOpts.size}"
        } else audit += "📡 لم أجد إعدادات القناة"
    }

    private fun mainFlow() {
        // ----- الدخول وتحديد الراوتر وواجهته قبل أي تعديل -----
        setStep(3, 1); setChip("● جارٍ الدخول", cAmber)
        captureIdentity()
        log("🔌 أفتح صفحة الراوتر $gwIp وأسجّل الدخول...")
        openRouter()
        val st = navRead("status", ROUTER_TICKS)
        if (st == null) {
            if (loginStuck) { loginFailed("تعذّر تسجيل الدخول. تأكد من اسم المستخدم وكلمة المرور."); return }
            unknownUi = true
            audit += "📋 لم أتعرّف على واجهة الراوتر (صفحة الحالة غير مقروءة). سأقرأ فقط ولن أعدّل إلا بعد موافقتك وتحقق صارم."
            setStep(3, 3)
        } else { parseStatus(st.optString("info")); setStep(3, 2) }
        readRouterState()

        // ----- قياسات الهاتف -----
        diagnose()
        chk()

        // ----- الخطة والموافقة -----
        val plan = buildPlan()
        var anyPlanned = plan.dns || plan.chan
        if (anyPlanned) {
            val lines = mutableListOf<String>()
            if (plan.dns) lines += "• DNS: ${rDns1.ifEmpty { "—" }} ← ${plan.d1}" + (if (plan.d2.isNotEmpty()) " (ثانوي ${plan.d2})" else "")
            if (plan.chan) lines += "• القناة: ${if (rCh > 0) rCh.toString() else "تلقائي"} ← ${plan.ch}" + (if (plan.wid.isNotEmpty()) " + عرض ${plan.wid}MHz" else "")
            val warn = "\n\nسأحفظ نسخة من الإعدادات الأصلية أولاً، ولا أعتبر أي تغيير ناجحاً إلا بعد إعادة قراءته من الراوتر." +
                (if (plan.chan) "\n⚠ تغيير القناة قد يقطع الواي فاي لثوانٍ." else "") +
                (if (unknownUi) "\n⚠ واجهة الراوتر غير معروفة لي؛ قد لا تنجح الأتمتة." else "")
            if (!askUser("تأكيد التعديلات", lines.joinToString("\n") + warn)) {
                skipList += "جميع التعديلات: لم يوافق المستخدم"
                plan.dns = false; plan.chan = false; anyPlanned = false
            }
        }

        if (anyPlanned) {
            approved.set(true)
            setStep(5, 0)
            if (!saveBackup()) {
                failList += "تعذّر حفظ نسخة احتياطية صالحة، لذلك لم أعدّل أي إعداد"
                plan.dns = false; plan.chan = false
                setStep(4, 4); setStep(5, 4)
            } else {
                log("🗄 تم حفظ نسخة احتياطية صالحة للإعدادات الأصلية")
                audit += "🗄 نسخة احتياطية: DNS $rDns1 / القناة ${if (rCh > 0) rCh else "تلقائي"}"
            }
        }

        // ----- تطبيق DNS -----
        if (plan.dns) {
            setStep(4, 1); plannedCount++
            val ok = applyDnsValue(plan.d1, plan.d2, "تغيير")
            if (ok) {
                verifiedCount++; changedAny = true; markApplied(plan.d1, null)
                okList += "DNS: كان $rDns1 ← أصبح ${plan.d1}" + (if (plan.d2.isNotEmpty()) " (ثانوي ${plan.d2})" else "") + " — تم التحقق بإعادة القراءة"
                setStep(4, 2)
            } else {
                if (failList.none { it.startsWith("DNS") }) failList += "DNS: لم تتطابق القيمة بعد الحفظ، لذلك تراجعتُ"
                log("↩ أحاول إرجاع DNS لقيمته الأصلية...")
                val back = applyDnsValue(rDns1, rDns2, "تراجع")
                failList += if (back) "DNS: تم التراجع للقيمة الأصلية والتحقق منها" else "DNS: تعذّر التحقق من التراجع، راجع الراوتر يدوياً (الأصل $rDns1)"
                setStep(4, 4)
            }
        } else setStep(4, 3)

        // ----- تطبيق القناة والعرض -----
        if (plan.chan) {
            setStep(5, 1); plannedCount++
            val ok = applyChanValue(plan.ch, plan.wid, "تغيير")
            if (ok) {
                verifiedCount++; changedAny = true; markApplied(null, plan.ch)
                okList += "القناة: كانت ${if (rCh > 0) rCh else "تلقائي"} ← أصبحت ${plan.ch}" + (if (plan.wid.isNotEmpty()) " + عرض 20MHz" else "") + " — تم التحقق بإعادة القراءة"
                setStep(5, 2)
            } else {
                if (failList.none { it.startsWith("القناة") }) failList += "القناة: لم تتطابق القيمة بعد الحفظ، لذلك تراجعتُ"
                log("↩ أحاول إرجاع القناة لقيمتها الأصلية...")
                val back = applyChanValue(if (rCh > 0) rCh else 0, rWd, "تراجع")
                failList += if (back) "القناة: تم التراجع للقيمة الأصلية والتحقق منها" else "القناة: تعذّر التحقق من التراجع، راجع الراوتر يدوياً"
                setStep(5, 4)
            }
        } else setStep(5, 3)
        if (!(plan.dns) || !(plan.chan)) manualSteps(plan)

        // ----- إعادة التشغيل (بعد موافقة صريحة) -----
        val needReboot = changedAny || oldUptime || (lowSpeed && !lineProblem)
        if (needReboot) {
            val why = if (changedAny) "لتطبيق التغييرات" else if (oldUptime) "لأنه يعمل منذ مدة طويلة" else "لتنظيف الاتصال لأن السرعة منخفضة"
            approved.set(true)
            val yes = askUser("إعادة تشغيل الراوتر؟",
                "أقترح إعادة تشغيل الراوتر $why.\n\n⚠ سينقطع الإنترنت والواي فاي عن كل الأجهزة نحو 2–4 دقائق، وسأنتظر عودة نفس الراوتر والإنترنت قبل أي قياس.",
                "نعم، أعد التشغيل", "لا")
            if (yes) {
                rebootPlanned = true; plannedCount++
                val done = rebootStage()
                if (done) verifiedCount++
                if (done && changedAny) postRebootVerify(plan)
            } else { skipList += "إعادة التشغيل: رفضها المستخدم"; setStep(6, 3) }
        } else { skipList += "إعادة التشغيل: غير مطلوبة"; setStep(6, 3) }

        finalizeRun()
    }

    private fun manualSteps(plan: Plan) {
        if (restoring) return
        if (dnsWorth && !plan.dns && !rDnsOk && bestDns.isNotEmpty())
            skipList += "DNS: تعذّرت الأتمتة على هذا الراوتر. يدوياً: من إعدادات الراوتر (DHCP/LAN/WAN) اجعل الأساسي $bestDns" + (if (bestDns2.isNotEmpty()) " والثانوي $bestDns2" else "")
        if (!rChOk && scan.ok)
            skipList += "القناة: لم أجد قائمة القنوات في الراوتر. يدوياً: Wireless ← 2.4GHz ← Channel، والأقل ازدحاماً حسب مسحي موضّحة في التقرير"
    }

    // ================= قياسات الهاتف =================
    private fun diagnose() {
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val info = wm.connectionInfo
        val is24 = info.frequency in 2400..2500
        phoneCh = if (is24) (if (info.frequency == 2484) 14 else (info.frequency - 2407) / 5) else 0

        setStep(0, 1)
        val s = gwAndNet("قبل")
        bDown = s.sp.down; bUp = s.sp.up; bLoaded = s.sp.loaded; gwBefore = s.gwMs; pingB = s.ping
        runOnUiThread { if (!destroyed) beforeTv.text = mb(bDown) }
        scoreB = health(pingB, bDown)
        updatePingCard()
        setStep(0, 2)
        lowSpeed = bDown in 0.0..5.0
        lineProblem = s.reach.gw && !s.reach.internet || (pingB.avg >= 0 && (pingB.loss > 5 || pingB.avg > 120))
        val bloat = bLoaded > 0 && pingB.avg > 0 && bLoaded - pingB.avg > 150

        setStep(1, 1)
        say("⏳ قياس DNS (11 خادماً × 24 استعلاماً، مهلة إجمالية 25 ثانية)...")
        curDnsAtStart = if (rDns1.isNotEmpty() && isIp(rDns1)) rDns1 else (ispDns().firstOrNull() ?: "")
        val ranked = benchmarkDns(listOf(rDns1, rDns2))
        dnsRank = ranked
        chooseDns(ranked, curDnsAtStart)
        renderDns(); say(dnsReport)
        setStep(1, 2)

        setStep(2, 1)
        say("⏳ مسح القنوات (3 مرات)...")
        scan = scanChannels()
        if (scan.ok) say("📡 تم مسح ${scan.count} شبكة مجاورة على 2.4GHz") else say("⚠ مسح القنوات غير متاح: ${scan.note}")
        setStep(2, if (scan.ok) 2 else 3)

        val causes = mutableListOf<String>()
        if (info.rssi < -75) causes += "📶 إشارة الواي فاي ضعيفة (${info.rssi}dBm): اقترب من الراوتر أو أزل العوائق."
        if (info.linkSpeed in 1..20) causes += "🐌 سرعة وصلة الواي فاي بين هاتفك والراوتر منخفضة (${info.linkSpeed}Mbps)."
        if (!s.reach.gw) causes += "🔌 تعذّر الوصول إلى الراوتر نفسه ($gwIp): مشكلة واي فاي أو عنوان خاطئ."
        else if (!s.reach.internet) causes += "🌐 الراوتر يعمل لكن الإنترنت غير متاح عبر أي وسيلة (TCP/UDP/HTTP): غالباً الخط أو المزوّد."
        if (s.reach.tcp && !s.reach.udp) causes += "ℹ UDP/53 محجوب على هذه الشبكة لكن الإنترنت يعمل عبر TCP؛ لذلك قياس DNS قد يكون محدوداً."
        if (s.gwLoss > 5 || s.gwMs > 40) causes += "🔌 اتصالك بالراوتر غير مستقر (فقد ${s.gwLoss}%، ${ms(s.gwMs)})."
        if (lineProblem && s.reach.internet) causes += "🌐 الإنترنت غير مستقر (${ms(pingB.avg)}، فقد ${pingB.loss}%، تذبذب ${pingB.jitter.toInt()}ms): غالباً الخط أو المزوّد."
        if (bloat) causes += "📉 عند التحميل يرتفع زمن الاستجابة من ${pingB.avg.toInt()} إلى ${bLoaded.toInt()}ms."
        if (dnsWorth) causes += "🧭 يوجد DNS أسرع بشكل واضح من الحالي ← المرشّح: $bestDns."
        if (scan.ok && is24) causes += "📡 ${scan.count} شبكة مجاورة على 2.4GHz."
        if (is24 && info.rssi > -65 && wm.is5GHzBandSupported) causes += "⚡ هاتفك يدعم 5GHz وإشارتك جيدة: اتصل بشبكة 5GHz (إن وُجدت)."
        if (lowSpeed) causes += "🐢 سرعة التنزيل منخفضة جداً (${fmt(bDown)})."
        if (causes.isEmpty()) causes += "✅ لم أجد مشكلة واضحة."

        primary = when {
            !s.reach.gw -> "تعذّر الوصول إلى الراوتر: تحقق من الاتصال بالواي فاي وعنوان الراوتر."
            !s.reach.internet -> "الراوتر سليم لكن الإنترنت غير متاح: الخط أو شركة الإنترنت."
            info.rssi < -75 || s.gwLoss > 5 || s.gwMs > 40 -> "المشكلة عندك محلياً: ضعف الواي فاي أو بعدك عن الراوتر أو ازدحام القنوات."
            lineProblem -> "المشكلة في الخط أو شركة الإنترنت (الراوتر سليم)."
            bDown in 0.0..10.0 -> "الواي فاي والراوتر سليمان، والسرعة منخفضة: سرعة الباقة أو الخط أو ازدحام الأجهزة."
            bloat -> "الخط يزدحم عند التحميل: قلّل الأجهزة أو فعّل QoS في الراوتر."
            else -> "لا توجد مشكلة واضحة."
        }
        diagText = "📊 نتائج فحص الهاتف\n" +
            "إشارة: ${info.rssi}dBm | ${if (is24) "2.4" else "5"}GHz قناة ${if (phoneCh > 0) phoneCh else "—"} | وصلة ${info.linkSpeed}Mbps\n" +
            "الراوتر: ${ms(s.gwMs)} فقد ${s.gwLoss}%\n" +
            "الإنترنت: ${pingLine(pingB)}\n" +
            "السرعة: تنزيل ${fmt(bDown)} | رفع ${fmt(bUp)} | زمن أثناء التحميل: ${if (bLoaded > 0) "${bLoaded.toInt()}ms" else "—"}\n" +
            dnsReport + "\n\n🔎 الأسباب:\n" + causes.joinToString("\n")
        setReport(diagText)
    }

    private fun buildPlan(): Plan {
        val p = Plan()
        // DNS
        if (!rDnsOk) skipList += "DNS: لم أجد حقل DNS قابلاً للتعديل في الراوتر"
        else if (!dnsWorth) skipList += "DNS: الحالي مناسب أو لم أستطع قياس بديل أفضل بثقة"
        else if (!isIp(bestDns)) skipList += "DNS: لم أجد بديلاً صالحاً"
        else { p.dns = true; p.d1 = bestDns; p.d2 = if (bestDns2.isNotEmpty() && isIp(bestDns2)) bestDns2 else "" }
        // القناة
        val target = chooseChannel()
        if (!rChOk) skipList += "القناة: لم أجد إعدادات القناة في الراوتر"
        else if (!scan.ok) skipList += "القناة: مسح القنوات غير متاح (${scan.note}) فلن أغيّر شيئاً بلا قياس"
        else if (target == null) skipList += "القناة: لا توجد قنوات مدعومة قابلة للمقارنة"
        else {
            val cur = if (rCh > 0) rCh else if (phoneCh in 1..14) phoneCh else 0
            val lc = scan.loads[cur] ?: 0.0; val lb = scan.loads[target] ?: 0.0
            val curBad = cur > 0 && target != cur && scan.count > 0 && lc > lb * 2
            val crowded = scan.count > 5 || curBad
            val wdNow = normW(rWd)
            val canNarrow = rWopts.any { normW(it).let { t -> t == "20" || t == "20mhz" } }
            val widthChange = crowded && canNarrow && rWd.isNotEmpty() && wdNow != "20" && wdNow != "20mhz"
            if (curBad) { p.chan = true; p.ch = target }
            else if (rCh <= 0 && scan.count > 8 && phoneCh > 0 && (scan.loads[phoneCh] ?: 0.0) > lb * 2) { p.chan = true; p.ch = target }
            else skipList += "القناة: الحالية (${if (rCh > 0) rCh else "تلقائي"}) مناسبة، لا داعي للتغيير"
            if (widthChange) { p.wid = "20"; if (!p.chan) { p.chan = true; p.ch = if (rCh > 0) rCh else 0 } }
            else if (crowded) skipList += "عرض القناة: لا خيار 20MHz صريح أو العرض الحالي مناسب"
        }
        return p
    }

    // ================= إعادة التشغيل (مرحلة انتظار مستقلة ومحفوظة) =================
    private fun rebootStage(): Boolean {
        setStep(6, 1)
        saveStage("rebooting")
        log("🔄 أبحث عن زر إعادة التشغيل...")
        openRouter()
        val r = navRead("reboot", 30, until = { it.optBoolean("clicked") })
        var manual = false
        if (r == null) {
            failList += "إعادة التشغيل: لم أجد زر Reboot في واجهة الراوتر"
            log("🖐 اضغط Reboot بنفسك في صفحة الراوتر (كبّرها بإصبعين)، وأنا أراقب")
            manual = true
        } else {
            log("🔄 تم الضغط على Reboot، أنتظر انقطاع الراوتر...")
            for (i in 1..3) { sleepC(2000); if (tcpAny(gwIp) >= 0) runOnUiThread { if (!destroyed) web.evaluateJavascript(confirmJs, null) } }
        }
        // انتظار الانقطاع (قراءتان متتاليتان فاشلتان)
        var down = false
        var fails = 0
        val limit = if (manual) 40 else 20
        var i = 0
        while (!down && i < limit) {
            sleepC(3000); bindToWifi()
            if (tcpAny(gwIp) < 0) fails++ else fails = 0
            if (fails >= 2) down = true
            i++
        }
        if (!down) {
            failList += "إعادة التشغيل: لم يُرصد انقطاع للراوتر، لا أستطيع تأكيد حدوثها (أعد تشغيله يدوياً إن لزم)"
            setStep(6, 4); rebootOk = false
            clearStage()
            return false
        }
        rebootOk = true
        log("📴 الراوتر انقطع، أنتظر رجوعه...")
        saveStage("waiting_router")
        val up = waitRouterBack(240_000)
        if (!up) {
            failList += "إعادة التشغيل: انقطع الراوتر لكن لم أصل لنفس الراوتر بعد 4 دقائق"
            setStep(6, 4); rebootOk = false
            return false
        }
        log("✅ الراوتر رجع")
        saveStage("waiting_internet")
        okList += "إعادة تشغيل الراوتر: انقطع ثم رجع نفس الراوتر (تحقق فعلي)"
        setStep(6, 2)
        return true
    }

    /** بعد الريبوت: هل بقيت القيم المحفوظة فعلاً؟ (يتطلب تسجيل دخول جديد). */
    private fun postRebootVerify(plan: Plan) {
        approved.set(true)
        log("🔍 أتحقق أن الإعدادات بقيت بعد إعادة التشغيل...")
        loginTries = 0
        try {
            if (plan.dns && okList.any { it.startsWith("DNS: كان") }) {
                if (verifyDns(plan.d1, plan.d2)) okList += "DNS: بقي ${plan.d1} بعد إعادة التشغيل"
                else failList += "DNS: لم تثبت القيمة بعد إعادة التشغيل (قد يكون الراوتر تجاهلها)"
            }
            if (plan.chan && okList.any { it.startsWith("القناة: كانت") }) {
                if (verifyChan(plan.ch, plan.wid)) okList += "القناة: بقيت ${plan.ch} بعد إعادة التشغيل"
                else failList += "القناة: لم تثبت القيمة بعد إعادة التشغيل"
                val (_, _, f) = wifiInfoSafe()
                if (f in 2400..2500) {
                    val pc = if (f == 2484) 14 else (f - 2407) / 5
                    if (pc == plan.ch) okList += "القناة: الهاتف يرصد الراوتر فعلاً على القناة $pc"
                    else failList += "القناة: الهاتف يرصد الراوتر عل
