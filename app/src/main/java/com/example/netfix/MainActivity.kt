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
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Switch
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

data class ChanScan(
    val best: Int,
    val count: Int,
    val curBad: Boolean,
    val scores: List<Pair<Int, Double>> = emptyList()
)

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
    private lateinit var pingTv: TextView
    private lateinit var autoSw: Switch
    private lateinit var logView: TextView
    private lateinit var reportCard: LinearLayout
    private lateinit var reportView: TextView
    private lateinit var liveWeb: TextView
    private lateinit var modeBtn: TextView
    private val stepViews = mutableListOf<TextView>()
    private val stepNames = listOf(
        "فحص الشبكة والسرعة", "قياس أسرع DNS", "مسح القنوات", "الدخول لصفحة الراوتر",
        "تطبيق DNS", "ضبط القناة والعرض", "إعادة تشغيل الراوتر", "قياس الجودة والـ Ping بعد الإصلاح", "تسجيل الخروج والنتيجة النهائية"
    )
    private val stepState = IntArray(9)
    private var webFull = false

    // ---------- الحالة ----------
    private var bestCh = 6
    private var bestDns = "1.1.1.1"
    private var bestDns2 = "8.8.8.8"
    private var requestedDnsPrimary = ""
    private var requestedDnsSecondary = ""
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
    private var dnsPendingVerify = false
    private var chanDone = false
    private var chanPendingVerify = false
    private var devices = -1
    private var phase = "status"
    private var ticks = 0
    private var pt = 0
    private var loginTries = 0
    private var rebootTry = 0
    private var gwIp = ""
    private var pingB: Triple<Double, Double, Int> = Triple(-1.0, 0.0, 0)
    private var pingA: Triple<Double, Double, Int>? = null
    private var scoreB = 0
    private var scoreA = 0
    private var rebootOk = false
    private var rebootPlanned = false
    private var loggedOut = false
    private var gwBefore = -1.0
    private var gwAfter = -1.0
    private var dnsRank: List<Pair<String, Double>> = emptyList()
    private var curDnsAtStart = ""
    private var scTasks = 0
    private var scImpr = 0
    private lateinit var aiAnalysisView: TextView
    private lateinit var aiAnalysisCard: LinearLayout
    private var aiSummary: String = "لم يتم إجراء التحليل الذكي بعد"
    private lateinit var dnsTv: TextView
    private lateinit var dnsPrimaryEt: EditText
    private lateinit var dnsSecondaryEt: EditText
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
    private var connecting = false
    private var connTicks = 0
    private var ipFails = 0
    private var primary = ""
    private var diagText = ""
    private var lastReport = ""
    private var lastLog = ""
    private val logLines = mutableListOf<String>()
    private val report = mutableListOf<String>()
    private val audit = mutableListOf<String>()
    private val order = listOf("status", "dns", "clients", "chan")
    private val ui = Handler(Looper.getMainLooper())

    // 10 مزوّدين مختلفين (مرشّحون فقط)، والترتيب والاختيار بالقياس الحي
    private val dnsCandidates = listOf(
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "94.140.14.140", "94.140.14.141",
        "76.76.2.0", "76.76.10.0", "64.6.64.6", "64.6.65.6", "4.2.2.1",
        "84.200.69.80", "8.26.56.26"
    )
    private val dnsNames = mapOf(
        "1.1.1.1" to "Cloudflare", "1.0.0.1" to "Cloudflare", "8.8.8.8" to "Google", "8.8.4.4" to "Google",
        "9.9.9.9" to "Quad9", "149.112.112.112" to "Quad9", "208.67.222.222" to "OpenDNS", "208.67.220.220" to "OpenDNS",
        "94.140.14.140" to "AdGuard", "94.140.14.141" to "AdGuard", "76.76.2.0" to "Control D", "76.76.10.0" to "Control D",
        "64.6.64.6" to "Verisign", "64.6.65.6" to "Verisign", "4.2.2.1" to "Level3", "84.200.69.80" to "DNS.WATCH", "8.26.56.26" to "Comodo"
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
        requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), 1)
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

        // التحليل الذكي المحلي القابل للتفسير
        aiAnalysisCard = cardBox()
        aiAnalysisCard.addView(label("🧠 مركز التحليل الذكي", 15f, cCyan, true))
        aiAnalysisCard.addView(label("يفحص الإشارة والبوابة والإنترنت وDNS، ثم يشرح الأدلة والتوصيات. لا يغيّر الإعدادات من تلقاء نفسه.", 12f, cMuted))
        aiAnalysisView = label("اضغط بدء الفحص لإظهار التحليل الذكي قبل أي تعديل.", 12f, cText).apply { setPadding(0, dp(8), 0, 0); setTextIsSelectable(true) }
        aiAnalysisCard.addView(aiAnalysisView)
        dash.addView(aiAnalysisCard)

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
        startBtn.setOnClickListener {
            if (running || diagBusy || connecting) return@setOnClickListener
            if (!readDnsOverrides()) return@setOnClickListener
            startBtn.isEnabled = false
            runAiPrecheck { connectRouter() }
        }
        dash.addView(startBtn)
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) }
        }
        fixBtn = smallBtn("🔁 إعادة المحاولة").apply { isEnabled = false; setOnClickListener { openRouter(); applyFixes() } }
        restoreBtn = smallBtn("↩ استرجاع").apply { isEnabled = hasBackup(); setOnClickListener { restoreBackup() } }
        val copyBtn = smallBtn("📋 نسخ التقرير").apply { setOnClickListener { copyReport() } }
        val settingsBtn = smallBtn("⚙ بيانات الراوتر").apply {
            setOnClickListener { if (!running && !diagBusy && !connecting) showWizard(1, "") }
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

        val pgCard = cardBox()
        pgCard.addView(label("⏱ استجابة DNS/UDP والتذبذب وفشل الاستعلامات", 13f, cMuted))
        pingTv = label("بعد الفحص تظهر هنا نتائج الاستجابة والتذبذب وفقد الحزم قبل وبعد الإصلاح", 13f, cText).apply { setPadding(0, dp(8), 0, 0) }
        pgCard.addView(pingTv)
        dash.addView(pgCard)

        val dnsCard = cardBox()
        dnsCard.addView(label("🧭 ترتيب أسرع DNS (قياس حي)", 13f, cMuted))
        dnsTv = label("سيظهر ترتيب خوادم DNS بعد القياس", 12f, cText).apply { typeface = Typeface.MONOSPACE; setPadding(0, dp(8), 0, 0) }
        dnsCard.addView(dnsTv)
        dnsCard.addView(label("⚙ إعداد DNS المستهدف (اختياري)", 12f, cMuted).apply { setPadding(0, dp(12), 0, dp(2)) })
        dnsPrimaryEt = field("Primary DNS — اتركه فارغًا للاختيار الذكي")
        dnsPrimaryEt.inputType = InputType.TYPE_CLASS_TEXT
        dnsSecondaryEt = field("Secondary DNS — اتركه فارغًا للاختيار الذكي")
        dnsSecondaryEt.inputType = InputType.TYPE_CLASS_TEXT
        dnsCard.addView(dnsPrimaryEt)
        dnsCard.addView(dnsSecondaryEt)
        dnsCard.addView(label("مثال: 1.1.1.1 و 1.0.0.1. لن يتم اعتماد التغيير إلا إذا كان الراوتر يعرض حقلي DNS ويدعم حفظهما.", 11f, cMuted).apply { setPadding(0, dp(6), 0, 0) })
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
        val frame = FrameLayout(this)
        frame.addView(root, FrameLayout.LayoutParams(-1, -1))
        buildWizard()
        frame.addView(wizard, FrameLayout.LayoutParams(-1, -1))
        setContentView(frame)
        showWizard(1, "")
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
            wizP1.visibility = if (page == 1) View.VISIBLE else View.GONE
            wizP2.visibility = if (page == 2) View.VISIBLE else View.GONE
            wizErr.text = msg
            wizard.animate().cancel()
            wizard.alpha = 1f; wizard.visibility = View.VISIBLE
        }
    }

    override fun onBackPressed() {
        if (wizard.visibility == View.VISIBLE && wizP2.visibility == View.VISIBLE) showWizard(1, "") else super.onBackPressed()
    }

    private fun onIpNext() {
        val v = wizIp.text.toString().trim()
        if (!Regex("[A-Za-z0-9.-]+").matches(v) || !v.contains(".")) { wizErr.text = "اكتب عنواناً صحيحاً مثل 192.168.1.1"; return }
        wizErr.text = "⏳ أتحقق من الاتصال بالراوتر..."
        thread {
            bindToWifi()
            val ok = routerUp(v)
            runOnUiThread {
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

    private fun onGoClicked() {
        val u = wizUser.text.toString().trim()
        val pw = wizPass.text.toString()
        val v = wizIp.text.toString().trim()
        ip.setText(v); userEt.setText(u); passEt.setText(pw)
        getSharedPreferences("nf", 0).edit().putString("router_ip", v).putString("router_user", u).apply()
        wizErr.text = ""
        wizard.animate().alpha(0f).setDuration(350).withEndAction { wizard.visibility = View.GONE }.start()
        runAiPrecheck { connectRouter() }
    }

    // تحليل أولي قبل تسجيل الدخول أو تغيير أي إعداد
    private fun runAiPrecheck(onDone: () -> Unit) {
        val target = ip.text.toString().trim()
        aiAnalysisView.text = "⏳ أجمع القياسات من الهاتف..."
        log("🧠 بدء التحليل الذكي الأولي؛ لن يتم تغيير أي إعداد خلال هذه المرحلة")
        Thread {
            val result = try { NetFixAiEngine.analyze(this, target) }
            catch (e: Exception) { null }
            runOnUiThread {
                if (result != null) {
                    aiSummary = result.toArabicText()
                    aiAnalysisView.text = aiSummary
                    log("🧠 اكتمل التحليل: ${result.overall}")
                } else {
                    aiSummary = "تعذّر إكمال التحليل الذكي؛ تحقق من اتصال Wi-Fi وصلاحيات الشبكة."
                    aiAnalysisView.text = aiSummary
                    log("⚠ تعذّر إكمال التحليل الذكي؛ سأتابع مسار الفحص المعتاد")
                }
                onDone()
            }
        }.start()
    }

    // ================= الدخول للراوتر ثم البدء التلقائي بمجرد ظهور الإعدادات =================
    private fun connectRouter() {
        if (connecting) return
        if (!readDnsOverrides()) { runOnUiThread { startBtn.isEnabled = true }; return }
        connecting = true; connTicks = 0; loginTries = 0; pt = 0
        gwIp = ip.text.toString().trim()
        bindToWifi()
        resetUi()
        setChip("● جارٍ الدخول", cAmber)
        setStep(3, 1)
        log("🔌 أفتح صفحة الراوتر $gwIp وأسجّل الدخول...")
        runOnUiThread { startBtn.isEnabled = false }
        openRouter()
        ui.postDelayed({ connectStep() }, 3000)
    }

    private fun connectStep() {
        connTicks++
        if (connTicks > 60) { loginFailed("لم تظهر إعدادات الراوتر خلال وقت معقول. تأكد من العنوان وبيانات الدخول."); return }
        web.evaluateJavascript(js("status")) { raw ->
            val r = try { JSONObject(raw ?: "") } catch (e: Exception) { null }
            if (r != null && r.optBoolean("pw")) {
                loginTries++
                if (loginTries >= 5) { loginFailed("تعذّر تسجيل الدخول. تأكد من اسم المستخدم وكلمة المرور."); return@evaluateJavascript }
                log(if (passEt.text.isNotEmpty() && loginTries <= 2) "🔐 أسجّل الدخول تلقائياً..." else "⏳ أنتظر نتيجة تسجيل الدخول... ($loginTries)")
            } else if (r != null && r.optBoolean("found")) {
                connecting = false
                loginTries = 0
                log("✅ ظهرت إعدادات الراوتر — أبدأ الفحص والتحسين تلقائياً")
                setStep(3, 2)
                diagnose(true)
                return@evaluateJavascript
            } else if (r != null) {
                pt++
                log("🔎 أبحث عن صفحة الإعدادات...")
            }
            ui.postDelayed({ connectStep() }, 2500)
        }
    }

    private fun loginFailed(msg: String) {
        connecting = false
        setStep(3, 3)
        setChip("● تعذّر الدخول", cRed)
        log("❌ $msg")
        runOnUiThread { startBtn.isEnabled = true }
        showWizard(2, "❌ $msg")
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
            ObjectAnimator.ofInt(bar, "progress", stepState.count { it == 2 || it == 3 } * 100 / stepState.size).setDuration(450).start()
        }
    }

    private fun resetUi() {
        for (i in stepState.indices) setStep(i, 0)
        runOnUiThread {
            beforeTv.text = "—"; afterTv.text = "—"; gainTv.text = "—"; gainTv.setTextColor(cMuted)
            pingTv.text = "جارٍ القياس..."
            dnsTv.text = "جارٍ القياس..."
            resultCard.visibility = View.GONE
            reportCard.visibility = View.GONE
        }
    }

    private fun setReport(t: String) = runOnUiThread {
        reportView.text = t
        if (reportCard.visibility != View.VISIBLE) {
            reportCard.alpha = 0f; reportCard.visibility = View.VISIBLE
            reportCard.animate().alpha(1f).setDuration(450).start()
        }
    }

    private fun mb(x: Double) = if (x < 0) "—" else "%.1f".format(x)

    // درجة صحة الشبكة من 100 (استجابة + تذبذب + فقد حزم + سرعة)
    private fun health(avg: Double, j: Double, l: Int, sp: Double): Int {
        var s = 100.0
        s -= if (avg < 0) 40.0 else Math.min(25.0, Math.max(0.0, (avg - 30) / 4))
        s -= Math.min(25.0, j * 2.5)
        s -= Math.min(25.0, l * 5.0)
        s -= if (sp < 0) 15.0 else if (sp < 5) 25.0 else if (sp < 15) 15.0 else if (sp < 30) 8.0 else 0.0
        return s.coerceIn(0.0, 100.0).toInt()
    }

    private fun verdict(sc: Int) = if (sc >= 85) "ممتاز 🟢" else if (sc >= 65) "جيد 🟡" else if (sc >= 40) "ضعيف 🟠" else "سيئ 🔴"

    private fun pingLine(p: Triple<Double, Double, Int>) =
        if (p.first < 0) "فشل القياس" else "${p.first.toInt()}ms | تذبذب ${p.second.toInt()}ms | فقد ${p.third}%"

    private fun updatePingCard() {
        val a = pingA
        val txt = "قبل: ${pingLine(pingB)}\nدرجة الصحة: $scoreB/100 (${verdict(scoreB)})\n\n" +
            (if (a == null) "بعد: —" else "بعد: ${pingLine(a)}\nدرجة الصحة: $scoreA/100 (${verdict(scoreA)})")
        runOnUiThread { pingTv.text = txt }
    }

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
        val savedRouter = sp.getString("bk_router", "") ?: ""
        if (savedRouter.isNotEmpty() && savedRouter != ip.text.toString().trim()) {
            Toast.makeText(this, "النسخة الاحتياطية تخص راوترًا بعنوان $savedRouter، ولن أطبقها على راوتر مختلف", Toast.LENGTH_LONG).show()
            return
        }
        restoring = true
        requestedDnsPrimary = ""; requestedDnsSecondary = ""
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

    // الدرجة تراعي السرعة والاستقرار ونسبة نجاح الاستعلامات، لا أقل قراءة لحظية فقط.
    private fun dnsScore(server: String): Double {
        val times = mutableListOf<Long>()
        var failed = 0
        repeat(3) {
            for (d in testDomains) {
                val x = dnsQuery(server, d, 1200)
                if (x < 0) failed++ else times.add(x)
            }
        }
        val total = testDomains.size * 3
        if (times.size < total / 2) return 5000.0 + (total - times.size) * 10.0
        val sorted = times.sorted()
        val median = sorted[sorted.size / 2].toDouble()
        val p90 = sorted[((sorted.size - 1) * 9) / 10].toInt().toDouble()
        val avg = times.average()
        val lossPenalty = failed * 90.0
        return median * 0.40 + p90 * 0.25 + avg * 0.20 + lossPenalty
    }

    private fun benchmarkDns(): List<Pair<String, Double>> {
        val all = (ispDns() + dnsCandidates).distinct()
        val results = java.util.Collections.synchronizedList(mutableListOf<Pair<String, Double>>())
        val ts = all.map { s -> thread { results.add(s to dnsScore(s)) } }
        ts.forEach { it.join(45000) }
        return ArrayList(results).filter { it.second < 2500 }.sortedBy { it.second }
    }

    private fun validIpv4(value: String): Boolean {
        val parts = value.trim().split(".")
        if (parts.size != 4) return false
        return parts.all { part ->
            val n = part.toIntOrNull()
            n != null && n in 0..255 && part.isNotEmpty()
        }
    }

    private fun selectedPrimaryDns(): String = requestedDnsPrimary.ifBlank { bestDns }
    private fun selectedSecondaryDns(): String = requestedDnsSecondary.ifBlank { bestDns2 }

    private fun readDnsOverrides(): Boolean {
        requestedDnsPrimary = dnsPrimaryEt.text.toString().trim()
        requestedDnsSecondary = dnsSecondaryEt.text.toString().trim()
        if (requestedDnsPrimary.isNotEmpty() && !validIpv4(requestedDnsPrimary)) {
            runOnUiThread { dnsPrimaryEt.error = "أدخل عنوان IPv4 صحيحًا" }
            return false
        }
        if (requestedDnsSecondary.isNotEmpty() && !validIpv4(requestedDnsSecondary)) {
            runOnUiThread { dnsSecondaryEt.error = "أدخل عنوان IPv4 صحيحًا" }
            return false
        }
        if (requestedDnsPrimary.isNotEmpty() && requestedDnsSecondary.isNotEmpty() && requestedDnsPrimary == requestedDnsSecondary) {
            runOnUiThread { dnsSecondaryEt.error = "يجب أن يختلف DNS الثانوي عن الأساسي" }
            return false
        }
        return true
    }

    private fun chooseDns(ranked: List<Pair<String, Double>>) {
        if (ranked.isEmpty()) {
            bestDns = requestedDnsPrimary.ifBlank { "1.1.1.1" }
            bestDns2 = requestedDnsSecondary.ifBlank { "8.8.8.8" }
            dnsWorth = requestedDnsPrimary.isNotEmpty() || requestedDnsSecondary.isNotEmpty()
            dnsReport = if (dnsWorth) "🧭 تعذّر ترتيب الخوادم؛ سيتم استخدام DNS الذي أدخلته فقط" else "🧭 تعذّر قياس DNS؛ لن يتم تغييره تلقائيًا"
            return
        }
        val currentPair = ispDns()
        val cur = currentPair.getOrNull(0)
        val cur2 = currentPair.getOrNull(1)
        val best = ranked[0]
        bestDns = best.first
        // نختار خادمين مختلفين من نتائج القياس الحي؛ الأول للأولوية والثاني كاحتياطي.
        bestDns2 = ranked.firstOrNull { it.first != bestDns }?.first ?:
            when (bestDns) { "1.1.1.1" -> "1.0.0.1"; "8.8.8.8" -> "8.8.4.4"; else -> "1.1.1.1" }
        if (requestedDnsPrimary.isNotEmpty()) bestDns = requestedDnsPrimary
        if (requestedDnsSecondary.isNotEmpty()) bestDns2 = requestedDnsSecondary
        dnsWorth = (cur != bestDns || cur2 != bestDns2)
        val best2Score = ranked.firstOrNull { it.first == bestDns2 }?.second
        dnsReport = "🧭 أفضل زوج حسب قياس السرعة والاستقرار: الأساسي $bestDns (${best.second.toInt()}ms)" +
            " | الثانوي $bestDns2 (${best2Score?.toInt()?.toString() ?: "احتياطي"})" +
            (if (cur != null || cur2 != null) " | الحالي $cur / ${cur2 ?: "غير محدد"}" else "") +
            if (dnsWorth) " ← سيتم تحديث الأساسي والثانوي معًا" else " ← الزوج الحالي مطابق للاختيار"
    }

    private fun pickChannel(wm: WifiManager, curCh: Int): ChanScan = try {
        pickChannelRaw(wm, curCh)
    } catch (e: Exception) {
        log("⚠ تعذّر مسح القنوات (فعّل الموقع وامنح الصلاحية)"); ChanScan(6, 0, false)
    }

    /**
     * يفحص كل قنوات 2.4GHz من 1 إلى 13.
     * درجة القناة تجمع قوة الشبكات القريبة مع وزن للتداخل حسب فرق رقم القناة.
     * الشبكة الأقوى والقريبة في التردد تؤثر أكثر من الشبكة الضعيفة أو البعيدة.
     */
    private fun pickChannelRaw(wm: WifiManager, curCh: Int): ChanScan {
        val own = try { wm.connectionInfo.bssid } catch (_: Exception) { null }
        val seen = HashMap<String, Int>()
        val freq = HashMap<String, Int>()

        // نأخذ أفضل RSSI لكل نقطة وصول حتى لا نكرر الشبكة نفسها في حساب الازدحام.
        repeat(3) {
            try {
                wm.startScan()
                Thread.sleep(2500)
                wm.scanResults
                    .filter { it.frequency in 2412..2472 && it.BSSID != own }
                    .forEach { result ->
                        val id = result.BSSID ?: return@forEach
                        if (result.level > (seen[id] ?: -200)) {
                            seen[id] = result.level
                            freq[id] = result.frequency
                        }
                    }
            } catch (_: SecurityException) {
                throw IllegalStateException("صلاحية مسح شبكات Wi-Fi غير متاحة")
            }
        }

        val networks = seen.mapNotNull { (bssid, level) ->
            val mhz = freq[bssid] ?: return@mapNotNull null
            val apChannel = ((mhz - 2407) / 5).coerceIn(1, 13)
            Triple(apChannel, level, bssid)
        }

        // فرق قناة 0..4 يعني وجود تداخل ملحوظ ضمن عرض 20MHz تقريباً.
        // نستخدم قوة نسبية محسوبة من RSSI لتجنب القيم الصغيرة جداً لـ dBm السالبة.
        fun load(channel: Int): Double = networks.sumOf { network ->
            val distance = kotlin.math.abs(network.first - channel)
            if (distance > 4) 0.0
            else {
                val overlapWeight = (5 - distance) / 5.0
                val signalPower = Math.pow(10.0, (network.second + 100.0) / 10.0)
                signalPower * overlapWeight
            }
        }

        val scores = (1..13).map { it to load(it) }
        // عند التعادل نفضّل القناة الحالية لتجنب تغيير غير مفيد، ثم الرقم الأقل.
        val best = scores.minWithOrNull(
            compareBy<Pair<Int, Double>> { it.second }
                .thenBy { if (it.first == curCh) 0 else 1 }
                .thenBy { it.first }
        )?.first ?: 6

        val currentLoad = if (curCh in 1..13) load(curCh) else Double.MAX_VALUE
        val bestLoad = load(best)
        val curBad = curCh != best && networks.isNotEmpty() &&
            currentLoad > bestLoad * 1.35

        return ChanScan(best, networks.size, curBad, scores.sortedBy { it.second })
    }

    private fun stats(f: () -> Long, n: Int = 10): Pair<Double, Int> {
        val ok = (1..n).map { f() }.filter { it >= 0 }
        return Pair(if (ok.isEmpty()) -1.0 else ok.average(), (n - ok.size) * 100 / n)
    }

    private fun pingStats(n: Int): Triple<Double, Double, Int> {
        val t = mutableListOf<Long>()
        for (i in 1..n) {
            val x = dnsUdp(bestDns)
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
                    val x = dnsUdp(bestDns)
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
                bindToWifi()
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                val info = wm.connectionInfo
                val is24 = info.frequency in 2400..2500
                val curCh = if (is24) (info.frequency - 2407) / 5 else (info.frequency - 5000) / 5

                setStep(0, 1)
                say("⏳ فحص الاتصال بالراوتر..."); val (gwMs, gwLoss) = stats({ tcp(gw, 80) }); gwBefore = gwMs
                say("⏳ فحص استجابة DNS/UDP على الخادم المرشح ${bestDns} (20 قياساً؛ ليست ICMP Ping)..."); val (netMs, jitter, netLoss) = pingStats(20)
                say("⏳ اختبار السرعة (قد يستغرق دقيقة)..."); val (sp, loaded) = speedRetry(); beforeSpeed = sp
                runOnUiThread { beforeTv.text = mb(sp) }
                pingB = Triple(netMs, jitter, netLoss); pingA = null
                scoreB = health(netMs, jitter, netLoss, sp)
                updatePingCard()
                setStep(0, 2)
                lowSpeed = sp in 0.0..5.0
                lineProblem = netLoss > 5 || netMs > 120
                val bloat = loaded > 0 && netMs > 0 && loaded - netMs > 150

                setStep(1, 1)
                say("⏳ قياس زمن استجابة استعلام DNS (8 نطاقات × كل خادم)...")
                val ranked = benchmarkDns()
                dnsRank = ranked; curDnsAtStart = ispDns().firstOrNull() ?: ""
                chooseDns(ranked)
                renderDns()
                say(dnsReport)
                setStep(1, 2)

                setStep(2, 1)
                say("⏳ مسح القنوات (3 مرات)...")
                val cs = pickChannel(wm, curCh)
                bestCh = cs.best
                crowded = is24 && (cs.count > 5 || cs.curBad)
                val topChannels = cs.scores.take(5).joinToString("، ") { (ch, score) ->
                    "$ch (${"%.2f".format(Locale.US, score)})"
                }
                say("📡 فحصت القنوات 1–13 | الأقل تداخلاً: $bestCh | الشبكات المرصودة: ${cs.count}")
                if (topChannels.isNotEmpty()) say("📊 أفضل 5 قنوات حسب درجة التداخل: $topChannels")
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
                if (dnsWorth && ranked.isNotEmpty()) causes += "🧭 تم اختيار زوج DNS بناءً على السرعة والاستقرار ونسبة نجاح الاستعلامات ← الأساسي $bestDns والثانوي $bestDns2."
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
                    "استعلام DNS/UDP: ${netMs.toInt()}ms تذبذب ${jitter.toInt()}ms فشل ${netLoss}%\n" +
                    "السرعة: ${fmt(sp)} | زمن أثناء التحميل: ${if (loaded > 0) "${loaded.toInt()}ms" else "—"}\n" +
                    dnsReport + "\n\n" +
                    "🔎 الأسباب:\n" + causes.joinToString("\n") +
                    "\n\n📡 تقييم قنوات 2.4GHz (الأقل تداخلاً أولاً):\n" +
                    cs.scores.take(13).joinToString("\n") { (ch, score) ->
                        "القناة $ch — درجة التداخل ${"%.2f".format(Locale.US, score)}" +
                            (if (ch == bestCh) " ⭐ الاختيار المقترح" else "")
                    }
                setReport(diagText + "\n\n🎯 الخطة: قناة $bestCh + DNS أساسي $bestDns + DNS ثانوي $bestDns2")
                diagBusy = false
                runOnUiThread { fixBtn.isEnabled = true; if (auto) { applyFixes() } else { startBtn.isEnabled = true } }
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
    (function(PH,CH,DNS,DNS2,DOCHG,DOCHAN,WID,PT,USER,PASS){
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
          if(dn.length>=2){r.found=true;r.info=dn[0].value.trim();r.info2=dn[1].value.trim();hl(dn[0]);hl(dn[1]);
            var needs=(r.info!==DNS || r.info2!==DNS2);
            if(DOCHG&&needs){setv(dn[0],DNS);setv(dn[1],DNS2);setTimeout(function(){save(d)},700);r.changed=true}
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
            if(DOCHAN&&tq>=0&&tq!==cs.selectedIndex){cs.selectedIndex=tq;cs.dispatchEvent(new Event('change',{bubbles:true}));chg=true}
            if(DOCHAN&&WID&&ws){for(var q=0;q<ws.options.length;q++){
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
          // لا نضغط على عناصر مجهولة كخطة احتياطية؛ التخطي أكثر أمانًا.
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
    })(${q(ph)},${bestCh},${q(selectedPrimaryDns())},${q(selectedSecondaryDns())},${dnsWorth && !dnsPendingVerify},${!chanPendingVerify},${q(widParam())},$pt,${q(user)},${q(pass)})
    """
    }

    // نوافذ التأكيد المخصصة (HTML) بعد الضغط على Reboot
    private val confirmJs = """
    // لا يتم تأكيد نوافذ الراوتر العامة تلقائيًا؛ يلزم تأكيد المستخدم من واجهة الراوتر.
    (function(){return false})()
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
        dnsDone = false; dnsPendingVerify = false; chanPendingVerify = false; chanDone = false; loginTries = 0; rebootTry = 0
        rebootOk = false; rebootPlanned = false; loggedOut = false
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
            "reboot" -> { rebootPlanned = true; setStep(5, if (chanDone) 2 else 3); setStep(6, 1) }
            "done" -> { setStep(5, if (chanDone) 2 else 3); setStep(6, 3) }
        }
    }

    private fun nextPhase() {
        val i = order.indexOf(phase)
        if (i >= 0 && i < order.size - 1) moveTo(order[i + 1])
        else {
            // إعادة التشغيل لا تتم إلا بعد تغيير إعداد تم رصده؛ لا نعيد التشغيل بسبب بطء السرعة وحده.
            val needReboot = changed
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
                        if (found && r.optBoolean("changed")) {
                            // تم إرسال القيم والحفظ؛ لا نعلن النجاح قبل قراءتها مرة أخرى من الصفحة.
                            if (!dnsPendingVerify && !restoring) {
                                sp.edit().putString("bk_dns1", r.optString("info")).putString("bk_dns2", r.optString("info2")).putString("bk_router", gwIp).apply()
                            }
                            dnsPendingVerify = true
                            wait = 1800
                            log("💾 أرسلت DNS الأساسي والثانوي للحفظ؛ أتحقق الآن من القيم المقروءة من الراوتر...")
                        } else if (found && dnsPendingVerify) {
                            val pRead = r.optString("info").trim()
                            val sRead = r.optString("info2").trim()
                            if (pRead == selectedPrimaryDns() && sRead == selectedSecondaryDns()) {
                                dnsDone = true; changed = true; dnsPendingVerify = false
                                val m = "✅ تم التحقق من DNS بعد إعادة القراءة: الأساسي $pRead | الثانوي $sRead"
                                report += m; log(m); nextPhase()
                            } else if (pt > 8) {
                                dnsPendingVerify = false
                                audit += "⚠ لم أستطع التحقق من حفظ DNS؛ القيم المقروءة: $pRead / $sRead. لم أعتبر التغيير ناجحًا"
                                log("⚠ الراوتر لم يعرض القيم المطلوبة بعد الحفظ؛ أوقف اعتماد DNS وانتقل دون ادعاء النجاح")
                                nextPhase()
                            } else {
                                wait = 1800
                                log("⏳ أنتظر ظهور القيم الجديدة في صفحة الراوتر...")
                            }
                        } else if (found) {
                            dnsDone = !dnsWorth
                            if (dnsWorth) {
                                audit += "⚠ لم يتغير DNS؛ القيم الحالية ${r.optString("info")} / ${r.optString("info2")}. لم يتم إثبات حفظ القيم المطلوبة"
                                log("⚠ لم يؤكد الراوتر تغيير DNS؛ لن أعتبره ناجحًا")
                            } else {
                                audit += "🧭 لم يظهر تحسن كافٍ يبرر تغيير DNS؛ تم الإبقاء على القيم الحالية ${r.optString("info")} / ${r.optString("info2")}"
                                log("🧭 DNS الحالي لم يثبت أنه أبطأ بشكل مؤثر؛ لا تغيير")
                            }
                            nextPhase()
                        } else if (pt > 30) { audit += "🧭 لم أجد حقلي DNS أساسي وثانوي قابلين للتحرير؛ لم أغيّر DNS"; log("⏭ لم أجد حقلي DNS الأساسي والثانوي معًا؛ لن أغيّر إعدادًا جزئيًا"); nextPhase() }
                        else log("🔎 أبحث عن حقلي DNS الأساسي والثانوي...")
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
                            val cur = r.optString("info"); val md = r.optString("md"); val wd = r.optString("wd")
                            val cn = r.optInt("cn", -1)
                            if (r.optBoolean("changed")) {
                                if (!chanPendingVerify && !restoring) sp.edit().putInt("bk_ch", cn.coerceAtLeast(0)).putString("bk_wd", wd).putString("bk_router", gwIp).apply()
                                chanPendingVerify = true
                                wait = 1800
                                log("💾 أرسلت إعداد القناة للحفظ؛ أعيد قراءة الإعداد للتحقق...")
                            } else if (chanPendingVerify) {
                                val channelOk = (bestCh == 0 && cur.contains("auto", true)) || cn == bestCh
                                val widthOk = if (restoring && restoreWid.isNotEmpty()) wd == restoreWid else (!crowded || wd.replace(" ", "").contains("20"))
                                if (channelOk && widthOk) {
                                    chanDone = true; changed = true; chanPendingVerify = false
                                    val m = "✅ تم التحقق من إعداد القناة بعد إعادة القراءة: $cur | العرض $wd"
                                    report += m; log(m); nextPhase()
                                } else if (pt > 8) {
                                    chanPendingVerify = false
                                    audit += "⚠ لم أستطع التحقق من حفظ القناة/العرض؛ القيم المقروءة: $cur / $wd"
                                    log("⚠ لم يؤكد الراوتر إعداد القناة بعد الحفظ؛ لن أعتبره نجاحًا")
                                    nextPhase()
                                } else { wait = 1800; log("⏳ أنتظر تأكيد إعداد القناة من الراوتر...") }
                            } else {
                                val channelOk = (bestCh == 0 && cur.contains("auto", true)) || cn == bestCh
                                val widthOk = if (restoring && restoreWid.isNotEmpty()) wd == restoreWid else (!crowded || wd.replace(" ", "").contains("20"))
                                chanDone = channelOk && widthOk
                                audit += "📡 القناة الحالية: $cur | العرض: ${if (wd.isEmpty()) "—" else wd} | النمط: ${if (md.isEmpty()) "—" else md}"
                                if (chanDone) log("📡 إعداد القناة يطابق الاختيار؛ لا حاجة للتغيير")
                                else log("⚠ تعذّر تأكيد إعداد القناة المطلوب")
                                nextPhase()
                            }
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

    // ================= الواي فاي بعد الريبوت (سبب التوقف السابق) =================
    // بعد الريبوت قد يختار أندرويد بيانات الهاتف كشبكة افتراضية فتفشل كل الاتصالات المحلية؛ لذلك نربط التطبيق بالواي فاي
    private fun bindToWifi(): Boolean = try {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val n = cm.allNetworks.firstOrNull { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true }
        if (n != null) { cm.bindProcessToNetwork(n); true } else false
    } catch (e: Exception) { false }

    private fun routerUp(gw: String): Boolean = listOf(80, 443, 8080).any { tcp(gw, it) >= 0 }

    private fun nudgeWifi() {
        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            if (!wm.isWifiEnabled) wm.isWifiEnabled = true
            wm.reconnect()
        } catch (e: Exception) {}
    }

    private fun awaitInternet() {
        val t0 = System.currentTimeMillis()
        var n = 0
        while (System.currentTimeMillis() - t0 < 90_000L) {
            bindToWifi()
            if (dnsUdp("1.1.1.1") >= 0 || dnsUdp("8.8.8.8") >= 0) { log("🌐 الإنترنت رجع"); break }
            if (n % 4 == 0) log("⏳ أنتظر عودة الإنترنت بعد إعادة التشغيل...")
            n++
            Thread.sleep(3000)
        }
        Thread.sleep(4000)
    }

    // ================= مراقبة إعادة التشغيل (لا تتوقف أبداً: تكمل للفحص والنتيجة دائماً) =================
    private fun rebooting(manualMode: Boolean) {
        val gw = gwIp
        log(if (manualMode) "🖐 اضغط Reboot بنفسك في صفحة الراوتر (كبّرها بإصبعين)، وأنا أراقب وأكمل تلقائياً" else "🔄 تم الضغط على Reboot، أنتظر انقطاع الراوتر...")
        thread {
            try {
                var down = false
                var i = 0
                val limit = if (manualMode) 40 else 12
                while (!down && i < limit) {
                    Thread.sleep(3000)
                    bindToWifi()
                    if (!manualMode && i < 4) runOnUiThread { web.evaluateJavascript(confirmJs, null) }
                    if (!routerUp(gw)) down = true
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
                    rebootOk = false
                    finalizeRun("⚠ لم أتأكد من إعادة تشغيل الراوتر (أعد تشغيله يدوياً)")
                    return@thread
                }
                rebootOk = true
                log("📴 الراوتر انقطع، أنتظر رجوعه...")
                val t0 = System.currentTimeMillis()
                var up = false
                var lastNote = 0L
                while (!up && System.currentTimeMillis() - t0 < 240_000L) {
                    bindToWifi()
                    if (routerUp(gw)) {
                        up = true
                    } else {
                        val el = (System.currentTimeMillis() - t0) / 1000
                        if (el - lastNote >= 15) {
                            lastNote = el
                            log("⏳ أنتظر رجوع الراوتر والواي فاي... (${el}ث)")
                            nudgeWifi()
                        }
                        if (el in 100L..110L) log("📶 لو الواي فاي لم يتصل تلقائياً، اتصل بشبكتك يدوياً وسأكمل")
                        Thread.sleep(3000)
                    }
                }
                setStep(6, if (up) 2 else 3)
                if (up) log("✅ الراوتر رجع") else log("⚠ لم أصل لصفحة الراوتر، سأكمل قياس الجودة على أي حال")
                finalizeRun(if (up) "✅ تمت إعادة تشغيل الراوتر فعلياً (انقطع ثم رجع)" else "⚠ الراوتر أعاد التشغيل لكن لم أستطع الوصول لصفحته بعد رجوعه")
            } catch (e: Exception) {
                log("❌ خطأ أثناء المراقبة: ${e.message}")
                finalizeRun("⚠ حدث خطأ أثناء مراقبة إعادة التشغيل")
            }
        }
    }

    // ================= الفحص بعد الإصلاح ← المقارنة ← تسجيل الخروج ← النتيجة =================
    private fun finalizeRun(msg: String) {
        try {
            bindToWifi()
            setStep(7, 1)
            if (rebootOk) awaitInternet()
            log("⏱ أقيس السرعة بعد الإصلاح...")
            val (after, _) = speedRetry()
            log("⏱ أقيس استجابة DNS/UDP بعد الإصلاح...")
            val pa = pingStats(20)
            gwAfter = stats({ tcp(gwIp, 80) }).first
            pingA = pa
            scoreA = health(pa.first, pa.second, pa.third, after)
            updatePingCard()
            runOnUiThread {
                afterTv.text = mb(after)
                if (beforeSpeed > 0 && after > 0) {
                    val pct = (after - beforeSpeed) / beforeSpeed * 100
                    gainTv.text = (if (pct >= 0) "+" else "") + "%.0f%%".format(pct)
                    gainTv.setTextColor(if (pct >= 0) cGreen else cRed)
                }
            }
            setStep(7, 2)
            setStep(8, 1)
            log("🚪 أسجّل الخروج من صفحة الراوتر...")
            doLogout()
            setStep(8, 2)
            showFinal(msg, after, pa)
        } catch (e: Exception) {
            log("❌ خطأ أثناء الفحص النهائي: ${e.message}")
            setChip("● خطأ", cRed)
            endRun()
        }
    }

    private fun doLogout() {
        val latch = java.util.concurrent.CountDownLatch(1)
        runOnUiThread {
            web.evaluateJavascript(logoutJs, null)
            ui.postDelayed({
                CookieManager.getInstance().removeAllCookies(null)
                web.clearCache(true); web.loadUrl("about:blank")
                latch.countDown()
            }, 2000)
        }
        latch.await(6, java.util.concurrent.TimeUnit.SECONDS)
        loggedOut = true
    }

    private fun endRun() {
        running = false; restoring = false
        try { (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).bindProcessToNetwork(null) } catch (_: Exception) {}
        runOnUiThread { restoreBtn.isEnabled = hasBackup(); startBtn.isEnabled = true }
    }

    private fun finish(msg: String) {
        log(msg)
        if (stepState[6] == 0 || stepState[6] == 1) setStep(6, 3)
        thread { finalizeRun(msg) }
    }

    private fun manual(): String {
        if (restoring) return ""
        val s = mutableListOf<String>()
        if (dnsWorth && !dnsDone) s += "• DNS: من إعدادات الراوتر (DHCP أو LAN أو WAN) اجعل الأساسي ${selectedPrimaryDns()} والثانوي ${selectedSecondaryDns()}"
        if (!chanDone) s += "• القناة: من Wireless ← 2.4GHz اجعل Channel = $bestCh" + (if (crowded) " وعرض القناة 20MHz" else "")
        return if (s.isEmpty()) "" else "\n\n🖐 خطوات يدوية (واجهة راوترك مختلفة عن المتوقع):\n" + s.joinToString("\n")
    }

    // ================= ترتيب الـ DNS ونسبة النجاح =================
    private fun dnsRankText(): String {
        if (dnsRank.isEmpty()) return "لم يتم القياس"
        return "الاختيار التلقائي: أساسي $bestDns | ثانوي $bestDns2\n" + dnsRank.take(17).mapIndexed { i, p ->
            val name = (dnsNames[p.first] ?: "DNS المزوّد") + (if (p.first == curDnsAtStart) " (الحالي)" else "")
            val mark = if (p.first == bestDns) " ⭐" else if (p.first == bestDns2) " ✔" else ""
            "${i + 1}. $name ${p.first} — ${p.second.toInt()}ms$mark"
        }.joinToString("\n")
    }

    private fun renderDns() { val t = dnsRankText(); runOnUiThread { dnsTv.text = t } }

    // نسبة النجاح = 40% اكتمال المهام + 40% صحة الشبكة بعد الإصلاح + 20% مقدار التحسّن
    private fun successScore(after: Double): Int {
        // لا نمنح نقاطًا لمجرد العثور على DNS مرشح؛ النقاط للقراءات والتحقق والاختبار النهائي.
        var tasks = 0
        if (dnsDone) tasks += 25
        if (chanDone) tasks += 20
        if (!rebootPlanned || rebootOk) tasks += 15
        if (after > 0 && pingA?.first?.let { it > 0 } == true) tasks += 30
        if (loggedOut) tasks += 10
        scTasks = tasks
        scImpr = (50 + (scoreA - scoreB) * 2.5).coerceIn(0.0, 100.0).toInt()
        return (tasks * 0.4 + scoreA * 0.4 + scImpr * 0.2).toInt().coerceIn(0, 100)
    }

    private fun ms(x: Double) = if (x < 0) "—" else "${x.toInt()}ms"

    // عنوان النتيجة + تفاصيل المقارنة + لون
    private fun improvementSummary(after: Double, pa: Triple<Double, Double, Int>): Triple<String, String, Int> {
        val lines = mutableListOf<String>()
        var head = "⚠ تعذّر مقارنة السرعة"
        var col = cMuted
        if (beforeSpeed > 0 && after > 0) {
            val g = (after - beforeSpeed) / beforeSpeed * 100
            val gi = Math.abs(g).toInt()
            if (g >= 10) { head = "🎉 تحسّنت السرعة بنسبة +$gi%"; col = cGreen; lines += "✅ السرعة: ${fmt(beforeSpeed)} ← ${fmt(after)} (+$gi%)" }
            else if (g <= -10) { head = "⚠ السرعة انخفضت $gi%"; col = cRed; lines += "⚠ السرعة: ${fmt(beforeSpeed)} ← ${fmt(after)} (-$gi%) — قد يكون تقلّباً مؤقتاً أو الخط نفسه" }
            else { head = "➖ السرعة شبه ثابتة"; col = cAmber; lines += "➖ السرعة: ${fmt(beforeSpeed)} ← ${fmt(after)} (${if (g >= 0) "+" else "-"}$gi%)" }
        } else lines += "⚠ تعذّر قياس السرعة في أحد الاختبارين"
        if (pingB.first > 0 && pa.first > 0) {
            val pg = (pingB.first - pa.first) / pingB.first * 100
            val pi = Math.abs(pg).toInt()
            lines += if (pg >= 10) "✅ زمن استجابة DNS/UDP تحسّن $pi%" else if (pg <= -10) "⚠ زمن الاستجابة ارتفع $pi%" else "➖ زمن DNS/UDP شبه ثابت (${pa.first.toInt()}ms)"
        }
        val jb = pingB.second; val ja = pa.second
        lines += if (ja < jb - 1) "✅ استقرار الاتصال تحسّن (تذبذب ${jb.toInt()}ms ← ${ja.toInt()}ms)"
            else if (ja > jb + 1) "⚠ التذبذب زاد (${jb.toInt()}ms ← ${ja.toInt()}ms)"
            else "➖ التذبذب ثابت (${ja.toInt()}ms)"
        lines += "📈 كفاءة الشبكة: $scoreB% ← $scoreA%"
        return Triple(head, lines.joinToString("\n"), col)
    }

    private fun advice(after: Double, pa: Triple<Double, Double, Int>): String {
        val tips = mutableListOf<String>()
        if (after in 0.0..5.0) tips += "⚠ السرعة ما زالت منخفضة بعد الضبط: السبب خارج الراوتر (خط الشركة أو الباقة). انسخ التقرير وأرسله للشركة."
        else if (beforeSpeed > 0 && after > beforeSpeed * 1.3) tips += "✅ تحسّنت السرعة بشكل واضح."
        if (pa.second > 15 || pa.third > 2) tips += "📉 استجابة DNS/UDP ما زالت غير مستقرة (تذبذب ${pa.second.toInt()}ms، فقد ${pa.third}%): جرّب 5GHz أو كابل وقلّل الأجهزة المتصلة."
        else if (pa.first in 0.0..60.0) tips += "✅ استجابة DNS/UDP مستقرة."
        if (devices > 8) tips += "💡 عدد الأجهزة المتصلة كبير ($devices). افصل غير المستخدم."
        if (tips.isEmpty()) tips += "💡 الشبكة مستقرة."
        return tips.joinToString("\n")
    }

    private fun showFinal(msg: String, after: Double, pa: Triple<Double, Double, Int>) {
        val sp = getSharedPreferences("nf", 0)
        val prev = sp.getFloat("last", -1f)
        val pct = if (restoring) -1 else successScore(after)
        val imp = improvementSummary(after, pa)
        val sb = StringBuilder()
        sb.append(msg).append("\n\n")
        sb.append("🧠 التحليل الذكي الأولي:\n").append(aiSummary).append("\n\n")
        if (pct >= 0) sb.append("🏆 نسبة نجاح الاختبار: $pct/100\n${imp.first}\n${imp.second}\n(اكتمال المهام $scTasks/100 • صحة الشبكة بعد $scoreA/100 • التحسّن $scImpr/100)\n\n")
        if (audit.isNotEmpty()) sb.append("🧪 فحص الراوتر:\n").append(audit.joinToString("\n")).append("\n\n")
        if (report.isNotEmpty()) sb.append("🛠 ما تم تنفيذه:\n").append(report.joinToString("\n")).append("\n\n")
        sb.append("🧭 DNS المستهدف: أساسي ${selectedPrimaryDns()} | ثانوي ${selectedSecondaryDns()}\n")
        sb.append("🧭 ترتيب أسرع DNS:\n").append(dnsRankText()).append("\n\n")
        sb.append(diagText).append("\n\n")
        sb.append("📊 المقارنة قبل ← بعد\n")
        sb.append("السرعة: ${fmt(beforeSpeed)} ← ${fmt(after)}\n")
        sb.append("DNS/UDP: ${pingLine(pingB)}\n  ← ${pingLine(pa)}\n")
        sb.append("الراوتر: ${ms(gwBefore)} ← ${ms(gwAfter)}\n")
        sb.append("درجة صحة الشبكة: $scoreB ← $scoreA\n")
        if (prev > 0) sb.append("🕘 آخر فحص سابق: ${fmt(prev.toDouble())}\n")
        if (after > 0) sp.edit().putFloat("last", after.toFloat()).apply()
        sb.append("\n🎯 التشخيص النهائي: $primary\n").append(advice(after, pa))
        sb.append(manual())
        sb.append("\n\n🚪 تم تسجيل الخروج من الراوتر")
        if (hasBackup()) sb.append("\n↩ تقدر ترجّع إعدادات الراوتر السابقة بزر «استرجاع».")
        lastReport = sb.toString()

        runOnUiThread {
            if (pct >= 0) {
                resultCard.alpha = 0f; resultCard.visibility = View.VISIBLE
                resultCard.animate().alpha(1f).setDuration(500).start()
                val col = if (pct >= 80) cGreen else if (pct >= 55) cAmber else cRed
                resultPct.setTextColor(col)
                resultBarV.progressTintList = ColorStateList.valueOf(col)
                verdictTv.text = imp.first; verdictTv.setTextColor(imp.third)
                resultSub.text = imp.second + "\n\nنسبة النجاح: " + (if (pct >= 80) "ممتازة 🟢" else if (pct >= 55) "جيدة 🟡" else "تحتاج تدخلاً 🔴") +
                    "\nاكتمال المهام $scTasks/100  •  صحة الشبكة $scoreA/100  •  التحسّن $scImpr/100"
                ValueAnimator.ofInt(0, pct).setDuration(1200).apply {
                    addUpdateListener { a -> val v = a.animatedValue as Int; resultPct.text = "$v%"; resultBarV.progress = v }
                }.start()
            }
        }
        setReport(lastReport)
        setChip(if (pct >= 55 || pct < 0) "● اكتمل" else "● يحتاج تدخل", if (pct >= 55 || pct < 0) cGreen else cAmber)
        log("🏁 انتهى الاختبار" + (if (pct >= 0) " — نسبة النجاح $pct%" else ""))
        endRun()
    }
}
