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

