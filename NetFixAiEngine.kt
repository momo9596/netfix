package com.example.netfix

import android.content.Context
import android.net.wifi.WifiManager
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

data class AiResult(
    val overall: String,
    val findings: List<String>,
    val recommendations: List<String>
) {
    fun toArabicText(): String {
        val sb = StringBuilder()
        sb.append("الحكم العام: ").append(overall).append("\n\n")
        sb.append("🔎 الأدلة:\n")
        findings.forEach { sb.append("• ").append(it).append("\n") }
        sb.append("\n💡 التوصيات:\n")
        recommendations.forEach { sb.append("• ").append(it).append("\n") }
        sb.append("\nلا يتم تغيير أي إعداد في هذه المرحلة.")
        return sb.toString()
    }
}

object NetFixAiEngine {

    private fun tcp(host: String, port: Int): Long = try {
        val t = System.nanoTime()
        Socket().use { it.connect(InetSocketAddress(host, port), 1500) }
        (System.nanoTime() - t) / 1_000_000
    } catch (e: Exception) {
        -1L
    }

    private fun dnsUdp(server: String): Long {
        val id = (Math.random() * 65535).toInt()
        val bo = java.io.ByteArrayOutputStream()
        bo.write(byteArrayOf((id shr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        "example.com".split(".").forEach { bo.write(it.length); bo.write(it.toByteArray()) }
        bo.write(byteArrayOf(0, 0, 1, 0, 1))
        val q = bo.toByteArray()
        return try {
            DatagramSocket().use { s ->
                s.soTimeout = 1500
                val t = System.nanoTime()
                s.send(DatagramPacket(q, q.size, InetAddress.getByName(server), 53))
                val buf = ByteArray(512)
                s.receive(DatagramPacket(buf, 512))
                (System.nanoTime() - t) / 1_000_000
            }
        } catch (e: Exception) {
            -1L
        }
    }

    private fun avgLoss(n: Int, f: () -> Long): Pair<Double, Int> {
        val ok = (1..n).map { f() }.filter { it >= 0 }
        return Pair(if (ok.isEmpty()) -1.0 else ok.average(), (n - ok.size) * 100 / n)
    }

    @Suppress("DEPRECATION")
    fun analyze(ctx: Context, gateway: String): AiResult {
        val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val info = wm.connectionInfo
        val findings = mutableListOf<String>()
        val recs = mutableListOf<String>()
        var problems = 0

        val is24 = info.frequency in 2400..2500
        findings += "الإشارة ${info.rssi}dBm على ${if (is24) "2.4" else "5"}GHz وسرعة الوصلة ${info.linkSpeed}Mbps"
        if (info.rssi < -75) {
            problems++
            recs += "اقترب من الراوتر أو أزل العوائق؛ الإشارة ضعيفة."
        }
        if (info.linkSpeed in 1..20) {
            problems++
            recs += "سرعة الوصلة منخفضة؛ جرّب 5GHz أو قرّب الهاتف."
        }

        val (gwMs, gwLoss) = avgLoss(5) { tcp(gateway, 80) }
        if (gwMs < 0) {
            findings += "تعذّر الاتصال بالراوتر على المنفذ 80"
            problems++
            recs += "تأكد من عنوان الراوتر ومن اتصالك بشبكته."
        } else {
            findings += "الراوتر: ${gwMs.toInt()}ms وفقد $gwLoss%"
            if (gwMs > 40 || gwLoss > 5) {
                problems++
                recs += "الاتصال بالراوتر غير مستقر؛ المشكلة غالباً في الواي فاي."
            }
        }

        val (netMs, netLoss) = avgLoss(8) { dnsUdp("1.1.1.1") }
        if (netMs < 0) {
            findings += "تعذّر قياس استجابة الإنترنت (DNS/UDP)"
            problems++
            recs += "الإنترنت قد يكون منقطعاً أو UDP محجوب."
        } else {
            findings += "استجابة الإنترنت: ${netMs.toInt()}ms وفشل $netLoss%"
            if (netMs > 120 || netLoss > 5) {
                problems++
                recs += "الخط أو المزوّد غير مستقر."
            }
        }

        if (recs.isEmpty()) recs += "لا توجد مشكلة واضحة؛ يمكن المتابعة للفحص الكامل."
        val overall = when {
            problems == 0 -> "الشبكة سليمة 🟢"
            problems <= 2 -> "توجد مشاكل بسيطة 🟡"
            else -> "توجد مشاكل واضحة 🔴"
        }
        return AiResult(overall, findings, recs)
    }
}
