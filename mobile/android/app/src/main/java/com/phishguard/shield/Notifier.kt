package com.phishguard.shield

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicInteger

/** PhishGuard's own alerts: "scam blocked" and "be careful" notifications. */
object Notifier {
    private const val CH_BLOCKED = "blocked"
    private const val CH_WARN = "warnings"
    private val ids = AtomicInteger(1000)

    fun createChannels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CH_BLOCKED, "Blocked scams", NotificationManager.IMPORTANCE_HIGH)
                .apply { description = "Shown when PhishGuard hides a scam or phishing message" }
        )
        nm.createNotificationChannel(
            NotificationChannel(CH_WARN, "Suspicious messages", NotificationManager.IMPORTANCE_DEFAULT)
                .apply { description = "Messages that look risky but were not hidden" }
        )
    }

    fun canPost(ctx: Context): Boolean =
        NotificationManagerCompat.from(ctx).areNotificationsEnabled() &&
            (Build.VERSION.SDK_INT < 33 ||
                ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED)

    fun blocked(ctx: Context, app: String, sender: String, v: Verdict) =
        post(ctx, CH_BLOCKED, "🛡️ Blocked a ${v.label} from $sender",
            "$app · risk ${v.risk}/100 · ${v.topReason}", "${v.topReason}\n\n${v.action}")

    fun warning(ctx: Context, app: String, sender: String, v: Verdict, hidden: Boolean) =
        post(ctx, if (hidden) CH_BLOCKED else CH_WARN,
            if (hidden) "🛡️ Hid a suspicious message from $sender" else "⚠️ Be careful with this message from $sender",
            "$app · risk ${v.risk}/100 · ${v.topReason}", "${v.reasons.joinToString("\n• ", "• ")}\n\n${v.action}")

    private fun post(ctx: Context, channel: String, title: String, text: String, big: String) {
        createChannels(ctx)
        if (!canPost(ctx)) return
        val open = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(ctx, channel)
            .setSmallIcon(R.drawable.ic_shield)
            .setColor(0xFFF43F5E.toInt())
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(big))
            .setPriority(if (channel == CH_BLOCKED) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(ctx).notify(ids.incrementAndGet(), n)
        } catch (_: SecurityException) {
            // permission revoked between check and post - nothing to do
        }
    }
}
