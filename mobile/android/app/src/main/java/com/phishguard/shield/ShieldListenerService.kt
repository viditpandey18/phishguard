package com.phishguard.shield

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationCompat

/**
 * Watches notifications from messaging and email apps. When a message is a
 * scam, it removes the notification so you can't tap it, puts the message in
 * PhishGuard's quarantine and shows a "blocked" alert instead.
 *
 * Note: this hides the *notification*. The original message still exists
 * inside WhatsApp/Gmail/Messages; only the app that owns it can delete it.
 */
class ShieldListenerService : NotificationListenerService() {

    private data class Source(val name: String, val channel: String)

    private val watched = mapOf(
        "com.whatsapp" to Source("WhatsApp", "whatsapp"),
        "com.whatsapp.w4b" to Source("WhatsApp Business", "whatsapp"),
        "com.google.android.gm" to Source("Gmail", "email"),
        "com.microsoft.office.outlook" to Source("Outlook", "email"),
        "com.google.android.apps.messaging" to Source("Messages", "sms"),
        "com.samsung.android.messaging" to Source("Samsung Messages", "sms"),
        "com.android.mms" to Source("Messages", "sms"),
        "com.oneplus.mms" to Source("Messages", "sms"),
        "com.miui.mms" to Source("Messages", "sms"),
        "com.truecaller" to Source("Truecaller", "sms"),
        "org.telegram.messenger" to Source("Telegram", "other"),
        "com.instagram.android" to Source("Instagram", "other"),
    )

    /** Remembers what we've already scanned; apps often re-post the same notification. */
    private val seen = object : LinkedHashMap<String, Boolean>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?) = size > 300
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName == packageName) return
        val source = watched[sbn.packageName] ?: return
        val ctx = applicationContext
        if (!Prefs.protectionOn(ctx)) return

        val n = sbn.notification ?: return
        if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return // "3 new messages" summaries
        val (sender, text) = extract(n) ?: return
        if (text.length < 8) return

        val dedupeKey = "${sbn.key}|${text.hashCode()}"
        synchronized(seen) {
            val previous = seen[dedupeKey]
            if (previous != null) {
                if (previous) cancelSafely(sbn.key) // already judged a scam: hide the re-post too
                return
            }
            seen[dedupeKey] = false
        }

        Shield.executor.execute {
            val hide = Shield.process(ctx, source.name, sender, text, source.channel, canHide = true)
            if (hide) {
                synchronized(seen) { seen[dedupeKey] = true }
                cancelSafely(sbn.key)
            }
        }
    }

    private fun cancelSafely(key: String) {
        try {
            cancelNotification(key)
        } catch (_: Exception) {
            // listener was disconnected; nothing else we can do
        }
    }

    /** Pulls (sender, message text) out of a notification. */
    private fun extract(n: Notification): Pair<String, String>? {
        // Chat apps (WhatsApp, Messages) use MessagingStyle: take the newest message.
        NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(n)?.let { style ->
            val last = style.messages.lastOrNull()
            val text = last?.text?.toString()
            if (last != null && !text.isNullOrBlank()) {
                val sender = last.person?.name?.toString()
                    ?: style.conversationTitle?.toString()
                    ?: n.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
                    ?: "Unknown"
                return sender to text
            }
        }
        // Email apps and plain notifications: title = sender, big text = subject + snippet.
        val extras = n.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: "Unknown"
        val text = (extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
            ?: extras.getCharSequence(Notification.EXTRA_TEXT))?.toString()
            ?: extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.lastOrNull()?.toString()
            ?: return null
        return title to text
    }
}
