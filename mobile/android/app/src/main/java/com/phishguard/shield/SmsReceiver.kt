package com.phishguard.shield

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

/**
 * Fallback path for SMS when notification access is NOT granted.
 *
 * Android only lets the *default SMS app* delete or suppress an SMS, so this
 * receiver can't hide the message. It warns you instead, with a high-priority
 * alert explaining why the SMS is a scam. With notification access enabled,
 * [ShieldListenerService] handles SMS too and can hide the notification.
 */
class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val ctx = context.applicationContext
        if (!Prefs.protectionOn(ctx)) return
        if (Shield.listenerEnabled(ctx)) return // listener will see the SMS app's notification and can hide it

        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        // A long SMS arrives in several parts: join them per sender.
        val bySender = parts.filterNotNull().groupBy { it.originatingAddress ?: "Unknown" }
            .mapValues { (_, msgs) -> msgs.joinToString("") { it.messageBody ?: "" } }
            .filterValues { it.isNotBlank() }
        if (bySender.isEmpty()) return

        val pending = goAsync()
        Shield.executor.execute {
            try {
                for ((sender, body) in bySender) {
                    Shield.process(ctx, "SMS", sender, body, "sms", canHide = false)
                }
            } finally {
                pending.finish()
            }
        }
    }
}
