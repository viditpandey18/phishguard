package com.phishguard.shield

import android.content.Context
import androidx.core.app.NotificationManagerCompat
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** The decision logic shared by the SMS receiver and the notification listener. */
object Shield {

    /** All network/scan work runs here, never on the main thread. */
    val executor: ExecutorService = Executors.newFixedThreadPool(2)

    fun listenerEnabled(ctx: Context): Boolean =
        NotificationManagerCompat.getEnabledListenerPackages(ctx).contains(ctx.packageName)

    /**
     * Scans one message, records it, and alerts the user.
     *
     * @param canHide true when the caller is able to hide the original
     *   notification (notification listener). The SMS receiver can't, so it
     *   only warns.
     * @return true if the caller should hide the original notification.
     */
    fun process(ctx: Context, app: String, sender: String, text: String, channel: String, canHide: Boolean): Boolean {
        val v = PhishGuardClient.scan(ctx, text, channel)
        val shouldHide = canHide && (v.malicious || (v.suspicious && Prefs.strict(ctx)))
        Prefs.count(ctx, v, shouldHide)

        if (v.malicious || v.suspicious) {
            Prefs.addThreat(ctx, Threat(System.currentTimeMillis(), app, sender, text, v.label, v.risk, v.topReason, shouldHide))
            when {
                v.malicious && shouldHide -> Notifier.blocked(ctx, app, sender, v)
                else -> Notifier.warning(ctx, app, sender, v, shouldHide)
            }
        }
        return shouldHide
    }
}
