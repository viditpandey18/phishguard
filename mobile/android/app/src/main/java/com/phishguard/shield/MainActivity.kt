package com.phishguard.shield

import android.Manifest
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.format.DateUtils
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.materialswitch.MaterialSwitch

class MainActivity : AppCompatActivity() {

    private lateinit var tvStatus: TextView
    private lateinit var tvStatusDetail: TextView
    private lateinit var tvStats: TextView
    private lateinit var swProtection: MaterialSwitch
    private lateinit var swStrict: MaterialSwitch
    private lateinit var btnListener: Button
    private lateinit var btnSms: Button
    private lateinit var btnNotif: Button
    private lateinit var etServer: EditText
    private lateinit var etKey: EditText
    private lateinit var tvTest: TextView
    private lateinit var etSample: EditText
    private lateinit var tvResult: TextView
    private lateinit var llThreats: LinearLayout

    private val prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ -> runOnUiThread { refresh() } }

    private val askPermissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { refresh() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        Notifier.createChannels(this)

        tvStatus = findViewById(R.id.tvStatus)
        tvStatusDetail = findViewById(R.id.tvStatusDetail)
        tvStats = findViewById(R.id.tvStats)
        swProtection = findViewById(R.id.swProtection)
        swStrict = findViewById(R.id.swStrict)
        btnListener = findViewById(R.id.btnListener)
        btnSms = findViewById(R.id.btnSms)
        btnNotif = findViewById(R.id.btnNotif)
        etServer = findViewById(R.id.etServer)
        etKey = findViewById(R.id.etKey)
        tvTest = findViewById(R.id.tvTest)
        etSample = findViewById(R.id.etSample)
        tvResult = findViewById(R.id.tvResult)
        llThreats = findViewById(R.id.llThreats)

        swProtection.isChecked = Prefs.protectionOn(this)
        swStrict.isChecked = Prefs.strict(this)
        swProtection.setOnCheckedChangeListener { _, on -> Prefs.setProtection(this, on) }
        swStrict.setOnCheckedChangeListener { _, on -> Prefs.setStrict(this, on) }

        etServer.setText(Prefs.serverUrl(this))
        etKey.setText(Prefs.apiKey(this))

        btnListener.setOnClickListener { startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) }
        btnSms.setOnClickListener { askPermissions.launch(arrayOf(Manifest.permission.RECEIVE_SMS)) }
        btnNotif.setOnClickListener {
            if (Build.VERSION.SDK_INT >= 33) askPermissions.launch(arrayOf(Manifest.permission.POST_NOTIFICATIONS))
            else startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
        }

        findViewById<Button>(R.id.btnTest).setOnClickListener {
            saveServer()
            tvTest.text = "Testing…"
            Shield.executor.execute {
                val msg = PhishGuardClient.health(this)
                runOnUiThread { tvTest.text = msg }
            }
        }

        findViewById<Button>(R.id.btnScan).setOnClickListener {
            val text = etSample.text.toString().trim()
            if (text.isEmpty()) return@setOnClickListener
            saveServer()
            tvResult.text = "Scanning…"
            Shield.executor.execute {
                val v = PhishGuardClient.scan(this, text, "sms")
                runOnUiThread { showResult(v) }
            }
        }

        findViewById<Button>(R.id.btnClear).setOnClickListener { Prefs.clearThreats(this) }
    }

    override fun onResume() {
        super.onResume()
        Prefs.get(this).registerOnSharedPreferenceChangeListener(prefsListener)
        refresh()
    }

    override fun onPause() {
        super.onPause()
        Prefs.get(this).unregisterOnSharedPreferenceChangeListener(prefsListener)
        saveServer()
    }

    private fun saveServer() = Prefs.saveServer(this, etServer.text.toString(), etKey.text.toString())

    private fun granted(perm: String) = ContextCompat.checkSelfPermission(this, perm) == PackageManager.PERMISSION_GRANTED

    private fun refresh() {
        val listener = Shield.listenerEnabled(this)
        val sms = granted(Manifest.permission.RECEIVE_SMS)
        val notif = Notifier.canPost(this)
        val on = Prefs.protectionOn(this)

        btnListener.text = if (listener) "✓ Notification access enabled" else "1. Enable notification access"
        btnSms.text = if (sms) "✓ SMS scanning allowed" else "2. Allow SMS scanning"
        btnNotif.text = if (notif) "✓ Alerts allowed" else "3. Allow alerts"

        val (status, color, detail) = when {
            !on -> Triple("Protection paused", R.color.pg_warn, "Turn protection on to scan incoming messages.")
            listener -> Triple("Protection active", R.color.pg_safe,
                "Scams from WhatsApp, Gmail and SMS are hidden before you can tap them.")
            sms -> Triple("Partial protection", R.color.pg_warn,
                "SMS scams trigger a warning. Enable notification access to hide them and cover WhatsApp and Gmail.")
            else -> Triple("Not protected yet", R.color.pg_bad, "Complete the setup steps below.")
        }
        tvStatus.text = status
        tvStatus.setTextColor(ContextCompat.getColor(this, color))
        tvStatusDetail.text = detail

        val s = Prefs.stats(this)
        tvStats.text = "Scanned ${s.scanned}  ·  Blocked ${s.blocked}  ·  Warned ${s.warned}"

        renderThreats()
    }

    private fun showResult(v: Verdict) {
        val color = when {
            v.malicious -> R.color.pg_bad
            v.suspicious -> R.color.pg_warn
            else -> R.color.pg_safe
        }
        tvResult.setTextColor(ContextCompat.getColor(this, color))
        val reasons = if (v.reasons.isEmpty()) "No red flags." else v.reasons.joinToString("\n• ", "• ")
        val src = if (v.source == "server") "PhishGuard server" else "offline rules (server unreachable)"
        tvResult.text = "${v.label.uppercase()} · risk ${v.risk}/100\n$reasons\n\nChecked by: $src"
    }

    private fun renderThreats() {
        llThreats.removeAllViews()
        val threats = Prefs.threats(this)
        if (threats.isEmpty()) {
            llThreats.addView(TextView(this).apply {
                text = "Nothing blocked yet. Scams that reach your phone will be listed here."
                setTextColor(ContextCompat.getColor(context, R.color.pg_muted))
            })
            return
        }
        val pad = (10 * resources.displayMetrics.density).toInt()
        for (t in threats.take(50)) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, pad, 0, pad)
            }
            val head = TextView(this).apply {
                val verb = if (t.hidden) "BLOCKED" else "WARNED"
                text = "$verb ${t.label} · ${t.risk}/100 · ${t.app} · ${t.sender}"
                setTypeface(typeface, Typeface.BOLD)
                setTextColor(ContextCompat.getColor(context, if (t.label == "suspicious") R.color.pg_warn else R.color.pg_bad))
            }
            val why = TextView(this).apply {
                text = "${t.reason} · ${DateUtils.getRelativeTimeSpanString(t.time)}"
                setTextColor(ContextCompat.getColor(context, R.color.pg_muted))
                textSize = 12f
            }
            val body = TextView(this).apply {
                text = t.text
                maxLines = 3
                setTextColor(ContextCompat.getColor(context, R.color.pg_text))
                textSize = 13f
                // tap to expand the full message
                setOnClickListener { maxLines = if (maxLines == 3) 50 else 3 }
            }
            row.addView(head)
            row.addView(why)
            row.addView(body)
            llThreats.addView(row)
            llThreats.addView(View(this).apply {
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1)
                setBackgroundColor(ContextCompat.getColor(context, R.color.pg_line))
            })
        }
    }
}
