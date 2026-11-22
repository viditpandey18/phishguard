package com.phishguard.shield

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Talks to the PhishGuard API (POST /v1/scan/text). Falls back to the
 * on-device [OfflineRules] when the server can't be reached, so the phone is
 * never left unprotected. Must be called off the main thread.
 */
object PhishGuardClient {

    private const val CONNECT_TIMEOUT_MS = 2500
    private const val READ_TIMEOUT_MS = 4000

    fun scan(ctx: Context, text: String, channel: String): Verdict =
        try {
            scanOnServer(ctx, text, channel)
        } catch (e: Exception) {
            OfflineRules.scan(text)
        }

    private fun scanOnServer(ctx: Context, text: String, channel: String): Verdict {
        val body = JSONObject()
            .put("text", text.take(20_000))
            .put("channel", if (channel in setOf("sms", "whatsapp", "email")) channel else "other")
            .toString()
        val conn = open(ctx, "/v1/scan/text").apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("content-type", "application/json; charset=utf-8")
        }
        try {
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            if (code !in 200..299) throw IllegalStateException("HTTP $code")
            val json = JSONObject(conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() })
            val flags = json.optJSONArray("red_flags")
            val reasons = buildList {
                if (flags != null) for (i in 0 until flags.length()) add(flags.getJSONObject(i).optString("description"))
            }.filter { it.isNotBlank() }
            return Verdict(
                label = json.getString("label"),
                risk = json.optInt("risk_score"),
                reasons = reasons,
                action = json.optString("recommended_action"),
                source = "server",
            )
        } finally {
            conn.disconnect()
        }
    }

    /** Returns a short human-readable status for the "Test connection" button. */
    fun health(ctx: Context): String =
        try {
            val conn = open(ctx, "/v1/info")
            try {
                val code = conn.responseCode
                if (code != 200) "Server answered HTTP $code"
                else {
                    val json = JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
                    val model = if (json.isNull("text_model")) "rules engine" else "ML + rules"
                    "Connected: PhishGuard v${json.optString("version")} ($model)"
                }
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            "Can't reach server (${e.javaClass.simpleName}). The offline rules will be used instead."
        }

    private fun open(ctx: Context, path: String): HttpURLConnection {
        val conn = URL(Prefs.serverUrl(ctx) + path).openConnection() as HttpURLConnection
        conn.connectTimeout = CONNECT_TIMEOUT_MS
        conn.readTimeout = READ_TIMEOUT_MS
        conn.setRequestProperty("accept", "application/json")
        Prefs.apiKey(ctx).takeIf { it.isNotBlank() }?.let { conn.setRequestProperty("x-api-key", it) }
        return conn
    }
}
