package com.phishguard.shield

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

/** Settings, counters and the quarantine list. Everything stays on the phone. */
object Prefs {
    private const val FILE = "phishguard"
    private const val MAX_THREATS = 100
    const val DEFAULT_SERVER = "http://192.168.1.10:8000"

    fun get(ctx: Context): SharedPreferences = ctx.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun serverUrl(ctx: Context): String = normalizeUrl(get(ctx).getString("server", DEFAULT_SERVER) ?: DEFAULT_SERVER)
    fun apiKey(ctx: Context): String = get(ctx).getString("api_key", "") ?: ""
    fun protectionOn(ctx: Context): Boolean = get(ctx).getBoolean("protection", true)
    fun strict(ctx: Context): Boolean = get(ctx).getBoolean("strict", false)

    fun saveServer(ctx: Context, url: String, key: String) {
        get(ctx).edit().putString("server", normalizeUrl(url)).putString("api_key", key.trim()).apply()
    }

    fun setProtection(ctx: Context, on: Boolean) = get(ctx).edit().putBoolean("protection", on).apply()
    fun setStrict(ctx: Context, on: Boolean) = get(ctx).edit().putBoolean("strict", on).apply()

    fun normalizeUrl(raw: String): String {
        var u = raw.trim().trimEnd('/')
        if (u.isEmpty()) u = DEFAULT_SERVER
        if (!u.startsWith("http://") && !u.startsWith("https://")) u = "http://$u"
        return u
    }

    // ---------------------------------------------------------------- counters
    data class Stats(val scanned: Int, val blocked: Int, val warned: Int)

    fun stats(ctx: Context): Stats = get(ctx).let {
        Stats(it.getInt("n_scanned", 0), it.getInt("n_blocked", 0), it.getInt("n_warned", 0))
    }

    @Synchronized
    fun count(ctx: Context, verdict: Verdict, hidden: Boolean) {
        val p = get(ctx)
        val e = p.edit().putInt("n_scanned", p.getInt("n_scanned", 0) + 1)
        if (hidden) e.putInt("n_blocked", p.getInt("n_blocked", 0) + 1)
        else if (verdict.malicious || verdict.suspicious) e.putInt("n_warned", p.getInt("n_warned", 0) + 1)
        e.apply()
    }

    // ---------------------------------------------------------------- quarantine
    @Synchronized
    fun addThreat(ctx: Context, t: Threat) {
        val arr = JSONArray(get(ctx).getString("threats", "[]"))
        val out = JSONArray().put(
            JSONObject()
                .put("time", t.time).put("app", t.app).put("sender", t.sender)
                .put("text", t.text.take(600)).put("label", t.label).put("risk", t.risk)
                .put("reason", t.reason).put("hidden", t.hidden)
        )
        for (i in 0 until minOf(arr.length(), MAX_THREATS - 1)) out.put(arr.getJSONObject(i))
        get(ctx).edit().putString("threats", out.toString()).apply()
    }

    fun threats(ctx: Context): List<Threat> {
        val arr = JSONArray(get(ctx).getString("threats", "[]"))
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            Threat(
                o.getLong("time"), o.getString("app"), o.getString("sender"), o.getString("text"),
                o.getString("label"), o.getInt("risk"), o.getString("reason"), o.optBoolean("hidden"),
            )
        }
    }

    fun clearThreats(ctx: Context) {
        get(ctx).edit().putString("threats", "[]").putInt("n_scanned", 0).putInt("n_blocked", 0).putInt("n_warned", 0).apply()
    }
}
