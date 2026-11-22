package com.phishguard.shield

/** Result of scanning one message, from the server or from the offline rules. */
data class Verdict(
    val label: String,          // safe | suspicious | phishing | scam
    val risk: Int,              // 0..100
    val reasons: List<String>,  // human-readable red flags, strongest first
    val action: String,
    val source: String,         // "server" or "offline"
) {
    val malicious: Boolean get() = label == "phishing" || label == "scam"
    val suspicious: Boolean get() = label == "suspicious"
    val topReason: String get() = reasons.firstOrNull() ?: "High-risk message"
}

/** A message the shield blocked or warned about (stored only on this phone). */
data class Threat(
    val time: Long,
    val app: String,
    val sender: String,
    val text: String,
    val label: String,
    val risk: Int,
    val reason: String,
    val hidden: Boolean,
)
