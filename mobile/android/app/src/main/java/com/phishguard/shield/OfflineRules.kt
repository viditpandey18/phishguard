package com.phishguard.shield

/**
 * Small on-device fallback used when the PhishGuard server is unreachable.
 * Much simpler than the server engine: a weighted keyword/regex score for the
 * most common Indian scam patterns (English, Hinglish, Hindi).
 */
object OfflineRules {

    private class Rule(val weight: Double, val reason: String, pattern: String) {
        val regex = Regex(pattern, setOf(RegexOption.IGNORE_CASE))
    }

    private val rules = listOf(
        Rule(2.0, "Asks you to update KYC/PAN/Aadhaar details", """\b(kyc|pan\s*card|aadhaa?r)\b.{0,40}\b(update|pending|expire|verify|link)|केवाईसी"""),
        Rule(3.0, "Asks for your OTP, PIN or CVV", """\b(share|send|tell|batao|bataye|bataen|bhejo|provide)\b.{0,25}\b(otp|pin|cvv|password)\b|ओटीपी\s*(बताएं|भेजें|बताओ)"""),
        Rule(1.5, "Threatens to block or suspend your account", """\b(block(ed)?|suspend(ed)?|deactivat\w*|band ho|disconnect\w*)\b|बंद हो"""),
        Rule(1.0, "Creates urgency", """\b(urgent\w*|immediately|turant|jaldi|within \d+ ?(hours?|hrs?|minutes?)|aaj raat|today)\b|तुरंत"""),
        Rule(2.0, "Promises a prize or lottery win", """\b(lottery|you have won|won rs|prize|kbc|jackpot|lucky draw|cashback of)\b"""),
        Rule(1.5, "Asks you to pay a fee to receive money", """\b(processing|registration|clearance|delivery)\s+(fee|charge)"""),
        Rule(2.5, "Police / customs / 'digital arrest' threat", """\b(arrest\w*|warrant|customs|narcotics|cbi|cyber ?crime police|illegal (drugs|parcel))\b"""),
        Rule(2.0, "Asks you to install a remote-access app", """\b(anydesk|teamviewer|quicksupport|rustdesk)\b"""),
        Rule(1.5, "Link uses a URL shortener that hides the destination", """\b(bit\.ly|tinyurl\.com|is\.gd|cutt\.ly|t\.ly|rb\.gy|shorturl\.at)/"""),
        Rule(1.5, "Link uses a domain ending often abused by scammers", """https?://[^\s/]+\.(xyz|top|tk|ml|ga|cf|gq|click|icu|buzz|rest|cfd|sbs)\b"""),
        Rule(1.0, "Pushes you to click a link", """\b(click|tap|open)\b.{0,20}\b(link|here|below)\b|link pe"""),
        Rule(1.5, "Job or investment offer with unrealistic pay", """\b(work from home|part[- ]time job|daily (income|earning)|earn rs ?\d|guaranteed returns?|double your money)\b"""),
    )

    private val negatedOtp = Regex("""\b(do not|don'?t|never|mat)\b.{0,15}\b(share|batayein|bataye|batao)""", RegexOption.IGNORE_CASE)

    fun scan(text: String): Verdict {
        val hits = rules.filter { it.regex.containsMatchIn(text) }
            // "Do not share this OTP" is what real banks say - don't count it as an OTP request.
            .filterNot { it.reason.startsWith("Asks for your OTP") && negatedOtp.containsMatchIn(text) }
        val score = hits.sumOf { it.weight }
        val label = when {
            score >= 4.5 -> "scam"
            score >= 2.5 -> "suspicious"
            else -> "safe"
        }
        val risk = (score / 7.0 * 100).toInt().coerceIn(0, 100)
        return Verdict(
            label = label,
            risk = risk,
            reasons = hits.sortedByDescending { it.weight }.map { it.reason },
            action = if (label == "safe") "No obvious scam signs." else "Do not click links, call back or share any codes.",
            source = "offline",
        )
    }
}
