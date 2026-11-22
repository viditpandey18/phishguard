# 📱 PhishGuard Shield (Android)

Companion app that checks incoming **SMS, WhatsApp, Gmail, Outlook and Telegram** messages with the PhishGuard engine and **hides scam notifications before you can tap them**. Blocked messages go to an in-app quarantine with the reason, and you get a "🛡️ Blocked a scam from …" alert instead.

## How it works

| Piece | What it does |
|---|---|
| `ShieldListenerService` | Notification listener. Reads the text of new notifications from messaging/email apps, scans it, and calls `cancelNotification()` on scams |
| `SmsReceiver` | Fallback when notification access is off: scans every incoming SMS and shows a warning |
| `PhishGuardClient` | `POST /v1/scan/text` to your PhishGuard server (timeouts: 2.5 s connect, 4 s read) |
| `OfflineRules` | On-device keyword rules used if the server is unreachable, so the phone is never unprotected |
| `MainActivity` | Setup, server URL/API key, test box, stats and quarantine list |

**Honest limits (say these if judges ask):**
- Android lets only the **default SMS app** delete an SMS. PhishGuard hides the *notification* and quarantines a copy. The original still exists inside the Messages/WhatsApp/Gmail app.
- Gmail notifications show only the sender, subject and a snippet, so email scans use that text, not the full headers. Moving a mail to Spam would need the Gmail API (OAuth), which this app doesn't do.
- Android 15+ hides OTP-style notification content from listener apps. Those are usually legitimate bank OTPs anyway.
- Message text is sent to **your own** PhishGuard server, which doesn't store content by default (`PG_STORE_CONTENT=false`). The quarantine list is stored only on the phone.

## Build & install

1. Install **Android Studio** (it bundles the JDK and Android SDK).
2. *File → Open* → select the `mobile/android` folder. Let Gradle sync (it downloads Gradle 8.9, AGP 8.7 and Kotlin 2.0). Accept any suggested upgrade if your Studio version asks.
3. Turn on **Developer options → USB debugging** on the phone, plug it in, and press ▶ Run.
   Or use *Build → Build APK(s)* and copy `app/build/outputs/apk/debug/app-debug.apk` to the phone.

## Connect the phone to your laptop's server

```powershell
# on the laptop, from the phishguard folder
$env:PG_API_KEYS = "choose-a-long-secret"
.\run.ps1 -Lan          # prints  Phone : http://192.168.x.x:8000
```
- Phone and laptop must be on the **same Wi-Fi**. Allow Python through Windows Firewall for *Private* networks when asked.
- In the app, enter that URL and the API key, then tap **Save & test connection**.

## Grant permissions (in the app, top to bottom)
1. **Enable notification access**: turn on *PhishGuard Shield*.
   On Android 13+ with a sideloaded APK the switch may be greyed out ("Restricted setting"). Go to *Settings → Apps → PhishGuard Shield → ⋮ → Allow restricted settings*, then try again.
2. **Allow SMS scanning** (RECEIVE_SMS).
3. **Allow alerts** (Android 13+ notification permission).

## Demo script
1. Show the app's status: **Protection active**.
2. From a second phone, send: `Aapka KYC pending hai, account aaj raat band ho jayega. Turant link pe click karein: bit.ly/kyc-upd8`
3. The SMS notification disappears and **🛡️ Blocked a scam** appears. Open the app: the message is in Quarantine with its reasons.
4. Send a normal message ("Kal milte hain?"): it's delivered untouched.
5. Turn the laptop's Wi-Fi off and repeat step 2. The offline rules still catch it.
