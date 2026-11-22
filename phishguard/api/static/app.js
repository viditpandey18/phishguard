// PhishGuard web UI. Security: every value coming back from the API (which may
// contain attacker-controlled text) is inserted with textContent / text nodes -
// never as HTML - and the page is served with a strict CSP (script-src 'self').
"use strict";

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const GAUGE_C = 2 * Math.PI * 52;
const MALICIOUS = new Set(["phishing", "scam"]);
const LABEL_COLOR = { safe: "#34d399", suspicious: "#fbbf24", phishing: "#f43f5e", scam: "#f43f5e" };
const HEADLINE = {
  safe: "Looks safe", suspicious: "Proceed with caution",
  phishing: "Phishing attempt detected", scam: "Scam detected",
};

let mode = "auto";
let emlFile = null;
let lastScanId = null;

// ------------------------------------------------------------------ helpers
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}

function headers(json = true) {
  const h = json ? { "content-type": "application/json" } : {};
  const key = $("apiKey").value.trim();
  if (key) h["x-api-key"] = key;
  return h;
}

async function apiScan(content, inputType) {
  const res = await fetch("/v1/scan", { method: "POST", headers: headers(), body: JSON.stringify({ content, input_type: inputType }) });
  return handle(res);
}

async function handle(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
    throw new Error(`${res.status}: ${detail || res.statusText}`);
  }
  return data;
}

function countUp(node, to, ms = 900) {
  const start = performance.now();
  const step = (t) => {
    const p = Math.min(1, (t - start) / ms);
    node.textContent = String(Math.round(to * (1 - Math.pow(1 - p, 3))));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ------------------------------------------------------------------ examples
const EXAMPLES = {
  "Bank KYC scam": ["text", "Dear Customer, your SBI account will be blocked today. Please update your PAN card immediately by clicking http://sbi-kyc-update.xyz/login", true],
  "KYC (Hinglish)": ["text", "Aapka KYC pending hai, aapka account aaj raat band ho jayega. Turant is link pe click karein: bit.ly/kyc-upd8", true],
  "OTP scam (हिंदी)": ["text", "प्रिय ग्राहक, आपका बैंक खाता बंद हो जाएगा। तुरंत केवाईसी अपडेट करें और अपना ओटीपी बताएं।", true],
  "KBC lottery": ["text", "Congratulations! You have won Rs 25,00,000 in KBC lottery. To claim your prize pay processing fee of Rs 12,500. Contact on WhatsApp +91 98765 43210", true],
  "Digital arrest": ["text", "FedEx alert: your parcel containing illegal drugs and 5 passports has been seized by customs. Mumbai cyber crime police will issue an arrest warrant. Press 1 to speak to the officer immediately.", true],
  "Phishing URL": ["url", "https://secure-login.hdfcbank.com.verify-account.top/netbanking", true],
  "Look-alike URL": ["url", "http://paypa1.com/signin", true],
  "Phishing email": ["email",
    "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-security.com; dkim=none; dmarc=fail header.from=paypa1-security.com\n" +
    "From: \"PayPal Security\" <service@paypa1-security.com>\nReply-To: helpdesk.paypal@gmail.com\nTo: user@example.com\n" +
    "Subject: Your account has been limited\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n" +
    "<html><body><p>Dear Customer,</p><p>Your account will be suspended within 24 hours unless you verify your information.</p>" +
    "<p><a href=\"http://paypa1-security.com/login.php\">https://www.paypal.com/login</a></p></body></html>\n", true],
  "Legit OTP": ["text", "482913 is your OTP for login to HDFC Bank NetBanking. Valid for 5 mins. Do not share this OTP with anyone. -HDFC Bank", false],
  "Friend chat": ["text", "Bhai kal match dekhne chalega? Tickets maine book kar li hain, 6 baje stadium ke bahar milte hain.", false],
  "Safe URL": ["url", "https://github.com/python/cpython", false],
  "Legit email": ["email",
    "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com\n" +
    "From: GitHub <noreply@github.com>\nTo: dev@example.com\nSubject: [GitHub] A new SSH key was added to your account\n" +
    "MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nHi there,\n\nThe following SSH key was added to your account. " +
    "If you believe this key was added in error, you can remove it at https://github.com/settings/keys\n\nThanks,\nThe GitHub Team\n", false],
};

// ------------------------------------------------------------------ scanner
function setMode(m) {
  mode = m;
  document.querySelectorAll("#mode button").forEach((b) => b.classList.toggle("active", b.dataset.mode === m));
}

function clearFile() { emlFile = null; $("eml").value = ""; $("fileName").textContent = ""; }

function showPanel(which) {
  for (const id of ["empty", "scanning", "result"]) $(id).classList.toggle("hidden", id !== which);
}

async function scan() {
  const content = $("content").value;
  if (!content.trim() && !emlFile) { $("content").focus(); return; }
  const btn = $("scan");
  btn.disabled = true;
  btn.querySelector(".btn-label").textContent = "Scanning…";
  $("error").classList.add("hidden");
  showPanel("scanning");
  const card = document.querySelector(".result-card");
  card.classList.remove("danger", "warn", "ok");
  try {
    const started = performance.now();
    let req;
    if (emlFile) {
      const fd = new FormData();
      fd.append("file", emlFile);
      req = fetch("/v1/scan/email/upload", { method: "POST", body: fd, headers: headers(false) }).then(handle);
    } else {
      req = apiScan(content, mode);
    }
    const data = await req;
    const elapsed = performance.now() - started;
    if (elapsed < 700) await sleep(700 - elapsed); // let the scan animation read
    render(data, emlFile ? null : content);
  } catch (e) {
    showPanel("empty");
    $("error").textContent = `Error ${e.message}`;
    $("error").classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.querySelector(".btn-label").textContent = "Scan now";
  }
}

function render(r, original) {
  lastScanId = r.scan_id;
  $("fbMsg").textContent = "";
  document.querySelectorAll("#fbChips .chip").forEach((c) => { c.disabled = false; });
  showPanel("result");

  const color = LABEL_COLOR[r.label] || LABEL_COLOR.suspicious;
  const card = document.querySelector(".result-card");
  card.classList.add(MALICIOUS.has(r.label) ? "danger" : r.label === "suspicious" ? "warn" : "ok");

  // gauge
  const arc = $("gaugeArc");
  arc.style.stroke = color;
  arc.style.color = color;
  arc.style.strokeDashoffset = String(GAUGE_C);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    arc.style.strokeDashoffset = String(GAUGE_C * (1 - r.risk_score / 100));
  }));
  $("score").style.color = color;
  countUp($("score"), r.risk_score);

  const badge = $("badge");
  badge.textContent = r.label;
  badge.className = `badge ${r.label}`;
  $("headline").textContent = HEADLINE[r.label] || r.label;
  $("explanation").textContent = r.explanation;

  const meta = [
    `${r.input_type}`,
    `confidence ${Math.round(r.confidence * 100)}% (${r.confidence_level})`,
    r.model.text_model ? `model: ${r.model.text_model}` : "heuristics engine",
    r.model.calibrated ? "calibrated" : "uncalibrated",
    `${Math.round(r.latency_ms)} ms`,
  ];
  $("meta").replaceChildren(...meta.map((m) => el("span", m)));

  const action = $("action");
  action.textContent = r.recommended_action;
  action.className = `action ${MALICIOUS.has(r.label) ? "danger" : r.label === "suspicious" ? "warn" : ""}`;

  // highlighted message
  const hl = original ? buildHighlight(original, r.red_flags) : null;
  $("highlightBlock").classList.toggle("hidden", !hl);
  if (hl) $("highlight").replaceChildren(...hl);

  // red flags
  const maxC = Math.max(0.01, ...r.red_flags.map((f) => Math.abs(f.contribution)),
                       ...r.mitigating_factors.map((f) => Math.abs(f.contribution)));
  $("flags").replaceChildren(...r.red_flags.map((f, i) => flagNode(f, maxC, i, false)));
  $("flagCount").textContent = r.red_flags.length ? String(r.red_flags.length) : "";
  $("noFlags").classList.toggle("hidden", r.red_flags.length !== 0);
  $("mitig").replaceChildren(...r.mitigating_factors.map((f, i) => flagNode(f, maxC, i, true)));
  $("mitigBlock").classList.toggle("hidden", r.mitigating_factors.length === 0);

  // layers
  const layers = Object.entries(r.layer_scores);
  $("layers").replaceChildren(...(layers.length ? layers.map(([k, v]) => {
    const d = el("div", undefined, `layer ${v >= 50 ? "hot" : ""}`);
    const h = el("div", undefined, "lh");
    h.append(el("span", k), el("b", `${v}`));
    const bar = el("div", undefined, "bar");
    const fill = el("i");
    bar.append(fill);
    d.append(h, bar);
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${v}%`; }));
    return d;
  }) : [el("p", "No layer fired.", "muted small")]));
  $("urls").replaceChildren(...(r.urls_analyzed.length ? r.urls_analyzed.map((u) => el("li", u)) : [el("li", "No links found")]));
  $("raw").textContent = JSON.stringify(r, null, 2);

  if (window.innerWidth < 1060) document.querySelector(".result-card").scrollIntoView({ behavior: "smooth", block: "start" });
}

function flagNode(f, maxC, i, good) {
  const d = el("div", undefined, `flag ${good ? "good" : f.severity}`);
  d.style.animationDelay = `${i * 70}ms`;
  const sev = el("span", undefined, "sev");
  const body = el("div");
  body.append(el("span", f.description, "desc"));
  if (f.evidence) body.append(el("span", f.evidence, "ev"));
  const tags = el("div", undefined, "tags");
  tags.append(el("span", good ? "reassuring" : f.severity), el("span", f.layer));
  body.append(tags);
  const c = el("div", undefined, "contrib");
  c.append(el("b", `${f.contribution >= 0 ? "+" : ""}${f.contribution.toFixed(2)}`));
  const bar = el("div", undefined, "bar");
  const fill = el("i");
  bar.append(fill);
  c.append(bar);
  requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${Math.min(100, (Math.abs(f.contribution) / maxC) * 100)}%`; }));
  d.append(sev, body, c);
  return d;
}

// Evidence looks like `"kyc pending"` (text) or `bit[.]ly/x: bit.ly` (url).
// Find those snippets in the user's own input and wrap them in <mark> nodes.
function buildHighlight(text, flags) {
  const src = text.slice(0, 20000);
  const lower = src.toLowerCase();
  const rank = { high: 3, medium: 2, low: 1 };
  const ranges = [];
  for (const f of flags) {
    const needles = [];
    for (const m of f.evidence.matchAll(/"([^"]{2,120})"/g)) needles.push(m[1]);
    if (f.layer === "url" && f.evidence) needles.push(f.evidence.split(": ")[0].replace(/\[\.\]/g, ".").replace(/^hxxp/i, "http"));
    for (const n of needles) {
      const needle = n.toLowerCase().trim();
      if (needle.length < 2) continue;
      let from = 0, idx;
      while ((idx = lower.indexOf(needle, from)) !== -1 && ranges.length < 200) {
        ranges.push([idx, idx + needle.length, f.severity]);
        from = idx + needle.length;
      }
    }
  }
  if (!ranges.length) return null;
  ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const merged = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) {
      last[1] = Math.max(last[1], r[1]);
      if (rank[r[2]] > rank[last[2]]) last[2] = r[2];
    } else merged.push([...r]);
  }
  const out = [];
  let pos = 0;
  for (const [s, e, sev] of merged) {
    if (s > pos) out.push(document.createTextNode(src.slice(pos, s)));
    out.push(el("mark", src.slice(s, e), sev));
    pos = e;
  }
  if (pos < src.length) out.push(document.createTextNode(src.slice(pos)));
  return out;
}

async function sendFeedback(label) {
  if (!lastScanId) return;
  document.querySelectorAll("#fbChips .chip").forEach((c) => { c.disabled = true; });
  try {
    const res = await fetch("/v1/feedback", { method: "POST", headers: headers(),
      body: JSON.stringify({ scan_id: lastScanId, correct_label: label }) });
    $("fbMsg").textContent = res.ok ? `✓ Saved "${label}". Only detection features are kept, never your message.` : `Failed (${res.status})`;
  } catch {
    $("fbMsg").textContent = "Failed to send feedback";
  }
}

// ------------------------------------------------------------------ engine status
async function loadInfo() {
  try {
    const info = await fetch("/v1/info").then((r) => r.json());
    $("engine").classList.add("ok");
    $("engineText").textContent = `Engine online · ${info.text_model ? "ML + rules" : "rules engine"} · v${info.version}`;
  } catch {
    $("engine").classList.add("down");
    $("engineText").textContent = "Engine offline";
  }
}

// ------------------------------------------------------------------ phone shield demo
const APP_ICON = { sms: "💬", whatsapp: "🟢", gmail: "✉️" };
const APP_NAME = { sms: "SMS", whatsapp: "WhatsApp", gmail: "Gmail" };

function email(from, subject, body, auth) {
  return `Authentication-Results: mx.google.com; ${auth}\nFrom: ${from}\nTo: you@gmail.com\nSubject: ${subject}\n` +
         `MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n${body}\n`;
}

const DEMO = [
  { app: "sms", sender: "AX-HDFCBK", text: "482913 is your OTP for login to HDFC Bank NetBanking. Valid for 5 mins. Do not share this OTP with anyone. -HDFC Bank" },
  { app: "sms", sender: "+91 70112 58430", text: "Dear Customer, your SBI account will be blocked today. Please update your PAN card immediately by clicking http://sbi-kyc-update.xyz/login" },
  { app: "whatsapp", sender: "Rahul (College)", text: "Bhai kal match dekhne chalega? Tickets maine book kar li hain, 6 baje stadium ke bahar milte hain." },
  { app: "whatsapp", sender: "+91 98765 43210", text: "Congratulations! You have won Rs 25,00,000 in KBC lottery. To claim your prize pay processing fee of Rs 12,500 on this number today." },
  { app: "gmail", sender: "PayPal Security", subject: "Your account has been limited", type: "email",
    text: email("\"PayPal Security\" <service@paypa1-security.com>\nReply-To: helpdesk.paypal@gmail.com", "Your account has been limited",
      "Dear Customer,\nYour account will be suspended within 24 hours unless you verify your information at http://paypa1-security.com/login.php",
      "spf=fail smtp.mailfrom=paypa1-security.com; dkim=none; dmarc=fail header.from=paypa1-security.com") },
  { app: "sms", sender: "Mom", text: "Beta khana kha liya? Papa aaj late aayenge, dinner pe wait mat karna." },
  { app: "sms", sender: "+91 83920 11745", text: "Aapka KYC pending hai, aapka account aaj raat band ho jayega. Turant is link pe click karein: bit.ly/kyc-upd8" },
  { app: "gmail", sender: "GitHub", subject: "A new SSH key was added to your account", type: "email",
    text: email("GitHub <noreply@github.com>", "[GitHub] A new SSH key was added to your account",
      "Hi there,\nThe following SSH key was added to your account. If you believe this key was added in error, you can remove it at https://github.com/settings/keys\nThanks,\nThe GitHub Team",
      "spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com") },
  { app: "whatsapp", sender: "+44 7700 900123", text: "FedEx alert: your parcel containing illegal drugs and 5 passports has been seized by customs. Mumbai cyber crime police will issue an arrest warrant. Press 1 to speak to the officer immediately." },
  { app: "sms", sender: "JD-SWIGGY", text: "Your Swiggy order #4821 from Paradise Biryani is out for delivery and will reach you in 12 minutes." },
  { app: "sms", sender: "+91 62019 77342", text: "प्रिय ग्राहक, आपका बैंक खाता बंद हो जाएगा। तुरंत केवाईसी अपडेट करें और अपना ओटीपी बताएं।" },
];

const demo = { running: false, token: 0, idx: 0, stats: { scanned: 0, blocked: 0, warned: 0, safe: 0 } };

function now() { return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }

function bumpStat(id, val) {
  const n = $(id);
  n.textContent = String(val);
  n.parentElement.classList.add("bump");
  setTimeout(() => n.parentElement.classList.remove("bump"), 250);
}

function refreshCounts() {
  $("inboxCount").textContent = String($("inbox").children.length);
  $("blockedCount").textContent = String($("blocked").children.length);
  $("phoneEmpty").classList.toggle("hidden", $("inbox").children.length + $("blocked").children.length > 0);
}

function msgNode(m) {
  const li = el("li", undefined, "msg scanning-msg");
  const av = el("div", APP_ICON[m.app], `avatar ${m.app}`);
  const main = el("div");
  const top = el("div", undefined, "top");
  top.append(el("b", m.sender), el("small", `${APP_NAME[m.app]} · ${now()}`));
  const preview = m.type === "email" ? `${m.subject}: ${m.text.split("\n\n").slice(1).join(" ")}` : m.text;
  const chip = el("span", "Scanning…", "verdict-chip");
  main.append(top, el("div", preview, "body"), chip);
  li.append(av, main);
  li.title = "Click to inspect in the scanner";
  li.addEventListener("click", () => {
    setMode(m.type === "email" ? "email" : "text");
    $("content").value = m.text;
    clearFile();
    document.getElementById("scanner").scrollIntoView({ behavior: "smooth" });
    scan();
  });
  return { li, chip };
}

function toast(title, body) {
  $("toastTitle").textContent = title;
  $("toastBody").textContent = body;
  const t = $("toast");
  t.classList.add("hidden");
  void t.offsetWidth; // restart animation
  t.classList.remove("hidden");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add("hidden"), 2600);
}

function logEvent(status, m, r) {
  const list = $("log");
  if (list.firstElementChild && !list.firstElementChild.classList.contains("ev")) list.replaceChildren();
  const li = el("li", undefined, "ev");
  const why = r ? (r.red_flags[0] ? r.red_flags[0].description : "No red flags") : "Engine unreachable";
  const sc = el("span", r ? `${r.risk_score}` : "-", "sc");
  if (r) sc.style.color = LABEL_COLOR[r.label];
  li.append(el("time", now()), el("span", status, `lbl ${status}`), el("span", `${APP_NAME[m.app]} · ${m.sender}: ${why}`, "why"), sc);
  list.prepend(li);
}

async function deliver(m, token) {
  const { li, chip } = msgNode(m);
  $("inbox").prepend(li);
  refreshCounts();
  let r;
  try {
    r = await apiScan(m.text, m.type || "text");
  } catch (e) {
    if (token !== demo.token) return;
    li.classList.remove("scanning-msg");
    chip.textContent = "Scan failed";
    logEvent("warned", m, null);
    return;
  }
  await sleep(450);
  if (token !== demo.token) return;
  li.classList.remove("scanning-msg");
  demo.stats.scanned++;
  bumpStat("stScanned", demo.stats.scanned);

  if (MALICIOUS.has(r.label)) {
    chip.textContent = `⛔ Blocked · ${r.label} · ${r.risk_score}/100`;
    li.classList.add("blocked");
    toast(`Blocked a ${r.label} ${m.app === "gmail" ? "email" : "message"}`, `From ${m.sender}: ${r.red_flags[0] ? r.red_flags[0].description : "high risk"}`);
    demo.stats.blocked++;
    bumpStat("stBlocked", demo.stats.blocked);
    logEvent("blocked", m, r);
    await sleep(700);
    if (token !== demo.token) return;
    li.classList.add("zap");
    await sleep(650);
    if (token !== demo.token) return;
    li.classList.remove("zap");
    $("blocked").prepend(li);
  } else if (r.label === "suspicious") {
    chip.textContent = `⚠ Caution · ${r.risk_score}/100`;
    li.classList.add("warn");
    demo.stats.warned++;
    bumpStat("stWarned", demo.stats.warned);
    logEvent("warned", m, r);
  } else {
    chip.textContent = `✓ Verified safe · ${r.risk_score}/100`;
    li.classList.add("safe");
    demo.stats.safe++;
    bumpStat("stSafe", demo.stats.safe);
    logEvent("delivered", m, r);
  }
  refreshCounts();
}

async function runDemo() {
  if (demo.running) { stopDemo(); return; }
  demo.running = true;
  const token = ++demo.token;
  $("demoStart").textContent = "⏸ Pause";
  while (demo.running && token === demo.token && demo.idx < DEMO.length) {
    await deliver(DEMO[demo.idx++], token);
    await sleep($("demoFast").checked ? 500 : 1900);
  }
  if (token === demo.token) {
    demo.running = false;
    $("demoStart").textContent = demo.idx >= DEMO.length ? "✓ Demo complete" : "▶ Resume";
  }
}

function stopDemo() {
  demo.running = false;
  demo.token++;
  $("demoStart").textContent = "▶ Resume";
}

function resetDemo() {
  demo.running = false;
  demo.token++;
  demo.idx = 0;
  demo.stats = { scanned: 0, blocked: 0, warned: 0, safe: 0 };
  for (const id of ["stScanned", "stBlocked", "stWarned", "stSafe"]) $(id).textContent = "0";
  $("inbox").replaceChildren();
  $("blocked").replaceChildren();
  $("log").replaceChildren(el("li", "No events yet.", "muted small"));
  $("demoStart").textContent = "▶ Start demo";
  $("toast").classList.add("hidden");
  setPhoneTab("inbox");
  refreshCounts();
}

function setPhoneTab(tab) {
  document.querySelectorAll("#ptabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $("inbox").classList.toggle("hidden", tab !== "inbox");
  $("blocked").classList.toggle("hidden", tab !== "blocked");
}

function injectMessage() {
  const text = $("injText").value.trim();
  if (!text) { $("injText").focus(); return; }
  const app = $("injApp").value;
  const sender = $("injSender").value.trim() || "Unknown";
  $("injText").value = "";
  setPhoneTab("inbox");
  deliver({ app, sender, text }, demo.token);
}

// ------------------------------------------------------------------ wiring
document.querySelectorAll("#mode button").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
$("scan").addEventListener("click", scan);
$("content").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) scan(); });
$("clear").addEventListener("click", () => {
  $("content").value = ""; clearFile();
  showPanel("empty"); $("error").classList.add("hidden");
  document.querySelector(".result-card").classList.remove("danger", "warn", "ok");
});
$("eml").addEventListener("change", (e) => {
  emlFile = e.target.files[0] || null;
  $("fileName").textContent = emlFile ? `${emlFile.name} will be scanned` : "";
});
const dz = $("dropzone");
dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("drag"); });
dz.addEventListener("dragleave", () => dz.classList.remove("drag"));
dz.addEventListener("drop", (e) => {
  e.preventDefault();
  dz.classList.remove("drag");
  const f = e.dataTransfer.files[0];
  if (f) { emlFile = f; $("fileName").textContent = `${f.name} will be scanned`; setMode("email"); scan(); }
});
document.querySelectorAll("#fbChips .chip").forEach((c) => c.addEventListener("click", () => sendFeedback(c.dataset.label)));

for (const [name, [m, text, bad]] of Object.entries(EXAMPLES)) {
  const b = el("button", undefined, "chip");
  b.append(el("i", undefined, bad ? "bad" : "ok"), document.createTextNode(name));
  b.addEventListener("click", () => { setMode(m); $("content").value = text; clearFile(); scan(); });
  $("examples").append(b);
}

$("demoStart").addEventListener("click", () => { if (demo.idx >= DEMO.length && !demo.running) resetDemo(); runDemo(); });
$("demoReset").addEventListener("click", resetDemo);
$("injSend").addEventListener("click", injectMessage);
$("injText").addEventListener("keydown", (e) => { if (e.key === "Enter") injectMessage(); });
document.querySelectorAll("#ptabs button").forEach((b) => b.addEventListener("click", () => setPhoneTab(b.dataset.tab)));

const tick = () => { $("clock").textContent = new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }).replace(/\s?[AP]M$/i, ""); };
tick();
setInterval(tick, 30000);
refreshCounts();
loadInfo();
