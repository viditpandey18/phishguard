// PhishGuard Defense Console: front-end.
// Security: everything from the API or the user (attacker-controlled text!) is
// inserted with textContent / text nodes, never as HTML. The page is served
// with a strict CSP (script-src 'self', no inline script, no third parties).
"use strict";

const $ = (id) => document.getElementById(id);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const SVGNS = "http://www.w3.org/2000/svg";
const RING = 2 * Math.PI * 52;
const MALICIOUS = new Set(["phishing", "scam"]);
const TONE = { safe: "success", suspicious: "warning", phishing: "danger", scam: "danger" };
const RISK_COLOR = { safe: "var(--success)", suspicious: "var(--warning)", phishing: "var(--danger)", scam: "var(--danger)" };

// ------------------------------------------------------------------ DOM helpers
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function icon(name, cls) {
  const s = document.createElementNS(SVGNS, "svg");
  if (cls) s.setAttribute("class", cls);
  const u = document.createElementNS(SVGNS, "use");
  u.setAttribute("href", `#i-${name}`);
  s.append(u);
  return s;
}
function verdictBadge(label, small = false) {
  const b = el("span", `badge verdict-badge ${label}${small ? " badge-sm" : ""}`);
  b.append(el("span", "dot"), document.createTextNode(label));
  return b;
}
function riskCell(label, risk) {
  const wrap = el("span", "risk-cell");
  const bar = el("span", "risk-mini");
  const fill = el("i");
  fill.style.width = `${risk}%`;
  fill.style.background = RISK_COLOR[label];
  bar.append(fill);
  wrap.append(bar, document.createTextNode(String(risk)));
  return wrap;
}
const fmtTime = (d) => d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const preview = (s, n = 90) => { const t = s.replace(/\s+/g, " ").trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };

// ------------------------------------------------------------------ toasts
function toast(kind, title, body = "") {
  const t = el("div", `toast ${kind}`);
  t.append(icon(kind === "success" ? "check" : kind === "error" ? "alert" : "info"));
  const txt = el("div");
  txt.append(el("b", "", title));
  if (body) txt.append(el("span", "", body));
  t.append(txt);
  $("toasts").append(t);
  setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 220); }, 3200);
}

// ------------------------------------------------------------------ API
function apiHeaders(json = true) {
  const h = json ? { "content-type": "application/json" } : {};
  const key = $("apiKey").value.trim();
  if (key) h["x-api-key"] = key;
  return h;
}
async function api(path, opts = {}, retry = true) {
  const res = await fetch(path, opts);
  if (res.status === 429 && retry) {
    const wait = Math.min(8, parseInt(res.headers.get("retry-after") || "2", 10));
    await sleep(wait * 1000);
    return api(path, opts, false);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
    const msg = res.status === 401 ? "This server requires an API key (Scanner → API key)."
      : res.status === 413 ? "Input is too large."
      : res.status === 429 ? "Too many requests. Wait a few seconds." : (detail || res.statusText);
    throw new Error(msg);
  }
  return data;
}
const scanApi = (content, input_type) =>
  api("/v1/scan", { method: "POST", headers: apiHeaders(), body: JSON.stringify({ content, input_type }) });

// ================================================================== THEME
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $("themeBtn").querySelector("use").setAttribute("href", t === "dark" ? "#i-sun" : "#i-moon");
  try { localStorage.setItem("pg-theme", t); } catch { /* storage disabled */ }
}
function initTheme() {
  let t = "dark";
  try { t = localStorage.getItem("pg-theme") || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"); } catch { /* ignore */ }
  applyTheme(t);
  $("themeBtn").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
}

// ================================================================== ROUTER
const PAGES = {
  overview: ["Overview", "Real-time scam and phishing defense"],
  scanner: ["Threat Scanner", "Analyze messages, emails and links with explainable results"],
  shield: ["Phone Shield", "Watch PhishGuard intercept scams on a device in real time"],
  activity: ["Activity", "Everything scanned in this session"],
  about: ["How it works", "Detection layers, pipeline and privacy"],
};
function route() {
  const page = (location.hash.match(/^#\/(\w+)/) || [])[1];
  const name = PAGES[page] ? page : "overview";
  $$("[data-page]").forEach((p) => { p.hidden = p.dataset.page !== name; });
  $$("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === name));
  $("pageTitle").textContent = PAGES[name][0];
  $("pageSub").textContent = PAGES[name][1];
  document.title = `${PAGES[name][0]} · PhishGuard`;
  closeSidebar();
  window.scrollTo({ top: 0 });
}
const go = (page) => { if (location.hash !== `#/${page}`) location.hash = `#/${page}`; else route(); };
function closeSidebar() { $("sidebar").classList.remove("open"); $("scrim").classList.remove("show"); }

// ================================================================== SAMPLES
const SAMPLES = [
  { name: "SBI KYC lure", bad: true, type: "text", threat: ["shield-alert", "KYC / bank lure", "\"Account will be blocked\" plus a link to update KYC or PAN.", "English · Hinglish"],
    text: "Dear Customer, your SBI account will be blocked today. Please update your PAN card immediately by clicking http://sbi-kyc-update.xyz/login" },
  { name: "Hindi OTP theft", bad: true, type: "text", threat: ["lock", "OTP theft", "Asks you to share the one-time password you just received.", "हिंदी · English"],
    text: "प्रिय ग्राहक, आपका बैंक खाता बंद हो जाएगा। तुरंत केवाईसी अपडेट करें और अपना ओटीपी बताएं।" },
  { name: "Digital arrest", bad: true, type: "text", threat: ["alert", "Digital arrest", "Fake police or customs officers claim your parcel held drugs.", "English"],
    text: "FedEx alert: your parcel containing illegal drugs and 5 passports has been seized by customs. Mumbai cyber crime police will issue an arrest warrant. Press 1 to speak to the officer immediately." },
  { name: "Electricity cut-off", bad: true, type: "text", threat: ["zap", "Utility disconnection", "\"Power will be cut tonight. Call this officer now.\"", "English · Hinglish"],
    text: "Dear consumer your electricity power will be disconnected tonight at 9.30pm because your previous month bill was not updated. Please immediately call our electricity officer 9876543210" },
  { name: "Task job scam", bad: true, type: "text", threat: ["activity", "Task / job scam", "Easy money for liking videos, then moved to Telegram.", "English · Hinglish"],
    text: "Part time job offer! Earn Rs 5000 per day by liking YouTube videos. Work from home, no experience. Contact HR on Telegram for task group link." },
  { name: "Look-alike URL", bad: true, type: "url", threat: ["link", "Look-alike links", "A brand name in the subdomain hides the real, attacker-owned domain.", "Any language"],
    text: "https://secure-login.hdfcbank.com.verify-account.top/netbanking" },
  { name: "Spoofed PayPal email", bad: true, type: "email", threat: ["mail", "Spoofed email", "Failed DMARC, Gmail Reply-To, and a link whose text lies about its target.", "Email"],
    text: "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-security.com; dkim=none; dmarc=fail header.from=paypa1-security.com\n" +
      "From: \"PayPal Security\" <service@paypa1-security.com>\nReply-To: helpdesk.paypal@gmail.com\nTo: user@example.com\n" +
      "Subject: Your account has been limited\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n" +
      "<html><body><p>Dear Customer,</p><p>Your account will be suspended within 24 hours unless you verify your information.</p>" +
      "<p><a href=\"http://paypa1-security.com/login.php\">https://www.paypal.com/login</a></p></body></html>\n" },
  { name: "CEO gift cards", bad: true, type: "text", threat: ["message", "CEO gift-card fraud", "\"Buy gift cards urgently and keep this confidential.\"", "English"],
    text: "Hi, this is your CEO. I need you to buy 5 Google Play gift cards urgently for a client and send me the codes. Keep this confidential." },
  { name: "Hidden characters", bad: true, type: "text",
    text: "Your P​a​y​P​a​l account has been su​spended. Verify your password now at http://paypa1-secure.com/login" },
  { name: "Real bank OTP", bad: false, type: "text",
    text: "482913 is your OTP for login to HDFC Bank NetBanking. Valid for 5 mins. Do not share this OTP with anyone. -HDFC Bank" },
  { name: "Friend (Hinglish)", bad: false, type: "text",
    text: "Bhai kal match dekhne chalega? Tickets maine book kar li hain, 6 baje stadium ke bahar milte hain." },
  { name: "GitHub email", bad: false, type: "email",
    text: "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com\n" +
      "From: GitHub <noreply@github.com>\nTo: dev@example.com\nSubject: [GitHub] A new SSH key was added to your account\n" +
      "MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nHi there,\n\nThe following SSH key was added to your account. " +
      "If you believe this key was added in error, you can remove it at https://github.com/settings/keys\n\nThanks,\nThe GitHub Team\n" },
];

// ================================================================== HISTORY / DASHBOARD
const scans = []; // in-memory only, for this tab (not persisted)
let historyFilter = "all";

const TACTICS = [
  [/^url\.(typosquat|homoglyph_brand|combosquat|brand_in_subdomain|brand_in_path)/, "Look-alike / brand-spoof link"],
  [/credential_request/, "OTP / password request"],
  [/kyc_update/, "KYC / PAN lure"],
  [/law_enforcement/, "Police / digital arrest"],
  [/prize/, "Prize / lottery"],
  [/job_investment/, "Job / investment scam"],
  [/utility_disconnect/, "Utility disconnection"],
  [/remote_access/, "Remote-access app"],
  [/gift_card/, "Gift card / crypto"],
  [/payment_request/, "Fee / payment request"],
  [/^(hdr|att)\./, "Email spoofing / attachment"],
  [/(invisible_chars|mixed_script|link_text_mismatch)/, "Obfuscation tricks"],
  [/(threat|urgency|secrecy)/, "Pressure & threats"],
  [/^url\./, "Risky link"],
];
function tacticsOf(r) {
  const out = new Set();
  for (const f of r.red_flags) {
    const hit = TACTICS.find(([rx]) => rx.test(f.id));
    if (hit) out.add(hit[1]);
  }
  return out;
}

function addHistory(entry) {
  scans.unshift({ id: entry.response.scan_id, ts: new Date(), ...entry });
  refreshDashboard();
}

function refreshDashboard() {
  const n = scans.length;
  const threats = scans.filter((h) => MALICIOUS.has(h.response.label)).length;
  $("navCount").textContent = n;
  $("kScans").textContent = n;
  $("kScansSub").textContent = n ? `${scans.filter((h) => h.source === "Phone Shield").length} from Phone Shield` : "Run a scan to get started";
  $("kThreats").textContent = threats;
  if (n) {
    const avg = scans.reduce((a, h) => a + h.response.latency_ms, 0) / n;
    $("kLatency").textContent = `${avg < 10 ? avg.toFixed(1) : Math.round(avg)} ms`;
  }

  // recent activity (5)
  const recent = scans.slice(0, 5);
  $("recentBody").replaceChildren(...recent.map((h) => {
    const tr = el("tr");
    const inputTd = el("td");
    const wrap = el("div", "cell-type");
    wrap.append(icon(h.type === "url" ? "link" : h.type === "email" ? "mail" : "message"));
    wrap.append(el("span", "cell-preview", h.preview));
    inputTd.append(wrap);
    const vTd = el("td"); vTd.append(verdictBadge(h.response.label, true));
    const rTd = el("td", "num"); rTd.append(riskCell(h.response.label, h.response.risk_score));
    tr.append(inputTd, vTd, rTd, el("td", "num cell-mono", fmtTime(h.ts)));
    tr.addEventListener("click", () => openFromHistory(h));
    return tr;
  }));
  $("recentEmpty").classList.toggle("hidden", recent.length > 0);
  $("recentBody").closest(".table-wrap").classList.toggle("hidden", recent.length === 0);

  // threat breakdown
  const counts = new Map();
  for (const h of scans) if (h.response.label !== "safe") for (const t of tacticsOf(h.response)) counts.set(t, (counts.get(t) || 0) + 1);
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = Math.max(1, ...rows.map((r) => r[1]));
  $("breakdown").replaceChildren(...rows.map(([name, c]) => {
    const row = el("div", "bd-row");
    const bar = el("div", "bd-bar"); const fill = el("i"); bar.append(fill);
    row.append(el("span", "", name), el("b", "", c), bar);
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${(c / max) * 100}%`; }));
    return row;
  }));
  $("breakdownEmpty").classList.toggle("hidden", rows.length > 0);

  renderHistory();
}

function renderHistory() {
  const keep = (h) => historyFilter === "all" || (historyFilter === "threat" ? MALICIOUS.has(h.response.label) : h.response.label === historyFilter);
  const rows = scans.filter(keep);
  $("historyBody").replaceChildren(...rows.map((h) => {
    const tr = el("tr");
    const typeTd = el("td"); const t = el("span", "cell-type");
    t.append(icon(h.type === "url" ? "link" : h.type === "email" ? "mail" : "message"), document.createTextNode(h.type)); typeTd.append(t);
    const vTd = el("td"); vTd.append(verdictBadge(h.response.label, true));
    const rTd = el("td", "num"); rTd.append(riskCell(h.response.label, h.response.risk_score));
    tr.append(el("td", "cell-mono", fmtTime(h.ts)), el("td", "", h.source), typeTd, el("td", "cell-preview", h.preview), vTd, rTd,
      el("td", "num cell-mono", `${h.response.latency_ms} ms`));
    tr.addEventListener("click", () => openFromHistory(h));
    return tr;
  }));
  $("historyEmpty").classList.toggle("hidden", rows.length > 0);
  $("historyBody").closest(".table-wrap").classList.toggle("hidden", rows.length === 0);
}

function openFromHistory(h) {
  go("scanner");
  setFile(null);
  setMode(h.mode || h.type);
  $("content").value = h.content || "";
  lastContent = h.content || "";
  $("error").classList.add("hidden");
  render(h.response);
}

// ================================================================== SCANNER
let mode = "auto";
let emlFile = null;
let lastScanId = null;
let lastContent = "";

function setMode(m) {
  mode = ["auto", "text", "url", "email"].includes(m) ? m : "auto";
  $$("#mode button").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
}
function setFile(f) {
  emlFile = f || null;
  $("fileChip").classList.toggle("hidden", !emlFile);
  $("fileName").textContent = emlFile ? `${emlFile.name} · ${(emlFile.size / 1024).toFixed(1)} KB (scanned instead of the text box)` : "";
  if (!emlFile) $("eml").value = "";
}
function showPanel(which) {
  for (const id of ["empty", "scanning", "result"]) $(id).classList.toggle("hidden", id !== which);
}
function setResultTone(label) {
  const card = $("resultCard");
  card.classList.remove("tone-danger-card", "tone-warning-card", "tone-success-card");
  if (label) card.classList.add(`tone-${TONE[label]}-card`);
}

async function scan() {
  const content = $("content").value;
  if (!content.trim() && !emlFile) { $("content").focus(); toast("info", "Nothing to analyze", "Paste a message, link or email first."); return; }
  const btn = $("scan");
  btn.disabled = true;
  btn.querySelector(".btn-label").textContent = "Analyzing…";
  $("error").classList.add("hidden");
  setResultTone(null);
  showPanel("scanning");
  const steps = $$("#steps li");
  steps.forEach((s) => s.classList.remove("done"));
  const stepTimer = setInterval(() => { const next = steps.find((s) => !s.classList.contains("done")); if (next) next.classList.add("done"); }, 190);
  const started = performance.now();
  try {
    let data, type;
    if (emlFile) {
      const fd = new FormData();
      fd.append("file", emlFile);
      data = await api("/v1/scan/email/upload", { method: "POST", body: fd, headers: apiHeaders(false) });
      lastContent = "";
      type = "email";
    } else {
      data = await scanApi(content, mode);
      lastContent = content;
      type = data.input_type;
    }
    const elapsed = performance.now() - started;
    if (elapsed < 850) await sleep(850 - elapsed); // keep the progress readable; real analysis takes ms
    steps.forEach((s) => s.classList.add("done"));
    render(data);
    addHistory({ source: "Scanner", type, mode, content: emlFile ? "" : content,
                 preview: emlFile ? `📎 ${emlFile.name}` : preview(content), response: data });
  } catch (e) {
    showPanel("empty");
    const err = $("error");
    err.replaceChildren(icon("alert", "alert-icon"), el("div", "", e.message));
    err.classList.remove("hidden");
  } finally {
    clearInterval(stepTimer);
    btn.disabled = false;
    btn.querySelector(".btn-label").textContent = "Analyze";
  }
}

const HEADLINE = {
  safe: "No threats detected",
  suspicious: "Suspicious: proceed with caution",
  phishing: "Phishing attempt detected",
  scam: "Scam detected",
};
const ACTION = {
  safe: ["success", "check", "No action needed"],
  suspicious: ["warning", "alert", "Verify before you act"],
  phishing: ["danger", "ban", "Do not engage"],
  scam: ["danger", "ban", "Do not engage"],
};

function countUp(node, to, ms = 800) {
  const t0 = performance.now();
  const step = (t) => {
    const k = Math.min(1, (t - t0) / ms);
    node.textContent = String(Math.round(to * (1 - Math.pow(1 - k, 3))));
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function render(r) {
  lastScanId = r.scan_id;
  $$("#fbChips .btn").forEach((b) => { b.disabled = false; b.classList.remove("selected"); });
  showPanel("result");
  setResultTone(r.label);

  const arc = $("gaugeArc");
  arc.style.stroke = RISK_COLOR[r.label];
  arc.style.strokeDashoffset = String(RING);
  requestAnimationFrame(() => requestAnimationFrame(() => { arc.style.strokeDashoffset = String(RING * (1 - r.risk_score / 100)); }));
  $("score").style.color = RISK_COLOR[r.label];
  countUp($("score"), r.risk_score);

  $("badge").replaceWith(Object.assign(verdictBadge(r.label), { id: "badge" }));
  $("confidence").textContent = `${Math.round(r.confidence * 100)}% confidence · ${r.input_type}`;
  $("headline").textContent = HEADLINE[r.label];
  $("explanation").textContent = r.explanation;

  const [tone, ico, title] = ACTION[r.label];
  $("action").className = `alert alert-${tone}`;
  $("action").querySelector("use").setAttribute("href", `#i-${ico}`);
  $("actionTitle").textContent = title;
  $("actionText").textContent = r.recommended_action;

  renderHighlight(r);
  renderSignals($("flags"), r.red_flags, false);
  $("flagCount").textContent = r.red_flags.length || "";
  $("flagCount").classList.toggle("hidden", !r.red_flags.length);
  $("flags").classList.toggle("hidden", !r.red_flags.length);
  $("noFlags").classList.toggle("hidden", r.red_flags.length !== 0);
  renderSignals($("mitig"), r.mitigating_factors, true);
  $("mitigBlock").classList.toggle("hidden", r.mitigating_factors.length === 0);

  const LAYER_NAME = { url: "URL analysis", text: "Language signals", header: "Email headers", model: "ML text model", intel: "Threat intelligence" };
  const layers = Object.entries(r.layer_scores);
  $("layers").replaceChildren(...(layers.length ? layers.map(([k, v]) => {
    const row = el("div", `layer-row${v >= 50 ? " hot" : ""}`);
    const m = el("div", "meter"); const fill = el("i"); m.append(fill);
    row.append(el("span", "", LAYER_NAME[k] || k), el("b", "", `${v}`), m);
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${v}%`; }));
    return row;
  }) : [el("p", "muted small", "No layer produced evidence.")]));
  $("urls").replaceChildren(...(r.urls_analyzed.length ? r.urls_analyzed.map((u) => el("li", "", u)) : [el("li", "", "No links found")]));
  $("meta").replaceChildren(...[
    `scan ${r.scan_id.slice(0, 8)}`, `${r.latency_ms} ms`, r.model.text_model ? `model: ${r.model.text_model}` : "rule engine",
    r.model.calibrated ? "calibrated" : "uncalibrated", `ensemble ${r.model.ensemble_version}`, `p = ${r.probability}`,
  ].map((t) => el("span", "badge badge-outline badge-sm", t)));
  $("raw").textContent = JSON.stringify(r, null, 2);

  if (window.innerWidth < 1180) $("resultCard").scrollIntoView({ behavior: "smooth", block: "start" });
}

const SEV_ICON = { high: "shield-alert", medium: "alert", low: "info" };
function renderSignals(list, flags, good) {
  const max = Math.max(0.01, ...flags.map((f) => Math.abs(f.contribution)));
  list.replaceChildren(...flags.map((f, i) => {
    const li = el("li", `signal ${good ? "good" : f.severity}`);
    li.style.animationDelay = `${i * 45}ms`;
    const ic = el("span", "sig-icon"); ic.append(icon(good ? "check" : SEV_ICON[f.severity]));
    const body = el("div", "sig-body");
    body.append(el("span", "sig-title", f.description));
    if (f.evidence) body.append(el("span", "sig-ev", f.evidence));
    const tags = el("div", "sig-tags");
    tags.append(el("span", "", f.layer));
    if (!good) tags.append(el("span", "", `${f.severity} severity`));
    body.append(tags);
    const w = el("div", "sig-weight");
    w.append(el("b", "", `${f.contribution > 0 ? "+" : ""}${f.contribution.toFixed(2)}`));
    const m = el("div", "meter"); const fill = el("i"); m.append(fill); w.append(m);
    li.title = "Contribution to the risk score in log-odds (exact and additive)";
    li.append(ic, body, w);
    setTimeout(() => { fill.style.width = `${(Math.abs(f.contribution) / max) * 100}%`; }, 80 + i * 45);
    return li;
  }));
}

// Find the evidence snippets inside the user's own input and mark them.
const SEV_RANK = { high: 3, medium: 2, low: 1 };
function renderHighlight(r) {
  const block = $("highlightBlock");
  const text = (lastContent || "").slice(0, 20000);
  if (!text || r.input_type === "email") { block.classList.add("hidden"); return; }
  const lower = text.toLowerCase();
  const ranges = [];
  for (const f of r.red_flags) {
    const needles = [...f.evidence.matchAll(/"([^"]{2,120})"/g)].map((m) => m[1].replace(/…$/, ""));
    if (f.layer === "url" && f.evidence) {
      const u = f.evidence.split(": ")[0].replace(/\[\.\]/g, ".").replace(/^hxxp/i, "http");
      needles.push(u, u.replace(/^https?:\/\//, ""));
    }
    for (const n of needles) {
      const needle = n.toLowerCase().trim();
      if (needle.length < 2) continue;
      let from = 0, idx;
      while ((idx = lower.indexOf(needle, from)) !== -1 && ranges.length < 300) {
        ranges.push([idx, idx + needle.length, f.severity]);
        from = idx + needle.length;
      }
    }
  }
  if (!ranges.length) { block.classList.add("hidden"); return; }
  ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const merged = [];
  for (const rg of ranges) {
    const last = merged[merged.length - 1];
    if (last && rg[0] <= last[1]) { last[1] = Math.max(last[1], rg[1]); if (SEV_RANK[rg[2]] > SEV_RANK[last[2]]) last[2] = rg[2]; }
    else merged.push([...rg]);
  }
  const out = $("highlight");
  out.replaceChildren();
  let pos = 0;
  for (const [s, e, sev] of merged) {
    if (s > pos) out.append(document.createTextNode(text.slice(pos, s)));
    const m = el("mark", sev === "high" ? "" : sev, text.slice(s, e));
    m.title = `${sev} severity`;
    out.append(m);
    pos = e;
  }
  if (pos < text.length) out.append(document.createTextNode(text.slice(pos)));
  block.classList.remove("hidden");
}

async function sendFeedback(btn) {
  if (!lastScanId) return;
  $$("#fbChips .btn").forEach((b) => { b.disabled = true; });
  try {
    await api("/v1/feedback", { method: "POST", headers: apiHeaders(), body: JSON.stringify({ scan_id: lastScanId, correct_label: btn.dataset.label }) });
    btn.classList.add("selected");
    toast("success", "Feedback recorded", "Only detection signals are kept, never your message.");
  } catch (e) {
    $$("#fbChips .btn").forEach((b) => { b.disabled = false; });
    toast("error", "Feedback failed", e.message);
  }
}

function loadSample(s) {
  go("scanner");
  setFile(null);
  setMode(s.type);
  $("content").value = s.text;
  scan();
}

// ================================================================== PHONE SHIELD
const APP_ICON = { sms: "message", whatsapp: "phone", gmail: "mail" };
const APP_NAME = { sms: "SMS", whatsapp: "WhatsApp", gmail: "Gmail" };
function emailMsg(from, subject, body, auth) {
  return `Authentication-Results: mx.google.com; ${auth}\nFrom: ${from}\nTo: you@gmail.com\nSubject: ${subject}\n` +
         `MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n${body}\n`;
}
const DEMO = [
  { app: "sms", sender: "AX-HDFCBK", text: "482913 is your OTP for login to HDFC Bank NetBanking. Valid for 5 mins. Do not share this OTP with anyone. -HDFC Bank" },
  { app: "sms", sender: "+91 70112 58430", text: "Dear Customer, your SBI account will be blocked today. Please update your PAN card immediately by clicking http://sbi-kyc-update.xyz/login" },
  { app: "whatsapp", sender: "Rahul (College)", text: "Bhai kal match dekhne chalega? Tickets maine book kar li hain, 6 baje stadium ke bahar milte hain." },
  { app: "whatsapp", sender: "+91 98765 43210", text: "Congratulations! You have won Rs 25,00,000 in KBC lottery. To claim your prize pay processing fee of Rs 12,500 on this number today." },
  { app: "gmail", sender: "PayPal Security", subject: "Your account has been limited", type: "email",
    text: emailMsg("\"PayPal Security\" <service@paypa1-security.com>\nReply-To: helpdesk.paypal@gmail.com", "Your account has been limited",
      "Dear Customer,\nYour account will be suspended within 24 hours unless you verify your information at http://paypa1-security.com/login.php",
      "spf=fail smtp.mailfrom=paypa1-security.com; dkim=none; dmarc=fail header.from=paypa1-security.com") },
  { app: "sms", sender: "Mom", text: "Beta khana kha liya? Papa aaj late aayenge, dinner pe wait mat karna." },
  { app: "sms", sender: "+91 83920 11745", text: "Aapka KYC pending hai, aapka account aaj raat band ho jayega. Turant is link pe click karein: bit.ly/kyc-upd8" },
  { app: "gmail", sender: "GitHub", subject: "A new SSH key was added to your account", type: "email",
    text: emailMsg("GitHub <noreply@github.com>", "[GitHub] A new SSH key was added to your account",
      "Hi there,\nThe following SSH key was added to your account. If you believe this key was added in error, you can remove it at https://github.com/settings/keys\nThanks,\nThe GitHub Team",
      "spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com") },
  { app: "whatsapp", sender: "+44 7700 900123", text: "FedEx alert: your parcel containing illegal drugs and 5 passports has been seized by customs. Mumbai cyber crime police will issue an arrest warrant. Press 1 to speak to the officer immediately." },
  { app: "sms", sender: "JD-SWIGGY", text: "Your Swiggy order #4821 from Paradise Biryani is out for delivery and will reach you in 12 minutes." },
  { app: "sms", sender: "+91 62019 77342", text: "प्रिय ग्राहक, आपका बैंक खाता बंद हो जाएगा। तुरंत केवाईसी अपडेट करें और अपना ओटीपी बताएं।" },
];
const demo = { running: false, token: 0, idx: 0, stats: { scanned: 0, blocked: 0, warned: 0, safe: 0 } };
let phoneTab = "inbox";

const clock = () => new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });

function bumpStat(id, key) {
  demo.stats[key] += 1;
  const n = $(id);
  n.textContent = String(demo.stats[key]);
  n.parentElement.classList.add("bump");
  setTimeout(() => n.parentElement.classList.remove("bump"), 220);
}
function refreshPhone() {
  $("inboxCount").textContent = $("inbox").children.length;
  $("blockedCount").textContent = $("blocked").children.length;
  const list = phoneTab === "inbox" ? $("inbox") : $("blocked");
  const empty = $("phoneEmpty");
  empty.classList.toggle("hidden", list.children.length > 0);
  const msg = empty.querySelector("span");
  if (phoneTab === "blocked") msg.replaceChildren(document.createTextNode("No threats blocked yet"));
  else msg.replaceChildren(document.createTextNode("Press "), el("b", "", "Start demo"), document.createTextNode(" to receive messages"));
}
function setPhoneTab(t) {
  phoneTab = t;
  $$("#ptabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === t));
  $("inbox").classList.toggle("hidden", t !== "inbox");
  $("blocked").classList.toggle("hidden", t !== "blocked");
  refreshPhone();
}
function setChip(chip, ico, text) { chip.replaceChildren(icon(ico), document.createTextNode(text)); }

function msgNode(m) {
  const li = el("li", "msg scanning");
  const av = el("div", `avatar ${m.app}`);
  av.append(icon(APP_ICON[m.app]));
  const main = el("div");
  const top = el("div", "msg-top");
  top.append(el("b", "", m.sender), el("small", "", clock()));
  const prev = m.type === "email" ? `${m.subject}: ${m.text.split("\n\n").slice(1).join(" ")}` : m.text;
  const chip = el("span", "chip");
  setChip(chip, "search", "Scanning…");
  main.append(top, el("div", "msg-body", prev), chip);
  li.append(av, main);
  li.title = "Open the full analysis";
  return { li, chip };
}

let headsupTimer = null;
function headsup(title, body) {
  $("toastTitle").textContent = title;
  $("toastBody").textContent = body;
  const t = $("toast");
  t.classList.add("hidden");
  void t.offsetWidth;
  t.classList.remove("hidden");
  clearTimeout(headsupTimer);
  headsupTimer = setTimeout(() => t.classList.add("hidden"), 2800);
}

function logEvent(action, m, r, entry) {
  const tr = el("tr");
  const kind = action === "blocked" ? "phishing" : action === "warned" ? "suspicious" : "safe";
  const badge = el("span", `badge badge-sm ${kind}`);
  badge.append(el("span", "dot"), document.createTextNode(action));
  const aTd = el("td"); aTd.append(badge);
  const reason = r ? (r.red_flags[0] ? r.red_flags[0].description.replace(/\.$/, "") : "No red flags") : "Engine unreachable";
  const rTd = el("td", "num");
  if (r) rTd.append(riskCell(r.label, r.risk_score)); else rTd.textContent = "–";
  tr.append(el("td", "cell-mono", fmtTime(new Date())), aTd, el("td", "", `${APP_NAME[m.app]} · ${m.sender}`), el("td", "reason", reason), rTd);
  if (entry) tr.addEventListener("click", () => openFromHistory(entry));
  $("log").prepend(tr);
  $("logEmpty").classList.add("hidden");
  $("log").closest(".table-wrap").classList.remove("hidden");
}

async function deliver(m, token) {
  const { li, chip } = msgNode(m);
  $("inbox").prepend(li);
  if (phoneTab !== "inbox") setPhoneTab("inbox"); else refreshPhone();
  let r;
  try {
    [r] = await Promise.all([scanApi(m.text, m.type || "text"), sleep($("demoFast").checked ? 250 : 700)]);
  } catch (e) {
    if (token !== demo.token) return;
    li.className = "msg warn";
    setChip(chip, "alert", "Not scanned");
    logEvent("warned", m, null, null);
    toast("error", "Scan failed", e.message);
    return;
  }
  if (token !== demo.token) return;
  const entry = { source: "Phone Shield", type: r.input_type, mode: m.type || "text", content: m.text,
                  preview: `${APP_NAME[m.app]} · ${m.sender}: ${preview(m.type === "email" ? m.subject : m.text, 70)}`, response: r };
  addHistory(entry);
  bumpStat("stScanned", "scanned");
  li.addEventListener("click", () => openFromHistory(entry));

  if (MALICIOUS.has(r.label)) {
    li.className = "msg blocked";
    setChip(chip, "ban", `Blocked · ${r.label} · ${r.risk_score}`);
    headsup(`${r.label === "scam" ? "Scam" : "Phishing"} blocked from ${m.sender}`,
            r.red_flags[0] ? r.red_flags[0].description : "High-risk message quarantined");
    bumpStat("stBlocked", "blocked");
    logEvent("blocked", m, r, entry);
    await sleep($("demoFast").checked ? 400 : 900);
    if (token !== demo.token) return;
    li.classList.add("removing");
    await sleep(450);
    if (token !== demo.token) return;
    li.classList.remove("removing");
    $("blocked").prepend(li);
  } else if (r.label === "suspicious") {
    li.className = "msg warn";
    setChip(chip, "alert", `Caution · risk ${r.risk_score}`);
    bumpStat("stWarned", "warned");
    logEvent("warned", m, r, entry);
  } else {
    li.className = "msg safe";
    setChip(chip, "shield-check", "Verified safe");
    bumpStat("stSafe", "safe");
    logEvent("delivered", m, r, entry);
  }
  refreshPhone();
}

function setDemoButton(state) {
  const [ico, label] = { idle: ["play", "Start demo"], running: ["pause", "Pause"], paused: ["play", "Resume"], done: ["rotate", "Replay demo"] }[state];
  $("demoIcon").setAttribute("href", `#i-${ico}`);
  $("demoLabel").textContent = label;
}
async function runDemo() {
  if (demo.running) { demo.running = false; demo.token++; setDemoButton("paused"); return; }
  if (demo.idx >= DEMO.length) resetDemo();
  demo.running = true;
  const token = ++demo.token;
  setDemoButton("running");
  while (demo.running && token === demo.token && demo.idx < DEMO.length) {
    await deliver(DEMO[demo.idx++], token);
    await sleep($("demoFast").checked ? 450 : 1600);
  }
  if (token === demo.token) {
    demo.running = false;
    setDemoButton(demo.idx >= DEMO.length ? "done" : "paused");
    if (demo.idx >= DEMO.length) toast("success", "Demo complete", `${demo.stats.blocked} threats blocked, ${demo.stats.safe} messages delivered safely.`);
  }
}
function resetDemo() {
  demo.running = false;
  demo.token++;
  demo.idx = 0;
  demo.stats = { scanned: 0, blocked: 0, warned: 0, safe: 0 };
  for (const id of ["stScanned", "stBlocked", "stWarned", "stSafe"]) $(id).textContent = "0";
  $("inbox").replaceChildren();
  $("blocked").replaceChildren();
  $("log").replaceChildren();
  $("logEmpty").classList.remove("hidden");
  $("log").closest(".table-wrap").classList.add("hidden");
  $("toast").classList.add("hidden");
  setDemoButton("idle");
  setPhoneTab("inbox");
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

// ================================================================== ENGINE STATUS
async function loadInfo() {
  const card = $("engine");
  try {
    const info = await api("/v1/info", {}, false);
    card.className = "status-card ok";
    $("engineText").textContent = "Engine online";
    $("engineSub").textContent = `v${info.version} · ${info.text_model ? "ML + rules" : "rule engine"}`;
  } catch {
    card.className = "status-card down";
    $("engineText").textContent = "Engine offline";
    $("engineSub").textContent = "Start the server with run.ps1";
  }
}

// ================================================================== WIRING
function init() {
  initTheme();

  // navigation
  window.addEventListener("hashchange", route);
  $("menuBtn").addEventListener("click", () => { $("sidebar").classList.add("open"); $("scrim").classList.add("show"); });
  $("scrim").addEventListener("click", closeSidebar);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSidebar(); });

  // overview
  $("quickForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("quickInput").value.trim();
    if (!v) { $("quickInput").focus(); return; }
    go("scanner"); setFile(null); setMode("auto"); $("content").value = v; $("quickInput").value = ""; scan();
  });
  $$("[data-quick]").forEach((b) => b.addEventListener("click", () => { $("quickInput").value = b.dataset.quick; $("quickForm").requestSubmit(); }));
  $("threatGrid").replaceChildren(...SAMPLES.filter((s) => s.threat).map((s) => {
    const [ico, title, desc, lang] = s.threat;
    const b = el("button", "threat");
    b.type = "button";
    const top = el("span", "threat-top"); top.append(icon(ico), document.createTextNode(title));
    b.append(top, el("p", "", desc), el("span", "lang", lang));
    b.addEventListener("click", () => loadSample(s));
    return b;
  }));

  // scanner
  $$("#mode button").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
  $("scan").addEventListener("click", scan);
  $("content").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); scan(); } });
  $("clear").addEventListener("click", () => {
    $("content").value = ""; setFile(null); lastContent = "";
    $("error").classList.add("hidden"); showPanel("empty"); setResultTone(null); $("content").focus();
  });
  $("eml").addEventListener("change", (e) => { setFile(e.target.files[0]); if (emlFile) setMode("email"); });
  $("fileRemove").addEventListener("click", () => setFile(null));
  const dz = $("dropzone");
  ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  dz.addEventListener("dragleave", (e) => { if (!dz.contains(e.relatedTarget)) dz.classList.remove("drag"); });
  dz.addEventListener("drop", (e) => {
    e.preventDefault(); dz.classList.remove("drag");
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) { setFile(f); setMode("email"); scan(); }
  });
  $("examples").replaceChildren(...SAMPLES.map((s) => {
    const b = el("button", "sample");
    b.type = "button";
    b.title = s.bad ? "Malicious sample" : "Legitimate sample";
    b.append(el("span", `dot ${s.bad ? "bad" : "ok"}`), document.createTextNode(s.name));
    b.addEventListener("click", () => { setFile(null); setMode(s.type); $("content").value = s.text; scan(); });
    return b;
  }));
  $$("#fbChips .btn").forEach((b) => b.addEventListener("click", () => sendFeedback(b)));

  // phone shield
  $$("#ptabs button").forEach((b) => b.addEventListener("click", () => setPhoneTab(b.dataset.tab)));
  $("demoStart").addEventListener("click", runDemo);
  $("demoReset").addEventListener("click", resetDemo);
  $("injSend").addEventListener("click", injectMessage);
  $("injText").addEventListener("keydown", (e) => { if (e.key === "Enter") injectMessage(); });
  const tick = () => { $("clock").textContent = clock(); };
  tick();
  setInterval(tick, 20000);

  // activity
  $$("#filter button").forEach((b) => b.addEventListener("click", () => {
    historyFilter = b.dataset.filter;
    $$("#filter button").forEach((x) => x.classList.toggle("active", x === b));
    renderHistory();
  }));
  $("clearHistory").addEventListener("click", () => { scans.length = 0; refreshDashboard(); toast("info", "History cleared"); });

  refreshDashboard();
  resetDemo();
  route();
  loadInfo();
  setInterval(loadInfo, 30000);
}

init();
