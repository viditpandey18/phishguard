// All API output is inserted with textContent (never innerHTML) to avoid XSS
// from attacker-controlled evidence strings.
const $ = (id) => document.getElementById(id);

chrome.storage.sync.get(["apiBase", "apiKey"]).then(({ apiBase = "http://localhost:8000", apiKey = "" }) => {
  $("apiBase").value = apiBase;
  $("apiKey").value = apiKey;
});

$("save").addEventListener("click", () =>
  chrome.storage.sync.set({ apiBase: $("apiBase").value.trim(), apiKey: $("apiKey").value.trim() }));

$("scan").addEventListener("click", async () => {
  const out = $("out");
  out.className = "";
  out.textContent = "Scanning…";
  try {
    const { apiBase = "http://localhost:8000", apiKey = "" } = await chrome.storage.sync.get(["apiBase", "apiKey"]);
    const res = await fetch(`${apiBase}/v1/scan`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(apiKey ? { "x-api-key": apiKey } : {}) },
      body: JSON.stringify({ content: $("content").value }),
    });
    const r = await res.json();
    if (!res.ok) throw new Error(r.detail || res.status);
    out.className = r.label;
    out.textContent = `${r.label.toUpperCase()} — risk ${r.risk_score}/100\n\n${r.explanation}\n\n` +
      r.red_flags.map((f) => `• ${f.description}`).join("\n") + `\n\n${r.recommended_action}`;
  } catch (e) {
    out.textContent = `Error: ${e.message || e}`;
  }
});
