// PhishGuard extension stub (Manifest V3).
// Adds right-click "Scan link" / "Scan selected text" menu items that call the
// PhishGuard API. Nothing is sent automatically: only what the user picks.
// Add your extension origin to PG_CORS_ORIGINS on the server.

const DEFAULT_API = "http://localhost:8000";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "pg-link", title: "PhishGuard: scan this link", contexts: ["link"] });
  chrome.contextMenus.create({ id: "pg-text", title: "PhishGuard: scan selected text", contexts: ["selection"] });
});

async function scan(path, body) {
  const { apiBase = DEFAULT_API, apiKey = "" } = await chrome.storage.sync.get(["apiBase", "apiKey"]);
  const res = await fetch(`${apiBase}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(apiKey ? { "x-api-key": apiKey } : {}) },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

function notify(result) {
  const top = (result.red_flags || []).slice(0, 2).map((f) => f.description).join(" ");
  chrome.notifications.create({
    type: "basic",
    iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    title: `PhishGuard: ${result.label.toUpperCase()} (${result.risk_score}/100)`,
    message: top || result.explanation.slice(0, 200),
  });
}

chrome.contextMenus.onClicked.addListener(async (info) => {
  try {
    if (info.menuItemId === "pg-link" && info.linkUrl) notify(await scan("/v1/scan/url", { url: info.linkUrl }));
    if (info.menuItemId === "pg-text" && info.selectionText) notify(await scan("/v1/scan/text", { text: info.selectionText }));
  } catch (e) {
    chrome.notifications.create({ type: "basic", iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
      title: "PhishGuard error", message: String(e.message || e) });
  }
});

// TODO (roadmap): optional hover-preview on Gmail/Outlook Web using a content
// script that sends only link hrefs (never message bodies) after explicit opt-in.
