/* PyNIDS for Thunderbird: hand the untouched message source to the local
 * PyNIDS service and open the analysis in the browser.
 *
 * Only http://127.0.0.1 is contacted.  The message is sent exactly as
 * Thunderbird stored it (getRaw), never re-encoded. */
"use strict";

async function settings() {
  return messenger.storage.local.get({ port: 8787, token: "" });
}

function notify(title, message) {
  return messenger.notifications.create({ type: "basic", title, message, iconUrl: "icon.svg" });
}

async function rawBytes(messageId) {
  // Thunderbird 117+ can return a File (exact bytes); 115 returns a "binary
  // string" with one char per byte.
  try {
    const file = await messenger.messages.getRaw(messageId, { data_format: "File" });
    if (file instanceof File) return new Uint8Array(await file.arrayBuffer());
  } catch (_) { /* older Thunderbird */ }
  const s = await messenger.messages.getRaw(messageId);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

async function analyze(message) {
  const { port, token } = await settings();
  if (!token) {
    await notify("PyNIDS: setup needed", "Paste your PyNIDS API token in the add-on options (run: pynids mail token).");
    messenger.runtime.openOptionsPage();
    return;
  }
  let res;
  try {
    const body = await rawBytes(message.id);
    const name = (message.subject || "message").replace(/[^\w .-]+/g, "_").slice(0, 80) + ".eml";
    res = await fetch(`http://127.0.0.1:${port}/api/soc/email`, {
      method: "POST",
      body,
      headers: {
        "X-PyNIDS-Token": token,
        "Content-Type": "message/rfc822",
        "X-Filename": encodeURIComponent(name),
        "X-Source": "thunderbird",
      },
    });
  } catch (e) {
    await notify("PyNIDS isn't reachable", `Is the PyNIDS service running on port ${port}? (${e.message})`);
    return;
  }
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty */ }
  if (!res.ok) {
    await notify("PyNIDS refused the message", data.error || `HTTP ${res.status}` +
      (res.status === 401 ? " — check the API token in the add-on options" : ""));
    return;
  }
  await messenger.windows.openDefaultBrowser(`http://127.0.0.1:${port}/#email/${data.sha256}`);
}

messenger.messageDisplayAction.onClicked.addListener(async (tab) => {
  const msg = await messenger.messageDisplay.getDisplayedMessage(tab.id);
  if (msg) analyze(msg);
});

messenger.menus.create({ id: "pynids-analyze", title: "Analyze in PyNIDS", contexts: ["message_list"] });
messenger.menus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== "pynids-analyze") return;
  const msgs = (info.selectedMessages && info.selectedMessages.messages) || [];
  for (const m of msgs.slice(0, 10)) await analyze(m);
});
