"use strict";
const $ = (id) => document.getElementById(id);

async function load() {
  const s = await messenger.storage.local.get({ port: 8787, token: "" });
  $("port").value = s.port;
  $("token").value = s.token;
}

$("save").addEventListener("click", async () => {
  await messenger.storage.local.set({ port: parseInt($("port").value, 10) || 8787, token: $("token").value.trim() });
  $("status").textContent = "Saved.";
});

$("test").addEventListener("click", async () => {
  const port = parseInt($("port").value, 10) || 8787;
  $("status").textContent = "Testing…";
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/soc/email?limit=1`, { headers: { "X-PyNIDS-Token": $("token").value.trim() } });
    $("status").textContent = res.ok ? "Connected ✓" : res.status === 401 ? "Service reached, but the token is wrong." : `HTTP ${res.status}`;
  } catch (e) {
    $("status").textContent = "PyNIDS isn't reachable on that port.";
  }
});

load();
