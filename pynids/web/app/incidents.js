/* Incidents and reputation — the investigation side of the Detections tab.
 *
 *   incidents list      every group of related alerts, most urgent first
 *   openIncident(id)    the full story of one incident: timeline, ATT&CK path,
 *                       indicators with their reputation, triage status and note
 *   openAlertSet(f)     every incident and alert behind a tactic, a technique,
 *                       a rule or a built-in detector (the tiles and tables of
 *                       the Detections tab open this)
 *   reputationBox(t, v) what VirusTotal & co. say about one indicator
 *
 * Loaded after ops.js; reuses the dashboard helpers (el, icon, api, toast, table,
 * kvList, emptyBox, ipLink, appLink, progLink, sevBadge, vpill, fmtNum, fmtAgo,
 * fmtTime, fmtDuration, showDrawer, openDrawer, pivotEvents, investigate, $).
 * Everything is rendered with textContent: values taken from traffic are never
 * interpreted as HTML. */
"use strict";

const INC = {
  range: "session",     // session | 86400 | 604800 | 2592000
  status: "active",     // active | "" (all) | closed
  low: false,           // include incidents whose worst alert is LOW
  data: null,
  gen: 0,
};
const INC_RANGES = [["session", "This session"], ["86400", "24 h"], ["604800", "7 d"], ["2592000", "30 d"]];
const INC_STATUS_LABEL = { open: "Open", acknowledged: "Acknowledged", closed: "Closed" };
const ENTITY_LABEL = { ip: "Address", domain: "Domain", program: "Program" };
const IOC_TYPE_LABEL = { ipv4: "IPv4", ipv6: "IPv6", domain: "Domain", url: "URL", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", sha512: "SHA-512" };

function incSince(range) {
  if (range === "session") return OPS.det && OPS.det.since ? OPS.det.since : null;
  return Date.now() / 1000 - Number(range);
}
function fmtWhen(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000), today = new Date().toDateString() === d.toDateString();
  return today ? fmtTime(ts) : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function statusChip(status) {
  return el("span", { class: "inc-status " + (status || "open"), text: INC_STATUS_LABEL[status] || status || "Open" });
}
function tacticChips(tactics, max) {
  const list = (tactics || []).filter((t) => t !== "Other");
  if (!list.length) return el("span", { class: "muted", text: "—" });
  const shown = max ? list.slice(0, max) : list;
  return el("div", { class: "chips" }, shown.map((t) => el("span", { class: "chip mitre", text: t })),
    list.length > shown.length ? el("span", { class: "muted", style: "font-size:12px", text: "+" + (list.length - shown.length) }) : null);
}
function entityNode(e) {
  if (!e) return el("span", { class: "muted", text: "—" });
  if (e.type === "ip") return el("span", {}, ipLink(e.value), e.label ? el("span", { class: "muted", text: "  " + e.label }) : null);
  if (e.type === "program") return e.value.startsWith("/") ? progLink(e.label || e.value, e.value) : (e.label ? appLink(e.label) : el("span", { text: e.value }));
  return el("button", { class: "link mono", title: "Investigate " + e.value, onclick: (ev) => { ev.stopPropagation(); closeDrawer(); investigate(e.value); } }, e.value);
}
function entityText(e) { return e ? (e.label && e.label !== e.value ? `${e.label} (${e.value})` : e.value) : ""; }

// ---------------------------------------------------------------- incidents card (Detections tab)
function incidentsCard() {
  const seg = (id, options, current, set) => el("div", { class: "seg", id, role: "group" },
    options.map(([v, label]) => el("button", { "data-v": v, "aria-pressed": String(v === current()), onclick: () => { set(v); syncIncidentControls(); loadIncidents(); } }, label)));
  return el("div", { class: "grid row-1" }, el("div", { class: "card" },
    el("div", { class: "card-head" }, el("h2", { text: "Incidents" }),
      el("span", { class: "sub", id: "incSub", text: "related alerts kept together · click one for the full story" })),
    el("div", { class: "toolbar" },
      seg("incRange", INC_RANGES, () => INC.range, (v) => { INC.range = v; }),
      seg("incStatus", [["active", "Active"], ["", "All"], ["closed", "Closed"]], () => INC.status, (v) => { INC.status = v; }),
      el("label", { class: "check" }, el("input", { type: "checkbox", id: "incLow", onchange: (e) => { INC.low = e.target.checked; loadIncidents(); } }), " Include low severity")),
    el("div", { class: "card-body table-wrap", id: "incTable", style: "padding-top:0" })));
}
function syncIncidentControls() {
  document.querySelectorAll("#incRange button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.v === INC.range)));
  document.querySelectorAll("#incStatus button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.v === INC.status)));
}
async function loadIncidents() {
  if (!$("incTable")) return;
  const params = new URLSearchParams({ limit: "100", min_severity: INC.low ? "LOW" : "MEDIUM" });
  const since = incSince(INC.range);
  if (since) params.set("since", String(since));
  if (INC.status) params.set("status", INC.status);
  const gen = ++INC.gen;
  let data;
  try { data = await api("/api/incidents?" + params, { timeout: 20000 }); }
  catch (e) { if (gen === INC.gen && !(e.offline && INC.data)) $("incTable").replaceChildren(emptyBox(e.message)); return; }
  if (gen !== INC.gen) return;
  INC.data = data;
  renderIncidents();
}
function incidentRow(i) {
  return el("tr", { class: "clickable" + (i.status === "closed" ? " dim" : ""), tabindex: "0", onclick: () => openIncident(i.incident_id),
    onkeydown: (e) => { if (e.key === "Enter") openIncident(i.incident_id); } },
    el("td", {}, sevBadge(i.severity)),
    el("td", {}, el("div", { class: "inc-title", text: i.title }),
      el("div", { class: "sub2", text: [ENTITY_LABEL[i.entity.type] || i.entity.type, entityText(i.entity), (i.apps || []).slice(0, 2).join(", ")].filter(Boolean).join(" · ") })),
    el("td", {}, tacticChips(i.tactics, 3)),
    el("td", { class: "num", text: fmtNum(i.alert_count) }),
    el("td", { class: "muted", text: fmtWhen(i.first_seen) }),
    el("td", { class: "muted", text: fmtAgo(i.last_seen) }),
    el("td", {}, statusChip(i.status)));
}
function incidentTable(rows) {
  return table(["Severity", "Incident", "ATT&CK tactics", { label: "Alerts", num: true }, "Started", "Last alert", "Status"], rows.map(incidentRow));
}
function renderIncidents() {
  const d = INC.data; if (!d || !$("incTable")) return;
  const rows = d.incidents || [];
  const c = d.counts || {};
  $("incSub").textContent = rows.length
    ? `${fmtNum(d.total)} incident${d.total === 1 ? "" : "s"} · ${c.open || 0} open, ${c.acknowledged || 0} acknowledged · click one for the full story`
    : "related alerts kept together · click one for the full story";
  $("incTable").replaceChildren(rows.length ? incidentTable(rows)
    : emptyBox(INC.status === "closed" ? "No closed incidents in this period."
      : INC.low ? "No incidents in this period." : "No incidents at medium severity or above in this period. Tick “Include low severity” to see the rest."));
}
setInterval(() => { if (typeof state !== "undefined" && state.tab === "detections" && !document.hidden) loadIncidents(); }, 15000);

// ---------------------------------------------------------------- reputation
function repLine(r) {
  const failed = !["ok", "not_found", "pending"].includes(r.status);
  const text = r.status === "pending" ? "not checked yet"
    : r.status === "not_found" ? (r.message || "no record")
    : failed ? (r.message || r.status) : (r.headline || r.message || "");
  return el("tr", {},
    el("td", { text: r.label }),
    el("td", {}, r.status === "ok" ? vpill(r.verdict) : el("span", { class: "muted", style: "font-size:12px", text: r.status === "not_found" ? "No record" : r.status === "pending" ? "—" : "Failed" })),
    el("td", {}, el("div", { class: "sub2", text: String(text).slice(0, 200) })));
}
function repSummaryNode(rep) {
  if (!rep) return el("span", { class: "muted", text: "—" });
  if (rep.private) return el("span", { class: "muted", style: "font-size:12px", text: "internal — never sent out" });
  if (!rep.checked) return el("span", { class: "muted", style: "font-size:12px", text: (rep.sources || []).length ? "not checked yet" : "no source configured" });
  const flagged = (rep.flagged_by || []).length;
  return el("span", { title: (rep.sources || []).filter((s) => s.status === "ok").map((s) => `${s.label}: ${s.verdict}`).join("\n") },
    vpill(rep.verdict), el("span", { class: "muted", style: "font-size:12px;margin-left:6px", text: flagged ? `${flagged} of ${rep.checked}` : `${rep.checked} source${rep.checked === 1 ? "" : "s"}` }));
}
/** A box that shows what is already known about an indicator and can ask the sources now. */
function reputationBox(type, value, opts = {}) {
  const box = el("div", { class: "rep-box" });
  const paint = (rep, busy) => {
    const rows = (rep && rep.sources) || [];
    const missing = (rep && rep.missing_keys) || [];
    const btn = el("button", { class: "btn", disabled: !!busy || !rep || !!rep.private || (!rows.length && !missing.length) },
      busy ? el("span", { class: "spinner" }) : icon("i-refresh"), busy ? "Checking…" : rep && rep.checked ? "Check again" : "Check reputation");
    btn.addEventListener("click", async () => {
      paint(rep, true);
      try { paint(await api("/api/reputation", { method: "POST", timeout: 45000, body: JSON.stringify({ type, value, refresh: !!(rep && rep.checked) }) })); }
      catch (e) { toast(e.message); paint(rep); }
    });
    box.replaceChildren(
      el("div", { class: "rep-head" }, rep && rep.checked ? vpill(rep.verdict) : null,
        el("span", { class: "mono", style: "font-size:12px;overflow-wrap:anywhere", text: opts.label || value }), btn),
      rep && rep.private ? el("p", { class: "note", text: `Not sent to outside services: ${rep.private}.` }) : null,
      rows.length ? el("table", { class: "minitable" }, el("tbody", {}, rows.map(repLine))) : null,
      missing.length ? el("p", { class: "note" }, `${missing.map((m) => m.label).join(", ")} ${missing.length === 1 ? "needs" : "need"} a free API key. `,
        el("button", { class: "link", onclick: () => openSourcesDrawer(missing[0].name) }, "Add a key")) : null,
      rep && rep.fetched ? el("p", { class: "note", text: `Last answer ${fmtAgo(rep.fetched)}. A check sends this ${IOC_TYPE_LABEL[type] || "indicator"} to the sources listed${type === "url" ? ", without its query string" : ""}.` }) : null);
  };
  paint(null, false);
  api("/api/reputation?type=" + encodeURIComponent(type) + "&value=" + encodeURIComponent(value)).then((rep) => paint(rep)).catch(() => box.remove());
  return box;
}
function iocTypeOfIp(ip) { return String(ip).includes(":") ? "ipv6" : "ipv4"; }
function isPublicIp(ip) {
  const v = String(ip || "");
  if (!v) return false;
  if (v.includes(":")) return !/^(::1$|fe[89ab]|f[cd]|ff)/i.test(v);
  const p = v.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !(n >= 0 && n <= 255))) return false;
  return !(p[0] === 10 || p[0] === 127 || p[0] === 0 || p[0] >= 224 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
    || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127));
}
/** Extra sections for the alert drawer: its incident and the remote side's reputation. */
function alertIncidentExtras(a) {
  const out = [];
  const ctx = a.context || {}, ev = a.evidence || {};
  const slot = el("div");
  out.push(slot);
  const showIncident = (id) => {
    if (!id) return;
    slot.replaceChildren(el("div", { class: "inc-link" }, icon("i-shield"),
      el("span", { text: "Part of an incident — related alerts, timeline and indicators in one place." }),
      el("button", { class: "btn", onclick: () => openIncident(id, true) }, "Open incident")));
  };
  if (a.incident_id) showIncident(a.incident_id);
  else if (a.alert_id) api("/api/alerts/" + encodeURIComponent(a.alert_id)).then((full) => showIncident(full.incident_id)).catch(() => {});
  if (ev.indicator && Array.isArray(ev.sources) && (a.tags || []).includes("reputation")) {
    out.push(el("h4", { text: "Who flagged it" }),
      el("table", { class: "minitable" }, el("tbody", {}, ev.sources.map((s) => el("tr", {},
        el("td", { text: s.label }), el("td", {}, vpill(s.verdict)), el("td", {}, el("div", { class: "sub2", text: String(s.headline || "").slice(0, 200) })))))));
    if (ev.triggered_by && ev.triggered_by.alert_id) out.push(el("p", { class: "note" }, "Checked because of: ",
      el("button", { class: "link", onclick: () => openAlertById(ev.triggered_by.alert_id) }, String(ev.triggered_by.message || ev.triggered_by.rule_id).slice(0, 120))));
  }
  const remote = ctx.remote_ip || (ctx.direction === "inbound" ? a.src_ip : a.dst_ip);
  const boxes = [];
  if (isPublicIp(remote)) boxes.push(reputationBox(iocTypeOfIp(remote), remote));
  const host = ctx.remote_host || ev.sni || ev.query_name || ((ev.layer7 || {}).dns || {}).query_name || ((ev.layer7 || {}).tls || {}).sni;
  if (host && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) boxes.push(reputationBox("domain", String(host).toLowerCase()));
  if (boxes.length) out.push(el("h4", { text: "Reputation" }), ...boxes);
  return out;
}

// ---------------------------------------------------------------- incident detail
function incidentStory(i) {
  const n = i.alert_count, tactics = (i.tactics || []).filter((t) => t !== "Other");
  const span = i.duration < 60 ? "within a minute" : "over " + fmtDuration(Math.round(i.duration));
  let text = `${fmtNum(n)} alert${n === 1 ? "" : "s"} about ${entityText(i.entity)} ${span}, from ${new Date(i.first_seen * 1000).toLocaleString()} to ${new Date(i.last_seen * 1000).toLocaleString()}.`;
  if (tactics.length > 1) text += ` The activity spans ${tactics.length} ATT&CK tactics (${tactics.join(" → ")}): several stages of an attack, not a single probe.`;
  else if (tactics.length === 1) text += ` All of it maps to ${tactics[0]}.`;
  if (i.threat_intel) text += " At least one indicator is on a threat-intelligence list.";
  return text;
}
function incidentReport(i) {
  const lines = [`# Incident ${i.incident_id} — ${i.severity}`, "", i.title, "",
    `- Subject: ${entityText(i.entity)} (${ENTITY_LABEL[i.entity.type] || i.entity.type})`,
    `- Status: ${INC_STATUS_LABEL[i.status] || i.status}`,
    `- First alert: ${new Date(i.first_seen * 1000).toISOString()}`,
    `- Last alert: ${new Date(i.last_seen * 1000).toISOString()}`,
    `- Alerts: ${i.alert_count}`,
    `- ATT&CK tactics: ${(i.tactics || []).join(", ") || "—"}`,
    `- Techniques: ${(i.techniques || []).map((t) => t.id + (t.name ? " " + t.name : "")).join("; ") || "—"}`,
    `- Apps: ${(i.apps || []).join(", ") || "—"}`];
  if (i.note) lines.push("", "## Analyst note", "", i.note);
  if ((i.iocs || []).length) {
    lines.push("", "## Indicators", "");
    for (const x of i.iocs) lines.push(`- ${x.type} \`${x.value}\`${x.reputation && x.reputation.checked ? ` — ${x.reputation.verdict}${(x.reputation.flagged_by || []).length ? " (" + x.reputation.flagged_by.join(", ") + ")" : ""}` : ""}`);
  }
  lines.push("", "## Timeline", "");
  for (const a of i.alerts || []) lines.push(`- ${new Date(a.timestamp * 1000).toISOString()} ${a.severity} ${a.rule_id || a.alert_type}${a.mitre_technique ? " " + a.mitre_technique : ""} — ${a.message}`);
  return lines.join("\n");
}
function incidentTimeline(alerts) {
  const rows = [];
  let day = "";
  for (const a of alerts) {
    const d = new Date(a.timestamp * 1000).toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
    if (d !== day) { day = d; rows.push(el("div", { class: "tl-day", text: d })); }
    const ctx = a.context || {};
    rows.push(el("button", { class: "tl-row", "data-sev": a.severity, onclick: () => openDrawer(a, true) },
      el("span", { class: "tl-time mono", text: fmtTime(a.timestamp) }),
      el("span", { class: "tl-dot" }),
      el("span", { class: "tl-main" },
        el("span", { class: "tl-msg", text: a.message }),
        el("span", { class: "tl-sub", text: [a.rule_id || (a.alert_type || "").replace("_", " "), a.mitre_technique ? a.mitre_technique + (a.mitre && a.mitre.tactic ? " " + a.mitre.tactic : "") : null, ctx.app, ctx.remote_host].filter(Boolean).join(" · ") })),
      sevBadge(a.severity)));
  }
  return el("div", { class: "timeline" }, rows);
}
function iocRow(x, onChanged) {
  const valueNode = x.type === "ipv4" || x.type === "ipv6" ? ipLink(x.value)
    : el("button", { class: "link mono", style: "overflow-wrap:anywhere;text-align:left", title: "Investigate in the workbench", onclick: () => { closeDrawer(); investigate(x.value); } }, x.value);
  const repCell = el("td", {}, repSummaryNode(x.reputation || (x.public ? null : { private: x.private_reason })));
  const btn = x.public ? el("button", { class: "btn small", title: "Ask the reputation sources now" }, "Check") : null;
  if (btn) btn.addEventListener("click", async () => {
    btn.disabled = true; btn.replaceChildren(el("span", { class: "spinner" }));
    try { x.reputation = await api("/api/reputation", { method: "POST", timeout: 45000, body: JSON.stringify({ type: x.type, value: x.value, refresh: !!(x.reputation && x.reputation.checked) }) }); repCell.replaceChildren(repSummaryNode(x.reputation)); if (onChanged) onChanged(); }
    catch (e) { toast(e.message); }
    btn.disabled = false; btn.textContent = "Check";
  });
  return el("tr", {},
    el("td", { class: "muted", text: IOC_TYPE_LABEL[x.type] || x.type }),
    el("td", {}, valueNode, el("div", { class: "sub2", text: `${x.role} · in ${x.count} alert${x.count === 1 ? "" : "s"}` })),
    repCell,
    el("td", { class: "num" }, btn));
}
function reputationNote(st) {
  if (!st) return null;
  const on = (st.sources || []).filter((s) => s.automatic).map((s) => s.label);
  const off = (st.sources || []).filter((s) => !s.has_key).map((s) => s.label);
  const parts = [];
  parts.push(st.automatic
    ? (on.length ? `Indicators behind alerts are checked automatically with ${on.join(", ")}.` : "Automatic checks start as soon as you add an API key: only sources you gave a key are used unattended.")
    : "Automatic reputation checks are off (lookups.mode is manual or lookups.reputation is false) — use Check.");
  if (off.length && on.length) parts.push(`No key yet for ${off.join(", ")}.`);
  return el("p", { class: "note" }, parts.join(" ") + " ", el("button", { class: "link", onclick: () => openSourcesDrawer() }, "Sources & API keys"));
}
function incidentView(i) {
  return {
    title: i.title,
    head: [sevBadge(i.severity), " ", statusChip(i.status), " ", el("span", { class: "muted mono", style: "font-size:11.5px", text: i.incident_id })],
    body: () => {
      const setStatus = async (status) => {
        try { const next = await api("/api/incidents/" + encodeURIComponent(i.incident_id), { method: "POST", body: JSON.stringify({ status }) }); toast("Incident " + (INC_STATUS_LABEL[status] || status).toLowerCase()); replaceIncidentView(next); loadIncidents(); }
        catch (e) { toast(e.message); }
      };
      const note = el("textarea", { class: "inc-note", rows: "3", placeholder: "What you found, what you did…", "aria-label": "Analyst note" });
      note.value = i.note || "";
      const saveNote = el("button", { class: "btn", onclick: async () => {
        try { const next = await api("/api/incidents/" + encodeURIComponent(i.incident_id), { method: "POST", body: JSON.stringify({ note: note.value }) }); i.note = next.note; toast("Note saved"); }
        catch (e) { toast(e.message); } } }, "Save note");
      const ent = i.entity;
      const iocs = i.iocs || [];
      const iocBody = el("tbody", {}, iocs.map((x) => iocRow(x)));
      const checkAll = el("button", { class: "btn small" }, "Check all");
      checkAll.addEventListener("click", () => { iocBody.querySelectorAll("button.btn.small").forEach((b) => b.click()); });
      const worstRep = iocs.map((x) => x.reputation).filter((r) => r && (r.verdict === "malicious" || r.verdict === "suspicious"));
      const maxT = Math.max(1, ...(i.techniques || []).map((t) => t.count));
      return [
        el("section", { class: "guide", "aria-label": "Summary" },
          el("div", { class: "summary", text: `${ENTITY_LABEL[ent.type] || "Subject"}: ${entityText(ent)}` }),
          el("p", { text: incidentStory(i) }),
          worstRep.length ? el("p", { text: `Outside sources flag ${worstRep.length} indicator${worstRep.length === 1 ? "" : "s"} of this incident as ${worstRep.some((r) => r.verdict === "malicious") ? "malicious" : "suspicious"} — see Indicators below.` }) : null),
        el("div", { class: "actions" },
          i.status !== "acknowledged" && i.status !== "closed" ? el("button", { class: "btn primary", onclick: () => setStatus("acknowledged"), title: "You have seen it and are looking into it" }, "Acknowledge") : null,
          i.status !== "closed" ? el("button", { class: "btn", onclick: () => setStatus("closed"), title: "Handled or harmless. New alerts about the same subject open a new incident." }, "Close") : el("button", { class: "btn", onclick: () => setStatus("open") }, "Reopen"),
          ent.type === "ip" && isPublicIp(ent.value) ? el("button", { class: "btn danger", onclick: () => blockIp(ent.value, "Blocked from incident " + i.incident_id) }, icon("i-ban"), "Block " + ent.value) : null,
          ent.type !== "program" ? el("button", { class: "btn", onclick: () => { closeDrawer(); investigate(ent.value); } }, icon("i-search"), "Investigate") : null,
          el("button", { class: "btn", onclick: () => copyText(incidentReport(i), "incident report") }, "Copy report")),
        el("h4", { text: "ATT&CK path" }),
        (i.techniques || []).length ? el("table", { class: "minitable" }, el("tbody", {}, i.techniques.map((t) => el("tr", {},
          el("td", { class: "muted", text: t.tactic || "Other" }),
          el("td", {}, safeHref(t.url) ? el("a", { href: safeHref(t.url), target: "_blank", rel: "noreferrer noopener", class: "mono ext", text: t.id }) : el("span", { class: "mono", text: t.id }), t.name ? el("span", { text: "  " + t.name }) : null),
          el("td", { style: "width:90px" }, el("div", { class: "bar" }, el("div", { style: `width:${Math.max(6, (t.count / maxT) * 100).toFixed(0)}%` }))),
          el("td", { class: "num", text: fmtNum(t.count) })))))
          : el("p", { class: "note", text: "None of these alerts carries an ATT&CK technique." }),
        el("h4", { text: "At a glance" }),
        kvList([
          ["Subject", entityNode(ent)],
          ["Apps involved", (i.apps || []).length ? el("span", {}, ...i.apps.flatMap((a, n) => [n ? ", " : "", appLink(a)])) : null],
          ["Programs", (i.programs || []).length ? el("span", {}, ...i.programs.flatMap((p, n) => [n ? ", " : "", progLink(p.app, p.exe)])) : null],
          ["Hosts", (i.hosts || []).join(", ")],
          ["Countries", (i.countries || []).join(", ")],
          ["What fired", el("div", { class: "chips" }, (i.rules || []).slice(0, 12).map((r) => el("span", { class: "chip rule", title: `${r.count}× · worst ${r.severity}\n${r.example}`, text: `${r.id.replace(/^detector:/, "")} ×${r.count}` })))],
        ]),
        el("div", { class: "section-row" }, el("h4", { text: `Indicators (${iocs.length})` }), iocs.some((x) => x.public) ? checkAll : null),
        iocs.length ? el("table", { class: "minitable iocs" }, el("thead", {}, el("tr", {}, ["Type", "Indicator", "Reputation", ""].map((h) => el("th", { text: h })))), iocBody)
          : el("p", { class: "note", text: "No address, domain, URL or hash could be taken from these alerts." }),
        reputationNote(i.reputation_status),
        el("h4", { text: "Notes" }), note, el("div", { class: "actions", style: "margin-top:6px" }, saveNote),
        el("h4", { text: `Timeline (${fmtNum((i.alerts || []).length)} alert${(i.alerts || []).length === 1 ? "" : "s"}${i.truncated ? ", first " + i.alerts.length + " shown" : ""})` }),
        incidentTimeline(i.alerts || []),
      ].filter(Boolean);
    },
  };
}
function replaceIncidentView(i) {
  const view = incidentView(i);
  view.incident = i.incident_id;
  const at = drawerStack.findIndex((v) => v.incident === i.incident_id);
  if (at >= 0) drawerStack[at] = view; else drawerStack.push(view);
  paintDrawer();
}
async function openIncident(id, push) {
  const loading = loadingView("Incident " + id);
  loading.incident = id;
  showDrawer(loading, push == null ? isOpen() : push);
  try { replaceIncidentView(await api("/api/incidents/" + encodeURIComponent(id), { timeout: 30000 })); }
  catch (e) { const at = drawerStack.indexOf(loading); if (at >= 0) drawerStack.splice(at, 1); toast(e.message); paintDrawer(); }
}

// ---------------------------------------------------------------- everything behind a tactic / technique / rule
/** filter: { tactic } | { mitre } | { rule } | { detector, kind }, plus a title. */
function openAlertSet(filter) {
  const view = { title: filter.title || filter.tactic || filter.mitre || filter.rule || filter.detector, head: [el("span", { class: "chip mitre", text: filter.tactic ? "ATT&CK tactic" : filter.mitre ? "ATT&CK technique" : filter.rule ? "Rule" : "Detector" })],
    range: OPS.det && OPS.det.since ? "session" : "86400", data: null, error: null };
  const load = async () => {
    view.data = null; view.error = null;
    if (drawerStack[drawerStack.length - 1] === view) paintDrawer();
    const since = incSince(view.range);
    const ap = new URLSearchParams({ limit: "500" }), ip = new URLSearchParams({ limit: "100" });
    if (since) { ap.set("since", String(since)); ip.set("since", String(since)); }
    if (filter.tactic) { ap.set("tactic", filter.tactic); ip.set("tactic", filter.tactic); }
    if (filter.mitre) { ap.set("mitre", filter.mitre); ip.set("technique", filter.mitre); }
    if (filter.rule) { ap.set("rule", filter.rule); ip.set("rule", filter.rule); }
    if (filter.detector) { ap.set("detector", filter.detector); ip.set("rule", "detector:" + filter.detector); }
    try {
      const [alerts, incidents] = await Promise.all([
        api("/api/alerts?" + ap, { timeout: 30000 }),
        api("/api/incidents?" + ip, { timeout: 30000 }).catch(() => ({ incidents: [] }))]);
      view.data = { alerts, incidents: incidents.incidents || [] };
    } catch (e) { view.error = e.message; }
    if (drawerStack[drawerStack.length - 1] === view) paintDrawer();
  };
  view.body = () => {
    const seg = el("div", { class: "seg", role: "group", "aria-label": "Period" }, INC_RANGES.map(([v, label]) =>
      el("button", { "aria-pressed": String(v === view.range), onclick: () => { view.range = v; load(); } }, label)));
    const head = el("div", { class: "actions", style: "margin-top:0" }, seg,
      el("button", { class: "btn", title: "Filter, search and export these in the Events tab", onclick: () => pivotEvents({ tactic: filter.tactic, mitre: filter.mitre, rule: filter.rule, kind: filter.kind }) }, "Open in Events"));
    if (view.error) return [head, emptyBox(view.error)];
    if (!view.data) return [head, el("div", { style: "display:flex;gap:8px;align-items:center;color:var(--ink-2);margin-top:14px" }, el("span", { class: "spinner" }), "Loading…")];
    const { alerts, incidents } = view.data;
    const count = (fn) => { const m = new Map(); for (const a of alerts) { const k = fn(a); if (k) m.set(k, (m.get(k) || 0) + 1); } return [...m.entries()].sort((x, y) => y[1] - x[1]); };
    const byApp = count((a) => (a.context || {}).app), byRule = count((a) => a.rule_id || (a.alert_type || "").replace("_", " ")), bySubject = count((a) => subjectOf(a));
    const top = (rows, n) => rows.slice(0, n).map(([k, c]) => `${k} (${c})`).join(", ");
    return [
      head,
      el("p", { class: "note", style: "margin:10px 0 0", text: alerts.length
        ? `${fmtNum(alerts.length)}${alerts.length >= 500 ? "+" : ""} alert${alerts.length === 1 ? "" : "s"} in ${incidents.length} incident${incidents.length === 1 ? "" : "s"}. Click an incident for its whole story, or an alert for the evidence.`
        : "Nothing in this period — try a longer one." }),
      alerts.length ? kvList([["Apps", top(byApp, 5)], ["Subjects", top(bySubject, 5)], ["What fired", top(byRule, 6)]]) : null,
      incidents.length ? el("h4", { text: `Incidents (${incidents.length})` }) : null,
      incidents.length ? el("div", { class: "timeline" }, incidents.map((i) => el("button", { class: "tl-row", "data-sev": i.severity, onclick: () => openIncident(i.incident_id, true) },
        el("span", { class: "tl-time mono", text: fmtAgo(i.last_seen) }), el("span", { class: "tl-dot" }),
        el("span", { class: "tl-main" }, el("span", { class: "tl-msg", text: i.title }),
          el("span", { class: "tl-sub", text: [entityText(i.entity), `${i.alert_count} alert${i.alert_count === 1 ? "" : "s"}`, (i.tactics || []).filter((t) => t !== "Other").join(" → "), INC_STATUS_LABEL[i.status]].filter(Boolean).join(" · ") })),
        sevBadge(i.severity)))) : null,
      alerts.length ? el("h4", { text: `Alerts (${fmtNum(alerts.length)}${alerts.length >= 500 ? ", newest 500" : ""})` }) : null,
      alerts.length ? incidentTimeline(alerts) : null,
    ].filter(Boolean);
  };
  showDrawer(view, false);
  load();
}
