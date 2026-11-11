/* Analyst views — the Detections and Flows tabs, alert-drawer extras and
 * keyboard shortcuts.
 * Loaded after the dashboard script; reuses its helpers (el, icon, api, toast,
 * table, kvList, emptyBox, ipLink, appLink, sevBadge, fmtNum, fmtBytes,
 * fmtAgo, fmtTime, go, state, $).  Everything is rendered with textContent:
 * values taken from traffic are never interpreted as HTML. */
"use strict";

const OPS = {
  det: null,            // /api/detections
  rules: null,          // /api/rules
  ruleQ: "",
  flows: null,          // /api/flows
  flowQ: "",
  flowState: "",
  flowSort: "recent",
  flowGen: 0,
};

function opsTile(label, value, hint, cls) {
  return el("div", { class: "card tile" + (cls ? " " + cls : "") },
    el("div", { class: "label", text: label }),
    el("div", { class: "value", text: typeof value === "number" ? fmtNum(value) : value }),
    el("div", { class: "hint", text: hint || "" }));
}

/** Show the event stream over the last 24 hours, filtered to a search term
 * (an IP, a host) or to an exact field: pivotEvents({ rule: "SIG-C2-009" }),
 * pivotEvents({ mitre: "T1071.004" }), pivotEvents({ kind: "attack" }). */
function pivotEvents(what) {
  const f = typeof what === "string" ? { q: what } : (what || {});
  state.q = f.q || ""; $("search").value = state.q;
  state.kind = f.kind || null; state.app = null;
  state.rule = f.rule || null; state.mitre = f.mitre || null;
  state.range = "86400"; $("rangeFilter").value = "86400";
  if (typeof closeDrawer === "function") closeDrawer();
  go("events"); loadAlerts();
}

// ---------------------------------------------------------------- MITRE helpers
function mitreLink(a) {
  const m = a.mitre;
  if (!a.mitre_technique) return null;
  const href = m && safeHref(m.url);
  const label = a.mitre_technique + (m && m.name ? " · " + m.name : "");
  const node = href ? el("a", { href, target: "_blank", rel: "noreferrer noopener", class: "ext", text: label }) : el("span", { text: label });
  return m && m.tactic ? el("span", {}, node, el("span", { class: "muted", text: "  (" + m.tactic + ")" })) : node;
}

// ---------------------------------------------------------------- alert drawer extras
const FLOW_OUTCOME = {
  attempt: "No answer", rejected: "Refused", established: "Open", reset: "Reset",
  closed: "Closed", closing: "Closing", active: "Active",
};
const HISTORY_LEGEND = "S syn · H syn-ack · A ack · D data · F fin · R reset — upper case: client, lower case: server";
function flowStateChip(outcome) {
  return el("span", { class: "flowstate " + (outcome || "active"), text: FLOW_OUTCOME[outcome] || outcome || "—" });
}
/** Printable dump of a payload preview: control characters become dots. */
function printable(text) {
  return String(text).replace(/[^\x20-\x7e\n\r\t]/g, ".").replace(/\r\n/g, "\n");
}
function alertExtras(a) {
  const out = [];
  const ctx = a.context || {}, ev = a.evidence || {};
  const f = ctx.flow;
  if (f && typeof f === "object") {
    out.push(el("h4", { text: "Connection state" }), kvList([
      ["Outcome", flowStateChip(f.outcome)],
      ["Opened by", f.initiator ? ipLink(f.initiator) : null],
      ["Service", [f.app_proto ? f.app_proto.toUpperCase() : null, f.server_name].filter(Boolean).join(" · ")],
      ["Traffic", f.packets != null ? `${fmtNum(f.packets)} packets · ${fmtBytes(f.bytes_out || 0)} sent · ${fmtBytes(f.bytes_in || 0)} received` : null],
      ["Duration", f.duration != null ? (f.duration < 1 ? "under a second" : fmtDuration(Math.round(f.duration))) : null],
      ["TCP history", f.history ? el("span", { class: "hist", title: HISTORY_LEGEND, text: f.history }) : null],
    ]));
  }
  if (Array.isArray(ev.matched) && ev.matched.length) {
    out.push(el("h4", { text: "Why the rule matched" }),
      el("table", { class: "minitable matched" }, el("tbody", {}, ev.matched.map((m) => el("tr", {},
        el("td", { text: String(m.field) }),
        el("td", { class: "muted", text: String(m.op) }),
        el("td", { text: m.actual === true ? "yes" : m.actual === false ? "no" : String(m.actual == null ? "" : m.actual) }))))));
    if (ev.threshold) out.push(el("p", { class: "note", text: `Fired after ${ev.threshold.hits} matches in ${ev.threshold.seconds}s (rule needs ${ev.threshold.required} within ${ev.threshold.window}s, counted per ${String(ev.threshold.tracked_by).replace("_", " ")}).` }));
  }
  if (Array.isArray(ev.chain) && ev.chain.length) {
    out.push(el("h4", { text: "Attack chain" }),
      el("table", { class: "minitable" }, el("tbody", {}, ev.chain.map((c) => el("tr", {},
        el("td", { class: "mono muted", text: fmtTime(c.time) }),
        el("td", {}, sevBadge(c.severity)),
        el("td", {}, el("div", { text: c.message }), el("div", { class: "sub2", text: [c.detection, c.mitre].filter(Boolean).join(" · ") })))))));
  }
  if (Array.isArray(ev.sample_names) && ev.sample_names.length) {
    out.push(el("h4", { text: "Names that failed to resolve" }),
      el("div", { class: "chips" }, ev.sample_names.map((n) => el("button", { class: "chip", title: "Investigate " + n, onclick: () => { closeDrawer(); investigate(n); } }, n))));
  }
  if (ev.payload_preview) {
    out.push(el("h4", { text: "Payload" + (ev.payload_len ? ` (first ${Math.min(256, ev.payload_len)} of ${fmtNum(ev.payload_len)} bytes)` : "") }),
      el("pre", { class: "payload", text: printable(ev.payload_preview) }));
  }
  // Pivots: one click to the rest of the story.
  const pivots = [];
  const remote = ctx.remote_ip || (ctx.direction === "inbound" ? a.src_ip : a.dst_ip);
  if (remote) pivots.push(el("button", { class: "btn", onclick: () => pivotEvents(remote) }, icon("i-search"), "All events for " + remote));
  if (a.rule_id) pivots.push(el("button", { class: "btn", onclick: () => pivotEvents({ rule: a.rule_id }) }, "Same rule"));
  if (a.mitre_technique) pivots.push(el("button", { class: "btn", onclick: () => pivotEvents({ mitre: a.mitre_technique }) }, "Same technique"));
  if (a.flow_id) pivots.push(el("button", { class: "btn", onclick: () => { closeDrawer(); OPS.flowQ = remote || a.dst_ip || ""; go("flows"); } }, "Show in Flows"));
  pivots.push(el("button", { class: "btn", onclick: () => copyText(JSON.stringify(a, (k, v) => (k === "about" ? undefined : v), 2), "alert JSON") }, "Copy JSON"));
  out.push(el("h4", { text: "Pivot" }), el("div", { class: "actions", style: "margin-top:0" }, pivots));
  return out;
}

// ---------------------------------------------------------------- Detections tab
function detectionsRoot() {
  const root = $("tab-detections");
  if (root.dataset.ready) return root;
  root.dataset.ready = "1";
  root.append(
    el("div", { class: "section-title" },
      el("h1", { text: "Detections" }), el("span", { class: "sub", id: "detSub", text: "what fired this session, mapped to MITRE ATT&CK" }),
      el("div", { class: "right" }, el("button", { class: "btn", onclick: () => loadDetections() }, icon("i-refresh"), "Refresh"))),
    el("div", { class: "grid kpis", id: "detKpis", style: "grid-template-columns:repeat(auto-fit,minmax(170px,1fr))" }),
    el("div", { class: "grid row-1" }, el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", { text: "ATT&CK tactics" }), el("span", { class: "sub", text: "kill-chain order · alerts per tactic" })),
      el("div", { class: "card-body" }, el("div", { class: "tactics", id: "detTactics" })))),
    el("div", { class: "grid row-2" },
      el("div", { class: "card" },
        el("div", { class: "card-head" }, el("h2", { text: "Techniques seen" }), el("span", { class: "sub", text: "click an id for the ATT&CK page" })),
        el("div", { class: "card-body table-wrap", id: "detTechniques" })),
      el("div", { class: "card" },
        el("div", { class: "card-head" }, el("h2", { text: "Top offenders" }), el("span", { class: "sub", text: "addresses behind threat, attack and host alerts" })),
        el("div", { class: "card-body table-wrap", id: "detSources" }))),
    el("div", { class: "grid row-1" }, el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", { text: "What fired" }), el("span", { class: "sub", text: "every rule and detector with at least one alert · click to see its events" })),
      el("div", { class: "card-body table-wrap", id: "detFired" }))),
    el("div", { class: "grid row-1" }, el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", { text: "Signature rules" }), el("span", { class: "sub", id: "rulesSub" })),
      el("div", { class: "toolbar" }, el("input", { type: "search", id: "ruleSearch", placeholder: "Filter rules by id, text, tag, technique…", "aria-label": "Filter rules",
        oninput: (e) => { OPS.ruleQ = e.target.value.trim().toLowerCase(); renderRules(); } })),
      el("div", { class: "card-body table-wrap", id: "rulesTable", style: "padding-top:0" }))));
  return root;
}
function detectionsShow() { detectionsRoot(); loadDetections(); }
function loadDetections() { return once("detections", loadDetectionsNow); }
async function loadDetectionsNow() {
  detectionsRoot();
  try {
    const [det, rules] = await Promise.all([api("/api/detections"), api("/api/rules")]);
    OPS.det = det; OPS.rules = rules;
  } catch (e) {
    if (!(e.offline && OPS.det)) $("detFired").replaceChildren(emptyBox(e.message));
    return;
  }
  renderDetections(); renderRules();
}
function renderDetections() {
  const d = OPS.det; if (!d) return;
  const fired = d.detections || [], total = fired.reduce((n, x) => n + x.count, 0);
  const serious = fired.filter((x) => x.severity === "HIGH" || x.severity === "CRITICAL");
  const rules = (OPS.rules && OPS.rules.rules) || [];
  const activeRules = rules.filter((r) => r.status === "active").length;
  $("detKpis").replaceChildren(
    opsTile("Alerts raised", total, `${fired.length} distinct detections`, "hero"),
    opsTile("High & critical", serious.reduce((n, x) => n + x.count, 0), serious.length ? `${serious.length} detections need a look` : "none this session", serious.length ? "alarm" : ""),
    opsTile("Techniques", (d.techniques || []).length, `${(d.tactics || []).filter((t) => t.tactic !== "Other").length} ATT&CK tactics touched`),
    opsTile("Offending addresses", (d.sources || []).length, "behind threat and attack alerts"),
    opsTile("Rules loaded", activeRules, `${((OPS.rules && OPS.rules.detectors) || []).length} detectors running`));

  // Tactic strip: all tactics in kill-chain order, the ones with alerts lit.
  const byTactic = new Map((d.tactics || []).map((t) => [t.tactic, t.count]));
  const order = [...(d.tactic_order || [])];
  if (byTactic.has("Other")) order.push("Other");
  const maxT = Math.max(1, ...byTactic.values());
  $("detTactics").replaceChildren(...order.map((name) => {
    const n = byTactic.get(name) || 0;
    return el("div", { class: "tactic" + (n ? " hit" : ""), title: n ? `${n} alert${n === 1 ? "" : "s"} mapped to ${name}` : "No alerts mapped to " + name },
      el("div", { class: "name", text: name }), el("div", { class: "n", text: n ? fmtNum(n) : "·" }),
      n ? el("div", { class: "heat", style: `width:${Math.max(6, (n / maxT) * 100).toFixed(0)}%` }) : null);
  }));

  const tech = d.techniques || [];
  $("detTechniques").replaceChildren(tech.length ? table(["Technique", "Name", "Tactic", { label: "Alerts", num: true }],
    tech.map((t) => el("tr", {},
      el("td", {}, safeHref(t.url) ? el("a", { href: safeHref(t.url), target: "_blank", rel: "noreferrer noopener", class: "mono ext", text: t.id }) : el("span", { class: "mono", text: t.id })),
      el("td", { text: t.name || "—" }),
      el("td", { class: "muted", text: t.tactic || "—" }),
      el("td", { class: "num" }, el("button", { class: "link", title: "Show these events", onclick: () => pivotEvents({ mitre: t.id }) }, fmtNum(t.count))))))
    : emptyBox("No alert carried an ATT&CK technique yet."));

  const src = d.sources || [];
  $("detSources").replaceChildren(src.length ? table(["Address", "Worst", { label: "Alerts", num: true }, "Detections", "Last seen"],
    src.slice(0, 25).map((s) => el("tr", {},
      el("td", {}, ipLink(s.ip), s.remote_host || s.org ? el("div", { class: "sub2", text: [s.remote_host, s.org, s.country].filter(Boolean).join(" · ") }) : null),
      el("td", {}, sevBadge(s.worst)),
      el("td", { class: "num" }, el("button", { class: "link", onclick: () => pivotEvents(s.ip) }, fmtNum(s.count))),
      el("td", {}, el("div", { class: "chips" }, (s.detections || []).slice(0, 4).map((n) => el("span", { class: "chip", title: n, text: n.replace(/^detector:/, "") })),
        (s.detections || []).length > 4 ? el("span", { class: "muted", style: "font-size:12px", text: "+" + ((s.detections || []).length - 4) }) : null)),
      el("td", { class: "muted", text: fmtAgo(s.last_seen) }))))
    : emptyBox("No address has triggered a threat or attack alert. 👍"));

  $("detFired").replaceChildren(fired.length ? table(["Detection", "Type", "Worst", "ATT&CK", { label: "Alerts", num: true }, "Last seen", "Latest example"],
    fired.map((x) => {
      const builtin = x.name.startsWith("detector:");
      return el("tr", { class: "clickable", onclick: () => pivotEvents(builtin ? { kind: x.kind } : { rule: x.name }) },
        el("td", { class: "mono", text: x.name.replace(/^detector:/, "") }),
        el("td", { class: "muted", text: builtin ? "built-in detector" : x.type.replace("_", " ") }),
        el("td", {}, sevBadge(x.severity)),
        el("td", { class: "mono muted", text: x.mitre || "—" }),
        el("td", { class: "num", text: fmtNum(x.count) }),
        el("td", { class: "muted", text: fmtAgo(x.last_seen) }),
        el("td", {}, el("div", { class: "sub2", style: "max-width:520px", text: String(x.example || "").slice(0, 160) })));
    }))
    : emptyBox("Nothing has fired yet this session."));
  $("detSub").textContent = `${fmtNum(total)} alerts this session, mapped to MITRE ATT&CK`;
}
function renderRules() {
  const r = OPS.rules; if (!r || !$("rulesTable")) return;
  const q = OPS.ruleQ;
  const all = r.rules || [];
  const rows = all.filter((x) => !q || [x.id, x.description, x.mitre, x.severity, (x.tags || []).join(" ")].join(" ").toLowerCase().includes(q))
    .sort((a, b) => (b.hits - a.hits) || String(a.id).localeCompare(String(b.id)));
  const files = (r.files || []).map((f) => f.split("/").pop()).join(" + ");
  $("rulesSub").textContent = all.length ? `${all.filter((x) => x.status === "active").length} active of ${all.length}${files ? " · " + files : ""}` : "no rules loaded";
  const parts = [];
  if ((r.problems || []).length) parts.push(el("div", { class: "problems", role: "alert" }, el("b", { text: `${r.problems.length} rule${r.problems.length > 1 ? "s" : ""} could not be loaded` }), r.problems.slice(0, 8).map((p) => el("div", { text: p }))));
  parts.push(rows.length ? table(["Rule", "Severity", "What it detects", "ATT&CK", "Threshold", { label: "Hits", num: true }, "Last hit", "Status"],
    rows.map((x) => el("tr", {},
      el("td", { class: "mono", text: x.id }),
      el("td", {}, sevBadge(x.severity)),
      el("td", {}, el("div", { text: x.description }), (x.tags || []).length ? el("div", { class: "sub2", text: x.tags.join(" · ") }) : null),
      el("td", { class: "mono muted", text: x.mitre || "—" }),
      el("td", { class: "mono muted", text: x.threshold ? `${x.threshold.count} / ${x.threshold.seconds}s` : "—" }),
      el("td", { class: "num" }, x.hits ? el("button", { class: "link", onclick: () => pivotEvents({ rule: x.id }) }, fmtNum(x.hits)) : el("span", { class: "muted", text: "0" })),
      el("td", { class: "muted", text: x.last_hit ? fmtAgo(x.last_hit) : "—" }),
      el("td", {}, el("span", { class: "rule-status " + x.status, text: x.status })))))
    : emptyBox(all.length ? "No rule matches the filter." : "No signature rules are loaded. The daemon loads the built-in set unless daemon.rules is 'none'."));
  if (all.length) parts.push(el("div", { class: "tablecap", text: "Retune or switch off single rules in rules.yaml in the PyNIDS data directory, e.g.  - {id: SIG-C2-006, enabled: false}  — changes are picked up within 30 seconds." }));
  $("rulesTable").replaceChildren(...parts);
}

// ---------------------------------------------------------------- Flows tab
function flowsRoot() {
  const root = $("tab-flows");
  if (root.dataset.ready) return root;
  root.dataset.ready = "1";
  const seg = el("div", { class: "seg", id: "flowStateSeg", role: "group", "aria-label": "Filter by state" },
    [["", "All"], ["established", "Open"], ["attempt", "No answer"], ["rejected", "Refused"], ["reset", "Reset"], ["closed", "Closed"]].map(([v, label]) =>
      el("button", { "data-s": v, "aria-pressed": String(v === OPS.flowState), onclick: () => { OPS.flowState = v; syncFlowControls(); loadFlows(); } }, label)));
  let timer;
  root.append(
    el("div", { class: "section-title" },
      el("h1", { text: "Flows" }), el("span", { class: "sub", id: "flowSub", text: "the live connection table" }),
      el("div", { class: "right" }, el("button", { class: "btn", onclick: () => loadFlows() }, icon("i-refresh"), "Refresh"))),
    el("div", { class: "grid kpis", id: "flowKpis", style: "grid-template-columns:repeat(auto-fit,minmax(170px,1fr))" }),
    el("div", { class: "grid row-1" }, el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", { text: "Connections seen on the wire" }), el("span", { class: "sub", id: "flowCount" })),
      el("div", { class: "toolbar" }, seg,
        el("input", { type: "search", id: "flowSearch", placeholder: "Filter by IP, port, host, app, protocol…", "aria-label": "Filter flows",
          oninput: (e) => { clearTimeout(timer); timer = setTimeout(() => { OPS.flowQ = e.target.value.trim(); loadFlows(); }, 250); } }),
        el("select", { id: "flowSort", "aria-label": "Sort flows", onchange: (e) => { OPS.flowSort = e.target.value; loadFlows(); } },
          [["recent", "Most recent"], ["bytes", "Most data"], ["duration", "Longest"], ["packets", "Most packets"]].map(([v, label]) => el("option", { value: v, text: label })))),
      el("div", { class: "card-body table-wrap", id: "flowTable", style: "padding-top:0" }))));
  return root;
}
function syncFlowControls() {
  document.querySelectorAll("#flowStateSeg button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.s === OPS.flowState)));
  const s = $("flowSearch"); if (s && s.value !== OPS.flowQ) s.value = OPS.flowQ;
  const sort = $("flowSort"); if (sort) sort.value = OPS.flowSort;
}
function flowsShow() { flowsRoot(); syncFlowControls(); loadFlows(); }
async function loadFlows() {
  flowsRoot();
  const params = new URLSearchParams({ limit: "300", sort: OPS.flowSort });
  if (OPS.flowQ) params.set("q", OPS.flowQ);
  if (OPS.flowState) params.set("state", OPS.flowState);
  const gen = ++OPS.flowGen;  // filters change faster than answers arrive
  let data;
  try { data = await api("/api/flows?" + params); }
  catch (e) { if (gen === OPS.flowGen && !(e.offline && OPS.flows)) $("flowTable").replaceChildren(emptyBox(e.message)); return; }
  if (gen !== OPS.flowGen) return;
  OPS.flows = data;
  renderFlows();
}
function endpoint(ip, port) {
  return el("span", {}, ipLink(ip), port ? el("span", { class: "mono muted", text: ":" + port }) : null);
}
function renderFlows() {
  const d = OPS.flows; if (!d) return;
  const c = d.counts || {};
  $("flowKpis").replaceChildren(
    opsTile("Tracked flows", c.active || 0, `${fmtNum(c.total || 0)} since start`, "hero"),
    opsTile("TCP", c.tcp || 0, `${fmtNum(c.established || 0)} established`),
    opsTile("UDP", c.udp || 0, "includes QUIC and DNS"),
    opsTile("Opening", c.new || 0, "handshake not finished, or no flags seen"),
    opsTile("Closed", (c.closed || 0) + (c.closing || 0), "kept for a minute"));
  const rows = d.flows || [];
  $("flowCount").textContent = d.total > rows.length ? `showing ${rows.length} of ${fmtNum(d.total)}` : `${rows.length} flow${rows.length === 1 ? "" : "s"}`;
  $("flowTable").replaceChildren(rows.length ? el("div", {},
    table(["Proto", "Client → server", "Service", "App", "State", { label: "Packets", num: true }, { label: "Sent", num: true }, { label: "Received", num: true }, { label: "Duration", num: true }, "Last packet"],
      rows.map((f) => el("tr", {},
        el("td", {}, el("span", { class: "proto", text: f.protocol })),
        el("td", {}, endpoint(f.src_ip, f.src_port), el("span", { class: "arrow", text: "→" }), endpoint(f.dst_ip, f.dst_port),
          f.initiator_inferred ? el("div", { class: "sub2", title: "The first packet seen came from the server; the client was worked out from flags and ports.", text: "direction inferred" }) : null),
        el("td", {}, el("div", { text: [f.app_proto ? f.app_proto.toUpperCase() : null, f.server_name].filter(Boolean).join(" · ") || "—" }),
          f.org || f.country ? el("div", { class: "sub2", text: [f.org, f.country].filter(Boolean).join(" · ") }) : null),
        el("td", {}, f.app ? appLink(f.app) : el("span", { class: "muted", text: "—" })),
        el("td", {}, flowStateChip(f.outcome), f.history ? el("div", { class: "hist", title: HISTORY_LEGEND, text: f.history }) : null),
        el("td", { class: "num", text: fmtNum(f.packets) }),
        el("td", { class: "num", text: fmtBytes(f.bytes_out) }),
        el("td", { class: "num", text: fmtBytes(f.bytes_in) }),
        el("td", { class: "num", text: f.duration < 1 ? "<1s" : fmtDuration(Math.round(f.duration)) }),
        el("td", { class: "muted", text: fmtAgo(f.last_seen) })))),
    el("div", { class: "tablecap", text: "Sent / received count application payload from the client's point of view. “No answer” means a SYN went out and nothing came back (filtered port or dead host); “Refused” means the other side reset it (closed port)." }))
    : emptyBox(OPS.flowQ || OPS.flowState ? "No flow matches these filters." : "No flows yet — capture may be paused or still starting."));
}

// ---------------------------------------------------------------- keyboard shortcuts
const TAB_KEYS = { o: "overview", c: "connections", e: "events", d: "detections", f: "flows", a: "apps", n: "network", p: "protection", i: "investigate", m: "email" };
const TAB_SEARCH = { events: "search", connections: "connSearch", flows: "flowSearch", detections: "ruleSearch", investigate: "invInput" };
function showShortcuts() {
  showDrawer({
    title: "Keyboard shortcuts", head: [],
    body: () => [el("div", { class: "keys" },
      [["g then o / c / e / d / f", "Overview · Connections · Events · Detections · Flows"],
       ["g then a / n / p / i / m", "Apps · Network · Protection · Investigate · Email"],
       ["/", "Focus the search box of the current tab"],
       ["j / k", "Next / previous event in the stream"],
       ["Enter", "Open the focused event"],
       ["Esc", "Close the drawer, or leave a search box"],
       ["?", "This list"]].flatMap(([k, d]) => [el("div", {}, el("kbd", { text: k })), el("div", { text: d })]))],
  });
}
let goPending = 0;
addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey || isEditable(document.activeElement)) return;
  const key = e.key;
  if (goPending && Date.now() - goPending < 1200 && TAB_KEYS[key]) { goPending = 0; e.preventDefault(); if (isOpen()) closeDrawer(); go(TAB_KEYS[key]); return; }
  goPending = 0;
  if (key === "g") { goPending = Date.now(); return; }
  if (key === "?") { e.preventDefault(); showShortcuts(); return; }
  if (key === "/") {
    const box = $(TAB_SEARCH[state.tab] || "");
    if (box) { e.preventDefault(); box.focus(); if (box.select) box.select(); }
    return;
  }
  if ((key === "j" || key === "k") && state.tab === "events" && !isOpen()) {
    const rows = [...document.querySelectorAll("#eventList .event")];
    if (!rows.length) return;
    const at = rows.indexOf(document.activeElement);
    const next = rows[Math.max(0, Math.min(rows.length - 1, at < 0 ? 0 : at + (key === "j" ? 1 : -1)))];
    e.preventDefault(); next.focus(); next.scrollIntoView({ block: "nearest" });
  }
});
if ($("keysBtn")) $("keysBtn").addEventListener("click", showShortcuts);
