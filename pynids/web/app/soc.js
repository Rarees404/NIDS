/* SOC workbench — the Investigate tab.
 * Loaded after the dashboard script; reuses its helpers (el, icon, api, toast,
 * kvList, table, fmtAgo, blockIp, go, $).  Everything is rendered with
 * textContent: values from sources are never interpreted as HTML. */
"use strict";

const SOC = {
  sources: null,        // [{name, label, configured, key, ...}]
  ioc: null,            // the indicator being investigated
  results: {},          // source name -> result | {loading: true}
  trail: [],            // pivot history: [{type, value, ...ioc}]
  parsed: null,         // multi-indicator extraction result
  listFilter: null,
  retry: {},            // source name -> timer (rate limits)
};
const VERDICT_LABEL = { malicious: "Malicious", suspicious: "Suspicious", clean: "Clean", info: "Info", unknown: "No verdict" };
const VERDICT_ORDER = ["malicious", "suspicious", "clean", "info", "unknown"];
const TYPE_LABEL = { ipv4: "IPv4", ipv6: "IPv6", domain: "Domain", url: "URL", email: "Email", md5: "MD5", sha1: "SHA-1",
  sha256: "SHA-256", sha512: "SHA-512", asn: "ASN", cve: "CVE" };
const RANK = { unknown: 0, info: 1, clean: 2, suspicious: 3, malicious: 4 };

async function copyText(text, what) {
  try { await navigator.clipboard.writeText(text); toast("Copied " + (what || "")); }
  catch (_) { toast("Couldn't copy — select and copy manually"); }
}
/** Text with its https:// URLs turned into links (built with textContent, never HTML). */
function linkify(text) {
  return String(text || "").split(/(https:\/\/[^\s)]+)/).map((part, i) =>
    i % 2 ? el("a", { href: part, target: "_blank", rel: "noreferrer noopener" }, part) : part);
}
function vpill(verdict) { return el("span", { class: "vpill", "data-verdict": verdict, text: VERDICT_LABEL[verdict] || verdict }); }

// ---------------------------------------------------------------- shell
function socRoot() {
  const root = $("tab-investigate");
  if (root.dataset.ready) return root;
  root.dataset.ready = "1";
  const input = el("textarea", { id: "invInput", rows: "1", spellcheck: "false", autocomplete: "off",
    placeholder: "IP, domain, URL, hash, email, ASN, CVE — or paste a whole alert / report",
    "aria-label": "Indicator to investigate" });
  input.addEventListener("input", () => { input.style.height = "auto"; input.style.height = Math.min(260, input.scrollHeight) + "px"; });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); socRun(input.value); } });
  const examples = el("span", { class: "examples" }, "Try ",
    ...[["8.8.8.8"], ["hxxps://example[.]com/login"], ["44d88612fea8a8f36de82e1278abb02f"]].flatMap(([v], i) =>
      [i ? ", " : "", el("button", { onclick: () => { input.value = v; socRun(v); } }, v)]));
  root.append(
    el("div", { class: "section-title" }, el("h1", { text: "Investigate" }),
      el("span", { class: "sub", text: "Look up indicators across threat-intel sources, then pivot." }),
      el("div", { class: "right" },
        el("button", { class: "btn", onclick: () => socHome() }, "Home"),
        el("button", { class: "btn", onclick: () => openSourcesDrawer() }, "Sources & API keys"))),
    el("div", { class: "card inv-search" },
      el("div", { class: "box" }, input,
        el("button", { class: "btn primary", onclick: () => socRun(input.value) }, icon("i-spark"), "Investigate")),
      el("div", { class: "hint" },
        el("span", {}, el("kbd", { text: "Enter" }), " investigate · ", el("kbd", { text: "Shift" }), "+", el("kbd", { text: "Enter" }), " new line"),
        el("span", { text: "Defanged input (hxxp, [.]) is understood." }), examples)),
    el("div", { id: "invTrail", class: "trail" }),
    el("div", { id: "invMain" }));
  return root;
}

async function loadSources(force) {
  if (SOC.sources && !force) return SOC.sources;
  SOC.sources = await api("/api/soc/sources");
  return SOC.sources;
}
function sourceInfo(name) { return (SOC.sources || []).find((s) => s.name === name) || { name, label: name }; }

async function socShow(arg) {
  socRoot();
  try { await loadSources(); } catch (e) { $("invMain").replaceChildren(emptyBox(e.message)); return; }
  if (arg) { $("invInput").value = arg; socRun(arg); }
  else if (!SOC.ioc && !SOC.parsed) socHome();
  setTimeout(() => $("invInput").focus(), 0);
}

/** Entry point used elsewhere in the dashboard ("Investigate" buttons). */
function investigate(value) {
  go("investigate/" + encodeURIComponent(value));
}

// ---------------------------------------------------------------- home
async function socHome() {
  SOC.ioc = null; SOC.parsed = null; SOC.trail = []; renderTrail();
  const main = $("invMain");
  const hist = el("div", { class: "hist" }, el("div", { class: "skeleton" }));
  const srcs = el("div", { class: "srclist" });
  main.replaceChildren(el("div", { class: "inv-home" },
    el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", { text: "Recent investigations" }),
        el("div", { class: "right" }, el("button", { class: "mini-btn", onclick: async () => {
          if (!confirm("Clear the investigation history?")) return;
          await api("/api/soc/history", { method: "DELETE" }); socHome(); } }, "Clear"))),
      el("div", { class: "card-body" }, hist)),
    el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", { text: "Sources" }), el("span", { class: "sub", text: "passive lookups — nothing is scanned" })),
      el("div", { class: "card-body" }, srcs))));
  try {
    const rows = await api("/api/soc/history?limit=40");
    hist.replaceChildren(...(rows.length ? rows.map((r) => el("button", { "data-verdict": r.verdict, onclick: () => investigate(r.value) },
      el("i"), el("span", { class: "t", text: TYPE_LABEL[r.kind] || r.kind }), el("span", { class: "v", text: r.value }),
      el("span", { class: "a", text: fmtAgo(r.last) }))) : [emptyBox("Nothing investigated yet.")]));
  } catch (e) { hist.replaceChildren(emptyBox(e.message)); }
  await loadSources().catch(() => {});
  srcs.replaceChildren(...(SOC.sources || []).map((s) => el("div", { class: "srcline" },
    el("b", { text: s.label }), s.configured ? el("span", { class: "ok-dot", text: s.key ? "● key set" : "● ready" })
      : s.key_optional ? el("span", {}, el("span", { class: "ok-dot", text: "● ready " }),
          el("button", { class: "mini-btn", title: "Works without a key; a free key raises the limits", onclick: () => openSourcesDrawer(s.name) }, "add key"))
      : el("button", { class: "mini-btn", onclick: () => openSourcesDrawer(s.name) }, "Add free key"),
    el("p", { text: s.description }),
    el("div", { class: "types" }, s.types.map((t) => el("span", { text: TYPE_LABEL[t] || t }))))));
}

// ---------------------------------------------------------------- run
async function socRun(text) {
  text = (text || "").trim();
  if (!text) return;
  const main = $("invMain");
  main.replaceChildren(el("div", { class: "card", style: "margin-top:16px;padding:18px" }, el("div", { class: "skeleton" }), el("div", { class: "skeleton", style: "width:60%" })));
  let parsed;
  try { parsed = await api("/api/soc/parse", { method: "POST", body: JSON.stringify({ text }) }); }
  catch (e) { main.replaceChildren(emptyBox(e.message)); return; }
  if (!parsed.iocs.length) {
    main.replaceChildren(el("div", { class: "card", style: "margin-top:16px" }, emptyBox("No indicators recognised. Paste an IP, domain, URL, file hash, email address, ASN or CVE.")));
    return;
  }
  if (parsed.single) { SOC.trail = []; openIoc(parsed.iocs[0]); return; }
  SOC.parsed = parsed; SOC.ioc = null; SOC.listFilter = null; SOC.trail = []; renderTrail();
  renderList();
}

function renderList() {
  const p = SOC.parsed, counts = {};
  for (const i of p.iocs) counts[i.type] = (counts[i.type] || 0) + 1;
  const rows = p.iocs.filter((i) => !SOC.listFilter || i.type === SOC.listFilter);
  const defangedAll = () => rows.map((i) => i.defanged).join("\n");
  $("invMain").replaceChildren(el("div", { class: "card", style: "margin-top:16px" },
    el("div", { class: "card-head" }, el("h2", { text: `${p.iocs.length} indicators found` }),
      el("span", { class: "sub", text: "pick one to investigate" }),
      el("div", { class: "right" },
        el("button", { class: "mini-btn", onclick: () => copyText(defangedAll(), "defanged list") }, "Copy defanged"),
        el("button", { class: "mini-btn", onclick: () => copyText(rows.map((i) => i.value).join("\n"), "list") }, "Copy raw"),
        el("button", { class: "mini-btn", onclick: () => downloadCsv(rows) }, "CSV"))),
    el("div", { class: "toolbar" }, el("div", { class: "ioc-filter" },
      el("button", { class: "filter-chip", "aria-pressed": String(!SOC.listFilter), onclick: () => { SOC.listFilter = null; renderList(); } }, "All", el("span", { class: "n", text: p.iocs.length })),
      ...Object.entries(counts).map(([t, n]) => el("button", { class: "filter-chip", "aria-pressed": String(SOC.listFilter === t),
        onclick: () => { SOC.listFilter = t; renderList(); } }, TYPE_LABEL[t] || t, el("span", { class: "n", text: n }))))),
    el("div", { class: "table-wrap", style: "padding:0 8px 8px" }, table(["Type", "Indicator", ""], rows.map((i) =>
      el("tr", { class: "clickable", onclick: () => openIoc(i) },
        el("td", {}, el("span", { class: "type-chip", text: TYPE_LABEL[i.type] || i.type })),
        el("td", { class: "v" }, i.value, i.public === false ? el("small", { text: "private / reserved address" }) : null),
        el("td", { class: "num" }, el("button", { class: "btn", onclick: (e) => { e.stopPropagation(); openIoc(i); } }, "Investigate →")))), { cls: "ioc-list" }))));
}

function downloadCsv(rows) {
  const q = (s) => '"' + String(s).replace(/"/g, '""') + '"';
  const csv = "type,value,defanged\n" + rows.map((i) => [i.type, i.value, i.defanged].map(q).join(",")).join("\n");
  const a = el("a", { href: URL.createObjectURL(new Blob([csv], { type: "text/csv" })), download: "indicators.csv" });
  document.body.append(a); a.click(); a.remove();
}

// ---------------------------------------------------------------- one indicator
async function openIoc(ioc, opts = {}) {
  if (!ioc.sources) {  // a pivot: only type + value known
    try { ioc = (await api("/api/soc/parse", { method: "POST", body: JSON.stringify({ text: ioc.value }) })).iocs[0] || ioc; }
    catch (e) { toast(e.message); return; }
  }
  Object.values(SOC.retry).forEach(clearTimeout); SOC.retry = {};
  SOC.ioc = ioc; SOC.results = {};
  if (!opts.fromTrail) {
    const idx = SOC.trail.findIndex((t) => t.type === ioc.type && t.value === ioc.value);
    if (idx >= 0) SOC.trail = SOC.trail.slice(0, idx + 1); else SOC.trail.push(ioc);
  }
  $("invInput").value = ioc.value;
  renderTrail();
  await loadSources().catch(() => {});
  const runnable = ioc.sources.filter((n) => { const s = sourceInfo(n); return s.configured || s.key_optional; });
  const missing = ioc.sources.filter((n) => !runnable.includes(n));
  $("invMain").replaceChildren(
    el("div", { class: "card", style: "margin-top:16px", id: "invSubject" }),
    el("div", { class: "src-grid", id: "invGrid" }, runnable.map((n) => el("div", { class: "card src", id: "src-" + n }))),
    el("div", { class: "grid row-2", style: "margin-top:16px" }, linksCard(ioc), missingCard(missing)));
  for (const n of runnable) { SOC.results[n] = { loading: true }; renderCard(n); }
  renderSubject();
  runnable.forEach((n) => lookupOne(n, false));
  scrollTo({ top: 0 });
}

async function lookupOne(name, refresh) {
  const ioc = SOC.ioc;
  SOC.results[name] = { loading: true }; renderCard(name);
  let res;
  try { res = await api("/api/soc/lookup", { method: "POST", body: JSON.stringify({ source: name, type: ioc.type, value: ioc.value, refresh }) }); }
  catch (e) { res = { source: name, status: "error", message: e.message, verdict: "unknown", summary: [], tags: [], pivots: [] }; }
  if (SOC.ioc !== ioc) return;  // the analyst moved on
  SOC.results[name] = res;
  if (res.status === "rate_limited") {
    SOC.retry[name] = setTimeout(() => { if (SOC.ioc === ioc) lookupOne(name, refresh); }, (res.retry_after || 15) * 1000);
  }
  renderCard(name); renderSubject();
}

function renderTrail() {
  const host = $("invTrail");
  if (!host) return;
  if (SOC.trail.length < 2) { host.replaceChildren(); return; }
  host.replaceChildren(el("span", { text: "Pivot trail:" }), ...SOC.trail.flatMap((t, i) => [
    i ? el("span", { class: "sep", text: "›" }) : null,
    el("button", { title: t.value, "aria-current": String(i === SOC.trail.length - 1),
      onclick: () => { SOC.trail = SOC.trail.slice(0, i + 1); openIoc(t, { fromTrail: true }); } }, t.value),
  ].filter(Boolean)));
}

function overall() {
  const done = Object.values(SOC.results).filter((r) => !r.loading);
  let v = "unknown";
  for (const r of done) if (r.status === "ok" && RANK[r.verdict] > RANK[v]) v = r.verdict;
  const tally = {};
  for (const r of done) {
    const k = r.status === "ok" ? r.verdict : r.status === "not_found" ? "no data" : r.status === "error" ? "failed" : r.status;
    tally[k] = (tally[k] || 0) + 1;
  }
  return { verdict: v, tally, pending: Object.values(SOC.results).filter((r) => r.loading).length };
}

function renderSubject() {
  const ioc = SOC.ioc, box = $("invSubject");
  if (!ioc || !box) return;
  const o = overall();
  const isIp = ioc.type === "ipv4" || ioc.type === "ipv6";
  const verdictText = o.verdict === "unknown" ? (o.pending ? "Checking…" : "No verdict")
    : o.verdict === "info" ? "No reputation hits" : VERDICT_LABEL[o.verdict];
  const tallyColors = { malicious: "var(--critical)", suspicious: "var(--warning)", clean: "var(--good)", info: "var(--accent)" };
  box.replaceChildren(el("div", { class: "subject" },
    el("div", {},
      el("div", { class: "meta", style: "margin:0 0 6px" }, el("span", { class: "type-chip", text: TYPE_LABEL[ioc.type] || ioc.type }),
        ioc.public === false ? el("span", { class: "chip", text: "private / reserved — not sent to outside sources" }) : null),
      el("div", { class: "value", text: ioc.value }),
      el("div", { class: "meta" }, el("span", { class: "defanged", text: ioc.defanged }),
        el("button", { class: "mini-btn", onclick: () => copyText(ioc.defanged, "defanged") }, "Copy defanged"),
        el("button", { class: "mini-btn", onclick: () => copyText(ioc.value, "value") }, "Copy raw"),
        ioc.original && ioc.original !== ioc.value ? el("span", { class: "muted", text: "you entered: " + ioc.original }) : null),
      el("div", { class: "tally" }, ...Object.entries(o.tally).sort((a, b) => (RANK[b[0]] || 0) - (RANK[a[0]] || 0)).map(([k, n]) =>
        el("span", {}, el("i", { style: "background:" + (tallyColors[k] || "var(--muted)") }), `${n} ${k}`)),
        o.pending ? el("span", {}, el("span", { class: "spinner" }), `${o.pending} pending`) : null)),
    el("div", { class: "side" },
      el("span", { class: "verdict-big " + o.verdict, "data-verdict": o.verdict, text: verdictText }),
      el("div", { class: "actions" },
        el("button", { class: "btn", onclick: () => Object.keys(SOC.results).forEach((n) => lookupOne(n, true)) }, icon("i-refresh"), "Refresh all"),
        el("button", { class: "btn", onclick: () => copyText(reportMarkdown(), "report") }, "Copy report"),
        isIp && ioc.public !== false ? el("button", { class: "btn danger", onclick: () => blockIp(ioc.value, "Blocked from Investigate") }, icon("i-ban"), "Block") : null))));
}

// ---------------------------------------------------------------- source card
function renderCard(name) {
  const card = $("src-" + name);
  if (!card) return;
  const s = sourceInfo(name), r = SOC.results[name] || {};
  const head = el("div", { class: "card-head" },
    el("h2", {}, s.homepage ? el("a", { href: s.homepage, target: "_blank", rel: "noreferrer noopener", style: "color:inherit;text-decoration:none", title: s.description }, s.label) : s.label),
    r.loading ? el("span", { class: "spinner" }) : r.status === "ok" ? vpill(r.verdict) : null,
    el("div", { class: "right" },
      r.fetched && !r.loading ? el("span", { class: "when", title: new Date(r.fetched * 1000).toLocaleString(), text: (r.cached ? "cached · " : "") + fmtAgo(r.fetched) }) : null,
      el("button", { class: "icon-btn", title: "Look up again (skip cache)", "aria-label": "Refresh " + s.label, disabled: !!r.loading, onclick: () => lookupOne(name, true) }, icon("i-refresh"))));
  card.dataset.verdict = r.status === "ok" ? r.verdict : "unknown";
  const body = el("div", { class: "card-body" });
  if (r.loading) body.append(el("div", { class: "skeleton" }), el("div", { class: "skeleton", style: "width:70%" }), el("div", { class: "skeleton", style: "width:45%" }));
  else body.append(...cardBody(r));
  card.replaceChildren(head, body);
}

const STATUS_TEXT = { not_found: "No record", error: "Failed", needs_key: "Needs an API key", unsupported: "Not applicable", rate_limited: "Rate limited" };

function cardBody(r) {
  const out = [];
  if (r.status !== "ok") {
    out.push(el("div", { class: "status" + (r.status === "error" ? " err" : "") },
      r.status === "rate_limited" ? el("span", { class: "spinner" }) : null,
      el("b", { text: STATUS_TEXT[r.status] || r.status }), r.message ? el("span", { text: "— " + r.message }) : null));
  } else if (r.message) out.push(el("div", { class: "status", text: r.message }));
  if (r.summary && r.summary.length) {
    const dl = el("dl", { class: "kv" });
    for (const [k, v] of r.summary) {
      const rows = Array.isArray(v) && v.length && typeof v[0] === "object" && v[0] !== null;
      const dd = summaryValue(v);
      if (rows) dd.classList.add("wide");
      dl.append(el("dt", { class: rows ? "wide" : "", text: k }), dd);
    }
    out.push(dl);
  }
  if (r.tags && r.tags.length) out.push(el("div", { class: "chips tags" }, r.tags.map((t) => el("span", { class: "chip", text: t }))));
  if (r.pivots && r.pivots.length) out.push(pivotBlock(r.pivots));
  if (r.raw != null) out.push(rawBlock(r));
  return out;
}

function summaryValue(v) {
  if (Array.isArray(v)) {
    if (v.length && typeof v[0] === "object" && v[0] !== null) {  // structured rows (urlscan scans)
      const dd = el("dd", {});
      const draw = (all) => dd.replaceChildren(...(all ? v : v.slice(0, 5)).map((row) => el("div", { class: "scan-row" },
        el("span", { class: "muted", text: row.time || "" }),
        el("span", { class: "u", text: row.url || "" }),
        el("span", {}), el("span", { class: "muted", text: [row.ip, row.country, row.server].filter(Boolean).join(" · ") }),
        row.report ? el("span", {}) : null,
        row.report ? el("span", {}, el("a", { href: row.report, target: "_blank", rel: "noreferrer noopener", class: "ext" }, "report")) : null)),
        !all && v.length > 5 ? el("button", { class: "mini-btn", onclick: () => draw(true) }, `+${v.length - 5} more`) : null);
      draw(false);
      return dd;
    }
    const dd = el("dd", {});
    const draw = (all) => dd.replaceChildren(el("ul", {}, (all ? v : v.slice(0, 6)).map((x) => el("li", { text: String(x) }))),
      !all && v.length > 6 ? el("button", { class: "mini-btn", onclick: () => draw(true) }, `+${v.length - 6} more`) : "");
    draw(false);
    return dd;
  }
  const s = String(v);
  return el("dd", { class: /^[0-9a-f:./\-]{16,}$/i.test(s) ? "mono-ish" : "", text: s });
}

function pivotBlock(pivots) {
  const LIMIT = 16;
  const wrap = el("div", { class: "pivots" });
  const draw = (all) => {
    const shown = all ? pivots : pivots.slice(0, LIMIT);
    wrap.replaceChildren(el("div", { class: "lbl", text: `Pivot (${pivots.length})` }),
      el("div", { class: "chips" }, shown.map((p) => el("button", { class: "pivot", title: `Investigate ${p.value}${p.label ? " (" + p.label + ")" : ""}`,
        onclick: () => openIoc({ type: p.type, value: p.value }) }, p.value, p.label ? el("small", { text: p.label }) : null)),
        !all && pivots.length > LIMIT ? el("button", { class: "mini-btn", onclick: () => draw(true) }, `+${pivots.length - LIMIT} more`) : null));
  };
  draw(false);
  return wrap;
}

function rawBlock(r) {
  const text = typeof r.raw === "string" ? r.raw : JSON.stringify(r.raw, null, 2);
  const pre = el("pre", { class: "json" });
  const det = el("details", { class: "raw" },
    el("summary", {}, `Raw response (${fmtBytes(text.length)})`, r.truncated ? el("span", { class: "chip flag", text: "truncated at 2 MB" }) : null,
      el("button", { class: "mini-btn copy", onclick: (e) => { e.preventDefault(); copyText(text, "raw response"); } }, "Copy")),
    pre);
  det.addEventListener("toggle", () => { if (det.open && !pre.textContent) pre.textContent = text; });
  return det;
}

function linksCard(ioc) {
  return el("div", { class: "card" },
    el("div", { class: "card-head" }, el("h2", { text: "Open in…" }), el("span", { class: "sub", text: "nothing is sent until you click" })),
    el("div", { class: "card-body" }, ioc.links && ioc.links.length
      ? el("div", { class: "linkgrid" }, ioc.links.map((l) => el("a", { href: l.url, target: "_blank", rel: "noreferrer noopener" }, l.label)))
      : emptyBox("No external tools for this type.")));
}

function missingCard(names) {
  if (!names.length) return el("div");
  return el("div", { class: "card src needs-key" },
    el("div", { class: "card-head" }, el("h2", { text: "More sources" }), el("span", { class: "sub", text: "free API key needed" })),
    el("div", { class: "card-body" }, el("div", { class: "srclist" }, names.map((n) => {
      const s = sourceInfo(n);
      return el("div", { class: "srcline" }, el("b", { text: s.label }),
        el("button", { class: "mini-btn", onclick: () => openSourcesDrawer(n) }, "Add key"),
        el("p", { text: s.description }));
    }))));
}

// ---------------------------------------------------------------- report
function reportMarkdown() {
  const ioc = SOC.ioc, o = overall();
  const lines = [`## Investigation: ${ioc.defanged}`, "",
    `- **Type:** ${TYPE_LABEL[ioc.type] || ioc.type}`,
    `- **Overall:** ${VERDICT_LABEL[o.verdict]}`,
    `- **Investigated:** ${new Date().toISOString().replace("T", " ").slice(0, 16)} UTC (PyNIDS workbench)`, ""];
  const defangText = (s) => String(s).replace(/https?:\/\//gi, (m) => m.replace(/^http/i, "hxxp")).replace(/(\w)\.(\w)/g, "$1[.]$2");
  for (const [name, r] of Object.entries(SOC.results)) {
    if (r.loading) continue;
    const s = sourceInfo(name);
    lines.push(`### ${s.label} — ${r.status === "ok" ? VERDICT_LABEL[r.verdict] : STATUS_TEXT[r.status] || r.status}`);
    if (r.message) lines.push(`_${r.message}_`);
    for (const [k, v] of r.summary || []) {
      const val = Array.isArray(v) ? v.map((x) => typeof x === "object" ? [x.time, x.url, x.ip].filter(Boolean).join(" · ") : x).join("; ") : v;
      lines.push(`- ${k}: ${defangText(val)}`);
    }
    if (r.tags && r.tags.length) lines.push(`- Tags: ${r.tags.join(", ")}`);
    if (r.fetched) lines.push(`- Retrieved: ${new Date(r.fetched * 1000).toISOString().replace("T", " ").slice(0, 16)} UTC${r.cached ? " (cached)" : ""}`);
    lines.push("");
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------- sources drawer
async function openSourcesDrawer(focus) {
  await loadSources(true).catch(() => {});
  const keyed = (SOC.sources || []).filter((s) => s.key);
  const seen = new Set();
  const groups = keyed.filter((s) => !seen.has(s.key) && seen.add(s.key));
  showDrawer({
    title: "Sources & API keys",
    head: [el("span", { class: "chip", text: "stored on this Mac only" })],
    body: () => [
      el("p", { class: "note", style: "margin:0 0 12px", text: "Keys are saved in PyNIDS's data folder, readable only by the service. The dashboard can see whether a key is set, never the key itself." }),
      ...groups.map((s) => {
        const users = keyed.filter((x) => x.key === s.key).map((x) => x.label);
        const input = el("input", { type: "password", placeholder: s.configured ? "•••••••• (set — paste to replace)" : "paste API key", autocomplete: "off", "aria-label": s.key + " API key" });
        const save = async () => {
          try { await api("/api/soc/keys", { method: "POST", body: JSON.stringify({ name: s.key, value: input.value }) }); toast("Saved"); await loadSources(true); openSourcesDrawer(); if (SOC.ioc) openIoc(SOC.ioc, { fromTrail: true }); }
          catch (e) { toast(e.message); }
        };
        input.addEventListener("keydown", (e) => { if (e.key === "Enter") save(); });
        if (focus && keyed.find((x) => x.name === focus && x.key === s.key)) setTimeout(() => input.focus(), 50);
        return el("div", { class: "section" },
          el("h4", { text: users.join(" · ") }),
          el("div", { style: "display:flex;gap:8px;align-items:center" },
            s.configured ? el("span", { class: "ok-dot", text: "● key set" }) : el("span", { class: "no-dot", text: s.key_optional ? "○ optional" : "○ not set" })),
          el("p", { class: "note" }, ...linkify(s.key_help)),
          el("div", { class: "keyform" }, input, el("button", { class: "btn primary", onclick: save }, "Save"),
            s.configured ? el("button", { class: "btn danger", onclick: async () => {
              await api("/api/soc/keys/" + encodeURIComponent(s.key), { method: "DELETE" }); toast("Removed"); await loadSources(true); openSourcesDrawer(); } }, "Remove") : null));
      }),
    ],
  }, false);
}

addEventListener("keydown", (e) => {
  if (e.key === "/" && state.tab === "investigate" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
    e.preventDefault(); $("invInput").focus();
  }
});
