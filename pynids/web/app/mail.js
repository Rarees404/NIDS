/* Email analysis tab.  Loaded after soc.js; uses the dashboard helpers.
 *
 * Safety: message content is only ever inserted with textContent.  The one
 * exception is the optional HTML preview, which runs in a sandboxed iframe
 * (no scripts, no same-origin, no forms) under a CSP that blocks every
 * network request, so remote images and tracking pixels never load. */
"use strict";

const MAIL = { list: null, a: null, sub: "overview", raw: null, mark: null, find: "", wrap: false };
const SEV_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info" };
const HEADER_CAT = (() => {
  const m = {};
  for (const h of ["received", "return-path", "x-originating-ip", "x-sender-ip", "delivered-to", "x-received", "envelope-to", "x-forefront-antispam-report", "x-ms-exchange-organization-network-message-id"]) m[h] = "routing";
  for (const h of ["authentication-results", "arc-authentication-results", "arc-seal", "arc-message-signature", "dkim-signature", "received-spf", "x-google-dkim-signature", "domainkey-signature"]) m[h] = "auth";
  for (const h of ["from", "sender", "reply-to", "to", "cc", "bcc", "subject", "date", "message-id", "in-reply-to", "references", "x-mailer", "user-agent"]) m[h] = "identity";
  return m;
})();

async function mailApi(path, opts) { return api("/api/soc/email" + path, opts); }

// ---------------------------------------------------------------- shell
function mailRoot() {
  const root = $("tab-email");
  if (root.dataset.ready) return root;
  root.dataset.ready = "1";
  root.append(
    el("div", { class: "section-title" }, el("h1", { text: "Email analysis" }),
      el("span", { class: "sub", text: "Decode a suspicious email safely: every finding points to the exact raw lines." }),
      el("div", { class: "right" }, el("button", { class: "btn", onclick: () => mailHome() }, "All emails"))),
    el("div", { id: "mailMain" }));
  // Drop an .eml anywhere on the tab.
  root.addEventListener("dragover", (e) => { e.preventDefault(); const d = root.querySelector(".drop"); if (d) d.classList.add("over"); });
  root.addEventListener("dragleave", (e) => { if (e.target === root) { const d = root.querySelector(".drop"); if (d) d.classList.remove("over"); } });
  root.addEventListener("drop", (e) => { e.preventDefault(); const f = e.dataTransfer.files && e.dataTransfer.files[0]; if (f) uploadFile(f); });
  return root;
}

function mailShow(arg) {
  mailRoot();
  if (arg) openEmail(arg);
  else if (!MAIL.a) mailHome();
}

async function uploadBytes(body, name, source) {
  const main = $("mailMain");
  main.replaceChildren(el("div", { class: "card", style: "padding:24px;display:flex;gap:10px;align-items:center" }, el("span", { class: "spinner" }), "Parsing and analysing…"));
  try {
    const res = await fetch("/api/soc/email", { method: "POST", body,
      headers: { "X-PyNIDS-Token": TOKEN, "Content-Type": "message/rfc822", "X-Filename": encodeURIComponent(name || ""), "X-Source": source } });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    MAIL.list = null;
    go("email/" + data.sha256);
  } catch (e) { toast(e.message); mailHome(); }
}
function uploadFile(file) {
  if (file.size > 50 * 1024 * 1024) { toast("Larger than 50 MB"); return; }
  file.arrayBuffer().then((buf) => uploadBytes(buf, file.name, "file"));
}

// ---------------------------------------------------------------- home
async function mailHome() {
  MAIL.a = null; MAIL.raw = null;
  if (location.hash !== "#email") history.replaceState(null, "", "#email");
  const picker = el("input", { type: "file", accept: ".eml,.txt,message/rfc822", hidden: true, onchange: (e) => e.target.files[0] && uploadFile(e.target.files[0]) });
  const paste = el("textarea", { placeholder: "…or paste the raw message source here (headers included).\nThunderbird: More → View Source · Outlook: File → Properties → Internet headers · Gmail: ⋮ → Show original", spellcheck: "false" });
  const list = el("div", { class: "mlist" }, el("div", { class: "skeleton" }), el("div", { class: "skeleton" }));
  $("mailMain").replaceChildren(el("div", { class: "mail-home" },
    el("div", { class: "card" }, el("div", { class: "card-body", style: "padding-top:18px" },
      el("div", { class: "drop" },
        el("h3", { text: "Drop an .eml file here" }),
        el("p", { text: "The original is stored unchanged (read-only, named by its SHA-256). Nothing is opened, rendered or sent anywhere." }),
        picker, el("button", { class: "btn primary", onclick: () => picker.click() }, "Choose file…")),
      el("div", { class: "paste", style: "margin-top:14px" }, paste,
        el("div", { class: "actions", style: "margin-top:8px" },
          el("button", { class: "btn primary", onclick: () => {
            if (!paste.value.trim()) return;
            // CRLF is the wire format; pasted text has lost it, so say so instead of guessing.
            uploadBytes(new TextEncoder().encode(paste.value), "pasted.eml", "paste");
          } }, "Analyse pasted source"),
          el("span", { class: "muted", style: "font-size:12px", text: "Pasted text loses the original line endings and encoding; a saved .eml is better evidence." }))))),
    el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", { text: "Analysed emails" }), el("span", { class: "sub", text: "stored on this Mac" })),
      el("div", { class: "card-body" }, list))));
  try {
    MAIL.list = await mailApi("");
    list.replaceChildren(...(MAIL.list.length ? MAIL.list.map((m) => el("button", { onclick: () => go("email/" + m.sha256) },
      el("span", { class: "risk-dot" }, el("span", { class: "risk-pill " + m.risk, text: m.risk })),
      el("span", { class: "s", text: m.subject || "(no subject)" }),
      el("span", { class: "when", text: fmtAgo(m.added) }),
      el("span", { class: "f", text: (m.sender || "unknown sender") + " · " + (m.name || m.source) }))) : [emptyBox("No emails analysed yet.")]));
  } catch (e) { list.replaceChildren(emptyBox(e.message)); }
}

// ---------------------------------------------------------------- one email
async function openEmail(sha, sub) {
  const main = $("mailMain");
  if (!MAIL.a || MAIL.a.sha256 !== sha) {
    main.replaceChildren(el("div", { class: "card", style: "padding:24px" }, el("div", { class: "skeleton" }), el("div", { class: "skeleton", style: "width:50%" })));
    try { MAIL.a = await mailApi("/" + sha); } catch (e) { main.replaceChildren(emptyBox(e.message)); return; }
    MAIL.raw = null; MAIL.mark = null; MAIL.sub = "overview";
  }
  if (sub) MAIL.sub = sub;
  renderEmail();
}

function renderEmail() {
  const a = MAIL.a, s = a.summary;
  const tabs = [["overview", "Overview", a.findings.length], ["raw", "Raw source", a.line_count], ["headers", "Headers", a.structure.headers.length],
    ["body", "Body", a.bodies.length], ["links", "Links", a.links.length], ["attachments", "Attachments", a.attachments.length],
    ["structure", "Structure", null], ["iocs", "Indicators", a.iocs.length]];
  const panel = el("div", { class: "subpanel", id: "mailPanel" });
  $("mailMain").replaceChildren(
    el("div", { class: "card mhead" },
      el("div", {},
        el("h2", { class: "subj", text: s.subject || "(no subject)" }),
        el("div", { class: "who" }, el("b", { text: s.from || "(no From)" }), s.to ? "  →  " + s.to : ""),
        el("div", { class: "who", style: "margin-top:2px" }, s.date || ""),
        el("div", { class: "ids" },
          "SHA-256 ", el("code", { text: a.sha256 }), el("button", { class: "mini-btn", onclick: () => copyText(a.sha256, "SHA-256") }, "Copy"),
          el("span", { text: `${fmtBytes(a.size)} · ${a.line_count.toLocaleString()} lines` }),
          a.eol.bare_cr || (a.eol.crlf && a.eol.lf) ? el("span", { class: "chip flag", text: `mixed line endings (${a.eol.crlf} CRLF, ${a.eol.lf} LF, ${a.eol.bare_cr} bare CR)` }) : null,
          a.eol.nul ? el("span", { class: "chip flag bad", text: `${a.eol.nul} NUL bytes` }) : null)),
      el("div", { class: "side" },
        el("span", { class: "risk-pill " + a.risk, text: a.risk === "none" ? "No findings" : a.risk + " risk" }),
        el("div", { style: "font-size:12px;color:var(--ink-2)" }, ["high", "medium", "low"].filter((k) => a.counts[k]).map((k) => `${a.counts[k]} ${k}`).join(" · ") || "nothing notable"),
        el("div", { class: "actions" },
          el("button", { class: "btn", onclick: () => copyText(mailReport(), "report") }, "Copy report"),
          el("a", { class: "btn", href: `/api/soc/email/${a.sha256}/download?token=${TOKEN}`, title: "The original bytes, unchanged" }, icon("i-download"), "Original .eml"),
          el("button", { class: "btn danger", onclick: async () => {
            if (!confirm("Delete this email and its stored original?")) return;
            await mailApi("/" + a.sha256, { method: "DELETE" }); MAIL.a = null; mailHome(); } }, "Delete")))),
    el("div", { class: "subtabs", role: "tablist" }, tabs.map(([id, label, n]) => el("button", { role: "tab", "aria-selected": String(MAIL.sub === id),
      onclick: () => { MAIL.sub = id; renderEmail(); } }, label, n != null ? el("span", { class: "n", text: n }) : null))),
    panel);
  const render = { overview: renderOverview, raw: renderRaw, headers: renderHeaders, body: renderBodies, links: renderLinks,
    attachments: renderAttachments, structure: renderStructure, iocs: renderIocs }[MAIL.sub];
  render(panel);
}

function showLines(range, part) {
  if (!range) return;
  MAIL.mark = range; MAIL.sub = "raw"; renderEmail();
}
function linesBtn(range, label) {
  if (!range || range[1] < range[0]) return null;
  return el("button", { class: "mini-btn", title: "Show in raw source", onclick: () => showLines(range) },
    label || (range[0] === range[1] ? `line ${range[0]}` : `lines ${range[0]}–${range[1]}`));
}

// ---------------------------------------------------------------- overview
function renderOverview(panel) {
  const a = MAIL.a, v = a.auth.verdicts;
  const findings = a.findings.length ? el("div", { class: "findings" }, a.findings.map((f) => el("div", { class: "finding" },
    el("span", { class: "fsev " + f.severity, text: SEV_LABEL[f.severity] }),
    el("div", {}, el("div", { class: "t", text: f.title }), f.detail ? el("div", { class: "d", text: f.detail }) : null,
      el("div", { class: "cat", text: f.category + (f.part ? " · part " + f.part : "") })),
    linesBtn(f.lines) || el("span")))) : emptyBox("Nothing notable found. That isn't proof it's safe — check the links and sender.");
  const authPill = (k) => el("span", { class: "authpill " + (v[k] || "missing") }, el("small", { text: k }), v[k] || "not reported");
  const top = a.auth.results.find((r) => r.header === "Authentication-Results");
  panel.append(
    el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", { text: "Findings" }), el("span", { class: "sub", text: "observations, most severe first — each links to its evidence" })),
      el("div", { class: "card-body" }, findings)),
    el("div", { class: "grid row-2" },
      el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", { text: "Sender" })),
        el("div", { class: "card-body" }, kvList([
          ["From", a.summary.from], ["Reply-To", a.summary.reply_to], ["Return-Path", a.summary.return_path], ["Sender", a.summary.sender],
          ["Message-ID", a.summary.message_id], ["Mailer", a.summary.x_mailer], ["Originating IP", a.summary.x_originating_ip],
          ["First public hop", a.origin ? el("span", {}, iocChip("ipv4", a.origin.ip), a.origin.rdns ? "  " + a.origin.rdns : "", a.origin.helo ? `  (HELO ${a.origin.helo})` : "") : null],
        ]))),
      el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", { text: "Authentication" }),
          el("span", { class: "sub", text: top ? "as reported by " + top.authserv : "no Authentication-Results" }), el("div", { class: "right" }, top ? linesBtn(top.lines) : null)),
        el("div", { class: "card-body" },
          el("div", { class: "authrow" }, authPill("spf"), authPill("dkim"), authPill("dmarc")),
          a.auth.dkim.length ? table(["DKIM d=", "Selector", "Algorithm", "Aligned", ""], a.auth.dkim.map((d) => el("tr", {},
            el("td", { class: "mono", text: d.d || "" }), el("td", { class: "mono", text: d.s || "" }), el("td", { text: d.a || "" }),
            el("td", { text: d.aligned ? "yes" : "no" }), el("td", {}, linesBtn(d.lines, "raw")))), { cls: "minitable" }) : el("p", { class: "note", text: "No DKIM signature." }),
          el("p", { class: "note", text: "The top-most Authentication-Results was added by the receiving server; lower ones can be forged by the sender." })))),
    el("div", { class: "card mt" }, el("div", { class: "card-head" }, el("h2", { text: "Delivery path" }), el("span", { class: "sub", text: "Received headers, oldest first" })),
      el("div", { class: "card-body table-wrap" }, a.hops.length ? table(["#", "From (HELO · rDNS)", "IP", "By", "With", "Time (UTC)", "Delay", ""], a.hops.map((h) => el("tr", {},
        el("td", { text: h.n }), el("td", { class: "mono", style: "font-size:12px", text: [h.helo, h.rdns && h.rdns !== h.helo ? h.rdns : null].filter(Boolean).join(" · ") || "—" }),
        el("td", { class: "ipcell" }, h.ip ? (h.private ? el("span", { class: "muted", text: h.ip + " (private)" }) : iocChip(h.ip.includes(":") ? "ipv6" : "ipv4", h.ip)) : "—"),
        el("td", { class: "mono", style: "font-size:12px", text: (h.by || "").split(" ")[0] }), el("td", { text: (h.with || "").split(" ")[0] }),
        el("td", { text: h.ts ? new Date(h.ts * 1000).toISOString().replace("T", " ").slice(0, 19) : h.date || "—" }),
        el("td", { class: h.delay < 0 ? "neg" : "", text: h.delay == null ? "" : h.delay + " s" }),
        el("td", {}, linesBtn(h.lines, "raw")))), { cls: "hops" }) : emptyBox("No Received headers."))));
}

function iocChip(type, value) {
  return el("button", { class: "pivot", title: "Investigate " + value, onclick: () => investigate(value) }, value);
}

// ---------------------------------------------------------------- raw viewer
async function renderRaw(panel) {
  const a = MAIL.a;
  const src = el("div", { class: "raw-src" + (MAIL.wrap ? " wrap" : ""), id: "rawSrc" }, el("div", { style: "padding:16px" }, el("div", { class: "skeleton" })));
  const findBox = el("input", { type: "search", placeholder: "Find in source…", value: MAIL.find, "aria-label": "Find in raw source" });
  const count = el("span", { class: "muted", style: "font-size:12px" });
  findBox.addEventListener("input", () => { MAIL.find = findBox.value; highlightFind(src, count, true); });
  findBox.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); nextHit(src); } });
  panel.append(el("div", { class: "card" },
    el("div", { class: "rawbar" }, findBox, count,
      el("label", { class: "check" }, el("input", { type: "checkbox", checked: MAIL.wrap, onchange: (e) => { MAIL.wrap = e.target.checked; src.classList.toggle("wrap", MAIL.wrap); } }), "Wrap lines"),
      el("button", { class: "mini-btn", onclick: () => copyText(rawText(), "raw source") }, "Copy all"),
      el("span", { class: "leg legend" }, el("span", { class: "r", text: "routing" }), el("span", { class: "a", text: "authentication" }), el("span", { class: "i", text: "identity" }), el("span", { class: "m", text: "MIME" }))),
    el("div", { class: "rawwrap" }, rawNav(a), src),
    el("div", { class: "card-body", style: "padding-top:8px" }, el("p", { class: "note", text: "Exactly the stored bytes. Invisible characters are shown as ⟨RLO⟩, ⟨ZWSP⟩ …; bytes that aren't valid UTF-8 as \\xNN; control characters as \\x00, \\r. Long encoded attachments are folded — click to expand." }))));
  if (!MAIL.raw) {
    try { MAIL.raw = await mailApi(`/${a.sha256}/raw`); } catch (e) { src.replaceChildren(emptyBox(e.message)); return; }
  }
  paintRaw(src);
  highlightFind(src, count, false);
  if (MAIL.mark) {
    const t = src.querySelector(`[data-n="${MAIL.mark[0]}"]`);
    if (t) t.scrollIntoView({ block: "center" });
  }
}

function rawText() { return (MAIL.raw.lines || []).map((l) => typeof l === "string" ? l : `[… ${l.count} folded lines …]`).join("\n"); }

function lineClasses(a) {
  // line number → {cls, header category}; built from the parsed structure
  const map = new Map(), boundaries = new Set();
  const walk = (p) => {
    for (const h of p.headers) {
      const cat = HEADER_CAT[h.name.toLowerCase()] || (h.name.toLowerCase().startsWith("content-") || h.name.toLowerCase() === "mime-version" ? "mime" : "other");
      for (let n = h.lines[0]; n <= h.lines[1]; n++) map.set(n, n === h.lines[0] ? "h-" + cat : "h-cont h-" + cat);
    }
    if (p.params && p.params.boundary) boundaries.add(p.params.boundary);
    if (!p.multipart && !p.embedded && (p.cte === "base64" || p.cte === "x-uuencode")) {
      for (let n = p.body_lines[0]; n <= p.body_lines[1]; n++) if (!map.has(n)) map.set(n, "enc");
    }
    for (const r of [p.preamble_lines, p.epilogue_lines]) if (r) for (let n = r[0]; n <= r[1]; n++) map.set(n, "hidden-zone");
    (p.children || []).forEach(walk);
    if (p.embedded) walk(p.embedded);
  };
  walk(a.structure);
  return { map, boundaries };
}

const TOKEN_RE = /(https?:\/\/[^\s"'<>()]+)|((?:\d{1,3}\.){3}\d{1,3})|([\w.+-]+@[\w-]+(?:\.[\w-]+)+)|(⟨[A-Z]{2,4}⟩)|(\\x[0-9a-f]{2}|\\r)/gi;

function tokenize(text, plain) {
  if (plain || text.length > 4000) return [text];
  const out = []; let last = 0, m;
  TOKEN_RE.lastIndex = 0;
  while ((m = TOKEN_RE.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const v = m[0];
    if (m[4]) out.push(el("span", { class: "tok-inv", title: "invisible character", text: v }));
    else if (m[5]) out.push(el("span", { class: "tok-esc", title: "byte / control character", text: v }));
    else {
      const cls = m[1] ? "tok-url" : m[2] ? "tok-ip" : "tok-mail";
      const val = m[1] ? v.replace(/[.,;:]+$/, "") : v;
      out.push(el("span", { class: cls, title: "Investigate " + val, onclick: () => investigate(val) }, v));
    }
    last = m.index + v.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function paintRaw(src) {
  const a = MAIL.a, { map, boundaries } = lineClasses(a);
  const mark = MAIL.mark;
  const frag = document.createDocumentFragment();
  let n = MAIL.raw.start;
  for (const line of MAIL.raw.lines) {
    if (typeof line !== "string") {
      const [f0, f1] = line.fold;
      const btn = el("button", { onclick: async () => {
        btn.textContent = "Loading…";
        try {
          const r = await mailApi(`/${a.sha256}/raw?start=${f0}&end=${f1}`);
          const idx = MAIL.raw.lines.indexOf(line);
          MAIL.raw.lines.splice(idx, 1, ...r.lines);
          paintRaw(src);
        } catch (e) { toast(e.message); }
      } }, `▸ ${line.count.toLocaleString()} encoded lines folded (${f0}–${f1}) — expand`);
      frag.append(el("div", { class: "fold" }, el("span"), btn));
      n = f1 + 1;
      continue;
    }
    let cls = map.get(n) || "";
    const t = line.replace(/\s+$/, "");
    if (t.startsWith("--") && [...boundaries].some((b) => t === "--" + b || t === "--" + b + "--")) cls = "boundary";
    if (mark && n >= mark[0] && n <= mark[1]) cls += " mark";
    const tx = el("span", { class: "tx" });
    if (cls.includes("h-") && !cls.includes("h-cont")) {
      const i = line.indexOf(":");
      tx.append(el("span", { class: "h-name", text: line.slice(0, i + 1) }), ...tokenize(line.slice(i + 1), false));
    } else tx.append(...tokenize(line, cls.includes("enc")));
    const num = n;
    frag.append(el("div", { class: "ln " + cls, "data-n": n }, el("span", { class: "no", text: n, onclick: () => { MAIL.mark = [num, num]; src.querySelectorAll(".ln.mark").forEach((x) => x.classList.remove("mark")); src.querySelector(`[data-n="${num}"]`).classList.add("mark"); } }), tx));
    n++;
  }
  src.replaceChildren(frag);
}

function highlightFind(src, count, jump) {
  src.querySelectorAll(".ln.hit").forEach((x) => x.classList.remove("hit"));
  const q = MAIL.find.trim().toLowerCase();
  if (!q) { count.textContent = ""; return; }
  const hits = [...src.querySelectorAll(".ln")].filter((x) => x.querySelector(".tx").textContent.toLowerCase().includes(q));
  hits.forEach((x) => x.classList.add("hit"));
  count.textContent = hits.length ? `${hits.length} line${hits.length > 1 ? "s" : ""}` : "no match (folded blocks aren't searched)";
  src._hits = hits; src._hitIdx = -1;
  if (jump && hits.length) nextHit(src);
}
function nextHit(src) {
  if (!src._hits || !src._hits.length) return;
  src._hitIdx = (src._hitIdx + 1) % src._hits.length;
  src._hits[src._hitIdx].scrollIntoView({ block: "center" });
}

function rawNav(a) {
  const nav = el("nav", { class: "rawnav", "aria-label": "Jump to" });
  const jump = (range) => { MAIL.mark = range; const src = $("rawSrc"); src.querySelectorAll(".ln.mark").forEach((x) => x.classList.remove("mark"));
    for (let n = range[0]; n <= range[1]; n++) { const r = src.querySelector(`[data-n="${n}"]`); if (r) r.classList.add("mark"); }
    const t = src.querySelector(`[data-n="${range[0]}"]`); if (t) t.scrollIntoView({ block: "center" }); };
  nav.append(el("div", { class: "grp", text: "Headers" }));
  const seen = new Set();
  for (const h of a.structure.headers) {
    const k = h.name.toLowerCase();
    if (seen.has(k) && k !== "received") continue;
    seen.add(k);
    nav.append(el("button", { title: h.name, onclick: () => jump(h.lines) }, h.name));
  }
  nav.append(el("div", { class: "grp", text: "Parts" }));
  const walk = (p, depth) => {
    nav.append(el("button", { style: `padding-left:${6 + depth * 10}px`, title: p.content_type, onclick: () => jump(p.lines) },
      `${p.id} ${p.filename || p.content_type}`));
    (p.children || []).forEach((c) => walk(c, depth + 1));
    if (p.embedded) walk(p.embedded, depth + 1);
  };
  walk(a.structure, 0);
  return nav;
}

// ---------------------------------------------------------------- headers
function renderHeaders(panel) {
  const all = [];
  const walk = (p) => { for (const h of p.headers) all.push([p.id, h]); (p.children || []).forEach(walk); if (p.embedded) walk(p.embedded); };
  walk(MAIL.a.structure);
  const top = all.filter(([pid]) => pid === "1"), inner = all.filter(([pid]) => pid !== "1");
  const rows = (list) => list.map(([pid, h]) => el("tr", {},
    el("td", { class: "n", text: h.name }),
    el("td", { class: "v" }, ...tokenize(h.value, false), h.decoded !== h.value ? el("span", { class: "dec", text: "decoded: " + h.decoded }) : null,
      h.encodings.length ? el("span", { class: "dec", style: "color:var(--muted)", text: "encoded words: " + h.encodings.join(", ") }) : null),
    el("td", {}, pid !== "1" ? el("span", { class: "muted", style: "font-size:11.5px", text: "part " + pid + " " }) : null, linesBtn(h.lines))));
  panel.append(el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", { text: "Message headers" }), el("span", { class: "sub", text: "in original order; folded lines joined" })),
    el("div", { class: "card-body table-wrap" }, table(["Name", "Value", ""], rows(top), { cls: "hdrs" }))),
    inner.length ? el("div", { class: "card mt" }, el("div", { class: "card-head" }, el("h2", { text: "MIME part headers" })),
      el("div", { class: "card-body table-wrap" }, table(["Name", "Value", ""], rows(inner), { cls: "hdrs" }))) : "");
}

// ---------------------------------------------------------------- bodies
function renderBodies(panel) {
  const a = MAIL.a;
  if (!a.bodies.length) { panel.append(el("div", { class: "card" }, emptyBox("No text body."))); return; }
  for (const b of a.bodies) {
    const box = el("div", { class: "card-body bodyview" }, el("div", { class: "skeleton" }));
    const card = el("div", { class: "card", style: "margin-bottom:16px" },
      el("div", { class: "card-head" }, el("h2", { text: `Part ${b.part} · ${b.content_type}` }),
        el("span", { class: "sub", text: [b.charset, b.length.toLocaleString() + " characters"].filter(Boolean).join(" · ") }),
        el("div", { class: "right" }, linesBtn(b.lines, "raw"))),
      b.content_type === "text/html" ? el("div", { class: "card-body", style: "padding-bottom:0" }, kvList([
        ["Forms", (b.forms || []).map((f) => f.action || "(no action)").join(", ")], ["Scripts", b.scripts || null],
        ["Hidden elements", b.hidden_elements || null], ["Tracking pixels", b.tracking_pixels || null], ["Embedded frames", b.iframes || null],
        ["Meta refresh", (b.meta_refresh || []).join("; ")]])) : null,
      box);
    panel.append(card);
    mailApi(`/${a.sha256}/part/${encodeURIComponent(b.part)}`).then((p) => {
      const pre = el("pre", {}, ...tokenize(p.text || "", (p.text || "").length > 200000));
      if (b.content_type !== "text/html") { box.replaceChildren(pre); return; }
      const holder = el("div");
      const showSource = () => holder.replaceChildren(pre);
      const showRender = () => {
        const csp = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:; form-action 'none'; base-uri 'none'";
        const frame = el("iframe", { class: "sandbox-frame", sandbox: "", referrerpolicy: "no-referrer", title: "Sandboxed preview" });
        frame.srcdoc = `<meta http-equiv="Content-Security-Policy" content="${csp}"><style>a,area{pointer-events:none!important;cursor:not-allowed}</style>` + p.source;
        holder.replaceChildren(el("div", { class: "warnbox", text: "Sandboxed preview: scripts, forms, links and every remote image are blocked, so the sender can't tell it was opened. Layout may look broken without the images." }), frame);
      };
      box.replaceChildren(el("div", { class: "seg", style: "margin-bottom:10px" },
        el("button", { "aria-pressed": "true", onclick: (e) => { setSeg(e); showSource(); } }, "Source"),
        el("button", { "aria-pressed": "false", onclick: (e) => { setSeg(e); showRender(); } }, "Render safely")), holder);
      showSource();
    }).catch((e) => box.replaceChildren(emptyBox(e.message)));
  }
}
function setSeg(e) { e.target.parentElement.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === e.target))); }

// ---------------------------------------------------------------- links
const FLAG_TEXT = { "text-mismatch": "text ≠ target", userinfo: "user@host trick", "ip-literal": "bare IP", shortener: "shortener",
  "free-hosting": "free hosting", punycode: "punycode", unwrapped: "unwrapped" };
function renderLinks(panel) {
  const links = MAIL.a.links;
  panel.append(el("div", { class: "card" },
    el("div", { class: "card-head" }, el("h2", { text: `${links.length} links` }), el("span", { class: "sub", text: "from every part: text, HTML attributes, CSS, PDFs, HTML attachments" }),
      el("div", { class: "right" }, links.length ? el("button", { class: "mini-btn", onclick: () => copyText(links.map((l) => l.defanged).join("\n"), "defanged links") }, "Copy defanged") : null,
        links.length ? el("button", { class: "mini-btn", onclick: () => investigateMany(links.map((l) => l.url)) }, "Investigate all") : null)),
    el("div", { class: "card-body table-wrap" }, links.length ? table(["Link (defanged)", "Flags", "Where", ""], links.map((l) => el("tr", { class: "linkrow" },
      el("td", { class: "u" }, l.defanged,
        l.texts.length ? el("small", { text: "shown as: " + l.texts.join(" | ") }) : null,
        l.wrapped ? el("small", { text: `unwrapped from ${l.wrapper}: ${l.wrapped.slice(0, 120)}…` }) : null),
      el("td", {}, el("div", { class: "chips" }, l.flags.map((f) => el("span", { class: "chip" + (["text-mismatch", "userinfo", "ip-literal", "punycode"].includes(f) || f.startsWith("lookalike") ? " flag bad" : f === "unwrapped" ? "" : " flag"),
        text: f.startsWith("lookalike:") ? "imitates " + f.slice(10) : FLAG_TEXT[f] || f })))),
      el("td", { class: "muted", style: "font-size:12px", text: l.contexts.join(", ") + " · part " + l.parts.join(", ") }),
      el("td", { class: "num" }, el("button", { class: "mini-btn", onclick: () => copyText(l.url, "link") }, "Copy"), " ",
        el("button", { class: "btn", onclick: () => investigate(l.url) }, "Investigate"))))) : emptyBox("No links."))));
}

function investigateMany(values) {
  go("investigate");
  socRoot();
  const text = values.join("\n");
  $("invInput").value = text;
  socRun(text);
}

// ---------------------------------------------------------------- attachments
function renderAttachments(panel) {
  const a = MAIL.a;
  if (!a.attachments.length) { panel.append(el("div", { class: "card" }, emptyBox("No attachments."))); return; }
  for (const att of a.attachments) {
    const t = att.triage, fs = a.findings.filter((f) => f.part === att.part && f.category === "attachment");
    const extra = el("div");
    const showHex = async () => { const r = await mailApi(`/${a.sha256}/part/${encodeURIComponent(att.part)}?view=hex`); extra.replaceChildren(el("div", { class: "hexview", text: r.hex + (r.truncated ? "\n… (first 64 KB)" : "") })); };
    const showStrings = async () => { const r = await mailApi(`/${a.sha256}/part/${encodeURIComponent(att.part)}?view=strings`); extra.replaceChildren(el("div", { class: "hexview", text: r.strings.join("\n") })); };
    panel.append(el("div", { class: "card attcard", style: "margin-bottom:16px" },
      el("div", { style: "display:flex;gap:12px;align-items:flex-start;flex-wrap:wrap" },
        el("div", { style: "flex:1;min-width:0" }, el("h3", { text: att.filename || "(no file name)" }),
          el("div", { class: "meta", text: `part ${att.part} · declared ${att.content_type} · detected: ${t.detected || "unknown"} · ${fmtBytes(att.size)} · entropy ${t.entropy}` })),
        linesBtn(att.lines, "raw")),
      fs.length ? el("div", { class: "findings", style: "margin-top:12px" }, fs.map((f) => el("div", { class: "finding" }, el("span", { class: "fsev " + f.severity, text: SEV_LABEL[f.severity] }),
        el("div", {}, el("div", { class: "t", text: f.title }), f.detail ? el("div", { class: "d", text: f.detail }) : null), el("span")))) : null,
      el("div", { class: "hashes" }, ["md5", "sha1", "sha256"].map((h) => [el("span", { class: "muted", text: h.toUpperCase() }), el("code", { text: att.hashes[h] }),
        el("span", {}, el("button", { class: "mini-btn", onclick: () => copyText(att.hashes[h], h) }, "Copy"), " ", el("button", { class: "mini-btn", onclick: () => investigate(att.hashes[h]) }, "Investigate"))]).flat()),
      t.archive ? el("div", { class: "section" }, el("h4", { text: `Archive contents (${t.archive.length})` }), table(["Name", "Size", "Encrypted"], t.archive.map((x) =>
        el("tr", {}, el("td", { class: "mono", text: x.name }), el("td", { class: "num", text: fmtBytes(x.size) }), el("td", { text: x.encrypted ? "yes" : "" }))), { cls: "minitable" })) : null,
      t.pdf_keywords && Object.keys(t.pdf_keywords).length ? el("div", { class: "section" }, el("h4", { text: "PDF keywords" }),
        el("div", { class: "chips" }, Object.entries(t.pdf_keywords).map(([k, n]) => el("span", { class: "chip", text: `${k} ×${n}` })))) : null,
      el("div", { class: "actions" },
        el("button", { class: "btn", onclick: showHex }, "Hex"), el("button", { class: "btn", onclick: showStrings }, "Strings"),
        el("a", { class: "btn danger", href: `/api/soc/email/${a.sha256}/part/${encodeURIComponent(att.part)}?view=download&token=${TOKEN}`,
          onclick: (e) => { if (!confirm("Download the decoded attachment as a .bin file? It may be malware — don't open it outside an isolated analysis machine.")) e.preventDefault(); } },
          icon("i-download"), "Download .bin")),
      extra));
  }
}

// ---------------------------------------------------------------- structure & indicators
function renderStructure(panel) {
  const rows = [];
  const walk = (p, depth) => {
    rows.push(el("tr", { class: "clickable", onclick: () => showLines(p.lines) },
      el("td", { class: "mono", style: `padding-left:${10 + depth * 18}px`, text: p.id }),
      el("td", { class: "mono", text: p.content_type + (p.filename ? "  · " + p.filename : "") }),
      el("td", { text: p.multipart ? "" : p.cte }), el("td", { text: p.charset || "" }),
      el("td", { class: "num", text: fmtBytes(p.raw_size) }), el("td", { class: "num", text: p.multipart ? "" : fmtBytes(p.decoded_size) }),
      el("td", { class: "muted", style: "font-size:12px", text: `${p.lines[0]}–${p.lines[1]}` }),
      el("td", { style: "font-size:12px;color:var(--critical)", text: p.warnings.join("; ") })));
    (p.children || []).forEach((c) => walk(c, depth + 1));
    if (p.embedded) walk(p.embedded, depth + 1);
  };
  walk(MAIL.a.structure, 0);
  panel.append(el("div", { class: "card" }, el("div", { class: "card-head" }, el("h2", { text: "MIME structure" }), el("span", { class: "sub", text: "click a part to see its raw lines" })),
    el("div", { class: "card-body table-wrap" }, table(["Part", "Type", "Encoding", "Charset", "Raw", "Decoded", "Lines", "Warnings"], rows))));
}

function renderIocs(panel) {
  const iocs = MAIL.a.iocs;
  panel.append(el("div", { class: "card" },
    el("div", { class: "card-head" }, el("h2", { text: `${iocs.length} indicators` }), el("span", { class: "sub", text: "and where each was found" }),
      el("div", { class: "right" },
        el("button", { class: "mini-btn", onclick: () => copyText(iocs.map((i) => i.defanged).join("\n"), "defanged indicators") }, "Copy defanged"),
        el("button", { class: "mini-btn", onclick: () => investigateMany(iocs.map((i) => i.value)) }, "Investigate all"))),
    el("div", { class: "card-body table-wrap" }, table(["Type", "Indicator", "Found in", ""], iocs.map((i) => el("tr", {},
      el("td", {}, el("span", { class: "type-chip", text: (TYPE_LABEL[i.type] || i.type) })),
      el("td", { class: "mono", style: "overflow-wrap:anywhere", text: i.value }),
      el("td", { class: "muted", style: "font-size:12px", text: i.where.join(", ") }),
      el("td", { class: "num" }, el("button", { class: "btn", onclick: () => investigate(i.value) }, "Investigate")))), { cls: "ioc-list" }))));
}

// ---------------------------------------------------------------- report
function mailReport() {
  const a = MAIL.a, s = a.summary;
  const d = (x) => String(x || "").replace(/https?:\/\//gi, (m) => m.replace(/^http/i, "hxxp")).replace(/(\w)\.(\w)/g, "$1[.]$2").replace(/@/g, "[@]");
  const out = [`## Email analysis — ${s.subject || "(no subject)"}`, "",
    `- **From:** ${d(s.from)}`, `- **To:** ${d(s.to)}`, `- **Date:** ${s.date}`, `- **Reply-To:** ${d(s.reply_to) || "—"}`, `- **Return-Path:** ${d(s.return_path) || "—"}`,
    `- **SHA-256 (original .eml):** ${a.sha256}`, `- **Risk:** ${a.risk} (${["high", "medium", "low"].map((k) => `${a.counts[k]} ${k}`).join(", ")})`,
    `- **SPF / DKIM / DMARC:** ${a.auth.verdicts.spf || "—"} / ${a.auth.verdicts.dkim || "—"} / ${a.auth.verdicts.dmarc || "—"}`,
    a.origin ? `- **First public hop:** ${d(a.origin.ip)} ${d(a.origin.rdns || "")}` : "", "", "### Findings"];
  for (const f of a.findings.filter((f) => f.severity !== "info")) out.push(`- **${SEV_LABEL[f.severity]}** — ${d(f.title)}${f.detail ? ": " + d(f.detail) : ""}${f.lines ? ` (raw lines ${f.lines[0]}–${f.lines[1]})` : ""}`);
  if (a.links.length) { out.push("", "### Links"); for (const l of a.links.slice(0, 50)) out.push(`- ${l.defanged}${l.flags.length ? " [" + l.flags.join(", ") + "]" : ""}`); }
  if (a.attachments.length) { out.push("", "### Attachments"); for (const x of a.attachments) out.push(`- ${d(x.filename) || "(unnamed)"} — ${x.triage.detected || x.content_type}, ${x.size} bytes, SHA-256 ${x.hashes.sha256}`); }
  return out.filter((l) => l !== null).join("\n");
}
