// Frontend logic. It only talks to the backend through /api/... (see backend/api.py).
// Everything is drawn with textContent / createElement, never innerHTML: alert text comes from the
// network and can be written by an attacker, so it must never be treated as HTML.
const $ = id => document.getElementById(id);
const root = document.documentElement;

// ---------- helpers ----------
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e[k] = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
   kids.flat(Infinity).forEach(c => e.append(c instanceof Node ? c : document.createTextNode(c == null ? "" : String(c))));
  return e;
}
const td = (...kids) => h("td", {}, ...kids);
// Wazuh stores IPv6 in the long form (fe80:0000:0000:...). Show the short form; filters still use the stored text.
const showIp = ip => { if (!String(ip).includes(":")) return ip; try { return new URL("http://[" + ip + "]/").hostname.slice(1, -1); } catch (e) { return ip; } };
const RANGE_TEXT = { "1h": "in the last hour", "24h": "in the last 24 hours", "7d": "in the last 7 days", "30d": "in the last 30 days", all: "all time" };
const badge = (cls, text) => h("span", { class: "badge " + cls }, text);
const SEV = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
function remember(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
function recall(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function showError(msg) { $("err").hidden = !msg; $("err").textContent = msg || ""; }
function empty(tbody, cols, text) { tbody.append(h("tr", {}, h("td", { colspan: cols, class: "mute" }, text))); }

async function api(path, options = {}) {
  const res = await fetch("/api" + path, {
    credentials: "same-origin", ...options,
    headers: { "X-Requested-With": "mini-soc", ...(options.body ? { "Content-Type": "application/json" } : {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { location.href = "/login.html"; throw new Error("Login required"); }
  if (!res.ok) throw new Error(data.error || res.status);
  return data;
}
const send = (method, path, body) => api(path, { method, body: JSON.stringify(body || {}) });

// ---------- state ----------
let rows = [], selected = null, blocked = new Set(), arMode = "dry-run";
let detailNote = "";  // the message under the alert details (kept when the screen refreshes)
let me = { email: "", role: "viewer", must_change: false };
const RANK = { viewer: 1, analyst: 2, admin: 3 }, can = role => RANK[me.role] >= RANK[role];  // the server checks too

// ---------- theme, colour, sign out ----------
if (recall("theme")) root.dataset.theme = recall("theme");
$("theme").onclick = () => { root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light"; remember("theme", root.dataset.theme); };
$("logout").onclick = async () => { try { await send("POST", "/logout"); } finally { location.href = "/login.html"; } };

// ---------- tabs ----------
const loaders = { dashboard: () => loadDashboard(true), events: () => loadDashboard(true), incidents: () => loadIncidents(), blocklist: () => loadBlocklist(),
  agents: () => fetchAgents(), soon: () => {}, audit: () => loadAudit(), users: () => loadUsers(), account: () => loadAccount() };
let view = "dashboard";
const go = name => document.querySelector('.nv[data-view="' + name + '"]').click();
document.querySelectorAll(".nv").forEach(t => t.onclick = () => {
  if (me.must_change && t.dataset.view !== "account") return;  // a new password comes first
  view = t.dataset.view;
  document.querySelectorAll(".nv").forEach(x => x.classList.toggle("on", x === t));
  Object.keys(loaders).forEach(v => $(v).hidden = v !== view);
  if (view === "soon") $("soon-title").textContent = (t.childNodes[1] || t).textContent.trim();
  showError("");
  loaders[view]();
});
$("viewall").onclick = e => { e.preventDefault(); go("events"); };
$("viewag").onclick = e => { e.preventDefault(); go("agents"); };
$("search").onkeydown = e => { if (e.key === "Enter") { $("q").value = e.target.value.trim(); go("events"); } };

// ---------- dashboard panels ----------
function filterQuery() {
  const p = new URLSearchParams();
  if ($("q").value.trim()) p.set("q", $("q").value.trim());
  if ($("level").value) p.set("level", $("level").value);
  p.set("range", $("range").value);
  if ($("scan").checked) p.set("scan", "1");
  if ($("noipv6").checked) p.set("noipv6", "1");
  return p.toString();
}

const SVGNS = "http://www.w3.org/2000/svg";
function S(tag, attrs) { const e = document.createElementNS(SVGNS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; }
const sum = a => a.reduce((x, y) => x + y, 0);

function spark(vals, color) {
  const svg = S("svg", { viewBox: "0 0 100 28", preserveAspectRatio: "none" }), top = Math.max(1, ...vals);
  const pts = vals.map((v, i) => (i * 100 / Math.max(vals.length - 1, 1)).toFixed(1) + "," + (26 - 24 * v / top).toFixed(1)).join(" ");
  svg.append(S("polyline", { points: pts, fill: "none", stroke: `var(${color})`, "stroke-width": 1.6, "vector-effect": "non-scaling-stroke" }));
  return svg;
}
function drawKpis(d) {
  $("total2").textContent = d.total;
  const all = d.history_all && d.history_all.length ? d.history_all : d.history;
  const series = { total: all.map(x => x.count), suricata: d.history.map(x => x.count), scans: d.history.map(x => x.scans || 0) };  // hourly points: the last 24 are the last 24 hours
  [["total", "d-total", "sp-total", "--bl"], ["suricata", "d-total2", "sp-total2", "--rd"], ["scans", "d-scans", "sp-scans", "--or"]].forEach(([k, dl, sp, col]) => {
    const c = series[k], before = sum(c.slice(-48, -24)), pct = before ? Math.round((sum(c.slice(-24)) - before) / before * 100) : null, el = $(dl);
    el.textContent = pct === null ? "" : (pct > 0 ? "\u25B2 " : pct < 0 ? "\u25BC " : "") + Math.abs(pct) + "%";
    el.className = "dl " + (pct > 0 ? "inc" : "dec");
    $(sp).textContent = ""; if (c.length > 1) $(sp).append(spark(c.slice(-24), col));
  });
}
let lastHist = [], lastAll = [], lastD = null, ipKind = "top_ips";
function drawChart(hist, all) {
  lastHist = hist; lastAll = all || [];
  // Total = every Wazuh alert that hour, Suricata = only Suricata, Other = the difference (auth, rootcheck ...)
  const byLabel = {}; lastAll.forEach(x => { byLabel[x.label] = x.count; });
  const total = x => (x.label in byLabel ? byLabel[x.label] : x.count);
  const hours = +$("crange").value, pts = hist.slice(-hours), n = Math.max(pts.length, 2), svg = $("ch"), w = 560, hh = 200, L = 36, B = 22;
  svg.textContent = ""; svg.setAttribute("viewBox", `0 0 ${w} ${hh}`); $("lg").textContent = "";
  const series = [["Total", "--bl", total], ["Suricata", "--rd", x => x.count], ["Port scan", "--or", x => x.scans || 0], ["Other", "--pu", x => Math.max(0, total(x) - x.count)]];
  series.forEach(([name, col]) => $("lg").append(h("span", {}, h("i", { class: "sw", style: `background:var(${col})` }), name)));
  if (!pts.length) return;
  const top = Math.max(10, Math.ceil(Math.max(...pts.map(total)) / 10) * 10);
  const X = i => L + i * (w - L - 6) / (n - 1), Y = v => hh - B - (hh - B - 8) * v / top;
  [0, .25, .5, .75, 1].forEach(f => {
    const v = Math.round(top * f), t = S("text", { x: 0, y: Y(v) + 3, class: "lb" }); t.textContent = v;
    svg.append(S("line", { x1: L, x2: w, y1: Y(v), y2: Y(v), class: "gl" }), t);
  });
  const step = hours <= 24 ? 4 : 24;  // a label every 4 hours, or every day
  pts.forEach((x, i) => { if (i % step === 0) { const t = S("text", { x: X(i) - 8, y: hh - 6, class: "lb" }); t.textContent = hours <= 24 ? x.label.slice(6) : x.label.slice(0, 5); svg.append(t); } });
  series.forEach(([name, col, f], k) => {
    const line = pts.map((x, i) => X(i).toFixed(1) + "," + Y(f(x)).toFixed(1)).join(" ");
    if (k === 0) svg.append(S("polygon", { points: `${L},${Y(0)} ${line} ${X(pts.length - 1)},${Y(0)}`, fill: "var(--bl)", opacity: ".15" }));
    svg.append(S("polyline", { points: line, fill: "none", stroke: `var(${col})`, "stroke-width": 2, "stroke-linejoin": "round" }));
  });
}
$("crange").onchange = () => drawChart(lastHist, lastAll);
function drawSeverity(sev) {
  const svg = $("dn"), R = 58, C = 2 * Math.PI * R, total = sum(Object.values(sev));
  let off = 0; svg.textContent = ""; $("dl").textContent = "";
  svg.append(S("circle", { cx: 80, cy: 80, r: R, fill: "none", stroke: "var(--bd)", "stroke-width": 18 }));
  [["critical", "--rd"], ["high", "--or"], ["medium", "--yl"], ["low", "--bl"]].forEach(([k, col]) => {
    const n = sev[k], len = total ? C * n / total : 0;
    svg.append(S("circle", { cx: 80, cy: 80, r: R, fill: "none", stroke: `var(${col})`, "stroke-width": 18, "stroke-dasharray": `${len} ${C - len}`, "stroke-dashoffset": -off, transform: "rotate(-90 80 80)" }));
    off += len;
    $("dl").append(h("div", { class: "row2" }, h("span", {}, h("i", { class: "sw", style: `background:var(${col})` }), SEV[k]), h("span", {}, n + " (" + (total ? (n / total * 100).toFixed(1) : "0.0") + "%)")));
  });
  const big = S("text", { x: 80, y: 82, "text-anchor": "middle", style: "font-size:22px;font-weight:700;fill:var(--tx)" }); big.textContent = total;
  const small = S("text", { x: 80, y: 98, "text-anchor": "middle", style: "font-size:10px;fill:var(--mu)" }); small.textContent = "Total alerts";
  svg.append(big, small);
}
const BARCOL = ["--rd", "--or", "--yl", "--bl", "--pu"];
function bars(id, list, emptyText) {
  const box = $(id); box.textContent = "";
  if (!list.length) { box.append(h("p", { class: "mute" }, emptyText)); return; }
  list.slice(0, 7).forEach((t, i) => {
    const fill = h("i"); fill.style.width = (t.count / list[0].count * 100) + "%"; fill.style.background = `var(${BARCOL[Math.min(i, 4)]})`;
    box.append(h("div", { class: "bar" }, h("b", { title: t.name }, t.name), h("span", {}, fill), h("em", {}, t.count)));
  });
}
function drawIps() {
  const list = (lastD && lastD[ipKind]) || [], tb = $("ip"); tb.textContent = "";
  list.forEach(({ ip, count }, i) => {
    const mark = ipKind === "top_ips" && blocked.has(ip) ? h("span", { class: "blockedmark" }, "blocked") : null;
    const tr = h("tr", { "data-id": ip, tabindex: 0 }, td(i + 1), td(showIp(ip), mark), td(count));
    const pick = () => { $("q").value = ip; go("events"); };
    tr.onclick = pick; tr.onkeydown = e => { if (e.key === "Enter") pick(); };
    tb.append(tr);
  });
  if (!list.length) empty(tb, 3, "No data yet");
}
document.querySelectorAll("#iptabs button").forEach(b => b.onclick = () => {
  ipKind = b.dataset.k;
  document.querySelectorAll("#iptabs button").forEach(x => x.classList.toggle("on", x === b));
  drawIps();
});
$("go").onclick = () => { $("aim").textContent = "Not connected yet: this needs an AI key."; };
function drawRecent(list) {
  const tb = $("ev"); tb.textContent = "";
  list.slice(0, 5).forEach(r => {
    const link = h("a", { href: "#" }, "[View]");
    link.onclick = e => { e.preventDefault(); selected = r; go("events"); };
    tb.append(h("tr", {}, td(r.time.slice(11)), td(badge(r.sev, SEV[r.sev])), td(r.msg), td(showIp(r.src)), td(r.agent || "-"), td(link)));
  });
  if (!list.length) empty(tb, 6, "No alerts yet.");
}
function drawStatus(ok, d, netFail) {
  const set = (id, text, cls) => { $(id).textContent = text; $(id).className = cls; };
  $("wz").textContent = ok ? "Wazuh Connected" : "Wazuh unreachable"; $("wzdot").classList.toggle("off", !ok);
  set("s-idx", ok ? "Online" : "Offline", ok ? "good" : "bad");
  set("s-api", netFail ? "Offline" : "Healthy", netFail ? "bad" : "good");
  if (!ok) { set("s-sur", "Unknown", "idle"); return; }  // without Wazuh we cannot know
  lastOkAt = Date.now();
  $("sync").textContent = "Last sync: " + new Date().toLocaleTimeString();
  const recent = sum(d.history.slice(-2).map(x => x.count)) > 0;  // any alert in the last 3 to 6 hours
  set("s-sur", recent ? "Active" : "Quiet", recent ? "good" : "idle");
}
// If Wazuh stops answering (no error yet, the request is just stuck), do not keep saying "Connected".
let lastOkAt = 0;
setInterval(() => {
  const every = +$("every").value;
     if (every && lastOkAt && (view === "dashboard" || view === "events") && Date.now() - lastOkAt > Math.max(15000, every * 3) && !$("wzdot").classList.contains("off")) {
    $("wz").textContent = "No fresh data"; $("wzdot").classList.add("off");
  }
}, 1000);
function drawDash(d) {
  $("u-vs").textContent = RANGE_TEXT[$("range").value] || "";
  lastD = d; drawKpis(d); drawChart(d.history, d.history_all); drawSeverity(d.severity); drawIps(); drawRecent(d.rows);
  bars("tac", d.tactics, "No MITRE-mapped alerts yet. Add a <mitre> tag to your custom Wazuh rules and they appear here.");
  bars("cat", d.categories, "No alerts in this time range.");
}

// ---------- agents (read from the Wazuh Manager) ----------
let agents = null, agentsErr = "", agentsNotSet = false;
function ago(iso) {
  const t = Date.parse(iso);
  if (!t || t > Date.now() + 3.15e10) return "-";
  const m = Math.round((Date.now() - t) / 60000);
  return m < 1 ? "just now" : m < 60 ? m + " min ago" : m < 1440 ? Math.round(m / 60) + " h ago" : Math.round(m / 1440) + " d ago";
}
const AGENT_STATE = { active: ["Online", "good"], disconnected: ["Offline", "bad"], never_connected: ["Never connected", "idle"], pending: ["Pending", "idle"] };
async function fetchAgents() {
  try {
    const d = await api("/agents");
    agents = d.items; agentsErr = d.message || ""; agentsNotSet = d.items === null;
  } catch (e) { if (e.message === "Login required") return; agents = null; agentsErr = e.message; agentsNotSet = false; }
  drawAgents();
}
function drawAgents() {
  const ok = agents !== null, online = ok ? agents.filter(a => a.status === "active").length : 0;
  $("k-agents").textContent = ok ? online + " / " + agents.length : "-";
  $("d-agents").textContent = ok ? (agents.length - online) + " offline" : "";
  $("s-mgr").textContent = ok ? "Online" : agentsNotSet ? "Not set" : "Not connected"; $("s-mgr").className = ok ? "good" : "idle";
  $("agmsg").textContent = $("agmsg2").textContent = ok ? (agents.length ? "" : "No agents are registered yet.") : agentsErr;
  const state = a => { const [text, cls] = AGENT_STATE[a.status] || [a.status, "idle"]; return h("span", { class: cls }, "\u25CF " + text); };
  $("ag").textContent = ""; $("ag-rows").textContent = "";
  (ok ? agents : []).forEach((a, i) => {
    if (i < 5) $("ag").append(h("tr", {}, td(a.id), td(a.name), td(state(a)), td(ago(a.last_seen))));
    $("ag-rows").append(h("tr", {}, td(a.id), td(a.name), td(a.ip), td(state(a)), td(ago(a.last_seen))));
  });
}

function drawRows() {
  const tb = $("rows"); tb.textContent = "";
  rows.forEach(r => {
    const tr = h("tr", { "data-id": r.id, tabindex: 0, class: (r.msg.includes("Port Scan") ? "scanrow " : "") + (selected && selected.id === r.id ? "sel" : "") },
      td(r.time), td(badge(r.sev, SEV[r.sev] + " (" + r.level + ")")), td(showIp(r.src), r.blocked ? h("span", { class: "blockedmark" }, "blocked") : ""), td(showIp(r.dst)), td(r.msg));
    tr.onclick = () => select(r);
    tr.onkeydown = e => { if (e.key === "Enter") select(r); };
    tb.append(tr);
  });
  if (!rows.length) empty(tb, 5, "No alerts match these filters.");
}

function select(r) {
  selected = r; detailNote = "";
  document.querySelectorAll("#rows tr").forEach(tr => tr.classList.toggle("sel", tr.dataset.id === r.id));
  drawDetail();
}

function drawDetail(note) {
  if (note !== undefined) detailNote = note;
  const box = $("detail"), r = selected;
  box.textContent = "";
  box.append(h("h2", {}, "Alert details"));
  if (!r) { box.append(h("p", { class: "mute" }, "Select an alert to see details and take action.")); return; }
  const isBlocked = blocked.has(r.src);
  const kv = [["Time (UTC)", r.time], ["Attacker", showIp(r.src)], ["Target", showIp(r.dst) + (r.port ? ":" + r.port : "") + (r.proto ? " (" + r.proto + ")" : "")],
    ["Rule", r.rule_id], ["Signature", r.signature || "-"], ["Agent", r.agent || "-"],
    ["MITRE", [...r.mitre_ids, ...r.tactics].join(", ") || "not mapped"]];
  box.append(badge(r.sev, SEV[r.sev] + " (level " + r.level + ")"), h("h3", {}, r.msg),
    h("dl", { class: "kv" }, kv.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])));
  const status = h("p", { class: "mute", role: "status" }, detailNote);
  box.append(h("div", { class: "actions" },
    can("analyst") ? h("button", { class: "primary", onclick: () => createIncident(r) }, "Create incident") : null,
    can("admin") ? h("button", { class: "danger", disabled: isBlocked, onclick: () => blockFromAlert(r) }, isBlocked ? "Already blocked" : "Block attacker IP") : null,
    h("button", { onclick: () => { $("q").value = r.src; loadDashboard(true); } }, "All alerts from this IP")), status);
}

async function createIncident(r) {
  try {
    const d = await send("POST", "/incidents", r);
    drawDetail(d.created ? "Incident #" + d.id + " created." : "Already tracked in incident #" + d.id + ": its alert count went up.");
    loadDashboard(true);
  } catch (e) { showError(e.message); }
}

async function blockFromAlert(r) {
  const how = arMode === "live" ? "LIVE: this changes the firewall on the target machine." : "Dry run: only recorded, no firewall change.";
  if (!confirm("Block " + r.src + "?\n\n" + how)) return;
  try {
    const d = await send("POST", "/blocklist", { ip: r.src, reason: "From alert: " + r.msg.slice(0, 120), confirm: true });
    showError("");
    blocked.add(r.src);
    drawRows(); drawDetail(r.src + " blocked. " + d.message);
    loadDashboard(true);
  } catch (e) { showError(e.message); }
}

let lastRefresh = 0;
async function loadDashboard(force) {
  // Do not move the rows under the mouse or the keyboard focus while the analyst is reading them.
  const tw = $("tw"), frozen = !force && (tw.matches(":hover") || tw.contains(document.activeElement));
  try {
    const d = await api("/dashboard?" + filterQuery());
    showError("");
    blocked = new Set(d.blocked); arMode = d.ar_mode;
    checkNewAlerts(d);
    $("total").textContent = d.total_all !== undefined ? d.total_all : d.total; $("scans").textContent = d.scans; $("unique").textContent = d.unique;
    $("open").textContent = $("open2").textContent = d.open_incidents; $("nblocked").textContent = d.blocked.length;
    const sel = $("level"), cur = sel.value; sel.length = 1;
    d.levels.forEach(l => sel.add(new Option("Level " + l, l))); sel.value = cur;
    drawDash(d); drawStatus(true, d, false);
    if (!frozen) { rows = d.rows; drawRows(); if (selected) { const fresh = rows.find(x => x.id === selected.id); if (fresh) selected = fresh; } drawDetail(); }
    $("count").textContent = "(" + d.matched + " match, showing " + d.loaded + ")";
    $("updated").textContent = "Updated " + new Date().toLocaleTimeString() + (frozen ? " (table paused while you read it)" : "");
    $("csv").href = "/api/alerts.csv?" + filterQuery();
  } catch (e) { if (e.message !== "Login required") { showError("Could not load alerts: " + e.message); drawStatus(false, null, e instanceof TypeError); } }
}

let timer;
// One time range for the whole dashboard: the picker on the Dashboard page and the one on Security Events are the same setting.
$("range").addEventListener("change", () => { $("drange").value = $("range").value; prev = null; });
$("drange").addEventListener("change", () => { $("range").value = $("drange").value; prev = null; loadDashboard(true); });
["q", "level", "range", "scan", "noipv6"].forEach(id => $(id).addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => loadDashboard(true), 300); }));
$("clear").onclick = () => { $("q").value = ""; $("level").value = ""; $("range").value = "24h"; $("drange").value = "24h"; prev = null; $("scan").checked = false; $("noipv6").checked = false; loadDashboard(true); };
$("tw").addEventListener("mouseleave", () => { if (view === "dashboard") loadDashboard(); });

// ---------- incidents ----------
async function loadIncidents() {
  try {
    const d = await api("/incidents");
    const tb = $("inc-rows"); tb.textContent = "";
    d.items.forEach(i => {
      const status = h("select", { disabled: !can("analyst"), "aria-label": "Status of incident " + i.id }, d.statuses.map(s => h("option", { value: s, selected: s === i.status }, s)));
      const note = h("input", { type: "text", value: i.note, disabled: !can("analyst"), style: "min-width:200px", "aria-label": "Note for incident " + i.id });
      const save = h("button", { disabled: !can("analyst"), onclick: async () => {
        try { await send("PATCH", "/incidents/" + i.id, { status: status.value, note: note.value }); showError(""); loadDashboard(true); }
        catch (e) { showError(e.message); }
      } }, "Save");
      tb.append(h("tr", {}, td(i.id), td(i.created), td(i.src), td(i.dst), td(i.msg), td(i.count), td(status), td(note), td(save)));
    });
    if (!d.items.length) empty(tb, 9, 'No incidents yet. Open an alert and use "Create incident".');
  } catch (e) { showError(e.message); }
}

// ---------- blocked IPs ----------
async function loadBlocklist() {
  try {
    const d = await api("/blocklist");
    arMode = d.ar_mode;
    const m = $("mode"); m.className = "banner" + (arMode === "live" ? " live" : ""); m.textContent = "";
    m.append(badge(arMode, arMode === "live" ? "LIVE" : "DRY RUN"), " ",
      arMode === "live" ? "Blocks are sent to Wazuh Active Response and change the firewall on the agent." +
        (d.unblock_auto ? "" : " Unblock only updates this list: the firewall rule stays until you delete it on the agent (or set SOC_AR_UNBLOCK_COMMAND).")
        : "Blocks are only recorded. No firewall is changed. Set SOC_AR_DRY_RUN=false after you tested the Wazuh API.");
    $("b-info").textContent = "Protected, can never be blocked: " + d.protected.join(", ");
    const tb = $("b-rows"); tb.textContent = "";
    d.items.forEach(b => {
      const act = b.status === "Active" && can("admin") ? h("button", { onclick: async () => {
        if (!confirm("Unblock " + b.ip + "?")) return;
        try { const r = await send("POST", "/blocklist/" + b.id + "/unblock"); showError(""); alert(r.message); loadBlocklist(); }
        catch (e) { showError(e.message); }
      } }, "Unblock") : "";
      tb.append(h("tr", {}, td(b.id), td(b.ip), td(b.reason), td(b.created), td(b.actor), td(badge(b.mode, b.mode)), td(b.status), td(b.result), td(act)));
    });
    if (!d.items.length) empty(tb, 9, "No blocked IPs yet.");
  } catch (e) { showError(e.message); }
}
$("b-go").onclick = async () => {
  const ip = $("b-ip").value.trim();
  if (!ip) { showError("Enter an IP address"); return; }
  if (!confirm("Block " + ip + "?\n\n" + (arMode === "live" ? "LIVE: this changes the firewall on the target machine." : "Dry run: only recorded."))) return;
  try {
    await send("POST", "/blocklist", { ip, reason: $("b-reason").value || "Blocked manually", confirm: true });
    $("b-ip").value = ""; $("b-reason").value = ""; showError(""); loadBlocklist();
  } catch (e) { showError(e.message); }
};

// ---------- audit log ----------
async function loadAudit() {
  try {
    const d = await api("/audit");
    const tb = $("a-rows"); tb.textContent = "";
    d.items.forEach(a => tb.append(h("tr", {}, td(a.ts), td(a.actor), td(a.action), td(a.target), td(a.detail))));
    if (!d.items.length) empty(tb, 5, "Nothing logged yet.");
  } catch (e) { showError(e.message); }
}

// ---------- users (admin) ----------
async function loadUsers() {
  try {
    const d = await api("/users");
    const tb = $("u-rows"); tb.textContent = "";
    const waiting = d.items.filter(u => u.status === "pending").length;
    $("npend").textContent = waiting || "";
    d.items.forEach(u => {
      const self = u.email === me.email;
      const role = h("select", { "aria-label": "Role of " + u.email, disabled: self }, d.roles.map(r => h("option", { value: r, selected: r === u.role }, r)));
      const call = (path, body, method = "POST") => async () => {
        try { await send(method, "/users/" + u.id + path, body && body()); showError(""); loadUsers(); } catch (e) { showError(e.message); }
      };
      const ask = (text, fn) => () => { if (confirm(text)) fn(); };
      const reset = () => {
        const pw = prompt("Temporary password for " + u.email + " (10+ characters).\nThey must choose a new one at the next sign-in.");
        if (pw) call("/reset", () => ({ password: pw }))();
      };
      let acts = [];
      if (u.status === "pending") {
        acts = [h("button", { class: "primary", onclick: call("/approve", () => ({ role: role.value })) }, "Approve"),
                h("button", { class: "danger", onclick: ask("Reject and delete the request from " + u.email + "?", call("", null, "DELETE")) }, "Reject")];
      } else if (!self) {
        acts = [h("button", { onclick: call("/role", () => ({ role: role.value })) }, "Save role"),
                u.status === "active" ? h("button", { onclick: call("/status", () => ({ status: "disabled" })) }, "Disable")
                                      : h("button", { onclick: call("/status", () => ({ status: "active" })) }, "Enable"),
                h("button", { onclick: reset }, "Reset password"),
                h("button", { class: "danger", onclick: ask("Delete " + u.email + " for good?", call("", null, "DELETE")) }, "Delete")];
      }
      tb.append(h("tr", {}, td(u.email + (self ? " (you)" : "")), td(badge(u.status, u.status)), td(role), td(u.created),
        td(u.approved_by || "-"), td(h("div", { class: "actions" }, acts))));
    });
  } catch (e) { showError(e.message); }
}

// ---------- my account ----------
function loadAccount() {
  $("acc-info").textContent = "Signed in as " + me.email + " (" + me.role + ")." +
    (me.must_change ? " An admin reset your password. Choose a new one to continue." : "");
}
$("acc-form").onsubmit = async e => {
  e.preventDefault();
  $("acc-msg").textContent = "";
  if ($("acc-new").value !== $("acc-new2").value) { showError("The two new passwords do not match."); return; }
  try {
    await send("POST", "/change-password", { old: $("acc-old").value, new: $("acc-new").value });
    ["acc-old", "acc-new", "acc-new2"].forEach(i => $(i).value = "");
    me.must_change = false; showError(""); loadAccount();
    $("acc-msg").textContent = "Password changed. You can use the other tabs now.";
  } catch (err) { showError(err.message); }
};

// ---------- notifications (bell) ----------
let notes = [], prev = null, lastPending = 0;
function notify(text, sub, onclick) {
  notes.unshift({ text, sub, time: new Date().toLocaleTimeString(), onclick, read: false });
  notes = notes.slice(0, 30);
  drawNotes();
}
function drawNotes() {
  const unread = notes.filter(n => !n.read).length;
  $("nbell").textContent = unread;
  document.title = (unread ? "(" + unread + ") " : "") + "SOC Dashboard";
  const ul = $("nlist"); ul.textContent = "";
  notes.forEach(n => {
    const li = h("li", { tabindex: 0 }, h("b", {}, n.text), h("small", {}, n.sub + " | " + n.time));
    li.onclick = () => { if (n.onclick) n.onclick(); $("notif").hidden = true; };
    ul.append(li);
  });
  if (!notes.length) ul.append(h("li", { class: "mute" }, "Nothing new."));
}
$("bell").onclick = () => {
  $("notif").hidden = !$("notif").hidden;
  if (!$("notif").hidden) { notes.forEach(n => n.read = true); drawNotes(); }
};
$("nclear").onclick = () => { notes = []; drawNotes(); };

// New Critical / High alerts and new port scans. The server sends the time of the newest alert of each kind.
// (Comparing counts would miss new alerts while old ones leave the time range.)
const lastNote = {};
function checkNewAlerts(d) {
  const now = d.newest || {};
  if (prev) {
    [["critical", "New Critical alert"], ["high", "New High alert"], ["scans", "New port scan"]].forEach(([k, text]) => {
      const fresh = now[k] && (!prev[k] || now[k] > prev[k]);
      if (fresh && Date.now() - (lastNote[k] || 0) > 30000) {  // at most one message per kind every 30 seconds
        lastNote[k] = Date.now();
        notify(text, "Alert time " + new Date(now[k]).toLocaleTimeString() + ". See the alerts table.", null);
      }
    });
  }
  prev = now;
}

// New sign-up requests (admin only)
async function checkPending() {
  if (!can("admin")) return;
  try {
    const d = await api("/users");
    const n = d.items.filter(u => u.status === "pending").length;
    $("npend").textContent = n || "";
    if (n > lastPending) notify((n - lastPending) + " new account request" + (n - lastPending > 1 ? "s" : ""), "Click to open the Users tab",
      () => document.querySelector('[data-view="users"]').click());
    lastPending = n;
  } catch (e) { /* the next tick tries again */ }
}

// ---------- refresh ----------
let timer2, busy = false, lastPendingCheck = 0, lastAgentsCheck = 0;
function tick() {
  if (document.hidden || me.must_change) return;
  if ((view === "dashboard" || view === "events") && !busy) { busy = true; loadDashboard().finally(() => busy = false); }  // never stack requests
  if (can("admin") && Date.now() - lastPendingCheck > 5000) { lastPendingCheck = Date.now(); checkPending(); }
  if (Date.now() - lastAgentsCheck > 30000) { lastAgentsCheck = Date.now(); fetchAgents(); }
}
function setEvery() {
  clearInterval(timer2);
  const ms = +$("every").value;
  if (ms) timer2 = setInterval(tick, ms);
}
$("every").onchange = setEvery;
$("refresh").onclick = () => { loadDashboard(true); checkPending(); fetchAgents(); };

// ---------- start ----------
function applyRole() {
  $("who").textContent = me.email; $("role").textContent = me.role; $("av").textContent = me.email.charAt(0).toUpperCase();
  $("t-audit").hidden = $("t-users").hidden = !can("admin");
  $("b-card").hidden = !can("admin");
  $("csv").hidden = !can("analyst");
}
async function init() {
  try { me = await api("/me"); } catch (e) { return; }
  applyRole();
  if (me.must_change) { document.querySelector('[data-view="account"]').click(); return; }
  loadDashboard(true);
  checkPending();  // pending sign-ups (admin only)
  fetchAgents();
}
init();
setEvery();
