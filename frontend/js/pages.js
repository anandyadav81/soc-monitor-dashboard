// Extra pages: Threat Intelligence, MITRE ATT&CK, Vulnerabilities, Response Playbooks, Reports,
// and the "Attack origins" panel on the dashboard.
// Loaded AFTER app.js and re-uses its helpers: $, h, td, api, bars, badge, showIp, showError, go, can, loaders, view.
// Like app.js, everything is drawn with textContent / createElement, never innerHTML.
(function () {
  const RANGES = [["1h", "Last hour"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["all", "All time"]];
  const RANGE_NAME = Object.fromEntries(RANGES);
  const when = s => (s ? String(s).slice(0, 19).replace("T", " ") : "-");
  const clear = el => { el.textContent = ""; return el; };
  const main = document.querySelector("main.main");

  function rangeSelect(id, onchange) {
    const s = h("select", { id, "aria-label": "Time range" }, RANGES.map(([v, t]) => h("option", { value: v }, t)));
    s.value = recall("pg-range") || "24h";
    s.onchange = () => { remember("pg-range", s.value); onchange(); };
    return s;
  }
  function section(id, title, ...kids) {
    const sec = h("section", { id, hidden: true }, h("div", { class: "pn" }, h("h2", {}, title), ...kids));
    main.append(sec);
    return sec;
  }
  function allBars(box, list, emptyText) {
    clear(box);
    if (!list.length) { box.append(h("p", { class: "mute" }, emptyText)); return; }
    list.forEach((t, i) => {
      const fill = h("i"); fill.style.width = (t.count / list[0].count * 100) + "%"; fill.style.background = `var(${BARCOL[Math.min(i, 4)]})`;
      box.append(h("div", { class: "bar" }, h("b", { title: t.name }, t.name), h("span", {}, fill), h("em", {}, t.count)));
    });
  }
  const toEvents = text => { $("q").value = text; go("events"); };

  // ================= Threat Intelligence =================
  const tRange = rangeSelect("t-range", () => loadThreat());
  const tSum = h("p", { class: "mute" });
  const tRows = h("tbody");
  section("threat", "Threat Intelligence",
    h("p", { class: "mute" }, "Attackers seen by Suricata in your own lab. The risk score (0-100) combines how many alerts, how severe and how many targets. No outside reputation service is used."),
    h("div", { class: "tw" }, tRange), tSum,
    h("div", { class: "tw" }, h("table", {}, h("thead", {}, h("tr", {}, ["IP address", "Network", "Alerts", "Targets", "Main alert types", "First seen", "Last seen", "Risk", ""].map(t => h("th", {}, t)))), tRows)));
  async function loadThreat() {
    try {
      const d = await api("/threat?range=" + tRange.value);
      clear(tRows);
      d.items.forEach(i => {
        tRows.append(h("tr", {},
          td(showIp(i.ip), i.blocked ? h("span", { class: "blockedmark" }, "blocked") : null),
          td(i.scope === "public" ? "Internet" : i.scope === "private" ? "Private / lab" : "Unknown"),
          td(i.count), td(i.targets), td(i.signatures.join(", ")), td(when(i.first)), td(when(i.last)),
          td(badge(i.sev, i.risk + " " + SEV[i.sev])),
          td(h("button", { onclick: () => toEvents(i.ip) }, "Alerts"))));
      });
      if (!d.items.length) empty(tRows, 9, "No Suricata attackers in this time range.");
      const high = d.items.filter(i => i.risk >= 65).length, pub = d.items.filter(i => i.scope === "public").length;
      tSum.textContent = `${d.items.length} attacker IPs, ${high} high risk, ${pub} from the internet (${RANGE_NAME[d.range]}).`;
      showError("");
    } catch (e) { showError(e.message); }
  }

  // ================= MITRE ATT&CK =================
  const mRange = rangeSelect("m-range", () => loadMitre());
  const mSum = h("p", { class: "mute" }), mTac = h("div"), mRows = h("tbody");
  section("mitre", "MITRE ATT&CK",
    h("p", { class: "mute" }, "Only alerts that carry a MITRE tag are counted (Wazuh adds the tags from its rules)."),
    h("div", { class: "tw" }, mRange), mSum,
    h("h3", {}, "Tactics"), mTac,
    h("h3", {}, "Techniques"),
    h("div", { class: "tw" }, h("table", {}, h("thead", {}, h("tr", {}, ["ID", "Technique", "Tactic", "Alerts", ""].map(t => h("th", {}, t)))), mRows)));
  async function loadMitre() {
    try {
      const d = await api("/mitre?range=" + mRange.value);
      mSum.textContent = `${d.total} alerts with a MITRE tag (${RANGE_NAME[d.range]}).`;
      allBars(mTac, d.tactics, "No MITRE-tagged alerts in this time range.");
      clear(mRows);
      d.techniques.forEach(t => {
        const link = h("a", { href: "https://attack.mitre.org/techniques/" + t.id.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer" }, "MITRE page");
        mRows.append(h("tr", {}, td(t.id), td(t.name), td(t.tactics.join(", ")), td(t.count), td(link)));
      });
      if (!d.techniques.length) empty(mRows, 5, "No techniques in this time range.");
      showError("");
    } catch (e) { showError(e.message); }
  }

  // ================= Vulnerabilities =================
  const vSum = h("p", { class: "mute" }), vRows = h("tbody"), vTable = h("div", { class: "tw" });
  vTable.append(h("table", {}, h("thead", {}, h("tr", {}, ["CVE", "Severity", "CVSS", "Package", "Version", "Agent", "Description"].map(t => h("th", {}, t)))), vRows));
  section("vulns", "Vulnerabilities",
    h("p", { class: "mute" }, "Results of Wazuh Vulnerability Detection, worst first (top 100 by CVSS score)."), vSum, vTable);
  async function loadVulns() {
    try {
      const d = await api("/vulns");
      clear(vRows);
      if (!d.available) { vSum.textContent = d.message; vTable.hidden = true; showError(""); return; }
      vTable.hidden = false;
      const s = d.severity;
      vSum.textContent = `${d.total} vulnerabilities: ${s.critical || 0} critical, ${s.high || 0} high, ${s.medium || 0} medium, ${s.low || 0} low.`;
      d.items.forEach(v => vRows.append(h("tr", {}, td(v.cve), td(badge(v.sev, SEV[v.sev])), td(v.score == null ? "-" : v.score),
        td(v.package), td(v.version), td(v.agent), td(v.desc))));
      if (!d.items.length) empty(vRows, 7, "No vulnerabilities found. Either the agents are clean or the first scan has not finished.");
      showError("");
    } catch (e) { showError(e.message); }
  }

  // ================= Response Playbooks =================
  const PLAYBOOKS = [
    { title: "Port scan", sev: "medium", search: "Port scan",
      what: "One IP probes many ports on a host to see what is open. Usually the first step before a real attack.",
      steps: [
        ["Identify", "Open the alert, note the attacker IP, the target host and the ports touched. Check Threat Intelligence for how long and how often this IP has been active."],
        ["Contain", "If the IP is not a known scanner or your own tool, block it from the Blocked IPs page (or on the target: sudo ufw deny from <IP>)."],
        ["Investigate", "Look for follow-up activity from the same IP: login attempts, web requests, anything after the scan. Search the IP in Security Events."],
        ["Harden", "Close ports that do not need to be open (sudo ss -tulpn shows what is listening) and keep the firewall on."],
        ["Close", "Record what you found in an incident note. If it was your own lab scan, mark the incident False positive."]] },
    { title: "SSH brute force", sev: "high", search: "sshd",
      what: "Many failed SSH logins from one IP, trying to guess a password.",
      steps: [
        ["Identify", "Find the attacker IP and the usernames tried. On the target: sudo grep \"Failed password\" /var/log/auth.log | tail -50"],
        ["Contain", "Block the IP. Confirm the block took effect on the Blocked IPs page."],
        ["Check for success", "Look for a login that worked after the failures: sudo grep \"Accepted\" /var/log/auth.log. A success after many failures means the account is compromised, follow the next playbook."],
        ["Harden", "Turn off password login (PasswordAuthentication no in /etc/ssh/sshd_config), use keys, disable root login, install fail2ban."],
        ["Close", "Document the IP, usernames tried and the actions taken."]] },
    { title: "Account compromise (login after failures)", sev: "critical", search: "authentication success",
      what: "A successful login that follows many failures, or a login from an unexpected IP. Treat as a real incident.",
      steps: [
        ["Contain now", "Block the attacker IP and lock the account: sudo passwd -l <user>. Kill live sessions: sudo pkill -KILL -u <user>"],
        ["Preserve evidence", "Copy /var/log/auth.log and the shell history before changing anything else."],
        ["Investigate", "What did the account do after login? Check history, new users (cat /etc/passwd), new cron jobs (crontab -l), new SSH keys (~/.ssh/authorized_keys)."],
        ["Eradicate", "Remove anything the attacker added. If you cannot be sure the host is clean, rebuild it from a snapshot."],
        ["Recover", "Reset all passwords and keys that were on the host, restore service, watch the host closely for a week."],
        ["Close", "Write the timeline into the incident note and set the status to Closed."]] },
    { title: "Privilege escalation / AppArmor denied", sev: "high", search: "Apparmor",
      what: "A program tried to do something its security profile does not allow, or a user gained higher rights.",
      steps: [
        ["Identify", "Open the alert: which program, which file or action was denied, and which user ran it."],
        ["Decide", "Normal software after an update, or something unexpected? Unknown program or unknown user means treat it as suspicious."],
        ["Investigate", "Check who ran it (last, sudo grep sudo /var/log/auth.log) and what else that user did around the same time."],
        ["Contain", "If suspicious, stop the process, lock the user and isolate the host from the network."],
        ["Close", "If the denial was harmless, tune the profile or note it as a false positive."]] },
    { title: "Suspicious network alert (Suricata signature)", sev: "medium", search: "Suricata",
      what: "Suricata matched a known bad pattern, for example a scan tool, malware beacon or exploit attempt.",
      steps: [
        ["Identify", "Read the signature name and the source/destination. Is the destination one of your hosts?"],
        ["Validate", "Check whether the host really answered the attacker. Traffic that was only sent and never answered is less urgent."],
        ["Contain", "Block the source IP if it is external or unknown."],
        ["Investigate", "Look at other alerts from the same source and at the target host's logs around the same time."],
        ["Close", "Record the signature, the decision and the result."]] },
  ];
  const pbBox = h("div");
  PLAYBOOKS.forEach(p => {
    const steps = h("ol", {}, p.steps.map(([t, d]) => h("li", {}, h("b", {}, t + ": "), d)));
    pbBox.append(h("details", { class: "pb" },
      h("summary", {}, h("b", {}, p.title), " ", badge(p.sev, SEV[p.sev])),
      h("p", { class: "mute" }, p.what), steps,
      h("button", { onclick: () => toEvents(p.search) }, "Show related alerts")));
  });
  section("playbooks", "Response Playbooks",
    h("p", { class: "mute" }, "Step-by-step guides for the alerts you see most. Commands are examples for a Linux (Ubuntu) target: check them before you run them."), pbBox);

  // ================= Reports =================
  const rRange = rangeSelect("r-range", () => loadReport());
  const rBody = h("div", { id: "r-body" });
  const csv = h("a", { class: "btn", href: "#", download: "" }, "Download alerts (CSV)");
  const rBar = h("div", { class: "tw noprint" }, rRange, h("button", { onclick: () => window.print() }, "Print / Save as PDF"), csv);
  section("reports", "Reports", rBar, rBody);
  const kv = rows => h("table", {}, h("tbody", {}, rows.map(([k, v]) => h("tr", {}, td(k), td(v)))));
  const block = (title, ...kids) => h("div", { class: "psec" }, h("h3", {}, title), ...kids);
  async function loadReport() {
    try {
      const r = rRange.value;
      csv.href = "/api/alerts.csv?range=" + r; csv.hidden = !can("analyst");
      const [d, inc] = await Promise.all([api("/dashboard?range=" + r + "&limit=1"), api("/incidents")]);
      clear(rBody);
      rBody.append(h("p", { class: "mute" }, `Period: ${RANGE_NAME[r]}. Generated: ${new Date().toLocaleString()}.`));
      rBody.append(block("Summary", kv([["Total Wazuh alerts", d.total_all], ["Suricata alerts", d.total], ["Port scan alerts", d.scans],
        ["Unique attacker IPs", d.unique], ["Open incidents", d.open_incidents], ["Blocked IPs", d.blocked.length]])));
      const s = d.severity;
      rBody.append(block("Alerts by severity", kv(["critical", "high", "medium", "low"].map(k => [SEV[k], s[k] || 0]))));
      rBody.append(block("Top attacker IPs", d.top_ips.length ? kv(d.top_ips.slice(0, 10).map(i => [showIp(i.ip), i.count])) : h("p", { class: "mute" }, "None.")));
      rBody.append(block("Top alert types", d.categories.length ? kv(d.categories.slice(0, 10).map(c => [c.name, c.count])) : h("p", { class: "mute" }, "None.")));
      rBody.append(block("MITRE ATT&CK tactics", d.tactics.length ? kv(d.tactics.map(t => [t.name, t.count])) : h("p", { class: "mute" }, "None.")));
      const open = inc.items.filter(i => !["Closed", "False positive"].includes(i.status));
      rBody.append(block(`Incidents (${inc.items.length} total, ${open.length} not closed)`,
        inc.items.length ? h("table", {}, h("thead", {}, h("tr", {}, ["#", "Created", "Attacker", "Alert", "Status"].map(t => h("th", {}, t)))),
          h("tbody", {}, inc.items.slice(0, 25).map(i => h("tr", {}, td(i.id), td(i.created), td(i.src), td(i.msg), td(i.status))))) : h("p", { class: "mute" }, "No incidents.")));
      showError("");
    } catch (e) { showError(e.message); }
  }

  // ================= Attack origins panel on the dashboard =================
  async function loadGeo() {
    const box = $("geo"); if (!box) return;
    try {
      const d = await api("/geo?range=" + ($("drange") ? $("drange").value : "24h"));
      allBars(box, d.countries, "No attackers in this time range.");
      $("geonote").textContent = d.note;
    } catch (e) { /* the dashboard already shows connection errors */ }
  }

  // ----- hook into the app -----
  loaders.threat = loadThreat; loaders.mitre = loadMitre; loaders.vulns = loadVulns;
  loaders.playbooks = () => {}; loaders.reports = loadReport;
  const baseDash = loaders.dashboard;
  loaders.dashboard = () => { loadGeo(); return baseDash && baseDash(); };
  setInterval(() => {  // light refresh every 30 s for the data pages
    if (document.hidden) return;
    if (view === "dashboard") loadGeo();
    else if (["threat", "mitre", "vulns"].includes(view)) loaders[view]();
  }, 30000);
  loadGeo();
})();