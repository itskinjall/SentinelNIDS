"use strict";
/* SentinelNIDS dashboard. All data comes from /api/*; every dynamic value is escaped (EVE fields are attacker-controlled). */
const $ = (s, r = document) => r.querySelector(s);
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = (p, o) => fetch("/api" + p, o).then(r => r.json());
const post = (p, body) => api(p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const fmt = t => t ? new Date(t * 1000).toLocaleString([], { hour12: false }) : "–";
const SEV = ["critical", "high", "medium", "low"];
const SEVCOL = { critical: "#e5484d", high: "#d95926", medium: "#c98500", low: "#5C8DC5" };
const sevChip = s => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const ep = (ip, p) => `<span class="mono">${esc(ip)}${p ? ":" + esc(p) : ""}</span>`;
const STATUS = ["Open", "Investigating", "Resolved"];
const statusSel = (cls, v) => `<select class="${cls}" aria-label="Alert status">${STATUS.map(s => `<option${s === v ? " selected" : ""}>${s}</option>`).join("")}</select>`;

let view = "overview", selAlert = null, selCase = null, charts = {};
const TITLES = { overview: "Overview", alerts: "Live Alerts", investigate: "Threat Investigation", analytics: "Analytics", reports: "Incident Reports" };

/* ---------- navigation ---------- */
function show(v) {
  view = v;
  document.querySelectorAll(".view").forEach(e => e.hidden = e.id !== "v-" + v);
  document.querySelectorAll("#nav button").forEach(b => b.classList.toggle("on", b.dataset.view === v));
  $("#title").textContent = TITLES[v];
  history.replaceState(null, "", "#" + v);
  refresh(true);
}
$("#nav").addEventListener("click", e => e.target.dataset.view && show(e.target.dataset.view));

/* ---------- health + banner ---------- */
async function health() {
  const h = await api("/health");
  const el = $("#health"); el.className = "health " + h.state;
  $("#health-text").textContent = { healthy: "Suricata: running", stale: "Suricata: NO HEARTBEAT", no_file: "EVE file missing", waiting: "Waiting for Suricata" }[h.state];
  const b = $("#banner"), o = $("#origin");
  const sample = h.sample_events > 0, live = h.live_events > 0;
  o.hidden = !sample; o.textContent = live ? "Sample + live data" : "SAMPLE DATA – not live traffic";
  if (h.state === "stale" || h.state === "no_file") {
    b.hidden = false; b.className = "banner"; b.innerHTML = `<b>Detection may be offline.</b> ${esc(h.message)}`;
  } else if (!sample && !live) {
    b.hidden = false; b.className = "banner info";
    b.innerHTML = `No events collected yet. ${esc(h.message)} <button class="btn ghost" id="load-sample">Load labelled sample data</button>`;
    $("#load-sample").onclick = async () => { await api("/sample/load", { method: "POST" }); refresh(true); };
  } else if (sample && !live) {
    b.hidden = false; b.className = "banner info";
    b.innerHTML = `Showing <b>sample events</b> for development. ${esc(h.message)} <button class="btn ghost" id="clr-sample">Clear sample data</button>`;
    $("#clr-sample").onclick = async () => { await api("/sample/clear", { method: "POST" }); refresh(true); };
  } else b.hidden = true;
}

/* ---------- overview ---------- */
async function overview() {
  const [o, cases] = await Promise.all([api("/overview"), api("/cases")]);
  const k = (l, v, c) => `<div class="kpi"><div class="l">${c ? `<i style="background:${c}"></i>` : ""}${l}</div><div class="v">${v.toLocaleString()}</div></div>`;
  $("#kpis").innerHTML = k("Total events collected", o.total_events) + k("Total alerts", o.total_alerts) +
    SEV.map(s => k(s[0].toUpperCase() + s.slice(1) + " alerts", o.by_severity[s], SEVCOL[s])).join("") +
    k("Unique source IPs", o.unique_sources) + k("Open cases", o.open_cases);
  const max = Math.max(1, ...o.top_ports.map(p => p.n));
  $("#ports").innerHTML = o.top_ports.map(p => `<div class="bar-row"><span class="mono">${esc(p.proto)}/${esc(p.port)}</span><div class="bar"><span style="width:${p.n / max * 100}%"></span></div><span>${p.n}</span></div>`).join("") || '<p class="muted">No alerts yet.</p>';
  $("#ov-cases").innerHTML = cases.slice(0, 6).map(c => `<div class="item row" style="justify-content:space-between;cursor:pointer" data-case="${c.id}">
      <span><b>Case #${c.id}</b> <span class="mono">${esc(c.src_ip)}</span><br><span class="muted small">${c.alert_count} alert(s) · ${c.correlated ? "correlated" : "isolated"} · ${esc(c.status)}</span></span>
      <span>${sevChip(c.max_severity)} <span class="score" title="Calculated heuristic, not a verdict">risk ${c.risk_score}</span></span></div>`).join("") || '<p class="muted">No cases yet.</p>';
  document.querySelectorAll("[data-case]").forEach(e => e.onclick = () => { selCase = +e.dataset.case; show("reports"); });
}

/* ---------- live alerts ---------- */
async function alerts() {
  const q = new URLSearchParams({ severity: $("#f-sev").value, status: $("#f-status").value, q: $("#f-q").value });
  [...q.keys()].forEach(k => !q.get(k) && q.delete(k));
  const rows = await api("/alerts?" + q);
  $("#alert-count").textContent = rows.length + " alert(s)";
  $("#alert-table tbody").innerHTML = rows.map(a => `<tr class="click" tabindex="0" data-id="${a.id}">
    <td class="mono">${esc(fmt(a.ts))}</td><td>${sevChip(a.severity)}</td><td>${esc(a.signature)}</td>
    <td>${ep(a.src_ip, a.src_port)}</td><td>${ep(a.dest_ip, a.dest_port)}</td><td>${esc(a.proto)}</td>
    <td class="risk" title="Calculated by SentinelNIDS (${esc(a.risk_band)}). Not an IDS verdict.">${a.risk_score ?? "–"}</td>
    <td>${statusSel("st", a.status)}</td></tr>`).join("") || '<tr><td colspan="8" class="muted">No alerts match.</td></tr>';
  document.querySelectorAll("#alert-table tr.click").forEach(tr => {
    const open = () => { selAlert = +tr.dataset.id; show("investigate"); };
    tr.addEventListener("click", e => { if (e.target.tagName !== "SELECT") open(); });
    tr.addEventListener("keydown", e => { if (e.key === "Enter") open(); });
    tr.querySelector("select").onchange = async e => { await post(`/alerts/${tr.dataset.id}/status`, { status: e.target.value }); };
  });
}
["f-sev", "f-status"].forEach(i => $("#" + i).onchange = alerts);
$("#f-q").oninput = alerts;

/* ---------- investigation ---------- */
async function investigate(force) {
  const list = await api("/alerts?limit=200");
  const pick = $("#pick");
  if (force || pick.options.length !== list.length) {
    pick.innerHTML = list.map(a => `<option value="${a.id}">#${a.id} · ${esc(fmt(a.ts))} · ${esc(a.severity)} · ${esc(a.signature).slice(0, 70)}</option>`).join("");
  }
  $("#inv-empty").hidden = list.length > 0; $("#inv").hidden = !list.length;
  if (!list.length) return;
  if (!selAlert || !list.some(a => a.id === selAlert)) selAlert = list[0].id;
  pick.value = selAlert;
  const d = await api("/alerts/" + selAlert), a = d.alert;
  const row = (k, v) => `<dt>${k}</dt><dd>${v}</dd>`;
  const ev = d.event || {};
  $("#inv-details").innerHTML = row("Time", esc(fmt(a.ts))) + row("IDS severity", sevChip(a.severity) + ` <span class="muted small">(rule priority ${esc(a.ids_severity)})</span>`) +
    row("Signature", esc(a.signature) + ` <span class="muted">SID ${esc(a.signature_id)}</span>`) + row("Category", esc(a.category)) +
    row("Source", ep(a.src_ip, a.src_port)) + row("Destination", ep(a.dest_ip, a.dest_port)) + row("Protocol", esc(a.proto) + (ev.app_proto ? " / " + esc(ev.app_proto) : "")) +
    row("IDS action", esc(a.action) + ' <span class="muted small">(IDS mode: logged, not blocked)</span>') + row("Case", d.case ? `#${d.case.id}` : "–") + row("Data origin", esc(a.origin));
  $("#inv-raw").textContent = JSON.stringify(ev, null, 2);
  const c = d.case;
  $("#inv-risk").innerHTML = c ? `<p>Score <span class="score">${c.risk_score}/100 · ${esc(c.risk_band)}</span> for case #${c.id} (${c.alert_count} alert(s) from ${esc(c.src_ip)}).</p>
    <table><thead><tr><th>Factor</th><th>Detail</th><th>Pts</th></tr></thead><tbody>${c.risk_breakdown.map(f => `<tr><td>${esc(f.factor)}</td><td>${esc(f.detail)}</td><td>${f.points}</td></tr>`).join("")}</tbody></table>
    <p class="muted small">Heuristic triage aid. It is not evidence of compromise and not a Suricata verdict.</p>` : '<p class="muted">Not part of a case.</p>';
  $("#inv-rule").innerHTML = d.rule ? `<p class="muted">${esc(d.rule.why)}</p><pre>${esc(d.rule.rule)}</pre>` : '<p class="muted">Rule text not found in rules/local.rules (non-local signature).</p>';
  $("#inv-related tbody").innerHTML = d.related.map(r => `<tr><td class="mono">${esc(fmt(r.ts))}</td><td>${esc(r.event_type)}</td><td>${ep(r.src_ip, r.src_port)}</td><td>${ep(r.dest_ip, r.dest_port)}</td><td>${esc(r.app_proto || r.proto)}</td><td>${esc(r.summary)}</td></tr>`).join("") || '<tr><td colspan="6" class="muted">None</td></tr>';
  const p = d.pcap;
  $("#inv-pcap").innerHTML = p.available ? `<p>Capture file(s): <span class="mono">${esc(p.files.join(", "))}</span></p><button class="btn ghost" id="pk">Preview packets</button> <a class="btn" href="/api/alerts/${a.id}/pcap">Download filtered PCAP</a><div id="pk-out"></div>`
    : `<p class="muted">No PCAP linked to this alert. ${esc(p.hint)}</p>`;
  if (p.available) $("#pk").onclick = async () => {
    const r = await api(`/alerts/${a.id}/packets`);
    $("#pk-out").innerHTML = r.packets.length ? `<pre>${esc(r.packets.map(x => x.info && !x.src ? x.info : `${x.t}s ${x.src} → ${x.dst} ${x.proto} ${x.len}B ${x.info}`).join("\n"))}</pre>` : `<p class="muted">${esc(r.note || "No packets matched.")}</p>`;
  };
  $("#inv-status").value = a.status;
  $("#inv-notes").innerHTML = d.notes.map(n => `<div class="note-item"><span class="muted small">${esc(fmt(n.ts))}</span><br>${esc(n.body)}</div>`).join("") || '<p class="muted small">No notes yet.</p>';
}
$("#pick").onchange = e => { selAlert = +e.target.value; investigate(); };
$("#inv-status").onchange = async e => { await post(`/alerts/${selAlert}/status`, { status: e.target.value }); };
$("#inv-note-save").onclick = async () => { const t = $("#inv-note-text"); if (!t.value.trim()) return; await post(`/alerts/${selAlert}/notes`, { body: t.value }); t.value = ""; investigate(); };

/* ---------- analytics ---------- */
const axis = { ticks: { color: "#AD9E90" }, grid: { color: "#3a382f" }, border: { color: "#3a382f" } };
function chart(id, cfg) {
  charts[id]?.destroy();
  charts[id] = new Chart($("#" + id), { ...cfg, options: { responsive: true, maintainAspectRatio: false, animation: false, ...cfg.options } });
}
async function analytics() {
  const a = await api("/analytics");
  Chart.defaults.color = "#AD9E90";
  $("#bucket").textContent = (a.bucket_sec / 60) + " min buckets";
  chart("c-time", { type: "bar", data: { labels: a.over_time.map(r => new Date(r.t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })),
    datasets: SEV.map(s => ({ label: s, data: a.over_time.map(r => r[s]), backgroundColor: SEVCOL[s], borderColor: "#1e1d17", borderWidth: 2, borderRadius: 3 })) },
    options: { scales: { x: { ...axis, stacked: true }, y: { ...axis, stacked: true, beginAtZero: true, ticks: { precision: 0, color: "#AD9E90" } } }, plugins: { legend: { position: "bottom", labels: { color: "#ece7e0", boxWidth: 12 } } } } });
  const hbar = (id, rows, key, color) => chart(id, { type: "bar", data: { labels: rows.map(r => r[key]), datasets: [{ label: "Count", data: rows.map(r => r.n), backgroundColor: color, borderRadius: 3, maxBarThickness: 28 }] },
    options: { indexAxis: "y", scales: { x: { ...axis, beginAtZero: true, ticks: { precision: 0, color: "#AD9E90" } }, y: { ...axis, grid: { display: false }, ticks: { color: "#AD9E90", callback(v) { const l = this.getLabelForValue(v); return l.length > 28 ? l.slice(0, 27) + "…" : l; } } } }, plugins: { legend: { display: false } } } });
  hbar("c-src", a.top_sources, "src_ip", "#5C8DC5");
  hbar("c-proto", a.protocols, "p", "#909EAE");
  hbar("c-cat", a.categories, "category", "#AD9E90");
  const tbl = (t, rows, k) => `<h3 class="small">${t}</h3><table><tbody>${rows.map(r => `<tr><td>${esc(r[k])}</td><td>${r.n}</td></tr>`).join("")}</tbody></table>`;
  $("#an-tables").innerHTML = tbl("Top source IPs", a.top_sources, "src_ip") + tbl("Protocols", a.protocols, "p") + tbl("Categories", a.categories, "category");
}

/* ---------- incident reports ---------- */
async function reports(force) {
  const cases = await api("/cases");
  if (!selCase && cases.length) selCase = cases[0].id;
  $("#case-list").innerHTML = cases.map(c => `<div class="item${c.id === selCase ? " on" : ""}" data-id="${c.id}" tabindex="0">
    <div><b>Case #${c.id}</b> ${sevChip(c.max_severity)}</div><div class="mono">${esc(c.src_ip)}</div>
    <div class="muted small">${c.alert_count} alert(s) · ${c.correlated ? "correlated" : "isolated"} · ${esc(c.status)} · ${esc(fmt(c.first_seen))}</div></div>`).join("") || '<p class="muted" style="padding:14px">No cases yet.</p>';
  document.querySelectorAll("#case-list .item").forEach(e => { e.onclick = () => { selCase = +e.dataset.id; reports(true); }; e.onkeydown = ev => ev.key === "Enter" && e.click(); });
  if (!selCase) { $("#report").innerHTML = '<p class="muted">No cases yet.</p>'; return; }
  if (!force && document.activeElement?.closest("#report")) return;    // don't clobber typing during auto-refresh
  const r = await api("/cases/" + selCase), c = r.case;
  $("#report").className = "card report";
  $("#report").innerHTML = `<h2>Incident Report – Case #${r.case_id} ${r.origin === "sample" ? '<span class="tag warn">SAMPLE DATA</span>' : ""}</h2>
    <div class="exports"><a class="btn ghost" href="/api/cases/${r.case_id}/export?format=md">Report (Markdown)</a><a class="btn ghost" href="/api/cases/${r.case_id}/export?format=json">Evidence (JSON)</a><a class="btn ghost" href="/api/cases/${r.case_id}/export?format=csv">Evidence (CSV)</a></div>
    <h3>Incident summary</h3><p>${esc(r.summary)}</p>
    <p>IDS max severity: ${sevChip(c.max_severity)} &nbsp; Calculated risk: <span class="score" title="SentinelNIDS heuristic, not a verdict">${c.risk_score}/100 · ${esc(c.risk_band)}</span></p>
    <h3>Evidence</h3><div class="tw"><table><thead><tr><th>Time</th><th>Severity</th><th>Signature</th><th>Source</th><th>Destination</th><th>Proto</th></tr></thead><tbody>${r.evidence.map(a => `<tr><td class="mono">${esc(fmt(a.ts))}</td><td>${sevChip(a.severity)}</td><td>${esc(a.signature)}</td><td>${ep(a.src_ip, a.src_port)}</td><td>${ep(a.dest_ip, a.dest_port)}</td><td>${esc(a.proto)}</td></tr>`).join("")}</tbody></table></div>
    <h3>Detection rule</h3>${r.detection_rules.map(d => `<p class="muted">SID ${d.sid} – ${esc(d.why)}</p><pre>${esc(d.rule)}</pre>`).join("") || '<p class="muted">No local rule text available.</p>'}
    <h3>Analysis</h3><p>${esc(r.analysis)}</p>
    <h3>Recommended mitigation</h3><ul>${r.recommended_mitigation.map(m => `<li>${esc(m)}</li>`).join("")}</ul>
    <h3>Investigation status</h3><div class="row"><select id="case-status">${STATUS.map(s => `<option${s === r.status ? " selected" : ""}>${s}</option>`).join("")}</select><span class="muted small">Changing it updates every alert in the case.</span></div>
    ${r.analyst_notes.map(n => `<div class="note-item"><span class="muted small">${esc(fmt(n.ts))}</span><br>${esc(n.body)}</div>`).join("")}
    <textarea id="case-note" rows="3" placeholder="Add an analyst note to the case…"></textarea><button class="btn" id="case-note-save">Add note</button>
    <p class="muted small">${esc(r.disclaimer)}</p>`;
  $("#case-status").onchange = async e => { await post(`/cases/${r.case_id}/status`, { status: e.target.value }); reports(true); };
  $("#case-note-save").onclick = async () => { const t = $("#case-note"); if (t.value.trim()) { await post(`/cases/${r.case_id}/notes`, { body: t.value }); reports(true); } };
}

/* ---------- refresh loop ---------- */
async function refresh(force) {
  try {
    await health();
    if (view === "overview") await overview();
    else if (view === "alerts") { if (force || !document.activeElement?.matches("select.st,#f-q")) await alerts(); }
    else if (view === "investigate") { if (force || !document.activeElement?.matches("#inv-note-text,select")) await investigate(force); }
    else if (view === "analytics") await analytics();
    else if (view === "reports") await reports(force);
  } catch (e) { console.error(e); }
}
setInterval(() => $("#live").checked && refresh(false), 3000);
show((location.hash || "#overview").slice(1) in TITLES ? location.hash.slice(1) : "overview");
