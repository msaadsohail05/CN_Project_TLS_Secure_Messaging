/* Cipherline dashboard. No dependencies, no network access beyond the local server. */
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k === "html") e.innerHTML = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(k));
  return e;
};
const api = async (path, body) => {
  const r = await fetch(path, body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return r.json();
};
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmt = (x, d = 1) => x == null ? "–" : (+x).toFixed(d);
const store = { get: (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } }, set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} } };

/* ----------------------------------------------------------------- theme + nav */
const root = document.documentElement;
root.dataset.theme = store.get("theme", matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
$("#theme").onclick = () => { root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark"; store.set("theme", root.dataset.theme); drawExperiments(); };
const lazy = { experiments: false, attacks: false, evidence: false, topology: false };
function show(view) {
  $$("#nav button").forEach(b => b.classList.toggle("on", b.dataset.view === view));
  $$(".view").forEach(v => v.classList.toggle("on", v.id === "view-" + view));
  if (view in lazy && !lazy[view]) { lazy[view] = true; ({ experiments: loadExperiments, attacks: loadAttacks, evidence: loadEvidence, topology: loadTopology })[view](); }
  history.replaceState(null, "", "#" + view);
}
$("#nav").onclick = e => { const b = e.target.closest("button"); if (b) show(b.dataset.view); };

/* ----------------------------------------------------------------- live lab */
let S = { cfg: { mode: "e2ee", tamper: false, evil: false, pin: false }, fp: {}, info: {} };
const MODE_TEXT = {
  tcp: "<b>Plain TCP.</b> Nothing is protected. The on-wire feed shows the message text itself, and the relay reads it too.",
  tls: "<b>TLS 1.3 protects each hop.</b> The eavesdropper now sees only encrypted records. But the relay is the TLS endpoint, so it still reads every message in clear.",
  e2ee: "<b>TLS protects the hop, NaCl Box protects the content.</b> The wire shows opaque records and the relay only ever handles ciphertext it cannot open.",
};
const LAYER = { plaintext: ["Plaintext", "pt"], e2ee: ["E2EE · NaCl Box", "e2ee"], framing: ["App framing", "framing"], tls: ["TLS record", "tls"], tcpip: ["TCP/IP headers", "tcpip"] };

function applyState(st) {
  S = st;
  $$("#modeSeg button").forEach(b => b.classList.toggle("on", b.dataset.mode === st.cfg.mode));
  $("#modeSeg").dataset.m = st.cfg.mode;
  $("#tTamper").checked = st.cfg.tamper; $("#tEvil").checked = st.cfg.evil; $("#tPin").checked = st.cfg.pin;
  const e2 = st.cfg.mode === "e2ee";
  ["tTamper", "tEvil", "tPin"].forEach(id => $("#" + id).closest(".tg").classList.toggle("dis", !e2));
  $("#fp-alice-own").textContent = st.fp.alice || ""; $("#fp-bob-own").textContent = st.fp.bob || "";
  for (const who of ["alice", "bob"]) { const c = $("#fp-" + who + "-peer"); c.textContent = "not looked up yet"; c.className = "dim"; c.parentElement.className = "fp"; }
  const i = st.info || {};
  $("#sessionChips").replaceChildren(
    chip("transport", i.version === "TCP" ? "plain TCP" : (i.version || "–")), ...(i.cipher ? [chip("cipher", i.cipher.replace("TLS_", ""))] : []),
    ...(i.tls_ms ? [chip("TLS handshake", i.tls_ms + " ms")] : []), chip("TCP connect", (i.tcp_ms ?? "–") + " ms"));
  let t = MODE_TEXT[st.cfg.mode];
  if (e2 && st.cfg.evil) t += " <b style='color:var(--danger)'>The relay is malicious: it will hand Alice its own key for Bob.</b>" + (st.cfg.pin ? " Alice pinned Bob's fingerprint, so she should catch it." : " Compare the two fingerprints below to spot it.");
  if (e2 && st.cfg.tamper) t += " <b style='color:var(--danger)'>Alice's client corrupts one ciphertext byte of every message.</b>";
  $("#explain").innerHTML = t;
  const tlsOn = st.cfg.mode !== "tcp";
  for (const [id, tag] of [["pl1", "tag1"], ["pl2", "tag2"]]) { $("#" + id).className = "pl " + (tlsOn ? "tls" : "plain"); $("#" + tag).textContent = tlsOn ? "TLS 1.3" : "plain"; }
  $("#pnRelay").textContent = e2 ? "Relay (blind)" : (st.cfg.mode === "tls" ? "Relay (reads all)" : "Relay (reads all)");
  $("#pipeHint").textContent = e2 ? "E2EE: the relay forwards sealed boxes it has no key for." : tlsOn ? "TLS ends at the relay: it decrypts, reads, and re-encrypts for Bob." : "Everything on every hop is readable.";
}
const chip = (k, v) => h("span", { class: "chip" }, k + " ", h("b", {}, v));

function bubble(who, cls, text, meta, metaCls = "") {
  const box = $("#chat-" + who);
  box.append(h("div", { class: "bub " + cls }, text, meta ? h("small", { class: metaCls }, meta) : null));
  box.scrollTop = box.scrollHeight;
}
function zap(from) {   // light the two hops in the direction of travel
  const first = from === "alice" ? "pl1" : "pl2", second = from === "alice" ? "pl2" : "pl1";
  const go = id => { const i = $("#" + id + " i"); $("#" + id).classList.toggle("rev", from === "bob"); i.classList.remove("zap"); void i.offsetWidth; i.classList.add("zap"); };
  go(first); setTimeout(() => go(second), 520);
}
function pushFeed(feed, node, limit = 60) { const f = $(feed); if (f.querySelector(".empty")) f.replaceChildren(); f.prepend(node); while (f.children.length > limit) f.lastChild.remove(); }

function onEvent(ev) {
  switch (ev.type) {
    case "reset":
      $$(".chat").forEach(c => c.replaceChildren()); $("#wireFeed").replaceChildren(h("div", { class: "empty" }, "Parsed from raw bytes with no keys: this is all a sniffer can ever read."));
      $("#relayFeed").replaceChildren(h("div", { class: "empty" }, "Frames the relay forwards, after TLS is removed."));
      $("#alerts").replaceChildren(h("div", { class: "empty" }, "Alerts from the clients and relay appear here."));
      $("#stack").replaceChildren(h("div", { class: "empty" }, "Send a message to see where every byte comes from.")); $("#stackLegend").replaceChildren(); $("#stackTotal").textContent = ""; $("#anatomyVerified").textContent = "";
      applyState(ev.state); break;
    case "chat":
      if (ev.dir === "out") { bubble(ev.who, "out", ev.text, "to " + ev.to); zap(ev.who); animateRoute(ev.who); }
      else bubble(ev.who, "in", ev.text, S.cfg.mode === "e2ee" ? `decrypted ✓ · from ${ev.frm}` : `from ${ev.frm} · plaintext on the wire`, S.cfg.mode === "e2ee" ? "ok" : "leak");
      break;
    case "fp": {
      const peer = ev.peer, real = S.fp[peer], c = $("#fp-" + ev.who + "-peer"), ok = ev.fp === real;
      c.textContent = ev.fp + (ok ? "  ✓ matches" : "  ✗ NOT " + peer + "'s real key"); c.className = ""; c.parentElement.className = "fp " + (ok ? "match" : "mismatch"); break; }
    case "alert": {
      const a = $("#alerts"); if (a.querySelector(".empty")) a.replaceChildren();
      a.prepend(h("div", { class: "al " + ev.level }, h("b", {}, ev.title), ev.text, ev.got ? h("div", {}, h("code", {}, "relay gave   " + ev.got)) : null, ev.expected ? h("div", {}, h("code", {}, "you pinned   " + ev.expected)) : null)); break; }
    case "wire": wireRow(ev); break;
    case "relay": relayRow(ev); break;
    case "breakdown": drawStack(ev); break;
  }
}
function wireRow(ev) {
  const arrow = ev.dir === "c2s" ? `${ev.who} → relay` : `relay → ${ev.who}`;
  let ty, cls = "ad", rowCls = "row", body;
  if (ev.layer === "tls") {
    ty = ev.rtype; cls = ev.type_id === 22 ? "hs" : ev.type_id === 20 ? "cc" : "ad";
    body = ev.version.includes("legacy") ? `${ev.version} · ${ev.head}…` : `${ev.version} · ${ev.head}…`;
    if (ev.type_id === 23) body = "encrypted · " + ev.head + "…";
  } else {
    ty = ev.rtype; cls = "app";
    if (ev.text) { rowCls += " leak"; body = "“" + ev.text + "”  ← readable"; } else body = ev.head + "…";
  }
  pushFeed("#wireFeed", h("div", { class: rowCls }, h("span", { class: "who" }, arrow), h("span", { class: "ty " + cls }, ty), h("span", { class: "sz" }, ev.wire + " B"), h("span", { class: "hx" }, body)));
}
function relayRow(ev) {
  if (ev.kind === "forward") {
    const leak = ev.readable;
    pushFeed("#relayFeed", h("div", { class: "row relayrow " + (leak ? "leak" : "safe") }, h("span", { class: "who" }, `${ev.sender} → ${ev.to}`), h("span", { class: "sz" }, ev.size + " B"),
      h("span", { class: "hx" }, h("span", { class: "badge " + (leak ? "r" : "c") }, leak ? "READABLE" : "CIPHERTEXT"), leak ? "“" + ev.text + "”" : ev.head + "…")));
  } else if (ev.kind === "intercepted") {
    pushFeed("#relayFeed", h("div", { class: "row relayrow leak" }, h("span", { class: "who" }, `${ev.sender} → ${ev.to}`), h("span", { class: "sz" }, "MITM"), h("span", { class: "hx" }, h("span", { class: "badge x" }, "DECRYPTED"), "“" + ev.text + "”")));
  } else {
    pushFeed("#relayFeed", h("div", { class: "row relayrow" }, h("span", { class: "who" }, ev.kind), h("span", { class: "sz" }, ""), h("span", { class: "hx" }, ev.user || ev.by ? `${ev.user || ev.by}${ev.found ? "" : ""}` : "")));
  }
}
function drawStack(ev) {
  const stack = $("#stack"), leg = $("#stackLegend"); stack.replaceChildren(); leg.replaceChildren();
  const total = ev.parts.reduce((a, p) => a + p.bytes, 0), pt = ev.parts[0].bytes;
  for (const p of ev.parts) {
    const [name, cls] = LAYER[p.layer];
    const d = h("div", { class: cls, title: `${name}: ${p.bytes} B` }, p.bytes / total > .07 ? String(p.bytes) : ""); d.style.flex = String(p.bytes); stack.append(d);
    leg.append(h("li", {}, h("i", { style: `background:var(--${cls === "pt" ? "pt" : cls})` }), h("b", {}, name), h("code", {}, p.bytes + " B"), h("span", {}, p.note)));
  }
  $("#stackTotal").innerHTML = `A <b>${pt}-byte</b> message becomes <b>${total} bytes</b> on the wire: <b>${(total / pt).toFixed(1)}×</b> the payload.`;
  const v = $("#anatomyVerified"); v.className = ev.verified ? "ver-ok" : "ver-mod"; v.textContent = ev.verified ? "✓ record size matches the tap" : "";
}

document.addEventListener("submit", async e => {
  const f = e.target.closest(".composer"); if (!f) return; e.preventDefault();
  const i = f.querySelector("input"), text = i.value.trim(); if (!text) return; i.value = "";
  const r = await api("/api/send", { who: f.dataset.who, text });
  if (r.ok === false) bubble(f.dataset.who, "out", "✗ not sent", "refused by the client");
});
$("#modeSeg").onclick = async e => { const b = e.target.closest("button"); if (b) applyState(await api("/api/lab", { mode: b.dataset.mode })); };
for (const [id, key] of [["tTamper", "tamper"], ["tEvil", "evil"], ["tPin", "pin"]]) $("#" + id).onchange = async e => applyState(await api("/api/lab", { [key]: e.target.checked }));
$("#btnRogue").onclick = async () => { const r = await api("/api/rogue-client", {}); if (!r.ok) onEvent({ type: "alert", level: "warn", title: "Rogue client", text: r.text }); };
$("#btnClear").onclick = () => { $("#wireFeed").replaceChildren(); $("#relayFeed").replaceChildren(); };

function connectSSE() {
  const es = new EventSource("/api/events"), live = $("#live");
  es.onopen = () => { live.classList.add("ok"); live.lastChild.textContent = "live"; };
  es.onerror = () => { live.classList.remove("ok"); live.lastChild.textContent = "reconnecting"; };
  es.onmessage = m => onEvent(JSON.parse(m.data));
}

/* ----------------------------------------------------------------- topology */
const DESC = {};
async function loadTopology() {
  const svg = await (await fetch("/files/docs/architecture.svg")).text();
  $("#topo").innerHTML = svg;
  $("#topo svg").removeAttribute("width");
  const res = await (RES || (RES = await api("/api/results")));
  const seg = $("#condSeg"); seg.replaceChildren(h("button", { "data-c": "", class: "on" }, "no impairment"));
  for (const c of res.summary?.conditions || []) seg.append(h("button", { "data-c": c.id }, `${c.rtt_ms} ms · ${c.loss_pct}%`));
  const byId = Object.fromEntries((res.summary?.conditions || []).map(c => [c.id, c]));
  seg.onclick = e => {
    const b = e.target.closest("button"); if (!b) return;
    $$("button", seg).forEach(x => x.classList.toggle("on", x === b));
    const t = $$("#topo .bt"), c = byId[b.dataset.c];
    t[0].textContent = c ? `netem delay ${c.rtt_ms / 2} ms each side (RTT ${c.rtt_ms} ms)` : "tc netem delay (both sides)";
    t[1].textContent = c ? (c.loss_pct ? `loss ${c.loss_pct}% on R1 egress only` : "no loss") : "loss on R1 egress · tbf rate";
  };
}
function animateRoute(from) {
  const svg = $("#topo svg"); if (!svg || !$("#view-topology").classList.contains("on")) return;
  const a = svg.getElementById("route-a"), b = svg.getElementById("route-b"); if (!a || !b) return;
  const legs = from === "alice" ? [[a, false], [b, true]] : [[b, false], [a, true]];
  const seq = from === "alice" ? ["n-clientA", "n-r1", "n-r2", "n-relay", "n-r2", "n-r1", "n-clientB"] : ["n-clientB", "n-r1", "n-r2", "n-relay", "n-r2", "n-r1", "n-clientA"];
  const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle"); dot.setAttribute("r", 7); dot.setAttribute("fill", "var(--e2ee)"); dot.setAttribute("stroke", "var(--text)"); dot.setAttribute("stroke-width", 2); svg.append(dot);
  const dur = 900, t0 = performance.now();
  seq.forEach((id, i) => setTimeout(() => { const g = svg.getElementById(id); g?.classList.add("hot"); setTimeout(() => g?.classList.remove("hot"), 500); }, i * (2 * dur) / 6.2));
  (function step(now) {
    const t = now - t0, k = Math.floor(t / dur); if (k >= 2) return dot.remove();
    const [path, rev] = legs[k], L = path.getTotalLength(), f = Math.min(1, (t - k * dur) / dur), p = path.getPointAtLength(rev ? L * (1 - f) : L * f);
    dot.setAttribute("cx", p.x); dot.setAttribute("cy", p.y); requestAnimationFrame(step);
  })(t0);
}

/* ----------------------------------------------------------------- charts */
const tip = $("#tip");
function tipOn(e, html) { tip.innerHTML = html; tip.classList.add("on"); const w = tip.offsetWidth; tip.style.left = Math.min(innerWidth - w - 10, e.clientX + 14) + "px"; tip.style.top = (e.clientY + 14) + "px"; }
const tipOff = () => tip.classList.remove("on");
const NS = "http://www.w3.org/2000/svg";
const sv = (tag, attrs = {}, ...kids) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); kids.forEach(k => e.append(k)); return e; };
const niceMax = v => { const p = 10 ** Math.floor(Math.log10(v || 1)); for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * p) return m * p; return 10 * p; };
const css = n => getComputedStyle(root).getPropertyValue(n).trim();

function groupedBars(groups, series, stat, unit) {
  const W = 640, H = 300, m = { l: 50, r: 10, t: 14, b: 38 }, iw = W - m.l - m.r, ih = H - m.t - m.b;
  const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
  let max = 0; groups.forEach(g => series.forEach(s => { const v = stat(g, s); if (v) max = Math.max(max, v.mean + v.sd); }));
  max = niceMax(max * 1.06 || 1);
  for (let i = 0; i <= 4; i++) {
    const y = m.t + ih - ih * i / 4;
    svg.append(sv("line", { x1: m.l, x2: W - m.r, y1: y, y2: y, class: i ? "gridl" : "axis" }));
    const t = sv("text", { x: m.l - 8, y: y + 4, "text-anchor": "end" }); t.textContent = +(max * i / 4).toFixed(max < 10 ? 1 : 0); svg.append(t);
  }
  const yl = sv("text", { x: 12, y: m.t + ih / 2, transform: `rotate(-90 12 ${m.t + ih / 2})`, "text-anchor": "middle" }); yl.textContent = unit; svg.append(yl);
  const gw = iw / groups.length, bw = Math.min(26, gw * .8 / series.length);
  groups.forEach((g, gi) => {
    const cx = m.l + gw * (gi + .5);
    const tl = sv("text", { x: cx, y: H - 16, "text-anchor": "middle" }); tl.textContent = g.label; svg.append(tl);
    series.forEach((s, si) => {
      const v = stat(g, s); if (!v) return;
      const x = cx + (si - (series.length - 1) / 2) * (bw + 3) - bw / 2, hh = ih * v.mean / max, y = m.t + ih - hh;
      const r = sv("rect", { x, y, width: bw, height: Math.max(hh, 1), rx: 3, fill: css("--" + s.color), class: "bar" });
      r.onmousemove = e => tipOn(e, `<b>${s.label}</b><br>${g.label}<br>${fmt(v.mean, v.mean < 10 ? 2 : 1)} ± ${fmt(v.sd, 2)} ${unit}<br>${v.runs} runs · n=${v.n}${v.p95 != null ? `<br>p95 ${fmt(v.p95)} · max ${fmt(v.max)}` : ""}`);
      r.onmouseleave = tipOff; svg.append(r);
      if (v.sd) { const ex = x + bw / 2, y1 = m.t + ih - ih * (v.mean + v.sd) / max, y2 = m.t + ih - ih * Math.max(0, v.mean - v.sd) / max;
        svg.append(sv("line", { x1: ex, x2: ex, y1, y2, stroke: css("--text"), "stroke-width": 1.2, opacity: .75 }), sv("line", { x1: ex - 3, x2: ex + 3, y1, y2: y1, stroke: css("--text"), "stroke-width": 1.2, opacity: .75 })); }
    });
  });
  return svg;
}
const legendRow = series => h("div", { class: "legendrow" }, series.map(s => h("span", {}, h("i", { style: `background:var(--${s.color})` }), s.label)));

/* ----------------------------------------------------------------- experiments */
let RES = null, expState = { sweep: "A", hmetric: "tls_ms", payload: "64" };
async function loadExperiments() { RES = RES || await api("/api/results"); drawExperiments(); }
function drawExperiments() {
  if (!RES || !lazy.experiments) return;
  const body = $("#expBody"), ban = $("#expBanner"); body.replaceChildren(); ban.replaceChildren();
  if (!RES.summary) { ban.append(h("div", { class: "banner" }, h("b", {}, "No results yet"), h("span", {}, "Run  sudo python3 -m bench.run_experiments --env netns  inside the topology, or  python3 -m bench.run_experiments --env local --quick  for a loopback smoke test."))); return; }
  const S_ = RES.summary, meta = RES.meta || {}, H = S_.handshake, L = S_.latency, C = S_.conditions;
  const real = RES.source === "netns";
  ban.append(h("div", { class: "banner " + (real ? "real" : "sample") }, h("b", {}, real ? "Measured in the routed topology" : "Sample data · loopback emulation"),
    h("span", {}, real ? `${meta.runs ?? "?"} runs × ${meta.conns ?? "?"} connections / ${meta.msgs ?? "?"} messages per condition · kernel ${meta.kernel ?? "?"} · ${meta.openssl ?? ""}`
      : "These numbers come from a user-space delay emulator on loopback (no packet loss, TCP connect not delayed). They show the pipeline and the shape of the results; official numbers come from  sudo python3 -m bench.run_experiments --env netns.")));
  // ---- KPIs
  const pick = C.filter(c => c.loss_pct === 0).sort((a, b) => b.rtt_ms - a.rtt_ms)[0], low = C.filter(c => c.loss_pct === 0).sort((a, b) => a.rtt_ms - b.rtt_ms)[0];
  const rt = (cid, cfg, rtt) => { const s = H[cid]?.[cfg]?.tls_ms; return s ? s.mean / rtt : null; };
  const kp = [];
  if (pick) {
    kp.push(["TLS 1.2 handshake", fmt(rt(pick.id, "tls12", pick.rtt_ms), 1) + " RTT", `${fmt(H[pick.id]?.tls12?.tls_ms?.mean)} ms at ${pick.rtt_ms} ms RTT`, "pt"]);
    kp.push(["TLS 1.3 full", fmt(rt(pick.id, "tls13", pick.rtt_ms), 1) + " RTT", `${fmt(H[pick.id]?.tls13?.tls_ms?.mean)} ms: one round trip`, "tls"]);
    kp.push(["TLS 1.3 resumed", fmt(rt(pick.id, "tls13_resumed", pick.rtt_ms), 1) + " RTT", "same round trips, fewer bytes (no certificate)", "good"]);
  }
  if (low) { const a = L[low.id]?.e2ee?.["64"], b = L[low.id]?.tls?.["64"]; if (a && b) kp.push(["E2EE cost per message", (a.mean >= b.mean ? "+" : "−") + fmt(Math.abs(a.mean - b.mean), 2) + " ms", `64 B at ${low.rtt_ms} ms RTT: NaCl Box seal+open, +40 B`, "e"]); }
  if (kp.length) body.append(h("div", { class: "kpis" }, kp.map(([k, v, t, c]) => h("div", { class: "card kpi " + c }, h("div", { class: "k" }, k), h("div", { class: "v" }, v), h("div", { class: "t" }, t)))));
  // ---- charts
  const sweepOf = k => C.filter(c => c.sweep.includes(k)).sort((a, b) => (a.rtt_ms - b.rtt_ms) || (a.loss_pct - b.loss_pct));
  const sw = sweepOf(expState.sweep).length ? expState.sweep : (sweepOf("A").length ? "A" : "B");
  const groups = sweepOf(sw).map(c => ({ id: c.id, label: sw === "A" ? `${c.rtt_ms} ms` : `${c.loss_pct}% loss` }));
  const ctl = (opts, cur, set) => h("div", { class: "ctl" }, opts.map(([k, l]) => h("button", { class: k === cur ? "on" : "", onclick: () => { set(k); drawExperiments(); } }, l)));
  const hsSeries = [{ key: "tcp", label: "Plain TCP", color: "tcpip" }, { key: "tls12", label: "TLS 1.2", color: "pt" }, { key: "tls13", label: "TLS 1.3", color: "tls" }, { key: "tls13_resumed", label: "TLS 1.3 resumed", color: "e2ee" }]
    .filter(s => expState.hmetric !== "tls_ms" || s.key !== "tcp");
  const latSeries = [{ key: "tcp", label: "Plain TCP", color: "tcpip" }, { key: "tls", label: "TLS only", color: "tls" }, { key: "e2ee", label: "TLS + E2EE", color: "e2ee" }];
  const sweepCtl = ctl([["A", "RTT sweep"], ["B", "Loss sweep"]].filter(([k]) => sweepOf(k).length), sw, k => expState.sweep = k);
  const c1 = h("div", { class: "card chartbox" }, h("h4", {}, "Handshake", h("span", { style: "display:flex;gap:8px" }, sweepCtl, ctl([["tls_ms", "TLS time"], ["ttfd_ms", "first data"], ["tcp_ms", "TCP connect"]], expState.hmetric, k => expState.hmetric = k))));
  c1.append(groupedBars(groups, hsSeries, (g, s) => H[g.id]?.[s.key]?.[expState.hmetric], "ms"), legendRow(hsSeries));
  const c2 = h("div", { class: "card chartbox" }, h("h4", {}, "Message latency A → relay → B", ctl([["64", "64 B"], ["1024", "1 KiB"], ["16384", "16 KiB"]], expState.payload, k => expState.payload = k)));
  c2.append(groupedBars(groups, latSeries, (g, s) => L[g.id]?.[s.key]?.[expState.payload], "ms"), legendRow(latSeries));
  body.append(h("div", { class: "charts" }, c1, c2));
  // ---- tables
  const pm = s => s ? h("span", {}, fmt(s.mean, s.mean < 10 ? 2 : 1), h("span", { class: "pm" }, " ± " + fmt(s.sd, 2))) : "–";
  const thead = cols => h("thead", {}, h("tr", {}, cols.map(c => h("th", {}, c))));
  const ht = h("tbody"), lt = h("tbody");
  for (const c of C) for (const cfg of ["tcp", "tls12", "tls13", "tls13_resumed"]) { const e = H[c.id]?.[cfg]; if (!e) continue;
    ht.append(h("tr", {}, h("td", {}, c.id), h("td", {}, S_.meta.labels[cfg]), h("td", { class: "num" }, pm(e.tcp_ms)), h("td", { class: "num" }, cfg === "tcp" ? "–" : pm(e.tls_ms)), h("td", { class: "num" }, pm(e.ttfd_ms)), h("td", { class: "num" }, e.tls_ms?.runs ?? "–"), h("td", { class: "num" }, e.connections), h("td", { class: "num" }, e.errors))); }
  for (const c of C) for (const mode of ["tcp", "tls", "e2ee"]) for (const pl of S_.meta.payloads) { const e = L[c.id]?.[mode]?.[pl]; if (!e) continue;
    lt.append(h("tr", {}, h("td", {}, c.id), h("td", {}, S_.meta.labels[mode]), h("td", { class: "num" }, pl), h("td", { class: "num" }, pm(e)), h("td", { class: "num" }, fmt(e.median, 2)), h("td", { class: "num" }, fmt(e.p95, 2)), h("td", { class: "num" }, fmt(e.max, 1)), h("td", { class: "num" }, e.wire_body_bytes), h("td", { class: "num" }, e.runs))); }
  body.append(h("div", { class: "charts" },
    h("div", { class: "card" }, h("h4", {}, "Handshake table (ms, mean ± σ across runs)"), h("div", { class: "tablewrap" }, h("table", { class: "tbl mono" }, thead(["condition", "config", "TCP", "TLS", "first data", "runs", "conns", "err"]), ht))),
    h("div", { class: "card" }, h("h4", {}, "Message-latency table (ms)"), h("div", { class: "tablewrap" }, h("table", { class: "tbl mono" }, thead(["condition", "mode", "payload B", "mean ± σ", "median", "p95", "max", "body B", "runs"]), lt)))));
  const ov = Object.entries(RES.overhead || {}).filter(([, v]) => v && v.length);
  if (ov.length) body.append(h("div", { class: "card", style: "margin-bottom:16px" }, h("h4", {}, "Byte overhead from packet captures"), h("div", { class: "tablewrap" }, h("table", { class: "tbl mono" }, thead(["capture", "TLS", "resumed", "ClientHello B", "ServerHello B", "handshake →srv B", "handshake ←srv B"]),
    h("tbody", {}, ov.map(([k, v]) => { const t = v[0].tls || {}; return h("tr", {}, h("td", {}, k), h("td", {}, t.version), h("td", {}, String(t.resumed)), h("td", { class: "num" }, t.client_hello?.wire), h("td", { class: "num" }, t.server_hello?.wire), h("td", { class: "num" }, t.handshake_bytes?.c2s), h("td", { class: "num" }, t.handshake_bytes?.s2c)); }))))));
}

/* ----------------------------------------------------------------- attacks */
const ATK = {
  untrusted_cert: ["Forged certificate on the path", "An on-path attacker redirects the relay port to a proxy with a certificate signed by its own CA."],
  key_substitution: ["Malicious relay swaps Bob's key · pinned", "The relay answers Alice's lookup with its own key. Alice pinned Bob's fingerprint out-of-band."],
  key_substitution_unpinned: ["Malicious relay swaps Bob's key · not pinned", "Same attack, nobody compares fingerprints: the relay silently reads and re-encrypts everything."],
  tampering: ["Ciphertext tampering", "One byte of the NaCl Box ciphertext is flipped. Poly1305 must reject it."],
  mitm_trusted_tls: ["Rogue CA trusted · TLS only", "If TLS is the only protection and the victim trusts the attacker's CA, the attacker reads every message."],
  mitm_trusted_e2ee: ["Rogue CA trusted · TLS + E2EE", "Same worst case, but the content is end-to-end encrypted: the attacker sees only ciphertext."],
  eavesdropper: ["Passive eavesdropper", "A tap on the link parses all three modes with no keys: plain TCP leaks, TLS and E2EE do not."],
};
async function loadAttacks() {
  const grid = $("#attackGrid"); grid.replaceChildren();
  const run = async (id, card) => {
    const btn = $(".run", card); btn.disabled = true; btn.replaceChildren(h("span", { class: "spin" }), "Running");
    const r = await api("/api/attack/" + id, {});
    btn.disabled = false; btn.textContent = "Run again";
    const res = $(".res", card); res.replaceChildren(r.error ? h("div", { class: "obs2" }, r.error) : h("div", {},
      h("span", { class: "verd " + (r.passed ? "pass" : "fail") }, r.passed ? "AS EXPECTED" : "UNEXPECTED"),
      h("p", {}, h("b", {}, "Expected: "), r.expected), h("ul", { class: "tl" }, r.timeline.map(t => h("li", {}, t))), h("div", { class: "obs2" }, h("b", {}, "Observed: "), r.observed)));
    card.classList.add("done"); return r;
  };
  const cards = Object.entries(ATK).map(([id, [t, d]]) => {
    const c = h("article", { class: "card atk", "data-id": id }, h("header", {}, h("div", {}, h("h3", {}, t), h("p", {}, d)), h("button", { class: "ghost run", onclick: () => run(id, c) }, "Run")), h("div", { class: "res" }));
    return c;
  });
  grid.append(...cards);
  $("#runAll").onclick = async () => { $("#runAll").disabled = true; for (const c of cards) await run(c.dataset.id, c); $("#runAll").disabled = false; };
}

/* ----------------------------------------------------------------- evidence */
const CAPS = [
  ["TCP three-way handshake", "tcp_handshake"], ["TLS 1.3 full handshake (decrypt with keylog)", "tls13_full"], ["TLS 1.2 handshake (comparison)", "tls12_handshake"],
  ["TLS 1.3 resumed handshake (no Certificate)", "tls13_resumed"], ["Key registration + lookup, one E2EE message relayed", "e2ee_transit"], ["Relay-side view: ciphertext only", "e2ee_relay_side"],
  ["Routing proof: traceroute / ICMP TTL exceeded", "routing_traceroute"], ["Untrusted-certificate rejection", "untrusted_cert_rejection"], ["Substituted key / fingerprint mismatch", "keyswap_fingerprint_mismatch"],
];
const DEMO = [
  ["Prove the routed topology", "ip netns list, routing tables on R1/R2, one traceroute from Client A to the relay"],
  ["Exchange messages in both directions", "relay + both clients in their namespaces; Live lab shows the same flow"],
  ["Show the decrypted capture in Wireshark", "relay sees only E2EE ciphertext; the wire shows TLS 1.3 application-data records (type 23)"],
  ["Apply a delay live", "scripts/impair.sh set --rtt-ms 100, then run bench.probe tls13: the handshake time jumps"],
  ["Security demos", "bash scripts/attack_demo.sh all: forged certificate refused, substituted key caught by fingerprint"],
];
async function loadEvidence() {
  const ev = await api("/api/evidence"), body = $("#evBody"); body.replaceChildren();
  const have = n => { const f = (ev["evidence/captures"] || []).find(x => x.startsWith(n + ".pcap")); return f; };
  const li = ([label, name]) => { const f = have(name); return h("li", { class: f ? "have" : "" }, h("span", { class: "s" }, f ? "✓" : ""), h("div", {}, label, h("small", {}, name + ".pcapng")), f ? h("a", { href: "/files/evidence/captures/" + f, download: f }, "download") : h("span", { class: "dim mono" }, "not captured yet")); };
  const done = store.get("demo", []);
  const demo = h("ol", { class: "check demo" }, DEMO.map(([t, d], i) => h("li", { class: done.includes(i) ? "done" : "", onclick: e => { const s = new Set(store.get("demo", [])); s.has(i) ? s.delete(i) : s.add(i); store.set("demo", [...s]); e.currentTarget.classList.toggle("done"); } }, h("div", {}, h("b", {}, t), h("span", {}, d)))));
  const plots = [...(ev["results/plots"] || []).map(f => "results/plots/" + f), ...((ev["results/plots"] || []).length ? [] : (ev["results/sample_loopback/plots"] || []).map(f => "results/sample_loopback/plots/" + f))];
  const docs = ["README.md", "REPORT.md", "ARCHITECTURE.md", "DEMO_SCRIPT.md", "AI_USE_DISCLOSURE.md", "architecture.svg"];
  body.append(h("div", { class: "ev" },
    h("div", { style: "display:grid;gap:16px" },
      h("div", { class: "card" }, h("h4", {}, "Required captures (9)"), h("ul", { class: "check" }, CAPS.map(li))),
      h("div", { class: "card" }, h("h4", {}, "Other evidence files"), h("ul", { class: "check" }, (ev.evidence || []).filter(f => /\.(txt|log)$/.test(f)).map(f => h("li", { class: "have" }, h("span", { class: "s" }, "✓"), h("div", {}, f), h("a", { href: "/files/evidence/" + f }, "open"))))
        , (ev.evidence || []).filter(f => /\.(txt|log)$/.test(f)).length ? null : h("div", { class: "empty" }, "routing_tables.txt and traceroute output appear here after scripts/run_all.sh."))),
    h("div", { style: "display:grid;gap:16px" },
      h("div", { class: "card" }, h("h4", {}, "Five-minute demo script", h("small", {}, "click to tick off")), demo),
      h("div", { class: "card" }, h("h4", {}, "Documents"), h("div", { class: "docs" }, docs.map(d => h("a", { href: d === "README.md" ? "/files/README.md" : "/files/docs/" + d, target: "_blank" }, d)))))));
  if (plots.length) body.append(h("div", { class: "card", style: "margin-top:16px" }, h("h4", {}, "Figures"), h("div", { class: "gallery" }, plots.map(p => h("a", { href: "/files/" + p, target: "_blank" }, h("img", { src: "/files/" + p, alt: p, loading: "lazy" }))))));
}

/* ----------------------------------------------------------------- boot */
(async function boot() {
  const st = await api("/api/state"); applyState(st); connectSSE();
  const v = location.hash.slice(1); show(["lab", "topology", "experiments", "attacks", "evidence"].includes(v) ? v : "lab");
})();
