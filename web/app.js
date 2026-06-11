(function () {
  const $ = (id) => document.getElementById(id);
  const form = $("scanform");
  const urlInput = $("url");
  const authBox = $("authorized");
  const crawlBox = $("crawl");
  const goBtn = $("go");

  let current = null;   // último reporte renderizado
  let history = [];     // resúmenes del historial

  loadHistory();

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;
    if (!authBox.checked) {
      return showMsg("Marcá la casilla: solo escaneá sitios propios o autorizados.", "warn");
    }
    runScan(url);
  });

  $("exp-html").addEventListener("click", exportHTML);
  $("exp-pdf").addEventListener("click", () => window.print());

  async function runScan(url) {
    const pentest = $("pentest").checked;
    showMsg("", null, true);
    setLoading(true, url, pentest);
    const cookie = $("cookie").value.trim() || undefined;
    const body = pentest
      ? { url, authorized: true, mode: "pentest", lab: $("lab").checked, cookie }
      : { url, authorized: true, crawl: $("crawl").checked, tier: $("profile").value, cookie };
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setLoading(false);
        return showMsg(data.error || `Error ${res.status}`, "err");
      }
      const prev = lastFor(data.target);
      render(data, prev);
      loadHistory();
    } catch (err) {
      setLoading(false);
      showMsg("No se pudo contactar el servidor local: " + err.message, "err");
    }
  }

  async function loadHistory() {
    try {
      const res = await fetch("/api/history");
      history = await res.json();
    } catch { history = []; }
    renderHistory();
  }

  function lastFor(target) {
    return history.find((h) => h.target === target) || null;
  }

  function renderHistory() {
    const box = $("history");
    $("histcount").textContent = history.length ? `${history.length}` : "";
    box.innerHTML = "";
    if (!history.length) {
      box.innerHTML = `<p class="dim hist-empty">Todavía no escaneaste nada.</p>`;
      return;
    }
    history.forEach((h) => {
      const el = document.createElement("button");
      el.className = "hist-item";
      el.innerHTML = `
        <span class="hist-grade g-${h.grade}">${h.grade}</span>
        <span class="hist-meta">
          <span class="hist-target">${esc(shortHost(h.target))}</span>
          <span class="hist-date mono">${esc(h.scanned_at)}${h.pages > 1 ? " · " + h.pages + "p" : ""}</span>
        </span>`;
      el.addEventListener("click", () => openScan(h.id));
      box.appendChild(el);
    });
  }

  async function openScan(id) {
    try {
      const res = await fetch("/api/scan/" + id);
      const data = await res.json();
      if (data.error) return showMsg(data.error, "err");
      render(data, lastForExcluding(data.target, id));
    } catch (err) {
      showMsg("No se pudo abrir el escaneo: " + err.message, "err");
    }
  }

  function lastForExcluding(target, id) {
    return history.find((h) => h.target === target && h.id !== id) || null;
  }

  function setLoading(on, url, pentest) {
    $("loading").hidden = !on;
    goBtn.disabled = on;
    goBtn.textContent = on ? (pentest ? "Pentesteando…" : "Escaneando…") : "Escanear";
    if (on) {
      $("empty").hidden = true;
      $("result").hidden = true;
      $("loadtxt").textContent = pentest
        ? "pentesteando " + url + " — puede tardar unos segundos…"
        : "escaneando " + url + " …";
    }
  }

  function showMsg(text, kind, hide) {
    const m = $("msg");
    if (hide || !text) { m.hidden = true; return; }
    m.hidden = false;
    m.textContent = text;
    m.className = "msg " + (kind || "");
  }

  function render(R, prev) {
    current = R;
    setLoading(false);
    $("empty").hidden = true;
    $("result").hidden = false;

    $("target").textContent = R.target;
    $("scanned").textContent = R.scanned_at;

    const np = (R.pages || []).length;
    $("pages").textContent = np > 1 ? `${np} páginas escaneadas` : "";

    const g = $("grade");
    if (R.reachable === false) {
      g.textContent = "—";
      g.className = "grade g-na";
      $("score").textContent = "N/A";
    } else {
      g.textContent = R.grade;
      g.className = "grade g-" + R.grade;
      $("score").textContent = R.score;
    }

    renderNotice(R);
    renderAgent(R);
    renderDelta(R, prev);
    renderProfile(R);

    const labels = { critical: "crit", high: "high", medium: "med", low: "low" };
    const counts = $("counts");
    counts.innerHTML = "";
    let any = false;
    ["critical", "high", "medium", "low"].forEach((sev) => {
      const n = R.counts[sev] || 0;
      if (!n) return;
      any = true;
      const chip = document.createElement("span");
      chip.className = "chip " + labels[sev];
      chip.innerHTML = `<b>${n}</b> ${sevName(sev)}`;
      counts.appendChild(chip);
    });
    if (!any) counts.innerHTML = `<span class="chip" style="color:var(--green)">sin problemas detectados</span>`;

    const fails = R.findings.filter((f) => !f.passed);
    const passes = R.findings.filter((f) => f.passed);
    const multi = np > 1;

    const list = $("list");
    list.innerHTML = "";
    if (!fails.length) list.innerHTML = `<p class="dim">Ningún hallazgo. Pasó todos los chequeos. ✓</p>`;
    fails.forEach((f) => list.appendChild(card(f, R.target, multi)));

    $("passcount").textContent = `(${passes.length})`;
    const pw = $("passed");
    pw.innerHTML = "";
    passes.forEach((f) => {
      const el = document.createElement("span");
      el.className = "pass-item";
      el.textContent = f.title;
      pw.appendChild(el);
    });

    $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderDelta(R, prev) {
    const d = $("delta");
    if (R.reachable === false || !prev || (prev.score === R.score && prev.grade === R.grade)) {
      d.hidden = true; return;
    }
    const diff = R.score - prev.score;
    const up = diff > 0;
    d.hidden = false;
    d.className = "delta " + (up ? "up" : "down");
    d.innerHTML = `Antes: <b class="g-${prev.grade}">${prev.grade}</b> ${prev.score} `
      + `<span class="arrow">→</span> ahora: <b class="g-${R.grade}">${R.grade}</b> ${R.score} `
      + `<span class="diff">(${up ? "+" : ""}${diff})</span>`;
  }

  function renderAgent(R) {
    const b = $("agent-banner");
    if (R.kind !== "agent") { b.hidden = true; return; }
    b.hidden = false;
    const u = R.usage || {};
    const risk = R.overall_risk || "—";
    const local = R.provider === "engine" || R.provider === "ollama";
    const tag = R.provider === "engine" ? "🛡 PENTEST AUTOMÁTICO" : "🛡 PENTEST CON IA";
    const usage = local
      ? "local · gratis · sin dependencias"
      : `${u.input_tokens || 0}↓ ${u.output_tokens || 0}↑ tokens · ~USD ${u.est_cost_usd ?? 0}`;
    b.innerHTML = `
      <div class="ab-top">
        <span class="ab-tag">${tag}</span>
        <span class="ab-meta mono">${esc(R.model || "")} · ${R.steps || 0} pasos · riesgo ${esc(risk)}</span>
      </div>
      ${R.summary ? `<div class="ab-summary">${esc(R.summary)}</div>` : ""}
      <div class="ab-usage mono">${usage}</div>`;
  }

  function renderNotice(R) {
    const n = $("notice");
    if (!R.notice) { n.hidden = true; return; }
    n.hidden = false;
    const sev = (R.http_status >= 400 || R.http_status < 200) ? "err" : "warn";
    n.className = "notice-banner " + sev;
    n.innerHTML = `<span class="nb-code mono">HTTP ${R.http_status}</span><span>${esc(R.notice)}</span>`;
  }

  function renderProfile(R) {
    const b = $("profile-banner");
    const p = R.profile;
    if (!p || p.tier === undefined) { b.hidden = true; return; }
    b.hidden = false;
    b.className = "profile-banner t" + p.tier;
    const tag = p.auto ? "detectado" : "manual";
    b.innerHTML = `
      <div class="pb-top">
        <span class="pb-label">${esc(p.label)}</span>
        <span class="pb-demand">exigencia ${esc(p.demand)}</span>
        <span class="pb-tag mono">${tag}</span>
      </div>
      <div class="pb-note">${esc(p.note)}</div>
      <div class="pb-signals mono">señales: ${esc((p.signals || []).join(" · "))}</div>`;
  }

  function card(f, target, multi) {
    const el = document.createElement("div");
    el.className = "finding s-" + f.severity;
    const pageBadge = (multi && f.page && f.page !== target)
      ? `<span class="finding-page mono">${esc(pathOf(f.page))}</span>` : "";
    el.innerHTML = `
      <div class="finding-head">
        <span class="sev s-${f.severity}">${f.severity.toUpperCase()}</span>
        <span class="finding-title">${esc(f.title)}</span>
        ${pageBadge}
        <span class="finding-cat">${esc(f.category)}</span>
        <span class="caret">▶</span>
      </div>
      <div class="finding-body"><div class="finding-body-inner">
        ${f.evidence ? `<div class="evidence">${esc(f.evidence)}</div>` : ""}
        ${f.remediation ? `<div class="fix"><b>Cómo arreglarlo:</b> ${esc(f.remediation)}</div>` : ""}
      </div></div>`;
    el.querySelector(".finding-head").addEventListener("click", () => el.classList.toggle("open"));
    return el;
  }

  // ── exportar informe HTML autocontenido ──────────────────────────
  function exportHTML() {
    if (!current) return;
    const R = current;
    const rows = R.findings.map((f) => `
      <tr class="${f.passed ? 'ok' : 's-' + f.severity}">
        <td>${f.passed ? '✓ OK' : f.severity.toUpperCase()}</td>
        <td><b>${esc(f.title)}</b>${f.evidence ? `<br><code>${esc(f.evidence)}</code>` : ""}
            ${!f.passed && f.remediation ? `<br><i>${esc(f.remediation)}</i>` : ""}</td>
        <td>${esc(f.category)}</td>
      </tr>`).join("");
    const html = `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Informe Centinela — ${esc(R.target)}</title><style>
body{font-family:system-ui,Arial,sans-serif;max-width:820px;margin:40px auto;padding:0 20px;color:#111}
h1{font-size:20px}.grade{font-size:64px;font-weight:800}
.A,.B{color:#1a7f37}.C,.D{color:#9a6700}.E,.F{color:#cf222e}
table{width:100%;border-collapse:collapse;margin-top:20px;font-size:14px}
td,th{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}
code{background:#f3f3f3;padding:1px 4px;border-radius:3px;font-size:12px}
.s-critical td:first-child{color:#cf222e;font-weight:700}.s-high td:first-child{color:#bc4c00;font-weight:700}
.s-medium td:first-child{color:#9a6700}.ok td:first-child{color:#1a7f37}
.muted{color:#666;font-size:13px}</style></head><body>
<h1>Informe de seguridad — Centinela</h1>
<p class="muted">${esc(R.target)} · ${esc(R.scanned_at)} · ${(R.pages||[]).length} página(s)${R.profile && R.profile.label ? " · perfil: " + esc(R.profile.label) + " (exigencia " + esc(R.profile.demand) + ")" : ""}</p>
<div class="grade ${R.grade}">${R.grade} <span style="font-size:22px;color:#111">${R.score}/100</span></div>
<p>${R.counts.critical} críticas · ${R.counts.high} altas · ${R.counts.medium} medias · ${R.counts.low} bajas</p>
<table><thead><tr><th>Severidad</th><th>Hallazgo</th><th>Categoría</th></tr></thead><tbody>${rows}</tbody></table>
<p class="muted">Generado por Centinela · uso ético — solo sitios propios o autorizados</p>
</body></html>`;
    const blob = new Blob([html], { type: "text/html" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "centinela-" + shortHost(R.target).replace(/[^a-z0-9]/gi, "_") + ".html";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function sevName(s) {
    return { critical: "críticas", high: "altas", medium: "medias", low: "bajas" }[s] || s;
  }
  function shortHost(u) { try { return new URL(u).host; } catch { return u; } }
  function pathOf(u) { try { const x = new URL(u); return x.pathname + x.search || "/"; } catch { return u; } }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  // ── Panel de Protección ─────────────────────────────────────────
  const SEV_ICON = { critical: "🔴", high: "🟠", medium: "🟡", low: "⚪", info: "⚪" };
  const ST_ICON = { open: "🔴", acknowledged: "👀", false_positive: "🚫",
                    accepted_risk: "🟡", fixed: "✅" };
  const ST_OPTS = ["open", "acknowledged", "false_positive", "accepted_risk", "fixed"];

  document.querySelectorAll(".tab").forEach((t) => {
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      const v = t.dataset.view;
      $("view-scan").hidden = v !== "scan";
      $("view-protect").hidden = v !== "protect";
      if (v === "protect") loadProtect();
    });
  });

  async function jget(u) { const r = await fetch(u); return r.ok ? r.json() : null; }

  function loadProtect() {
    loadVulns(); loadAssets(); loadAlerts();
  }
  $("vulns-refresh").addEventListener("click", loadVulns);
  $("vf-status").addEventListener("change", loadVulns);
  $("vf-sev").addEventListener("change", loadVulns);

  async function loadVulns() {
    const st = $("vf-status").value, sv = $("vf-sev").value;
    const s = await jget("/api/vulns/stats");
    if (s) renderStats(s);
    const q = new URLSearchParams();
    if (st) q.set("status", st);
    if (sv) q.set("severity", sv);
    const list = await jget("/api/vulns?" + q.toString());
    renderVulns(list || []);
  }

  function renderStats(s) {
    const bs = s.by_status, ob = s.open_by_severity;
    $("prot-stats").innerHTML = `
      <div class="stat big"><div class="n">${s.open_risk_score}</div><div class="l">puntaje de riesgo</div></div>
      <div class="stat"><div class="n">${bs.open}</div><div class="l">🔴 abiertas</div></div>
      <div class="stat"><div class="n">${bs.acknowledged}</div><div class="l">👀 reconocidas</div></div>
      <div class="stat"><div class="n">${bs.fixed}</div><div class="l">✅ arregladas</div></div>
      <div class="stat"><div class="n">${bs.false_positive + bs.accepted_risk}</div><div class="l">🚫 silenciadas</div></div>
      <div class="stat"><div class="l">abiertas:</div><div class="sevline">
        <b style="color:#f85149">${ob.critical}</b>c · <b style="color:#ff8c42">${ob.high}</b>a ·
        <b style="color:#d29922">${ob.medium}</b>m · <span class="dim">${ob.low}b</span></div></div>`;
  }

  function renderVulns(list) {
    const box = $("vulns-list");
    if (!list.length) { box.innerHTML = `<p class="dim">Sin vulnerabilidades. Escaneá algo primero.</p>`; return; }
    box.innerHTML = "";
    list.forEach((v) => {
      const row = document.createElement("div");
      row.className = "vrow";
      const opts = ST_OPTS.map((o) =>
        `<option value="${o}" ${o === v.status ? "selected" : ""}>${ST_ICON[o]} ${o}</option>`).join("");
      row.innerHTML = `
        <div class="vmain">
          <span class="vsev">${SEV_ICON[v.severity] || "⚪"}</span>
          <div class="vtxt"><div class="vtitle">${esc(v.title)}</div>
            <div class="vmeta mono">${esc(v.host)} · ${esc(v.owasp || v.category)} · visto ${v.times_seen}x</div></div>
        </div>
        <div class="vactions">
          <input class="vassign mono" placeholder="responsable" value="${esc(v.assignee || "")}" />
          <select class="vstatus mono">${opts}</select>
        </div>`;
      row.querySelector(".vstatus").addEventListener("change", (e) =>
        updateVuln(v.key, { status: e.target.value }));
      const ai = row.querySelector(".vassign");
      ai.addEventListener("change", () => updateVuln(v.key, { assignee: ai.value }));
      box.appendChild(row);
    });
  }

  async function updateVuln(key, patch) {
    await fetch("/api/vulns/" + key, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    loadVulns();
  }

  async function loadAssets() {
    const list = await jget("/api/assets") || [];
    const box = $("assets-list");
    if (!list.length) { box.innerHTML = `<p class="dim">Ningún sitio en vigilancia.</p>`; return; }
    box.innerHTML = "";
    list.forEach((a) => {
      const el = document.createElement("div");
      el.className = "arow";
      el.innerHTML = `<span class="atxt mono">${esc(a.url)} <span class="dim">[${a.mode}] cada ${a.interval}m</span></span>
        <button class="ghost arm" type="button">✕</button>`;
      el.querySelector(".arm").addEventListener("click", async () => {
        await fetch("/api/assets?url=" + encodeURIComponent(a.url), { method: "DELETE" });
        loadAssets();
      });
      box.appendChild(el);
    });
  }

  $("asset-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = $("asset-url").value.trim();
    if (!url) return;
    await fetch("/api/assets", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, interval: parseInt($("asset-int").value) || 60,
        mode: $("asset-pentest").checked ? "pentest" : "scan" }),
    });
    $("asset-url").value = "";
    loadAssets();
  });

  $("guard-run").addEventListener("click", async () => {
    const b = $("guard-run");
    b.disabled = true; b.textContent = "corriendo…";
    const r = await fetch("/api/guard/run", { method: "POST" });
    const d = await r.json().catch(() => ({}));
    b.disabled = false; b.textContent = "▶ Correr guardián ahora";
    loadAlerts(); loadVulns();
    if (d.alerts) alert(d.alerts.length ? d.alerts.length + " alerta(s) nueva(s)" : "Todo en orden 🛡");
  });

  async function loadAlerts() {
    const list = await jget("/api/alerts") || [];
    const box = $("alerts-list");
    if (!list.length) { box.innerHTML = `<p class="dim">Sin alertas.</p>`; return; }
    box.innerHTML = "";
    list.slice(0, 20).forEach((a) => {
      const el = document.createElement("div");
      el.className = "alrow s-" + a.severity;
      el.innerHTML = `<span class="alsev">${SEV_ICON[a.severity] || "⚪"}</span>
        <div><div>${esc(a.title)}</div>
        <div class="dim mono">${esc((a.target || "").replace(/^https?:\/\//, ""))} · ${esc(a.ts)}</div></div>`;
      box.appendChild(el);
    });
  }
})();
