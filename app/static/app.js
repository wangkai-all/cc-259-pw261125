"use strict";

const state = {
  meta: null,
  principal: null,
  query: null,        // query_view from server
  page: 0,
  cursor: null,
  pageSize: 8,
  deliveredPages: [], // client-side summary of pages received this session
  download: null,
  activeTab: "plan",
  pageNotice: "",
  authModeDefault: "recheck",
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function esc(v) {
  return String(v ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}
function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("zh-CN", { hour12: false }) + "." +
    String(d.getMilliseconds()).padStart(3, "0");
}
function fmtNum(n) {
  if (n === null || n === undefined) return "—";
  if (typeof n !== "number") return String(n);
  return n.toLocaleString("en-US");
}
function toast(msg, bad = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast" + (bad ? " bad" : "");
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 3200);
}

async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (state.principal) headers["X-Principal"] = state.principal;
  const res = await fetch(path, { ...opts, headers });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error((body.error && body.error.reason) || res.statusText);
    err.code = body.error && body.error.code;
    err.detail = body.error && body.error.detail;
    err.status = res.status;
    throw err;
  }
  return body;
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function boot() {
  state.meta = await api("/api/meta");
  const sel = $("#principal");
  sel.innerHTML = state.meta.principals.map(p =>
    `<option value="${esc(p.principal_id)}">${esc(p.display_name)} · ${esc(p.team)}</option>`
  ).join("");
  const saved = localStorage.getItem("shan-principal");
  if (saved && state.meta.principals.some(p => p.principal_id === saved)) sel.value = saved;
  else if (state.meta.principals.some(p => p.role === "admin")) {
    sel.value = state.meta.principals.find(p => p.role === "admin").principal_id;
  }
  state.principal = sel.value;
  sel.addEventListener("change", async () => {
    state.principal = sel.value;
    localStorage.setItem("shan-principal", state.principal);
    state.query = null;
    state.page = 0; state.cursor = null; state.download = null;
    state.deliveredPages = []; state.pageNotice = "";
    $("#queryPanel").hidden = true;
    $("#scenarioResult")?.remove();
    renderQueryForm();
    await refreshAll();
  });
  renderPolicy();
  renderQueryForm();
  bindEvents();
  await refreshAll();
}

function principalInfo() {
  return state.meta.principals.find(p => p.principal_id === state.principal) || {};
}

function keepLiveGrants(grants) {
  // /api/meta embeds a launch-time grant; /api/grants is authoritative.
  for (const p of state.meta.principals) {
    const latest = grants
      .filter(g => g.principal_id === p.principal_id && g.status === "active")
      .sort((a, b) => b.version - a.version)[0];
    if (latest) {
      p.grant = {
        version: latest.version, digest: latest.digest,
        columns: latest.columns, organizations: latest.organizations,
        note: latest.note, granted_at: latest.created_at,
      };
    }
  }
}

async function refreshAll() {
  const [grantRes, auditRes, denialRes, cacheRes] = await Promise.all([
    api("/api/grants"),
    api("/api/audit?limit=50"),
    api("/api/denials"),
    api("/api/cache"),
  ]);
  keepLiveGrants(grantRes.grants);
  renderGrant(grantRes.grants);
  renderGrantHistory(grantRes.grants);
  renderAudit(auditRes.events);
  renderDenials(denialRes.denials);
  renderCache(cacheRes.entries);
  renderLedger();
  renderQueryForm();
  const badge = $("#roleBadge");
  const role = principalInfo().role || "analyst";
  badge.textContent = role === "admin" ? "管理员" : "分析员";
  badge.className = "badge " + (role === "admin" ? "warn" : "ok");
  $("#grantEditor").hidden = role !== "admin";
  $("#scenarioBtn").disabled = role !== "admin";
  $("#scenarioBtn").title = role === "admin" ? "" : "仅管理员可运行样例";
  if (role === "admin") renderAdminForm();
}

function renderPolicy() {
  const p = state.meta.policy;
  const cards = [
    {
      key: "pinned", title: "查询启动时固定（pinned）", tag: "snapshot_pinned",
      bullets: [
        "启动时冻结授权版本，执行阶段可继续读快照",
        "撤权后引擎可能仍算出被撤行，但交付前会再检查",
        "未交付部分被扣留并给出拒绝依据",
        "已交付分页是冻结字节，永不回滚",
      ],
    },
    {
      key: "recheck", title: "每次交付重新检查（recheck）", tag: "live_intersect",
      bullets: [
        "启动时只记录交集，执行阶段读 live ∩ launch",
        "撤权在慢查询窗口内即时生效，被撤列/组织不参与执行",
        "分页与下载分块逐次复核 live grant",
        "缓存按实际作用域取键，窄授权不会命中宽缓存",
      ],
    },
  ];
  $("#policyGrid").innerHTML = cards.map(c => `
    <div class="policy-card ${state.authModeDefault === c.key ? "active" : ""}">
      <h4>${esc(c.title)}</h4>
      <span class="tag">${esc(c.tag)}</span>
      <ul>${c.bullets.map(b => `<li>${esc(b)}</li>`).join("")}</ul>
    </div>`).join("");
}

function renderGrant(grants) {
  const live = principalInfo().grant || { columns: [], organizations: [], version: null, digest: "—" };
  const mine = grants.filter(g => g.principal_id === state.principal);
  $("#grantDigestLabel").textContent = `v${live.version ?? "—"} · ${live.digest}`;
  const allCols = state.meta.columns.filter(c => !["row_key"].includes(c));
  const allOrgs = state.meta.organizations.map(o => o.id);
  const chip = (label, on) =>
    `<span class="chip ${on ? "on" : "off"}" title="${on ? "已授权" : "未授权"}">${esc(label)}</span>`;
  $("#grantProfile").innerHTML = `
    <dl class="kv">
      <dt>生效版本</dt><dd>v${live.version ?? "—"} <span class="badge">${esc(live.note || "")}</span></dd>
      <dt>版本摘要</dt><dd>${esc(live.digest || "—")}</dd>
      <dt>授权列</dt><dd><div class="chips">${allCols.map(c => chip(c, live.columns.includes(c))).join("")}</div></dd>
      <dt>授权组织</dt><dd><div class="chips">${allOrgs.map(o => chip(o, live.organizations.includes(o))).join("")}</div></dd>
      <dt>历史版本数</dt><dd>${mine.length}</dd>
    </dl>
    <p class="hint">未授权的列/组织在查询时会从请求中扣除；如果全部被扣除，启动即被拒绝并记录依据。</p>`;
}

function renderAdminForm() {
  const live = principalInfo().grant || { columns: [], organizations: [] };
  const targets = state.meta.principals;
  const allCols = state.meta.columns.filter(c => c !== "row_key");
  const allOrgs = state.meta.organizations.map(o => o.id);
  const targetSel = targets.map(p =>
    `<option value="${esc(p.principal_id)}" ${p.principal_id === "analyst-ada" ? "selected" : ""}>${esc(p.display_name)}</option>`
  ).join("");
  const build = (target) => {
    const g = (targets.find(p => p.principal_id === target) || {}).grant || { columns: [], organizations: [] };
    const colBoxes = allCols.map(c =>
      `<label><input type="checkbox" data-role="cols" value="${esc(c)}" ${g.columns.includes(c) ? "checked" : ""}> ${esc(c)}</label>`
    ).join("");
    const orgBoxes = allOrgs.map(o =>
      `<label><input type="checkbox" data-role="orgs" value="${esc(o)}" ${g.organizations.includes(o) ? "checked" : ""}> ${esc(o)}</label>`
    ).join("");
    return `
      <label class="dim small">目标主体
        <select id="grantTarget">${targetSel}</select>
      </label>
      <fieldset><legend>列</legend><div class="checks" id="grantColsBox">${colBoxes}</div></fieldset>
      <fieldset><legend>组织</legend><div class="checks" id="grantOrgsBox">${orgBoxes}</div></fieldset>
      <div class="actions">
        <button type="button" class="primary" id="publishBtn">发布新版本</button>
        <button type="button" class="ghost" id="revokeSouthBtn">撤掉 south 与 orders</button>
        <button type="button" class="ghost" id="restoreBtn">恢复完整样例授权</button>
      </div>
      <p class="hint">发布只新增版本，旧版本保留；任何已固定到旧版本的查询继续可见自己的快照。</p>`;
  };
  const container = $("#adminGrantForm");
  container.innerHTML = build("analyst-ada");
  $("#grantTarget").addEventListener("change", (e) => {
    container.innerHTML = build(e.target.value);
    wireAdminForm();
  });
  wireAdminForm();
}

function wireAdminForm() {
  const collect = () => ({
    principal_id: $("#grantTarget").value,
    columns: $$('[data-role="cols"]:checked').map(x => x.value),
    organizations: $$('[data-role="orgs"]:checked').map(x => x.value),
  });
  const publish = async (payload) => {
    try {
      const res = await api("/api/grants", { method: "POST", body: JSON.stringify(payload) });
      toast(`已发布 ${payload.principal_id} 的授权 v${res.version}`);
      await refreshAll();
    } catch (e) { toast(e.message, true); }
  };
  $("#publishBtn")?.addEventListener("click", () => publish({ ...collect(), note: "管理员手动发布" }));
  $("#revokeSouthBtn")?.addEventListener("click", async () => {
    const target = $("#grantTarget").value;
    const g = (state.meta.principals.find(p => p.principal_id === target) || {}).grant || {};
    await publish({
      principal_id: target,
      columns: (g.columns || []).filter(c => c !== "orders"),
      organizations: (g.organizations || []).filter(o => o !== "south"),
      note: "撤掉 south 与 orders",
    });
  });
  $("#restoreBtn")?.addEventListener("click", async () => {
    const target = $("#grantTarget").value;
    await publish({
      principal_id: target,
      columns: ["organization", "segment", "occurred_at", "revenue_cents", "orders", "refund_cents", "active_users"],
      organizations: ["north", "south", "east", "west"],
      note: "恢复完整样例授权",
    });
  });
}

function renderGrantHistory(grants) {
  const mine = grants.filter(g => g.principal_id === state.principal).slice().reverse();
  const box = $("#grantHistory");
  if (!mine.length) { box.innerHTML = `<div class="empty">尚无版本</div>`; return; }
  box.innerHTML = mine.map(g => `
    <div class="feed-item ${g.status === "active" ? "ok" : ""}">
      <div class="head">
        <span class="title">v${g.version} · ${esc(g.digest)}</span>
        <span class="time">${fmtTime(g.created_at)}</span>
      </div>
      <div class="detail">${esc(g.note || "")} · 由 ${esc(g.created_by)} 发布</div>
      <div class="detail mono">列: ${esc(g.columns.join(", ")) || "—"}</div>
      <div class="detail mono">组织: ${esc(g.organizations.join(", ")) || "—"}</div>
    </div>`).join("");
}

function renderDenials(denials) {
  const mine = denials.filter(d => d.principal_id === state.principal);
  $("#denialCount").textContent = mine.length ? `${mine.length} 条` : "";
  const box = $("#denials");
  if (!mine.length) { box.innerHTML = `<div class="empty">当前身份暂无拒绝记录</div>`; return; }
  box.innerHTML = mine.map(d => `
    <div class="feed-item deny">
      <div class="head">
        <span class="title">${esc(d.kind)} · ${esc(d.code)}</span>
        <span class="time">${fmtTime(d.at)}</span>
      </div>
      <div class="detail">${esc(d.reason)}</div>
      ${renderDenialDetail(d.detail)}
      <div class="detail mono">denial ${esc(d.denial_id)}${d.query_id ? " · " + esc(d.query_id) : ""}${d.job_id ? " · " + esc(d.job_id) : ""}</div>
    </div>`).join("");
}

function renderDenialDetail(detail) {
  if (!detail) return "";
  const bits = [];
  if (detail.withheld_columns?.length) bits.push(`扣留列: ${detail.withheld_columns.join(", ")}`);
  if (detail.withheld_organizations?.length) bits.push(`扣留组织: ${detail.withheld_organizations.join(", ")}`);
  if (detail.live_version !== undefined) bits.push(`live v${detail.live_version}`);
  if (detail.recomputed !== undefined) bits.push(detail.recomputed ? "已从明细重算" : "");
  return bits.filter(Boolean).length ? `<div class="detail mono">${esc(bits.filter(Boolean).join(" · "))}</div>` : "";
}

function renderAudit(events) {
  $("#auditFeed").innerHTML = events.map(e => `
    <div class="feed-item">
      <div class="head">
        <span class="title">${esc(e.action)}</span>
        <span class="time">${fmtTime(e.at)}</span>
      </div>
      <div class="detail">${esc(e.actor)} → ${esc(e.subject || "—")}</div>
    </div>`).join("") || `<div class="empty">暂无</div>`;
}

function renderCache(entries) {
  const box = $("#cacheEntries");
  if (!entries.length) { box.innerHTML = `<div class="empty">尚无缓存条目</div>`; return; }
  box.innerHTML = entries.map(c => `
    <div class="feed-item">
      <div class="head">
        <span class="title mono">${esc(c.cache_entry_id)} <span class="badge">${esc(c.key_digest)}</span></span>
        <span class="time">${fmtTime(c.created_at)}</span>
      </div>
      <div class="detail mono">${esc(c.sql)}</div>
      <div class="detail">列: ${esc(c.columns.join(", "))}</div>
      <div class="detail">组织: ${esc(c.organizations.join(", "))} · ${c.row_count} 行 · 由 ${esc(c.created_by)} 创建 · v${esc(c.auth_version)}</div>
    </div>`).join("");
}

// ---------------------------------------------------------------------------
// Query form
// ---------------------------------------------------------------------------

function renderQueryForm() {
  const orgs = state.meta.organizations;
  $("#orgFilter").innerHTML = orgs.map(o => {
    const g = principalInfo().grant || { organizations: [] };
    const on = g.organizations.includes(o.id);
    return `<label><input type="checkbox" name="org" value="${esc(o.id)}" ${on ? "checked" : ""} ${on ? "" : "disabled"}> ${esc(o.id)} <span class="dim small">${esc(o.label)}</span></label>`;
  }).join("");
  $("#dimFilter").innerHTML = ["organization", "segment", "occurred_at"].map(d =>
    `<label><input type="checkbox" name="dim" value="${esc(d)}" ${d === "organization" ? "checked" : ""}> ${esc(d)}</label>`
  ).join("");
  $("#measureFilter").innerHTML = state.meta.measures.map(m =>
    `<label><input type="checkbox" name="measure" value="${esc(m)}" ${m === "revenue_cents" ? "checked" : ""}> ${esc(m)}</label>`
  ).join("");
}

function collectSpec() {
  const orgs = $$('input[name="org"]:checked').map(x => x.value);
  const dims = $$('input[name="dim"]:checked').map(x => x.value);
  const measures = $$('input[name="measure"]:checked').map(x => x.value);
  const raw = $("#rawSql").value.trim();
  return {
    spec: { organization: orgs, group_by: dims, measures, order_by: dims[0] || "organization" },
    raw_sql: raw || null,
  };
}

function bindEvents() {
  $("#queryForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#launchError").hidden = true;
    const { spec, raw_sql } = collectSpec();
    const body = {
      spec,
      raw_sql,
      auth_mode: $("#authMode").value,
      delay: parseFloat($("#delay").value) || 0,
    };
    try {
      const launched = await launchQuery(body);
      if (!launched) return;
    } catch (err) {
      $("#launchError").hidden = false;
      $("#launchError").innerHTML = `<strong>${esc(err.code || "error")}</strong> — ${esc(err.message)}` +
        (err.detail?.denial_id ? `<div class="mono small">拒绝记录 ${esc(err.detail.denial_id)}</div>` : "");
      await refreshAll();
    }
  });

  $("#scenarioBtn").addEventListener("click", async () => {
    $("#launchError").hidden = true;
    try {
      const res = await api("/api/demo/revoke", { method: "POST", body: "{}" });
      toast("样例已运行：撤权撞上任务恢复");
      await refreshAll();
      if (res.query_id) {
        await loadQuery(res.query_id);
        state.cursor = res.cursor_id;
        state.page = 0;
      }
      renderScenario(res);
    } catch (err) {
      toast(`${err.code || "error"}: ${err.message}`, true);
    }
  });

  $("#resetBtn").addEventListener("click", async () => {
    if (!confirm("重置所有模拟数据？")) return;
    await api("/api/admin/reset", { method: "POST", body: "{}" });
    state.query = null; state.page = 0; state.cursor = null; state.download = null;
    $("#queryPanel").hidden = true;
    $("#scenarioResult")?.remove();
    toast("已重置");
    await refreshAll();
  });

  $("#queryTabs").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-tab]");
    if (!btn) return;
    switchTab(btn.dataset.tab);
  });
}

function switchTab(tab) {
  state.activeTab = tab;
  $$("#queryTabs button").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
  ["plan", "auth", "cache", "results", "download"].forEach(t => {
    $(`#tab-${t}`).hidden = t !== tab;
  });
}

async function launchQuery(body) {
  const res = await api("/api/query", { method: "POST", body: JSON.stringify(body) });
  state.query = res.query;
  state.page = 0;
  state.cursor = null;
  state.download = null;
  state.deliveredPages = [];
  showQuery();
  switchTab("plan");
  await refreshAll();
  return res;
}

async function loadQuery(qid) {
  const res = await api(`/api/queries/${encodeURIComponent(qid)}`);
  state.query = res.query;
  showQuery();
}

function showQuery() {
  if (!state.query) return;
  $("#queryPanel").hidden = false;
  renderQuerySummary();
  renderPlanTab();
  renderAuthTab();
  renderCacheTab();
  renderResultsTab();
  renderDownloadTab();
}

function renderQuerySummary() {
  const q = state.query;
  const ok = q.status === "succeeded";
  $("#querySummary").innerHTML = `
    <dl class="kv">
      <dt>查询</dt><dd>${esc(q.query_id)}</dd>
      <dt>状态</dt><dd><span class="badge ${ok ? "ok" : "bad"}">${esc(q.status)}</span>
        <span class="badge">${esc(q.auth_mode)}</span>
        ${q.cache_entry ? `<span class="badge">cache ${esc(q.cache_entry)}</span>` : ""}</dd>
      <dt>授权版本</dt><dd>v${esc(q.auth_version ?? "—")} · 快照 ${esc(q.auth_snapshot || "—")}</dd>
      <dt>编译 SQL</dt><dd>${esc(q.sql)}</dd>
      ${q.error ? `<dt>错误</dt><dd class="bad">${esc(q.error)}</dd>` : ""}
    </dl>`;
}

function renderPlanTab() {
  const plan = state.query.plan || {};
  const ex = plan.execution_scope || {};
  const qp = plan.query_plan || [];
  $("#tab-plan").innerHTML = `
    <div class="flow">
      <span class="step done">启动 ${esc(plan.mode)}</span><span class="arrow">→</span>
      <span class="step done">执行 ${esc(ex.source || "—")}</span><span class="arrow">→</span>
      <span class="step done">缓存 ${plan.cache?.hit ? "命中" : "未命中"}</span><span class="arrow">→</span>
      <span class="step done">分页逐页重授权</span><span class="arrow">→</span>
      <span class="step done">下载逐块重授权</span>
    </div>
    <h3>SQLite 执行计划</h3>
    <div class="table-scroll"><table>
      <thead><tr><th>id</th><th>parent</th><th>detail</th></tr></thead>
      <tbody>${qp.map(r => `<tr><td class="mono">${esc(r.id)}</td><td class="mono">${esc(r.parent)}</td><td class="mono">${esc(r.detail)}</td></tr>`).join("") || `<tr><td colspan="3" class="empty">无</td></tr>`}</tbody>
    </table></div>
    <h3>编译参数</h3>
    <dl class="kv">
      <dt>启动模式</dt><dd>${esc(plan.mode)}</dd>
      <dt>慢查询窗口</dt><dd>${esc(plan.slow_query_seconds ?? 0)}s</dd>
      <dt>缓存键</dt><dd>${esc(plan.cache_lookup_key ? JSON.stringify(plan.cache_lookup_key) : "—")}</dd>
      <dt>已交付安全提示</dt><dd>客户端已收到的分页是冻结字节，不能收回</dd>
    </dl>`;
}

function renderAuthTab() {
  const plan = state.query.plan || {};
  const ex = plan.execution_scope || {};
  const launch = plan.authorization_at_launch || {};
  const rows = [
    ["启动授权快照", launch.snapshot || "—"],
    ["启动授权版本", `v${launch.version ?? "—"} · ${launch.digest || "—"}`],
    ["执行读取来源", ex.source || "—"],
    ["执行时 live 版本", `v${ex.live_version ?? "—"}`],
    ["执行可用列", (ex.served_columns || []).join(", ") || "—"],
    ["执行可用组织", (ex.served_organizations || []).join(", ") || "—"],
    ["执行时扣除列", (ex.withheld_columns || []).join(", ") || "—"],
    ["执行时扣除组织", (ex.withheld_organizations || []).join(", ") || "—"],
    ["启动时扣除列", (plan.withheld_columns_at_launch || []).join(", ") || "—"],
    ["启动时扣除组织", (plan.withheld_organizations_at_launch || []).join(", ") || "—"],
  ];
  $("#tab-auth").innerHTML = `
    <table><tbody>${rows.map(([k, v]) =>
      `<tr><th>${esc(k)}</th><td class="mono">${esc(v)}</td></tr>`).join("")}</tbody></table>
    <div class="notice">
      交付时会再次对照 live grant 求交；即使执行阶段读到了快照中的行，撤权后的组织与列也不会出现在未交付的分页或下载分块中。
    </div>`;
}

function renderCacheTab() {
  const plan = state.query.plan || {};
  const cache = plan.cache || {};
  const candidates = plan.cache_candidates || [];
  const hit = cache.hit;
  $("#tab-cache").innerHTML = `
    <div class="notice ${hit ? "ok" : "warn"}">
      ${hit
        ? `命中共享缓存 <span class="mono">${esc(cache.entry)}</span>（由 ${esc(cache.created_by || "—")} 创建）。键覆盖 SQL、列、组织与数据代际。`
        : "未命中：没有与当前“实际授权作用域”完全一致的缓存。缓存不会按主体归属，也不会把宽作用域结果交给窄授权。"}
    </div>
    <dl class="kv">
      <dt>查键摘要</dt><dd>${esc(cache.key_digest || "—")}</dd>
      <dt>数据代际</dt><dd>${esc(plan.cache_lookup_key?.data_epoch ?? "—")}</dd>
      <dt>键列</dt><dd>${esc((plan.cache_lookup_key?.columns || []).join(", ") || "—")}</dd>
      <dt>键组织</dt><dd>${esc((plan.cache_lookup_key?.organizations || []).join(", ") || "—")}</dd>
    </dl>
    <h3>近似缓存条目（仅供参考，不会被复用）</h3>
    ${candidates.filter(c => !c.is_exact).length ? `<table>
      <thead><tr><th>条目</th><th>列</th><th>组织</th><th>缺少</th></tr></thead>
      <tbody>${candidates.filter(c => !c.is_exact).map(c => `<tr>
        <td class="mono">${esc(c.cache_entry_id)}</td>
        <td class="mono">${esc(c.columns.join(", "))}</td>
        <td class="mono">${esc(c.organizations.join(", "))}</td>
        <td class="mono">${esc([...c.missing_columns, ...c.missing_organizations].join(", ") || "—")}</td>
      </tr>`).join("")}</tbody></table>` : `<div class="empty">没有近似条目</div>`}`;
}

// ---------------------------------------------------------------------------
// Results & paging
// ---------------------------------------------------------------------------

function lastPageRecord() {
  return state.deliveredPages.length
    ? state.deliveredPages[state.deliveredPages.length - 1]
    : null;
}

function renderResultsTab() {
  const q = state.query;
  if (!q || q.status !== "succeeded") {
    $("#tab-results").innerHTML = `<div class="notice bad">查询未成功（${esc(q?.status || "—")}），没有可交付结果。${q?.error ? " " + esc(q.error) : ""}</div>`;
    return;
  }
  const delivered = state.deliveredPages;
  const total = delivered.reduce((n, p) => n + (p.row_count || 0), 0);
  $("#tab-results").innerHTML = `
    <div class="pager">
      <button id="prevPage" class="ghost" ${delivered.length === 0 ? "disabled" : ""}>← 查看已交付页</button>
      <button id="nextPage" class="primary">交付下一页 →</button>
      <span class="status">已交付 ${delivered.length} 页 / ${total} 行 · 游标 ${esc(state.cursor || "（未开启）")}</span>
      <label class="dim small">每页
        <select id="pageSize">
          ${[3, 5, 8, 20].map(n => `<option value="${n}" ${n === state.pageSize ? "selected" : ""}>${n}</option>`).join("")}
        </select>
      </label>
    </div>
    ${state.pageNotice || ""}
    <div id="pageTable"></div>
    <h3>本会话交付记录</h3>
    <div class="feed">${delivered.length ? delivered.map(p => `
      <div class="feed-item ${p.withheld_columns?.length || p.withheld_organizations?.length ? "warn" : "ok"}">
        <div class="head">
          <span class="title">第 ${p.page + 1} 页 · ${p.row_count} 行 ${p.replay ? "（冻结重放）" : ""}</span>
          <span class="time">${fmtTime(p.frozen_at)}</span>
        </div>
        <div class="detail mono">列: ${esc(p.columns.join(", "))}</div>
        ${p.withheld_columns?.length || p.withheld_organizations?.length
          ? `<div class="detail">扣留列: ${esc(p.withheld_columns.join(", ") || "—")} · 扣留组织: ${esc(p.withheld_organizations.join(", ") || "—")}</div>`
          : ""}
        <button class="ghost small" data-replay="${p.page}">重新请求该页（冻结重放）</button>
      </div>`).join("") : `<div class="empty">尚未交付任何页</div>`}</div>`;
  $("#nextPage").addEventListener("click", () => fetchPage(state.page));
  $("#prevPage").addEventListener("click", () => {
    const last = lastPageRecord();
    if (!last) return;
    state.pageNotice = "";
    renderPageTable(last);
  });
  $("#pageSize").addEventListener("change", (e) => { state.pageSize = parseInt(e.target.value, 10); });
  $$("[data-replay]", $("#tab-results")).forEach(btn => {
    btn.addEventListener("click", () => replayPage(parseInt(btn.dataset.replay, 10)));
  });
  const last = lastPageRecord();
  if (last) renderPageTable(last);
}

async function replayPage(pageNo) {
  const q = state.query;
  const params = new URLSearchParams({ page: String(pageNo), page_size: String(state.pageSize) });
  if (state.cursor) params.set("cursor", state.cursor);
  try {
    const res = await api(`/api/queries/${encodeURIComponent(q.query_id)}/page?${params.toString()}`);
    handlePageResult(res);
  } catch (e) { toast(`${e.code || "error"}: ${e.message}`, true); }
}

async function fetchPage(page) {
  const q = state.query;
  if (!q) return;
  const params = new URLSearchParams({ page: String(page), page_size: String(state.pageSize) });
  if (state.cursor) params.set("cursor", state.cursor);
  try {
    const res = await api(`/api/queries/${encodeURIComponent(q.query_id)}/page?${params.toString()}`);
    handlePageResult(res);
  } catch (e) {
    toast(`${e.code || "error"}: ${e.message}`, true);
  }
  await refreshAll();
}

function handlePageResult(res) {
  const blocks = [];
  if (res.status === "delivered") {
    state.cursor = res.cursor_id;
    const existing = state.deliveredPages.findIndex(p => p.page === res.page);
    if (existing >= 0) state.deliveredPages[existing] = res;
    else state.deliveredPages.push(res);
    state.page = res.page + 1;
    if (res.replay) {
      blocks.push(`<div class="notice ok">这是冻结重放：返回与首次交付完全相同的字节，撤权不会修改已交付内容。</div>`);
    }
    if (res.withheld_columns?.length || res.withheld_organizations?.length) {
      blocks.push(`<div class="notice warn">本页已扣除撤权数据：列 ${esc(res.withheld_columns.join(", ") || "—")} ·
        组织 ${esc(res.withheld_organizations.join(", ") || "—")}
        ${res.recomputed_from_detail ? " · 聚合已从授权明细重算" : ""}</div>`);
    } else if (res.recomputed_from_detail) {
      blocks.push(`<div class="notice warn">授权收窄：本页聚合从授权范围内的明细重算，而不是读取旧缓存。</div>`);
    }
  } else if (res.status === "exhausted") {
    blocks.push(`<div class="notice warn">${esc(res.reason)}
      ${res.withheld_columns?.length || res.withheld_organizations?.length
        ? `<br>扣留列: ${esc(res.withheld_columns.join(", ") || "—")} · 扣留组织: ${esc(res.withheld_organizations.join(", ") || "—")}` : ""}
      ${res.denial_id ? `<br><span class="mono small">拒绝记录 ${esc(res.denial_id)}</span>` : ""}</div>`);
  } else if (res.status === "denied") {
    blocks.push(denialNotice(res));
  }
  state.pageNotice = blocks.join("");
  renderResultsTab();
}

function renderPageTable(p) {
  const box = $("#pageTable");
  if (!box) return;
  if (!p.rows?.length) { box.innerHTML = `<div class="empty">没有可显示的行</div>`; return; }
  const cols = p.columns?.length ? p.columns : Object.keys(p.rows[0]);
  box.innerHTML = `<div class="table-scroll"><table>
    <thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${p.rows.map(r => `<tr>${cols.map(c =>
      `<td class="${typeof r[c] === "number" ? "num" : ""}">${esc(typeof r[c] === "number" ? fmtNum(r[c]) : r[c])}</td>`).join("")}</tr>`).join("")}</tbody>
  </table></div>`;
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

function renderDownloadTab() {
  const q = state.query;
  if (!q || q.status !== "succeeded") {
    $("#tab-download").innerHTML = `<div class="notice bad">查询未成功，无法创建下载任务。</div>`;
    return;
  }
  const job = state.download;
  $("#tab-download").innerHTML = `
    <div class="actions">
      <button id="createJob" class="primary">创建下载任务（暂停态）</button>
      <button id="resumeJob" class="secondary" ${job ? "" : "disabled"}>恢复一个分块</button>
      <button id="resumeJob3" class="ghost" ${job ? "" : "disabled"}>恢复三个分块</button>
    </div>
    <div id="downloadNotice"></div>
    <div id="downloadDetail">${job ? renderJob(job) : `<div class="empty">尚未创建下载任务</div>`}</div>`;
  $("#createJob").addEventListener("click", async () => {
    try {
      const res = await api("/api/downloads", {
        method: "POST",
        body: JSON.stringify({ query_id: q.query_id, rows_per_chunk: 1 }),
      });
      if (res.status === "created") {
        state.download = { ...res, chunks_done: 0, rows_done: 0, status: "paused", delivered: [] };
        toast("下载任务已创建，处于暂停态");
      } else {
        toast(`${res.code}: ${res.reason}`, true);
        $("#downloadNotice").innerHTML = denialNotice(res);
      }
      renderDownloadTab();
      await refreshAll();
    } catch (e) { toast(e.message, true); }
  });
  $("#resumeJob")?.addEventListener("click", () => resumeJob(1));
  $("#resumeJob3")?.addEventListener("click", () => resumeJob(3));
}

function denialNotice(res) {
  return `<div class="notice bad"><strong>${esc(res.code || "denied")}</strong> — ${esc(res.reason || "")}
    ${res.withheld_columns?.length || res.withheld_organizations?.length
      ? `<br>扣留列: ${esc(res.withheld_columns.join(", ") || "—")} · 扣留组织: ${esc(res.withheld_organizations.join(", ") || "—")}` : ""}
    ${res.denial_id ? `<br><span class="mono small">拒绝记录 ${esc(res.denial_id)}</span>` : ""}</div>`;
}

async function resumeJob(chunks) {
  if (!state.download) return;
  try {
    const res = await api(`/api/downloads/${encodeURIComponent(state.download.job_id)}/resume`, {
      method: "POST", body: JSON.stringify({ chunks }),
    });
    state.download = { ...state.download, ...res, delivered: [...(state.download.delivered || []), ...(res.chunks || [])] };
    const notice = $("#downloadNotice");
    if (res.status === "revoked") {
      notice.innerHTML = denialNotice(res);
    } else if (res.truncated_by_revocation) {
      notice.innerHTML = `<div class="notice bad">任务提前终止：已交付 ${res.rows_done} 行后，剩余分块因撤权
        <strong>永久不可交付</strong>。${res.withheld_columns?.length || res.withheld_organizations?.length
          ? `扣留列 ${esc(res.withheld_columns.join(", ") || "—")} · 扣留组织 ${esc(res.withheld_organizations.join(", ") || "—")}。` : ""}
        已交付字节保持不变，未交付字节已作废。</div>`;
    } else if (res.withheld_columns?.length || res.withheld_organizations?.length) {
      notice.innerHTML = `<div class="notice warn">分块在交付前重新授权：扣留列 ${esc(res.withheld_columns.join(", ") || "—")} ·
        扣留组织 ${esc(res.withheld_organizations.join(", ") || "—")}
        ${res.recomputed_from_detail ? " · 聚合已重算" : ""}</div>`;
    } else {
      notice.innerHTML = `<div class="notice ok">已交付分块 ${res.chunks_done}/${res.chunks_total}。</div>`;
    }
    renderDownloadTab();
    $("#downloadNotice").innerHTML = notice.innerHTML;
    await refreshAll();
  } catch (e) { toast(e.message, true); }
}

function renderJob(job) {
  const pct = job.chunks_total ? Math.round((job.chunks_done / job.chunks_total) * 100) : 0;
  return `
    <dl class="kv">
      <dt>任务</dt><dd>${esc(job.job_id)}</dd>
      <dt>状态</dt><dd><span class="badge ${job.status === "completed" ? "ok" : job.status === "revoked" ? "bad" : "warn"}">${esc(job.status)}</span></dd>
      <dt>进度</dt><dd>${job.chunks_done}/${job.chunks_total} 分块（${pct}%）· ${job.rows_done}/${job.rows_total} 行</dd>
      <dt>冻结版本</dt><dd>v${esc(job.auth_version ?? "—")} · 快照 ${esc(job.auth_snapshot || "—")}</dd>
      ${job.note ? `<dt>说明</dt><dd>${esc(job.note)}</dd>` : ""}
    </dl>
    <h3>已交付分块</h3>
    ${(job.delivered || []).length ? `<div class="table-scroll"><table>
      <thead><tr><th>分块</th><th>行</th><th>内容</th></tr></thead>
      <tbody>${job.delivered.map(c => `<tr>
        <td class="mono">#${c.chunk}</td>
        <td class="num">${c.row_count}</td>
        <td class="mono">${esc(JSON.stringify(c.rows))}</td>
      </tr>`).join("")}</tbody></table></div>` : `<div class="empty">还没有已交付分块</div>`}`;
}

// ---------------------------------------------------------------------------
// Ledger & scenario
// ---------------------------------------------------------------------------

function renderLedger() {
  const pages = state.deliveredPages;
  const box = $("#ledger");
  if (!state.query && !pages.length) {
    box.innerHTML = `<div class="empty">交付后会在这里显示冻结的分页字节。</div>`;
    return;
  }
  const rows = [];
  for (const p of pages) {
    rows.push(`
      <div class="ledger-item">
        <div><span class="mono">第 ${p.page + 1} 页</span> · ${p.row_count} 行 · ${p.replay ? "冻结重放" : "首次交付"}
          ${p.denial_id ? `<span class="badge bad">${esc(p.code)}</span>` : ""}</div>
        <div class="detail mono">${fmtTime(p.frozen_at)} · 列 ${esc((p.columns || []).join(", "))}</div>
        ${p.withheld_columns?.length || p.withheld_organizations?.length
          ? `<div class="detail">扣留 L ${esc((p.withheld_columns || []).join(",") || "—")} / R ${esc((p.withheld_organizations || []).join(",") || "—")}</div>` : ""}
      </div>`);
  }
  if (state.download?.delivered?.length) {
    for (const c of state.download.delivered) {
      rows.push(`<div class="ledger-item"><div><span class="mono">下载分块 #${c.chunk}</span> · ${c.row_count} 行</div>
        <div class="detail mono">${esc(JSON.stringify(c.rows))}</div></div>`);
    }
  }
  box.innerHTML = rows.join("") || `<div class="empty">交付后会在这里显示冻结的分页字节。</div>`;
}

function renderScenario(res) {
  $("#scenarioResult")?.remove();
  const panel = document.createElement("section");
  panel.className = "panel";
  panel.id = "scenarioResult";
  const steps = res.steps || [];
  panel.innerHTML = `
    <h2>样例回放：撤权撞上任务恢复 <span class="hint">${esc(res.scenario)}</span></h2>
    <ol class="feed" style="max-height:none">
      ${steps.map(s => {
        const detail = Object.fromEntries(Object.entries(s).filter(([k]) => k !== "step"));
        return `<li class="feed-item"><div class="title">${esc(s.step)}</div>
          <pre class="mono small" style="white-space:pre-wrap;margin:6px 0 0">${esc(JSON.stringify(detail, null, 2))}</pre></li>`;
      }).join("")}
    </ol>`;
  $(".col.right").prepend(panel);
}

boot().catch(e => {
  document.body.innerHTML = `<pre style="padding:24px;color:#ff8a8a">启动失败：${esc(e.message)}</pre>`;
});
