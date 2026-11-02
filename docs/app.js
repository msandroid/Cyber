"use strict";

const LABELS = {
  kind: {
    incident: "被害事例", mishandling: "誤送信・誤公開等", vulnerability: "脆弱性・悪用",
    enforcement: "摘発・対策", advisory: "注意喚起・脅威動向", summary: "月次まとめ",
  },
  attack: {
    ransomware: "ランサムウェア", data_breach: "情報流出", unauthorized_access: "不正アクセス・侵害",
    vuln_exploit: "脆弱性悪用", phishing: "フィッシング・詐欺", ddos: "DDoS・サービス妨害",
    supply_chain: "サプライチェーン・委託先", malware: "マルウェア", espionage: "国家系・諜報",
    crypto_theft: "暗号資産窃取", ai_abuse: "AI悪用",
  },
  country: {
    JP: "日本", US: "米国", UK: "英国", GB: "英国", DE: "ドイツ", BE: "ベルギー", FR: "フランス", KR: "韓国",
    UA: "ウクライナ", AU: "オーストラリア", TW: "台湾", VN: "ベトナム", IN: "インド", SG: "シンガポール",
    CA: "カナダ", IT: "イタリア", ES: "スペイン", BR: "ブラジル", CN: "中国", NL: "オランダ",
  },
};
const KIND_ORDER = Object.keys(LABELS.kind);
const DEFAULT_KINDS = ["incident"];
const PAGE = 50;

const state = { records: [], kinds: new Set(DEFAULT_KINDS), shown: PAGE, tab: "list" };
const $ = (id) => document.getElementById(id);
const label = (facet, v) => (LABELS[facet] && LABELS[facet][v]) || v;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function safeUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : "#";
  } catch { return "#"; }
}

// ------------------------------------------------------------ 絞り込み

const FILTERS = {
  attack: { el: "f-attack", key: "attack_types", facet: "attack" },
  sector: { el: "f-sector", key: "sectors" },
  country: { el: "f-country", key: "countries", facet: "country" },
  actor: { el: "f-actor", key: "actors" },
  source: { el: "f-source", key: "source_name" },
};

function currentFilters() {
  const f = { q: $("q").value.trim().toLowerCase(), lang: $("f-lang").value, from: $("f-from").value, to: $("f-to").value };
  for (const name in FILTERS) f[name] = $(FILTERS[name].el).value;
  return f;
}

function matches(r, f, ignoreKind) {
  if (!ignoreKind && !state.kinds.has(r.kind)) return false;
  if (f.lang && r.lang !== f.lang) return false;
  if (f.from && (r.published || "") < f.from) return false;
  if (f.to && (r.published || "9999") > f.to) return false;
  for (const name in FILTERS) {
    const v = f[name];
    if (!v) continue;
    const field = r[FILTERS[name].key];
    if (Array.isArray(field) ? !field.includes(v) : field !== v) return false;
  }
  if (f.q) {
    const terms = f.q.split(/\s+/);
    const hay = r._hay || (r._hay = [r.title, r.summary, r.victim, r.notes, r.cve, ...(r.actors || []),
      ...(r.attack_types || []).map((a) => label("attack", a)), ...(r.sectors || [])].join(" ").toLowerCase());
    if (!terms.every((t) => hay.includes(t))) return false;
  }
  return true;
}

function filtered() {
  const f = currentFilters();
  return state.records.filter((r) => matches(r, f));
}

// ------------------------------------------------------------ 描画

function fillSelect(id, values, facet) {
  const sel = $(id);
  const prev = sel.value;
  sel.innerHTML = `<option value="">すべて</option>` +
    values.map(([v, n]) => `<option value="${esc(v)}">${esc(label(facet, v))} (${n})</option>`).join("");
  sel.value = values.some(([v]) => v === prev) ? prev : "";
}

function countBy(records, key) {
  const m = new Map();
  for (const r of records) {
    const vals = Array.isArray(r[key]) ? r[key] : [r[key]];
    for (const v of vals) if (v) m.set(v, (m.get(v) || 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
}

function renderKinds() {
  const f = currentFilters();
  const base = state.records.filter((r) => matches(r, f, true));
  const counts = Object.fromEntries(countBy(base, "kind"));
  $("kinds").innerHTML = KIND_ORDER.map((k) =>
    `<button class="chip" data-kind="${k}" aria-pressed="${state.kinds.has(k)}">` +
    `<span class="dot" style="background:var(--k-${k})"></span>${esc(LABELS.kind[k])}<span class="n">${counts[k] || 0}</span></button>`
  ).join("");
}

function itemNode(r) {
  const li = $("item-tpl").content.firstElementChild.cloneNode(true);
  li.querySelector(".date").textContent = r.published || "日付不明";
  const kind = li.querySelector(".kind");
  kind.textContent = label("kind", r.kind);
  kind.style.setProperty("--kc", `var(--k-${r.kind})`);
  li.querySelector(".title").textContent = r.title;
  const tags = [];
  if (r.victim) tags.push(`<span class="tag victim" title="被害組織（推定）">${esc(r.victim)}</span>`);
  for (const a of r.attack_types || []) tags.push(`<span class="tag">${esc(label("attack", a))}</span>`);
  for (const c of r.countries || []) tags.push(`<span class="tag">${esc(label("country", c))}</span>`);
  for (const s of r.sectors || []) tags.push(`<span class="tag">${esc(s)}</span>`);
  for (const a of r.actors || []) tags.push(`<span class="tag">${esc(a)}</span>`);
  if (r.claim_unverified) tags.push(`<span class="tag warn">攻撃者の主張・未検証</span>`);
  tags.push(`<span class="tag">${esc(r.source_name)}</span>`);
  li.querySelector(".item-sub").innerHTML = tags.join("");
  const head = li.querySelector(".item-head");
  const body = li.querySelector(".item-body");
  head.addEventListener("click", () => {
    const open = head.getAttribute("aria-expanded") === "true";
    head.setAttribute("aria-expanded", String(!open));
    if (!open && !body.innerHTML) body.innerHTML = detailHtml(r);
    body.hidden = open;
  });
  return li;
}

function detailHtml(r) {
  const rows = [
    ["被害組織", r.victim ? `${esc(r.victim)}${r.curated ? "" : "（自動推定）"}` : "—"],
    ["攻撃種別", (r.attack_types || []).map((a) => esc(label("attack", a))).join("、") || "—"],
    ["攻撃者", (r.actors || []).map(esc).join("、") || "—"],
    ["業種", (r.sectors || []).map(esc).join("、") || "—"],
    ["国・地域", (r.countries || []).map((c) => esc(label("country", c))).join("、") || "—"],
    ["収集元", `${esc(r.source_name)}（${r.lang === "ja" ? "日本語" : "英語"}）`],
    ["初回収集", esc((r.first_seen || "").slice(0, 10))],
  ];
  if (r.cve) rows.splice(2, 0, ["CVE", esc(r.cve)]);
  return (r.summary ? `<p>${esc(r.summary)}</p>` : "") +
    (r.notes ? `<p><strong>補足:</strong> ${esc(r.notes)}</p>` : "") +
    `<dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>` +
    `<a href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener noreferrer">原文を開く ↗</a>`;
}

function renderList(rows) {
  const list = $("list");
  list.innerHTML = "";
  if (!rows.length) {
    list.innerHTML = `<li class="empty">条件に一致する事例はありません。</li>`;
  } else {
    const frag = document.createDocumentFragment();
    rows.slice(0, state.shown).forEach((r) => frag.appendChild(itemNode(r)));
    list.appendChild(frag);
  }
  $("more").hidden = rows.length <= state.shown;
}

function bars(id, entries, facet, filterName, limit = 12) {
  const top = entries.slice(0, limit);
  const max = Math.max(1, ...top.map(([, n]) => n));
  $(id).innerHTML = top.length ? top.map(([v, n]) => {
    const lbl = esc(label(facet, v));
    const name = filterName ? `<button class="lbl" data-filter="${filterName}" data-value="${esc(v)}" title="${lbl}で絞り込む">${lbl}</button>`
      : `<span class="lbl">${lbl}</span>`;
    return `${name}<span class="track"><span class="fill" style="width:${(n / max) * 100}%;display:block"></span></span><span class="val">${n}</span>`;
  }).join("") : `<span class="hint">データなし</span>`;
}

function renderStats(rows) {
  const months = countBy(rows.map((r) => ({ m: (r.published || "").slice(0, 7) })), "m")
    .sort((a, b) => b[0].localeCompare(a[0]));
  bars("s-month", months, null, null, 18);
  bars("s-attack", countBy(rows, "attack_types"), "attack", "attack");
  bars("s-sector", countBy(rows, "sectors"), null, "sector");
  bars("s-country", countBy(rows, "countries"), "country", "country");
  bars("s-actor", countBy(rows, "actors"), null, "actor");
  bars("s-source", countBy(rows, "source_name"), null, "source");
}

function render() {
  const rows = filtered();
  renderKinds();
  $("count").textContent = `${rows.length.toLocaleString()} 件 / 全 ${state.records.length.toLocaleString()} 件`;
  if (state.tab === "list") renderList(rows);
  if (state.tab === "stats") renderStats(rows);
  saveHash();
}

// ------------------------------------------------------------ URL ハッシュに条件を保存（共有用）

function saveHash() {
  const p = new URLSearchParams();
  const f = currentFilters();
  for (const k of ["q", "lang", "from", "to", ...Object.keys(FILTERS)]) if (f[k]) p.set(k, k === "q" ? $("q").value.trim() : f[k]);
  const kinds = [...state.kinds].sort().join(",");
  if (kinds !== [...DEFAULT_KINDS].sort().join(",")) p.set("kind", kinds || "none");
  if (state.tab !== "list") p.set("tab", state.tab);
  const h = p.toString();
  history.replaceState(null, "", h ? `#${h}` : location.pathname + location.search);
}

function loadHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  $("q").value = p.get("q") || "";
  $("f-lang").value = p.get("lang") || "";
  $("f-from").value = p.get("from") || "";
  $("f-to").value = p.get("to") || "";
  for (const name in FILTERS) if (p.get(name)) $(FILTERS[name].el).value = p.get(name);
  if (p.get("kind")) state.kinds = new Set(p.get("kind") === "none" ? [] : p.get("kind").split(","));
  if (p.get("tab")) setTab(p.get("tab"), false);
}

// ------------------------------------------------------------ その他

function setTab(tab, rerender = true) {
  state.tab = tab;
  document.querySelectorAll(".tab").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
  for (const t of ["list", "stats", "sources"]) $(`tab-${t}`).hidden = t !== tab;
  $("filters").hidden = tab === "sources";
  if (rerender) render();
}

function exportCsv() {
  const cols = ["published", "kind", "title", "victim", "attack_types", "sectors", "countries", "actors", "source_name", "url", "summary"];
  const cell = (v) => {
    const s = Array.isArray(v) ? v.join("; ") : String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [cols.join(",")].concat(filtered().map((r) => cols.map((c) => cell(c === "kind" ? label("kind", r.kind) : r[c])).join(",")));
  const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `cyber-incidents-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function renderSources(status) {
  const rows = Object.entries(status.sources || {}).map(([id, s]) => {
    const st = s.ok === true ? `<span class="ok">取得成功</span>` : s.ok === false
      ? `<span class="ng">取得失敗</span><span class="err">${esc(s.error || "")}</span>` : `<span class="na">未取得</span>`;
    return `<tr><td><a href="${esc(safeUrl(s.home))}" target="_blank" rel="noopener noreferrer">${esc(s.name)}</a></td>` +
      `<td>${s.lang === "ja" ? "日本語" : "英語"}</td><td>${st}</td>` +
      `<td>${esc((s.last_success || "").replace("T", " ").slice(0, 16)) || "—"}</td><td>${s.last_count ?? "—"}</td></tr>`;
  });
  $("sources").innerHTML = rows.join("");
}

async function init() {
  const [inc, status] = await Promise.all([
    fetch("data/incidents.json", { cache: "no-cache" }).then((r) => r.json()),
    fetch("data/status.json", { cache: "no-cache" }).then((r) => r.json()).catch(() => ({ sources: {} })),
  ]);
  state.records = inc.records || [];
  $("meta").textContent = `${state.records.length.toLocaleString()} 件収録・最終更新 ${(inc.generated_at || "").replace("T", " ").slice(0, 16)} (UTC)`;
  fillSelect("f-attack", countBy(state.records, "attack_types"), "attack");
  fillSelect("f-sector", countBy(state.records, "sectors"));
  fillSelect("f-country", countBy(state.records, "countries"), "country");
  fillSelect("f-actor", countBy(state.records, "actors"));
  fillSelect("f-source", countBy(state.records, "source_name"));
  renderSources(status);
  loadHash();

  let timer;
  $("q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { state.shown = PAGE; render(); }, 150); });
  document.querySelectorAll("#filters select, #filters input[type=date]").forEach((el) =>
    el.addEventListener("change", () => { state.shown = PAGE; render(); }));
  $("kinds").addEventListener("click", (e) => {
    const b = e.target.closest(".chip");
    if (!b) return;
    const k = b.dataset.kind;
    state.kinds.has(k) ? state.kinds.delete(k) : state.kinds.add(k);
    state.shown = PAGE;
    render();
  });
  $("reset").addEventListener("click", () => {
    $("q").value = ""; $("f-lang").value = ""; $("f-from").value = ""; $("f-to").value = "";
    for (const name in FILTERS) $(FILTERS[name].el).value = "";
    state.kinds = new Set(DEFAULT_KINDS); state.shown = PAGE;
    render();
  });
  $("more").addEventListener("click", () => { state.shown += PAGE; render(); });
  $("csv").addEventListener("click", exportCsv);
  document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => setTab(b.dataset.tab)));
  $("tab-stats").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-filter]");
    if (!b) return;
    $(FILTERS[b.dataset.filter].el).value = b.dataset.value;
    setTab("list");
  });
  render();
}

init().catch((e) => {
  $("meta").textContent = "データの読み込みに失敗しました: " + e.message;
});
