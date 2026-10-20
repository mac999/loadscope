const I18N = {
  ko: {
    "label.path": "분석할 파일 경로",
    "label.depth": "깊이",
    "action.analyze": "분석",
    "action.analyzing": "분석 중",
    "pane.tree": "의존성 트리",
    "pane.imports": "임포트",
    "pane.exports": "익스포트",
    "pane.modules": "모듈",
    "status.ready": "준비됨",
    "status.loading": "PE 파일 분석 중",
    "status.loaded": "PE 파일 분석 완료",
    "status.missing": "찾지 못한 모듈",
    "col.ordinal": "서수",
    "col.hint": "힌트",
    "col.function": "함수",
    "col.module": "모듈",
    "col.va": "가상 주소",
    "col.forward": "포워드 대상",
    "col.machine": "머신",
    "col.type": "종류",
    "col.filesize": "파일 크기",
    "col.imagebase": "이미지 베이스",
    "col.virtualsize": "가상 크기",
    "col.entry": "엔트리 포인트",
    "col.subsystem": "서브시스템",
    "col.subsysver": "서브시스템 버전",
    "col.checksum": "체크섬",
    "col.strategy": "탐색 전략",
    "col.assembly": "어셈블리",
    "col.version": "버전",
    "col.culture": "컬처",
    "view.explorer": "탐색기",
    "view.dashboard": "대시보드",
    "action.browse": "찾아보기",
    "action.browsing": "선택 중",
    "dash.overview": "개요",
    "dash.modules": "모듈",
    "dash.edges": "의존 간선",
    "dash.depth": "최대 깊이",
    "dash.missing": "미해석",
    "dash.functions": "임포트 함수",
    "dash.ordinal": "서수 임포트",
    "dash.dotnet": ".NET 모듈",
    "dash.native": "네이티브 모듈",
    "dash.strategy": "모듈이 어디서 왔는가",
    "dash.strategy.note": "모듈이 해석된 위치의 분포입니다. 시스템 디렉터리 밖에서 온 모듈이 많을수록 로딩 경로를 외부에서 바꿀 여지가 큽니다.",
    "dash.hijack": "검색 순서 하이재킹 표면",
    "dash.hijack.note": "쓰기 가능한 위치(앱 디렉터리, 작업 디렉터리, PATH)에서 해석된 모듈입니다. 해당 폴더에 같은 이름의 DLL을 놓으면 이 프로세스가 그것을 먼저 로드할 수 있습니다 (MITRE ATT&CK T1574.001).",
    "dash.hijack.none": "쓰기 가능한 위치에서 해석된 모듈이 없습니다.",
    "dash.missing.title": "해석되지 않은 모듈",
    "dash.missing.note": "필수 임포트가 없으면 로드가 실패합니다. 지연 임포트는 실제 호출 시점까지 로드되지 않으므로 보통 정상입니다. 다만 없는 이름은 그 자리에 DLL을 놓는 phantom 하이재킹의 대상이 됩니다.",
    "dash.missing.required": "필수",
    "dash.missing.delayed": "지연",
    "dash.missing.none": "모든 임포트가 해석되었습니다.",
    "dash.mitigation": "완화 기능 적용",
    "dash.mitigation.note": "PE 옵션 헤더 DllCharacteristics 값입니다. 같은 프로세스에 로드되는 모듈 하나라도 ASLR이나 CFG가 빠지면 그 프로세스의 완화 수준이 내려갑니다.",
    "dash.mitigation.weak": "일부 완화가 빠진 모듈",
    "dash.mitigation.none": "모든 모듈이 ASLR, DEP, CFG를 갖추고 있습니다.",
    "dash.fanin": "많이 의존되는 모듈 (fan-in)",
    "dash.fanin.note": "다른 모듈이 많이 참조할수록 교체나 변경의 영향 범위가 넓습니다.",
    "dash.fanout": "많이 의존하는 모듈 (fan-out)",
    "dash.fanout.note": "참조하는 모듈이 많을수록 결합도가 높고 로드 실패 지점이 늘어납니다.",
    "dash.arch": "아키텍처",
    "dash.arch.mismatch": "루트와 아키텍처가 다른 모듈",
    "dash.arch.note": "같은 프로세스에는 한 아키텍처만 로드됩니다. MSIL 어셈블리는 제외했습니다.",
    "dash.depthdist": "깊이 분포",
    "dash.depthdist.note": "루트에서 몇 단계 떨어져 처음 등장하는지입니다.",
    "dash.empty": "먼저 파일을 분석하십시오.",
    "dash.level": "단계",
    "empty.tree": "파일 경로를 입력하고 분석을 누르십시오.",
    "empty.imports": "임포트가 없습니다.",
    "empty.exports": "익스포트가 없습니다.",
    "empty.select": "트리에서 모듈을 선택하십시오.",
    "err.empty": "파일 경로를 입력하십시오.",
    "unit.modules": "개 모듈"
  },
  en: {
    "label.path": "File path to analyze",
    "label.depth": "Depth",
    "action.analyze": "Analyze",
    "action.analyzing": "Analyzing",
    "pane.tree": "Dependency tree",
    "pane.imports": "Imports",
    "pane.exports": "Exports",
    "pane.modules": "Modules",
    "status.ready": "Ready",
    "status.loading": "Loading PE file",
    "status.loaded": "Loading PE file successful",
    "status.missing": "modules not found",
    "col.ordinal": "Ordinal",
    "col.hint": "Hint",
    "col.function": "Function",
    "col.module": "Module",
    "col.va": "VirtualAddress",
    "col.forward": "Forwarded to",
    "col.machine": "Machine",
    "col.type": "Type",
    "col.filesize": "File Size",
    "col.imagebase": "Image Base",
    "col.virtualsize": "Virtual Size",
    "col.entry": "Entry point",
    "col.subsystem": "Subsystem",
    "col.subsysver": "Subsystem Ver.",
    "col.checksum": "Checksum",
    "col.strategy": "Search strategy",
    "col.assembly": "Assembly",
    "col.version": "Version",
    "col.culture": "Culture",
    "view.explorer": "Explorer",
    "view.dashboard": "Dashboard",
    "action.browse": "Browse",
    "action.browsing": "Choosing",
    "dash.overview": "Overview",
    "dash.modules": "Modules",
    "dash.edges": "Edges",
    "dash.depth": "Max depth",
    "dash.missing": "Unresolved",
    "dash.functions": "Imported functions",
    "dash.ordinal": "Ordinal imports",
    "dash.dotnet": ".NET modules",
    "dash.native": "Native modules",
    "dash.strategy": "Where modules come from",
    "dash.strategy.note": "Distribution of the locations modules were resolved from. The more that come from outside the system directories, the more the load path can be influenced from outside.",
    "dash.hijack": "Search order hijacking surface",
    "dash.hijack.note": "Modules resolved from writable locations (application directory, working directory, PATH). Dropping a DLL of the same name into such a folder can make this process load it first (MITRE ATT&CK T1574.001).",
    "dash.hijack.none": "No module was resolved from a writable location.",
    "dash.missing.title": "Unresolved modules",
    "dash.missing.note": "A missing required import makes the load fail. Delay imports are not loaded until actually called, so they are usually fine. Still, an absent name is exactly what phantom DLL hijacking targets.",
    "dash.missing.required": "Required",
    "dash.missing.delayed": "Delayed",
    "dash.missing.none": "Every import was resolved.",
    "dash.mitigation": "Mitigation coverage",
    "dash.mitigation.note": "Read from the PE optional header DllCharacteristics. A single module without ASLR or CFG lowers the mitigation level of the whole process it loads into.",
    "dash.mitigation.weak": "Modules missing a mitigation",
    "dash.mitigation.none": "Every module has ASLR, DEP and CFG.",
    "dash.fanin": "Most depended upon (fan-in)",
    "dash.fanin.note": "The more modules reference it, the wider the blast radius of replacing or changing it.",
    "dash.fanout": "Most dependencies (fan-out)",
    "dash.fanout.note": "More references mean tighter coupling and more places a load can fail.",
    "dash.arch": "Architecture",
    "dash.arch.mismatch": "Modules whose architecture differs from the root",
    "dash.arch.note": "One process loads one architecture. MSIL assemblies are excluded.",
    "dash.depthdist": "Depth distribution",
    "dash.depthdist.note": "How many levels from the root a module first appears at.",
    "dash.empty": "Analyze a file first.",
    "dash.level": "level",
    "empty.tree": "Enter a file path and press Analyze.",
    "empty.imports": "No imports.",
    "empty.exports": "No exports.",
    "empty.select": "Select a module in the tree.",
    "err.empty": "Enter a file path.",
    "unit.modules": "modules"
  }
};

let lang = "en";
let view = "explorer";
let data = null;
let selectedKey = null;
const collapsed = new Set();

const $ = (sel) => document.querySelector(sel);
const t = (key) => I18N[lang][key] || key;

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function hex(n, width) {
  return "0x" + Number(n).toString(16).padStart(width || 0, "0");
}

function setStatus(text, bad) {
  const el = $("#status");
  el.textContent = text;
  el.classList.toggle("bad", !!bad);
}

// Mirrors the original status line: 'Loading PE file "..." successful.'
function setLoadedStatus() {
  if (!data) return;
  const missing = data.missing.length
    ? `, ${data.missing.length} ${t("status.missing")}`
    : "";
  setStatus(`${t("status.loaded")}: "${data.modules[data.root_key].path}"${missing}`);
}

function applyLanguage() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll(".lang-switch button").forEach((b) => {
    b.classList.toggle("active", b.dataset.lang === lang);
  });
  if (data) {
    renderAll();
    setLoadedStatus();
  } else {
    $("#tree").innerHTML = `<p class="empty">${t("empty.tree")}</p>`;
    renderDashboard();
    setStatus(t("status.ready"));
  }
}

async function run() {
  const path = $("#path").value.trim();
  if (!path) {
    setStatus(t("err.empty"), true);
    return;
  }
  const button = $("#run");
  button.disabled = true;
  button.textContent = t("action.analyzing");
  setStatus(`${t("status.loading")} "${path}" ...`);

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, depth: Number($("#depth").value) || 4 })
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || res.statusText);
    data = body;
    selectedKey = body.root_key;
    collapsed.clear();
    autoCollapsePending = true;
    renderAll();
    setLoadedStatus();
  } catch (e) {
    data = null;
    selectedKey = null;
    $("#tree").innerHTML = "";
    $("#imports").innerHTML = "";
    $("#exports").innerHTML = "";
    $("#modules").innerHTML = "";
    setStatus(String(e.message || e), true);
  } finally {
    button.disabled = false;
    button.textContent = t("action.analyze");
  }
}

function renderAll() {
  renderTree();
  renderModules();
  renderDetail();
  renderDashboard();
}

function setView(next) {
  view = next;
  document.querySelectorAll(".view-switch button").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === view));
  const dashboard = view === "dashboard";
  $("#workspace").classList.toggle("hidden", dashboard);
  document.querySelector(".modules-pane").classList.toggle("hidden", dashboard);
  document.querySelector('body > .splitter[data-split="modules"]')
    .classList.toggle("hidden", dashboard);
  $("#dashboard").classList.toggle("hidden", !dashboard);
}

// ---- Panel resizing ----

const SPLITTERS = {
  tree: {
    variable: "--tree-width",
    measure: (ev) => ev.clientX - $("#workspace").getBoundingClientRect().left,
    min: 180,
    max: () => $("#workspace").getBoundingClientRect().width - 320
  },
  imports: {
    variable: "--imports-height",
    measure: (ev) =>
      ev.clientY - document.querySelector(".right-column").getBoundingClientRect().top,
    min: 90,
    max: () => document.querySelector(".right-column").getBoundingClientRect().height - 90
  },
  modules: {
    // Measured from the status bar's top edge so it matches the panel height
    variable: "--modules-height",
    measure: (ev) => $("#status").getBoundingClientRect().top - ev.clientY,
    min: 80,
    max: () => window.innerHeight - 340
  }
};

function startResize(el, event) {
  const spec = SPLITTERS[el.dataset.split];
  if (!spec) return;
  event.preventDefault();
  el.classList.add("dragging");
  document.body.classList.add("resizing");

  const move = (ev) => {
    const size = Math.max(spec.min, Math.min(spec.measure(ev), spec.max()));
    document.documentElement.style.setProperty(spec.variable, `${Math.round(size)}px`);
  };

  const stop = () => {
    el.classList.remove("dragging");
    document.body.classList.remove("resizing");
    window.removeEventListener("mousemove", move);
    window.removeEventListener("mouseup", stop);
  };

  window.addEventListener("mousemove", move);
  window.addEventListener("mouseup", stop);
}

document.querySelectorAll(".splitter").forEach((el) =>
  el.addEventListener("mousedown", (ev) => startResize(el, ev)));

async function browse() {
  const button = $("#browse");
  button.disabled = true;
  button.textContent = t("action.browsing");
  try {
    const res = await fetch("/api/browse");
    const body = await res.json();
    if (body.path) {
      $("#path").value = body.path;
      await run();
    }
  } catch (e) {
    setStatus(String(e.message || e), true);
  } finally {
    button.disabled = false;
    button.textContent = t("action.browse");
  }
}

// Dependency tree. The root sits on top with the chain underneath.
function renderTree() {
  const root = data.modules[data.root_key];
  nodeSeq = 0; // Ids must stay stable across renders so collapse state survives.
  const children = data.chain.map((n) => nodeHtml(n, "n", 0)).join("");
  autoCollapsePending = false;
  const rootRow = rowHtml({
    key: data.root_key,
    cls: "found",
    icon: "■",
    label: root.path,
    strategy: "ROOT",
    id: "root",
    hasChildren: data.chain.length > 0
  });
  $("#tree").innerHTML = `<ul class="tree"><li id="li-root" class="${collapsed.has("root") ? "collapsed" : ""}">${rootRow}<ul>${children}</ul></li></ul>`;
  $("#tree-count").textContent =
    `${Object.keys(data.modules).length} ${t("unit.modules")}`;
  bindTree();
}

function rowHtml(o) {
  const twist = o.hasChildren
    ? `<span class="twist" data-twist="${o.id}">${collapsed.has(o.id) ? "+" : "-"}</span>`
    : `<span class="twist leaf">-</span>`;
  const key = o.key ? ` data-key="${escapeHtml(o.key)}"` : "";
  const sel = o.key && o.key === selectedKey ? " selected" : "";
  return `<div class="node ${o.cls}${sel}"${key}>${twist}` +
    `<span class="icon">${o.icon}</span>` +
    `<span class="label">${escapeHtml(o.label)}</span>` +
    `<span class="strategy">(${o.strategy})</span></div>`;
}

let nodeSeq = 0;
// Right after an analysis only the first level is expanded.
let autoCollapsePending = false;

function nodeHtml(n, prefix, depth) {
  const id = `${prefix}-${nodeSeq++}`;
  if (autoCollapsePending && depth >= 1 && n.children.length) collapsed.add(id);
  const cls = n.duplicate ? "dup" : (n.resolved_path ? "found" : "missing");
  const assembly = n.kind === "assembly";
  const icon = n.duplicate ? "≡"
    : (n.resolved_path ? (assembly ? "A" : (n.delay_import ? "◇" : "▪")) : "?");
  const label = n.resolved_path || n.name;
  const tags = [n.strategy];
  if (n.delay_import) tags.push("delay");
  if (assembly && n.version) tags.push(`v${n.version}`);
  const row = rowHtml({
    key: n.module_key,
    cls,
    icon,
    label,
    strategy: tags.join(", "),
    id,
    hasChildren: n.children.length > 0
  });
  const kids = n.children.length
    ? `<ul>${n.children.map((c) => nodeHtml(c, prefix, depth + 1)).join("")}</ul>`
    : "";
  return `<li id="li-${id}" class="${collapsed.has(id) ? "collapsed" : ""}">${row}${kids}</li>`;
}

function bindTree() {
  $("#tree").querySelectorAll("[data-twist]").forEach((el) => {
    el.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const id = el.dataset.twist;
      if (collapsed.has(id)) collapsed.delete(id);
      else collapsed.add(id);
      const li = document.getElementById(`li-${id}`);
      li.classList.toggle("collapsed");
      el.textContent = li.classList.contains("collapsed") ? "+" : "-";
    });
  });
  $("#tree").querySelectorAll(".node[data-key]").forEach((el) => {
    el.addEventListener("click", () => select(el.dataset.key));
  });
}

function select(key) {
  if (!data.modules[key]) return;
  selectedKey = key;
  document.querySelectorAll(".node").forEach((el) =>
    el.classList.toggle("selected", el.dataset.key === key));
  document.querySelectorAll("#modules tbody tr").forEach((tr) =>
    tr.classList.toggle("selected", tr.dataset.key === key));
  renderDetail();
}

function renderDetail() {
  const m = data.modules[selectedKey];
  if (!m) {
    $("#imports").innerHTML = `<p class="empty">${t("empty.select")}</p>`;
    $("#exports").innerHTML = `<p class="empty">${t("empty.select")}</p>`;
    return;
  }
  $("#imports-of").textContent = m.name;
  $("#exports-of").textContent = m.export_module_name || m.name;
  $("#imports").innerHTML = importsHtml(m);
  $("#exports").innerHTML = exportsHtml(m);
}

// Imports table: PI | Ordinal | Hint | Function | Module (resolved full path)
function importsHtml(m) {
  const assemblies = assemblyRefsHtml(m);
  if (!m.imports.length) {
    return assemblies || `<p class="empty">${t("empty.imports")}</p>`;
  }
  const rows = [];
  for (const mod of m.imports) {
    const where = mod.resolved_path || `${mod.name} (${mod.strategy})`;
    for (const f of mod.functions) {
      const byOrdinal = !f.name;
      rows.push(`<tr class="${mod.delay_import ? "delay" : ""}">
        <td class="mark">${byOrdinal ? "O#" : "C"}</td>
        <td class="num dim">${f.ordinal ?? "N/A"}</td>
        <td class="num dim">${f.hint != null ? `${f.hint} (${hex(f.hint, 4)})` : "N/A"}</td>
        <td>${escapeHtml(f.name || `Ordinal_${f.ordinal}`)}</td>
        <td class="dim">${escapeHtml(where)}</td>
      </tr>`);
    }
  }
  return assemblies + `<table><thead><tr>
      <th>PI</th><th>${t("col.ordinal")}</th><th>${t("col.hint")}</th>
      <th>${t("col.function")}</th><th>${t("col.module")}</th>
    </tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

// IL-only assemblies have no import table, so show AssemblyRefs instead.
function assemblyRefsHtml(m) {
  if (!m.assembly_refs.length) return "";
  const rows = m.assembly_refs.map((r) => `<tr>
    <td class="mark">A</td>
    <td>${escapeHtml(r.name)}</td>
    <td class="dim">${escapeHtml(r.version)}</td>
    <td class="dim">${r.culture ? escapeHtml(r.culture) : "neutral"}</td>
  </tr>`).join("");
  return `<table><thead><tr>
      <th>A</th><th>${t("col.assembly")}</th>
      <th>${t("col.version")}</th><th>${t("col.culture")}</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
}

// Exports table: E | Ordinal | Hint | Function | VirtualAddress | Forwarded
function exportsHtml(m) {
  if (!m.exports.length) return `<p class="empty">${t("empty.exports")}</p>`;
  const rows = m.exports.map((e) => `<tr>
    <td class="mark">${e.name ? "C" : "O#"}</td>
    <td class="num dim">${e.ordinal} (${hex(e.ordinal, 4)})</td>
    <td class="num dim">N/A</td>
    <td>${escapeHtml(e.name || `Ordinal_${e.ordinal}`)}</td>
    <td class="num">${hex(e.virtual_address, 8)}</td>
    <td class="dim">${e.forwarded_name ? escapeHtml(e.forwarded_name) : "None"}</td>
  </tr>`).join("");
  return `<table><thead><tr>
      <th>E</th><th>${t("col.ordinal")}</th><th>${t("col.hint")}</th>
      <th>${t("col.function")}</th><th>${t("col.va")}</th><th>${t("col.forward")}</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
}

function renderModules() {
  const list = Object.values(data.modules);
  const rows = list.map((m) => `<tr class="clickable${m.key === selectedKey ? " selected" : ""}" data-key="${escapeHtml(m.key)}">
    <td>${escapeHtml(m.path)}</td>
    <td>${m.machine_name}</td>
    <td class="dim">${m.type_label}</td>
    <td class="num">${hex(m.file_size, 8)}</td>
    <td class="num">${hex(m.image_base, 8)}</td>
    <td class="num">${hex(m.size_of_image, 8)}</td>
    <td class="num">${hex(m.entry_point, 8)}</td>
    <td class="num">${hex(m.subsystem, 8)}</td>
    <td class="num">${m.subsystem_version}</td>
    <td class="num">${hex(m.checksum, 8)}</td>
    <td class="dim">${m.strategy}</td>
  </tr>`).join("");

  $("#modules").innerHTML = `<table><thead><tr>
      <th>${t("col.module")}</th><th>${t("col.machine")}</th><th>${t("col.type")}</th>
      <th>${t("col.filesize")}</th><th>${t("col.imagebase")}</th><th>${t("col.virtualsize")}</th>
      <th>${t("col.entry")}</th><th>${t("col.subsystem")}</th><th>${t("col.subsysver")}</th>
      <th>${t("col.checksum")}</th><th>${t("col.strategy")}</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
  $("#modules-count").textContent = `${list.length} ${t("unit.modules")}`;

  $("#modules").querySelectorAll("tr[data-key]").forEach((tr) =>
    tr.addEventListener("click", () => select(tr.dataset.key)));
}

// ---- Dashboard ----

function card(title, note, body, wide) {
  return `<section class="card${wide ? " wide" : ""}">
    <h2>${title}</h2>${note ? `<p class="note">${note}</p>` : ""}${body}</section>`;
}

function bars(rows, kind) {
  if (!rows.length) return "";
  const max = Math.max(...rows.map((r) => r[1])) || 1;
  return `<div class="bars">` + rows.map(([label, value]) => {
    const cls = typeof kind === "function" ? kind(label) : (kind || "");
    return `<div class="bar-row">
      <div class="bar-label"><span>${escapeHtml(label)}</span>
        <div class="bar-track"><div class="bar-fill ${cls}" style="width:${(value / max) * 100}%"></div></div>
      </div>
      <div class="bar-value">${value}</div>
    </div>`;
  }).join("") + `</div>`;
}

function kpi(label, value, cls) {
  return `<div class="kpi ${cls || ""}"><span>${label}</span><strong>${value}</strong></div>`;
}

const WRITABLE = ["ApplicationDirectory", "WorkingDirectory", "Environment", "UserDefined"];

function renderDashboard() {
  const el = $("#dashboard");
  if (!data) {
    el.innerHTML = `<p class="empty">${t("dash.empty")}</p>`;
    return;
  }
  const d = data.dashboard;
  const total = d.totals;

  const overview = card(t("dash.overview"), "",
    `<div class="kpis">
      ${kpi(t("dash.modules"), total.modules)}
      ${kpi(t("dash.edges"), total.edges)}
      ${kpi(t("dash.depth"), total.max_depth)}
      ${kpi(t("dash.missing"), total.missing, total.missing ? "warn" : "good")}
      ${kpi(t("dash.functions"), total.import_functions.toLocaleString())}
      ${kpi(t("dash.ordinal"), total.ordinal_imports, total.ordinal_imports ? "warn" : "")}
      ${kpi(t("dash.dotnet"), d.dotnet_modules)}
      ${kpi(t("dash.native"), d.native_modules)}
    </div>`, true);

  const strategy = card(t("dash.strategy"), t("dash.strategy.note"),
    bars(d.strategies, (label) => (WRITABLE.includes(label) ? "risk" : "")));

  const hijack = card(t("dash.hijack"), t("dash.hijack.note"),
    d.hijack_surface.length
      ? `<div class="scroll-box"><table><tbody>${d.hijack_surface.map((r) => `<tr>
          <td>${escapeHtml(r.name)}</td>
          <td class="dim">${escapeHtml(r.strategy)}</td>
          <td class="dim">${escapeHtml(r.path)}</td></tr>`).join("")}</tbody></table></div>`
      : `<p class="finding">${t("dash.hijack.none")}</p>`);

  const missingBody = (total.missing === 0)
    ? `<p class="finding">${t("dash.missing.none")}</p>`
    : `<div class="scroll-box"><table><tbody>${
        d.missing_required.map((n) => `<tr><td><span class="tag off">${t("dash.missing.required")}</span></td><td>${escapeHtml(n)}</td></tr>`).join("") +
        d.missing_delayed.map((n) => `<tr><td><span class="tag">${t("dash.missing.delayed")}</span></td><td class="dim">${escapeHtml(n)}</td></tr>`).join("")
      }</tbody></table></div>`;
  const missing = card(t("dash.missing.title"), t("dash.missing.note"), missingBody);

  const mitigationBody = bars(
    d.mitigation_counts.map(([name, count]) => [`${name} (${count}/${total.modules})`, count]),
    "ok"
  ) + (d.weak_mitigations.length
    ? `<h2 style="margin-top:14px">${t("dash.mitigation.weak")} (${d.weak_mitigations.length})</h2>
       <div class="scroll-box"><table><tbody>${d.weak_mitigations.map((m) => `<tr>
         <td>${escapeHtml(m.name)}</td>
         <td><span class="tag ${m.aslr ? "on" : "off"}">ASLR</span>
             <span class="tag ${m.dep ? "on" : "off"}">DEP</span>
             <span class="tag ${m.cfg ? "on" : "off"}">CFG</span></td>
       </tr>`).join("")}</tbody></table></div>`
    : `<p class="finding" style="margin-top:12px">${t("dash.mitigation.none")}</p>`);
  const mitigation = card(t("dash.mitigation"), t("dash.mitigation.note"), mitigationBody);

  const fanIn = card(t("dash.fanin"), t("dash.fanin.note"), bars(d.top_fan_in));
  const fanOut = card(t("dash.fanout"), t("dash.fanout.note"), bars(d.top_fan_out));

  const archBody = bars(d.architectures) + (d.architecture_mismatch.length
    ? `<h2 style="margin-top:14px">${t("dash.arch.mismatch")} (${d.architecture_mismatch.length})</h2>
       <div class="scroll-box"><table><tbody>${d.architecture_mismatch.map((r) => `<tr>
         <td>${escapeHtml(r.name)}</td><td class="dim">${escapeHtml(r.strategy)}</td>
       </tr>`).join("")}</tbody></table></div>`
    : "");
  const arch = card(t("dash.arch"), t("dash.arch.note"), archBody);

  const depth = card(t("dash.depthdist"), t("dash.depthdist.note"),
    bars(d.depth_histogram.map(([level, count]) => [`${t("dash.level")} ${level}`, count])));

  el.innerHTML = overview + hijack + missing + strategy + mitigation + fanIn + fanOut + arch + depth;
}

document.querySelectorAll(".view-switch button").forEach((b) =>
  b.addEventListener("click", () => setView(b.dataset.view)));

$("#browse").addEventListener("click", browse);

document.querySelectorAll(".lang-switch button").forEach((b) =>
  b.addEventListener("click", () => { lang = b.dataset.lang; applyLanguage(); }));

$("#run").addEventListener("click", run);
$("#path").addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });

applyLanguage();
