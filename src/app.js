// 可攜式 FIDO2 密碼金庫 — 前端邏輯（繁中 UI）
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);

let selectedKey = null;      // { credential_id, label, key_type, prompt_zh }
let idleTimer = null;
let idleMinutes = 5;

// ─────────────── 工具 ───────────────
function show(id) { $(id).classList.remove("hidden"); }
function hide(id) { $(id).classList.add("hidden"); }
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function errBox(msg) { $("login-error").textContent = msg || ""; }

// ─────────────── 啟動 ───────────────
async function boot() {
  try {
    const info = await invoke("boot_info");
    if (info.has_vault) {
      show("screen-login");
      hide("setup-panel");
      show("login-panel");
      $("login-sub").textContent = "請輸入主密碼，或選擇 FIDO2 金鑰登入";
      renderLoginKeys(info.keys);
    } else {
      show("screen-login");
      show("setup-panel");
      hide("login-panel");
      $("login-sub").textContent = "首次執行 — 請建立帳號";
    }
  } catch (e) {
    errBox(String(e));
  }
}

function renderLoginKeys(keys) {
  const box = $("key-list-login");
  box.innerHTML = "";
  if (!keys.length) {
    box.innerHTML = '<div class="muted" style="font-size:12px">（尚無已註冊金鑰 — 登入後可於「金鑰管理」註冊）</div>';
    return;
  }
  for (const k of keys) {
    const div = document.createElement("div");
    div.className = "key-item";
    div.innerHTML = `<span>🔑 <span class="klabel">${esc(k.label)}</span></span><span class="ktype">${esc(k.key_type)} · ${esc(k.prompt_zh)}</span>`;
    div.onclick = () => selectLoginKey(k, keys);
    box.appendChild(div);
  }
}

function selectLoginKey(k) {
  selectedKey = k;
  document.querySelectorAll("#key-list-login .key-item").forEach((el) => el.classList.remove("selected"));
  event.currentTarget.classList.add("selected");
  if (k.key_type === "pin") show("pin-box"); else hide("pin-box");
  show("btn-login-key");
}

// ─────────────── 建立 / 登入 ───────────────
async function doCreate() {
  errBox("");
  const pw = $("setup-pw").value, pw2 = $("setup-pw2").value;
  if (pw.length < 8) return errBox("主密碼至少 8 個字元");
  if (pw !== pw2) return errBox("兩次輸入的主密碼不一致");
  try {
    await invoke("create_vault", { password: pw });
    await enterMain();
  } catch (e) { errBox(String(e)); }
}

async function doLoginPw() {
  errBox("");
  try {
    const entries = await invoke("login_password", { password: $("login-pw").value });
    await enterMain(entries);
  } catch (e) { errBox(String(e)); }
}

async function doLoginKey() {
  errBox("");
  if (!selectedKey) return errBox("請先選擇一支金鑰");
  try {
    const pin = selectedKey.key_type === "pin" ? $("login-pin").value : null;
    const entries = await invoke("login_key", { credentialId: selectedKey.credential_id, pin });
    await enterMain(entries);
  } catch (e) { errBox(String(e)); }
}

async function enterMain(entries) {
  hide("screen-login");
  show("screen-main");
  if (!entries) entries = await invoke("list_entries");
  const audit = await invoke("list_audit");
  renderEntries(entries);
  renderAudit(audit);
  renderKeys();
  startIdleTimer(idleMinutes);
}

// ─────────────── 條目 CRUD ───────────────
function renderEntries(entries) {
  const tb = document.querySelector("#entries-table tbody");
  tb.innerHTML = "";
  for (const e of entries) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(e.site)}</td>
      <td>${esc(e.account)}</td>
      <td class="mono">${esc(e.created_at)}</td>
      <td class="mono">${esc(e.updated_at)}</td>
      <td class="rowbtns">
        <button data-act="show" data-id="${e.id}">顯示</button>
        <button data-act="edit" data-id="${e.id}">編輯</button>
        <button data-act="del" data-id="${e.id}">刪除</button>
      </td>`;
    tb.appendChild(tr);
  }
  tb.querySelectorAll("button").forEach((b) => {
    b.onclick = async () => {
      const id = b.dataset.id;
      if (b.dataset.act === "del") {
        if (!confirm("確定刪除該條目？（不可復原）")) return;
        await invoke("delete_entry", { id }).then(() => refreshEntries()).catch((e) => alert(String(e)));
      } else if (b.dataset.act === "edit") {
        openEdit(id);
      } else if (b.dataset.act === "show") {
        const en = entries.find((x) => x.id === id);
        prompt("密碼", en ? en.password : "");
      }
    };
  });
}

async function refreshEntries() {
  renderEntries(await invoke("list_entries"));
}

let editingId = null;
function openEdit(id) {
  const e = (window.__lastEntries || []).find((x) => x.id === id);
  if (!e) return;
  editingId = id;
  $("ed-site").value = e.site;
  $("ed-account").value = e.account;
  $("ed-pass").value = e.password;
  $("ed-notes").value = e.notes || "";
  show("entry-edit");
}

async function saveEntry() {
  try {
    await invoke("update_entry", {
      id: editingId,
      site: $("ed-site").value,
      account: $("ed-account").value,
      password: $("ed-pass").value,
      notes: $("ed-notes").value,
    });
    hide("entry-edit");
    await refreshEntries();
  } catch (e) { alert(String(e)); }
}

async function addEntry() {
  const site = $("e-site").value.trim();
  if (!site) return alert("請輸入網站名稱");
  try {
    await invoke("add_entry", {
      site,
      account: $("e-account").value.trim(),
      password: prompt("密碼：") || "",
      notes: null,
    });
    $("e-site").value = ""; $("e-account").value = "";
    await refreshEntries();
  } catch (e) { alert(String(e)); }
}

// ─────────────── 金鑰管理 ───────────────
async function renderKeys() {
  // 需解鎖後 header；用 list_entries 無法取 → 另加 command。此處以 register/remove 後重新 boot_info 近似。
  const info = await invoke("boot_info").catch(() => null);
  const box = $("keys-list");
  box.innerHTML = "";
  if (!info || !info.keys.length) { box.innerHTML = '<div class="muted">（尚無已註冊金鑰）</div>'; return; }
  info.keys.forEach((k, i) => {
    const div = document.createElement("div");
    div.className = "key-item";
    div.style.cursor = "default";
    div.innerHTML = `<span>🔑 <span class="klabel">${esc(k.label)}</span></span><span class="ktype">${esc(k.key_type)} · ${esc(k.prompt_zh)}</span>`;
    const rm = document.createElement("button");
    rm.textContent = "移除";
    rm.style.marginLeft = "auto";
    rm.onclick = async () => {
      if (!confirm(`確定移除金鑰「${k.label}」？\n移除後該金鑰無法再解鎖（不可逆）。`)) return;
      await invoke("remove_key", { credentialId: k.credential_id }).then(() => renderKeys()).catch((e) => alert(String(e)));
    };
    div.appendChild(rm);
    box.appendChild(div);
  });
}

async function registerKey() {
  $("register-status").textContent = "偵測中…請插入金鑰";
  try {
    const det = await invoke("detect_key");
    let pin = null;
    if (det.key_type === "pin") {
      pin = prompt(`「${det.label}」為 PIN 型金鑰 — 請輸入 PIN：`);
      if (pin === null) return; // 取消
    }
    const reg = await invoke("register_key", { pin });
    $("register-status").textContent = `已註冊：${reg.label}（${reg.key_type}）`;
    renderKeys();
  } catch (e) { $("register-status").textContent = "失敗：" + String(e); }
}

// ─────────────── 軌跡 ───────────────
async function renderAudit(audit) {
  const tb = document.querySelector("#audit-table tbody");
  tb.innerHTML = "";
  for (const a of [...audit].reverse()) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${esc(a.ts)}</td><td>${esc(a.event)}</td><td>${esc(a.method)}</td><td>${esc(a.detail)}</td>`;
    tb.appendChild(tr);
  }
}

// ─────────────── 設定 / 上鎖 / 閒置 ───────────────
async function setIdle() {
  const m = parseInt($("idle-minutes").value, 10) || 5;
  try {
    await invoke("set_idle_lock", { minutes: m });
    idleMinutes = Math.min(60, Math.max(1, m));
    startIdleTimer(idleMinutes);
    alert(`已套用：閒置 ${idleMinutes} 分鐘自動上鎖`);
  } catch (e) { alert(String(e)); }
}

function resetIdle() {
  if (idleTimer) { clearTimeout(idleTimer); startIdleTimer(idleMinutes); }
}
function startIdleTimer(mins) {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(async () => {
    try { await invoke("lock", { reason: "idle" }); } catch {}
    location.reload();
  }, mins * 60 * 1000);
}

async function doLock() {
  try { await invoke("lock", { reason: null }); } catch {}
  location.reload();
}

// ─────────────── 事件綁定 ───────────────
document.addEventListener("DOMContentLoaded", () => {
  boot();

  $("btn-create").onclick = doCreate;
  $("btn-login-pw").onclick = doLoginPw;
  $("btn-login-key").onclick = doLoginKey;
  $("login-pw").addEventListener("keydown", (e) => e.key === "Enter" && doLoginPw());
  $("login-pin").addEventListener("keydown", (e) => e.key === "Enter" && doLoginKey());

  document.querySelectorAll(".tabs button").forEach((b) => {
    b.onclick = () => {
      document.querySelectorAll(".tabs button").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      document.querySelectorAll(".tab").forEach((t) => t.classList.add("hidden"));
      show("tab-" + b.dataset.tab);
      if (b.dataset.tab === "audit") invoke("list_audit").then(renderAudit).catch(() => {});
      if (b.dataset.tab === "keys") renderKeys();
    };
  });

  $("btn-add").onclick = addEntry;
  $("btn-save-entry").onclick = saveEntry;
  $("btn-cancel-entry").onclick = () => hide("entry-edit");
  $("btn-register-key").onclick = registerKey;
  $("btn-set-idle").onclick = setIdle;
  $("btn-lock").onclick = doLock;

  ["mousemove", "keydown", "click"].forEach((ev) => window.addEventListener(ev, resetIdle));
});

// 保留最後一次 entries 供編輯用
const _origRender = renderEntries;
renderEntries = (entries) => { window.__lastEntries = entries; _origRender(entries); };
