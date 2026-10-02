// 可攜式 FIDO2 密碼金庫 — 前端邏輯（繁中 UI）
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);

let selectedKey = null;
let brokeredKeyLogin = false;
let idleTimer = null;
let idleMinutes = 5;
let editingRestoreHistory = null;
let clipboardClearTimer = null;
let clipboardCopyGeneration = 0;
let clipboardOperationQueue = Promise.resolve();

let keyNameDialogGeneration = 0;

// ─────────────── 工具 ───────────────
function show(id) { $(id).classList.remove("hidden"); }
function hide(id) { $(id).classList.add("hidden"); }
function setPasswordVisibility(inputId, buttonId, visible) {
  const input = $(inputId);
  const button = $(buttonId);
  input.type = visible ? "text" : "password";
  const label = visible ? "隱藏密碼" : "顯示密碼";
  button.setAttribute("aria-label", label);
  button.setAttribute("title", label);
  button.setAttribute("aria-pressed", String(visible));
}
function togglePasswordVisibility(inputId, buttonId) {
  setPasswordVisibility(inputId, buttonId, $(inputId).type === "password");
}
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
      $("login-sub").textContent = "可使用主密碼或任一支已註冊金鑰登入";
      renderLoginKeys(info.keys, info.brokered_key_login);
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

function renderLoginKeys(keys, useBrokeredKeyLogin) {
  const box = $("key-list-login");
  const button = $("btn-login-key");
  selectedKey = null;
  brokeredKeyLogin = Boolean(useBrokeredKeyLogin);
  box.innerHTML = "";
  hide("btn-login-key");
  hide("pin-box");
  if (!keys.length) {
    box.textContent = "（尚無已註冊金鑰 — 登入後可於「金鑰管理」註冊）";
    return;
  }

  if (brokeredKeyLogin) {
    button.textContent = "以金鑰登入";
    show("btn-login-key");
    return;
  }

  for (const key of keys) {
    const item = document.createElement("div");
    item.className = "key-item";
    item.innerHTML = `<span>🔑 <span class="klabel">${esc(key.label)}</span></span><span class="ktype">${esc(key.key_type)} · ${esc(key.prompt_zh)}</span>`;
    item.onclick = () => selectLoginKey(key, item);
    box.appendChild(item);
  }
}

function selectLoginKey(key, item) {
  selectedKey = key;
  document.querySelectorAll("#key-list-login .key-item").forEach((entry) => entry.classList.remove("selected"));
  item.classList.add("selected");
  if (key.key_type === "pin") show("pin-box"); else hide("pin-box");
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
  if (!brokeredKeyLogin && !selectedKey) return errBox("請先選擇一支金鑰");
  const button = $("btn-login-key");
  button.disabled = true;
  $("key-login-status").textContent = brokeredKeyLogin
    ? "請依 Windows 安全性視窗提示操作金鑰"
    : selectedKey.prompt_zh;
  try {
    const entries = brokeredKeyLogin
      ? await invoke("login_any_key")
      : await invoke("login_key", {
          credentialId: selectedKey.credential_id,
          pin: selectedKey.key_type === "pin" ? $("login-pin").value : null,
        });
    await enterMain(entries);
  } catch (e) {
    errBox(String(e));
  } finally {
    button.disabled = false;
    $("key-login-status").textContent = "";
  }
}

async function enterMain(entries) {
  hide("screen-login");
  show("screen-main");
  if (!entries) entries = await invoke("list_entries");
  const settings = await invoke("get_vault_settings");
  idleMinutes = Math.min(60, Math.max(1, Number(settings.idle_lock_minutes) || 5));
  $("idle-minutes").value = idleMinutes;
  $("password-history-limit").value = Math.min(20, Math.max(1, Number(settings.password_history_limit) || 3));
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
        <button data-act="copy" data-id="${e.id}">複製密碼</button>
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
      } else if (b.dataset.act === "copy") {
        await copyEntryPassword(id);
      }
    };
  });
}

function queueClipboardOperation(operation) {
  const result = clipboardOperationQueue.then(operation, operation);
  clipboardOperationQueue = result.catch(() => {});
  return result;
}

async function copyEntryPassword(id) {
  const entry = (window.__lastEntries || []).find((item) => item.id === id);
  if (!entry) return;
  const clipboard = window.__TAURI__.clipboardManager;
  try {
    await queueClipboardOperation(() => clipboard.writeText(entry.password));
    const generation = ++clipboardCopyGeneration;
    $("copy-password-status").textContent = "已複製密碼到剪貼簿，60 秒後自動清除";
    if (clipboardClearTimer !== null) clearTimeout(clipboardClearTimer);
    const copiedPassword = entry.password;
    clipboardClearTimer = setTimeout(async () => {
      if (generation !== clipboardCopyGeneration) return;
      try {
        const outcome = await queueClipboardOperation(async () => {
          if (generation !== clipboardCopyGeneration) return "superseded";
          const cleared = await invoke("clear_clipboard_if_matches", { expected: copiedPassword });
          return cleared ? "cleared" : "changed";
        });
        if (generation !== clipboardCopyGeneration) return;
        if (outcome === "cleared") $("copy-password-status").textContent = "已自動清除剪貼簿";
        else if (outcome === "changed") $("copy-password-status").textContent = "剪貼簿內容已變更，未清除";
      } catch {
        if (generation === clipboardCopyGeneration) $("copy-password-status").textContent = "自動清除失敗，請手動清除剪貼簿";
      } finally {
        if (generation === clipboardCopyGeneration) clipboardClearTimer = null;
      }
    }, 60_000);
  } catch {
    $("copy-password-status").textContent = "複製失敗，請確認剪貼簿功能可用";
  }
}

async function refreshEntries() {
  renderEntries(await invoke("list_entries"));
}

let editingId = null;
function renderPasswordHistory(history) {
  const box = $("ed-pass-history");
  box.innerHTML = "";
  $("ed-pass-history-status").textContent = "";
  if (!history.length) {
    box.textContent = "（尚無舊密碼版本）";
    return;
  }
  for (const version of history) {
    const row = document.createElement("div");
    row.className = "password-history-item";
    const date = document.createElement("span");
    date.textContent = `變更於 ${version.archived_at}`;
    const restore = document.createElement("button");
    restore.type = "button";
    restore.textContent = "還原";
    restore.setAttribute("aria-label", `還原 ${version.archived_at} 的密碼`);
    restore.onclick = () => {
      editingRestoreHistory = { id: version.id, password: version.password };
      $("ed-pass").value = version.password;
      setPasswordVisibility("ed-pass", "btn-toggle-ed-pass", false);
      $("ed-pass-history-status").textContent = "已選擇該版本；按「儲存」後還原";
    };
    row.appendChild(date);
    row.appendChild(restore);
    box.appendChild(row);
  }
}

function openEdit(id) {
  const e = (window.__lastEntries || []).find((x) => x.id === id);
  if (!e) return;
  editingId = id;
  editingRestoreHistory = null;
  $("ed-site").value = e.site;
  $("ed-account").value = e.account;
  $("ed-pass").value = e.password;
  setPasswordVisibility("ed-pass", "btn-toggle-ed-pass", false);
  renderPasswordHistory(e.password_history || []);
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
      restoreHistoryId: editingRestoreHistory && editingRestoreHistory.password === $("ed-pass").value
        ? editingRestoreHistory.id
        : null,
    });
    hide("entry-edit");
    $("ed-pass").value = "";
    setPasswordVisibility("ed-pass", "btn-toggle-ed-pass", false);
    editingRestoreHistory = null;
    $("ed-pass-history-status").textContent = "";
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
      password: $("e-pass").value,
      notes: null,
    });
    $("e-site").value = ""; $("e-account").value = "";
    $("e-pass").value = "";
    setPasswordVisibility("e-pass", "btn-toggle-e-pass", false);
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


function validateKeyLabel(value) {
  const raw = String(value ?? "");
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(raw)) return "名稱不能包含控制字元";
  const label = raw.trim();
  if (!label) return "名稱不可空白";
  if ([...label].length > 64) return "名稱最多 64 個字元";
  return "";
}



async function requestKeyLabel() {
  const dialog = $("key-name-dialog");
  const input = $("key-name-input");
  const status = $("key-name-status");
  const confirmButton = $("btn-confirm-key-name");
  const suggestedLabel = await invoke("suggest_key_label");
  keyNameDialogGeneration += 1;
  confirmButton.disabled = false;
  confirmButton.removeAttribute?.("aria-busy");
  input.value = suggestedLabel;
  input.removeAttribute?.("aria-invalid");
  status.textContent = "";
  dialog.returnValue = "";
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      resolve(dialog.returnValue === "confirm" ? input.value.trim() : null);
    }, { once: true });
    dialog.showModal();
    input.focus?.();
  });
}

function bindKeyNameDialog() {
  const dialog = $("key-name-dialog");
  const input = $("key-name-input");
  const status = $("key-name-status");
  const confirmButton = $("btn-confirm-key-name");
  confirmButton.onclick = async () => {
    if (confirmButton.disabled) return;
    const issue = validateKeyLabel(input.value);
    if (issue) {
      status.textContent = issue;
      input.setAttribute("aria-invalid", "true");
      input.focus?.();
      return;
    }
    const generation = keyNameDialogGeneration;
    confirmButton.disabled = true;
    confirmButton.setAttribute("aria-busy", "true");
    try {
      await invoke("validate_key_label", { label: input.value.trim() });
      if (dialog.open && generation === keyNameDialogGeneration) {
        input.setAttribute("aria-invalid", "false");
        dialog.close("confirm");
      }
    } catch (error) {
      if (dialog.open && generation === keyNameDialogGeneration) {
        status.textContent = String(error);
        input.setAttribute("aria-invalid", "true");
        input.focus?.();
      }
    } finally {
      if (dialog.open && generation === keyNameDialogGeneration) {
        confirmButton.disabled = false;
        confirmButton.removeAttribute?.("aria-busy");
      }
    }
  };
  $("btn-cancel-key-name").onclick = () => dialog.close("cancel");
}

async function registerKey() {
  const registerButton = $("btn-register-key");
  if (registerButton.disabled) return;
  registerButton.disabled = true;
  registerButton.setAttribute("aria-busy", "true");
  $("register-status").textContent = "請先為此金鑰命名";
  try {
    const label = await requestKeyLabel();
    if (label === null) {
      $("register-status").textContent = "已取消註冊";
      return;
    }
    $("register-status").textContent = "偵測中…請插入金鑰";
    const det = await invoke("detect_key");
    let pin = null;
    if (det.key_type === "windows_managed") {
      $("register-status").textContent = "請依 Windows 安全性視窗提示完成金鑰驗證";
    }
    if (det.key_type === "pin") {
      pin = prompt(`「${det.label}」為 PIN 型金鑰 — 請輸入 PIN：`);
      if (pin === null) return; // 取消
    }
    const reg = await invoke("register_key", { pin, label });
    $("register-status").textContent = `已註冊：${reg.label}（${reg.key_type}）`;
    renderKeys();
  } catch (e) { $("register-status").textContent = "失敗：" + String(e); }
  finally {
    registerButton.disabled = false;
    registerButton.removeAttribute?.("aria-busy");
  }
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

async function setPasswordHistoryLimit() {
  const limit = Number.parseInt($("password-history-limit").value, 10);
  if (!Number.isInteger(limit) || limit < 1 || limit > 20) {
    return alert("請輸入 1–20 的舊密碼保留代數");
  }
  try {
    await invoke("set_password_history_limit", { limit });
    $("password-history-limit").value = limit;
    alert(`已套用：每筆條目保留最近 ${limit} 代舊密碼`);
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
  $("btn-cancel-entry").onclick = () => {
    hide("entry-edit");
    $("ed-pass").value = "";
    setPasswordVisibility("ed-pass", "btn-toggle-ed-pass", false);
    editingRestoreHistory = null;
    $("ed-pass-history-status").textContent = "";
  };
  $("btn-toggle-e-pass").onclick = () => togglePasswordVisibility("e-pass", "btn-toggle-e-pass");
  $("btn-toggle-ed-pass").onclick = () => togglePasswordVisibility("ed-pass", "btn-toggle-ed-pass");
  $("btn-register-key").onclick = registerKey;
  bindKeyNameDialog();
  $("btn-set-idle").onclick = setIdle;
  $("btn-set-password-history-limit").onclick = setPasswordHistoryLimit;
  $("btn-lock").onclick = doLock;

  ["mousemove", "keydown", "click"].forEach((ev) => window.addEventListener(ev, resetIdle));
});

// 保留最後一次 entries 供編輯用
const _origRender = renderEntries;
renderEntries = (entries) => { window.__lastEntries = entries; _origRender(entries); };
