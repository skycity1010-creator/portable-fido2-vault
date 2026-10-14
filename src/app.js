// 可攜式 FIDO2 密碼金庫 — 前端邏輯（繁中 UI）
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);

let selectedKey = null;
let registrationCleanupReceipt = null;
let registrationCleanupQuerySequence = 0;
let registrationHandoffReceiptTimer = null;
let registrationCleanupAckInFlight = false;
// One policy for the acknowledge button: never while an ack is in flight, never for the
// journal-unavailable notice (it cannot be acknowledged).
function registrationCleanupAckDisabled() {
  return registrationCleanupAckInFlight || registrationCleanupReceipt?.id === "journal-unavailable";
}
const CLEANUP_WARNING = "本次建立的 Windows Hello 憑證未能自動刪除，請到「設定 → 帳戶 → 通行金鑰」只刪除本次測試項目。確認已閱讀後，按「我已知悉」。";
// 無法重新證明本機持有時程式刻意不刪除（避免誤刪），但憑證仍可能存在。
const UNVERIFIED_CLEANUP_WARNING = "本次建立的 Windows Hello 憑證無法確認是否已清除（程式未刪除無法證明的項目），請到「設定 → 帳戶 → 通行金鑰」只檢查並刪除本次測試項目。確認已閱讀後，按「我已知悉」。";
async function refreshRegistrationCleanupWarning() {
  const sequence = ++registrationCleanupQuerySequence;
  const receipts = await invoke("registration_cleanup_status");
  if (sequence !== registrationCleanupQuerySequence) return;
  registrationCleanupReceipt = Array.isArray(receipts)
    ? receipts.find((receipt) => receipt?.cleanup === "manual_removal_required"
        && receipt.reason === "storage_unavailable")
      || receipts.find((receipt) => receipt?.cleanup === "manual_removal_required") || null : null;
  if (registrationCleanupReceipt) {
    const unavailable = registrationCleanupReceipt.reason === "storage_unavailable";
    $("registration-cleanup-message").textContent = unavailable
      ? `清理通知的儲存位置無法使用，關閉程式後可能無法保留警告。若本次 Windows Hello 憑證未能自動清理，請只檢查本次測試項目；${CLEANUP_WARNING}`
      : registrationCleanupReceipt.reason === "unverified" ? UNVERIFIED_CLEANUP_WARNING : CLEANUP_WARNING;
    $("btn-acknowledge-registration-cleanup").disabled = registrationCleanupAckDisabled();
    show("registration-cleanup-warning");
  } else {
    $("registration-cleanup-message").textContent = "";
    hide("registration-cleanup-warning");
  }
}
async function acknowledgeRegistrationCleanup() {
  const receipt = registrationCleanupReceipt;
  if (!receipt) return;
  const button = $("btn-acknowledge-registration-cleanup");
  if (button.disabled || registrationCleanupAckInFlight) return;
  registrationCleanupAckInFlight = true;
  button.disabled = true;
  try {
    await invoke("acknowledge_registration_cleanup", { id: receipt.id });
    await refreshRegistrationCleanupWarning();
  } catch (e) {
    $("registration-cleanup-message").textContent = `${CLEANUP_WARNING} 確認失敗：${String(e)}`;
  } finally {
    registrationCleanupAckInFlight = false;
    button.disabled = registrationCleanupAckDisabled();
  }
}
let brokeredKeyLogin = false;
let idleTimer = null;
let idleMinutes = 5;
let editingRestoreHistory = null;
let clipboardClearTimer = null;
let clipboardCopyGeneration = 0;
let clipboardOperationQueue = Promise.resolve();

let keyNameDialogGeneration = 0;
let activeCsvImportToken = null;
let csvImportInFlight = false;
let entrySearchQuery = "";
// Manual Windows credential cleanup remains visible across independent removals.
const manualRemovalWarnings = new Map();
function keyRemovalFeedback(message) {
  const warning = manualRemovalWarnings.size
    ? `已從金庫移除「${[...manualRemovalWarnings.values()].join("」、「")}」；Windows 通行金鑰可能殘留，請到 設定 → 帳戶 → 通行金鑰 手動刪除。`
    : "";
  $("key-removal-status").textContent = warning ? `${warning} ${message}` : message;
}

// 雙群組控管版（dual-control）狀態；單人版維持 "single"，不改既有行為。
// 兩步驟登入的 share 只存在 Rust 端；前端只保存顯示用的截止時間（倒數僅供顯示，以 Rust 為準）。
let edition = "single";
let helloEditionConfirmed = false;
let dualLoginReady = false;
let dualLogin = null; // { deadline, timer }
let dualBusy = false;
let dualGeneration = 0;
const GROUP_NAMES = { A: "A 群組", B: "B 群組" };
function isDual() { return edition === "dual"; }
function groupName(group) { return GROUP_NAMES[group] || "未知群組"; }
function groupCounts(keys) {
  const counts = { A: 0, B: 0 };
  for (const key of keys || []) if (key.group === "A" || key.group === "B") counts[key.group] += 1;
  return counts;
}

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
async function loadEdition() {
  // 取不到 edition 時維持單人版 UI；雙人版金庫仍由 Rust 端版本互斥 fail closed。
  try {
    const reportedEdition = await invoke("get_edition");
    helloEditionConfirmed = reportedEdition === "single";
    edition = reportedEdition === "dual" ? "dual" : "single";
  } catch {
    helloEditionConfirmed = false;
    edition = "single";
  }
  if (!isDual()) return;
  document.title = "可攜式 FIDO2 密碼金庫（雙群組控管版）";
  show("edition-badge");
}

async function boot() {
  try {
    await loadEdition();
    const info = await invoke("boot_info");
    try { await refreshRegistrationCleanupWarning(); } catch { /* 登入仍可用，下一次操作再查。 */ }
    if (info.has_vault) {
      show("screen-login");
      hide("setup-panel");
      show("login-panel");
      $("login-sub").textContent = isDual()
        ? "以 A、B 群組金鑰各一支依序驗證登入；主密碼僅供緊急登入"
        : "可使用主密碼或任一支已註冊金鑰登入";
      renderLoginKeys(info.keys, info.brokered_key_login);
      if (helloEditionConfirmed) {
        // An unreadable/unavailable platform must never display a Hello login action.
        hide("btn-login-hello");
        try {
          const status = await invoke("platform_status");
          if (status.api_ok && status.uvpa && status.console && status.local_credential) show("btn-login-hello");
        } catch { /* Password and roaming login remain available. */ }
      }
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
  if (isDual()) return renderDualLoginKeys(keys);
  // Only roaming credentials can be selected by the YubiKey path.
  keys = keys.filter((key) => key.authenticator !== "platform");
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

function renderDualLoginKeys(keys) {
  const counts = groupCounts(keys);
  const hint = $("dual-login-hint");
  show("dual-login-hint");
  dualLoginReady = counts.A > 0 && counts.B > 0;
  if (!dualLoginReady) {
    hint.textContent = "需 A、B 群組各至少一支金鑰；目前請以主密碼登入";
    return;
  }
  hint.textContent = `雙群組控管：需 A 群組與 B 群組成員各以一支金鑰依序驗證（先 A 或先 B 皆可）。目前 A 群組 ${counts.A} 支、B 群組 ${counts.B} 支。`;
  $("btn-login-key").textContent = "以金鑰登入（第一步）";
  show("btn-login-key");
  if (!brokeredKeyLogin) show("pin-box");
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
  if (!isDual()) {
    try {
      const entries = await invoke("login_password", { password: $("login-pw").value });
      await enterMain(entries);
    } catch (e) { errBox(String(e)); }
    return;
  }
  // 雙人版：begin／complete／cancel／主密碼登入共用同一個 in-flight 鎖，彼此序列化。
  // 金鑰步驟進行中不接受主密碼：避免丟棄一個可能已在 Rust 端成功解鎖的回應（UI 與 Rust 狀態不一致）。
  if (dualBusy) return errBox("金鑰驗證進行中，請先完成或取消後再改用主密碼登入");
  await withDualLock(async () => {
    try {
      // 改用主密碼登入：先放棄等待中的第二步（Rust 端清零 share 並記錄取消）。
      if (dualLogin) await abandonDualLogin();
      const entries = await invoke("login_password", { password: $("login-pw").value });
      await enterMain(entries, { breakGlass: true });
    } catch (e) {
      safely(() => errBox(String(e)));
    }
  });
}

async function doLoginKey() {
  // 雙人版：第二步等待中（例如在 PIN 欄按 Enter）送出第二步，否則開始第一步。
  if (isDual()) return dualLogin ? doDualComplete() : doDualBegin();
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

async function doLoginHello() {
  if (!helloEditionConfirmed) return;
  const button = $("btn-login-hello");
  if (button.disabled || button.classList.contains("hidden")) return;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  errBox("");
  $("hello-login-status").textContent = "請依 Windows Hello 提示完成驗證";
  try {
    const entries = await invoke("login_windows_hello");
    await enterMain(entries);
  } catch (e) {
    errBox(String(e));
  } finally {
    $("hello-login-status").textContent = "";
    button.disabled = false;
    button.removeAttribute?.("aria-busy");
  }
}

async function enterMain(entries, options = {}) {
  const session = ++entryDeleteSession;
  // 防禦：進入主畫面時不留任何兩步驟倒數。
  if (dualLogin) returnToDualStepOne();
  hide("screen-login");
  show("screen-main");
  if (helloEditionConfirmed) show("btn-register-hello");
  if (options.breakGlass) show("breakglass-banner"); else hide("breakglass-banner");
  if (!entries) entries = await invoke("list_entries");
  const settings = await invoke("get_vault_settings");
  idleMinutes = Math.min(60, Math.max(1, Number(settings.idle_lock_minutes) || 5));
  $("idle-minutes").value = idleMinutes;
  $("password-history-limit").value = Math.min(20, Math.max(1, Number(settings.password_history_limit) || 3));
  if (isDual()) {
    show("dual-settings");
    $("dual-step-timeout").value = Math.min(600, Math.max(30, Number(settings.dual_step_timeout_secs) || 120));
  }
  const audit = await invoke("list_audit");
  if (session !== entryDeleteSession) return;
  entryDeleteLocking = false;
  try { await refreshRegistrationCleanupWarning(); } catch { /* 保留既有警告，下次再查。 */ }
  if (session !== entryDeleteSession) return;
  renderEntries(entries);
  renderAudit(audit);
  renderKeys();
  startIdleTimer(idleMinutes);
}

let entryDeleteTarget = null;
let entryDeleteInFlight = false;
let entryDeleteLocking = false;
let entryDeleteSession = 0;
function lockEntryDeleteSession() {
  entryDeleteLocking = true;
  entryDeleteSession += 1;
  cancelEntryDelete();
}
function cancelEntryDelete() {
  entryDeleteTarget = null;
  $("entry-delete-site").textContent = "";
  $("entry-delete-account").textContent = "";
  $("entry-delete-status").textContent = "";
  $("entry-delete-result").textContent = "";
  if ($("entry-delete-dialog").open) $("entry-delete-dialog").close();
}
async function confirmEntryDelete() {
  const target = entryDeleteTarget;
  if (entryDeleteLocking || !target || entryDeleteInFlight || !$("entry-delete-dialog").open) return;
  const session = entryDeleteSession;
  // Submitted work belongs to the vault session, independently of modal dismissal.
  entryDeleteInFlight = true;
  try {
    $("btn-confirm-entry-delete").disabled = true;
    $("btn-cancel-entry-delete").disabled = true;
    try {
      await invoke("delete_entry", { id: target.id });
    } catch {
      if (entryDeleteLocking || session !== entryDeleteSession) return;
      if (entryDeleteTarget === target && $("entry-delete-dialog").open) {
        $("entry-delete-status").textContent = "刪除失敗，請重試或取消。";
        $("btn-confirm-entry-delete").disabled = false;
        $("btn-cancel-entry-delete").disabled = false;
      } else {
        $("entry-delete-result").textContent = "刪除失敗，請稍後再試。";
      }
      return;
    }
    if (entryDeleteLocking || session !== entryDeleteSession) return;
    if (editingId === target.id) {
      editingId = null;
      editingRestoreHistory = null;
      hide("entry-edit");
      for (const id of ["ed-site", "ed-account", "ed-pass", "ed-notes"]) $(id).value = "";
      setPasswordVisibility("ed-pass", "btn-toggle-ed-pass", false);
      $("ed-pass-history").innerHTML = "";
      $("ed-pass-history-status").textContent = "";
    }
    cancelEntryDelete();
    // Remove the completed target even if the backend list refresh fails.
    renderEntries((window.__lastEntries || []).filter((entry) => entry.id !== target.id));
    try {
      const entries = await invoke("list_entries");
      if (entryDeleteLocking || session !== entryDeleteSession) return;
      renderEntries(entries);
      $("entry-delete-result").textContent = "刪除完成。";
    } catch {
      if (entryDeleteLocking || session !== entryDeleteSession) return;
      $("entry-delete-result").textContent = "刪除完成，清單重載失敗。請重新載入清單。";
    }
  } finally {
    entryDeleteInFlight = false;
  }
}
function openEntryDelete(entry) {
  if (entryDeleteLocking || entryDeleteInFlight || (entryDeleteTarget && $("entry-delete-dialog").open)) return;
  if (!entry) { $("entry-delete-result").textContent = "無法開啟刪除確認。"; return; }
  $("entry-delete-result").textContent = "";
  entryDeleteTarget = { id: entry.id };
  $("btn-confirm-entry-delete").disabled = false;
  $("btn-cancel-entry-delete").disabled = false;
  $("entry-delete-status").textContent = "";
  $("entry-delete-site").textContent = entry.site;
  $("entry-delete-account").textContent = entry.account;
  try {
    $("entry-delete-dialog").showModal();
    $("btn-cancel-entry-delete").focus();
  } catch {
    cancelEntryDelete();
    $("entry-delete-result").textContent = "無法開啟刪除確認，請稍後再試。";
  }
}

// ─────────────── 條目 CRUD ───────────────
function renderEntries(entries) {
  const tb = document.querySelector("#entries-table tbody");
  tb.innerHTML = "";
  const query = entrySearchQuery.trim().toLowerCase();
  const visibleEntries = query
    ? entries.filter((entry) => [entry.site, entry.account, entry.notes]
      .some((value) => String(value ?? "").toLowerCase().includes(query)))
    : entries;
  const status = $("entry-search-status");
  if (!entries.length) status.textContent = "金庫尚無條目";
  else if (query && !visibleEntries.length) status.textContent = "沒有符合搜尋條件";
  else if (query) status.textContent = `符合 ${visibleEntries.length} / ${entries.length} 筆條目`;
  else status.textContent = `共 ${entries.length} 筆條目`;

  for (const e of visibleEntries) {
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
        openEntryDelete(entries.find((entry) => entry.id === id));
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

async function saveCsvTemplate() {
  const button = $("btn-save-csv-template");
  if (button.disabled) return;
  button.disabled = true;
  $("csv-import-status").textContent = "請選擇 CSV 範本的儲存位置…";
  try {
    const saved = await invoke("save_csv_template");
    $("csv-import-status").textContent = saved ? "CSV 範本已儲存。" : "已取消儲存 CSV 範本。";
  } catch (error) {
    $("csv-import-status").textContent = String(error);
  } finally {
    button.disabled = false;
  }
}

function renderCsvImportPreview(preview) {
  const added = Number(preview?.added) || 0;
  const updated = Number(preview?.updated) || 0;
  const skipped = Number(preview?.skipped) || 0;
  $("csv-import-summary").textContent = `新增 ${added} 筆、更新 ${updated} 筆、略過 ${skipped} 筆`;

  const body = $("csv-import-rows");
  body.replaceChildren();
  const actionLabels = { add: "新增", update: "更新", skip: "略過" };
  for (const item of Array.isArray(preview?.rows) ? preview.rows : []) {
    const row = document.createElement("tr");
    const numberCell = document.createElement("td");
    numberCell.textContent = `第 ${Number(item.row_number) || "?"} 列`;
    const actionCell = document.createElement("td");
    actionCell.textContent = actionLabels[item.action] || "略過";
    const reasonCell = document.createElement("td");
    reasonCell.textContent = typeof item.reason === "string" ? item.reason : "—";
    row.appendChild(numberCell);
    row.appendChild(actionCell);
    row.appendChild(reasonCell);
    body.appendChild(row);
  }
}

async function previewCsvImport() {
  const button = $("btn-import-csv");
  if (button.disabled) return;
  button.disabled = true;
  $("csv-import-status").textContent = "請選擇要匯入的 CSV 檔案…";
  try {
    const result = await invoke("preview_csv_import");
    if (!result) {
      $("csv-import-status").textContent = "已取消選擇 CSV 檔案。";
      return;
    }
    activeCsvImportToken = result.token;
    renderCsvImportPreview(result.preview);
    const dialog = $("csv-import-dialog");
    dialog.returnValue = "";
    $("btn-confirm-csv-import").disabled = !activeCsvImportToken;
    $("btn-cancel-csv-import").disabled = false;
    dialog.showModal();
    $("csv-import-status").textContent = "";
  } catch (error) {
    $("csv-import-status").textContent = String(error);
  } finally {
    button.disabled = false;
  }
}

function cancelCsvImport() {
  const dialog = $("csv-import-dialog");
  if (dialog.open) dialog.close("cancel");
}

function bindCsvImportDialog() {
  $("csv-import-dialog").addEventListener("close", () => {
    const token = activeCsvImportToken;
    activeCsvImportToken = null;
    if (token) invoke("cancel_csv_import", { token }).catch(() => {});
    if ($("csv-import-dialog").returnValue !== "applied") {
      $("csv-import-status").textContent = "已取消 CSV 匯入預覽。";
    }
  });
}

async function confirmCsvImport() {
  const token = activeCsvImportToken;
  if (!token || csvImportInFlight) return;
  csvImportInFlight = true;
  $("btn-confirm-csv-import").disabled = true;
  $("btn-cancel-csv-import").disabled = true;
  try {
    const result = await invoke("apply_csv_import", { token });
    activeCsvImportToken = null;
    $("csv-import-dialog").close("applied");
    const success = `匯入完成：新增 ${Number(result.added) || 0} 筆、更新 ${Number(result.updated) || 0} 筆、略過 ${Number(result.skipped) || 0} 筆。`;
    try {
      await refreshEntries();
      renderAudit(await invoke("list_audit"));
      $("csv-import-status").textContent = success;
    } catch {
      $("csv-import-status").textContent = `${success} 條目清單重新載入失敗。`;
    }
  } catch (error) {
    const message = String(error);
    $("csv-import-status").textContent = `匯入失敗：${message}`;
    if (message.includes("預覽已失效") || message.includes("條目已變更")) {
      activeCsvImportToken = null;
      $("csv-import-dialog").close("stale");
    }
  } finally {
    csvImportInFlight = false;
    if ($("csv-import-dialog").open) {
      $("btn-confirm-csv-import").disabled = !activeCsvImportToken;
      $("btn-cancel-csv-import").disabled = false;
    }
  }
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
  if (isDual()) return renderDualKeys(box, info ? info.keys : null);
  box.innerHTML = "";
  if (!info || !info.keys.length) { box.innerHTML = '<div class="muted">（尚無已註冊金鑰）</div>'; return; }
  info.keys.forEach((k) => {
    const div = document.createElement("div");
    div.className = "key-item";
    div.style.cursor = "default";
    const label = document.createElement("span");
    label.className = "klabel";
    label.textContent = `${k.authenticator === "platform" ? "Windows Hello" : "🔑"} ${k.label}`;
    const type = document.createElement("span");
    type.className = "ktype";
    type.textContent = k.authenticator === "platform"
      ? `Windows Hello（平台憑證；${k.platform_local === true ? "此帳號可用（查詢時）" : k.platform_local === false ? "非本機／此帳號無此憑證" : "本機狀態未確認"}）`
      : `${k.key_type} · ${k.prompt_zh}`;
    div.appendChild(label);
    div.appendChild(type);
    const rm = document.createElement("button");
    rm.textContent = "移除";
    rm.style.marginLeft = "auto";
    // 註冊待確認期間停用金鑰管理（Rust 端移除前也會先取消 pending）。
    rm.disabled = Boolean(registrationHandoff);
    rm.onclick = async () => {
      if (rm.disabled || registrationHandoff) return;
      if (!confirm(`確定移除金鑰「${k.label}」？\n移除後該金鑰無法再解鎖（不可逆）。`)) return;
      rm.disabled = true;
      keyRemovalFeedback("正在移除金鑰…");
      try {
        const outcome = await invoke("remove_key", { credentialId: k.credential_id });
        if (outcome?.outcome === "manual_removal_required") {
          manualRemovalWarnings.set(k.credential_id, k.label);
          keyRemovalFeedback("");
        } else if (outcome?.outcome === "removed" || (outcome === null && k.authenticator !== "platform")) {
          // D5 的 roaming remove_key 仍回傳 JSON null；不可誤報為平台結果未知。
          keyRemovalFeedback("已從金庫移除金鑰");
        } else {
          keyRemovalFeedback("回傳結果未知；請確認金庫與 Windows 通行金鑰狀態");
        }
        await renderKeys();
      } catch (e) {
        keyRemovalFeedback(`移除失敗：${String(e)}`);
      } finally { rm.disabled = Boolean(registrationHandoff); }
    };
    div.appendChild(rm);
    box.appendChild(div);
  });
}

function renderDualKeys(box, keys) {
  box.replaceChildren();
  $("keys-hint").textContent = "金鑰登入需 A 群組與 B 群組各一支金鑰依序驗證。群組註冊後不可修改；每個群組至少須保留一支金鑰。移除後該金鑰無法再解鎖（不可逆）。";
  const status = $("dual-key-status");
  show("dual-key-status");
  if (!keys) {
    status.textContent = "無法讀取金鑰清單";
    return;
  }
  const counts = groupCounts(keys);
  status.textContent = `A 群組 ${counts.A} 支、B 群組 ${counts.B} 支` + (counts.A && counts.B
    ? "：雙群組金鑰登入已啟用"
    : "：需 A、B 群組各至少一支金鑰才能以金鑰登入（目前僅能以主密碼登入）");
  for (const group of ["A", "B"]) {
    const section = document.createElement("div");
    section.className = "key-group";
    const heading = document.createElement("h4");
    heading.textContent = `${groupName(group)}（${counts[group]} 支）`;
    section.appendChild(heading);
    const members = keys.filter((key) => key.group === group);
    if (!members.length) {
      const empty = document.createElement("div");
      empty.className = "muted";
      empty.textContent = "（尚無金鑰）";
      section.appendChild(empty);
    }
    for (const key of members) section.appendChild(dualKeyItem(key));
    box.appendChild(section);
  }
}

function dualKeyItem(key) {
  // 名稱是金庫標頭的明文資料：一律以 textContent 呈現，不經 innerHTML。
  const item = document.createElement("div");
  item.className = "key-item";
  item.style.cursor = "default";
  const label = document.createElement("span");
  label.className = "klabel";
  label.textContent = `🔑 ${key.label}`;
  const type = document.createElement("span");
  type.className = "ktype";
  type.textContent = `${groupName(key.group)} · ${key.key_type} · ${key.prompt_zh}`;
  const remove = document.createElement("button");
  remove.type = "button";
  remove.textContent = "移除";
  remove.style.marginLeft = "auto";
  remove.dataset.credentialId = key.credential_id;
  if (key.last_in_group) {
    // 只是輔助；刪除限制由 Rust 端強制（LastKeyInGroup）。
    remove.disabled = true;
    remove.title = `不可刪除 ${groupName(key.group)}的最後一支金鑰（A、B 群組各須保留至少一支）`;
    remove.setAttribute("aria-disabled", "true");
  }
  if (registrationHandoff) remove.disabled = true;
  remove.onclick = async () => {
    if (remove.disabled || registrationHandoff) return;
    if (!confirm(`確定移除${groupName(key.group)}金鑰「${key.label}」？\n移除後該金鑰無法再解鎖（不可逆）。`)) return;
    await invoke("remove_key", { credentialId: key.credential_id }).then(() => renderKeys()).catch((e) => alert(String(e)));
  };
  item.appendChild(label);
  item.appendChild(type);
  item.appendChild(remove);
  return item;
}

function selectedKeyGroup() {
  if ($("key-group-a").checked) return "A";
  if ($("key-group-b").checked) return "B";
  return null;
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
  $("key-group-a").checked = false;
  $("key-group-b").checked = false;
  if (isDual()) show("key-group-fieldset"); else hide("key-group-fieldset");
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
    if (isDual() && !selectedKeyGroup()) {
      status.textContent = "請選擇金鑰所屬群組（A 群組或 B 群組）";
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

// ─────────────── D9-F1：註冊第二階段前景交接 ───────────────
// 第一個 ceremony 已建立 credential，但 Windows 未把焦點交回 → Rust 保留 pending 註冊。
// 使用者點「繼續驗證」本身讓 FidoVault 成為前景，再以全新斷言完成；或點「取消」放棄。
let registrationHandoff = null; // { kind: "key" | "hello", group }
let registrationHandoffInFlight = false;
const CANCEL_CLEANUP_MESSAGES = {
  removed: "已取消註冊，並已刪除本次建立的 Windows Hello 憑證；金庫未新增金鑰槽。",
  manual_removal_required: "已取消註冊（金庫未新增金鑰槽），但無法自動刪除本次建立的 Windows Hello 憑證；請到「設定 → 帳戶 → 通行金鑰」只刪除本次測試項目。",
  discarded: "已取消註冊；金庫未新增金鑰槽。",
  none: "已取消（沒有待完成的註冊）；金庫未新增金鑰槽。",
};

function registrationStatusId(kind) {
  return kind === "hello" ? "hello-register-status" : "register-status";
}

function registrationFailureText(kind, error) {
  return kind === "hello"
    ? `註冊失敗：${String(error)}。若 Windows 通行金鑰仍有殘留，請到 設定 → 帳戶 → 通行金鑰 手動刪除。`
    : "失敗：" + String(error);
}

function setRegistrationHandoffButtonsDisabled(disabled) {
  $("btn-continue-registration").disabled = disabled;
  $("btn-cancel-registration").disabled = disabled;
}

function showRegistrationHandoff(kind, message, group) {
  registrationHandoff = { kind, group: group || null };
  const handoff = registrationHandoff;
  const checkReceipt = async () => {
    registrationHandoffReceiptTimer = null;
    if (registrationHandoff !== handoff) return;
    try {
      await refreshRegistrationCleanupWarning();
    } catch {
      console.error("registration cleanup status unavailable");
    }
    if (registrationHandoff === handoff) {
      registrationHandoffReceiptTimer = setTimeout(checkReceipt, 3000);
    }
  };
  if (registrationHandoffReceiptTimer !== null) clearTimeout(registrationHandoffReceiptTimer);
  registrationHandoffReceiptTimer = setTimeout(checkReceipt, 3000);
  // 訊息一律以 textContent 呈現，不經 innerHTML。
  $("registration-handoff-message").textContent = String(message ?? "");
  show("registration-handoff");
  setRegistrationHandoffButtonsDisabled(false);
  $("btn-register-key").disabled = true;
  $("btn-register-hello").disabled = true;
  $(registrationStatusId(kind)).textContent = "金鑰已建立，尚未加入金庫；請選擇「繼續驗證」或「取消」。";
  renderKeys();
}

function hideRegistrationHandoff() {
  if (registrationHandoffReceiptTimer !== null) {
    clearTimeout(registrationHandoffReceiptTimer);
    registrationHandoffReceiptTimer = null;
  }
  registrationHandoff = null;
  $("registration-handoff-message").textContent = "";
  hide("registration-handoff");
  $("btn-register-key").disabled = false;
  $("btn-register-hello").disabled = false;
}

// 共用：register_key / register_windows_hello / continue_registration 的回應。
async function applyRegisterResult(kind, result, group) {
  if (result?.status === "handoff_required") {
    showRegistrationHandoff(kind, result.message, group);
    return;
  }
  if (result?.status !== "registered" || !result.credential) throw Error("未知的註冊回應");
  if (registrationHandoff) hideRegistrationHandoff();
  const reg = result.credential;
  if (kind === "hello") {
    $("hello-register-status").textContent = `已註冊 Windows Hello：${reg.label}`;
    await renderKeys();
  } else {
    $("register-status").textContent = group
      ? `已註冊：${reg.label}（${reg.key_type}）— ${groupName(group)}`
      : `已註冊：${reg.label}（${reg.key_type}）`;
    renderKeys();
  }
}

async function continueRegistration() {
  const handoff = registrationHandoff;
  if (!handoff || registrationHandoffInFlight) return;
  registrationHandoffInFlight = true;
  setRegistrationHandoffButtonsDisabled(true);
  $(registrationStatusId(handoff.kind)).textContent = handoff.kind === "hello"
    ? "請依 Windows Hello 提示完成驗證…"
    : "請依 Windows 安全性視窗提示完成金鑰驗證";
  try {
    const result = await invoke("continue_registration");
    await applyRegisterResult(handoff.kind, result, handoff.group);
  } catch (e) {
    $(registrationStatusId(handoff.kind)).textContent = registrationFailureText(handoff.kind, e);
    if (/沒有待完成|逾時|金庫已變更/.test(String(e))) hideRegistrationHandoff();
    try { await refreshRegistrationCleanupWarning(); } catch { /* 保留既有警告。 */ }
  } finally {
    registrationHandoffInFlight = false;
    setRegistrationHandoffButtonsDisabled(false);
  }
}

async function cancelRegistration() {
  const handoff = registrationHandoff;
  if (!handoff || registrationHandoffInFlight) return;
  registrationHandoffInFlight = true;
  setRegistrationHandoffButtonsDisabled(true);
  try {
    const result = await invoke("cancel_registration");
    hideRegistrationHandoff();
    $(registrationStatusId(handoff.kind)).textContent = CANCEL_CLEANUP_MESSAGES[result?.cleanup]
      || "已取消註冊；清理結果未知，請確認金庫與 Windows 通行金鑰狀態。";
    await renderKeys();
    try { await refreshRegistrationCleanupWarning(); } catch { /* 已顯示取消結果，不覆蓋警告。 */ }
  } catch (e) {
    $(registrationStatusId(handoff.kind)).textContent = `取消失敗：${String(e)}`;
  } finally {
    registrationHandoffInFlight = false;
    setRegistrationHandoffButtonsDisabled(false);
  }
}

async function registerHello() {
  if (!helloEditionConfirmed) return;
  const button = $("btn-register-hello");
  if (button.disabled || button.classList.contains("hidden") || registrationHandoff) return;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  $("hello-register-status").textContent = "請依 Windows Hello 提示完成建立與再次驗證…";
  try {
    await applyRegisterResult("hello", await invoke("register_windows_hello"), null);
  } catch (e) {
    $("hello-register-status").textContent = registrationFailureText("hello", e);
  } finally {
    try { await refreshRegistrationCleanupWarning(); } catch { /* 保留既有警告。 */ }
    button.disabled = Boolean(registrationHandoff);
    button.removeAttribute?.("aria-busy");
  }
}

async function registerKey() {
  const registerButton = $("btn-register-key");
  if (registerButton.disabled || registrationHandoff) return;
  registerButton.disabled = true;
  registerButton.setAttribute("aria-busy", "true");
  $("register-status").textContent = "請先為此金鑰命名";
  try {
    const label = await requestKeyLabel();
    if (label === null) {
      $("register-status").textContent = "已取消註冊";
      return;
    }
    const group = isDual() ? selectedKeyGroup() : null;
    if (isDual() && !group) {
      $("register-status").textContent = "未選擇群組，已取消註冊";
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
    const args = { pin, label };
    if (isDual()) args.group = group;
    await applyRegisterResult("key", await invoke("register_key", args), isDual() ? group : null);
  } catch (e) { $("register-status").textContent = registrationFailureText("key", e); }
  finally {
    try { await refreshRegistrationCleanupWarning(); } catch { /* 保留既有警告。 */ }
    registerButton.disabled = Boolean(registrationHandoff);
    registerButton.removeAttribute?.("aria-busy");
  }
}

// ─────────────── 雙群組控管：兩步驟金鑰登入 ───────────────
function dualPin() {
  // Broker 由 Windows 處理 PIN；非 broker 後端每一步各自讀取並清除，避免第一位成員的 PIN 留在欄位。
  if (brokeredKeyLogin) return null;
  const value = $("login-pin").value;
  $("login-pin").value = "";
  return value ? value : null;
}

// UI 清理（DOM 操作）各自獨立執行：單一步驟失敗不可阻止解鎖、IPC 或 in-flight 鎖的釋放。
function safely(step) {
  try { step(); } catch { /* best-effort UI cleanup */ }
}

// begin／complete／cancel／主密碼登入共用同一個 in-flight 鎖；鎖一定在 finally 釋放。
async function withDualLock(work) {
  if (dualBusy) return;
  dualBusy = true;
  try {
    await work();
  } finally {
    dualBusy = false;
  }
}

async function doDualBegin() {
  if (dualBusy || dualLogin || !dualLoginReady) return;
  const button = $("btn-login-key");
  await withDualLock(async () => {
    try {
      errBox("");
      const generation = ++dualGeneration;
      button.disabled = true;
      $("key-login-status").textContent = brokeredKeyLogin
        ? "第一步：請依 Windows 安全性視窗提示操作金鑰"
        : "第一步：請操作金鑰";
      let info;
      try {
        info = await invoke("login_dual_begin", { pin: dualPin() });
      } catch (e) {
        if (generation === dualGeneration) safely(() => errBox(String(e)));
        return;
      }
      if (generation === dualGeneration) startDualStep(info);
    } finally {
      safely(() => { button.disabled = false; });
      safely(() => { $("key-login-status").textContent = ""; });
    }
  });
}

function startDualStep(info) {
  const remainingMs = Math.max(0, Number(info.remaining_ms) || 0);
  const second = groupName(info.second_group);
  // 先建立狀態與計時器，再更新畫面：畫面更新失敗時倒數與逾時仍然有效。
  dualLogin = { deadline: Date.now() + remainingMs, timer: null };
  dualLogin.timer = setInterval(updateDualCountdown, 250);
  safely(() => { $("dual-step-text").textContent = `${groupName(info.first_group)}（${info.first_label}）已驗證，請 ${second}成員於 ${Number(info.timeout_secs) || 0} 秒內完成驗證`; });
  safely(() => { $("btn-dual-complete").textContent = `以 ${second}金鑰完成第二步`; });
  safely(() => hide("btn-login-key"));
  safely(() => show("dual-step-panel"));
  safely(updateDualCountdown);
}

function updateDualCountdown() {
  if (!dualLogin) return;
  const remaining = dualLogin.deadline - Date.now();
  if (remaining <= 0) {
    // Rust 端計時執行緒會自行清除並記錄逾時；前端只回到第一步，不呼叫取消。
    dualGeneration += 1;
    returnToDualStepOne();
    errBox("第二步等待逾時，第一步驗證已失效；請從第一步重新開始");
    return;
  }
  $("dual-countdown").textContent = `剩餘 ${Math.ceil(remaining / 1000)} 秒`;
}

function returnToDualStepOne() {
  // 先清狀態與計時器（不會失敗），再盡力還原畫面。
  if (dualLogin && dualLogin.timer !== null) clearInterval(dualLogin.timer);
  dualLogin = null;
  safely(() => { $("dual-step-text").textContent = ""; });
  safely(() => { $("dual-countdown").textContent = ""; });
  safely(() => hide("dual-step-panel"));
  if (dualLoginReady) safely(() => show("btn-login-key"));
}

async function doDualComplete() {
  if (!dualLogin || dualBusy) return;
  let entries;
  let unlocked = false;
  let generation;
  await withDualLock(async () => {
    try {
      generation = dualGeneration;
      // 送出前的畫面更新只是提示：失敗不可阻止送出，也不可留下停止的倒數。
      safely(() => { $("btn-dual-complete").disabled = true; });
      safely(() => { $("btn-dual-cancel").disabled = true; });
      safely(() => errBox(""));
      const pin = dualPin();
      // 第二步進行中停止前端倒數（緊接在送出前）；截止時間由 Rust 在金鑰操作前後各檢查一次。
      if (dualLogin.timer !== null) clearInterval(dualLogin.timer);
      dualLogin.timer = null;
      safely(() => {
        $("dual-countdown").textContent = brokeredKeyLogin
          ? "第二步：請依 Windows 安全性視窗提示操作金鑰"
          : "第二步：請操作金鑰";
      });
      try {
        entries = await invoke("login_dual_complete", { pin });
        unlocked = true;
      } catch (e) {
        if (generation === dualGeneration) {
          // Rust 端暫存不論成敗都已取走：一律回到第一步。
          returnToDualStepOne();
          safely(() => errBox(`${String(e)}\n請從第一步重新開始`));
        }
      }
    } finally {
      safely(() => { $("btn-dual-complete").disabled = false; });
      safely(() => { $("btn-dual-cancel").disabled = false; });
    }
  });
  if (!unlocked || generation !== dualGeneration) return;
  // 已在 Rust 端解鎖：畫面清理失敗也必須進入主畫面；之後的錯誤不是第二步失敗，不提示重新開始。
  returnToDualStepOne();
  try {
    await enterMain(entries);
  } catch (e) {
    safely(() => errBox(String(e)));
  }
}

async function doDualCancel() {
  if (!dualLogin || dualBusy) return;
  await withDualLock(async () => {
    dualGeneration += 1;
    returnToDualStepOne();
    safely(() => errBox(""));
    try {
      await invoke("login_dual_cancel");
      safely(() => { $("key-login-status").textContent = "已取消兩步驟登入；請從第一步重新開始"; });
    } catch (e) {
      safely(() => errBox(String(e)));
    }
  });
}

async function abandonDualLogin() {
  dualGeneration += 1;
  returnToDualStepOne();
  // 取消失敗不阻擋主密碼登入；成功登入時 Rust 也會清除暫存。
  try { await invoke("login_dual_cancel"); } catch {}
}

function showDualTimeoutFeedback(message) {
  $("dual-timeout-feedback").textContent = message;
  show("dual-timeout-feedback");
}

let dualTimeoutSaving = false;

async function setDualStepTimeout() {
  if (dualTimeoutSaving) return;
  const raw = String($("dual-step-timeout").value ?? "").trim();
  const secs = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(secs) || secs < 30 || secs > 600) {
    showDualTimeoutFeedback("未套用：請輸入 30–600 秒的第二步等待時限");
    return;
  }
  const button = $("btn-set-dual-step-timeout");
  const input = $("dual-step-timeout");
  dualTimeoutSaving = true;
  try {
    button.disabled = true;
    input.disabled = true;
    showDualTimeoutFeedback("套用中，請稍候…");
    await invoke("set_dual_step_timeout", { secs });
    input.value = secs;
    showDualTimeoutFeedback(`已套用：第二步等待時限 ${secs} 秒（自下次金鑰登入起生效）`);
  } catch (e) { showDualTimeoutFeedback(`套用失敗：${String(e)}`); }
  finally {
    dualTimeoutSaving = false;
    button.disabled = false;
    input.disabled = false;
  }
}

// ─────────────── 軌跡 ───────────────
function formatLocalAuditDate(date) {
  const pad = (value, width = 2) => String(value).padStart(width, "0");
  return `${pad(date.getFullYear(), 4)}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function parseAuditDate(value) {
  if (typeof value !== "string") return null;
  const local = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value);
  const legacy = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value);
  if (!local && !legacy) return null;
  // Date normalizes nonexistent calendar days and permits 24:00. Reject those
  // explicitly instead of inventing a different timestamp for an invalid record.
  const day = new Date(`${value.slice(0, 10)}T00:00:00Z`);
  if (!Number.isFinite(day.getTime()) || day.toISOString().slice(0, 10) !== value.slice(0, 10)) return null;
  if (Number(value.slice(11, 13)) > 23 || Number(value.slice(14, 16)) > 59 || Number(value.slice(17, 19)) > 59) return null;
  // ISO local date-time (without an offset) is interpreted in the current timezone.
  // Legacy RFC3339 includes its own offset and must be converted exactly once.
  const date = new Date(local ? value.replace(" ", "T") : value);
  if (!Number.isFinite(date.getTime())) return null;
  if (local && formatLocalAuditDate(date) !== value) return null;
  return date;
}

async function renderAudit(audit) {
  const tb = document.querySelector("#audit-table tbody");
  tb.innerHTML = "";
  const ordered = audit.map((event, index) => {
    const date = parseAuditDate(event.ts);
    // Display resolution is one second. At that resolution, later append wins;
    // legacy fractional seconds must not outrank a newer local-format event.
    const time = date ? Math.floor(date.getTime() / 1000) : -Infinity;
    return { event, index, date, time };
  }).sort((a, b) => b.time - a.time || b.index - a.index);
  for (const { event: a, date } of ordered) {
    const tr = document.createElement("tr");
    const timestamp = date ? formatLocalAuditDate(date) : a.ts;
    tr.innerHTML = `<td class="mono">${esc(timestamp)}</td><td>${esc(a.event)}</td><td>${esc(a.method)}</td><td>${esc(a.detail)}</td>`;
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
    lockEntryDeleteSession();
    try { await invoke("lock", { reason: "idle" }); } catch {}
    location.reload();
  }, mins * 60 * 1000);
}

async function doLock() {
  lockEntryDeleteSession();
  try { await invoke("lock", { reason: null }); } catch {}
  location.reload();
}

// ─────────────── 事件綁定 ───────────────
document.addEventListener("DOMContentLoaded", () => {
  boot();

  $("btn-create").onclick = doCreate;
  $("btn-login-pw").onclick = doLoginPw;
  $("btn-login-key").onclick = doLoginKey;
  $("btn-login-hello").onclick = doLoginHello;
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
  $("entry-search").addEventListener("input", () => {
    entrySearchQuery = $("entry-search").value;
    renderEntries(window.__lastEntries || []);
  });
  $("btn-save-csv-template").onclick = saveCsvTemplate;
  $("btn-import-csv").onclick = previewCsvImport;
  $("btn-confirm-csv-import").onclick = confirmCsvImport;
  $("btn-cancel-csv-import").onclick = cancelCsvImport;
  bindCsvImportDialog();
  $("btn-confirm-entry-delete").onclick = confirmEntryDelete;
  $("btn-cancel-entry-delete").onclick = cancelEntryDelete;
  $("entry-delete-dialog").addEventListener("cancel", cancelEntryDelete);
  $("entry-delete-dialog").addEventListener("close", () => {
    // A queued close from an earlier opening must not invalidate a new modal.
    if (!$("entry-delete-dialog").open) {
      entryDeleteTarget = null;
      $("entry-delete-site").textContent = "";
      $("entry-delete-account").textContent = "";
      $("entry-delete-status").textContent = "";
    }
  });
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
  $("btn-register-hello").onclick = registerHello;
  $("btn-continue-registration").onclick = continueRegistration;
  $("btn-cancel-registration").onclick = cancelRegistration;
  $("btn-acknowledge-registration-cleanup").onclick = acknowledgeRegistrationCleanup;
  bindKeyNameDialog();
  $("btn-set-idle").onclick = setIdle;
  $("btn-set-password-history-limit").onclick = setPasswordHistoryLimit;
  $("btn-dual-complete").onclick = doDualComplete;
  $("btn-dual-cancel").onclick = doDualCancel;
  $("btn-set-dual-step-timeout").onclick = setDualStepTimeout;
  $("btn-lock").onclick = doLock;

  ["mousemove", "keydown", "click"].forEach((ev) => window.addEventListener(ev, resetIdle));
});

// 保留最後一次 entries 供編輯用
const _origRender = renderEntries;
renderEntries = (entries) => { window.__lastEntries = entries; _origRender(entries); };
