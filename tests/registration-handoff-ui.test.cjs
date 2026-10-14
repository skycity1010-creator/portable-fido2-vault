const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

// D9-F1：註冊第二階段前景交接（「繼續驗證」／「取消」）的 UI 合約。
function node() {
  const classes = new Set(["hidden"]);
  const attributes = {};
  const listeners = new Map();
  let children = [];
  let text = "";
  const el = {
    value: "", style: {}, dataset: {}, disabled: false, onclick: null, open: false, returnValue: "",
    innerHTMLWrites: [],
    get textContent() { return text; }, set textContent(v) { text = String(v); },
    get innerHTML() { return ""; },
    set innerHTML(v) { el.innerHTMLWrites.push(String(v)); children = []; },
    get children() { return children; },
    classList: { add(s) { classes.add(s); }, remove(s) { classes.delete(s); }, contains(s) { return classes.has(s); } },
    appendChild(n) { children.push(n); }, replaceChildren(...items) { children = [...items]; },
    setAttribute(k, v) { attributes[k] = String(v); }, removeAttribute(k) { delete attributes[k]; },
    getAttribute(k) { return attributes[k] ?? null; },
    querySelectorAll() { return []; },
    addEventListener(name, callback) {
      const callbacks = listeners.get(name) || [];
      callbacks.push(callback);
      listeners.set(name, callbacks);
    },
    showModal() { el.open = true; el.onShowModal?.(); },
    close(value = "") {
      el.open = false;
      el.returnValue = String(value);
      for (const callback of listeners.get("close") || []) callback({});
      listeners.delete("close");
    },
  };
  return el;
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const HANDOFF = "金鑰已建立，但 Windows 未將焦點交回 FidoVault；請按「繼續驗證」完成註冊，或按「取消」放棄。";
const handoff = (message = HANDOFF) => ({ status: "handoff_required", message });
const registered = (label, key_type = "windows_managed") => ({ status: "registered", credential: { label, key_type } });

function load({ edition = "single", keys = [], handlers = {} } = {}) {
  const elements = new Map();
  const calls = [];
  const timers = [];
  const cleared = [];
  let ready;
  const dialog = node();
  dialog.onShowModal = () => {
    // Auto-confirm the alias dialog with the suggested name (and group A in dual).
    queueMicrotask(async () => {
      if (edition === "dual") document.getElementById("key-group-a").checked = true;
      await document.getElementById("btn-confirm-key-name").onclick();
    });
  };
  elements.set("key-name-dialog", dialog);
  const document = {
    getElementById(id) { if (!elements.has(id)) elements.set(id, node()); return elements.get(id); },
    createElement() { return node(); }, querySelector() { return node(); }, querySelectorAll() { return []; },
    addEventListener(event, callback) { if (event === "DOMContentLoaded") ready = callback; },
  };
  const defaults = {
    get_edition: () => edition,
    boot_info: () => ({ has_vault: true, keys, brokered_key_login: true }),
    platform_status: () => ({ api_ok: true, uvpa: true, console: true, local_credential: true }),
    get_vault_settings: () => ({ idle_lock_minutes: 5, password_history_limit: 3 }),
    list_audit: () => [], list_entries: () => [],
    suggest_key_label: () => "安全性金鑰",
    validate_key_label: () => undefined,
    detect_key: () => ({ key_type: "windows_managed", label: "Windows" }),
    register_key: () => handoff(),
    register_windows_hello: () => handoff(),
    continue_registration: () => registered("Windows Hello（本機 TEST）"),
    cancel_registration: () => ({ status: "cancelled", cleanup: "removed" }),
    registration_cleanup_status: () => [],
    acknowledge_registration_cleanup: () => undefined,
  };
  const window = { addEventListener() {}, __TAURI__: { core: { async invoke(command, args) {
    calls.push({ command, args });
    const handler = handlers[command] || defaults[command];
    if (!handler) throw Error(`unexpected IPC: ${command}`);
    return handler(args);
  } } } };
  const ctx = vm.createContext({ document, window, console, confirm: () => true, alert() {}, prompt: () => null,
    setTimeout: (callback, ms) => { timers.push({ callback, ms }); return timers.length; }, clearTimeout: (id) => { cleared.push(id); }, queueMicrotask });
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8");
  vm.runInContext(source, ctx, { filename: "src/app.js" });
  ready();
  const $ = (id) => document.getElementById(id);
  const visible = (id) => !$(id).classList.contains("hidden");
  const count = (command) => calls.filter((c) => c.command === command).length;
  return { ctx, calls, timers, cleared, $, visible, count };
}
const settle = async () => { for (let i = 0; i < 20; ++i) await new Promise((r) => setImmediate(r)); };
function click(ui, id) {
  assert.equal(typeof ui.$(id).onclick, "function", `${id} must be bound`);
  return ui.$(id).onclick();
}

async function helloHandoff(options = {}) {
  const ui = load(options);
  await settle();
  await ui.ctx.enterMain([]);
  await ui.$("btn-register-hello").onclick();
  await settle();
  return ui;
}

function assertKeyManagementLocked(ui, locked) {
  assert.equal(ui.$("btn-register-key").disabled, locked, "btn-register-key");
  assert.equal(ui.$("btn-register-hello").disabled, locked, "btn-register-hello");
  for (const item of ui.$("keys-list").children) {
    const remove = item.children.at(-1);
    if (remove && "disabled" in remove) assert.equal(remove.disabled, locked, "remove button");
  }
}

test("implicit failed cleanup survives reload, is displayed as text, and requires explicit acknowledgement", async () => {
  const receipts = [{ id: "11111111111111111111111111111111", generation: 17, reason: "locked", cleanup: "manual_removal_required" }];
  const ui = load({ handlers: {
    registration_cleanup_status: () => receipts,
    acknowledge_registration_cleanup: ({ id }) => {
      assert.equal(id, "11111111111111111111111111111111");
      receipts.splice(0, 1);
    },
  } });
  await settle();
  assert.ok(ui.count("registration_cleanup_status") >= 1);
  assert.equal(ui.visible("registration-cleanup-warning"), true);
  assert.match(ui.$("registration-cleanup-message").textContent, /設定 → 帳戶 → 通行金鑰.*本次/);
  assert.deepEqual(ui.$("registration-cleanup-message").innerHTMLWrites, []);
  await click(ui, "btn-acknowledge-registration-cleanup");
  await settle();
  assert.equal(ui.count("acknowledge_registration_cleanup"), 1);
  assert.equal(ui.visible("registration-cleanup-warning"), false);
});

test("lazy cleanup failure during successful registration is announced immediately", async () => {
  const receipts = [{ generation: 21, reason: "expired", cleanup: "manual_removal_required" }];
  let registrationStarted = false;
  const ui = load({ handlers: {
    registration_cleanup_status: () => registrationStarted ? receipts : [],
    register_windows_hello: () => { registrationStarted = true; return registered("Windows Hello（本機 TEST）"); },
  } });
  await settle();
  await ui.ctx.enterMain([]);
  await ui.$("btn-register-hello").onclick();
  await settle();
  assert.equal(ui.visible("registration-cleanup-warning"), true);
  assert.match(ui.$("registration-cleanup-message").textContent, /設定 → 帳戶 → 通行金鑰/);
});

test("older empty cleanup query cannot erase a newer warning", async () => {
  let queryCount = 0;
  const older = deferred();
  const newer = deferred();
  const ui = load({ handlers: { registration_cleanup_status: () => {
    queryCount += 1;
    if (queryCount === 1) return [];
    if (queryCount === 2) return older.promise;
    if (queryCount === 3) return newer.promise;
    return [{ generation: 31, reason: "expired", cleanup: "manual_removal_required" }];
  } } });
  await settle();
  const first = ui.ctx.refreshRegistrationCleanupWarning();
  const second = ui.ctx.refreshRegistrationCleanupWarning();
  newer.resolve([{ generation: 31, reason: "expired", cleanup: "manual_removal_required" }]);
  await second;
  older.resolve([]);
  await first;
  assert.equal(ui.visible("registration-cleanup-warning"), true);
  assert.match(ui.$("registration-cleanup-message").textContent, /設定 → 帳戶 → 通行金鑰/);
});

test("timer cleanup failure is polled while the handoff UI remains open", async () => {
  let failed = false;
  const ui = await helloHandoff({ handlers: {
    registration_cleanup_status: () => failed
      ? [{ generation: 27, reason: "expired", cleanup: "manual_removal_required" }]
      : [],
  } });
  const poll = ui.timers.find((t) => t.ms > 0 && t.ms <= 5000);
  assert.ok(poll, "handoff must schedule a bounded receipt check");
  failed = true;
  await poll.callback();
  await settle();
  assert.equal(ui.visible("registration-cleanup-warning"), true);
});

test("acknowledging cannot re-enable the button for an unavailable journal notice", async () => {
  let acked = false;
  const ui = load({ handlers: {
    registration_cleanup_status: () => acked
      ? [{ id: "journal-unavailable", generation: 0, reason: "storage_unavailable", cleanup: "manual_removal_required" }]
      : [{ id: "22222222222222222222222222222222", generation: 0, reason: "expired", cleanup: "manual_removal_required" }],
    acknowledge_registration_cleanup: () => { acked = true; },
  } });
  await settle();
  assert.equal(ui.$("btn-acknowledge-registration-cleanup").disabled, false);
  await click(ui, "btn-acknowledge-registration-cleanup");
  await settle();
  assert.equal(ui.visible("registration-cleanup-warning"), true);
  assert.match(ui.$("registration-cleanup-message").textContent, /儲存位置/);
  assert.equal(ui.$("btn-acknowledge-registration-cleanup").disabled, true,
    "the unacknowledgeable storage notice must keep its button disabled");
});

test("multiple receipts are acknowledged one opaque ID at a time", async () => {
  const receipts = [
    { id: "33333333333333333333333333333333", generation: 0, reason: "expired", cleanup: "manual_removal_required" },
    { id: "44444444444444444444444444444444", generation: 0, reason: "locked", cleanup: "manual_removal_required" },
  ];
  const acked = [];
  const ui = load({ handlers: {
    registration_cleanup_status: () => receipts.slice(),
    acknowledge_registration_cleanup: ({ id }) => {
      acked.push(id);
      receipts.splice(receipts.findIndex((r) => r.id === id), 1);
    },
  } });
  await settle();
  await click(ui, "btn-acknowledge-registration-cleanup");
  await settle();
  assert.deepEqual(acked, ["33333333333333333333333333333333"]);
  assert.equal(ui.visible("registration-cleanup-warning"), true, "the second receipt stays visible");
  await click(ui, "btn-acknowledge-registration-cleanup");
  await settle();
  assert.deepEqual(acked, ["33333333333333333333333333333333", "44444444444444444444444444444444"]);
  assert.equal(ui.visible("registration-cleanup-warning"), false);
});

test("receipt polling stops once the handoff is closed", async () => {
  const ui = await helloHandoff({ handlers: { cancel_registration: () => ({ status: "cancelled", cleanup: "removed" }) } });
  const poll = ui.timers.find((t) => t.ms > 0 && t.ms <= 5000);
  assert.ok(poll);
  await click(ui, "btn-cancel-registration");
  await settle();
  const queriesAfterCancel = ui.count("registration_cleanup_status");
  const timersAfterCancel = ui.timers.length;
  await poll.callback();
  await settle();
  assert.equal(ui.count("registration_cleanup_status"), queriesAfterCancel, "stale poll must not query");
  assert.equal(ui.timers.length, timersAfterCancel, "stale poll must not reschedule");
});

test("a poll during an in-flight acknowledgement cannot re-enable the button", async () => {
  const ack = deferred();
  const receipts = [{ id: "55555555555555555555555555555555", generation: 0, reason: "expired", cleanup: "manual_removal_required" }];
  const ui = load({ handlers: {
    registration_cleanup_status: () => receipts.slice(),
    acknowledge_registration_cleanup: () => ack.promise,
  } });
  await settle();
  const pending = click(ui, "btn-acknowledge-registration-cleanup");
  await settle();
  assert.equal(ui.$("btn-acknowledge-registration-cleanup").disabled, true);
  await ui.ctx.refreshRegistrationCleanupWarning(); // e.g. the handoff poll fires meanwhile
  await settle();
  assert.equal(ui.$("btn-acknowledge-registration-cleanup").disabled, true,
    "a refresh must not re-enable the button while the acknowledgement is in flight");
  receipts.splice(0, 1);
  ack.resolve();
  await pending;
  await settle();
  assert.equal(ui.visible("registration-cleanup-warning"), false);
});

test("unverified receipts use the dedicated text and are rendered as text", async () => {
  const ui = load({ handlers: { registration_cleanup_status: () => [
    { id: "66666666666666666666666666666666", generation: 0, reason: "unverified", cleanup: "manual_removal_required" },
  ] } });
  await settle();
  const message = ui.$("registration-cleanup-message");
  assert.match(message.textContent, /無法確認是否已清除/);
  assert.match(message.textContent, /只檢查並刪除本次測試項目/);
  assert.deepEqual(message.innerHTMLWrites, []);
});

test("closing the handoff clears the pending poll timer", async () => {
  const ui = await helloHandoff({ handlers: { cancel_registration: () => ({ status: "cancelled", cleanup: "removed" }) } });
  const index = ui.timers.findIndex((t) => t.ms > 0 && t.ms <= 5000);
  assert.ok(index >= 0);
  await click(ui, "btn-cancel-registration");
  await settle();
  assert.ok(ui.cleared.includes(index + 1), `timer id ${index + 1} must be cleared: ${ui.cleared}`);
});

test("static handoff block starts hidden with two buttons and live feedback", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "src", "index.html"), "utf8");
  assert.match(html, /id="registration-handoff"[^>]*class="[^"]*hidden/);
  assert.match(html, /id="registration-handoff-message"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(html, /id="btn-continue-registration"[^>]*>繼續驗證</);
  assert.match(html, /id="btn-cancel-registration"[^>]*>取消</);
});

test("Hello handoff shows the inline prompt and locks other key-management buttons", async () => {
  const keys = [{ credential_id: "one", label: "Old", authenticator: "platform", key_type: "windows_managed" }];
  const ui = await helloHandoff({ keys });
  assert.equal(ui.visible("registration-handoff"), true);
  assert.equal(ui.$("registration-handoff-message").textContent, HANDOFF);
  assert.doesNotMatch(ui.$("hello-register-status").textContent, /已註冊|失敗/);
  await ui.ctx.renderKeys();
  assertKeyManagementLocked(ui, true);
  assert.equal(ui.$("btn-continue-registration").disabled, false);
  assert.equal(ui.$("btn-cancel-registration").disabled, false);
  // A locked register button never re-enters registration.
  await ui.$("btn-register-hello").onclick();
  assert.equal(ui.count("register_windows_hello"), 1);
});

test("continue success hides the prompt, reports success and refreshes keys", async () => {
  const ui = await helloHandoff();
  const bootCalls = ui.count("boot_info");
  await click(ui, "btn-continue-registration");
  await settle();
  assert.equal(ui.count("continue_registration"), 1);
  assert.equal(ui.calls.find((c) => c.command === "continue_registration").args, undefined);
  assert.equal(ui.visible("registration-handoff"), false);
  assert.match(ui.$("hello-register-status").textContent, /已註冊 Windows Hello：Windows Hello（本機 TEST）/);
  assert.ok(ui.count("boot_info") > bootCalls, "keys list refreshed");
  assertKeyManagementLocked(ui, false);
});

test("continue that needs another handoff keeps the prompt and re-enables both buttons", async () => {
  const ui = await helloHandoff({ handlers: { continue_registration: () => handoff("再試一次：" + HANDOFF) } });
  await click(ui, "btn-continue-registration");
  await settle();
  assert.equal(ui.visible("registration-handoff"), true);
  assert.equal(ui.$("registration-handoff-message").textContent, "再試一次：" + HANDOFF);
  assert.equal(ui.$("btn-continue-registration").disabled, false);
  assert.equal(ui.$("btn-cancel-registration").disabled, false);
  assertKeyManagementLocked(ui, true);
});

test("cancel reports each cleanup outcome and unlocks key management", async () => {
  const expectations = {
    removed: /已取消.*已刪除/,
    manual_removal_required: /設定 → 帳戶 → 通行金鑰.*本次/,
    discarded: /已取消.*未新增金鑰槽/,
    none: /已取消/,
  };
  for (const [cleanup, pattern] of Object.entries(expectations)) {
    const ui = await helloHandoff({ handlers: { cancel_registration: () => ({ status: "cancelled", cleanup }) } });
    await click(ui, "btn-cancel-registration");
    await settle();
    assert.equal(ui.count("cancel_registration"), 1, cleanup);
    assert.equal(ui.visible("registration-handoff"), false, cleanup);
    assert.match(ui.$("hello-register-status").textContent, pattern, cleanup);
    assert.doesNotMatch(ui.$("hello-register-status").textContent, /已註冊 Windows Hello/, cleanup);
    assertKeyManagementLocked(ui, false);
  }
});

test("handoff message is rendered as text, never parsed as HTML", async () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const ui = await helloHandoff({ handlers: { register_windows_hello: () => handoff(hostile) } });
  const message = ui.$("registration-handoff-message");
  assert.equal(message.textContent, hostile);
  assert.deepEqual(message.innerHTMLWrites, []);
  assert.deepEqual(ui.$("registration-handoff").innerHTMLWrites, []);
});

test("continue/cancel are locked while in flight and restored after an error", async () => {
  const pending = deferred();
  const ui = await helloHandoff({ handlers: { continue_registration: () => pending.promise } });
  const first = click(ui, "btn-continue-registration");
  assert.equal(ui.$("btn-continue-registration").disabled, true);
  assert.equal(ui.$("btn-cancel-registration").disabled, true);
  await click(ui, "btn-continue-registration");
  await click(ui, "btn-cancel-registration");
  assert.equal(ui.count("continue_registration"), 1);
  assert.equal(ui.count("cancel_registration"), 0);
  pending.reject(Error("Windows could not activate the visible FidoVault window"));
  await first;
  await settle();
  assert.equal(ui.$("btn-continue-registration").disabled, false);
  assert.equal(ui.$("btn-cancel-registration").disabled, false);
  assert.equal(ui.visible("registration-handoff"), true, "user can still retry or cancel");
  assert.match(ui.$("hello-register-status").textContent, /失敗.*activate/);
  assertKeyManagementLocked(ui, true);
});

test("YubiKey registration shares the handoff path, including dual group messages", async () => {
  for (const edition of ["single", "dual"]) {
    const ui = load({ edition, handlers: { continue_registration: () => registered("安全性金鑰", "windows_managed") } });
    await settle();
    await ui.ctx.enterMain([]);
    await ui.$("btn-register-key").onclick();
    await settle();
    assert.equal(ui.count("register_key"), 1, edition);
    assert.equal(ui.visible("registration-handoff"), true, edition);
    assert.equal(ui.$("btn-register-key").disabled, true, edition);
    await click(ui, "btn-continue-registration");
    await settle();
    assert.equal(ui.visible("registration-handoff"), false, edition);
    const status = ui.$("register-status").textContent;
    assert.match(status, /已註冊：安全性金鑰/, edition);
    if (edition === "dual") assert.match(status, /A 群組/);
    assert.equal(ui.$("btn-register-key").disabled, false, edition);
  }
});

test("registered responses keep the existing success messages", async () => {
  const ui = load({ handlers: { register_windows_hello: () => registered("Windows Hello（本機 PC）") } });
  await settle();
  await ui.ctx.enterMain([]);
  await ui.$("btn-register-hello").onclick();
  await settle();
  assert.equal(ui.visible("registration-handoff"), false);
  assert.match(ui.$("hello-register-status").textContent, /已註冊 Windows Hello：Windows Hello（本機 PC）/);
  assert.equal(ui.count("continue_registration"), 0);
});
