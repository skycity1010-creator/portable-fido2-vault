const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

// D9-F2 R2：WebAuthn / 建立金庫指令離開主執行緒後 UI 不再被凍結，所以登入類入口必須在 JS 端
// 自己擋下重入（雙擊、PIN／密碼欄 Enter、跨登入方式），而不是只靠按鈕 disabled。
// 這裡用未完成的 Promise 模擬進行中的 IPC，驅動真正的 app.js 事件處理。
function node() {
  const classes = new Set(["hidden"]);
  const attributes = {};
  const listeners = {};
  let children = [];
  let text = "";
  return {
    value: "", style: {}, dataset: {}, disabled: false, onclick: null, listeners,
    get textContent() { return text; }, set textContent(v) { text = String(v); },
    get children() { return children; },
    set innerHTML(_) { children = []; },
    classList: { add(s) { classes.add(s); }, remove(s) { classes.delete(s); }, contains(s) { return classes.has(s); } },
    appendChild(n) { children.push(n); }, replaceChildren(...items) { children = [...items]; },
    setAttribute(k, v) { attributes[k] = v; }, removeAttribute(k) { delete attributes[k]; },
    querySelectorAll() { return []; },
    addEventListener(event, callback) { listeners[event] = callback; },
  };
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const settle = async () => { for (let i = 0; i < 10; ++i) await new Promise((r) => setImmediate(r)); };

function load({ handlers = {} } = {}) {
  const elements = new Map();
  elements.set("btn-login-pw", node());
  elements.get("btn-login-pw").classList.remove("hidden");
  const calls = [];
  let ready;
  const document = {
    getElementById(id) { if (!elements.has(id)) elements.set(id, node()); return elements.get(id); },
    createElement() { return node(); }, querySelector() { return node(); }, querySelectorAll() { return []; },
    addEventListener(event, callback) { if (event === "DOMContentLoaded") ready = callback; },
  };
  const defaults = {
    get_edition: () => "single",
    boot_info: () => ({ has_vault: true, keys: [], brokered_key_login: true }),
    platform_status: () => ({ api_ok: true, uvpa: true, console: true, local_credential: true }),
    get_vault_settings: () => ({ idle_lock_minutes: 5, password_history_limit: 3 }),
    list_audit: () => [], list_entries: () => [],
    registration_cleanup_status: () => [],
    create_vault: () => null,
    login_password: () => [], login_any_key: () => [], login_windows_hello: () => [],
  };
  const window = { addEventListener() {}, __TAURI__: { core: { async invoke(command, args) {
    calls.push({ command, args });
    const handler = handlers[command] || defaults[command];
    if (!handler) throw Error(`unexpected IPC: ${command}`);
    return handler(args);
  } } } };
  const ctx = vm.createContext({ document, window, console, confirm: () => true, alert() {},
    setTimeout: () => 1, clearTimeout() {} });
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8");
  vm.runInContext(source, ctx, { filename: "src/app.js" });
  ready();
  const $ = (id) => document.getElementById(id);
  const count = (command) => calls.filter((c) => c.command === command).length;
  return { ctx, calls, $, count };
}

test("doCreate: a double click or Enter while create_vault is pending sends one IPC", async () => {
  const pending = deferred();
  const ui = load({ handlers: { create_vault: () => pending.promise } });
  await settle();
  ui.$("setup-pw").value = "synthetic-password-8";
  ui.$("setup-pw2").value = "synthetic-password-8";
  const first = ui.ctx.doCreate();
  const second = ui.ctx.doCreate();
  const third = ui.$("btn-create").onclick();
  assert.equal(ui.count("create_vault"), 1);
  pending.resolve(null);
  await Promise.all([first, second, third]);
  assert.equal(ui.count("create_vault"), 1, "still exactly one creation after completion");
});

test("doCreate: the in-flight lock is released after a failure so the user can retry", async () => {
  const failing = deferred();
  const ui = load({ handlers: { create_vault: () => failing.promise } });
  await settle();
  ui.$("setup-pw").value = "synthetic-password-8";
  ui.$("setup-pw2").value = "synthetic-password-8";
  const first = ui.ctx.doCreate();
  failing.reject(Error("simulated failure"));
  await first;
  assert.match(ui.$("login-error").textContent, /simulated failure/);
  await ui.ctx.doCreate();
  assert.equal(ui.count("create_vault"), 2);
});

test("doLoginKey: PIN-field Enter and button clicks while the key login is pending do not re-enter", async () => {
  const pending = deferred();
  const ui = load({ handlers: { login_any_key: () => pending.promise } });
  await settle();
  const first = ui.$("btn-login-key").onclick();
  const enter = ui.$("login-pin").listeners.keydown({ key: "Enter" });
  const again = ui.ctx.doLoginKey();
  assert.equal(ui.count("login_any_key"), 1);
  pending.reject(Error("使用者取消"));
  await Promise.all([first, enter, again]);
  assert.equal(ui.count("login_any_key"), 1);
  // After the failure the lock is gone: the user can try again.
  await ui.ctx.doLoginKey();
  assert.equal(ui.count("login_any_key"), 2);
});

test("login methods share one in-flight lock across password, key, Hello and create", async () => {
  const pending = deferred();
  const ui = load({ handlers: { login_any_key: () => pending.promise } });
  await settle();
  ui.$("setup-pw").value = "synthetic-password-8";
  ui.$("setup-pw2").value = "synthetic-password-8";
  ui.$("login-pw").value = "synthetic-password-8";
  const key = ui.ctx.doLoginKey();
  await Promise.all([
    ui.ctx.doLoginPw(),
    ui.$("login-pw").listeners.keydown({ key: "Enter" }),
    ui.ctx.doLoginHello(),
    ui.ctx.doCreate(),
  ]);
  assert.equal(ui.count("login_password"), 0);
  assert.equal(ui.count("login_windows_hello"), 0);
  assert.equal(ui.count("create_vault"), 0);
  pending.resolve([]);
  await key;
  assert.equal(ui.count("login_any_key"), 1);
});

test("doLoginPw (single edition): a second Enter while the password login is pending is ignored", async () => {
  const pending = deferred();
  const ui = load({ handlers: { login_password: () => pending.promise } });
  await settle();
  ui.$("login-pw").value = "synthetic-password-8";
  const first = ui.$("login-pw").listeners.keydown({ key: "Enter" });
  const second = ui.$("btn-login-pw").onclick();
  assert.equal(ui.count("login_password"), 1);
  pending.resolve([]);
  await Promise.all([first, second]);
  assert.equal(ui.count("login_password"), 1);
});
