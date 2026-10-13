const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function node() {
  const classes = new Set(["hidden"]);
  const attributes = {};
  let children = [];
  let text = "";
  return {
    value: "", style: {}, dataset: {}, disabled: false, onclick: null,
    get textContent() { return text; }, set textContent(v) { text = String(v); },
    get children() { return children; },
    set innerHTML(_) { children = []; },
    classList: { add(s) { classes.add(s); }, remove(s) { classes.delete(s); }, contains(s) { return classes.has(s); } },
    appendChild(n) { children.push(n); }, replaceChildren(...items) { children = [...items]; },
    setAttribute(k, v) { attributes[k] = v; }, removeAttribute(k) { delete attributes[k]; },
    querySelectorAll() { return []; }, addEventListener() {},
  };
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}
function load({ edition = "single", keys = [], status = { api_ok: true, uvpa: true, console: true, local_credential: true }, handlers = {}, brokered = true } = {}) {
  const elements = new Map();
  // Mirror the HTML's initially visible password-login button.
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
    get_edition: () => edition,
    boot_info: () => ({ has_vault: true, keys, brokered_key_login: brokered }),
    platform_status: () => status,
    login_windows_hello: () => [],
    register_windows_hello: () => ({ label: "Windows Hello（本機 TEST）", key_type: "windows_managed" }),
    get_vault_settings: () => ({ idle_lock_minutes: 5, password_history_limit: 3 }),
    list_audit: () => [], list_entries: () => [],
    remove_key: () => ({ outcome: "removed" }),
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
  const visible = (id) => !$(id).classList.contains("hidden");
  return { ctx, calls, $, visible };
}
const settle = async () => { for (let i = 0; i < 10; ++i) await new Promise((r) => setImmediate(r)); };

test("single boot shows Hello only with available local credential; dual never queries status", async () => {
  for (const local of [true, false]) {
    const ui = load({ status: { api_ok: true, uvpa: true, console: true, local_credential: local } });
    await settle();
    assert.equal(ui.visible("btn-login-hello"), local);
    assert.equal(ui.calls.filter((c) => c.command === "platform_status").length, 1);
  }
  const dual = load({ edition: "dual" });
  await settle();
  assert.equal(dual.visible("btn-login-hello"), false);
  assert.equal(dual.visible("btn-register-hello"), false);
  assert.equal(dual.calls.some((c) => c.command === "platform_status"), false);
});

test("status query failure hides Hello login but preserves other login methods", async () => {
  const ui = load({ handlers: { platform_status: () => { throw Error("offline"); } } });
  await settle();
  assert.equal(ui.visible("btn-login-hello"), false);
  assert.equal(ui.visible("btn-login-pw"), true);
  assert.equal(ui.$("login-error").textContent, "");
});

test("Hello login sends no user-controlled arguments and has in-flight guard", async () => {
  const pending = deferred();
  const ui = load({ handlers: { login_windows_hello: () => pending.promise } });
  await settle();
  const first = ui.$("btn-login-hello").onclick();
  const second = ui.$("btn-login-hello").onclick();
  assert.equal(ui.$("btn-login-hello").disabled, true);
  assert.match(ui.$("hello-login-status").textContent, /Windows Hello/);
  assert.equal(ui.calls.filter((c) => c.command === "login_windows_hello").length, 1);
  assert.equal(ui.calls.find((c) => c.command === "login_windows_hello").args, undefined);
  pending.reject(Error("使用者取消"));
  await Promise.all([first, second]);
  assert.match(ui.$("login-error").textContent, /取消/);
  assert.equal(ui.$("btn-login-hello").disabled, false);
});

test("Hello registration skips YubiKey detect/name dialog and reports outcome", async () => {
  const pending = deferred();
  const ui = load({ handlers: { register_windows_hello: () => pending.promise } });
  await settle();
  await ui.ctx.enterMain([]);
  const first = ui.$("btn-register-hello").onclick();
  const second = ui.$("btn-register-hello").onclick();
  assert.equal(ui.$("btn-register-hello").disabled, true);
  assert.match(ui.$("hello-register-status").textContent, /Windows Hello/);
  assert.equal(ui.calls.filter((c) => c.command === "register_windows_hello").length, 1);
  assert.equal(ui.calls.some((c) => c.command === "detect_key" || c.command === "suggest_key_label"), false);
  pending.resolve({ label: "Windows Hello（本機 TEST）", key_type: "windows_managed" });
  await Promise.all([first, second]);
  assert.match(ui.$("hello-register-status").textContent, /已註冊/);
  assert.equal(ui.$("btn-register-hello").disabled, false);
});

test("failed registration explains possible orphan without claiming a slot was saved", async () => {
  const ui = load({ handlers: { register_windows_hello: () => { throw Error("platform assertion PRF failed"); } } });
  await settle();
  await ui.ctx.enterMain([]);
  await ui.$("btn-register-hello").onclick();
  assert.match(ui.$("hello-register-status").textContent, /失敗/);
  assert.match(ui.$("hello-register-status").textContent, /通行金鑰|殘留/);
  assert.doesNotMatch(ui.$("hello-register-status").textContent, /已註冊/);
});

test("Hello slot label is safely rendered and cleanup warning survives refresh", async () => {
  const ui = load({ keys: [{ credential_id: "one", label: "<script>", authenticator: "platform", key_type: "windows_managed", prompt_zh: "hello" }],
    handlers: { remove_key: () => ({ outcome: "manual_removal_required", warning: "delete_failed" }) } });
  await settle();
  await ui.ctx.renderKeys();
  const item = ui.$("keys-list").children[0];
  assert.match(item.children[0].textContent, /Windows Hello/);
  assert.match(item.children[0].textContent, /<script>/);
  await item.children.at(-1).onclick();
  assert.match(ui.$("key-removal-status").textContent, /手動刪除|通行金鑰/);
  assert.equal(ui.calls.filter((c) => c.command === "remove_key").length, 1);
});

test("brokered roaming button ignores platform slots and Hello login stays separate", async () => {
  const ui = load({ keys: [{ credential_id: "hello", label: "Hello", authenticator: "platform" }], brokered: true });
  await settle();
  assert.equal(ui.visible("btn-login-key"), false);
  assert.equal(ui.visible("btn-login-hello"), true);
});

test("partial capability never shows Hello even if a local credential is reported", async () => {
  const ui = load({ status: { api_ok: false, uvpa: true, console: true, local_credential: true } });
  await settle();
  assert.equal(ui.visible("btn-login-hello"), false);
});

test("dual login and key-management never expose Hello controls or call Hello IPC", async () => {
  const ui = load({ edition: "dual" });
  await settle();
  await ui.ctx.enterMain([]);
  assert.equal(ui.visible("btn-register-hello"), false);
  await ui.$("btn-login-hello").onclick();
  await ui.$("btn-register-hello").onclick();
  assert.equal(ui.calls.some((c) => /windows_hello|platform_status/.test(c.command)), false);
});

test("registration sends no user-controlled label or attachment arguments", async () => {
  const ui = load();
  await settle();
  await ui.ctx.enterMain([]);
  await ui.$("btn-register-hello").onclick();
  assert.equal(ui.calls.find((c) => c.command === "register_windows_hello").args, undefined);
});

test("failed edition identification never exposes or invokes Hello, even if status claims local", async () => {
  const ui = load({ handlers: { get_edition: () => { throw Error("edition unavailable"); } } });
  await settle();
  assert.equal(ui.visible("btn-login-hello"), false);
  assert.equal(ui.calls.some((c) => c.command === "platform_status"), false);
  await ui.ctx.enterMain([]);
  assert.equal(ui.visible("btn-register-hello"), false);
  await ui.$("btn-register-hello").onclick();
  await ui.$("btn-login-hello").onclick();
  assert.equal(ui.calls.some((c) => /windows_hello/.test(c.command)), false);
});

test("manual-removal warning survives later ordinary removal and reverse async completion", async () => {
  for (const reverse of [false, true]) {
    const a = deferred(), b = deferred();
    const keys = ["a", "b"].map((id) => ({ credential_id: id, label: id, authenticator: "platform" }));
    const ui = load({ keys, handlers: { remove_key: ({ credentialId }) => credentialId === "a" ? a.promise : b.promise } });
    await settle();
    await ui.ctx.renderKeys();
    const first = ui.$("keys-list").children[0].children.at(-1).onclick();
    const second = ui.$("keys-list").children[1].children.at(-1).onclick();
    assert.equal(ui.calls.filter((c) => c.command === "remove_key").length, 2);
    if (reverse) {
      b.resolve({ outcome: "removed" }); await second;
      a.resolve({ outcome: "manual_removal_required", warning: "not_local" }); await first;
    } else {
      a.resolve({ outcome: "manual_removal_required", warning: "delete_failed" }); await first;
      b.resolve({ outcome: "removed" }); await second;
    }
    assert.match(ui.$("key-removal-status").textContent, /手動刪除|通行金鑰/);
    assert.doesNotMatch(ui.$("key-removal-status").textContent, /^已從金庫移除金鑰$/);
  }
});

test("platform labels distinguish RP-local, foreign, and discovery-unknown without trusting saved names", async () => {
  for (const [local, expected] of [[true, "此帳號可用"], [false, "非本機"], [undefined, "未確認"]]) {
    const ui = load({ keys: [{ credential_id: "one", label: "Windows Hello（本機 OTHER-PC）",
      authenticator: "platform", platform_local: local, key_type: "windows_managed" }] });
    await settle(); await ui.ctx.renderKeys();
    const item = ui.$("keys-list").children[0];
    assert.match(item.children[1].textContent, new RegExp(expected));
    assert.match(item.children[0].textContent, /OTHER-PC/); // historical name is preserved, not trusted
  }
});

test("single roaming removal accepts legacy null outcome without an unknown-result warning", async () => {
  const ui = load({ keys: [{ credential_id: "roaming", label: "YubiKey", key_type: "fingerprint" }],
    handlers: { remove_key: () => null } });
  await settle(); await ui.ctx.renderKeys();
  await ui.$("keys-list").children[0].children.at(-1).onclick();
  assert.match(ui.$("key-removal-status").textContent, /已從金庫移除金鑰/);
  assert.doesNotMatch(ui.$("key-removal-status").textContent, /結果未知|通行金鑰可能殘留/);
});

test("static Hello controls begin hidden and have live feedback", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "src", "index.html"), "utf8");
  for (const id of ["btn-login-hello", "btn-register-hello"]) assert.match(html, new RegExp(`id="${id}"[^>]*class="[^"]*hidden`));
  for (const id of ["hello-login-status", "hello-register-status", "key-removal-status"]) assert.match(html, new RegExp(`id="${id}"[^>]*role="status"[^>]*aria-live="polite"`));
});
