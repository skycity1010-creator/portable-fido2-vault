// D10：雙群組控管版前端（edition 切換、兩步驟登入、群組註冊、金鑰清單、時限設定、break-glass 提示）。
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function element(id) {
  const attributes = {};
  const listeners = new Map();
  const classes = new Set(["hidden"]);
  let children = [];
  let html = "";
  const node = {
    id,
    value: "",
    checked: false,
    disabled: false,
    title: "",
    textContent: "",
    dataset: {},
    style: {},
    onclick: null,
    open: false,
    returnValue: "",
    get children() { return children; },
    get innerHTML() { return html; },
    set innerHTML(value) { html = String(value); children = []; },
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute(name) { return attributes[name] ?? null; },
    removeAttribute(name) { delete attributes[name]; },
    addEventListener(name, callback) {
      const callbacks = listeners.get(name) || [];
      callbacks.push(callback);
      listeners.set(name, callbacks);
    },
    dispatch(name, event = {}) {
      for (const callback of listeners.get(name) || []) callback(event);
    },
    appendChild(child) { children.push(child); return child; },
    replaceChildren(...nodes) { children = [...nodes]; },
    showModal() { this.open = true; },
    close(value = "") {
      this.open = false;
      this.returnValue = String(value);
      this.dispatch("close");
    },
    focus() {},
    querySelectorAll() { return []; },
  };
  return node;
}

function walk(node, visit) {
  visit(node);
  for (const child of node.children || []) walk(child, visit);
}
function allText(node) {
  const parts = [];
  walk(node, (item) => { if (item.textContent) parts.push(item.textContent); });
  return parts.join(" ");
}
const visible = (node) => !node.classList.contains("hidden");

async function flush() {
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

const KEYS_AB = [
  { credential_id: "a1", label: "王小明", key_type: "windows_managed", prompt_zh: "Windows 提示", group: "A", last_in_group: true },
  { credential_id: "b1", label: "李小華", key_type: "windows_managed", prompt_zh: "Windows 提示", group: "B", last_in_group: true },
];

function loadUi({ edition = "dual", keys = KEYS_AB, brokered = true, handlers = {}, settings } = {}) {
  const elements = new Map();
  const calls = [];
  const alerts = [];
  const clock = { now: 1_000_000 };
  const intervals = new Map();
  let nextTimer = 1;
  let readyHandler;
  const document = {
    title: "可攜式 FIDO2 密碼金庫",
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element(id));
      return elements.get(id);
    },
    createElement(type) { const node = element(""); node.tagName = String(type).toUpperCase(); return node; },
    querySelector() { return element(""); },
    querySelectorAll() { return []; },
    addEventListener(event, callback) {
      if (event === "DOMContentLoaded") readyHandler = callback;
    },
  };
  const defaults = {
    get_edition: () => edition,
    boot_info: () => ({ has_vault: true, keys, idle_lock_minutes: 5, brokered_key_login: brokered }),
    list_entries: () => [],
    get_vault_settings: () => settings || (edition === "dual"
      ? { idle_lock_minutes: 5, password_history_limit: 3, dual_step_timeout_secs: 120 }
      : { idle_lock_minutes: 5, password_history_limit: 3 }),
    list_audit: () => [],
    login_password: () => [],
    login_any_key: () => [],
    login_dual_begin: () => ({ first_group: "A", first_label: "王小明", second_group: "B", timeout_secs: 120, remaining_ms: 120_000 }),
    login_dual_complete: () => [],
    login_dual_cancel: () => undefined,
    suggest_key_label: () => "安全性金鑰",
    validate_key_label: () => undefined,
    detect_key: () => ({ key_type: "windows_managed", label: "Windows" }),
    register_key: (args) => ({ label: args.label, key_type: "windows_managed" }),
    remove_key: () => undefined,
    set_dual_step_timeout: () => undefined,
    lock: () => ({}),
  };
  const window = {
    addEventListener() {},
    __TAURI__: {
      core: {
        async invoke(command, args) {
          calls.push({ command, args });
          const handler = handlers[command] || defaults[command];
          return handler ? handler(args) : undefined;
        },
      },
    },
  };
  const context = vm.createContext({
    window,
    document,
    console,
    location: { reload() {} },
    Date: { now: () => clock.now },
    alert(message) { alerts.push(String(message)); },
    prompt() { return null; },
    confirm() { return true; },
    setTimeout() { return nextTimer++; },
    clearTimeout() {},
    setInterval(callback) { const timer = nextTimer++; intervals.set(timer, callback); return timer; },
    clearInterval(timer) { intervals.delete(timer); },
  });
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8");
  vm.runInContext(source, context, { filename: "src/app.js" });
  readyHandler();
  const advance = (ms) => {
    clock.now += ms;
    for (const callback of [...intervals.values()]) callback();
  };
  return { context, document, elements, calls, alerts, intervals, advance, $: (id) => document.getElementById(id) };
}

const commands = (ui) => ui.calls.map((item) => item.command);

// ─────────────── HTML ───────────────
test("dual-control controls exist in the HTML and start hidden", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "src", "index.html"), "utf8");
  for (const id of ["edition-badge", "dual-login-hint", "dual-step-panel", "breakglass-banner", "dual-key-status", "dual-settings", "key-group-fieldset"]) {
    assert.match(html, new RegExp(`id="${id}"[^>]*class="[^"]*hidden`), `${id} must start hidden`);
  }
  assert.match(html, /<input type="radio" name="key-group" id="key-group-a" value="A"/);
  assert.match(html, /<input type="radio" name="key-group" id="key-group-b" value="B"/);
  assert.doesNotMatch(html, /id="key-group-[ab]"[^>]*checked/, "group radios must have no default");
  assert.match(html, /id="dual-step-timeout"[^>]*min="30"[^>]*max="600"/);
  assert.match(html, /id="btn-dual-complete"/);
  assert.match(html, /id="btn-dual-cancel"/);
  assert.match(html, /緊急登入/);
});

// ─────────────── edition 切換 ───────────────
test("single edition keeps the generic key login and hides dual controls", async () => {
  const ui = loadUi({ edition: "single", keys: [{ credential_id: "k1", label: "K1", key_type: "windows_managed", prompt_zh: "p" }] });
  await flush();
  assert.equal(visible(ui.$("edition-badge")), false);
  assert.equal(visible(ui.$("dual-login-hint")), false);
  assert.equal(ui.$("btn-login-key").textContent, "以金鑰登入");
  assert.equal(ui.document.title, "可攜式 FIDO2 密碼金庫");
  await ui.$("btn-login-key").onclick();
  await flush();
  assert.ok(commands(ui).includes("login_any_key"));
  assert.equal(commands(ui).includes("login_dual_begin"), false);
});

test("dual edition shows the edition label and a first-step key login when A and B both have keys", async () => {
  const ui = loadUi();
  await flush();
  assert.equal(visible(ui.$("edition-badge")), true, "edition badge");
  assert.match(ui.document.title, /雙群組控管版/);
  assert.equal(visible(ui.$("btn-login-key")), true);
  assert.equal(ui.$("btn-login-key").textContent, "以金鑰登入（第一步）");
  assert.equal(visible(ui.$("dual-login-hint")), true);
  assert.match(ui.$("dual-login-hint").textContent, /A 群組.*B 群組/);
  assert.equal(visible(ui.$("pin-box")), false, "brokered login needs no PIN box");
});

test("dual key login is disabled until both A and B groups have a key", async () => {
  for (const keys of [[KEYS_AB[0]], [KEYS_AB[1]], []]) {
    const ui = loadUi({ keys });
    await flush();
    assert.equal(visible(ui.$("btn-login-key")), false, `keys=${keys.length}`);
    assert.equal(visible(ui.$("dual-login-hint")), true);
    assert.match(ui.$("dual-login-hint").textContent, /需 A、B 群組各至少一支金鑰；目前請以主密碼登入/);
  }
});

// ─────────────── 兩步驟登入 ───────────────
test("A then B: first step shows who verified, a countdown, and the second step unlocks", async () => {
  const ui = loadUi();
  await flush();
  await ui.$("btn-login-key").onclick();
  await flush();
  const begin = ui.calls.find((item) => item.command === "login_dual_begin");
  assert.ok(begin, "login_dual_begin must be called");
  assert.equal(begin.args.pin, null);
  assert.equal(commands(ui).includes("login_any_key"), false);
  assert.equal(visible(ui.$("dual-step-panel")), true);
  assert.equal(visible(ui.$("btn-login-key")), false);
  assert.match(ui.$("dual-step-text").textContent, /A 群組（王小明）已驗證，請 B 群組成員於 120 秒內完成驗證/);
  assert.equal(ui.$("dual-step-text").innerHTML, "", "labels must not be rendered as HTML");
  assert.match(ui.$("dual-countdown").textContent, /剩餘 120 秒/);
  ui.advance(30_000);
  assert.match(ui.$("dual-countdown").textContent, /剩餘 90 秒/);

  await ui.$("btn-dual-complete").onclick();
  await flush();
  assert.ok(commands(ui).includes("login_dual_complete"));
  assert.equal(visible(ui.$("screen-main")), true);
  assert.equal(visible(ui.$("dual-step-panel")), false);
  assert.equal(visible(ui.$("breakglass-banner")), false, "key login is not break-glass");
  assert.equal(ui.intervals.size, 0, "countdown must stop after unlock");
});

test("B then A order is reported as returned by Rust", async () => {
  const ui = loadUi({ handlers: { login_dual_begin: () => ({ first_group: "B", first_label: "李小華", second_group: "A", timeout_secs: 60, remaining_ms: 59_400 }) } });
  await flush();
  await ui.$("btn-login-key").onclick();
  await flush();
  assert.match(ui.$("dual-step-text").textContent, /B 群組（李小華）已驗證，請 A 群組成員於 60 秒內完成驗證/);
  assert.match(ui.$("dual-countdown").textContent, /剩餘 60 秒/);
  assert.match(ui.$("btn-dual-complete").textContent, /A 群組/);
});

test("second-step failure returns to step one and cannot be retried without a new first step", async () => {
  const ui = loadUi({ handlers: { login_dual_complete: () => { throw new Error("金鑰解鎖失敗"); } } });
  await flush();
  await ui.$("btn-login-key").onclick();
  await flush();
  await ui.$("btn-dual-complete").onclick();
  await flush();
  assert.match(ui.$("login-error").textContent, /金鑰解鎖失敗/);
  assert.match(ui.$("login-error").textContent, /請從第一步重新開始/);
  assert.equal(visible(ui.$("dual-step-panel")), false);
  assert.equal(visible(ui.$("btn-login-key")), true);
  assert.equal(ui.$("btn-login-key").disabled, false);
  assert.equal(visible(ui.$("screen-main")), false);
  assert.equal(ui.intervals.size, 0);
  await ui.$("btn-dual-complete").onclick();
  await flush();
  assert.equal(ui.calls.filter((item) => item.command === "login_dual_complete").length, 1);
});

test("cancel discards the pending first step in Rust and resets the screen", async () => {
  const ui = loadUi();
  await flush();
  await ui.$("btn-login-key").onclick();
  await flush();
  await ui.$("btn-dual-cancel").onclick();
  await flush();
  assert.ok(commands(ui).includes("login_dual_cancel"));
  assert.equal(visible(ui.$("dual-step-panel")), false);
  assert.equal(visible(ui.$("btn-login-key")), true);
  assert.match(ui.$("key-login-status").textContent, /已取消/);
  assert.equal(ui.intervals.size, 0);
});

test("countdown expiry resets to step one without a cancel or second-step call", async () => {
  const ui = loadUi();
  await flush();
  await ui.$("btn-login-key").onclick();
  await flush();
  ui.advance(120_001);
  await flush();
  assert.equal(visible(ui.$("dual-step-panel")), false);
  assert.match(ui.$("login-error").textContent, /逾時/);
  assert.equal(visible(ui.$("btn-login-key")), true);
  assert.equal(ui.intervals.size, 0);
  await ui.$("btn-dual-complete").onclick();
  await flush();
  assert.equal(commands(ui).includes("login_dual_complete"), false);
  assert.equal(commands(ui).includes("login_dual_cancel"), false, "Rust sweeps the expired step itself");
});

test("first-step failure stays on step one", async () => {
  const ui = loadUi({ handlers: { login_dual_begin: () => { throw new Error("已取消 Windows 安全性"); } } });
  await flush();
  await ui.$("btn-login-key").onclick();
  await flush();
  assert.match(ui.$("login-error").textContent, /已取消 Windows 安全性/);
  assert.equal(visible(ui.$("dual-step-panel")), false);
  assert.equal(visible(ui.$("btn-login-key")), true);
  assert.equal(ui.$("btn-login-key").disabled, false);
  assert.equal(ui.intervals.size, 0);
});

test("repeated first-step clicks start only one Rust first step", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const ui = loadUi({ handlers: { login_dual_begin: async () => { await gate; return { first_group: "A", first_label: "王小明", second_group: "B", timeout_secs: 120, remaining_ms: 120_000 }; } } });
  await flush();
  const first = ui.$("btn-login-key").onclick();
  const second = ui.$("btn-login-key").onclick();
  release();
  await Promise.all([first, second]);
  await flush();
  assert.equal(ui.calls.filter((item) => item.command === "login_dual_begin").length, 1);
});

test("non-broker backends read an optional PIN for each step separately", async () => {
  const ui = loadUi({ brokered: false });
  await flush();
  assert.equal(visible(ui.$("pin-box")), true);
  ui.$("login-pin").value = "1234";
  await ui.$("btn-login-key").onclick();
  await flush();
  assert.equal(ui.calls.find((item) => item.command === "login_dual_begin").args.pin, "1234");
  assert.equal(ui.$("login-pin").value, "", "first member's PIN must be cleared");
  ui.$("login-pin").value = "5678";
  await ui.$("btn-dual-complete").onclick();
  await flush();
  assert.equal(ui.calls.find((item) => item.command === "login_dual_complete").args.pin, "5678");
});

// ─────────────── break-glass ───────────────
test("switching to the master password during a pending step cancels it first and shows the break-glass banner", async () => {
  const ui = loadUi();
  await flush();
  await ui.$("btn-login-key").onclick();
  await flush();
  ui.$("login-pw").value = "correct horse";
  await ui.$("btn-login-pw").onclick();
  await flush();
  const order = commands(ui);
  assert.ok(order.includes("login_dual_cancel"), "pending first step must be cancelled");
  assert.ok(order.indexOf("login_dual_cancel") < order.indexOf("login_password"));
  assert.equal(visible(ui.$("screen-main")), true);
  assert.equal(visible(ui.$("breakglass-banner")), true);
  assert.equal(ui.intervals.size, 0);
});

test("dual master-password login shows the break-glass banner; single edition does not", async () => {
  const dual = loadUi();
  await flush();
  dual.$("login-pw").value = "pw";
  await dual.$("btn-login-pw").onclick();
  await flush();
  assert.equal(visible(dual.$("breakglass-banner")), true);
  assert.equal(commands(dual).includes("login_dual_cancel"), false, "no pending step to cancel");

  const single = loadUi({ edition: "single", keys: [] });
  await flush();
  await single.$("btn-login-pw").onclick();
  await flush();
  assert.equal(visible(single.$("screen-main")), true);
  assert.equal(visible(single.$("breakglass-banner")), false);
});

// ─────────────── 註冊 ───────────────
test("dual registration requires a group choice and sends it to Rust", async () => {
  const ui = loadUi();
  await flush();
  await ui.$("btn-login-pw").onclick();
  await flush();
  const registration = ui.$("btn-register-key").onclick();
  await flush();
  const dialog = ui.$("key-name-dialog");
  assert.equal(dialog.open, true);
  assert.equal(visible(ui.$("key-group-fieldset")), true);
  assert.equal(ui.$("key-group-a").checked, false);
  assert.equal(ui.$("key-group-b").checked, false);
  ui.$("key-name-input").value = "陳大同";
  await ui.$("btn-confirm-key-name").onclick();
  await flush();
  assert.equal(dialog.open, true, "missing group keeps the dialog open");
  assert.match(ui.$("key-name-status").textContent, /請選擇.*群組/);
  assert.equal(commands(ui).includes("detect_key"), false);

  ui.$("key-group-b").checked = true;
  await ui.$("btn-confirm-key-name").onclick();
  await registration;
  await flush();
  const call = ui.calls.find((item) => item.command === "register_key");
  assert.ok(call, "register_key must be called");
  assert.equal(call.args.group, "B");
  assert.equal(call.args.label, "陳大同");
  assert.match(ui.$("register-status").textContent, /B 群組/);

  const again = ui.$("btn-register-key").onclick();
  await flush();
  assert.equal(ui.$("key-group-a").checked, false, "group choice resets on reopen");
  assert.equal(ui.$("key-group-b").checked, false, "group choice resets on reopen");
  ui.$("btn-cancel-key-name").onclick();
  await again;
});

test("single registration sends no group argument and hides the group choice", async () => {
  const ui = loadUi({ edition: "single", keys: [] });
  await flush();
  await ui.$("btn-login-pw").onclick();
  await flush();
  const registration = ui.$("btn-register-key").onclick();
  await flush();
  assert.equal(visible(ui.$("key-group-fieldset")), false);
  ui.$("key-name-input").value = "K1";
  await ui.$("btn-confirm-key-name").onclick();
  await registration;
  await flush();
  const call = ui.calls.find((item) => item.command === "register_key");
  assert.ok(call);
  assert.equal(Object.prototype.hasOwnProperty.call(call.args, "group"), false);
});

// ─────────────── 金鑰清單 ───────────────
test("dual key list groups keys, shows counts, and disables removing a group's last key", async () => {
  const keys = [
    { credential_id: "b2", label: "陳大同", key_type: "windows_managed", prompt_zh: "p", group: "B" },
    { credential_id: "a1", label: "<img src=x>", key_type: "windows_managed", prompt_zh: "p", group: "A", last_in_group: true },
    { credential_id: "b1", label: "李小華", key_type: "windows_managed", prompt_zh: "p", group: "B" },
  ];
  const ui = loadUi({ keys });
  await flush();
  await ui.$("btn-login-pw").onclick();
  await flush();
  const list = ui.$("keys-list");
  const text = allText(list);
  assert.ok(text.indexOf("A 群組") >= 0 && text.indexOf("A 群組") < text.indexOf("B 群組"), "A section before B section");
  assert.match(ui.$("dual-key-status").textContent, /A 群組 1 支、B 群組 2 支/);
  assert.equal(visible(ui.$("dual-key-status")), true);
  assert.match(ui.$("keys-hint").textContent, /A 群組.*B 群組/);
  const buttons = {};
  walk(list, (node) => { if (node.dataset && node.dataset.credentialId) buttons[node.dataset.credentialId] = node; });
  assert.equal(buttons.a1.disabled, true);
  assert.match(buttons.a1.title, /不可刪除 A 群組的最後一支金鑰/);
  assert.equal(buttons.b1.disabled, false);
  walk(list, (node) => assert.doesNotMatch(node.innerHTML, /<img/));
  await buttons.a1.onclick();
  await flush();
  assert.equal(commands(ui).includes("remove_key"), false, "disabled button must not remove");
  await buttons.b1.onclick();
  await flush();
  const removal = ui.calls.find((item) => item.command === "remove_key");
  assert.ok(removal);
  assert.equal(removal.args.credentialId, "b1");
});

// ─────────────── 時限設定 ───────────────
test("dual timeout setting loads the vault value and validates 30–600 seconds before saving", async () => {
  const ui = loadUi({ settings: { idle_lock_minutes: 5, password_history_limit: 3, dual_step_timeout_secs: 90 } });
  await flush();
  await ui.$("btn-login-pw").onclick();
  await flush();
  assert.equal(visible(ui.$("dual-settings")), true);
  assert.equal(String(ui.$("dual-step-timeout").value), "90");
  for (const bad of ["29", "601", "abc", "45.5"]) {
    ui.$("dual-step-timeout").value = bad;
    await ui.$("btn-set-dual-step-timeout").onclick();
    await flush();
    assert.match(ui.alerts.at(-1) || "", /30–600/, `value ${bad}`);
  }
  assert.equal(commands(ui).includes("set_dual_step_timeout"), false);
  ui.$("dual-step-timeout").value = "60";
  await ui.$("btn-set-dual-step-timeout").onclick();
  await flush();
  const call = ui.calls.find((item) => item.command === "set_dual_step_timeout");
  assert.ok(call);
  assert.equal(call.args.secs, 60);
  assert.match(ui.alerts.at(-1), /60 秒/);
});

test("single edition hides the dual timeout setting", async () => {
  const ui = loadUi({ edition: "single", keys: [] });
  await flush();
  await ui.$("btn-login-pw").onclick();
  await flush();
  assert.equal(visible(ui.$("dual-settings")), false);
  assert.equal(visible(ui.$("dual-key-status")), false);
});
