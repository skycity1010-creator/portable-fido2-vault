const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function element(type = "") {
  const attributes = {};
  const listeners = new Map();
  const classes = new Set(["hidden"]);
  const node = {
    type,
    value: "",
    textContent: "",
    innerHTML: "",
    children: [],
    dataset: {},
    style: {},
    onclick: null,
    open: false,
    returnValue: "",
    showModalCount: 0,
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute(name) { return attributes[name] ?? null; },
    addEventListener(name, callback) {
      const callbacks = listeners.get(name) || [];
      callbacks.push(callback);
      listeners.set(name, callbacks);
    },
    dispatch(name, event = {}) {
      for (const callback of listeners.get(name) || []) callback(event);
    },
    appendChild(child) { this.children.push(child); },
    showModal() { this.showModalCount += 1; this.open = true; this.onShowModal?.(); },
    close(value = "") {
      this.open = false;
      this.returnValue = String(value);
      this.dispatch("close");
    },
  };
  return node;
}

function waitForDialog(ui) {
  return Promise.race([
    ui.dialogOpened.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 100)),
  ]);
}

function loadKeyNameUi({ keys = [], detected = { key_type: "fingerprint", label: "指紋型金鑰" } } = {}) {
  const elements = new Map();
  const calls = [];
  const foldKeyLabel = (value) => String(value).trim().toLowerCase().replaceAll("ς", "σ").replaceAll("ß", "ss");
  let readyHandler;
  let announceDialog;
  const dialogOpened = new Promise((resolve) => { announceDialog = resolve; });
  const dialog = element("dialog");
  dialog.onShowModal = () => announceDialog();
  elements.set("key-name-dialog", dialog);
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement(type) { return element(type); },
    querySelector() { return element(); },
    querySelectorAll() { return []; },
    addEventListener(event, callback) {
      if (event === "DOMContentLoaded") readyHandler = callback;
    },
  };
  const window = {
    addEventListener() {},
    __TAURI__: {
      core: {
        async invoke(command, args) {
          calls.push({ command, args });
          if (command === "boot_info") {
            return { has_vault: true, keys, idle_lock_minutes: 5, brokered_key_login: false };
          }
          if (command === "suggest_key_label") {
            const base = "安全性金鑰";
            let candidate = base;
            let suffix = 2;
            while (keys.some((key) => foldKeyLabel(key.label) === foldKeyLabel(candidate))) {
              candidate = `${base} ${suffix++}`;
            }
            return candidate;
          }
          if (command === "detect_key") return detected;
          if (command === "validate_key_label") {
            if (keys.some((key) => foldKeyLabel(key.label) === foldKeyLabel(args.label))) {
              throw new Error("金鑰名稱已存在，請改用其他名稱");
            }
            return undefined;
          }
          if (command === "register_key") {
            return { label: args.label, key_type: detected.key_type };
          }
          if (command === "list_entries") return [];
          if (command === "get_vault_settings") return { idle_lock_minutes: 5, password_history_limit: 3 };
          if (command === "list_audit") return [];
          return undefined;
        },
      },
    },
  };
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8");
  const context = vm.createContext({
    window,
    document,
    console,
    alert() {},
    prompt() { return null; },
    confirm() { return true; },
    setTimeout() { return 1; },
    clearTimeout() {},
  });
  vm.runInContext(source, context, { filename: "src/app.js" });
  readyHandler();
  return { context, elements, calls, dialogOpened };
}

test("registration provides an accessible local-alias dialog and plaintext warning", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "src", "index.html"), "utf8");
  assert.match(html, /<dialog[^>]*id="key-name-dialog"/);
  assert.match(html, /id="key-name-input"[^>]*required/);
  assert.match(html, /plaintext|明文/);
  assert.match(html, /FidoVault|本機|此金庫/);
  assert.match(html, /id="btn-confirm-key-name"/);
  assert.match(html, /id="btn-cancel-key-name"/);
});

test("registration disables repeat clicks while the name dialog is open", async () => {
  const ui = loadKeyNameUi();
  const button = ui.elements.get("btn-register-key");
  const registration = button.onclick();
  assert.equal(await waitForDialog(ui), true, "registration should show the alias dialog");
  const secondRegistration = button.onclick();
  await new Promise((resolve) => setImmediate(resolve));
  const disabledWhileOpen = button.disabled;
  const dialogOpenCount = ui.elements.get("key-name-dialog").showModalCount;
  const detectCallCount = ui.calls.filter((item) => item.command === "detect_key").length;
  ui.elements.get("btn-cancel-key-name").onclick();
  await Promise.all([registration, secondRegistration]);

  assert.equal(disabledWhileOpen, true);
  assert.equal(dialogOpenCount, 1);
  assert.equal(detectCallCount, 0, "cancel must happen before authenticator detection");
  assert.equal(button.disabled, false);
});

test("registration suggests an unused alias and sends the trimmed custom label", async () => {
  const ui = loadKeyNameUi({ keys: [{ label: "安全性金鑰", key_type: "fingerprint" }] });
  const registration = ui.elements.get("btn-register-key").onclick();
  assert.equal(await waitForDialog(ui), true, "registration should show the alias dialog");
  assert.equal(ui.calls.filter((item) => item.command === "suggest_key_label").length, 1);
  assert.equal(ui.calls.some((item) => item.command === "detect_key"), false);

  assert.equal(ui.elements.get("key-name-input").value, "安全性金鑰 2");
  ui.elements.get("key-name-input").value = "  Personal Backup Key  ";
  await ui.elements.get("btn-confirm-key-name").onclick();
  await registration;

  const validateIndex = ui.calls.findIndex((item) => item.command === "validate_key_label");
  const detectIndex = ui.calls.findIndex((item) => item.command === "detect_key");
  const registerIndex = ui.calls.findIndex((item) => item.command === "register_key");
  const call = ui.calls[registerIndex];
  assert.ok(call);
  assert.ok(validateIndex < detectIndex && detectIndex < registerIndex);
  assert.equal(call.args.label, "Personal Backup Key");
  assert.match(ui.elements.get("register-status").textContent, /Personal Backup Key/);
});

test("blank and duplicate names stay in the dialog, and cancel never registers", async () => {
  const ui = loadKeyNameUi({ keys: [{ label: "Recovery Key", key_type: "pin" }] });
  const registration = ui.elements.get("btn-register-key").onclick();
  assert.equal(await waitForDialog(ui), true, "registration should show the alias dialog");
  const input = ui.elements.get("key-name-input");
  const dialog = ui.elements.get("key-name-dialog");

  input.value = "   ";
  await ui.elements.get("btn-confirm-key-name").onclick();
  assert.equal(dialog.open, true);
  assert.equal(ui.calls.some((item) => item.command === "detect_key"), false);
  assert.match(ui.elements.get("key-name-status").textContent, /名稱|空白/);

  input.value = "  recovery key  ";
  await ui.elements.get("btn-confirm-key-name").onclick();
  assert.equal(dialog.open, true);
  assert.equal(ui.calls.some((item) => item.command === "detect_key"), false);
  assert.match(ui.elements.get("key-name-status").textContent, /重複|已存在/);
  assert.equal(ui.calls.some((item) => item.command === "register_key"), false);

  input.value = "Temporary Label";
  ui.elements.get("btn-cancel-key-name").onclick();
  await registration;
  assert.equal(ui.calls.some((item) => item.command === "register_key"), false);
});

test("Unicode caseless duplicates stay in the dialog without authenticator detection", async () => {
  const ui = loadKeyNameUi({ keys: [{ label: "Σ", key_type: "fingerprint" }] });
  const registration = ui.elements.get("btn-register-key").onclick();
  assert.equal(await waitForDialog(ui), true, "registration should show the alias dialog");

  ui.elements.get("key-name-input").value = "ς";
  await ui.elements.get("btn-confirm-key-name").onclick();
  assert.equal(ui.elements.get("key-name-dialog").open, true);
  assert.match(ui.elements.get("key-name-status").textContent, /已存在/);
  assert.equal(ui.calls.some((item) => item.command === "validate_key_label"), true);
  assert.equal(ui.calls.some((item) => item.command === "detect_key"), false);

  ui.elements.get("btn-cancel-key-name").onclick();
  await registration;
  assert.equal(ui.calls.some((item) => item.command === "register_key"), false);
});
