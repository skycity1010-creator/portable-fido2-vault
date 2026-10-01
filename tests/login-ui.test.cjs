const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function element() {
  const classes = new Set(["hidden"]);
  return {
    textContent: "",
    innerHTML: "",
    children: [],
    style: {},
    className: "",
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
    appendChild(child) { this.children.push(child); },
  };
}

function loadLoginUi() {
  const elements = new Map([
    ["btn-login-key", element()],
    ["login-error", element()],
    ["pin-box", element()],
    ["login-pin", element()],
  ]);
  const calls = [];
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement() { return element(); },
    querySelectorAll() { return []; },
    addEventListener() {},
  };
  const window = {
    __TAURI__: {
      core: {
        invoke: async (command, args) => {
          calls.push({ command, args });
          throw new Error("simulated broker cancellation");
        },
      },
    },
  };
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8");
  const context = vm.createContext({ window, document, console });
  vm.runInContext(source, context, { filename: "src/app.js" });
  return { context, elements, calls };
}

test("one generic key-login button replaces per-key selection cards", () => {
  const { context, elements } = loadLoginUi();
  context.renderLoginKeys([
    { credential_id: "credential-one", label: "YubiKey A", key_type: "windows_managed", prompt_zh: "Windows 提示" },
    { credential_id: "credential-two", label: "YubiKey NFC", key_type: "windows_managed", prompt_zh: "Windows 提示" },
  ], true);

  const button = elements.get("btn-login-key");
  const list = elements.get("key-list-login");
  assert.equal(button.classList.contains("hidden"), false);
  assert.equal(list.children.length, 0);
  assert.equal(button.textContent, "以金鑰登入");
  assert.doesNotMatch(button.textContent, /YubiKey A|YubiKey NFC/);
});

test("generic key-login starts without a selected credential ID", async () => {
  const { context, calls } = loadLoginUi();
  context.renderLoginKeys([{ credential_id: "credential-one", label: "YubiKey A" }], true);
  await context.doLoginKey();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "login_any_key");
  assert.equal(calls[0].args, undefined);
});

test("non-broker backend retains per-key selection and PIN login", async () => {
  const { context, elements, calls } = loadLoginUi();
  context.renderLoginKeys([
    { credential_id: "bio-id", label: "Bio", key_type: "fingerprint", prompt_zh: "按指紋" },
    { credential_id: "pin-id", label: "PIN key", key_type: "pin", prompt_zh: "輸入 PIN" },
  ], false);

  const list = elements.get("key-list-login");
  assert.equal(list.children.length, 2);
  assert.equal(elements.get("btn-login-key").classList.contains("hidden"), true);
  list.children[1].onclick();
  assert.equal(elements.get("pin-box").classList.contains("hidden"), false);
  elements.get("login-pin").value = "1234";
  await context.doLoginKey();
  assert.equal(calls[0].command, "login_key");
  assert.equal(calls[0].args.credentialId, "pin-id");
  assert.equal(calls[0].args.pin, "1234");
});

test("key-login action stays hidden when the vault has no registered keys", () => {
  const { context, elements } = loadLoginUi();
  context.renderLoginKeys([]);
  assert.equal(elements.get("btn-login-key").classList.contains("hidden"), true);
});
