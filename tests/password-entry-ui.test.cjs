const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function element(type = "") {
  const attributes = {};
  const classes = new Set(["hidden"]);
  return {
    type,
    value: "",
    textContent: "",
    innerHTML: "",
    children: [],
    style: {},
    dataset: {},
    onclick: null,
    className: "",
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute(name) { return attributes[name] ?? null; },
    appendChild(child) { this.children.push(child); },
    addEventListener() {},
    querySelectorAll() { return []; },
  };
}

function loadEntryUi() {
  const elements = new Map([
    ["e-site", element()],
    ["e-account", element()],
    ["e-pass", element("password")],
    ["ed-pass", element("password")],
    ["entries-body", element()],
  ]);
  const calls = [];
  let readyHandler;
  let promptCalls = 0;
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement() { return element(); },
    querySelectorAll() { return []; },
    querySelector(selector) {
      if (selector === "#entries-table tbody") return elements.get("entries-body");
      return element();
    },
    addEventListener(event, callback) {
      if (event === "DOMContentLoaded") readyHandler = callback;
    },
  };
  const window = {
    addEventListener() {},
    __TAURI__: {
      core: {
        invoke: async (command, args) => {
          calls.push({ command, args });
          if (command === "boot_info") {
            return { has_vault: false, keys: [], idle_lock_minutes: 5 };
          }
          if (command === "list_entries") return [];
          if (command === "add_entry") return { id: "entry-1" };
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
    prompt() { promptCalls += 1; return "prompt-secret"; },
    alert() {},
    confirm() { return true; },
    setTimeout,
    clearTimeout,
  });
  vm.runInContext(source, context, { filename: "src/app.js" });
  readyHandler();
  return { context, elements, calls, promptCount: () => promptCalls };
}

test("add and edit password inputs are masked and have eye controls", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "src", "index.html"), "utf8");
  assert.match(html, /<input[^>]*id="e-pass"[^>]*type="password"/);
  assert.match(html, /<input[^>]*id="ed-pass"[^>]*type="password"/);
  assert.match(html, /id="btn-toggle-e-pass"/);
  assert.match(html, /id="btn-toggle-ed-pass"/);
});

test("eye controls reveal and hide only their own password field accessibly", () => {
  const { elements } = loadEntryUi();
  const addPass = elements.get("e-pass");
  const editPass = elements.get("ed-pass");
  const addToggle = elements.get("btn-toggle-e-pass");
  const editToggle = elements.get("btn-toggle-ed-pass");

  assert.equal(addPass.type, "password");
  assert.equal(editPass.type, "password");
  addToggle.onclick();
  assert.equal(addPass.type, "text");
  assert.equal(addToggle.getAttribute("aria-label"), "隱藏密碼");
  assert.equal(addToggle.getAttribute("aria-pressed"), "true");
  assert.equal(editPass.type, "password");
  addToggle.onclick();
  assert.equal(addPass.type, "password");
  assert.equal(addToggle.getAttribute("aria-label"), "顯示密碼");
  assert.equal(addToggle.getAttribute("aria-pressed"), "false");
  editToggle.onclick();
  assert.equal(editPass.type, "text");
});

test("adding an entry submits the in-app password without prompting", async () => {
  const { context, elements, calls, promptCount } = loadEntryUi();
  elements.get("e-site").value = "example.com";
  elements.get("e-account").value = "alice";
  elements.get("e-pass").value = "form-secret";

  await context.addEntry();

  const addCall = calls.find((call) => call.command === "add_entry");
  assert.ok(addCall);
  assert.equal(addCall.args.password, "form-secret");
  assert.equal(promptCount(), 0);
  assert.equal(elements.get("e-pass").value, "");
  assert.equal(elements.get("e-pass").type, "password");
});

test("opening an entry for edit always remasks its password", () => {
  const { context, elements } = loadEntryUi();
  context.window.__lastEntries = [{
    id: "entry-1",
    site: "example.com",
    account: "alice",
    password: "old-secret",
    notes: "",
  }];
  elements.get("ed-pass").type = "text";

  context.openEdit("entry-1");

  assert.equal(elements.get("ed-pass").value, "old-secret");
  assert.equal(elements.get("ed-pass").type, "password");
});
