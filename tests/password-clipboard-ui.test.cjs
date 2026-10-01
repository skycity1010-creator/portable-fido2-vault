const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function element(type = "") {
  const attributes = {};
  const classes = new Set(["hidden"]);
  let html = "";
  const node = {
    type,
    value: "",
    textContent: "",
    children: [],
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
    querySelectorAll(selector) {
      if (selector !== "button") return [];
      return this.children.flatMap((child) => child.buttons || []);
    },
  };
  Object.defineProperty(node, "innerHTML", {
    get() { return html; },
    set(value) {
      html = String(value);
      node.buttons = [...html.matchAll(/<button\s+([^>]*)>([^<]*)<\/button>/g)].map((match) => {
        const button = element("button");
        button.textContent = match[2];
        for (const attr of match[1].matchAll(/([\w-]+)="([^"]*)"/g)) {
          if (attr[1].startsWith("data-")) button.dataset[attr[1].slice(5)] = attr[2];
          else button.setAttribute(attr[1], attr[2]);
        }
        return button;
      });
    },
  });
  return node;
}

function loadClipboardUi({ writeError = null, readError = null, clearError = null } = {}) {
  const elements = new Map([["entries-body", element()], ["copy-password-status", element()]]);
  const writeCalls = [];
  const clearCalls = [];
  const timers = new Map();
  let nextTimerId = 1;
  let clipboardText = "";
  let alertCount = 0;
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement(type) { return element(type); },
    querySelector() { return elements.get("entries-body"); },
    querySelectorAll() { return []; },
    addEventListener() {},
  };
  const window = {
    addEventListener() {},
    __TAURI__: {
      core: { invoke: async () => undefined },
      clipboardManager: {
        async writeText(value) {
          if (writeError) throw writeError;
          writeCalls.push(value);
          clipboardText = value;
        },
        async readText() {
          if (readError) throw readError;
          return clipboardText;
        },
        async clear() {
          if (clearError) throw clearError;
          clearCalls.push(true);
          clipboardText = "";
        },
      },
    },
  };
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8");
  const context = vm.createContext({
    window,
    document,
    console,
    alert() { alertCount += 1; },
    prompt() { return null; },
    confirm() { return true; },
    setTimeout(callback, delay) {
      const id = nextTimerId++;
      timers.set(id, { callback, delay });
      return id;
    },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(source, context, { filename: "src/app.js" });
  return {
    context,
    elements,
    timers,
    writeCalls,
    clearCalls,
    get clipboardText() { return clipboardText; },
    set clipboardText(value) { clipboardText = value; },
    get alertCount() { return alertCount; },
  };
}

test("clipboard clear failure is contained and reported generically", async () => {
  const ui = loadClipboardUi({ clearError: new Error("secret-a") });
  const entries = [{ id: "entry-a", site: "a.example", account: "alice", password: "secret-a", created_at: "now", updated_at: "now" }];
  ui.context.renderEntries(entries);
  await ui.elements.get("entries-body").children[0].buttons.find((item) => item.dataset.act === "copy").onclick();
  const timer = [...ui.timers.values()].find((item) => item.delay === 60_000);

  await assert.doesNotReject(timer.callback());

  const status = ui.elements.get("copy-password-status").textContent;
  assert.match(status, /自動清除失敗/);
  assert.doesNotMatch(status, /secret-a/);
  assert.equal(ui.clipboardText, "secret-a");
});

test("clipboard read failure at expiry is contained and reported generically", async () => {
  const ui = loadClipboardUi({ readError: new Error("secret-a") });
  const entries = [{ id: "entry-a", site: "a.example", account: "alice", password: "secret-a", created_at: "now", updated_at: "now" }];
  ui.context.renderEntries(entries);
  await ui.elements.get("entries-body").children[0].buttons.find((item) => item.dataset.act === "copy").onclick();
  const timer = [...ui.timers.values()].find((item) => item.delay === 60_000);

  await assert.doesNotReject(timer.callback());

  const status = ui.elements.get("copy-password-status").textContent;
  assert.match(status, /自動清除失敗/);
  assert.doesNotMatch(status, /secret-a/);
  assert.equal(ui.clipboardText, "secret-a");
  assert.equal(ui.clearCalls.length, 0);
});

test("60-second expiry preserves clipboard text replaced by another app", async () => {
  const ui = loadClipboardUi();
  const entries = [{ id: "entry-a", site: "a.example", account: "alice", password: "secret-a", created_at: "now", updated_at: "now" }];
  ui.context.renderEntries(entries);
  await ui.elements.get("entries-body").children[0].buttons.find((item) => item.dataset.act === "copy").onclick();
  const timer = [...ui.timers.values()].find((item) => item.delay === 60_000);
  ui.clipboardText = "copied-by-another-app";

  await timer.callback();

  assert.equal(ui.clipboardText, "copied-by-another-app");
  assert.equal(ui.clearCalls.length, 0);
  assert.match(ui.elements.get("copy-password-status").textContent, /已變更|未清除/);
  assert.doesNotMatch(ui.elements.get("copy-password-status").textContent, /copied-by-another-app/);
});

test("60-second expiry clears the clipboard when the copied text is unchanged", async () => {
  const ui = loadClipboardUi();
  const entries = [{ id: "entry-a", site: "a.example", account: "alice", password: "secret-a", created_at: "now", updated_at: "now" }];
  ui.context.renderEntries(entries);
  const button = ui.elements.get("entries-body").children[0].buttons.find((item) => item.dataset.act === "copy");
  await button.onclick();

  const timer = [...ui.timers.values()].find((item) => item.delay === 60_000);
  assert.ok(timer, "copy should schedule clearing after 60 seconds");
  await timer.callback();

  assert.equal(ui.clipboardText, "");
  assert.equal(ui.clearCalls.length, 1);
  assert.match(ui.elements.get("copy-password-status").textContent, /自動清除/);
});

test("clipboard write failure is reported without exposing clipboard error details", async () => {
  const ui = loadClipboardUi({ writeError: new Error("secret-b") });
  const entries = [{ id: "entry-b", site: "b.example", account: "bob", password: "secret-b", created_at: "now", updated_at: "now" }];
  ui.context.renderEntries(entries);
  const button = ui.elements.get("entries-body").children[0].buttons.find((item) => item.dataset.act === "copy");

  await assert.doesNotReject(button.onclick());

  const status = ui.elements.get("copy-password-status").textContent;
  assert.match(status, /複製失敗/);
  assert.doesNotMatch(status, /secret-b/);
  assert.doesNotMatch(status, /clipboard error details|secret-b/);
  assert.equal(ui.timers.size, 0);
});

test("an older in-flight expiry cannot erase a later FidoVault copy", async () => {
  const ui = loadClipboardUi();
  const entries = [
    { id: "entry-a", site: "a.example", account: "alice", password: "secret-a", created_at: "now", updated_at: "now" },
    { id: "entry-b", site: "b.example", account: "bob", password: "secret-b", created_at: "now", updated_at: "now" },
  ];
  ui.context.renderEntries(entries);
  const buttons = ui.elements.get("entries-body").children.map((row) => row.buttons.find((button) => button.dataset.act === "copy"));
  await buttons[0].onclick();
  const expiry = [...ui.timers.values()][0].callback;

  let releaseClear;
  let announceClear;
  const clearStarted = new Promise((resolve) => { announceClear = resolve; });
  const clipboard = ui.context.window.__TAURI__.clipboardManager;
  const realClear = clipboard.clear;
  clipboard.clear = async () => {
    announceClear();
    await new Promise((resolve) => { releaseClear = resolve; });
    await realClear();
  };

  const expiryWork = expiry();
  await clearStarted;
  const laterCopy = buttons[1].onclick();
  releaseClear();
  await Promise.all([expiryWork, laterCopy]);

  assert.equal(ui.clipboardText, "secret-b");
});

test("each entry copies its own password and confirms without exposing the value", async () => {
  const ui = loadClipboardUi();
  const entries = [
    { id: "entry-a", site: "a.example", account: "alice", password: "secret-a", created_at: "now", updated_at: "now" },
    { id: "entry-b", site: "b.example", account: "bob", password: "secret-b", created_at: "now", updated_at: "now" },
  ];
  ui.context.renderEntries(entries);

  const row = ui.elements.get("entries-body").children[1];
  const copyButton = row.buttons.find((button) => button.dataset.act === "copy");
  assert.ok(copyButton, "each entry row should have a copy button");
  await copyButton.onclick();

  assert.deepEqual(ui.writeCalls, ["secret-b"]);
  assert.equal(ui.clipboardText, "secret-b");
  assert.match(ui.elements.get("copy-password-status").textContent, /已複製/);
  assert.doesNotMatch(ui.elements.get("copy-password-status").textContent, /secret-b/);
  assert.ok([...ui.timers.values()].some((timer) => timer.delay === 60_000));
});
