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

function loadHistoryUi() {
  const elements = new Map([
    ["e-pass", element("password")],
    ["ed-pass", element("password")],
    ["ed-pass-history", element()],
    ["ed-pass-history-status", element()],
    ["password-history-limit", element()],
    ["idle-minutes", element()],
    ["entries-body", element()],
    ["audit-body", element()],
  ]);
  const calls = [];
  const alerts = [];
  const entries = [{
    id: "entry-1",
    site: "example.com",
    account: "alice",
    password: "current-secret",
    password_history: [
      { id: "history-1", password: "older-secret", archived_at: "2026-09-30T10:00:00Z" },
      { id: "history-2", password: "oldest-secret", archived_at: "2026-09-20T10:00:00Z" },
    ],
    notes: "",
    created_at: "2026-09-01T00:00:00Z",
    updated_at: "2026-09-30T10:00:00Z",
  }];
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement() { return element(); },
    querySelectorAll() { return []; },
    querySelector(selector) {
      if (selector === "#entries-table tbody") return elements.get("entries-body");
      if (selector === "#audit-table tbody") return elements.get("audit-body");
      return element();
    },
    addEventListener() {},
  };
  const window = {
    addEventListener() {},
    __TAURI__: {
      core: {
        invoke: async (command, args) => {
          calls.push({ command, args });
          if (command === "get_vault_settings") {
            return { idle_lock_minutes: 7, password_history_limit: 4 };
          }
          if (command === "list_entries") return entries;
          if (command === "list_audit") return [];
          if (command === "boot_info") return { keys: [], brokered_key_login: true };
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
    alert(message) { alerts.push(String(message)); },
    prompt() { return null; },
    confirm() { return true; },
    setTimeout() { return 1; },
    clearTimeout() {},
  });
  vm.runInContext(source, context, { filename: "src/app.js" });
  return { context, elements, calls, alerts, entries };
}

test("history limit setting is bounded and defaults to 3", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "src", "index.html"), "utf8");
  assert.match(html, /id="password-history-limit"[^>]*type="number"[^>]*min="1"[^>]*max="20"[^>]*value="3"/);
  assert.match(html, /id="btn-set-password-history-limit"/);
  assert.match(html, /id="ed-pass-history"/);
});

test("unlock loads persisted idle-lock and password-history settings", async () => {
  const { context, elements, calls } = loadHistoryUi();
  await context.enterMain([]);

  assert.equal(elements.get("idle-minutes").value, 7);
  assert.equal(elements.get("password-history-limit").value, 4);
  assert.ok(calls.some((call) => call.command === "get_vault_settings"));
});

test("history setting saves valid values and rejects values outside 1 to 20", async () => {
  const { context, elements, calls } = loadHistoryUi();
  elements.get("password-history-limit").value = "4";
  await context.setPasswordHistoryLimit();
  const call = calls.find((item) => item.command === "set_password_history_limit");
  assert.ok(call);
  assert.equal(call.args.limit, 4);

  const countBeforeInvalid = calls.length;
  elements.get("password-history-limit").value = "21";
  await context.setPasswordHistoryLimit();
  assert.equal(calls.length, countBeforeInvalid);
});

test("edit view shows history dates without password text and stages selected restore", async () => {
  const { context, elements, calls, entries } = loadHistoryUi();
  context.window.__lastEntries = entries;
  context.openEdit("entry-1");

  const box = elements.get("ed-pass-history");
  assert.equal(box.children.length, 2);
  assert.match(box.children[0].children[0].textContent, /2026-09-30/);
  assert.equal(box.children[0].children[1].textContent, "還原");
  assert.doesNotMatch(JSON.stringify(box.children.map((row) => row.children.map((child) => child.textContent))), /older-secret|oldest-secret/);

  box.children[0].children[1].onclick();
  assert.equal(elements.get("ed-pass").value, "older-secret");
  assert.equal(elements.get("ed-pass").type, "password");
  await context.saveEntry();
  const update = calls.find((call) => call.command === "update_entry");
  assert.ok(update);
  assert.equal(update.args.password, "older-secret");
  assert.equal(update.args.restoreHistoryId, "history-1");
});
