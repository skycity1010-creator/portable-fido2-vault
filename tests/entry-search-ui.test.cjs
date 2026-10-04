const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function decodeHtml(value) {
  return String(value)
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&");
}

function element(tag = "") {
  const attributes = {};
  const listeners = new Map();
  const classes = new Set(["hidden"]);
  let html = "";
  const node = {
    tag,
    type: "",
    value: "",
    textContent: "",
    children: [],
    buttons: [],
    dataset: {},
    style: {},
    disabled: false,
    onclick: null,
    className: "",
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute(name) { return attributes[name] ?? null; },
    removeAttribute(name) { delete attributes[name]; },
    addEventListener(name, callback) {
      if (!listeners.has(name)) listeners.set(name, []);
      listeners.get(name).push(callback);
    },
    dispatch(name) {
      for (const callback of listeners.get(name) ?? []) callback({ target: this });
    },
    appendChild(child) { this.children.push(child); },
    replaceChildren(...children) { this.children = children; },
    querySelectorAll(selector) {
      if (selector !== "button") return [];
      if (this.tag === "tbody") return this.children.flatMap((child) => child.buttons ?? []);
      return this.buttons ?? [];
    },
    focus() { this.focused = true; },
    open: false,
    showModal() { this.open = true; },
    close() { this.open = false; this.dispatch("close"); },
  };
  Object.defineProperty(node, "innerHTML", {
    get() { return html; },
    set(value) {
      html = String(value);
      node.children = [];
      node.buttons = [...html.matchAll(/<button\s+([^>]*)>([\s\S]*?)<\/button>/g)].map((match) => {
        const button = element("button");
        button.textContent = decodeHtml(match[2].replace(/<[^>]*>/g, ""));
        for (const attr of match[1].matchAll(/([\w-]+)="([^"]*)"/g)) {
          if (attr[1].startsWith("data-")) button.dataset[attr[1].slice(5)] = attr[2];
          else button.setAttribute(attr[1], attr[2]);
        }
        return button;
      });
      node.cells = [...html.matchAll(/<td(?:\s[^>]*)?>([\s\S]*?)<\/td>/g)].map((match) => {
        const cell = element("td");
        cell.textContent = decodeHtml(match[1].replace(/<[^>]*>/g, ""));
        return cell;
      });
      node.textContent = node.cells.map((cell) => cell.textContent).join(" ");
    },
  });
  return node;
}

function loadSearchUi() {
  const elements = new Map([
    ["entry-delete-result", element("div")],
    ["entries-body", element("tbody")],
    ["audit-body", element("tbody")],
    ["entry-search", element("input")],
    ["entry-search-status", element("div")],
  ]);
  const calls = [];
  const logs = [];
  const prompts = [];
  const clipboardWrites = [];
  let entries = [];
  let intercept = () => undefined;
  const timers = [];
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement(tag) { return element(tag); },
    querySelector(selector) {
      if (selector === "#entries-table tbody") return elements.get("entries-body");
      if (selector === "#audit-table tbody") return elements.get("audit-body");
      return element();
    },
    querySelectorAll() { return []; },
    addEventListener(event, callback) {
      if (event === "DOMContentLoaded") callback();
    },
  };
  const window = {
    addEventListener() {},
    __TAURI__: {
      core: {
        async invoke(command, args) {
          calls.push({ command, args });
          const intercepted = intercept(command, args);
          if (intercepted !== undefined) return intercepted;
          if (command === "boot_info") return { has_vault: true, keys: [], brokered_key_login: true };
          if (command === "get_vault_settings") return { idle_lock_minutes: 5, password_history_limit: 3 };
          if (command === "list_audit") return [];
          if (command === "list_entries") return entries;
          return undefined;
        },
      },
      clipboardManager: { async writeText(value) { clipboardWrites.push(value); } },
    },
  };
  const consoleCapture = Object.fromEntries(
    ["log", "info", "warn", "error", "debug"].map((level) => [level, (...args) => logs.push(args)]),
  );
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8");
  const context = vm.createContext({
    window,
    document,
    console: consoleCapture,
    location: { reload() {} },
    alert() {},
    confirm() { return true; },
    prompt(...args) { prompts.push(args); return null; },
    setTimeout(callback) { timers.push(callback); return timers.length; },
    clearTimeout() {},
  });
  vm.runInContext(source, context, { filename: "src/app.js" });
  return {
    context,
    timers,
    set intercept(value) { intercept = value; },
    elements,
    calls,
    logs,
    prompts,
    clipboardWrites,
    window,
    get entries() { return entries; },
    set entries(value) { entries = value; },
    setQuery(value) {
      const input = elements.get("entry-search") ?? document.getElementById("entry-search");
      input.value = value;
      input.dispatch("input");
    },
    visibleIds() {
      return elements.get("entries-body").children.map((row) => row.buttons[0]?.dataset.id);
    },
  };
}

const sampleEntries = [
  {
    id: "entry-a",
    site: "mail.example.com",
    account: "Alice",
    notes: "Personal finance account",
    password: "current-secret-only-a",
    password_history: [{ id: "history-a", password: "old-secret-only-a", archived_at: "2026-09-01" }],
    created_at: "2026-01-01",
    updated_at: "2026-01-02",
  },
  {
    id: "entry-b",
    site: "work.example.com",
    account: "bob",
    notes: "Internal tools",
    password: "current-secret-only-b",
    password_history: [],
    created_at: "2026-02-01",
    updated_at: "2026-02-02",
  },
];

test("entry search is a labeled searchbox with autocomplete disabled and a live result status", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "src", "index.html"), "utf8");
  assert.match(html, /<label[^>]*for="entry-search"[^>]*>\s*搜尋條目\s*<\/label>/);
  assert.match(html, /<input[^>]*id="entry-search"[^>]*type="search"[^>]*autocomplete="off"/);
  assert.match(html, /id="entry-search-status"[^>]*role="status"[^>]*aria-live="polite"/);
});

test("search filters site, account, and notes by case-insensitive substring without backend calls", () => {
  const ui = loadSearchUi();
  ui.context.renderEntries(sampleEntries);
  const beforeSearchCalls = ui.calls.length;

  ui.setQuery("MAIL.EXAMPLE");
  assert.deepEqual(ui.visibleIds(), ["entry-a"]);
  ui.setQuery("ALICE");
  assert.deepEqual(ui.visibleIds(), ["entry-a"]);
  ui.setQuery("FINANCE");
  assert.deepEqual(ui.visibleIds(), ["entry-a"]);
  assert.equal(ui.calls.length, beforeSearchCalls);
});

test("search never matches current or historical passwords", () => {
  const ui = loadSearchUi();
  ui.context.renderEntries(sampleEntries);

  ui.setQuery("current-secret-only-a");
  assert.deepEqual(ui.visibleIds(), []);
  ui.setQuery("old-secret-only-a");
  assert.deepEqual(ui.visibleIds(), []);
  assert.doesNotMatch(ui.elements.get("entry-search-status").textContent, /current-secret|old-secret/);
});

test("search count, no-results state, whitespace, and clearing restore the full list", () => {
  const ui = loadSearchUi();
  ui.context.renderEntries(sampleEntries);
  assert.match(ui.elements.get("entry-search-status").textContent, /2/);

  ui.setQuery("not-present");
  assert.deepEqual(ui.visibleIds(), []);
  assert.match(ui.elements.get("entry-search-status").textContent, /沒有符合搜尋條件/);

  ui.setQuery("   ");
  assert.deepEqual(ui.visibleIds(), ["entry-a", "entry-b"]);
  ui.setQuery("work");
  assert.deepEqual(ui.visibleIds(), ["entry-b"]);
  ui.setQuery("");
  assert.deepEqual(ui.visibleIds(), ["entry-a", "entry-b"]);

  ui.context.renderEntries([]);
  assert.match(ui.elements.get("entry-search-status").textContent, /尚無條目/);
});

test("show, copy, edit, and delete actions on a filtered row target the matching entry", async () => {
  const ui = loadSearchUi();
  ui.context.renderEntries(sampleEntries);
  ui.setQuery("work.example");

  const buttons = ui.elements.get("entries-body").children[0].buttons;
  const buttonFor = (action) => buttons.find((button) => button.dataset.act === action);
  await buttonFor("show").onclick();
  assert.equal(ui.prompts[0][1], "current-secret-only-b");

  await buttonFor("copy").onclick();
  assert.deepEqual(ui.clipboardWrites, ["current-secret-only-b"]);

  buttonFor("edit").onclick();
  assert.equal(ui.elements.get("ed-site").value, "work.example.com");
  assert.equal(ui.elements.get("ed-account").value, "bob");

  await buttonFor("del").onclick();
  assert.ok(!ui.calls.some((call) => call.command === "delete_entry"));
  await ui.elements.get("btn-confirm-entry-delete").onclick();
  const deletion = ui.calls.find((call) => call.command === "delete_entry");
  assert.equal(deletion.args.id, "entry-b");
});

test("refreshing entries preserves the active query without exposing it in status text", async () => {
  const ui = loadSearchUi();
  ui.context.renderEntries(sampleEntries);
  ui.setQuery("carol");
  assert.deepEqual(ui.visibleIds(), []);

  ui.entries = [...sampleEntries, {
    id: "entry-c",
    site: "target.example",
    account: "carol",
    notes: "Added while filtering",
    password: "secret-c",
    password_history: [],
    created_at: "2026-03-01",
    updated_at: "2026-03-01",
  }];
  await ui.context.refreshEntries();

  assert.deepEqual(ui.visibleIds(), ["entry-c"]);
  assert.doesNotMatch(ui.elements.get("entry-search-status").textContent, /carol/);
  assert.ok(ui.calls.some((call) => call.command === "list_entries"));
  assert.ok(ui.calls.every((call) => !JSON.stringify(call.args ?? {}).includes("carol")));
  assert.doesNotMatch(JSON.stringify(ui.logs), /carol/);
});

test("searching a markup-like entry value renders it as text, not HTML", () => {
  const ui = loadSearchUi();
  const value = '<img src=x onerror="alert(1)">';
  ui.context.renderEntries([{
    id: "entry-xss",
    site: value,
    account: "alice",
    notes: "",
    password: "secret",
    password_history: [],
    created_at: "2026-01-01",
    updated_at: "2026-01-01",
  }]);
  ui.setQuery("<IMG");

  assert.deepEqual(ui.visibleIds(), ["entry-xss"]);
  const rendered = ui.elements.get("entries-body").children[0].innerHTML;
  assert.doesNotMatch(rendered, /<img\b/i);
  assert.match(rendered, /&lt;img/i);
});
