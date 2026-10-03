const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function element() {
  const attributes = {};
  const classes = new Set();
  const listeners = new Map();
  return {
    value: "",
    textContent: "",
    innerHTML: "",
    children: [],
    dataset: {},
    disabled: false,
    open: false,
    returnValue: "",
    onclick: null,
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
    appendChild(child) {
      this.children.push(child);
      this.textContent += child.textContent ?? "";
    },
    replaceChildren(...children) {
      this.children = children;
      this.textContent = children.map((child) => child.textContent ?? "").join("");
    },
    showModal() { this.open = true; },
    close(value = "") {
      this.returnValue = value;
      this.open = false;
      for (const callback of listeners.get("close") ?? []) callback({ target: this });
    },
  };
}

function loadImportUi() {
  const ids = [
    "btn-save-csv-template", "btn-import-csv", "csv-import-dialog",
    "csv-import-summary", "csv-import-rows", "btn-confirm-csv-import",
    "btn-cancel-csv-import", "csv-import-status", "entries-body", "audit-body",
  ];
  const elements = new Map(ids.map((id) => [id, element()]));
  const calls = [];
  const alerts = [];
  const previewResponse = {
    token: "preview-token-1",
    preview: {
      added: 1,
      updated: 1,
      skipped: 1,
      rows: [
        { row_number: 2, action: "update", reason: null, password: "DO_NOT_RENDER_PASSWORD" },
        { row_number: 3, action: "add", reason: null, site: "DO_NOT_RENDER_SITE" },
        { row_number: 4, action: "skip", reason: "欄位數不符", account: "DO_NOT_RENDER_ACCOUNT" },
      ],
    },
  };
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement() { return element(); },
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
          if (command === "preview_csv_import") return previewResponse;
          if (command === "apply_csv_import") {
            return { added: 1, updated: 1, skipped: 1, rows: [] };
          }
          if (command === "list_entries" || command === "list_audit") return [];
          if (command === "boot_info") return { has_vault: true, keys: [], brokered_key_login: true };
          return true;
        },
      },
    },
  };
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8");
  const context = vm.createContext({
    window, document, console,
    alert(message) { alerts.push(String(message)); },
    confirm() { return true; },
    prompt() { return null; },
    setTimeout() { return 1; },
    clearTimeout() {},
  });
  vm.runInContext(source, context, { filename: "src/app.js" });
  return { context, elements, calls, alerts, previewResponse };
}

test("entry screen offers a header-only template and warns that imports contain plaintext passwords", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "src", "index.html"), "utf8");
  assert.match(html, /id="btn-save-csv-template"/);
  assert.match(html, /id="btn-import-csv"/);
  assert.match(html, /site,account,password,notes/);
  assert.match(html, /明文密碼/);
});

test("preview displays only counts, row numbers, actions, and non-secret reasons", async () => {
  const ui = loadImportUi();
  await ui.context.previewCsvImport();

  const dialog = ui.elements.get("csv-import-dialog");
  assert.equal(dialog.open, true);
  assert.equal(ui.elements.get("csv-import-summary").textContent, "新增 1 筆、更新 1 筆、略過 1 筆");
  const rowsText = JSON.stringify(ui.elements.get("csv-import-rows").children.map((row) => row.textContent));
  assert.match(rowsText, /第 2 列/);
  assert.match(rowsText, /第 3 列/);
  assert.match(rowsText, /第 4 列/);
  assert.match(rowsText, /欄位數不符/);
  assert.doesNotMatch(rowsText, /DO_NOT_RENDER_PASSWORD|DO_NOT_RENDER_SITE|DO_NOT_RENDER_ACCOUNT/);
});

test("canceling the preview clears its backend token without importing", async () => {
  const ui = loadImportUi();
  await ui.context.previewCsvImport();
  await ui.elements.get("btn-cancel-csv-import").onclick();

  assert.ok(ui.calls.some((call) => call.command === "cancel_csv_import" && call.args.token === "preview-token-1"));
  assert.ok(!ui.calls.some((call) => call.command === "apply_csv_import"));
  assert.equal(ui.elements.get("csv-import-dialog").open, false);
});

test("confirming applies the preview token then refreshes the entry list", async () => {
  const ui = loadImportUi();
  await ui.context.previewCsvImport();
  await ui.elements.get("btn-confirm-csv-import").onclick();

  assert.ok(ui.calls.some((call) => call.command === "apply_csv_import" && call.args.token === "preview-token-1"));
  assert.ok(ui.calls.some((call) => call.command === "list_entries"));
  assert.equal(ui.elements.get("csv-import-dialog").open, false);
  assert.match(ui.elements.get("csv-import-status").textContent, /匯入完成/);
});

test("template action delegates to the native save dialog command", async () => {
  const ui = loadImportUi();
  await ui.elements.get("btn-save-csv-template").onclick();
  assert.ok(ui.calls.some((call) => call.command === "save_csv_template"));
});
