const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function loadAuditUi() {
  const body = { innerHTML: "", children: [], appendChild(row) { this.children.push(row); } };
  const document = {
    addEventListener() {},
    querySelector(selector) { assert.equal(selector, "#audit-table tbody"); return body; },
    createElement() { return { innerHTML: "" }; },
  };
  const context = vm.createContext({ document, window: { __TAURI__: { core: { invoke() {} } } }, Date, console });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8"), context);
  return { context, body };
}
const event = (ts, method) => ({ ts, method, event: "login_failed", detail: "synthetic" });
const rowMethod = (row) => row.innerHTML.match(/<td>(.*?)<\/td>/g)[1].slice(4, -5);

test("audit renders newest events first even when legacy sidecar events were prepended", async () => {
  const { context, body } = loadAuditUi();
  const audit = [
    event("2026-10-10T01:00:00Z", "cancel"),
    event("2026-10-10T02:00:00Z", "timeout"),
    event("2026-10-09T00:00:00Z", "created"),
    event("2026-10-10T03:00:00Z", "success"),
  ];
  const before = JSON.stringify(audit);
  await context.renderAudit(audit);
  assert.deepEqual(body.children.map(rowMethod), ["success", "timeout", "cancel", "created"]);
  assert.equal(JSON.stringify(audit), before, "render must not mutate historical input records");
});

const rowTime = (row) => row.innerHTML.match(/<td class="mono">(.*?)<\/td>/)[1];
const localExpected = (date) => {
  const pad = (v) => String(v).padStart(2, "0");
  return `${String(date.getFullYear()).padStart(4, "0")}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
};

test("audit displays legacy UTC and offset timestamps in local yyyy-MM-dd HH:mm:ss without rewriting records", async () => {
  const { context, body } = loadAuditUi();
  const audit = [event("2026-10-11T16:00:00.123Z", "utc"), event("2026-10-12T01:00:00+09:00", "offset"), event("2026-10-12 02:03:04", "local")];
  const original = JSON.stringify(audit);
  await context.renderAudit(audit);
  const times = Object.fromEntries(body.children.map((row) => [rowMethod(row), rowTime(row)]));
  assert.equal(times.utc, localExpected(new Date("2026-10-11T16:00:00.123Z")));
  assert.equal(times.offset, localExpected(new Date("2026-10-12T01:00:00+09:00")));
  assert.equal(times.local, "2026-10-12 02:03:04", "new local timestamps must not be shifted a second time");
  for (const time of Object.values(times)) assert.match(time, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  assert.equal(JSON.stringify(audit), original);
});

test("audit same-second ties put the later appended event first across old and new formats", async () => {
  const { context, body } = loadAuditUi();
  const old = "2026-10-11T16:00:00.999Z";
  const local = localExpected(new Date(old));
  await context.renderAudit([event(old, "earlier-legacy"), event(local, "later-local")]);
  assert.deepEqual(body.children.map(rowMethod), ["later-local", "earlier-legacy"]);
});

test("audit sorts by the actual offset-aware time rather than timestamp text", async () => {
  const { context, body } = loadAuditUi();
  await context.renderAudit([event("2026-10-12T01:00:00+09:00", "older"), event("2026-10-11T17:00:00Z", "newer")]);
  assert.deepEqual(body.children.map(rowMethod), ["newer", "older"]);
});

test("invalid audit timestamps are escaped and placed after valid records without hiding them", async () => {
  const { context, body } = loadAuditUi();
  const malicious = '<img src=x onerror="evil()">';
  await context.renderAudit([event(malicious, "invalid"), event("2026-10-11T17:00:00Z", "valid")]);
  assert.deepEqual(body.children.map(rowMethod), ["valid", "invalid"]);
  assert.match(rowTime(body.children[1]), /&lt;img/);
  assert.doesNotMatch(body.children[1].innerHTML, /<img/);
  for (const value of [null, undefined, "", "not-a-date", "2026-02-30 01:00:00", "2026-10-12 25:00:00"])
    assert.equal(context.parseAuditDate(value), null);
  assert.equal(context.formatLocalAuditDate(context.parseAuditDate("2024-02-29 01:02:03")), "2024-02-29 01:02:03");
});

test("invalid legacy calendar dates and rolled-over hours remain verbatim at the bottom", async () => {
  for (const invalid of ["2026-02-30T01:00:00Z", "2026-02-30T01:00:00+09:00", "2026-02-29T01:00:00Z", "2026-04-31T01:00:00Z", "2026-10-12T24:00:00Z"]) {
    const { context, body } = loadAuditUi();
    assert.equal(context.parseAuditDate(invalid), null, `must not normalize ${invalid}`);
    await context.renderAudit([event(invalid, "invalid"), event("2025-01-01T01:00:00Z", "valid")]);
    assert.deepEqual(body.children.map(rowMethod), ["valid", "invalid"]);
    assert.equal(rowTime(body.children[1]), invalid);
  }
});
