const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

// D9-F2：WebAuthn 指令移到工作執行緒後 UI 不再被凍結，所以每個金鑰操作入口都必須在
// 呼叫 IPC 之前同步停用觸發鈕／設旗標（防雙擊重入）。後端另有單一進行中操作 guard
// （「已有金鑰操作進行中」）作最後防線；這裡只釘住 UI 這一側的既有契約。
const source = fs.readFileSync(path.join(__dirname, "..", "src", "app.js"), "utf8");

function body(name) {
  const start = source.indexOf(`async function ${name}(`);
  assert.notEqual(start, -1, `${name} exists`);
  const next = source.indexOf("\nasync function ", start + 10);
  const nextSync = source.indexOf("\nfunction ", start + 10);
  const ends = [next, nextSync].filter((index) => index !== -1);
  return source.slice(start, ends.length ? Math.min(...ends) : undefined);
}

const entries = [
  ["doLoginKey", 'invoke("login_any_key")', /button\.disabled = true/],
  ["doLoginHello", 'invoke("login_windows_hello")', /button\.disabled = true/],
  ["registerHello", 'invoke("register_windows_hello")', /button\.disabled = true/],
  ["registerKey", 'invoke("register_key"', /registerButton\.disabled = true/],
  ["continueRegistration", 'invoke("continue_registration")', /registrationHandoffInFlight = true/],
  ["cancelRegistration", 'invoke("cancel_registration")', /registrationHandoffInFlight = true/],
];

for (const [name, call, guard] of entries) {
  test(`${name} locks its trigger before the IPC so a double click cannot re-enter`, () => {
    const text = body(name);
    const guardAt = text.search(guard);
    const callAt = text.indexOf(call);
    assert.notEqual(guardAt, -1, `${name} has an in-flight lock`);
    assert.notEqual(callAt, -1, `${name} calls ${call}`);
    assert.ok(guardAt < callAt, `${name} must lock before awaiting ${call}`);
  });
}

test("dual-control begin/complete/cancel share one in-flight lock", () => {
  const text = source.slice(source.indexOf("async function withDualLock("));
  assert.match(text, /if \(dualBusy\) return;\s*dualBusy = true;/);
  assert.match(source, /finally \{\s*dualBusy = false;/);
});

test("a rejected second key operation is shown through the existing error paths", () => {
  // Backend rejection text reaches the user as a normal error string (no special casing needed).
  assert.match(body("doLoginKey"), /errBox\(String\(e\)\)/);
  assert.match(body("registerHello"), /registrationFailureText\("hello", e\)/);
  assert.match(body("registerKey"), /registrationFailureText\("key", e\)/);
});
