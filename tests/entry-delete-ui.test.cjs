const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
// Reuse the search harness, excluding its test declarations. It runs the real
// app.js in vm; only DOM, timers and Tauri IPC are synthetic.
const source = fs.readFileSync(require.resolve("./entry-search-ui.test.cjs"), "utf8").split("const sampleEntries =")[0];
const load = new Function("require", "__dirname", source + "\nreturn loadSearchUi;")(require, __dirname);
const entries = ["a", "b"].map(id => ({id, site: "<img>" + id, account: "account" + id, notes: "private-note", password: "private-password", password_history: [{id: "history-" + id, password: "private-history", archived_at: "2026-01-01"}]}));
function setup() {
  const ui = load();
  ui.context.renderEntries(entries);
  ui.del = id => ui.elements.get("entries-body").children.flatMap(r => r.buttons).find(b => b.dataset.act === "del" && b.dataset.id === id).onclick();
  ui.button = id => ui.elements.get(id);
  ui.deletes = () => ui.calls.filter(c => c.command === "delete_entry");
  return ui;
}
test("delete opens modal without native confirm or IPC", async () => {
  const ui = setup();
  ui.context.confirm = () => { throw Error("native confirm forbidden"); };
  await ui.del("a");
  assert.equal(ui.button("entry-delete-dialog").open, true);
  assert.equal(ui.deletes().length, 0);
});

test("explicit confirm deletes original target once", async () => {
 const ui=setup(); let opens=0;
 const dialog=ui.button("entry-delete-dialog");
 const show=dialog.showModal;
 dialog.showModal=function(){opens++;show.call(this);};
 await ui.del("a"); await ui.del("a"); await ui.del("b");
 assert.equal(opens,1);
 await ui.button("btn-confirm-entry-delete").onclick();
 await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes().length,1); assert.equal(ui.deletes()[0].args.id,"a");
});

test("cancel, Esc and external close fail closed; deferred close does not cancel reopen", async () => {
 const ui=setup(); const d=ui.button("entry-delete-dialog");
 await ui.del("a"); ui.button("btn-cancel-entry-delete").onclick();
 await ui.del("b"); d.dispatch("cancel"); await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes().length,0);
 await ui.del("a"); d.close(); await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes().length,0);
 d.close=function(){this.open=false;};
 await ui.del("a"); ui.button("btn-cancel-entry-delete").onclick();
 await ui.del("b"); d.dispatch("close");
 await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes()[0].args.id,"b");
});

test("cancel focus, safe text, modal accessibility and open failure", async () => {
 const ui=setup(); await ui.del("a");
 assert.equal(ui.button("btn-cancel-entry-delete").focused,true);
 assert.equal(ui.button("entry-delete-site").textContent,"<img>a");
 assert.equal(ui.button("entry-delete-site").innerHTML,"");
 assert.equal(ui.button("entry-delete-account").textContent,"accounta");
 assert.doesNotMatch(JSON.stringify([...ui.elements].filter(([id])=>id.includes("entry-delete")).map(([id,node])=>[id,node.textContent,node.innerHTML])),/private-password|private-history|private-note/);
 assert.doesNotMatch(JSON.stringify(ui.logs),/private-password|private-history|private-note/);
 const html=fs.readFileSync(require.resolve("../src/index.html"),"utf8");
 assert.match(html,/aria-labelledby="entry-delete-title"/);
 assert.match(html,/aria-describedby="entry-delete-description entry-delete-status"/);
 assert.match(html,/刪除後不可復原/);
 assert.match(html, /id="btn-cancel-entry-delete" type="button" autofocus/);
 assert.match(html, /id="btn-confirm-entry-delete" type="button"/);
 assert.doesNotMatch(html.slice(html.indexOf('<dialog id="entry-delete-dialog"')), /private-password|private-note/);
 ui.button("btn-cancel-entry-delete").onclick();
 ui.button("entry-delete-dialog").showModal=()=>{throw Error("private-password");};
 await ui.del("b"); await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes().length,0);
 assert.doesNotMatch(ui.button("entry-delete-result").textContent,/private-password/);
});

test("pending IPC is single shot, backend failure generic and retry safe", async () => {
 const ui=setup(); let reject;
 ui.intercept=c=>c==="delete_entry"?new Promise((_,r)=>reject=r):undefined;
 await ui.del("a"); const pending=ui.button("btn-confirm-entry-delete").onclick();
 await ui.del("b"); await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes().length,1);
 assert.equal(ui.button("btn-confirm-entry-delete").disabled,true);
 reject(Error("private-password")); await pending;
 assert.doesNotMatch(ui.button("entry-delete-status").textContent,/private-password/);
 assert.ok(ui.button("entry-delete-status").textContent);
 assert.equal(ui.button("btn-confirm-entry-delete").disabled,false);
 assert.deepEqual(ui.visibleIds(),["a","b"]);
 ui.intercept=()=>undefined; ui.entries=entries;
 await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes().length,2); assert.equal(ui.deletes()[1].args.id,"a");
});

test("success preserves search and clears deleted editor including password history", async () => {
 const ui=setup(); ui.context.openEdit("a"); ui.setQuery("<img>"); ui.entries=[entries[1]];
 ui.button("ed-pass-history").children[0].children[1].onclick();
 await ui.del("a"); await ui.button("btn-confirm-entry-delete").onclick();
 assert.deepEqual(ui.visibleIds(),["b"]);
 assert.equal(ui.button("entry-search").value,"<img>");
 assert.ok(ui.button("entry-search-status").textContent.includes("1 / 1"));
 assert.equal(ui.button("ed-pass").value,"");
 assert.equal(ui.button("entry-edit").classList.contains("hidden"),true);
 assert.equal(require("node:vm").runInContext("editingId",ui.context),null);
 assert.equal(require("node:vm").runInContext("editingRestoreHistory",ui.context),null);
 assert.equal(ui.button("ed-pass-history").innerHTML,"");
});

test("refresh error is distinct after deletion and cannot repeat deleted target", async () => {
 const ui=setup(); ui.intercept=c=>c==="list_entries"?Promise.reject(Error("private-password")):undefined;
 await ui.del("a"); await ui.button("btn-confirm-entry-delete").onclick();
 assert.match(ui.button("entry-delete-result").textContent,/刪除完成.*清單重載失敗/);
 assert.doesNotMatch(ui.button("entry-delete-result").textContent,/private-password/);
 await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes().length,1);
 assert.deepEqual(ui.visibleIds(),["b"]);
});

test("manual and idle lock invalidate synchronously before lock IPC", async () => {
 for (const idle of [false,true]) {
  const ui=setup(); await ui.del("a");
  ui.intercept=c=>c==="lock"?new Promise(()=>{}):undefined;
  if(idle){ui.context.startIdleTimer(1);ui.timers.at(-1)();}else ui.button("btn-lock").onclick();
  await ui.button("btn-confirm-entry-delete").onclick();
  assert.equal(ui.deletes().length,0); assert.equal(ui.button("entry-delete-dialog").open,false);
  await ui.del("b");
  await ui.button("btn-confirm-entry-delete").onclick();
  assert.equal(ui.deletes().length,0);
 }
});

test("late delete completion after lock cannot touch new modal or locked list", async () => {
 for(const fails of [false,true]) {
 const ui=setup(); let settle;
 ui.intercept=c=>c==="delete_entry"?new Promise((resolve,reject)=>settle=()=>fails?reject(Error("secret")):resolve()):undefined;
 await ui.del("a"); const old=ui.button("btn-confirm-entry-delete").onclick();
 await ui.button("btn-lock").onclick();
 await ui.del("b");
 assert.equal(ui.button("entry-delete-dialog").open,false);
 settle(); await old;
 assert.deepEqual(ui.visibleIds(),["a","b"]);
 await ui.del("b"); await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes().length,1);
 assert.equal(ui.button("entry-delete-dialog").open,false);
 ui.intercept=c=>c==="login_password"?Promise.resolve(entries):undefined;
 await ui.button("btn-login-pw").onclick();
 await ui.del("b");
 assert.equal(ui.button("entry-delete-dialog").open,true);
 assert.equal(ui.button("entry-delete-site").textContent,"<img>b");
 assert.equal(ui.button("entry-delete-status").textContent,"");
 assert.equal(ui.button("btn-confirm-entry-delete").disabled,false);
 }
});

test("late list refresh after lock cannot render or overwrite a newer confirmation", async () => {
 const ui=setup(); let resolve;
 ui.intercept=c=>c==="list_entries"?new Promise(r=>resolve=r):undefined;
 await ui.del("a"); const old=ui.button("btn-confirm-entry-delete").onclick();
 await new Promise(setImmediate);
 assert.ok(resolve);
 await ui.button("btn-lock").onclick();
 const before=ui.visibleIds();
 resolve(entries); await old;
 assert.deepEqual(ui.visibleIds(),before);
 assert.equal(ui.button("entry-delete-result").textContent,"");
 ui.intercept=c=>c==="login_password"?Promise.resolve([entries[1]]):undefined;
 await ui.button("btn-login-pw").onclick();
 await ui.del("b"); assert.equal(ui.button("entry-delete-site").textContent,"<img>b");
});

test("lock latch persists after resolve or reject and failed login; verified login restores deletion", async () => {
 for (const idle of [false,true]) for (const fails of [false,true]) {
  const ui=setup(); let settle;
  ui.intercept=c=>c==="lock"?new Promise((r,j)=>settle=()=>fails?j(Error("synthetic")):r()):undefined;
  await ui.del("a");
  const lock=idle?(ui.context.startIdleTimer(1),ui.timers.at(-1)()):ui.button("btn-lock").onclick();
  await ui.del("b"); await ui.button("btn-confirm-entry-delete").onclick();
  assert.equal(ui.deletes().length,0);
  settle(); await lock;
  ui.intercept=c=>c==="login_password"?Promise.reject(Error("synthetic")):undefined;
  await ui.button("btn-login-pw").onclick();
  await ui.del("b"); await ui.button("btn-confirm-entry-delete").onclick();
  assert.equal(ui.deletes().length,0);
  ui.intercept=c=>c==="login_password"?Promise.resolve(entries):undefined;
  await ui.button("btn-login-pw").onclick();
  await ui.del("b"); await ui.button("btn-confirm-entry-delete").onclick();
  assert.equal(ui.deletes().length,1);
  assert.equal(ui.deletes()[0].args.id,"b");
 }
});

test("cancellation clears identifying text and reopening clears previous result", async () => {
 const ui=setup(); await ui.del("a"); ui.button("btn-cancel-entry-delete").onclick();
 assert.equal(ui.button("entry-delete-site").textContent,"");
 assert.equal(ui.button("entry-delete-account").textContent,"");
 ui.button("entry-delete-result").textContent="old-result";
 await ui.del("b"); assert.equal(ui.button("entry-delete-result").textContent,"");
 ui.button("entry-delete-dialog").returnValue="confirm";
 ui.button("entry-delete-dialog").close();
 await ui.button("btn-confirm-entry-delete").onclick();
 assert.equal(ui.deletes().length,0);
 ui.context.openEntryDelete(undefined);
 assert.equal(ui.deletes().length,0);
 assert.ok(ui.button("entry-delete-result").textContent);
});

test("submitted success survives cancel, Esc, external and delayed close, including refresh failure", async () => {
 for (const dismissal of ["cancel", "esc", "external", "delayed"]) for (const refreshFails of [false,true]) {
  const ui=setup(); let resolve;
  ui.context.openEdit("a"); ui.setQuery("<img>");
  ui.button("ed-pass-history").children[0].children[1].onclick();
  ui.intercept=c=>c==="delete_entry"?new Promise(r=>resolve=r):c==="list_entries"?(refreshFails?Promise.reject(Error("private-password")):Promise.resolve([entries[1]])):undefined;
  await ui.del("a"); const pending=ui.button("btn-confirm-entry-delete").onclick();
  const d=ui.button("entry-delete-dialog");
  if(dismissal==="cancel") ui.button("btn-cancel-entry-delete").onclick();
  else if(dismissal==="esc") d.dispatch("cancel");
  else if(dismissal==="external") d.close();
  else {d.close=function(){this.open=false;}; d.close();}
  await ui.del("b"); await ui.button("btn-confirm-entry-delete").onclick();
  assert.equal(ui.deletes().length,1);
  resolve(); await pending;
  if(dismissal==="delayed") d.dispatch("close");
  assert.deepEqual(ui.visibleIds(),["b"]);
  assert.deepEqual(Array.from(ui.window.__lastEntries,e=>e.id),["b"]);
  assert.equal(ui.button("ed-pass").value,"");
  assert.equal(ui.button("ed-pass-history").innerHTML,"");
  assert.equal(require("node:vm").runInContext("editingRestoreHistory",ui.context),null);
  assert.equal(ui.button("entry-edit").classList.contains("hidden"),true);
  assert.equal(ui.button("entry-search").value,"<img>");
  assert.match(ui.button("entry-delete-result").textContent,refreshFails?/刪除完成.*清單重載失敗/:/刪除完成/);
  assert.doesNotMatch(ui.button("entry-delete-result").textContent,/private-password/);
  assert.equal(ui.deletes()[0].args.id,"a");
 }
});

test("submitted rejection after dismissal reports generic failure outside closed modal", async () => {
 for(const mode of ["cancel","esc","external"]) {
  const ui=setup(); let reject;
  ui.intercept=c=>c==="delete_entry"?new Promise((_,r)=>reject=r):undefined;
  await ui.del("a"); const pending=ui.button("btn-confirm-entry-delete").onclick();
  if(mode==="cancel") ui.button("btn-cancel-entry-delete").onclick();
  else if(mode==="esc") ui.button("entry-delete-dialog").dispatch("cancel");
  else ui.button("entry-delete-dialog").close();
  reject(Error("private-password")); await pending;
  assert.equal(ui.button("entry-delete-dialog").open,false);
  assert.match(ui.button("entry-delete-result").textContent,/刪除失敗/);
  assert.doesNotMatch(ui.button("entry-delete-result").textContent,/private-password/);
  assert.deepEqual(ui.visibleIds(),["a","b"]);
 }
});

test("old submitted delete and list callbacks cannot touch a later verified session", async () => {
 for(const phase of ["delete","list"]) for(const fails of [false,true]) for(const idle of [false,true]) {
  const ui=setup(); let settle;
  ui.intercept=c=>c===(phase==="delete"?"delete_entry":"list_entries")?new Promise((r,j)=>settle=()=>fails?j(Error("private-password")):r(entries)):undefined;
  await ui.del("a"); const pending=ui.button("btn-confirm-entry-delete").onclick();
  await new Promise(setImmediate);
  if(idle){ui.context.startIdleTimer(1);await ui.timers.at(-1)();}else await ui.button("btn-lock").onclick();
  ui.intercept=c=>c==="login_password"?Promise.resolve([entries[1]]):undefined;
  await ui.button("btn-login-pw").onclick();
  ui.context.openEdit("b"); const before=ui.button("ed-pass").value;
  settle(); await pending;
  assert.deepEqual(ui.visibleIds(),["b"]);
  assert.equal(ui.button("ed-pass").value,before);
  assert.equal(ui.button("entry-delete-result").textContent,"");
  await ui.del("b"); assert.equal(ui.button("entry-delete-site").textContent,"<img>b");
 }
});
