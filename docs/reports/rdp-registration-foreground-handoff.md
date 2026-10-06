# RDP registration foreground handoff：條件式修復候選

2026-10-06。修復僅限 Windows backend；本機自動驗證通過的結果見下表，實際 Console／RDP 新 slot registration 仍 **NOT_TESTED**，不是 C/R4 PASS 或 RDP 支援提升。Parent 仍須獨立 review native transport、來源 hashes 與 candidate build，再安排另行授權的實機驗證。

唯一 worktree：`D:/project/_worktrees/portable-fido2-vault-rdp-handoff-20261006`；scope HEAD `765f11545d8611c38a0abf6eb9097f4208351a57`。Parent 建立的 blocked card t_2fad9e76／stacked Draft PR21 不由本輪操作。本輪沒有 commit/push/merge、GitHub/Kanban API、GUI／CLI 硬體／WinRM／RDP／設定操作，沒有實際使用者 vault 存取。只有明確授權的自動 mock fixture tests 使用各自新建的 temp fixture。

## 發現、假說與物理界線

既有人測由使用者提供：PID10088/API7，21:17:40.757 MakeCredential 成功且 hmac_creation_confirmed=true；21:17:40.760 owner!=foreground；21:17:40.761 GetAssertion preflight failure。foreground HWND/PID/TID/session/path 當時沒有捕捉；本輪不推定那是 broker。

| 排序 | 來源與可否證界線 |
|---|---|
| 1：只在 command 準備一次 parent | lib.rs register_key 在 vault 前只 raise 一次；vault register_key_internal 依序 register_credential?、get_prf_secret?。已知來源事實；production seam 的兩 ceremony 回歸證實舊準備策略在注入的失焦狀態會拒絕第二 call。不能因此宣稱歷史失焦由 broker 造成。 |
| 2：broker return race | 原 monitor 有 unique NEW window＋process、same session、System32 path、title/class、revalidation；原候選僅存在 worker stack，沒有 continuation transport。這輪保留本次 monitor 真正接受的 identity，讓未來 operation 可條件式復原。歷史 race 仍未證實；若實機 foreground 是 unrelated app／未觀察 broker／已銷毀或不同 identity，本修復刻意 fail closed。 |
| 3：owner stale/hidden/minimized/reused | 原 command 只取一次 HWND；這輪在第一 ceremony snapshot、continuation prepare 與最後 guard 前檢查 native owner validity、PID/TID/session／visibility，並比對同一 owner snapshot。測試覆蓋身分改變與無效 owner；歷史人測缺同時的 owner 狀態，不能排除此假說。 |

第一輪 diagnostic-only 結果沒有 RED 或修復，保留為 `handoff-evidence/diagnostic-step1/report-before-continuation.md`，不改寫為早已修復。Parent 的續接明確授權在未來 operation runtime 捕捉身分；因此歷史未知身分不再阻止這個狹義條件式實作，但仍阻止物理 PASS。

## 最終行為與信任界線

1. 每一 monitor 自己持有 baseline windows／broker PIDs、native System32 directory 與 current session。它只在原 strict unique-new selection／revalidation 下、實際候選已 foreground 時，經 capture 再驗證後，寫入該 monitor 私有的 `Arc<Mutex<Option<AcceptedBroker>>>`。沒有外部 trusted boolean，沒有僅靠 exe/class 許可。shared broker predicate 同時供 monitor 與 continuation 使用，原 identity filters 未放寬。
2. MakeCredential 返回後維持原取消／join lifetime；`finish` 在 join 後 take observation，worker error 或 poisoned channel 不提供 observation。只有原 HMAC confirmation、credential ID／authenticator data parse 全部成功後，才以成功 Result 發布 context，綁定 owner HWND/PID/TID 與 exact newly created credential。API error/cancel/unconfirmed/parse error 沒有 context。
3. 下一次 get-secret 在任何 preflight error 前先 take backend context，只有單一 exact credential＋相同 owner 才可使用。parent 更新（即使同 HWND）、另一 detection／enrollment query、新 MakeCredential、不同 credential、多 IDs、所有 errors 及 consumption 都不保留授權。只讀 capability/label 方法沒有新的 native ceremony 或 activation。
4. owner 已 foreground 時不 activate。否則只有 current foreground 等於該 monitor 已接受的 broker，且 same session、System32 executable path、title/class、visibility、HWND/PID/TID、unique candidate 與原 new-window/new-process baseline 再度成立，才允許一次 native SetForegroundWindow。owner 必須是本 process 的有效 visible window；昂貴 broker 重驗之後再驗 owner，然後最後 foreground sample 立即接一次 activation。Windows 返回值與 activation 後 native snapshot 都必須成功，否則 abort，不 retry。
5. 只有符合上述信任條件的 minimized owner 可 SW_RESTORE；visible maximized window 不 restore、不 demaximize。restore 失敗／restore 後 unrelated focus 都 abort。沒有 ShowWindow 顯示 hidden owner、替代 foreign/stale HWND、AttachThreadInput／topmost／ASFW_ANY。
6. monitor prepare 與其他 native queries／logs 都在最後 sample 之前。最後 owner identity revalidation 後仍 GetForegroundWindow→strict validate_owner_foreground→既有 monitor.arm→FFI；沒有新 sleep/retry/observer 插入。LF/CRLF oracle 保留原 log/diagnose 禁令並加上 exact allowed gap，mutation 測試亦拒絕 sleep/policy call。

Windows HWND 與 focus sampling 是 best-effort，並非跨 process 的原子操作；這輪比對 Windows 可觀察的 HWND/PID/TID 與 fresh metadata，不宣稱消除了 OS 在最後 sample 後的競態或完整 tuple 被系統重用的所有可能。SetForegroundWindow 的限制也可能使符合條件的 recovery 被拒絕；本實作會 fail closed，不以成功 boolean 代替 native snapshot。

已讀 Parent 的 read-only `D:/project/_archives/portable-fido2-vault/20261006-rdp-foreground-handoff/primary-references/`（ledger 及三份原文）。[Microsoft SetForegroundWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow) 明載即使符合條件仍可能被拒絕；[MakeCredential](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatormakecredential)、[GetAssertion](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion) 的 owner/UI 與 HRESULT 語義不變。

未修改 API>=4、RP/origin/raw salt、PRF/crypto、credential match、exact32-byte output、secret success 後才 append、vault format、Mock/rawCTAP/nonWindows、frontend/vendor/manifests/locks/build.rs/CI/config/policy。production deliverable 只有 windows_webauthn.rs；webauthn_diagnostics.rs 的變更全部在 test oracle。vault/lib/fido2 不改。

## 垂直 TDD 與保留的失敗

先抽出行為中性的 injectable system/transport seam 與不實作新行為的 stub，再執行 assertion RED；不是聲稱在任何 scaffolding 來源 edit 之前已有 RED。第一個 genuine RED 與該版本來源封存於 `red-01-capture-retry-source/`；在這個 RED 之前沒有 capture/context/recovery 行為實作。各後續 RED 都各自保存來源與 SHA-256，沒有批次先寫完修復再造 RED。

每個 target 使用 `cargo +stable-x86_64-pc-windows-gnu test --lib --locked --features real-ctap -j1 <exact-name>`；下表每項 genuine RED exit101（0 pass/1 fail）→GREEN exit0（1 pass/0 fail）。JSON 保存 exact target／env／exit，stdout 保存真實 assertion 與非零執行計數。

| #／evidence stem | Exact test target | RED 原因 |
|---|---|---|
| 01 capture-retry／capture | handoff_capture_retains_only_the_revalidated_unique_new_broker | None ≠ accepted identity |
| 02 context | handoff_successful_validated_creation_publishes_bound_context | successful validated result 未發布 context |
| 03 handoff | handoff_successful_first_ceremony_recovers_only_its_broker_for_second | Err(Foreground) ≠ Ok(Recovered) |
| 04 owner-update | handoff_parent_update_clears_even_same_hwnd_context | parent update 未清 context |
| 05 detect | handoff_other_detection_clears_context | detection 未清 context |
| 06 minimized | handoff_restores_only_a_minimized_valid_associated_owner | Err(Owner) ≠ Ok(Recovered) |
| 07 enrollment | handoff_other_enrollment_query_clears_context | enrollment query 未清 context |
| 08 owner-snapshot | handoff_rejects_stale_hidden_foreign_or_null_owner | final snapshot 未綁定原 PID/TID |
| 09 owner-race | handoff_owner_changed_during_broker_revalidation_is_never_activated | late owner change 在 activation 後才發現 |
| 10 gap-oracle | backend_wiring_rejects_blocking_or_policy_calls_in_final_gap | 原 oracle 沒有拒絕 sleep／policy mutant |
| 11 worker-error | handoff_monitor_worker_error_discards_observation | worker error 後仍可取得 observation |

真實額外失敗不刪除：`red-01-capture` exit101 是 Rust unsafe block tail-expression 語法 compile error（0 tests），不算 RED；修正語法後的 capture-retry 才是 genuine RED。`safety-branches` 15 pass/1 fail 的 standalone checked_owner 斷言錯把「fresh snapshot」當作「綁定 earlier snapshot」；保留該失敗，明確新增 bound-snapshot seam 後以 red-08／green-08 實作並重跑所有分支。這些沒有被記成 GREEN。

其餘 safety supplemental tests 是已實作分支覆蓋，不捏造它們都曾 RED。最終 handoff target 23 個 real policy/state/order tests，涵蓋 unknown/unrelated/late focus change、missing/ambiguous/preexisting/hidden broker、PID/TID/session/path/class/visibility revalidation、stale/hidden/foreign/null owner、multiple/mismatched IDs、owner change、activation false／wrong snapshot、restore failure／focus change、one-use/replay、worker/channel error/cancel、maximized preservation。三個 vault tests 使用真實 Vault register orchestration＋production capture/continuation/final-guard seam：first cancel/error 防止第二 call；第二 API/preflight failure 保持已有 slot、audit 與 fixture bytes；success 僅在 secret success 後 append。Native calls 在這些測試中由 injected observations／mutations 替代，**不是 physical proof**。

## 實際修改後候選檢查

Cargo cwd=`<worktree>/src-tauri`；其餘 root。每次 Cargo 明確使用 process-local：

```text
CARGO_HOME=C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target/isolated-cargo-home
CARGO_TARGET_DIR=C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-handoff-20261006-target
CARGO_BUILD_JOBS=1
CARGO_INCREMENTAL=0
CARGO_PROFILE_TEST_DEBUG=0
CARGO_PROFILE_DEV_DEBUG=0
PATH prefix=C:/Users/skycity1010/.cargo/bin;C:/Users/skycity1010/tools/winlibs-mingw/mingw64/bin;
```

| Exact command | actual exit／計數 | evidence stem |
|---|---|---|
| cargo +stable-x86_64-pc-windows-gnu test --lib --locked --features real-ctap -j1 handoff_ | 0；23 pass/0 fail/90 filtered | targeted-final |
| cargo +stable-x86_64-pc-windows-gnu test --lib --locked --features real-ctap -j1 backend_wiring | 0；6 pass/0 fail/107 filtered | oracle-candidate-final |
| cargo +stable-x86_64-pc-windows-gnu test --lib --locked --features real-ctap -j1 | 0；113 pass/0 fail/0 filtered | lib-candidate-final |
| node --test --test-reporter=tap tests/*.test.cjs | 0；65 pass/0 fail/0 skipped | node-candidate-final |
| node --check src/app.js | 0 | syntax-candidate-final |
| cargo +stable-x86_64-pc-windows-gnu clippy --lib --locked --features real-ctap -j1 -- -D warnings | 0 | clippy-candidate-final |
| cargo +stable-x86_64-pc-windows-gnu fmt --check | 0 | fmt-candidate-final |

GNU release 實際命令 cargo +stable-x86_64-pc-windows-gnu build --release --locked --features real-ctap --bin portable-fido-vault -j1 exit0，optimized build 6m00s（release-candidate-final.*）。候選未執行。最終 git diff --check 與 report whitespace check 見 diff-candidate-final／report-diff-check。

## Tooling／基線與 evidence

archive 建立 `D:/project/_archives/portable-fido2-vault/20261006-rdp-foreground-handoff/codex-evidence/diagnostic-step1` 被 PermissionDenied，未升級權限。Parent 可封存持久 fallback：
`D:/project/_worktrees/portable-fido2-vault-rdp-handoff-20261006/handoff-evidence/diagnostic-step1/`。

Python invocation 在本 PowerShell 未找到 python，0 tests；改用現有 Node runner。第一次基線 Rust targeted exit101／loader 0xc0000139、0 tests，不是 RED。只對 scratch lib test executable 加官方 tauri-build-2.7.0 manifest sidecar：isolated .crate SHA-256 `5b5ae674f48836f5dd2eeaf9e221c095bd3e78a8d0439c77ca93b48740a1b644` 等於 lock checksum，解出 official tar entry 與 source bytes 完全比對後 copy；source／sidecar SHA-256 都是 `4636f3ba46080315ac3277d473d433b79c00863c9cdca1c93c0c83554c6a3d43`，詳 test-manifest-provenance.json。沒有改正式 manifest、EXE、system DLL、registry/policy、delivery build.rs 或 dependency source。後續相同 lib test artifact 的 sidecar 保留在 scratch。

原基線 targeted 18/18、lib 89/89、Node 65/65、Clippy/fmt/syntax/diff exit0 仍保留。第一輪 release-baseline 在續接前留下 stdout/stderr，但續接後 session 92199 不存在、沒有 completed exit JSON；標為 **INCOMPLETE/unknown exit**，不當成 baseline candidate 或成功 build。

run-*.cjs、每命令 .json/.stdout.log/.stderr.log、初始全部 tracked SHA-256／相關 source snapshots、每次 RED-source snapshots、候選 source snapshots 均分開保留，不覆寫失敗／R1 歷史證據。工具 setup 失敗的重述摘要與原始 session transcript 明確區分。

## 未完成的物理驗收

Parent 需實機捕捉本次 operation monitor baseline／accepted HWND/PID/TID/session/path 與 returning foreground，確認 native transport 實際看到 eligible broker，並檢查 owner 同時的 valid/visible/minimized/maximized 狀態、activation return＋after snapshot、第二 API 結果。若 capture 不存在或 current foreground 不符合，本候選會 fail closed；不保證修復 PID10088 那次未知身分的案例。

B old-slot 的既有人測 RDP PASS 不改寫；新 slot 的歷史 FAIL 不改成 PASS。Console/RDP C/R4、R5 physical retest 仍 pending。這只是 step1 repair candidate，不是 RDP support promotion。

## Candidate／source provenance

EXE：C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-handoff-20261006-target/release/portable-fido-vault.exe；SHA-256 953a794ffd7067890d3b6e0141798c16f2632cfc88d4ac016ff75fe05ad0dc80。同目錄 WebView2Loader.dll SHA-256 86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5，與 isolated registry 的官方 DLL bytes hash 相同；兩個 PE machine 都檢查為 x64 0x8664。EXE/DLL 完整副本保留在 evidence candidate-artifact/，沒有啟動。

source 是 scope HEAD＋本輪未提交的 backend/test oracle diff；candidate-source/ 的兩份來源在 checks/build 後逐檔 hash 比對相同。initial-source-hashes、candidate-before-build-source-hashes、final-source-hashes 及 candidate-provenance 保存來源／artifact 關係。報告 final hash 另由 final-provenance 保存。除兩份授權 Rust 來源外，其餘 tracked 檔案最終 SHA-256 與初始相同；新 report 與 evidence 是 untracked deliverables／獨立證據，不混入 artifact identity。

Tauri build 自動重寫三份 schemas；generated-after-release/ 保存原生成 bytes，generated-restoration.json 保存初始／生成 hashes，再由 git blob 或其原 CRLF 形式中選出與初始 hash 完全相同的 bytes 還原，沒有 broad reset／config edit。這是移除自動 build side effects，交付不含 schema diff。

第一個 seal-candidate invocation exit1 是 reference raw hash check：read-only Parent texts 的 CRLF 與 ledger 的 LF 不同。三份 normalized LF hash 都等於 ledger；retry 同時保留 raw／normalized hashes，沒有改 references。這個封存工具失敗與 Python／archive／loader／compile／額外 assertion failure 一樣保留；不算 regression RED，也不否定實際 release build exit0。

最終 `git diff --check` 實際 exit0。新增 report 的 `git diff --no-index --check -- NUL docs/reports/rdp-registration-foreground-handoff.md` exit1（新增檔案有 diff）；stdout 0 bytes，stderr 只有 LF→CRLF 提示，沒有 whitespace error，未將它偽記成 exit0。`tdd-and-check-results.json` 再核對全部 11 個 genuine RED/ GREEN 計數、每輪 source snapshot hashes 與 required check exits。
# Review fixes 01：第三個獨立實作 context

Candidate-01 的獨立審查結果是 **FAILED／REJECTED**；先前測試與 build 通過並未推翻 S1、L1、S2。以下增補是本次修正紀錄，前文 candidate-01 的數字與 artifact 僅代表歷史候選，不代表本次候選。

本次 production delta 只有 `src-tauri/src/windows_webauthn.rs`。既有 `webauthn_diagnostics.rs` 的 candidate-01 修改保留，本輪未修改它。S1 在所有 broker metadata 後重新比對 HWND/PID/TID，且最後 activation focus sample 前再次檢查 owner 與 broker identity；最後 identity 後沒有慢速 metadata query。L1 在 current PID 等於 owner PID 的既有前提下，只接受一次明確成功的 session query，失敗即拒絕。S2 以 Result 明確傳遞 EnumWindows／potential broker 觀察完整性；baseline 列舉或 identity 不完整也不能建立 monitor。零長度或截斷的 GetWindowText／GetClassName 不視為可信空字串。具有確定 ordinary class 或不符 title 的視窗不查 slow process path；未知 class/title 保守拒絕，可能造成相容性假陰性。

正式 worker 使用 injectable MonitorPolicy／monitor_observe seam，完整性失敗或已觀察 ambiguity 永久終止本 instance。測試再移除競爭者並呼叫同一 policy，仍不能重新授權。補測 broker already foreground／activate、session/path/identity/metadata/列舉失敗、取消與 metadata 期間 late cancellation、instance channel 隔離、baseline 不完整及繁體中文 title。既有 join 後 take、worker panic 丟棄結果、context entry take、credential／owner 綁定、同 HWND update 與其他 operation 清除、失敗 response 清除的測試保留。

新證據目錄：`D:/project/_worktrees/portable-fido2-vault-rdp-handoff-20261006/handoff-evidence/review-fixes-01/`。所有新 log、JSON、RED source snapshot 以 exclusive create 保留；原 diagnostic-step1 的 11 個 RED/GREEN 與 candidate-01 archive 未修改。

垂直 TDD 順序是 S1 → L1 → S2，各自在下一項開始前 GREEN。`red-s1-terminal`、`red-l1-single-query`、`red-s2` 都是 exit101、0 passed／1 failed 的真正 expected assertion RED，對應 `green-s1`、`green-l1`、`green-s2` 都 exit0、1 passed／0 failed。`red-s1` 名稱下第一次早期 drift 被既有檢查擋住而通過，不列為 RED。`red-l1` 保留原 Option equality 反例（0 passed／1 failed）；之後單一成功 query 的正確期望以 `red-l1-single-query` 重新 RED，再修正，未將先前反例重新標成 GREEN。

最終本次 source：targeted-final2 30 passed／0 failed；lib-final2 120 passed／0 failed；node-final 65 passed／0 failed／0 skipped；syntax-final、clippy-final2（-D warnings）、fmt-final2 均 exit0。所有 Cargo 明確使用 GNU stable toolchain 與指定 isolated CARGO_HOME／TARGET_DIR、jobs1、incremental0、debug0；TEMP/TMP/TMPDIR 為 process-local scratch review-fix-fixtures/run-01。既有官方 scratch test manifest sidecar保留，無正式 manifest 修改。

第一個 release-final build 期間追加 localized title／最終 owner identity 補測與檢查，所以該次 build 不作最終 artifact provenance；最終必須以 release-final2 與 final-build-source-hashes／final-build-dirty.diff 配對。本輪沒有重標舊 candidate-01 build。最終 artifact、schema 副作用封存／精確還原、diff check 與完整 hashes 由本目錄 final-provenance.json 記錄。

這仍是 best-effort broker 關聯，沒有 cryptographic ceremony association 或 Windows 原子保證；最後 sample 後仍有不可避免的 OS race。API>=4、固定 RP/origin、raw salt flag、hmac confirmation、credential match、exact32-byte secret、成功後 append 與 final snapshot→nonblocking arm→FFI 邊界保持不變。恢復僅限合格 minimized owner；不 demaximize，不使用 topmost、AttachThreadInput、ASFW_ANY 或 retry。

本次 physical gates：**NOT_TESTED**。歷史 foreground identity **UNKNOWN**；actual RDP new-slot 維持 **FAILED**，直到另行 physical PASS；Console/RDP C/R4、R5 待測。blocked card t_2fad9e76、stacked draft PR21 狀態未操作；沒有 GUI／裝置／deploy／merge／支援升級、commit／push 或外部 API。Parent 仍須獨立測試、fresh final review 與決定 publication。

本次最終 release-final2 實際 exit0，GNU optimized build 1m57s（含等待第一輪 build lock）；final source 逐檔 hash 與 build 前完全一致，HEAD＋dirty delta 也完全一致。EXE SHA-256 5464b96ba52b494110b0f8bce53690c6b8f4db7b870bf3836edbc4bac1cdff65，大小 6913536 bytes；完整 EXE／DLL 副本保存於新 evidence candidate-artifact。三個 schema 原始 hash 均保持不變，仍封存 build 後 bytes 與核對紀錄。git diff --check exit0。

## Parent 最終核驗與發布交接：candidate-02

本節是 parent 在 writer 結束後的獨立核驗結果，取代前文「parent 仍待核驗」的狀態敘述；不改寫 candidate-01 的 REJECTED、舊 build、歷史 UNKNOWN／FAILED 或任一失敗證據。只接受 candidate-02 的程式範圍，不宣告實機問題已解決。

- 凍結候選：archive `review-candidate-02/`；完整 181 個 tracked source SHA-256 與 live worktree、review snapshot 均符合 manifest。最終 writer exit0；production 只改 `windows_webauthn.rs`，`webauthn_diagnostics.rs` 僅 test oracle，其他 tracked source（含 generated schemas）未漂移。
- Fresh 獨立程式審查 `deleg_eb2746b5`：**PASS**；`security_concerns=[]`、`logic_errors=[]`，完整裁決封存於 `review-candidate-02/verdict.json`。S1 metadata 後／activation 前完整 identity 核對、S2 不完整觀察 fail-closed、L1 單次明確成功 session query 已核實。先前 `deleg_afbf2a32` provider HTTP429 是未完成審查，不算程式 PASS；原失敗保留。
- Parent 自行實跑並核對完整 logs：handoff targeted **30 passed / 0 failed**、real-ctap Rust library **120 passed / 0 failed**、Node TAP **65 passed / 0 failed / 0 skipped**；syntax、Clippy `-D warnings`、rustfmt、diff check 全部 exit0。證據為 archive `parent-verification-01/`，各命令 stdout/stderr hash 已驗。
- Parent real-ctap GNU Release build exit0；`parent-release-01/` 的 source-before / source-after 完全相同，與 reviewed candidate source 相符。這是實際完成的增量 build，不把 writer 的舊候選 build 冒稱為本次結果。
- Canonical 垂直 TDD 核實 **14 組**：原 11 組與 S1、L1、S2 各 1 組。採 archive `parent-tdd-audit-02.json`；L1 canonical 是 `red-l1-single-query` → `green-l1`，RED 與最終測試的預期斷言相同（僅 formatter whitespace 差異）。初始 `red-l1` Option-equality 反例另保留為歷史 RED，不拿經調整的預期偽配 GREEN。舊 `parent-tdd-audit.json` 保留但由新 audit 取代。
- 新的非覆寫 artifact archive：`D:/project/_archives/portable-fido2-vault/20261006-rdp-foreground-handoff/candidate-02-accepted-artifacts/`；僅 EXE、必要 loader 及 metadata，不含使用者 vault、憑證、plaintext fixture 或原始診斷。EXE SHA-256 `5464b96ba52b494110b0f8bce53690c6b8f4db7b870bf3836edbc4bac1cdff65`，6,913,536 bytes；loader SHA-256 `86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5`。兩者 x64；EXE subsystem 3 與先前候選一致，imports 確認需要 app-local `WebView2Loader.dll`。Loader Authenticode **Valid / Microsoft Corporation**；自建 EXE **NotSigned**，未宣稱已簽章或執行驗收。
- Build 真實身分是 scope HEAD `765f11545d8611c38a0abf6eb9097f4208351a57` 加完整已審 Rust dirty delta（SHA-256 `6e3b0549ad28edc08a2b036983b1526b6cab996d307bfce56d12d40a15bf0746`）。編譯在 publication commit 之前；parent 會以 Git blob 比對核實提交內容，remote／PR 的讀回證據另保存，不把它描述為 commit 後重建。

### 非阻擋性測試補強建議

Reviewer 指出兩項後續補強：以兩個實際 monitor/backend context 的交錯觀察、取消與消費替代空 unrelated-instance Mutex 的隔離斷言；把完整性失敗／metadata 期間取消矩陣也套用至 owner-foreground activation 分支，明確斷言無 activation、無 publication 與同 policy 不重新授權。現有 production channel 為各 monitor 私有，拒絕分支已存在，未發現阻擋性漏洞；本輪不為建議再擴大 production scope。

### 保持待驗與未授權的界線

PR21 仍是 stacked **Draft**、base 為未合併 PR20 分支；workflow 只接受 main base，因此本修正 hosted CI 是 **NOT_RUN**，不能挪用 PR20 綠燈，亦不修改 workflow。Kanban `t_2fad9e76` 保持 blocked，以讀回的 comment 記錄已通過程式 gate 與發布身分；不強制原生 PR acceptance 或 DONE。

本輪沒有 merge、deployment、GUI／authenticator、WinRM／RDP 或真實使用者 vault 操作。舊槽 RDP PASS 保留；新槽的歷史實測 **FAILED**、foreground 身分 **UNKNOWN**，新候選 Console／RDP C/R4／R5 仍 **NOT_TESTED**。下一步須另行授權後，以隔離測試 vault 進行一次完整新槽註冊（MakeCredential + GetAssertion）、確認 slot 增量與 Console／RDP 雙向解鎖，再做負面測試；失敗不可連續重註冊、刪舊槽或重設金鑰，第一段成功可能留下 key-side orphan credential。沒有 RDP 支援範圍提升。
