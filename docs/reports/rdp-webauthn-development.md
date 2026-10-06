# RDP WebAuthn R1 開發報告（自動化候選版已交付）

自動化候選版已交付；Parent review-round1 為 FAIL，collector metadata 尾 LF bug 已修正，仍待 Parent 獨立重審與 Console/RDP physical acceptance。本輪 Node 65/65、real-ctap lib 85/85、fmt、Clippy、PS5.1 parser/actual collector、Parent 原 probe 均實際 exit0。GUI 使用 qualityfix 輪候選，Rust 未變，本輪未重建或執行 GUI。下方保留先前 PermissionDenied／missing component 等歷史；本輪證據詳見 reviewfix 章節。

## Provenance 與先前失敗

Main 基準 `591269560eae3b36aa2c85f4b44d7d704e588e09`；HEAD/scope `d87e1763c295b139cfbd73714608293a01788d5d`；branch `feat/rdp-webauthn-validation-20261006`。唯一 worktree `D:/project/_worktrees/portable-fido2-vault-rdp-20261006`。

完整重讀 archive/codex-r1-prompt.md、tracked plan、四個 partial 檔案與既有 backend/logger/FidoError。Parent 已在 production edit 前建立並讀回 draft PR #20：<https://github.com/skycity1010-creator/portable-fido2-vault/pull/20>。本輪不呼叫 PR/Kanban API。

第一次 `cargo +stable-x86_64-pc-windows-gnu test --lib --locked --features real-ctap -j 1 diagnostics_tests` exit **101**，在共用 registry 的 Tauri generated permission docs 遭 PermissionDenied，0 tests executed；不是預期 TDD RED。舊所有 logs 未覆蓋。上一輪 collector 的四項一起 RED→一起 GREEN 是水平切片，**不算逐項 tracer-bullet TDD**；原 partial 四檔及 hash 已保存於 `codex-evidence/partial-before-resume/`。

Parent 依 Cargo 官方 CARGO_HOME 機制建立 allowed scratch 中的隔離 cache，驗證 329 個 .crate checksum、508 個 registry index；未複製 auth/credentials/global config/registry src。Parent setup evidence（只讀）：`parent-evidence/isolated-cargo-home-manifest.json`、`isolated-cargo-tree*.log`。成功 cargo tree 只表示 graph 可解析，**不是 test/build PASS**。Cargo 自行在新 home 解壓依賴，Tauri 生成 docs 的路徑因此留在已允許 root；未放寬 sandbox、改 ACL、改共用 registry 或安裝工具。

## 每次 Cargo 的 process-local 環境

```powershell
$env:CARGO_HOME='C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target/isolated-cargo-home'
$env:CARGO_TARGET_DIR='C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target/build-v2'
$env:CARGO_BUILD_JOBS='1'
$env:CARGO_INCREMENTAL='0'
$env:CARGO_PROFILE_TEST_DEBUG='0'
$env:CARGO_PROFILE_DEV_DEBUG='0'
$env:PATH='C:/Users/skycity1010/.cargo/bin;C:/Users/skycity1010/tools/winlibs-mingw/mingw64/bin;'+$env:PATH
```

所有工具命令均明確設隔離 CARGO_HOME。沒有改持久環境；測試注入 metadata/provider，不改全域 process env。Cargo 命令 cwd=`<worktree>/src-tauri`，Node/collector/git cwd=`<worktree>`。原 GNU Rust toolchain proxy 與 RUSTUP_HOME 不變。

## Test executable loader 修復（只在 scratch）

Resume 第一次 Rust 首項命令完成 dependency compile，但 test executable loader 回報 `0xc0000139 STATUS_ENTRYPOINT_NOT_FOUND`。實際 outer native exit **-1073741511**，0 tests executed，不算功能 RED。唯讀 PE import/export 查到 test 匯入 `TaskDialogIndirect`，System32 comctl32.dll 缺此 entrypoint；Tauri 官方套件文件要求 Common Controls v6。

只將隔離、已依 lock checksum 驗證的 `tauri-build-2.7.0/src/windows-app-manifest.xml` 複製為 scratch test executable 的 `.exe.manifest`，啟用標準 Common Controls v6；不修改 test EXE、系統 DLL、registry/policy、delivery build.rs 或 dependency source。原檔／sidecar hashes 相同，見 `resume-test-manifest-provenance.json`。之後相同 cargo test 命令真實跑到預期 assertion RED（0 pass/1 fail），再進 GREEN。這個 sidecar 僅為 lib test artifact，不是部署或 GUI 支援證據。

## 實作與安全語義

- constructor 讀實際 same-process WebAuthNGetApiVersionNumber/GetCurrentProcessId/ProcessIdToSessionId，先輸出固定 capability JSON，再保留原 API v4+ guard。API 未測與 SessionId 不可得為 null；session 0=noninteractive，其餘 unknown。不讀 SESSIONNAME，不新增 RDP support/verified boolean。
- operation 使用 closed enum 與固定六 key JSON，只接受布林／長度／stage metadata。所有 FidoError 均 exhaustively 映射 category，不解析或序列化 raw text。diagnose observer 在 operation 返回後 emit 一次，原成功／錯誤 Result 保持不變。
- 原 foreground final sample→monitor.arm→FFI 間隙未加入 log；原 guard/RP/origin/raw-salt/credential validation/32-byte validation/RAII freeing/fail-closed/vault format 不變。
- creation confirmed 只記既有 extension 正向確認；Get output pointer/length 與 selected credential validation 布林按原步驟記錄。尚未量到的欄位為 null；missing output、invalid output、credential mismatch 分開。generic api-error 不臆測取消／policy／timeout 原因。
- collector 只讀 metadata，UTF-8 BOM、PS5.1 parser。OS build+UBR 任一缺失時 null；installed mstsc.exe version 不當成 actual client。policy 只讀 HKLM Terminal Services fDisableWebAuthn，0/1 allowlist，其餘 null，不宣稱 effective policy。API measured_in 固定 collector-process，不覆蓋 GUI evidence。
- 來源 missing/exception/invalid metadata 為 null，error/warning/verbose/information streams 不進 stdout。collector 沒有 make/get、GUI、vault、PIN、policy 寫入或硬體操作。

## 逐項 RED→GREEN→REFACTOR

Collector 移除舊未驗收實作後，依次新增一項測試、使用 `node --test --test-name-pattern <pattern> tests/rdp-webauthn-environment.test.cjs` 跑出該行為預期失敗，再最小實作 GREEN。九個循環：

| # | Pattern | 預期 RED 原因 | Actual RED→GREEN |
|---|---|---|---|
| 01 | `^serializer_empty_allowlist$` | 空 serializer 缺固定 keys/unknown defaults | exit 1（0/1）→0（1/0） |
| 02 | `^serializer_api_boundaries$` | API 0/1/3/4/9 未序列化 | 1（0/1）→0（1/0） |
| 03 | `^serializer_process_unknown_and_noninteractive$` | PID/SessionId/session kind 未序列化 | 1（0/1）→0（1/0） |
| 04 | `^serializer_installed_client_only$` | installed client metadata 缺失 | 1（0/1）→0（1/0） |
| 05 | `^serializer_policy_allowlist$` | policy 0/1 未序列化 | 1（0/1）→0（1/0） |
| 06 | `^serializer_build_and_ubr$` | build+UBR 缺失 | 1（0/1）→0（1/0） |
| 07 | `^metadata_injected_providers$` | metadata provider 函式尚不存在 | 1（0/1）→0（1/0） |
| 08 | `^metadata_failures_and_missing_sources$` | provider exception 尚未捕捉 | 1（0/1）→0（1/0） |
| 09 | `^actual_collector_metadata_and_parser$` | 真實 collector 尚未接來源，PID null | 1（0/1）→0（1/0） |

括號為 pass/fail。refactor 抽出 nonnegative integer metadata helper，保持拒絕字串 coercion；`node --test tests/rdp-webauthn-environment.test.cjs` exit 0，9 pass/0 fail。

Rust 每一項以完整命令 `cargo +stable-x86_64-pc-windows-gnu test --lib --locked --offline --features real-ctap -j 1 webauthn_diagnostics::tests::<name>` 順序执行 RED/GREEN：

| # | Test name | 預期 assertion RED | Actual RED→GREEN |
|---|---|---|---|
| 01 | capability_api_boundaries | 空 record 缺 API field | 101（0/1，loader 修復 retry）→0（1/0） |
| 02 | capability_unknown_session_and_allowlist | 未輸出 provenance/PID/session/unknown | 101（0/1）→0（1/0） |
| 03 | error_categories_never_use_raw_text | unknown 尚未映射所有 FidoError | 101（0/1）→0（1/0） |
| 04 | operation_names_and_keys_are_closed_allowlists | 空 operation record 缺封閉名字及 keys | 101（0/1）→0（1/0） |
| 05 | hmac_creation_reports_positive_and_unconfirmed_only | creation 欄位仍 null | 101（0/1）→0（1/0，retry） |
| 06 | valid_output_metadata_is_32_bytes_and_matched | output/match 欄位仍 null | 101（0/1，retry）→0（1/0） |
| 07 | missing_and_invalid_output_and_mismatch_are_distinct | generic internal 尚未分 output/mismatch | 101（0/1）→0（1/0） |
| 08 | api_preflight_and_response_failures_do_not_guess_cause | stage 尚未分類 | 101（0/1）→0（1/0） |
| 09 | observer_runs_after_operation_and_keeps_result_unchanged | operation 已返回但尚未 emit | 101（0/1）→0（1/0） |
| 10 | backend_wiring_preserves_guard_and_foreground_ffi_gap | constructor 尚未接 capability logging | 101（0/1）→0（1/0） |

第 10 項為 source wiring 補充回歸，前九項為真正執行的純函式／JSON／注入 observer 測試，並非只用 regex 假測試。Refactor 抽出 failure_category、明確 enum/struct、集中 serializer；`cargo ... test ... webauthn_diagnostics` exit 0，10 pass/0 fail。

真實額外失敗保留：`resume-rust-05-creation-green.log` 與 `resume-rust-06-output-red.log` 的 exit 101 是文字替換誤改 test 預期的 E0424 compile error，不算 GREEN／功能 RED；修正後的 `*-retry.log` 才取得上述 actual assertions。Node stdout supplementary audit 的一次 inline shell quoting SyntaxError 未執行 collector，inner exit 未捕捉、outer shell exit0，不計驗收；換 `.cjs` 檔案後獨立實際 collector exit0、audit exit0。

## Resume 已執行驗證（qualityfix 前歷史）

| Exact command | Actual exit | Actual counts / 結果 |
|---|---:|---|
| `cargo +stable-x86_64-pc-windows-gnu test --lib --locked --offline --features real-ctap -j 1 webauthn_diagnostics` | 0 | 10 pass / 0 fail |
| `cargo +stable-x86_64-pc-windows-gnu test --lib --locked --offline --features real-ctap -j 1` | 0 | 85 pass / 0 fail |
| `cargo +stable-x86_64-pc-windows-gnu clippy --lib --locked --offline --features real-ctap -j 1 -- -D warnings` | 1 | cargo-clippy 未安裝；未執行 Clippy，不宣稱零 warning |
| `cargo +stable-x86_64-pc-windows-gnu fmt --check` | 1 | cargo-fmt 未安裝；未執行格式檢查 |
| `cargo +stable-x86_64-pc-windows-gnu build --release --locked --offline --features real-ctap --bin portable-fido-vault` | 0 | 真實 optimized build，8m09s；不執行 GUI |
| `node --test tests/*.test.cjs` | 0 | 最終 62 pass / 0 fail（stderr 不得洩漏 metadata error text 的回歸亦通過） |
| `node --check src/app.js` | 0 | syntax check |
| `git diff --check`（cleanup 前） | 0 | whitespace check |
| `powershell.exe -NoProfile -NonInteractive -File scripts/collect-rdp-webauthn-environment.ps1` | 0 | 獨立真實 collector；raw stdout `resume-collector-actual.json`、stderr 0 bytes、root/nested allowlist audit PASS |

補充 `rustfmt +stable-x86_64-pc-windows-gnu --edition 2021 --config skip_children=true src-tauri/src/webauthn_diagnostics.rs src-tauri/src/windows_webauthn.rs src-tauri/src/lib.rs` 也因未安裝 component exit1；未自行安裝。測試程式碼後續手動排版後已執行 final lib rerun，85 pass/0 fail、exit 0（resume-rust-lib-final.log）；未把舊版本 PASS 當最終驗收。

## Evidence 與尚未驗收

全部原始 logs、每次 exact command/arguments/cwd/environment/exit JSON、timestamps、TDD retries 與 metadata stdout：`D:/project/_archives/portable-fido2-vault/20261006-rdp-verification/codex-evidence/`，新增均使用 `resume-*` 名稱，first-failure 原檔與 parent evidence 不變。

Resume 舊候選（歷史，非本輪最終 hash）已建置，只 hash／靜態 PE metadata 檢查，沒有 launch：

- EXE absolute path：`C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target/build-v2/release/portable-fido-vault.exe`
- SHA-256：`A82C32400C543CE6A03E67D3F212E565A9E9DC426589E211D38AC21ED08FCC1A`
- app-local loader：同目錄 `WebView2Loader.dll`，SHA-256 `86545B66CDB0603BC26B626FB9AD610CB6E71F28D468F5EA66DF23B03DDA96D5`。
- EXE/loader 皆 `pei-x86-64`（objdump -f actual exit0）。loader hash 等於隔離 registry 中 `webview2-com-sys-0.39.1/x64/WebView2Loader.dll`；該 crate checksum 由 Parent setup manifest 對 Cargo.lock 驗證。見 resume-release-artifacts.json、resume-release-pe-architecture.log、resume-loader-source-provenance.json。這是 build candidate，不宣稱 portable 部署成功。

最終修改完整清單（全部符合原允許 diff）：

1. `src-tauri/src/windows_webauthn.rs`
2. `src-tauri/src/webauthn_diagnostics.rs`
3. `src-tauri/src/lib.rs`（只必要 mod 宣告）
4. `scripts/collect-rdp-webauthn-environment.ps1`
5. `tests/rdp-webauthn-environment.test.cjs`
6. `docs/rdp-webauthn-verification.md`
7. `docs/reports/rdp-webauthn-development.md`

Tauri build 自動重生的 acl-manifests/desktop-schema/windows-schema 均已還原：先保存 cleanup hash evidence，再從 HEAD blob／既有 checkout EOL filters 還原；三檔 git diff HEAD exit0，最終 status 無 schema 修改。未修改 Git index/config。Cargo.toml/Cargo.lock/vendor/frontend/vault/crypto/部署腳本/已提交 scope plan 均無 diff。

所有逐項 command 的完整 arguments、environment、actual exit/pass counts 彙整於 resume-results-final.json；final source hashes／branch/HEAD／tracked dirty diff hash 與 artifact hash 見 resume-final-provenance.json。原 logs 保留，這些 hash 表示未提交的候選 source snapshot，不把 HEAD scope commit 當成包含新增代碼的 commit。

**Resume 當時仍欠指定 GNU Clippy 與 fmt 的實際驗收（歷史）**：component 不存在，沒有安裝，也沒有拿其他 toolchain 的結果替代。Parent 需提供符合 GNU 約束的工具後重跑這兩項；未聲稱 R1 全部完成。

physical R2–R5 全部 NOT_TESTED；GUI 實際 process/Console/RDP/hardware 沒有操作。正式金庫／生產支援範圍／部署未變更。未 commit/push/merge、未修改 PR/Kanban；PR 依前置仍為 draft。交 Parent Coder 獨立 review，缺 Clippy/fmt 不應提前結案。

最終 `git diff --check` actual exit0（resume-diff-check-final.log），`node --check src/app.js` actual exit0（resume-node-check-final.log）。Git 的 LF→CRLF 提示是既有 checkout EOL warning，非 Clippy 結果；不把它當格式檢查 PASS。

## Qualityfix：Parent 補齊官方 component 後的本輪驗證

Parent 已補齊 GNU 官方 rustfmt/clippy component 並獨立重跑 Node 62/62、Rust lib 85/85、Clippy exit0、Release exit0、actual collector allowlist。這是 Parent 提供的獨立結果，未冒充本輪 Codex 執行。Parent `parent-evidence/parent-fmt.log` 記錄當時 fmt exit1 的四個 block，本輪已讀回。唯讀 reviewer 正在 immutable review-round1 快照 review，不是第二個 writer；本輪沒有啟動其他 writer 或自行結 Kanban。

本輪實際讀 Cargo.toml 確認 edition=2021。`rustfmt +stable-x86_64-pc-windows-gnu --version` actual exit0：`rustfmt 1.9.0-stable (48a229ceae 2026-09-01)`；`cargo +stable-x86_64-pc-windows-gnu clippy --version` actual exit0：`clippy 0.1.98 (48a229ceae 2026-09-01)`。沒有安裝任何工具。

本輪只修以下四個 block，沒有功能／測試行為變更，也沒有用 regex 放寬測試：

- lib.rs：必要 mod 宣告順序調整，webauthn_diagnostics 在 windows_webauthn 前。
- webauthn_diagnostics.rs：is_some_and 條件排版。
- webauthn_diagnostics.rs：before_ffi.rsplit 呼叫鏈排版。
- windows_webauthn.rs：capability_record 多行參數排版。

Exact formatter command（cwd=worktree root）：

```text
rustfmt +stable-x86_64-pc-windows-gnu --edition 2021 --config skip_children=true src-tauri/src/lib.rs src-tauri/src/webauthn_diagnostics.rs src-tauri/src/windows_webauthn.rs
```

Actual exit0。只傳這三檔，skip_children=true 避免 lib.rs 遞迴整理其他 module。qualityfix-before/ 保存三個 Rust 檔與舊報告、SHA-256；qualityfix-format-diff-{lib,diagnostics,windows}.log 分別保存 1/2/1 hunks。這三次 `git diff --no-index <before> <current>` actual exit1 表示存在預期格式 diff，**不是新增 TDD RED**。使用既有 tests 證明 refactor 前後 GREEN：Parent 前述獨立結果與本輪實際結果分開記錄；歷史 tracer-bullet RED/GREEN 保留不改名。

每次工具命令都明確設定原 process-local 隔離 CARGO_HOME、build-v2 target、jobs1、incremental0、test/dev debug0、原 cargo/Winlibs PATH；完整值同前述環境段落。沒有修改共用 Cargo、lockfile、vendor、auth、ACL 或持久環境。

### 本輪實際命令與結果

Cargo cwd=`D:/project/_worktrees/portable-fido2-vault-rdp-20261006/src-tauri`；Node/collector/git cwd=worktree root。

| Exact command | Actual exit | Actual counts / 結果 | 新 evidence |
|---|---:|---|---|
| `cargo +stable-x86_64-pc-windows-gnu fmt --check` | 0 | 格式檢查通過 | qualityfix-fmt-check.log |
| `cargo +stable-x86_64-pc-windows-gnu test --lib --locked --offline --features real-ctap -j 1` | 0 | 85 pass / 0 fail / 0 ignored | qualityfix-rust-lib.log |
| `cargo +stable-x86_64-pc-windows-gnu clippy --lib --locked --offline --features real-ctap -j 1 -- -D warnings` | 0 | Clippy 零 warning；無 test count | qualityfix-clippy.log |
| `cargo +stable-x86_64-pc-windows-gnu build --release --locked --offline --features real-ctap --bin portable-fido-vault` | 0 | 真實 optimized rebuild，1m45s；未 launch | qualityfix-release-build.log |
| `node --test --test-reporter=tap tests/*.test.cjs` | 0 | 62 pass / 0 fail / 0 skipped | qualityfix-node-suite.log |
| `node --check src/app.js` | 0 | syntax check 通過 | qualityfix-node-check.log |
| `git diff --check` | 0 | cleanup 後 whitespace check 通過 | qualityfix-diff-check.log |
| `node --test --test-reporter=tap --test-name-pattern ^actual_collector_metadata_and_parser$ tests/rdp-webauthn-environment.test.cjs` | 0 | 1 pass / 0 fail；真實 PS5.1 Parser::ParseFile、BOM、collector metadata/schema | qualityfix-parser-collector.log |
| `powershell.exe -NoProfile -NonInteractive -File D:/project/_worktrees/portable-fido2-vault-rdp-20261006/scripts/collect-rdp-webauthn-environment.ps1` | 0 | 另一次真實 stdout JSON、stderr 0 bytes；root/nested allowlist 審查 PASS | qualityfix-collector-actual.json / qualityfix-collector-actual.command.json |
| `node D:/project/_archives/portable-fido2-vault/20261006-rdp-verification/codex-evidence/qualityfix-collector-audit.cjs` | 0 | collector stdout audit 通過 | qualityfix-collector-stdout-audit.log |

PS5.1 parser 版本 assertion 為 major5/minor1、errors0。collector API 仍 measured_in=collector-process；stdout 沒有 sensitive/raw exception 欄位，不直接貼未審核內容。只收 metadata，沒有 Make/Get、GUI、vault、PIN、policy 寫入或實體金鑰操作。

所有 build/check 完成後，先確認 scope 僅已知三個 generated schemas 與原允許七檔；保存 generated 三檔 raw bytes、diff、SHA-256（qualityfix-generated-before/、qualityfix-generated-before.diff、qualityfix-generated-before.json），再只還原這三個 worktree 檔至 HEAD，使用既有 checkout EOL filters；每檔 git diff HEAD exit0，不改 index。qualityfix-generated-restoration.json 與 cleanup log actual exit0 記最後只有允許七檔。沒有 broad restore/reset/clean 或捨棄未知變更。

### 本輪最終候選（取代所有歷史候選 hash）

- EXE absolute path：`C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target/build-v2/release/portable-fido-vault.exe`
- **SHA-256：`758C22D5373868D0733C2424C69CADDB701C74A80623C61538C4CA397AED3466`**。
- app-local DLL absolute path：`C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target/build-v2/release/WebView2Loader.dll`
- DLL SHA-256：`86545B66CDB0603BC26B626FB9AD610CB6E71F28D468F5EA66DF23B03DDA96D5`，與已驗證 crate 中 webview2-com-sys-0.39.1/x64/WebView2Loader.dll 相同。
- `objdump -f <上述 EXE> <上述 DLL>` actual exit0，兩者均 pei-x86-64。只做靜態 metadata/hash，不執行 EXE 或 DLL，不宣告 bundle／部署成功。

最終 source、branch/HEAD、七檔 hash、完整 tracked dirty diff/hash、EXE/DLL provenance 及每次 exact command/environment/exit/counts 保存為 qualityfix-final-provenance.json、qualityfix-tracked-source.diff、qualityfix-results-final.json；全在 `D:/project/_archives/portable-fido2-vault/20261006-rdp-verification/codex-evidence/`。沒有覆寫任何 resume/parent logs；Parent evidence 與 immutable review 快照未修改。

**自動化候選版已交付，Parent 獨立 review 與 Console/RDP physical acceptance 尚待。** R2–R5 全部 NOT_TESTED；不宣告 RDP 支援。正式金庫、生產支援範圍與部署未變更。未 commit/push/merge、未改 PR/Kanban/remote；PR 依前置仍為 draft，交 Parent 獨立 review 與後續裁決。

## reviewfix：review-round1 P2 metadata serializer 修正

Parent 獨立初審 FAIL：Windows PowerShell 5.1 的 .NET regex `$` 可在最後 LF 前匹配，因此 build `26100` 加尾 LF 與 client version `10.0` 加尾 LF 被錯誤保留。原 `parent-evidence/review-round1-verdict.json`、`regex-repro.ps1`、`regex-repro-red.log`（exit1）唯讀保留。本輪僅改 collector、Node tests、此報告；Rust 三檔、manual checklist、Cargo.lock 的 hashes 與 qualityfix provenance 相同。

.NET build/client pattern 改為 `\A[0-9]+\z`／`\A[0-9]+(\.[0-9]+)*\z`。沒有 Trim、Replace 或 normalization；來源不合法即 null，client binary/version 同時 null。PS5.1 UTF-8 BOM 保留。七種 synthetic invalid case 覆蓋 LF、CRLF、前後空白、前後 tab、多行 digits；合法值仍保留。

逐項真實測試（root 執行；各 log 與 `.command.json` 位於下述 evidence root，環境沿用本文 process-local 設定）：

| 行為／exact command | 修改前 | 修改後 | evidence prefix |
|---|---|---|---|
| `node --test --test-reporter=tap --test-name-pattern=^serializer_rejects_noncanonical_build$ tests/rdp-webauthn-environment.test.cjs` | exit1，0 pass／1 fail，錯誤保留尾 LF | exit0，1 pass／0 fail | reviewfix-build-red / build-green |
| `node --test --test-reporter=tap --test-name-pattern=^serializer_rejects_noncanonical_client_version$ tests/rdp-webauthn-environment.test.cjs` | exit1，0 pass／1 fail，binary/version 非 null | exit0，1 pass／0 fail | reviewfix-client-red / client-green |
| `node --test --test-reporter=tap --test-name-pattern=^schema_rejects_noncanonical_versions_directly$ tests/rdp-webauthn-environment.test.cjs` | **exit0，1 pass／0 fail，未得到預期 RED** | exit0，1 pass／0 fail | reviewfix-schema-red / schema-green |

schema regression 直接傳合成 record，不透過 collector；包含兩個 version 欄位與尾 LF 等各種非法值。實測現有 JavaScript regex 未開 multiline flag，已拒絕尾 LF；不得捏造 RED。`reviewfix-schema-red.log` 名稱是原預定 RED invocation，內容實際為 GREEN。此項是 GREEN→GREEN 加強：明確檢查 string、完整 match 的 index=0 與 match 長度等於輸入長度，不將 .NET `\z` 放入 JavaScript。故使用者要求的第三項「真實 RED」未達成；原因是指定尾 LF regression 在原 JS helper 已通過，留待 Parent 判定，不把它算成 TDD RED。

本輪完整驗證（actual exit codes，沒有使用舊 PASS 代替）：

| cwd | exact command | actual result | log |
|---|---|---|---|
| root | `node --test --test-reporter=tap tests/*.test.cjs` | exit0；65 pass／0 fail | reviewfix-node-full.log |
| root | `node --check src/app.js` | exit0 | reviewfix-node-check.log |
| root | `node --test --test-reporter=tap --test-name-pattern=^actual_collector_metadata_and_parser$ tests/rdp-webauthn-environment.test.cjs` | exit0；1 pass；PS5.1 ParseFile errors=0、BOM、真實 collector/schema 及 same collector PID/session/build+UBR 驗證 | reviewfix-parser-collector.log |
| root | `powershell.exe -NoProfile -NonInteractive -File D:/project/_archives/portable-fido2-vault/20261006-rdp-verification/parent-evidence/regex-repro.ps1` | exit0；5 invalid build + 5 invalid client cases PASS | reviewfix-parent-probe-green.log |
| root | `node D:/project/_archives/portable-fido2-vault/20261006-rdp-verification/codex-evidence/reviewfix-collector-audit.cjs` | exit0；另一次 actual collector exit0，stdout single allowlist JSON，stderr 0 bytes，無敏感欄位 | reviewfix-collector-stdout-audit.log |
| src-tauri | `cargo +stable-x86_64-pc-windows-gnu fmt --check` | exit0 | reviewfix-fmt.log |
| src-tauri | `cargo +stable-x86_64-pc-windows-gnu test --lib --locked --offline --features real-ctap -j 1` | exit0；85 passed、0 failed、0 ignored、0 filtered | reviewfix-rust-lib.log |
| src-tauri | `cargo +stable-x86_64-pc-windows-gnu clippy --lib --locked --offline --features real-ctap -j 1 -- -D warnings` | exit0；零 warning | reviewfix-clippy.log |
| root | `git diff --check` | exit0 | reviewfix-diff-check.log |

完整原始輸出、argv/cwd/environment/actual exit：`D:/project/_archives/portable-fido2-vault/20261006-rdp-verification/codex-evidence/reviewfix-*`。collector 原 stdout 只存 evidence，經 root/nested key allowlists 審核；API measured_in=collector-process，不能覆蓋 GUI 診斷，也不代表 actual RDP client 或支援。PowerShell runner 包装 native stderr 為 NativeCommandError 的格式訊息不是 cargo failure；依實際 LASTEXITCODE 與測試結果判定。

GUI candidate 是 **qualityfix 輪**產物，本輪 collector regex/tests/docs 不影響 GUI，未重建：
`C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target/build-v2/release/portable-fido-vault.exe`
SHA-256 `758C22D5373868D0733C2424C69CADDB701C74A80623C61538C4CA397AED3466`。
同目錄 `WebView2Loader.dll` SHA-256 `86545B66CDB0603BC26B626FB9AD610CB6E71F28D468F5EA66DF23B03DDA96D5`；兩者 x64，來源與架構證據沿用 `qualityfix-release-artifacts.json`／`qualityfix-pe-architecture.log`，本輪再次讀回 hash。source+diff/hash snapshot 在 `reviewfix-final-provenance.json`／`reviewfix-final-source/`／`reviewfix-tracked-source.diff`，並對照 `qualityfix-final-provenance.json`，不是重新宣稱 Release build 成功。

本輪 checks 後三個 known generated schemas 無 diff，無需還原；最終只有原允許七個 delivery paths 有工作樹變更，其中本輪新改只有 collector、tests、report。沒有丟棄其他 edits、改 index 或覆寫舊 evidence。Console/RDP physical acceptance、R2–R6 仍 NOT_TESTED；正式金庫、支援聲明與部署未變。未 launch GUI、hardware、WinRM/RDP、commit/push/merge 或 PR/Kanban 操作。R1 不自行結案，待 Parent 獨立 re-review。
