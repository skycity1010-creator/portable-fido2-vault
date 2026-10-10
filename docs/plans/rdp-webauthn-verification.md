# Portable FIDO Vault RDP WebAuthn Verification Implementation Plan

> **For Hermes:** 本次依使用者明確指定，由 Codex CLI 在隔離 worktree 執行 R1 開發；Coder 負責規格、安全審查、證據讀回與 Kanban 管理。R2–R5 的互動金鑰操作由 Skycity1010 執行，不由無人值守代理代操作。

**Goal:** 證明或否定指定 Windows-to-Windows RDP 組合能否以連線發起端的實體金鑰，透過原生 Windows WebAuthn 重導安全解鎖 Portable FIDO Vault，且不破壞既有 Console／raw-salt 槽位相容性。

**Architecture:** 保留現有 Windows WebAuthn backend、API v4+ guard、固定 RP/origin/raw salt 與既有 vault 格式。先補足不洩密的同 process 診斷與唯讀環境收集，再以隔離測試金庫驗證 Console→RDP 舊槽、RDP→RDP/Console 新槽及 fail-closed 情境。協定欄位存在只是研究依據，實機結果才是支援裁決依據。

**Tech Stack:** Rust／Tauri 2／windows-sys 0.61.2、PowerShell 5.1（UTF-8 BOM）、Node test runner；Codex CLI 使用現有 OAuth；Windows GNU Rust toolchain + Winlibs MinGW。

---

## 授權與追蹤

- 看板：`portable-fido-vault`；顯示名稱 `Portable FIDO Vault`。不搬動 default 看板歷史卡片，也不切換其他 session 的 current board。
- 建立看板與規劃授權：Discord message `1556830412150542450`。
- 開發交給 Codex 授權：Discord message `1556830695090036769`。
- 來源 thread：`1556822039879225375`。
- 基準：main `591269560eae3b36aa2c85f4b44d7d704e588e09`。
- 來源 checkout：`D:/project/portable-fido2-vault`，只讀，不在 main 開發。
- Codex worktree：`D:/project/_worktrees/portable-fido2-vault-rdp-20261006`。
- branch：`feat/rdp-webauthn-validation-20261006`。
- 既有研究：`D:/project/_archives/portable-fido2-vault/20261006-rdp-feasibility/rdp-feasibility.md`；來源 ledger/snapshots 在同目錄。
- 所有新卡首次建立為 `blocked`。R1 由本 session 控制外部 Codex writer；保持 blocked 避免 gateway 同時派出第二名 writer。這不是實體驗收失敗，也不是任務已完成。
- R2–R5 等待前置證據與使用者互動時機；R6 為人工裁決關卡，允許在能力不足時提前判定 NO-GO，不要求把未執行項目偽標 PASS。

## 非目標與安全邊界

1. 不降低 API v4+；不以普通 assertion/signature 替代 PRF；不 silent fallback mock；不變更 RP `fido-vault.local`、origin `https://fido-vault.local` 或既有 raw salt／HKDF／vault 格式。
2. 不修改或讀取正式金庫內容；不寫入 `C:/FidoVault`；本次不自動部署、啟動 GUI、遠端登入、觸發 WebAuthn/UV/PIN 或操作實體金鑰。
3. 不強制終止可能持有 CTAP/UV 的程序。不修改主機政策、持久環境變數或 RDP 設定，不安裝更新/驅動。
4. 不記錄或輸出 PIN、主密碼、credential ID、salt、HMAC secret、KEK、原始 CTAP payload、使用者帳號/網域名稱或實際條目。只記錄 capability、布林結果、output 長度、PID/SessionId、錯誤分類及檔案/build provenance。
5. 初始資格矩陣限 Windows client→Windows host；macOS/web、第三方 USB-over-IP、自訂 DVC helper 皆不在本輪開發範圍。
6. 生產支援文件仍保持 RDP 不支援；開發、自動化 PASS、Console PASS 或 API v4+ 均不能提前宣告 RDP PASS。

## 相依與停止規則

正常成功路徑：R1 → R2 → R3 → R4 → R5 → R6。

Kanban hard dependencies：R1→R2、R2→R3、R3→R4、R4→R5；R6 只依賴 R1，並以 body 人工 gate 收集 R2–R5 結果，避免 API 能力不足時結案裁決被未測硬體卡鎖死。

- API <4：保留拒絕；其後的 secret/註冊流程標記 NOT_TESTED／blocked(capability)。允許收集明確同 process 證據後由 R6 判 NO-GO，不刪 parent 或偽完成卡片。
- API ≥4 但沒有有效 output：記錄 unsupported-output，不因一般 FIDO 登入成功宣布支援。
- 有 output 但既有槽解密失敗：停止，檢查 raw-salt transform／credential／UV 一致性；不重建舊槽。
- 同一操作失敗超過三次先收集資訊與根因，再決定是否重試，不反覆觸發 UV。
- status 與 test_result 分開：結果採 PASS / FAIL / NOT_TESTED / NOT_APPLICABLE（後者須有原因），不能把 waived、blocked 或工具不可用當 PASS。

## R1 — Codex：診斷 PoC、環境收集與自動化驗證

**Objective:** 交付可建置、可測試且不自動操作金鑰的診斷候選版，以及完整 R2–R5 手動 checklist。此階段不新增「RDP 支援已完成」產品行為。

**Files（允許範圍）:**
- Modify: `src-tauri/src/windows_webauthn.rs`（同 process capability/operation 結果診斷及純函式測試；不改 cryptographic/guard/focus 語義）。
- Optional create: `src-tauri/src/webauthn_diagnostics.rs`；若抽出小模組，只允許 `src-tauri/src/lib.rs` 增加必要 mod 宣告。
- Create: `scripts/collect-rdp-webauthn-environment.ps1`（唯讀 metadata collector；不得呼叫 MakeCredential/GetAssertion）。
- Create: `tests/rdp-webauthn-environment.test.cjs`（collector schema、unknown/error、無敏感欄位與非互動 provenance 的回歸）。
- Create: `docs/rdp-webauthn-verification.md`（精確的 R2–R5 checklist 與 PASS/FAIL/NOT_TESTED 欄位）。
- Create: `docs/reports/rdp-webauthn-development.md`（真實 RED/GREEN、完整命令與 exit code、候選 artifact/hash、尚未實機驗收的限制）。
- Do not touch: vault/crypto/credential persistence、frontend、vendor、Cargo.lock、部署腳本、已完成其他功能。

**Steps:**
1. 先閱讀原始碼、既有測試、診斷 logger 與 scope plan；以目前 header/API 為依據，不新增任意 capability bypass。
2. 用 strict RED→GREEN→REFACTOR，每個新行為先跑出預期失敗。以注入 metadata 的純函式測試 API 0/1/3/4+、SessionId unavailable、非互動/未知 session、固定輸出欄位與錯誤分類。不得在測試中修改全域 process env。
3. backend constructor 在 API gate 前寫出同 process 的 API version、API 是否達 v4、PID、SessionId（失敗為 unknown），若提供 session kind 則以 Win32/WTS 查詢為準。只把 SESSIONNAME 當標明不可信的 hint，不能靠它宣告 Console/RDP。不得把 API capability boolean 命名為 `rdp_supported`。
4. makeCredential/getAssertion 的診斷僅涵蓋 success/error category、正向 hmac-secret 確認、output presence/length 與 credential-match boolean；不新增原始資料的 Debug/hex logging。
5. collector 以同一次執行的結構化 JSON 回傳 OS build、client binary/version（可取得才記錄）、probe process PID/SessionId、API version 與已知重導 policy 值；missing 資料為 null/unknown。每項 API 標示 `measured_in=collector-process`；不得把 collector 版本當成 GUI process 證據。預設只讀，不啟動 GUI、不碰 vault、不要求 PIN、不變更 policy。
6. PowerShell 保存 UTF-8 BOM；用 PS 5.1 Parser::ParseFile 驗證，再實際執行 collector 及驗證 JSON/schema/禁止欄位。probe 執行只證明該 probe process 的 metadata，不證明 RDP 金鑰流程。
7. 在 fresh scratch CARGO_TARGET_DIR、GNU toolchain 與單 job 下跑 targeted tests、real-ctap lib suite、既有 UI suite、Clippy、format check、release GUI build。缺工具或測試未完成，保留真實 blocker，不偽造 PASS。
8. 不執行 Release GUI。候選 artifact 留在本機隔離建置目錄，記 SHA-256/source branch；若需 portable bundle，驗證 app-local WebView2Loader.dll 同架構/可信來源，不能只複製 EXE 就宣告可攜部署成功。
9. Codex 不 commit/push/merge、不改 Kanban、不 deploy；回報可審查 diff、tests/evidence 路徑與限制。Coder 獨立 review 後才決定提交 PR code diff。draft scope PR 必須先於 production-code edits 已建立並讀回。

**Verification commands（在 `src-tauri`；PATH 包含 `%USERPROFILE%/.cargo/bin` 與 Winlibs MinGW bin）:**
```bash
CARGO_TARGET_DIR=C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo +stable-x86_64-pc-windows-gnu test --lib --locked --features real-ctap -j 1
CARGO_TARGET_DIR=C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo +stable-x86_64-pc-windows-gnu clippy --lib --locked --features real-ctap -j 1 -- -D warnings
cargo +stable-x86_64-pc-windows-gnu fmt --check
CARGO_TARGET_DIR=C:/Users/skycity1010/AppData/Local/hermes/cache/scratch/pfv-rdp-20261006-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo +stable-x86_64-pc-windows-gnu build --release --locked --features real-ctap --bin portable-fido-vault
```
從 worktree root 執行 `node --test tests/*.test.cjs`、`node --check src/app.js`、`git diff --check`。保留全部 log 與 actual exit code，不只靠 agent 最終文字宣稱成功。

**Done criteria:** scoped diff、TDD/測試/實際 collector 輸出與候選建置可讀回、獨立安全審查通過、PR source/branch 與 artifact provenance 明確；hardware/RDP acceptance 仍 NOT_TESTED。

## R2 — 雙端環境確認與 Console 基準

**Objective:** 建立唯一可重現的 endpoint/client/key/binary 矩陣與安全測試 fixture。

**Owner:** Coder 彙整；Skycity1010 提供連線發起端/目標互動 session 與金鑰操作。

1. 確認連線發起端、Windows target（預計 Win11-NB，待確認）、client 名稱/版本、OS build、key 型號/韌體，以及目前 GUI artifact/hash。
2. 只讀確認 redirection request/policy/使用者 WebAuthn resource consent；缺失時先記錄，由使用者另行核准設定變更，不擅自修改。
3. 確认沒有其他 FIDO process/pending request。任何程序狀態未知則停止，不 force-kill。
4. 選一個唯一、不存在的專用測試資料夾，例如 `C:/FidoVault-RdpTest/<run-id>`；`vault.db` 在該處新建。不得使用正式 `C:/FidoVault/vault.db` 或覆寫已有路徑。測試密碼只在本機安全輸入。
5. 使用 Console 註冊支援 hmac-secret 的專用 key、讀回 slot count，並完成 Console 解鎖。保存 fixture baseline（vault ID 的非敏感本機識別、slot count、pre-test 檔案 hash/backup）但不傳回金庫/secret。
6. 同一候選 GUI process 的 capability log 是門檻證據；collector 只當補充。實體操作不由 WinRM/session 0 執行。

**Done criteria:** exact matrix + Console PASS + fixture/backups + 發起端/目標機角色已確認；未知值不能填猜測內容。

## R3 — Console 舊測試槽 → RDP 解鎖

**Objective:** 證明同一個 Console-created credential/slot 的 raw secret 語義可跨 RDP 使用。

1. 關閉 Console FIDO client，正常拔插 key 到 RDP 連線發起端，確認不是使用目標機插著的另一支 key。
2. 使用已記錄的 client/consent 連入目標互動桌面；在專用測試路徑執行同一候選 GUI。
3. 同 process API ≥4、正確 credential-match、HMAC output presence/length=32 是必要条件；實際成功解鎖同一測試 vault 才是相容性 PASS。
4. 不要求把 secret bytes 傳到聊天或日志；若工具需比較，只在記憶體比較/清零並回報布林。
5. API <4／無 output／AEAD 解密失敗則記錄分別的錯誤分類，停止，不改 guard、不重註冊來掩蓋旧槽失敗。

**Done criteria:** exact candidate/matrix 的既有測試槽 RDP 解鎖 PASS。API pass 或一般網站 key-login 不等於本 gate PASS。

## R4 — RDP 註冊 → RDP/Console 雙向相容

**Objective:** 新增測試 slot 後，兩種 session 都能用相同 physical key 解鎖。

1. 記錄該 exact test DB 的 slot baseline。
2. 在 RDP 金鑰管理註冊專用測試 credential，確認正向 hmac-secret creation output，getAssertion secret 成功，slot count 恰增加一。
3. 上鎖再以新 credential 在 RDP 解鎖。
4. 正常離開 RDP；把同一 key 移到目標 Console，再以同一 test vault/new slot 解鎖。
5. 若註冊後 secret 取得失敗，vault 不寫入槽；可能留下 key-side orphan credential，須準確註記，不自動刪 key credential。

**Done criteria:** registration、slot +1、new-slot RDP unlock、new-slot Console unlock 四項逐項 PASS。不得以 slot 數不變的登入當成註冊 PASS。

## R5 — Fail-closed 與 Console 回歸

**Objective:** 失敗不降級、不產生不可用槽，不破壞既有正常 Console 路徑。

分別驗證：
- 錯誤/未註冊 key：拒絕解鎖、key slots unchanged。
- 使用者取消 PIN/UV/dialog：拒絕、slots unchanged。
- 連線中斷/逾時：已鎖定 vault 保持鎖定，沒有殘留成功 token 或 invalid slot；不得宣稱產品原本有「斷線立即自動上鎖」功能。
- 重導關閉、policy deny／consent拒絕：測試只有發起端插 key 的情境，應失敗，不 mock fallback；關閉重導不是保證目標端本機 key 也不可用。
- 不支援 PRF 或 API<4：硬體在手才作 physical case；缺 fixture 以 automated regression + NOT_TESTED 記錄，不能偽 physical PASS。是否接受此 coverage 由 R6 裁決。
- 既有 Console 正常登入／註冊與視窗前景行為回歸。
- 後測讀回 test slot count/fixture 可解鎖，正式 vault 若核准只讀 baseline 則前後不得改變。

**Done criteria:** required cases 逐項有 actual result；optional/hardware-unavailable coverage 保留來源與風險。此 gate 與先前 entry-delete 的 D6 waiver 無關，不重新要求已免測的 D6。

## R6 — GO/NO-GO 與支援文件裁決

**Objective:** 依 exact matrix 的實測證據決定是否增加原生 RDP 支援，不以 research/CI 代替 physical acceptance。

- GO：R2–R5 的 required gates 都 PASS；宣告支援只限已測 OS/client/key/build 矩陣。由使用者核准後才同步 `README.md`、`docs/spec.md`、`docs/PROJECT.md`、`docs/user-verification-steps.md`，分清 Console/RDP 與提示出現端。
- NO-GO：有可重現能力/語義/安全失敗，記錄 exact failure；未執行卡保留 NOT_TESTED/blocked，不回填 PASS。不自動改走 USB-over-IP 或 DVC helper；另經使用者授權評估。
- Pending：缺實體操作、client version/consent 未確認或 required coverage 未完成；維持 RDP 不支援，不結成已驗收。

**Done criteria:** 使用者裁決、矩陣/證據/殘餘風險與文件一致，無虛構 PASS；merge/deploy 需要另行授權。

## 統一證據格式

每個案例保存：case ID、來源 task ID、時間與時區、role（Console/RDP client/host）、candidate source SHA/hash、OS/client/key 非敏感 metadata、same-process API/PID/SessionId、expected、actual、PASS/FAIL/NOT_TESTED、error category、post-test slot count 與下一步。省略密碼/credential/salt/secret/KEK/原始 payload/真實條目；分享前以欄位 allowlist 審核。

## 本次交付狀態

計畫及六張卡建立後，立即把 R1 的 scoped development prompt 交給 Codex。其餘實機 gate 維持等待，不在此規劃回合執行金鑰操作或部署。研究報告只提供背景，不替代實測。
