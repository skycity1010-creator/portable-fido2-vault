# 2026-10-04 維護盤點：格式檢查、驗收文件、工作目錄

## 範圍與證據基準

- 檢查基準：main `18134cbe5ae603dd502f5be59b6cbb8520933dd3`（PR #12 merge commit）。
- 三項工作分隔執行：格式檢查使用 detached worktree；驗收文件在獨立 docs 分支編輯；原工作目錄先備份，再安全同步 main。
- 未修改 Rust／前端程式碼，未重新建置或部署，未操作實體金鑰／WebAuthn，未刪除或重建既有金庫。
- 下列數字來自本輪命令與保存結果，不把歷史驗證、mock 測試或使用者未回報項目當作新 PASS。

## 1. 全庫 Rust 格式檢查：FAIL，程式碼未修改

在基準 revision 的 `src-tauri` 執行：

```text
cargo fmt --all -- --check
exit code: 1
14 files / 94 Diff blocks
src-tauri: 7 files / 83 blocks
vendor: 7 files / 11 blocks
```

差異檔案及 block 數：

- `src-tauri/examples/vault_cli.rs`：19
- `src-tauri/src/bin/yk_open_test.rs`：9
- `src-tauri/src/crypto.rs`：2
- `src-tauri/src/diag_log.rs`：3
- `src-tauri/src/fido2.rs`：25
- `src-tauri/src/lib.rs`：5
- `src-tauri/src/vault.rs`：20
- `vendor/authenticator-rs/src/authenticatorservice.rs`：1
- `vendor/authenticator-rs/src/device_filter.rs`：1
- `vendor/authenticator-rs/src/manager.rs`：2
- `vendor/authenticator-rs/src/transport/hidproto.rs`：2
- `vendor/authenticator-rs/src/transport/linux/monitor.rs`：1
- `vendor/authenticator-rs/src/transport/mod.rs`：1
- `vendor/authenticator-rs/src/util.rs`：3

stable rustfmt 另回報 nightly-only 設定警告：`comment_width = 200`、`wrap_comments = true`，各 9 次，共 18 次；警告不代表格式差異已修正。

本輪沒有執行不帶 `--check` 的 `cargo fmt`。檢查 worktree 前後快照一致，HEAD 未改、工作目錄 clean、`git diff --check` 通過。父流程另以完整輸出的 SHA-256 及 Python 重算檔案／block 數，確認結果檔與命令輸出一致。

格式修正仍待獨立處理：應先決定 vendor 範圍及 stable／nightly 格式設定策略，再用獨立格式 PR 修正與重驗；不得因 CI 或歷史 scoped rustfmt 通過便宣稱全庫格式通過。

## 2. 驗收文件同步：已更新，不重開已確認功能

- `docs/PROJECT.md`：Gate 9–11 對齊 2026-10-02 使用者 PASS；彙整 Feature 1–7，補搜尋、最大化及金鑰登入維持最大化的驗收／部署歷史，區分本輪檢查與 PR #11／#12 的既有工程驗證。
- `docs/user-verification-steps.md`：搜尋與最大化標題對齊 2026-10-03 PASS；歷史 H2 候選及舊模板標示 superseded／未回報，不將未勾選項批量改為通過。
- 原驗收清單仍為 50 個已勾選、18 個未勾選；歷史部署雜湊及備份路徑保留。
- Gate 8 的 PASS 限於既有 mock copy-test；實體 GUI 跨 Windows 機器使用同一金庫與金鑰的人工 PASS 尚未找到。`scripts/nb_gate.py` 是在 NB 新建測試金庫的流程，本身不是搬移既有金庫的證據。
- D5 手動上鎖對照選測仍未回報；RDP 明確不支援，舊 raw-CTAP CLI 實體路線已 retired，不列為目前必須重測的功能。

## 3. 原工作目錄與主線：已同步、clean，資料保留

- `D:\project\portable-fido2-vault` 留在 main；本機 main／origin/main 已同步至檢查基準 revision。
- 整理前備份 17 個檔案：2 個 schema、15 個本機計畫／建置 log；ZIP 逐檔 SHA-256 驗證通過，另保存原 branch、HEAD 與 status。
- schema 原工作樹經 Git 正規化的 blob 與 index 相同；僅刷新正規化狀態，沒有提交 schema 內容修改。
- 本機計畫／log 保留原位且雜湊不變；僅在 `.git/info/exclude` 加入 `/.hermes/`、`/src-tauri/yk_build*.log`，未修改共用 `.gitignore`。
- 以 `git merge --ff-only origin/main` 同步，未使用 `git clean`、`reset --hard`、force push 或刪除分支。
- 本輪基準 revision 的 Node suite：38/38 PASS，fail／skip／todo 均為 0；`node --check src/app.js`、`git diff --check` 通過。未重跑 Rust 測試／Clippy。
- PR #11／#12 已合併，是讀回其他授權流程的結果；基準 SHA 的 Actions run `37177652514` 為 completed／success，非本輪新觸發 CI。

## 保存位置

持久化本機證據目錄：

```text
D:\project\_archives\portable-fido2-vault\20261004-132136\
  pre-cleanup-worktree.zip
  manifest.json
  initial-snapshot.json
  workspace-cleanup-result.json
  verification-evidence\
    format-check-output.txt
    format-check-result.json
    main-node-tests.tap.txt
    main-node-summary.json
    main-sanity-checks.json
```

格式檢查完整輸出、JSON、Node 輸出已複製至上述非 scratch 目錄並核對雜湊，避免 scratch 自動清理後只剩摘要。驗收來源及部署歷史詳見 `docs/PROJECT.md`、`docs/user-verification-steps.md`；此報告不附金庫、密碼、PIN 或 authenticator payload。
