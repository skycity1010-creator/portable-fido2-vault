# 全庫 Rust 格式維護 — 已授權範圍

## 授權

使用者 message `1556265625158946837` 授權：「把全庫rust格式整理交由codex處理，d6不用測試，可以不用再提醒。」

- 全庫範圍包含 `src-tauri` 與現有 vendored `authenticator-rs` Rust 程式。
- 由實際 Codex CLI 作為唯一程式碼 writer；父流程负责獨立驗證、review 與 PR 發布。
- 條目刪除 D6 人工失敗情境已免測，不再列為待辦或主動提醒；歷史 NOT_TESTED 不改為 PASS。
- 不合併、不部署、不操作 Win11-NB、既有金庫或實體驗證器。

## 目標

將既有全庫 `cargo fmt --all -- --check` 的格式負債清除，使 stable rustfmt 可乾淨通過；只做格式與必要格式設定，不改行為、依賴、金庫 schema、加密、FIDO/WebAuthn 或 UI。

## 基準

- main: `9bd08502d74ccc36077728b5c88959dc6b62ff24`。
- 最近全庫只讀格式檢查 exit 1：14 檔、94 Diff blocks，自有 7 檔／83 blocks，vendor 7 檔／11 blocks。
- vendor `rustfmt.toml` 含 stable 不生效的 `comment_width = 200`、`wrap_comments = true`，並有有效的 `edition = "2018"`。
- 最新 main CI success；Node 基線 53 PASS / 0 FAIL。

## 格式策略

- 使用已安裝、具 rustfmt 的 stable toolchain；不能把 GNU toolchain 缺 cargo-fmt 當格式失敗。
- 保留各 crate 現有 Rust edition、compiler/build 選型和有效 stable 設定。
- 可以移除 vendor 中兩個已被 stable 忽略的 nightly-only 設定；不新增 nightly 依賴、不避開 vendor、不設排除來假裝全庫通過。
- 不修改 Cargo.toml、Cargo.lock、generated schemas、前端 production code、CI workflow 或與本次無關文件。
- 可在目前驗收文件及 PROJECT roll-up 加入 D6 免測／不再待辦的使用者裁決；保留歷史證據，不假造 PASS。

## 驗證

- 全庫 stable `cargo fmt --all -- --check` exit 0，無格式差異及上述 nightly-only 設定警告；vendor 明確納入。
- `git diff --check`、`node --check src/app.js`、全套 Node UI tests 通過。
- `cargo test --lib --locked --features real-ctap -j 1` 通過；無硬體／GUI 操作。
- vendored device_filter unit regressions 通過：`cargo test --manifest-path ../vendor/authenticator-rs/Cargo.toml --no-default-features --features crypto_rust --locked --lib device_filter -j 1`。
- `cargo clippy --lib --locked --features real-ctap -j 1 -- -D warnings` 通過。
- 保存完整未截斷 stdout/stderr、真正 exit code、revision、檔案列表與工具版本。
- 父流程独立 review 確認只有格式／已授權文件和 stable-format 設定；驗證後提交推送並讀回 PR head 與 exact-head CI。

## 工作流程

獨立 worktree、獨立 branch 與 draft PR；Kanban 從建立起保持 blocked，避免 gateway dispatcher 與 Codex 同時寫入。所有程式碼修改與測試在指定 worktree 執行，原 main checkout 必須維持不變。PR 待使用者核准合併；此 scope commit 在任何 production-code 編輯前發布。
