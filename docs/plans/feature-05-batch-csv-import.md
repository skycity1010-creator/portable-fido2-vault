# Feature 5 — CSV 批次匯入／更新與範本下載實作計畫

> 功能規格已由使用者確認；先以本文件建立 scope/acceptance commit 與 draft PR，再修改 production code。

**Goal:** 在已解鎖的 FidoVault 中提供 CSV 範本下載、預覽及批次新增／更新條目，單檔上限 1,000 列。

**Architecture:** UI 使用原生檔案選擇器取得 CSV，Rust 後端解析並驗證；預覽不顯示密碼，使用者確認後由 vault 層一次套用有效資料並原子加密寫入。沿用現有條目模型、更新密碼歷史和加密格式。

**Tech Stack:** Tauri v2 dialog plugin、Rust `csv` reader、現有 Serde/VaultState、原生靜態 HTML/JavaScript。

---

## 已確認行為規格

- 條目介面提供「下載 CSV 範本」與「匯入 CSV」；僅在金庫解鎖後可使用。
- 範本檔為 UTF-8 CSV，只含表頭 `site,account,password,notes`，不放示範帳密。
- 匯入支援 UTF-8 CSV，可接受 BOM；欄位順序不拘，但四個表頭必須存在。支援標準 CSV quoting；不接受缺少欄位、重複表頭或欄數不一致的資料列。
- `site` 必填；單檔最多 1,000 筆資料列（不含表頭）。超過上限時整檔拒絕，不修改金庫。
- 以去除 `site`、`account` 首尾空白後、不區分大小寫的配對鍵比對既有條目。恰好命中一筆則更新；沒有命中則新增。
- 更新時空白欄位保留原值，非空欄位更新為匯入值；`site` 與 `account` 用修剪後的值保存。新增時空白 `account`、`password`、`notes` 保存為空字串。
- CSV 重複配對鍵的所有相關資料列皆略過；若一個配對鍵對應多筆既有條目，該資料列略過，不任意選擇。
- 預覽回報新增／更新／略過數量與資料列行號及非機密錯誤原因；不得顯示密碼值。使用者確認後只套用有效列；所有有效列同批提交。寫檔失敗時不留下部分變更。
- 更新密碼時沿用現有密碼歷史規則與上限。匯入 audit 只記錄新增／更新／略過計數，不記錄欄位內容；診斷 log、錯誤訊息及暫存檔不得包含 CSV 密碼或整列內容。
- UI 清楚提醒匯入 CSV 含明文密碼。功能不包含刪除、匯出、雲端傳送或網路呼叫。

## 預計修改檔案

- `src/index.html`、`src/app.js`、`src/styles.css`：範本下載、檔案選擇、預覽／確認／取消與安全提示。
- `src-tauri/Cargo.toml`、`src-tauri/Cargo.lock`、`src-tauri/src/lib.rs`：dialog 與 CSV command／依賴。
- `src-tauri/src/vault.rs`：資料列配對、有效列批次套用、密碼歷史、單次原子落盤及非機密 audit。
- `tests/batch-import-ui.test.cjs` 與 Rust 單元測試：解析、預覽、配對、空白更新、重複／錯誤列、上限、密碼歷史、原子性及範本。
- `docs/spec.md`：補上新功能規格及 CSV import audit 事件（若實作採新事件名稱）。

## 實作與驗收順序

1. 先新增 UI／Rust 測試，確認測試因缺少匯入功能而失敗。
2. 以 Tauri dialog 開啟 CSV，Rust 後端驗證 UTF-8、表頭及每列欄數，並對檔案列數與錯誤列做 fail-closed 檢查。
3. 加入不含密碼的預覽及逐列狀態；對確認的有效列執行一次批次交易與一次加密落盤。
4. 增加 header-only 範本下載及明文密碼警告；確保範本和匯入皆不使用網路或暫存檔。
5. 執行 targeted/full Node UI tests、Rust real-CTAP library tests、backend-mode tests、鎖定依賴的 Windows Release GUI/CLI build、`git diff --check`。
6. 開發 draft PR；Win11-NB local Console acceptance 由使用者操作與回報。使用者回報前不得標為 PASS 或結案。

## 安全／相容性注意事項

- 不改變既有 vault payload 格式；新增條目仍使用既有 ID 與時間戳產生方式。
- 任何解析失敗、超過 1,000 列或無法安全儲存都不能部分修改金庫。
- CSV 密碼不進入 UI 預覽、Tauri 回傳錯誤、audit 或 log；範本不含 placeholder credentials。
- 對已有相同 `(site, account)` 的非唯一資料不可猜測；該列略過並要求使用者修正資料。

## 參考

- Tauri v2 Dialog plugin: https://v2.tauri.app/plugin/dialog/
- Rust `csv` ReaderBuilder: https://docs.rs/csv/latest/csv/struct.ReaderBuilder.html
- RFC 4180 (CSV quoting): https://datatracker.ietf.org/doc/html/rfc4180
