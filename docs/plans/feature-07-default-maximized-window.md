# Feature 7 — 預設最大化主視窗

## Goal

啟動 Portable Fido Vault 時，主視窗預設以最大化狀態開啟，讓可用畫面空間更大。

## 已確認範圍

- 僅修改 Tauri `main` 主視窗的啟動狀態；使用 `WindowConfig.maximized`。
- 最大化不是全螢幕：保留一般視窗標題列、視窗控制項及工作列。
- 保留現有可調整大小、最小寬高設定；使用者啟動後仍可還原、移動及調整視窗。
- 每次啟動均預設最大化；不加入記憶上次視窗大小／狀態的外掛或持久化設定。
- 不改動條目搜尋、vault、FIDO2、加密流程或其他視窗。

## 驗收條件

- [x] Tauri `src-tauri/tauri.conf.json` 將 `app.windows[label=main].maximized` 設為 `true`，且 `fullscreen` 不設為 `true`。
- [x] Node 測試會解析 Tauri JSON 並驗證主視窗的最大化預設與非全螢幕設定。
- [x] 全套 Node UI 測試、`node --check src/app.js`、`git diff --check` 通過；real-ctap Windows Release build 成功。
- [x] 金鑰登入前景處理只在視窗已最小化時呼叫 restore；最大化／一般視窗只要求前景，不改變視窗狀態。
- [x] 使用者於 2026-10-03 確認 Win11-NB 本機 Console 驗收通過：每次啟動皆最大化、金鑰登入時維持最大化、標題列可見、可還原／調整大小及再次啟動後仍預設最大化。

## 工作流程

- 本功能獨立 Kanban 任務及 stacked draft PR；基於尚未合併的 `feat/entry-search` / PR #14 建立分支與 PR。
- PR #14 的 Win11-NB 條目搜尋驗收於 2026-10-03 由使用者確認通過；本功能與 PR #14 按依賴順序合併。
- 先提交此 scope/acceptance，再新增測試與設定變更。