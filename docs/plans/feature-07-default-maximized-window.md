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

- Tauri `src-tauri/tauri.conf.json` 將 `app.windows[label=main].maximized` 設為 `true`，且 `fullscreen` 不設為 `true`。
- Node 測試會解析 Tauri JSON 並驗證主視窗的最大化預設與非全螢幕設定。
- 全套 Node UI 測試、`node --check src/app.js`、`git diff --check` 通過；執行 real-ctap Windows Release build 驗證 Tauri config 可建置。
- 金鑰登入前景處理只在視窗已最小化時呼叫 restore；最大化／一般視窗只要求前景，不改變視窗狀態。
- 部署後由使用者在 Win11-NB 本機 Console 確認：每次啟動皆最大化、按「以金鑰登入」時維持最大化、標題列仍可見、可還原／調整大小及再次啟動後仍預設最大化。
- 在使用者回報實機結果前，不得把 Win11-NB 手動驗收標記為 PASS。

## 工作流程

- 本功能獨立 Kanban 任務及 stacked draft PR；基於尚未合併的 `feat/entry-search` / PR #14 建立分支與 PR。
- PR #14 的 Win11-NB 條目搜尋手動驗收仍為 pending、未判 PASS；依使用者最新指示先處理本功能，不得因此把前一驗收視為完成。
- 先提交此 scope/acceptance，再新增測試與設定變更。