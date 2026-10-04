# 主畫面條目刪除確認 — 實作範圍

## 授權與範圍

使用者於 2026-10-04 要求先規劃、再交由 Codex 執行。此功能只修改主畫面條目刪除的 frontend；不變更 Rust IPC、金庫格式、FIDO/WebAuthn、金鑰移除或其他功能，不部署、不合併、不操作既有金庫。

目前 `src/app.js` 的條目刪除使用 `window.confirm()`。改用既有風格的程式內 HTML modal dialog，避免依賴 WebView 的 JavaScript 原生提示。

## 驗收條件

- 刪除按鈕只開「確認刪除條目」視窗，有不可復原警告及網站／帳號辨識；不顯示密碼、舊密碼或備註，文字使用 textContent。
- 「取消」為初始焦點；只有明確按「確認刪除」才呼叫 delete_entry。取消、Esc、其他非確認關閉與 showModal 失敗均不得刪除。
- 確認目標保持原始 ID；快速連點／非同步請求期間不得替换目標、重複開窗或重複刪除。
- 成功重載清單並保持搜尋查詢；若刪除正在編輯的條目，清理失效編輯／密碼狀態。
- 刪除失敗顯示通用不含機密提示，保留條目，可取消／重試。刪除成功後的重載失敗要與刪除失敗區分，不可讓同一確認重複送出。
- 手動／閒置上鎖同步失效未送出的確認；晚到的 close／IPC callback 不得影響後來的確認。
- Node 行為測試涵蓋開窗零刪除、明確確認、取消／Esc、原始 ID、搜尋、連點／pending IPC、錯誤、上鎖及 delayed-close。
- Win11-NB 本機 Console 驗收維持 PENDING，直到使用者明確回報；自動化 PASS 不代表實機 PASS。

## 實作與品質閘門

Codex 按逐個行為 RED→GREEN→REFACTOR 執行。主要檔案：src/app.js、src/index.html、src/styles.css、tests/entry-delete-ui.test.cjs；調整 tests/entry-search-ui.test.cjs 的刪除路徑為明確確認；docs/user-verification-steps.md 加入待驗清單。

執行：

```bash
node --test tests/entry-delete-ui.test.cjs
node --test tests/*.test.cjs
node --check src/app.js
git diff --check
```

基線 38 PASS / 0 FAIL。Frontend-only 不跑 Rust build；独立规格／安全与逻辑审查通过后才提交与推送。
