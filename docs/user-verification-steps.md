# 可攜式 FIDO2 密碼金庫 v0.1 — NB 桌面驗證步驟（使用者用）

> 適用：Win11-NB，`C:\FidoVault`（portable 資料夾）。完成約 15–20 分鐘。
> 硬體版 Release GUI 必須以 `--features real-ctap` 建置，從檔案總管啟動時會直接使用實體 FIDO2 金鑰；不需預設環境變數。Debug build 預設為 MockBackend；若要明確跑 mock 流程，設定 `F2V_AUTHENTICATOR=mock`。

## 驗證前狀態（Coder 已確認 ✅）
`C:\FidoVault` 內應**恰好只有這三個檔案**（SHA256 與建置機逐一比對一致，測試殘留已清除）：

| 檔案 | 說明 |
|---|---|
| `portable-fido-vault.exe` | 主程式（GUI） |
| `WebView2Loader.dll` | WebView2 載入器（GUI 必備） |
| `vault_cli.exe` | 命令列工具（選用，可測 E2E；不用也沒關係） |

## A. Gate 1 — 雙擊免安裝執行
- [ ] **A1** 雙擊 `C:\FidoVault\portable-fido-vault.exe`
  - 若出現 Windows SmartScreen「未識別應用程式」→ 點「其他資訊」→「仍要執行」（exe 未簽章，預期行為）
  - **預期**：數秒內跳出視窗「🔐 可攜式 FIDO2 密碼金庫 — 請輸入主密碼登入」
- [ ] **A2** 首次執行會顯示「首次執行 — 建立帳號」面板 → 設定主密碼（≥8 字元，例：`Test-Pw-1234`）→ 按「建立金庫」
  - **預期**：跳回登入畫面
- [ ] **A3** 確認 `C:\FidoVault` 下多了一個 `vault.db`（金庫檔；之後所有資料都在這裡）

## B. Gate 2 — 密碼登入 + 錯誤計軌跡
- [ ] **B1** 輸入**錯**主密碼 → 按「以主密碼登入」→ **預期**：顯示錯誤、留在登入畫面
- [ ] **B2** 到 `C:\FidoVault` 確認出現 `vault.db.failures`（失敗軌跡 sidecar；只有時間+方式，無機密）
- [ ] **B3** 輸入**正確**主密碼 → 登入成功 → **預期**：進主畫面（頂欄「已解鎖」+ 四個分頁）
- [ ] **B4**（選用）進「軌跡紀錄」分頁：應看到 `login_failed`、`login_success`、`vault_created`；且**任何一列都不含密碼明文**

## C. Gate 5 — 條目 CRUD + 時間戳
- [ ] **C1** 「條目」分頁：網站=`example.com`、帳號=`alice` →「＋ 新增」→ 彈出框輸入密碼 `S3cret!`
  - **預期**：表格出現該列，含建立/更新時間
- [ ] **C2** 點該列「編輯」→ 改備註或密碼 →「儲存」→ **預期**：「更新時間」變新、「建立時間」不變
- [ ] **C3** 點「顯示」→ 彈出框應回顯 `S3cret!`（可讀回）
- [ ] **C4**（選用）新增第二條再「刪除」（會問確認）→ 表格少一列

## D. Gate 7 — 閒置自動上鎖 ⭐（本卡重點）
- [ ] **D1** 「設定」分頁：輸入 `1` →「套用」→ **預期**：彈出「已套用：閒置 1 分鐘自動上鎖」
- [ ] **D2** 切到**其他視窗或桌面**，**完全不要碰滑鼠與鍵盤超過 60 秒**
  - ⚠️ 注意：**只要滑鼠在 app 視窗內移動、或在它上面按鍵/打字，計時器就會重算**。最保險：切走後去泡杯咖啡，別回頭動滑鼠。
- [ ] **D3** 60 秒後回到該視窗 → **預期**：已自動跳回登入畫面（「已解鎖」變鎖定狀態）
- [ ] **D4** 重新登入 →「軌跡紀錄」→ **預期**：最新一列是 `auto_lock`（方式欄 idle）
- [ ] **D5**（對照組，選測）再上鎖一次前點右上「上鎖」手動按鈕 → 回登入畫面 → 軌跡多一列 `lock`

## E. Gate 3/4 — FIDO2 金鑰流程（mock）

> 此節只測 MockBackend。若由 PowerShell 啟動 mock GUI，僅在該視窗設定 `$env:F2V_AUTHENTICATOR='mock'`；關閉 app 後用 `Remove-Item Env:F2V_AUTHENTICATOR -ErrorAction SilentlyContinue` 清除，勿用 `setx` 持久設定。

- [ ] **E1** 「金鑰管理」分頁 →「＋ 註冊新金鑰」→ **預期**：狀態列顯示已註冊某型別（fingerprint / pin / touch-only 輪流；PIN 型會先問 PIN，任意輸入即可，mock 不驗證真 PIN）
- [ ] **E2** 再註冊第二支（型別會不同）→「上鎖」→ 登入畫面應列出已註冊金鑰
- [ ] **E3** 選任一金鑰 →「以金鑰登入」→ **預期**：成功進主畫面（多支金鑰任一支皆可解鎖）

## F. Gate 8 — 可攜性直拷
- [ ] **F1** 完全關閉 app
- [ ] **F2** 把整個 `C:\FidoVault` 資料夾複製到別處（例：`D:\FidoVault-copy` 或 USB）
- [ ] **F3** 到新位置雙擊 exe → 用主密碼登入 → **預期**：條目、金鑰、軌跡全都在（vault.db 隨資料夾走，免安裝免設定）

## 回報格式（做完貼回即可）
```
A: A1 _ / A2 _ / A3 _
B: B1 _ / B2 _ / B3 _ / B4 _
C: C1 _ / C2 _ / C3 _ / C4 _
D: D1 _ / D2 _ / D3 _ / D4 _ / D5 _   ← 重點
E: E1 _ / E2 _ / E3 _
F: F1 _ / F2 _ / F3 _
（_ 填 ✓ 或 ✗+一句話現象）
```

## G. Gate 3/4 — 實體 YubiKey Bio 註冊與登入（Release GUI）

> 本節不需設定 `F2V_AUTHENTICATOR`；請確認 Windows 使用者／系統環境變數沒有殘留 `mock`。若曾持久設定，清除後登出再登入或重啟 Explorer。

- [ ] **G1** 在 Win11-NB 本機互動桌面確認沒有 `vault_cli`、`portable-fido-vault` 或 `yk_open_test` 程序；若有，正常關閉，不要 force-kill。
- [ ] **G2** 關閉 GUI 後備份 `C:\FidoVault\vault.db`，並記下註冊前金鑰槽位數。
- [ ] **G3** 直接雙擊 `C:\FidoVault\portable-fido-vault.exe`，以主密碼登入 →「金鑰管理」→「＋ 註冊新金鑰」。
- [ ] **G4** 在 YubiKey Bio 金鑰本體銀色外框感應區及時按指紋；不要改用 Windows Hello。若提示 PIN，只在本機輸入。
- [ ] **G5** 確認 UI 顯示「已註冊」、金鑰出現在清單，且槽位數比註冊前增加 1。
- [ ] **G6** 上鎖後用新金鑰登入，確認 Gate 3 完整通過；如要驗證 Gate 4，再註冊第二支支援 PRF 的實體金鑰並交叉登入。

若視窗未啟動或金鑰未要求互動，保留目前 vault 備份並回報 UI 狀態；不要移除任何無法辨識的槽位。

## 常見狀況
| 現象 | 說明 |
|---|---|
| SmartScreen 警告 | 未簽章 exe，「仍要執行」即可（後續可加簽章） |
| D3 沒自動上鎖 | 多半是滑鼠/鍵盤在 app 視窗內動過 → 計時器被重算；再試一次、切走後別碰輸入設備 |
| 雙擊完全無反應 | 回傳訊息給 Coder（查 WebView2 / 事件紀錄） |
