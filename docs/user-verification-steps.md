# 可攜式 FIDO2 密碼金庫 v0.1 — NB 桌面驗證步驟（使用者用）

> 適用：Win11-NB，`C:\FidoVault`（portable 資料夾）。完成約 15–20 分鐘。
> Windows Release GUI 必須以 `--features real-ctap` 建置；一般權限的檔案總管直接啟動時使用 Windows WebAuthn API，無需環境變數或系統管理員提升。Windows 安全性視窗負責 PIN/UV/觸碰；目標系統需 WebAuthn API v4+。Debug build 預設為 MockBackend；明確跑 mock 流程時設定 `F2V_AUTHENTICATOR=mock`。

## 部署後驗證前確認（2026-10-01）
已部署的 Release GUI 為 Windows WebAuthn 版本，SHA256：`06B1C5BE7A5E760D28D594B128A1B5BC681C31A6FD26D672E942E5F1062F0EA2`。部署時只替換主程式，`vault.db` 未變更；當時有 1 個金鑰槽。`F2V_AUTHENTICATOR` 的使用者與系統環境變數均未設定。

執行所需檔案如下；`C:\FidoVault` 也有診斷紀錄與備份檔，**不要因舊版「只有三個檔案」說明而刪除任何其他檔案**：

| 檔案 | 說明 |
|---|---|
| `portable-fido-vault.exe` | 主程式（GUI）；Windows GUI 透過 Windows WebAuthn API v4+ 使用安全金鑰 |
| `WebView2Loader.dll` | WebView2 載入器（GUI 必備，部署時保留） |
| `vault.db` | 既有金庫資料；驗證前另做使用者備份，切勿刪除或重建 |
| `vault_cli.exe` | 選用 CLI；保留 raw CTAP 診斷路徑，本次部署未替換 |

> 這台 NB 已有既存 `vault.db`。A–F 是全新測試金庫的舊 Gate 流程；本次請照 **G 節** 驗證，勿建立、清空或重建現有金庫。

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

> 本節不需設定 `F2V_AUTHENTICATOR`；請以一般權限從檔案總管啟動。Windows 安全性視窗負責安全金鑰選擇、PIN/UV 與觸碰。

- [ ] **G1** 在 Win11-NB 本機互動桌面確認沒有 `vault_cli`、`portable-fido-vault` 或 `yk_open_test` 程序；若有，正常關閉，不要 force-kill。
- [ ] **G2** 關閉 GUI 後備份 `C:\FidoVault\vault.db`，並記下註冊前金鑰槽位數。
- [ ] **G3** 用一般權限（非系統管理員）的檔案總管直接啟動 `C:\FidoVault\portable-fido-vault.exe`；不設 `F2V_AUTHENTICATOR`。啟動診斷應顯示 `GUI FIDO backend selected: windows-webauthn`。
- [ ] **G4（舊槽相容性）** 先在登入畫面選取原有金鑰槽，用建立該槽的實體金鑰嘗試登入。成功可確認舊 raw-CTAP 槽能由 Windows WebAuthn backend 解鎖；此時槽位數仍應為 1。若失敗，不要移除或覆寫舊槽；記下錯誤，再用主密碼登入後繼續測試。
- [ ] **G5（註冊）** 登入後進入「金鑰管理」→「＋ 註冊新金鑰」。依 Windows 安全性視窗選用外接安全金鑰，插入 YubiKey Bio，按提示觸碰／按指紋；如要求 PIN，只在本機系統視窗輸入，不要改用 Windows Hello。
- [ ] **G6（新槽登入）** 確認 UI 顯示「已註冊」、金鑰出現在清單，槽位數由 1 增至 2；上鎖後用新金鑰登入。若要驗證 Gate 4，再註冊第二支支援 PRF 的實體金鑰並交叉登入。

若視窗未啟動或金鑰未要求互動，保留目前 vault 備份並回報 UI 狀態；不要移除任何無法辨識的槽位。

## 常見狀況
| 現象 | 說明 |
|---|---|
| SmartScreen 警告 | 未簽章 exe，「仍要執行」即可（後續可加簽章） |
| D3 沒自動上鎖 | 多半是滑鼠/鍵盤在 app 視窗內動過 → 計時器被重算；再試一次、切走後別碰輸入設備 |
| 雙擊完全無反應 | 回傳訊息給 Coder（查 WebView2 / 事件紀錄） |
