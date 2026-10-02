# 可攜式 FIDO2 密碼金庫 v0.1 — NB 桌面驗證步驟（使用者用）

> 適用：Win11-NB，`C:\FidoVault`（portable 資料夾）。完成約 15–20 分鐘。
> Windows Release GUI 必須以 `--features real-ctap` 建置；一般權限的檔案總管直接啟動時使用 Windows WebAuthn API，無需環境變數或系統管理員提升。Windows 安全性視窗負責 PIN/UV/觸碰；目標系統需 WebAuthn API v4+。Debug build 預設為 MockBackend；明確跑 mock 流程時設定 `F2V_AUTHENTICATOR=mock`。
> **Win11-NB RDP 注意：**已確認 `RDP-Tcp#0` Session 2 的 WebAuthn API 回報 v1，程式依 v4+ fail-closed 而閃退；使用者確認從 Console 啟動可正常開啟。H1–H5 請在 Console session 驗收；RDP redirection 路線未驗收，勿降低 API 版本檢查。

## 部署後驗證前確認（2026-10-01）
已部署 PR #3 的 Windows GNU Release GUI，SHA256：`E9A28C81C73456800E3F1FAF0E8F1A9F6576146C8A675F5AB125FF9135ED8503`。替換前舊 exe 已備份為 `C:\FidoVault\portable-fido-vault.exe.pre-single-key-20261001-112834.bak`（SHA256 `06B1C5BE7A5E760D28D594B128A1B5BC681C31A6FD26D672E942E5F1062F0EA2`）。`vault.db` 未替換，SHA256 `848F961C4C5CB741EF1ADE452008F1D3F17649D06582B4809CEBFC4E16877B99`，3 個 key slots；備份 `C:\FidoVault\vault.db.pre-single-key-20261001-112834.bak` SHA256 相同。部署前 WinRM read-only process check 為 0 個 FIDO client，`F2V_AUTHENTICATOR` 使用者/系統變數均未設定。

## H2 焦點修正候選部署（2026-10-01）
PR #3 commit `ab3d123` 的 Windows GNU Release GUI 已部署至 `C:\FidoVault\portable-fido-vault.exe`，SHA256 `42D6DB566BEA217282D5BB487FA5DFB207B9252D2F3B1349938C4BB658AB2B58`（6,121,472 bytes）。部署前 exe 備份：`C:\FidoVault\portable-fido-vault.exe.pre-focusfix-20261001-203755-e9759808.bak`，SHA256 `E9A28C81C73456800E3F1FAF0E8F1A9F6576146C8A675F5AB125FF9135ED8503`。vault 備份：`C:\FidoVault\vault.db.pre-focusfix-20261001-203755-e9759808.bak`，SHA256 `EB3A9271259DE1A0348DFF031F922456248C5A21A5B387000F6B03B6E4488C46`。部署後遠端回讀確認 exe hash 相符；`vault.db` 保持相同 hash、3 個 key slots；FIDO client process 為 0，user/machine `F2V_AUTHENTICATOR` 均未設定。尚待使用者於本機 Console 驗收 H2 前景；WinRM 未啟動 GUI、未執行 WebAuthn。

## H2 broker 對話框前景候選部署（2026-10-01）
唯讀 Console 探測確認：擷取時 FidoVault HWND `0x1D056C` 是 foreground、z-order 17；`CredentialUIBroker` HWND `0x1203CE`（PID 1492，Session 2）顯示「Windows 安全性」、class `Credential Dialog Xaml Host`，z-order 18，`OWNER=0`、`ROOTOWNER` 為自身。這證實 broker 對話框是獨立的 unowned top-level window；主窗置前不會自動提升它。

新候選在 GetAssertion/MakeCredential 等待期間監測；只有唯一、同 session、新建立的 System32 `CredentialUIBroker.exe` 安全性視窗才嘗試一次 `SetForegroundWindow`，並要求使用者仍把 FidoVault 留在 foreground。基線包含隱藏 top-level 視窗及既有 broker PID；不改對話框 owner、不設 topmost、不使用 `ASFW_ANY`。前景交接仍是 best-effort，Windows 在檢查與呼叫間仍可能切換焦點。

新候選來源 commit `45d3aa6`（PR #3）部署為 `C:\FidoVault\portable-fido-vault.exe` SHA256 `59BBAB25C21A419702D02FA7E97242392C388149432BAF733AC0C715F06085D8`（6,140,928 bytes）。取代前 GUI 備份 `C:\FidoVault\portable-fido-vault.exe.pre-H2focus-20261001-223428-2985cea4.bak`，SHA256 `42D6DB566BEA217282D5BB487FA5DFB207B9252D2F3B1349938C4BB658AB2B58`。vault 備份 `C:\FidoVault\vault.db.pre-H2focus-20261001-223428-2985cea4.bak`，SHA256 `58A1D4877C2274B3D403E1D87CD1E9BA7C5404D450C3F69E1D9486501F02D780`；部署前後維持 3 個 slots 與相同 vault hash。`WebView2Loader.dll` 未替換，SHA256 `86545B66CDB0603BC26B626FB9AD610CB6E71F28D468F5EA66DF23B03DDA96D5`；user/machine `F2V_AUTHENTICATOR` 均未設定，遠端沒有啟動 GUI 或 WebAuthn。程式碼獨立審查通過，Rust 53/53、UI 4/4、GNU Release build 成功。**使用者已確認 H2 本機 Console 測試 OK：通用登入免選金鑰，Windows 安全性操作提示置前；本項已結案。**

執行所需檔案如下；`C:\FidoVault` 也有診斷紀錄與備份檔，**不要因舊版「只有三個檔案」說明而刪除任何其他檔案**：

| 檔案 | 說明 |
|---|---|
| `portable-fido-vault.exe` | 主程式（GUI）；Windows GUI 透過 Windows WebAuthn API v4+ 使用安全金鑰 |
| `WebView2Loader.dll` | WebView2 載入器（GUI 必備，部署時保留） |
| `vault.db` | 既有金庫資料；驗證前另做使用者備份，切勿刪除或重建 |
| `vault_cli.exe` | 選用 CLI；保留 raw CTAP 診斷路徑，本次部署未替換 |

> 這台 NB 已有既存 `vault.db`，目前有 3 個 key slots。A–F 是全新測試金庫的舊 Gate 流程；G4–G6 是先前已完成的實體驗收（其步驟中的槽位數是當時紀錄，不代表目前數量）。本次請驗收 **H1–H5**，勿建立、清空或重建現有金庫。

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

> 本節不需設定 `F2V_AUTHENTICATOR`；此 Win11-NB 請從本機 Console session 以一般權限啟動，不要從 RDP session 啟動。Windows 安全性視窗負責安全金鑰選擇、PIN/UV 與觸碰。

- [ ] **G1** 在 Win11-NB 本機互動桌面確認沒有 `vault_cli`、`portable-fido-vault` 或 `yk_open_test` 程序；若有，正常關閉，不要 force-kill。
- [x] **G2** 部署前已備份 `C:\FidoVault\vault.db` 並記錄 baseline：3 個 key slots、SHA256 與備份路徑見上方；切勿刪除或重建此金庫。
- [ ] **G3** 用一般權限（非系統管理員）的檔案總管直接啟動 `C:\FidoVault\portable-fido-vault.exe`；不設 `F2V_AUTHENTICATOR`。啟動診斷應顯示 `GUI FIDO backend selected: windows-webauthn`。
- [x] **G4（舊槽相容性；先前已驗收）** 以原有實體金鑰完成 Windows 安全性提示，確認舊 raw-CTAP 槽能由 Windows WebAuthn backend 解鎖；驗收當時槽位數為 1。若本次 H 驗收遇到登入失敗，不要移除或覆寫任何槽位。
- [x] **G5（註冊；先前已驗收）** 「金鑰管理」→「＋ 註冊新金鑰」註冊 YubiKey Bio；Windows 安全性提示與觸碰／指紋流程已通過，PIN 只在本機提示輸入。
- [x] **G6（新槽登入；先前已驗收）** 新槽登入已通過；第二支 YubiKey NFC 亦已註冊並完成交叉登入。這些完成當時的槽位數紀錄不代表目前數量；目前部署前 baseline 為 3 個 key slots。

若視窗未啟動或金鑰未要求互動，保留目前 vault 備份並回報 UI 狀態；不要移除任何無法辨識的槽位。

## H. 單一金鑰登入入口與 Windows 安全性視窗前景驗收

> 使用已完成 G4–G6 的既有金庫與兩支不同 YubiKey；不要重建或刪除任何 key slot。主密碼登入仍須保留。

- [x] **H1** 登入畫面仍有主密碼欄位；金鑰區不列出逐支金鑰卡片，只顯示一個通用「以金鑰登入」按鈕。
- [x] **H2** 通用按鈕不需先選金鑰；使用者已確認 Win11-NB 本機 Console 測試中 Windows 安全性操作提示出現在前景。broker 視窗置前仍是 best-effort，Windows 可能在其他情境切換焦點。
- [x] **H3** 上鎖後用同一按鈕改用第二支 YubiKey NFC 登入，確認可解鎖相同金庫。
- [x] **H4** 取消 Windows 金鑰操作，確認金庫仍維持鎖定、顯示錯誤/取消狀態，且可重試或改用主密碼登入。
- [x] **H5** 使用者回報註冊流程通過；H2 前景驗收已另行完成。本次不需註冊多餘金鑰。

## 常見狀況
| 現象 | 說明 |
|---|---|
| SmartScreen 警告 | 未簽章 exe，「仍要執行」即可（後續可加簽章） |
| D3 沒自動上鎖 | 多半是滑鼠/鍵盤在 app 視窗內動過 → 計時器被重算；再試一次、切走後別碰輸入設備 |
| 雙擊完全無反應 | 回傳訊息給 Coder（查 WebView2 / 事件紀錄） |

## 密碼欄位遮罩 — Win11-NB 驗收（2026-10-01）

本次以 PR #5 功能分支 commit `a651a12` 建置 Windows GNU Release（`--features real-ctap`），已部署至 `C:\FidoVault\portable-fido-vault.exe`。
使用者已確認 Win11-NB 本機 Console 實機驗收通過。

| 項目 | 回讀結果 |
|---|---|
| 新版 EXE SHA-256 / 大小 | `50D17C57685E1740DB763EB65A09666DFF7F34CC8009A555EC0D830F4A6C9A57` / 6,145,024 bytes |
| 替換前 EXE 備份 | `C:\FidoVault\portable-fido-vault.exe.pre-password-mask-20261001-234130.bak`，SHA-256 `59BBAB25C21A419702D02FA7E97242392C388149432BAF733AC0C715F06085D8` |
| vault 備份 | `C:\FidoVault\vault.db.pre-password-mask-20261001-234130.bak`，SHA-256 `93945AEF2941A2D0785564A57D7D652847E92FD7CF8FD30A26501BA965184087` |
| 目前 vault | SHA-256 與備份相同，3 個 key slots；部署前後未替換 |
| 部署後 FIDO client / backend override | 0 個 FIDO client；user/machine `F2V_AUTHENTICATOR` 均未設定 |

本次只推送 GUI EXE，未啟動 GUI、未操作 WebAuthn，也未推送 `vault_cli.exe` 或 `WebView2Loader.dll`。請在 Win11-NB **本機 Console** 以一般權限驗收；RDP 遠端啟動不支援（見 README）。

- [x] 新增測試條目：密碼預設遮罩；眼睛按鈕可顯示／隱藏。
- [x] 編輯該條目：密碼預設遮罩；眼睛按鈕可顯示／隱藏；重新開啟編輯時仍預設遮罩。
- [x] 儲存或取消後密碼欄清空並恢復遮罩；條目列表不顯示密碼。

請使用測試用密碼，不要把密碼貼到聊天。本次密碼遮罩 build 未包含密碼歷史；剪貼簿複製、自訂金鑰名稱仍待後續實作。

## 舊密碼歷史 — Win11-NB 驗收

本次以 PR #6 功能分支 commit `fdc55be` 建置 Windows GNU Release（`--features real-ctap`），已部署至 `C:\FidoVault\portable-fido-vault.exe`。

- 新版 EXE SHA-256：`9c79a04dcfbd0f16b1f37a4b1c3cdd9e571f39190ef26904c269ba69c6102057`（6,158,336 bytes）。
- 替換前 EXE 備份：`C:\FidoVault\portable-fido-vault.exe.pre-password-history-20261002-010914.bak`，SHA-256 `50d17c57685e1740db763eb65a09666dff7f34cc8009a555ec0d830f4a6c9a57`。
- vault 備份：`C:\FidoVault\vault.db.pre-password-history-20261002-010914.bak`，SHA-256 `1e3c9fe8266bf41a7f25ece8f2c2bf45cbb63367001042e06291234efe2b9f54`。
- 部署後回讀確認新版 EXE 雜湊相符；`vault.db` 未替換，仍為 3 個 key slots 且雜湊與備份相同；0 個 FIDO client，user/machine `F2V_AUTHENTICATOR` 均未設定。
- 本次只推送 GUI EXE，未啟動 GUI、未操作 WebAuthn，也未推送 `vault_cli.exe` 或 `WebView2Loader.dll`。請在 Win11-NB **本機 Console** 以一般權限驗收；RDP 遠端啟動不支援（見 README）。

舊 vault 缺少歷史資料欄位時應以空歷史、保留上限 3 開啟；部署前已建立可回復的 vault 備份。使用者登入會把相容預設值寫入加密 payload，屆時 vault 雜湊自然會更新。

- [ ] 解鎖既有 vault，在設定確認舊密碼保留代數預設為 3；設定改為 4、重新登入後仍為 4。
- [ ] 對測試條目依序改密碼 3 次；編輯畫面顯示三筆舊版本日期，最近版本在前，舊密碼值預設不明文顯示。
- [ ] 只修改網站/帳號/備註或儲存相同密碼，不新增歷史版本。
- [ ] 選一筆舊版本按「還原」並儲存：該值成為目前密碼；原目前密碼成為最新舊版本；被還原版本不再重複留在歷史。
- [ ] 將保留代數調低為 1 並套用：每筆條目立即只留最新一筆舊密碼；重新登入後設定仍為 1。

請使用測試用條目與密碼，不要將密碼貼到聊天。調低保留代數會立即刪除超額的最舊歷史版本。

## 條目密碼複製 — Win11-NB 驗收（PR #8，尚未部署）

候選 Windows GNU Release（`--features real-ctap`）GUI：6,589,440 bytes，SHA-256 `58ba298f7f2bcd5fa4d2c1bdda5ab6e5d2847379af8e282c7ea92e3732838dde`。此 build 尚未部署至 NB；Feature 2 本機驗收也仍依使用者指示延後。

- [ ] 在 Win11-NB **本機 Console** 以一般權限開啟，建立只含測試資料的條目；逐列按「複製密碼」，確認各自複製正確條目的密碼，狀態不顯示密碼明文。
- [ ] 複製後保持剪貼簿不變，等候 60 秒；確認內容自動清除。
- [ ] 再複製測試密碼，60 秒內從另一個程式把無敏感性的標記文字複製到剪貼簿；等候 60 秒，確認標記文字仍在，未被清除。
- [ ] 快速連續複製兩個測試條目；確認舊計時器不會清掉後一次複製的密碼，並以後一次複製時間起算 60 秒。
- [ ] 確認複製操作不新增包含密碼的軌跡紀錄；剪貼簿錯誤不能使 App 崩潰。

系統剪貼簿是共用資源，其他桌面程式可能在清除前讀取內容；Windows 剪貼簿歷程/雲端剪貼簿也可能保存或同步，EmptyClipboard 不會移除已保存的歷程項目。請只用測試用密碼，切勿貼到聊天。不要透過 RDP/WinRM 啟動或操作 GUI；本功能不需要實體 FIDO 金鑰。
