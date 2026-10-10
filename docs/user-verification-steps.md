# 可攜式 FIDO2 密碼金庫 v0.1 — NB 桌面驗證步驟（使用者用）

> 適用：Win11-NB，`C:\FidoVault`（portable 資料夾）。本文保留部署與已確認驗收紀錄，不是要求重新執行全部舊模板。
> Windows Release GUI 必須以 `--features real-ctap` 建置；一般權限的檔案總管直接啟動時使用 Windows WebAuthn API，無需環境變數或系統管理員提升。Windows 安全性視窗負責 PIN/UV/觸碰；目標系統需 WebAuthn API v4+。Debug build 預設為 MockBackend；明確跑 mock 流程時設定 `F2V_AUTHENTICATOR=mock`。
> **RDP 範圍（2026-10-10 R6 GO）：**已支援（限已測矩陣，見 `docs/rdp-webauthn-verification.md` R6）：由 Win11-NB 以 mstsc（啟用 WebAuthn 重新導向、YubiKey Bio 插在 Win11-NB）連入 WS2，在 RDP session 內以主密碼或已註冊金鑰登入、註冊新金鑰；WS2 RDP 回報 API v7。資料夾須以一般權限複製（避免 os error 5）。重新導向關閉時 GUI 仍啟動、僅主密碼可用。下方各節「從本機 Console 啟動、不要從 RDP」的文字是當時快照，已由本段取代。API 低於 v4 的 session 仍 fail closed；勿降低 API 版本檢查。早期 Win11-NB RDP session 曾回報 API v1。

## 已確認驗收彙整（文件同步：2026-10-11）

| 項目 | 已確認結果（Win11-NB 本機 Console） |
|---|---|
| Feature 1 — 密碼欄位遮罩 | 2026-10-01 PASS |
| Feature 2/3/4 — 舊密碼歷史、60 秒條件清除、本機金鑰別名 | 2026-10-02 集中驗收整體 PASS |
| Feature 5 — CSV 範本與批次匯入／更新 | 2026-10-03 全項 PASS（PR #13 已合併） |
| Feature 6 — 條目即時搜尋 | 2026-10-03 明確 PASS（PR #14 已合併） |
| Feature 7 — 預設最大化與金鑰登入期間維持最大化 | 2026-10-03 明確 PASS（PR #15 修正版，已合併） |
| 主畫面條目刪除確認（PR #17） | 使用者確認 D1–D5 PASS；D6 已免測、不列待辦（歷史 NOT_TESTED 非 PASS） |
| Console 金鑰提示前景（PR #23） | 2026-10-10 C1–C6 PASS；已知 F2 第二個安全性視窗可能在背景（使用者接受） |
| RDP 支援（R2–R6，PR #20–#26） | 2026-10-10 實機驗收；R6 GO 限已測矩陣（見 `docs/rdp-webauthn-verification.md`） |
| WebAuthn 不可用時保留主密碼登入（PR #25） | 2026-10-10 WS2 RDP W1–W6 PASS；2026-10-11 正式部署（見本文末節） |

各節部署雜湊、備份、槽位數與操作說明保留為**當時快照**；2026-10-01 的 3 slots 不代表後續部署數量。最新已記錄部署為本文末節的 PR #25 版本（2026-10-11，GUI SHA-256 `3b3f7367be81baab…`）；Rust 格式維護版本（來源 `99ff0e5e537c5485f6fb65819f45662c2769c0a1`）已被取代。

A–C/E/F 是舊模板，沒有逐項人工 PASS 回報，不因功能／任務結案而補勾；D1–D4 已確認，D5 為選測且未回報。Gate 8 除 mock E2E copy-test 外，2026-10-10 已有專用測試金庫的實體 GUI 跨機人工 PASS（Win11-NB ↔ WS2）。H1–H5 與下方 Feature 1–7 的既有確認維持完成；RDP 已於 2026-10-10 R6 GO（限已測矩陣，見上方）、raw CTAP CLI 實體 register/login 路線已由 GUI 驗收取代（superseded），不是待驗項。

## 部署後驗證前確認（2026-10-01，歷史部署／已取代）
已部署 PR #3 的 Windows GNU Release GUI，SHA256：`E9A28C81C73456800E3F1FAF0E8F1A9F6576146C8A675F5AB125FF9135ED8503`。替換前舊 exe 已備份為 `C:\FidoVault\portable-fido-vault.exe.pre-single-key-20261001-112834.bak`（SHA256 `06B1C5BE7A5E760D28D594B128A1B5BC681C31A6FD26D672E942E5F1062F0EA2`）。`vault.db` 未替換，SHA256 `848F961C4C5CB741EF1ADE452008F1D3F17649D06582B4809CEBFC4E16877B99`，3 個 key slots；備份 `C:\FidoVault\vault.db.pre-single-key-20261001-112834.bak` SHA256 相同。部署前 WinRM read-only process check 為 0 個 FIDO client，`F2V_AUTHENTICATOR` 使用者/系統變數均未設定。

## H2 焦點修正候選部署（2026-10-01，歷史候選／superseded）
PR #3 commit `ab3d123` 的 Windows GNU Release GUI 已部署至 `C:\FidoVault\portable-fido-vault.exe`，SHA256 `42D6DB566BEA217282D5BB487FA5DFB207B9252D2F3B1349938C4BB658AB2B58`（6,121,472 bytes）。部署前 exe 備份：`C:\FidoVault\portable-fido-vault.exe.pre-focusfix-20261001-203755-e9759808.bak`，SHA256 `E9A28C81C73456800E3F1FAF0E8F1A9F6576146C8A675F5AB125FF9135ED8503`。vault 備份：`C:\FidoVault\vault.db.pre-focusfix-20261001-203755-e9759808.bak`，SHA256 `EB3A9271259DE1A0348DFF031F922456248C5A21A5B387000F6B03B6E4488C46`。部署後遠端回讀確認 exe hash 相符；`vault.db` 保持相同 hash、3 個 key slots；FIDO client process 為 0，user/machine `F2V_AUTHENTICATOR` 均未設定。當時尚待使用者於本機 Console 驗收 H2 前景；此候選後續已由 `45d3aa6` 取代，H2 已在下節確認通過，不是目前待驗項。WinRM 未啟動 GUI、未執行 WebAuthn。

## H2 broker 對話框前景候選部署（2026-10-01，H2 已通過／歷史部署）
唯讀 Console 探測確認：擷取時 FidoVault HWND `0x1D056C` 是 foreground、z-order 17；`CredentialUIBroker` HWND `0x1203CE`（PID 1492，Session 2）顯示「Windows 安全性」、class `Credential Dialog Xaml Host`，z-order 18，`OWNER=0`、`ROOTOWNER` 為自身。這證實 broker 對話框是獨立的 unowned top-level window；主窗置前不會自動提升它。

新候選在 GetAssertion/MakeCredential 等待期間監測；只有唯一、同 session、新建立的 System32 `CredentialUIBroker.exe` 安全性視窗才嘗試一次 `SetForegroundWindow`，並要求使用者仍把 FidoVault 留在 foreground。基線包含隱藏 top-level 視窗及既有 broker PID；不改對話框 owner、不設 topmost、不使用 `ASFW_ANY`。前景交接仍是 best-effort，Windows 在檢查與呼叫間仍可能切換焦點。

新候選來源 commit `45d3aa6`（PR #3）部署為 `C:\FidoVault\portable-fido-vault.exe` SHA256 `59BBAB25C21A419702D02FA7E97242392C388149432BAF733AC0C715F06085D8`（6,140,928 bytes）。取代前 GUI 備份 `C:\FidoVault\portable-fido-vault.exe.pre-H2focus-20261001-223428-2985cea4.bak`，SHA256 `42D6DB566BEA217282D5BB487FA5DFB207B9252D2F3B1349938C4BB658AB2B58`。vault 備份 `C:\FidoVault\vault.db.pre-H2focus-20261001-223428-2985cea4.bak`，SHA256 `58A1D4877C2274B3D403E1D87CD1E9BA7C5404D450C3F69E1D9486501F02D780`；部署前後維持 3 個 slots 與相同 vault hash。`WebView2Loader.dll` 未替換，SHA256 `86545B66CDB0603BC26B626FB9AD610CB6E71F28D468F5EA66DF23B03DDA96D5`；user/machine `F2V_AUTHENTICATOR` 均未設定，遠端沒有啟動 GUI 或 WebAuthn。程式碼獨立審查通過，Rust 53/53、UI 4/4、GNU Release build 成功。**使用者已確認 H2 本機 Console 測試 OK：通用登入免選金鑰，Windows 安全性操作提示置前；本項已結案。**

執行所需檔案如下；`C:\FidoVault` 也有診斷紀錄與備份檔，**不要因舊版「只有三個檔案」說明而刪除任何其他檔案**：

| 檔案 | 說明 |
|---|---|
| `portable-fido-vault.exe` | 主程式（GUI）；Windows GUI 透過 Windows WebAuthn API v4+ 使用安全金鑰 |
| `WebView2Loader.dll` | app-local 載入器（GUI 必備）；須與 EXE 同一層、同版 x64，跨機搬移也要複製，不等同 Runtime |
| `vault.db` | 既有金庫資料；驗證前另做使用者備份，切勿刪除或重建 |
| `vault_cli.exe` | 選用 CLI；保留 raw CTAP 診斷路徑，本次部署未替換 |

### 跨機搬移前置條件與啟動排錯

- **不能只複製 EXE 與 DB。**目標資料夾須一起攜帶 `portable-fido-vault.exe`、同版 x64 `WebView2Loader.dll` 與原 `vault.db`；有 `vault.db.failures` 時一併備份／複製，保留未合併失敗軌跡。
- 目標機須有 **WebView2 Runtime**；Windows 11／Edge 已安裝不代替可用性檢查。DLL 與 Runtime 是不同元件，互不取代；缺少 Runtime 的離線電腦可用微軟官方 x64 Evergreen Standalone Installer。官方依據與打包範例見 README 的 portable 部署章節。
- 在來源機正常關閉 GUI／CLI 後先另做備份，複製至**全新**且可寫入的目的資料夾；不可覆寫目的機另一份金庫。啟動前核對 EXE／DLL／DB 來源與目的 SHA-256，保留來源與備份；登入可能寫入 audit，不用登入後的 DB hash 判斷傳輸是否一致。
- 遇到「找不到 `WebView2Loader.dll`」：從可信任同版 x64 套件補到 EXE 旁；**不要刪除、覆寫或重建 DB，也不要重新註冊／移除金鑰**。搬移舊 DB 卻顯示首次建立帳號時立即停止，核對該 EXE 同目錄的 `vault.db`。
- 硬體版 GUI 要求 Windows WebAuthn API v4+，在目標機本機 Console 或已測矩陣內的 RDP session 操作；不以 WinRM 取代驗證。mock Gate 8、PE import 或 DLL 載入檢查不代表實體 GUI 跨機解鎖 PASS。實體 GUI 跨機已有人工 PASS（2026-10-10，專用測試金庫）：Win11-NB 本機 Console 建立的測試金庫以一般權限複製到 WS2，在 RDP session 以同一主密碼與同一把金鑰解鎖；WS2 RDP 建立的測試金庫複製回 Win11-NB 本機 Console 以同一金鑰解鎖。正式金庫未做跨機搬移。

> 2026-10-01 的 NB 部署已有既存 `vault.db`，當時有 3 個 key slots。A–F 是全新測試金庫的舊 Gate 流程；G4–G6 與 H1–H5 的實體驗收已完成，步驟中的槽位數僅為當時紀錄。後續部署快照見 Feature 5/7；不要把舊槽位數當作目前數量，勿建立、清空或重建現有金庫。

## A. Gate 1 — 雙擊免安裝執行（舊模板，未逐項回報）
- [ ] **A1** 雙擊 `C:\FidoVault\portable-fido-vault.exe`
  - 若出現 Windows SmartScreen「未識別應用程式」→ 點「其他資訊」→「仍要執行」（exe 未簽章，預期行為）
  - **預期**：數秒內跳出視窗「🔐 可攜式 FIDO2 密碼金庫 — 請輸入主密碼登入」
- [ ] **A2** 首次執行會顯示「首次執行 — 建立帳號」面板 → 設定主密碼（≥8 字元，例：`Test-Pw-1234`）→ 按「建立金庫」
  - **預期**：跳回登入畫面
- [ ] **A3** 確認 `C:\FidoVault` 下多了一個 `vault.db`（金庫檔；之後所有資料都在這裡）

## B. Gate 2 — 密碼登入 + 錯誤計軌跡（舊模板，未逐項回報）
- [ ] **B1** 輸入**錯**主密碼 → 按「以主密碼登入」→ **預期**：顯示錯誤、留在登入畫面
- [ ] **B2** 到 `C:\FidoVault` 確認出現 `vault.db.failures`（失敗軌跡 sidecar；只有時間+方式，無機密）
- [ ] **B3** 輸入**正確**主密碼 → 登入成功 → **預期**：進主畫面（頂欄「已解鎖」+ 四個分頁）
- [ ] **B4**（選用）進「軌跡紀錄」分頁：應看到 `login_failed`、`login_success`、`vault_created`；且**任何一列都不含密碼明文**

## C. Gate 5 — 條目 CRUD + 時間戳（舊模板，未逐項回報）
- [ ] **C1** 「條目」分頁：網站=`example.com`、帳號=`alice` →「＋ 新增」→ 彈出框輸入密碼 `S3cret!`
  - **預期**：表格出現該列，含建立/更新時間
- [ ] **C2** 點該列「編輯」→ 改備註或密碼 →「儲存」→ **預期**：「更新時間」變新、「建立時間」不變
- [ ] **C3** 點「顯示」→ 彈出框應回顯 `S3cret!`（可讀回）
- [ ] **C4**（選用）新增第二條再「刪除」（會問確認）→ 表格少一列

## D. Gate 7 — 閒置自動上鎖（D1–D4 已通過；D5 選測未回報）
- [x] **D1** 「設定」分頁：輸入 `1` →「套用」→ **預期**：彈出「已套用：閒置 1 分鐘自動上鎖」
- [x] **D2** 切到**其他視窗或桌面**，**完全不要碰滑鼠與鍵盤超過 60 秒**
  - ⚠️ 注意：**只要滑鼠在 app 視窗內移動、或在它上面按鍵/打字，計時器就會重算**。最保險：切走後去泡杯咖啡，別回頭動滑鼠。
- [x] **D3** 60 秒後回到該視窗 → **預期**：已自動跳回登入畫面（「已解鎖」變鎖定狀態）
- [x] **D4** 重新登入 →「軌跡紀錄」→ **預期**：最新一列是 `auto_lock`（方式欄 idle）
- [ ] **D5**（對照組，選測）再上鎖一次前點右上「上鎖」手動按鈕 → 回登入畫面 → 軌跡多一列 `lock`

## E. Gate 3/4 — FIDO2 金鑰流程（mock 舊模板，未逐項回報）

> 此節只測 MockBackend。若由 PowerShell 啟動 mock GUI，僅在該視窗設定 `$env:F2V_AUTHENTICATOR='mock'`；關閉 app 後用 `Remove-Item Env:F2V_AUTHENTICATOR -ErrorAction SilentlyContinue` 清除，勿用 `setx` 持久設定。

- [ ] **E1** 「金鑰管理」分頁 →「＋ 註冊新金鑰」→ **預期**：狀態列顯示已註冊某型別（fingerprint / pin / touch-only 輪流；PIN 型會先問 PIN，任意輸入即可，mock 不驗證真 PIN）
- [ ] **E2** 再註冊第二支（型別會不同）→「上鎖」→ 登入畫面應列出已註冊金鑰
- [ ] **E3** 選任一金鑰 →「以金鑰登入」→ **預期**：成功進主畫面（多支金鑰任一支皆可解鎖）

## F. Gate 8 — 可攜性直拷（舊模板，實體 GUI 跨機未回報 PASS）
- [ ] **F1** 正常關閉來源 GUI／CLI，另做金庫備份；不要強制終止等待金鑰驗證的程式
- [ ] **F2** 將完整 portable 資料夾複製至全新位置（例：`D:\FidoVault-copy` 或 USB）；確認 EXE、同版 x64 `WebView2Loader.dll`、原 `vault.db` 均在同一層，有 `vault.db.failures` 時一併攜帶。啟動前核對來源／目的 EXE、DLL、DB SHA-256；不覆寫既有目的金庫
- [ ] **F3** 先確認目標機 Runtime 可用、硬體版 GUI 的 WebAuthn API v4+／本機 Console 條件，再從新位置啟動 EXE，以原主密碼或已註冊金鑰登入 → **預期**：原條目、金鑰與軌跡可用；若變成首次建立帳號，停止並查 DB 路徑，不建立新金庫

## 舊模板回報格式（保留參考，不要求重跑已確認項目）
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

- [x] **G1** 在 Win11-NB 本機互動桌面確認沒有 `vault_cli`、`portable-fido-vault` 或 `yk_open_test` 程序；若有，正常關閉，不要 force-kill。
- [x] **G2** 部署前已備份 `C:\FidoVault\vault.db` 並記錄 baseline：3 個 key slots、SHA256 與備份路徑見上方；切勿刪除或重建此金庫。
- [x] **G3** 用一般權限（非系統管理員）的檔案總管直接啟動 `C:\FidoVault\portable-fido-vault.exe`；不設 `F2V_AUTHENTICATOR`。啟動診斷應顯示 `GUI FIDO backend selected: windows-webauthn`。
- [x] **G4（舊槽相容性；先前已驗收）** 以原有實體金鑰完成 Windows 安全性提示，確認舊 raw-CTAP 槽能由 Windows WebAuthn backend 解鎖；驗收當時槽位數為 1。若本次 H 驗收遇到登入失敗，不要移除或覆寫任何槽位。
- [x] **G5（註冊；先前已驗收）** 「金鑰管理」→「＋ 註冊新金鑰」註冊 YubiKey Bio；Windows 安全性提示與觸碰／指紋流程已通過，PIN 只在本機提示輸入。
- [x] **G6（新槽登入；先前已驗收）** 新槽登入已通過；第二支 YubiKey NFC 亦已註冊並完成交叉登入。這些完成當時的槽位數紀錄不代表目前數量；2026-10-01 部署前 baseline 為 3 個 key slots。

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

## 密碼欄位遮罩 — Win11-NB 驗收（通過，2026-10-01）

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

請使用測試用密碼，不要把密碼貼到聊天。當時的 Feature 1 build 未包含 Feature 2–4；後續驗收結果記錄於下列各節。

## 舊密碼歷史 — Win11-NB 驗收（通過，2026-10-02）

> 使用者確認 Feature 2、3、4 在 Win11-NB 本機 Console 集中驗收全部通過；以下手動驗收項依此整體 PASS 標記完成。

Feature 2 standalone staging 以 PR #6 功能分支 commit `fdc55be` 建置 Windows GNU Release（`--features real-ctap`），已部署至 `C:\FidoVault\portable-fido-vault.exe`。

- 新版 EXE SHA-256：`9c79a04dcfbd0f16b1f37a4b1c3cdd9e571f39190ef26904c269ba69c6102057`（6,158,336 bytes）。
- 替換前 EXE 備份：`C:\FidoVault\portable-fido-vault.exe.pre-password-history-20261002-010914.bak`，SHA-256 `50d17c57685e1740db763eb65a09666dff7f34cc8009a555ec0d830f4a6c9a57`。
- vault 備份：`C:\FidoVault\vault.db.pre-password-history-20261002-010914.bak`，SHA-256 `1e3c9fe8266bf41a7f25ece8f2c2bf45cbb63367001042e06291234efe2b9f54`。
- 部署後回讀確認新版 EXE 雜湊相符；`vault.db` 未替換，仍為 3 個 key slots 且雜湊與備份相同；0 個 FIDO client，user/machine `F2V_AUTHENTICATOR` 均未設定。
- 本次只推送 GUI EXE，未啟動 GUI、未操作 WebAuthn，也未推送 `vault_cli.exe` 或 `WebView2Loader.dll`。請在 Win11-NB **本機 Console** 以一般權限驗收；RDP 遠端啟動不支援（見 README）。

舊 vault 缺少歷史資料欄位時應以空歷史、保留上限 3 開啟；部署前已建立可回復的 vault 備份。使用者登入會把相容預設值寫入加密 payload，屆時 vault 雜湊自然會更新。

- [x] 解鎖既有 vault，在設定確認舊密碼保留代數預設為 3；設定改為 4、重新登入後仍為 4。
- [x] 對測試條目依序改密碼 3 次；編輯畫面顯示三筆舊版本日期，最近版本在前，舊密碼值預設不明文顯示。
- [x] 只修改網站/帳號/備註或儲存相同密碼，不新增歷史版本。
- [x] 選一筆舊版本按「還原」並儲存：該值成為目前密碼；原目前密碼成為最新舊版本；被還原版本不再重複留在歷史。
- [x] 將保留代數調低為 1 並套用：每筆條目立即只留最新一筆舊密碼；重新登入後設定仍為 1。

請使用測試用條目與密碼，不要將密碼貼到聊天。調低保留代數會立即刪除超額的最舊歷史版本。

## 條目密碼複製 — Win11-NB 驗收（PR #8，通過，2026-10-02）

Feature 3 standalone 候選 GUI（6,589,440 bytes，SHA-256 `58ba298f7f2bcd5fa4d2c1bdda5ab6e5d2847379af8e282c7ea92e3732838dde`）未單獨部署；三項功能以 Feature 4 整合 GUI（見下節）在 Win11-NB 本機 Console 一起驗收，使用者確認通過。

- [x] 在 Win11-NB **本機 Console** 以一般權限開啟，建立只含測試資料的條目；逐列按「複製密碼」，確認各自複製正確條目的密碼，狀態不顯示密碼明文。
- [x] 複製後保持剪貼簿不變，等候 60 秒；確認內容自動清除。
- [x] 再複製測試密碼，60 秒內從另一個程式把無敏感性的標記文字複製到剪貼簿；等候 60 秒，確認標記文字仍在，未被清除。
- [x] 快速連續複製兩個測試條目；確認舊計時器不會清掉後一次複製的密碼，並以後一次複製時間起算 60 秒。
- [x] 確認複製操作不新增包含密碼的軌跡紀錄；剪貼簿錯誤不能使 App 崩潰。

系統剪貼簿是共用資源，其他桌面程式可能在清除前讀取內容；Windows 剪貼簿歷程/雲端剪貼簿也可能保存或同步，EmptyClipboard 不會移除已保存的歷程項目。請只用測試用密碼，切勿貼到聊天。不要透過 RDP/WinRM 啟動或操作 GUI；本功能不需要實體 FIDO 金鑰。

## 安全性金鑰自訂名稱 — Win11-NB 驗收（PR #9，通過，2026-10-02）

本機候選 Windows GNU Release（`--locked --features real-ctap`）GUI：6,729,216 bytes，SHA-256 `7deba32418fb173d5ada126e600c81a748ffa51bcfe503afc7bed683fb928ed1`；CLI 2,427,392 bytes，SHA-256 `1493ab5d09fb942a61f77cc9e82827b2fa08f60e3e74d81e5d1cd657771ab3c2`。GUI 已部署至 `C:\FidoVault\portable-fido-vault.exe`（source commit `c8c10c23a97c08cf4074c79b1b6aee5728721b98`），目標端讀回 SHA-256 `7deba32418fb173d5ada126e600c81a748ffa51bcfe503afc7bed683fb928ed1`。舊 GUI 備份：`C:\FidoVault\portable-fido-vault.exe.pre-custom-key-name-c8c10c2.bak`，SHA-256 `9c79a04dcfbd0f16b1f37a4b1c3cdd9e571f39190ef26904c269ba69c6102057`；vault 備份：`C:\FidoVault\vault.db.pre-custom-key-name-c8c10c2.bak`，SHA-256 `00d772240939a12eee85dde5b0b0a2a12096f9039e1323a7c4c1c1c7dbd1faf0`。部署前後 live vault SHA-256 均為 `00d772240939a12eee85dde5b0b0a2a12096f9039e1323a7c4c1c1c7dbd1faf0`、3 key slots；前後唯讀檢查均未發現 FIDO client，`F2V_AUTHENTICATOR` user/machine override 均未設定。使用者於 2026-10-02 確認 Feature 2/3/4 整合 GUI 本機 Console 驗收全部通過。

**安全準備：**使用測試金鑰與測試資料；不要以唯一解鎖金鑰做測試。只在 Win11-NB **本機 Console** 以一般權限開啟；RDP 遠端啟動／操作 GUI 不支援。

- [x] 開啟「金鑰管理 → 註冊新金鑰」：對話框顯示一個未使用的建議別名；可編輯；文字說明此為 FidoVault 本機名稱，且 header 中的名稱是明文資料。
- [x] 將名稱留白、輸入已存在名稱的大小寫／空白變體，或輸入 Unicode 大小寫等價名稱（例如既有 `Σ` 時輸入 `ς`）：顯示驗證錯誤、對話框保持開啟，且尚未執行 authenticator 偵測或出現 Windows 安全性註冊提示。
- [x] 取消註冊：不出現 Windows 安全性註冊提示；金庫 key-slot 數與 audit 不變。
- [x] 以測試別名（例如 `F4 Local Test Key`）完成一支測試金鑰註冊：Windows 安全性視窗照常驗證；成功狀態、金鑰清單與 `key_registered` audit 使用自訂別名。確認提示視窗名稱／authenticator credential 本身不因別名改變。
- [x] 上鎖並重新登入：清單仍顯示該別名；確認只新增一個 slot。不要把真實密碼或敏感個資當成別名。
- [x] 按前節 Feature 2 步驟驗證舊密碼保留數、歷史檢視／還原；按 Feature 3 步驟驗證複製、60 秒清除、外部替換保留及快速連續複製。

剪貼簿只使用測試用密碼；Windows 剪貼簿歷程／雲端剪貼簿可能保存或同步，條件清除不會刪除歷程項目。FIDO/WebAuthn 必須由使用者在本機 Console 操作，不能透過 RDP 或 WinRM 執行 GUI 驗收。

## CSV 批次匯入／更新 — Win11-NB 本機驗收（PR #13，PASS，2026-10-03）

> 使用者於 2026-10-03 回報以下 Win11-NB 本機 Console 驗收項目全部通過。WinRM staging 階段未啟動 GUI，也未操作 WebAuthn。

- Source commit：`f33eea8d24fd77e1a85e9a59e409ba8ddf9cbfa3`；Windows Release 使用 `--locked --features real-ctap`。
- 新 GUI：`C:\FidoVault\portable-fido-vault.exe`，10,107,392 bytes，SHA-256 `1e2d22aba57f394a7b41e5500fa9deccaf3d414cfa7870699a0c7862ea73db82`；WinRM 部署後另行唯讀回讀，雜湊相符。
- 替換前 GUI 備份：`C:\FidoVault\portable-fido-vault.exe.pre-batch-csv-20261003-170756-f33eea8.bak`，SHA-256 `7deba32418fb173d5ada126e600c81a748ffa51bcfe503afc7bed683fb928ed1`。
- Vault 備份：`C:\FidoVault\vault.db.pre-batch-csv-20261003-170756-f33eea8.bak`，SHA-256 `34e7b94de6f04ee207f063b6b2c797b29ef1f7a900c6215851ccb66e19c916df`。
- staging 前後 live `vault.db` 雜湊相同，key-slot 數維持 1；備份雜湊均與來源一致。前後未發現 FIDO client，user/machine `F2V_AUTHENTICATOR` 均未設定，暫存 `.b64` 已清除。
- 本次只推送 GUI EXE；未推送 `vault_cli.exe` 或 `WebView2Loader.dll`。使用者已在 Win11-NB **本機 Console** 完成驗收；未透過 RDP/WinRM 操作 GUI 或 WebAuthn。測試使用專用條目，不涉及真實條目或在聊天中傳送密碼。

### 使用者確認通過

- [x] 範本下載成功，檔案為 UTF-8 且只有 `site,account,password,notes` 表頭。
- [x] 匯入含 BOM、欄位順序不同及標準 quoting（逗號、雙引號、欄位內換行）的測試 CSV；預覽列號正確，且不顯示任何 CSV 欄位值／密碼。
- [x] 新配對新增；唯一既有配對（忽略首尾空白與大小寫）更新；更新列空白欄位保留原值，非空欄位更新；密碼變更沿用密碼歷史規則。
- [x] 缺少必填 site、欄數錯誤、CSV 內重複配對及多筆既有匹配等情況，列號與略過原因正確；其他有效列仍可預覽／匯入。
- [x] 超過 1,000 筆資料列時整檔拒絕，金庫不變；預覽後取消或上鎖不寫入；確認匯入後所有有效列一起保存，重新解鎖後資料與新增／更新／略過計數正確。
- [x] 確認 UI 有明文 CSV 密碼提醒，預覽、audit、診斷訊息與暫存檔均未暴露 CSV 密碼或整列內容。首次登入可能改寫加密 payload／audit，請保留上述備份，不因雜湊變更而覆寫 vault。

使用者已確認全部項目 PASS；部署紀錄、備份與驗收項目維持可追溯。詳見 PR #13 與 Kanban task `t_1430ad96`。

## 條目介面即時搜尋 — Win11-NB 本機驗收（PR #14，PASS，2026-10-03）

> 僅使用專用測試條目與假資料；不要修改或刪除既有真實條目。Win11-NB GUI 驗收由使用者在本機 Console 完成；使用者於 2026-10-03 確認本節驗證通過，勿透過 RDP/WinRM 操作 GUI。

- [x] 解鎖後進入「條目」分頁，確認可用鍵盤聚焦「搜尋條目」欄位；在網站、帳號及備註分別輸入大小寫不同的部分字串，確認即時篩選及筆數正確。
- [x] 清除查詢或只輸入空白，確認所有條目恢復；輸入不可能命中的測試字串，確認顯示「沒有符合搜尋條件」，與空金庫狀態「金庫尚無條目」不同。
- [x] 對專用測試條目搜尋其測試用目前密碼及舊密碼標記，確認兩者均不會命中；不要將測試密碼傳送到聊天。
- [x] 在唯一符合的測試結果上逐一確認「顯示」、「複製密碼」、「編輯」及「刪除」作用於該條目；複製後清除剪貼簿，刪除前再次核對是專用測試條目。
- [x] 保持查詢時新增或編輯測試條目，並（如可安全建立測試 CSV）完成 CSV 匯入；確認重新載入後查詢仍有效、符合筆數正確，清除查詢後新資料可見。
- [x] 確認輸入搜尋字串不新增軌跡紀錄；關閉並重新開啟程式後搜尋欄為空。完成後只清除本次建立的專用測試資料。

回報格式：搜尋欄位比對 __；清除/空白 __；零結果與空金庫提示 __；目前/舊密碼排除 __；列操作 __；新增/編輯/CSV 重載 __；audit/重啟 __（每項填 PASS/FAIL + 簡短現象）。

## 主視窗預設最大化 — Win11-NB 本機驗收（PR #15，PASS，2026-10-03）

> PR #15 原先 stacked on PR #14；兩項功能皆由使用者於 2026-10-03 確認本機 Console 驗證通過，PR #14/#15 均已合併。驗收由使用者在本機完成，未透過 RDP/WinRM 操作 GUI。
>
> **部署歷史（2026-10-03）：** 初次最大化版本（commit `a7fb6a0`）GUI SHA-256 `a874a96026e1c2a6baa7857a9fe3c7b564758347f2458aba5bd254ddd70e2092`（7,171,584 bytes），曾部署至 `C:\FidoVault\portable-fido-vault.exe`。當時備份在 `C:\FidoVault\backups\maximized-20261003-a7fb6a0`；其前一版 exe SHA-256 `3873d0701f24ce23272e8633195a98eda6313f67ba7f82505562d6b950f77d1d`，vault SHA-256 `09ea6c2cc94d4e4ceef3f7d4c201826c7cb3930da9cf6e9909c862d4c8451025`。使用者回報點「以金鑰登入」會還原視窗；此版本已由下列修正版取代。
>
> **最近一次已記錄部署（2026-10-03，fix commit `1bf77fd23d27dcea2235821fc36bc74a21c269db`）：** GUI SHA-256 `0910d0cd5f29518e83c5ebd60b562572165adda91fae335f4771a386f52570f6`（7,172,096 bytes）。部署前備份位於 `C:\FidoVault\backups\key-login-maximized-20261003-1bf77fd`：舊 exe SHA-256 `a874a96026e1c2a6baa7857a9fe3c7b564758347f2458aba5bd254ddd70e2092`，vault SHA-256 `35b669a0c720314ccb9f602faa89b7e8b5adf82d09f1c43831f40f5968fdf1a1`。部署後 exe hash 與建置檔相符，vault hash 不變、header 有效且有 1 個 key slot；沒有相關程序、持久 authenticator override 或傳輸暫存檔。未透過 WinRM 啟動 GUI。使用者於 2026-10-03 確認本節驗收通過。

- [x] 關閉並重新啟動程式，確認主視窗開啟時已最大化，標題列及工作列仍可見（不是全螢幕）。
- [x] 按「以金鑰登入」，確認 Windows 安全性提示出現時主視窗不會縮回一般視窗；完成或取消金鑰操作後，主視窗仍維持最大化。
- [x] 使用還原按鈕，確認視窗可移動、調整大小，最小寬高限制仍生效；再最大化時版面可正常重排。
- [x] 關閉程式後重新啟動，確認仍預設最大化，不會記憶先前還原後的視窗大小。

回報格式：啟動最大化／標題列 __；金鑰登入期間維持最大化 __；還原／移動／調整大小 __；重啟預設最大化 __（每項填 PASS/FAIL + 簡短現象）。

## 條目刪除確認 — Win11-NB 本機 Console 驗收（D1–D5 PASS；D6 已免測）

僅使用可拋棄的合成測試條目；不得刪除真實資料或將密碼傳至聊天。自動化證據包含 Node VM 與隔離 headless Edge，皆使用合成 IPC／記憶體條目，不操作真實金庫或驗證器。來源 `c2409fa` 的 Windows CI 已通過，parent 已於 2026-10-04T15:35:44+08:00 建置 `real-ctap` Release GUI 並部署至 `C:\FidoVault\portable-fido-vault.exe`；獨立讀回 EXE SHA-256 `615378235e2f73752f39db5b85f0149f3401e4a5488935a545d5913b76ac97f0` 與本機新建 artifact 相符。部署後、使用者開始驗收前，原金庫 hash 與 1 個 key slot 均未變動，舊 EXE／金庫非覆寫備份已驗證。詳細 metadata 見 `docs/reports/entry-delete-confirmation-deployment.json`。未透過 WinRM 啟動 GUI 或操作金鑰；使用者已明確回報 D1–D5 PASS、D6 未測，並授權收尾與合併；不把 D6 記為 PASS，保留既有已接受 gates。

- [x] D1：一般權限開啟待驗版本，刪除測試列只開啟「確認刪除條目」，網站／帳號與不可復原警告正確，無密碼／歷史／備註；初始焦點在取消，Tab 留在 modal。
- [x] D2：取消、Esc 各一次，條目保留；重開選另一測試列正常，取消焦點下 Enter 不會批准刪除。
- [x] D3：只按明確「確認刪除」才刪除原始目標一次；另一測試條目不變。快速連點不能換目標或重複送出。
- [x] D4：搜尋結果內取消／確認後保留搜尋條件與正確筆數；刪除正在編輯的測試條目後編輯區與密碼／歷史清空。
- [x] D5：手動路徑先開啟確認、按「取消」，再按主畫面「上鎖」；原生 modal 開啟時外部 UI 為 inert，不能直接點外面的上鎖。閒置路徑可保持確認開啟，完全停止輸入至自動上鎖。兩條路徑各自返回登入；再次登入確認一次性合成測試條目仍在，無殘留確認。程式觸發手動 lock-start 與 modal 的交錯由 Node 自動測試涵蓋，不是實體滑鼠操作路徑。
- D6（已免測，不列待辦）：歷史失敗情境為刪除失敗顯示通用訊息且可重試／取消；刪除完成但重載失敗明確區分，不能再刪同一目標。歷史 NOT_TESTED 保留，不記為 PASS。

使用者回報（Discord message `1556211623264522241`）：「D1~5通過，D6未測，進行收尾和合併」。D1–D5 已勾選；D6 保留未勾選／未測，不推定失敗路徑實機通過。依此授權進行收尾與合併；僅更新明確回報項目，不延伸為其他 Gate 的人工 PASS。

目前裁決（使用者 message `1556265625158946837`）：條目刪除 D6 已免測、不再要求執行，排除於目前待辦；上述歷史未測紀錄不改為 PASS。

## 全庫 Rust 格式維護 — Win11-NB 使用者驗收（PR #18，整體 PASS）

- 已驗收 GUI 來源：`99ff0e5e537c5485f6fb65819f45662c2769c0a1`，Windows GNU Release（`--release --locked --features real-ctap`）。
- 目標：`C:\FidoVault\portable-fido-vault.exe`；7,173,120 bytes，SHA-256 `be089077c6a37d578e036338c77f4870d2c526c07dbb7e010f117873e6d214c2`。部署完成後、使用者啟動前獨立讀回相符。
- 備份：`C:\FidoVault\backup-rustfmt-99ff0e5-20261004-204309-c3957955`，舊 EXE／金庫備份雜湊均已驗證。部署前後 exact sibling `vault.db` hash 及 1 個 key slot 不變，既有 CLI／WebView2Loader 未替換；這些是部署時快照，非人工登入後即時狀態。
- 交接要求由使用者在 Win11-NB 本機 Console、一般權限操作，確認正常啟動／最大化、既有金鑰解鎖及 Windows 安全性提示前景、鎖定後主密碼解鎖。使用者於 `2026-10-04T21:03:42.075+08:00` 回報：「我驗證成功，進行收尾與合併」（message `1556290719763665058`）。據此記錄本次版本的**整體使用者驗收 PASS**及收尾／合併授權；回報未逐項展開，因此不新增逐項勾選或延伸其他歷史／跨機 gates。
- 詳細 metadata／provenance：`docs/reports/rust-format-deployment.json`；格式、測試、獨立審查與發布邊界見 `docs/reports/rust-format-verification.md`。本輪後續僅更新文件及已授權合併，不再部署、啟動 GUI、操作 WebAuthn 或覆寫金庫。

## WebAuthn 不可用時保留主密碼登入 — 正式部署（PR #25，2026-10-11）

- 驗收：2026-10-10 WS2 RDP W1–W6 PASS（重新導向關閉時程式開啟、主密碼登入、金鑰登入／註冊顯示繁中說明且槽數不變；重新導向開啟後金鑰登入；Win11-NB 本機 Console 金鑰登入）。詳見 `docs/reports/webauthn-unavailable-password-login-acceptance.md`。
- 部署：2026-10-11 00:13 經使用者授權，`C:\FidoVault\portable-fido-vault.exe` 更新為 7,206,912 bytes、SHA-256 `3b3f7367be81baab1a37c5249788f815c397b9e5241289880a3e6f7618996322`（來源 commit `5b943c7`，GNU Release `--locked --features real-ctap`）；部署後獨立讀回相符。
- 備份：`C:\FidoVault\backups\webauthn-unavailable-20261011-5073642`（舊 EXE `be089077c6a37d57…`、`vault.db` `b8423f97626309e0…`，hash 均已驗證）。部署前後 `vault.db` hash 與 1 個 key slot 不變；`WebView2Loader.dll`（簽章 Valid）與 `vault_cli.exe` 未替換。
- 部署後首次啟動（使用者回報「驗證成功」）：
  - [x] 在 Win11-NB 本機 Console 以一般權限開啟 `C:\FidoVault\portable-fido-vault.exe`，以主密碼或已註冊金鑰登入，確認既有條目正常。唯讀 log 佐證：2026-10-11 00:48 pid 5880，API v9，GetAssertion `credential_match=true`、32 bytes；登入寫入 audit 後 `vault.db` 仍為 1 個 key slot。
