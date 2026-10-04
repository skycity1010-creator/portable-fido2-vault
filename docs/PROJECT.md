# 可攜式 FIDO2 密碼金庫（portable-fido2-vault）— 專案彙整文件

> 彙整日期：2026-10-04｜建置機：WS2｜部署/驗證機：Win11-NB（`C:\FidoVault`）
> 本檔彙整 README.md、docs/spec.md、docs/user-verification-steps.md 與近期修復紀錄（§9），
> 作為單一入口文件；細節以各原始文件為準。
> 本次同步已確認驗收、讀回既有工程驗證紀錄，並執行全庫格式只讀檢查及本機 Node sanity checks；未重新建置、部署或重跑 Rust／Clippy。歷史部署雜湊與槽位數僅代表各次部署的快照，不代表本次重新回讀目標機。

## 1. 專案概況

Windows 桌面、**完全離線**、**portable 免安裝**的 FIDO2 密碼金庫。
單一資料夾（`portable-fido-vault.exe + vault.db`）複製到任何 Windows 電腦即可使用。

- 首次執行建立帳號：主密碼經 **Argon2id** 派生金鑰
- 之後**主密碼或任一支已註冊 FIDO2 金鑰**皆可登入（允許多支）
- 金鑰類型：raw CTAP 可辨識指紋型 / PIN 型 / touch-only；Windows GUI 使用 `windows_managed`，由 Windows broker 提示驗證。
- **僅接受支援 CTAP2 hmac-secret/PRF 的金鑰**（如 YubiKey 5+）；不支援者拒絕註冊並顯示原因
- 新增安全性金鑰時可設定 FidoVault 本機別名；沿用明文 header `KeySlot.label`，Rust 以 Unicode canonical caseless matching 提供唯一建議並在 authenticator 偵測前驗證，UI 警告勿輸入敏感資料
- 加密：Argon2id + **AES-256-GCM**，整個金庫加密為單一檔案 `vault.db`
- CRUD ＋ created_at/updated_at ＋ 每筆條目舊密碼歷史（預設 3 代，可設 1–20）＋ 條目密碼複製（60 秒後僅在剪貼簿內容仍相同時清除）＋ CSV 範本下載與批次匯入／更新（上限 1,000 列）＋ 軌跡紀錄（絕不明文記錄密碼）＋ 閒置自動上鎖
- 條目分頁即時搜尋網站、帳號及備註（不分大小寫的部分比對），不搜尋目前或舊密碼；清除查詢恢復完整清單。
- 主視窗每次啟動預設最大化（非全螢幕）；金鑰登入提示出現、完成或取消後維持最大化，仍可還原、移動及調整大小。
- ⚠️ **無復原機制**：主密碼遺忘且所有 FIDO2 金鑰全失 = 資料永久無法取回（設計如此，UI 明示）

**非目標（v0.1）**：TOTP、密碼產生器、雲端同步、多使用者、行動裝置。

## 2. 架構與目錄結構

```
portable-fido2-vault/
├─ README.md                  簡易說明
├─ docs/
│  ├─ spec.md                 技術規格（本檔細化來源）
│  ├─ user-verification-steps.md  NB 桌面驗證步驟（既有 Gate 流程與 Feature 1–7 驗收紀錄）
│  └─ PROJECT.md              ← 本檔（彙整）
├─ src/                       前端（純靜態 HTML/JS/CSS，繁中 UI）
├─ src-tauri/                 Tauri v2 (Rust) 後端
│  ├─ src/lib.rs              Tauri commands + VaultState（Mutex）+ make_backend
│  ├─ src/vault.rs            金庫格式 / 載入 / 建立 / 加密落盤
│  ├─ src/crypto.rs           Argon2id / AES-256-GCM / HKDF
│  ├─ src/fido2.rs            FidoBackend trait + MockBackend / RealBackend（CLI raw CTAP）
│  ├─ src/windows_webauthn.rs  Windows GUI broker backend + raw-salt hmac-secret
│  ├─ src/diag_log.rs         診斷 log（real-ctap feature）
│  └─ examples/vault_cli.rs   E2E 測試 CLI（Gate 驗證用）
├─ scripts/
│  ├─ nb_push.py              WinRM base64-chunk 推檔到 Win11-NB + SHA256 驗證
│  ├─ nb_gate.py              Gate 1 NB 遠端驗證（啟動存活 + WebView2 子程序 + 截圖 + CLI E2E）
│  └─ gate_e2e.py             本機 CLI E2E
└─ vendor/authenticator-rs/   vendored mozilla authenticator-rs v0.6.1（ctap2 + crypto_rust）
```

- **狀態**：解鎖後 KEK（32B，`Zeroizing<[u8;32]>`）與金庫資料僅存於記憶體；上鎖即清零。
- **落盤策略**：任何變更 → 以記憶體 KEK 重新加密整個 payload → 暫存檔 + rename 原子寫入。
- **後端選擇**：Windows GUI Release 若編入 `real-ctap`，未設定環境變數時預設使用 Windows WebAuthn API；Windows 安全性視窗管理金鑰選擇與 PIN/UV/觸碰。此路徑供一般權限的 Explorer 啟動；要求 WebAuthn API v4+。Debug 預設 MockBackend。`F2V_AUTHENTICATOR=mock|hw` 可明確覆寫；Release 缺少 `real-ctap` 時拒絕啟動。`vault_cli --authenticator hw` 仍走 authenticator-rs raw CTAP/HID，不等同 GUI backend。

## 3. 金庫格式與加密（vault.db v1）

```
offset   size   field
0        6      magic "F2VLT\x01"
6        4      header_len u32 LE
10       N     header JSON（明文金鑰包裝區；不含密碼/金鑰機密，`key_slots[].label` 為明文顯示別名）
10+N     12    payload nonce（AES-GCM 96-bit）
22+N     …     AES-256-GCM(KEK, vault_json) — 含 16B tag 於尾端
```

| 項目 | 演算法 / 參數 |
|---|---|
| 主密碼 KDF | Argon2id t=3, m=19456 KiB, p=4, salt 32B（登入延遲 ~0.5s） |
| 對稱加密 | AES-256-GCM，nonce 每次隨機 12B |
| 金鑰槽 KEK 派生 | HKDF-SHA256(ikm=PRF secret 32B, salt=`f2vlt-domain-v1`, info=`f2vlt-kek-wrap-v1`) |
| PRF salt（固定） | `f2vlt-prf-salt-v1`（32B domain separation，非機密） |

- **密碼登入**：Argon2id → AES-GCM 解 password_slot.ct → KEK → 解 payload。
- **金鑰登入**：Windows GUI 透過 Windows WebAuthn API `GetAssertion` 取得 hmac-secret，明確要求 raw salt 以保持 vault slot 相容；CLI 直接執行 CTAP2 `getAssertion(allow=[cred_id], hmac-secret)`。兩者回傳 S(32B) → HKDF → 解該槽 ct → KEK。
- **設計要點（仿 LUKS 多槽位）**：KEK 從不明文落盤；每個解鎖方式各自包裝同一份 KEK；
  增刪金鑰只改 header、不需重加密 payload。

## 4. FIDO2 流程

### 註冊（金庫已解鎖）
0. CLI raw-CTAP 以 `getInfo.extensions` 預查 hmac-secret；Windows GUI 的 WebAuthn API 無 CTAP `getInfo`，註冊時要求 hmac-secret 並檢查 extension output。若 Windows 未確認支援，vault 不寫入槽位，但 authenticator 端可能已留下未採用的 credential。
1. Windows GUI 使用 WebAuthn API v4+、RP ID `fido-vault.local`、cross-platform attachment；Windows broker 負責選擇外接金鑰及 PIN/UV/觸碰提示。CLI/診斷保留 raw CTAP getInfo / BioEnrollment。
2. `makeCredential(rp_id="fido-vault.local", residentKey=preferred, extensions={hmac-secret})` → credentialId + AAGUID。
3. Windows GUI assertion 設 raw HMAC-secret values flag，使用既有 32-byte vault salt，不採用 PRF domain transform；CLI 使用相同 salt 的 CTAP hmac-secret。兩條路徑共用既有 slot 格式。
4. PRF secret 派生槽位金流 → 包裝 KEK → 寫 header.key_slots；audit `key_registered`。

### 登入提示
| type | UI 提示 |
|---|---|
| fingerprint | 「請插入金鑰並**按指紋**」 |
| pin | 「請插入金鑰並**輸入 PIN**」 |
| touch_only | 「請插入金鑰並**觸碰**」 |
| windows_managed | 「請依 Windows 安全性提示完成驗證」 |

多支金鑰：每支獨立槽位，任一支成功即解鎖。

### Windows backend 選型
- Windows GUI Release 使用 Microsoft Windows WebAuthn API，預期支援一般權限直接啟動，不自行開啟 raw HID。
- `vault_cli --authenticator hw` 及底層診斷保留 mozilla `authenticator-rs` raw CTAP/HID；Windows 對此路徑可能套用存取限制，不能代表 GUI 的一般使用者體驗。
- WebAuthn API v4+ 可回傳 HMAC-secret assertion；`WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG` 讓 Windows 傳入原始 vault salt，保留舊槽相容性。

## 5. 安全模型

- 金庫檔案外洩（無解鎖因子）→ payload AES-256-GCM 不可解；header 僅包裝槽位。
- 無復原（設計如此）；移除金鑰不可逆。
- 離線：不開啟任何 socket；未加 http/fs 插件；Clipboard Manager 僅寫入本機剪貼簿，條件清除使用 Win32 鎖定後比對/清除。
- audit 僅記非機密資訊（事件、方式、site 名稱、失敗代碼）；**永不明文記錄密碼/PIN/金流**。複製狀態與 app 診斷 log 不含密碼明文。系統其他程式或 Windows 剪貼簿歷程/雲端功能仍可能在清除前讀取、保存或同步剪貼簿內容。
- 已知限制（v0.1）：單機單使用者；檔案權限依賴 OS 使用者權限；不防執行中記憶體 dump。

## 6. 建置（WS2 建置機）

前置：
- Rust **stable-x86_64-pc-windows-gnu** toolchain（WS2 無 MSVC/VS，走 GNU 免 UAC）。
- **winlibs-mingw**（posix-seh x86_64）提供 dlltool.exe（Rust GNU toolchain 不自帶 binutils）：
  `PATH += $HOME/tools/winlibs-mingw/mingw64/bin`。
- WebView2（Win11 內建；portable 資料夾需同梱 `WebView2Loader.dll`）。

```bash
# bash / git-bash（WS2）
export PATH="$HOME/.cargo/bin:$HOME/tools/winlibs-mingw/mingw64/bin:$PATH"
cd C:/project/portable-fido2-vault/src-tauri
cargo +stable-x86_64-pc-windows-gnu build --release --features real-ctap --bin portable-fido-vault --example vault_cli
# 產出 target/release/portable-fido-vault.exe + vault_cli.exe
```

- `--features real-ctap`：編入實體 FIDO2 支援；Windows GUI 使用系統 WebAuthn API，CLI `--authenticator hw` 使用 raw CTAP/HID。
- Windows Release GUI 無需 `F2V_AUTHENTICATOR` 或系統管理員權限即可走 brokered backend；Debug 預設 mock，mock demo 可明確設 `F2V_AUTHENTICATOR=mock`。
- 歷史驗證與部署（截至 2026-10-02）：MSVC `cargo test --lib --locked --features real-ctap` 64/64；Release backend-mode 7/7；Node UI 24/24（Feature 4 targeted 5/5）；`node --check src/app.js`、`git diff --check` 通過。Windows GNU Release GUI + CLI（`--locked --features real-ctap`）建置成功；GUI 6,729,216 bytes，SHA-256 `7deba32418fb173d5ada126e600c81a748ffa51bcfe503afc7bed683fb928ed1`；CLI 2,427,392 bytes，SHA-256 `1493ab5d09fb942a61f77cc9e82827b2fa08f60e3e74d81e5d1cd657771ab3c2`。當時 `cargo clippy -D warnings` 受 11 個既有其他模組警告阻擋，新增別名路徑無相關警告；此歷史限制已由後續 PR #12 處理，PR #11/#12 已合併，既有整合驗證與 main CI 讀回結果見 §15（本次未重跑）。Feature 4 獨立 review 已通過並部署至 Win11-NB（GUI 目標端 SHA-256 `7deba32418fb173d5ada126e600c81a748ffa51bcfe503afc7bed683fb928ed1`）；舊 EXE 與 vault 均有驗證備份，部署前後 live vault hash 不變、3 slots。使用者於 2026-10-02 確認 Feature 2、3、4 集中 Win11-NB 本機 Console 驗收全部通過；Feature 1 先前亦已通過。此 GUI 部署快照已由後續 Feature 5–7 部署取代（superseded）。
- 實體驗收已由使用者在 Win11-NB 互動桌面通過：舊 raw-CTAP 槽可由 Windows WebAuthn 解鎖、新金鑰註冊與登入成功，第二支 YubiKey NFC 交叉登入亦通過；不再執行原 Kanban 規劃的 raw-CTAP CLI 實體路線。
- 2026-10-01 單一登入入口/提示前景修改（歷史紀錄，GUI 版本已由後續功能部署取代）：使用者確認 Console 啟動正常；H1、H3、H4、H5 通過。H2 通用按鈕免選金鑰通過；上一候選的安全性視窗仍在背景。Console 唯讀 EnumWindows 探測確認 FidoVault 前景 z-order 17，獨立 `CredentialUIBroker`「Windows 安全性」視窗 z-order 18、`OWNER=0`。新增窄範圍 best-effort broker-window monitor：baseline 所有 top-level HWND 與既有 broker PID，只針對唯一的新同-session System32 CredentialUIBroker 視窗，在 FidoVault 仍為 foreground 時嘗試一次 SetForegroundWindow；不設 topmost、不用 ASFW_ANY。程式碼獨立審查通過；commit `45d3aa6` 已推至 PR #3 branch；Rust 53/53、UI 4/4、Windows GNU Release build 成功。該 commit 的新 GUI 已部署至 Win11-NB，SHA256 `59BBAB25C21A419702D02FA7E97242392C388149432BAF733AC0C715F06085D8`，6,140,928 bytes；舊 exe 備份 `C:\FidoVault\portable-fido-vault.exe.pre-H2focus-20261001-223428-2985cea4.bak`。vault 備份 `C:\FidoVault\vault.db.pre-H2focus-20261001-223428-2985cea4.bak`；部署前後均為 3 slots、SHA256 `58A1D4877C2274B3D403E1D87CD1E9BA7C5404D450C3F69E1D9486501F02D780`。本機 Console H2 測試已由使用者確認 OK：通用登入免選金鑰，Windows 安全性操作提示置前；H2 驗收通過並結案。前景交接仍是 best-effort。RDP-Tcp#0 Session 2 曾回報 WebAuthn API v1，維持 v4+ fail-closed；RDP／WebAuthn redirection 不支援，並已在 README 明確說明；硬體驗收使用本機 Console session。
- 建置檔參數：release `strip + lto`。

## 7. 部署（Win11-NB，WinRM）

- 部署目錄：`C:\FidoVault`（portable 資料夾＝全部資產）。
- 推檔：`python scripts/nb_push.py <file> [remote_dir]`
  - WinRM（`Invoke-Command -ComputerName Win11-NB -UseSSL:$false`）+ base64 chunk（200KB/次，
    outer 腳本走 stdin 避開 CreateProcess 8KB 上限）+ 落地 SHA256 驗證。
- 歷史 Gate 1 腳本：`python scripts/nb_gate.py <exe> [vault_cli.exe]`
  - 當時流程為推檔 → session-0 啟動 GUI → 10s 存活檢查（程序 + WebView2 子程序；截圖僅供參考）。此流程已由本機 Console GUI 驗收取代（superseded），不可作為目前的 GUI／WebAuthn 操作方式。
  - 腳本有 vault_cli 時會在 NB 新建測試金庫並執行 mock CLI E2E；此腳本本身未搬移既有金庫，不構成既有金庫或實體 GUI 跨機人工驗收證據。
- 注意：PS 5.1 讀無 BOM 腳本會當 ANSI(950) 解碼 → 所有遠端 PS 腳本純 ASCII（nb_push.py 已用 base64 內層迴避）。
- **GUI／實體 FIDO2 驗證僅由使用者在本機 Console 互動 session 操作**；WinRM 僅供唯讀檢查、備份與核准部署，不啟動 GUI 或執行 WebAuthn。RDP／WebAuthn redirection 不支援，不是待驗項。

## 8. Gate 與功能驗收狀態（彙整至 2026-10-04；最新功能驗收為 2026-10-03）

| Gate | 內容 | 狀態 |
|---|---|---|
| 1 | portable + NB 一般權限直接啟動 | ✅ 使用者確認 G1/G3 驗收通過：一般權限、檔案總管啟動 |
| 2 | 建立帳號/密碼登入/錯誤拒絕 | ✅（mock E2E，20/20） |
| 3 | 金鑰註冊+登入（實體） | ✅ Win11-NB Windows WebAuthn：註冊與登入通過 |
| 4 | 第二支金鑰/任一支可登入 | ✅ 第二支 YubiKey NFC 交叉登入通過 |
| 5 | CRUD + 時間戳 | ✅（mock E2E） |
| 6 | 軌跡完整/無明文密碼 | ✅（mock E2E） |
| 7 | 閒置自動上鎖 | ✅ 使用者確認驗收通過（D1–D4） |
| 8 | 加密檔直拷別機可解密 | ✅ mock E2E copy-test 通過；此結論限於 mock 測試，未見實體 GUI 跨機人工 PASS 回報 |
| 9 | 每筆條目舊密碼歷史（預設 3，可設 1–20） | ✅ 使用者於 2026-10-02 確認 Feature 2/3/4 集中本機 Console 驗收全部 PASS，已取代先前延後狀態 |
| 10 | 條目複製密碼（60 秒 Win32 原子條件清除） | ✅ 同次 2026-10-02 集中驗收全部 PASS；60 秒清除、外部替換保留與連續複製結果見使用者驗收文件 |
| 11 | 註冊時設定安全性金鑰本機別名 | ✅ 同次 2026-10-02 集中驗收全部 PASS；別名驗證、註冊與重登入結果見使用者驗收文件 |

### 已確認功能彙整

| Feature | 內容 | 使用者確認（Win11-NB 本機 Console） |
|---|---|---|
| 1 | 密碼欄位遮罩 | ✅ 2026-10-01 PASS |
| 2 | 舊密碼歷史 | ✅ 2026-10-02，Feature 2/3/4 整體 PASS |
| 3 | 密碼複製與 60 秒條件清除 | ✅ 2026-10-02，Feature 2/3/4 整體 PASS |
| 4 | 安全性金鑰本機別名 | ✅ 2026-10-02，Feature 2/3/4 整體 PASS |
| 5 | CSV 範本、批次匯入／更新 | ✅ 2026-10-03 全項 PASS（PR #13；§12） |
| 6 | 條目即時搜尋 | ✅ 2026-10-03 明確 PASS（PR #14；§13） |
| 7 | 預設最大化與金鑰登入期間維持最大化 | ✅ 2026-10-03 明確 PASS（PR #15 修正版；§14） |

PR #13/#14/#15 均已合併；8 張 `[FidoVault]` Kanban 卡均為 done。驗收、PR 合併與任務完成不等同所有舊模板都逐項人工 PASS：`user-verification-steps.md` 的 A–C/E/F 保留未勾選，D5 為未回報的選測；Gate 8 仍僅有上述 mock 證據。RDP 為不支援、raw CTAP CLI 實體路線為已退役／由 GUI 驗收取代（superseded），均不是待驗項。

## 9. 2026-09-29 Win11-NB log 問題：根因與修復

### 症狀
`vault_cli register-key --authenticator hw` 於 Win11-NB 失敗：
`FAIL register_key elapsed_ms=96329 :: U2FToken(NotAllowed)`（`C:\FidoVault\reg.out`）。
`fido2-diag.log`（pid=10844，17:06:17.674 → 17:07:54.010，共 96.3s）顯示 3 次 detect 重試。

### 根因（log 重建 timeline）
1. `register_key` → `RealBackend::detect()` → `retry_on_contention("detect", get_info)`。
2. 每次 attempt（30s timeout）內**機器上全部 HID 裝置**（鍵盤 vid_045e、滑鼠 vid_046d、
   Intel vid_03eb、YubiKey vid_1050）open 皆 `os error 5/32`（Access denied / Sharing violation）→
   30s 無 callback → vendor（authenticator-rs）回 timeout fallback `U2FToken(NotAllowed)`。
3. contention 偵測器正確判出 open-denied 並重試 3 次（backoff 2s/4s）→ 96.3s 耗盡。
4. `register_credential` **從未執行**；尾端 29 筆「Removing device」= USB 重枚舉。
5. **最終錯誤 `U2FToken(NotAllowed)` 是 vendor timeout fallback，遮蔽真正原因**
   （device handle 被外部 process/USB session 鎖定），誤導為「金鑰拒絕」。

環境探查（09-29）：YubiKey 在位、無 process 佔用、無互動 session → 當時為 transient/會話性狀態
（09-28 17:06 的機器級 HID 存取被拒與 session 狀態相關）。

### 修復（`src-tauri/src/fido2.rs`，2026-09-29，32+/1−）
1. 新增 `FidoError::DeviceOpenDenied { what, last_err, attempts }` —
   點名「FIDO HID open 被拒（os error 5/32），handle 被外部 process/USB session 鎖定」的獨立錯誤。
2. `Display` 對用 arm：明確提示「請關閉其他使用該金鑰的程序（FidoVault/瀏覽器 FIDO/遠端 session）或拔插後重試」。
3. `retry_on_contention`：重試耗盡（attempt==MAX_ATTEMPTS=3）**且**本次 attempt log 已確認
   FIDO HID open-denied → 回傳 `DeviceOpenDenied`（附 vendor 最終錯 + 重試次數），
   取代模糊的 `U2FToken(NotAllowed)`/`CancelledByUser`。重試機制本身保留（contention 仍會重試暫時佔用）。

影響面：`FidoError` 唯一 exhaustive match 為 `Display`（已補 arm）；`vault.rs` 的
`From<FidoError> for VaultError` 為 blanket wrap（`Self::Fido(e)`），新 variant 自動流通，無斷裂。

### 驗證（WS2）
- `cargo check --features real-ctap --lib`（MSVC）：通過。
- `cargo test --features real-ctap --lib`：**23 passed / 0 failed**。
- release build（GNU + `--features real-ctap`，含 `vault_cli`）：產出後部署 NB。

## 10. raw CTAP CLI 硬體路線（非目前驗收範圍）

2026-09-29 build 的 `vault_cli --authenticator hw` register/login 驗證曾列為待辦；後續產品 GUI 硬體驗收改採 Windows WebAuthn API，並已由使用者在 Win11-NB 本機 Console 完成 G4–G6 與 H1–H5 驗收。**raw CTAP CLI 的實體 register/login 不再是目前驗收項目**；`vault_cli` 仍保留作為獨立診斷路徑，若未來要將 CLI 硬體流程納入支援範圍，再另行驗證。Mock E2E 與自動化測試結果見 §6。

## 11. 相關專案

- `keycloak-fido2-logon-s4u-poc`（`C:\project\keycloak-fido2-logon-s4u-poc`，
  GitHub: skycity1010-creator/keycloak-fido2-logon-s4u-poc）：FIDO2 logon + S4U PoC（Windows CP/LSA AP）。
  本專案（portable-fido2-vault）為獨立密碼金庫應用，與之共用建置機（WS2）與測試機（Win11-NB）。

## 12. Feature 5 — CSV 批次匯入／更新與範本下載

- 使用者於 2026-10-03 確認 Win11-NB 本機 Console 驗收項目全部通過；PR #13 已合併。逐項結果見 `docs/user-verification-steps.md` 的 Feature 5 區段。
- Release GUI 來源 commit `f33eea8d24fd77e1a85e9a59e409ba8ddf9cbfa3`，Win11-NB 目標 SHA-256 `1e2d22aba57f394a7b41e5500fa9deccaf3d414cfa7870699a0c7862ea73db82`。舊 GUI 與 vault 均已建立並驗證備份；部署前後 live vault hash 相同、key-slot 數為 1。
- 歷史驗證（Feature 5 候選當時）：Rust 74/74、Node 29/29、Release backend-mode 7/7、vendor 6/6；Release GUI/CLI build、scoped rustfmt 與 `git diff --check` 通過。當時 `clippy -D warnings` 有 11 項既有、非本次變更檔案的診斷；當時此 PR head 未找到 hosted Actions run。這些是候選當時的紀錄，已由 PR #11/#12 後續工程收尾與 §15 的精確 main CI 讀回結果取代（superseded），不是目前的 Clippy／CI 結論；本次未重跑。上述部署快照亦已由後續 Feature 6/7 部署取代，保留來源與雜湊供追溯。

## 13. Feature 6 — 條目介面即時搜尋

- 使用者於 2026-10-03 明確確認 Win11-NB 本機 Console 驗收 PASS；PR #14 已合併。規格與既有測試結果見 `docs/plans/feature-06-entry-search.md`，人工驗收紀錄見 `docs/user-verification-steps.md` 的條目介面即時搜尋區段。
- 已解鎖條目分頁以記憶體資料即時比對網站、帳號及備註，不分大小寫；不讀取或比對目前／舊密碼，也不持久化查詢或寫入 audit。
- 清除／空白查詢恢復全列表；零結果與空金庫分開提示；列操作仍作用於正確條目，CRUD／CSV 重載後保留目前查詢。既有 Node UI、語法與 diff 檢查結果是當時驗證，本次僅同步文件。

## 14. Feature 7 — 主視窗預設最大化與金鑰登入狀態保持

- 使用者於 2026-10-03 明確確認 Win11-NB 本機 Console 驗收 PASS：啟動最大化（非全螢幕）、金鑰登入提示出現與完成／取消後維持最大化、可還原／移動／調整大小、重新啟動仍預設最大化。PR #15 原先 stacked on PR #14，兩者均已合併。
- 初次版本 commit `a7fb6a0` 曾在金鑰登入時還原視窗，已由修正版取代（superseded），不是待驗收候選。前景處理僅在視窗已最小化時 restore，不改變可見最大化／一般視窗的狀態；規格見 `docs/plans/feature-07-default-maximized-window.md`。
- 最近一次已記錄 GUI 部署（2026-10-03）來源 fix commit `1bf77fd23d27dcea2235821fc36bc74a21c269db`；`C:\FidoVault\portable-fido-vault.exe` 為 7,172,096 bytes，SHA-256 `0910d0cd5f29518e83c5ebd60b562572165adda91fae335f4771a386f52570f6`。來源 commit、雜湊、大小與下列備份紀錄皆逐字取自 `docs/user-verification-steps.md`，本次未部署或重新回讀目標機。
- 當時部署前備份目錄 `C:\FidoVault\backups\key-login-maximized-20261003-1bf77fd`；舊 GUI SHA-256 `a874a96026e1c2a6baa7857a9fe3c7b564758347f2458aba5bd254ddd70e2092`，vault SHA-256 `35b669a0c720314ccb9f602faa89b7e8b5adf82d09f1c43831f40f5968fdf1a1`。當時部署後 GUI hash 相符、vault hash 不變、header 有效且有 1 個 key slot；無相關程序、持久 authenticator override 或傳輸暫存檔，WinRM 未啟動 GUI。較早部署與備份紀錄保留於使用者驗收文件，不把歷史 3-slot 快照當作本次槽位數。

## 15. 2026-10-04 工程收尾紀錄（區分既有驗證讀回與本輪檢查）

- 文件維護基準為 main `18134cbe5ae603dd502f5be59b6cbb8520933dd3`（Merge PR #12: verified Clippy baseline cleanup）；本輪文件變更不修改 Rust／前端程式碼，不部署或操作 WebAuthn。
- 工程收尾流程已重新讀回：PR #11 為 MERGED，merge commit `8f34ccd10a24d9561fa09d10500e1ef7fff6c34e`；PR #12 為 MERGED，merge commit `18134cbe5ae603dd502f5be59b6cbb8520933dd3`。兩者由其他授權流程完成合併，並非本次文件維護執行。
- PR #12 既有整合收尾紀錄針對 exact-head `66d18317`：測試 75/75、Clippy 無 diagnostics、local Node 38/38。這是已完成驗證的讀回紀錄，不宣稱本次重新執行，亦不將該 exact-head 測試冒充為 main commit 的本機重跑。
- 工程收尾流程以 Actions REST 對精確 main `18134cbe5ae603dd502f5be59b6cbb8520933dd3` 讀回 1 個 run：`37177652514`，event=`push`、status=`completed`、conclusion=`success`、updated_at=`2026-10-04T04:55:56Z`。此結果僅對應該 main SHA，不延伸為其他 revision 或所有品質檢查的證據。
- 本輪在該 main SHA 的獨立 worktree 實跑 `cargo fmt --all -- --check`：exit code 1，14 個檔案、94 個 Diff blocks（src-tauri：7 檔／83 blocks；vendor：7 檔／11 blocks），未通過。未執行格式修正；歷史 scoped rustfmt 不等同全庫格式檢查。
- 同一 SHA 的本機 Node suite 38/38、`node --check src/app.js` 與 `git diff --check` 通過；文件另核對原有驗收勾選及部署雜湊未遭改動。本機 main／origin/main 已同步，計畫與建置 log 原位保留並加入本機 ignore；整理前 17 個檔案已備份並逐檔驗證。完整盤點見 `docs/reports/2026-10-04-maintenance-audit.md`。
