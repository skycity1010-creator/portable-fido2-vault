# 可攜式 FIDO2 密碼金庫（portable-fido2-vault）— 專案彙整文件

> 彙整日期：2026-10-01｜建置機：WS2｜部署/驗證機：Win11-NB（`C:\FidoVault`）
> 本檔彙整 README.md、docs/spec.md、docs/user-verification-steps.md 與近期修復紀錄（§9），
> 作為單一入口文件；細節以各原始文件為準。

## 1. 專案概況

Windows 桌面、**完全離線**、**portable 免安裝**的 FIDO2 密碼金庫。
單一資料夾（`portable-fido-vault.exe + vault.db`）複製到任何 Windows 電腦即可使用。

- 首次執行建立帳號：主密碼經 **Argon2id** 派生金鑰
- 之後**主密碼或任一支已註冊 FIDO2 金鑰**皆可登入（允許多支）
- 金鑰類型：raw CTAP 可辨識指紋型 / PIN 型 / touch-only；Windows GUI 使用 `windows_managed`，由 Windows broker 提示驗證。
- **僅接受支援 CTAP2 hmac-secret/PRF 的金鑰**（如 YubiKey 5+）；不支援者拒絕註冊並顯示原因
- 加密：Argon2id + **AES-256-GCM**，整個金庫加密為單一檔案 `vault.db`
- CRUD ＋ created_at/updated_at ＋ 軌跡紀錄（絕不明文記錄密碼）＋ 閒置自動上鎖
- ⚠️ **無復原機制**：主密碼遺忘且所有 FIDO2 金鑰全失 = 資料永久無法取回（設計如此，UI 明示）

**非目標（v0.1）**：TOTP、密碼產生器、雲端同步、多使用者、行動裝置。

## 2. 架構與目錄結構

```
portable-fido2-vault/
├─ README.md                  簡易說明
├─ docs/
│  ├─ spec.md                 技術規格（本檔細化來源）
│  ├─ user-verification-steps.md  NB 桌面驗證步驟（使用者用，Gate 1–8）
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
10       N     header JSON（明文、僅金鑰包裝槽位，不含機密值）
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
- 離線：不開啟任何 socket；Tauri 未加 http/fs 外部插件。
- audit 僅記非機密資訊（事件、方式、site 名稱、失敗代碼）；**永不記錄密碼/PIN/金流**。
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
- 驗證（2026-10-01）：`cargo test --locked --features real-ctap --lib` 47/47；Release backend-mode 7/7；vendor `device_filter` 6/6；Gate E2E 20/20；login UI Node tests 4/4；Windows GNU Release GUI + CLI build 成功。
- 實體驗收已由使用者在 Win11-NB 互動桌面通過：舊 raw-CTAP 槽可由 Windows WebAuthn 解鎖、新金鑰註冊與登入成功，第二支 YubiKey NFC 交叉登入亦通過；不再執行原 Kanban 規劃的 raw-CTAP CLI 實體路線。
- 本次單一登入入口/提示前景修改：使用者確認 Win11-NB Console 啟動正常；H1、H3、H4、H5 通過。H2 部分通過（通用按鈕免選金鑰已確認，但 Windows 安全性操作畫面未置前）；commit `ab3d123` 的焦點修正候選已部署，GUI SHA256 `42D6DB566BEA217282D5BB487FA5DFB207B9252D2F3B1349938C4BB658AB2B58`，尚待本機 Console 驗收 H2。RDP-Tcp#0 Session 2 曾回報 WebAuthn API v1 並依 v4+ fail-closed；RDP redirection 未驗收，不可移除安全檢查。
- 建置檔參數：release `strip + lto`。

## 7. 部署（Win11-NB，WinRM）

- 部署目錄：`C:\FidoVault`（portable 資料夾＝全部資產）。
- 推檔：`python scripts/nb_push.py <file> [remote_dir]`
  - WinRM（`Invoke-Command -ComputerName Win11-NB -UseSSL:$false`）+ base64 chunk（200KB/次，
    outer 腳本走 stdin 避開 CreateProcess 8KB 上限）+ 落地 SHA256 驗證。
- Gate 1 驗證：`python scripts/nb_gate.py <exe> [vault_cli.exe]`
  - 推檔 → 啟動 GUI → 10s 存活檢查（過程 + WebView2 子程序當證據；session-0 無互動桌面，截圖仅供参考）
  - 有 vault_cli 時順帶 NB CLI E2E（Gate 8 跨機：create/register/login/add/list）。
- 注意：PS 5.1 讀無 BOM 腳本會當 ANSI(950) 解碼 → 所有遠端 PS 腳本純 ASCII（nb_push.py 已用 base64 內層迴避）。
- **實體 FIDO2 驗證需互動 session**（WinRM session-0 下 HID 存取行為不同，見 §9 根因）。

## 8. Gate 狀態（截至 2026-10-01）

| Gate | 內容 | 狀態 |
|---|---|---|
| 1 | portable + NB 一般權限直接啟動 | ⚠️ WebAuthn build 已部署且互動驗收；一般權限/Explorer 啟動條件未單獨確認 |
| 2 | 建立帳號/密碼登入/錯誤拒絕 | ✅（mock E2E，20/20） |
| 3 | 金鑰註冊+登入（實體） | ✅ Win11-NB Windows WebAuthn：註冊與登入通過 |
| 4 | 第二支金鑰/任一支可登入 | ✅ 第二支 YubiKey NFC 交叉登入通過 |
| 5 | CRUD + 時間戳 | ✅（mock E2E） |
| 6 | 軌跡完整/無明文密碼 | ✅（mock E2E） |
| 7 | 閒置自動上鎖 | ✅（先前 GUI 實測；新 build 未重測） |
| 8 | 加密檔直拷別機可解密 | ✅（mock E2E copy-test） |

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

## 10. 待驗證（2026-09-29 build，含 §9 修復）

部署機：Win11-NB `C:\FidoVault`（portable-fido-vault.exe / vault_cli.exe / WebView2Loader.dll）。
**實體金鑰流程需互動桌面 session**（登入 NB 後手動執行；WinRM session-0 的 HID 行為不同）。

1. **硬體 register（§9 重點）**：插入 YubiKey 5 → `vault_cli register-key --path vault.db --pw <pw> --authenticator hw`
   - 正常：成功註冊（fingerprint 型），audit 有 `key_registered`。
   - 若 handle 仍被鎖：**快速失敗並顯示 `DeviceOpenDenied` 訊息**（不再是 96s 後 `U2FToken(NotAllowed)`）；
     關閉其他占用金鑰的程序/拔插重試。
2. **硬體 login**：`vault_cli login-key --path vault.db --idx 0 --authenticator hw`（按指紋）→ 成功。
3. **GUI 硬體流程**：金鑰管理「＋ 註冊新金鑰」（hw）→ 上鎖 → 以該金鑰登入。
4. 既有 mock E2E 回歸：`python scripts/gate_e2e.py`（WS2）不受影響（23/23 測試通過）。

## 11. 相關專案

- `keycloak-fido2-logon-s4u-poc`（`C:\project\keycloak-fido2-logon-s4u-poc`，
  GitHub: skycity1010-creator/keycloak-fido2-logon-s4u-poc）：FIDO2 logon + S4U PoC（Windows CP/LSA AP）。
  本專案（portable-fido2-vault）為獨立密碼金庫應用，與之共用建置機（WS2）與測試機（Win11-NB）。
