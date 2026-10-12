# 單人版 Windows Hello 登入／解鎖（windows-hello-single）

> 狀態：設計完成，**尚未授權實作**（Kanban 卡 blocked，等使用者說「開始 D1」）。
> 範圍：只有單人版 `portable-fido-vault.exe`。雙群組控管版（`portable-fido-vault-dual.exe`，v2）**不動**。

## 0 目標

在單人版（v1 金庫）新增「Windows Hello」作為第三種解鎖方式，與 YubiKey、主密碼並存，任一可解鎖。
Windows Hello 必須以密碼學綁定金庫（PRF／hmac-secret 包裝 KEK），不得只是 UI 層的放行。

## 1 已確認決策

| Q | 問題 | 決策 |
|---|---|---|
| Q1 | Windows Hello 的角色 | (a) 新增，與 YubiKey、主密碼並存，任一可解鎖 |
| Q2 | 登入／解鎖範圍 | (a) 啟動登入與手動鎖定／閒置鎖定後解鎖皆可用 |
| Q3 | 數量限制 | (a) 每台電腦 × Windows 帳號最多一個 Windows Hello slot（excludeCredentials），不同電腦可各註冊一個 |
| Q4 | 刪 slot 時 | (a) 一併 `WebAuthNDeletePlatformCredential`；失敗只提示、不阻擋刪除 |
| Q5 | 平台不支援時 | (a) 註冊／登入時明確提示需求，不影響 YubiKey／主密碼 |
| Q6 | 格式 | (a) 維持 v1，`KeySlot` 新增 optional `authenticator: "platform"` |
| Q7 | 金鑰管理畫面 | (a) 單一列表，標示「Windows Hello（本機 COMPUTERNAME）」 |
| Q8 | 開發順序 | (a) 先做 S0 spike，通過後才寫本文件 → **已通過**（見 §1.1） |
| — | S0 結果後的方向 | 方案 A'：維持 WebAuthn + PRF，限定在「斷言時可取得 PRF」的電腦；註冊時實測，不支援就拒絕 |

### 1.1 S0 spike 結論（2026-10-12，證據：`D:\scratch\windows-hello-s0-20261012\DECISIONS-AND-S0.md`）

| 電腦 | 環境 | 結果 |
|---|---|---|
| Win11-NB | 24H2 26100.9457、TPM 1.2、software KSP、網域帳號、PIN | 建立：ES256-only → Ngc `0x80090029`；加 RS256 後成功，v8 PRF-on-create 有輸出；**斷言要求 PRF 一律 Ngc `0x8009000B` NTE_BAD_KEY_STATE**（Edge + Corbado PRF demo 同樣失敗 → 平台限制）；無 salt 斷言成功；excludeCredentials → `0x8009000F` 無提示；列出／刪除可用 |
| SKYCITY-PC | 26H2 26300.9457、臉部辨識 | **全數通過**：v8 PRF-on-create 32B；無 salt、global raw、per-credential raw、PRF 模式斷言皆 Success 32B、credential_match；create 輸出 = global raw = per-credential raw（決定性）；列出／刪除可用；建立提示框在前景 |

可直接沿用的技術事實：
- 平台路徑 COSE 參數必須是 `[ES256, RS256]`（TPM 1.2／software KSP 只產 RSA）。
- PRF 必須走 API v8：MakeCredential options v8 `pPRFGlobalEval` + `dwFlags=WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`，讀 attestation v7 `pHmacSecret`；舊的 `hmac-secret` extension／v6 `bEnablePrf` 單獨使用時 `bPrfEnabled=false`。
- 斷言用現行的 global raw salt（`crypto::prf_salt_bytes()` + raw flag）即可，與 YubiKey slot 的 KDF 相同。
- 建立時有 PRF ≠ 斷言時有 PRF（Win11-NB），所以註冊必須額外做一次斷言驗證。

## 2 密碼學設計

```
vault.db (v1，格式不變)
├─ password_slot : AES-GCM( Argon2id(主密碼), KEK )
├─ key_slots[]   : AES-GCM( HKDF(hmac-secret 輸出), KEK )
│    ├─ YubiKey slot      （authenticator 欄位不存在 = roaming）
│    └─ Windows Hello slot（authenticator = "platform"；同一 KDF、同一 salt）
└─ payload       : AES-GCM( KEK, 資料 )
```

- Windows Hello slot 與 YubiKey slot 用**完全相同**的 wrap/unwrap 程式路徑（`open_with_key_secret`），只差 backend 呼叫參數。不新增 KDF、不改 AAD。
- `authenticator` 欄位是未認證的明文 metadata，只用來決定「用哪種 attachment 去要 PRF」。竄改它不會讓攻擊者解開 KEK（仍需該 credential 的 PRF 輸出），最多造成該 slot 無法使用。

| 攻擊者持有 | 結果 |
|---|---|
| 只有 `vault.db` | 無法解鎖（需主密碼、YubiKey，或註冊電腦上的 Windows Hello） |
| `vault.db` + 另一台電腦 | Windows Hello slot 無效（credential 只存在原電腦 TPM／Windows 帳號） |
| 原電腦的 Windows 帳號工作階段 + Windows Hello PIN 或生物辨識 | 可解鎖（這是本功能的設計強度：電腦 + Windows Hello UV，低於 YubiKey） |
| 改 header 把 YubiKey slot 標成 platform（或反之） | 該 slot 無法使用，KEK 不外洩 |

## 3 檔案格式

v1 不變，`KeySlot` 新增：

```json
{
  "credential_id": "…", "aaguid": "…", "label": "Windows Hello（本機 SKYCITY-PC）",
  "key_type": "WindowsManaged",
  "authenticator": "platform",
  "nonce": "…", "ct": "…"
}
```

- `#[serde(default, skip_serializing_if = "Option::is_none")] authenticator: Option<SlotAuthenticator>`；enum 只有 `platform`，大小寫嚴格，未知值反序列化失敗（fail closed）。
- 沒有 Windows Hello slot 的 v1 檔案序列化結果與現行 byte-for-byte 相同（GREEN→GREEN 回歸）。
- v2（雙群組）任何 slot 帶 `authenticator` → `Format` 錯誤，不解密。
- 舊版程式相容：v1 未啟用 `deny_unknown_fields`，舊 exe 可讀；但**舊 exe 存檔會丟掉 `authenticator` 欄位**（見 R3）。

## 4 行為規格

### 4.1 可用性檢查（不跳提示）
`platform_status` 回傳：
- `api_ok`：`WebAuthNGetApiVersionNumber() >= 8`
- `uvpa`：`WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable`
- `console`：本機 Console session（沿用 `windows_webauthn.rs` 的 local-console 判斷；RDP／session 0 不提供）
- `local_credential`：`WebAuthNGetPlatformCredentialList(rp=fido-vault.local)` 與金庫內 platform slot 的 credential ID 交集

### 4.2 註冊（金鑰管理 →「＋ 註冊 Windows Hello」）
1. 前置：已解鎖、單人版、`api_ok && uvpa && console`，否則顯示需求訊息（Q5）。
2. MakeCredential：`PLATFORM`、UV required、resident key required、COSE `[ES256, RS256]`、options v8 + `bEnablePrf` + `pPRFGlobalEval`(vault salt, raw flag)、excludeCredentials = 金庫內所有 platform slot 的 credential ID。
   - `NTE_EXISTS` → 「這台電腦已註冊 Windows Hello」（Q3）。
3. 要求 attestation `bPrfEnabled=true` 且 `pHmacSecret` 32 bytes，否則 fail closed。
4. **斷言驗證**（第二次 Windows Hello 提示）：allowList=[新 credential]、global raw salt；輸出必須 32 bytes 且等於步驟 3 的輸出。失敗（含 NTE_BAD_KEY_STATE）→ 刪除剛建立的 platform credential，顯示「此電腦的 Windows Hello 不支援金庫解鎖所需的 PRF」，不寫入 slot。
5. 用驗證後的 PRF 輸出 wrap KEK，新增 slot（label「Windows Hello（本機 COMPUTERNAME）」、`authenticator: platform`），寫檔 + 稽核 `register_key:windows-hello:<fp>`。
6. 寫檔失敗 → 刪除剛建立的 platform credential（best effort），回報錯誤。

### 4.3 登入／解鎖（Q2）
- 登入畫面：`local_credential` 為真才顯示「使用 Windows Hello 登入」。
- GetAssertion：`PLATFORM`、UV required、allowList = 本機有的 platform slot IDs、global raw salt。
- 回傳 credential ID 必須在 platform slot 內（不信任 backend 選擇）。
- 現有「使用金鑰登入」改為只送 roaming slot 的 credential ID（避免把 platform ID 交給 YubiKey 路徑）。
- 失敗紀錄：沿用 sidecar，method `windows-hello:<label>`；使用者取消不紀錄（與 YubiKey 相同）。

### 4.4 刪除（Q4）
- 刪 slot 照現有流程寫檔；成功後若此 credential 在本機清單中，呼叫 `WebAuthNDeletePlatformCredential`；失敗或不在本機 → 提示「已從金庫移除；Windows 中的通行金鑰需到 設定 → 帳戶 → 通行金鑰 手動刪除」，不回滾。

### 4.5 雙群組版
- vault 層：`register_platform_*` 對 v2 金庫在觸碰 backend 前拒絕；v2 header 出現 `authenticator` → `Format`。
- UI：`get_edition() == dual` 時所有 Windows Hello 元素保持 `hidden`；IPC 參數形狀不變。

## 5 版本與建置

- 只改單人版行為；`dual-control` feature 下編譯但功能關閉。
- 需求：Windows 11、WebAuthn API v8+、斷言時支援 PRF 的 Windows Hello（實測：Win11-NB TPM 1.2 不支援）。
- Release：沿用 `cargo +stable-x86_64-pc-windows-gnu build --release --locked --features real-ctap --bin portable-fido-vault`。
- `vault_cli` 不支援 Windows Hello（範圍外）。

## 6 驗收條件

### 6.1 自動化（mock）
- 格式：`authenticator` 序列化／嚴格反序列化；無 platform slot 的 v1 byte-identical；v2 帶欄位 → `Format`。
- Mock platform backend：可註冊、建立／斷言 PRF 一致；可模擬「建立有 PRF、斷言失敗」（NB 型）→ 不寫 slot、刪除 credential。
- excludeCredentials 傳入金庫 platform IDs；同機重複註冊 → 指定錯誤。
- 登入只接受 platform slot 內的 credential；YubiKey 路徑不再收到 platform ID。
- 雙群組：註冊在觸碰 backend 前被拒（counting backend）。
- UI（Node vm）：按鈕顯示條件、訊息、dual 版隱藏、IPC 形狀。
- 全部既有 Rust／Node／Gate E2E 套件不變通過。

### 6.2 本機 Console 驗收（隔離測試金庫，不碰正式 `C:\FidoVault\vault.db`）
- SKYCITY-PC（正向）：V1 建立測試金庫 → V2 註冊 Windows Hello（兩次提示，slot +1）→ V3 鎖定後 Windows Hello 解鎖 → V4 重啟 GUI 後 Windows Hello 登入 → V5 同機再註冊 → 被擋 → V6 YubiKey 與主密碼仍可解鎖 → V7 刪除 Windows Hello slot，設定 → 通行金鑰 無殘留。
- Win11-NB（負向）：V8 註冊 → 第二次提示後顯示「不支援 PRF」，slot 數不變、Windows 無殘留通行金鑰。
- 跨機：V9 把 SKYCITY-PC 測試金庫複製到 Win11-NB → 不顯示 Windows Hello 按鈕，YubiKey／主密碼可解鎖。
- 每個提示框都要回報是否在前景（Windows Hello 對話框可能不是 `CredentialUIBroker`，見 R2）。

## 7 風險與待實機確認

| ID | 風險 | 處理 |
|---|---|---|
| R1 | 使用者驗證可用 Windows Hello PIN 完成，強度 = 電腦 + PIN | 文件明示；不宣稱等同 YubiKey |
| R2 | Windows Hello 對話框的視窗類別／程序可能與 YubiKey 的 Windows 安全性對話框不同，現有前景監控可能不適用 | S0 回報建立提示在前景；D-item 中以 passive 模式記錄，6.2 每步回報前景 |
| R3 | 舊版 exe 存檔會丟掉 `authenticator` 欄位，slot 會被當成 YubiKey | 新版在讀 header 後，若 slot 無標記但 credential ID 出現在本機 platform 清單，視為 platform（不寫回，除非下次正常存檔）；並在 README 標示「勿用舊版編輯」 |
| R4 | 重灌、重設 Windows Hello PIN、清 TPM → slot 永久失效 | 文件明示；YubiKey／主密碼為備援 |
| R5 | RDP 時 WebAuthn 轉送到用戶端，會用到另一份 Windows Hello | 只在本機 Console 提供 |
| R6 | 只有一台正向實機（26H2）；24H2 + TPM 2.0 未實測 | 註冊時的斷言驗證是執行期保證；支援宣告限縮在實測矩陣 |
| R7 | `windows-sys 0.61.2` 缺 v8 結構欄位 | 依 `microsoft/webauthn` webauthn.h 以 `#[repr(C)]` 自訂擴充結構，加 size/offset 測試 |

## 8 範圍外

- 雙群組控管版、`vault_cli`、RDP、Windows Hello 取代主密碼、同步型 passkey（Microsoft 帳戶同步）。

## 9 開發項目

| 順序 | 項目 | 主要檔案 | 依賴 |
|---|---|---|---|
| D1 | 格式：`SlotAuthenticator` + `KeySlot.authenticator`；v1 byte-identical、v2 拒絕 | `src-tauri/src/vault.rs` | — |
| D2 | Backend trait 平台方法（status/register/assert/list/delete，預設 NotSupported）+ Mock（含 NB 型失敗模式） | `src-tauri/src/fido2.rs` | D1 |
| D3 | Windows FFI：v8 擴充結構、PLATFORM 建立／斷言、list/delete、錯誤對應（NTE_EXISTS／NTE_BAD_KEY_STATE／NTE_NOT_SUPPORTED） | `src-tauri/src/windows_webauthn.rs`、`src-tauri/src/webauthn_diagnostics.rs` | D2 |
| D4 | Vault：註冊（建立→斷言驗證→wrap→寫檔，失敗清理）、platform 登入、roaming 登入排除 platform ID、刪除後清理、edition 守門、R3 判定 | `src-tauri/src/vault.rs` | D2 |
| D5 | IPC：`platform_status`、`register_windows_hello`、`login_windows_hello`；Console 守門 | `src-tauri/src/lib.rs` | D3, D4 |
| D6 | UI：登入按鈕、金鑰管理註冊按鈕與標示、訊息；dual 版隱藏 | `src/index.html`、`src/app.js`、`tests/` | D5 |
| D7 | Mock Gate E2E + 回歸套件 | `scripts/gate_e2e.py`、`src-tauri/examples/` | D4 |
| D8 | 文件：README、spec、PROJECT、user-verification-steps（V1–V9） | `README.md`、`docs/` | D6 |
| D9 | Release 建置、隔離 staging、SKYCITY-PC／Win11-NB Console 驗收 | — | D8 |

順序理由：先固定檔案格式與 trait（D1–D2，純邏輯可 mock 測），再做風險最高的 FFI（D3，需兩位 reviewer），vault 邏輯（D4）可與 D3 依賴同一 trait 平行設計但依序實作；UI 與文件最後。

## 10 進度

- [x] S0 spike（Win11-NB 負向、SKYCITY-PC 正向）
- [x] 設計文件
- [ ] D1
- [ ] D2
- [ ] D3
- [ ] D4
- [ ] D5
- [ ] D6
- [ ] D7
- [ ] D8
- [ ] D9
