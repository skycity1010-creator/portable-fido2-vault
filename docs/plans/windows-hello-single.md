# 單人版 Windows Hello 登入／解鎖（windows-hello-single）

> 狀態：實作中（2026-10-12 使用者授權「開始 D1」；逐項進行，每項完成後停下等下一個指示）。
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
- [x] D1（2026-10-12，見 §11 D1）
- [x] D2（2026-10-12，見 §11 D2）
- [x] D3（2026-10-13，FFI、兩位 completed-code reviewer、本機驗證完成；見 §11 D3）
- [x] D4（2026-10-13，本機實作／兩位 completed-code review 完成；Hosted CI 結果以 §11 D4 的發布 receipt／Kanban 為準）
- [x] D5（2026-10-13，本機 IPC／兩位 completed-code review／回歸及建置完成；Hosted CI 以 §11 D5 的發布 receipt／Kanban 為準）
- [ ] D6
- [ ] D7
- [ ] D8
- [ ] D9

## 11 驗證紀錄

### D1（2026-10-12）格式：`SlotAuthenticator` + `KeySlot.authenticator`

變更（只有 `src-tauri/src/vault.rs`）：
- 新增 `pub enum SlotAuthenticator { Platform }`，`#[serde(rename_all = "lowercase")]`：只接受 `"platform"`，`"Platform"`／`"PLATFORM"`／`"roaming"`／空字串／非字串一律反序列化失敗。
- `KeySlot.authenticator: Option<SlotAuthenticator>`，`#[serde(default, skip_serializing_if = "Option::is_none")]`；既有註冊路徑寫 `None`。
- `check_header_edition`：v2（雙群組）任何 slot 帶 `authenticator` → `Format`，在解密前拒絕；v1 接受。

測試（7 個新測試，`vault::tests::wh_d1_*`）：

| 測試 | stub 階段 | 說明 |
|---|---|---|
| `wh_d1_platform_authenticator_serializes_as_lowercase` | RED（left `"Platform"` / right `"platform"`） | 序列化大小寫 |
| `wh_d1_authenticator_deserialization_is_strict` | RED（`"platform"` 無法解析） | 嚴格大小寫、未知值拒絕 |
| `wh_d1_single_edition_accepts_and_preserves_platform_slot` | RED（v1 platform slot 無法讀） | v1 可讀、可用主密碼開啟，正常存檔後 `authenticator` 保留 |
| `wh_d1_edition_check_platform_slot_single_ok_dual_rejected` | RED（v2 回傳 `Ok(())`） | 純 header 版本守門 |
| `wh_d1_dual_open_rejects_v2_file_with_authenticator_without_writing` | RED（stub 時因大小寫先在 JSON 解析失敗，回傳 `Json` 而非 `Format`） | 真實 v2 檔：`open_password_dual`／`read_header` → `Format`，檔案 byte-identical、無 sidecar、無 `.db.tmp` |
| `wh_d1_roaming_slot_serialization_is_unchanged` | GREEN→GREEN（既有行為回歸） | 無 platform slot 的 `KeySlot` JSON 與變更前逐字相同 |
| `wh_d1_v1_file_header_roundtrip_is_byte_identical` | GREEN→GREEN（既有行為回歸） | 真實 v1 檔 header 往返 byte-identical、不含 `authenticator` |

- RED 證據：`D:\scratch\windows-hello-single-20261012\d1\red-stub-2.log`（5 failed / 2 passed，皆為 assertion 失敗，非編譯錯誤）。
- 第一次 stub 執行 `red-stub-1-FIXTURE-literal-error.log` 中 `wh_d1_roaming_slot_serialization_is_unchanged` 的失敗是測試字面值寫錯（`KeyKind` 實際序列化為 `touch_only`），只修正該期望字面值，不計為 RED。
- 全套件（MSVC wrapper，`D:\scratch\wh-test-msvc.sh`）：baseline `real-ctap` 330／`real-ctap,dual-control` 330 → D1 後各 **337 passed, 0 failed**；兩者 0 warning（與 baseline 相同）。
- Node：108 tests / 108 pass；`node --check src/app.js` OK；`git diff --check` OK；`vault.rs` hash-lock 前後一致。
- 格式：`origin/main` 的 `vault.rs` 本來 rustfmt 乾淨，整檔 `rustfmt --config skip_children=true` 只影響新增行（diff 181 行全為新增）。
- D1 為 lib-only 格式項目，不含 FFI／金鑰派生變更：未派 reviewer、未做 Release 建置（留給 D3 與 D9）。
- 證據目錄：`D:\scratch\windows-hello-single-20261012\d1\`。

### D2（2026-10-12）Backend trait 平台方法 + Mock

變更（`src-tauri/src/fido2.rs`、`src-tauri/src/webauthn_diagnostics.rs`；只有新增，沒有刪改既有行）：
- `PlatformStatus { api_ok, uvpa, console }` + `available()`（三項皆真）；`Default` 全為 false。
- `PlatformRegistration { credential, creation_prf: Zeroizing<[u8;32]> }`，自訂 `Debug` 遮蔽 `creation_prf`。
- `FidoBackend` 新增 5 個預設方法，預設全部 fail closed（`platform_status` 回全 false，其餘回 `NotSupported(PLATFORM_UNSUPPORTED_MSG)`）：
  `platform_status`、`register_platform_credential(label, exclude)`、`get_platform_prf_secret(ids) -> (id, secret)`、`list_platform_credentials`、`delete_platform_credential`。
  既有後端（Windows WebAuthn、raw CTAP、`UnavailableBackend`、各測試後端）沿用預設，行為不變；Windows 實作留給 D3。
- `FidoError` 新增 `PlatformCredentialExists`（NTE_EXISTS，「這台電腦…已註冊 Windows Hello…未新增金鑰槽」）、`PlatformPrfUnsupported`（「不支援金庫解鎖所需的 PRF…未新增金鑰槽」）、`PlatformCredentialMissing`（「這台電腦沒有此金庫的 Windows Hello 憑證…」）；診斷分類 `platform-credential-exists`／`platform-prf-unsupported`／`platform-credential-missing`（closed 字串）。既有 `CredentialExcluded`（YubiKey、A/B 群組）訊息不變。
- `MockBackend`：每個實例 = 一台電腦，在記憶體保存本機 Windows Hello credential；ID 版面 `b"f2vl-wh:" ‖ random(24)`（32 bytes，與 roaming ID 首位元組 0..=2 不衝突）；PRF = 既有 `prf_for_credential`（建立輸出 = 斷言輸出）。
  - `MockPlatformMode`：`Supported`（預設，SKYCITY-PC 型）、`AssertionPrfFails`（Win11-NB 型：建立成功、斷言回 `PlatformPrfUnsupported`）、`CreationPrfMismatch`、`Unavailable`。
  - `with_platform_mode`、`with_platform_credentials`（模擬同機重啟）、`platform_credential_ids`、`is_mock_platform_credential`。
  - excludeCredentials：清單中有本機持有的 ID → `PlatformCredentialExists`，不建立；其他電腦的 ID 不擋。
  - 斷言只挑本機持有的 ID（不在本機 → `PlatformCredentialMissing`）；刪除不存在 → `PlatformCredentialMissing`。
  - roaming 路徑（`get_prf_secret`／`get_prf_secret_for_any`）收到 platform ID → `NoDevice`（模擬 YubiKey 不持有此 credential），供 D4 驗證「YubiKey 路徑不收 platform ID」。
- 限制：Mock 的本機 credential 只在記憶體；跨行程（D7 Gate E2E）需用 `with_platform_credentials` 帶入。

測試（15 個 `fido2::tests::wh_d2_*` + 既有 `webauthn_diagnostics::tests::error_categories_never_use_raw_text` 新增 3 列）：
- stub 階段（Mock 未覆寫平台方法、`Display` 回 `TODO`、分類回 `todo`、`PlatformRegistration` 用 derive Debug）：
  - RED（assertion 失敗，11 個）：`mock_platform_available_by_default`、`mock_register_then_assert_returns_creation_prf`、`mock_exclude_existing_rejects_without_creating`、`mock_nb_mode_creation_prf_but_assertion_fails`、`mock_creation_prf_mismatch_mode`、`mock_assert_picks_local_credential_only`、`mock_restart_keeps_machine_credentials`、`mock_roaming_path_rejects_platform_ids`（stub 時卡在前置的平台註冊，roaming 拒絕本身於 GREEN 才實際執行）、`mock_delete_unknown_and_twice`、`platform_registration_debug_redacts_prf`、`platform_error_messages`；另 `error_categories_never_use_raw_text` RED（left `"todo"`）。
  - stub 即通過（4 個，trait 預設即規格／型別性質，不計 RED）：`trait_defaults_fail_closed`、`unavailable_backend_platform_ops_fail_closed`、`platform_status_requires_all_three`、`mock_unavailable_mode`。
- RED 證據：`D:\scratch\windows-hello-single-20261012\d2\red-stub.log`、`red-stub-diag.log`。
- 全套件：`real-ctap` 337 → **352 passed**、`real-ctap,dual-control` 337 → **352 passed**，0 failed、0 warning；Node 108/108；`node --check`、`git diff --check` OK；兩個來源檔 hash-lock 前後一致。
- 格式：兩檔在 base 為 rustfmt 乾淨，整檔格式化後 diff 只有新增行（538 行）。
- D2 不含 FFI／金鑰派生：未派 reviewer（D3 FFI 才派兩位）；未做 Release 建置。
- 證據目錄：`D:\scratch\windows-hello-single-20261012\d2\`。

### D3（2026-10-13）Windows Hello 平台 FFI 與審查修補

- **範圍：** `windows_webauthn.rs`、`webauthn_diagnostics.rs`；D4 的 Vault 流程、D5 IPC、D6 UI 與 D9 實機操作尚未開始。本項不是 Windows Hello 端到端登入驗收。
- API v8、UVPA 與有效本機 Active Console 守門；平台 MakeCredential 使用 PLATFORM、UV REQUIRED、resident key、ES256／RS256 與固定 raw PRF salt。以 v8 options 擴充及 v7 attestation prefix 讀取 creation PRF；platform assertion 保留 allow-list membership 與 32-byte output 守門。
- 平台 credential list 限定 `fido-vault.local`、筆數／累計大小／指標與長度；僅 `NTE_NOT_FOUND` 轉空清單，其餘失敗不冒充空清單。delete 原生 API 無 RP 參數，本 RP／本機 membership 的端到端守門屬 D4 caller，未宣稱已完成。
- 指定 HRESULT 轉 closed typed errors；新增診斷僅含白名單分類、布林值與長度，不輸出 PRF／credential bytes。建立後解析失敗由 `PendingPlatformCredential` best-effort 清理當次 credential；返回後的二次斷言、PRF 相等比對、wrap／寫檔失敗清理留 D4。

#### Completed-code review 與修補

1. 原始 Reviewer 與 Officer 獨立確認 D3-S1（原生 creation PRF 只 free、未顯式 wipe）及 D3-L1（平台沿用 active monitor，與 passive 設計不符）。原始拒絕 verdict 保留，不以建置成功代替審查。
2. 平台專用 `PlatformAttestationGuard` 在 native return 後立即取得配置，涵蓋成功與 early-error 路徑；已知 v7／v8 中 first／second output 各自以非 NULL、恰 32 bytes 守門，zeroize 後 free 一次。roaming `AttestationGuard` 不變。
3. `ForegroundMonitorPolicy::ObservationOnly` 沿 prepare／worker／observe 真正接線；平台 worker activation count 為 0，roaming active control 維持 1；既有 owner preflight 與最後前景採樣到 FFI 的無 blocking／logging gap 保留。
4. 第一輪複審：Officer 通過，Reviewer 拒絕 parser 接受 v9+、cleanup 只認 v7／v8 的不對稱。parent 先跑 1 個 assertion RED，再以共用 `platform_attestation_version_supported` 統一兩者接受域。v9／`u32::MAX` 在讀 flags／extension 前 fail closed，dangling extension fixture 不被讀取；v7／v8 正向與 error／first／second 控制保留。
5. 最終 candidate2 的 Reviewer 與 Officer gate verdict 都為 `passed=true`、`coverage_complete=true`、`security_concerns=[]`、`logic_errors=[]`，manifest SHA256 `41975a277771c0715120f41e4a03c13ee98009917a34e78237da600c9532bc13`。Officer 原非 blocking 分類與後續 gate 分類兩檔並存，技術限制未刪除。
6. Parent 另核對 Reviewer 實際 numbered read stream：兩份完整 D3／followup patch 與增量 patch 全讀；最終 changed regions 無漏讀，讀取內容與快照逐行相符。不是只依 `coverage_complete` 自述。

#### ABI 與自動驗證

- 官方 `microsoft/webauthn` header 固定 commit `0ef86c2fe31e5b0608cc4fce4820935bd644cabb`，SHA256 `da82d5be6b90a2706185ae44ad93649bcefc0f89c97ab930ec4e6f0abb7b2283`；官方 C++ checker 對照實際 Rust emitter 的 65 筆 field offset／field size、7 筆 structure size，72 列一致。僅 x64 layout／contract 證據，不是硬體結果。
- Writer 保留 4 組 assertion RED→GREEN；parent 追加上述 unknown-version RED→GREEN。compile／fixture setup failure 另留紀錄，不計為 RED。
- Parent 重新執行：`real-ctap` **365/365**、`real-ctap,dual-control` **365/365**，0 failed、0 test-compile warning；Node **108/108**；`node --check`、`git diff --check` 通過，來源 hash-lock 前後一致。
- GNU Release 單人版 `--features real-ctap` 建置成功，EXE SHA256 `c35bb922cf88b6071882df03402a01753d4914c2f9c09960e3c921256fc03a5b`、7,257,088 bytes；保留既有 `MonitorTerminal::try_lock` dead_code warning。產物標為 **NOT-DEPLOYABLE**，沒有 staging／launch／實機 WebAuthn。建置使用獨立 source mirror，僅 Tauri 自動生成的兩份 schema 有變動；runtime source 與 reviewed snapshot 一致。初始重疊建置已停止並保存 SUPERSEDED 紀錄，不列為成功證據。
- Hosted exact-head／current-integration CI 由 parent 在發布後讀回 run、jobs、named steps 與完整 logs；結果及測試 checkout parents 以 Kanban 收尾留言與 `ci-final-receipt.json` 為準，不以 D2 的舊綠燈代替。

#### 保留限制與 D4 交接

- Native buffers 的有效性／可寫性依賴可信 Windows API 契約；NULL、未知版本及非法長度守門不代表任意 dangling pointer 都安全。未知未來 attestation 版本刻意 fail closed，支援新版本須以官方證據同步擴充 parser 與 cleanup。
- 既有 shared assertion response-version／原生 PRF wipe／普通陣列回傳問題保留為 PRE-S1／PRE-S2，未擴大重構 roaming 範圍、未宣稱已修。ObservationOnly 的 candidate-foreground publication 沒有平台 downstream handoff 效果；foreground-to-FFI 仍非 OS 原子操作。
- D4 需補建立後斷言比對、失敗清理、slot persistence、edition 守門與刪除前 membership。D4–D9 仍未勾選；本項完成後停止，等待使用者下一項指示。
- 證據：`D:\project\_archives\portable-fido2-vault\wh-d3-followup-20261013-085634\`。原始快照另保存在 `wh-d3-review-20261013-081309`，兩者均不改寫歷史 verdict。

### D4（2026-10-13）Vault 平台流程、相容性與失敗清理

- **範圍：** production 只有 `src-tauri/src/vault.rs`，source commit `681c399694188327ad5991072b5a731650706120`；另更新本計畫驗證紀錄。沒有新增 IPC／UI／Gate 功能，沒有 Release 建置、部署、GUI、native WebAuthn、實體金鑰或使用者金庫操作；D5–D9 未開始。
- **新增 API：** `register_windows_hello`、`open_windows_hello`、`read_header_with_platform`、`open_password_with_platform`、`remove_key_with_platform`，及 `PlatformCleanupOutcome`／`PlatformCleanupWarning`。所有平台寫入／登入入口 edition-explicit，在 backend 前拒絕 v2；既有雙群組路徑不變。
- **註冊：** available／本 RP local-list 守門、排除所有 platform IDs（含 verified R3 分類）、拒絕空 ID／vault 或 local-before 碰撞；post-create list 證明 new credential ownership 後才斷言及清理。Assertion selected ID 必須完全一致，creation/assertion PRF 以鎖定 digest 0.10.7 的 `CtOutput` 常數時間比對，沿既有 HKDF／AES-GCM 包裝 KEK。新增 caller secret／wrap／解包 KEK 以 `Zeroizing` 及明確 `zeroize` 保護，不新增 KDF、AAD 或 dependency。
- **失敗與移除：** 註冊 assertion／mismatch／persist 失敗只 best-effort 清理可證實的新 credential；保留 primary error，完整還原 header 與 audit（含 cap trim）。Backend-aware removal 先成功 persist，再重新查 available／fresh RP membership 才 delete；不在本機、discovery／delete 失敗皆回 typed 手動清理 outcome，不回滾已落盤的 slot 移除。未知 marker 與 unavailable/list-error 交集同樣提示可能殘留；platform removal audit 使用 `windows-hello:<label>`，roaming 保持 `fido2:<label>`。
- **登入／R3：** Windows Hello 只送本機 platform intersection，回傳 ID 必須在 allow-list 且有 matching slot；共用既有 KEK／payload unlock、success audit 與 sidecar merge。兩個 roaming 入口排除 explicit／verified-local platform ID，any-key 回傳亦驗 membership。Read-only R3 query 不寫檔；正常 authenticated password／roaming／platform save 才保留修復 marker。不依 label、AAGUID 或 prefix 猜種類。

#### TDD、審查與修補

- **41 個新 `wh_d4_*` tests**；parent 以 log／exit／exact test name／正整數執行數及每階段來源 snapshot 核實 **32 組 assertion RED→GREEN**（其中 1 組為 fixture-disjoint invariant），另 **9 個 GREEN→GREEN 控制**。原 118 個 vault tests 的完整原始區段 byte-preserved；其他 tracked production 不變。
- R3 原始 Reviewer verdict `passed=false`：D4-L1 固定 COMPUTERNAME 展示名稱阻擋不同電腦／Windows 帳號；D4-L2 真實 cancellation 以 opaque `Internal` 返回，不能被當成已證實拒絕。兩項各有直接 RED→GREEN：L1 使用 Unicode 長度受限的唯一 suffix，身份重複仍只由 local membership 決定；L2 只有 typed `PinRejected`／已證實 rogue ID／AEAD wrong-secret 記失敗，opaque `Internal` 原樣返 caller，不解析 HRESULT 文字、不猜取消。
- R4 Reviewer 再拒絕 D4-L3（lost marker＋unavailable removal 無警告），以交集 RED→GREEN 補齊。Officer 的 lost-marker＋list-error warning 與 platform removal audit 建議亦各有 RED→GREEN；補上 4 個 scripted negative controls：post-create list error、空／local non-vault ID collision、save＋delete 雙失敗、persist 後 fresh-list 改變。
- R5 首次 full suite **404 passed／1 failed** 是註冊 tmp／rename rollback fixtures 共用同 tag／process-ID 路徑的平行衝突；原 FAIL 保留。用純 fixture-tag 不等 assertion RED→GREEN 分離兩路徑，production 不為此改動。R3 另有一次 removal-loop fixture reuse 的 unwrap error，保留但不列為 production RED。
- **最終 R5**：Reviewer 與 Officer 都 `passed=true`／`coverage_complete=true`，security／logic arrays 空；manifest SHA256 `69fdc9081150fe7110fcbdec9caa880f286d6b581c0e7e131db898b86f830577`，196 檔快照與 full／incremental patch 雜湊核對。Parent 另核 Reviewer 真正 numbered-read stream，1846-line full patch、82-line delta、1699 added source lines 全讀，與凍結來源逐行一致，不只信任 coverage 自述。R3／R4 原拒絕結果與所有限制保留，不改寫為 PASS。

#### 自動驗證與發布 gate

- Parent 最終完整 MSVC lib suites：`real-ctap` **406 passed／0 failed**；`real-ctap,dual-control` **406 passed／0 failed**，無 test-compile warning。Node **108/108**；`node --check`、`rustfmt --check`、`git diff --check` 成功。Source hash-lock `0dec9dd45e3d37cd1d27982449dbf3c327e327002792be3a3ee1d344b04043c8` 前後一致。
- Fixture 修正後另以 **8 threads** 執行全部 41 個 D4 tests **三次，各 41/41**，全部成功；不宣稱無限次壓力測試或 timing／allocator residue 已驗證。
- Hosted **exact-head／current-integration CI** 在發布後由 parent 讀回 run、jobs、named steps 與完整 logs。PR #30 保持 Draft，整張功能卡 `t_01329074` 維持 blocked；**CI 未讀回前不宣稱 D4 收尾完成**。最終結果、tested merge parents 與 counts 以 `D4-final-closeout-receipt.json`／`ci-final-receipt.json` 及 Kanban 收尾留言為準，不以 D3 舊綠燈替代。

#### 保留限制與後續交接

- Legacy password／roaming 的 platform discovery 不可用／list error 時採 best-effort 跳過 R3 修復，保留 explicit marker；strict query／platform login 的實際 list error 仍可見。已失去 marker 的未知異機 ID 無法可靠分類，仍須真正取得 PRF 並通過 AEAD；不宣稱完整修復所有 metadata 遺失。
- Native `Internal` 契約仍無法細分取消與未 typed 原生拒絕，因此保守不記已證實 auth failure；沒有新增取消 variant 或修改 FFI。原有 PRE-S1／PRE-S2 shared native assertion 問題未修，caller zeroization 不等同 native memory wiping 或編譯器暫存器擦除證據。
- Post-create RP-list proof 失敗不可盲刪不明 credential；best-effort delete 也可能失敗，因此可能有 Windows credential 殘留。D6 應呈現消歧 label、typed 手動清理警告及 proof-failure 殘留提示；D9 補原生 roaming 拒收 platform IDs、取消 sidecar 空及 Console V1–V9 實機回歸。這些是交接，不是已開始 D6／D9 或已報物理 PASS。
- 證據：`D:\project\_archives\portable-fido2-vault\wh-d4-review-20261013-R5\`；完整 TDD／suite 原始 logs：`D:\scratch\wh-d4-20261013\`。本項收尾後停止，等待使用者下一項指示。

### D5（2026-10-13）Windows Hello IPC 與 Console／edition 守門

- **範圍：** production 只有 `src-tauri/src/lib.rs`，source commit `e100881`；新增並真正註冊 `platform_status`、`register_windows_hello`、`login_windows_hello`。不接受 frontend 指定 edition、attachment、computer name、PRF 或 Hello credential；未修改 UI／KeyInfo、Vault／FFI／crypto、Cargo／lock。D6–D9 未開始，未 merge／deploy／GUI／native WebAuthn／實體金鑰／使用者金庫操作。
- **Status：** 安全回應只有 `api_ok`／`uvpa`／`console`／`local_credential`。single 版讀共用 checked persisted header，RP-local credential 與 slot IDs 交集包含 R3 lost marker；無金庫回 local false、discovery／header error 不冒充成功。query 無 prompt、解密或寫回；dual 在 backend 前拒絕。
- **註冊／登入：** single／unlocked registration／fresh API+UVPA+Console 守門先於 window activation 與 mutating backend，活 HWND 經既有 helper 交給 backend，再呼叫 D4 API。電腦名稱由 Rust 讀 `COMPUTERNAME`，讀取失敗明確拒絕。Hello 完整認證、成功 persist、取得 entries、發布 unlocked Vault 與清 CSV／dual pending 在同一 state lock；失敗不發布或清 pending。主密碼 single path 接入 D4 authenticated R3 save，dual 仍沿既有 password path。
- **移除：** single 接入 D4 persist→fresh RP membership→best-effort delete，回安全 typed `removed`／`manual_removal_required`＋`not_local`／`discovery_failed`／`delete_failed`；dual 與已確認 roaming 的 JSON `null` 回應保留。D6 才呈現 cleanup warning，現有 UI 忽略回傳值的相容性已靜態核對，未宣稱警告畫面完成。

#### TDD、完成程式碼審查與測試修補

- 原 writer 6 組 assertion RED→GREEN、13 GREEN→GREEN controls；parent 核實每組來源 snapshot、log、exit code、精確 test name／正整數執行數。首次 compile／fixture-oracle 失敗保留，不列為 production RED。Claude Code 首次 API 429 `usage_limit_reached` 未執行且來源未變，改用 per-run `gpt-6.1-sol/openai-codex` Hermes CLI，未修改持久 configuration，未使用 Codex CLI。
- **R1 Reviewer 拒絕原 verdict 保留：** D5-T1 fixture 硬編碼作者 D: 路徑；D5-T2 `remove_key` wiring oracle 匹配自身測試字串、漏看 production body。兩項各有 parent 直接 assertion RED exit101／1 failed→GREEN exit0／1 passed。測試改為非空 TMPDIR／OS temp root、原子 `create_dir`（不採納 existing dir）與 scoped owner cleanup；wiring oracle 限 production prefix、匹配真實多行宣告、拒絕缺少／重複宣告，負向 string fixture 真正移除第一個 production helper call 後 oracle 必須拒絕。production prefix 對 R1 byte-identical。
- **最終 R2：** 共 21 新 D5 tests；原 6＋parent 2 組直接 RED→GREEN及13 controls。C: Hermes 指定 scratch 作 TMPDIR，兩 features 各 **21/21**，執行後 fixture root 為空。證明可配置與 scoped cleanup，不宣稱已在實體只有 C: 的電腦上測試。
- Reviewer 與 Officer 皆 `passed=true`／`coverage_complete=true`，security／logic／test arrays 空；manifest SHA256 `ba9822500c6c6a0a370f89b4941b797302bafaa6a0ca5523e6b6c6166d3ec8fb`。Parent 核196檔 hashes與兩位完整 raw verdict；Officer 經既有授權 SSH/scp 取得 bundle，獨立核 source receipt，首次 A2A timeout 不當作拒絕或完成。Parent 另核 Reviewer 實際 numbered read stream：1191-line full patch、192-line delta、1137 added source lines 全讀，與 frozen source 逐行相符；不是只信 coverage 自述。

#### Parent 自動驗證、建置與發布 gate

- 只在 R2 review gate 通過後執行長驗證。MSVC lib suites：`real-ctap` **427/427**，`real-ctap,dual-control` **427/427**；Node **108/108**；既有 mock Gate **20/20**、dual Gate **25/25**（MSVC mock CLI、合成 fixtures，非 D7 Hello 新 Gate／非硬體結果）。`node --check`／`rustfmt --check`／`git diff --check` 通過；test／mock CLI compile 無 warning。
- GNU locked/offline Release single `--features real-ctap --bin portable-fido-vault` 與 dual `--features real-ctap,dual-control --bin portable-fido-vault-dual` 均成功；各保留既有 `MonitorTerminal::try_lock` dead_code warning，PE imports 為 x64。single EXE SHA256 `220d9c1c7a8381c5e7732aed8bbd67d1e2c9512507288173f93323b91db75953`（7,312,896 bytes）；dual `19a8d979088571181a0557b78489f154da5031179f54cbe7e4333358c74629d2`（7,322,624 bytes）。兩者 **NOT-DEPLOYABLE**，UI 尚未接線且 D9 物理驗收未做。
- Tests／Release 使用分離且 hash-verified source mirrors；writer／test mirror196檔前後一致。Build mirror 僅 Tauri 自動生成的兩份 schema 變動，reviewed runtime source 不變。發布 commit 的 Git blob provenance 由 parent 另核。
- PR #30 保持 OPEN Draft，功能卡 `t_01329074` 保持 blocked／parent-controlled。Hosted **exact-head／current-integration CI** 在發布後讀回 run、jobs、named steps 與完整 logs；**未讀回前不宣稱 D5 收尾完成**。最終 CI、tested merge parents、counts 與收尾結論以 `ci-final-receipt.json`／`D5-final-closeout-receipt.json` 及 Kanban 收尾留言為準。

#### 保留限制與 D6 交接

- Mock Console／HWND seam 不是物理 Windows Hello、提示前景或 GUI event-loop scheduling／deadlock 驗證；D9 補 Console V1–V9。`platform_status` 在 unlocked session 重讀 checked persisted `v.path`，外部檔案變更仍可能使 query 與 session header 不同。
- D6 需接入 status／登入／註冊元素、platform 標示及 typed cleanup warning／proof-failure 殘留提示；KeyInfo 本次未擴充。D4 best-effort R3 discovery／credential cleanup 的限制不變；source-text oracle 是 frozen source 格式的文字檢查，不是 AST 或任意 source mutation 的語意保證；scoped cleanup 為 best effort，不保證所有 OS／權限／open-handle 情境都無殘留。
- PRE-L1 既有 roaming／dual two-lock publication race、PRE-S1／PRE-S2 shared native assertion version／PRF wipe 問題未修，另案處理；不因本次 Hello single-lock publish 或 caller zeroization 宣稱已修。
- 原 R1 拒絕與 R2 verdict／全部限制保留。證據：`D:\project\_archives\portable-fido2-vault\wh-d5-review-20261013-R2\`；完整原始 TDD／suite／build logs：`D:\scratch\wh-d5-20261013\`。D5 收尾後停止，等待使用者下一項指示。
