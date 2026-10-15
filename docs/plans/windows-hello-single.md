# 單人版 Windows Hello 登入／解鎖（windows-hello-single）

> 狀態：D1–D8 完成；D9 Release／隔離 staging／實機 V1–V9 尚未執行。PR #30 維持 OPEN Draft，未合併／未部署。
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
- PRF 建立使用 API v8 MakeCredential options 的 `pPRFGlobalEval`，搭配 `dwFlags=WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG` 傳入 raw HMAC-secret salt，並核對 attestation v7 `pHmacSecret`；舊的 `hmac-secret` extension／v6 `bEnablePrf` 單獨使用時 `bPrfEnabled=false`。Microsoft header 的基礎 MakeCredential `dwFlags` 欄位註記為 reserved，但 v8 `pPRFGlobalEval` 欄位說明明確列出此 flag 作為 raw-salt 選項；請 Officer 確認此版本化說明與目標 Windows SDK/API 相符，不可只讀基礎欄位註記。
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
- 測試前記錄 Windows passkey access consent 與 provider 設定；只有確認使用裝置本機 Windows passkey provider 時才繼續。未獲核准／遭拒時列為受阻未測，不視為 PRF 失敗；若第三方同步 provider 啟用或狀態不明，取消並標示超出功能範圍，不建立測試 credential。
- SKYCITY-PC（正向）：V1 建立測試金庫 → V2 註冊 Windows Hello（Create 與 PRF assertion 各自記錄提示前景，slot +1；access consent 另計）→ V3 鎖定後 Windows Hello 解鎖 → V4 重啟 GUI 後 Windows Hello 登入 → V5 同機再註冊 → 被擋 → V6 YubiKey 與主密碼仍可解鎖 → **V9 跨機複製（必須在 V7 移除 slot 前執行）** → V7 刪除 Windows Hello slot，檢查本機及 provider 的特定測試 passkey。
- Win11-NB（負向）：V8 註冊 → 若 passkey access/provider 前置條件不滿足，列受阻／未測並停止；只有在同意已核准且使用本機 provider 時，才驗證第二階段 PRF assertion 被拒、slot 數不變。程式會嘗試清理；若提示可能有殘留，按單一測試 passkey 規則逐項核對，不可預設 Windows 無殘留。
- 跨機 V9 預期 Win11-NB 不顯示可用 Windows Hello 按鈕，YubiKey／主密碼仍可解鎖；若 provider 同步使 Hello 可用，記 V9 FAIL、停止並重新評估範圍，不更動全域設定。
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
- [x] D6（R3 雙審查、本機回歸與 source+doc head `27553a2` exact-head CI `38392679679` PASS；見 §11 D6）
- [x] D7（2026-10-13，R2 Reviewer PASS、本機回歸與 source+doc head `054f525` exact-head CI `38402500039` PASS；見 §11 D7）
- [x] D8（2026-10-14，Officer R3 完整文件審查 PASS＋Reviewer R3→R4 增量 PASS；reviewed 文件 commit `bbc731f`；見下方 D8 節）
- [ ] D9

### D8（2026-10-13～14）文件同步與審查

- 同步範圍：`README.md`、`docs/spec.md`、`docs/PROJECT.md`、`docs/user-verification-steps.md`；本計畫亦同步 passkey access consent、provider 限定及 V9 必須先於 V7 的次序，避免手動驗收互相矛盾。
- 文件界定單人版 Windows Hello 的 API v8+／PRF assertion／本機 Console、dual-control 拒絕、slot 及清理行為；清楚分隔 Mock Gate 與實體驗收，標示 PR #30 Draft／未部署；並明示 backend 目前使用 v8、僅請求 PLATFORM attachment，尚未使用 API v9 authenticator ID 鎖 provider，因此 Windows 本機 provider 是必要前置而非程式保證。
- V1–V9 只列待測，加入隔離金庫、主密碼與測試 YubiKey 備援、Windows consent/provider 檢查、提示前景觀察、單項 passkey 清理與停損規則；不重設 Windows Hello 容器、不碰正式金庫、不輸出憑證資料。
- Microsoft 官方來源已連結，用於 Windows WebAuthn/platform-versus-plugin provider、PRF/raw hmac-secret option 欄位、Windows passkey access consent 及本機/同步 provider 管理。V1–V9 均未實測；D9 build/staging/GUI 尚未執行。
- **審查：** Officer R3 全新唯讀審查（manifest SHA256 `deb5e7b0…a061`、patch `21c4bf31…f4a7`）`passed=true`、`coverage_complete=true`，3 項非阻斷建議。Reviewer 獨立確認建議 1–3 應採納並同意安全邊界；R4（manifest `3f32fb80…d0e2`、patch `59726bb8…d4e0`）落實三項，Reviewer `WH-D8-R4-DELTA-RETRY-2` 5/5 checks PASS（完整性依據為 parent-verified；199 檔逐 byte 與來源一致）。使用者 2026-10-14 決定 R4 以 Reviewer 審查即可，不再送 Officer。
- **發布：** reviewed R4 內容原樣提交為 `bbc731f`（逐檔 EOL 正規化後與 R4 snapshot 相同）；本狀態同步為獨立 docs-only commit。D8 只涵蓋文件；V1–V9 仍全部未測，D9、部署與合併未開始。

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

### D6（2026-10-13）單人版 Windows Hello UI

- **範圍與候選：** `src/index.html`、`src/app.js`、`tests/windows-hello-ui.test.cjs`，另 `src-tauri/src/lib.rs` 的 KeyInfo／read-only RP-local membership；source commit `8ffeb165a5c42c6380805187312acae11b20535a`。雙群組 UI／IPC 原形狀保持；D7–D9 未開始，沒有 GUI、native WebAuthn、實體金鑰或正式金庫操作。
- 登入按鈕預設 hidden，僅 `get_edition == single` 且 status 四個能力欄位全 true 時顯示；edition 查詢失敗或未知值不呼叫任何 Hello IPC。註冊按鈕只在單人版解鎖後顯示；登入／註冊皆有同步 disabled 重入守門，參數不接受前端指定的憑證／label／attachment。KeyInfo 的 `authenticator` 與 `platform_local` 為 optional；只用本 RP credential discovery 證明 local／foreign，失敗維持 unknown，不憑歷史 label 判身份；既有 roaming JSON 未新增欄位。新標籤、錯誤、清理警告以 `textContent` 呈現。
- 平台移除的 `manual_removal_required` 警告以 credential ID 累積，不被其他移除進度／成功／失敗或反向 async 完成覆蓋。D5 roaming 移除原有 JSON `null` 仍視為成功；這項在 parent 實測 14/15 RED（該測試失敗）→最小修補→15/15 GREEN，原失敗不改寫。平台未知／null 回傳仍顯示未知，不誤稱清理成功。
- **Frozen R3：** `D:\project\_archives\portable-fido2-vault\wh-d6-review-20261013-R3\`，197/197 source hashes 親自讀回一致；manifest SHA256 `fa8fac01ec5be50a2379508a747e66b78c8768c38bcbf769d97c1953d21845d4`，完整四檔 patch SHA256 `649ba0869370835bedd70fe1b78177d10e50333c2215940b309f33fa9c5d6f98`。原 R1 否決、R2 兩個 429 無 verdict 均保留；R3 Reviewer 對完整 patch／依賴讀取後 `passed=true`，Officer 透過既有 SSH/scp 唯讀取回獨立審查 `passed=true`（A2A context `ctx-d4a48ad2820645cf`），兩者無 blocking security／logic concern。Claude CLI 另因 weekly limit 429 未執行、Hermes 子代理因模型不支援 400 未執行，均不列為審查通過。
- **Parent 本機驗證：** D6 Node 15/15，Node 全套 123/123；MSVC Rust `real-ctap` 428/428、`real-ctap,dual-control` 428/428；原有 mock Gate 20/20、dual Gate 25/25；GNU locked/offline Release 單／雙 GUI 與兩種 CLI example 建置成功。build 曾因 GNU `windres` 未在 PATH 失敗，補入既有 winlibs 工具路徑後通過；僅既有 `MonitorTerminal::try_lock` dead_code warning。`git diff --check`、`node --check src/app.js` 通過；整庫 `cargo fmt --check` 在未改動的 `windows_webauthn.rs` 顯示既有差異，未擴大 D6 scope。這些測試不代表 D9 實機驗收或可部署。
- **發布 gate：** source+doc head `27553a2c476a2530e93dc465b583f8ab429ba6af` 的 exact-head CI run `38392679679` / job `115280075583` completed/success，所有步驟均成功；完整 log SHA256 `05d29f23f89b39e82e13505a91cba2bf24d1b37d279716825790ff5761c84051`（`wh-d6-review-20261013-R3/ci-run-38392679679.log`）。Hosted merge checkout `11ffd36` 顯示 `Merge 27553a2c... into 368f103...`；log 逐項核實 Node 123/123、Rust single 428/428、dual 428/428、mock Gate 20/20、dual Gate 25/25。PR #30 維持 OPEN Draft；本段後續僅提交 D6 驗收文件，最終 remote/PR head 與該文件 commit 的 CI 另於 Kanban 留 receipt，不把前述 run 冒充新的 head run。整張功能卡 `t_01329074` 維持 blocked，D7–D9 不隨本次開始。

### D7（2026-10-13）Mock Gate 實作中；尚未發布／驗收

- 新增獨立 `scripts/gate_e2e_windows_hello.py` 與 `src-tauri/examples/windows_hello_gate_cli.rs`；不動既有 Gate scripts、shared production vault／backend／IPC。CLI 將 mock platform IDs 自隔離金庫 header 經 `with_platform_credentials` 預載，跨 process 驗證註冊、同機登入、異機拒絕／主密碼備援、PRF assertion 失敗拒絕落 slot 並清理 credential、重複註冊、移除、雙人版守門與 roaming 異機登入。這是邏輯 mock，不模擬真正 Windows Hello 的本機通行金鑰儲存體或實體硬體。
- 10 組 assertion RED→GREEN（含總 Gate runner）：每組最後有效 RED exit 1，無 compile／unwrap panic；相對應 MSVC example 建置 exit 0、GREEN exit 0。總 Gate 初稿 `29` 曾直接通過僅 2 checks，未列為 RED；修正斷言後 `30` 才為有效 RED。最終同一套 Gate 在 `real-ctap` 與 `real-ctap,dual-control` 的 MSVC targeted example build 後各 **8 cases／27 checks**；既有 fixture directory 拒絕且既存金庫 SHA256 不變。原始記錄 `D:\scratch\wh-d7-20261013\evidence\`（`01`–`39`）。
- **R1 審查否決與 R2 候選：** Reviewer R1 `passed=false`，指出測試 CLI 對 pre-existing tmp/symlink 缺乏守門、PRF 失敗與 dual edition Gate 可偽陽性。保留原 verdict `D:\scratch\wh-d7-20261013\reviewer.raw.txt`，不算通過。Parent 新增 CLI fixture 檔名／marker／tmp／sidecar 檢查與 canonicalized path；CI 只在 GitHub Actions 使用 `RUNNER_TEMP`，本機仍只接受 `D:/scratch`。Python -O 的檢查改用 `if/raise`。`TracedPlatform` 驗證 dual 版在 backend 任何方法前拒絕、PRF fail 的建立 ID → 斷言同一 ID → 刪除同一 ID；註冊後檢查真實 slot/ID/本機清單，duplicate 以完整檔案 bytes 驗證不變。受控 mutation 將註冊改為建立前拒絕，Gate exit 1（`55`）；守門前觸碰 backend，Gate exit 1（`57`），均已還原。新 `fixture-guard` 子例拒絕既存 tmp 和缺 marker，合計 **9 cases／29 checks**（`59` GREEN）；額外 `-O` 與 CI-root 模擬的先前版本各 8／27。R2 尚待獨立 completed-code review、兩 features 完整回歸、hosted exact-head CI；未宣稱物理 Windows Hello PASS。
- **R2 completed-code review + parent verification：** frozen R2 manifest SHA256 `27fe82f66844e5eee7f3252a7daf2846d3e6220780cb154f737f1bf9ae7d46d2`；Reviewer `passed=true`、`coverage_complete=true`、security／logic arrays 空，原 R1 否決保留。Parent 讀回四檔 hashes 一致；MSVC Rust `real-ctap` **428/428**、dual **428/428**、Node **123/123**、既有 single Gate **20/20**、dual Gate **25/25**；Hello example 兩 features 各 **9 cases／29 checks**，Python `-O` **9／29**，CI-root 模擬 **9／29**；GNU offline Release example build + CI-root Gate **9／29**。Rustfmt、Python AST、diff check PASS。證據 `D:\scratch\wh-d7-20261013\evidence\60`–`72`。本機因 Windows user 缺 symlink privilege（WinError 1314）未能實際做 symlink 負測；不把靜態防護說成抗 TOCTOU／同帳號惡意程序。既有 Gate local debug binaries 是 D6 warm target，hosted CI 將自 source 重新建置。**D7 仍待 exact-head hosted CI；尚不勾選。**
- **發布前狀態（歷史紀錄）：** 當時仍需 hosted exact-head CI 與發布驗證；PR #30 保持 Draft、卡 `t_01329074` 保持 blocked。沒有實體金鑰／GUI／部署；Mock Gate 不證明物理 Hello。
- **D7 發布 gate：** source+doc head `054f525e694d05d460f09119aa6611311d3f0e07` 的 exact-head CI run `38402500039` / job `115313422084` completed/success，所有步驟成功。Hosted merge checkout `31964d7` 顯示 `Merge 054f525... into 368f103...`；完整 log SHA256 `709fc2c50a2a654b5241fa12c8376265d6bdbad134fba4c8ced2cd409eddfda7`（`D:\scratch\wh-d7-20261013\evidence\79-ci-job-full.log`）；逐項核實 Node 123／Rust 428+428／既有 Gate 20+dual25／新增 Hello Gate **9 cases／29 checks**。初次 `gh run watch` 因暫時網路錯誤退出 1，後續唯讀 API 重試直到實際 success，未重跑 CI。本段為 D7 收尾文件，若另有 docs-only commit，該 commit 的新 head CI 應另查，不冒充前述 run。PR #30 保持 OPEN Draft、整張功能卡仍 blocked；D8–D9、實體 Windows Hello、正式金庫、部署及合併未開始。

## 12 D9-F1 註冊第二階段前景交接（A+C）

**狀態：候選，待審查，未實測。** 本節不改動 D1–D9 狀態；沒有 GUI、native WebAuthn、實體金鑰、正式金庫或部署操作。

### 12.1 背景

- SKYCITY-PC（Windows 11 26H2 build 26300）實測：註冊的第一個 ceremony（MakeCredential）成功後，Windows 未把前景交回 FidoVault（前景為另一個不明視窗，pid 未知、每次 hwnd 不同）。第二個 ceremony（驗證用 GetAssertion）依既有設計 fail-closed：
  - YubiKey：`prepare_assertion_continuation` 拒絕（`broker-not-observed` 或 `foreground-not-associated-broker`）→ `Windows WebAuthn continuation refused: ...`。main（368f103）同樣失敗，屬既有行為，非回歸。
  - Windows Hello：pre-API `validate_owner_foreground` 拒絕（owner 非前景），vault 依現行邏輯刪除剛建立的 platform credential。
- Win11-NB 前景會自然交回，現行流程正常，行為不得改變。

### 12.2 決策（使用者：A＋C）

- **A 兩段式「按一下繼續」：** 第二個 ceremony 因「前景未交回」被拒時不視為註冊失敗，保留 pending 註冊並顯示「金鑰已建立，但 Windows 未將焦點交回 FidoVault……」；使用者按「繼續驗證」的點擊本身讓 FidoVault 成為前景，第二個 ceremony 以全新一般斷言執行（continuation 已消耗 → `Ordinary` → 新 owner baseline → 既有 pre-API 守門）。**不放寬任何守門**：未新增 SetForegroundWindow／AllowSetForegroundWindow／AttachThreadInput／最小化還原等主動搶焦點；`prepare_continuation_inner`、`passive_owner_return`、`validate_owner_foreground` 的判斷條件未變寬。
- **C 前景診斷：** continuation 拒絕與 pre-API owner 前景拒絕後，各記一行 `[WebAuthN-foreground-owner] {json}`；欄位白名單 `operation`、`site`（`continuation`｜`pre-api`）、`foreground_class`（≤64 字元）、`foreground_process`（basename 小寫 ≤64 字元）、`foreground_same_session`、`foreground_is_owner_process`；取不到為 null。不記錄視窗標題、完整路徑、credential、PRF、PIN。

### 12.3 設計摘要

- `fido2.rs`：新增 `FidoError::ForegroundHandoffRequired`（Display 為上述提示）與 `FidoError::OwnerNotForeground`（Display 與舊 `Internal(...)` 顯示逐字相同：`FIDO2 內部錯誤：Windows WebAuthn was not started because its owner window is not foreground. ...`，登入路徑文字不變）；`is_foreground_handoff()` 只對這兩者為真。MockBackend 可注入 N 次 roaming／platform handoff 拒絕並記錄呼叫順序（`MockCall`）。
- `windows_webauthn.rs`：`validate_owner_foreground` 在 owner 非 null 且非前景時回 `OwnerNotForeground`（null owner 仍為原 Internal）；`continuation_refusal_error`：`UnobservedBroker`／`Foreground`／`PassiveDeadline` → `ForegroundHandoffRequired`，其餘 variant 維持原 Internal。診斷純邏輯在 `webauthn_diagnostics.rs`（私有欄位 + 消毒建構子），native 查詢只讀 class／image path／session。continuation 診斷用拒絕當下取樣的 foreground hwnd；pre-API 診斷在操作 wrapper 回傳 `OwnerNotForeground` 之後才重新取樣前景，最終守門與 FFI 之間沒有新增任何程式碼（既有 source-wiring 契約維持）。
- `vault.rs`：`PendingRegistration`（Roaming：credential、`Zeroizing` PIN、label、group；Platform：credential、`Zeroizing` 建立時 PRF、label；手寫 Debug 只顯示種類與 label；不可 Clone／Serialize）、`RegistrationOutcome`、`CancelOutcome`。`begin_register_key_for`／`begin_register_windows_hello` 在第二個 ceremony 回 handoff 錯誤時回 `HandoffRequired`（platform 不刪除）；其他錯誤維持現行。舊 `register_key*`／`register_windows_hello` 為相容 wrapper：handoff → `Fido(ForegroundHandoffRequired)`，platform 先 best-effort 刪除。`continue_registration` 重新檢查 edition、群組 share、credential 不在既有 slot、label；platform 再做 RP 清單證明（不在 → `PlatformCredentialMissing`，不刪），再執行相同的斷言、constant-time PRF 比對、wrap、slot、audit 與回滾；再次 handoff → 回同一 pending；其他失敗 platform 刪除、roaming 直接失敗。`cancel_registration`：platform 先以 RP 清單證明再刪除（`removed`／`manual_removal_required`），roaming → `discarded`。
- `lib.rs`：`AppInner.pending_registration`（pending、120 秒 deadline、金庫路徑、世代）。`register_key`／`register_windows_hello` 回 `{status:"registered",credential}` 或 `{status:"handoff_required",message}`；已有 pending 時拒絕新註冊（在任何前景操作之前）。新 IPC `continue_registration`（先 `raise_key_operation_window(&window, true)` 與 `set_webauthn_parent_hwnd`；逾時或金庫不同 → 取消並清理；再次 handoff 放回 pending、期限不延長；視窗無法成為前景時保留 pending）與 `cancel_registration`（`{status:"cancelled",cleanup:"removed"|"manual_removal_required"|"discarded"|"none"}`），兩者已註冊於 `invoke_handler`。上鎖、各登入成功、建立金庫、移除金鑰前先取消 pending；另以世代計時器在期限後主動取消。
- `src/app.js`／`src/index.html`：YubiKey（單人／雙人群組）與 Windows Hello 註冊共用 `applyRegisterResult`；`handoff_required` 顯示 inline 區塊（`textContent`）含「繼續驗證」「取消」；pending 期間停用註冊與移除按鈕；in-flight 兩鈕停用、例外時恢復並保留區塊；取消依 cleanup 顯示結果（`manual_removal_required` 指向「設定 → 帳戶 → 通行金鑰」只刪除本次測試項目）。

### 12.4 測試清單（候選；證據 `D:\scratch\wh-d9f1-20261014\evidence\`）

- 錯誤對應全 variant、`validate_owner_foreground` typed、兩個 Display（`01`→`02`）。
- 診斷 serializer exact allowlist、截斷、basename／小寫、null、native 取樣只讀 class／image（`03`→`04`）。
- Mock handoff 注入與呼叫紀錄（`05`→`06`）。
- vault roaming／platform：handoff 無 slot／audit／寫檔且 platform 未刪；continue 單人 KEK、雙人 group share + AAD、再次 handoff、重複 credential 拒絕、RP 清單不含不刪、PRF 不符刪除；cancel removed／manual／discarded；相容 wrapper（`07`→`08`，vault 子集 `09`）。
- lib：pending 拒絕新註冊、continue 成功／再次 handoff、逾時取消並刪除、cancel 各 cleanup、lock／登入／移除清 pending、dual edition 拒絕 Hello pending、兩 IPC 已註冊、未新增主動前景 API（`10`→`12`）。
- UI：handoff 顯示、繼續成功／再次 handoff、取消各 cleanup、XSS、in-flight 鎖、YubiKey 單／雙人共用路徑（`13`→`14`）。
- 全套：R1 frozen candidate（非 R2）MSVC `real-ctap` 461/461、`real-ctap,dual-control` 461/461、Node 132/132（R1 最終 `24`、`25`、`22`）。首次全套 `17` 有 10 個既有 source-wiring 契約失敗（候選曾改動最終守門呼叫處文字）；已還原呼叫處、改為操作 wrapper 回傳後才記 pre-API 診斷，未修改任何既有契約測試。既有 UI 測試只把 `register_key`／`register_windows_hello` 的 mock 回應改成新 IPC 形狀。實機（SKYCITY-PC／Win11-NB）尚未驗證。

### 12.5 R1 Reviewer 否決與 R2 修正候選（2026-10-14）

- R1 completed-code Reviewer `passed=false`，blocking S1／L1／L2／L3／T1；verdict 保留 `D:/project/_archives/portable-fido2-vault/wh-d9f1-review-20261014-R1/reviewer-verdict.json`。不得將 R1 的長套件 461/461、132/132 當作 R2 驗證，也不得宣稱實機成功。
- S1：`continue_registration` 在 state mutex **內**使用即時 clock，raise 前與 raise 返回、take pending 前各檢查一次，逾時取消並以 RP membership 證明後 best-effort 清除，斷言不啟動；排隊跨期限及 raise 跨期限為行為測試。L1：Hello 120 秒期限自 MakeCredential 第一階段返回後起算，原先較早的時間只用於 lazy sweep；再次 handoff 不延長期限。
- L2：清理失敗時 pending 機密立即清零，`AppInner.registration_cleanup_receipts` 僅存非機密 generation／reason／cleanup；逾時、上鎖、lazy sweep、其他登入與新 pending 不抹去舊失敗收據。`registration_cleanup_status` 唯讀 IPC 與 `acknowledge_registration_cleanup(generation)` 明確確認後才移除該代收據；登入／UI reload／進入主畫面可查詢並以 `textContent` 顯示警告。**收據僅在 GUI process 記憶體；若整個程式退出則不保證跨 process 保留，須在 R2 review 評估是否為阻擋。**
- L3：roaming 登記寫檔失敗回滾完整 header 與 audit（含裁切），single／dual 的 tmp-write／rename failure 及原 direct 路徑均有負向測試；不嘗試刪除 roaming passkey。T1：舊世代 sweep、新 pending、逾時與 cancel 競爭、金庫路徑不符、第二次 continue、查詢／確認收據均新增行為測試。
- parent 自行執行 R2 targeted RED→GREEN 原始記錄：L3 `27`→`28`（5/5）、S1 `31`→`32`（後續 S1+L3 7/7）、L1 `33`→`34`（8/8）、L2 core `35`→`36`、IPC `39`→`40`、UI `38`→`41`；Rust handoff targeted `48` 49/49、相關 UI `49` 67/67。R2 完整 suite／獨立 R2 reviewer／hosted CI／Release／實機均尚未完成。

### 12.6 R2 Reviewer 否決與 R3 本機候選（2026-10-14）

- R2 唯讀 completed-code verdict `passed=false`、`coverage_complete=true`，原檔 `D:/project/_archives/portable-fido2-vault/wh-d9f1-review-20261014-R2/reviewer-verdict.json`。S1／L1／L3 維持修正；L2 仍缺 process-exit 持久收據、timer/lazy 通知與 async query 排序、continue 刪除失敗結果；T1 尚需受控 clock／跨重啟精確確認。R2 不得推至 Release／實機。
- R3 改以使用者 `%LOCALAPPDATA%/FidoVault/registration-cleanup-v1/` 的非機密、每筆 128-bit 隨機 ID 收據（僅 reason tag）持久化；`create_new` 防碰撞、`sync_all`、損毀紀錄保守顯示 unknown，ack 精確驗證 ID 並刪除個別檔案；沒有儲存 credential ID、PIN、PRF、主密碼、視窗標題或完整執行檔路徑。GUI restart 再查狀態，記憶體寫入失敗以 `storage_unavailable` 立即示警且不得阻擋 lock；若 `%LOCALAPPDATA%` 缺失／收據不可讀，啟動亦保守顯示儲存不可用。**磁碟本身不可寫且程式退出時無法保證保留新收據；此為物理限制，介面會明示。** 不代表已發現實體 orphan passkey。
- 第二階段 cleanup 刪除失敗以 `Vault::take_registration_cleanup_failure()` 的一次性非機密 side-channel 回報並留下持久警告；原始 `VaultError` 型別與訊息（包含既有 D4 failure contract）及 fail-closed slot rollback 均保留。UI 在 lazy 註冊返回後刷新、handoff 期間每 3 秒輪詢，並以 query sequence 防舊回應覆蓋新警告；不自動清理未知 passkey、不搶焦點。計時測試改用受控 clock（first ceremony、mutex 排隊、raise 中跨期限），無 120 秒 wall-clock 等待。
- R3 RED→GREEN 證據：UI `50/51`→`52`、delete-failure report 初版 `54`→`55`（其後完整套件 `73` 揭露 D4 primary error 合約回歸，已改一次性 side-channel 並以 `74`／`75` 恢復）、journal 契約 `62`→`63`、fresh state `64`→`65`。最終 R3 MSVC Rust `real-ctap` **483/483**（`76`）、dual **483/483**（`77`）、Node **136/136**（`70`）；completed-code review／exact-head CI／Release 或實機尚未完成，待獨立審查後再決定。

### 12.7 R3 Reviewer 否決與 R4 本機候選（2026-10-14）

- R3 completed-code verdict `passed=false`、`coverage_complete=true`、security 0（`D:/project/_archives/portable-fido2-vault/wh-d9f1-review-20261014-R3/reviewer-verdict.json`；首次審查因 provider 429 未執行，log 保留於 `reviewer-R3/attempt1-429/`）。S1／L1／L3／L2B 關閉；阻擋 L2-R3-A、L2-R3-C、T1-R3、T2-R3。
- **L2-R3-A：** journal 成為權威狀態。`registration_cleanup_status_inner_unlocked` 成功列舉時以磁碟收據取代記憶體快取中的所有持久項目（保留同 ID 的 generation 與 `memory-*` fallback），因此其他程序 ack 後原程序不再誤報、重啟後未 ack 的收據會出現；`cancel` 無 pending 與 `continue` 無 pending 皆改經同一 `has_unacknowledged_cleanup()`（journal 無法讀取時保守視為仍有警告）。
- **L2-R3-C：** `Vault` 一次性 side-channel 改為 `RegistrationCleanupReport { Removed, DeleteFailed, NotAttempted }`。`continue_registration` 包裝層：新的 platform pending 在任何前置失敗（能力不可用、RP discovery 失敗、membership 無法證明、label／edition）被消耗而無清理結論時回報 `NotAttempted`；既有 slot 的 credential ID 永不視為新 credential。`begin_register_windows_hello` 在 MakeCredential 之後的 discovery 失敗／membership 不成立／header 解碼失敗亦回報 `NotAttempted`。lib 將 `DeleteFailed`→`continue_error`、`NotAttempted`→`unverified` 寫入持久收據；未證明者仍**不刪除**，原 primary `VaultError` 不變。UI 以專屬文字提示「無法確認是否已清除，只檢查本次測試項目」。
- **其他硬化：** journal ID 改 `try_fill_bytes`（熵失敗回 I/O 錯誤而非 panic）、經 handle 的有界讀取（≤64 bytes，否則 `unknown`）；`LOCALAPPDATA` 空字串或相對路徑視為儲存不可用；UI ack 的 `finally` 不再重新啟用 journal-unavailable 的按鈕。
- **T1-R3：** L1 改以 MakeCredential seam 內推進的合成時鐘驗證期限；排隊測試在持鎖期間觀測「不得讀 clock」並確認 worker 仍在等鎖；race 檢查雙方回傳值、focus／assertion／delete 次數與收據；新增固定兩順序 sweep/cancel、journal ID 碰撞、write/sync 失敗、損毀／超長／非檔案收據、root 不可讀、惡意 ID ack、LOCALAPPDATA、lib 寫入失敗跨重啟、多收據 UI、ack 後按鈕、poll 停止等 oracle。
- **T2-R3：** 自然 assertion RED：`80`（6 個後端，均在預期斷言行失敗；既有 slot 控制測試保持通過）、`81`（UI ack 按鈕）→ GREEN `84`／`83`。已有正確行為的 oracle 以 13 個**可編譯的受控反向 mutation** 取得 assertion RED（`evidence/r4-mutations/`，最終格式化 source 上 13/13 `red_ok`，每次以 SHA-256 驗證還原；格式化前一輪保留於 `r4-mutations-prefmt/`，M12 首輪 unwrap panic 已改明確斷言並標 SUPERSEDED）。`82`、`85` 為編譯失敗，已標 `NOT_EXECUTED`，不計為 RED。
- **格式：** 只套用觸及 R1–R4 變更行的 rustfmt hunk（`--config skip_children=true`）；`88` 稽核顯示觸及 hunk 全為 0，`windows_webauthn.rs` 37 個 BASE 既有差異未動。
- **驗證：** R4 MSVC Rust `real-ctap` **500/500**（`90`）、`real-ctap,dual-control` **500/500**（`91`）、Node **139/139**（`92`）、`node --check`、`git diff --check` 通過。completed-code review、exact-head CI、Release 與 SKYCITY-PC／Win11-NB 實機 V1/V2 尚未完成。

### 12.8 R4 Reviewer 否決與 R5 本機候選（2026-10-14）

- R4 completed-code verdict `passed=false`、`coverage_complete=true`、security 0、logic 0（`D:/project/_archives/portable-fido2-vault/wh-d9f1-review-20261014-R4/reviewer-verdict.json`）。L2-R3-A、L2-R3-C、T2-R3 關閉，S1／L1／L2B／L3 無回歸；剩餘阻擋僅測試 T1-R4-A、T1-R4-B。
- **T1-R4-A：** `VaultState::with_lock` 在 `cfg(test)` 下先 `try_lock`，`WouldBlock` 時觸發每執行緒的 `lock_wait_hook`（模組位於測試區，production 編譯不含）。排隊測試只在 worker **確實卡在 state mutex** 後才推進時鐘；未到達即測試失敗（30 秒上限），不再以 300 ms 未觀察推定。到達後以 `try_recv` 檢查此前不得有任何 clock 讀取。
- **T1-R4-B：** journal 寫入改為單一 `write_receipt` 處理點，分別注入「建立後失敗（空檔）」「寫一半失敗」「寫完後 sync 失敗」三種模式；三者在 journal 與 lib 層（目前程序 fallback 警告、無 pending cancel、重啟後保守可見）均有 oracle。新增端到端矩陣 {begin, continue} × {assertion 錯誤, PRF 不符, 存檔失敗} × {刪除成功, 刪除失敗}（12 例）檢查原 primary error、精確 create/assert/delete、slot rollback、durable 收據、cancel 與 fresh state，其中「刪除成功不得留下收據／不得升級為 NotAttempted」為負向 oracle。另補 continue 的 Removed 保留、begin 方向 reset、`memory-*` fallback 與同 ID generation 保留（連續兩次同步無遺失、無重複）。
- **非阻斷建議採納：** UI 以獨立 `registrationCleanupAckInFlight` 統一計算確認按鈕（輪詢不得在 ack 進行中重新啟用；自然 RED `93`→GREEN `94`）；`unverified` 專屬文字與關閉 handoff 確實 `clearTimeout` 有測試；同步快取改用 HashMap 索引。持鎖 journal I/O 的延遲上界仍未證明，維持為已知限制。
- **Mutation runner 強化：** `r5-mutations.py` 預檢全部錨點、拒絕空選集、要求指定測試實際執行且所有 FAILED 測試符合 filter、拒收 unwrap 類 panic，並逐筆記錄原始／還原 SHA-256。最終格式化 source 上 **19/19** 為 assertion RED（`evidence/r5-mutations/`、`98`），其中 M14–M19 為 R5 新增。`95` 為既有 source-wiring 守門測試抓到測試模組誤放在 production 區（已移入測試區），不是產品缺陷。
- **格式用語更正：** 先前「只修觸及行」應精確為「只套用與 R1–R5 變更行相交的 rustfmt hunk（可能含相鄰舊行）」；腳本現固定比對 BASE `5d34ccf`。`97`：五檔相交 hunk 為 0，`windows_webauthn.rs` 37 個未相交的 BASE 既有差異未動；完整 `cargo fmt --check` 不宣稱 PASS（非 CI 必要 gate）。
- **驗證：** R5 MSVC Rust `real-ctap` **507/507**（`99`）、`real-ctap,dual-control` **507/507**（`100`）、Node **142/142**（`101`）、`node --check`、`git diff --check` 通過。completed-code review（Reviewer＋Officer）、exact-head CI、Release 與實機 V1/V2 尚未完成。

## 13 D9-F2 WebAuthn 指令移出主執行緒

**狀態：候選，待審查，未實測。** 本節不改動 D1–D9 勾選；沒有 GUI、native WebAuthn、實體金鑰、正式金庫（`C:\FidoVault`）或部署操作。D9-F1 的 A+C（繼續驗證／取消、前景診斷、持久收據）完整保留，守門條件未放寬。

### 13.1 根因與證據

- 所有 WebAuthn IPC 原為同步 `#[tauri::command] fn`。Tauri v2：「Commands without the async keyword are executed on the main thread unless defined with `#[tauri::command(async)]`」。MakeCredential／GetAssertion 在主（UI）執行緒同步阻塞 → owner 視窗不處理訊息 → Windows Hello 提示框停在背景 → 臉部辨識後 Ngc 回 `0x80090029` → Windows 退回「選擇安全性金鑰」→ 使用者取消 → 程式只看到 `0x800704C7`。
- 證據（SKYCITY-PC，`D:/scratch/wh-d9f2-diag-20261015/DIAG-NOTES.md` 第 6、7 輪）：probe7 以產品相同請求值在 console probe 通過；probe8 自建 Win32 視窗當 owner、相同 RP／salt／名稱／選項，**worker thread 呼叫 PASS（提示框前景）、在 UI thread 內呼叫 FAIL（症狀與產品完全相同）**。
- 另觀察：Ngc 失敗後 Windows 可能讓使用者以 YubiKey 完成「PLATFORM」請求（事件 2104 MicrosoftCtapHidProvider、attachment cross-platform）；因此新增非 platform 憑證拒絕（§13.4）。

### 13.2 決策（使用者）

修正範圍＝**全部 WebAuthn 指令**（含 YubiKey 註冊／登入、雙人登入）移出主執行緒；接受回歸範圍擴大，**YubiKey／RDP 之後需重新實機驗收**。

### 13.3 盤點（`invoke_handler` 全部 36 個 IPC）

| 指令 | 觸及 WebAuthn／backend | 會顯示 UI | 改法 |
|---|---|---|---|
| `register_windows_hello` | MakeCredential＋GetAssertion（platform） | 是 | `(async)`＋KeyOperationGuard |
| `login_windows_hello` | GetAssertion（platform） | 是 | `(async)`＋Guard |
| `register_key` | MakeCredential（roaming） | 是 | `(async)`＋Guard |
| `continue_registration` | GetAssertion（pending 第二階段） | 是 | `(async)`＋Guard |
| `login_key` / `login_any_key` | GetAssertion（roaming） | 是 | `(async)`＋Guard |
| `login_dual_begin` / `login_dual_complete` | GetAssertion（雙人） | 是 | `(async)`＋Guard |
| `lock` | 取消 pending 時 platform 清單／刪除 | 否（可能阻塞） | `(async)`；ceremony 中只記錄待上鎖；idle 時 native 清理在鎖外（R2） |
| `cancel_registration` | platform 清單／刪除 | 否（可能阻塞） | `(async)`；ceremony 中拒絕 |
| `create_vault` | 取消 pending 時 platform 刪除 | 否（可能阻塞） | `(async)`；ceremony 中拒絕 |
| `login_password` | `open_password_with_platform`（platform 清單） | 否（可能阻塞） | `(async)`；ceremony 中拒絕 |
| `remove_key` | platform 清單／刪除 | 否（可能阻塞） | `(async)`；ceremony 中拒絕 |
| `boot_info` | platform 清單、`platform_status` | 否（可能阻塞） | `(async)` |
| `platform_status` | IsUVPAA、platform 清單 | 否（可能阻塞） | `(async)`；ceremony 中回「進行中」 |
| `detect_key` | `peek_kind`／`key_unavailable_reason`（不呼叫 OS） | 否 | `(async)`（持有狀態鎖並經 trait 呼叫，保守處理） |
| `login_dual_cancel` | 否 | 否 | R2：進行中的金鑰操作期間回「進行中」（同一短鎖內 `require_key_operation_idle`），不再「取消成功但流程仍發布」 |
| `get_edition`、`list_entries`、`add_entry`、`update_entry`、`delete_entry`、`list_audit`、`validate_key_label`、`suggest_key_label`、`set_idle_lock`、`set_dual_step_timeout`、`get_vault_settings`、`set_password_history_limit`、`cancel_csv_import`、`apply_csv_import`、`registration_cleanup_status`、`acknowledge_registration_cleanup`、`clear_clipboard_if_matches` | 否（只動記憶體狀態／金庫／journal／剪貼簿） | 否 | 不變（同步，狀態鎖只短暫持有） |
| `preview_csv_import`、`save_csv_template` | 否（檔案對話框） | 檔案對話框 | 已是 `async fn` |

契約測試（§13.5）要求：此表的每個 IPC 都被分類；WebAuthn 類必須是 `#[tauri::command(async)]` 或 `async fn`；新增 IPC 未分類即失敗；非 WebAuthn 類的函式本體**及其（遞迴追蹤的）自由函式呼叫鏈**不得出現 `backend`／`KeyOperationGuard`／`raise_key_operation_window`／`platform_status`／`list_platform_credentials`／`delete_platform_credential`（R2；方法呼叫與 `path::call` 不追蹤，仍屬人工分類表的範圍，不是完整 call-graph 偵測器）。

### 13.4 設計

- **狀態鎖不跨 ceremony 持有（`KeyOperationGuard`）：** 每個 WebAuthn 指令在任何前景／backend 動作前呼叫 `KeyOperationGuard::begin`：在短暫的狀態鎖內檢查 `key_op.active`（已有進行中操作 → 立即回「已有金鑰操作進行中，請先完成或取消」，不排隊、不碰前景、不呼叫 backend）、執行該指令的前置檢查、標記 active，並把真正的 backend（及註冊／繼續註冊所需的已解鎖金庫）**租出**，原位換成 `BusyBackend`（任何 authenticator 呼叫回錯、`key_unavailable_reason` 為「進行中」）。ceremony 在**不持有狀態鎖**時執行。`complete` 重新取鎖、歸還 backend／金庫、套用結果、執行待上鎖、清除 active；`Drop`（錯誤、提前返回、panic）同樣歸還、執行待上鎖並清除 active。因此 `list_entries`、`get_vault_settings`、`lock` 等指令即使在主執行緒也不會等待 ceremony；金庫被租出時它們回「進行中」而非「金庫未解鎖」，UI 不會誤判為已上鎖。
- **ceremony 期間的上鎖：** `lock`（含 idle 觸發）在 active 時不阻塞，只記錄待上鎖並用金庫檔頭回登入畫面資訊；ceremony 結束、回傳前完成上鎖。登入類：結果丟棄（`v.lock()`），回「金鑰操作期間已收到上鎖要求…」不含條目；註冊類：沿用既有 lock 語意（pending 以 `queue_pending_cancellation(…, "locked")` 排入佇列，由持有 backend 租約者在鎖外取消；platform credential 以 RP 清單證明後刪除並沿用 D9-F1 收據），pending 被取消時回上述錯誤，已完成的註冊（slot 已持久化）回原結果後上鎖。
- **改變金庫的指令：** `create_vault`（在建立檔案前檢查）、`remove_key`、`login_password`、`apply_csv_import`、`cancel_registration`、`platform_status` 在 ceremony 中回「進行中」，不改狀態。逾時 sweep 在 active 時略過（backend 被租出）；R2 起 `complete` 與 `Drop`（含 panic）的收尾一律補做（見 §13.7）。
- **世代／金庫路徑：** 因 ceremony 期間所有會改金庫、pending、世代的指令都被拒絕或延後，租出的金庫與 pending 不可能被其他指令改動；歸還後的寫入沿用原有的世代檢查（continue 的期限／金庫路徑在租出前、raise 後各檢查一次）。
- **前景守門不放寬：** `raise_key_operation_window`、`set_webauthn_parent_hwnd`、`validate_owner_foreground`、continuation／passive 判斷條件沒有修改；沒有新增 SetForegroundWindow／AllowSetForegroundWindow／AttachThreadInput。從工作執行緒呼叫的正確性：`window.hwnd()` 直接讀取；`unminimize`／`show`／`set_focus` 由 Tauri 派送到主執行緒（現在主執行緒不再被阻塞所以能處理）；`GetForegroundWindow`／`IsIconic`／`IsWindowVisible` 與執行緒無關；`SetForegroundWindow`／`ShowWindow` 的呼叫次數與條件不變。這與 probe8 的 worker thread PASS 呼叫形態一致，**仍待實機確認**。
- **非 platform 憑證拒絕：** platform MakeCredential 成功後、複製 credential ID 之前，以純函式檢查 `dwUsedTransport` 必須含 `WEBAUTHN_CTAP_TRANSPORT_INTERNAL`（0x10）；先只讀 `dwVersion`：僅接受此平台 PRF 路徑既有的 v7／v8 版面，其餘版本（含 v1–v6、未知）一律以 `PlatformPrfUnsupported` 拒絕（fail closed），**通過版本檢查後才讀取** `dwUsedTransport`（該欄位依官方 `webauthn.h` 為 attestation **v3** 新增，不是 v4；v3 在此被拒是因為此路徑只信任 v7／v8，而非欄位不存在）。不符 → 新 `FidoError::PlatformAuthenticatorSubstituted`：不寫 slot、不嘗試 platform 刪除該 ID（尚未建立 pending-delete guard）；vault 層回報 `RegistrationCleanupReport::NotAttempted`，lib 層留下持久「unverified」收據。
- **診斷：** platform MakeCredential／GetAssertion 的 `api-error` 在 `[WebAuthN-platform-operation]` 增加 `hresult`（`0x%08X`）與 `error_name`（`WebAuthNGetErrorName`：含非 ASCII 英數字的名稱整個丟棄為 null；全為 ASCII 英數字但超過 64 字元者**截斷**為前 64 字元）；未發生 API 失敗時不輸出這兩欄（既有 record 形狀不變）。不記錄 credential、PRF、PIN、標題、完整路徑。

### 13.5 測試清單（證據 `D:/scratch/wh-d9f2-20261015/evidence/`）

- 契約：每個 IPC 已分類；WebAuthn 類為 async（`07` RED→`08` GREEN；反向 mutation 拿掉 `register_key` 的 `(async)` → `09` RED）；非 WebAuthn 類不碰 backend；偵測器對 sync／async／無屬性函式的判斷。
- 非 platform 憑證與診斷：transport 位元全組合與版本不足、Display 精確文字、vault 層無 slot／不刪除／`unverified` 收據、診斷欄位 exact allowlist 與消毒（`01`→`03`；vault `02`）。
- ceremony 並行（`05` RED→`06` GREEN）：停住的登入 ceremony 期間 `list_entries`／`get_vault_settings`／`platform_status`／`lock` 於 2 秒內返回；登入中上鎖→結果丟棄、金庫保持上鎖；註冊成功中上鎖→回傳前上鎖；handoff 中上鎖→pending 取消並刪除；第二個金鑰操作（8 種入口）立即被拒且未呼叫 raise／backend；guard 於錯誤、前景失敗、panic 後釋放且 backend 歸還；panic 後仍執行待上鎖（`11`）；`create_vault`／`login_password`／`remove_key`／`cancel_registration`／`apply_csv_import` 在 ceremony 中被拒且狀態不變。
- 既有測試調整：`wh_d5_login_publishes_and_clears_pending_under_one_lock` 原斷言「raise 時狀態鎖被持有」（正是本項要移除的行為），改為斷言「鎖未被持有且 operation 標記為進行中」；發佈仍在同一把鎖內。其餘既有 source-wiring 契約測試未改（`#[tauri::command(async)]` 讓以 `#[tauri::command]` 切割的測試取到較長文字，斷言仍成立）。
- UI：`tests/key-operation-inflight-ui.test.cjs`（8 項，特徵化測試，無 RED：既有 UI 已在 IPC 前停用觸發鈕）。
- R1 全套（舊）：MSVC `real-ctap` 523/523（`14`）、`real-ctap,dual-control` 523/523（`15`）、Node 150/150（`16`；基線 507／507／142，`00`）。

### 13.6 殘留風險與未完成

- **YubiKey（單人／雙人）與 RDP 路徑需重新實機驗收**；Win11-NB 行為需重驗。工作執行緒呼叫 Windows Hello 的實機結果（SKYCITY-PC）尚未驗證；尚未有 GUI 實測。
- ceremony 期間 UI 不再凍結：使用者可點「上鎖」（登出畫面出現但提示框仍在，結果會被丟棄）或其他按鈕（以「已有金鑰操作進行中」拒絕）；頁面重新載入不會得知進行中狀態。
- 同一程序內一次只有一個金鑰操作；ceremony 期間 `boot_info` 的 platform 本機清單不可用（視同未知）。
- mock Gate（單人／Hello／雙人）需要 Release 範例建置，本次規則禁止 Release build，**未執行**，留待 CI。
- 尚未完成：獨立 completed-code review、exact-head CI、Release 與實機驗收。

### 13.7 R1 審查否決與 R2 修正

**狀態：候選，待審查，未實測。** R1 Reviewer 與 Officer 均否決（`reviewer-R1`／`officer-R1`）。R2 逐項修正如下（證據 `D:/scratch/wh-d9f2-20261015/evidence/`，R1 舊 log `00`–`16` 未改動；RED＝自然 assertion failure，已正確者以可編譯反向 mutation 取得，含原始／還原 SHA-256 於各 log）。

| 項 | 修正 | RED → GREEN |
|---|---|---|
| S1 已解鎖金庫可讀寫 | 所有金鑰**登入**（單人 key、any key、Hello、dual begin／complete）改走 `KeyOperationGuard::begin_login`：同一短鎖內若金庫已解鎖即拒絕（「金庫已解鎖；請先上鎖後再以金鑰登入」），不碰前景／backend；`with_unlocked` 與 `preview_csv_import` 先 `require_vault_readable`（active → 進行中；pending_lock → 已收到上鎖要求）才接受 `Some(v)`。 | `27` → `29` |
| S2 逾時補掃被 active 擋掉 | 計時器改 `sweep_expired_registration_off_lock`（active 時略過）；`complete` 與 `Drop`（含 panic）收尾一律補做：到期 pending 排入佇列，於**鎖外**用租出的 backend 取消並記收據。 | `27` → `29` |
| S3 版本檢查前讀 transport | `require_internal_platform_transport(read_version, read_transport)` seam：先只讀 `dwVersion`，非 v7／v8 → `PlatformPrfUnsupported`，之後才讀 `dwUsedTransport`；source 順序測試確認在 `copy_api_bytes`／`PendingPlatformCredential`／PRF 之前。文件／註解更正為 attestation **v3** 新增 `dwUsedTransport`。 | `23` → `24` |
| L1 create_vault 競態 | `create_vault_inner` 先 `begin_native`（程序內保留，與所有金鑰操作互斥，第二個呼叫立即「進行中」），保留跨越 exists／KDF／建檔／發布；`Vault::create_for` 改以建立專用隨機 tmp 檔 + `hard_link`（目的檔已存在即失敗；無 hard link 的磁碟區退回 `create_new`）；前端 `doCreate` 與各登入入口共用 `authFlowInFlight`。 | Rust vault `25` → `26`；lib `27` → `29`；Node `35` → `36` |
| L2 持鎖 native 清理 | 新增租約模型：所有會呼叫 platform status／list／delete 的路徑（Guard complete 的 deferred-lock 與到期清理、continue 逾時、idle `lock`、`cancel_registration`、`remove_key`、`login_password`、`create_vault`、`platform_status`、`boot_info`、到期計時器）一律租出 backend，native 在鎖外執行，再以短鎖發布收據。10 個情境讓 platform list／delete 阻塞，`list_entries`／`get_vault_settings`／`registration_cleanup_status` 於 2 秒內返回。 | `27` → `29` |
| L3 `login_dual_cancel` | 擇「進行中立即回 busy」（同一短鎖內 `require_key_operation_idle`）；理由：不需 cancellation generation，不新增狀態；第一／二步 ceremony 中呼叫 cancel 皆回進行中，第一步暫存不被動到。 | `27` → `29` |
| T1 RED 分類 | R1 的 `01`（對 `Option::unwrap()` panic）與 `02`（停在 `TODO-D9F2` 訊息，尚未到 NotAttempted 斷言）**更正分類為非合格 RED**，log 保留。測試改為明確 `assert_eq!`；精確反向 mutation：拿掉 sanitation（`20`）、拿掉 NotAttempted 回報（`21`）皆 assertion RED，還原後 GREEN（`22`）。 | `20`／`21` → `22` |

非阻擋建議採納：契約測試加 helper 邊界遞迴偵測（`32`；間接呼叫 mutation `33` RED，舊的本體掃描測試在同一 mutation 下仍綠）；`wh_d5_login_publishes_and_clears_pending_under_one_lock` 加指向觀察測試的註解，新增 sampler 觀察測試與「拆鎖」負向控制（mutation 拿掉 reset → `34` RED）；Node 以未完成 Promise 模擬雙擊／PIN 與密碼欄 Enter／跨登入方式（`35` RED → `36`）；`error_name` 超長實際行為為**截斷**，文件已一致。

驗證：MSVC `real-ctap` **542/542**（`40`）、`real-ctap,dual-control` **542/542**（`41`）、Node **155/155**（`42`）、`node --check src/app.js`、`git diff --check`（僅 CRLF 提示）。mock Gate、Release、實機仍**未執行**。

殘留／限制：`hard_link` 退回 `create_new` 的路徑只有單元測試；租約模型使 `platform_status`／`boot_info` 等短暫呼叫期間 `list_entries` 也可能回「進行中」（已登入金鑰管理頁也會呼叫 `boot_info`）；`login_dual_cancel` 在 ceremony 期間不可取消（等 ceremony 結束或逾時）。

### 13.8 R2 Reviewer 否決與 R3 最小修正候選

**狀態：R3 候選，未獨立審查／mock Gate／Release／CI／實機。** R2 Reviewer `passed=false`（完整唯讀結論 `D:/scratch/wh-d9f2-20261015/reviewer-R2/reviewer-verdict.json`；R1 的 S1–S3、L1–L3、T1 與 Officer 原建庫競態已判定關閉）。Officer R2 因 Claude session limit 僅產生額度錯誤，**沒有 verdict**；不可稱雙審查通過。

- **R2-S4（高）：** `KeyOperationGuard::finish` 在第一短鎖產生登入條目後，鎖外清理期間才收到 lock 時仍回 `Ok(entries)`。R3 在每次短鎖保留本次操作的上鎖訊號，不依賴被 `follow_up_work` 消耗的 pending 狀態；五個登入入口改用 `complete_login`，在最後短鎖以同一原子決策丟棄條目結果並釋放 active。決定性測試：native delete 阻塞時上鎖 `50` assertion RED → `52` GREEN；沒有 cleanup job 的兩鎖間隙控制測試 `53` GREEN。`51` 曾因 closure lifetime 編譯失敗，**非 RED/GREEN 證據**。
- **R2-L4（中）：** 新建金庫專屬暫存檔成功開啟後，`write_all`／`sync_all` 失敗時 `?` 跳過清理。R3 在寫入失敗時先關閉自己的 handle 再清除自己的 tmp；link/fallback 後同樣檢查**自有 tmp** 的清理結果，不再吞掉 tmp 清理錯誤。若清理本身失敗，回明確錯誤指出目的檔**可能已建立**、須檢查既有金庫且不可重試建立。write/sync fault injection `54` assertion RED → `55` GREEN。**無法保證在 OS 拒絕刪除時無殘留；需人工檢查，不能宣稱此故障路徑已實機驗證。**

此輪完整本機回歸：MSVC `real-ctap` **545/545**（`56`）、`real-ctap,dual-control` **545/545**（`57`）、Node **155/155**（`58`）；均 exit 0。這些結果不能取代獨立審查與實機驗收。

### 13.9 R3 Reviewer 否決與使用者授權的 R4 局部修正

R3 Reviewer 唯讀 verdict `D:/scratch/wh-d9f2-20261015/reviewer-R3/reviewer-verdict.json` 為 **不通過**：R2-S4 已關閉；R2-L4 尚有在 `hard_link` 不支援時，exclusive fallback 建立目的檔後寫入／同步失敗、再遇到目的檔刪除失敗會吞掉 cleanup 錯誤的殘支。使用者於第三輪否決後明確選擇「只修正這個替代寫入的錯誤回報與清理測試，再送審」，不擴大發布架構。

R4 增可注入 write／sync／remove 的 fallback seam，先在 `create_new` 取得自有目的檔後執行寫入／同步，關檔後若失敗則檢查移除結果；移除成功保留原始 I/O 錯誤；移除失敗回傳含**寫入與清理兩個錯誤**、目的檔可能殘留不完整及**勿重試建立**的明確訊息（外層仍會清理自己的 tmp，並透過 `VaultError::Io` 顯示文字）。只刪本次成功 create_new 所取得的檔案，既有目的檔依 `create_new` 拒絕，不可覆寫。決定性 fixture 注入：`60` 一項 assertion RED、另一項 control 通過 → `61` 兩項 GREEN；test cleanup 只清其自有合成 fixture。**若 OS 拒絕刪除，仍可能留下不完整 vault.db，不能宣稱無殘留；只保證不靜默吞掉，使用者必須人工檢查。** 本段仍是候選。本機全套 MSVC `real-ctap` **547/547**（`62`）、`real-ctap,dual-control` **547/547**（`63`）、Node **155/155**（`64`），production check 單人／雙人均 exit 0（`parent/p20`／`p21`）。獨立審查／mock Gate／Release／CI／實機驗收待進行。

### 13.10 R4 Reviewer 否決與 R5 錯誤合併（仍限原授權範圍）

R4 Reviewer `D:/scratch/wh-d9f2-20261015/reviewer-R4/reviewer-verdict.json` 為 **不通過**：當 fallback 目的檔寫入／清理都失敗，且之後 tmp 也清理失敗時，外層只回 tmp 警告而遮蔽目的檔的詳細錯誤。R5 只在本次 create_new 專屬檔案的清理分支合併錯誤，不更改建庫發布架構：外層保留 fallback 的寫入、目的檔刪除失敗與「可能殘留不完整」訊息，再附 tmp 刪除失敗；若 tmp 自身寫入與清理都失敗，也保留原始寫入原因。

決定性合成 fixture：兩檔清理同時失敗 `70` assertion RED → `71` GREEN；tmp 自身寫入＋清理雙失敗 `72` assertion RED → `73` GREEN。測試僅於測試 fixture 清除自己建立的兩個檔案，絕不碰真金庫。**實際 OS 拒絕刪檔時可能殘留；訊息引導使用者檢查而非盲目重試，並非自動恢復。**

本機完整套件：`real-ctap` **549/549**（`81`）、`real-ctap,dual-control` **549/549**（`80`）及 Node **155/155**（`76`），production check 單人／雙人 exit 0（`parent/p22`、`p23`）。先前雙人套件於 Windows C: TEMP 路徑遭遇既有測試 fixture 的 `PermissionDenied`，第一次 547/549（`75`）、重跑仍有一例（`79`）；兩項單獨重跑均 PASS（`77`、`78`），改將該輪 `TMP`、`TEMP` 指向 `D:/scratch/wh-d9f2-20261015/test-fixtures` 後全套 549/549。**僅證實差異與最後結果，未證明 C: TEMP 拒絕的根因，不得隱藏失敗紀錄。** R5 仍是候選，待獨立審查／mock Gate／Release／CI／實機。
