# 可攜式 FIDO2 密碼金庫 v0.1 — 技術規格書

> 專案：`portable-fido2-vault`｜卡：t_31e9ef5e｜語言介面：繁體中文
> 雙群組控管版（v2 金庫、`portable-fido-vault-dual.exe`）：§3.1、§5.5、§6.1、§8.1；開發中（PR #29 draft，實機驗收待執行），設計決策見 `docs/plans/dual-control.md`。
> 目標平台：Windows 10/11 x64；目標機須確認 WebView2 Runtime 可用，硬體版 GUI 需 Windows WebAuthn API v4+，於本機 Console 或已驗證矩陣內的 RDP session（WebAuthn 重新導向）操作；RDP 支援範圍見 `docs/rdp-webauthn-verification.md` R6。WebAuthn 不可用（API < v4）時 GUI 仍啟動，僅主密碼可用、金鑰操作 fail closed。Windows 11／Edge 已安裝不代替 Runtime 檢查。

## 1. 目標 / 非目標

**目標**
- Windows 桌面 App，完全離線（零網路呼叫；Tauri 不啟用任何 http 插件）。
- 可攜：GUI EXE、同一發行套件的 x64 `WebView2Loader.dll` 與既有 `vault.db` 同資料夾攜帶；目標機另須 WebView2 Runtime。免安裝本程式，不代表無系統 prerequisites；Loader 與 Runtime 不可互相取代。既有金庫須正常關閉後備份／搬移，不刪除或重建 DB；完整程序見 README 的 portable 部署章節。
- 首次執行建立帳號（主密碼）；之後**主密碼或任一支已註冊 FIDO2 金鑰**皆可登入（允許多支）。
- 金鑰類型自動偵測：指紋型 / PIN 型 / touch-only；登入時依類型給正確提示。
- 加密儲存：Argon2id + AES-256-GCM，整個金庫加密為單一檔案。
- CRUD（網站/帳號/密碼/備註）＋ created_at/updated_at ＋ 每筆條目舊密碼歷史（預設 3 代，可設 1–20）＋ 軌跡紀錄（絕不明文記錄密碼）＋ 閒置自動上鎖。

**非目標（v0.1）**
- TOTP、密碼產生器、雲端同步、多使用者、行動裝置。
- **無復原機制**（設計如此，UI 明示）。

## 2. 架構

```
┌─────────────────────────── Tauri v2 (Rust) ───────────────────────────┐
│  前端 (src/): index.html + app.js + styles.css — 純靜態、無 npm、繁中   │
│    window.__TAURI__.core.invoke(...) → commands                        │
│    window.__TAURI__.clipboardManager → text copy / conditional clear   │
│    native Rust dialog → choose CSV / save header-only template         │
├─────────────────────────────────────────────────────────────────────────┤
│  src-tauri/src/lib.rs      — Tauri commands + VaultState (Mutex)        │
│  src-tauri/src/vault.rs    — 金庫檔案格式 / 載入 / 建立 / 加密落盤       │
│  src-tauri/src/crypto.rs   — Argon2id KDF / AES-256-GCM / HKDF          │
│  src-tauri/src/fido2.rs    — FidoBackend trait + Mock/Real CTAP2        │
└─────────────────────────────────────────────────────────────────────────┘
```

- **狀態**：解鎖後 KEK（32B，`Zeroizing<[u8;32]>`）與金庫資料僅存於記憶體；上鎖即清零。
- **落盤策略**：任何變更 → 以記憶體 KEK 重新加密整個 payload → 暫存檔 + rename 原子寫入。
- **FIDO2 後端**：trait `FidoBackend`（detect / register_credential / get_prf_secret）。
  - `MockBackend`（feature 預設）：軟體金鑰，實作 hmac-secret 語義（HMAC-SHA256），供無硬體環境端到端驗證。
  - Real CTAP2 後端：CTAP2 `getInfo` + `authenticatorBioEnrollment`(0x09) + `makeCredential`/`getAssertion`（含 hmac-secret extension）。函式庫選型見 §5.4。

## 3. 金庫檔案格式（vault.db，v1）

```
offset   size   field
──────── ────── ────────────────────────────────────────────────
0        6      magic "F2VLT\x01"（version 1）
6        4      header_len u32 LE
10       N     header JSON（UTF-8，**明文金鑰包裝區**，不含密碼或金鑰機密）
10+N     12    payload nonce（AES-GCM 96-bit）
22+N     …     AES-256-GCM(KEK, vault_json) — 含 16B tag 於尾端
```

### header JSON（明文、可攜關鍵：金鑰包裝槽位）
```json
{
  "argon2":        { "t": 3, "m": 19456, "p": 4, "salt": "<b64 32B>" },
  "password_slot": { "nonce": "<b64 12B>", "ct": "<b64 AES-GCM(KEK)>" },
  "key_slots": [
    {
      "credential_id": "<b64url>", "aaguid": "<hex32>",
      "label": "YubiKey 5C", "key_type": "fingerprint|pin|touch_only|windows_managed",
      "nonce": "<b64 12B>", "ct": "<b64 AES-GCM(KEK)>"
    }
  ],
  "created_at": "RFC3339"
}
```

`key_slots[].label` 是存於明文 header 的 FidoVault 本機顯示別名，payload 加密不會涵蓋它。註冊對話框會提醒此風險，使用者不應把密碼或敏感個資當作別名。既有 vault 維持相同 v1 header 格式與標籤。

新別名由 Rust 依 Unicode canonical caseless matching 產生唯一建議並驗證；使用者確認後，UI 先透過 Rust 驗證，再進行 authenticator 偵測，註冊方法亦會對實際 vault slots 再驗證一次。

### payload（vault_json，加密後不可讀）
```json
{
  "entries": [
    { "id": "<hex32>", "site": "", "account": "", "password": "",
      "password_history": [
        { "id": "<hex32>", "password": "<prior password>", "archived_at": "RFC3339" }
      ],
      "notes": "", "created_at": "RFC3339", "updated_at": "RFC3339" }
  ],
  "audit": [ { "ts": "RFC3339", "event": "", "method": "", "detail": "" } ],
  "settings": { "idle_lock_minutes": 5, "password_history_limit": 3 }
}
```

`password_history` 與 `password_history_limit` 位於 AES-GCM 加密 payload，不寫入明文 header 或 audit。向後相容：舊 payload 缺少條目歷史欄位時讀為空清單，缺少保留設定時預設為 3；vault 格式版本仍為 v1。功能啟用前已被覆寫的密碼無法回復。

**設計要點（仿 LUKS 多槽位）**：KEK 是隨機 256-bit，本身從不明文落盤；每個「解鎖方式」（密碼／每支金鑰）各自用不同金流把同一份 KEK 包裝一次。新增/移除金鑰只改 header、不需重加密 payload。

## 3.1 金庫檔案格式 v2（雙群組控管版）

只有以 `--features dual-control` 建置的 `portable-fido-vault-dual.exe` 建立／開啟 v2；單人版只建立／開啟 v1。二進位外框（magic、`header_len`、payload nonce、AES-GCM payload）與 v1 相同，差異在 header JSON 與 payload 內容。

### 金鑰階層

```
KEK（隨機 256-bit，加解密 payload；與 v1 相同）
 ├─ password_slot  = AES-GCM( Argon2id(主密碼), KEK )                         ← break-glass，結構同 v1
 ├─ dual_slot      = AES-GCM( HKDF(share_A ‖ share_B), KEK, AAD="f2vlt-v2|dual-slot" )
 ├─ key_slots[A]   = AES-GCM( HKDF(PRF secret), share_A, AAD="f2vlt-v2|A|" ‖ credential_id )
 └─ key_slots[B]   = AES-GCM( HKDF(PRF secret), share_B, AAD="f2vlt-v2|B|" ‖ credential_id )
```

- `share_A`、`share_B` 各為建立金庫時以 OS CSPRNG 產生的 256-bit 隨機值，存在加密 payload（`dual.share_a/share_b`），所以任何完整解鎖的 session（含主密碼 break-glass）都能替新金鑰包裝槽位。
- 合併：`HKDF-SHA256(salt="f2vlt-domain-v1", ikm=share_A ‖ share_B, info="f2vlt-dual-v2")`，參數順序固定 A、B；Rust 單元測試以 Python 獨立計算的 KAT 鎖定輸出。
- 金鑰槽的 PRF → 包裝金鑰派生與 v1 相同（§4）。差別在槽位包裝的是群組 share 而不是 KEK，而且 AAD 綁定群組與 credential ID：把 header 中的 `group` 從 A 改成 B 會讓 GCM 驗證失敗，不會得到錯誤的 share。
- 每次 v2 解鎖（兩支金鑰或主密碼）後，都以 payload 的兩個 share 重新解 `dual_slot`，要求結果等於本次使用的 KEK；不一致即 `Format` 錯誤、不寫檔，避免 `dual_slot` 被竄改後主密碼仍可登入、金鑰登入卻默默失效。

### header JSON（v2 新增欄位）

```json
{
  "v": 2,
  "policy": "dual",
  "argon2": { "t": 3, "m": 19456, "p": 4, "salt": "<b64 32B>" },
  "password_slot": { "nonce": "<b64 12B>", "ct": "<b64 AES-GCM(KEK)>" },
  "dual_slot":     { "nonce": "<b64 12B>", "ct": "<b64 AES-GCM(KEK)>" },
  "key_slots": [
    { "credential_id": "<b64url>", "aaguid": "<hex32>", "label": "王小明",
      "key_type": "windows_managed", "group": "A",
      "nonce": "<b64 12B>", "ct": "<b64 AES-GCM(share_A)>" }
  ],
  "dual_step_timeout_secs": 120,
  "created_at": "RFC3339"
}
```

- `policy` 只接受 `"dual"`；`group` 只接受大寫 `"A"`/`"B"`，未知值反序列化失敗（fail closed）。
- `dual_step_timeout_secs` 是加密 payload 權威值的**明文鏡像**，只供登入畫面（尚未解密）使用，見 §5.5。
- 新欄位在 Rust 型別中皆為 `Option` + `skip_serializing_if`，v1 檔序列化結果逐位元組不變（有 GREEN→GREEN 迴歸測試）。

### payload（v2 新增）

- `dual: { "share_a": "<b64 32B>", "share_b": "<b64 32B>" }`（只在 v2；記憶體中 `ZeroizeOnDrop`，Debug 遮蔽）。
- `settings.dual_step_timeout_secs`：第二步等待時限權威值，30–600 秒（含端點），新金庫預設 120。

### 版本判斷（任何解密或寫檔之前）

| 檔案 | 單人版 | 雙群組控管版 |
|---|---|---|
| `v=1` 且無任何 v2 欄位 | 開啟 | `WrongEdition`：「此為單人版金庫…」 |
| `v=2` 且 `policy=dual`、有 `dual_slot`、每個槽位都有 `group` | `WrongEdition`：「此為雙群組控管版金庫，請改用雙群組控管版程式（portable-fido-vault-dual.exe）」 | 開啟 |
| `v=1` 帶任一 v2 欄位、`v=2` 缺 policy／dual_slot／group、其他版本 | `Format` 錯誤 | `Format` 錯誤 |

- 版本不符時不解密、不寫失敗 sidecar、不產生 `.db.tmp`，檔案逐位元組不變。
- 解密後再檢查 payload 形狀：v2 必須有 `dual` 與合法的 `dual_step_timeout_secs`，v1 不可有；不符即拒絕。
- 登入畫面讀 header 與 vault 核心共用 `Vault::read_header(path, edition)`，magic／長度／版本規則只有一份實作。
- 不提供 v1→v2 轉換或降級；`vault_cli` 不支援 v2。

## 4. 金鑰派生與加密

| 項目 | 演算法 / 參數 |
|---|---|
| 主密碼 KDF | Argon2id，t=3, m=19456 KiB (19 MiB), p=4, salt 32B（OWASP 建議下限附近，登入延遲 ~0.5s） |
| 對稱加密 | AES-256-GCM，nonce 每次隨機 12B |
| 金鑰槽 KEK 派生 | HKDF-SHA256(ikm=PRF secret 32B, salt=`f2vlt-domain-v1`, info=`f2vlt-kek-wrap-v1`) → 32B |
| PRF salt（固定） | `f2vlt-prf-salt-v1`（32B，domain separation；非機密，公開於程式碼） |

- **密碼登入**：K=Argon2id(pw, salt) → AES-GCM 解 password_slot.ct → KEK → 解 payload。tag 驗證失敗 = 拒絕並記軌跡。
- **金鑰登入（raw CTAP per-slot 路徑）**：CTAP2 getAssertion(allow=[cred_id], hmac-secret{salt1=PRF_SALT}) → S(32B) → HKDF → AES-GCM 解該槽 ct → KEK → 解 payload。Windows WebAuthn GUI 則一次提交全部已註冊 credential IDs，由 broker 選擇後以回傳的 credential ID 對應槽位。

## 5. FIDO2 偵測與登入流程

### 5.1 註冊（金庫已解鎖時）
- 啟動 FIDO 操作前，UI 提示輸入可編輯的 FidoVault 本機別名，預填目前金鑰槽中未使用的建議名稱。別名須先去除首尾空白、不可空白、不可含控制字元、最多 64 個 Unicode scalar value，且以去空白後不分大小寫不可重複；前端提供即時驗證，Rust vault 層在呼叫 authenticator 前再次驗證。取消或驗證失敗不呼叫註冊命令。
- 別名沿用 `KeySlot.label` 儲存，不改變 authenticator credential 或 Windows Security prompt。別名是明文 header metadata；UI 明確警告勿輸入密碼或敏感個資。Vault v1 格式不變，舊 vault 相容。
0. **PRF 強制檢查**：CLI raw-CTAP backend 可由 `getInfo.extensions` 預先判定；Windows GUI 的 WebAuthn API 不提供 CTAP `getInfo`，因此在建立 credential 時要求 `hmac-secret`，並檢查 authenticator 的正向 extension output。若未回報支援，拒絕建立 vault slot；因 API 無預查能力，authenticator 端可能留下未被金庫採用的 credential。
1. **Windows GUI**：使用 WebAuthn API v4+，RP ID 固定 `fido-vault.local`，限制 cross-platform authenticator；Windows broker 顯示 PIN/UV/觸碰 UI。
2. **CLI/診斷**：raw CTAP2 `getInfo` 取得 AAGUID、hmac-secret 能力與 pin/bio flags；用 flags 分類 fingerprint / pin / touch-only。
3. `makeCredential(rp_id="fido-vault.local", user, pubKeyCredParams=[ES256], residentKey=preferred, extensions={hmac-secret})` → 取 credentialId + aaguid。
4. Windows GUI assertion 傳遞 vault 固定 salt 並設定 `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`，要求 Windows API 使用 raw hmac-secret salt；不套用 WebAuthn PRF 的 salt transform。此點維持既有 raw-CTAP vault slot 相容。
5. 以 PRF secret 包裝 KEK，寫入 header.key_slots；audit `key_registered`（含 label、type）。

### 5.2 登入提示（依已存 key_type）
| type | UI 提示 |
|---|---|
| fingerprint | 「請插入金鑰並**按指紋**」 |
| pin | 「請插入金鑰並**輸入 PIN**」（UI 收集 PIN → CTAP2 authenticate） |
| touch_only | 「請插入金鑰並**觸碰**」 |
| windows_managed | 「請依 Windows 安全性提示完成驗證」 |

### 5.3 多支金鑰
每支 credential 維持獨立槽位。Windows GUI 登入畫面保留主密碼備援，金鑰登入只顯示一個通用入口；啟動後以單次 WebAuthn `GetAssertion` 將全部已註冊 credential IDs 放入 allow-list，由 Windows broker 處理金鑰選擇及 PIN/UV/觸碰提示。回傳的 credential ID 必須對應既有 vault slot，再以該槽 PRF secret 解鎖。使用者不需先在應用程式點選特定金鑰。非 brokered 的 Mock/raw-CTAP GUI 模式維持原逐支選擇與 app PIN 流程。

### 5.4 Windows backend 選型
- **Windows GUI 使用 Microsoft Windows WebAuthn API**：一般使用者權限可透過 Windows broker 執行 MakeCredential/GetAssertion，PIN/UV/觸碰提示由系統 UI 負責；需要 API v4+ 才能取得 HMAC-secret assertion output。
- **raw CTAP/HID 保留給 CLI 與診斷**：`authenticator-rs` 提供 getInfo、BioEnrollment 和 hmac-secret；但 Windows 對一般程式的 FIDO HID 存取會受權限/使用中裝置限制，不能把此路徑當成一般權限 GUI 的預設。
- Windows API assertion 設定 `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`，明確傳入原始 32-byte vault salt，避免 WebAuthn PRF 的 domain-separated transform 造成既有槽位無法解鎖。
- 呼叫註冊或登入前，GUI 先還原/顯示並聚焦 Tauri 主視窗，並以該視窗 HWND 作為 WebAuthn parent，讓系統金鑰 UI 由前景應用程式觸發；視窗聚焦失敗只記錄警告，仍不提升權限或切換 backend。

### 5.5 雙群組控管版：註冊與兩步驟登入

**註冊**（已解鎖）：
- 名稱規則同 §5.1；另需選擇群組 A/B（必選、無預設、註冊後不可修改）。Rust 在呼叫 authenticator 前驗證名稱、群組與版本，並先解析所有既有槽位的 credential ID（槽位損毀即 `Format`，不碰金鑰）。
- MakeCredential 帶 **excludeCredentials = 金庫內全部 credential ID**（A+B）。Windows WebAuthn 填入 `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS.CredentialList`；raw CTAP 填 `exclude_list`；只有帶了 exclude 清單時才把 `NTE_EXISTS`（Windows）／CTAP2 `0x19`（raw）對應為 `CredentialExcluded`，單人版錯誤訊息不變。被拒時不新增槽位。
- 成功後以該群組的 share 包裝槽位，audit `key_registered` 的 detail 為 `type=<類型> group=<A|B>`。

**金鑰登入**（A、B 群組各至少一支才啟用，否則回 `DualNotReady`，只能用主密碼）：
1. `login_dual_begin`：broker allowList = 全部 credential。依回傳的 credential ID 找到槽位（必須存在於金庫），以 AAD 解出該群組 share，存進 Rust 端 `AppState` 的 pending 狀態（`Zeroizing`、不可 Clone、Debug 遮蔽），截止時間在第一支金鑰與 share 解包**之後**才取樣。IPC 只回傳第一步的群組、名稱、時限與剩餘毫秒，不回傳 share。
2. `login_dual_complete`：以 by-value 取出 pending（單次使用），先檢查未逾時、金庫 header 仍與第一步相同（綁定 `created_at` + dual_slot 密文），再以 **另一群組** 的 credential 作 allowList 呼叫 broker；返回後再檢查一次逾時，並要求回傳的 credential 確實屬於另一群組。之後合併 share、解 `dual_slot` 得 KEK、解 payload。
3. `login_dual_cancel`、逾時、第二步任何失敗、上鎖、視窗關閉、改用主密碼：pending 一律清零，需從第一步重新開始。逾時以 Rust 端 `Instant` 為準：begin 時遞增 generation 並啟動計時執行緒，到期只清除同一 generation 的 pending；前端倒數僅供顯示。

**第二步時限設定**：
- `set_dual_step_timeout(secs)`：只在已解鎖的雙人版 session 接受 30–600 秒；一次寫入 payload 權威值、header 鏡像與 audit `settings_changed`（detail `dual_step_timeout_secs=<n>`）。任何存檔失敗都還原原設定、鏡像與 audit。
- 登入當下只能讀 header 鏡像：合法 `u32` 夾在 30–600；缺值或 null 用 120；字串、負數、小數、超出 `u32` 的值維持反序列化拒絕。
- 完整解鎖（兩支金鑰或主密碼）後，若 header 原始鏡像（未 clamp 的值）與 payload 權威值不同，以權威值修復 header 並記 `settings_tamper_detected`，與 `login_success` 同一次存檔。payload 權威值缺失或超界則拒絕解鎖，不以預設值掩蓋；登入失敗或只完成第一步不修復、不寫金庫。

**主密碼 break-glass**：與 v1 相同的密碼槽；audit method=`password-breakglass`，UI 顯示醒目提示（不阻擋操作）。

**金鑰刪除**：刪除後該群組會剩 0 支 → `LastKeyInGroup`，拒絕且槽位數不變（vault 層強制）。

## 6. 軌跡紀錄（audit）

事件集：`vault_created, login_success, login_failed, key_registered, key_removed, entry_added, entry_updated, entry_deleted, entries_imported, auto_lock, manual_lock`。
- `method`：`password` / `fido2:<label>` / `setup` / `idle` / `manual` / `csv`。
- `detail`：**僅非機密資訊**（如 site 名稱、失敗原因代碼 wrong_password/no_device/decrypt_failed）。**永不記錄密碼、PIN、金流、credentialId 明文值以外的敏感資料。**`entries_imported` 僅記新增／更新／略過數量，不記錄 CSV 欄位或資料列內容。
- 儲存於加密 payload 內；UI「軌跡紀錄」頁可查（最新在前，上限 1000 筆，超出丟最舊）。

### 6.1 雙群組控管版的 audit 與失敗紀錄

- 新增事件：`settings_changed`（第二步時限，method=`manual`）、`settings_tamper_detected`（header 鏡像被改、解鎖後修復，method=`system`）。
- 成功：`login_success` method=`fido2-dual:<群組>:<名稱>#<fp>+<群組>:<名稱>#<fp>`（依實際順序）；`fp` 為 SHA-256(credential_id) 前 4 bytes hex，讓 audit 不只依賴可被竄改的明文名稱；名稱中的 `% + : #` 會跳脫（`%25` 等）。主密碼為 `password-breakglass`。
- 失敗 sidecar（上限 10 筆，只記時間戳與 method）：`fido2-dual-step1:<名稱>`、`fido2-dual-step2:<名稱>`、`fido2-dual-step2-rejected`（第二步回傳非另一群組的 credential）、`fido2-dual-binding-mismatch`（兩步之間金庫被換掉）、`fido2-dual-timeout`、`fido2-dual-cancel`。broker 取消／無裝置與 v1 相同不記錄。

## 7. 閒置自動上鎖

- `settings.idle_lock_minutes`（預設 5，UI 可改 1–60）。
- 前端監聽 mousemove/keydown/click 重置計時；逾時 → `invoke('lock', {reason:'idle'})` → Rust 端 audit `auto_lock` + KEK 清零 + 回登入畫面。
- 手動上鎖鈕 → reason=manual。

### 7.1 舊密碼歷史

- `settings.password_history_limit` 預設 3，範圍 1–20；此上限計算每筆條目的舊密碼數，不含目前密碼。
- 僅密碼值實際變更時，才把原目前密碼與封存時間加入該條目歷史；網站、帳號、備註修改或相同密碼不新增版本。
- 降低上限時立即移除最舊超額版本。歷史值仍保存在加密 payload。
- 編輯畫面列出歷史日期並提供「還原」；使用者按儲存才套用，原目前密碼進入歷史，已還原的版本自歷史移除。

### 7.2 密碼剪貼簿複製

- 條目列表提供「複製密碼」操作，使用 Tauri v2 Clipboard Manager 寫入系統文字剪貼簿。
- 成功/失敗狀態只顯示通用訊息；密碼內容不進 audit、診斷 log 或狀態文字。
- 60 秒後執行 Windows 原生條件清除：以 `OpenClipboard` 鎖定系統剪貼簿，在同一個鎖定區段中取得 `CF_UNICODETEXT`、與該次複製值逐字比較，符合才呼叫 `EmptyClipboard`，然後才釋放鎖。Windows 文件保證剪貼簿開啟期間其他程式不能修改，因此比較與清除之間沒有 read-then-clear 競態；內容不同時保留原內容。
- 若剪貼簿沒有相符文字、鎖定/讀取/清除 API 失敗，UI 只顯示通用訊息且 App 不崩潰；密碼不進 audit、診斷 log 或狀態文字。
- App 內的剪貼簿操作會序列化，避免舊到期清除擦掉後續 FidoVault 複製的值。剪貼簿仍是 OS 共用資源，其他桌面程式可能在到期前讀取內容。
- Capability 僅授予 `clipboard-manager:allow-write-text`；條件清除使用本機 Win32 API，不授予 plugin 的讀取或清除權限，也不開放圖片或 HTML 剪貼簿命令。
- Windows API 參考：[`OpenClipboard`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-openclipboard)（阻止其他程式修改）、[`EmptyClipboard`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-emptyclipboard)。

### 7.3 CSV 批次匯入／更新

- 解鎖後條目介面提供 CSV 範本下載與匯入；範本為 UTF-8、只有 `site,account,password,notes` 表頭，不附示範資料。
- 匯入支援 UTF-8（可有 BOM）、標準 CSV quoting、欄位順序不拘；`site` 必填，最多 1,000 筆資料列。超出上限或檔案格式無效時整檔拒絕。
- 以 trim 後、不區分大小寫的 `(site, account)` 配對；唯一既有命中更新，無命中新增。更新的空欄位保留原值，非空欄位套用；新增的空欄位存空字串。密碼變更沿用既有歷史上限。
- CSV 中重複配對鍵的相關列全部略過；多重既有命中、缺少 site 或欄數錯誤的資料列略過並在預覽說明。預覽只顯示新增／更新／略過數量、列號與非機密原因，不顯示欄位內容。
- 使用者確認後所有有效列以一次加密落盤，寫入失敗不改變金庫。Audit `entries_imported` 僅記計數；CSV 密碼或整列內容不寫入 log、錯誤、audit 或暫存檔。選檔與儲存範本使用本機原生對話框，不進行網路呼叫。

## 8. 安全模型 / 威脅說明

- 金庫檔案外洩（無任何解鎖因子）→ payload 為 AES-256-GCM，header 僅含包裝槽位，無法取得 KEK。
- **無復原**：主密碼遺忘 + 全部 FIDO2 金鑰全失 = 永久無法取回（UI 於建立帳號與設定頁明示）。
- 移除金鑰 = 刪該槽；該金鑰即無法再解鎖（不可逆，需確認對話框）。
- 離線：程式不開啟任何 socket；Tauri 未啟用 http 或一般檔案系統 plugin。Dialog plugin 僅提供使用者選擇 CSV 來源與範本儲存位置；選取後由 Rust 直接讀寫該路徑，不把 CSV 複製到暫存檔。
- 複製密碼會短暫暴露於系統共用剪貼簿；其他桌面程式可能在 60 秒清除前讀取。Windows 剪貼簿歷程/雲端剪貼簿也可能在此期間擷取或同步內容；EmptyClipboard 不負責清除已另行保存的歷程項目。
- 已知限制（v0.1）：單機單使用者；檔案權限依賴 OS 使用者權限；不防執行中記憶體 dump（與一般密碼管理程式同級）。

### 8.1 雙群組控管版

| 攻擊者持有 | 結果 |
|---|---|
| `vault.db` + A 群組任意數量金鑰 | 只得 `share_A`，無法得 KEK |
| `vault.db` + A 一支 + B 一支 | 可解鎖（設計預期） |
| `vault.db` + 主密碼 | 可解鎖（break-glass，刻意接受；以 UI 提示與 audit 補強） |
| 竄改 header `group` | 解包 GCM 驗證失敗，記失敗 |
| 竄改 header `dual_step_timeout_secs` | 登入時夾在 30–600；完整解鎖後以權威值修復並記 `settings_tamper_detected` |
| 竄改 `dual_slot` | 解鎖後一致性檢查失敗，拒絕且不寫檔 |

- 兩步驟之間的 share 只存在 Rust 端 `Zeroizing` 記憶體，設有時限，任何中斷都清零。仍不防執行中記憶體 dump。
- 「同一支實體金鑰只能註冊一次」依賴 authenticator 遵守 excludeList；金鑰 reset 後舊 credential 失效，可重新註冊（舊槽位應由管理者刪除）。
- 槽位名稱仍是明文 header metadata，audit 另附 credential 指紋以利追查。

## 9. Gate 對應

| Gate | 驗證方式 |
|---|---|
| 1 portable + NB 免安裝 | `cargo tauri build` → 資料夾複製至 Win11-NB（WinRM）執行 |
| 2 建立帳號/密碼登入/錯誤拒絕 | vault_cli E2E + GUI |
| 3 金鑰註冊+類型偵測+金鑰登入 | 實測（有硬體時）或 MockBackend E2E（F2V_MOCK=1） |
| 4 第二支金鑰/任一支可登入 | 同上，register 兩支後交叉登入 |
| 5 CRUD + 時間戳 | vault_cli E2E |
| 6 軌跡完整/無明文密碼 | vault_cli：解出 audit JSON 檢查 + 檔案 grep 驗證密碼值不出現在 header |
| 7 閒置自動上鎖 | GUI 計時器（縮短逾時實測）+ lock 命令 |
| 8 加密檔直拷別機可解密 | vault_cli copy-test：A 建立 → 複製 vault.db 至 B 路徑 → B 同密碼/金鑰登入成功 |
| 9 舊密碼歷史 | 修改密碼時封存；N=1–20（預設3）；調低立即裁剪；查看日期並還原；舊 payload 預設相容 |
| 10 密碼剪貼簿複製 | 複製成功/失敗、60 秒到期條件清除、保留被其他 app 取代的剪貼簿內容 |
| D 雙群組控管版 | Rust 單元測試（`--features real-ctap,dual-control`）＋ `scripts/gate_e2e_dual.py` mock 跨行程 25 項（DG1–DG9）；Tauri IPC、計時執行緒實際觸發、Windows broker 與實體金鑰由 Win11-NB 本機 Console 實機驗收（`docs/user-verification-steps.md` 末節） |
