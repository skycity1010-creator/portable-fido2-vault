# 可攜式 FIDO2 密碼金庫 v0.1 — 技術規格書

> 專案：`portable-fido2-vault`｜卡：t_31e9ef5e｜語言介面：繁體中文
> 目標平台：Windows 10/11 x64（WebView2 內建於 Win11）

## 1. 目標 / 非目標

**目標**
- Windows 桌面 App，完全離線（零網路呼叫；Tauri 不啟用任何 http 插件）。
- 可攜：單一資料夾 `exe + vault.db`，複製到別台電腦免安裝即可執行。
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
10       N     header JSON（UTF-8，**明文金鑰包裝區**，不含任何機密值）
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

## 6. 軌跡紀錄（audit）

事件集：`vault_created, login_success, login_failed, key_registered, key_removed, entry_added, entry_updated, entry_deleted, auto_lock, manual_lock`。
- `method`：`password` / `fido2:<label>` / `setup` / `idle` / `manual`。
- `detail`：**僅非機密資訊**（如 site 名稱、失敗原因代碼 wrong_password/no_device/decrypt_failed）。**永不記錄密碼、PIN、金流、credentialId 明文值以外的敏感資料。**
- 儲存於加密 payload 內；UI「軌跡紀錄」頁可查（最新在前，上限 1000 筆，超出丟最舊）。

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
- 60 秒後讀取目前剪貼簿文字；只在內容與該次複製值相同時呼叫清除。若內容已被取代或讀取失敗，保留剪貼簿不動；寫入、讀取及清除錯誤皆由 UI 捕捉並以不含密碼的訊息回報。
- App 內的剪貼簿操作會序列化，避免已開始的舊到期清除擦掉後續 FidoVault 複製的值。剪貼簿為 OS 共用資源，其他桌面程式可能在到期前讀取內容。
- Capability 僅授予 `clipboard-manager:allow-write-text`、`clipboard-manager:allow-read-text`、`clipboard-manager:allow-clear`；不開放圖片或 HTML 剪貼簿命令。

## 8. 安全模型 / 威脅說明

- 金庫檔案外洩（無任何解鎖因子）→ payload 為 AES-256-GCM，header 僅含包裝槽位，無法取得 KEK。
- **無復原**：主密碼遺忘 + 全部 FIDO2 金鑰全失 = 永久無法取回（UI 於建立帳號與設定頁明示）。
- 移除金鑰 = 刪該槽；該金鑰即無法再解鎖（不可逆，需確認對話框）。
- 離線：程式不開啟任何 socket；Tauri 未加 http/fs 外部插件。Clipboard Manager 僅使用本機系統剪貼簿。
- 複製密碼會短暫暴露於系統共用剪貼簿；其他桌面程式可能在 60 秒清除前讀取，且清除只在內容仍相同時執行。
- 已知限制（v0.1）：單機單使用者；檔案權限依賴 OS 使用者權限；不防執行中記憶體 dump（與一般密碼管理程式同級）。

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
