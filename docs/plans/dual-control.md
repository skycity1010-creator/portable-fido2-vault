# 雙群組金鑰控管版（Dual-Control Edition）設計文件

> 狀態：**設計確認，未開始實作**（production code 未修改）。
> 分支：`feature/dual-control-20261011`（base `main` `656ac95`）。
> 需求來源：使用者 2026-10-11 Hermes desktop 對話（Q1–Q6 已裁決，見 §1）。

## 0. 目標

在現有單人版之外，新增一個「雙群組控管」版本：

1. 首次啟動一樣以主密碼建立金庫；之後註冊金鑰時，必須指定該金鑰屬於 **A 群組** 或 **B 群組**。
2. 以金鑰登入時，必須 **A 群組一支 + B 群組一支** 都認證通過才能解鎖；先 A 後 B 或先 B 後 A 皆可，但第二步必須是**另一群組**的金鑰。解鎖後可操作全部金庫內容。

## 1. 已確認決策（2026-10-11）

| # | 問題 | 決策 |
|---|------|------|
| Q1 | 主密碼角色 | **保留為緊急用（break-glass）**：主密碼單獨即可完整解鎖。這是刻意接受的繞道，主密碼保管責任在組織。 |
| Q2 | 使用情境 | 主密碼由**人工分持**（程式不處理密碼拆分）。每人一支自己的金鑰；註冊時輸入金鑰名稱（現有）與所屬群組 A/B（新增）。 |
| Q3 | 實體金鑰重複 | **同一支實體金鑰在整個金庫只能註冊一筆**，且只能隸屬 A 或 B 其中之一。 |
| Q4 | 金鑰管理 | (1) 不能刪除群組中的最後一支金鑰；(2) 群組名稱固定為「A 群組」「B 群組」，不可自訂，註冊後也**不可改群組**（要改就刪除後重新註冊）。 |
| Q5 | 版本形式 | 同一份 code base，以 Cargo feature `dual-control` 另編一個執行檔；單人版行為不變。 |
| Q6 | 第一步等待時限 | 預設 **120 秒**，可在設定中調整。 |

## 2. 密碼學設計

### 2.1 為什麼必須拆 share

單人版每個金鑰槽都包裝**完整 KEK**，任一槽即可解鎖。若雙人版只在 UI/流程上要求第二支金鑰，取得 `vault.db` + 任一支金鑰的人改用 CLI 或改程式即可繞過。因此雙重控管必須在**密碼學層**成立：任一單一群組的金鑰在數學上都不足以得到 KEK。

### 2.2 金鑰階層（v2）

```
KEK（隨機 256-bit，加解密 payload；與 v1 相同）
 ├─ password_slot   = AES-GCM( Argon2id(主密碼),                 KEK )   ← break-glass，結構同 v1
 ├─ dual_slot       = AES-GCM( HKDF(share_A ‖ share_B, "f2vlt-dual-v2"), KEK )
 ├─ key_slots[g=A]  = AES-GCM( HKDF(prf_secret_i, "f2vlt-kek-wrap-v1"), share_A, AAD = "f2vlt-v2|A|" ‖ credential_id )
 └─ key_slots[g=B]  = AES-GCM( HKDF(prf_secret_j, "f2vlt-kek-wrap-v1"), share_B, AAD = "f2vlt-v2|B|" ‖ credential_id )
```

- `share_A`、`share_B`：建立金庫時各自隨機產生 256-bit，**存在加密 payload 內**（`VaultData.dual.share_a/share_b`）。任何完整解鎖的 session（包括密碼 break-glass）都可以替新金鑰包裝槽位，不需要兩支金鑰同時在場。
- KEK 維持隨機值，不直接由 share 推導：密碼槽格式不變，也保留未來換 share（re-key）的彈性。
- **群組綁定 AAD**：`group` 與 `credential_id` 放在 header 明文區，但寫入 AES-GCM AAD。攻擊者把 A 槽改標成 B，會在解包時 GCM 驗證失敗，不會得到錯誤的 share。
- `crypto.rs` 需新增 `aes_gcm_encrypt_aad / aes_gcm_decrypt_aad`；v1 路徑不變。

### 2.3 安全性質

| 攻擊者持有 | 結果 |
|-----------|------|
| `vault.db` + A 群組任意數量金鑰 | 只得 `share_A` → 無法得 KEK |
| `vault.db` + A 一支 + B 一支 | 可解鎖（設計預期） |
| `vault.db` + 主密碼 | 可解鎖（Q1 break-glass，刻意接受） |
| 竄改 header 群組標記 / 等待時限 | 群組：AAD 失敗；時限：讀取時 clamp 在允許範圍（§4.3） |

## 3. 檔案格式（Header v2）

```jsonc
{
  "v": 2,
  "policy": "dual",                       // v2 僅此值；未知值 fail closed
  "argon2": { "salt": "…" },
  "password_slot": { "nonce": "…", "ct": "…" },
  "dual_slot":     { "nonce": "…", "ct": "…" },
  "key_slots": [
    { "credential_id": "…", "aaguid": "…", "label": "王小明", "key_type": "…",
      "group": "A", "nonce": "…", "ct": "…" }
  ],
  "dual_step_timeout_secs": 120,          // 明文鏡像，見 §4.3
  "created_at": "…"
}
```

- 單人版既有 `header.v != 1` 檢查 → 開到 v2 檔會直接報「不支援的版本」，不會誤解析。
- 雙人版只建立/開啟 v2；開到 v1 檔回清楚的中文錯誤（「此為單人版金庫，請使用單人版程式」）。**不做 v1→v2 轉換**（本期範圍外）。
- `VAULT_MAGIC` 不變；`FORMAT_VERSION` 依 edition 區分。
- 預設檔名：維持與 exe 同資料夾的 `vault.db`；版本不符時 fail closed，不覆寫、不轉換。

## 4. 行為規格

### 4.1 建立金庫

與 v1 相同（主密碼 + 確認），另外產生 `share_A/share_B`、`dual_slot`。此時沒有任何金鑰，只能用主密碼登入。

### 4.2 註冊金鑰

1. 註冊對話框：金鑰名稱（現有規則：必填、≤64 字、caseless 不重複）＋**群組單選（A 群組 / B 群組，必選、無預設）**。
2. Rust 端在呼叫 authenticator 前驗證名稱與群組。
3. MakeCredential 帶 **excludeCredentials = 金庫內所有既有 credential_id**（A+B 全部）。同一支實體金鑰若已有本金庫的 credential，authenticator 會拒絕建立，對應 Q3「同一實體金鑰只能一筆、只能屬一群組」。
   - Windows WebAuthn：填 `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS` 的 exclude 清單（目前程式未帶，需新增）。
   - raw CTAP（CLI/診斷）：`exclude_list` 目前為 `vec![]`，需一併填入。
   - Mock backend：模擬「同一裝置已有 credential → CredentialExcluded」。
   - 錯誤對應為中文訊息「此安全性金鑰已註冊於本金庫」。實際 HRESULT 需於 Win11-NB 實機確認（§7 風險 R1）。
4. 成功後以該群組的 share 包裝槽位，寫入 `group`，audit `key_registered` 的 detail 帶群組。
5. 群組註冊後**不可修改**；UI 不提供改群組功能。

### 4.3 金鑰登入（兩步驟）

前置條件：A、B 群組**各至少一支**金鑰；否則金鑰登入按鈕停用，提示「需 A、B 群組各至少一支金鑰；目前請以主密碼登入」。

1. **第一步**：broker `allowList` = 全部 credential（A+B）。依回傳的 credential 找到槽位與群組，解包得到該群組 share（AAD 驗證）。
   - share 暫存在 **Rust 端** `AppState` 的 pending 狀態（`Zeroizing`、記錄群組、第一位的 label、`Instant` 截止時間），**不交給前端**。
   - UI 顯示「A 群組（王小明）已驗證，請 B 群組成員於 N 秒內完成驗證」與倒數。
2. **第二步**：broker `allowList` = **另一群組**的 credential，同群組金鑰不在清單中，無法完成第二步。解包另一 share → `HKDF(share_A‖share_B)` 解 `dual_slot` 得 KEK → 解 payload → 解鎖。
3. 第二步成功前，以下任一情況都會**清零 pending share、回到第一步**：逾時、按「取消」、第二步失敗（解包失敗、broker 錯誤或取消）、視窗關閉、改用密碼登入。逾時以 Rust 端截止時間為準，前端倒數僅供顯示。
4. 等待時限設定：
   - 存放：加密 payload `Settings.dual_step_timeout_secs`（權威值），並鏡像到 header 明文 `dual_step_timeout_secs`。登入當下金庫還沒解密，只能讀明文鏡像。
   - 範圍：**30–600 秒**，預設 120。讀取 header 時一律 clamp；值不合法時用預設值。
   - 解鎖後若兩值不一致，以 payload 值覆寫 header，並記 audit `settings_tamper_detected`。
   - 只有已解鎖的 session 才能修改（設定頁新增欄位），改動記 audit `settings_changed`。
5. 稽核：
   - 成功：`login_success` method=`fido2-dual:A:<label>+B:<label>`（依實際順序）。
   - 失敗：第一步、第二步分別寫 sidecar，method=`fido2-dual-step1:<label>` / `fido2-dual-step2:<label>`；逾時與取消寫 `fido2-dual-timeout` / `fido2-dual-cancel`。sidecar 仍為上限 10 筆、只記時間戳和 method。

### 4.4 主密碼登入（break-glass）

- 行為同 v1：密碼正確即完整解鎖。
- audit method=`password-breakglass`。解鎖後在主畫面顯示**醒目提示**「本次以主密碼緊急登入」（不阻擋操作）。

### 4.5 金鑰管理

- 金鑰清單多一欄「群組」，並依群組分組顯示。
- 刪除：若刪除後該群組剩 0 支 → **拒絕**（Rust 層強制，UI 也停用按鈕），訊息「不可刪除 A 群組的最後一支金鑰」。
  - 例外：若該群組本來就只有這一支、另一群組也還沒有金鑰（雙重控管尚未啟用），是否允許刪除？**本設計採一律禁止**：群組一旦有金鑰就不會再歸零，規則單純。
- 刪除與註冊都需要已解鎖的 session（金鑰雙步驟或主密碼皆可）。

### 4.6 其他

- 閒置自動上鎖、手動上鎖：KEK、share、pending 狀態一律清零。
- RDP/Console 能力判斷、WebAuthn 不可用時的密碼登入 fallback、前景處理：沿用現有機制。兩步驟各自是一次獨立的 GetAssertion。

## 5. 版本與建置

- `src-tauri/Cargo.toml`：新增 feature `dual-control`，以及 `[[bin]] name = "portable-fido-vault-dual"`（`required-features = ["dual-control"]`）。
- 建置：`cargo +stable-x86_64-pc-windows-gnu build --release --locked --features real-ctap,dual-control --bin portable-fido-vault-dual`。
- 前端共用 `src/`：Rust 提供 `get_edition()` IPC（`"single"`/`"dual"`），UI 依此顯示群組欄位、兩步驟登入與時限設定。單人版 UI 的 DOM 與行為**不變**，由既有 Node 測試迴歸保證。
- 視窗標題與「關於」顯示「FidoVault（雙群組控管版）」。
- `vault_cli`：本期**不支援** v2（維持 v1 檢查 fail closed）；CLI 仍只用於 raw CTAP 診斷。
- 單人版 Release 也要重編並跑完整測試，確認 feature 未編入、行為不變。

## 6. 驗收條件

### 6.1 自動化（mock backend）

- 建立 v2 → 註冊 A1、B1 → 上鎖 → A1→B1 解鎖成功；B1→A1 解鎖成功。
- A1→A2（同群組）第二步失敗：broker allowList 排除，mock 回 NoCredentials。
- 只持有 A 群組全部槽位與 share_A：直接呼叫 vault 層解 `dual_slot` 失敗（密碼學性質測試）。
- 竄改 header `group`：解包 GCM 失敗、記失敗。
- 同一 mock 裝置第二次註冊（不論群組）→ CredentialExcluded，slot 數不變。
- 刪除群組最後一支 → 拒絕，slot 數不變。
- 第一步後逾時、取消、第二步失敗 → pending 清零，第二步指令回「請重新開始」。
- 時限設定：範圍外拒絕；header 鏡像 clamp；竄改後解鎖修復並記 audit。
- 主密碼 break-glass 完整解鎖、audit method 正確。
- v1 檔交給雙人版、v2 檔交給單人版 → 皆 fail closed，且不寫檔。
- 單人版既有 Rust/Node 全套測試不退化。

### 6.2 Win11-NB 本機 Console 實機（使用者執行）

使用**獨立測試資料夾和新測試金庫**，不碰 `C:\FidoVault\vault.db`。

1. 建立 v2 金庫，以主密碼登入。
2. 註冊金鑰 K1 → A 群組；K2 → B 群組。
3. 以 K1 嘗試再註冊一次（選 B）→ 顯示「已註冊」，slot 數不變（Q3）。
4. 上鎖 → K1 → K2 解鎖成功；上鎖 → K2 → K1 解鎖成功。
5. 第一步 K1 後，第二步再刷 K1 → 無法完成；第一步後等候逾時 → 回到第一步。
6. 刪除 K1（A 群組最後一支）→ 被拒。
7. 主密碼 break-glass 登入 → 完整解鎖、看到緊急登入提示。
8. 調整時限為 60 秒並驗證生效。

若只有兩支實體金鑰，第 5 步「同群組第二支」以「同一支再刷一次」代替；同群組不同金鑰的情境由 mock 測試涵蓋。

## 7. 風險與待實機確認

| ID | 風險 | 處理 |
|----|------|------|
| R1 | Windows WebAuthn 對 excludeCredentials 命中時的 HRESULT/UI 文案未知（可能 `NTE_EXISTS` 或通用錯誤）| 實作時加 diag 記錄；未知碼一律視為失敗、不寫 slot，訊息寫「可能已註冊」。實機確認後再精確對應 |
| R2 | excludeCredentials 只對「仍認得該 credential 的金鑰」有效；金鑰 reset 後可重新註冊 | 可接受：reset 後舊 credential 已失效，舊槽位等於失效，應由管理者刪除 |
| R3 | 主密碼 break-glass 可繞過雙重控管 | Q1 刻意接受；以醒目 UI 提示和 audit 紀錄補強，文件明載 |
| R4 | header 明文鏡像可被竄改以縮短/延長時限 | clamp 30–600 秒；解鎖後修復並記 audit |
| R5 | 兩步驟之間 share 暫存於記憶體 | 只存 Rust 端、`Zeroizing`，設時限，任何中斷都清零；不經 IPC 回傳 |

## 8. 範圍外

- v1 → v2 金庫轉換、v2 → v1 降級。
- 主密碼拆分或多人密碼（Q2：人工處理）。
- 自訂群組名稱、修改既有金鑰的群組、超過兩個群組或 M-of-N。
- `vault_cli` 支援 v2。
- share 輪替（re-key）、撤銷某群組全部金鑰後重建。

## 9. 開發項目與建議順序

每項都採 vertical TDD：先寫一個會失敗的測試、確認 RED（必須是 assertion 失敗，不是編譯錯誤），再實作到 GREEN，然後才進下一項。

| 順序 | 項目 | 主要檔案 | 依賴 |
|-----|------|---------|------|
| D1 | Cargo feature `dual-control` + `[[bin]] portable-fido-vault-dual` + `get_edition()`；確認單人版 build 不受影響 | `Cargo.toml`, `main.rs`, `lib.rs` | — |
| D2 | crypto：AES-GCM AAD 版本、`dual_kek_from_shares` HKDF | `crypto.rs` | — |
| D3 | 資料模型：Header v2（`policy`、`dual_slot`、`group`、timeout 鏡像）、`VaultData.dual`、版本互斥 fail closed | `vault.rs` | D2 |
| D4 | `Vault::create` v2 + 主密碼 break-glass 登入 + audit | `vault.rs` | D3 |
| D5 | 註冊：群組必選、以 share 包槽位（AAD）、名稱驗證沿用 | `vault.rs` | D4 |
| D6 | excludeCredentials：`FidoBackend::register_credential` 介面加 exclude 清單；Mock / raw CTAP / Windows WebAuthn 三個實作；錯誤對應 | `fido2.rs`, `windows_webauthn.rs` | D5 |
| D7 | 兩步驟登入狀態機：`begin`（全清單）→ pending（Rust 端、逾時）→ `complete`（另一群組清單）→ `cancel`；密碼學性質測試 | `vault.rs`, `lib.rs` | D5 |
| D8 | 金鑰刪除限制（群組最後一支）與群組顯示資料 | `vault.rs`, `lib.rs` | D5 |
| D9 | 時限設定：payload 權威值 + header 鏡像 + clamp + 竄改修復 | `vault.rs`, `lib.rs` | D7 |
| D10 | 前端：註冊對話框群組選擇、兩步驟登入畫面與倒數、金鑰清單群組欄、刪除限制、時限設定、break-glass 提示；以 edition 切換 | `src/app.js`, `src/index.html`, `tests/*.test.cjs` | D7–D9 |
| D11 | 全套驗證：Rust MSVC 單元測試、單人版迴歸、mock E2E（`scripts/gate_e2e.py` 新增 dual 情境）、Node 全套、GNU Release 雙執行檔建置、靜態掃描、獨立 code review | — | D1–D10 |
| D12 | 文件：README、spec.md（v2 格式）、PROJECT.md、user-verification-steps.md（§6.2 清單） | `docs/` | D11 |
| D13 | Win11-NB 獨立資料夾 staging（不碰正式 vault）→ 使用者本機 Console 實機驗收 §6.2 | — | D11–D12 |

**建議順序理由**：

1. **D1–D4 先打底**：先確定格式與密碼學。之後每一層都依賴 v2 header，而版本互斥是保護單人版正式金庫最重要的防線。
2. **D6（exclude）緊接在 D5 註冊之後**：它碰 Windows FFI，R1 風險最高，越早做越能及早用 mock 鎖定介面。實機錯誤碼可以在 D13 一併確認。
3. **D7 兩步驟登入是核心**，D8、D9 都可以在它之後並行，但依專案慣例仍逐項完成。
4. **D10 前端最後做**：等後端 IPC 介面穩定後再串，避免反覆修改 UI 測試。
5. **D11–D13** 走專案既有的驗證、review、staging 與人工驗收流程。實機 PASS 之前不合併。

## 10. 進度

- [x] 需求確認（Q1–Q6）與設計文件
- [x] D1 edition feature / 第二執行檔 / `get_edition()`（見 §11）
- [x] D2 crypto：AAD 版 AES-GCM、`KeyGroup`、金鑰槽 AAD、`dual_wrap_key_from_shares`（見 §11）
- [x] D3 Header v2 資料模型與版本互斥（見 §11）
- [x] D4 建立 v2 金庫、主密碼 break-glass、payload 形狀與 dual_slot 一致性檢查（見 §11）
- [x] D5 雙群組註冊：槽位只包該群組 share、AAD 綁定群組與 credential（見 §11）
- [x] D6 excludeCredentials：同一支實體金鑰只能註冊一筆（mock / raw CTAP / Windows WebAuthn，見 §11）
- [ ] D7–D13

## 11. 驗證紀錄

### D1（2026-10-11）

- 變更：`Cargo.toml` 新增 feature `dual-control`，並明確宣告兩個 `[[bin]]`：`portable-fido-vault`、`portable-fido-vault-dual`（後者 `required-features = ["dual-control"]`）；新增 `src/edition.rs`（`Edition` / `edition_for` / `current`）與 Tauri IPC `get_edition()`；`main.rs` 在啟用 `dual-control` 時以 `compile_error!` 拒絕編譯；CI 新增 dual-control 單元測試步驟。
- TDD：RED 為 2 個 assertion 失敗（`edition_for(true)` 回 `Single`；序列化結果是 `"Single"` 而非 `"single"`）→ GREEN。
- Rust MSVC lib 測試：單人版 `real-ctap` 204/204（baseline 200 + 4）；雙人版 `real-ctap,dual-control` 204/204。
- Node 65/65；`node --check src/app.js`、`git diff --check` 通過。
- GNU Release：`--features real-ctap` 8m00s 成功（未編出 dual bin）；`--features real-ctap,dual-control --bin portable-fido-vault-dual` 成功。兩者都是 non-deployable scratch 產物，不部署。
- 反向防護（預期失敗）：單人版 bin 加 `dual-control` → 出現自訂的 `compile_error`；dual bin 不加 feature → Cargo 回 `requires the features: dual-control`。
- 既有 warning（`windows_webauthn.rs` `try_lock`、`yk_open_test`）是 baseline 就有的，D1 沒有新增 warning。

### D2（2026-10-11）

- 變更只有 `src-tauri/src/crypto.rs`，v1 既有函式與常數不變：
  - 常數 `HKDF_INFO_DUAL_KEK = "f2vlt-dual-v2"`、`DUAL_KEY_SLOT_AAD_PREFIX = "f2vlt-v2|"`。
  - `KeyGroup { A, B }`（serde 為 `"A"`/`"B"`，大小寫嚴格；`aad_tag()`、`other()`）。D3 header 直接使用這個型別。
  - `aes_gcm_encrypt_aad` / `aes_gcm_decrypt_aad`：AAD 為空時與 v1 `aes_gcm_encrypt` 輸出逐位元組相同。
  - `dual_key_slot_aad(group, credential_id)` = `"f2vlt-v2|" ‖ tag ‖ "|" ‖ credential_id`；tag 固定 1 byte，不會有串接歧義。
  - `dual_wrap_key_from_shares(share_a, share_b)` = HKDF-SHA256(salt=`f2vlt-domain-v1`, ikm=share_A‖share_B, info=`f2vlt-dual-v2`)；參數順序固定 A、B；64B ikm 以 `Zeroizing` 清零。
- TDD：stub 先讓 6 個測試出現 assertion RED（AAD 被忽略、AAD 版面、share_B 未參與、KAT 不符）→ GREEN。新增 9 個測試，其中 KAT 期望值由 Python `hmac`/`hashlib` 依 RFC 5869 獨立計算。
- Rust MSVC lib：單人版 213/213、雙人版 213/213（204 + 9），無編譯 warning。第一輪測試與 rustfmt 寫入重疊，標為 SUPERSEDED；最終數據取自鎖定 `crypto.rs` SHA-256 後的重跑。
- `rustfmt --check --config skip_children=true`：`crypto.rs`、`edition.rs` 通過（baseline `crypto.rs` 本來就符合格式）。`git diff --check` 通過。
- 給 D3 的注意事項：`aes_gcm_decrypt_aad` 回傳的明文 `Vec<u8>`（share/KEK）呼叫端要立刻複製進 `Zeroizing<[u8;32]>`，並清零原本的 Vec。

### D3（2026-10-11）

- **設計補充：vault 核心 API 明確指定版本。** `read_file(path, edition)` 一律先呼叫 `check_header_edition`，再做任何解密或寫檔。
  - 既有的 `Vault::create/open_password/open_key/open_any_key` 固定為**單人版**語意（`Edition::Single`），所以 `vault_cli` 與既有測試在兩種 feature 下行為都不變。
  - 雙人版的入口在 D4/D7 另外新增；由 `lib.rs` 依 `edition::current()` 分派。
  - D3 到 D4 之間，dual 執行檔仍會建立 v1 檔並拒絕開啟它。這是過渡狀態，dual 執行檔在 D13 之前都不是可部署產物。
- 資料模型（v1 序列化不變，新欄位都是 `Option` + `skip_serializing_if`）：
  - `Header.policy: Option<VaultPolicy>`（v2 只有 `"dual"`，未知值反序列化失敗）、`Header.dual_slot`、`Header.dual_step_timeout_secs`。
  - `KeySlot.group: Option<KeyGroup>`；`Settings.dual_step_timeout_secs`；`VaultData.dual: Option<DualShares>`。
  - `DualShares` 為 `ZeroizeOnDrop`，Debug 輸出遮蔽。
  - `crypto::FORMAT_VERSION_DUAL = 2`。
- `check_header_edition` 規則：
  - v1 → Single、v2 → Dual，其他版本 → `Format` 錯誤。
  - 版本不符 → `VaultError::WrongEdition`，訊息指出應改用哪一個 exe。
  - v1 帶任何雙群組欄位 → 拒絕；v2 缺 `policy=dual`、`dual_slot`，或有槽位沒有群組 → 拒絕。
- `Vault::read_header(path, edition)`：登入畫面 `lib.rs::read_keys_from_file` 改用這個共用 reader，順便修掉原本 `10 + header_len` 沒做邊界檢查、可能 panic 的問題。
- 版本不符時不解密、不寫 sidecar、不產生 `.db.tmp`，檔案逐位元組不變（有測試驗證）。
- TDD：9 個 assertion RED → GREEN。新增 12 個測試，其中 `v1_files_serialize_without_dual_fields` 是既有行為回歸（GREEN→GREEN），`unknown_policy_or_group_value_fails_to_parse` 由型別本身保證，兩者都不算 RED。
- Rust MSVC lib：單人版 225/225、雙人版 225/225（213 + 12），無 warning；跑測試前後原始碼 SHA-256 不變。`rustfmt --check`（`lib.rs`/`vault.rs`/`crypto.rs`/`edition.rs`，skip_children）通過。也順便修正了 D1 在 `lib.rs` 造成的 mod 排序格式差異。
- 留給 D4 的事項：解密 payload 後還要檢查 payload 形狀（v2 必須有 `dual` shares 與 `settings.dual_step_timeout_secs`；v1 必須沒有）。

### D4（2026-10-11）

- `Vault::create_dual` / `create_for(path, pw, edition)`（內部共用 `create_with_edition`；單人版建立流程與 audit detail 逐字不變）：
  - v2 另外產生隨機 `share_A`、`share_B`。
  - `dual_slot = AES-GCM(HKDF(share_A‖share_B), KEK, AAD="f2vlt-v2|dual-slot")`。`crypto::DUAL_SLOT_AAD` 是本步新增的 domain separation 常數。
  - header/payload 的等待時限都寫入 `DEFAULT_DUAL_STEP_TIMEOUT_SECS = 120`。
  - audit `vault_created` 的 detail 附加 ` edition=dual`。
- `Vault::open_password_dual` / `open_password_for(path, pw, edition)`：
  - 雙人版主密碼登入就是 break-glass，成功與失敗（sidecar）的 method 都記為 `password-breakglass`；單人版仍是 `password`。
  - `Vault::edition()` 依 header.v 判斷版本。
- **payload 形狀檢查（`check_payload_edition`）**：在解密後、合併 sidecar 與寫檔之前執行，所有解鎖路徑都會經過。
  - v1 payload 不可含 `dual` 或等待時限設定。
  - v2 必須有兩份 32B share 和等待時限設定，而且 `dual_slot` 用 HKDF(shares) 解開後必須等於目前的 KEK。這樣可以防止 header 被竄改後，主密碼仍能登入、金鑰登入卻默默失效。
  - 檢查不通過 → `Format` 錯誤，不寫檔、不記錄登入失敗。
- `lib.rs`：`create_vault` 改呼叫 `create_for`，`login_password` 改呼叫 `open_password_for`，兩者都帶 `edition::current()`。dual 執行檔現在會建立 v2 金庫，並能用主密碼登入。
- 過渡防護：v2 金庫呼叫既有的 `register_key*` 會直接拒絕（「須指定群組」），不呼叫 authenticator、不新增槽位，等 D5 補上指定群組的註冊路徑。
- TDD：11 個 assertion RED（含自訂訊息的 assert）→ GREEN，新增 11 個測試。Rust MSVC lib：單人版 236/236、雙人版 236/236，無 warning；跑測試前後原始碼 SHA-256 不變；rustfmt 通過。

### D5（2026-10-11）

- `Vault::register_key_in_group(backend, pin, label, group)`：
  - 只限 v2 使用；先驗證名稱（規則同單人版），再呼叫 authenticator。
  - 槽位密文 = `AES-GCM(HKDF(prf_secret), share_<group>, AAD = dual_key_slot_aad(group, credential_id))`，**不包 KEK**。
  - header 寫入 `group`；audit `key_registered` 的 detail 附加 ` group=A|B`。
- `Vault::register_key_for(…, group: Option<KeyGroup>)`：依金庫版本分派。單人版 + 有群組，或雙人版 + 無群組，都在呼叫 authenticator 之前 fail closed（有計數後端驗證 detect 次數為 0）。
- `register_key_internal` 加上 `group` 參數，版本與群組的一致性檢查移到這裡集中處理。單人版路徑仍包 KEK，audit detail 不變。
- `lib.rs` 的 `register_key` IPC 新增選用參數 `group`（`"A"`/`"B"`，serde 嚴格大小寫），改呼叫 `register_key_for`。前端目前不傳 `group`，單人版行為不變；雙人版要等 D10 的 UI 補上群組選擇才能註冊。
- TDD：6 個 assertion RED → GREEN，新增 6 個測試。
  - 第一次 GREEN 有 2 個測試失敗，原因在測試 fixture：`MockBackend` 每次 `detect` 會循環金鑰類型，第二支是 PIN 型 → `PinRequired`。
  - 修正方式是每支金鑰改用新的 mock 實例，assertion 不變，也沒改 production code。
  - 那次失敗的 log 保留為 `02/03-FAIL-fixture-pin-cycle-*.log`。
- Rust MSVC lib：單人版 242/242、雙人版 242/242，無 warning；跑測試前後原始碼 SHA-256 不變；rustfmt 通過；Node 65/65。

### D6（2026-10-11）

- `FidoError::CredentialExcluded`（中文訊息：已註冊、只能屬於一個群組、未新增金鑰槽）；診斷分類為 `credential-excluded`（`webauthn_diagnostics`，封閉分類，不含原始文字）。
- trait `FidoBackend::register_credential_excluding(detected, pin, exclude)`：
  - 預設實作：清單為空時等同 `register_credential`；清單非空而後端沒有實作排除時，回 `NotSupported` fail closed，不會在無法排除的情況下重複註冊。
  - `UnavailableBackend` 一律回自己的「WebAuthn 不可用」訊息。
- **MockBackend**：
  - 每個實例有隨機 `instance_key`；`device_tag = HMAC(instance_key, seq)[..8]` 嵌在 `credential_id[1..9]`。credential 長度 32、`[0]` 仍是 kind，PRF 語義不變。
  - 排除清單中有本裝置簽發的 credential → `CredentialExcluded`；不同實例（另一支實體金鑰）不會誤判。
  - 新增測試輔助 `reuse_device()`：下一次 detect 視為同一支金鑰再次插入。
- **raw CTAP（CLI/診斷）**：`do_register` 的 `exclude_list` 填入 `PublicKeyCredentialDescriptor`；`AuthenticatorError::CredentialExcluded`（CTAP2 0x19）→ `FidoError::CredentialExcluded`。
- **Windows WebAuthn（GUI）**：
  - `make_credential(detected, exclude)` 把排除清單放進 `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS.CredentialList`（v1 exclude 欄位，`exclude` 與 entries 存活到 API 返回）。清單可以是空的；每筆先通過長度驗證。
  - `make_credential_error`：`NTE_EXISTS`（0x8009000F；Microsoft webauthn.h 中 `WebAuthNGetErrorName` 對應 `"InvalidStateError"`）→ `CredentialExcluded`；其他 HRESULT 維持原本的 `Internal` 訊息。
  - **實機行為待 D13 確認（風險 R1）**：Windows 安全性對話框的文案，以及命中時是否真的回 `NTE_EXISTS`。
- **vault**：雙人版註冊在呼叫 authenticator 之前，先把全部既有 credential（A+B）解碼成排除清單，再呼叫 `register_credential_excluding`。單人版仍呼叫原本的 `register_credential`，不帶排除清單（有測試驗證）。被拒絕時不新增槽位、不寫 `key_registered` audit。
- TDD：
  - 第一次 RED 編譯失敗（`webauthn_diagnostics::error_category` 是窮舉 match），log 保留為 `00-NOT_EXECUTED-compile-error.log`，不算 RED。
  - 補上 stub 後，9 個 assertion RED → GREEN。
  - 第一次 GREEN 有 1 項失敗，原因是測試寫法錯誤：比較了 `w!("public-key")` 常數的指標，但每次使用位址可能不同。改為比較字串內容，production code 沒有改，log 保留為 `FAIL-test-pointer-compare`。
- 新增 11 個測試（另外在既有的分類測試加入 1 個案例）。Rust MSVC lib：單人版 253/253、雙人版 253/253，無 warning；跑測試前後原始碼 SHA-256 不變。
- rustfmt：`fido2.rs`/`vault.rs`/`webauthn_diagnostics.rs` 通過；`windows_webauthn.rs` 的 baseline 本來就有 7 處格式差異，本次沒有新增。
