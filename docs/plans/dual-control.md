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
- [ ] D2–D13

## 11. 驗證紀錄

### D1（2026-10-11）

- 變更：`Cargo.toml` 新增 feature `dual-control`，並明確宣告兩個 `[[bin]]`：`portable-fido-vault`、`portable-fido-vault-dual`（後者 `required-features = ["dual-control"]`）；新增 `src/edition.rs`（`Edition` / `edition_for` / `current`）與 Tauri IPC `get_edition()`；`main.rs` 在啟用 `dual-control` 時以 `compile_error!` 拒絕編譯；CI 新增 dual-control 單元測試步驟。
- TDD：RED 為 2 個 assertion 失敗（`edition_for(true)` 回 `Single`；序列化結果是 `"Single"` 而非 `"single"`）→ GREEN。
- Rust MSVC lib 測試：單人版 `real-ctap` 204/204（baseline 200 + 4）；雙人版 `real-ctap,dual-control` 204/204。
- Node 65/65；`node --check src/app.js`、`git diff --check` 通過。
- GNU Release：`--features real-ctap` 8m00s 成功（未編出 dual bin）；`--features real-ctap,dual-control --bin portable-fido-vault-dual` 成功。兩者都是 non-deployable scratch 產物，不部署。
- 反向防護（預期失敗）：單人版 bin 加 `dual-control` → 出現自訂的 `compile_error`；dual bin 不加 feature → Cargo 回 `requires the features: dual-control`。
- 既有 warning（`windows_webauthn.rs` `try_lock`、`yk_open_test`）是 baseline 就有的，D1 沒有新增 warning。
