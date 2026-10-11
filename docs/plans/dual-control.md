# 雙群組金鑰控管版（Dual-Control Edition）設計文件

> 狀態：**D1–D11 已完成；D12–D13 未開始，實機驗收待 D13**。PR #29 維持 draft，未合併／未部署。
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
   - 範圍：**30–600 秒**，預設 120。登入時以 header 的合法 `u32` 鏡像做 clamp；鏡像缺失／null 時使用預設 120。字串、負數、小數、超出 `u32` 的 JSON 值維持既有反序列化拒絕，不寬容解析。加密 payload 權威值缺失或超界時拒絕解鎖，不用預設值掩蓋不合法資料。
   - 解鎖後若兩值不一致，以 payload 值覆寫 header，並記 audit `settings_tamper_detected`。
   - 只有已解鎖的 session 才能修改（設定頁新增欄位），改動記 audit `settings_changed`。
5. 稽核：
   - 成功：`login_success` method=`fido2-dual:<群組>:<label>#<fp>+<群組>:<label>#<fp>`（依實際順序；`fp` 為 SHA-256(credential_id) 前 4 bytes hex，label 中的 `% + : #` 會跳脫；見 §11 D7 追加修正）。
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
3. 以 K1 嘗試再註冊一次（選 B），再試一次選 A → 兩次都顯示「已註冊」，slot 數不變（Q3）。手邊若有不同類型的金鑰（觸碰型、PIN/指紋型），各測一次（R6）。
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
| R6 | Q3「同一實體金鑰只註冊一筆」完全依賴 authenticator 遵守 CTAP2 excludeList 語意；應用端無法由 credential_id/AAGUID 判斷是否為同一支實體金鑰（設計限制）。若 credential 帶 credProtect=3 且該次註冊未完成 UV，authenticator 可能看不到既有 credential | D13 實機分別以觸碰型與 PIN/指紋型金鑰驗證重複註冊被拒（§6.2 第 3 步）；不符合時記錄型號並回報，不在應用端以弱指紋自行判斷 |

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
- [x] D7 兩步驟登入狀態機（begin / complete / cancel / 逾時，見 §11）
- [x] D8 群組最後一支金鑰不可刪除 + 金鑰清單群組資料（見 §11）
- [x] D9 時限設定：payload 權威值、header 鏡像、clamp 與竄改修復（見 §11）
- [x] D10 前端：edition 切換、兩步驟登入與倒數、群組註冊、金鑰清單群組／刪除限制、時限設定、break-glass 提示（見 §11）
- [x] D11 全套驗證：Rust single/dual、Node、單人版與雙人版 mock Gate E2E、GNU Release 雙執行檔、Clippy／rustfmt、靜態掃描、兩位獨立審查（見 §11）
- [ ] D12–D13

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

#### D6 審查與追加修正（2026-10-11）

- 兩位獨立唯讀審查員都審查 patch `e6b812ab…5bab93`（commit `5b5a31f`），結果都是 **passed=true，沒有 blocking**。證據在 `D:/scratch/dual-control-20261011/d6/review/`：
  - Claude Code CLI：`claude-cli.raw.json` / `claude-cli-verdict.json`。
  - Hermes SubAgent：`subagent-verdict.json`。
- 依審查的 minor 意見與測試缺口追加修正：
  - `make_credential_error(hr, exclude_requested)`：只有在有送排除清單時，`NTE_EXISTS` 才對應 `CredentialExcluded`；單人版（清單為空）維持通用錯誤，不顯示雙人版專用訊息。這是唯一的行為變更，TDD 1 個 assertion RED → GREEN。
  - 抽出 `exclude_credential_list`（空清單 → null 指標 + count 0）與 raw CTAP `exclude_descriptors`，各補單元測試。
  - 新增原始碼 contract 測試：makeCredential options 一定帶入 `CredentialList: exclude_list`，且不使用 v3 `pExcludeCredentialList`。
  - 補上其他測試：`validate_exclude_credential_ids` 的拒絕分支；mock 忽略長度不足 9 的排除項；`UnavailableBackend` 保留自己的訊息；槽位 credential_id 損壞時在呼叫 authenticator 前 fail closed（detect/register 計數為 0）；移除槽位後，同一支金鑰可以重新註冊（排除清單只含目前存在的槽位）。
  - 設計文件新增殘餘風險 R6（Q3 依賴 authenticator 遵守 excludeList、credProtect/UV 前提），§6.2 第 3 步加上 A/B 兩群組、不同金鑰類型各測一次。
  - raw CTAP 的排除清單過長時，authenticator-rs preflight 會分批送出；仍無法送出就 fail closed。`vault_cli` 本期不支援 v2（§5），所以雙人版產品不會走到這條路徑。
- 過程中的失敗（沒有改 production code，log 都保留）：第一版 contract 測試用字面量寫了 `fn make_credential_with_diagnostics(` 和 `fn get_hmac_secret(`，違反既有 source-wiring oracle 的「標記在檔案中唯一」規則，造成 10 個既有測試失敗（`LOCATOR:section-start`），log 為 `d6r1/02/03-FAIL-contract-test-duplicates-locator-*.log`。改成以 `format!` 組出定位字串，既有 oracle 一行都沒改。
- Rust MSVC lib：單人版 262/262、雙人版 262/262（253 + 9），無 warning；跑測試前後原始碼 SHA-256 不變；rustfmt：`windows_webauthn.rs` 維持 baseline 的 7 處、沒有新增，其餘檔案通過。

### D7（2026-10-11）

- **vault 層**（時間以參數 `now: Instant` 注入，方便測試逾時）：
  - `Vault::dual_login_begin(path, pin, backend, now) -> DualPending`：
    - 讀檔（v2 版本互斥），A、B 群組必須各至少一支，否則回 `VaultError::DualNotReady`，不提示金鑰。
    - broker 允許清單 = 全部 A+B credential；依所選 credential 找到槽位，用 AAD(群組, credential) 解出該群組 share。
    - 解包失敗時記 sidecar `fido2-dual-step1:<label>`，回 `DecryptFailed`。
  - `DualPending`：只存在 Rust 端，不可複製，Debug 遮蔽 share，share 為 `Zeroizing`，drop 時清零。內含第一群組/名稱、截止時間、時限，以及綁定值（`created_at` + `dual_slot` 密文）。
  - `Vault::dual_login_complete(pending, pin, backend, now)`：以 by-value 取用 `pending`（一次性）。
    - 逾時（`now > deadline`）→ 記 `fido2-dual-timeout`，回 `DualStepExpired`，**不提示第二支金鑰**。
    - 檔案綁定值不同 → 回「金庫在兩步驟之間已變更」，不提示金鑰。
    - 允許清單**只含另一群組**；**不信任後端**，所選 credential 必須屬於另一群組，否則拒絕。
    - 解包失敗，或 `HKDF(share_A‖share_B)` 解不開 `dual_slot` → 記 `fido2-dual-step2:<label>`，回 `DecryptFailed`，不寫檔。
    - 成功時走共用的 `unlock`（含 payload 形狀與 dual_slot 一致性檢查），audit method 為 `fido2-dual:<第一群組>:<名稱>+<第二群組>:<名稱>`，依實際順序記錄。
  - `DualPending::cancel` → 記 `fido2-dual-cancel`，金庫檔不變。
  - `effective_dual_step_timeout_secs(header)`：header 明文鏡像 clamp 到 30–600 秒，缺值時為 120。設定變更與竄改修復留給 D9。
- **app 層（`lib.rs`）**：
  - `AppInner.dual_pending`。
  - IPC `login_dual_begin(pin)` 回 `{first_group, first_label, second_group, timeout_secs, remaining_ms}`，不含機密；每次都會先丟棄舊的暫存。
  - `login_dual_complete(pin)`：不論成敗都會取走暫存。
  - `login_dual_cancel`。
  - 三個 IPC 只限雙人版執行檔。`create_vault`、`login_password`、`lock` 都會清掉暫存；視窗關閉時 state drop 也會清零。
- TDD：
  - 第一次執行因 cargo 測試過濾參數用錯，沒有跑任何測試，log 保留為 `00-NOT_EXECUTED-bad-filter-args.log`。
  - 正式 RED 為 14 個 assertion 失敗 → GREEN，新增 14 個測試。
  - 涵蓋：A→B、B→A、第一步資訊與允許清單、第二步只提供另一群組、惡意後端回同群組被拒、兩群組不齊、逾時、恰好在截止時間仍可完成、取消、第一步/第二步群組標記被竄改、兩步之間金庫被替換、單人版檔案、時限 clamp。
- Rust MSVC lib：單人版 276/276、雙人版 276/276，無 warning；跑測試前後原始碼 SHA-256 不變；rustfmt 通過。

#### D7 審查與追加修正（2026-10-11）

- 兩位獨立唯讀審查員都審查 patch `11f7fdd7…26e4ae`（commit `c56d859`），結果都是 **passed=true，沒有 blocking**。兩人都確認核心安全性質成立：任一群組的金鑰（任意支數），不論 header 被竄改或後端不遵守允許清單，都解不開 KEK。證據在 `d7/review/`（`claude-cli.raw.json`、`claude-cli-verdict.json`、`subagent-verdict.json`）。
- 依 minor 意見修正（commit 見 PR）：
  1. **倒數起點**：改為「第一支金鑰完成並解出 share 之後」才取時間（`clock` 參數改成 `&mut dyn FnMut() -> Instant`），`remaining_ms` 在第一步回來後重新取樣。原本從第一步開始前計時，會吃掉第一步的互動時間。
  2. **截止時間是硬上限**：第二支金鑰互動結束後再檢查一次；逾時 → 記 `fido2-dual-timeout`，回 `DualStepExpired`，不寫檔。
  3. **Rust 端主動清除**：`login_dual_begin` 成功後啟動計時執行緒，截止後呼叫 `sweep_expired_dual`；只清同一代（`dual_generation`）的暫存，記 `fido2-dual-timeout`，share 清零，不依賴前端呼叫。
  4. **稽核可追責**：成員識別改為 `<群組>:<跳脫名稱>#<credential 指紋>`。指紋來自已通過 AAD 驗證的 credential_id，竄改 header 的名稱無法冒名；名稱中的 `% + : #` 一律跳脫，step1/step2 失敗紀錄也套用。群組文字改用 `KeyGroup::as_str()`，不依賴 Debug 輸出；D5 註冊 audit 也改用它，輸出不變。
  5. **補記失敗紀錄**：第二步後端回傳群組外 credential → `fido2-dual-step2-rejected`；兩步之間金庫被替換 → `fido2-dual-binding-mismatch`。broker 錯誤或使用者取消 Windows 對話框，仍與 `login_any_key` 一致，不記錄。
  6. **不改（文件化）**：第二步遇到 `PinRequired` 時，暫存仍會被取用，必須從第一步重來（符合 §4.3）。這只會發生在非 broker 的後端（mock / raw CTAP）；雙人版 Release GUI 走 Windows broker，PIN 由系統 UI 處理，不會遇到。`login_dual_complete` 分兩段取鎖再寫入 `g.vault`，與既有的 `login_any_key` 相同，不在本次範圍。
- 新增 16 個測試：
  - vault 13 個：時鐘在金鑰互動後取樣、刷完才逾時被拒且不寫檔、剛過截止時間即逾時、第二步刷同一支金鑰被拒、群組外 credential 被記錄、第一步回傳不在金庫的 credential 不會建立暫存、綁定不符被記錄且不寫檔、header 時限被竄改時登入端仍 clamp、同群組的 share 解不開 dual_slot（直接密碼學驗證）、Debug 不含 share 位元組、`expire` 記錄、稽核跳脫與指紋、失敗紀錄跳脫。
  - lib 3 個：`sweep_expired_dual` 會清除同一代且已逾時的暫存；未逾時或已是新一代的暫存保留。
- TDD：10 個 assertion RED → GREEN。Rust MSVC lib：單人版 292/292、雙人版 292/292（276 + 16），無 warning；跑測試前後原始碼 SHA-256 不變；rustfmt：`lib.rs`/`vault.rs`/`crypto.rs`/`fido2.rs` 通過。
- 仍未涵蓋（需 GUI 或 IPC 整合）：`lock`/`login_password`/`create_vault`/新的 begin 會清除暫存（都是一行指定，已人工檢查），以及計時執行緒實際觸發。留到 D10/D11 的 UI 與 E2E 驗證。

### D8（2026-10-11）

- `vault::last_key_in_group(header, credential_id_b64) -> Option<KeyGroup>`：只對雙人版有效；刪除該 credential 會讓所屬群組歸零時，回傳該群組。
- `Vault::remove_key`：雙人版若是群組最後一支 → `VaultError::LastKeyInGroup(group)`（「不可刪除 A 群組的最後一支金鑰（A、B 群組各須保留至少一支）」），不改 header、不寫檔、不記 audit。
  - 依 §4.5 一律禁止，包括另一群組還沒有金鑰時的唯一金鑰。
  - 雙人版成功刪除時，audit detail 附加 ` group=A|B`；單人版的行為與 detail 逐字不變（可刪唯一金鑰，有回歸測試）。
- `lib.rs`：抽出 `key_infos(header)`，登入畫面與金鑰管理共用（原本兩處重複的建構程式改呼叫它）。
  - `KeyInfo` 新增 `group` 與 `last_in_group`（UI 用來停用移除鈕），兩者在單人版都不輸出（`skip_serializing_if`），單人版 JSON 形狀不變，有測試保證。
  - 實際的刪除限制以 Rust 端為準，UI 只是輔助。
- TDD：6 個 assertion RED → GREEN；另有 2 個既有行為的回歸測試（GREEN→GREEN，不算 RED）：單人版 KeyInfo JSON 形狀、單人版可刪唯一金鑰。新增測試共 8 個。
- Rust MSVC lib：單人版 300/300、雙人版 300/300，無 warning；跑測試前後原始碼 SHA-256 不變；rustfmt 通過；Node 65/65（前端未改）。

#### D8 接續核對、審查與測試補強（2026-10-11）

- 上一對話已推送 D8 commit `e7052f0`，中斷在 CI 觀察；本輪讀回 exact-head run `38120790725` / job `114414912355` 為 completed/success，必要步驟全部 success，完整 log 為 Node 65/65、Rust single/dual 各 300/300、既有單人版 mock Gate E2E 20/20（不是雙人版完整 E2E 或實體驗收）。
- 原始 10 檔 source manifest 與本輪重跑前後一致；MSVC single/dual 各 300/300、Node 65/65、syntax/scoped rustfmt/diff check 通過。第一次 Node 在非 repo cwd 執行，collector 路徑解析失敗；保留失敗 log，以正確 cwd 重跑 PASS，未更動 production code。
- 審查路由阻礙如實保留：Claude Code CLI API 429 usage_limit_reached 未讀取候選；SubAgent 的 Claude model 與 openai-codex 不相容（HTTP 400），不算有效審查。改用現有 Reviewer profile（實際名稱 `reviwer`）與獨立 default CLI session，僅對該次執行指定 model/provider，不修改任何持久設定。兩份完整唯讀 verdict 皆 passed=true、security_concerns/logic_errors 空，並覆蓋全部 touched regions；manifest 由 parent 獨立驗證，reviewer 不假稱已計算 SHA256。
- 依兩份審查建議新增 5 個 test-only 回歸測試（production code 不變）：
  1. A/B 各自非最後成員刪除，在另一群組存在／尚未建立兩種情境，於 lock/drop 或重新解鎖前立即讀回 credential／group／順序，並驗證 persisted group audit。
  2. A-only、B-only、雙群組最後成員及未知 credential 拒絕後，完整 header、payload（含 audit）、磁碟 bytes 不變；布林比較避免輸出合成 share。
  3. 已通過結構驗證的同／跨群組重複 credential，首次匹配、每次只刪一槽、剩餘單例仍受保護；不放寬 header 驗證。重複 credential 的清單提示描述的是同 ID 實際刪除目標，不是授權依據。
  4. 清單欄位值／順序、空清單、A-only/B-only、重複 credential 提示，以及 Header conversion 一致性。
  5. 實際 `read_keys_from_file` 與 public lock 回傳 Header conversion 一致性；全部使用專屬 synthetic fixture + MockBackend，不讀正式 vault。
- 新增 5 項 targeted tests 直接通過，屬既有行為 GREEN→GREEN 覆蓋，不計為新的 RED。首輪因測試跨模組存取 private header 編譯失敗（NOT_EXECUTED，不算 assertion RED），改用既有 public lock 回傳 header 後通過，未改既有斷言與 production code。
- 最終 MSVC single/dual 各 **305/305**、Node **65/65**、node syntax、scoped rustfmt、git diff check 全通過；測試前後兩檔 source SHA256 與 final frozen manifest 一致。
- test-only follow-up 再由兩位獨立 CLI reviewer 檢查完整 diff/context，皆 passed=true、blocking 與 suggestions 空。final manifest SHA256 `0b27c308cb00718fa3cf258740f4151698d47219d0c18757b813a3e57d967552`。
- 完整原始 log／失敗嘗試／verdict／snapshot 留存 `D:/scratch/dual-control-20261011/d8/`；收尾另存 durable evidence archive。實機刪除／前端停用鈕留待 D10/D13，未宣稱 PASS；PR 維持 draft、整體 Kanban blocked，不合併、不部署、不開始 D9。

### D9（2026-10-11）

- `Vault::set_dual_step_timeout(secs)`：僅雙人版接受 30–600 秒（含端點）；一次持久化加密 `Settings.dual_step_timeout_secs`、header 明文鏡像及 `settings_changed`（method=`manual`）。任何存檔錯誤都還原原設定、原鏡像和完整 audit，包含 audit 上限裁切前的紀錄。單人版或超界輸入拒絕，不改記憶體／磁碟／audit。
- `lib.rs` 註冊 `set_dual_step_timeout` IPC；委派給受既有 session mutex／`with_unlocked` 保護的 `update_dual_step_timeout`。`get_vault_settings` 仍回傳加密 payload 的設定，不以 header 作權威來源。前端欄位是 D10，未在本輪加入。
- 共用解鎖路徑先完成 AES-GCM 解密、payload 版本／dual-slot／權威時限驗證，再比較原始 header `Option<u32>`。不一致就以權威值修復並新增 `settings_tamper_detected`（method=`system`），與登入成功 audit 一次存檔。不能比較 clamp 後的值，否則 0→30、極大值→600、缺值→120 的竄改會被忽略。
- 密碼與兩支金鑰登入共用修復；錯誤密碼、只完成第一步、第二步失敗、不合法權威設定皆不修復／不寫金庫。已鎖定時仍只採用有上限的明文鏡像，鏡像不是授權依據。D7 截止時間保留既有 `now > deadline` 判定，未改成 `>=`。
- TDD 四個切片共 **10 個已執行 assertion RED**：setter 4、修復 2、權威範圍 1、IPC 3；各切片 GREEN 後才進下一步。其他 9 項新增測試為既有／補強行為 GREEN→GREEN，共新增 **19 個測試**。IPC 最初兩輪缺 dependency／錯誤 enum import 的編譯失敗保留為 NOT_EXECUTED，不算 RED；截止時間補強測試首次誤用 `>=`，查明 D7 原有判定後修正測試，未修改 production 邊界。
- 候選兩份獨立唯讀審查通過後，加入 5 項 test-only 建議覆蓋：原始鏡像與 clamp 同值仍修復、缺少加密權威值、非 `u32` header 值、setter rename 失敗、修復存檔失敗保留 sidecar；另強化 audit 上限 rollback 和雙金鑰 repair audit 的重新解鎖持久化。初始 prompt 曾錯稱 sidecar 在存檔前刪除，兩位 reviewer 與父代理核對原始碼更正：實際一直是存檔成功後才刪除，production 未變動此順序。
- 補強後兩份完整獨立審查皆 `passed=true`、`coverage_complete=true`，security／logic finding 空；父代理核對每個 touched line 與 immutable snapshot。Final manifest SHA256：`443e711de5e073d4812a12a4575d03cf4d86751605be10b704adae4a3d8d1a97`。
- 最終本機 Rust MSVC：single／dual 各 **324/324**；Node **65/65**；syntax、scoped rustfmt、git diff check、新增行靜態安全掃描通過。source 與已審查 snapshot 一致。嚴格 Clippy `-D warnings` 仍被 `windows_webauthn.rs` 的 3 個既有基線問題阻擋（dead_code、兩個 too_many_arguments），不是 clean PASS；單次豁免這兩類既有 lint 後、限定 `--lib` 的 single／dual 檢查通過，未改永久 lint 設定。含所有 bin tests 的額外檢查也受既有診斷程式 lint／single-vs-dual 編譯 guard 阻擋，保留原始 log，不宣稱整體 Clippy clean。
- GNU Release 單人版 `--features real-ctap --bin portable-fido-vault` 與雙人版 `--features real-ctap,dual-control --bin portable-fido-vault-dual` 均建置成功，x86_64 PE 與 SHA256 已核對；產物僅留在獨立 scratch target，未執行 GUI／未部署。隔離的 `TEMP/TMP/TMPDIR` synthetic fixture 目錄下另重跑 single／dual 各 324/324，production source 仍與審查 snapshot 一致。
- 最終 reviewer 剩餘建議屬非阻擋性，留待 D11：鏡像不一致＋payload tag 破壞的組合；兩支金鑰成功但權威設定缺失／超界且有 sidecar；修復登入的 rename 階段故障。既有共用驗證／寫入順序已覆核，未發現 production 缺陷。
- 全部原始 log、失敗嘗試、唯讀 verdict、snapshot／manifest 留存 `D:/scratch/dual-control-20261011/d9/`，收尾另存 durable archive。PR #29 保持 draft、整體 Kanban blocked；未合併／未部署／未接觸正式 vault／未開始 D10，實機驗收仍待 D13。新的 exact-head CI 結果由 archive receipt 與 Kanban 讀回紀錄，不以舊 D8 run 替代。

### D10（2026-10-11）

- 範圍只有靜態前端：`src/app.js`、`src/index.html`、`src/styles.css`，新增 `tests/dual-control-ui.test.cjs`。Rust／Tauri IPC 未變更（沿用 D1–D9 的 `get_edition`、`login_dual_begin/complete/cancel`、`register_key(group)`、`KeyInfo.group/last_in_group`、`set_dual_step_timeout`、`Settings.dual_step_timeout_secs`）。
- **edition 切換**：`boot` 先呼叫 `get_edition`；回 `"dual"` 才顯示雙人版 UI（頁面標題、`edition-badge`）。呼叫失敗時維持單人版 UI，雙人版金庫仍由 Rust 版本互斥 fail closed。所有雙人版元素在 HTML 預設 `hidden`；單人版既有 65 個 Node 測試不變且全過。
- **兩步驟登入**：
  - A、B 群組各至少一支才顯示「以金鑰登入（第一步）」；否則隱藏並提示「需 A、B 群組各至少一支金鑰；目前請以主密碼登入」。
  - 第一步呼叫 `login_dual_begin`，顯示「<群組>（<名稱>）已驗證，請 <另一群組>成員於 N 秒內完成驗證」與倒數（以 Rust 回傳的 `remaining_ms` 計算，僅供顯示）。名稱一律用 `textContent`。
  - 第二步 `login_dual_complete`：進行中停止前端倒數（截止由 Rust 前後檢查）；失敗一律回第一步並提示「請從第一步重新開始」（Rust 暫存不論成敗都已取走）。
  - 取消呼叫 `login_dual_cancel`；倒數歸零只回第一步，不呼叫取消（Rust 計時執行緒自行清除並記錄逾時）。
  - 第一步進行中重複點擊只送一次；以 generation 忽略已失效的回應。
  - 非 broker 後端（debug mock／raw CTAP）每步各自讀取選填 PIN，讀後清空欄位。
- **break-glass**：雙人版主密碼登入成功後顯示醒目提示「本次以主密碼緊急登入」；若有進行中的兩步驟，先 `login_dual_cancel` 再送密碼。單人版不顯示。
- **註冊**：命名對話框加 A/B 單選（無預設、每次開啟重設），未選群組留在對話框且不偵測金鑰；雙人版 `register_key` 帶 `group`，單人版參數形狀不變（不含 `group` 鍵）。
- **金鑰管理**：雙人版依 A、B 分組列出並顯示各群組支數與是否已啟用金鑰登入；`last_in_group` 的移除鈕停用並說明原因（刪除限制仍以 Rust `LastKeyInGroup` 為準）。清單全以 DOM 節點 + `textContent` 建立。
- **設定**：雙人版顯示「第二步等待時限（30–600 秒）」，載入加密 payload 的權威值；前端驗證整數 30–600 後呼叫 `set_dual_step_timeout`。
- TDD：先加 HTML 與空殼函式（stub），19 個新測試中 **15 個 assertion RED**（`02-red-stub.log`，皆 `ERR_ASSERTION`）；其餘 4 個在 stub 階段即通過，屬既有／靜態行為（HTML 元素與預設 hidden、單人版 key login、單人版註冊不帶 group、單人版隱藏時限設定），不計 RED。第一次 RED 因測試 fake DOM 缺 `querySelectorAll` 產生非斷言錯誤訊息，保留為 `01-SUPERSEDED-harness-*.log`，只補 fixture，未改斷言。GREEN 一次通過。
- 驗證：Node **84/84**（65 + 19）、`node --check src/app.js`、`git diff --check` 通過；跑測試前後四個檔案 SHA-256 一致；新增程式行未使用 `innerHTML`／`eval`／`insertAdjacentHTML`。Rust 未變更，本機未重跑 Rust 套件，以 exact-head CI 為準。
- 證據：`D:/scratch/dual-control-20261011/d10/`。
- 未涵蓋／留待後續：
  - 原生視窗標題仍為 `tauri.conf.json` 的「可攜式 FIDO2 密碼金庫」；D10 只改頁面標題與畫面內標示。§5「視窗標題顯示雙群組控管版」需 Rust 端 `set_title` 或設定調整，留待 D11 決定。
  - 「關於」畫面目前不存在，本期未新增。
  - 計時執行緒實際觸發、IPC 整合與 GUI 實際操作留待 D11 mock E2E 與 D13 實機。

### D11（2026-10-11）

- 使用者決定：原生視窗標題**不改**（維持 `tauri.conf.json`）；§5 標題要求以畫面內「雙群組控管版」標示為準。
- **雙人版 mock Gate E2E**（新增，`scripts/gate_e2e.py` 與單人版 20 項不變）：
  - `src-tauri/examples/dual_vault_cli.rs`：只供 E2E 的 mock CLI，`required-features = ["dual-control"]`，不進產品執行檔。`--device` 名稱代表一支實體金鑰：同名即同一支（excludeCredentials 拒絕），金鑰只認得自己簽發的 credential（模擬 broker 允許清單）。`vault_cli` 仍不支援 v2（§5 不變）。
  - `scripts/gate_e2e_dual.py`：跨行程驗證 25 項（DG1–DG9），涵蓋 §6.1：建立 v2、break-glass 成功／失敗、群組註冊、同一支金鑰重複註冊（選 A、選 B）被拒、A→B／B→A 解鎖、同群組第二步失敗、未註冊金鑰、逾時（120／60 秒，含恰好截止）、取消、時限 29／601 拒絕與 60 生效、明文鏡像竄改 clamp 與修復、群組標記竄改（AAD 失敗，在另一個合成副本上進行）、群組最後一支不可刪、移除後可重新註冊、v1／v2 版本互斥且檔案不變、audit 完整、金庫檔不含主密碼。腳本拒絕使用既有資料夾、不刪除任何檔案、subprocess 不用 shell、每個子行程 120 秒逾時。
  - CI 新增兩步：`cargo build --release --locked --features dual-control --example dual_vault_cli` 與 `python ../scripts/gate_e2e_dual.py`。
- **D9 審查留下的測試補強**（`vault.rs` 3 個 test-only 測試，由 Claude Code CLI writer 撰寫、parent 重跑驗證，production 未改）：鏡像不一致＋payload tag 破壞不修復；兩支金鑰成功但權威時限缺失／29／601 且有 sidecar → `Format`、檔案與 sidecar 不變；修復登入的 rename 失敗（tmp 已寫入）→ `Io`、檔案與 sidecar 不變，之後可正常修復（`#[cfg(windows)]`）。三項首次即 GREEN，屬 GREEN→GREEN 覆蓋。觀察：payload 解密失敗不記 sidecar（既有行為）。
- **獨立審查與追加修正**（Reviewer profile `reviwer` ＋ Claude Code CLI，唯讀、各自 JSON verdict；evidence 在 `d11/review`、`followup-review`、`followup2-review`、`followup3-review`）：
  1. 第一輪（D10＋D11 全 patch）兩位都 `passed=false`，各一項邏輯問題：第二步進行中改用主密碼可能丟掉 Rust 已成功的解鎖（UI 已鎖／Rust 已解鎖）；cancel／密碼登入與新的第一步沒有序列化；E2E 腳本會刪 sidecar；CLI `--advance-secs` 溢位 panic。
  2. 修正：雙人版 begin／complete／cancel／主密碼登入共用同一個 in-flight 鎖（`withDualLock`，finally 必釋放），金鑰步驟進行中拒絕主密碼；PIN 欄 Enter 在第二步送出第二步；解鎖後的 `enterMain` 錯誤不再顯示「請從第一步重新開始」；UI 清理以 `safely` 個別執行，任一 DOM 失敗都不阻止 IPC、解鎖或釋放鎖；送出第二步前的提示失敗不再停住倒數；`startDualStep` 先建狀態與計時器再更新畫面。E2E 腳本不再刪檔（竄改情境改用新副本）、負向檢查比對具體原因、`assert`→`raise`；CLI 改用 `checked_add`。
  3. 每次行為修正都先 assertion RED：follow-up 1 共 4＋2 個 RED，follow-up 2 共 4 個，follow-up 3 共 2 個（`d11/followup/*-red-*.log`）。fake DOM 加入非空 `innerHTML` 寫入記錄與一次性 `textContent` 故障注入。follow-up 3 把「第二步開始前 DOM 故障」測試的預期由「中止後取消」改為「照常送出並解鎖」，屬刻意的行為變更。
  4. 第 2、3、4 輪：Claude Code CLI 皆 `passed=true`；Reviewer profile 第 2、3 輪各指出一項 exception-safety 缺口（已修），第 4 輪確認前述問題已解決，但另提出一項**既有**問題（見下方殘餘風險 1），判 `passed=false`。使用者 2026-10-11 決定列為既有殘餘風險，D11 以目前候選版收尾。
- 最終驗證（`d11/verify-final3/`，跑前跑後九個檔案 SHA-256 一致，並與 follow-up 3 審查 snapshot 相同）：
  - Rust MSVC lib：單人版 327/327、雙人版 327/327（324 + 3）。
  - Node 98/98（65 + 33）、`node --check src/app.js`、`git diff --check`。
  - mock Gate E2E：單人版 20/20、雙人版 25/25（MSVC release example）。
  - Clippy `--lib`（single、dual）與 `--example dual_vault_cli`：以 `-D warnings -A dead_code -A clippy::too_many_arguments` 全過；嚴格 `-D warnings` 對照組仍只有既有的 3 項（`try_lock` dead_code、兩個 too_many_arguments），證明 lib 有被檢查、沒有新增 lint。
  - rustfmt（`vault.rs`、`dual_vault_cli.rs` 等，skip_children）通過。
  - GNU Release：`portable-fido-vault.exe` SHA256 `a6d16552edfe0333faea13bed8bf273d9c6a45e5882223602c4a4822a0c6ee13`、`portable-fido-vault-dual.exe` SHA256 `e2e9f52c060fbf4dbe4046104b2515973303cc00c1d371b3a45304ed11441af6`（x86_64 PE）；僅留在 scratch target，未執行、未部署。
  - 新增行靜態掃描（hardcoded credentials、shell injection、eval/exec、pickle、SQL interpolation、HTML sink、unsafe、刪檔）：無發現；測試用密碼皆為合成值。
  - 較早的驗證回合因之後又修改原始碼，保留為 `verify-SUPERSEDED-*`，不計入。
- **殘餘風險／後續事項**：
  1. （既有、單人版與雙人版共用，使用者決定另開維護項目）`enterMain` 在 Rust 已解鎖後，若畫面切換的 DOM 操作或之後的設定／audit 讀取失敗，畫面可能停在登入頁或閒置自動上鎖不啟動。
  2. （既有）`write_data` 的 rename 失敗時會留下 `vault.db.tmp`（含密文），兩個版本相同。
  3. 打包規則：`target/*/examples/*`（`vault_cli`、`dual_vault_cli`）不得隨產品發佈 → D12 文件。
  4. 雙人版 E2E 是 vault 層跨行程驗證，不涵蓋 Tauri IPC、Rust 計時執行緒實際觸發、Windows broker 與實體金鑰 → D13 實機。
  5. 審查的其他非阻擋建議（begin 前置提示改 `safely`、更多種 DOM 故障注入、`--advance-secs` 溢位時先取消暫存等）未處理，視需要併入後續維護。
