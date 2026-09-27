# 可攜式 FIDO2 密碼金庫（portable-fido2-vault）v0.1

Windows 桌面、**完全離線**、**portable 免安裝**的 FIDO2 密碼金庫。
單一資料夾（`PortableFidoVault.exe + vault.db`）複製到任何 Windows 電腦即可使用。

- 首次執行建立帳號：主密碼經 **Argon2id** 派生金鑰
- 之後**主密碼或任一支已註冊 FIDO2 金鑰**皆可登入（允許多支）
- 金鑰類型自動偵測：**指紋型 / PIN 型 / touch-only**，登入時依類型給提示
- 加密：Argon2id + **AES-256-GCM**，整個金庫加密為單一檔案 `vault.db`
- CRUD ＋ created_at/updated_at ＋ 軌跡紀錄（絕不明文記錄密碼）＋ 閒置自動上鎖
- ⚠️ **無復原機制**：主密碼遺忘且所有 FIDO2 金鑰全失 = 資料永久無法取回

## 目錄結構

```
portable-fido2-vault/
├─ README.md            ← 本檔
├─ docs/spec.md         ← 技術規格（架構、金庫格式、FIDO2 偵測流程）
├─ src/                 ← 前端（純靜態 HTML/JS/CSS，繁中 UI）
└─ src-tauri/           ← Tauri v2 (Rust) 後端
   ├─ src/vault.rs      金庫格式 / 加密落盤
   ├─ src/crypto.rs     Argon2id / AES-GCM / HKDF
   ├─ src/fido2.rs      FIDO2 後端 trait + Mock/Real
   └─ examples/vault_cli.rs  E2E 測試 CLI（Gate 驗證用）
```

## 建置（WS2 建置機）

前置：Rust stable（rustup）、WebView2（Win11 內建）。

```powershell
cd C:\project\portable-fido2-vault\src-tauri
cargo tauri build          # 產出 target\release\PortableFidoVault.exe
```

> portable 部署：將 `target\release\PortableFidoVault.exe` 複製到任意資料夾即完成安裝；
> 首次執行後該資料夾會多出 `vault.db`（你的金庫）。整個資料夾＝全部資產。

## 使用流程

1. **首次執行**：輸入主密碼（兩次）→ 建立 `vault.db` → 可順手註冊 FIDO2 金鑰。
2. **登入**：主密碼，或點選任一支已註冊金鑰（依類型提示：按指紋 / 輸入 PIN / 觸碰）。
3. **條目**：新增/編輯/刪除（網站、帳號、密碼、備註），自動記 created_at/updated_at。
4. **金鑰管理**：註冊新金鑰（自動偵測類型）／移除金鑰（不可逆，需確認）。
5. **軌跡紀錄**：登入成功/失敗、金鑰註冊/移除、條目增刪改＋時間（不含任何密碼明文）。
6. **設定**：閒置自動上鎖分鐘數（預設 5）。

## portable 部署到別台電腦（Win11-NB）

```powershell
# 本機打包
Copy-Item target\release\PortableFidoVault.exe C:\deploy\fido-vault\
# 把整個 fido-vault 資料夾（含 vault.db）複製/USB 到 NB，雙擊 exe 即可
```

## 測試 / Gate 驗證

```powershell
cd src-tauri
# 核心 E2E（建立→密碼登入→金鑰註冊→金鑰登入→CRUD→軌跡→跨路徑可攜）
cargo run --example vault_cli -- create --path .\test-vault.db --pw Test1234!
cargo run --example vault_cli -- register-key --path .\test-vault.db
cargo run --example vault_cli -- login-key 0    --path .\test-vault.db
cargo run --example vault_cli -- add-entry example.com alice Secret!234 --path .\test-vault.db
cargo run --example vault_cli -- audit          --path .\test-vault.db
```

無 FIDO 硬體時，MockBackend（預設）以軟體金鑰實作 hmac-secret 語義，Gate 3/4 仍可端到端驗證；
有實體 YubiKey 5+ 時切換 real CTAP2 後端實測。

## 安全聲明

- 離線：程式不開啟任何網路連線。
- 軌跡紀錄絕不含密碼/PIN/金流明文。
- 無復原機制（設計如此）。詳見 `docs/spec.md` §8。
