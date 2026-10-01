# 可攜式 FIDO2 密碼金庫（portable-fido2-vault）v0.1

Windows 桌面、**完全離線**、**portable 免安裝**的 FIDO2 密碼金庫。
單一資料夾（`portable-fido-vault.exe + vault.db`）複製到任何 Windows 電腦即可使用。

- 首次執行建立帳號：主密碼經 **Argon2id** 派生金鑰
- 之後**主密碼或任一支已註冊 FIDO2 金鑰**皆可登入（允許多支）
- 金鑰類型自動偵測：**指紋型 / PIN 型 / touch-only**，登入時依類型給提示
- **僅接受支援 CTAP2 hmac-secret/PRF 的金鑰**（如 YubiKey 5+）；不支援者拒絕註冊並顯示原因 → 所有已註冊金鑰皆可單獨解鎖金庫
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

前置：
- Rust stable + **GNU toolchain**（`rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal`；本機無 MSVC/VS，走 GNU 免 UAC）。
- **dlltool.exe**（Rust GNU toolchain 不自帶 binutils）：下載 [winlibs-mingw](https://github.com/brechtsanders/winlibs_mingw/releases) x86_64-posix-seh zip，把其 `bin/` 加進 PATH。
- WebView2（Win11 內建）。

```bash
# bash / git-bash（WS2）
export PATH="$HOME/.cargo/bin:$HOME/tools/winlibs-x86_64-posix-seh-gcc-14.2.0-mingw-w64ucrt-12.0.0-r2/bin:$PATH"
cd C:/project/portable-fido2-vault/src-tauri
cargo +stable-x86_64-pc-windows-gnu build --release --features real-ctap --bin portable-fido-vault
# 產出硬體版 GUI；target/release/portable-fido-vault.exe
```

Windows Release GUI（`real-ctap`）從檔案總管啟動時使用 Windows WebAuthn API；PIN、指紋與觸碰提示由 Windows 安全性視窗處理，無需設定 `F2V_AUTHENTICATOR` 或以系統管理員身分啟動。目標系統需提供 WebAuthn API v4 或更新版本。Debug 建置仍預設 MockBackend；若需在 Release 明確執行 mock 測試，可設定 `F2V_AUTHENTICATOR=mock`。未設定覆寫值且 Release 缺少 `real-ctap` 時會拒絕啟動。`vault_cli --authenticator hw` 保留 raw CTAP/HID 診斷路徑，與 GUI 使用的 Windows API 不同。

> portable 部署：將 `target\release\portable-fido-vault.exe` 複製到任意資料夾即完成安裝；
> 首次執行後該資料夾會多出 `vault.db`（你的金庫）。整個資料夾＝全部資產。

## 使用流程

1. **首次執行**：輸入主密碼（兩次）→ 建立 `vault.db` → 可順手註冊 FIDO2 金鑰。
2. **登入**：主密碼，或在 Windows Release 硬體模式按單一「以金鑰登入」入口；Windows 安全性視窗負責選擇／驗證已註冊的金鑰及 PIN/UV/觸碰，不必先在 App 點選特定金鑰。非 brokered 的 Mock/raw-CTAP 模式仍使用逐支選擇與 PIN 欄位。
3. **條目**：新增/編輯/刪除（網站、帳號、密碼、備註），自動記 created_at/updated_at。
4. **金鑰管理**：註冊新金鑰（自動偵測類型）／移除金鑰（不可逆，需確認）。
5. **軌跡紀錄**：登入成功/失敗、金鑰註冊/移除、條目增刪改＋時間（不含任何密碼明文）。
6. **設定**：閒置自動上鎖分鐘數（預設 5）。

## portable 部署到別台電腦（Win11-NB）

```powershell
# 本機打包
Copy-Item target\release\portable-fido-vault.exe C:\deploy\fido-vault\
# 把整個 fido-vault 資料夾（含 vault.db）複製/USB 到 NB，雙擊 exe 即可
```

## 測試 / Gate 驗證

**一鍵跑全部 E2E（Gate 2/3/4/5/6/8）**：

```bash
cd C:/project/portable-fido2-vault/src-tauri
cargo +stable-x86_64-pc-windows-gnu build --release --example vault_cli
python ../scripts/gate_e2e.py     # 逐項 PASS/FAIL + 證據；全綠 = exit 0
```

手動範例（CLI 參數皆為 `--flag value`）：

```bash
V=./test-vault.db; P=target/release/examples/vault_cli.exe
$P create       --path $V --pw Test1234!
$P register-key --path $V --pw Test1234! --kind pin --pin 2468   # 類型：fingerprint|pin|touch_only；--no-prf 模擬不支援 PRF 的金鑰（應被拒絕）
$P login-key    --path $V --idx 0
$P add-entry    --path $V --pw Test1234! --site example.com --account alice --pass Secret!234
$P list         --path $V --pw Test1234!
$P audit        --path $V --pw Test1234!
```

無 FIDO 硬體時，MockBackend（預設）以軟體金鑰實作 hmac-secret 語義，Gate 3/4 仍可端到端驗證；
有實體 YubiKey 5+ 時切換 real CTAP2 後端實測。

## 安全聲明

- 離線：程式不開啟任何網路連線。
- 軌跡紀錄絕不含密碼/PIN/金流明文。
- 無復原機制（設計如此）。詳見 `docs/spec.md` §8。
