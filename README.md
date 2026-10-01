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

### 不支援 RDP 遠端桌面啟動

目前**不支援從 RDP 遠端桌面 session 啟動 FidoVault，也不支援在 RDP session 中操作硬體金鑰流程**。請在目標 Windows 電腦的本機 Console session 啟動程式，並在該 session 完成 Windows 安全性提示。Win11-NB 的 RDP session 曾回報 WebAuthn API v1，低於本程式要求的 v4+；程式會 fail closed，不會為了支援 RDP 而降低版本檢查。RDP／WebAuthn redirection 不屬於目前支援的使用情境。

> portable 部署：將 `target\release\portable-fido-vault.exe` 複製到任意資料夾即完成安裝；
> 首次執行後該資料夾會多出 `vault.db`（你的金庫）。整個資料夾＝全部資產。

## 使用流程

1. **首次執行**：輸入主密碼（兩次）→ 建立 `vault.db` → 可順手註冊 FIDO2 金鑰。
2. **登入**：主密碼，或在 Windows Release 硬體模式按單一「以金鑰登入」入口；Windows 安全性視窗負責選擇／驗證已註冊的金鑰及 PIN/UV/觸碰，不必先在 App 點選特定金鑰。非 brokered 的 Mock/raw-CTAP 模式仍使用逐支選擇與 PIN 欄位。
3. **條目**：新增/編輯/刪除（網站、帳號、密碼、備註），自動記 created_at/updated_at。
4. **金鑰管理**：註冊新金鑰（自動偵測類型）／移除金鑰（不可逆，需確認）。
5. **軌跡紀錄**：登入成功/失敗、金鑰註冊/移除、條目增刪改＋時間（不含任何密碼明文）。
6. **設定**：閒置自動上鎖分鐘數（預設 5）。

## Windows WebAuthn 與安全性提示焦點

Windows Release 硬體模式以單一通用「以金鑰登入」入口呼叫 Windows WebAuthn；金鑰選擇、PIN/UV 與觸碰由 Windows 安全性提示處理。操作期間，程式會對唯一的新同 session 安全性 broker 視窗做一次受限的前景請求，但只有在 FidoVault 仍為前景時才嘗試；不會把提示設成 topmost，也不會繞過 Windows 的全域前景政策。這是 best-effort，Windows 仍可能切換焦點。

Win11-NB 本機 Console 已確認通用登入不需先選金鑰，Windows 安全性操作提示也出現在前景。Windows WebAuthn API v4+ 仍是硬體 GUI 的必要條件；較舊 API 版本會 fail closed。

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

## 加密機制（KEK 與多槽位設計）

仿 LUKS 的「隨機 master key + 多槽位包裝」架構，核心事實如下：

- **KEK（master key）是純隨機數**：`Vault::create()` 首次建立金庫時以 `OsRng`（OS CSPRNG）抽取 256-bit 隨機 KEK，與主密碼無關；之後所有登入都只「解包」同一把 KEK，不會重新產生。
- **KEK 從不明文落盤**：僅存在於記憶體（`Zeroizing<[u8;32]>`），上鎖／閒置自動上鎖時立即清零。
- **多槽位包裝（header 明文區）**：每個解鎖方式各自把同一份 KEK 用 AES-256-GCM 包一次，存於 header JSON：
  - 密碼槽：`Argon2id(pw, salt32B)`（t=3 / m=19456 KiB / p=4）→ 包裝金流 → 解出 KEK
  - FIDO2 槽：CTAP2 hmac-secret PRF（固定 salt `f2vlt-prf-salt-v1`）→ 32B secret → `HKDF-SHA256(salt="f2vlt-domain-v1", info="f2vlt-kek-wrap-v1")` → 包裝金流 → 解出 KEK
  - 增刪金鑰只改 header，不需重加密 payload。
- **payload（機密區）**：整個 vault JSON（entries/audit/settings）以 KEK 做 AES-256-GCM；每次寫入重新抽 12B nonce，tmp + rename 原子落盤。
- **全有或全無的存取模型**：主密碼或任一支已註冊 FIDO2 金鑰登入後，可取得所有條目的明文密碼（payload 是單一大塊 blob，無欄位級別名）。因此任何一支金鑰洩露 = 整個金庫失守；金鑰丟失或轉讓前務必先「移除金鑰」（不可逆）。
- **錯誤判別與失敗軌跡**：GCM tag 驗證失敗即視為密碼／金鑰錯誤（不洩漏 timing）；未解鎖狀態的登入失敗寫入 sidecar `vault.db.failures`（僅時間戳＋method，上限 10 筆），成功解鎖後合併進加密 audit 並刪除 sidecar。

## 安全聲明

- 離線：程式不開啟任何網路連線。
- 軌跡紀錄絕不含密碼/PIN/金流明文。
- 無復原機制（設計如此）。詳見 `docs/spec.md` §8。
