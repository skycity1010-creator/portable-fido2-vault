# 可攜式 FIDO2 密碼金庫（portable-fido2-vault）v0.1

Windows 桌面、**完全離線**、**portable 免安裝**的 FIDO2 密碼金庫。
可攜資料夾須包含 `portable-fido-vault.exe`、同版 x64 `WebView2Loader.dll` 與既有 `vault.db`；目標電腦另須具備 WebView2 Runtime，硬體版 GUI 需 Windows WebAuthn API v4+。**免安裝本程式，不代表目標電腦不需要系統執行環境。**

- 首次執行建立帳號：主密碼經 **Argon2id** 派生金鑰
- 之後**主密碼或任一支已註冊 FIDO2 金鑰**皆可登入（允許多支）
- 金鑰類型自動偵測：**指紋型 / PIN 型 / touch-only**，登入時依類型給提示
- **僅接受支援 CTAP2 hmac-secret/PRF 的金鑰**（如 YubiKey 5+）；不支援者拒絕註冊並顯示原因 → 所有已註冊金鑰皆可單獨解鎖金庫
- 加密：Argon2id + **AES-256-GCM**，整個金庫加密為單一檔案 `vault.db`
- CRUD ＋ created_at/updated_at ＋ 軌跡紀錄（絕不明文記錄密碼）＋ 閒置自動上鎖
- 每筆條目可保留 **1–20 代舊密碼**（預設 3）；修改密碼時自動保存舊值，可查看日期並還原
- 條目分頁支援即時搜尋網站、帳號及備註；不搜尋目前或舊密碼
- 每筆條目可複製目前密碼；60 秒後僅在剪貼簿內容仍相同時嘗試清除
- 主視窗每次啟動預設最大化；金鑰登入期間不會意外還原成一般視窗；保留標題列及還原／調整大小功能，不進入全螢幕
- 安全性金鑰可在註冊時設定 FidoVault 本機別名；名稱以明文存於 vault header，請勿輸入敏感資料
- 本機 Console 金鑰操作時，第一個 Windows 安全性視窗會盡力拉到前景（已知：同一操作的第二個視窗可能仍在背景）
- 支援在已實測矩陣內以 RDP（WebAuthn 重新導向）使用金鑰；WebAuthn 不可用（API < v4）時程式仍可啟動並以主密碼登入，金鑰操作會說明原因並拒絕
- 單人版另可在本機 Console 註冊 **Windows Hello**（需 WebAuthn API v8+ 與 PRF；RDP 不提供）作為另一種解鎖方式
- 金鑰／Windows Hello 驗證在背景執行緒進行，期間 UI 不凍結；驗證途中按「上鎖」或閒置上鎖時，該次登入結果一律丟棄並提示重新登入
- 另有**雙群組控管版**（`portable-fido-vault-dual.exe`）：金鑰登入須 A、B 群組各一支依序驗證，見下方專節
- ⚠️ **無復原機制**：主密碼遺忘且所有 FIDO2 金鑰全失 = 資料永久無法取回

## 目前狀態（2026-10-17）

- `main` 已包含 PR #2–#30；最新 merge commit `fe520ae`（PR #30：單人版 Windows Hello、WebAuthn 驗證移出 UI 執行緒、lock-overlap Case B 診斷探針）。PR #29（雙群組控管版）已於 2026-10-12 合併。
- **正式部署（Win11-NB，2026-10-17）**：由 `fe520ae` 建置（GNU Release，`real-ctap`；不含 `lock-overlap-diag`），只替換 EXE、未動 `vault.db`，部署前 EXE 與 DB 已備份至 `C:\FidoVault\backups\pr30-fe520ae-20261017`；部署後使用者回報可正常登入。

  | 位置 | 版本 | SHA-256 |
  |---|---|---|
  | `C:\FidoVault\portable-fido-vault.exe` | 單人版 | `10ca994cfb6195163c8f8ce522367061b0b6e54599a81092160b0429102e9887` |
  | `C:\FidoVault\dual\portable-fido-vault-dual.exe` | 雙群組控管版 | `b0ad4856cd68d653c90134111df85347a4d52a1cbecf2ecd77f642b92231bf8d` |
  | 兩資料夾的 `WebView2Loader.dll` | x64 載入器（Microsoft 簽章） | `86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5` |

- **自動化驗證（GitHub Actions，Windows，`fe520ae` main run `39002784117`）**：UI 155/155、Python Gate 診斷 7/7、Rust `real-ctap` 549/549、`real-ctap,dual-control` 549/549、`real-ctap,lock-overlap-diag` 585 通過＋1 ignored、dual＋diag 診斷模組 19 通過＋1 ignored、Windows Hello mock CLI 診斷 4/4、mock Gate 單人 20/20、Windows Hello 10 cases／31 checks、雙群組 25/25。
- **實機驗收（使用者回報，非 assistant 操作硬體）**：
  - 單人版 Windows Hello C1–C5（SKYCITY-PC 本機 Console，臉部辨識）、YubiKey Y1–Y4／T1–T3（SKYCITY-PC Console）、YubiKey N1–N4（Win11-NB Console）、RDP R1–R8（SKYCITY-PC → WS2）皆 PASS；R9-1 自動逾時 **WAIVED**（使用者同意略過，非 PASS）。以上驗收對象為候選 `cde4e24`（PR #30 合併前版本），未在 `fe520ae` 正式版重跑。
  - lock-overlap Case B（金庫已解開、結果尚未顯示時收到上鎖）以診斷版在 WS2 本機 Console、YubiKey Bio 指紋 PASS：登入結果被丟棄並顯示上鎖訊息，下一次登入正常。
  - 雙群組控管版 D13：Win11-NB 本機 Console、兩支 YubiKey Bio，V1–V11 PASS；V12 軌跡紀錄排序問題修正後於最新候選補驗通過；V13（單人版版本互斥實機選測）**NOT_TESTED**。
- **已知未處理（2026-10-17 決定暫不處理）**：新金庫寫入偶發 `os error 5`（推測防毒／索引短暫占用，未確認）、7 項既有 Clippy lint、Symlink 權限測試（OS 1314）、Case A（Windows 驗證進行中收到上鎖）未實機驗證；Win11-NB（TPM 1.2）於 S0 spike 時 PRF assertion 不可用，Windows Hello 註冊在該機會 fail closed。
- 細節與證據：`docs/plans/windows-hello-single.md`（§13 D9-F2、§14 Case B）、`docs/plans/dual-control.md`、`docs/PROJECT.md`、`docs/rdp-webauthn-verification.md`。`docs/PROJECT.md` 與計畫檔中部分 D9／D13 段落仍保留合併前的「未驗收」字樣，以本節為最新狀態。

## 目錄結構

```
portable-fido2-vault/
├─ README.md            ← 本檔
├─ docs/spec.md         ← 技術規格（架構、金庫格式、FIDO2 偵測流程）
├─ docs/plans/          ← 各功能設計／決策與驗證紀錄（windows-hello-single.md、dual-control.md…）
├─ src/                 ← 前端（純靜態 HTML/JS/CSS，繁中 UI）
├─ tests/               ← UI 測試（node --test）與 Windows Hello Gate 診斷 Python 測試
├─ scripts/             ← mock Gate E2E（gate_e2e*.py）與 Win11-NB 部署／診斷輔助
└─ src-tauri/           ← Tauri v2 (Rust) 後端
   ├─ src/vault.rs      金庫格式 / 加密落盤
   ├─ src/crypto.rs     Argon2id / AES-GCM / HKDF
   ├─ src/fido2.rs      FIDO2 後端 trait + Mock/Real
   ├─ src/windows_webauthn.rs  Windows WebAuthn（外接金鑰與 Windows Hello 平台驗證器）
   ├─ src/registration_cleanup_journal.rs  Windows Hello 註冊失敗清理收據
   ├─ src/edition.rs    版本判斷（single / dual，依 Cargo feature `dual-control`）
   ├─ src/lock_overlap_diag.rs  Case B 診斷探針（feature `lock-overlap-diag`，預設關閉，不隨正式版發佈）
   ├─ src/bin/portable-fido-vault-dual.rs  雙群組控管版 GUI 入口（需 `dual-control`）
   ├─ examples/vault_cli.rs       E2E 測試 CLI（單人版 Gate 驗證用）
   ├─ examples/windows_hello_gate_cli.rs  Windows Hello mock Gate CLI（僅供測試，不可發佈）
   └─ examples/dual_vault_cli.rs  雙群組控管版 mock E2E CLI（僅供測試，不可發佈）
```

## 建置（WS2 建置機）

前置：
- Rust stable + **GNU toolchain**（`rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal`；本機無 MSVC/VS，走 GNU 免 UAC）。
- **dlltool.exe**（Rust GNU toolchain 不自帶 binutils）：下載 [winlibs-mingw](https://github.com/brechtsanders/winlibs_mingw/releases) x86_64-posix-seh zip，把其 `bin/` 加進 PATH。
- WebView2 Runtime（建置機與目標電腦均需確認）；Windows 11 通常已具備，仍不可跳過檢查。GUI 打包時另須帶上同次建置輸出的 x64 `WebView2Loader.dll`。[1]

```bash
# bash / git-bash（WS2）
export PATH="$HOME/.cargo/bin:$HOME/tools/winlibs-mingw/mingw64/bin:$PATH"
cd D:/project/portable-fido2-vault/src-tauri
cargo +stable-x86_64-pc-windows-gnu build --release --locked --features real-ctap --bin portable-fido-vault
# 產出硬體版 GUI；打包須取 target/release/portable-fido-vault.exe 及同目錄 WebView2Loader.dll
```

Windows Release GUI（`real-ctap`）從檔案總管啟動時使用 Windows WebAuthn API；PIN、指紋與觸碰提示由 Windows 安全性視窗處理，無需設定 `F2V_AUTHENTICATOR` 或以系統管理員身分啟動。目標系統需提供 WebAuthn API v4 或更新版本。Debug 建置仍預設 MockBackend；若需在 Release 明確執行 mock 測試，可設定 `F2V_AUTHENTICATOR=mock`。未設定覆寫值且 Release 缺少 `real-ctap` 時會拒絕啟動。`vault_cli --authenticator hw` 保留 raw CTAP/HID 診斷路徑，與 GUI 使用的 Windows API 不同。

### RDP 遠端桌面使用範圍

**支援（R6 GO，2026-10-10）——僅限已實測矩陣：**連線發起端 Win11-NB（Windows 11 24H2 build 26100.9457，mstsc 10.0.26100.8875，金鑰插此端）→ RDP（mstsc 啟用 WebAuthn 重新導向）→ 目標 WS2（Windows Server 2025 Standard 24H2 build 26100.33438，RDP session 回報 WebAuthn API v7）；金鑰 YubiKey Bio（USB PID 0402，推定韌體 5.7.2）；FidoVault Release GUI（PR #25 起，含 WebAuthn 不可用時保留主密碼登入）。矩陣外的 OS、RDP 用戶端、金鑰型號、巢狀 RDP、RemoteApp 不在支援範圍。完整裁決與殘餘風險見 `docs/rdp-webauthn-verification.md` 的 R6。

已實測可用（2026-10-10）：在 Win11-NB 本機 Console 建立金庫並註冊金鑰後，把整個 FidoVault 資料夾複製到 WS2，再從 Win11-NB 以 RDP 連到 WS2，在 WS2 的 RDP session 內以**同一主密碼**或**插在 Win11-NB 上的已註冊金鑰**登入。RDP 下金鑰驗證經 Windows WebAuthn redirection 轉送到連線發起端，Windows 安全性提示依 Windows 預設通常顯示在發起端本機畫面；FidoVault 在 RDP 下不主動拉提示到前景。硬體 GUI 仍要求同一 process 回報 WebAuthn API v4+（WS2 RDP 實測 v7）；版本不足會 fail closed。

2026-10-10 亦實測：在 WS2 的 RDP session 中建立新測試金庫並註冊插在 Win11-NB 的金鑰（兩段 ceremony、槽數 0→1），之後在 RDP 以新槽解鎖，並把資料夾複製回 Win11-NB 本機 Console 以同一金鑰解鎖成功。若 RDP 未開啟 WebAuthn 重新導向（或 Windows WebAuthn API 低於 v4），程式仍會啟動、主密碼登入照常可用，金鑰登入／註冊會顯示「此 session 無法使用安全金鑰」的說明（2026-10-10 WS2 RDP 實測）。未驗收：WS2 本機 Console 解鎖、RDP 斷線中的金鑰操作（使用者豁免）、群組原則停用 WebAuthn／拒絕資源同意、API 低於 v4 或不支援 PRF 的金鑰（見 `docs/rdp-webauthn-verification.md`）。WinRM／session 0 不可操作 GUI 或金鑰。

> portable 部署必須一起攜帶 GUI EXE 與同版 `WebView2Loader.dll`；搬移既有金庫時，還須攜帶 EXE 同目錄的 `vault.db`。首次建立新金庫才會產生 DB；搬移舊金庫**不得刪除或重建 DB**。完整檔案清單與目標環境見下方部署說明。
>
> **複製到另一台電腦時請用一般權限**，放在自己有修改權限的位置（例如 `D:\FidoVault`、使用者資料夾底下）。若以系統管理員權限複製到 `C:\` 底下的新資料夾，一般權限執行的 FidoVault 無法覆寫 `vault.db`，登入時會出現「檔案錯誤：存取被拒。 (os error 5)」（密碼／金鑰本身正確，存檔被拒並留下 `vault.db.tmp`）；改放可寫位置或補上自己的修改權限即可。程式不會在兩台電腦間同步金庫：資料要回到另一台時請自行複製整個資料夾，且同一份 `vault.db` 不可同時由兩台開啟。

## 使用流程

1. **首次執行**：輸入主密碼（兩次）→ 建立 `vault.db` → 可順手註冊 FIDO2 金鑰。
2. **登入**：主密碼，或在 Windows Release 硬體模式按單一「以金鑰登入」入口；Windows 安全性視窗負責選擇／驗證已註冊的金鑰及 PIN/UV/觸碰，不必先在 App 點選特定金鑰。非 brokered 的 Mock/raw-CTAP 模式仍使用逐支選擇與 PIN 欄位。
3. **條目**：新增/編輯/刪除（網站、帳號、密碼、備註），自動記 created_at/updated_at。可在條目分頁即時依網站、帳號或備註作不分大小寫的部分搜尋；搜尋只篩選記憶體中已載入的條目，不比對密碼欄位。實際更改密碼時會保留舊版本；編輯時可查看日期並還原舊密碼。列表可複製目前密碼；60 秒後若剪貼簿文字仍是該密碼才清除，期間被其他內容取代則保留新內容。
4. **金鑰管理**：註冊新金鑰時先設定 FidoVault 本機別名，確認後才偵測類型並進行驗證；可移除金鑰（不可逆，需確認）。別名只供本機辨識，存於明文 header，請勿輸入敏感資料。
5. **軌跡紀錄**：登入成功/失敗、金鑰註冊/移除、條目增刪改＋時間（不含任何密碼明文）。
6. **設定**：閒置自動上鎖分鐘數（預設 5）；舊密碼保留代數（1–20，預設 3）。降低保留數時會立即刪除每筆條目最舊的超額版本。

## Windows WebAuthn 與安全性提示焦點

Windows Release 硬體模式以單一通用「以金鑰登入」入口呼叫 Windows WebAuthn；金鑰選擇、PIN/UV 與觸碰由 Windows 安全性提示處理。操作期間，程式會對唯一的新同 session 安全性 broker 視窗做一次受限的前景請求，但只有在 FidoVault 仍為前景時才嘗試；不會把提示設成 topmost，也不會繞過 Windows 的全域前景政策。這是 best-effort，Windows 仍可能切換焦點。

Win11-NB 本機 Console 已確認通用登入不需先選金鑰。每次金鑰操作的第一個 Windows 安全性視窗會被拉到前景；已知問題：同一次操作的第二個視窗（按指紋／觸碰提示）仍可能被 FidoVault 擋住，直接操作金鑰即可完成，不影響使用（需同一操作多次拉前景才能修正，目前未授權）。Windows WebAuthn API v4+ 仍是硬體 GUI 的必要條件；較舊 API 版本會 fail closed。

## 單人版 Windows Hello（本機 Console）

Windows Hello 是單人版的本機平台憑證，和外接 YubiKey 是兩種不同的解鎖方式。可用性檢查要求 Windows WebAuthn API v8+、Windows Hello 平台驗證器可用，且程式在本機 Console 執行；RDP／WinRM／session 0 不提供此功能。外接 FIDO2 金鑰既有的 API v4+ 與 RDP 支援範圍，不能套用到 Windows Hello。

註冊時 Windows 會進行建立及 PRF assertion 驗證；只有 assertion 回傳預期憑證及 32-byte PRF 後才新增金庫槽位。若建立成功但 PRF 驗證失敗，金庫不新增槽位，程式會嘗試清理 Windows 憑證；清理也失敗時可能留下 Windows 端的測試憑證。主密碼和已註冊的 YubiKey 仍是備援解鎖方式。

Windows Hello 使用 Windows platform authenticator；此功能範圍限 Windows 本機儲存的 credential，第三方／同步型 passkey manager 不支援。**目前 backend 使用 v8 options，只要求 PLATFORM attachment；未呼叫 v9 `WebAuthNGetAuthenticatorList`／傳入 authenticator ID 來鎖定特定 provider。**Microsoft API v9 提供指定 authenticator 的能力，但 FidoVault 尚未實作；Windows 的 provider 選擇不是程式可保證的設定。credential 不存放於 `vault.db`，因此複製金庫檔案本身不會匯出該 credential。執行驗收前須在「設定 → 帳戶 → 通行金鑰 → 進階選項」確認使用「儲存到這部 Windows 裝置」的本機 provider；若 provider 為第三方同步服務或狀態不明，停止並標記超出範圍／未測，不要改同步設定。從 Windows 11 24H2 起，應用程式存取 passkeys 前可能出現 privacy-consent 提示；若出現，記錄實際選擇與結果。只有在專用測試機且經使用者／管理員核准時才允許本測試程式使用 passkeys；不要變更組織政策或全域設定。若未授權或被拒絕，將該次驗收標記為「受同意設定阻擋／未測」，不可誤報成 PRF 不支援。

已合併（PR #30）並隨 2026-10-17 單人版正式部署。實機驗收為 SKYCITY-PC 本機 Console（C1–C5，使用者回報 PASS）；Win11-NB 於 S0 spike 時 PRF assertion 不可用，註冊會 fail closed，屬平台限制。自動化 mock Gate 為 10 cases／31 checks，不代表 Windows Settings 清理結果。

註冊第二階段（PRF 驗證）若因 Windows 未把前景交回 FidoVault 而被拒，程式會保留這次註冊並顯示「繼續驗證／取消」：按「繼續驗證」讓 FidoVault 回到前景後再進行驗證，不會主動搶焦點。

## portable 部署到別台電腦（含 Win11-NB）

### 必須一起複製的檔案

現行 Windows GUI 為 x64；既有金庫搬移時，以下三個檔案須放在**同一層資料夾**：

```text
FidoVault\
├─ portable-fido-vault.exe   GUI 主程式（Release + real-ctap）
├─ WebView2Loader.dll        同一發行套件／同次建置的 x64 載入器
└─ vault.db                 使用者原本的加密金庫，不是新建的空白 DB
```

- `WebView2Loader.dll` 是應用程式旁的載入器，**不是 WebView2 Runtime**；安裝 Runtime 不能取代漏帶的 DLL，單獨補 DLL 也不能取代缺少的 Runtime。不要使用 x86/ARM64 DLL，或從不明 DLL 下載網站取檔。[1]
- `vault_cli.exe` 是選用診斷工具，不是 GUI 啟動必備檔。若有 `vault.db.failures`，為保留尚未合併的失敗登入軌跡，請在程式關閉後一併備份／複製。
- 舊備份與診斷紀錄不是最小啟動清單的一部分，但**不得據此刪除原資料夾其他檔案**。請保留原金庫及備份，勿把 DB、PIN、主密碼或未清理的診斷紀錄上傳到聊天或公開發行套件。

### 目標電腦 prerequisites

1. Windows x64，硬體版 GUI 需 Windows WebAuthn API v4+；建立金庫、註冊金鑰與登入可在目標機**本機 Console**，或在上方「RDP 遠端桌面使用範圍」的已測矩陣內於 RDP session 進行（需啟用 mstsc WebAuthn 重新導向，金鑰插在連線發起端）；不使用 WinRM 操作 GUI 或金鑰。
2. **Microsoft WebView2 Runtime** 可用。不要只因 Windows 11 或已安裝 Edge 瀏覽器就假定 Runtime 可用；若缺少，依微軟官方說明安裝 Evergreen Runtime。離線電腦可由其他電腦先下載 x64 **Evergreen Standalone Installer** 再搬入安裝；Bootstrapper 需要連網下載，不適合完全離線安裝。[1]
3. 可寫入的本機資料夾（以一般權限複製、目前使用者有修改權限；否則存檔會出現 os error 5）；需要以金鑰登入時，使用原金庫已註冊的實體安全金鑰。補啟動依賴不需要重新註冊或移除金鑰。

官方 Runtime 部署、離線安裝及隨附檔案說明與下載入口，見文末 Sources 的 Microsoft Learn 文件。[1]

### 打包程式檔案（不包含使用者 DB）

下例在 `src-tauri` 目錄執行，使用**全新**目的資料夾；若設定了 `CARGO_TARGET_DIR` 或額外的 target triple，請把 `$releaseDir` 改成該次建置的實際 Release 輸出位置。不可混用舊 EXE 與別次建置的 DLL。

```powershell
$ErrorActionPreference = 'Stop'
$releaseDir = Join-Path (Get-Location).Path 'target/release'
$packageDir = 'C:\deploy\fido-vault-portable'
$programFiles = @('portable-fido-vault.exe', 'WebView2Loader.dll')
if (Test-Path -LiteralPath $packageDir) { throw '請選擇全新資料夾，勿覆寫既有部署。' }
foreach ($name in $programFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $releaseDir $name) -PathType Leaf)) {
        throw "缺少建置輸出：$name；不要只打包 EXE。"
    }
}
New-Item -ItemType Directory -Path $packageDir | Out-Null
foreach ($name in $programFiles) {
    Copy-Item -LiteralPath (Join-Path $releaseDir $name) -Destination $packageDir
}
```

### 搬移既有金庫與啟動排錯

1. 在來源機**正常關閉** GUI／CLI，先另做金庫備份；不要強制終止正在等待 PIN/UV/觸碰的程式。
2. 將 EXE、同版 DLL、原 `vault.db`（以及存在的 `vault.db.failures`）複製至新機的全新資料夾。不要覆寫新機已有的另一份金庫；來源檔案與備份保留不動。
3. 在啟動前，以 `Get-FileHash -Algorithm SHA256` 分別核對來源與目的 EXE、DLL、DB 的雜湊相同；正常登入會寫入 audit，登入後 DB hash 改變不等於搬移損毀。
4. 確認 Runtime 與本機 Console 條件後，雙擊**新資料夾內**的 EXE，以既有主密碼或原已註冊金鑰登入；不要把搬移當成首次建立帳號。

若 Windows 提示**找不到 `WebView2Loader.dll`**，先從可信任的同版 x64 套件補到 EXE 旁，再重試；**不要刪除、覆寫或重建 `vault.db`**。若 DLL 已補齊但仍提示 Runtime 不可用，再處理 Runtime 安裝。若搬移既有 DB 後卻顯示「首次執行／建立帳號」，立即停止，檢查啟動的 EXE 路徑及其同目錄的 `vault.db`，不要建立空白金庫來排錯。

驗證範圍：mock Gate 8、PE imports／DLL 架構或載入檢查，都不等同實體 GUI 跨電腦啟動／金鑰解鎖 PASS。實體 GUI 跨機已有人工 PASS（2026-10-10，專用測試金庫）：Win11-NB 本機 Console 建立的測試金庫以一般權限複製到 WS2，在 RDP session 以同一主密碼與同一把金鑰解鎖；WS2 RDP 建立的測試金庫複製回 Win11-NB 本機 Console 以同一金鑰解鎖。正式金庫未做跨機搬移。詳見 `docs/reports/rdp-physical-acceptance-2026-10-10.md`。

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

CI（`.github/workflows/ci.yml`，PR 與 `main` push 觸發）依序執行：`node --test`、Windows Hello Gate 診斷 Python 測試、Rust `real-ctap`／`real-ctap,dual-control`／`real-ctap,lock-overlap-diag` 全套、dual＋diag 的 `lock_overlap_diag::` 模組、三個 mock Gate（`gate_e2e.py`、`gate_e2e_windows_hello.py --case all`、`gate_e2e_dual.py`）。本機重現：

```bash
cd src-tauri
cargo test --lib --locked --features real-ctap
cargo test --lib --locked --features real-ctap,lock-overlap-diag -- --test-threads=1   # fixture 根目錄須為長路徑（非 8.3 短檔名）
cargo build --release --locked --example windows_hello_gate_cli
python ../scripts/gate_e2e_windows_hello.py <全新資料夾> --cli ./target/release/examples/windows_hello_gate_cli.exe --case all
```

### lock-overlap Case B 診斷版（僅開發驗證，不可發佈）

Cargo feature `lock-overlap-diag`（預設關閉）可編出用來實機驗證「金庫已解開、登入結果尚未顯示時收到上鎖」的診斷版。只有同時符合以下條件才會啟用一次，否則以結束碼 78 拒絕啟動且不碰金庫：命令列 `--lock-overlap-diag-case-b`、執行檔名 `fidovault-lock-overlap-diag.exe`、所在資料夾名稱 `lock-overlap-diag-*`、固定內容的 marker 檔、既有 `vault.db`、本機磁碟長路徑（非 UNC／reparse／8.3 短檔名，且路徑中沒有名為 `FidoVault` 的資料夾）、硬體 backend 與單人版。結果寫入不含秘密的收據。**正式版建置不得加此 feature**，也不要對正式金庫使用；細節見 `docs/plans/windows-hello-single.md` §14。

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

## 雙群組控管版（dual-control）

> 狀態：PR #29 已合併；Win11-NB 本機 Console 實機驗收 D13（兩支 YubiKey Bio）V1–V11 使用者回報 PASS、V12 修正後補驗通過，V13 NOT_TESTED。正式版部署於 Win11-NB `C:\FidoVault\dual`（2026-10-17 更新為 `fe520ae`）。設計與決策紀錄見 `docs/plans/dual-control.md`，格式見 `docs/spec.md` §3.1。

同一份程式碼以 Cargo feature `dual-control` 另外編出 `portable-fido-vault-dual.exe`。單人版 `portable-fido-vault.exe` 的行為、檔案格式與 UI 不變。

- **金鑰登入需兩人**：註冊金鑰時必須指定 **A 群組**或 **B 群組**（必選、註冊後不可修改）。金鑰登入必須 A 群組一支 + B 群組一支依序驗證；先 A 或先 B 皆可，第二步只接受另一群組的金鑰。
- **在密碼學層強制**：A 群組金鑰只能解出 `share_A`，B 群組只能解出 `share_B`，兩者經 HKDF 合併後才能解開 KEK。只持有 `vault.db` 與單一群組的金鑰（不論幾支），改用 CLI 或修改程式也無法解鎖。
- **第二步時限**：第一步通過後，另一群組須在時限內完成（預設 120 秒，設定頁可調 30–600 秒）。逾時、取消、第二步失敗、改用主密碼都會清除第一步結果，需從第一步重新開始；第一步取得的 share 只存在 Rust 端記憶體，不經 IPC 交給前端。
- **主密碼是緊急用（break-glass）**：主密碼單獨即可完整解鎖（刻意接受的繞道，主密碼由組織人工分持保管）。以主密碼登入後主畫面顯示醒目提示，軌跡紀錄 method=`password-breakglass`。
- **同一支實體金鑰只能註冊一次**：註冊時把金庫內全部 credential 放入 excludeCredentials，同一支金鑰再註冊（不論選 A 或 B）會被金鑰本身拒絕，顯示「此安全性金鑰已註冊於本金庫…」。此限制依賴金鑰遵守 CTAP2 excludeList（見設計 §7 R6）。
- **群組最後一支金鑰不可刪除**（Rust 層強制，UI 也停用按鈕）。A、B 群組各至少一支金鑰之前，只能以主密碼登入。
- **版本互斥**：雙群組控管版只開 v2 金庫，單人版只開 v1 金庫；開錯版本會顯示應改用哪個程式，且不解密、不寫檔。**不提供 v1↔v2 轉換**，要使用雙群組控管版請建立新金庫。`vault_cli` 不支援 v2。

### 建置與打包（雙群組控管版）

```bash
cd src-tauri
cargo +stable-x86_64-pc-windows-gnu build --release --locked --features real-ctap,dual-control --bin portable-fido-vault-dual
# 打包取 target/release/portable-fido-vault-dual.exe 與同目錄 WebView2Loader.dll
```

- 啟用 `dual-control` 時一定要加 `--bin portable-fido-vault-dual`：單人版 bin 在此 feature 下會以 `compile_error!` 拒絕編譯，避免單人版檔名的 EXE 混入雙人版邏輯；反之 dual bin 沒有 feature 時 Cargo 會拒絕建置。
- 發行資料夾只放 `portable-fido-vault-dual.exe`、同次建置的 x64 `WebView2Loader.dll`，以及第一次啟動後產生的 `vault.db`。**`target/*/examples/` 下的 `vault_cli.exe`、`dual_vault_cli.exe` 都不得隨雙群組控管版發佈**：`dual_vault_cli` 是以 mock 金鑰模擬的測試工具；`vault_cli` 不支援 v2。
- 雙人版與單人版請放在**不同資料夾**（各自旁邊的 `vault.db` 版本不同）。不要把雙人版 EXE 放進既有 `C:\FidoVault` 對著正式單人版金庫啟動；版本互斥會拒絕開啟，但仍不應以正式金庫測試。
- 測試：`cargo test --lib --locked --features real-ctap,dual-control`；mock E2E：`cargo build --release --locked --features dual-control --example dual_vault_cli` 後執行 `python ../scripts/gate_e2e_dual.py <全新資料夾> --dual-cli <dual_vault_cli.exe> --single-cli <vault_cli.exe>`（腳本拒絕既有資料夾、不刪檔）。

## 安全聲明

- 離線：程式不開啟任何網路連線。
- 軌跡紀錄、複製成功/失敗提示與 app 診斷 log 絕不含密碼/PIN/金流明文。複製時密碼會暫存在系統共用剪貼簿；60 秒自動清除僅在內容仍相同時執行。其他桌面程式或 Windows 剪貼簿歷程/雲端剪貼簿可能在此期間讀取、保存或同步內容；清除不會刪除已保存的歷程項目。
- 無復原機制（設計如此）。詳見 `docs/spec.md` §8。

Sources:
[1] https://learn.microsoft.com/zh-tw/microsoft-edge/webview2/concepts/distribution — Microsoft Learn: Distribute WebView2 applications and Runtime
