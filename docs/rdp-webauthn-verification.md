# RDP WebAuthn 手動驗證

本文件是 R1 候選版的 R2–R5 操作 checklist。2026-10-10 以 main `ab68de0` 的 Release GUI 完成部分 physical acceptance（結果見下表；證據：`docs/reports/rdp-physical-acceptance-2026-10-10.md`）；未列 PASS 者仍為 **NOT_TESTED**。自動化測試與 collector-only metadata 不構成 Console/RDP 金鑰驗收。生產 RDP 支援聲明不變。

## 證據與角色

由使用者在互動桌面操作專用金鑰，Parent Coder 彙整與裁決；無人代理不執行硬體流程。每例記錄 case ID、時間／時區、client/host/Console 角色、source SHA＋dirty diff hash、候選 EXE SHA-256、OS build、client binary/version、key 型號／韌體、GUI 同 process API/PID/SessionId、預期／實際／結果、error category、slot count 前後與下一步。

禁止記錄 PIN、主密碼、credential ID、salt、secret、KEK、payload、帳號／網域名或實際條目。分享前以 allowlist 審查。未知資料填 null/unknown，未操作填 NOT_TESTED；NOT_APPLICABLE 必須附原因。

## Automated 與 collector-only

Automated（執行結果見 development report，不能轉填 physical PASS）：純 metadata serializer、API 0/1/3/4+、未知／session 0、診斷固定欄位、錯誤文字不輸出；PS 5.1 parser、BOM、collector schema；Rust/UI/Clippy/fmt/release 結果見 development report。

Collector-only：`powershell.exe -NoProfile -NonInteractive -File scripts/collect-rdp-webauthn-environment.ps1`。只讀 OS build+UBR（任一不可取得則 null）、mstsc.exe 檔案版本、該 process PID/SessionId、WebAuthNGetApiVersionNumber、HKLM Terminal Services 的 fDisableWebAuthn；不代表實際連線 client、不代表有效政策／consent、更不代表 GUI。API 的 `measured_in=collector-process` 不可覆蓋 GUI 的 `measured_in=gui-process`。session 0 只標 noninteractive；其餘 unknown，不以 SESSIONNAME 猜測。metadata 失敗為 null，不輸出 exception 文字。

## 診斷欄位解讀

GUI capability JSON 僅允許 api_version、hmac_secret_api_supported、pid、session_id、session_kind、measured_in。 constructor 先記錄同 process metadata，然後執行既有 API v4+ guard；API 0/1/3 不會因此被放行。session 0 為 noninteractive，其餘 unknown；查詢失敗為 null，不讀 SESSIONNAME 推論。

MakeCredential/GetAssertion operation JSON 僅允許 operation、error_category、hmac_creation_confirmed、output_present、output_length、credential_match。null 表示尚未量到，不能當 false 或 PASS；output_length=32 仍須 pointer 存在及 credential-match，並成功解鎖測試 DB。operation 使用封閉 enum，不接受任意字串。只記已觀察的 metadata，原 API response 不 Debug/hex/JSON stringify。最後 foreground sample 至 FFI 呼叫之間不新增 logging；operation log 在返回後輸出。

錯誤分類只描述此次階段／錯誤種類，不能從 generic api-error 推論取消、逾時、policy deny 或 RDP 不支援；實體根因須另有非敏感證據。API≥4 與 valid-output 都不是支援裁決。

## R2：環境及 Console fixture

| Case | 操作與 PASS 條件 | Actual | Result |
|---|---|---|---|
| R2-1 | 確認 Windows client/host 角色，記 OS/client/key 精確矩陣與候選 hash；未知先停 | 未執行 | NOT_TESTED |
| R2-2 | 唯讀收集雙端 metadata；確認 redirection request、policy、resource consent。變更設定需另行使用者核准 | 未執行 | NOT_TESTED |
| R2-3 | 確認無其他 FIDO pending request；未知停止，不 force-kill | 未執行 | NOT_TESTED |
| R2-4 | 選唯一不存在的 `C:/FidoVault-RdpTest/<run-id>`，只建立專用測試 DB；本機輸入測試密碼。記 slot/hash/backup baseline | 未執行 | NOT_TESTED |
| R2-5 | Console 專用 key 註冊，hmac creation confirmed；32-byte output，slot +1，Console 解鎖成功 | 未執行 | NOT_TESTED |
| R2-6 | 同候選 GUI process 的 capability log 為門檻證據；API≥4，非 WinRM/session0 操作 | 未執行 | NOT_TESTED |

## R3：Console 舊槽 → RDP

正常關閉 Console FIDO client，把同一 key 移至連線發起端，確認 host 無另一支 key。使用已記錄 client/consent 進入互動 RDP，執行同候選於測試路徑。禁止接觸正式金庫。

| Case | PASS 條件 | Actual | Result |
|---|---|---|---|
| R3-1 | GUI 同 process API≥4；credential_match=true；output_present=true，output_length=32 | 2026-10-10 09:47 WS2 RDP（NB 發起）：API v7、local_console=false、credential_match=true、32 bytes | PASS |
| R3-2 | 同一 Console-created 舊測試槽成功解鎖同一 DB，slot count 不變 | NB Console 建立的測試 DB 複製到 WS2 後在 RDP 解鎖成功（使用者回報）；slot count 未另行讀 DB 核對 | PASS（解鎖）；slot 核對 NOT_TESTED |

API<4 保留拒絕，後續 NOT_TESTED/blocked(capability)。無有效 output 記 unsupported-output。有 output 但 AEAD 失敗立即停止，檢查 raw-salt/credential/UV 一致性，不重建舊槽。一般網站登入不是 PASS。secret 不傳出，若比較只在記憶體比較並清零、回報布林。

## R4：RDP 新槽 → RDP/Console

| Case | 操作與 PASS 條件 | Actual | Result |
|---|---|---|---|
| R4-1 | 記 test DB slot baseline，在 RDP 註冊專用 credential，正向 hmac creation confirmed、get output=32、slot 恰 +1 | 2026-10-10 18:28 WS2 RDP 新測試庫 0→1；MakeCredential HMAC confirmed → continuation owner-foreground → GetAssertion credential_match、32 bytes；RDP 未主動 activation | PASS |
| R4-2 | 上鎖後用新槽在 RDP 解鎖 | 重開後僅金鑰登入成功、假條目可見、slot 仍 1 | PASS |
| R4-3 | 正常離開 RDP，把同 key 移回 host Console；同 DB/new slot 解鎖 | WS2 host Console 未測；替代：同 DB 以一般權限複製回 NB（client）Console，以同 key 新槽解鎖成功（使用者回報，client-Console 跨機反向覆蓋） | host Console NOT_TESTED；client Console PASS |
| R4-4 | 註冊後 secret 取得失敗時 slot 不寫入；如有 key-side orphan 如實註記，不自動刪 key credential | 未執行 | NOT_TESTED |

## R5：Fail-closed 與 Console 回歸

| Case | 操作與 PASS 條件 | Actual | Result |
|---|---|---|---|
| R5-1 | 錯誤／未註冊 key：拒絕、slot 不變 | 未執行 | NOT_TESTED |
| R5-2 | 取消 PIN/UV/dialog：拒絕、slot 不變 | RDP 內 3 次取消皆 api-error 拒絕，之後登入成功、slot 仍 1 | PASS |
| R5-3 | 斷線／逾時：原已鎖定 vault 保持鎖定，無殘留成功 token/invalid slot；不宣稱有斷線即自動上鎖 | 未執行 | NOT_TESTED |
| R5-4 | redirection off/policy deny/consent拒絕，只有 client 插 key：失敗、無 mock fallback。設定變更另外核准 | 未執行 | NOT_TESTED |
| R5-5 | API<4／不支援 PRF fixture：拒絕、無新槽；缺硬體保留 NOT_TESTED，自動化不可取代 | 未執行 | NOT_TESTED |
| R5-6 | Console 正常登入、註冊、owner/Windows Security 前景行為回歸 | 未執行 | NOT_TESTED |
| R5-7 | 後測 test slot count 正確、fixture 仍可解鎖，保存非敏感 hash/backup | 未執行 | NOT_TESTED |

同一操作失敗超過三次先查根因，不反覆 UV。正式 vault 不讀寫；本輪未授權任何正式 baseline 操作。R6 由 Parent/使用者依 required gates 作 GO/NO-GO/Pending；不得因 automated/collector/API pass 宣告 RDP 支援。部署與支援文件變更需後續授權。
