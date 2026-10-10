# RDP physical acceptance — 2026-10-10

Candidate: main `ab68de0` (PR #20–#23 merged) Release GUI, `portable-fido-vault.exe` SHA-256 `7dd28a6ba3c23722b80451f1298c5f099640c9ca318b0f714157a33851c5984e`, `WebView2Loader.dll` `86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5` (Microsoft signature Valid).

Topology: connection origin Win11-NB (security key inserted there) → mstsc RDP-Tcp with WebAuthn redirection → WS2 interactive session 2. GUI started by the user from File Explorer inside the RDP session, normal privileges. Isolated test folders only; production `C:\FidoVault` untouched.

| Case | Evidence | Result |
|---|---|---|
| R3-1 | 09:47, pid 6596: `api_version=7` (gui-process), `local_console=false`, monitor `api-returned`, GetAssertion `credential_match=true`, `output_length=32` | PASS |
| R3-2 | Console-created test DB copied to WS2 unlocked in RDP (user report); slot count not separately read | PASS (unlock) / slot check NOT_TESTED |
| R4-1 | 18:28, pid 9600, new test DB: MakeCredential `hmac_creation_confirmed=true` → continuation `owner-foreground` → GetAssertion `credential_match=true`, 32 bytes; slot 0→1 (user report); monitor `api-returned` (no activation under RDP) | PASS |
| R4-2 | pid 2012: key-only login, `credential_match=true`, 32 bytes; entry visible, slot 1 (user report) | PASS |
| R4-3 | WS2 host Console: not run. Same DB copied back to Win11-NB (client) Console and unlocked with the new slot (user report) | host NOT_TESTED / client-Console reverse PASS |
| R4-4 | — | NOT_TESTED |
| R5-2 | pid 2012: three cancels → `api-error`, then successful login, slot 1 | PASS |
| R5-1 | 19:11 unregistered key → `api-error`, still locked, slot 1 (user report + log) | PASS |
| R5-3 | timeout: monitor `deadline` → `api-error`, later login OK; RDP-disconnect variant could not be run, waived by the user (not a PASS) | timeout PASS / disconnect WAIVED |
| R5-4 | main `e27b0c9`: redirection off → API v0 → GUI exits at startup, password login impossible → FAIL. Fixed in PR #25 (see `webauthn-unavailable-password-login-acceptance.md`): redirection-off PASS | FAIL on e27b0c9 / PASS with PR #25 |
| R5-5 | no API<4 / non-PRF hardware | NOT_TESTED |
| R5-6 | Console regression: c04 NB Console C1–C6 | PASS (cited) |
| R5-7 | post-test: key-only login, slot 1; pre/post fixture backups archived | PASS |

Earlier same-day failure ("檔案錯誤：存取被拒。 (os error 5)") was a folder ACL issue (folder and `vault.db` copied with administrator rights under `C:\`, users read-only), not an RDP or key problem; resolved by the user.

Known issue F2 (Console only): the second Windows Security dialog of one operation can stay behind FidoVault; accepted by the user.
