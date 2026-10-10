# PR #23 Console WebAuthn foreground — verification and acceptance

Date: 2026-10-10 (Asia/Taipei). Scope: `docs/plans/console-webauthn-foreground.md`.

## Source and candidates

| Candidate | Change | Automated | Review | Win11-NB Console |
|---|---|---|---|---|
| c02 | LE-03 final COMMITTED CAS for activation vs API-return/cancel | lib 184/184 | 2 independent reviews passed | C2 FAIL: monitor never prepared (`baseline-window-snapshot-failed stage=window-identity`) |
| c03 | Baseline keeps session-unreadable windows (e.g. `dwm.exe`, `ProcessIdToSessionId` = ERROR_ACCESS_DENIED) as `(hwnd,pid,tid)` instead of failing | lib 188/188 | 2 independent reviews passed | C2 FAIL: monitor `stop_reason=incomplete` |
| c04 | Visible `Credential Dialog Xaml Host` with an empty caption (broker shows it untitled for 60–110 ms) is `Pending`: first scan keeps polling; any later rescan in the same round → `Ambiguous`; real query failures stay `Incomplete`. Test-only sync fix for `terminal_transition_is_serialized_with_accepted_publication` | lib 193/193 ×3 | 2 independent reviews passed | Accepted (below) |

Root causes were confirmed with read-only probes run by the user in the Win11-NB Console session (no window titles recorded):
- 148 top-level windows, exactly one session-query failure: hidden `dwm.exe` window, error 5.
- Six broker dialogs observed: each visible with `title_len=0` for 60–110 ms, then `Windows 安全性` (11 chars) from `C:\Windows\System32\CredentialUIBroker.exe`, same session; no class/identity/session/image-path failures.

c04 release artifact (GNU, `--release --locked --features real-ctap`): `portable-fido-vault.exe` SHA-256 `7dd28a6ba3c23722b80451f1298c5f099640c9ca318b0f714157a33851c5984e`; `WebView2Loader.dll` `86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5` (Microsoft signature Valid). Staged on Win11-NB in an isolated test directory; the production `C:\FidoVault` was not touched.

## Physical acceptance (user-reported, 2026-10-10)

| Item | Result |
|---|---|
| C1 new test vault + dummy entry | PASS |
| C2/C3 registration, maximized, both ceremonies, slot 0→1 | PASS (functional) |
| C4 key-only login after restart | PASS |
| C5 non-maximized key login | PASS |
| C6 cancel at prompt | PASS |
| First Windows Security dialog in foreground | PASS |
| Second dialog (fingerprint/touch) in foreground | FAIL — accepted as known issue F2 |
| Win11-NB → RDP → WS2: password login, existing-key login | PASS (user report; GUI log API v7, `local_console=false`, monitor passive `api-returned`, credential match, 32-byte output) |

GUI diagnostics for the Console run: every operation `prepared ... baseline_unattributed=1 baseline_attempts=1`; registration continuation `outcome=owner-foreground` followed by successful GetAssertion (credential match, 32 bytes).

## Known issues and decisions

- **F2** — second Windows Security dialog of one operation can stay behind FidoVault. Fix would need multiple activations per operation (outside the one-shot authorization). User decision: not fixed; does not block use.
- **Folder permissions when copying to another PC** — if the folder/`vault.db` is copied with administrator rights into a location where normal users only have read access (e.g. a new folder under `C:\`), saving fails with `檔案錯誤：存取被拒。 (os error 5)` for both password and key login (decryption succeeds; replacing `vault.db` is denied and `vault.db.tmp` remains). User decision: document the copy procedure; no code change.
- **Moving data back** between PCs is a manual user task; the program does not synchronize copies, and the same `vault.db` must not be opened from two machines at once.
- RDP registration of a new key was not part of this acceptance.
