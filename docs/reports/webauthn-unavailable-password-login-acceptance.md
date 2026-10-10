# WebAuthn unavailable → master-password login — acceptance (2026-10-10)

Scope: `docs/plans/webauthn-unavailable-password-login.md`. Fixes R5-4 FAIL on main `e27b0c9` (RDP with WebAuthn redirection off → API v0 → GUI exited, password login impossible).

## Candidate
- Frozen candidate-01: manifest SHA-256 `7cd2c9d6e4ff26a04a7f63a1ed5bbdac70c6e3334c5f13e19aa7f06397a2992c`, patch `b58348b8…` (`fido2.rs`, `lib.rs`, `windows_webauthn.rs`).
- Release GUI (GNU, `real-ctap`) `portable-fido-vault.exe` SHA-256 `3b3f7367be81baab1a37c5249788f815c397b9e5241289880a3e6f7618996322`; `WebView2Loader.dll` `86545b66…` (unchanged).

## Tests and reviews
- Strict TDD: 7 new tests; 5 RED by assertion failure before the fix, 2 GREEN→GREEN behaviour locks. Full `cargo test --lib --features real-ctap` 200/200 (writer and parent re-run).
- Two independent read-only reviews (Claude Code CLI, Hermes SubAgent) on the frozen manifest: both `passed=true`, 0 security / 0 logic findings.
- Accepted non-blocking suggestions (not implemented): key operations raise the window before returning the unavailable error (a foreground failure could show the English activation error instead); the startup log prints `selected: windows-webauthn` before `key-unavailable`; no pre-click notice via `boot_info` (optional in scope); source-structure test could also assert a single `WebAuthnApiBelowV4` in the constructor.

## Physical (WS2 RDP session 2 from Win11-NB, key on NB; copy of the R4 test vault, 1 slot)
| # | Check | Evidence | Result |
|---|---|---|---|
| W1 | Redirection off → GUI starts | pid 736 `api_version=0` → WARN `key-unavailable (windows_webauthn_api_version=0, requires v4); master-password login remains available`; GUI stayed open | PASS |
| W2 | Master-password login, fake entry visible | user report | PASS |
| W3 | Key login → Traditional Chinese unavailable notice, stays locked | user report; no WebAuthn operation logged | PASS |
| W4 | Register key → same notice, slot still 1 | user report; post-test header slot count 1 | PASS |
| W5 | Redirection on → key-only login | pid 5940 API v7, `local_console=false`, `credential_match=true`, 32 bytes | PASS |
| W6 | NB local Console key-only login with the same EXE | user report | PASS |

pid 3536 (API v7, one `api-error` GetAssertion at 23:26) preceded W1 and is a cancelled/aborted attempt with redirection still on; it does not affect any result.

Unchanged: no MockBackend fallback, API v4+ requirement and HMAC/PRF/credential-match/32-byte checks, other backend construction errors remain fatal.
