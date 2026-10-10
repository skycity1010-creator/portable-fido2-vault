# Win11-NB Console WebAuthn prompt foreground — scope

Date: 2026-10-08
Authorization source: Discord message `1557735129781116929`.
Base: PR #22 head `7f2daefda37bf69c7e102fbec5aced917a69107b`; stacked branch `fix/console-webauthn-foreground-20261008`, PR base remains `fix/rdp-passive-foreground-20261007`.

## Goal

Repair the reported case where the Windows Security/security-key operation prompt is behind FidoVault when the candidate is run on Win11-NB's local Console. Preserve the successful unlock report separately from foreground acceptance. Do not claim the physical issue is fixed until the user verifies the rebuilt candidate on that local Console.

## Evidence and limits

- User reported R4-3 unlock PASS on Win11-NB Console and that the key-operation prompt was obscured by the FidoVault main window.
- A prior read-only record for the same candidate EXE bytes (`BF8D737571D91E4CDEBAC133088D97AE05C0307FFFCFB82929D52C6975F6239F`) reports API 9, successful GetAssertion, 32-byte output and credential match, with the owner foreground immediately before the API. It found no monitor-prepared or monitor-stop record for that PID. That record refers to the then-current `C:\FidoVault-RdpTest\R4` path; it does not prove the historical process path/session for the latest report or the prompt's HWND/owner/z-order.
- The prior record labels root cause NOT_CONFIRMED. Current source has early monitor-preparation exits, including a complete baseline-window identity capture failure before the prepared log. This is a falsifiable hypothesis, not an established cause.
- Microsoft documents that `SetForegroundWindow` is restricted and can be denied; the handoff remains best-effort. Do not substitute topmost, `ASFW_ANY`, `AttachThreadInput`, or broad focus retries.

## Investigation and acceptance

1. Trace the exact Win11 Console `GetAssertion` and `MakeCredential` monitor preparation, candidate selection, and stop reasons. Make missing/failed initialization stages observable with closed, privacy-safe categories; do not log arbitrary window titles, unrelated process paths, credential data, raw CTAP, PINs, secrets, or vault contents.
2. Use strict vertical TDD for any behavior change. A complete window baseline must continue to include all top-level windows (including hidden windows). Identify a candidate by a fresh full window identity; do not require the broker process itself to be new, because `CredentialUIBroker.exe` may already be running. If a bounded retry is added, retry only a complete baseline capture; never skip unknown windows or treat an incomplete sample as absence. Persistent failure remains fail-closed and must not silently masquerade as a prepared monitor.
3. The user explicitly authorized one-shot, narrow, best-effort broker foregrounding after reviewing the temporal-correlation limitation. This is not a platform-provided operation-to-HWND binding. Keep the complete hidden-inclusive baseline; accept only one full-identity-new, visible, same-session dialog from the trusted System32 `CredentialUIBroker.exe`, with the observed `Credential Dialog Xaml Host` class and Windows Security title. A new dialog HWND in a broker PID already present in the baseline is eligible; process novelty is not required. Before activation, revalidate candidate uniqueness, identity and visibility, and require the live FidoVault owner to remain foreground with no cancellation/focus change. The activation boundary must recheck candidate identity/visibility and owner foreground immediately before the single `SetForegroundWindow` attempt. Activation is allowed only when the current session is positively identified as local Console; RDP remains passive and must never activate the candidate. Continuation may proceed only if the owner is already foreground or naturally returns to foreground; never restore or activate the owner. Any ambiguity, incomplete observation, identity drift, user focus change, cancellation, API return, non-Console activation request, or failed activation terminates the attempt without retry or activation of another window. Do not use topmost, `ASFW_ANY`, `AttachThreadInput`, or broad owner activation. Windows focus can still race between native checks and the OS call, so this remains a best-effort mitigation requiring local visual acceptance, not a universal guarantee.
4. Keep API v4+, HMAC/PRF, credential-match, output-length, persistence, owner-identity, maximized-window, cancellation, and RDP passive-continuation guards unchanged unless a separately tested minimal change is required by this scope.
5. Run focused RED/GREEN tests, required Rust/lint/format checks, source/artifact provenance, and independent completed-code review. A Release candidate may be built only in a unique scratch directory and must be labeled non-deployable pending local Console acceptance. Keep PR #23 Draft and unmerged.
6. Do not operate the GUI or authenticator through WinRM/RDP; do not access/copy/hash/write vault or key data, alter machine policy/environment, or stage over an existing installation. The user runs the scratch candidate in the local Console using an isolated test vault. Require visual confirmation that the prompt is foreground, unobscured and operable, plus separate successful existing-key `GetAssertion` and test-vault `MakeCredential`/registration flows before calling the issue fixed. Automated checks and the user-authorized best-effort monitor do not replace that physical acceptance.

## Completion state

Automated tests/review establish source behavior only. The authorized monitor uses a tightly constrained temporal association and remains best-effort; it is not an OS-provided operation binding.

Accepted 2026-10-10 by the user (closeout authorized) with candidate-04 (`portable-fido-vault.exe` SHA-256 `7dd28a6ba3c23722b80451f1298c5f099640c9ca318b0f714157a33851c5984e`); evidence in `docs/reports/console-webauthn-foreground-acceptance.md`:

- Win11-NB local Console C1–C6 functional flows: PASS (test vault, registration 0→1 with both ceremonies, key-only login, non-maximized login, cancel).
- First Windows Security dialog of each operation is brought to the foreground: PASS.
- Known issue F2 (accepted, not fixed): the second Windows Security dialog of the same operation (fingerprint/touch prompt) can still appear behind FidoVault. Operating the key directly still completes the operation. Fixing it would require more than one activation per operation, which is outside the one-shot authorization; the user chose not to authorize it.
- Win11-NB → RDP → WS2 session: password and existing-key login reported working by the user after correcting folder permissions; GUI log shows API v7 via WebAuthn redirection, `local_console=false`, monitor `api-returned` (passive, no activation), `credential_match=true`, 32-byte output. RDP registration of a new key was not part of this acceptance.
