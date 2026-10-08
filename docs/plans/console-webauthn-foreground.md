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
2. Use strict vertical TDD for any behavior change. A complete baseline must continue to include all top-level windows (including hidden windows) and existing broker process IDs. If a bounded retry is added, retry only a complete baseline capture; never skip unknown windows or treat an incomplete sample as absence. Persistent failure remains fail-closed and must not silently masquerade as a prepared monitor.
3. Preserve exact broker restrictions: unique newly created visible `CredentialUIBroker.exe` from the Windows System32 directory, same session, expected class/title, identity revalidation, and FidoVault still foreground immediately before one activation attempt. If the user has changed focus, stop. No owner mutation, topmost, `ASFW_ANY`, `AttachThreadInput`, or unbounded/periodic activation attempts.
4. Keep API v4+, HMAC/PRF, credential-match, output-length, persistence, owner-identity, maximized-window, cancellation, and RDP passive-continuation guards unchanged unless a separately tested minimal change is required by this scope.
5. Run focused RED/GREEN tests, full required Rust/Node/lint/format checks and a fresh GNU `real-ctap` Release build with source/artifact provenance. Obtain independent completed-code review before source publication. Keep PR Draft and unmerged.
6. Do not launch the GUI, trigger WebAuthn, access/copy/hash/write any vault or key data, use WinRM/RDP, stage/deploy to NB, or alter machine policy/environment. Those actions are outside this authorization. Deliver the build/archive path and an itemized local Console verification checklist; the user performs the physical confirmation.

## Completion state

Automated tests/build/review establish source and candidate quality only. The foreground behavior remains NOT_VERIFIED until the user reports the rebuilt candidate's local Console prompt result. Preserve R4-3 unlock PASS and the foreground failure as separate acceptance facts; leave R5-6/R6 blocked while this physical subcase is unresolved.
