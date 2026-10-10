# RDP continuation: privacy-safe diagnosis and passive foreground-return candidate

## Authorization and boundary

Skycity1010 approved this next investigation/repair round in Discord message `1557179346014183566`, thread `1557170177299320983`. The preceding confirmation `1557173842311516182` says the Windows Security prompt was on the NB connection-origin desktop and the user did not switch/click another window.

Base is reviewed PR21 source `de0bb4e0fd320441f9aba7b52fa13dccd6686faa`. Use only `D:/project/_worktrees/portable-fido2-vault-rdp-passive-20261007`, branch `fix/rdp-passive-foreground-20261007`; a new stacked Draft PR targets PR21's unmerged branch. Keep a parent-controlled native card blocked from creation. Preserve all original worktrees and older evidence/candidates.

Authorization covers source investigation/repair, focused TDD, automated QA, independent review, Release build/archive and reviewed source publication. It does NOT cover GUI launch, WebAuthn/key/PIN/touch operation, real vault reads/writes/copies, WinRM/RDP sessions, staging/deployment, merge, key reset/deletion, policy/environment persistence changes or support promotion. Synthetic disposable mock fixtures under owned Hermes scratch are allowed for automated tests.

## Observed facts and hypotheses

The prior parent read-only diagnostic correlated exact candidate EXE SHA256 `5464b96ba52b494110b0f8bce53690c6b8f4db7b870bf3836edbc4bac1cdff65`, GUI PID11840/session2/API7, MakeCredential HMAC creation confirmation at log time 2026-10-07 07:16:48, GetAssertion preflight `broker-not-observed`, and zero slots in the exact isolated WS2 test DB. No failure-time foreground identity was recorded. These are historical observations, not authorization to read that DB again.

Ranked falsifiable hypotheses:
1. A short NULL foreground activation transition after client-side redirection resolves naturally to the same live owner. Inject NULL -> owner on the production continuation seam; historical native timing remains UNKNOWN.
2. A non-NULL unrelated foreground remains after creation. Diagnose identity scalars, immediately refuse; do not wait through or activate that window.
3. Monitor ended before accepting any broker due to focus loss, ambiguity, incomplete observation or cancellation. Expose a closed, per-instance stop-reason enum without altering existing broker filters/terminal refusal.

Microsoft's RDP guide places the Security prompt on the client device; GetForegroundWindow permits NULL during activation transitions. Neither establishes that this physical failure was NULL or that any fixed deadline repairs it. The candidate must remain physically unqualified until exact-environment evidence.

## Accepted candidate policy

- Add allowlisted structured continuation diagnostics: numeric/nullable owner and foreground HWND/PID/TID/session, identity/visible/minimized booleans, typed session/protocol status, monotonic elapsed time and closed refusal/outcome labels. Do not log titles, paths, usernames, arbitrary error strings, credential IDs, challenges, raw CTAP, passwords, PINs or secrets. Unknown identity/session/protocol is null/unknown, never a fabricated successful value.
- Record the monitor's precise closed stop reason at the production worker seam, preserving each instance's private channel, completeness/unique-new/new-process/same-session/System32 filters and permanent disqualification. Diagnostics must not create authority or change observed-policy decisions.
- A minimal passive candidate is allowed only on the one-use registration continuation with successful validated creation, the exact single created credential and unchanged owner identity. Require independently validated native RDP protocol + active session, bound to the creation/current owner session; missing/malformed/unknown/session0/Console/disconnected evidence is NOT RDP authority.
- Preserve the ordinary owner-already-foreground path and the existing observed trusted-broker recovery policy. Do not replace them with a general focus retry.
- Only an unobserved-broker **NULL** foreground transition on an explicitly validated active RDP session may be observed for at most 1000 ms, polling no more frequently than 20 ms. The bound is a conservative candidate budget, NOT measured physical return time. Start the monotonic budget before potentially blocking eligibility queries; account for their time. A non-NULL unrelated foreground, invalid/changed/hidden/minimized/foreign owner, session/protocol/active-state failure or expiry immediately refuses and consumes the continuation.
- Success requires the same valid visible non-minimized owner to become foreground within the budget without any activation/restore, followed by all unchanged credential/output/crypto and final owner/foreground guards. Passive waiting never calls SetForegroundWindow, SW_RESTORE, show/focus, AttachThreadInput, topmost or ASFW_ANY. No sleeps, metadata, synchronous diagnostics or retry may enter the final sample -> arm -> WebAuthn FFI gap.
- Preserve context take/clear/replay prevention, first-ceremony failures preventing the second call, persistence only after valid matching 32-byte secret, API>=4, fixed RP/origin/raw salt, vault format, Console ordinary/login behavior and maximization. No retry of MakeCredential and no automatic new slot on a failure.

## Delivery gates

Implement vertical genuine assertion RED -> minimal GREEN pairs using the real production seams and injected native observations/clock; preserve unchanged assertions and immutable source snapshots for each RED. Already-GREEN safety regressions are coverage, not fabricated REDs. No hardware in tests.

Cover NULL -> owner, NULL timeout/deadline including slow metadata, NULL -> unrelated refusal, initial unrelated refusal, Console/unknown/disconnected/malformed/native-WTS status, owner/session/PID/TID changes, hidden/minimized owner, creation/context/credential mismatch, consumption/replay, cancellation/monitor ambiguity/incompleteness, per-instance stop reasons, unchanged broker recovery, no activation/restore, registration second-failure no persistence and exact final-FFI-gap LF/CRLF/mutation oracle.

Production allowlist: `src-tauri/src/windows_webauthn.rs`, `src-tauri/src/webauthn_diagnostics.rs`. Focused tests in these modules, this scope document and `docs/reports/rdp-passive-foreground.md`. No frontend/vendor/manifest/lock/schema/build/CI/config/policy changes. Build-generated schema side effects must be captured then restored exactly to the pre-build bytes.

Required actual QA: GNU real-ctap targeted/library suite, complete Node TAP suite and frontend syntax, Clippy -D warnings, rustfmt/diff checks, new GNU real-ctap Release GUI build with source-before/source-after provenance, parent re-verification and independent fail-closed completed-code review before source publication. Archive a new EXE + signed architecture-matching loader bundle without DB/credentials/raw logs. PR stays Draft/unmerged, cards blocked. Hosted CI is separately measured; the current workflow's main-only filter excludes a stacked base, so NOT_RUN cannot be relabeled PASS or solved by changing CI scope.

R4 new-slot physical acceptance remains FAILED; historical old-slot RDP PASS is preserved. No statement of actual natural focus return, repaired RDP registration, bidirectional unlock or product RDP support PASS is permitted from synthetic tests/build/review alone.
