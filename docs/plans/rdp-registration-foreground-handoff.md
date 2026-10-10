# RDP registration foreground handoff repair

Authorization: Skycity1010 Discord message 1557026048489553952, thread 1557024926261575721. Execute localization and repair only. No merge/deployment/GUI/authenticator/database operation or policy change is authorized.

Base: reviewed diagnostic PR #20 source 71ff94580283a7b42d6e64b3158d8c600308a27d. Fix branch: fix/rdp-registration-foreground-handoff-20261006. Isolated worktree D:/project/_worktrees/portable-fido2-vault-rdp-handoff-20261006. Existing PR #20 remains draft/unmerged; use a stacked draft PR targeting its branch. Never modify the original worktree or main.

Observed failure: actual GUI PID10088/API7; MakeCredential positive hmac-secret creation succeeds, then GetAssertion is rejected before FFI because owner HWND differs from foreground HWND. Source register command activates the parent once before two vault/backend ceremonies. Exact foreground window/process at failure is unknown; broker focus-return timing remains a hypothesis, not a proven physical cause. Preserve B old-slot RDP PASS; full new-slot registration remains FAIL until physical retest.

Ranked hypotheses:
1. Once-only orchestration preparation leaves second API without required fresh parent preparation. Reproduce via production-seam deterministic regression.
2. A broker-return focus transition delays/rests foreground elsewhere. Use injected trusted/unknown window identities to test handoff policy; do not assume any broker window is related.
3. Parent HWND becomes stale/invalid/hidden/minimized between calls. Test fail-closed and preserve maximized state; do not substitute global foreground as owner.

Acceptance:
- Establish a tight deterministic agent-runnable RED that executes production orchestration/policy for successful first ceremony followed by foreground loss, then GREEN after minimal repair. Hardware symptom remains human evidence; synthetic tests are not physical PASS.
- Fresh safe preparation for the continued registration/second ceremony; no arbitrary unrelated-window focus theft, broad HWND/process allowance, topmost, ASFW_ANY, AttachThreadInput bypass, persistent flags, or guard deletion. One minimal scoped fix. If safe recovery needs unavailable physical identity evidence, deliver diagnostics and report that blocker rather than guessing.
- Preserve API>=4, RP/origin/raw salt, credential-match, exact32-byte output, registration persistence only after valid secret, and last foreground-sample-to-FFI boundary without new blocking observers. Keep previous broker monitor lifetime/identity protections.
- Null/stale/unowned/hidden parent and inability to activate still abort before FFI. Restore only minimized windows; never demaximize a visible maximized window. Mock/rawCTAP/nonWindows semantics remain unchanged.
- Add unit regressions for success handoff, activation failure/unrelated focus, canceled first ceremony preventing second, no persistence on second failure, and Console/login/maximized contracts. Use actual production seam, no mock-only success claim. Retain source-wiring LF/CRLF safety oracle and assertions.
- Run targeted tests, GNU real-ctap library suite, complete Node suite/frontend syntax, Clippy -D warnings, rustfmt check, diff check, and GNU real-ctap release build. Independent review required. Do not publish before parent review.
- Report source/command/exit/log evidence and source/artifact provenance. Test-only source changes still require candidate rebuild. No GUI launch or physical key tests. Keep manual C/R4 and R5 pending, no RDP-support promotion.

Allowed code: src-tauri/src/windows_webauthn.rs; minimal related src-tauri/src/lib.rs/fido2.rs/vault.rs/webauthn_diagnostics.rs only if required by production seam, focused regression tests and docs/plans/rdp-registration-foreground-handoff.md, docs/reports/rdp-registration-foreground-handoff.md. No frontend/vendor/locks/schema/CI/policy changes. Evidence outside deliverable allowlist.

Kanban remains blocked from first creation while parent-controlled Codex writer is active; no dispatcher. A code-review/local/CI success is not physical new-slot acceptance. Existing R1 provider403 contract is unchanged, not bypassed by this repair.
