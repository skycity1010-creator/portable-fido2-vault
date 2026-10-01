# Feature 3/4 — Copy an entry password with timed clipboard clearing

## Confirmed behavior

- Add a **copy password** action to every password entry. It copies that entry's current password as plain text to the operating-system clipboard.
- Show a generic success or failure status in the UI. Never place password text in a status message, audit record, diagnostic log, or error message.
- After 60 seconds, read the current clipboard and clear it only if its text still exactly matches the value copied by this action. If another value replaced it, preserve that newer content.
- A later copy initiated in FidoVault supersedes the previous FidoVault clear timer, even when the copied values happen to be equal; the earlier timer must not clear the later copy prematurely.
- Clipboard API failures must produce a generic user-facing status without crashing the app. If the delayed read fails, do not clear unknown clipboard content.
- Use the official Tauri v2 clipboard-manager plugin. Request only plain-text read/write and clear permissions; do not enable image or HTML clipboard commands. The app already uses `withGlobalTauri: true`, so no JavaScript bundler dependency is needed.

## Acceptance criteria

- Every rendered entry has an accessible copy button that copies only its own current password.
- A successful write displays a non-secret confirmation; the row and confirmation never expose the secret.
- A write failure displays a generic failure and does not schedule automatic clearing.
- At 60 seconds, unchanged copied text is cleared; different clipboard text remains unchanged.
- Repeated app copies cannot be cleared by an earlier timer. Read/clear failures do not crash the app and do not expose secret contents.
- TDD covers successful copy, write failure, unchanged-text clearing, replacement preservation, repeated copies, and delayed clipboard API errors.
- Run targeted and full Node UI suites, the real-CTAP Rust library suite, locked Windows Release GUI/CLI build, and `git diff --check`.
- Record a separate Win11-NB **local Console** acceptance result; do not use WinRM/RDP to operate the GUI or clipboard.

## Explicitly out of scope

Custom security-key labels (Feature 4), changing password display behavior, and copying password history entries.

## Ordered work

Feature 2 implementation is complete, but its Win11-NB local acceptance was explicitly deferred by the user. The user directed that Feature 3 proceed now. This is sequential work—not parallel implementation—and does not mark Feature 2 as manually accepted. Do not start Feature 4 while Feature 3 is active.

## Implementation sequence

1. [x] Add focused UI tests and observe expected RED failures for missing copy, write-error handling, 60-second clearing, read failure, and in-flight expiry race.
2. [x] Integrate Tauri clipboard-manager, minimum text-only permissions, row action, and non-secret status.
3. [x] Cover timer replacement preservation, clear/read errors, and serial ordering for concurrent copies.
4. [x] Run targeted/full automated tests, Windows Release GUI/CLI build, and `git diff --check`.
5. [x] Open draft PR #8 before implementation on `feat/copy-password`, stacked on `feat/password-history` (Feature 2 PR #6).
6. [ ] Win11-NB local Console acceptance; not deployed yet. Do not use WinRM/RDP to operate the GUI or clipboard.

## Verification results

- Targeted clipboard UI tests: 7/7 passed. Full Node UI suite: 19/19; `node --check src/app.js` passed.
- MSVC Rust library suite (`--locked --features real-ctap`): 57/57. Release backend-mode matrix: 7/7.
- Windows GNU Release GUI + `vault_cli` build with `--locked --features real-ctap`: passed. GUI artifact is 6,579,712 bytes, SHA-256 `609fa36a872fea3f449a90d605a32ecf8ee10a859573b0f6f242dfbdae428b6a`; CLI SHA-256 `0e0621e595004206b19c5fbc9ff07136c4cfd18d67668fcfbb44a11301365abf`.
- Draft PR: https://github.com/skycity1010-creator/portable-fido2-vault/pull/8. Feature 2 local acceptance remains deferred per user instruction; Feature 4 has not started.

## Official API references

- Tauri Clipboard plugin: https://v2.tauri.app/plugin/clipboard/
- Plugin JavaScript API/source: https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/clipboard-manager/guest-js
- Rust crate API (Tauri 2-compatible): https://docs.rs/tauri-plugin-clipboard-manager/latest/tauri_plugin_clipboard_manager/
