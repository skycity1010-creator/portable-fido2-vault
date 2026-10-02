# Feature 3/4 — Copy an entry password with timed clipboard clearing

## Confirmed behavior

- Add a **copy password** action to every password entry. It copies that entry's current password as plain text to the operating-system clipboard.
- Show a generic success or failure status in the UI. Never place password text in a status message, audit record, diagnostic log, or error message.
- After 60 seconds, execute one Windows native conditional-clear operation: hold the clipboard lock, compare its CF_UNICODETEXT value to the copied password, and empty the clipboard only on an exact match. This closes the external read-then-clear race; if the text differs, preserve it.
- A later copy initiated in FidoVault supersedes the previous FidoVault clear timer, even when the copied values happen to be equal; the earlier timer must not clear the later copy prematurely.
- Clipboard API/Win32 failures must produce a generic user-facing status without crashing the app. If the conditional operation cannot safely inspect or clear the clipboard, leave it unchanged.
- Use the official Tauri v2 clipboard-manager plugin for plain-text writes only. Grant only `clipboard-manager:allow-write-text`; use Win32 `OpenClipboard`/`EmptyClipboard` for atomic compare-and-clear. The app already uses `withGlobalTauri: true`, so no JavaScript bundler dependency is needed.

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

Feature 2 and Feature 3 implementations are complete. The user confirmed Features 2, 3, and 4 passed the combined Win11-NB local Console acceptance on 2026-10-02.

## Implementation sequence

1. [x] Add focused UI regression and Rust UTF-16 matcher tests; observe RED for the non-atomic clipboard race and missing matcher.
2. [x] Integrate Tauri clipboard-manager with write-text-only permission and a synchronous Win32 compare-and-clear command under the OS clipboard lock.
3. [x] Cover atomic-command invocation, replacement preservation, Win32-command errors, and serial ordering for concurrent copies.
4. [x] Run targeted/full automated tests, Windows Release GUI/CLI build, and `git diff --check`.
5. [x] Open draft PR #8 before implementation on `feat/copy-password`, stacked on `feat/password-history` (Feature 2 PR #6).
6. [x] Win11-NB local Console acceptance passed, user-confirmed 2026-10-02 as part of the combined Feature 2/3/4 test. Do not use WinRM/RDP to operate the GUI or clipboard.

## Verification results

- Targeted clipboard UI tests: 7/7 passed. Full Node UI suite: 19/19; `node --check src/app.js` passed.
- MSVC Rust library suite (`--locked --features real-ctap`): 60/60. Release backend-mode matrix: 7/7.
- Windows GNU Release GUI + `vault_cli` build with `--locked --features real-ctap`: passed. GUI artifact is 6,589,440 bytes, SHA-256 `58ba298f7f2bcd5fa4d2c1bdda5ab6e5d2847379af8e282c7ea92e3732838dde`; CLI SHA-256 `d98ce617f19054467818f46df611d4cea6eea723be30000c77102e0a8b134674`.
- Draft PR: https://github.com/skycity1010-creator/portable-fido2-vault/pull/8. User confirmed Feature 3 local Console acceptance passed on 2026-10-02 as part of the combined Feature 2/3/4 test.

## Official API references

- Tauri Clipboard plugin: https://v2.tauri.app/plugin/clipboard/
- Plugin JavaScript API/source: https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/clipboard-manager/guest-js
- Rust crate API (Tauri 2-compatible): https://docs.rs/tauri-plugin-clipboard-manager/latest/tauri_plugin_clipboard_manager/
- Microsoft Win32 `OpenClipboard` (locks against other writers): https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-openclipboard
- Microsoft Win32 `EmptyClipboard`: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-emptyclipboard
