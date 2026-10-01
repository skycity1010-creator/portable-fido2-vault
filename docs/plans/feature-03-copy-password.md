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

1. Add a focused UI test for one copy behavior and observe the expected RED failure.
2. Integrate Tauri clipboard-manager, minimal permissions, entry action, and non-secret status; make that vertical slice GREEN.
3. Add further timer-race and error-path tests one behavior at a time, then implement each.
4. Run targeted and full automated tests, build the Windows Release GUI/CLI, and update this plan with actual results.
5. Open/keep the implementation PR before coding; deploy only after automated verification. Manual acceptance remains in the user's local Console session.

## Official API references

- Tauri Clipboard plugin: https://v2.tauri.app/plugin/clipboard/
- Plugin JavaScript API/source: https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/clipboard-manager/guest-js
- Rust crate API (Tauri 2-compatible): https://docs.rs/tauri-plugin-clipboard-manager/latest/tauri_plugin_clipboard_manager/
