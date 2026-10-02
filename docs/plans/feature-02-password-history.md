# Feature 2/4 — Per-entry password history

## Confirmed behavior

- Each entry retains the most recent **1–20 prior passwords**, excluding the current password; the default is 3.
- Only an actual password change archives the previous current password. Metadata-only edits and unchanged passwords do not add history.
- Reducing the configured limit immediately removes the oldest excess versions from every entry.
- The edit screen shows prior-version dates and offers a restore action. Restoring stages the selected password in the edit field; Save applies it as the current password. The formerly current password becomes the newest history entry, and the selected history item is removed so the current password is not duplicated as an old version.
- History and its retention setting are part of the AES-GCM encrypted payload. Existing vaults default to an empty history and a limit of 3. Passwords overwritten before this feature cannot be recovered.

## Acceptance criteria

- Add/edit a vault entry model for password versions with stable IDs and timestamps.
- Enforce retention 1–20 and default 3 in the encrypted vault settings; setting persists across unlock/restart.
- Existing vault payloads deserialize without migration loss when history/limit fields are absent.
- Password changes archive correctly; unchanged passwords and metadata-only edits do not. Restore behavior preserves the current password and removes the restored version from history.
- Changing the retention limit prunes oldest history immediately for all entries.
- UI displays dates without exposing old password text by default and allows selecting a version to restore through the normal Save action.
- Follow TDD: add targeted Rust and UI tests, observe expected RED failures, then implement; run targeted tests, full Rust/UI suites, and Windows GNU Release build.

## Explicitly out of scope

Clipboard copy/auto-clear and custom security-key labels (separate feature cards/PRs). No legacy password history is synthesized.

## Implementation sequence

1. Add failing Rust tests for defaults/backward compatibility, archival, trimming, and restore; run targeted tests to verify RED.
2. Implement the encrypted data/settings model and Tauri command, retaining the existing serialized vault compatibility.
3. Add failing UI tests for retention controls and history/restore interaction, then implement the UI.
4. Run targeted and full tests, build, and update this verification plan. Deploy only after the implementation PR is open and all build checks pass.

## Win11-NB acceptance

- User confirmed Feature 2 passed the combined Win11-NB local Console acceptance with Features 3 and 4 on 2026-10-02.
