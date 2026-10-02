# Feature 4/4 — Custom security-key labels

## Confirmed behavior

- Registration asks for a FidoVault-local display name in an in-app dialog, prefilled with a suggested name that is unique among current key slots; the user can edit it before the authenticator operation begins.
- The name is required. Trim surrounding whitespace; reject an empty value, control characters, values longer than 64 Unicode scalar values, and duplicates after Unicode lowercase normalization. Enforce the same rules in the UI and again in the Rust vault layer so callers cannot bypass validation. Duplicate validation must happen before invoking authenticator registration.
- Persist the chosen alias in the existing `KeySlot.label`; return/display it in the registered-key list and use it in the `key_registered` / subsequent key-related audit labels. Do not rename or alter the authenticator credential itself, Windows Security prompts, or key-side metadata.
- `KeySlot.label` is plaintext header metadata, not part of the encrypted payload. The dialog must warn users not to enter sensitive personal information. This does not change the vault format; existing labels and vaults remain compatible.
- Cancelling the name dialog or failing validation must not invoke key registration or add a vault slot. A failed authenticator operation must not persist a slot.

## Acceptance criteria

- The registration flow shows a keyboard-accessible in-app modal with an editable, unique suggested name, a clear explanation that this is only a local FidoVault alias, and a plaintext-metadata warning.
- Blank/whitespace-only, control-character, overlength, and duplicate (including case-only or surrounding-space variants) labels are rejected with a useful message. Validation is repeated in Rust before any FIDO operation.
- A successful registration stores the exact trimmed user alias in `KeySlot.label`; the list, success status, and audit event use the alias.
- Cancelling before authenticator registration results in no `register_key` command, no FIDO request, and no slot. Registration errors leave the vault slot count unchanged.
- Existing header serialization remains unchanged and existing vault files with labels continue to load.
- Follow vertical TDD slices: add one focused failing UI/backend test, observe expected RED, implement that behavior, then proceed to the next slice. Run relevant Rust tests, targeted and complete Node suites, static checks, and Windows GNU Release GUI + CLI build with `real-ctap`.

## Implementation sequence

1. Add a failing backend test for normalized label validation/uniqueness and prove invalid names are rejected before backend registration; implement the pure validator and vault-layer enforcement.
2. Add a failing UI test for the accessible name dialog, unique suggestion, cancel behavior, and `label` passed through Tauri IPC; implement the modal and flow.
3. Verify successful persistence/list/audit label, failed registration rollback behavior, and old-header compatibility with focused tests.
4. Run full verification and independent code review; update README/spec/project/user-verification docs and PR #9. Keep Feature 2 and Feature 3 local acceptance explicitly pending until the user's requested combined Win11-NB Console test.
5. Only after build and review pass, stage the exact GUI Release artifact on Win11-NB using the read-only preflight/backup/hash workflow. Do not launch the app, operate WebAuthn, or use RDP/WinRM for GUI acceptance. Hand off Feature 2, 3, and 4 checks together for local Console testing.

## Explicitly out of scope

- Changing authenticator credential names, Windows Security prompt text, FIDO credential properties, or existing slot-removal behavior.
- Editing/renaming existing key labels after registration.
- Encrypting the header label (separate vault-format/security migration).
- Starting other features or marking the deferred Feature 2/3 physical acceptance as passed.
