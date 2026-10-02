# Feature 4/4 — Custom security-key labels

## Confirmed behavior

- Registration asks for a FidoVault-local display name in an in-app dialog, prefilled with a suggested name that is unique among current key slots; the user can edit it before the authenticator operation begins.
- The name is required. Trim surrounding whitespace; reject an empty value, control characters, values longer than 64 Unicode scalar values, and duplicates under Unicode canonical caseless matching. The dialog obtains the suggested unique alias from Rust and validates candidates through Rust before the UI may proceed; the vault validates again before any authenticator operation.
- Persist the chosen alias in the existing `KeySlot.label`; return/display it in the registered-key list and use it in the `key_registered` / subsequent key-related audit labels. Do not rename or alter the authenticator credential itself, Windows Security prompts, or key-side metadata.
- `KeySlot.label` is plaintext header metadata, not part of the encrypted payload. The dialog must warn users not to enter sensitive personal information. This does not change the vault format; existing labels and vaults remain compatible.
- Cancelling the name dialog or failing validation must not invoke key registration or add a vault slot. A failed authenticator operation must not persist a slot.

## Acceptance criteria

- The registration flow shows a keyboard-accessible in-app modal with an editable, unique suggested name, a clear explanation that this is only a local FidoVault alias, and a plaintext-metadata warning.
- Blank/whitespace-only, control-character, overlength, and duplicate (including Unicode case-fold expansions and canonically equivalent forms) labels are rejected with a useful message. Rust supplies the unique suggestion, validates each confirmed candidate before any UI detection call, and validates again in the registration method.
- A successful registration stores the exact trimmed user alias in `KeySlot.label`; the list, success status, and audit event use the alias.
- Cancelling before authenticator registration results in no `register_key` command, no FIDO request, and no slot. Registration errors leave the vault slot count unchanged.
- Existing header serialization remains unchanged and existing vault files with labels continue to load.
- Follow vertical TDD slices: add one focused failing UI/backend test, observe expected RED, implement that behavior, then proceed to the next slice. Run relevant Rust tests, targeted and complete Node suites, static checks, and Windows GNU Release GUI + CLI build with `real-ctap`.

## Implementation sequence

1. [x] Add a failing Rust test for normalized label validation/uniqueness and prove invalid names are rejected before backend detection; implement the pure validator and vault-layer enforcement.
2. [x] Add failing UI tests for the accessible name dialog, unique suggestion, cancel behavior, disabled repeat clicks, and `label` passed through Tauri IPC; implement the modal and flow.
3. [x] Verify successful persistence/list/audit labels after reopening the vault, rejected duplicate/blank names before FIDO detection, and failed non-PRF registration leaves the slot count unchanged.
4. [x] Run full Rust/Node suites, backend-mode Release tests, static scan, and Windows GNU Release GUI/CLI build; update README/spec/project/user-verification docs and PR #9.
5. [x] Independent code review passed.
6. [ ] Stage the exact GUI Release artifact on Win11-NB using the read-only preflight/backup/hash workflow. Do not launch the app or operate WebAuthn over WinRM/RDP; hand off Feature 2/3/4 checks for the user's local Console test.

## Verification results

- UI: Feature 4 targeted tests 5/5; full Node suite 24/24; `node --check src/app.js` passed.
- Rust MSVC library suite (`--locked --features real-ctap`): 64/64; Release backend-mode matrix: 7/7.
- Windows GNU Release GUI + CLI build (`--locked --features real-ctap`): passed. GUI 6,729,216 bytes, SHA-256 `7deba32418fb173d5ada126e600c81a748ffa51bcfe503afc7bed683fb928ed1`; CLI 2,427,392 bytes, SHA-256 `1493ab5d09fb942a61f77cc9e82827b2fa08f60e3e74d81e5d1cd657771ab3c2`.
- Static added-line security scan: no findings; `git diff --check` passed.
- `cargo clippy -D warnings` remains blocked by 11 existing diagnostics in `diag_log.rs`, `fido2.rs`, `windows_webauthn.rs`, and unrelated `vault.rs` lines; no warning points to the new alias code. Whole-file rustfmt check also fails on baseline formatting; unrelated lines were not reformatted.
- Manual Win11-NB acceptance and deployment have not yet occurred. Feature 2/3/4 remain pending the user's requested combined local Console test.

## Explicitly out of scope

- Changing authenticator credential names, Windows Security prompt text, FIDO credential properties, or existing slot-removal behavior.
- Editing/renaming existing key labels after registration.
- Encrypting the header label (separate vault-format/security migration).
- Starting other features or marking the deferred Feature 2/3 physical acceptance as passed.
