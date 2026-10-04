# Rust formatting verification — 2026-10-04

## Codex-stage snapshot (before parent verification and publication)

Revision: 97c7bba88a0b9c456e859ce934e8f3952c9ea970; branch: chore/rustfmt-baseline. Base main supplied by parent: 9bd08502d74ccc36077728b5c88959dc6b62ff24. At this snapshot, changes were unstaged and uncommitted; parent results below supersede the pending-work status, not the historical command records.

Tools: cargo 1.98.1; rustc 1.98.1 (MSVC); rustfmt 1.9.0-stable; Node v24.15.0; Git 2.54.0.windows.1. Full versions and active toolchain are recorded in rustfmt-evidence/.

## Inventory and scope

Tracked Rust inventory: 111 files (application 11; vendor 100), saved in tracked-rust.stdout.log. Offline cargo metadata --no-deps inventories 5 application targets (library, main binary, yk_open_test binary, vault_cli example, build script), and 9 vendor targets (library, 7 examples, build script). Editions remain application 2021 and vendor 2018. Both manifests were checked explicitly; all 111 tracked Rust files were additionally checked directly using rustfmt with their crate editions, including platform-specific modules. Cargo manifests/locks and build scripts are unchanged.

Application --all baseline: exit 1, 14 differing files / 94 Diff blocks (application 7 files / 83 blocks; local dependency 7 files / 11 blocks). Explicit vendor baseline: exit 1, 7 files / 11 blocks. Both emitted ignored nightly-only wrap_comments/comment_width warnings. Only these two settings were removed; vendor edition = "2018" retained. Both post-format cargo checks exit 0 with empty stdout/stderr, and both direct tracked-source checks exit 0 with empty stdout/stderr.

Deliverable changes: 18 files: 14 formatter-produced Rust files, vendor configuration, two authorized current-status documents, and this report. Full file inventory (including separate untracked evidence artifacts) is saved in rustfmt-evidence/changed-files.json.

| File | Lexical token count delta | Sequence |
|---|---|---|
| src-tauri/examples/vault_cli.rs | {",":1} | changed |
| src-tauri/src/bin/yk_open_test.rs | {",":1} | changed |
| src-tauri/src/crypto.rs | {} | changed |
| src-tauri/src/diag_log.rs | {} | unchanged (outside whitespace) |
| src-tauri/src/fido2.rs | {"{":2,",":10,"}":2} | changed |
| src-tauri/src/lib.rs | {"{":2,",":1,"}":2} | changed |
| src-tauri/src/vault.rs | {"{":1,",":10,"}":1} | changed |
| vendor/authenticator-rs/src/authenticatorservice.rs | {",":-1} | changed |
| vendor/authenticator-rs/src/device_filter.rs | {} | unchanged (outside whitespace) |
| vendor/authenticator-rs/src/manager.rs | {",":-2} | changed |
| vendor/authenticator-rs/src/transport/hidproto.rs | {",":3} | changed |
| vendor/authenticator-rs/src/transport/linux/monitor.rs | {",":-1} | changed |
| vendor/authenticator-rs/src/transport/mod.rs | {"{":-1,"}":-1} | changed |
| vendor/authenticator-rs/src/util.rs | {} | unchanged (outside whitespace) |

Other changed files:

- docs/PROJECT.md
- docs/user-verification-steps.md
- vendor/authenticator-rs/rustfmt.toml
- docs/reports/rust-format-verification.md

The lightweight lexer compares comments and literal spelling separately: both sequences are unchanged in all 14 Rust files. Token differences include formatter import reordering (vault_cli, yk_open_test, crypto), trailing comma changes, match-arm braces (fido2/vault), closure-body braces (lib.rs remove_key/set_idle_lock), and removal of an unnecessary closure block (vendor transport/mod). This is not a Rust parser or proof of semantic equivalence. Full diff and git diff -w output are preserved; -w still contains line wrapping and must not be treated as token proof. Independent parent review was PENDING at this snapshot and has since passed as recorded below. No manual source rewrites were made.

## Actual checks

- baseline-application: `cargo +stable-x86_64-pc-windows-msvc fmt --manifest-path src-tauri/Cargo.toml --all -- --check` — exit 1.
- baseline-vendor: `cargo +stable-x86_64-pc-windows-msvc fmt --manifest-path vendor/authenticator-rs/Cargo.toml --all -- --check` — exit 1.
- apply-application: `cargo +stable-x86_64-pc-windows-msvc fmt --manifest-path src-tauri/Cargo.toml --all` — exit 0.
- apply-vendor: `cargo +stable-x86_64-pc-windows-msvc fmt --manifest-path vendor/authenticator-rs/Cargo.toml --all` — exit 0.
- after-application: `cargo +stable-x86_64-pc-windows-msvc fmt --manifest-path src-tauri/Cargo.toml --all -- --check` — exit 0.
- after-vendor: `cargo +stable-x86_64-pc-windows-msvc fmt --manifest-path vendor/authenticator-rs/Cargo.toml --all -- --check` — exit 0.
- all-tracked-check-application: `rustfmt +stable-x86_64-pc-windows-msvc --check --edition 2021 src-tauri/build.rs src-tauri/examples/vault_cli.rs src-tauri/src/bin/yk_open_test.rs src-tauri/src/crypto.rs src-tauri/src/csv_import.rs src-tauri/src/diag_log.rs src-tauri/src/fido2.rs src-tauri/src/lib.rs src-tauri/src/main.rs src-tauri/src/vault.rs src-tauri/src/windows_webauthn.rs` — exit 0.
- all-tracked-check-vendor: `rustfmt +stable-x86_64-pc-windows-msvc --check --edition 2018 vendor/authenticator-rs/build.rs vendor/authenticator-rs/examples/ctap2.rs vendor/authenticator-rs/examples/ctap2_discoverable_creds.rs vendor/authenticator-rs/examples/interactive_management.rs vendor/authenticator-rs/examples/prf.rs vendor/authenticator-rs/examples/reset.rs vendor/authenticator-rs/examples/set_pin.rs vendor/authenticator-rs/examples/test_exclude_list.rs vendor/authenticator-rs/src/authenticatorservice.rs vendor/authenticator-rs/src/consts.rs vendor/authenticator-rs/src/crypto/der.rs vendor/authenticator-rs/src/crypto/dummy.rs vendor/authenticator-rs/src/crypto/mod.rs vendor/authenticator-rs/src/crypto/nss.rs vendor/authenticator-rs/src/crypto/openssl.rs vendor/authenticator-rs/src/crypto/rustcrypto.rs vendor/authenticator-rs/src/ctap2/attestation.rs vendor/authenticator-rs/src/ctap2/client_data.rs vendor/authenticator-rs/src/ctap2/commands/authenticator_config.rs vendor/authenticator-rs/src/ctap2/commands/bio_enrollment.rs vendor/authenticator-rs/src/ctap2/commands/client_pin.rs vendor/authenticator-rs/src/ctap2/commands/credential_management.rs vendor/authenticator-rs/src/ctap2/commands/get_assertion.rs vendor/authenticator-rs/src/ctap2/commands/get_info.rs vendor/authenticator-rs/src/ctap2/commands/get_next_assertion.rs vendor/authenticator-rs/src/ctap2/commands/get_version.rs vendor/authenticator-rs/src/ctap2/commands/large_blobs.rs vendor/authenticator-rs/src/ctap2/commands/make_credentials.rs vendor/authenticator-rs/src/ctap2/commands/mod.rs vendor/authenticator-rs/src/ctap2/commands/reset.rs vendor/authenticator-rs/src/ctap2/commands/selection.rs vendor/authenticator-rs/src/ctap2/mod.rs vendor/authenticator-rs/src/ctap2/preflight.rs vendor/authenticator-rs/src/ctap2/server.rs vendor/authenticator-rs/src/ctap2/utils.rs vendor/authenticator-rs/src/device_filter.rs vendor/authenticator-rs/src/errors.rs vendor/authenticator-rs/src/lib.rs vendor/authenticator-rs/src/manager.rs vendor/authenticator-rs/src/statecallback.rs vendor/authenticator-rs/src/statemachine.rs vendor/authenticator-rs/src/status_update.rs vendor/authenticator-rs/src/transport/device_selector.rs vendor/authenticator-rs/src/transport/errors.rs vendor/authenticator-rs/src/transport/freebsd/device.rs vendor/authenticator-rs/src/transport/freebsd/mod.rs vendor/authenticator-rs/src/transport/freebsd/monitor.rs vendor/authenticator-rs/src/transport/freebsd/transaction.rs vendor/authenticator-rs/src/transport/freebsd/uhid.rs vendor/authenticator-rs/src/transport/hid.rs vendor/authenticator-rs/src/transport/hidproto.rs vendor/authenticator-rs/src/transport/linux/device.rs vendor/authenticator-rs/src/transport/linux/hidraw.rs vendor/authenticator-rs/src/transport/linux/hidwrapper.rs vendor/authenticator-rs/src/transport/linux/ioctl_aarch64le.rs vendor/authenticator-rs/src/transport/linux/ioctl_armle.rs vendor/authenticator-rs/src/transport/linux/ioctl_loongarch64.rs vendor/authenticator-rs/src/transport/linux/ioctl_mips64le.rs vendor/authenticator-rs/src/transport/linux/ioctl_mipsbe.rs vendor/authenticator-rs/src/transport/linux/ioctl_mipsle.rs vendor/authenticator-rs/src/transport/linux/ioctl_powerpc64be.rs vendor/authenticator-rs/src/transport/linux/ioctl_powerpc64le.rs vendor/authenticator-rs/src/transport/linux/ioctl_powerpcbe.rs vendor/authenticator-rs/src/transport/linux/ioctl_riscv64.rs vendor/authenticator-rs/src/transport/linux/ioctl_s390xbe.rs vendor/authenticator-rs/src/transport/linux/ioctl_sparc64.rs vendor/authenticator-rs/src/transport/linux/ioctl_x86.rs vendor/authenticator-rs/src/transport/linux/ioctl_x86_64.rs vendor/authenticator-rs/src/transport/linux/mod.rs vendor/authenticator-rs/src/transport/linux/monitor.rs vendor/authenticator-rs/src/transport/linux/transaction.rs vendor/authenticator-rs/src/transport/macos/device.rs vendor/authenticator-rs/src/transport/macos/iokit.rs vendor/authenticator-rs/src/transport/macos/mod.rs vendor/authenticator-rs/src/transport/macos/monitor.rs vendor/authenticator-rs/src/transport/macos/transaction.rs vendor/authenticator-rs/src/transport/mock/device.rs vendor/authenticator-rs/src/transport/mock/mod.rs vendor/authenticator-rs/src/transport/mock/transaction.rs vendor/authenticator-rs/src/transport/mod.rs vendor/authenticator-rs/src/transport/netbsd/device.rs vendor/authenticator-rs/src/transport/netbsd/fd.rs vendor/authenticator-rs/src/transport/netbsd/mod.rs vendor/authenticator-rs/src/transport/netbsd/monitor.rs vendor/authenticator-rs/src/transport/netbsd/transaction.rs vendor/authenticator-rs/src/transport/netbsd/uhid.rs vendor/authenticator-rs/src/transport/openbsd/device.rs vendor/authenticator-rs/src/transport/openbsd/mod.rs vendor/authenticator-rs/src/transport/openbsd/monitor.rs vendor/authenticator-rs/src/transport/openbsd/transaction.rs vendor/authenticator-rs/src/transport/stub/device.rs vendor/authenticator-rs/src/transport/stub/mod.rs vendor/authenticator-rs/src/transport/stub/transaction.rs vendor/authenticator-rs/src/transport/windows/device.rs vendor/authenticator-rs/src/transport/windows/mod.rs vendor/authenticator-rs/src/transport/windows/monitor.rs vendor/authenticator-rs/src/transport/windows/transaction.rs vendor/authenticator-rs/src/transport/windows/winapi.rs vendor/authenticator-rs/src/u2ftypes.rs vendor/authenticator-rs/src/util.rs` — exit 0.
- node-tests: `node --test tests/*.test.cjs` — exit 0.
- node-check: `node --check src/app.js` — exit 0.
- diff-check: `git diff --check` — exit 0.

Node tests: 53 passed, 0 failed/cancelled/skipped/todo. No hardware, GUI, E2E, vault, or authenticator operation was run. Git diff --check passed; Git emits LF-to-CRLF conversion notices while displaying diffs, preserved in stderr logs.

## Evidence and pending work

Preferred archive directory D:/project/_archives/portable-fido2-vault/20261004-rustfmt-maintenance/codex could not be created (PowerShell access denied; Node EPERM). Full untruncated UTF-8 stdout/stderr and command/exit JSON files are retained in the durable worktree rustfmt-evidence/ directory, alongside scripts, file inventory, token analysis and full diffs. These untracked evidence artifacts are separate from the 18 deliverable files; parent should retain them before removing this worktree.

Only read-only Git inspections were attempted against the original checkout; initial calls returned 128 (dubious ownership), followed by command-local safe.directory and --no-optional-locks reads. No original checkout or main write was performed. See original-main-readonly and original-status-readonly logs for actual state; a post-task snapshot alone does not prove before/after equality.

At the Codex-stage snapshot, Rust compilation (real-ctap library tests, vendor device_filter regressions, Clippy), independent parent review and publication were PENDING and were not run/passed by Codex. Codex performed no commit, staging, push, PR edit, deployment or merge and did not change Kanban.

## Parent independent verification — completed before publication

- Both application and explicit vendor stable `cargo fmt --all -- --check`: exit 0, empty output.
- Direct stable `rustfmt --check` inventory: all 111 tracked Rust files passed, application 11 with edition 2021 and vendor 100 with edition 2018, including platform-specific modules. Empty stdout/stderr for both groups.
- Deterministic reproduction from scope revision `97c7bba88a0b9c456e859ce934e8f3952c9ea970` in a separate baseline worktree: all 111 Rust Git blobs and the approved stable configuration exactly match the formatter-produced expected output. Git normalization handles LF/CRLF; no manual semantic changes were introduced.
- `node --test tests/*.test.cjs`: 53 passed, 0 failed/cancelled/skipped/todo. `node --check src/app.js` and `git diff --check`: exit 0.
- `cargo +stable-x86_64-pc-windows-msvc test --lib --locked --features real-ctap -j 1`: 75 passed, 0 failed/ignored, exit 0.
- `cargo +stable-x86_64-pc-windows-msvc clippy --lib --locked --features real-ctap -j 1 -- -D warnings`: exit 0.
- Standalone vendor `device_filter` regressions: 6 passed, 0 failed/ignored, 154 filtered out, exit 0. The first delivery-worktree attempt exited 101 before running tests because its ignored standalone vendor `Cargo.lock` did not exist and `--locked` forbade creating it. The parent copied all 115 tracked vendor files to a unique scratch crate, verified every source hash, generated only that isolated crate's lock with `cargo generate-lockfile --offline`, then ran `cargo test --no-default-features --features crypto_rust --locked --lib device_filter -j 1`. Delivery manifests and locks were unchanged; source hashes before and after the isolated test match. The generated test lock and original failure log are retained, not discarded or presented as a passing first attempt.
- Independent read-only review `deleg_74dd14c2`: PASS, all 18 deliverable paths reviewed, 0 security concerns and 0 logic errors. Its one nonblocking suggestion about lib.rs closure-body braces was corrected in this report; no production code changed after review.
- Compile-generated schema files normalize to the existing index blobs. Their raw generated copies were archived before an index-stat refresh; no schema content or staged schema change remains.
- Original checkout before and after parent checks: clean `main` at `9bd08502d74ccc36077728b5c88959dc6b62ff24`. No Win11-NB deployment, physical hardware, GUI, or existing-vault operation was performed. Hardware-free unit checks do not extend previous manual acceptance.

## Retained evidence and publication boundary

Parent archive: `D:/project/_archives/portable-fido2-vault/20261004-rustfmt-maintenance`.

- `codex/`: all 113 original Codex evidence files copied by the parent after sandbox archive denial; every copied file hash matched. Inventory and SHA-256 values are in `codex-evidence-manifest.json`.
- `parent/verification-result.json`: complete first parent attempt, including the truthful vendor lock-resolution failure.
- `parent/vendor-isolated-verification-result.json` and `parent/vendor-isolated.Cargo.lock`: resolved locked vendor regression, exact-source/hash proof and retained test lock.
- `parent/automated-verification-summary.json`: aggregated successful checks; the independent-review field records the pre-review snapshot rather than replacing it.
- `parent/independent-review.json`: received review verdict with validated 18-file coverage. Per-file reviewed diffs remain under `review-input/`.
- `formatter-reproduction-result.json` and `parent-all-tracked-format-result.json`: full source/config blob comparisons and direct tracked-source checks.
- `parent/schema-cache-refresh.json`: normalized schema identity and empty staged diff after refresh.

Only the explicit 18 deliverables are intended for publication; raw evidence is not part of the PR. PR #18 targets main and remains unmerged until the user authorizes merge. Hosted CI for the published head must be read back separately; local results above are not a claim that hosted CI has already passed. This maintenance does not deploy a new executable or operate the target vault.
