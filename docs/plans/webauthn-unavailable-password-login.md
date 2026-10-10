# WebAuthn unavailable must not block password login (R5-4 follow-up)

Date: 2026-10-10. Authorization: user, Hermes desktop conversation — 「同意B4照上面的方向修正」 after the R5-4 result.
Base: `main` `e27b0c9`. Branch: `fix/webauthn-unavailable-password-login-20261010`.

## Observed failure (R5-4)
WS2 RDP session with mstsc WebAuthn redirection disabled: GUI capability log `api_version=0`, `hmac_secret_api_supported=false`. `WindowsWebAuthnBackend::new` returns `FidoError::NotSupported` (API < v4), `make_backend` propagates it, `AppInner::new` fails inside Tauri `setup`, and the whole GUI exits. Master-password login is therefore impossible although it does not need WebAuthn.

## Required behavior
1. Release hardware mode on Windows: when the Windows WebAuthn backend cannot be constructed **only because the same-process WebAuthn capability is below the v4 HMAC-secret requirement**, the GUI still starts with an explicit "key unavailable" backend.
2. Master-password create/login/lock and all vault operations that do not need a key keep working.
3. Every key operation (detect, register, key login, any-key login, kind probe) fails closed with a clear, secret-free Traditional Chinese message that states the session has no usable Windows security-key support (WebAuthn API version, v4+ required) and suggests enabling RDP WebAuthn redirection or using the local Console; it must say master-password login is unaffected. No partial vault/slot writes.
4. Never fall back to MockBackend; the API v4+ requirement, RP/origin/raw salt, HMAC/PRF, credential-match and 32-byte checks are unchanged. Invalid `F2V_AUTHENTICATOR` values, missing compiled features and any other backend construction error remain fatal exactly as today.
5. Log a closed-category startup warning (API version only) when the unavailable backend is selected.
6. Optional UI: if cheap, expose the unavailability through `boot_info` so the login screen can show the notice before the user clicks; not required.

## Verification
- Strict TDD: pure policy test(s) for the construction mapping (capability error → unavailable backend; other errors → fatal; success → real backend) and backend behavior tests (each key operation returns the unavailable error; no slot change). RED must be an assertion failure.
- Full `cargo test --lib --features real-ctap`, frontend tests if touched, two independent reviews, Release build.
- Physical: WS2 RDP with redirection off → GUI starts, password login works, key login shows the message; redirection on → key login still works; NB Console key login regression.
