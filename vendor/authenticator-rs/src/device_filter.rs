/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! [vendor patch] Targeted HID device filter for the offline FIDO2 vault.
//!
//! The stock Windows monitor (`transport::windows::monitor::Monitor::run`)
//! enumerates *every* HID interface on the machine — keyboards, mice,
//! touchpads, webcams — and opens each one in turn, running the CTAP2 probe
//! against all of them. On a laptop with ~30 HID devices that both burns the
//! CTAP2 timeout and lets the device selector latch onto a non-FIDO device, so
//! key *detection* fails even when the authenticator is present and perfectly
//! openable. (Proven by `yk_open_test`: the YubiKey's FIDO HID opens cleanly as
//! both the interactive user and SYSTEM, and answers CTAP2 Init + GetInfo with
//! a real 424-byte response. The full-scan, not the key, was the failure.)
//!
//! The fix: filter the enumeration down to the authenticator(s) we actually
//! care about, identified by the USB VID/PID embedded in the device interface
//! path (e.g. `\\?\hid#vid_1050&pid_0402#...`). This is a **no-op until the
//! application calls [`set_target_devices`]**, so the stock full-scan behavior
//! is preserved for any other caller of this crate.
//!
//! Why VID/PID from the path and not `HIDP_CAPS` usage page: even the real
//! YubiKey reports `usage_page = 0x0000, usage = 0x00` from `HidP_GetCaps` on
//! this platform, so a usage-page "FIDO only" filter would *reject the
//! authenticator itself*. The USB identity in the PnP path is the reliable
//! identifier.

use std::sync::{Mutex, PoisonError};

/// Targeted USB (VID, PID) pairs. Empty = filter disabled (stock full-scan).
///
/// A PID of `0` in an entry means "match *any* PID for this VID" (used to
/// target the whole Yubico HID family by VID 0x1050 alone).
static TARGET: Mutex<Vec<(u16, u16)>> = Mutex::new(Vec::new());

fn lock() -> std::sync::MutexGuard<'static, Vec<(u16, u16)>> {
    TARGET.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Replace the set of targeted USB (VID, PID) pairs. Pass an empty slice to
/// restore the stock full-scan behavior.
pub fn set_target_devices(pairs: &[(u16, u16)]) {
    let mut g = lock();
    g.clear();
    g.extend_from_slice(pairs);
}

/// Append a targeted USB (VID, PID) pair. `pid == 0` means "any PID for this
/// VID".
pub fn add_target_device(vid: u16, pid: u16) {
    lock().push((vid, pid));
}

/// True when no filter is configured (i.e. the stock full-scan is in effect).
pub fn is_enabled() -> bool {
    !lock().is_empty()
}

/// Parse `(vid, pid)` out of a HID device interface path.
///
/// The Windows PnP instance path embeds the USB identity, e.g.
/// `\\?\hid#vid_1050&pid_0402#7&1a146b8&0&0000#{4d1e55b2-...}`. The
/// `vid_XXXX&pid_YYYY` segment is the reliable physical-device identity.
pub fn vid_pid_from_path(path: &str) -> Option<(u16, u16)> {
    let lower = path.to_ascii_lowercase();
    let vid_start = lower.find("vid_")?;
    let vid_str = &lower[vid_start + 4..];
    let vid_end = vid_str.find(|c: char| !c.is_ascii_alphanumeric())?;
    let vid = u16::from_str_radix(&vid_str[..vid_end], 16).ok()?;

    let rest = &vid_str[vid_end..];
    let pid_start = rest.find("pid_")?;
    let pid_str = &rest[pid_start + 4..];
    let pid_end = pid_str.find(|c: char| !c.is_ascii_alphanumeric())?;
    let pid = u16::from_str_radix(&pid_str[..pid_end], 16).ok()?;

    Some((vid, pid))
}

/// True when `path` matches a currently-targeted device. Returns `true` when
/// the filter is disabled (stock full-scan) so behavior is unchanged.
pub fn matches(path: &str) -> bool {
    let g = lock();
    matches_with(&g, path)
}

/// Core matching logic, exposed without the global for unit-testing (pure,
/// no shared state). Semantics:
/// - empty target list → match everything (filter disabled).
/// - otherwise the path must parse to a VID/PID, and some entry must match on
///   VID (and PID, unless the entry's PID is the `0` "any" sentinel).
/// - a path with no parsable USB identity never matches a filter.
fn matches_with(targets: &[(u16, u16)], path: &str) -> bool {
    if targets.is_empty() {
        return true;
    }
    match vid_pid_from_path(path) {
        Some((vid, pid)) => targets
            .iter()
            .any(|(tv, tp)| *tv == vid && (*tp == 0 || *tp == pid)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YUBIKEY: &str =
        r"\\?\hid#vid_1050&pid_0402#7&1a146b8&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}";
    const LOGITECH: &str =
        r"\\?\hid#vid_046d&pid_c52b#4&3b21c0f&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}";

    #[test]
    fn parses_vid_pid() {
        assert_eq!(vid_pid_from_path(YUBIKEY), Some((0x1050, 0x0402)));
        assert_eq!(vid_pid_from_path(LOGITECH), Some((0x046d, 0xc52b)));
    }

    #[test]
    fn rejects_unparsable_paths() {
        assert_eq!(vid_pid_from_path(r"\\.\keyboard"), None);
        assert_eq!(vid_pid_from_path(""), None);
        assert_eq!(
            vid_pid_from_path(r"\\?\hid#unknown&pid?#{4d1e55b2-f16f-11cf-88cb-001111000030}"),
            None
        );
    }

    #[test]
    fn disabled_filter_matches_all() {
        assert!(matches_with(&[], YUBIKEY));
        assert!(matches_with(&[], LOGITECH));
        assert!(matches_with(&[], r"\\.\keyboard"));
    }

    #[test]
    fn exact_pair_matches_only_that_device() {
        let targets = [(0x1050u16, 0x0402u16)];
        assert!(matches_with(&targets, YUBIKEY));
        assert!(!matches_with(&targets, LOGITECH));
    }

    #[test]
    fn vid_only_sentinel_matches_any_pid_for_that_vid() {
        let targets = [(0x1050u16, 0u16)];
        assert!(matches_with(&targets, YUBIKEY));
        assert!(!matches_with(&targets, LOGITECH));
        // A non-Yubico device is still rejected even when it is a HID.
        let other = [(0x046du16, 0u16)];
        assert!(!matches_with(&other, YUBIKEY));
    }

    #[test]
    fn global_setter_is_idempotent_and_toggles_enabled() {
        // The only test that touches the global TARGET, so no cross-test race.
        set_target_devices(&[]);
        assert!(!is_enabled());
        set_target_devices(&[(0x1050, 0)]);
        assert!(is_enabled());
        assert!(matches(YUBIKEY));
        assert!(!matches(LOGITECH));
        // Cleanup: restore disabled so other test binaries/processes are clean.
        set_target_devices(&[]);
        assert!(!is_enabled());
    }
}
