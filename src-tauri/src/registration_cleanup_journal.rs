//! Per-user, non-secret receipts for a platform credential that could not be removed.
//! One create-new file per receipt: crashes during a write leave a conservative warning;
//! acknowledging only removes the selected receipt. No credential IDs or paths are stored;
//! file names (random IDs) and timestamps still reveal how many events occurred and when.
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Reason tags written to disk; anything else read back is reported as `unknown`.
const REASONS: [&str; 5] = [
    "expired",
    "locked",
    "implicit",
    "continue_error",
    "unverified",
];
/// A receipt holds only a short tag; larger content is treated as corrupt (`unknown`).
const MAX_RECEIPT_BYTES: u64 = 64;

#[derive(Clone, Debug)]
pub struct Record {
    pub id: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct Journal {
    root: PathBuf,
    #[cfg(test)]
    faults: std::sync::Arc<std::sync::Mutex<TestFaults>>,
}

/// Test-only I/O fault injection; compiled out of production builds.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct TestFaults {
    pub forced_ids: std::collections::VecDeque<[u8; 16]>,
    /// Fail right after `create_new`, before any byte is written (empty receipt).
    pub fail_after_create: bool,
    /// Write only the first N bytes of the tag, then fail (partial receipt).
    pub partial_write: Option<usize>,
    /// Write the whole tag, then fail where `sync_all` would run (unsynced receipt).
    pub fail_sync: bool,
}

impl Journal {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            #[cfg(test)]
            faults: Default::default(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(test)]
    pub fn faults(&self) -> std::sync::MutexGuard<'_, TestFaults> {
        self.faults.lock().unwrap()
    }

    fn valid_id(id: &str) -> bool {
        id.len() == 32
            && id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    fn path(&self, id: &str) -> io::Result<PathBuf> {
        if !Self::valid_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid cleanup receipt ID",
            ));
        }
        Ok(self.root.join(format!("{id}.receipt")))
    }

    fn next_id_bytes(&self) -> io::Result<[u8; 16]> {
        #[cfg(test)]
        if let Some(forced) = self.faults().forced_ids.pop_front() {
            return Ok(forced);
        }
        let mut random = [0_u8; 16];
        // Entropy failure is an I/O-style error (caller falls back to a warning), not a panic
        // that would poison the application state lock.
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| io::Error::other("entropy source unavailable"))?;
        Ok(random)
    }

    pub fn record(&self, reason: &str) -> io::Result<String> {
        if !REASONS.contains(&reason) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid cleanup reason",
            ));
        }
        fs::create_dir_all(&self.root)?;
        for _ in 0..8 {
            let id: String = self
                .next_id_bytes()?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.path(&id)?)
            {
                Ok(mut file) => {
                    let written = self.write_receipt(&mut file, reason);
                    // Do not remove the file if write/sync fails: the next start must
                    // conservatively show a warning for even an empty/partial receipt.
                    written?;
                    return Ok(id);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "receipt ID collision",
        ))
    }

    /// Single write path for a newly created receipt (test faults inject here).
    fn write_receipt(&self, file: &mut fs::File, reason: &str) -> io::Result<()> {
        #[cfg(test)]
        {
            let faults = self.faults();
            if faults.fail_after_create {
                return Err(io::Error::other("injected failure after create"));
            }
            if let Some(n) = faults.partial_write {
                let bytes = reason.as_bytes();
                file.write_all(&bytes[..n.min(bytes.len())])?;
                return Err(io::Error::other("injected partial write"));
            }
        }
        file.write_all(reason.as_bytes())?;
        #[cfg(test)]
        if self.faults().fail_sync {
            return Err(io::Error::other("injected sync failure"));
        }
        file.sync_all()
    }

    /// Bounded read through the opened handle (no metadata-then-read size race).
    fn read_reason(path: &Path) -> String {
        let mut content = Vec::new();
        let read = fs::File::open(path).and_then(|file| {
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "not a file"));
            }
            file.take(MAX_RECEIPT_BYTES + 1).read_to_end(&mut content)
        });
        match read {
            Ok(n) if n as u64 <= MAX_RECEIPT_BYTES => match std::str::from_utf8(&content) {
                Ok(value) if REASONS.contains(&value) => value.to_owned(),
                _ => "unknown".to_owned(),
            },
            _ => "unknown".to_owned(),
        }
    }

    pub fn list(&self) -> io::Result<Vec<Record>> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => return Err(error),
        };
        let mut records = Vec::new();
        for item in entries {
            let item = item?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            let Some(id) = name.strip_suffix(".receipt") else {
                continue;
            };
            if !Self::valid_id(id) {
                continue;
            }
            records.push(Record {
                id: id.to_owned(),
                // Partial, corrupt, oversize or unreadable receipts stay visible as `unknown`.
                reason: Self::read_reason(&item.path()),
            });
        }
        records.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(records)
    }

    pub fn ack(&self, id: &str) -> io::Result<()> {
        fs::remove_file(self.path(id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(tag: &str) -> PathBuf {
        let base = std::env::var_os("TMPDIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        base.join(format!(
            "d9f1-r4-journal-{tag}-{:016x}",
            rand::random::<u64>()
        ))
    }

    fn hex(bytes: [u8; 16]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn d9f1_r4_journal_id_collision_retries_then_fails_closed() {
        let dir = root("collision");
        let journal = Journal::new(dir.clone());
        let (a, b) = ([0xa1; 16], [0xb2; 16]);
        journal.faults().forced_ids.extend([a, a, b]);
        assert_eq!(journal.record("expired").unwrap(), hex(a));
        let second = journal.record("locked");
        assert!(
            matches!(&second, Ok(id) if *id == hex(b)),
            "collision must retry with a new ID, not overwrite or abort: {second:?}"
        );
        let records = journal.list().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].reason, "expired",
            "first receipt must not be overwritten"
        );
        journal.faults().forced_ids.extend([a; 8]);
        let exhausted = journal.record("implicit");
        assert!(
            matches!(&exhausted, Err(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "{exhausted:?}"
        );
        assert_eq!(journal.list().unwrap().len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    fn assert_failed_write_stays_visible(
        tag: &str,
        inject: impl FnOnce(&mut TestFaults),
        want: &str,
    ) {
        let dir = root(tag);
        let journal = Journal::new(dir.clone());
        inject(&mut journal.faults());
        assert!(
            journal.record("expired").is_err(),
            "{tag}: injected failure must surface"
        );
        let records = Journal::new(dir.clone()).list().unwrap();
        assert_eq!(
            records.len(),
            1,
            "{tag}: the failed receipt must stay visible"
        );
        assert_eq!(records[0].reason, want, "{tag}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn d9f1_r5_journal_failure_after_create_leaves_empty_unknown_receipt() {
        assert_failed_write_stays_visible(
            "after-create",
            |f| f.fail_after_create = true,
            "unknown",
        );
    }

    #[test]
    fn d9f1_r5_journal_partial_write_leaves_unknown_receipt() {
        assert_failed_write_stays_visible("partial", |f| f.partial_write = Some(3), "unknown");
    }

    #[test]
    fn d9f1_r5_journal_sync_failure_after_full_write_keeps_valid_receipt() {
        assert_failed_write_stays_visible("sync", |f| f.fail_sync = true, "expired");
    }

    #[test]
    fn d9f1_r4_journal_corrupt_oversize_and_non_file_receipts_stay_visible() {
        let dir = root("corrupt");
        fs::create_dir_all(&dir).unwrap();
        let ids = [hex([1; 16]), hex([2; 16]), hex([3; 16]), hex([4; 16])];
        fs::write(dir.join(format!("{}.receipt", ids[0])), b"zzz").unwrap();
        fs::write(dir.join(format!("{}.receipt", ids[1])), [b'x'; 100]).unwrap();
        fs::create_dir(dir.join(format!("{}.receipt", ids[2]))).unwrap();
        fs::write(dir.join(format!("{}.receipt", ids[3])), [0xff, 0xfe]).unwrap();
        // Names that are not valid receipt IDs are ignored, never acknowledged or parsed.
        fs::write(dir.join("ABCDEF.receipt"), b"expired").unwrap();
        fs::write(dir.join("notes.txt"), b"expired").unwrap();
        let records = Journal::new(dir.clone()).list().unwrap();
        assert_eq!(
            records.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
            ids.to_vec()
        );
        assert!(records.iter().all(|r| r.reason == "unknown"), "{records:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn d9f1_r4_journal_unreadable_root_is_an_error_not_an_empty_list() {
        let dir = root("root-file");
        fs::create_dir_all(dir.parent().unwrap()).unwrap();
        fs::write(&dir, b"not a directory").unwrap();
        assert!(Journal::new(dir.clone()).list().is_err());
        let _ = fs::remove_file(&dir);
        // A root that does not exist yet simply has no receipts.
        assert!(Journal::new(root("absent")).list().unwrap().is_empty());
    }

    #[test]
    fn d9f1_r4_journal_ack_rejects_malformed_and_unknown_ids() {
        let dir = root("ack");
        let journal = Journal::new(dir.clone());
        let id = journal.record("locked").unwrap();
        let upper = id.to_uppercase();
        let long = format!("{id}0");
        for bad in ["../escape", "", upper.as_str(), &id[..31], long.as_str()] {
            let result = journal.ack(bad);
            assert!(
                matches!(&result, Err(e) if e.kind() == io::ErrorKind::InvalidInput),
                "{bad}: {result:?}"
            );
        }
        assert!(
            journal.ack(&hex([9; 16])).is_err(),
            "unknown valid ID is not silently accepted"
        );
        assert_eq!(journal.list().unwrap().len(), 1);
        journal.ack(&id).unwrap();
        assert!(journal.list().unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
