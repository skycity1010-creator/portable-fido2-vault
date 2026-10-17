//! Lock-overlap Case B 診斷探針（feature `lock-overlap-diag`，預設關閉；不新增 command／listener）。
//!
//! Case B = **post-native/pre-publication**：單人版 `login_any_key` 的 roaming 登入已由 backend 回傳
//! PRF 並成功解開金庫之後、`KeyOperationGuard::complete_login` 發布結果之前，由內部 worker 呼叫
//! 與 `lock` command 相同的 `lock_inner_at`，確認 `key_op.pending_lock` 已收件後才放行既有發布流程。
//! 本探針不是 Case A（native 等待中收件），也不觀察 FFI 本身：`native_success` 只由
//! 「brokered backend＋roaming 槽位經 AES-GCM 驗證解開」推論，收據明確標為 `ffi_observed=false`。
//!
//! Arm（每個行程最多一次）需要：顯式命令列旗標 `--lock-overlap-diag-case-b`、固定診斷執行檔名、
//! `lock-overlap-diag-*` 專用資料夾、內容固定的 fixture marker、本機磁碟路徑（非 UNC／reparse／
//! FidoVault 安裝目錄）、hardware backend 與單人版。任何一項不符：行程拒絕啟動（不碰金庫）。
//! Arm 只會被下一個 `login_any_key` 取走一次（其他入口不碰 arm）；結果一律寫入 exclusive-create
//! 收據，收據只含 case／generation／事件序／布林／類別／條目數，不含任何秘密或身分。
//!
//! Worker 為同步 scoped thread：`pre_publication` 返回前必定 join，因此 worker 不可能延續到下一個
//! 操作；ack 等待逾時只把本次標為握手失敗並丟棄已開啟的金庫（fail closed），join 仍無條件進行，
//! 而 worker 的上鎖要求（若遲到）仍落在同一個 `key_op.active` 期間，由同一 guard 消化。
//! 10 秒 ack 時限只是判定時限，不保證命令總時長。
//!
//! Fixture 隔離：vault.db 與 marker 須為一般檔案、非 reparse，且（由 handle 取得的）NTFS 連結數
//! 恰為 1（擋 hardlink）；arm 時記下 root／marker／vault.db／收據資料夾的 file identity，並以不含
//! DELETE share 的 handle 釘住 root 與收據資料夾（無法被改名或換成 junction；不影響資料夾內的
//! 金庫 tmp+rename 儲存）直到本次診斷結束。`Probe::claim` 在任何 ceremony 前重新檢查祖先 reparse、
//! identity、連結數與 marker 內容；任何不符：消耗 arm、不碰金鑰、fail closed，且只在收據資料夾
//! 仍通過驗證時才寫拒絕收據。合法的金庫儲存（tmp+rename）同樣會改變 identity，因此 arm 之後必須
//! 先做 `login_any_key`，否則本次診斷會判 INCONCLUSIVE_FIXTURE_CHANGED。
//! 殘餘限制：重新檢查之後到 `open_any_key` 讀檔之間，同一使用者的惡意程序仍可即時換掉 vault.db
//! 本身（檔案不釘，否則會擋住正常儲存）；本探針不宣稱消除檢查後的路徑競態。
//! Marker 只證明操作者把資料夾標成診斷 fixture，**不能**證明 vault.db 內容是合成資料：
//! 合成金庫副本必須由使用者另行建立並記錄步驟。

use super::{edition, vault, Result, VaultState};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 唯一啟用旗標（命令列）；沒有它，即使 feature 編入也不 arm。
pub(crate) const ARM_FLAG: &str = "--lock-overlap-diag-case-b";
/// 固定診斷執行檔名（Release 交付時須以此名稱放入專用資料夾）。
pub(crate) const DIAG_EXE_NAME: &str = "fidovault-lock-overlap-diag.exe";
/// 專用 fixture 資料夾名稱前綴。
pub(crate) const FIXTURE_DIR_PREFIX: &str = "lock-overlap-diag-";
pub(crate) const MARKER_FILE: &str = "LOCK-OVERLAP-DIAG-FIXTURE.marker";
/// Marker 內容：只有固定版本與 case ID（不含任何金庫身分）。
pub(crate) const MARKER_CONTENT: &str = "fidovault-lock-overlap-diag-fixture/v1 case=B";
pub(crate) const RECEIPT_DIR: &str = "lock-overlap-diag-receipts";
const RECEIPT_SCHEMA: &str = "fidovault-lock-overlap-diag-receipt/v2";
const ARM_TTL: Duration = Duration::from_secs(15 * 60);
/// 握手判定時限：只決定「本次是否視為握手失敗」，**不保證**命令總時長。scope 一定 join
/// worker；若 `lock_inner_at` 本身卡住（例如 state mutex 長期被占用），命令會一直等到它返回。
const WORKER_ACK_TIMEOUT: Duration = Duration::from_secs(10);
const ARM_REJECTED_EXIT_CODE: i32 = 78;

pub(crate) const DIAG_REJECTED_MSG: &str =
    "Lock-overlap 診斷：本次 arm 已失效、路徑不符或後端不符，已丟棄登入結果；請重新啟動診斷";
pub(crate) const DIAG_RECEIPT_MSG: &str =
    "Lock-overlap 診斷：無法寫入診斷收據，未發布登入結果";
pub(crate) const DIAG_HANDSHAKE_MSG: &str =
    "Lock-overlap 診斷：上鎖握手未確認，已丟棄登入結果";

/// Fixture 驗證失敗原因（固定字串，不含路徑）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reject {
    NotLocalDrivePath,
    RelativeOrDotComponent,
    ProductionInstallPath,
    WrongExecutableName,
    NotDedicatedFixtureDir,
    ReparseOrSymlink,
    /// vault.db 或 marker 的 NTFS 連結數不是 1（可能是指向 fixture 以外檔案的 hardlink）。
    HardLinked,
    CanonicalMismatch,
    MarkerMissingOrInvalid,
    VaultMissing,
    ReceiptDirUnusable,
    NotSingleEdition,
    NotHardwareBackend,
    RepeatedArm,
    Unsupported,
}

/// Arm 時驗證過的 fixture，連同從 handle 取得的 identity；claim 時逐項重新比對。
#[derive(Debug)]
pub(crate) struct Fixture {
    pub(crate) vault_path: PathBuf,
    pub(crate) receipt_dir: PathBuf,
    root: PathBuf,
    root_id: FileId,
    marker_id: FileId,
    vault_id: FileId,
    receipt_id: FileId,
    /// Root 與收據資料夾的釘選 handle（見 `pinned_dir`），從 arm 持有到本次診斷結束。
    pins: Vec<std::fs::File>,
}

// ─────────────────────────── fixture validation ───────────────────────────

/// 純字面檢查（不碰檔案系統）：本機磁碟絕對路徑、無 `.`/`..`、無 FidoVault 安裝目錄元件、
/// 固定執行檔名、專用資料夾名稱。
fn lexical_checks(exe: &Path) -> std::result::Result<(), Reject> {
    use std::path::{Component, Prefix};
    let mut components = exe.components();
    match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {}
            _ => return Err(Reject::NotLocalDrivePath),
        },
        _ => return Err(Reject::NotLocalDrivePath),
    }
    if components.next() != Some(Component::RootDir) {
        return Err(Reject::NotLocalDrivePath);
    }
    for component in components {
        match component {
            Component::Normal(name) => {
                if name.eq_ignore_ascii_case("FidoVault") {
                    return Err(Reject::ProductionInstallPath);
                }
            }
            _ => return Err(Reject::RelativeOrDotComponent),
        }
    }
    let exe_name = exe.file_name().ok_or(Reject::WrongExecutableName)?;
    if !exe_name.eq_ignore_ascii_case(DIAG_EXE_NAME) {
        return Err(Reject::WrongExecutableName);
    }
    let dir_name = exe
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .ok_or(Reject::NotDedicatedFixtureDir)?;
    let suffix = dir_name
        .strip_prefix(FIXTURE_DIR_PREFIX)
        .ok_or(Reject::NotDedicatedFixtureDir)?;
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Reject::NotDedicatedFixtureDir);
    }
    Ok(())
}

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

fn is_reparse_attribute(attributes: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn is_link_or_reparse(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_type().is_symlink() || is_reparse_attribute(meta.file_attributes())
}

#[cfg(not(windows))]
fn is_link_or_reparse(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// 一般檔案（非 link／reparse）；其他一律視為不存在。只用於執行檔（不檢查連結數）。
fn plain_file(path: &Path) -> Option<std::fs::Metadata> {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|meta| meta.is_file() && !is_link_or_reparse(meta))
}

// ── handle 層級的檔案事實（S1/S2）：不跟隨 reparse point，從已開啟的 handle 取得連結數與 identity ──

/// 檔案 identity：volume serial + NTFS file index（同一 volume 內唯一）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileId {
    volume: u32,
    index: u64,
}

struct HandleFacts {
    attributes: u32,
    links: u32,
    id: FileId,
}

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// FILE_READ_DATA（目錄上為 FILE_LIST_DIRECTORY）。
const FILE_READ_DATA: u32 = 0x1;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_SHARE_READ_WRITE: u32 = 0x1 | 0x2;
const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    /// BY_HANDLE_FILE_INFORMATION
    #[repr(C)]
    #[derive(Default)]
    pub(super) struct ByHandleFileInformation {
        pub(super) attributes: u32,
        pub(super) times: [u32; 6],
        pub(super) volume_serial: u32,
        pub(super) size_high: u32,
        pub(super) size_low: u32,
        pub(super) links: u32,
        pub(super) index_high: u32,
        pub(super) index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub(super) fn GetFileInformationByHandle(
            file: *mut c_void,
            info: *mut ByHandleFileInformation,
        ) -> i32;
    }
}

/// 以 `FILE_FLAG_OPEN_REPARSE_POINT` 開啟（handle 指向 link 本身，不跟隨到目標）。
#[cfg(windows)]
fn open_no_follow(path: &Path, access: u32, share: u32) -> Option<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .ok()
}

#[cfg(not(windows))]
fn open_no_follow(_: &Path, _: u32, _: u32) -> Option<std::fs::File> {
    None
}

#[cfg(windows)]
fn handle_facts(file: &std::fs::File) -> Option<HandleFacts> {
    use std::os::windows::io::AsRawHandle;
    let mut info = win::ByHandleFileInformation::default();
    // SAFETY: `file` owns a valid open handle for the duration of the call and `info` is a
    // correctly laid out BY_HANDLE_FILE_INFORMATION out-parameter.
    let ok = unsafe { win::GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    (ok != 0).then(|| HandleFacts {
        attributes: info.attributes,
        links: info.links,
        id: FileId {
            volume: info.volume_serial,
            index: (u64::from(info.index_high) << 32) | u64::from(info.index_low),
        },
    })
}

#[cfg(not(windows))]
fn handle_facts(_: &std::fs::File) -> Option<HandleFacts> {
    None
}

enum NotPlain {
    Missing,
    HardLinked,
}

/// 一般檔案、非 reparse、非目錄、連結數恰為 1；回傳同一個 handle 與其 identity。
/// share mode 含 DELETE：檢查用 handle 不阻擋金庫的 tmp+rename 儲存。
fn open_single_link_file(
    path: &Path,
    access: u32,
) -> std::result::Result<(std::fs::File, FileId), NotPlain> {
    let file = open_no_follow(path, access | FILE_READ_ATTRIBUTES, FILE_SHARE_ALL)
        .ok_or(NotPlain::Missing)?;
    let facts = handle_facts(&file).ok_or(NotPlain::Missing)?;
    if is_reparse_attribute(facts.attributes) || facts.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(NotPlain::Missing);
    }
    if facts.links != 1 {
        return Err(NotPlain::HardLinked);
    }
    Ok((file, facts.id))
}

/// Marker：同一個 handle 上檢查（plain、連結數 1）並讀取內容（<=128 B）。
fn marker_identity(path: &Path) -> std::result::Result<FileId, Reject> {
    use std::io::Read;
    let (file, id) = open_single_link_file(path, FILE_READ_DATA).map_err(|e| match e {
        NotPlain::Missing => Reject::MarkerMissingOrInvalid,
        NotPlain::HardLinked => Reject::HardLinked,
    })?;
    let mut bytes = Vec::new();
    file.take(129)
        .read_to_end(&mut bytes)
        .map_err(|_| Reject::MarkerMissingOrInvalid)?;
    let valid = bytes.len() <= 128
        && std::str::from_utf8(&bytes).is_ok_and(|text| text.trim_end() == MARKER_CONTENT);
    if valid {
        Ok(id)
    } else {
        Err(Reject::MarkerMissingOrInvalid)
    }
}

fn vault_identity(path: &Path) -> std::result::Result<FileId, Reject> {
    open_single_link_file(path, 0)
        .map(|(_, id)| id)
        .map_err(|e| match e {
            NotPlain::Missing => Reject::VaultMissing,
            NotPlain::HardLinked => Reject::HardLinked,
        })
}

fn plain_dir_id(file: &std::fs::File) -> Option<FileId> {
    let facts = handle_facts(file)?;
    (facts.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && !is_reparse_attribute(facts.attributes))
        .then_some(facts.id)
}

/// 非 reparse 的目錄（handle 指向目錄本身）；回傳其 identity。
fn dir_identity(path: &Path) -> Option<FileId> {
    plain_dir_id(&open_no_follow(path, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL)?)
}

/// 目錄釘選：FILE_LIST_DIRECTORY 存取＋share READ|WRITE（不含 DELETE）。持有期間該目錄本身
/// 無法被改名或刪除（因此無法被換成 junction），但目錄內的建立／改名（金庫 tmp+rename 儲存、
/// 收據建立）不受影響。vault.db 本身不釘：不含 DELETE 的 handle 會擋住正常的 rename 儲存。
fn pinned_dir(path: &Path) -> Option<(std::fs::File, FileId)> {
    let file = open_no_follow(path, FILE_READ_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ_WRITE)?;
    let id = plain_dir_id(&file)?;
    Some((file, id))
}

/// 路徑本身與每一層祖先（到磁碟根為止）都不是 symlink／junction／reparse point。
fn ancestors_plain(path: &Path) -> bool {
    path.ancestors()
        .take_while(|ancestor| ancestor.file_name().is_some())
        .all(|ancestor| {
            std::fs::symlink_metadata(ancestor).is_ok_and(|meta| !is_link_or_reparse(&meta))
        })
}

impl Fixture {
    /// 收據資料夾仍是 arm 時的那一個（同 identity、非 reparse、祖先皆非 reparse）。
    fn receipt_dir_intact(&self) -> bool {
        ancestors_plain(&self.receipt_dir)
            && dir_identity(&self.receipt_dir) == Some(self.receipt_id)
    }

    /// Root、marker、vault.db 仍是 arm 時驗證的那些檔案（同 identity、plain、連結數 1）。
    /// 金庫任何一次合法儲存（tmp+rename）也會改變 identity：同樣 fail closed。
    fn files_intact(&self) -> bool {
        ancestors_plain(&self.root)
            && dir_identity(&self.root) == Some(self.root_id)
            && marker_identity(&self.root.join(MARKER_FILE)).ok() == Some(self.marker_id)
            && vault_identity(&self.vault_path).ok() == Some(self.vault_id)
    }
}

fn normalized(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text).to_string();
    text.trim_end_matches('\\').to_string()
}

/// 候選 root（執行檔所在的專用資料夾）檢查：字面、每一層 reparse、canonical 一致、marker、
/// vault.db、收據資料夾。只讀取該資料夾內的 marker；收據資料夾不存在時建立。
pub(crate) fn validate_fixture(exe: &Path) -> std::result::Result<Fixture, Reject> {
    if !cfg!(windows) {
        return Err(Reject::Unsupported);
    }
    lexical_checks(exe)?;
    let dir = exe.parent().ok_or(Reject::NotDedicatedFixtureDir)?;
    if !ancestors_plain(exe) {
        return Err(Reject::ReparseOrSymlink);
    }
    if plain_file(exe).is_none() {
        return Err(Reject::WrongExecutableName);
    }
    let canonical = std::fs::canonicalize(dir).map_err(|_| Reject::CanonicalMismatch)?;
    let canonical = normalized(&canonical);
    if canonical.starts_with("UNC\\") || !canonical.eq_ignore_ascii_case(&normalized(dir)) {
        return Err(Reject::CanonicalMismatch);
    }
    let (root_pin, root_id) = pinned_dir(dir).ok_or(Reject::ReparseOrSymlink)?;
    let marker_id = marker_identity(&dir.join(MARKER_FILE))?;
    let vault_path = dir.join("vault.db");
    let vault_id = vault_identity(&vault_path)?;
    let receipt_dir = dir.join(RECEIPT_DIR);
    match std::fs::create_dir(&receipt_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(Reject::ReceiptDirUnusable),
    }
    let receipt_meta =
        std::fs::symlink_metadata(&receipt_dir).map_err(|_| Reject::ReceiptDirUnusable)?;
    if !receipt_meta.is_dir() || is_link_or_reparse(&receipt_meta) {
        return Err(Reject::ReceiptDirUnusable);
    }
    let (receipt_pin, receipt_id) = pinned_dir(&receipt_dir).ok_or(Reject::ReceiptDirUnusable)?;
    Ok(Fixture {
        vault_path,
        receipt_dir,
        root: dir.to_path_buf(),
        root_id,
        marker_id,
        vault_id,
        receipt_id,
        pins: vec![root_pin, receipt_pin],
    })
}

/// 命令列：旗標恰好出現一次 → Some(true)；未出現 → Some(false)；重複 → None（拒絕）。
pub(crate) fn flag_requested<I: IntoIterator<Item = std::ffi::OsString>>(args: I) -> Option<bool> {
    match args.into_iter().skip(1).filter(|arg| arg == ARM_FLAG).count() {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

// ─────────────────────────── controller ───────────────────────────

struct Arm {
    generation: u64,
    deadline: Instant,
    fixture: Fixture,
}

#[derive(Default)]
struct Slot {
    arm: Option<Arm>,
    armed_once: bool,
    generation: u64,
    inflight: Option<u64>,
}

/// 一個行程（或一個測試）的 arm 狀態。arm 至多一次；被取走即消耗。
pub(crate) struct Controller {
    slot: Mutex<Slot>,
    ack_timeout: Duration,
    #[cfg(test)]
    seams: test_seams::Seams,
}

enum Taken {
    Ready { generation: u64, fixture: Fixture },
    Rejected {
        generation: u64,
        fixture: Fixture,
        outcome: &'static str,
    },
}

impl Controller {
    pub(crate) fn new() -> Self {
        Self::with_ack_timeout(WORKER_ACK_TIMEOUT)
    }

    pub(crate) fn with_ack_timeout(ack_timeout: Duration) -> Self {
        Self {
            slot: Mutex::new(Slot::default()),
            ack_timeout,
            #[cfg(test)]
            seams: Default::default(),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Arm 一次（重複 arm 拒絕，即使前一次已被消耗）。
    pub(crate) fn arm(
        &self,
        fixture: Fixture,
        now: Instant,
        ttl: Duration,
    ) -> std::result::Result<u64, Reject> {
        let mut slot = self.slot();
        if slot.armed_once {
            return Err(Reject::RepeatedArm);
        }
        slot.armed_once = true;
        slot.generation = slot.generation.wrapping_add(1);
        let generation = slot.generation;
        slot.arm = Some(Arm {
            generation,
            deadline: now + ttl,
            fixture,
        });
        Ok(generation)
    }

    #[cfg(test)]
    pub(crate) fn is_armed(&self) -> bool {
        self.slot().arm.is_some()
    }

    /// 取走 arm（一次性）。逾時或路徑不符：仍消耗，回 Rejected（不得留給下一個請求）。
    fn take_arm(&self, path: &Path, now: Instant) -> Option<Taken> {
        let mut slot = self.slot();
        let arm = slot.arm.take()?;
        let outcome = if now >= arm.deadline {
            Some("INCONCLUSIVE_ARM_EXPIRED")
        } else if path != arm.fixture.vault_path {
            Some("INCONCLUSIVE_PATH_MISMATCH")
        } else {
            None
        };
        Some(match outcome {
            Some(outcome) => Taken::Rejected {
                generation: arm.generation,
                fixture: arm.fixture,
                outcome,
            },
            None => Taken::Ready {
                generation: arm.generation,
                fixture: arm.fixture,
            },
        })
    }

    fn begin_inflight(&self, generation: u64) {
        self.slot().inflight = Some(generation);
    }

    fn is_inflight(&self, generation: u64) -> bool {
        self.slot().inflight == Some(generation)
    }

    fn clear_inflight(&self, generation: u64) {
        let mut slot = self.slot();
        if slot.inflight == Some(generation) {
            slot.inflight = None;
        }
    }

    /// Test-only: drop the armed directory pins so a test can swap a directory after arm and
    /// exercise claim-time re-verification on its own (the pins would otherwise block the swap).
    #[cfg(all(test, not(feature = "dual-control")))]
    fn release_pins_for_test(&self) {
        if let Some(arm) = self.slot().arm.as_mut() {
            arm.fixture.pins.clear();
        }
    }
}

static PROCESS_CONTROLLER: OnceLock<Arc<Controller>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_CONTROLLER: std::cell::RefCell<Option<Arc<Controller>>> =
        const { std::cell::RefCell::new(None) };
}

/// 目前的 controller。測試只看本 thread 的覆寫，絕不讀行程級 controller。
fn current() -> Option<Arc<Controller>> {
    #[cfg(test)]
    {
        TEST_CONTROLLER.with(|c| c.borrow().clone())
    }
    #[cfg(not(test))]
    {
        PROCESS_CONTROLLER.get().cloned()
    }
}

/// 行程啟動時呼叫一次：沒有旗標 → 不做任何事；有旗標 → 全部檢查通過才 arm，否則拒絕啟動。
pub(crate) fn arm_from_process() {
    match arm_from(
        std::env::args_os(),
        std::env::current_exe().ok(),
        hardware_backend_selected(),
        edition::current(),
    ) {
        Ok(None) => {}
        Ok(Some(controller)) => {
            if PROCESS_CONTROLLER.set(controller).is_err() {
                reject_start(Reject::RepeatedArm);
            }
        }
        Err(reason) => reject_start(reason),
    }
}

fn reject_start(reason: Reject) -> ! {
    eprintln!("lock-overlap-diag: arming rejected ({reason:?}); no vault was touched");
    std::process::exit(ARM_REJECTED_EXIT_CODE)
}

fn hardware_backend_selected() -> bool {
    super::resolve_backend_mode(
        std::env::var("F2V_AUTHENTICATOR").ok().as_deref(),
        cfg!(debug_assertions),
        cfg!(feature = "real-ctap"),
        cfg!(feature = "mock-fido"),
    )
    .is_ok_and(|mode| matches!(mode, super::BackendMode::Hardware))
}

/// 可測試的 arm 決策（不設定行程級狀態）。
pub(crate) fn arm_from<I: IntoIterator<Item = std::ffi::OsString>>(
    args: I,
    exe: Option<PathBuf>,
    hardware: bool,
    ed: edition::Edition,
) -> std::result::Result<Option<Arc<Controller>>, Reject> {
    match flag_requested(args) {
        Some(false) => return Ok(None),
        None => return Err(Reject::RepeatedArm),
        Some(true) => {}
    }
    if ed != edition::Edition::Single {
        return Err(Reject::NotSingleEdition);
    }
    if !hardware {
        return Err(Reject::NotHardwareBackend);
    }
    let fixture = validate_fixture(&exe.ok_or(Reject::NotLocalDrivePath)?)?;
    let controller = Arc::new(Controller::new());
    controller.arm(fixture, Instant::now(), ARM_TTL)?;
    Ok(Some(controller))
}

// ─────────────────────────── receipt ───────────────────────────

#[derive(serde::Serialize)]
struct Event {
    seq: u32,
    event: &'static str,
}

#[derive(serde::Serialize)]
struct NativeSuccess {
    value: bool,
    source: &'static str,
    ffi_observed: bool,
}

/// 實際由 `VaultState` 觀測到的值，或明確標示未觀測（拒絕／中止路徑不得假報 true）。
#[derive(serde::Serialize)]
#[serde(untagged)]
enum Observed {
    Value(bool),
    NotObserved(&'static str),
}

const NOT_OBSERVED: Observed = Observed::NotObserved("not_observed");

/// 收據欄位全為固定字串／布林／數字：型別上不可能帶入秘密、credential ID 或條目內容。
#[derive(serde::Serialize)]
struct Receipt {
    schema: &'static str,
    case: &'static str,
    phase: &'static str,
    generation: u64,
    events: Vec<Event>,
    native_success: NativeSuccess,
    /// UV 種類（Bio／PIN）與 transport 不在 app 可觀測範圍：只能由操作者另行人工記錄。
    user_verification: &'static str,
    lock_received: bool,
    /// Worker join 之後才取的快照（不是上鎖瞬間的值）。
    key_op_active_after_worker_join: bool,
    pending_lock_after_worker_join: bool,
    response_category: &'static str,
    entry_count: usize,
    vault_locked: Observed,
    key_op_idle: Observed,
    outcome: &'static str,
    hardware_verified: bool,
}

const NATIVE_SOURCE: &str = "inferred:brokered-backend+authenticated-roaming-open";
const USER_VERIFICATION: &str = "not_observed:operator-must-report-bio-or-pin";

fn receipt_name(generation: u64) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!(
        "case-b-{nanos}-g{generation}-p{}.json",
        std::process::id()
    )
}

/// Exclusive create：已存在的檔案（含歷史收據）絕不覆寫。
fn create_receipt(dir: &Path, name: &str) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(name))
}

// ─────────────────────────── probe ───────────────────────────

struct Active {
    controller: Arc<Controller>,
    generation: u64,
    file: Option<std::fs::File>,
    /// Directory pins carried over from the arm; released when this attempt ends.
    _pins: Vec<std::fs::File>,
    events: Vec<Event>,
    authenticated_open: bool,
    brokered: bool,
    lock_received: bool,
    active_after_join: bool,
    pending_after_join: bool,
    handshake_failed: bool,
    concluded: bool,
}

impl Active {
    fn event(&mut self, event: &'static str) {
        let seq = self.events.len() as u32 + 1;
        self.events.push(Event { seq, event });
    }

    fn receipt(
        &mut self,
        response_category: &'static str,
        entry_count: usize,
        vault_locked: Observed,
        key_op_idle: Observed,
        outcome: &'static str,
    ) -> Receipt {
        Receipt {
            schema: RECEIPT_SCHEMA,
            case: "B",
            phase: "post-native/pre-publication",
            generation: self.generation,
            events: std::mem::take(&mut self.events),
            native_success: NativeSuccess {
                value: self.authenticated_open && self.brokered,
                source: NATIVE_SOURCE,
                ffi_observed: false,
            },
            user_verification: USER_VERIFICATION,
            lock_received: self.lock_received,
            key_op_active_after_worker_join: self.active_after_join,
            pending_lock_after_worker_join: self.pending_after_join,
            response_category,
            entry_count,
            vault_locked,
            key_op_idle,
            outcome,
            hardware_verified: false,
        }
    }

    fn write(&mut self, receipt: &Receipt) -> std::io::Result<()> {
        use std::io::Write;
        #[cfg(test)]
        if self.controller.seams.fail_final_write() {
            return Err(std::io::Error::other("synthetic receipt write failure"));
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("receipt file missing"))?;
        let bytes = serde_json::to_vec_pretty(receipt).map_err(std::io::Error::other)?;
        file.write_all(&bytes)?;
        file.sync_all()
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        if self.concluded {
            return;
        }
        // Panic or early exit between claim and conclusion: record it as aborted, never success.
        self.event("aborted");
        let receipt = self.receipt("none", 0, NOT_OBSERVED, NOT_OBSERVED, "INCONCLUSIVE_ABORTED");
        let _ = self.write(&receipt);
        self.controller.clear_inflight(self.generation);
    }
}

/// `login_any_key_inner` 內的 Case B 探針。未 arm 時三個 hook 都是原樣傳遞。
pub(super) struct Probe {
    active: Option<Active>,
}

struct Snapshot {
    key_op_active: bool,
    pending_lock: bool,
    vault_locked: bool,
}

fn snapshot(state: &VaultState) -> Snapshot {
    let g = super::lock_state_tolerant(state);
    Snapshot {
        key_op_active: g.key_op.active,
        pending_lock: g.key_op.pending_lock.is_some(),
        vault_locked: g.vault.is_none(),
    }
}

/// Worker 本體：只在自己那一代仍在進行時呼叫 **同一個** `lock_inner_at`。
/// None = 拒絕（舊代／已結束）；Some(ok) = lock_inner_at 的結果。
fn worker_lock(
    controller: &Controller,
    generation: u64,
    state: &VaultState,
    path: &Path,
) -> Option<bool> {
    if !controller.is_inflight(generation) {
        return None;
    }
    Some(super::lock_inner_at(state, None, path, edition::Edition::Single).is_ok())
}

impl Probe {
    const INACTIVE: Self = Self { active: None };

    /// 在 `begin_login` 取得 guard 之後呼叫：只有本入口會取走 arm。
    pub(super) fn claim(path: &Path) -> Result<Self> {
        let Some(controller) = current() else {
            return Ok(Self::INACTIVE);
        };
        if edition::current() != edition::Edition::Single {
            return Ok(Self::INACTIVE);
        }
        match controller.take_arm(path, Instant::now()) {
            None => Ok(Self::INACTIVE),
            Some(Taken::Rejected {
                generation,
                fixture,
                outcome,
            }) => Err(Self::refuse(controller, generation, &fixture, outcome)),
            Some(Taken::Ready {
                generation,
                fixture,
            }) => {
                // The arm may be up to ARM_TTL old: re-verify everything the ceremony and the
                // receipt will touch before any of it runs. The arm is already consumed here.
                if !fixture.receipt_dir_intact() {
                    // Unverified receipt location: write nothing anywhere, never touch the key.
                    return Err(DIAG_RECEIPT_MSG.to_string());
                }
                if !fixture.files_intact() {
                    return Err(Self::refuse(
                        controller,
                        generation,
                        &fixture,
                        "INCONCLUSIVE_FIXTURE_CHANGED",
                    ));
                }
                match create_receipt(&fixture.receipt_dir, &receipt_name(generation)) {
                    Ok(file) => {
                        controller.begin_inflight(generation);
                        let mut active = Self::new_active(controller, generation, Some(file));
                        active._pins = fixture.pins;
                        active.event("claimed");
                        Ok(Self {
                            active: Some(active),
                        })
                    }
                    // No receipt → no ceremony, no secret: fail closed before the backend.
                    Err(_) => Err(DIAG_RECEIPT_MSG.to_string()),
                }
            }
        }
    }

    /// Consumed and refused before any ceremony. Best-effort receipt, written only into a
    /// receipt directory that still verifies as the one checked at arm time.
    fn refuse(
        controller: Arc<Controller>,
        generation: u64,
        fixture: &Fixture,
        outcome: &'static str,
    ) -> String {
        let file = if fixture.receipt_dir_intact() {
            create_receipt(&fixture.receipt_dir, &receipt_name(generation)).ok()
        } else {
            None
        };
        let mut active = Self::new_active(controller, generation, file);
        active.event("claimed");
        active.event("arm_rejected");
        active.concluded = true;
        let receipt = active.receipt("diag_rejected", 0, NOT_OBSERVED, NOT_OBSERVED, outcome);
        let _ = active.write(&receipt);
        DIAG_REJECTED_MSG.to_string()
    }

    fn new_active(
        controller: Arc<Controller>,
        generation: u64,
        file: Option<std::fs::File>,
    ) -> Active {
        Active {
            controller,
            generation,
            file,
            _pins: Vec::new(),
            events: Vec::new(),
            authenticated_open: false,
            brokered: false,
            lock_received: false,
            active_after_join: false,
            pending_after_join: false,
            handshake_failed: false,
            concluded: false,
        }
    }

    /// Pre-publication gate：已開啟的金庫尚未交給 `complete_login`，`key_op.active` 仍為 true。
    pub(super) fn pre_publication(
        &mut self,
        state: &VaultState,
        path: &Path,
        brokered: bool,
        opened: Result<vault::Vault>,
    ) -> Result<vault::Vault> {
        let Some(active) = self.active.as_mut() else {
            return opened;
        };
        active.brokered = brokered;
        let v = match opened {
            Ok(v) => v,
            Err(error) => {
                // Native failure / cancellation / wrong key: nothing to discard, never success.
                active.event("native_or_open_failed");
                return Err(error);
            }
        };
        active.authenticated_open = true;
        active.event("authenticated_open_success");
        if !brokered {
            active.event("non_brokered_backend");
            drop(v.lock());
            return Err(DIAG_REJECTED_MSG.to_string());
        }
        active.event("pre_publication_gate_entered");
        if !snapshot(state).key_op_active {
            active.handshake_failed = true;
            active.event("handshake_failed");
            drop(v.lock());
            return Err(DIAG_HANDSHAKE_MSG.to_string());
        }
        #[cfg(test)]
        active.controller.seams.run_gate_hook();
        active.event("lock_requested");
        let controller = Arc::clone(&active.controller);
        let generation = active.generation;
        #[cfg(test)]
        let generation = generation.wrapping_add(controller.seams.worker_generation_skew());
        let ack_timeout = controller.ack_timeout;
        let (tx, rx) = std::sync::mpsc::channel();
        let ack = std::thread::scope(|scope| {
            scope.spawn(|| {
                #[cfg(test)]
                controller.seams.before_worker();
                let outcome = worker_lock(&controller, generation, state, path);
                #[cfg(test)]
                controller.seams.worker_finished();
                let _ = tx.send(outcome);
            });
            let ack = rx.recv_timeout(ack_timeout);
            // Leaving the scope joins the worker unconditionally (even after a timeout).
            ack
        });
        active.event("worker_joined");
        let seen = snapshot(state);
        active.active_after_join = seen.key_op_active;
        active.pending_after_join = seen.pending_lock;
        if matches!(ack, Ok(Some(true))) && seen.key_op_active && seen.pending_lock {
            active.lock_received = true;
            active.event("lock_received");
            active.event("gate_released");
            #[cfg(test)]
            active.controller.seams.run_after_gate_released();
            Ok(v)
        } else {
            active.handshake_failed = true;
            active.event("handshake_failed");
            drop(v.lock());
            Err(DIAG_HANDSHAKE_MSG.to_string())
        }
    }

    /// `complete_login` 之後：記錄最終狀態並寫入收據；寫入失敗時絕不放行條目。
    pub(super) fn conclude(
        mut self,
        state: &VaultState,
        path: &Path,
        result: Result<Vec<vault::Entry>>,
    ) -> Result<Vec<vault::Entry>> {
        let Some(mut active) = self.active.take() else {
            return result;
        };
        #[cfg(test)]
        active.controller.seams.run_before_conclude();
        let seen = snapshot(state);
        let key_op_idle = !seen.key_op_active && !seen.pending_lock;
        let (category, entry_count) = match &result {
            Ok(entries) => ("entries", entries.len()),
            Err(message) if message == super::KEY_OPERATION_LOCKED_MSG => ("lock_error", 0),
            Err(message) if message.starts_with("Lock-overlap 診斷") => ("diag_failed", 0),
            Err(_) => ("other_error", 0),
        };
        let outcome = if active.handshake_failed {
            "INCONCLUSIVE_HANDSHAKE_FAILED"
        } else if !active.authenticated_open {
            "INCONCLUSIVE_NATIVE_OR_OPEN_FAILED"
        } else if !active.brokered {
            "INCONCLUSIVE_NON_BROKERED_BACKEND"
        } else if !active.lock_received {
            "INCONCLUSIVE_HANDSHAKE_FAILED"
        } else if category == "entries" {
            "FAIL_ENTRIES_RETURNED_AFTER_LOCK"
        } else if category == "lock_error" && seen.vault_locked && key_op_idle {
            "CASE_B_RESPONSE_DISCARDED"
        } else {
            "FAIL_STATE_AFTER_LOCK"
        };
        active.event("concluded");
        active.concluded = true;
        let receipt = active.receipt(
            category,
            entry_count,
            Observed::Value(seen.vault_locked),
            Observed::Value(key_op_idle),
            outcome,
        );
        let written = active.write(&receipt);
        active.controller.clear_inflight(active.generation);
        match written {
            Ok(()) => result,
            Err(_) => {
                if result.is_ok() {
                    // Never release entries without evidence: lock through the same command path.
                    let _ = super::lock_inner_at(state, None, path, edition::Edition::Single);
                }
                Err(DIAG_RECEIPT_MSG.to_string())
            }
        }
    }
}

#[cfg(test)]
mod test_seams {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    type Hook = Box<dyn FnOnce() + Send>;

    #[derive(Default)]
    pub(super) struct Seams {
        pub(super) fail_final_write: AtomicBool,
        pub(super) generation_skew: AtomicU64,
        pub(super) worker_delay_ms: AtomicU64,
        pub(super) worker_runs: AtomicUsize,
        pub(super) gate_hook: Mutex<Option<Hook>>,
        /// Defect injection after the lock was acknowledged, before `complete_login`.
        pub(super) after_gate_released: Mutex<Option<Hook>>,
        /// Defect injection after `complete_login`, before the probe's final observation.
        pub(super) before_conclude: Mutex<Option<Hook>>,
    }

    fn run(slot: &Mutex<Option<Hook>>) {
        let hook = slot.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    impl Seams {
        pub(super) fn fail_final_write(&self) -> bool {
            self.fail_final_write.load(Ordering::SeqCst)
        }
        pub(super) fn worker_generation_skew(&self) -> u64 {
            self.generation_skew.load(Ordering::SeqCst)
        }
        pub(super) fn before_worker(&self) {
            let ms = self.worker_delay_ms.load(Ordering::SeqCst);
            if ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        pub(super) fn worker_finished(&self) {
            self.worker_runs.fetch_add(1, Ordering::SeqCst);
        }
        pub(super) fn run_gate_hook(&self) {
            run(&self.gate_hook);
        }
        pub(super) fn run_after_gate_released(&self) {
            run(&self.after_gate_released);
        }
        pub(super) fn run_before_conclude(&self) {
            run(&self.before_conclude);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::{Controller, Fixture, Reject, TEST_CONTROLLER};
    use fido2::{FidoBackend, FidoError, MockBackend};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Brokered (Windows-WebAuthn-like) synthetic roaming backend; counts assertions.
    struct Brokered {
        mock: MockBackend,
        brokered: bool,
        fail: bool,
        asserts: Arc<AtomicUsize>,
    }

    impl FidoBackend for Brokered {
        fn detect(&mut self) -> std::result::Result<fido2::DetectedKey, FidoError> {
            self.mock.detect()
        }
        fn register_credential(
            &mut self,
            d: &fido2::DetectedKey,
            pin: Option<&str>,
        ) -> std::result::Result<fido2::RegisteredCredential, FidoError> {
            self.mock.register_credential(d, pin)
        }
        fn get_prf_secret(
            &mut self,
            id: &[u8],
            pin: Option<&str>,
        ) -> std::result::Result<[u8; 32], FidoError> {
            self.asserts.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(FidoError::Internal("synthetic native cancellation".into()));
            }
            self.mock.get_prf_secret(id, pin)
        }
        fn uses_brokered_key_selection(&self) -> bool {
            self.brokered
        }
    }

    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixtures_root() -> std::path::PathBuf {
        std::env::var_os("TMPDIR")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
    }

    fn fixture_dir() -> Dir {
        let root = fixtures_root();
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join(format!("lock-overlap-diag-t{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        Dir(dir)
    }

    const PASSWORD: &str = "synthetic-caseB-password";
    const ENTRY_SITE: &str = "synthetic-site-7c1e";
    const ENTRY_SECRET: &str = "synthetic-entry-pw-93ab";

    /// Locked single-edition vault with one entry and one roaming key; returns (path, key id b64).
    fn locked_vault(dir: &Dir) -> (std::path::PathBuf, String) {
        let p = dir.0.join("vault.db");
        let mut v = vault::Vault::create_for(&p, PASSWORD, edition::Edition::Single).unwrap();
        v.add_entry(ENTRY_SITE, "synthetic-account", ENTRY_SECRET, "")
            .unwrap();
        let reg = v
            .register_key_with_label(&mut MockBackend::new(), None, "synthetic-roaming")
            .unwrap();
        v.lock();
        (p, crypto::base64_encode(&reg.credential_id))
    }

    struct App {
        state: Arc<VaultState>,
        #[cfg(not(feature = "dual-control"))]
        asserts: Arc<AtomicUsize>,
    }

    fn app(brokered: bool, fail: bool) -> App {
        let asserts = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(VaultState(std::sync::Mutex::new(AppInner {
            vault: None,
            backend: Box::new(Brokered {
                mock: MockBackend::new(),
                brokered,
                fail,
                asserts: Arc::clone(&asserts),
            }),
            pending_csv_import: None,
            dual_pending: None,
            dual_generation: 0,
            pending_registration: None,
            registration_generation: 0,
            registration_cleanup_receipts: Vec::new(),
            registration_cleanup_journal: None,
            registration_cleanup_storage_unavailable: false,
            key_op: KeyOpState::default(),
        })));
        App {
            state,
            #[cfg(not(feature = "dual-control"))]
            asserts,
        }
    }

    /// Completes `dir` into a diagnostic layout (exe placeholder + marker) and validates it
    /// through the real `validate_fixture`, so claim-time re-verification has real identities.
    fn validated(dir: &Dir) -> Fixture {
        let exe = dir.0.join(super::DIAG_EXE_NAME);
        std::fs::write(&exe, b"synthetic exe placeholder").unwrap();
        std::fs::write(dir.0.join(super::MARKER_FILE), super::MARKER_CONTENT).unwrap();
        super::validate_fixture(&exe).expect("valid synthetic fixture")
    }

    fn armed_with(controller: Controller, dir: &Dir, path: &std::path::Path) -> Arc<Controller> {
        let fixture = validated(dir);
        assert_eq!(fixture.vault_path, path);
        controller
            .arm(
                fixture,
                std::time::Instant::now(),
                std::time::Duration::from_secs(600),
            )
            .unwrap();
        Arc::new(controller)
    }

    fn armed(dir: &Dir, path: &std::path::Path) -> Arc<Controller> {
        armed_with(Controller::new(), dir, path)
    }

    fn with_controller<T>(controller: Option<Arc<Controller>>, f: impl FnOnce() -> T) -> T {
        TEST_CONTROLLER.with(|c| *c.borrow_mut() = controller);
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        TEST_CONTROLLER.with(|c| *c.borrow_mut() = None);
        out.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }

    fn login(app: &App, path: &std::path::Path) -> Result<Vec<vault::Entry>> {
        login_any_key_inner(&app.state, path, |_| Ok(1))
    }

    /// (key_op.active, pending_lock, vault unlocked)
    fn key_op(app: &App) -> (bool, bool, bool) {
        let g = lock_state_tolerant(&app.state);
        (g.key_op.active, g.key_op.pending_lock.is_some(), g.vault.is_some())
    }

    fn receipts(dir: &Dir) -> Vec<(String, serde_json::Value)> {
        let mut out = Vec::new();
        let Ok(read) = std::fs::read_dir(dir.0.join(super::RECEIPT_DIR)) else {
            return out;
        };
        for entry in read {
            let entry = entry.unwrap();
            let text = std::fs::read_to_string(entry.path()).unwrap();
            let value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
            out.push((text, value));
        }
        out
    }

    #[cfg(not(feature = "dual-control"))]
    fn only_receipt(dir: &Dir) -> (String, serde_json::Value) {
        let mut all = receipts(dir);
        assert_eq!(all.len(), 1, "exactly one receipt per armed attempt");
        all.remove(0)
    }

    #[cfg(not(feature = "dual-control"))]
    fn events(receipt: &serde_json::Value) -> Vec<String> {
        receipt["events"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, e)| {
                assert_eq!(e["seq"].as_u64(), Some(i as u64 + 1), "monotonic seq");
                e["event"].as_str().unwrap().to_string()
            })
            .collect()
    }

    /// No secret, credential ID, password or entry content may appear in a receipt.
    #[cfg(not(feature = "dual-control"))]
    fn assert_receipt_is_non_secret(text: &str, key_id: &str) {
        for forbidden in [PASSWORD, ENTRY_SITE, ENTRY_SECRET, "synthetic-account", key_id] {
            assert!(!text.contains(forbidden), "receipt leaked a forbidden value");
        }
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "case",
                "entry_count",
                "events",
                "generation",
                "hardware_verified",
                "key_op_active_after_worker_join",
                "key_op_idle",
                "lock_received",
                "native_success",
                "outcome",
                "pending_lock_after_worker_join",
                "phase",
                "response_category",
                "schema",
                "user_verification",
                "vault_locked",
            ]
        );
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_armed_success_is_discarded_through_the_real_lock() {
        let dir = fixture_dir();
        let (path, key_id) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(
            result.as_ref().map(|e| e.len()).map_err(String::as_str),
            Err(KEY_OPERATION_LOCKED_MSG),
            "armed Case B must return the lock error, never entries"
        );
        assert_eq!(key_op(&app), (false, false, false), "locked and idle");
        assert_eq!(app.asserts.load(Ordering::SeqCst), 1, "one real backend assertion");
        assert_eq!(controller.seams.worker_runs.load(Ordering::SeqCst), 1);
        assert!(!controller.is_armed(), "the arm is consumed");
        let (text, receipt) = only_receipt(&dir);
        assert_receipt_is_non_secret(&text, &key_id);
        assert_eq!(receipt["schema"], "fidovault-lock-overlap-diag-receipt/v2");
        assert_eq!(receipt["case"], "B");
        assert_eq!(receipt["phase"], "post-native/pre-publication");
        assert_eq!(receipt["outcome"], "CASE_B_RESPONSE_DISCARDED");
        assert_eq!(receipt["lock_received"], true);
        assert_eq!(receipt["key_op_active_after_worker_join"], true);
        assert_eq!(receipt["pending_lock_after_worker_join"], true);
        assert_eq!(
            receipt["user_verification"],
            "not_observed:operator-must-report-bio-or-pin"
        );
        assert_eq!(receipt["response_category"], "lock_error");
        assert_eq!(receipt["entry_count"], 0);
        assert_eq!(receipt["vault_locked"], true);
        assert_eq!(receipt["key_op_idle"], true);
        assert_eq!(receipt["hardware_verified"], false);
        assert_eq!(receipt["native_success"]["value"], true);
        assert_eq!(receipt["native_success"]["ffi_observed"], false);
        assert_eq!(
            receipt["native_success"]["source"],
            "inferred:brokered-backend+authenticated-roaming-open"
        );
        assert_eq!(
            events(&receipt),
            [
                "claimed",
                "authenticated_open_success",
                "pre_publication_gate_entered",
                "lock_requested",
                "worker_joined",
                "lock_received",
                "gate_released",
                "concluded",
            ]
        );
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_recovery_login_with_the_same_key_is_normal_and_not_rearmed() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        let (first, second) = with_controller(Some(Arc::clone(&controller)), || {
            (login(&app, &path), login(&app, &path))
        });
        assert_eq!(first.unwrap_err(), KEY_OPERATION_LOCKED_MSG);
        let entries = second.expect("recovery login must succeed normally");
        assert_eq!(entries.len(), 1);
        assert_eq!(key_op(&app), (false, false, true), "unlocked after recovery");
        assert_eq!(controller.seams.worker_runs.load(Ordering::SeqCst), 1, "no re-arm");
        assert_eq!(receipts(&dir).len(), 1, "recovery login writes no receipt");
    }

    #[test]
    fn case_b_unarmed_or_absent_controller_does_not_intervene() {
        for armed_controller in [false, true] {
            let dir = fixture_dir();
            let (path, _) = locked_vault(&dir);
            let app = app(true, false);
            let controller = armed_controller.then(|| Arc::new(Controller::new()));
            let result = with_controller(controller.clone(), || login(&app, &path));
            assert_eq!(result.map(|e| e.len()), Ok(1), "controller={armed_controller}");
            assert_eq!(key_op(&app), (false, false, true));
            assert!(receipts(&dir).is_empty());
            if let Some(controller) = controller {
                assert_eq!(controller.seams.worker_runs.load(Ordering::SeqCst), 0);
            }
        }
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_native_failure_consumes_arm_as_inconclusive_without_lock() {
        let dir = fixture_dir();
        let (path, key_id) = locked_vault(&dir);
        let app = app(true, true);
        let controller = armed(&dir, &path);
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        let error = result.unwrap_err();
        assert_ne!(error, KEY_OPERATION_LOCKED_MSG, "a native failure is not a lock result");
        assert_eq!(key_op(&app), (false, false, false));
        assert_eq!(controller.seams.worker_runs.load(Ordering::SeqCst), 0, "no lock injected");
        assert!(!controller.is_armed(), "consumed: never left for an unknown later request");
        let (text, receipt) = only_receipt(&dir);
        assert_receipt_is_non_secret(&text, &key_id);
        assert_eq!(receipt["outcome"], "INCONCLUSIVE_NATIVE_OR_OPEN_FAILED");
        assert_eq!(receipt["native_success"]["value"], false);
        assert_eq!(receipt["lock_received"], false);
        assert_eq!(receipt["response_category"], "other_error");
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_raise_refusal_before_native_is_inconclusive() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        let result = with_controller(Some(Arc::clone(&controller)), || {
            login_any_key_inner(&app.state, &path, |_| Err("no foreground".into()))
        });
        assert_eq!(result.unwrap_err(), "no foreground");
        assert_eq!(app.asserts.load(Ordering::SeqCst), 0);
        assert_eq!(only_receipt(&dir).1["outcome"], "INCONCLUSIVE_NATIVE_OR_OPEN_FAILED");
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_non_brokered_success_is_not_native_success_and_releases_nothing() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let app = app(false, false);
        let controller = armed(&dir, &path);
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(result.unwrap_err(), super::DIAG_REJECTED_MSG);
        assert_eq!(key_op(&app), (false, false, false));
        assert_eq!(controller.seams.worker_runs.load(Ordering::SeqCst), 0);
        let receipt = only_receipt(&dir).1;
        assert_eq!(receipt["outcome"], "INCONCLUSIVE_NON_BROKERED_BACKEND");
        assert_eq!(receipt["native_success"]["value"], false);
    }

    #[test]
    fn case_b_other_entrypoints_never_consume_the_arm() {
        let dir = fixture_dir();
        let (path, key_id) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        with_controller(Some(Arc::clone(&controller)), || {
            let pw = login_password_inner(&app.state, &path, PASSWORD, edition::Edition::Single);
            assert!(pw.is_ok(), "password login unaffected");
            assert!(lock_inner_at(&app.state, None, &path, edition::Edition::Single).is_ok());
            let key = login_key_inner(&app.state, &path, &key_id, None, |_| Ok(1));
            assert!(key.is_ok(), "explicit login_key unaffected");
            assert!(lock_inner_at(&app.state, None, &path, edition::Edition::Single).is_ok());
            let _ = login_windows_hello_inner(&app.state, &path, edition::Edition::Single, |_| {
                Ok(1)
            });
            let _ = login_dual_begin_inner(&app.state, &path, None, |_| Ok(1), |_, _| {});
            let _ = login_dual_complete_inner(&app.state, None, |_| Ok(1));
        });
        assert!(controller.is_armed(), "only login_any_key may consume the arm");
        assert_eq!(controller.seams.worker_runs.load(Ordering::SeqCst), 0);
        assert!(receipts(&dir).is_empty());
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_wrong_generation_worker_is_refused_and_fails_closed() {
        let dir = fixture_dir();
        let (path, key_id) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        controller.seams.generation_skew.store(1, Ordering::SeqCst);
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(result.unwrap_err(), super::DIAG_HANDSHAKE_MSG);
        assert_eq!(key_op(&app), (false, false, false), "no entries, still locked");
        let (text, receipt) = only_receipt(&dir);
        assert_receipt_is_non_secret(&text, &key_id);
        assert_eq!(receipt["outcome"], "INCONCLUSIVE_HANDSHAKE_FAILED");
        assert_eq!(receipt["lock_received"], false);
        assert_eq!(receipt["pending_lock_after_worker_join"], false);
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_stale_worker_cannot_lock_a_later_operation() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        let first = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(first.unwrap_err(), KEY_OPERATION_LOCKED_MSG);
        // A later key operation is active; the finished generation must not reach it.
        let (guard, ()) = KeyOperationGuard::begin_login(&app.state, |_| Ok(())).unwrap();
        assert_eq!(super::worker_lock(&controller, 1, &app.state, &path), None);
        assert_eq!(key_op(&app), (true, false, false), "no pending lock on the next operation");
        drop(guard);
        assert_eq!(key_op(&app), (false, false, false));
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_worker_ack_timeout_fails_closed_and_joins_before_return() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed_with(
            Controller::with_ack_timeout(std::time::Duration::from_millis(50)),
            &dir,
            &path,
        );
        controller.seams.worker_delay_ms.store(400, Ordering::SeqCst);
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(
            controller.seams.worker_runs.load(Ordering::SeqCst),
            1,
            "the late worker was joined before the command returned"
        );
        assert!(result.is_err(), "no entries after a timed-out handshake");
        assert_eq!(key_op(&app), (false, false, false), "late lock consumed by the same guard");
        assert_eq!(only_receipt(&dir).1["outcome"], "INCONCLUSIVE_HANDSHAKE_FAILED");
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_expired_or_mismatched_arm_is_consumed_and_runs_no_ceremony() {
        for expired in [true, false] {
            let dir = fixture_dir();
            let (path, _) = locked_vault(&dir);
            let app = app(true, false);
            let controller = Arc::new(Controller::new());
            let mut fixture = validated(&dir);
            let ttl = if expired {
                std::time::Duration::ZERO
            } else {
                fixture.vault_path = dir.0.join("other.db");
                std::time::Duration::from_secs(600)
            };
            controller
                .arm(fixture, std::time::Instant::now(), ttl)
                .unwrap();
            let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
            assert_eq!(result.unwrap_err(), super::DIAG_REJECTED_MSG);
            assert_eq!(app.asserts.load(Ordering::SeqCst), 0, "no ceremony");
            assert_eq!(key_op(&app), (false, false, false));
            assert!(!controller.is_armed());
            let receipt = only_receipt(&dir).1;
            let expected = if expired {
                "INCONCLUSIVE_ARM_EXPIRED"
            } else {
                "INCONCLUSIVE_PATH_MISMATCH"
            };
            assert_eq!(receipt["outcome"], expected);
            // Refused before any state observation: never claimed as locked/idle.
            assert_eq!(receipt["vault_locked"], "not_observed");
            assert_eq!(receipt["key_op_idle"], "not_observed");
            // Next request is a normal login (the arm is gone).
            let again = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
            assert_eq!(again.map(|e| e.len()), Ok(1));
        }
    }

    #[test]
    fn case_b_repeated_arm_is_rejected() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let controller = armed(&dir, &path);
        let again = controller.arm(
            validated(&dir),
            std::time::Instant::now(),
            std::time::Duration::from_secs(600),
        );
        assert_eq!(again, Err(Reject::RepeatedArm));
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_receipt_create_failure_fails_closed_before_the_backend() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let app = app(true, false);
        let controller = Arc::new(Controller::new());
        let mut fixture = validated(&dir);
        fixture.receipt_dir = dir.0.join("missing-receipt-dir");
        controller
            .arm(
                fixture,
                std::time::Instant::now(),
                std::time::Duration::from_secs(600),
            )
            .unwrap();
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(result.unwrap_err(), super::DIAG_RECEIPT_MSG);
        assert_eq!(app.asserts.load(Ordering::SeqCst), 0, "no ceremony without a receipt");
        assert_eq!(key_op(&app), (false, false, false));
        assert!(!controller.is_armed());
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_receipt_final_write_failure_never_releases_entries() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        controller
            .seams
            .fail_final_write
            .store(true, Ordering::SeqCst);
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(result.unwrap_err(), super::DIAG_RECEIPT_MSG, "no false PASS");
        assert_eq!(key_op(&app), (false, false, false));
        let all = receipts(&dir);
        assert_eq!(all.len(), 1);
        assert!(all[0].0.is_empty(), "the receipt stays empty (no claimed outcome)");
    }

    #[test]
    fn case_b_receipts_are_exclusive_create_and_never_overwrite_history() {
        let dir = fixture_dir();
        let receipt_dir = dir.0.join(super::RECEIPT_DIR);
        std::fs::create_dir_all(&receipt_dir).unwrap();
        std::fs::write(receipt_dir.join("history.json"), b"historic").unwrap();
        let error = super::create_receipt(&receipt_dir, "history.json").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(receipt_dir.join("history.json")).unwrap(),
            b"historic"
        );
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_reentry_during_gate_is_busy_and_does_not_reuse_the_arm() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let state = Arc::clone(&app.state);
            let path = path.clone();
            let controller_in_gate = Arc::clone(&controller);
            *controller.seams.gate_hook.lock().unwrap() = Some(Box::new(move || {
                let nested = with_controller(Some(controller_in_gate), || {
                    login_any_key_inner(&state, &path, |_| Ok(1))
                });
                let password =
                    login_password_inner(&state, &path, PASSWORD, edition::Edition::Single);
                let _ = tx.send((nested.map(|e| e.len()), password.map(|e| e.len())));
            }));
        }
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        let received = rx.recv_timeout(std::time::Duration::from_secs(5));
        let (nested, password) =
            received.expect("diagnostic reentry gate did not acknowledge within 5s");
        assert_eq!(nested, Err(KEY_OPERATION_BUSY_MSG.to_string()));
        assert_eq!(password, Err(KEY_OPERATION_BUSY_MSG.to_string()));
        assert_eq!(result.unwrap_err(), KEY_OPERATION_LOCKED_MSG);
        assert_eq!(app.asserts.load(Ordering::SeqCst), 1);
        assert_eq!(only_receipt(&dir).1["outcome"], "CASE_B_RESPONSE_DISCARDED");
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_user_lock_without_handshake_is_not_a_false_positive() {
        // A lock that the worker did not deliver (handshake refused) must never be scored as
        // Case B, even though the final response is the same lock error.
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        controller.seams.generation_skew.store(7, Ordering::SeqCst);
        {
            let state = Arc::clone(&app.state);
            let path = path.clone();
            *controller.seams.gate_hook.lock().unwrap() = Some(Box::new(move || {
                let _ = lock_inner_at(&state, None, &path, edition::Edition::Single);
            }));
        }
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(result.unwrap_err(), KEY_OPERATION_LOCKED_MSG);
        assert_eq!(key_op(&app), (false, false, false));
        let receipt = only_receipt(&dir).1;
        assert_eq!(receipt["outcome"], "INCONCLUSIVE_HANDSHAKE_FAILED");
        assert_eq!(receipt["lock_received"], false);
    }

    // ── T1: the probe must report a real lock defect as FAIL (never mask it as PASS) ──

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_defect_lost_lock_request_publishes_entries_and_is_fail_entries() {
        let dir = fixture_dir();
        let (path, key_id) = locked_vault(&dir);
        let app = app(true, false);
        let controller = armed(&dir, &path);
        {
            // Defect: after the lock was acknowledged (pending_lock observed), the recorded
            // request is lost before complete_login, so the real finish()/publish_login no
            // longer discards the opened vault.
            let state = Arc::clone(&app.state);
            *controller.seams.after_gate_released.lock().unwrap() = Some(Box::new(move || {
                lock_state_tolerant(&state).key_op.pending_lock = None;
            }));
        }
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        let entries = result.expect("the defective app publishes entries; the probe passes them");
        assert_eq!(entries.len(), 1);
        let published = serde_json::to_string(&entries).unwrap();
        assert!(published.contains(ENTRY_SECRET), "the response really carried the secret");
        assert_eq!(key_op(&app), (false, false, true), "the defect left the vault unlocked");
        assert_eq!(controller.seams.worker_runs.load(Ordering::SeqCst), 1);
        let (text, receipt) = only_receipt(&dir);
        assert_receipt_is_non_secret(&text, &key_id);
        assert!(!text.contains(ENTRY_SECRET) && !text.contains(ENTRY_SITE));
        assert_eq!(receipt["outcome"], "FAIL_ENTRIES_RETURNED_AFTER_LOCK");
        assert_eq!(receipt["response_category"], "entries");
        assert_eq!(receipt["entry_count"], 1);
        assert_eq!(receipt["lock_received"], true);
        assert_eq!(receipt["vault_locked"], false);
        assert_eq!(receipt["hardware_verified"], false);
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_defect_lock_error_with_bad_final_state_is_fail_state() {
        for defect in ["vault_republished", "lock_request_left_pending"] {
            let dir = fixture_dir();
            let (path, key_id) = locked_vault(&dir);
            let app = app(true, false);
            let controller = armed(&dir, &path);
            {
                // The app returned the lock error, but the state it leaves behind is wrong.
                let state = Arc::clone(&app.state);
                let path = path.clone();
                *controller.seams.before_conclude.lock().unwrap() = Some(Box::new(move || {
                    if defect == "vault_republished" {
                        let unlocked =
                            login_password_inner(&state, &path, PASSWORD, edition::Edition::Single);
                        assert!(unlocked.is_ok());
                    } else {
                        lock_state_tolerant(&state).key_op.pending_lock = Some(None);
                    }
                }));
            }
            let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
            assert_eq!(result.unwrap_err(), KEY_OPERATION_LOCKED_MSG, "{defect}");
            let (text, receipt) = only_receipt(&dir);
            assert_receipt_is_non_secret(&text, &key_id);
            assert_eq!(receipt["outcome"], "FAIL_STATE_AFTER_LOCK", "{defect}");
            assert_eq!(receipt["response_category"], "lock_error", "{defect}");
            assert_eq!(receipt["lock_received"], true, "{defect}");
            let (vault_locked, key_op_idle) = if defect == "vault_republished" {
                (false, true)
            } else {
                (true, false)
            };
            assert_eq!(receipt["vault_locked"], vault_locked, "{defect}");
            assert_eq!(receipt["key_op_idle"], key_op_idle, "{defect}");
        }
    }

    // ── arming / fixture validation ──

    fn diag_layout(marker: Option<&str>) -> (Dir, std::path::PathBuf) {
        let dir = fixture_dir();
        let exe = dir.0.join(super::DIAG_EXE_NAME);
        std::fs::write(&exe, b"synthetic exe placeholder").unwrap();
        let _ = locked_vault(&dir);
        if let Some(marker) = marker {
            std::fs::write(dir.0.join(super::MARKER_FILE), marker).unwrap();
        }
        (dir, exe)
    }

    fn args(list: &[&str]) -> Vec<std::ffi::OsString> {
        std::iter::once("fidovault-lock-overlap-diag.exe")
            .chain(list.iter().copied())
            .map(std::ffi::OsString::from)
            .collect()
    }

    #[test]
    fn arm_requires_explicit_flag_and_valid_fixture() {
        let (dir, exe) = diag_layout(Some("fidovault-lock-overlap-diag-fixture/v1 case=B\n"));
        let single = edition::Edition::Single;
        // No flag: never armed, even with a perfect fixture.
        assert!(matches!(super::arm_from(args(&[]), Some(exe.clone()), true, single), Ok(None)));
        // Duplicate flag, dual edition, non-hardware backend: rejected.
        let flag = super::ARM_FLAG;
        assert!(matches!(
            super::arm_from(args(&[flag, flag]), Some(exe.clone()), true, single),
            Err(Reject::RepeatedArm)
        ));
        assert!(matches!(
            super::arm_from(args(&[flag]), Some(exe.clone()), true, edition::Edition::Dual),
            Err(Reject::NotSingleEdition)
        ));
        assert!(matches!(
            super::arm_from(args(&[flag]), Some(exe.clone()), false, single),
            Err(Reject::NotHardwareBackend)
        ));
        let controller = super::arm_from(args(&[flag]), Some(exe.clone()), true, single)
            .unwrap()
            .expect("flag + valid fixture arms once");
        assert!(controller.is_armed());
        assert!(dir.0.join(super::RECEIPT_DIR).is_dir());
    }

    #[test]
    fn fixture_rejects_missing_or_wrong_marker() {
        let (_dir, exe) = diag_layout(None);
        assert_eq!(super::validate_fixture(&exe).err(), Some(Reject::MarkerMissingOrInvalid));
        let (_dir, exe) = diag_layout(Some("fidovault-lock-overlap-diag-fixture/v1 case=A"));
        assert_eq!(super::validate_fixture(&exe).err(), Some(Reject::MarkerMissingOrInvalid));
        let (dir, exe) = diag_layout(Some("fidovault-lock-overlap-diag-fixture/v1 case=B"));
        std::fs::remove_file(dir.0.join("vault.db")).unwrap();
        assert_eq!(super::validate_fixture(&exe).err(), Some(Reject::VaultMissing));
    }

    #[test]
    fn fixture_rejects_hardlinked_vault_or_marker() {
        // A synthetic stand-in for a vault/marker that lives outside the candidate root.
        let outside = fixture_dir();
        let (outside_vault, _) = locked_vault(&outside);
        let outside_before = std::fs::read(&outside_vault).unwrap();

        let (dir, exe) = diag_layout(Some(super::MARKER_CONTENT));
        std::fs::remove_file(dir.0.join("vault.db")).unwrap();
        std::fs::hard_link(&outside_vault, dir.0.join("vault.db")).unwrap();
        assert_eq!(
            super::validate_fixture(&exe).err(),
            Some(Reject::HardLinked),
            "vault.db hard-linked to a file outside the fixture"
        );
        assert_eq!(std::fs::read(&outside_vault).unwrap(), outside_before);

        let (dir, exe) = diag_layout(None);
        let outside_marker = outside.0.join("marker-elsewhere");
        std::fs::write(&outside_marker, super::MARKER_CONTENT).unwrap();
        std::fs::hard_link(&outside_marker, dir.0.join(super::MARKER_FILE)).unwrap();
        assert_eq!(
            super::validate_fixture(&exe).err(),
            Some(Reject::HardLinked),
            "marker hard-linked to a file outside the fixture"
        );

        // Negative control: the same layout without links still arms.
        let (_dir, exe) = diag_layout(Some(super::MARKER_CONTENT));
        assert!(super::validate_fixture(&exe).is_ok(), "plain fixture accepted");
    }

    #[test]
    fn fixture_rejects_paths_outside_a_dedicated_local_candidate_root() {
        for (path, expected) in [
            (r"C:\FidoVault\lock-overlap-diag-x\fidovault-lock-overlap-diag.exe", Reject::ProductionInstallPath),
            (r"D:\fidovault\lock-overlap-diag-x\fidovault-lock-overlap-diag.exe", Reject::ProductionInstallPath),
            (r"\\server\share\lock-overlap-diag-x\fidovault-lock-overlap-diag.exe", Reject::NotLocalDrivePath),
            (r"\\?\UNC\server\share\lock-overlap-diag-x\fidovault-lock-overlap-diag.exe", Reject::NotLocalDrivePath),
            (r"\\.\D:\lock-overlap-diag-x\fidovault-lock-overlap-diag.exe", Reject::NotLocalDrivePath),
            (r"lock-overlap-diag-x\fidovault-lock-overlap-diag.exe", Reject::NotLocalDrivePath),
            (r"D:\a\..\lock-overlap-diag-x\fidovault-lock-overlap-diag.exe", Reject::RelativeOrDotComponent),
            (r"D:\scratch\lock-overlap-diag-x\portable-fido-vault.exe", Reject::WrongExecutableName),
            (r"D:\scratch\release\fidovault-lock-overlap-diag.exe", Reject::NotDedicatedFixtureDir),
            (r"D:\fidovault-lock-overlap-diag.exe", Reject::NotDedicatedFixtureDir),
            (r"D:\scratch\lock-overlap-diag-\fidovault-lock-overlap-diag.exe", Reject::NotDedicatedFixtureDir),
            (r"D:\scratch\lock-overlap-diag-a b\fidovault-lock-overlap-diag.exe", Reject::NotDedicatedFixtureDir),
        ] {
            assert_eq!(
                super::validate_fixture(std::path::Path::new(path)).err(),
                Some(expected),
                "{path}"
            );
        }
        // A D: drive path is not enough: a dedicated dir without marker is still refused.
        let dir = fixture_dir();
        let exe = dir.0.join(super::DIAG_EXE_NAME);
        std::fs::write(&exe, b"x").unwrap();
        assert_eq!(super::validate_fixture(&exe).err(), Some(Reject::MarkerMissingOrInvalid));
    }

    #[test]
    fn fixture_rejects_reparse_attribute_and_non_file_marker() {
        assert!(super::is_reparse_attribute(0x400));
        assert!(super::is_reparse_attribute(0x410));
        assert!(!super::is_reparse_attribute(0x10));
        // The marker itself must be a plain file.
        let (dir, exe) = diag_layout(None);
        std::fs::create_dir(dir.0.join(super::MARKER_FILE)).unwrap();
        assert_eq!(super::validate_fixture(&exe).err(), Some(Reject::MarkerMissingOrInvalid));
    }

    #[test]
    #[ignore = "needs SeCreateSymbolicLinkPrivilege/Developer Mode, unavailable to this account; \
                junctions (fixture_rejects_*_junction) cover reparse rejection without privilege"]
    fn fixture_rejects_symlinked_root_requires_symlink_privilege() {
        let (dir, _) = diag_layout(Some(super::MARKER_CONTENT));
        let link = fixtures_root().join(format!(
            "lock-overlap-diag-link{:016x}",
            rand::random::<u64>()
        ));
        std::os::windows::fs::symlink_dir(&dir.0, &link)
            .expect("symlink creation must succeed for this test to mean anything");
        let _link = Junction(link.clone()); // removes only the link
        assert_eq!(
            super::validate_fixture(&link.join(super::DIAG_EXE_NAME)).err(),
            Some(Reject::ReparseOrSymlink)
        );
    }

    #[test]
    fn fixture_rejects_ancestor_junction() {
        let target = Dir(fixtures_root().join(format!("jtarget-{:016x}", rand::random::<u64>())));
        std::fs::create_dir(&target.0).unwrap();
        let inner = target.0.join("lock-overlap-diag-anc");
        std::fs::create_dir(&inner).unwrap();
        std::fs::write(inner.join(super::DIAG_EXE_NAME), b"synthetic exe placeholder").unwrap();
        std::fs::write(inner.join(super::MARKER_FILE), super::MARKER_CONTENT).unwrap();
        std::fs::write(inner.join("vault.db"), b"synthetic vault placeholder").unwrap();
        let via = fixtures_root().join(format!("jroot-{:016x}", rand::random::<u64>()));
        let _link = junction(&via, &target.0);
        // Control: the same layout through its real path arms.
        assert!(super::validate_fixture(&inner.join(super::DIAG_EXE_NAME)).is_ok());
        assert_eq!(
            super::validate_fixture(&via.join("lock-overlap-diag-anc").join(super::DIAG_EXE_NAME))
                .err(),
            Some(Reject::ReparseOrSymlink)
        );
    }

    #[test]
    fn fixture_rejects_root_junction() {
        let (dir, exe) = diag_layout(Some(super::MARKER_CONTENT));
        assert!(super::validate_fixture(&exe).is_ok(), "control: real root arms");
        let link = fixtures_root().join(format!(
            "lock-overlap-diag-j{:016x}",
            rand::random::<u64>()
        ));
        let _link = junction(&link, &dir.0);
        assert_eq!(
            super::validate_fixture(&link.join(super::DIAG_EXE_NAME)).err(),
            Some(Reject::ReparseOrSymlink)
        );
    }

    #[test]
    fn fixture_rejects_receipt_dir_junction() {
        let (dir, exe) = diag_layout(Some(super::MARKER_CONTENT));
        let elsewhere = fixture_dir();
        let _link = junction(&dir.0.join(super::RECEIPT_DIR), &elsewhere.0);
        assert_eq!(super::validate_fixture(&exe).err(), Some(Reject::ReceiptDirUnusable));
        assert_eq!(file_count(&elsewhere.0), 0, "nothing created through the junction");
    }

    // ── junction fixtures (T2/S2) ──

    /// Directory junction created by this test inside its own synthetic fixtures; removing it
    /// deletes only the link (`remove_dir` on a junction never descends into the target).
    struct Junction(std::path::PathBuf);
    impl Drop for Junction {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    /// `cmd /C mklink /J` needs no privilege. Panics (never silently passes) if the junction
    /// was not actually created as a reparse point.
    fn junction(link: &std::path::Path, target: &std::path::Path) -> Junction {
        let backslashed = |p: &std::path::Path| p.to_string_lossy().replace('/', "\\");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(backslashed(link))
            .arg(backslashed(target))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("cmd.exe available");
        let made = Junction(link.to_path_buf());
        let meta = std::fs::symlink_metadata(link).expect("junction exists");
        assert!(
            status.success() && super::is_link_or_reparse(&meta),
            "junction was not created; this test cannot run here"
        );
        made
    }

    fn file_count(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
    }

    #[cfg(not(feature = "dual-control"))]
    fn arm_validated(exe: &std::path::Path) -> Arc<Controller> {
        let controller = Arc::new(Controller::new());
        controller
            .arm(
                super::validate_fixture(exe).expect("valid synthetic fixture"),
                std::time::Instant::now(),
                std::time::Duration::from_secs(600),
            )
            .unwrap();
        controller
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_swap_after_arm_vault_hardlink_or_replacement_is_refused() {
        for swap in ["hardlink", "replacement"] {
            let outside = fixture_dir();
            let (outside_vault, _) = locked_vault(&outside);
            let outside_before = std::fs::read(&outside_vault).unwrap();
            let (dir, exe) = diag_layout(Some(super::MARKER_CONTENT));
            let path = dir.0.join("vault.db");
            let controller = arm_validated(&exe);
            std::fs::remove_file(&path).unwrap();
            if swap == "hardlink" {
                std::fs::hard_link(&outside_vault, &path).unwrap();
            } else {
                // A different plain single-link file at the same path (new file identity).
                std::fs::copy(&outside_vault, &path).unwrap();
            }
            let app = app(true, false);
            let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
            assert_eq!(result.unwrap_err(), super::DIAG_REJECTED_MSG, "{swap}");
            assert_eq!(app.asserts.load(Ordering::SeqCst), 0, "{swap}: key never touched");
            assert_eq!(key_op(&app), (false, false, false), "{swap}");
            assert!(!controller.is_armed(), "{swap}: arm consumed");
            assert_eq!(controller.seams.worker_runs.load(Ordering::SeqCst), 0);
            assert_eq!(std::fs::read(&outside_vault).unwrap(), outside_before, "{swap}");
            let receipt = only_receipt(&dir).1;
            assert_eq!(receipt["outcome"], "INCONCLUSIVE_FIXTURE_CHANGED", "{swap}");
            assert_eq!(receipt["vault_locked"], "not_observed", "{swap}");
            assert_eq!(receipt["key_op_idle"], "not_observed", "{swap}");
        }
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_swap_after_arm_receipt_dir_junction_writes_nothing() {
        let (dir, exe) = diag_layout(Some(super::MARKER_CONTENT));
        let path = dir.0.join("vault.db");
        let elsewhere = fixture_dir();
        let controller = arm_validated(&exe);
        // The armed pin blocks this swap (see case_b_armed_fixture_dirs_are_pinned_...);
        // release it to exercise claim-time re-verification on its own.
        controller.release_pins_for_test();
        let receipt_dir = dir.0.join(super::RECEIPT_DIR);
        std::fs::remove_dir(&receipt_dir).unwrap();
        let _link = junction(&receipt_dir, &elsewhere.0);
        let app = app(true, false);
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(result.unwrap_err(), super::DIAG_RECEIPT_MSG);
        assert_eq!(app.asserts.load(Ordering::SeqCst), 0, "key never touched");
        assert_eq!(key_op(&app), (false, false, false));
        assert!(!controller.is_armed(), "arm consumed");
        assert_eq!(file_count(&elsewhere.0), 0, "nothing written through the junction");
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_swap_after_arm_root_junction_writes_nothing() {
        let (dir, exe) = diag_layout(Some(super::MARKER_CONTENT));
        let path = dir.0.join("vault.db");
        let controller = arm_validated(&exe);
        controller.release_pins_for_test();
        let moved = Dir(dir.0.with_file_name(format!(
            "moved-{}",
            dir.0.file_name().unwrap().to_string_lossy()
        )));
        std::fs::rename(&dir.0, &moved.0).unwrap();
        let link = junction(&dir.0, &moved.0);
        let receipts_before = file_count(&moved.0.join(super::RECEIPT_DIR));
        let vault_before = std::fs::read(moved.0.join("vault.db")).unwrap();
        let app = app(true, false);
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(result.unwrap_err(), super::DIAG_RECEIPT_MSG);
        assert_eq!(app.asserts.load(Ordering::SeqCst), 0, "key never touched");
        assert!(!controller.is_armed(), "arm consumed");
        assert_eq!(file_count(&moved.0.join(super::RECEIPT_DIR)), receipts_before);
        assert_eq!(std::fs::read(moved.0.join("vault.db")).unwrap(), vault_before);
        drop(link);
    }

    #[cfg(not(feature = "dual-control"))]
    #[test]
    fn case_b_armed_fixture_dirs_are_pinned_without_blocking_vault_saves() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let controller = armed(&dir, &path);
        let receipt_dir = dir.0.join(super::RECEIPT_DIR);
        let moved_root = dir.0.with_file_name(format!(
            "moved-{}",
            dir.0.file_name().unwrap().to_string_lossy()
        ));
        // While armed, neither pinned directory can be renamed away (so neither can be
        // replaced by a junction) ...
        assert!(std::fs::rename(&receipt_dir, dir.0.join("receipts-moved")).is_err());
        assert!(std::fs::rename(&dir.0, &moved_root).is_err());
        // ... while the vault's own tmp+rename save inside the pinned root still works.
        let app = app(true, false);
        let vault_before = std::fs::read(&path).unwrap();
        with_controller(Some(Arc::clone(&controller)), || {
            let pw = login_password_inner(&app.state, &path, PASSWORD, edition::Edition::Single);
            assert!(pw.is_ok(), "password login (saves vault.db) works under the pins");
            assert!(lock_inner_at(&app.state, None, &path, edition::Edition::Single).is_ok());
        });
        assert_ne!(std::fs::read(&path).unwrap(), vault_before, "vault.db was rewritten");
        assert!(controller.is_armed());
        // That legitimate save replaced vault.db (new file identity): the armed attempt now
        // fails closed instead of running the ceremony on a file it did not verify.
        let result = with_controller(Some(Arc::clone(&controller)), || login(&app, &path));
        assert_eq!(result.unwrap_err(), super::DIAG_REJECTED_MSG);
        assert_eq!(app.asserts.load(Ordering::SeqCst), 0);
        assert_eq!(only_receipt(&dir).1["outcome"], "INCONCLUSIVE_FIXTURE_CHANGED");
        // The attempt is over: the pins are released.
        std::fs::rename(&receipt_dir, dir.0.join("receipts-moved")).unwrap();
    }

    // ── wiring oracles ──

    #[cfg(feature = "dual-control")]
    #[test]
    fn dual_build_refuses_arm_before_any_fixture_access() {
        let args = [
            std::ffi::OsString::from("diagnostic"),
            std::ffi::OsString::from(super::ARM_FLAG),
        ];
        let result = super::arm_from(args, None, true, edition::current());
        assert!(matches!(result, Err(super::Reject::NotSingleEdition)));
    }

    #[cfg(feature = "dual-control")]
    #[test]
    fn dual_build_claim_stays_inactive_and_preserves_the_injected_arm() {
        let dir = fixture_dir();
        let (path, _) = locked_vault(&dir);
        let controller = armed(&dir, &path);
        let before = std::fs::read(&path).unwrap();
        with_controller(Some(Arc::clone(&controller)), || {
            let probe = super::Probe::claim(&path).expect("dual claim is inert");
            assert!(probe.active.is_none());
        });
        assert!(
            controller.is_armed(),
            "dual must not consume a single-only arm"
        );
        assert!(
            receipts(&dir).is_empty(),
            "inactive probe writes no receipt"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn wiring_reentry_handshake_has_bounded_receive() {
        let source = include_str!("lock_overlap_diag.rs").replace('\r', "");
        let marker = format!(
            "    fn {}(",
            "case_b_reentry_during_gate_is_busy_and_does_not_reuse_the_arm"
        );
        let start = source.find(&marker).expect("reentry test exists");
        let body = &source[start..];
        let end = body.find("\n    }\n").expect("reentry test end exists");
        let body = &body[..end];
        assert!(body.contains("rx.recv_timeout("), "reentry handshake must fail on a bounded receive, never wait forever for an inactive gate");
        assert!(
            !body.contains("rx.recv()"),
            "unbounded reentry receive is forbidden"
        );
    }

    fn production_source() -> String {
        let source = include_str!("lib.rs").replace('\r', "");
        source.split("\n#[cfg(test)]\nmod lock_wait_hook").next().unwrap().to_string()
    }

    fn function_body(source: &str, name: &str) -> String {
        let start = source
            .find(&format!("\nfn {name}("))
            .or_else(|| source.find(&format!("\npub fn {name}(")))
            .expect(name);
        let rest = &source[start + 1..];
        let end = rest.find("\n}\n").expect(name);
        rest[..end].to_string()
    }

    #[test]
    fn wiring_production_login_any_key_command_reaches_the_hooks() {
        let source = production_source();
        let command = function_body(&source, "login_any_key");
        assert!(command.contains("login_any_key_inner(&state, &path_from_state_or_default()"));
        let inner = function_body(&source, "login_any_key_inner");
        let order = [
            "KeyOperationGuard::begin_login(",
            "lock_overlap_diag::Probe::claim(path)?",
            "vault::Vault::open_any_key(",
            "probe.pre_publication(state, path, require_foreground, opened)",
            "guard.complete_login(opened",
            "probe.conclude(state, path, result)",
        ];
        let mut at = 0;
        for needle in order {
            let found = inner[at..].find(needle).unwrap_or_else(|| panic!("{needle} out of order"));
            at += found + needle.len();
        }
        let handler = source
            .split(".invoke_handler(tauri::generate_handler![")
            .nth(1)
            .unwrap()
            .split("])")
            .next()
            .unwrap();
        assert!(handler.contains("login_any_key"));
        assert!(!handler.contains("diag"), "no new IPC command");
    }

    #[test]
    fn wiring_every_production_hook_is_feature_gated_and_feature_is_default_off() {
        let source = production_source();
        let lines: Vec<&str> = source.lines().collect();
        let mut hooks = 0;
        for (i, line) in lines.iter().enumerate() {
            if line.contains("lock_overlap_diag") || line.contains("probe.") {
                hooks += 1;
                assert_eq!(
                    lines[i - 1].trim(),
                    "#[cfg(feature = \"lock-overlap-diag\")]",
                    "ungated hook: {line}"
                );
            }
        }
        assert_eq!(hooks, 5, "module decl + arm + claim + gate + conclude");
        let run = function_body(&source, "run");
        assert!(run.contains("lock_overlap_diag::arm_from_process();"));
        let cargo = include_str!("../Cargo.toml").replace('\r', "");
        let features = cargo.split("\n[features]\n").nth(1).unwrap();
        let default = features.lines().find(|l| l.starts_with("default")).unwrap();
        assert_eq!(default, "default = [\"mock-fido\"]");
        assert!(features.lines().any(|l| l == "lock-overlap-diag = []"), "no dependencies");
        assert!(!cargo.split("\n[features]\n").next().unwrap().contains("lock-overlap"));
    }

    #[test]
    fn wiring_other_entrypoints_have_no_probe() {
        let source = production_source();
        for name in [
            "login_key_inner",
            "login_password_inner",
            "login_windows_hello_inner",
            "login_dual_begin_inner",
            "login_dual_complete_inner",
            "lock_inner_at",
            "register_key_inner",
        ] {
            assert!(
                !function_body(&source, name).contains("lock_overlap_diag"),
                "{name} must not be probed"
            );
        }
    }

    #[test]
    fn wiring_module_has_no_ipc_listener_or_network_surface() {
        let module = include_str!("lock_overlap_diag.rs").replace('\r', "");
        let module = module.split("\n#[cfg(test)]\nmod test_seams").next().unwrap();
        for forbidden in [
            "tauri::command",
            "generate_handler",
            ".listen(",
            "TcpListener",
            "UdpSocket",
            "NamedPipe",
            "\\\\.\\pipe",
            "RegisterHotKey",
            "devtools",
            "remote-debugging",
            "std::env::var(\"F2V_LOCK",
        ] {
            assert!(!module.contains(forbidden), "forbidden surface: {forbidden}");
        }
    }
}
