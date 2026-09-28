//! 共用 fido2-diag file logger（blocker #2）：CLI 與 GUI 同用 → vendor authenticator-rs
//! 內建 debug!/info!/warn! 全量落檔（append），含 PID + 時間戳（多 process 可歸因）。
//!
//! 路徑解析：<exe 同目錄>\fido2-diag.log → %USERPROFILE% → %TEMP%。
//! WinRM session-0（service context）下 std::env::current_exe() 可能失敗（Windows 已知行為：
//! service account 無 token 時 GetModuleFileNameW 解析不到完整路徑）→ 需 fallback，
//! 否則 logger 落 sink = 遠端診斷全盲。
//!
//! contention-aware retry（fido2.rs RealBackend）用 `scan_lines()` 只掃**本 process 本次
//! op 之後**的 log 行 → 判「FIDO VID open 被拒」signature；`mark_end()` 在 op 成功後
//! 推進 marker，排除更早 phase 的 stale Ioerror。

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

/// log 檔路徑（init 時解析；None = 無法落檔 → sink）。
static LOG_PATH: LazyLock<Option<PathBuf>> = LazyLock::new(resolve_path);
/// append file handle（開檔失敗 → io::sink，不阻斷執行）。
static FIDO_LOG: LazyLock<Mutex<Box<dyn std::io::Write + Send>>> = LazyLock::new(|| {
    let mut f: Box<dyn std::io::Write + Send> = match LOG_PATH.as_ref() {
        Some(p) => OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .map(|f| Box::new(f) as Box<dyn std::io::Write + Send>)
            .unwrap_or_else(|_| Box::new(std::io::sink()) as Box<dyn std::io::Write + Send>),
        None => Box::new(std::io::sink()),
    };
    // session marker：多 process 同檔 append → PID 歸因；retry scan 的 offset 基準。
    writeln!(f, "\n===== session start: pid={} ts={} path={} =====",
        std::process::id(),
        now_stamp(),
        LOG_PATH.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<none>".into()),
    ).ok();
    Mutex::new(f)
});

/// 本 process session start 時的行數（scan 起點）。
/// **先觸發 FIDO_LOG init**（寫入 session marker）再計數 → 確保 marker 在 scan 範圍內；
/// 否則 LazyLock 初始化順序不確定，marker 可能落在 skip 之後 = contention 偵測全盲。
static SESSION_START_LINES: LazyLock<Mutex<usize>> = LazyLock::new(|| {
    let _guard = FIDO_LOG.lock().unwrap_or_else(|e| e.into_inner()); // force marker write
    drop(_guard);
    let n = LOG_PATH.as_ref().map(|p| count_lines(p)).unwrap_or(0);
    Mutex::new(n)
});

fn resolve_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::current_exe() {
        if let Some(d) = p.parent() {
            return Some(d.join("fido2-diag.log"));
        }
    }
    for var in ["USERPROFILE", "TEMP"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return Some(PathBuf::from(v).join("fido2-diag.log"));
            }
        }
    }
    None
}

fn count_lines(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .map(|c| c.lines().count())
        .unwrap_or(0)
}

/// 本地時間戳（毫秒；chrono 為既有依賴）。
fn now_stamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

/// 安裝 global file logger。失敗（如已安裝）不阻斷執行 — 退化为 null logger。
pub fn init() {
    let _ = log::set_boxed_logger(Box::new(FileLogger));
    log::set_max_level(log::LevelFilter::Debug);
}

struct FileLogger;
impl log::Log for FileLogger {
    fn enabled(&self, _m: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        let line = format!(
            "[{}] [pid={}] [{}] {}: {}",
            record.level(),
            std::process::id(),
            now_stamp(),
            record.target(),
            record.args()
        );
        if let Ok(mut g) = FIDO_LOG.lock() {
            writeln!(g, "{line}").ok();
        }
        // 控制台一份（UTF-8；codepage 950 console 下中文可能顯示損毀，檔內恆為 UTF-8）。
        eprint!("{line}\n");
    }
    fn flush(&self) {}
}

/// 讀 log 檔中「本 process session marker 之後」的所有行（log 未初始化 → 全檔；開檔失敗 → 空）。
///
/// 以**本 process** 的 session start 為起點：同檔 append 的多 process log 不會互相干擾
/// （NB C:\FidoVault\fido2-diag.log 上 CLI + GUI 共用一檔）；同一 op 鏈（detect→register
/// 同 process）內前段 phase 的 Ioerror 也屬本 session 證據 → 全掃。
pub fn scan_lines() -> Vec<String> {
    let path = match LOG_PATH.as_ref() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let start = *SESSION_START_LINES.lock().unwrap_or_else(|e| e.into_inner());
    content.lines().skip(start).map(str::to_owned).collect()
}
