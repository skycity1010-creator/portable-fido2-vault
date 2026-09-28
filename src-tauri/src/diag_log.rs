//! 共用 fido2-diag file logger（blocker #2）：CLI 與 GUI 同用 → vendor authenticator-rs
//! 內建 debug!/info!/warn! 全量落檔（append），含 PID + 時間戳（多 process 可歸因）。
//!
//! 路徑解析：<exe 同目錄>\fido2-diag.log → %USERPROFILE% → %TEMP%。
//! WinRM session-0（service context）下 std::env::current_exe() 可能失敗（Windows 已知行為：
//! service account 無 token 時 GetModuleFileNameW 解析不到完整路徑）→ 需 fallback，
//! 否則 logger 落 sink = 遠端診斷全盲。
//!
//! contention-aware retry（fido2.rs RealBackend）在**每個 op attempt 前**取行數 checkpoint，
//! 之後只掃 checkpoint 後且 PID 屬於本 process 的行 → 避免舊 phase / 其他 process 的
//! stale Ioerror 誤觸發重試。

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
    // session marker：多 process append 的人工歸因標記。
    writeln!(f, "\n===== session start: pid={} ts={} path={} =====",
        std::process::id(),
        now_stamp(),
        LOG_PATH.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<none>".into()),
    ).ok();
    Mutex::new(f)
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

/// 每次 operation attempt 前另取 checkpoint；caller 再以 PID 篩選新追加的 log 行。
///
/// Session marker 供人工檢視多 process log；程式判斷以 checkpoint 與 PID 過濾為準。
/// CLI 與 GUI 共用 append log，所有 logger event 均帶 PID。
/// Earlier operation evidence is deliberately excluded from the retry predicate.

/// 行數 checkpoint：先 force FIDO_LOG 初始化（確保 session marker 落檔），再回傳目前行數。
pub fn checkpoint() -> usize {
    let guard = FIDO_LOG.lock().unwrap_or_else(|e| e.into_inner());
    let n = LOG_PATH.as_ref().map(|p| count_lines(p)).unwrap_or(0);
    drop(guard);
    n
}

/// 讀取 checkpoint 之後追加的 log 行。呼叫端須再依 PID 篩選，隔離其他 process 的 append。
pub fn scan_from(start_line: usize) -> Vec<String> {
    let path = match LOG_PATH.as_ref() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content.lines().skip(start_line).map(str::to_owned).collect()
}
