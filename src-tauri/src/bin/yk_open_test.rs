//! yk_open_test — extracted YubiKey FIDO HID open path (diagnostic).
//!
//! Enumerates the HID class, filters to YubiKey (VID_1050 & PID_0402), opens the
//! device handle (first reproducing the vendor's exact `OpenOptions::read+write`,
//! then a raw CreateFileW with explicit FILE_SHARE_READ|WRITE), checks HIDP_CAPS,
//! and runs CTAP2 Init + GetInfo.
//!
//! Purpose: run as the interactive user AND as NT AUTHORITY\SYSTEM (via
//! `psexec -s`) to determine whether the os-error-5 (ACCESS_DENIED) on open is
//! session-level or machine-level.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::FromRawHandle;
use std::ptr;
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// WinAPI FFI (inlined — no external crate dependency)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const GUID_DEVINTERFACE_HID: Guid = Guid {
    data1: 0x4d1e55b2,
    data2: 0xf16f,
    data3: 0x11cf,
    data4: [0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30],
};

const DIGCF_PRESENT: u32 = 0x00000002;
const DIGCF_DEVICEINTERFACE: u32 = 0x00000010;
const SPDRP_HARDWAREID: u32 = 0x00000001;
const DIOD_NO_ADD: u32 = 0x00000001;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

#[repr(C)]
struct SpDevinfoData {
    cb_size: u32,
    class_guid: Guid,
    dev_inst: u32,
    reserved: usize,
}

#[repr(C)]
struct SpDeviceInterfaceData {
    cb_size: u32,
    interface_class_guid: Guid,
    flags: u32,
    reserved: usize,
}

#[repr(C)]
struct SpDeviceInterfaceDetailDataW {
    cb_size: u32,
    device_path: [u16; 1],
}

type Hdevinfo = *mut c_void;

#[link(name = "setupapi")]
extern "system" {
    fn SetupDiGetClassDevsW(
        class_guid: *const Guid,
        enumerator: *const u8,
        hwnd: *mut c_void,
        flags: u32,
    ) -> Hdevinfo;
    fn SetupDiDestroyDeviceInfoList(set: Hdevinfo) -> i32;
    fn SetupDiEnumDeviceInterfaces(
        set: Hdevinfo,
        devinfo: *mut SpDevinfoData,
        class_guid: *const Guid,
        index: u32,
        didata: *mut SpDeviceInterfaceData,
    ) -> i32;
    fn SetupDiGetDeviceInterfaceDetailW(
        set: Hdevinfo,
        didata: *mut SpDeviceInterfaceData,
        detail: *mut c_void,
        detail_size: u32,
        required: *mut u32,
        devinfo: *mut SpDevinfoData,
    ) -> i32;
    fn SetupDiOpenDeviceInterfaceW(
        set: Hdevinfo,
        device_path: *const u16,
        flags: u32,
        devinfo: *mut SpDevinfoData,
    ) -> i32;
    fn SetupDiGetDeviceRegistryPropertyW(
        set: Hdevinfo,
        devinfo: *mut SpDevinfoData,
        prop: u32,
        reg_type: *mut u32,
        buffer: *mut c_void,
        buffer_size: u32,
        required: *mut c_void,
    ) -> i32;
}

#[link(name = "hid")]
extern "system" {
    fn HidD_GetPreparsedData(device: *mut c_void, preparsed: *mut *mut c_void) -> i32;
    fn HidD_FreePreparsedData(preparsed: *mut c_void) -> i32;
    fn HidP_GetCaps(preparsed: *mut c_void, caps: *mut c_void) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        lpfilename: *const u16,
        desiredaccess: u32,
        sharemode: u32,
        securityattributes: *mut c_void,
        creationdisposition: u32,
        flags: u32,
        templatefile: *mut c_void,
    ) -> isize;
    fn GetLastError() -> u32;
}

// ---------------------------------------------------------------------------
// HID frame constants (from FIDO U2F/CTAP2 HID protocol + vendor consts.rs)
// ---------------------------------------------------------------------------

const MAX_HID_RPT_SIZE: usize = 64;
const CID_BROADCAST: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_U2FHID: u16 = 0x01;

// CTAPHID command bytes (include TYPE_INIT 0x80)
const CMD_INIT: u8 = 0x86; // 0x80 | 0x06
const CMD_CBOR: u8 = 0x90; // 0x80 | 0x10 (CTAPHID_CBOR)
const CMD_KEEPALIVE: u8 = 0xbb; // 0x80 | 0x3b

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn now() -> SystemTime {
    SystemTime::now()
}

fn stamp() -> String {
    now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| format!("{:09.3}", d.as_secs_f32()))
        .unwrap_or_default()
}

fn log(msg: &str) {
    let line = format!("[{}] {}\n", stamp(), msg);
    // stdout (captured by psexec when run remotely)
    print!("{}", line);
    use std::fs::OpenOptions as _;
    use std::io::Write as _;
    // also persist to a file on the NB so it can be retrieved regardless of
    // how the process is launched (interactive / SYSTEM / scheduled task).
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\FidoVault\yk_out.log")
    {
        let _ = f.write_all(line.as_bytes());
    }
}

fn wide_to_string(bytes: &[u8]) -> String {
    let n = bytes.len() / 2;
    let wide = unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u16, n) };
    let wide: Vec<u16> = wide.iter().copied().take_while(|&w| w != 0).collect();
    String::from_utf16_lossy(&wide)
}

fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

struct HidDev {
    path_wide: Vec<u16>,
    path: String,
    hwid: String,
}

// ---------------------------------------------------------------------------
// enumeration (targeted: keep only VID_1050 & PID_0402)
// ---------------------------------------------------------------------------

fn enumerate_hid() -> Vec<HidDev> {
    let mut all: Vec<HidDev> = Vec::new();
    unsafe {
        let flags = DIGCF_PRESENT | DIGCF_DEVICEINTERFACE;
        let set = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_HID, ptr::null(), ptr::null_mut(), flags);
        // INVALID_HANDLE_VALUE = !0 as pointer; a null handle is not returned
        // (0) — failure is signaled by -1.
        if set == (-1isize as *mut c_void) || set.is_null() {
            let err = last_error();
            log(&format!(
                "SetupDiGetClassDevsW FAILED err={:?} (handle {:?})",
                err.raw_os_error(),
                set
            ));
            return all;
        }
        log(&format!(
            "SetupDiGetClassDevsW OK (flags=0x{:08x} PRESENT|DEVICEINTERFACE)",
            flags
        ));

        let mut index: u32 = 0;
        loop {
            let mut didata = mem::zeroed::<SpDeviceInterfaceData>();
            didata.cb_size = mem::size_of::<SpDeviceInterfaceData>() as u32;
            let ok = SetupDiEnumDeviceInterfaces(
                set,
                ptr::null_mut(),
                &GUID_DEVINTERFACE_HID,
                index,
                &mut didata,
            );
            if ok == 0 {
                break;
            }

            // two-step: query required detail size, then fill
            let mut required: u32 = 0;
            SetupDiGetDeviceInterfaceDetailW(
                set,
                &mut didata,
                ptr::null_mut(),
                0,
                &mut required,
                ptr::null_mut(),
            );
            if required == 0 {
                index += 1;
                continue;
            }
            let mut detail: Vec<u8> = vec![0u8; required as usize];
            let cb = mem::size_of::<SpDeviceInterfaceDetailDataW>() as u32;
            detail[0..4].copy_from_slice(&cb.to_ne_bytes());
            let ok = SetupDiGetDeviceInterfaceDetailW(
                set,
                &mut didata,
                detail.as_mut_ptr() as *mut c_void,
                required,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if ok == 0 {
                index += 1;
                continue;
            }
            // wide device path lives at detail[4..]
            let path_wide: Vec<u16> = unsafe {
                std::slice::from_raw_parts(
                    detail.as_ptr().add(4) as *const u16,
                    (detail.len() - 4) / 2,
                )
            }
            .iter()
            .copied()
            .take_while(|&w| w != 0)
            .collect();
            if path_wide.is_empty() {
                index += 1;
                continue;
            }
            let path = String::from_utf16_lossy(&path_wide);

            // fetch SPDRP_HARDWAREID for this interface
            let mut devinfo = mem::zeroed::<SpDevinfoData>();
            devinfo.cb_size = mem::size_of::<SpDevinfoData>() as u32;
            let mut hwid = String::new();
            if SetupDiOpenDeviceInterfaceW(set, path_wide.as_ptr(), DIOD_NO_ADD, &mut devinfo) != 0
            {
                let mut hwbuf: Vec<u8> = vec![0u8; 300];
                let mut regtype: u32 = 0;
                if SetupDiGetDeviceRegistryPropertyW(
                    set,
                    &mut devinfo,
                    SPDRP_HARDWAREID,
                    &mut regtype,
                    hwbuf.as_mut_ptr() as *mut c_void,
                    hwbuf.len() as u32,
                    ptr::null_mut(),
                ) != 0
                {
                    hwid = wide_to_string(&hwbuf);
                }
            }

            all.push(HidDev {
                path_wide,
                path,
                hwid,
            });
            index += 1;
        }
        SetupDiDestroyDeviceInfoList(set);
    }
    all
}

fn is_yubikey(hwid: &str, path: &str) -> bool {
    let h = hwid.to_lowercase();
    if h.contains("vid_1050") && h.contains("pid_0402") {
        return true;
    }
    // Fallback: the device interface path itself carries the USB hwid for
    // composite-interface devices whose SPDRP_HARDWAREID is empty, e.g.
    // \\?\hid#vid_1050&pid_0402#7&...
    let p = path.to_lowercase();
    p.contains("vid_1050") && p.contains("pid_0402")
}

// ---------------------------------------------------------------------------
// open paths
// ---------------------------------------------------------------------------

fn open_std(path_wide: &[u16]) -> Result<File, String> {
    // reproduces vendor device.rs exactly: OpenOptions::read(true).write(true)
    let os = OsString::from_wide(path_wide);
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&os)
        .map_err(|e| format!("os error {:?} ({})", e.raw_os_error(), e))
}

fn open_raw(path_wide: &[u16], share: u32) -> Result<File, String> {
    unsafe {
        // CreateFileW needs a NULL-terminated wide path. path_wide was built
        // with take_while(|w| w != 0), so it has NO trailing 0 — pass a
        // null-terminated copy, otherwise CreateFileW reads past the buffer
        // and fails with ERROR_PATH_NOT_FOUND (win32=3).
        let mut path_buf: Vec<u16> = path_wide.to_vec();
        path_buf.push(0);
        let h = CreateFileW(
            path_buf.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            share,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );
        if h == -1isize {
            let code = GetLastError();
            Err(format!(
                "CreateFileW failed win32={} (os error {})",
                code, code
            ))
        } else {
            // NB: File::from_raw_handle takes ownership; the returned File
            // must outlive any use of the handle (it lives in the caller's
            // scope). Do NOT wrap in a nested block or the File is dropped
            // and the handle closed.
            Ok(File::from_raw_handle(h as *mut c_void))
        }
    }
}

// ---------------------------------------------------------------------------
// HIDP_CAPS check
// ---------------------------------------------------------------------------

fn check_caps(file: &File) -> Result<(u16, u16, u16, u16), String> {
    use std::os::windows::io::AsRawHandle;
    let handle: *mut c_void = file.as_raw_handle() as *mut c_void;
    let mut preparsed: *mut c_void = ptr::null_mut();
    unsafe {
        // HidD_GetPreparsedData returns BOOL: 0 (FALSE) = failure.
        let rv = HidD_GetPreparsedData(handle, &mut preparsed);
        if rv == 0 || preparsed.is_null() {
            let e = last_error();
            return Err(format!(
                "HidD_GetPreparsedData FAILED (BOOL=0) win32={:?} ({:?})",
                e.raw_os_error(),
                e
            ));
        }
        let mut caps_buf = vec![0u8; 512];
        // HidP_GetCaps returns NTSTATUS. Success is signalled by the severity
        // bits (31:30) == 00, NOT by value == 0 (0x00110000 is a
        // success-severity status that still fills the buffer).
        let status = HidP_GetCaps(preparsed, caps_buf.as_mut_ptr() as *mut c_void);
        HidD_FreePreparsedData(preparsed);
        if (status as u32) & 0xC000_0000 != 0 {
            // severity = error
            return Err(format!(
                "HidP_GetCaps ntstatus=0x{:08x} (severity=error)",
                status as u32
            ));
        }
        // HIDP_CAPS offsets:
        //   0 bcdVersion, 2 bcdHIDClass, 4 wCountryCode, 6 wLanguageID,
        //   8 wVendorId, 10 wProductId, 12 wVersionNumber,
        //   14 bCollectionNumber, 16 bUsagePage, 18 bUsage,
        //   20 bInputReportCnt, 22 bOutputReportCnt, 24 bFeatureReportCnt
        let vid = u16::from_ne_bytes([caps_buf[8], caps_buf[9]]);
        let pid = u16::from_ne_bytes([caps_buf[10], caps_buf[11]]);
        let usage_page = u16::from_ne_bytes([caps_buf[16], caps_buf[17]]);
        let usage = u16::from_ne_bytes([caps_buf[18], caps_buf[19]]);
        Ok((usage_page, usage, vid, pid))
    }
}

// ---------------------------------------------------------------------------
// CTAP2 framing (mirrors vendor u2ftypes.rs / hid.rs)
// ---------------------------------------------------------------------------

fn write_init_frame(file: &mut File, cid: [u8; 4], cmd: u8, data: &[u8]) -> Result<(), String> {
    if data.len() > 0xffff {
        return Err("payload too large".into());
    }
    let inline = MAX_HID_RPT_SIZE - 7; // 57 bytes of data in the init frame
    let first = std::cmp::min(data.len(), inline);
    let mut frame = [0u8; MAX_HID_RPT_SIZE + 1]; // report id + 64
    frame[1..5].copy_from_slice(&cid);
    frame[5] = cmd;
    frame[6] = (data.len() >> 8) as u8;
    frame[7] = (data.len() & 0xff) as u8;
    frame[8..8 + first].copy_from_slice(&data[..first]);
    file.write_all(&frame).map_err(|e| e.to_string())?;

    let mut offset = first;
    let mut seq: u8 = 0;
    while offset < data.len() {
        let chunk = MAX_HID_RPT_SIZE - 5; // 59 bytes in a cont frame
        let take = std::cmp::min(chunk, data.len() - offset);
        let mut cframe = [0u8; MAX_HID_RPT_SIZE + 1];
        cframe[1..5].copy_from_slice(&cid);
        cframe[5] = seq;
        cframe[6..6 + take].copy_from_slice(&data[offset..offset + take]);
        file.write_all(&cframe).map_err(|e| e.to_string())?;
        offset += take;
        seq += 1;
    }
    Ok(())
}

struct Frame {
    cid: [u8; 4],
    cmd: u8,
    total: usize,
    data: Vec<u8>,
}

fn read_frame(file: &mut File) -> Result<Frame, String> {
    let mut buf = [0u8; MAX_HID_RPT_SIZE + 1];
    file.read_exact(&mut buf).map_err(|e| e.to_string())?;
    let cid = [buf[1], buf[2], buf[3], buf[4]];
    let cmd = buf[5];
    let total = ((buf[6] as usize) << 8) | (buf[7] as usize);
    let inline = MAX_HID_RPT_SIZE - 7;
    let first = std::cmp::min(total, inline);
    let mut data = buf[8..8 + first].to_vec();
    let mut seq: u8 = 0;
    while data.len() < total {
        let mut cbuf = [0u8; MAX_HID_RPT_SIZE + 1];
        file.read_exact(&mut cbuf).map_err(|e| e.to_string())?;
        // cont: cid=[1..5], seq=[5], data=[6..]
        if cbuf[1..5] != cid {
            return Err(format!("cont cid mismatch seq={}", seq));
        }
        let chunk = MAX_HID_RPT_SIZE - 5;
        let need = total - data.len();
        let take = std::cmp::min(chunk, need);
        data.extend_from_slice(&cbuf[6..6 + take]);
        seq += 1;
    }
    Ok(Frame {
        cid,
        cmd,
        total,
        data,
    })
}

/// read frames until one with the given cid and a non-keepalive cmd appears.
fn read_response(
    file: &mut File,
    cid: [u8; 4],
    timeout: Duration,
) -> Result<(u8, Vec<u8>), String> {
    let start = now();
    loop {
        if now().duration_since(start).unwrap_or_default() > timeout {
            return Err(format!(
                "timeout waiting for response ({} ms)",
                timeout.as_millis()
            ));
        }
        let f = read_frame(file)?;
        if f.cid != cid {
            continue;
        }
        if f.cmd == CMD_KEEPALIVE {
            continue; // skip keepalives
        }
        return Ok((f.cmd, f.data));
    }
}

fn ctap2_init(file: &mut File) -> Result<[u8; 4], String> {
    let mut nonce = [0u8; 8];
    // best-effort nonce from SystemTime (vendor uses thread_rng; fine for probe)
    let t = now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for i in 0..8 {
        nonce[i] = (t >> (8 * i)) as u8;
    }
    write_init_frame(file, CID_BROADCAST, CMD_INIT, &nonce)?;
    let (cmd, data) = read_response(file, CID_BROADCAST, Duration::from_secs(10))?;
    if cmd != CMD_INIT {
        return Err(format!("expected init response, got cmd={:#x}", cmd));
    }
    if data.len() < 17 {
        return Err(format!("init response too short ({} bytes)", data.len()));
    }
    if data[..8] != nonce {
        return Err("init nonce mismatch".into());
    }
    let cid = [data[8], data[9], data[10], data[11]];
    Ok(cid)
}

fn ctap2_getinfo(file: &mut File, cid: [u8; 4]) -> Result<Vec<u8>, String> {
    write_init_frame(file, cid, CMD_CBOR, &[0x04])?; // 0x04 = authenticatorGetInfo
    let (cmd, data) = read_response(file, cid, Duration::from_secs(10))?;
    if cmd != CMD_CBOR {
        return Err(format!("expected cbor response, got cmd={:#x}", cmd));
    }
    Ok(data)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    log("=== yk_open_test start ===");

    // who are we?
    let who = std::process::Command::new("whoami")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|e| format!("whoami failed: {}", e));
    log(&format!("identity: {}", who));
    let as_system = who.contains("nt authority\\system") || who.contains("SYSTEM");
    log(&format!("running as SYSTEM: {}", as_system));

    let all = enumerate_hid();
    log(&format!("total HID interfaces enumerated: {}", all.len()));

    let yubi: Vec<&HidDev> = all
        .iter()
        .filter(|d| is_yubikey(&d.hwid, &d.path))
        .collect();
    if yubi.is_empty() {
        log("NO YubiKey (VID_1050 & PID_0402) interface found among enumerated HID devices");
        for (i, d) in all.iter().take(40).enumerate() {
            log(&format!("   hid[{}] hwid={} path={}", i, d.hwid, d.path));
        }
        log("=== RESULT: DEVICE NOT FOUND ===");
        return;
    }

    for d in yubi.iter() {
        log(&format!("TARGET YubiKey hwid={} path={}", d.hwid, d.path));
    }

    // use the first matching interface
    let target = yubi[0];

    // 1) reproduce vendor open (std OpenOptions, no explicit share flags)
    log("--- open #1: std OpenOptions read+write (vendor parity) ---");
    match open_std(&target.path_wide) {
        Ok(mut file) => {
            log("open #1 OK (std OpenOptions)");
            run_ctap2_probe(&mut file, "std");
            // File dropped here
        }
        Err(e) => {
            log(&format!("open #1 FAILED: {}", e));
        }
    }

    // 2) raw CreateFileW with explicit share flags
    log("--- open #2: CreateFileW GENERIC_READ|WRITE + FILE_SHARE_READ|WRITE ---");
    match open_raw(&target.path_wide, FILE_SHARE_READ | FILE_SHARE_WRITE) {
        Ok(mut file) => {
            log("open #2 OK (CreateFileW share RW)");
            run_ctap2_probe(&mut file, "raw");
        }
        Err(e) => {
            log(&format!("open #2 FAILED: {}", e));
        }
    }

    // 3) raw CreateFileW with NO share (closest to FILE_SHARE_NONE)
    log("--- open #3: CreateFileW GENERIC_READ|WRITE + share NONE ---");
    match open_raw(&target.path_wide, 0) {
        Ok(mut file) => {
            log("open #3 OK (CreateFileW share NONE)");
            run_ctap2_probe(&mut file, "raw-nes");
        }
        Err(e) => {
            log(&format!("open #3 FAILED: {}", e));
        }
    }

    log("=== yk_open_test end ===");
}

fn run_ctap2_probe(file: &mut File, tag: &str) {
    // caps (informational only — do NOT block; the definitive test below is
    // CTAP2 Init/GetInfo, and we already narrowed the target to the YubiKey
    // FIDO interface by VID/PID).
    match check_caps(file) {
        Ok((usage_page, usage, vid, pid)) => {
            let is_fido = usage_page == FIDO_USAGE_PAGE && usage == FIDO_USAGE_U2FHID;
            log(&format!(
                "[{}] caps: usage_page={:#06x} usage={:#04x} vid={:#06x} pid={:#04x} -> {}",
                tag,
                usage_page,
                usage,
                vid,
                pid,
                if is_fido {
                    "FIDO U2F HID"
                } else {
                    "not FIDO U2F HID"
                }
            ));
        }
        Err(e) => {
            log(&format!(
                "[{}] caps check failed (non-blocking): {}",
                tag, e
            ));
        }
    }

    // init (the decisive open test: the device must answer a U2F HID Init)
    let cid = match ctap2_init(file) {
        Ok(cid) => cid,
        Err(e) => {
            log(&format!("[{}] CTAP2 Init FAILED: {}", tag, e));
            return;
        }
    };
    log(&format!(
        "[{}] CTAP2 Init OK, cid={:02x}{:02x}{:02x}{:02x}",
        tag, cid[0], cid[1], cid[2], cid[3]
    ));

    // get info
    match ctap2_getinfo(file, cid) {
        Ok(data) => {
            log(&format!(
                "[{}] CTAP2 GetInfo OK, {} bytes, head={}",
                tag,
                data.len(),
                hex(&data[..data.len().min(48)])
            ));
            log(&format!("[{}] *** FULL CTAP2 PROBE SUCCESS ***", tag));
        }
        Err(e) => {
            log(&format!("[{}] CTAP2 GetInfo FAILED: {}", tag, e));
        }
    }
}
