//! vault_cli：端到端驗證 CLI（Gate 2/3/4/5/6/8 用）。
//!
//! 用法（於 src-tauri/ 下）：
//!   cargo run --example vault_cli -- create     --path P --pw PASS [--kind fp|pin|touch]
//!   cargo run --example vault_cli -- login-pw   --path P --pw PASS
//!   cargo run --example vault_cli -- register-key --path P [--kind fp|pin|touch]
//!   cargo run --example vault_cli -- login-key  --path P --idx N [--pin PIN]
//!   cargo run --example vault_cli -- add-entry  --path P --pw PASS --site S --account A [--pass PW] [--notes N]
//!   cargo run --example vault_cli -- update-entry --path P --pw PASS --id ID [--pass PW] [--notes N]
//!   cargo run --example vault_cli -- del-entry  --path P --pw PASS --id ID
//!   cargo run --example vault_cli -- list       --path P --pw PASS
//!   cargo run --example vault_cli -- audit      --path P --pw PASS
//!   cargo run --example vault_cli -- keys       --path P [--pw PASS]
//!   cargo run --example vault_cli -- remove-key --path P --pw PASS --idx N
//!   cargo run --example vault_cli -- set-idle   --path P --pw PASS --minutes M
//!   cargo run --example vault_cli -- copy-test  --src A --dst B --pw PASS [--key-idx N]

use portable_fido_vault::fido2::{FidoBackend, KeyKind, MockBackend};
#[cfg(feature = "real-ctap")]
use portable_fido_vault::fido2::RealBackend;
use portable_fido_vault::vault::{failures_path, Vault};
use std::path::PathBuf;

struct Opts {
    path: Option<PathBuf>,
    pw: Option<String>,
    kind: Option<KeyKind>,
    idx: Option<usize>,
    pin: Option<String>,
    site: Option<String>,
    account: Option<String>,
    pass: Option<String>,
    notes: Option<String>,
    id: Option<String>,
    minutes: Option<u32>,
    src: Option<PathBuf>,
    dst: Option<PathBuf>,
    no_prf: bool, // 模擬不支援 hmac-secret/PRF 的金鑰（驗證裁決②拒絕註冊）
    authenticator: String, // mock（預設）| hw（實體 CTAP2，需 feature real-ctap）
}

fn parse(args: &[String]) -> (String, Opts) {
    let mut o = Opts {
        path: None, pw: None, kind: None, idx: None, pin: None,
        site: None, account: None, pass: None, notes: None, id: None,
        minutes: None, src: None, dst: None, no_prf: false, authenticator: "mock".into(),
    };
    let mut cmd = String::from("help");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            a if !a.starts_with("--") => cmd = a.to_string(),
            "--path" => o.path = Some(PathBuf::from(next(args, &mut i))),
            "--pw" => o.pw = Some(next(args, &mut i)),
            "--kind" => o.kind = KeyKind::parse(&next(args, &mut i)),
            "--idx" => o.idx = Some(next(args, &mut i).parse().unwrap_or(0)),
            "--pin" => o.pin = Some(next(args, &mut i)),
            "--site" => o.site = Some(next(args, &mut i)),
            "--account" => o.account = Some(next(args, &mut i)),
            "--pass" => o.pass = Some(next(args, &mut i)),
            "--notes" => o.notes = Some(next(args, &mut i)),
            "--id" => o.id = Some(next(args, &mut i)),
            "--minutes" => o.minutes = Some(next(args, &mut i).parse().unwrap_or(5)),
            "--src" => o.src = Some(PathBuf::from(next(args, &mut i))),
            "--dst" => o.dst = Some(PathBuf::from(next(args, &mut i))),
            "--no-prf" => o.no_prf = true,
            "--authenticator" => o.authenticator = next(args, &mut i),
            _ => {}
        }
        i += 1;
    }
    (cmd, o)
}

fn next(args: &[String], i: &mut usize) -> String {
    *i += 1;
    args.get(*i).cloned().unwrap_or_default()
}

/// 依 --authenticator 建後端（mock 預設；hw = 實體 CTAP2，需 feature real-ctap）。
fn make_backend(auth: &str, kind: Option<KeyKind>, prf: bool) -> Box<dyn FidoBackend> {
    if auth.eq_ignore_ascii_case("hw") {
        #[cfg(feature = "real-ctap")]
        {
            return Box::new(RealBackend::new());
        }
        #[cfg(not(feature = "real-ctap"))]
        {
            eprintln!("警告：--authenticator=hw 需以 --features real-ctap 建置；改用 mock");
        }
    }
    let b = match kind {
        Some(k) => MockBackend::new().with_next_kind(k),
        None => MockBackend::new(),
    };
    Box::new(b.with_prf(prf))
}

fn open_with_pw(path: &PathBuf, pw: &str) -> Result<Vault, String> {
    Vault::open_password(path, pw).map_err(|e| e.to_string())
}

fn main() {
    match run() {
        Ok(m) => println!("{m}"),
        Err(m) => { eprintln!("{m}"); std::process::exit(1); }
    }
}

fn run() -> Result<String, String> {
    let (cmd, o) = parse(&std::env::args().skip(1).collect::<Vec<_>>());
    match cmd.as_str() {
        "create" => {
            let path = req_path(&o.path);
            let pw = o.pw.clone().unwrap_or_default();
            if pw.len() < 8 {
                Err("主密碼至少 8 字元".into())
            } else {
                let _ = std::fs::remove_file(&path); // CLI 測試用：重跑先清
                let v = Vault::create(&path, &pw).map_err(|e| e.to_string())?;
                drop(v);
                Ok(format!("OK created {}", path.display()))
            }
        }
        "login-pw" => {
            let path = req_path(&o.path);
            match open_with_pw(&path, o.pw.as_deref().unwrap_or("")) {
                Ok(v) => Ok(format!("OK login_success entries={}", v.entries().len())),
                Err(e) => Err(format!("FAIL {e}")),
            }
        }
        "login-key" => {
            let path = req_path(&o.path);
            let idx = o.idx.unwrap_or(0);
            // 讀 header 取 credential_id（不需 KEK）
            let (h, _) = read_header_only(&path)?;
            if idx >= h.key_slots.len() {
                return Err(format!("idx {idx} 超出（共 {} 支）", h.key_slots.len()));
            }
            let cid = h.key_slots[idx].credential_id.clone();
            let label = h.key_slots[idx].label.clone();
            let mut b = make_backend(&o.authenticator, None, true);
            match Vault::open_key(&path, &cid, o.pin.as_deref(), &mut *b) {
                Ok(v) => Ok(format!("OK login_success key=#{idx}({}) entries={}", label, v.entries().len())),
                Err(e) => Err(format!("FAIL {e}")),
            }
        }
        "register-key" => {
            let path = req_path(&o.path);
            let mut v = open_with_pw(&path, o.pw.as_deref().unwrap_or(""))?;
            let mut b = make_backend(&o.authenticator, o.kind, !o.no_prf);
            let reg = v.register_key(&mut *b, o.pin.as_deref()).map_err(|e| e.to_string())?;
            Ok(format!("OK key_registered idx={} label={} type={}", v.keys_meta().len() - 1, reg.label, reg.kind))
        }
        "add-entry" => {
            let path = req_path(&o.path);
            let mut v = open_with_pw(&path, o.pw.as_deref().unwrap_or(""))?;
            let id = v.add_entry(
                o.site.as_deref().unwrap_or("example.com"),
                o.account.as_deref().unwrap_or(""),
                o.pass.as_deref().unwrap_or(""),
                o.notes.as_deref().unwrap_or(""),
            ).map_err(|e| e.to_string())?;
            Ok(format!("OK entry_added id={id}"))
        }
        "update-entry" => {
            let path = req_path(&o.path);
            let mut v = open_with_pw(&path, o.pw.as_deref().unwrap_or(""))?;
            v.update_entry(
                o.id.as_deref().unwrap_or(""),
                o.site.as_deref(),
                o.account.as_deref(),
                o.pass.as_deref(),
                o.notes.as_deref(),
            ).map_err(|e| e.to_string())?;
            Ok("OK entry_updated".into())
        }
        "del-entry" => {
            let path = req_path(&o.path);
            let mut v = open_with_pw(&path, o.pw.as_deref().unwrap_or(""))?;
            v.delete_entry(o.id.as_deref().unwrap_or("")).map_err(|e| e.to_string())?;
            Ok("OK entry_deleted".into())
        }
        "list" => {
            let path = req_path(&o.path);
            let v = open_with_pw(&path, o.pw.as_deref().unwrap_or(""))?;
            let mut out = String::new();
            for e in v.entries() {
                out.push_str(&format!(
                    "  {} | site={} account={} created={} updated={}\n",
                    &e.id[..8.min(e.id.len())], e.site, e.account, e.created_at, e.updated_at
                ));
            }
            Ok(format!("entries={}:\n{}", v.entries().len(), out))
        }
        "audit" => {
            let path = req_path(&o.path);
            let v = open_with_pw(&path, o.pw.as_deref().unwrap_or(""))?;
            let mut out = String::new();
            for a in v.audit().iter().rev().take(50) {
                out.push_str(&format!("  {} [{}] {} :: {}\n", a.ts, a.event, a.method, a.detail));
            }
            Ok(format!("audit_events={} (最新 50):\n{}", v.audit().len(), out))
        }
        "keys" => {
            let path = req_path(&o.path);
            let (h, _) = read_header_only(&path)?;
            let mut out = String::new();
            for (i, s) in h.key_slots.iter().enumerate() {
                out.push_str(&format!("  #{} {} [{}] prompt={}\n", i, s.label, s.key_type, s.key_type.prompt_zh()));
            }
            Ok(format!("keys={}:\n{}", h.key_slots.len(), out))
        }
        "remove-key" => {
            let path = req_path(&o.path);
            let mut v = open_with_pw(&path, o.pw.as_deref().unwrap_or(""))?;
            let idx = o.idx.unwrap_or(0);
            let metas = v.keys_meta();
            if idx >= metas.len() { return Err(format!("idx {idx} 超出")); }
            v.remove_key(&metas[idx].0).map_err(|e| e.to_string())?;
            Ok(format!("OK key_removed remaining={}", v.keys_meta().len()))
        }
        "set-idle" => {
            let path = req_path(&o.path);
            let mut v = open_with_pw(&path, o.pw.as_deref().unwrap_or(""))?;
            v.set_idle_lock(o.minutes.unwrap_or(5)).map_err(|e| e.to_string())?;
            Ok(format!("OK idle_lock={}", v.settings().idle_lock_minutes))
        }
        "copy-test" => {
            // Gate 8：加密檔直拷至別路徑 → 同密碼/金鑰可解密。
            let (a, b) = match (&o.src, &o.dst) {
                (Some(a), Some(b)) => (a.clone(), b.clone()),
                _ => return Err("需 --src 與 --dst".into()),
            };
            std::fs::copy(&a, &b).map_err(|e| e.to_string())?;
            if let Some(ki) = o.idx {
                let (h, _) = read_header_only(&b)?;
                if ki >= h.key_slots.len() { return Err("idx 超出".into()); }
                let cid = h.key_slots[ki].credential_id.clone();
                let mut bb = make_backend(&o.authenticator, None, true);
                Vault::open_key(&b, &cid, o.pin.as_deref(), &mut *bb).map_err(|e| e.to_string())?;
                Ok(format!("OK copy + key-login #{ki} success at {}", b.display()))
            } else {
                open_with_pw(&b, o.pw.as_deref().unwrap_or(""))?;
                Ok(format!("OK copy + password login success at {}", b.display()))
            }
        }
        "failure-demo" => {
            // Gate 2：錯誤密碼 → 拒絕 + sidecar 計一筆；成功後合併進 audit。
            let path = req_path(&o.path);
            let wrong = o.pw.clone().unwrap_or_default();
            match Vault::open_password(&path, &wrong) {
                Err(_) => {} // 預期失敗
                Ok(_) => return Err("意外：錯誤密碼竟登入成功".into()),
            }
            let fc = std::fs::read_to_string(failures_path(&path)).unwrap_or_default();
            Ok(format!("OK wrong-pw rejected; sidecar={fc}"))
        }
        _ => Err("help".into()),
    }
}

fn req_path(p: &Option<PathBuf>) -> PathBuf {
    p.clone().unwrap_or_else(|| panic!("需 --path"))
}

/// 只讀 header（不需 KEK）。
fn read_header_only(path: &PathBuf) -> Result<(portable_fido_vault::vault::Header, ()), String> {
    let buf = std::fs::read(path).map_err(|e| e.to_string())?;
    if buf.len() < 10 || &buf[..6] != portable_fido_vault::crypto::VAULT_MAGIC {
        return Err("非 vault.db".into());
    }
    let header_len = u32::from_le_bytes(buf[6..10].try_into().map_err(|_| "bad")?) as usize;
    let h: portable_fido_vault::vault::Header =
        serde_json::from_str(std::str::from_utf8(&buf[10..10 + header_len]).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    Ok((h, ()))
}
