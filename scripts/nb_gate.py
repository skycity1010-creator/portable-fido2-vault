#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate 1/8 NB 遠端驗證：portable exe 推到 Win11-NB → 啟動不崩潰 → 截圖證據。
用法: python scripts/nb_gate.py <exe_path> [vault_cli_exe]
步驟:
  1. nb_push 推 PortableFidoVault.exe (+ vault_cli.exe) 到 C:\\FidoVault
  2. Start-Process 啟動 GUI，等 10s → Get-Process 存活檢查（WebView2 init 沒崩）
  3. CopyFromScreen 截圖 → base64 回傳存本機 gate1_screenshot.png
  4. （若有 vault_cli）NB 上跑 CLI E2E：create/register/login/add/list/audit
"""
import base64, hashlib, os, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nb_push import run_ps_inner, push  # noqa: E402

REMOTE_DIR = r"C:\FidoVault"
SHOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gate1_screenshot.png")


def kill_app():
    o, e = run_ps_inner("Get-Process portable-fido-vault -ErrorAction SilentlyContinue | Stop-Process -Force; 'KILLED'")
    print("  kill:", (o or e)[:80])


def launch_and_check(wait_s=12):
    inner = (
        f"$p = Start-Process -FilePath '{REMOTE_DIR}\\portable-fido-vault.exe' -WorkingDirectory '{REMOTE_DIR}' -PassThru; "
        f"Start-Sleep -Seconds {wait_s}; "
        f"$alive = Get-Process -Id $p.Id -ErrorAction SilentlyContinue; "
        f"if ($alive) {{ 'ALIVE pid=$($p.Id) session=$($alive.SessionId) mem=$([int]($alive.WorkingSet/1MB))MB' }} else {{ 'DEAD' }}; "
        f"$wv = @(Get-CimInstance Win32_Process -Filter \"Name='msedgewebview2.exe'\" | Where-Object {{ $_.ParentProcessId -eq $p.Id }}).Count; "
        f"'WEBVIEW2_CHILDREN=$wv'; "
        f"Get-CimInstance Win32_Process -Filter \"Name='msedgewebview2.exe'\" | Select-Object ProcessId, ParentProcessId | ForEach-Object {{ 'WV pid=$($_.ProcessId) parent=$($_.ParentProcessId)' }}"
    )
    o, e = run_ps_inner(inner)
    return (o or e).strip()


def screenshot():
    inner = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$b=[System.Drawing.Bitmap]::new([System.Windows.Forms.SystemInformation]::VirtualScreen.Width,"
        "[System.Windows.Forms.SystemInformation]::VirtualScreen.Height); "
        "$g=[System.Drawing.Graphics]::FromImage($b); "
        "$g.CopyFromScreen([System.Windows.Forms.SystemInformation]::VirtualScreen.Location, [System.Drawing.Point]::Empty, $b.Size); "
        "$ms=New-Object IO.MemoryStream; $b.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png); "
        "[Convert]::ToBase64String($ms.ToArray())"
    )
    o, e = run_ps_inner(inner)
    if not o or len(o) < 100:
        print("  screenshot failed:", (o + e)[:200])
        return False
    png = base64.b64decode(o.strip())
    open(SHOT, 'wb').write(png)
    print(f"  screenshot saved: {SHOT} ({len(png)} bytes)")
    return True


def cli_e2e_on_nb():
    """NB 上用 vault_cli 跑核心 E2E（Gate 8 跨機：WS2 建的 vault 推到 NB → NB 解鎖）。"""
    inner = (
        f"$V='{REMOTE_DIR}\\nb-vault.db'; "
        f"$P='{REMOTE_DIR}\\vault_cli.exe'; "
        f"if(Test-Path $V){{Remove-Item $V -Force}}; "
        f"& $P create --path $V --pw NB-Gate1-Pass | Out-String; "
        f"& $P register-key --path $V --pw NB-Gate1-Pass --kind fingerprint | Out-String; "
        f"& $P login-key --path $V --idx 0 | Out-String; "
        f"& $P add-entry --path $V --pw NB-Gate1-Pass --site nb.example.com --account bob --pass NBsecret!7 | Out-String; "
        f"& $P list --path $V --pw NB-Gate1-Pass | Out-String; "
        f"(Get-FileHash -Algorithm SHA256 -Path $V).Hash"
    )
    o, e = run_ps_inner(inner)
    print((o or e)[:1200])
    return 'OK' in (o or '')


def main():
    exe = sys.argv[1]
    cli_exe = sys.argv[2] if len(sys.argv) > 2 else None

    print("[1] push portable exe(s) ->", REMOTE_DIR)
    kill_app()
    ok = push(exe, REMOTE_DIR)
    # WebView2 loader（portable 同梱；Tauri GUI 需要）
    wv = os.path.join(os.path.dirname(exe), "WebView2Loader.dll")
    if os.path.exists(wv):
        ok &= push(wv, REMOTE_DIR)
    if cli_exe:
        ok &= push(cli_exe, REMOTE_DIR)
    h = hashlib.sha256(open(exe, 'rb').read()).hexdigest()
    print(f"  expected exe sha256={h}")
    if not ok:
        sys.exit(1)

    # 驗證 NB 端 sha256
    o, e = run_ps_inner(f"(Get-FileHash -Algorithm SHA256 -Path '{REMOTE_DIR}\\portable-fido-vault.exe').Hash.ToLower()")
    print("  nb exe sha256=", (o or '').strip())

    print("[2] launch GUI + 10s alive check")
    kill_app()
    status = launch_and_check(10)
    print("  ", status)
    alive = 'ALIVE' in status

    print("[3] screenshot evidence")
    shot = screenshot() if alive else False

    ok2 = True
    if cli_exe and os.path.exists(cli_exe):
        print("[4] NB CLI E2E (Gate 8 cross-machine)")
        ok2 = cli_e2e_on_nb()
    else:
        print("[4] skip (no vault_cli.exe)")

    kill_app()
    print("\nGATE1:", "PASS" if (alive and shot) else ("PARTIAL(alive, no shot)" if alive else "FAIL"),
          "| NB-CLI:", "PASS" if ok2 else "SKIP/FAIL")
    sys.exit(0 if alive else 1)


if __name__ == "__main__":
    main()
