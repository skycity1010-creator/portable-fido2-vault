#!/usr/bin/env python3
"""Push local files to Win11-NB via WinRM (base64 chunks), verify SHA256.
Inner PS scripts are base64-encoded to dodge quoting hell (UTF-8 BOM rule)."""
import base64, hashlib, subprocess, sys, os

REMOTE = "Win11-NB"
CHUNK = 8000

def run_ps_inner(inner_ps: str):
    b64 = base64.b64encode(inner_ps.encode('utf-8')).decode()
    outer = (f"$ErrorActionPreference='Stop'; "
             f"$sb=[scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}'))); "
             f"Invoke-Command -ComputerName {REMOTE} -UseSSL:$false -ScriptBlock $sb")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", outer],
                       capture_output=True, text=True)
    return (r.stdout or "").strip(), (r.stderr or "").strip()

def push(local_path, remote_dir=r"C:\FidoVault"):
    data = open(local_path, 'rb').read()
    b64 = base64.b64encode(data).decode()
    name = os.path.basename(local_path)
    out = f"{remote_dir}\\{name}"
    tmp = out + ".b64"

    o, e = run_ps_inner(f"if(-not(Test-Path '{remote_dir}')){{New-Item -ItemType Directory -Force -Path '{remote_dir}'|Out-Null}}; "
                        f"if(Test-Path '{tmp}'){{Remove-Item '{tmp}' -Force}}; if(Test-Path '{out}'){{Remove-Item '{out}' -Force}}; 'INIT_OK'")
    if 'INIT_OK' not in o:
        print("  init err:", (o + e)[:300]); return False

    for i in range(0, len(b64), CHUNK):
        c = b64[i:i+CHUNK]
        if i == 0:
            inner = f"[IO.File]::WriteAllText('{tmp}','{c}')"
        else:
            inner = (f"$s=[IO.File]::ReadAllText('{tmp}'); "
                     f"[IO.File]::WriteAllText('{tmp}',($s+'{c}'))")
        o, e = run_ps_inner(inner)
        if e and 'Exception' in e:
            print(f"  chunk {i//CHUNK} err:", e[:300]); return False

    inner = (f"$b=[Convert]::FromBase64String([IO.File]::ReadAllText('{tmp}')); "
             f"[IO.File]::WriteAllBytes('{out}',$b); Remove-Item '{tmp}' -Force; "
             f"$h=(Get-FileHash -Algorithm SHA256 -Path '{out}').Hash.ToLower(); \"DEPLOYED {name} sha256=$h\"")
    o, e = run_ps_inner(inner)
    print("  ", (o or e)[:300])
    return 'DEPLOYED' in o

if __name__ == "__main__":
    args = sys.argv[1:]
    rd = r"C:\FidoVault"
    if len(args) > 1 and not os.path.exists(args[-1]):
        rd = args.pop()
    ok = True
    for p in args:
        print(f"[push] {os.path.basename(p)} -> {rd}")
        ok &= push(p, rd)
        h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        print(f"  EXPECTED sha256={h}")
    sys.exit(0 if ok else 1)
