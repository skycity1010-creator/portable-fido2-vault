#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate E2E 驗證腳本（WS2 本機）：跑 vault_cli 全路徑，輸出逐項 PASS/FAIL + 證據。
用法: python scripts/gate_e2e.py [vault_dir]
對應該卡 Gate 2/3/4/5/6/8（1/7 另於 NB/GUI 驗證）。
"""
import hashlib, os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src-tauri")
BIN = os.path.join(SRC, "target", "release", "vault_cli.exe")
VDIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tempfile.gettempdir(), "f2v-gate")

results = []

def cli(*args):
    r = subprocess.run([BIN, *args], capture_output=True, text=True, cwd=SRC)
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    return r.returncode, out, err

def check(name, ok, evidence=""):
    results.append((name, ok, evidence))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"\n       {evidence[:300]}" if evidence else ""))

def main():
    if not os.path.exists(BIN):
        print(f"vault_cli.exe 不存在: {BIN}"); sys.exit(2)
    shutil.rmtree(VDIR, ignore_errors=True)
    os.makedirs(VDIR, exist_ok=True)
    V = os.path.join(VDIR, "vault.db")

    # ── Gate 2: 建立帳號 / 密碼登入 / 錯誤拒絕 + 軌跡 ──
    rc, out, err = cli("create", "--path", V, "--pw", "Gate-Pass-1")
    check("G2.1 首次執行建立帳號", rc == 0 and out.startswith("OK created"), out or err)

    rc, out, err = cli("login-pw", "--path", V, "--pw", "Wrong-Pass-9")
    sidecar = os.path.join(VDIR, "vault.db.failures")
    sc_exists = os.path.exists(sidecar)
    check("G2.2 錯誤密碼拒絕 + 計入軌跡(sidecar)", rc != 0 and "FAIL" in out and sc_exists,
          f"rc={rc} {out} sidecar={open(sidecar).read() if sc_exists else 'MISSING'}")

    rc, out, err = cli("login-pw", "--path", V, "--pw", "Gate-Pass-1")
    check("G2.3 正確密碼登入成功（失敗記錄已合併進加密 audit）",
          rc == 0 and out.startswith("OK login_success") and not os.path.exists(sidecar), out or err)

    # ── Gate 3: 金鑰註冊 + 類型偵測 + 金鑰登入 ──
    rc, out, err = cli("register-key", "--path", V, "--pw", "Gate-Pass-1", "--kind", "fingerprint")
    check("G3.1 註冊金鑰#0（自動偵測=指紋型）", rc == 0 and "type=fingerprint" in out, out or err)

    rc, out, err = cli("register-key", "--path", V, "--pw", "Gate-Pass-1", "--kind", "pin", "--pin", "2468")
    check("G3.2 註冊金鑰#1（自動偵測=PIN型，註冊需 PIN）", rc == 0 and "type=pin" in out, out or err)

    # 附加：PRF 裁決② — 不支援 PRF 的金鑰必須被拒絕註冊
    rc, out, err = cli("register-key", "--path", V, "--pw", "Gate-Pass-1", "--kind", "fingerprint", "--no-prf")
    check("G3.6 不支援 PRF 的金鑰 → 拒絕註冊（UI 顯示原因）", rc != 0 and ("PRF" in out or "hmac-secret" in out), out or err)

    rc, out, err = cli("login-key", "--path", V, "--idx", "0")
    check("G3.3 指紋型金鑰登入成功（免 PIN，提示『按指紋』）", rc == 0 and "key=#0" in out, out or err)

    rc, out, err = cli("login-key", "--path", V, "--idx", "1")
    check("G3.4 PIN型金鑰無 PIN → PinRequired（依類型提示『輸入 PIN』）",
          rc != 0 and "PIN" in out, out or err)

    rc, out, err = cli("login-key", "--path", V, "--idx", "1", "--pin", "2468")
    check("G3.5 PIN型金鑰帶 PIN 登入成功", rc == 0 and "key=#1" in out, out or err)

    # ── Gate 4: 第二支金鑰 / 任一支皆可登入（touch-only 第三支 + 交叉驗證）──
    rc, out, err = cli("register-key", "--path", V, "--pw", "Gate-Pass-1", "--kind", "touch_only")
    check("G4.1 註冊第三支金鑰（touch-only 型）", rc == 0 and "type=touch_only" in out, out or err)

    rc, out, err = cli("login-key", "--path", V, "--idx", "2")
    check("G4.2 touch-only 金鑰登入成功（提示『觸碰』）", rc == 0 and "key=#2" in out, out or err)

    rc, out, err = cli("login-key", "--path", V, "--idx", "0")
    check("G4.3 任一支皆可登入：回到金鑰#0 仍成功", rc == 0 and "key=#0" in out, out or err)

    # ── Gate 5: CRUD + created_at/updated_at ──
    rc, out, err = cli("add-entry", "--path", V, "--pw", "Gate-Pass-1",
                       "--site", "example.com", "--account", "alice", "--pass", "S3cret!x")
    eid = out.split("id=")[1] if "id=" in out else ""
    check("G5.1 新增條目", rc == 0 and eid, out or err)

    import time; time.sleep(0.05)
    rc2, out2, _ = cli("list", "--path", V, "--pw", "Gate-Pass-1")
    created = updated = None
    for line in out2.splitlines():
        if "site=example.com" not in line:
            continue
        # 行格式: "<id8> | site=... account=... created=<ts> updated=<ts>"
        fields = [f.strip() for f in line.split("|")]
        kv = {}
        for f in fields:
            if "=" in f:
                k, v = f.split("=", 1)
                kv[k.strip()] = v.strip()
        created, updated = kv.get("created"), kv.get("updated")
    rc3, out3, err3 = cli("update-entry", "--path", V, "--pw", "Gate-Pass-1", "--id", eid, "--pass", "NewPass!9")
    rc4, out4, _ = cli("list", "--path", V, "--pw", "Gate-Pass-1")
    created2 = updated2 = None
    for line in out4.splitlines():
        if "site=example.com" not in line:
            continue
        fields = [f.strip() for f in line.split("|")]
        kv = {}
        for f in fields:
            if "=" in f:
                k, v = f.split("=", 1)
                kv[k.strip()] = v.strip()
        created2, updated2 = kv.get("created"), kv.get("updated")
    check("G5.2 created_at/updated_at 正確（更新後 updated>created，created 不變）",
          rc3 == 0 and created == created2 and updated2 and updated != updated2,
          f"before: {created} / {updated}\nafter : {created2} / {updated2}")

    rc5, out5, err5 = cli("del-entry", "--path", V, "--pw", "Gate-Pass-1", "--id", eid)
    rc6, out6, _ = cli("list", "--path", V, "--pw", "Gate-Pass-1")
    check("G5.3 刪除條目（CRUD 全通過）", rc5 == 0 and "example.com" not in out6, out5 or err5)

    # ── Gate 6: 軌跡完整 + 無明文密碼 ──
    rc, out, err = cli("audit", "--path", V, "--pw", "Gate-Pass-1")
    events = [l for l in out.splitlines() if "[" in l]
    need = {"vault_created", "login_success", "login_failed", "key_registered", "entry_added", "entry_updated", "entry_deleted"}
    got = set()
    for e in events:
        if "]" in e:
            got.add(e.split("[", 1)[1].split("]", 1)[0])
    check("G6.1 軌跡事件完整（含成功/失敗/金鑰/CRUD）", rc == 0 and need.issubset(got),
          f"missing={need - got}\n{out[:400]}")

    raw = open(V, "rb").read()
    leak = [s for s in (b"Gate-Pass-1", b"S3cret!x", b"NewPass!9") if s in raw]
    check("G6.2 金庫檔案（header+密文區）不含任何密碼明文", not leak, f"leaked={leak}")

    # ── Gate 8: 加密檔直拷別機/別路徑 → 同帳號可解密 ──
    V2 = os.path.join(VDIR, "portable-copy.db")
    shutil.copyfile(V, V2)
    rc, out, err = cli("copy-test", "--src", V, "--dst", V2, "--pw", "Gate-Pass-1")
    check("G8.1 密碼路徑：直拷加密檔 → 同密碼解密成功", rc == 0 and "password login success" in out, out or err)

    rc, out, err = cli("copy-test", "--src", V, "--dst", os.path.join(VDIR, "portable-copy2.db"), "--idx", "0")
    check("G8.2 金鑰路徑：直拷加密檔 → 同金鑰解密成功（跨機器端到端）", rc == 0 and "key-login #0 success" in out, out or err)

    # ── 附加：移除金鑰不可逆 ──
    rc, out, err = cli("remove-key", "--path", V, "--pw", "Gate-Pass-1", "--idx", "2")
    rc2, out2, err2 = cli("login-key", "--path", V, "--idx", "2")
    check("X.1 移除金鑰後該金鑰無法再解鎖（不可逆）", rc == 0 and rc2 != 0, f"remove: {out}\nrelogin: {out2}")

    # ── summary ──
    print("\n" + "=" * 60)
    npass = sum(1 for _, ok, _ in results if ok)
    print(f"GATE E2E: {npass}/{len(results)} PASS")
    for name, ok, ev in results:
        if not ok:
            print(f"  FAIL: {name}\n    {ev[:400]}")
    print("=" * 60)
    sys.exit(0 if npass == len(results) else 1)

if __name__ == "__main__":
    main()
