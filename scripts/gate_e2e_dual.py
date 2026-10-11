#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""雙群組控管版（v2）mock Gate E2E：以 dual_vault_cli（模擬金鑰）跨行程驗證 §6.1。

用法（於 src-tauri/ 下）:
  python ../scripts/gate_e2e_dual.py <新的測試資料夾> [--dual-cli PATH] [--single-cli PATH]

- 測試資料夾必須**不存在**（本腳本只在自己建立的資料夾內建立合成金庫，不刪除任何既有路徑）。
- 只使用合成密碼與模擬金鑰；不碰實體金鑰、不讀正式 vault。
- 預設 CLI 路徑為 CI 建置位置 target/release/examples/{dual_vault_cli,vault_cli}.exe。
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src-tauri")
EXE = ".exe" if os.name == "nt" else ""
DEFAULT_DUAL = os.path.join(SRC, "target", "release", "examples", "dual_vault_cli" + EXE)
DEFAULT_SINGLE = os.path.join(SRC, "target", "release", "examples", "vault_cli" + EXE)
MAGIC = b"F2VLT\x01"
PW = "Dual-Gate-Pass-1"

results = []


def check(name, ok, evidence=""):
    results.append((name, bool(ok), evidence))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"\n       {evidence[:300]}" if evidence else ""))


def run(binary, *args):
    try:
        r = subprocess.run([binary, *args], capture_output=True, text=True, encoding="utf-8",
                           cwd=SRC, timeout=120)
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT (120s)"
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def read_header(path):
    buf = read_bytes(path)
    if buf[:6] != MAGIC:
        raise ValueError(f"not a vault file: {path}")
    n = int.from_bytes(buf[6:10], "little")
    return json.loads(buf[10:10 + n].decode("utf-8")), buf[10 + n:]


def write_header(path, header, rest):
    data = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(MAGIC + len(data).to_bytes(4, "little") + data + rest)


def sidecar_methods(vault):
    p = vault + ".failures"
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [item["method"] for item in json.load(f)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vault_dir")
    ap.add_argument("--dual-cli", default=DEFAULT_DUAL)
    ap.add_argument("--single-cli", default=DEFAULT_SINGLE)
    a = ap.parse_args()
    for b in (a.dual_cli, a.single_cli):
        if not os.path.isfile(b):
            print(f"CLI 不存在: {b}")
            sys.exit(2)
    if os.path.exists(a.vault_dir):
        print(f"拒絕使用已存在的資料夾: {a.vault_dir}")
        sys.exit(2)
    os.makedirs(a.vault_dir)
    V = os.path.join(a.vault_dir, "vault.db")
    dual = lambda *x: run(a.dual_cli, *x)
    single = lambda *x: run(a.single_cli, *x)

    # ── 建立 v2 + break-glass ──
    rc, out = dual("create", "--path", V, "--pw", PW)
    h, _ = read_header(V)
    check("DG1.1 建立雙群組金庫（header v=2、policy=dual、dual_slot、時限鏡像 120）",
          rc == 0 and h.get("v") == 2 and h.get("policy") == "dual" and h.get("dual_slot")
          and h.get("dual_step_timeout_secs") == 120 and h.get("key_slots") == [], out)

    rc, out = dual("login-pw", "--path", V, "--pw", "Wrong-Pass-9")
    check("DG1.2 錯誤主密碼拒絕並記 sidecar（password-breakglass）",
          rc != 0 and sidecar_methods(V) == ["password-breakglass"], f"rc={rc} {out} {sidecar_methods(V)}")

    rc, out = dual("login-pw", "--path", V, "--pw", PW)
    check("DG1.3 主密碼 break-glass 完整解鎖（method=password-breakglass，sidecar 已併入 audit）",
          rc == 0 and "method=password-breakglass" in out and not os.path.exists(V + ".failures"), out)

    rc, out = dual("login-dual", "--path", V, "--first", "K1", "--second", "K2")
    check("DG1.4 尚無金鑰 → 金鑰登入拒絕（需 A、B 群組各至少一支）", rc != 0 and "A、B 群組各至少一支" in out, out)

    # ── 註冊（群組、excludeCredentials）──
    rc1, o1 = dual("register-key", "--path", V, "--pw", PW, "--device", "K1", "--group", "A", "--label", "王小明")
    rc_ready, o_ready = dual("login-dual", "--path", V, "--first", "K1", "--second", "K2")
    rc2, o2 = dual("register-key", "--path", V, "--pw", PW, "--device", "K2", "--group", "B", "--label", "李小華")
    rc3, o3 = dual("register-key", "--path", V, "--pw", PW, "--device", "K3", "--group", "A", "--label", "陳大同")
    h, _ = read_header(V)
    groups = [(s["label"], s.get("group")) for s in h["key_slots"]]
    check("DG2.1 註冊 K1→A、K2→B、K3→A，header 記錄群組",
          rc1 == rc2 == rc3 == 0 and groups == [("王小明", "A"), ("李小華", "B"), ("陳大同", "A")],
          f"{o1} | {o2} | {o3} | {groups}")
    check("DG2.2 只有 A 群組時金鑰登入仍拒絕", rc_ready != 0 and "A、B 群組各至少一支" in o_ready, o_ready)

    rcx, ox = dual("register-key", "--path", V, "--pw", PW, "--device", "K1", "--group", "B", "--label", "K1 again B")
    rcy, oy = dual("register-key", "--path", V, "--pw", PW, "--device", "K1", "--group", "A", "--label", "K1 again A")
    h, _ = read_header(V)
    check("DG2.3 同一支金鑰再註冊（選 B、選 A）→ 已註冊拒絕，slot 數不變",
          rcx != 0 and rcy != 0 and "已註冊於本金庫" in ox and "已註冊於本金庫" in oy and len(h["key_slots"]) == 3,
          f"{ox} | {oy} | slots={len(h['key_slots'])}")

    rc, out = dual("register-key", "--path", V, "--pw", PW, "--device", "K9", "--group", "C", "--label", "bad")
    check("DG2.4 群組只接受 A/B", rc != 0 and "只接受 A 或 B" in out and len(read_header(V)[0]["key_slots"]) == 3, out)

    # ── 兩步驟登入 ──
    rc, out = dual("login-dual", "--path", V, "--first", "K1", "--second", "K2")
    check("DG3.1 A(K1)→B(K2) 解鎖成功，audit method 依實際順序",
          rc == 0 and "STEP1 first_group=A first_label=王小明 timeout_secs=120" in out
          and "method=fido2-dual:A:王小明#" in out and "+B:李小華#" in out, out)

    rc, out = dual("login-dual", "--path", V, "--first", "K2", "--second", "K3")
    check("DG3.2 B(K2)→A(K3) 解鎖成功", rc == 0 and "method=fido2-dual:B:李小華#" in out and "+A:陳大同#" in out, out)

    before = sha256(V)
    rc_a, out_a = dual("login-dual", "--path", V, "--first", "K1", "--second", "K3")
    rc_b, out_b = dual("login-dual", "--path", V, "--first", "K1", "--second", "K1")
    check("DG3.3 第二步用同群組金鑰（K1→K3、K1→K1）→ 無法完成、金庫不變",
          rc_a != 0 and rc_b != 0 and "step2: " in out_a and "step2: " in out_b
          and "允許清單" in out_a and "允許清單" in out_b and sha256(V) == before,
          f"{out_a} | {out_b}")

    rc, out = dual("login-dual", "--path", V, "--first", "K9", "--second", "K2")
    check("DG3.4 未註冊金鑰無法完成第一步", rc != 0 and "step1: " in out and "允許清單" in out and sha256(V) == before, out)

    # ── 逾時 / 取消 ──
    rc, out = dual("login-dual", "--path", V, "--first", "K1", "--second", "K2", "--advance-secs", "121")
    check("DG4.1 第一步後超過 120 秒 → 逾時拒絕並記 fido2-dual-timeout",
          rc != 0 and "時限" in out and sidecar_methods(V)[-1:] == ["fido2-dual-timeout"] and sha256(V) == before, out)

    rc, out = dual("login-dual", "--path", V, "--first", "K1", "--cancel")
    check("DG4.2 第一步後取消 → 記 fido2-dual-cancel、金庫不變",
          rc == 0 and "OK cancelled" in out and sidecar_methods(V)[-1:] == ["fido2-dual-cancel"] and sha256(V) == before, out)

    rc, out = dual("login-dual", "--path", V, "--first", "K1", "--second", "K2", "--advance-secs", "120")
    check("DG4.3 恰好在截止時間完成仍可解鎖，並把先前失敗併入 audit",
          rc == 0 and "method=fido2-dual:A:" in out and not os.path.exists(V + ".failures"), out)

    # ── 時限設定 ──
    rc_lo, o_lo = dual("set-timeout", "--path", V, "--pw", PW, "--secs", "29")
    rc_hi, o_hi = dual("set-timeout", "--path", V, "--pw", PW, "--secs", "601")
    rc, out = dual("set-timeout", "--path", V, "--pw", PW, "--secs", "60")
    h, _ = read_header(V)
    check("DG5.1 時限 29/601 拒絕；60 套用並同步明文鏡像",
          rc_lo != 0 and rc_hi != 0 and "30–600" in o_lo and "30–600" in o_hi
          and rc == 0 and h.get("dual_step_timeout_secs") == 60, f"{o_lo} | {o_hi} | {out}")
    rc61, o61 = dual("login-dual", "--path", V, "--first", "K2", "--second", "K1", "--advance-secs", "61")
    timeout_recorded = sidecar_methods(V)[-1:] == ["fido2-dual-timeout"]
    rc59, o59 = dual("login-dual", "--path", V, "--first", "K2", "--second", "K1", "--advance-secs", "59")
    check("DG5.2 新時限 60 秒生效（61 秒逾時並記錄、59 秒成功）",
          rc61 != 0 and "timeout_secs=60" in o61 and "時限" in o61 and timeout_recorded and rc59 == 0,
          f"{o61} | {o59}")

    h, rest = read_header(V)
    h["dual_step_timeout_secs"] = 5
    write_header(V, h, rest)
    rc_k, o_k = dual("login-dual", "--path", V, "--first", "K1", "--cancel")
    rc, out = dual("login-pw", "--path", V, "--pw", PW)
    h, _ = read_header(V)
    rc_a, o_a = dual("audit", "--path", V, "--pw", PW)
    check("DG5.3 竄改明文鏡像為 5：登入端 clamp 為 30；解鎖後以權威值 60 修復並記 settings_tamper_detected",
          rc_k == 0 and "timeout_secs=30" in o_k and "OK cancelled" in o_k and rc_a == 0 and rc == 0 and h.get("dual_step_timeout_secs") == 60
          and "[settings_tamper_detected]" in o_a, f"{o_k} | {out} | mirror={h.get('dual_step_timeout_secs')}")

    # ── 群組標記竄改（AAD）：在另一個新的合成副本上進行，不動主金庫、不刪任何檔案 ──
    VT = os.path.join(a.vault_dir, "tampered-group.db")
    h, rest = read_header(V)
    for s in h["key_slots"]:
        if s["label"] == "陳大同":
            s["group"] = "B"
    write_header(VT, h, rest)
    tampered = sha256(VT)
    rc, out = dual("login-dual", "--path", VT, "--first", "K1", "--second", "K3")
    check("DG6.1 把 A 槽改標為 B → 第二步 AAD 驗證失敗、不解鎖、記 fido2-dual-step2",
          rc != 0 and "step2: " in out and "解密驗證失敗" in out and sha256(VT) == tampered
          and sidecar_methods(VT) == ["fido2-dual-step2:陳大同"], f"{out} {sidecar_methods(VT)}")

    # ── 刪除限制 ──
    rc, out = dual("remove-key", "--path", V, "--pw", PW, "--label", "李小華")
    after_reject = read_header(V)[0]
    rc2, out2 = dual("remove-key", "--path", V, "--pw", PW, "--label", "陳大同")
    rc3, out3 = dual("remove-key", "--path", V, "--pw", PW, "--label", "王小明")
    h, _ = read_header(V)
    check("DG7.1 刪除 B 群組最後一支 → 拒絕；A 非最後一支可刪；A 剩最後一支再刪 → 拒絕",
          rc != 0 and "不可刪除 B 群組的最後一支金鑰" in out and len(after_reject["key_slots"]) == 3
          and rc2 == 0 and rc3 != 0 and "不可刪除 A 群組的最後一支金鑰" in out3
          and [s["label"] for s in h["key_slots"]] == ["王小明", "李小華"], f"{out} | {out2} | {out3}")

    rc, out = dual("register-key", "--path", V, "--pw", PW, "--device", "K3", "--group", "B", "--label", "陳大同 B")
    check("DG7.2 移除後同一支金鑰可重新註冊（排除清單只含現存槽位）", rc == 0 and "group=B" in out, out)

    # ── 版本互斥 ──
    before = sha256(V)
    rc, out = single("login-pw", "--path", V, "--pw", PW)
    check("DG8.1 單人版 CLI 開 v2 金庫 → fail closed、檔案不變、無 tmp",
          rc != 0 and "雙群組控管版" in out and sha256(V) == before and not os.path.exists(V + ".tmp"),
          out)
    V1 = os.path.join(a.vault_dir, "single.db")
    rc0, out0 = single("create", "--path", V1, "--pw", PW)
    b1 = sha256(V1)
    rc, out = dual("login-pw", "--path", V1, "--pw", PW)
    rck, outk = dual("keys", "--path", V1)
    check("DG8.2 雙人版開 v1 金庫 → 「此為單人版金庫」、檔案不變、無 sidecar/tmp",
          rc0 == 0 and rc != 0 and rck != 0 and "單人版" in out and sha256(V1) == b1
          and not os.path.exists(V1 + ".failures") and not os.path.exists(os.path.join(a.vault_dir, "single.db.tmp")),
          f"{out} | {outk}")

    # ── audit 與機密 ──
    rc, out = dual("audit", "--path", V, "--pw", PW)
    need = ["[vault_created]", "[login_success] method=password-breakglass", "[login_failed] method=password-breakglass",
            "[login_success] method=fido2-dual:", "[login_failed] method=fido2-dual-timeout",
            "[login_failed] method=fido2-dual-cancel", "[key_registered]", "group=A", "group=B",
            "[key_removed]", "[settings_changed]", "[settings_tamper_detected]"]
    missing = [n for n in need if n not in out]
    check("DG9.1 audit 涵蓋建立／break-glass／雙金鑰／逾時／取消／群組註冊與刪除／設定變更與竄改修復",
          rc == 0 and not missing, f"missing={missing}")
    raw = read_bytes(V)
    check("DG9.2 金庫檔不含主密碼明文", PW.encode() not in raw)

    print("\n" + "=" * 60)
    npass = sum(1 for _, ok, _ in results if ok)
    print(f"DUAL GATE E2E: {npass}/{len(results)} PASS")
    for name, ok, ev in results:
        if not ok:
            print(f"  FAIL: {name}\n    {ev[:400]}")
    print("=" * 60)
    sys.exit(0 if npass == len(results) else 1)


if __name__ == "__main__":
    main()
