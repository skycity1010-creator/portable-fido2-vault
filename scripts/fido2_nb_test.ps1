# =====================================================================
#  portable-fido2-vault - Win11-NB test procedure (post device_filter fix)
#  commit 8bf2ea2 - targeted HID filter (YubiKey 1050:0402 only)
#
#  Usage:
#    Remote (from this PC, via PsExec over SMB):
#      powershell -NoProfile -File .\fido2_nb_test.ps1
#      powershell -NoProfile -File .\fido2_nb_test.ps1 -Pw 'Your8CharPw!'
#
#    Local (run directly ON Win11-NB, e.g. at its console):
#      powershell -NoProfile -File .\fido2_nb_test.ps1 -Local
#
#  Remote-safe steps (no finger needed) run automatically:
#    detect / create / failure-demo / add-entry / list / audit / keys /
#    set-idle / copy-test(password)
#
#  Interactive steps need a finger on the YubiKey Bio sensor
#  (silver frame on the key body, NOT Windows Hello on the NB).
#  They are printed at the end with -Local included; re-run with
#  -Local -Interactive there and follow the 30s countdown.
# =====================================================================
param(
    [string]$Nb = 'Win11-NB',
    [string]$Pw = 'Test@2026!',
    [switch]$Local,
    [switch]$Interactive
)
$ErrorActionPreference = 'Continue'
$exe   = 'C:\FidoVault\vault_cli.exe'
# psexec: prefer a copy next to the vault CLI, fall back to the dev PC path
$psex  = 'C:\FidoVault\psexec64.exe'
if (-not (Test-Path $psex)) {
    $psex = 'C:\Users\skycity1010\AppData\Local\hermes\cache\scratch\psexec64.exe'
}
if (-not (Test-Path $psex)) {
    Write-Output 'FATAL: psexec64.exe not found (put it in C:\FidoVault or set $psex)'
    exit 2
}
$dir   = 'C:\FidoVault\test'
$db    = "$dir\test_vault.db"
$dbcopy= "$dir\test_vault_copy.db"

function Step($name, $scriptBlock) {
    Write-Output ""
    Write-Output "===== $name ====="
    & $scriptBlock
    Write-Output ("[step exit={0}]" -f $LASTEXITCODE)
}

function RunRemote($remoteCmd) {
    & $psex "\\$Nb" -accepteula -nobanner cmd /c $remoteCmd
}

function Run($cmd) {
    if ($Local) {
        & $exe @($cmd) 2>&1
    } else {
        $esc = ($cmd -join ' ') -replace "'", "''"
        RunRemote ("C:\FidoVault\vault_cli.exe $esc")
    }
}

$hostLabel = if ($Local) { 'LOCAL' } else { $Nb }
Write-Output "### FIDO2 vault test @ $hostLabel  pw=$Pw"

# --- 0. make sure no stale vault process holds the YubiKey -----------
if ($Local) {
    Get-Process | Where-Object { $_.Name -match 'vault_cli|portable-fido-vault' } |
        ForEach-Object { Write-Output ("KILL stale {0}" -f $_.Id); Stop-Process -Id $_.Id -Force }
}

# --- 0.5 make sure the test dir exists on the target ------------------
if ($Local) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
} else {
    RunRemote ("if not exist `"$dir`" mkdir `"$dir`"")
}

# --- 1. detect (remote-safe; ~1.5s after filter fix, was 30s timeout) -
Step "1 detect (hw)" {
    Run @('detect', '--authenticator', 'hw')
    # expect: OK detected kind=fingerprint ... aaguid=dd86a2da...
    # enrollment_probe_err=CancelledByUser is EXPECTED remotely (bioEnroll
    # needs a finger) - it does not affect the detect result.
}

# --- 2. create vault (CLI removes pre-existing file first) ------------
Step "2 create" {
    Run @('create', '--path', $db, '--pw', $Pw)
    # expect: OK created ...
}

# --- 3. failure-demo (Gate 2: wrong pw rejected, sidecar counts) ------
Step "3 failure-demo" {
    Run @('failure-demo', '--path', $db, '--pw', 'WrongPass9')
    # expect: OK wrong-pw rejected; sidecar=1
}

# --- 4. add-entry / list / audit (Gate 3) -----------------------------
Step "4 add-entry" {
    Run @('add-entry', '--path', $db, '--pw', $Pw,
          '--site', 'example.com', '--account', 'testuser',
          '--pass', 's3cret!', '--notes', 'gate3')
}
Step "5 list" {
    Run @('list', '--path', $db, '--pw', $Pw)
}
Step "6 audit" {
    Run @('audit', '--path', $db, '--pw', $Pw)
}

# --- 7. keys (header only, no finger) ---------------------------------
Step "7 keys (pre-register, expect 0)" {
    Run @('keys', '--path', $db)
}

# --- 8. set-idle (Gate: idle lock setting) ----------------------------
Step "8 set-idle 5" {
    Run @('set-idle', '--path', $db, '--pw', $Pw, '--minutes', '5')
}

# --- 9. copy-test password path (Gate 8) ------------------------------
Step "9 copy-test (pw)" {
    Run @('copy-test', '--src', $db, '--dst', $dbcopy, '--pw', $Pw)
}

Write-Output ""
Write-Output "### REMOTE-SAFE STEPS DONE ###"
Write-Output "Expected: step1 'OK detected ... elapsed~<3s'; steps2-9 all OK."

if ($Local -and $Interactive) {
    Write-Output ""
    Write-Output "### INTERACTIVE STEPS (finger on YubiKey Bio sensor) ###"
    foreach ($s in @(
        @{ n = '10 register-key (hw)'; c = @('register-key', '--authenticator', 'hw', '--path', $db, '--pw', $Pw) },
        @{ n = '11 keys (post-register, expect 1)'; c = @('keys', '--path', $db) },
        @{ n = '12 login-key (hw)'; c = @('login-key', '--authenticator', 'hw', '--path', $db, '--idx', '0') },
        @{ n = '13 copy-test (key-idx 0)'; c = @('copy-test', '--src', $db, '--dst', $dbcopy, '--key-idx', '0', '--authenticator', 'hw') }
    )) {
        Write-Output ""
        Write-Output ("===== {0} =====" -f $s.n)
        Write-Output 'Place your finger on the YubiKey Bio sensor (silver frame) within ~90s.'
        & $exe @($s.c) 2>&1
        Write-Output ("[step exit={0}]" -f $LASTEXITCODE)
    }
} else {
    Write-Output ""
    Write-Output "Interactive (finger) steps - run at the NB console:"
    Write-Output "  powershell -NoProfile -File .\fido2_nb_test.ps1 -Local -Interactive"
    Write-Output "or individually:"
    Write-Output "  vault_cli.exe register-key --authenticator hw --path $db --pw $Pw"
    Write-Output "  vault_cli.exe keys --path $db"
    Write-Output "  vault_cli.exe login-key --authenticator hw --path $db --idx 0"
    Write-Output "  vault_cli.exe copy-test --src $db --dst $dbcopy --key-idx 0 --authenticator hw"
}
