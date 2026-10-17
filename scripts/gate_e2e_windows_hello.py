"""Mock Windows Hello gate. Usage: python script.py NEW_D_SCRATCH_DIR --cli EXE [--case NAME]."""
import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys


def safe_cli_failure(stderr: str) -> str:
    """Forward only fixed categories and validated, secret-free diagnostic fields."""
    redacted = 'CLI_FAILURE_REDACTED'
    if len(stderr) > 4096:
        return redacted
    lines = stderr.strip().splitlines()
    categories = {
        'FAIL unlock failed': 'UNLOCK_FAILED',
        'FAIL registration rejected': 'REGISTER_REJECTED',
        'FAIL platform registration postcondition failed': 'POSTCONDITION_FAILED',
        'FAIL header failed': 'HEADER_FAILED',
        'FAIL fixture contains a pre-existing temp file': 'FIXTURE_TEMP_EXISTS',
        'FAIL unclaimed mock gate fixture': 'FIXTURE_UNCLAIMED',
        'FAIL password input failed': 'INPUT_FAILED',
        'FAIL empty password': 'INPUT_EMPTY',
    }
    if not lines or len(lines) > 2 or lines[-1] not in categories:
        return redacted
    category = categories[lines[-1]]
    if len(lines) == 1:
        return category
    prefix = 'MOCK_GATE_DIAG '
    if not lines[0].startswith(prefix):
        return redacted

    def unique_fields(pairs):
        fields = {}
        for key, value in pairs:
            if key in fields:
                raise ValueError('duplicate diagnostic field')
            fields[key] = value
        return fields

    try:
        fields = json.loads(lines[0][len(prefix):], object_pairs_hook=unique_fields)
    except (ValueError, RecursionError):
        return redacted
    if not isinstance(fields, dict) or set(fields) != {'stage', 'category', 'os_code'}:
        return redacted
    stage, cause, code = fields['stage'], fields['category'], fields['os_code']
    if stage not in ('password-open', 'platform-register', 'header-read'):
        return redacted
    if cause not in ('io', 'format', 'crypto', 'authentication', 'fido', 'edition', 'dual-state'):
        return redacted
    if code is not None and (type(code) is not int or not -(2**31) <= code < 2**31):
        return redacted
    return f'{category} stage={stage} cause={cause} os_code={code if code is not None else "none"}'


def claim_fixture_dir(root: Path) -> None:
    # Hosted Windows CI has no D: drive. Permit only its runner-owned temp root there.
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        runner_temp = os.environ.get('RUNNER_TEMP')
        if not runner_temp or not Path(runner_temp).is_absolute():
            raise ValueError('CI runner temp root missing')
        scratch = Path(runner_temp).resolve(strict=True)
    else:
        scratch = Path('D:/scratch').resolve(strict=True)
    parent = root.parent.resolve(strict=True)
    if (parent != scratch and scratch not in parent.parents) or root.exists() or root.is_symlink():
        raise ValueError('fixture must be new and beneath the allowed scratch root')
    root.mkdir()  # exclusive: never adopt or delete an existing fixture
    (root / '.windows-hello-gate').open('x').close()


@contextmanager
def deny_delete_share(path: Path):
    """Hold only this test's freshly created vault; allow reads/writes but deny rename."""
    if os.name != 'nt':
        raise ValueError('storage-lock case requires Windows')
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    create = api.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = api.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    handle = create(str(path), 0x80000000, 0x00000003, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ValueError(f'storage-lock holder failed: os_code={ctypes.get_last_error()}')
    try:
        yield
    finally:
        if not close(handle):
            raise ValueError('storage-lock holder close failed')


def gate(root: Path, cli: Path, case: str) -> int:
    if not cli.is_file():
        raise ValueError('CLI missing')
    claim_fixture_dir(root)
    vault = root / 'vault.db'
    password = secrets.token_urlsafe(36)
    checks = 0

    def call(command: str, host: str = 'home') -> subprocess.CompletedProcess[str]:
        # No password in argv, stdout, stderr, or environment.
        result = subprocess.run([str(cli), command, str(vault), host], input=password,
                                text=True, capture_output=True, timeout=120, check=False)
        if password in result.stdout or password in result.stderr:
            raise ValueError('test password leaked to subprocess output (redacted)')
        return result

    def expect(command: str, marker: str, host: str = 'home') -> None:
        nonlocal checks
        result = call(command, host)
        if result.returncode != 0 or result.stdout.strip() != marker:
            category = safe_cli_failure(result.stderr)
            raise ValueError(f'{command}: exit={result.returncode}, category={category}, '
                             f'expected {marker!r}, actual response did not match (redacted)')
        checks += 1
        print(f'PASS {command} {host}')

    if case == 'fixture-guard':
        sentinel = root / 'vault.db.tmp'
        sentinel.write_bytes(b'synthetic gate sentinel')
        result = call('create')
        if result.returncode == 0 or sentinel.read_bytes() != b'synthetic gate sentinel' or vault.exists():
            raise ValueError('pre-existing temp file was not protected')
        checks += 1
        print('PASS pre-existing temp refused')
        empty = root / 'unclaimed'
        empty.mkdir()
        result = subprocess.run([str(cli), 'create', str(empty / 'vault.db'), 'home'],
                                input=password, text=True, capture_output=True, timeout=120)
        if result.returncode == 0 or (empty / 'vault.db').exists():
            raise ValueError('unclaimed fixture was not protected')
        checks += 1
        print('PASS unclaimed fixture refused')
        print(f'SUMMARY checks={checks}')
        return checks

    if case == 'dual-guard':
        expect('dual-guard', 'OK dual-rejected')
        if password.encode('utf-8') in vault.read_bytes():
            raise ValueError('plaintext test password appeared in vault file (redacted)')
        print(f'SUMMARY checks={checks}')
        return checks
    expect('create', 'OK created')
    if case == 'storage-lock':
        before = hashlib.sha256(vault.read_bytes()).digest()
        with deny_delete_share(vault):
            result = call('register')
        category = safe_cli_failure(result.stderr)
        accepted = {
            f'UNLOCK_FAILED stage=password-open cause=io os_code={code}'
            for code in (5, 32)
        }
        if result.returncode != 1 or category not in accepted:
            raise ValueError(f'storage-lock must expose password-open IO refusal; category={category}')
        tmp = root / 'vault.db.tmp'
        if hashlib.sha256(vault.read_bytes()).digest() != before or not tmp.is_file():
            raise ValueError('storage-lock changed the published vault or left no refusal evidence')
        for item in (vault, tmp):
            with item.open('rb') as stream:
                prefix = stream.read(10)
                length = int.from_bytes(prefix[6:10], 'little')
                if prefix[:6] != b'F2VLT\x01' or not 0 < length <= 1024 * 1024:
                    raise ValueError('storage-lock fixture header invalid')
                header = json.loads(stream.read(length))
                if header.get('key_slots') != []:
                    raise ValueError('storage-lock reached registration unexpectedly')
        checks += 1
        print(f'PASS storage-lock fails once before platform registration; {category}')
        print(f'SUMMARY checks={checks}')
        return checks  # preserve the expected tmp; never retry or remove failure evidence
    if case == 'assertion-failure':
        expect('register-fail', 'OK rejected-clean')
        expect('login-pw', 'OK password')
    else:
        expect('register', 'OK registered')
    if case in ('login', 'cross-host', 'duplicate', 'remove'):
        expect('login', 'OK login', 'home')
    if case == 'duplicate':
        expect('duplicate', 'OK duplicate-rejected')
    if case == 'remove':
        expect('remove', 'OK removed-clean')
        result = call('login', 'home')
        if result.returncode == 0 or result.stderr.strip() != 'FAIL platform login rejected':
            raise ValueError('removed platform slot still unlocks')
        checks += 1
        print('PASS removed slot refused')
    if case == 'roaming':
        expect('register-roaming', 'OK roaming-registered')
        expect('login-roaming', 'OK roaming-login', 'away')
    if case == 'cross-host':
        result = call('login', 'away')
        if result.returncode == 0 or result.stderr.strip() != 'FAIL platform login rejected':
            raise ValueError('away host unexpectedly unlocked platform slot')
        checks += 1
        print('PASS away platform refused')
        expect('login-pw', 'OK password', 'away')
    if password.encode('utf-8') in vault.read_bytes():
        raise ValueError('plaintext test password appeared in vault file (redacted)')
    print(f'SUMMARY checks={checks}')
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('--cli', required=True, type=Path)
    parser.add_argument('--case', choices=['register', 'login', 'cross-host', 'assertion-failure', 'duplicate', 'remove', 'dual-guard', 'roaming', 'fixture-guard', 'storage-lock', 'all'], default='all')
    args = parser.parse_args()
    if args.case == 'all':
        if not args.cli.is_file():
            raise ValueError('CLI missing')
        claim_fixture_dir(args.fixture)
        cases = ('register', 'login', 'cross-host', 'assertion-failure',
                 'duplicate', 'remove', 'dual-guard', 'roaming', 'fixture-guard', 'storage-lock')
        checks = sum(gate(args.fixture / case, args.cli, case) for case in cases)
        if checks != 31:
            raise ValueError(f'all gate checks incomplete: executed {checks}')
        print(f'SUMMARY cases={len(cases)} checks={checks}')
    else:
        gate(args.fixture, args.cli, args.case)


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f'FAIL {exc}', file=sys.stderr)
        sys.exit(1)
