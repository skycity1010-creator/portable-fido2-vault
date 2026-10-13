"""Mock Windows Hello gate. Usage: python script.py NEW_D_SCRATCH_DIR --cli EXE [--case NAME]."""
import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys


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
            raise ValueError(f'{command}: exit={result.returncode}, expected {marker!r}, '
                             'actual response did not match (redacted)')
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
    parser.add_argument('--case', choices=['register', 'login', 'cross-host', 'assertion-failure', 'duplicate', 'remove', 'dual-guard', 'roaming', 'fixture-guard', 'all'], default='all')
    args = parser.parse_args()
    if args.case == 'all':
        if not args.cli.is_file():
            raise ValueError('CLI missing')
        claim_fixture_dir(args.fixture)
        cases = ('register', 'login', 'cross-host', 'assertion-failure',
                 'duplicate', 'remove', 'dual-guard', 'roaming', 'fixture-guard')
        checks = sum(gate(args.fixture / case, args.cli, case) for case in cases)
        if checks != 29:
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
