"""Secret-free mock Gate diagnostics; no hardware or existing vault access."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    'hello_gate_under_test',
    Path(__file__).resolve().parents[1] / 'scripts/gate_e2e_windows_hello.py',
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class SafeFailureTests(unittest.TestCase):
    def diagnostic(self, **changes):
        fields = {'stage': 'password-open', 'category': 'io', 'os_code': 32}
        fields.update(changes)
        return 'MOCK_GATE_DIAG ' + json.dumps(fields) + '\nFAIL unlock failed\n'

    def test_expect_propagates_safe_category_without_retry(self):
        replies = [
            GATE.subprocess.CompletedProcess([], 0, 'OK created\n', ''),
            GATE.subprocess.CompletedProcess([], 1, '', self.diagnostic()),
        ]
        with mock.patch.object(GATE, 'claim_fixture_dir'), mock.patch.object(
            GATE.subprocess, 'run', side_effect=replies
        ) as process:
            with self.assertRaisesRegex(
                ValueError, 'category=UNLOCK_FAILED stage=password-open cause=io os_code=32'
            ):
                GATE.gate(Path('D:/scratch/not-created-by-this-unit-test'), Path(__file__), 'register')
            self.assertEqual(process.call_count, 2, 'fail once, never silently retry')

    def test_static_category_is_retained(self):
        self.assertEqual(GATE.safe_cli_failure('FAIL unlock failed\n'), 'UNLOCK_FAILED')
        self.assertEqual(GATE.safe_cli_failure('FAIL registration rejected\n'), 'REGISTER_REJECTED')
        self.assertEqual(GATE.safe_cli_failure('FAIL header failed\n'), 'HEADER_FAILED')

    def test_allowlisted_diagnostic_has_stage_and_numeric_os_code(self):
        self.assertEqual(
            GATE.safe_cli_failure(self.diagnostic()),
            'UNLOCK_FAILED stage=password-open cause=io os_code=32',
        )

    def test_unknown_output_is_not_forwarded(self):
        marker = 'synthetic-sensitive-marker'
        for value in [f'FAIL {marker}', f'FAIL unlock failed\n{marker}',
                      self.diagnostic(category=marker), self.diagnostic(stage=marker)]:
            with self.subTest(case='unknown'):
                result = GATE.safe_cli_failure(value)
                self.assertEqual(result, 'CLI_FAILURE_REDACTED')
                self.assertNotIn(marker, result)

    def test_bad_schema_and_bool_or_out_of_range_os_codes_are_rejected(self):
        for value in [self.diagnostic(extra='synthetic-sensitive-marker'),
                      self.diagnostic(os_code=True), self.diagnostic(os_code=2**40),
                      self.diagnostic(os_code='synthetic-sensitive-marker'),
                      'MOCK_GATE_DIAG []\nFAIL unlock failed',
                      'MOCK_GATE_DIAG {}\nFAIL unlock failed']:
            with self.subTest(case='schema'):
                self.assertEqual(GATE.safe_cli_failure(value), 'CLI_FAILURE_REDACTED')

    def test_duplicate_json_keys_are_rejected(self):
        value = ('MOCK_GATE_DIAG {"stage":"password-open","category":"io",'
                 '"os_code":32,"os_code":5}\nFAIL unlock failed')
        self.assertEqual(GATE.safe_cli_failure(value), 'CLI_FAILURE_REDACTED')

    def test_oversized_and_multiline_payloads_are_rejected(self):
        self.assertEqual(GATE.safe_cli_failure('x' * 4097), 'CLI_FAILURE_REDACTED')
        self.assertEqual(GATE.safe_cli_failure(self.diagnostic() + 'unexpected'), 'CLI_FAILURE_REDACTED')


if __name__ == '__main__':
    unittest.main()
