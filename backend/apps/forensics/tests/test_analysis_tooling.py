import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import SimpleTestCase

from common.parser_runner import ParserFailure, ParserLimits, ParserOutputLimit, ParserTimeout, run_parser


def _limits(**changes):
    values = {
        "timeout_seconds": 2,
        "stdout_max_bytes": 4096,
        "stderr_max_bytes": 4096,
        "cpu_seconds": 2,
        "memory_max_bytes": 256 * 1024 * 1024,
        "max_open_files": 64,
        "max_processes": 8,
        "temp_max_bytes": 1024 * 1024,
    }
    values.update(changes)
    return ParserLimits(**values)


class ParserRunnerTests(SimpleTestCase):
    def _run_python(self, script, *, limits=None):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.pcap"
            source.write_bytes(b"synthetic")
            with patch("common.parser_runner.shutil.which", return_value=sys.executable):
                return run_parser(
                    tool="tshark",
                    arguments=["-c", script],
                    input_path=source,
                    working_directory=root,
                    limits=limits or _limits(),
                )

    def test_runner_uses_bounded_output_and_scrubbed_environment(self):
        result = self._run_python("import os; print('HTTP_PROXY' in os.environ); print('ok')")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), ["False", "ok"])

    def test_runner_rejects_newline_argument(self):
        with self.assertRaises(ParserFailure):
            self._run_python("print('ok')\nprint('bad')")

    def test_runner_times_out_process_group(self):
        with self.assertRaises(ParserTimeout):
            self._run_python("import time; time.sleep(5)", limits=_limits(timeout_seconds=1))

    def test_runner_enforces_stdout_limit(self):
        with self.assertRaises(ParserOutputLimit):
            self._run_python("print('x' * 10000)", limits=_limits(stdout_max_bytes=1024))

    def test_runner_rejects_input_outside_workspace(self):
        with TemporaryDirectory() as directory, TemporaryDirectory() as other:
            source = Path(other) / "input.pcap"
            source.write_bytes(b"synthetic")
            with patch("common.parser_runner.shutil.which", return_value=sys.executable), self.assertRaises(ParserFailure):
                run_parser(tool="tshark", arguments=["-c", "print('ok')"], input_path=source, working_directory=Path(directory), limits=_limits())
