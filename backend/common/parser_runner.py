from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Sequence

from django.conf import settings


class ParserFailure(RuntimeError):
    code = "analysis_parse_failed"


class ParserUnavailable(ParserFailure):
    code = "analysis_tool_unavailable"


class ParserTimeout(ParserFailure):
    code = "analysis_tool_timeout"


class ParserOutputLimit(ParserFailure):
    code = "analysis_output_limit"


class ParserResourceLimit(ParserFailure):
    code = "analysis_worker_resource_limit"


@dataclass(frozen=True)
class ParserLimits:
    timeout_seconds: int
    stdout_max_bytes: int
    stderr_max_bytes: int
    cpu_seconds: int
    memory_max_bytes: int
    max_open_files: int
    max_processes: int
    temp_max_bytes: int

    @classmethod
    def configured(cls, *, timeout_seconds: int | None = None) -> "ParserLimits":
        return cls(
            timeout_seconds=timeout_seconds or settings.NETRA_PARSER_TIMEOUT_SECONDS,
            stdout_max_bytes=settings.NETRA_PARSER_STDOUT_MAX_BYTES,
            stderr_max_bytes=settings.NETRA_PARSER_STDERR_MAX_BYTES,
            cpu_seconds=settings.NETRA_PARSER_CPU_SECONDS,
            memory_max_bytes=settings.NETRA_PARSER_MEMORY_MAX_BYTES,
            max_open_files=settings.NETRA_PARSER_MAX_OPEN_FILES,
            max_processes=settings.NETRA_PARSER_MAX_PROCESSES,
            temp_max_bytes=settings.NETRA_PARSER_TEMP_MAX_BYTES,
        )


@dataclass(frozen=True)
class ParserResult:
    returncode: int
    stdout: str
    stderr: str


TOOLS = {"tshark", "zeek", "tcpdump", "mergecap", "capinfos", "editcap"}


def _safe_environment(working_directory: Path) -> dict[str, str]:
    allowed = ("PATH", "SystemRoot", "WINDIR", "LANG", "LC_ALL")
    result = {key: os.environ[key] for key in allowed if os.environ.get(key)}
    result.update({"HOME": str(working_directory), "TMPDIR": str(working_directory), "TEMP": str(working_directory), "TMP": str(working_directory)})
    return result


def _limit_resources(limits: ParserLimits):
    def apply() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_max_bytes, limits.memory_max_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits.temp_max_bytes, limits.temp_max_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (limits.max_open_files, limits.max_open_files))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes))

    return apply


def _terminate(process: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def run_parser(
    *,
    tool: str,
    arguments: Sequence[str],
    input_path: Path,
    working_directory: Path,
    limits: ParserLimits | None = None,
) -> ParserResult:
    if tool not in TOOLS:
        raise ParserUnavailable("The requested analysis tool is unavailable.")
    executable = shutil.which(tool)
    if not executable:
        raise ParserUnavailable("The required analysis tool is unavailable.")
    work = working_directory.resolve(strict=True)
    source = input_path.resolve(strict=True)
    try:
        source.relative_to(work)
    except ValueError as exc:
        raise ParserFailure("The parser input is outside its isolated workspace.") from exc
    safe_arguments = [str(value) for value in arguments]
    if any(not value or "\x00" in value or "\r" in value or "\n" in value for value in safe_arguments):
        raise ParserFailure("The parser argument contract is invalid.")
    configured = limits or ParserLimits.configured()
    stdout_file = NamedTemporaryFile(dir=work, prefix="parser-stdout-", suffix=".tmp", delete=False)
    stderr_file = NamedTemporaryFile(dir=work, prefix="parser-stderr-", suffix=".tmp", delete=False)
    stdout_path, stderr_path = Path(stdout_file.name), Path(stderr_file.name)
    process = None
    started = time.monotonic()
    try:
        kwargs = {
            "cwd": str(work),
            "env": _safe_environment(work),
            "stdin": subprocess.DEVNULL,
            "stdout": stdout_file,
            "stderr": stderr_file,
            "shell": False,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
            kwargs["preexec_fn"] = _limit_resources(configured)
        process = subprocess.Popen([str(Path(executable).resolve()), *safe_arguments], **kwargs)
        while process.poll() is None:
            stdout_file.flush()
            stderr_file.flush()
            if stdout_path.stat().st_size > configured.stdout_max_bytes or stderr_path.stat().st_size > configured.stderr_max_bytes:
                _terminate(process)
                raise ParserOutputLimit("The analysis tool exceeded its output limit.")
            if time.monotonic() - started > configured.timeout_seconds:
                _terminate(process)
                raise ParserTimeout("The analysis tool exceeded its time limit.")
            time.sleep(0.02)
        stdout_file.close()
        stderr_file.close()
        if stdout_path.stat().st_size > configured.stdout_max_bytes or stderr_path.stat().st_size > configured.stderr_max_bytes:
            raise ParserOutputLimit("The analysis tool exceeded its output limit.")
        stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
        stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
        if process.returncode < 0:
            raise ParserResourceLimit("The analysis worker terminated the parser at a resource boundary.")
        return ParserResult(process.returncode, stdout, stderr)
    finally:
        stdout_file.close()
        stderr_file.close()
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
