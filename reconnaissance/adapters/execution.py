"""Tool execution adapter.

Recon tools run only inside Docker — there is no host-binary mode. Each tool has
its own image and service (``docker/<tool>/Dockerfile`` + ``docker-compose.yml``);
:class:`DockerToolEnvironment` brings the whole set up with ``docker compose`` and,
while active, transparently routes every :func:`run_command` call to the matching
tool's container via ``docker exec``. Commands are always an argv list run with
``shell=False`` (no shell string is ever built), so a hostile target cannot inject
flags or commands. Per-tool env (e.g. a proxy) is forwarded with ``docker exec -e``.
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 120.0
_COMPOSE_FILE = Path(__file__).resolve().parent.parent.parent / "docker" / "docker-compose.yml"
_UP_TIMEOUT = 1200.0
_DOWN_TIMEOUT = 60.0
_INFO_TIMEOUT = 30.0
_CONTAINER_PREFIX = "reconnaissance-"

# The adapter currently bound (set by DockerToolEnvironment while active).
_ACTIVE: DockerToolEnvironment | None = None


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Outcome of one tool invocation.

    A missing binary or a timeout is an expected branch (the pipeline records it
    and continues), so it is returned here rather than raised.
    """

    argv: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    missing_binary: bool

    @property
    def ok(self) -> bool:
        """True when the tool ran to completion with a zero exit code."""
        return not self.missing_binary and not self.timed_out and self.exit_code == 0


class DockerError(RuntimeError):
    """A docker/compose operation failed."""


def _docker_arch() -> str:
    machine = platform.machine().lower()
    return "amd64" if machine in {"x86_64", "amd64"} else "arm64"


def run_command(argv: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT_SECONDS, env: Mapping[str, str] | None = None, input_text: str | None = None) -> CommandResult:
    """Run ``argv`` (in the matching tool container if an environment is active).

    Args:
        argv: Full argument vector; ``argv[0]`` is the tool. Never a shell string.
        timeout: Seconds before the child is killed and ``timed_out`` is set.
        env: Per-tool environment (e.g. proxy vars). Forwarded to the container
            via ``docker exec -e`` when active; applied locally otherwise.
        input_text: Optional text piped to stdin (e.g. a URL list).

    Returns:
        A :class:`CommandResult`. ``missing_binary`` is set if the executable is
        not found; ``timed_out`` if it exceeded ``timeout``. Neither raises.
    """
    tuple_argv = tuple(argv)
    if _ACTIVE is not None:
        args, local_env = _ACTIVE.wrap(tuple_argv, env), None
    else:
        args, local_env = tuple_argv, dict(env) if env is not None else None
    logger.debug("running tool: argv=%s timeout=%s", args, timeout)  # L2/L3: argv holds no secrets
    try:
        completed: subprocess.CompletedProcess[str] = subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=local_env,
            check=False,
        )
    except FileNotFoundError:
        logger.warning("tool executable not found: %s", args[0])
        return CommandResult(argv=args, exit_code=None, stdout="", stderr="", timed_out=False, missing_binary=True)
    except subprocess.TimeoutExpired as e:
        logger.warning("tool timed out: binary=%s timeout=%s", args[0], timeout)
        stdout = e.stdout if isinstance(e.stdout, str) else ""
        stderr = e.stderr if isinstance(e.stderr, str) else ""
        return CommandResult(argv=args, exit_code=None, stdout=stdout, stderr=stderr, timed_out=True, missing_binary=False)
    return CommandResult(argv=args, exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr, timed_out=False, missing_binary=False)


class DockerToolEnvironment:
    """Brings the per-tool container set up via compose (the execution adapter).

    Use as a context manager: on entry it builds (if needed) and starts every
    tool service and binds itself as the active environment; on exit it unbinds
    and tears the stack down. Each tool call is routed to its own
    ``reconnaissance-<tool>`` container.
    """

    def __init__(self, *, compose_file: Path = _COMPOSE_FILE) -> None:
        self._compose = str(compose_file)
        self._env = {"WEBRECON_ARCH": _docker_arch()}

    @staticmethod
    def available() -> bool:
        """True if the docker CLI is present and the daemon is reachable."""
        try:
            return subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=_INFO_TIMEOUT, check=False).returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def wrap(self, argv: tuple[str, ...], env: Mapping[str, str] | None) -> tuple[str, ...]:
        """Route argv to its tool container: ``docker exec -i [-e K=V ...] <container> …``."""
        container = f"{_CONTAINER_PREFIX}{argv[0]}"
        env_flags = tuple(flag for k, v in (env or {}).items() for flag in ("-e", f"{k}={v}"))
        return ("docker", "exec", "-i", *env_flags, container, *argv)

    def _compose_cmd(self, *args: str, timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["docker", "compose", "-f", self._compose, *args], capture_output=True, text=True, timeout=timeout, check=False, env={**os.environ, **self._env})

    def __enter__(self) -> DockerToolEnvironment:
        global _ACTIVE
        # `up -d` builds any image that does not exist yet, then starts all services.
        result = self._compose_cmd("up", "-d", timeout=_UP_TIMEOUT)
        if result.returncode != 0:
            raise DockerError(f"docker compose up failed: {result.stderr[-2000:]}")
        logger.info("tool containers up: compose=%s", self._compose)
        _ACTIVE = self
        return self

    def __exit__(self, *exc: object) -> None:
        global _ACTIVE
        _ACTIVE = None
        self._compose_cmd("down", timeout=_DOWN_TIMEOUT)
        logger.info("tool containers down")


def active_environment() -> DockerToolEnvironment | None:
    """The tool environment currently bound, if any (exposed for testing)."""
    return _ACTIVE
