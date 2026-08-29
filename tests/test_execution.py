"""Tests for the tool execution adapter (per-tool docker-exec wrapping)."""

from __future__ import annotations

from reconnaissance.adapters.execution import DockerToolEnvironment, active_environment, run_command


def test_wrap_routes_to_the_tools_own_container() -> None:
    env = DockerToolEnvironment()
    assert env.wrap(("katana", "-jc"), None) == ("docker", "exec", "-i", "reconnaissance-katana", "katana", "-jc")


def test_wrap_forwards_env_as_docker_exec_flags() -> None:
    env = DockerToolEnvironment()
    wrapped = env.wrap(("arjun", "-u", "http://x/"), {"HTTP_PROXY": "http://p:1"})
    assert wrapped == ("docker", "exec", "-i", "-e", "HTTP_PROXY=http://p:1", "reconnaissance-arjun", "arjun", "-u", "http://x/")


def test_run_command_runs_locally_when_no_environment_is_active() -> None:
    # Given no DockerToolEnvironment is bound
    assert active_environment() is None
    # When a non-existent binary is run, it degrades to missing_binary (not wrapped)
    result = run_command(("reconnaissance-nonexistent-binary-xyz",))
    assert result.missing_binary is True
    assert result.argv[0] == "reconnaissance-nonexistent-binary-xyz"
