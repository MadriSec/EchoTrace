#!/usr/bin/env python3
"""
EchoTrace MCP server.

Exposes profile generation as MCP tools so a coding agent can harden a
container without a human driving the shell.

Stages are separate tools on purpose. The pipeline takes minutes and needs
root, so wrapping it in one call would produce a tool that blocks for ten
minutes. final_tool.sh already resumes via SKIP_SYSDIG / SKIP_BYTECODE_ANALYSIS;
the agent sequences those itself.

Run:      python3 echotrace_mcp.py
Check:    python3 echotrace_mcp.py --selfcheck
"""
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

from mcp.server.fastmcp import FastMCP

REPO = Path(__file__).resolve().parent
CACHE = Path.home() / ".cache" / "echotrace"
# Pinned to a tag: moby deleted default.json from main/master, where the profile
# is now generated from Go source. Release tags still ship the JSON.
DOCKER_DEFAULT_URL = (
    "https://raw.githubusercontent.com/moby/moby/v24.0.7/profiles/seccomp/default.json"
)
TAIL = 4000  # the pipeline is very chatty; keep it out of the agent's context

mcp = FastMCP("echotrace")


def _tail(text: str) -> str:
    return text[-TAIL:] if len(text) > TAIL else text


def _allowed(profile: dict) -> set:
    """Allowed syscall names. The real Docker profile has several rule blocks."""
    return {
        name
        for rule in profile.get("syscalls", [])
        if rule.get("action") == "SCMP_ACT_ALLOW"
        for name in rule.get("names", [])
    }


def _docker_default() -> dict:
    CACHE.mkdir(parents=True, exist_ok=True)
    cached = CACHE / "docker-default.json"
    if not cached.exists():
        urllib.request.urlretrieve(DOCKER_DEFAULT_URL, cached)
    return json.loads(cached.read_text())


@mcp.tool()
def generate_profile(syscalls_path: str, output_path: str = "seccomp.json") -> dict:
    """
    Generate a seccomp profile from a syscall list or a directory of them.

    syscalls_path: file or directory of syscall names, one per line.
    output_path:   where to write the profile JSON.
    """
    out = Path(output_path)
    if not out.is_absolute():
        out = REPO / out

    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "generate_seccomp.py"),
            "--input", str(syscalls_path),
            "--output", str(out),
        ],
        capture_output=True, text=True, cwd=REPO,
    )
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": "generate_seccomp.py exited %d" % proc.returncode,
            "stderr": _tail(proc.stderr),
        }
    if not out.exists():
        return {"ok": False, "error": "no profile written to %s" % out,
                "stdout": _tail(proc.stdout)}

    profile = json.loads(out.read_text())
    return {
        "ok": True,
        "profile_path": str(out),
        "allowed": len(_allowed(profile)),
        "default_action": profile.get("defaultAction"),
    }


@mcp.tool()
def compare_to_docker_default(profile_path: str) -> dict:
    """
    Compare a generated profile against Docker's default seccomp profile.

    Returns the allowed counts, the reduction, and both set differences.
    """
    path = Path(profile_path)
    if not path.is_absolute():
        path = REPO / path
    if not path.exists():
        return {"ok": False, "error": "no such profile: %s" % path}

    mine = _allowed(json.loads(path.read_text()))
    theirs = _allowed(_docker_default())
    if not theirs:
        return {"ok": False, "error": "docker default profile has no allowed syscalls"}

    return {
        "ok": True,
        "profile_path": str(path),
        "allowed": len(mine),
        "docker_default": len(theirs),
        "reduction_pct": round((1 - len(mine) / len(theirs)) * 100, 1),
        "blocked_by_us": sorted(theirs - mine),
        "allowed_beyond_docker": sorted(mine - theirs),
    }


@mcp.tool()
def analyze_container(
    container_id: str, skip_sysdig: bool = False, skip_bytecode: bool = False
) -> dict:
    """
    Run the EchoTrace pipeline against a running container.

    Needs Docker, sysdig and root. Minutes, not seconds — use the skip flags to
    resume at a later stage rather than re-running work that is already done.

    skip_sysdig:   reuse the existing dynamic capture.
    skip_bytecode: reuse the existing native_methods.txt. The current
                   final_tool.sh stops after native mapping in this mode.
    """
    env = {"SKIP_SYSDIG": "1"} if skip_sysdig else {}
    if skip_bytecode:
        env["SKIP_BYTECODE_ANALYSIS"] = "1"

    import os
    proc = subprocess.run(
        ["bash", str(REPO / "final_tool.sh")],
        input=container_id + "\n",
        capture_output=True, text=True, cwd=REPO,
        env={**os.environ, **env},
    )
    result = {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "skipped": sorted(env),
        "stdout": _tail(proc.stdout),
        "stderr": _tail(proc.stderr),
    }
    if skip_bytecode:
        result["resume_note"] = (
            "final_tool.sh currently exits after native mapping when "
            "SKIP_BYTECODE_ANALYSIS=1; it does not run SysPart or emit a profile"
        )
    return result


def _selfcheck() -> int:
    """Catches generate_seccomp.py's interface drifting, the real failure mode."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "syscalls.txt"
        src.write_text("# a comment\nread\nwrite\nread\n")
        out = Path(tmp) / "seccomp.json"

        got = generate_profile(str(src), str(out))
        assert got["ok"], got
        assert got["allowed"] == 2, "expected read+write deduped, got %r" % got
        assert got["default_action"] == "SCMP_ACT_ERRNO", got

        cmp = compare_to_docker_default(str(out))
        assert cmp["ok"], cmp
        assert cmp["docker_default"] > 200, cmp
        assert cmp["reduction_pct"] > 90, cmp

    print("selfcheck ok")
    return 0


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        raise SystemExit(_selfcheck())
    mcp.run(transport="stdio")
