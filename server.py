"""API-RedBox-MCP server.

Exposes a fixed set of security tools (nmap, ffuf, arjun, nuclei) to an LLM over
the MCP Streamable HTTP transport. Every tool maps to one binary invoked with an
explicit argument list and `shell=False`. There is deliberately NO passthrough /
free-form flag field anywhere — that is the invariant that keeps an arbitrary
command out of reach of a hallucinating or prompt-injected model (see SPECS.md §3).
"""

from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# ffuf / arjun may only read wordlists from this directory, selected by alias.
# A caller never supplies a filesystem path.
WORDLIST_DIR = Path("/opt/seclists/Discovery/Web-Content")
WORDLISTS: dict[str, str] = {
    "common": "common.txt",
    "big": "big.txt",
    "raft-small": "raft-small-directories.txt",
}

# nuclei templates are baked into the image at build time (read-only rootfs).
NUCLEI_TEMPLATE_DIR = "/opt/nuclei-templates"

DEFAULT_TIMEOUT = 300  # seconds; every scan is bounded so a hung tool can't pin us

mcp = FastMCP(
    "api-redbox-mcp",
    host="0.0.0.0",  # noqa: S104 — intentional; reachability is constrained at the Docker boundary
    port=8000,
    stateless_http=True,
    json_response=True,
)


# ---------------------------------------------------------------------------
# Execution primitive — no shell, ever
# ---------------------------------------------------------------------------


def run_binary(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> str:
    """Execute a tool with no shell and a mandatory timeout.

    `cmd` is an argument list, so the OS execs the binary directly and shell
    metacharacters (`;`, `|`, `$()`) are inert. cmd[0] must be a known binary.
    """
    try:
        proc = subprocess.run(  # noqa: S603 — list args, shell=False, validated inputs
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"[error] {cmd[0]} timed out after {timeout}s"
    except FileNotFoundError:
        return f"[error] binary not found: {cmd[0]}"

    out = (proc.stdout or "").strip()
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        out = f"{out}\n[exit {proc.returncode}] {err}".strip()
    return out or "[no output]"


def _validate_target_ip(value: str) -> str:
    """Reject anything that is not a literal IP address (no hostnames, no payloads)."""
    ipaddress.ip_address(value)  # raises ValueError -> surfaced to the model as a tool error
    return value


def _resolve_wordlist(alias: str) -> str:
    path = WORDLIST_DIR / WORDLISTS[alias]
    return str(path)


def _validate_http_url(value: str) -> str:
    """Require a well-formed http(s) URL; reject anything else."""
    if not value.startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")
    return value


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def nmap_scan(
    target: Annotated[str, Field(description="A single IPv4/IPv6 address to scan")],
    ports: Annotated[
        str,
        Field(pattern=r"^[0-9,\-]{1,64}$", description="Ports, e.g. '80,443' or '1-1000'"),
    ] = "1-1000",
    scan_type: Literal["-sT", "-sV"] = "-sT",
) -> str:
    """Verify open ports on a single host. Uses an unprivileged TCP connect scan
    (`-sT -Pn`) so the container needs no elevated capabilities."""
    _validate_target_ip(target)
    return run_binary(["nmap", "-Pn", scan_type, "-p", ports, target])


@mcp.tool()
def ffuf_discover(
    url: Annotated[str, Field(description="Target URL containing the FUZZ keyword")],
    wordlist: Literal["common", "big", "raft-small"] = "common",
) -> str:
    """Discover endpoints by fuzzing the FUZZ keyword in the URL against a wordlist."""
    _validate_http_url(url)
    if "FUZZ" not in url:
        raise ValueError("url must contain the FUZZ keyword")
    return run_binary(
        ["ffuf", "-u", url, "-w", _resolve_wordlist(wordlist), "-noninteractive"]
    )


@mcp.tool()
def arjun_params(
    url: Annotated[str, Field(description="Target URL to fuzz for hidden parameters")],
    method: Literal["GET", "POST"] = "GET",
) -> str:
    """Fuzz a URL for hidden HTTP parameters."""
    _validate_http_url(url)
    return run_binary(["arjun", "-u", url, "-m", method])


@mcp.tool()
def nuclei_scan(
    url: Annotated[str, Field(description="Target URL to scan")],
) -> str:
    """Run REST/API vulnerability templates against a target URL."""
    _validate_http_url(url)
    return run_binary(
        [
            "nuclei",
            "-u",
            url,
            "-tags",
            "rest,api",
            "-templates",
            NUCLEI_TEMPLATE_DIR,
            "-disable-update-check",
        ]
    )


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
