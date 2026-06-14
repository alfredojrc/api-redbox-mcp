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
from urllib.parse import urlparse

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

# Hardcoded target allowlist — the application-layer companion to the egress
# firewall. Every tool refuses any target not covered here, so even a hijacked
# or hallucinating LLM cannot point these tools at the public internet or at a
# host outside the engagement. Entries may be single IPs or CIDR ranges.
#
# This is deliberately a baked-in constant, NOT an env var or a mounted file —
# both of those could be overridden at `docker run`. With the read-only rootfs,
# the only way to change the allowed targets is to edit this list and rebuild.
ALLOWED_TARGETS: tuple[str, ...] = (
    "192.168.68.100",  # add more IPs or CIDR ranges here, e.g. "192.168.68.0/24"
)
_ALLOWED_NETWORKS = [ipaddress.ip_network(t, strict=False) for t in ALLOWED_TARGETS]

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
    """Reject anything that is not a literal IP address on the hardcoded allowlist.

    Two gates: the value must parse as a literal IP (no hostnames, no payloads),
    and it must fall inside ALLOWED_TARGETS. The allowlist is the application-layer
    twin of the egress firewall — even a hijacked LLM cannot aim a tool at a host
    we did not pre-approve.
    """
    ip = ipaddress.ip_address(value)  # ValueError -> surfaced to the model as a tool error
    if not any(ip in net for net in _ALLOWED_NETWORKS):
        raise ValueError(f"target '{value}' is not in the allowed scan list")
    return value


def _resolve_wordlist(alias: str) -> str:
    path = WORDLIST_DIR / WORDLISTS[alias]
    return str(path)


def _validate_http_url(value: str) -> str:
    """Require a well-formed http(s) URL whose host is an allowed literal IP.

    The host is never resolved (resolving would reopen the DNS-exfiltration
    channel the sandbox closes); it must already be a literal IP, and it is run
    through the same allowlist as _validate_target_ip.
    """
    if not value.startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")
    host = urlparse(value).hostname
    if not host:
        raise ValueError("url has no host")
    _validate_target_ip(host)  # literal IP + allowlist membership
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
    """Verify open ports on a single host.

    Always an unprivileged TCP connect scan (`-sT -Pn`), so the container needs
    no elevated capabilities. `scan_type="-sV"` *adds* service/version detection
    on top of the connect scan — it never replaces it, because a bare `-sV` would
    let nmap fall back to a SYN scan that needs a raw socket the sandbox denies.
    """
    _validate_target_ip(target)
    cmd = ["nmap", "-Pn", "-sT", "-p", ports, target]
    if scan_type == "-sV":
        cmd.insert(3, "-sV")  # -> nmap -Pn -sT -sV -p <ports> <target>
    return run_binary(cmd)


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
