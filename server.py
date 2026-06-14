"""API-RedBox-MCP server.

Exposes a fixed set of security tools (nmap, ffuf, arjun, nuclei) to an LLM over
the MCP Streamable HTTP transport. Every tool maps to one binary invoked with an
explicit argument list and `shell=False`. There is deliberately NO passthrough /
free-form flag field anywhere — that is the invariant that keeps an arbitrary
command out of reach of a hallucinating or prompt-injected model (see SPECS.md §3).

Each tool returns a structured `ScanResult` (status + exit code + parsed findings
+ the raw machine output) so the model gets clean, typed data instead of having
to scrape free-form console text.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

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

DEFAULT_TIMEOUT = 300  # seconds; fallback bound so a hung tool can't pin us

# Per-tool execution timeouts (seconds). Version/vuln scans are much slower than
# the discovery tools — a 3-port nmap `-sV` already took ~200s in testing — so
# they get more headroom; all are still bounded.
TIMEOUTS: dict[str, int] = {
    "nmap": 900,
    "ffuf": 600,
    "arjun": 600,
    "nuclei": 900,
}

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
# Result types
# ---------------------------------------------------------------------------


@dataclass
class Execution:
    """Outcome of a single binary invocation (the raw, untyped layer)."""

    command: list[str]
    returncode: int | None  # None => process never completed (timeout / spawn failure)
    stdout: str
    stderr: str
    timed_out: bool = False


class ScanResult(BaseModel):
    """Structured tool output returned to the model."""

    tool: str
    target: str
    command: list[str]
    status: Literal["completed", "timed_out", "error"]
    exit_code: int | None
    findings: list[dict] = Field(default_factory=list)
    raw: str


# ---------------------------------------------------------------------------
# Execution primitive — no shell, ever
# ---------------------------------------------------------------------------


def run_binary(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> Execution:
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
        return Execution(cmd, None, "", f"timed out after {timeout}s", timed_out=True)
    except FileNotFoundError:
        return Execution(cmd, None, "", f"binary not found: {cmd[0]}")

    return Execution(cmd, proc.returncode, proc.stdout or "", proc.stderr or "")


def _result(
    tool: str,
    target: str,
    exe: Execution,
    findings: list[dict],
    raw: str | None = None,
) -> ScanResult:
    """Assemble a ScanResult, deriving status from the execution outcome."""
    if exe.timed_out:
        status: Literal["completed", "timed_out", "error"] = "timed_out"
    elif exe.returncode == 0:
        status = "completed"
    else:
        status = "error"

    raw_text = raw if raw is not None else exe.stdout
    raw_text = (raw_text or exe.stderr or "").strip()
    return ScanResult(
        tool=tool,
        target=target,
        command=exe.command,
        status=status,
        exit_code=exe.returncode,
        findings=findings,
        raw=raw_text,
    )


def _read_and_unlink(path: str) -> str:
    """Read a tool's report file from the tmpfs, then remove it. Best-effort."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


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
# Output parsers — defensive: any malformed output yields [] (raw is preserved)
# ---------------------------------------------------------------------------


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    """Extract ports from nmap `-oX` XML."""
    try:
        # Source is our own nmap invocation, not attacker-supplied markup.
        root = ET.fromstring(xml_text)  # noqa: S314
    except ET.ParseError:
        return []
    findings: list[dict] = []
    for port in root.findall("./host/ports/port"):
        state = port.find("state")
        service = port.find("service")
        findings.append(
            {
                "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol"),
                "state": state.get("state") if state is not None else None,
                "service": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
            }
        )
    return findings


def _parse_ffuf_json(text: str) -> list[dict]:
    """Extract matches from an ffuf JSON report."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    findings: list[dict] = []
    for r in data.get("results", []) or []:
        findings.append(
            {
                "url": r.get("url"),
                "status": r.get("status"),
                "length": r.get("length"),
                "words": r.get("words"),
                "lines": r.get("lines"),
            }
        )
    return findings


def _parse_arjun_json(text: str) -> list[dict]:
    """Extract discovered parameters from an arjun JSON report."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    findings: list[dict] = []
    for url, val in data.items():
        if isinstance(val, list):
            params = val
        elif isinstance(val, dict):
            params = val.get("params", [])
        else:
            params = []
        findings.append({"url": url, "params": params})
    return findings


def _parse_nuclei_jsonl(text: str) -> list[dict]:
    """Extract findings from nuclei JSONL (one JSON object per line)."""
    findings: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        info = obj.get("info", {}) or {}
        findings.append(
            {
                "template_id": obj.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": obj.get("matched-at") or obj.get("matched_at"),
                "type": obj.get("type"),
            }
        )
    return findings


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
) -> ScanResult:
    """Verify open ports on a single host.

    Always an unprivileged TCP connect scan (`-sT -Pn`), so the container needs
    no elevated capabilities. `scan_type="-sV"` *adds* service/version detection
    on top of the connect scan — it never replaces it, because a bare `-sV` would
    let nmap fall back to a SYN scan that needs a raw socket the sandbox denies.
    Returns the open ports parsed from nmap's XML output.
    """
    _validate_target_ip(target)
    cmd = ["nmap", "-Pn", "-sT", "-p", ports, "-oX", "-", target]
    if scan_type == "-sV":
        cmd.insert(3, "-sV")  # -> nmap -Pn -sT -sV -p <ports> -oX - <target>
    exe = run_binary(cmd, timeout=TIMEOUTS["nmap"])
    return _result("nmap", target, exe, _parse_nmap_xml(exe.stdout))


@mcp.tool()
def ffuf_discover(
    url: Annotated[str, Field(description="Target URL containing the FUZZ keyword")],
    wordlist: Literal["common", "big", "raft-small"] = "common",
) -> ScanResult:
    """Discover endpoints by fuzzing the FUZZ keyword in the URL against a wordlist.

    Returns the matched endpoints (url/status/length/words/lines) parsed from
    ffuf's JSON report.
    """
    _validate_http_url(url)
    if "FUZZ" not in url:
        raise ValueError("url must contain the FUZZ keyword")
    fd, report = tempfile.mkstemp(prefix="ffuf-", suffix=".json")  # tmpfs (/tmp)
    os.close(fd)
    cmd = [
        "ffuf",
        "-u",
        url,
        "-w",
        _resolve_wordlist(wordlist),
        "-noninteractive",
        "-s",
        "-of",
        "json",
        "-o",
        report,
    ]
    exe = run_binary(cmd, timeout=TIMEOUTS["ffuf"])
    report_text = _read_and_unlink(report)
    return _result("ffuf", url, exe, _parse_ffuf_json(report_text), raw=report_text)


@mcp.tool()
def arjun_params(
    url: Annotated[str, Field(description="Target URL to fuzz for hidden parameters")],
    method: Literal["GET", "POST"] = "GET",
) -> ScanResult:
    """Fuzz a URL for hidden HTTP parameters.

    Returns the discovered parameter names parsed from arjun's JSON report.
    """
    _validate_http_url(url)
    fd, report = tempfile.mkstemp(prefix="arjun-", suffix=".json")  # tmpfs (/tmp)
    os.close(fd)
    cmd = ["arjun", "-u", url, "-m", method, "-oJ", report]
    exe = run_binary(cmd, timeout=TIMEOUTS["arjun"])
    report_text = _read_and_unlink(report)
    return _result("arjun", url, exe, _parse_arjun_json(report_text), raw=report_text)


@mcp.tool()
def nuclei_scan(
    url: Annotated[str, Field(description="Target URL to scan")],
) -> ScanResult:
    """Run REST/API vulnerability templates against a target URL.

    Returns the findings (template id / name / severity / matched-at) parsed
    from nuclei's JSONL output.
    """
    _validate_http_url(url)
    cmd = [
        "nuclei",
        "-u",
        url,
        "-tags",
        "rest,api",
        "-templates",
        NUCLEI_TEMPLATE_DIR,
        "-disable-update-check",
        "-jsonl",
        "-silent",
    ]
    exe = run_binary(cmd, timeout=TIMEOUTS["nuclei"])
    return _result("nuclei", url, exe, _parse_nuclei_jsonl(exe.stdout))


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
