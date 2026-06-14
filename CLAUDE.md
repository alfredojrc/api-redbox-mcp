# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

MVP scaffold in place. `SPECS.md` is the authoritative design contract — implement against it rather than inventing alternative structure. Files:
- `server.py` — the MCP server (single file, all four tools)
- `Dockerfile` — multi-stage Kali build
- `requirements.txt` — `mcp` SDK + Pydantic

## What This Is

**API-RedBox-MCP**: a containerized Kali Linux sandbox that exposes an MCP (Model Context Protocol) server so an LLM (Claude Code on the host) can run security tooling against *published REST APIs* — without ever getting raw shell access.

Data flow: `Claude Code (host)` → `MCP client` → `Docker boundary` → `MCP server (container, port 8000)`. Transport is **Streamable HTTP** at `/mcp` (the legacy SSE transport is deprecated — do not reintroduce it).

## Build & Run

```bash
docker build -t api-redbox-mcp .          # multi-stage; bakes nuclei templates + SecLists slice

# Local server iteration without Docker (tools won't run unless installed on host):
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python server.py                          # serves http://0.0.0.0:8000/mcp

python3 -m py_compile server.py           # quick syntax check
```

See `README.md` for the full hardened `docker run` invocation.

## Server Architecture (`server.py`)

- Built on the official `mcp` SDK's `FastMCP`; tools are plain functions decorated with `@mcp.tool()`. FastMCP auto-derives the JSON schema from type hints and validates arguments before the handler runs.
- **Every tool's args are a closed allowlist**: `Literal[...]` for flags/wordlists, regex-`pattern` for ports, `_validate_target_ip` (must be a literal IP) and `_validate_http_url` for targets. There is no free-form flag field — adding one is a spec violation (`SPECS.md` §3).
- **Targets are restricted to a hardcoded allowlist** (`ALLOWED_TARGETS` in `server.py`, IPs/CIDRs). `_validate_target_ip` enforces membership; `_validate_http_url` requires the URL host to be a literal allowed IP and never resolves hostnames. It is the app-layer twin of the egress firewall — do not weaken it to an env var or mounted file (both overridable at `docker run`).
- **nmap is always a connect scan** (`-sT`): `-sV` is *additive* (`-sT -sV`), never a replacement — a bare `-sV` lets nmap fall back to a SYN scan needing a raw socket the cap-dropped sandbox denies.
- **`run_binary(cmd: list[str])` is the only execution path**: `subprocess.run` with `shell=False` and a mandatory timeout. Always invoke via an argument list, never a string.
- Wordlists are selected by **alias** (`WORDLISTS` dict → `/opt/seclists/...`), never by caller-supplied path.
- nuclei templates are baked into the image (`/opt/nuclei-templates`, made world-readable so the UID-1000 user can read them) and run with `-disable-update-check` because the runtime rootfs is read-only. nuclei/uncover insist on a writable config dir, so `XDG_CONFIG_HOME=/tmp/.config` points it at the tmpfs. The Dockerfile fails the build if the template bake produces nothing, and CI builds + runs the image to catch this class of regression.
- Every tool is bounded by a per-tool timeout (`TIMEOUTS` in `server.py`); `run_binary` enforces it so a hung scan can't pin the server.
- Tools return a structured `ScanResult` (`status`/`exit_code`/`findings`/`raw`), not raw text. `findings` is parsed from each tool's native machine format (nmap `-oX` XML, ffuf/arjun JSON, nuclei `-jsonl`) by defensive `_parse_*` helpers that yield `[]` on malformed output while keeping `raw`. `run_binary` returns an `Execution`, not a string.

To add a tool: add a `@mcp.tool()` function with typed/`Literal` args, validate any target, and route through `run_binary`. Keep the no-passthrough invariant.

## Non-Negotiable Security Constraints

These are the reason the project exists. Treat them as invariants — do not relax them for convenience when implementing.

- **No arbitrary shell.** The MCP server must NOT expose `/bin/sh -c` or any general command execution. Each MCP tool maps to one pre-defined binary with a strict allowlist of arguments — caller passes programmatic args only, never a command string.
- **Argument allowlists per tool** (see `SPECS.md` §3):
  - `nmap` — `-sV`, `-p`, IP/host
  - `ffuf` — `-u`, `-w` (local SecLists only)
  - `arjun` — `-u`, `-m` (GET/POST)
  - `nuclei` — `-u`, `-tags rest,api`
- **Target allowlist (application layer):** every tool refuses any target — or any URL host — not in the hardcoded `ALLOWED_TARGETS` (`server.py`). Baked into the read-only image; URL hosts must be literal allowed IPs (never resolved).
- **Container hardening:** base `kalilinux/kali-rolling`; run as `mcpbot` (UID 1000), root disabled; read-only root filesystem; ephemeral `tmpfs` at `/tmp` for tool output.
- **Network:** egress restricted to the target API IP range only (host `DOCKER-USER` rules via `setup-egress.sh`, which reads the CIDRs from `ALLOWED_TARGETS` so the app and network layers can't drift); ingress limited to port 8000; DNS blocked/pinned to block DNS-tunneling exfiltration.

The threat model assumes the LLM may be wrong or hijacked by prompt injection in a target's API response — every boundary above is there to confine the blast radius to a disposable container.

## Deployment (from README)

```bash
docker build -t api-redbox-mcp .

docker run --rm -it \
  --network target_vlan \
  --cap-drop=ALL \
  --read-only \
  --tmpfs /tmp \
  api-redbox-mcp
```
