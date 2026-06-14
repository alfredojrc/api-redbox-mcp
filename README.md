# API-RedBox-MCP

A containerized Kali Linux sandbox that exposes a fixed security toolset to an LLM
over the **Model Context Protocol (MCP)** — so an agent like Claude Code can run
recon/scanning against *published REST APIs* **without ever getting a shell**.

## Pragmatic truth

Giving an LLM unconstrained shell access is a catastrophic risk. This project
enforces boundaries instead. If the agent hallucinates, or hits a prompt-injection
payload inside a target's API response, the blast radius is confined to a
disposable container that can only run four pre-defined tools with validated
arguments — and can only talk to the target you allow.

## Architecture

```mermaid
flowchart LR
    subgraph HOST["Host"]
        CC["Claude Code<br/>(LLM agent)"] <--> MC["MCP client"]
    end

    subgraph BOX["Disposable Kali container — UID 1000 · read-only rootfs · cap-drop=ALL · tmpfs /tmp"]
        direction TB
        SRV["MCP server (FastMCP)<br/>:8000/mcp · Streamable HTTP"]
        VAL{"Allowlist validation<br/>Literal enums · regex · IP/URL"}
        RB["run_binary()<br/>shell=False · argv list · timeout"]
        ERR["rejected → ValueError / ToolError<br/>(never reaches a shell)"]
        SRV --> VAL
        VAL -- valid --> RB
        VAL -- rejected --> ERR
        RB --> T1["nmap"]
        RB --> T2["ffuf"]
        RB --> T3["arjun"]
        RB --> T4["nuclei"]
    end

    EG{{"egress filter<br/>DOCKER-USER iptables · target CIDR only · DNS pinned"}}
    API[("Allowlisted target<br/>e.g. 192.168.68.100")]

    MC ==>|"4 typed tools only - no shell"| SRV
    T1 --> EG
    T2 --> EG
    T3 --> EG
    T4 --> EG
    EG --> API
```

The host agent never spawns the tools and never reaches a command line. It can
only call four typed tools over HTTP; every call is validated, then executed via
an argv list with `shell=False`, so shell metacharacters are inert.

## Toolset

Each MCP tool maps to exactly one binary with a **closed allowlist** of arguments —
there is no free-form flag / command field anywhere (see [`SPECS.md`](SPECS.md) §3).

| Tool | Purpose | Permitted arguments |
| :--- | :--- | :--- |
| `nmap_scan` | Port verification | target (literal IP only), `-p <ports>` (regex), `-sT`\|`-sV` |
| `ffuf_discover` | Endpoint discovery | target URL (must contain `FUZZ`), wordlist *alias* (local SecLists only) |
| `arjun_params` | Hidden-parameter fuzzing | target URL, method `GET`\|`POST` |
| `nuclei_scan` | Vulnerability scanning | target URL, fixed `-tags rest,api` (templates baked into the image) |

## Security invariants

These are the reason the project exists; they are not relaxed for convenience.

- **No arbitrary shell.** No tool exposes `/bin/sh -c`, `additionalFlags`, `command`,
  or any passthrough field. A regression test (`test_no_tool_exposes_a_freeform_command_field`)
  fails the build if one ever appears.
- **Two-layer argument validation.** The MCP schema (pydantic `Literal`/regex)
  rejects out-of-allowlist values before handler code runs; the handlers then
  re-validate targets (`_validate_target_ip`, `_validate_http_url`) and select
  wordlists by alias only.
- **Hardcoded target allowlist.** Every tool refuses any target not in
  `ALLOWED_TARGETS` (IPs/CIDR ranges baked into `server.py`); URL hosts must be
  literal allowed IPs and are never resolved. This is the application-layer twin
  of the egress firewall — see [Allowed targets](#allowed-targets).
- **Container hardening.** Base `kalilinux/kali-rolling`; runs as `mcpbot` (UID 1000),
  root disabled; read-only root filesystem; ephemeral `tmpfs` at `/tmp`.
- **Network confinement.** Egress restricted to the target API's IP range; ingress
  limited to port 8000; DNS pinned to an internal resolver to block DNS-tunnel
  exfiltration.

## Allowed targets

Targets are restricted to a hardcoded list in `server.py` — not an env var or a
mounted file, both of which could be overridden at `docker run`:

```python
ALLOWED_TARGETS: tuple[str, ...] = (
    "192.168.68.100",  # add more IPs or CIDR ranges here, e.g. "192.168.68.0/24"
)
```

A tool refuses any IP target — or any URL whose host — that is not covered here,
so the tools cannot be aimed at the public internet or unrelated services. URL
hosts must be literal allowed IPs (hostnames are never resolved). To change the
allowed targets, edit this list and **rebuild the image** (the read-only rootfs
means it cannot be altered at runtime). Pair it with the egress firewall below
for network-level enforcement of the same restriction.

## Build

```bash
docker build -t api-redbox-mcp .   # multi-stage; bakes nuclei templates + a SecLists slice
```

## Run

```bash
# Ephemeral, hardened. nmap uses an unprivileged TCP connect scan (-sT),
# so NO capabilities are required — the container drops them all.
docker run --rm \
  --network target_vlan \
  --add-host api.target.com:203.0.113.10 --dns 0.0.0.0 \
  --user 1000:1000 \
  --cap-drop=ALL --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp --tmpfs /home/mcpbot/.cache \
  --pids-limit 256 --memory 1g --cpus 2 \
  -p 127.0.0.1:8000:8000 \
  api-redbox-mcp
```

The MCP server is then reachable at `http://127.0.0.1:8000/mcp` (Streamable HTTP).
Egress should additionally be restricted to the target API's IP range via a host
`DOCKER-USER` iptables rule (default-deny the sandbox subnet, allow only the target CIDR).

## Use from Claude Code (on-demand)

The sandbox is wired into Claude Code **only when you ask for it** — it is not a
default MCP server. [`redbox.mcp.json`](redbox.mcp.json) describes the connection;
a shell launcher loads it for a single session via `--mcp-config`:

```bash
# ~/.zshrc
claudered() {
  if ! nc -z -w1 127.0.0.1 8000 2>/dev/null; then
    echo "⚠️  api-redbox not reachable on 127.0.0.1:8000 — start the container first." >&2
  fi
  claude --mcp-config "$HOME/godz/projects/api-redbox-mcp/redbox.mcp.json" "$@"
}
```

```bash
docker run ... api-redbox-mcp   # 1. start the sandbox (see Run above)
claudered                       # 2. launch Claude Code with the 4 tools loaded
#                                 inside the session, `/mcp` lists `api-redbox`
```

Add `--strict-mcp-config` to the `claude` line for an isolated session exposing
*only* the redbox tools. The MCP loads at session start, so a regular `claude`
session is unaffected.

> **One residual boundary:** the container confines *execution*, but tool *output*
> (e.g. a finding that echoes a target's response) still flows back into the host
> agent's context. Treat all tool output as untrusted.

## Test

Unit tests assert the allowlist/no-passthrough invariants with the real binaries
mocked — no scans run.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest        # 48 tests
```

## Layout

| File | Role |
| :--- | :--- |
| `server.py` | The MCP server — all four tools, validators, `run_binary` |
| `test_server.py` | Allowlist / no-passthrough test suite |
| `Dockerfile` | Multi-stage hardened Kali build |
| `redbox.mcp.json` | Claude Code MCP connection for `claudered` |
| `SPECS.md` | Authoritative design contract |
| `TODO.md` | Status and remaining work |
</content>
