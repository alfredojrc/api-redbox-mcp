# Technical Specifications: API-RedBox-MCP

## 1. Architecture Map
`Claude Code (Host)` --> `MCP Client` --> `Docker boundary` --> `MCP Server (Container, Port 8000)`

Transport is **Streamable HTTP** (MCP spec rev 2025-03-26+), single endpoint `/mcp` on port 8000. The legacy HTTP+SSE transport is deprecated and must not be used.

## 2. Container Environment
- **Base Image:** `kalilinux/kali-rolling` (minimal footprint).
- **Identity:** `mcpbot` (UID 1000). Root is disabled.
- **Filesystem:** Read-only root. Ephemeral `tmpfs` mounted at `/tmp` for temporary tool outputs.

## 3. Toolset & MCP Tool Definitions
The MCP server must NOT expose arbitrary shell execution (`/bin/sh -c`). It must strictly map to these pre-defined tools using programmatic arguments.

**Hard invariant — no passthrough.** No tool may expose a free-form flag/argument field (`additionalFlags`, `extra_args`, `command`, etc.). Every argument is a typed, validated, closed allowlist (enum/`Literal`, bounded number, or validated IP/URL). This is the single mistake that has re-introduced arbitrary execution in every comparable project; it is forbidden here without exception. Binaries are invoked with an argument list and `shell=False` — never a command string.

| Tool | Purpose | Permitted Arguments |
| :--- | :--- | :--- |
| `nmap` | Port verification | `-sV`, `-p`, IP/Host |
| `ffuf` | Endpoint discovery | `-u`, `-w` (local SecLists only) |
| `arjun` | Parameter fuzzing | `-u`, `-m` (GET/POST) |
| `nuclei` | Vulnerability scanning | `-u`, `-tags rest,api` |

Each tool returns a structured `ScanResult` (`tool`, `target`, `command`, `status`, `exit_code`, `findings`, `raw`) rather than raw console text. `findings` is parsed from the tool's native machine format (nmap `-oX` XML, ffuf/arjun JSON, nuclei `-jsonl`) defensively — malformed output yields `findings: []` while `raw` is preserved.

## 4. Network Constraints
- **Egress:** Iptables/Docker network rules must restrict egress strictly to the target REST API IP range.
- **Ingress:** Only port 8000 (MCP Streamable HTTP, `/mcp`) exposed to the Host.
- **DNS:** Hardcoded to an internal resolver to prevent DNS tunneling exfiltration.
- **Target allowlist (application layer):** Every tool validates its target against a hardcoded allowlist (`ALLOWED_TARGETS` in `server.py`) of permitted IPs/CIDR ranges before executing. URL hosts must be literal allowed IPs and are **never resolved** (resolving would reopen the DNS-exfiltration channel). This is the in-process twin of the egress firewall — defence in depth so a hijacked or hallucinating LLM cannot point a tool at the public internet or a host outside the engagement, even before/independently of the firewall. The list is baked into the read-only image; changing it requires editing the constant and rebuilding.
