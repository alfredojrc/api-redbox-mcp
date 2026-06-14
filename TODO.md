# TODO — API-RedBox-MCP

Status legend: `[ ]` open · `[~]` in progress · `[x]` done

## MVP (done)
- [x] Spec corrections: SSE → Streamable HTTP, no-passthrough invariant (`SPECS.md`)
- [x] `server.py` — FastMCP server, 4 tools, allowlist args, `run_binary(shell=False)`
- [x] `Dockerfile` — multi-stage Kali build, non-root, baked nuclei templates + SecLists slice
- [x] `requirements.txt`, hardened `docker run` flags in `README.md`

## Next up
- [x] `docker build -t api-redbox-mcp .` and fix any build errors — image builds clean (~1.5GB)
- [x] `test_server.py` — 48 tests; allowlists reject bad input at schema + handler layers (binaries mocked).
      Run: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest && .venv/bin/python -m pytest`
- [x] Smoke test: live MCP client over Streamable HTTP — init, list 4 tools, real `nmap_scan`
      against loopback, and confirmed bad-input rejection over the wire.
      Caught + fixed a bug: `-sV` alone let nmap fall back to a SYN scan (raw socket,
      denied under `--cap-drop=ALL`); `-sV` is now additive over a mandatory `-sT`.
- [x] Hardcoded target allowlist (`ALLOWED_TARGETS` in `server.py`) — seeded with
      `192.168.68.100`; every tool refuses off-list IPs and URL hosts (hostnames never
      resolved). Verified live in the baked image. App-layer twin of the egress firewall.
- [ ] `setup-egress.sh` — parameterized host `DOCKER-USER` iptables rules (subnet + target CIDR),
      ideally derived from the same allowlist so the two layers can't drift.
- [ ] Pin the internal DNS resolver / confirm `--add-host` + no-DNS approach for the target
- [ ] Optional: allowed-hostname set for the `--add-host` workflow (exact-match, still no
      runtime DNS), if scanning by name is ever needed. IP/CIDR-only for now.

## Hardening / later
- [ ] Per-tool timeouts — a 3-port `-sV` smoke scan took ~198s; the single 300s default
      in `run_binary` gives little headroom for a real multi-port version scan.
- [ ] Structured output (JSON) from tools instead of raw stdout, for cleaner LLM parsing
- [ ] Decide if `nmap -sS` (SYN) is ever needed → would require `--cap-add NET_RAW`
- [ ] CI: lint + `py_compile` + tests on push
- [ ] Treat all tool *output* as untrusted (prompt-injection from target API responses)
