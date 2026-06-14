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
- [x] `setup-egress.sh` — default-deny host `DOCKER-USER` iptables rules; reads target CIDRs
      from `server.py` (no drift), v4/v6, idempotent, `--dry-run`. Linux Docker host only.
- [x] DNS resolver: blocked by default in `setup-egress.sh` (allow one via `--dns-resolver`);
      with `--dns 0.0.0.0` + `--add-host` at runtime this closes the DNS-tunnel path.
- [ ] Optional: allowed-hostname set for the `--add-host` workflow (exact-match, still no
      runtime DNS), if scanning by name is ever needed. IP/CIDR-only for now.

## Hardening / later
- [x] Per-tool timeouts — `TIMEOUTS` in `server.py` (nmap/nuclei 900s, ffuf/arjun 600s)
      replace the single 300s default; a 3-port `-sV` scan alone took ~198s.
- [x] CI: `.github/workflows/ci.yml` runs `py_compile` + `ruff check` (incl. bandit S rules)
      + `pytest` on push/PR.
- [x] Decided: `nmap -sS` (SYN) NOT needed — connect scan (`-sT`) covers our needs without
      capabilities; SYN would require `--cap-add NET_RAW` and weaken the hardening.
- [ ] Structured output (JSON) from tools instead of raw stdout, for cleaner LLM parsing
- [ ] Treat all tool *output* as untrusted (prompt-injection from target API responses)
