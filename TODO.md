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
- [ ] Smoke test: connect an MCP client to `http://127.0.0.1:8000/mcp`, list tools, run one scan
- [ ] `setup-egress.sh` — parameterized host `DOCKER-USER` iptables rules (subnet + target CIDR)
- [ ] Pin the internal DNS resolver / confirm `--add-host` + no-DNS approach for the target

## Hardening / later
- [ ] Per-tool timeouts (currently a single 300s default in `run_binary`)
- [ ] Structured output (JSON) from tools instead of raw stdout, for cleaner LLM parsing
- [ ] Decide if `nmap -sS` (SYN) is ever needed → would require `--cap-add NET_RAW`
- [ ] CI: lint + `py_compile` + tests on push
- [ ] Treat all tool *output* as untrusted (prompt-injection from target API responses)
