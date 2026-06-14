# API-RedBox-MCP

Containerized Kali Linux sandboxes exposing an MCP (Model Context Protocol) interface. Designed for LLM-driven security analysis of published REST APIs.

## Pragmatic Truth
Giving an LLM unconstrained shell access is a catastrophic risk. This project enforces boundaries. If Claude hallucinates or encounters a prompt injection payload in a target's API response, the blast radius is confined to a disposable container.

## Deployment
```bash
# Build the minimal Kali sandbox
docker build -t api-redbox-mcp .

# Run ephemerally, hardened. nmap uses an unprivileged TCP connect scan (-sT),
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
