#!/usr/bin/env bash
# setup-egress.sh — restrict the API-RedBox-MCP sandbox's egress to the target
# allowlist, at the host network layer (iptables DOCKER-USER chain).
#
# This is the network-layer twin of the application-layer ALLOWED_TARGETS check
# in server.py. The target CIDRs are read FROM server.py so the two layers
# cannot drift. Default-deny: the sandbox subnet may reach only the allowlisted
# targets (plus established replies, and DNS to an explicit resolver if given);
# everything else from the sandbox is dropped.
#
# Requires a Linux Docker host with iptables. It does NOT work on Docker Desktop
# for macOS/Windows, where Docker runs inside a VM. Use --dry-run anywhere to
# print the exact rules without touching the firewall.
#
# Usage:
#   sudo ./setup-egress.sh --network target_vlan
#   sudo ./setup-egress.sh --network target_vlan --dns-resolver 192.168.68.1
#   sudo ./setup-egress.sh --network target_vlan --down
#   ./setup-egress.sh --subnet 172.30.0.0/16 --dry-run     # review only, no root/docker
#
# Options:
#   --network NAME     Docker network the sandbox runs on (its subnet is derived)
#   --subnet CIDR      Use this source subnet instead of inspecting --network
#   --allowlist PATH   server.py to read ALLOWED_TARGETS from (default: ./server.py)
#   --dns-resolver IP  Allow DNS (53) only to this resolver; otherwise 53 is dropped
#   --down             Remove the rules
#   --dry-run          Print the iptables commands instead of running them
#   -h, --help         Show this help
set -euo pipefail

CHAIN="REDBOX-EGRESS"
NETWORK=""
SUBNET_OVERRIDE=""
ALLOWLIST_FILE="$(dirname "$0")/server.py"
DNS_RESOLVER=""
DRY_RUN=false
ACTION="up"

usage() { sed -n '2,38p' "$0"; exit "${1:-0}"; }
log() { printf '[setup-egress] %s\n' "$*" >&2; }
die() { printf '[setup-egress] error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --network)      NETWORK="$2"; shift 2;;
    --subnet)       SUBNET_OVERRIDE="$2"; shift 2;;
    --allowlist)    ALLOWLIST_FILE="$2"; shift 2;;
    --dns-resolver) DNS_RESOLVER="$2"; shift 2;;
    --down)         ACTION="down"; shift;;
    --dry-run)      DRY_RUN=true; shift;;
    -h|--help)      usage 0;;
    *) echo "unknown argument: $1" >&2; usage 1;;
  esac
done

[ -n "$NETWORK" ] || [ -n "$SUBNET_OVERRIDE" ] || die "one of --network or --subnet is required"

# ---------------------------------------------------------------------------
# Pre-flight (skipped in dry-run so the rules can be reviewed anywhere)
# ---------------------------------------------------------------------------
if ! $DRY_RUN; then
  [ "$(id -u)" -eq 0 ] || die "must run as root (or use --dry-run)"
  command -v iptables >/dev/null 2>&1 || die "iptables not found — this needs a Linux Docker host"
fi

fam_of() { case "$1" in *:*) echo 6;; *) echo 4;; esac; }

# emit a mutating iptables command for the given family (4|6)
emit() {
  fam="$1"; shift
  bin=iptables; [ "$fam" = 6 ] && bin=ip6tables
  if $DRY_RUN; then printf '+ %s %s\n' "$bin" "$*"; else "$bin" "$@"; fi
}
# like emit, but tolerate failure (for deletions that may not exist yet)
emit_ok() {
  fam="$1"; shift
  bin=iptables; [ "$fam" = 6 ] && bin=ip6tables
  if $DRY_RUN; then printf '+ %s %s\n' "$bin" "$*"; else "$bin" "$@" 2>/dev/null || true; fi
}

# ---------------------------------------------------------------------------
# Resolve source subnet(s)
# ---------------------------------------------------------------------------
SUBNETS=()
if [ -n "$SUBNET_OVERRIDE" ]; then
  SUBNETS+=("$SUBNET_OVERRIDE")
else
  command -v docker >/dev/null 2>&1 || die "docker not found (use --subnet to skip inspection)"
  while IFS= read -r line; do
    [ -n "$line" ] && SUBNETS+=("$line")
  done < <(docker network inspect "$NETWORK" \
             --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' 2>/dev/null)
  [ "${#SUBNETS[@]}" -gt 0 ] || die "could not find subnet(s) for docker network '$NETWORK'"
fi

# ---------------------------------------------------------------------------
# Read the target allowlist from server.py (no import of the mcp deps)
# ---------------------------------------------------------------------------
TARGETS=()
while IFS= read -r line; do
  [ -n "$line" ] && TARGETS+=("$line")
done < <(python3 - "$ALLOWLIST_FILE" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
for node in ast.walk(tree):
    value = None
    if isinstance(node, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "ALLOWED_TARGETS" for t in node.targets
    ):
        value = node.value
    elif (
        isinstance(node, ast.AnnAssign)  # `ALLOWED_TARGETS: tuple[...] = (...)`
        and isinstance(node.target, ast.Name)
        and node.target.id == "ALLOWED_TARGETS"
    ):
        value = node.value
    if value is not None:
        for item in ast.literal_eval(value):
            print(item)
PY
)
[ "${#TARGETS[@]}" -gt 0 ] || die "no ALLOWED_TARGETS found in $ALLOWLIST_FILE"

log "chain=$CHAIN  subnets=${SUBNETS[*]}  targets=${TARGETS[*]}  dns=${DNS_RESOLVER:-<blocked>}  action=$ACTION  dry_run=$DRY_RUN"

# families actually in play (from the source subnets)
fam_in_use() {
  for sn in "${SUBNETS[@]}"; do [ "$(fam_of "$sn")" = "$1" ] && return 0; done
  return 1
}

teardown() {
  for fam in 4 6; do
    fam_in_use "$fam" || continue
    for sn in "${SUBNETS[@]}"; do
      [ "$(fam_of "$sn")" = "$fam" ] && emit_ok "$fam" -D DOCKER-USER -s "$sn" -j "$CHAIN"
    done
    emit_ok "$fam" -F "$CHAIN"
    emit_ok "$fam" -X "$CHAIN"
  done
}

setup() {
  teardown  # start from a clean, idempotent state
  for fam in 4 6; do
    fam_in_use "$fam" || continue
    emit "$fam" -N "$CHAIN"
    emit "$fam" -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    for t in "${TARGETS[@]}"; do
      [ "$(fam_of "$t")" = "$fam" ] && emit "$fam" -A "$CHAIN" -d "$t" -j RETURN
    done
    if [ -n "$DNS_RESOLVER" ] && [ "$(fam_of "$DNS_RESOLVER")" = "$fam" ]; then
      emit "$fam" -A "$CHAIN" -d "$DNS_RESOLVER" -p udp --dport 53 -j RETURN
      emit "$fam" -A "$CHAIN" -d "$DNS_RESOLVER" -p tcp --dport 53 -j RETURN
    fi
    emit "$fam" -A "$CHAIN" -m limit --limit 5/min -j LOG --log-prefix "redbox-egress-drop: "
    emit "$fam" -A "$CHAIN" -j DROP
    for sn in "${SUBNETS[@]}"; do
      [ "$(fam_of "$sn")" = "$fam" ] && emit "$fam" -I DOCKER-USER -s "$sn" -j "$CHAIN"
    done
  done
}

if [ "$ACTION" = "down" ]; then
  teardown
  log "egress rules removed"
else
  setup
  log "egress restricted: sandbox subnet(s) may reach only the allowlisted target(s)"
fi
