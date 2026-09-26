#!/usr/bin/env bash
# Run on the Linux Docker host, as root. Docker must use its iptables backend.
set -euo pipefail

if [[ "$(uname -s)" != Linux || "${EUID}" -ne 0 ]]; then
  echo "setup-net.sh requires root on the Linux sandbox host" >&2
  exit 77
fi
for binary in docker iptables ip6tables python3; do
  command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 77; }
done
docker info >/dev/null
python3 - <<'PY'
import json
import os
import subprocess
host_override = os.environ.get("DOCKER_HOST")
if host_override and host_override != "unix:///var/run/docker.sock":
    raise SystemExit("remote/rootless DOCKER_HOST is not supported")
context = json.loads(subprocess.check_output(["docker", "context", "inspect"]))[0]
if context["Endpoints"]["docker"]["Host"] != "unix:///var/run/docker.sock":
    raise SystemExit("Docker context must use the local rootful daemon")
PY
iptables -w -S DOCKER-USER >/dev/null 2>&1 || {
  echo "Docker DOCKER-USER chain is unavailable; use Docker's iptables firewall backend" >&2
  exit 77
}

NET="${CRUCIBLE_NET:-crucible-net}"
SUBNET="${CRUCIBLE_SUBNET:-172.30.80.0/24}"
BRIDGE="${CRUCIBLE_BRIDGE:-br-crucible}"
STATE_DIR="${CRUCIBLE_STATE_DIR:-/var/lib/crucible}"
ALLOW_HOSTS="${CRUCIBLE_ALLOW_HOSTS-pypi.org files.pythonhosted.org registry.npmjs.org}"
if [[ ! "$NET" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$ ||
      ! "$BRIDGE" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$ ]]; then
  echo "invalid network or bridge name" >&2
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
python3 - "$NET" "$SUBNET" "$BRIDGE" "$ALLOW_HOSTS" "$TMP_DIR" <<'PY'
import ipaddress
import json
import re
import socket
import sys
from pathlib import Path

net, subnet, bridge, hosts_string, out = sys.argv[1:]
subnet = str(ipaddress.IPv4Network(subnet, strict=True))
hosts = hosts_string.split()
if len(hosts) > 16:
    raise SystemExit("too many allowlisted hosts")
pins = {}
for host in hosts:
    if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", host):
        raise SystemExit(f"invalid allowlisted host: {host}")
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
    addresses = [ip for ip in addresses if ipaddress.IPv4Address(ip).is_global]
    if not addresses or len(addresses) > 32:
        raise SystemExit(f"no usable public IPv4 addresses for {host}")
    pins[host] = addresses
Path(out, "net.json").write_text(json.dumps({"network": net, "subnet": subnet, "bridge": bridge, "allow_hosts": pins}, indent=2) + "\n")
with Path(out, "pins.tsv").open("w") as stream:
    for host, addresses in pins.items():
        for ip in addresses:
            print(host, ip, sep="\t", file=stream)
PY

if ! docker network inspect "$NET" >/dev/null 2>&1; then
  docker network create --driver bridge --subnet "$SUBNET" \
    --opt "com.docker.network.bridge.name=$BRIDGE" "$NET" >/dev/null
fi
python3 - "$NET" "$SUBNET" "$BRIDGE" <<'PY'
import json
import subprocess
import sys
net, subnet, bridge = sys.argv[1:]
info = json.loads(subprocess.check_output(["docker", "network", "inspect", net]))[0]
actual_subnets = [entry.get("Subnet") for entry in info["IPAM"]["Config"]]
if (info["Driver"] != "bridge" or info["EnableIPv6"] or
        actual_subnets != [subnet] or
        info["Options"].get("com.docker.network.bridge.name") != bridge):
    raise SystemExit("existing Docker network does not match the required IPv4-only bridge; use another CRUCIBLE_NET")
PY

# The temporary top rule makes policy refresh fail closed. If setup aborts,
# it deliberately remains in place and run-worker.sh will refuse to start.
iptables -w -I DOCKER-USER 1 -i "$BRIDGE" -s "$SUBNET" -j DROP
iptables -w -S CRUCIBLE_EGRESS >/dev/null 2>&1 || iptables -w -N CRUCIBLE_EGRESS
iptables -w -F CRUCIBLE_EGRESS
while IFS=$'\t' read -r _host ip; do
  iptables -w -A CRUCIBLE_EGRESS -d "$ip" -p tcp --dport 443 \
    -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
done < "$TMP_DIR/pins.tsv"
iptables -w -A CRUCIBLE_EGRESS -m limit --limit 20/min --limit-burst 20 \
  -j LOG --log-prefix 'CRUCIBLE-DROP: ' --log-level 4
iptables -w -A CRUCIBLE_EGRESS -j DROP

# DOCKER-USER only sees forwarded traffic. INPUT also blocks access to the
# bridge gateway and host services. IPv6 is forbidden even if later enabled.
iptables -w -C INPUT -i "$BRIDGE" -s "$SUBNET" -j DROP 2>/dev/null || \
  iptables -w -I INPUT 1 -i "$BRIDGE" -s "$SUBNET" -j DROP
ip6tables -w -C INPUT -i "$BRIDGE" -j DROP 2>/dev/null || \
  ip6tables -w -I INPUT 1 -i "$BRIDGE" -j DROP
ip6tables -w -C FORWARD -i "$BRIDGE" -j DROP 2>/dev/null || \
  ip6tables -w -I FORWARD 1 -i "$BRIDGE" -j DROP

while iptables -w -C DOCKER-USER -i "$BRIDGE" -s "$SUBNET" -j CRUCIBLE_EGRESS 2>/dev/null; do
  iptables -w -D DOCKER-USER -i "$BRIDGE" -s "$SUBNET" -j CRUCIBLE_EGRESS
done
iptables -w -I DOCKER-USER 2 -i "$BRIDGE" -s "$SUBNET" -j CRUCIBLE_EGRESS

install -d -m 0755 "$STATE_DIR"
install -m 0644 "$TMP_DIR/net.json" "$STATE_DIR/net.json.tmp"
mv -f "$STATE_DIR/net.json.tmp" "$STATE_DIR/net.json"

while iptables -w -C DOCKER-USER -i "$BRIDGE" -s "$SUBNET" -j DROP 2>/dev/null; do
  iptables -w -D DOCKER-USER -i "$BRIDGE" -s "$SUBNET" -j DROP
done

echo "CRUCIBLE egress policy active on $NET ($BRIDGE, $SUBNET)"
echo "Pinned allowlist: $ALLOW_HOSTS"
echo "Inspect: iptables -nvx -L CRUCIBLE_EGRESS"
echo "Drops:   journalctl -k -f | grep CRUCIBLE-DROP"
