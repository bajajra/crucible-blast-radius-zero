#!/usr/bin/env bash
# Idempotent teardown of one CRUCIBLE-managed sandbox session.
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[a-f0-9]{64}$ ]]; then
  echo "usage: destroy-worker.sh <full_container_id>" >&2
  exit 2
fi
CID="$1"
[[ "$(uname -s)" == Linux && "${EUID}" -eq 0 ]] || {
  echo "destroy-worker.sh requires root on the Linux sandbox host" >&2
  exit 77
}
if ! docker inspect "$CID" >/dev/null 2>&1; then
  exit 0
fi
[[ "$(docker inspect --format '{{ index .Config.Labels "crucible.managed" }}' "$CID")" == true ]] || {
  echo "refusing to remove a container without the CRUCIBLE label" >&2
  exit 2
}
docker rm --force "$CID" >/dev/null
