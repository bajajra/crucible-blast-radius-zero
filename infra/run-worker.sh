#!/usr/bin/env bash
# Convenience one-shot wrapper, used by the wall proof and simple callers.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: run-worker.sh <scenario_dir> [worker command and args...]" >&2
  exit 2
fi
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$1"
shift
CID="$("$INFRA_DIR/create-worker.sh" "$SCENARIO_DIR")"
trap '"$INFRA_DIR/destroy-worker.sh" "$CID"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ $# -eq 0 ]]; then
  "$INFRA_DIR/exec-worker.sh" "$CID" python -m crucible.worker \
    --action-file /work/scenario/action.json
else
  "$INFRA_DIR/exec-worker.sh" "$CID" "$@"
fi
