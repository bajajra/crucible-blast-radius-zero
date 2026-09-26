#!/usr/bin/env bash
set -euo pipefail

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$INFRA_DIR/.." && pwd)"
IMAGE="${CRUCIBLE_WORKER_IMAGE:-crucible-worker:latest}"
command -v docker >/dev/null || { echo "Docker is required" >&2; exit 77; }
[[ -f "$ROOT_DIR/crucible/worker.py" ]] || {
  echo "missing crucible/worker.py" >&2
  exit 2
}
IID_FILE="$(mktemp)"
trap 'rm -f "$IID_FILE"' EXIT
# --iidfile records the build result itself. Consumers run this immutable ID,
# so another process retagging $IMAGE cannot change the selected worker.
docker build --iidfile "$IID_FILE" --file "$INFRA_DIR/Dockerfile" --tag "$IMAGE" "$ROOT_DIR" >&2
IMAGE_ID="$(cat "$IID_FILE")"
[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "Docker did not report a valid worker image ID" >&2
  exit 1
}
docker image inspect "$IMAGE_ID" >/dev/null || {
  echo "built worker image is not available in the local Docker daemon" >&2
  exit 1
}
echo "Built $IMAGE ($IMAGE_ID)" >&2
printf '%s\n' "$IMAGE_ID"
