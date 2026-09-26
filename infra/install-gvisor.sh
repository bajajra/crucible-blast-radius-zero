#!/usr/bin/env bash
# Optional Ubuntu 24.04 runtime. Do not change Docker's default runtime.
set -euo pipefail

[[ "$(uname -s)" == Linux && "${EUID}" -eq 0 ]] || {
  echo "install-gvisor.sh requires root on the Linux sandbox host" >&2
  exit 77
}
[[ -r /etc/os-release ]] || { echo "cannot identify host OS" >&2; exit 77; }
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || {
  echo "this installer is scoped to Ubuntu 24.04" >&2
  exit 77
}
for binary in apt-get dpkg docker systemctl python3; do
  command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 77; }
done
case "$(dpkg --print-architecture)" in
  amd64|arm64) ;;
  *) echo "gVisor package architecture is unsupported" >&2; exit 77 ;;
esac

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_BEFORE="$(docker info --format '{{.DefaultRuntime}}')"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# gVisor's signed apt repository is the upstream installation path. Keep the
# keyring in the package manager's trust directory, scoped to this repository.
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  apt-transport-https ca-certificates curl gnupg
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  https://gvisor.dev/archive.key --output "$TMP_DIR/archive.key"
gpg --batch --dearmor --output "$TMP_DIR/gvisor-archive-keyring.gpg" \
  "$TMP_DIR/archive.key"
install -m 0644 "$TMP_DIR/gvisor-archive-keyring.gpg" \
  /usr/share/keyrings/gvisor-archive-keyring.gpg
ARCH="$(dpkg --print-architecture)"
printf 'deb [arch=%s signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main\n' \
  "$ARCH" > /etc/apt/sources.list.d/gvisor.list
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y runsc

# `runsc` without this flag ignores Docker's OCI seccomp profile. Register a
# distinct alias so the default runc worker and existing Docker users remain
# unchanged. Explicit network and platform flags make the wall auditable.
runsc install --runtime runsc-oci -- \
  --oci-seccomp --network=sandbox --platform=systrap
systemctl restart docker
DEFAULT_AFTER="$(docker info --format '{{.DefaultRuntime}}')"
[[ "$DEFAULT_AFTER" == "$DEFAULT_BEFORE" ]] || {
  echo "Docker default runtime changed during gVisor installation; inspect daemon configuration" >&2
  exit 77
}
python3 "$INFRA_DIR/verify-runtime.py"
echo "Run setup-net.sh again, then prove-wall.sh with CRUCIBLE_RUNTIME=runsc-oci."
