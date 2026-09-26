#!/usr/bin/env bash
# Upload a committed CRUCIBLE release to an existing VM and run its wall proof.
set -euo pipefail

usage() {
  echo "usage: deploy/ssh-deploy.sh --target user@host [--identity key] [--port 22] --apply" >&2
  exit 2
}

TARGET=""
IDENTITY=""
PORT=22
APPLY=0
while (($#)); do
  case "$1" in
    --target) (($# >= 2)) || usage; TARGET="$2"; shift 2 ;;
    --identity) (($# >= 2)) || usage; IDENTITY="$2"; shift 2 ;;
    --port) (($# >= 2)) || usage; PORT="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    *) usage ;;
  esac
done
((APPLY)) || usage
[[ "$TARGET" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*@([a-zA-Z0-9][a-zA-Z0-9.-]*|\[[0-9a-fA-F:]+\])$ ]] || usage
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && ((PORT >= 1 && PORT <= 65535)) || usage
[[ -z "$IDENTITY" || -f "$IDENTITY" ]] || { echo "identity file not found" >&2; exit 2; }
for binary in git python3 ssh scp od; do
  command -v "$binary" >/dev/null || { echo "missing $binary" >&2; exit 77; }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ARCHIVE="$TMP/crucible.tar.gz"
REV="$(python3 "$ROOT/deploy/package_tracked.py" --output "$ARCHIVE")"
[[ "$REV" =~ ^[0-9a-f]{40,64}$ ]] || { echo "invalid committed revision" >&2; exit 2; }
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
REMOTE_ARCHIVE="/tmp/crucible-$REV-$NONCE.tar.gz"

SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=yes -p "$PORT")
SCP_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=yes -P "$PORT")
if [[ -n "$IDENTITY" ]]; then
  SSH_OPTS+=(-i "$IDENTITY")
  SCP_OPTS+=(-i "$IDENTITY")
fi

echo "Uploading committed release $REV to $TARGET"
ssh "${SSH_OPTS[@]}" "$TARGET" 'sudo -n true'
scp "${SCP_OPTS[@]}" "$ARCHIVE" "$TARGET:$REMOTE_ARCHIVE"
ssh "${SSH_OPTS[@]}" "$TARGET" "sudo -n bash -s -- '$REV' '$REMOTE_ARCHIVE'" <<'REMOTE'
set -euo pipefail
REV="$1"
ARCHIVE="$2"
[[ "$REV" =~ ^[0-9a-f]{40,64}$ ]] || exit 2
[[ "$ARCHIVE" =~ ^/tmp/crucible-[0-9a-f]{40,64}-[0-9a-f]{16}\.tar\.gz$ ]] || exit 2
[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] || exit 2
RELEASE="/opt/crucible/releases/$REV"
STAGING="/opt/crucible/releases/.$REV.new"
cleanup() {
  rm -f "$ARCHIVE"
  if [[ -d "$STAGING" && ! -L "$STAGING" ]]; then rm -rf "$STAGING"; fi
}
trap cleanup EXIT
install -d -m 0755 /opt/crucible/releases
command -v flock >/dev/null || { echo "flock is required for serialized deployment" >&2; exit 77; }
exec 9>/var/lock/crucible-deploy.lock
flock -n 9 || { echo "another CRUCIBLE deployment is active" >&2; exit 75; }
if [[ -e "$RELEASE" || -L "$RELEASE" ]]; then
  [[ -d "$RELEASE" && ! -L "$RELEASE" ]] || {
    echo "existing release is not a directory" >&2; exit 2;
  }
  [[ "$(cat "$RELEASE/.crucible-revision" 2>/dev/null)" == "$REV" ]] || {
    echo "existing release lacks matching revision marker" >&2; exit 2;
  }
else
  [[ ! -e "$STAGING" && ! -L "$STAGING" ]] || {
    echo "stale release staging directory exists" >&2; exit 2;
  }
  install -d -m 0755 "$STAGING"
  tar --no-same-owner --no-same-permissions -xzf "$ARCHIVE" -C "$STAGING"
  printf '%s\n' "$REV" > "$STAGING/.crucible-revision"
  chmod 0644 "$STAGING/.crucible-revision"
  mv -T "$STAGING" "$RELEASE"
fi
bash "$RELEASE/deploy/bootstrap-vm.sh" --apply --release "$RELEASE"
REMOTE

echo "Deployment complete. Dashboard remains bound to the VM's loopback interface."
