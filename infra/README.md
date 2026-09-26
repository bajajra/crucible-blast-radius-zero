# CRUCIBLE sandbox host

This layer runs on a **Linux Vultr VM** with a local, rootful Docker Engine using
Docker's iptables firewall backend. The Python supervisor sends approved
actions into disposable Docker workers. The current DSH adapter is a host-side
policy seam: DSH's stock tool bodies execute on the DSH host, so its plugin
denies them there by default even when the broker approves. The
`CRUCIBLE_DSH_CONTAINERIZED=1` flag is only a guard switch; setting it on the
host does not create isolation. DSH tool calls are **not**
contained by this Docker wall until DSH itself runs inside a scoped worker with
a broker gateway. Workers use Docker's `runc` runtime by default, which shares
the host kernel. The optional `runsc-oci` runtime uses gVisor and requires its
own completed wall proof before making a containment claim.

## Host setup

1. Provision the Vultr VM, install [Docker Engine for Ubuntu](https://docs.docker.com/engine/install/ubuntu/), `iptables`, `python3`, and GNU `timeout` (`coreutils`). Keep the Docker socket accessible only to root or trusted administrators. Use Docker's iptables backend; this script rejects an nftables-only daemon because `DOCKER-USER` would not exist.
2. Copy the repository to the VM. Build and activate the wall:

   ```bash
   sudo ./infra/setup-net.sh
   sudo ./infra/build-worker.sh
   sudo ./infra/prove-wall.sh
   ```

   The proof must run **on the VM**. A laptop syntax check cannot establish a
   containment claim. Its output includes hostname/uname, CPU virtualization
   and `/dev/kvm` read/write availability, a timed-out direct-IP connection
   tied to the probe container's IPv4 address at the final kernel DROP rule,
   successful TLS to a pinned allowed host, failed external DNS resolution,
   a denied `ptrace` syscall, host-side Docker configuration inspection,
   including the requested runtime and the applied custom seccomp profile,
   a probe-specific packet counter, and teardown. A socket timeout or other
   transport error alone is not a verified kernel block. Use
   `sudo journalctl -k --since '5 minutes ago' | grep CRUCIBLE-DROP` for the
   kernel log line. Missing KVM means microVM mode is unavailable; the Docker
   wall can still be tested.

3. Re-run `setup-net.sh` after Docker or the VM restarts. The firewall rules
   are not persisted by this repository. `create-worker.sh` checks the live
   rules and refuses to start if they are missing or out of order.

### Optional gVisor runtime

On Ubuntu 24.04, after Docker is installed, register a separate `runsc-oci`
runtime through the [official signed gVisor apt repository](https://gvisor.dev/docs/user_guide/install/):

```bash
sudo ./infra/install-gvisor.sh
sudo ./infra/setup-net.sh
sudo env CRUCIBLE_RUNTIME=runsc-oci ./infra/prove-wall.sh
```

The installer leaves Docker's default runtime unchanged and registers
`runsc-oci` with exactly `--oci-seccomp --network=sandbox --platform=systrap`.
The [gVisor Docker guide](https://gvisor.dev/docs/user_guide/quick_start/docker/)
documents named runtime registration. Without `--oci-seccomp`, [runsc ignores
the OCI seccomp profile by default](https://raw.githubusercontent.com/google/gvisor/master/runsc/config/flags.go).
`create-worker.sh` fails closed unless Docker's effective runtime configuration
reports those exact flags and an executable root-owned `runsc` binary. The
wall proof verifies the runtime alias again, matches the applied profile, and
requires a denied `ptrace` in the worker. Current gVisor source applies the
[OCI filter to both the initial process and `docker exec`](https://raw.githubusercontent.com/google/gvisor/master/runsc/boot/loader.go).

The custom profile is enforced **inside gVisor's application kernel**, while
gVisor also applies its own seccomp rules to reduce its host syscall surface.
gVisor ignores the Docker AppArmor profile. Its
[Netstack writes packets through the Docker-created veth](https://gvisor.dev/docs/architecture_guide/networking/);
the live probe must still demonstrate
that this VM's `DOCKER-USER` rule counted and dropped the direct-IP packet.
Do not use gVisor host networking for this wall. If the optional proof fails,
keep using the proven `runc` path and report gVisor as unverified. Run model
episodes with `sudo env CRUCIBLE_RUNTIME=runsc-oci ...` only after the proof
passes on that host.

## Episode lifecycle

`create-worker.sh` creates one container and streams only regular scenario
files through a bounded tar archive into `/work/scenario` on tmpfs. It does not
bind-mount the scenario directory or the Docker socket. The worker gets no
Vultr inference key or defense configuration; the image contains only the
worker module and staging/proof helpers. The supervisor performs inference and policy judgments
outside the container, then sends one approved action at a time over stdin.
Each live container request builds the worker image from the current source,
uses Docker's build cache where applicable, and launches by the resulting
immutable image ID. An existing `crucible-worker:latest` tag alone is never
accepted as proof that the source matches. Docker documents `--iidfile` as the
[build-result image ID output](https://docs.docker.com/reference/cli/docker/buildx/build/).

```bash
CID="$(sudo ./infra/create-worker.sh /path/to/scenario)"
trap 'sudo ./infra/destroy-worker.sh "$CID"' EXIT
sudo ./infra/exec-worker.sh "$CID" < /path/to/approved-action.json
# The same CID may be used for the safe fallback within the episode.
```

`exec-worker.sh` runs `python -m crucible.worker --action-file -` by default.
It enforces a 60-second wall clock limit per command (`CRUCIBLE_TIMEOUT_SEC`,
1–600); a timed-out command destroys the whole container because the process
could continue after the Docker CLI exits. The supervisor must call
`destroy-worker.sh` in a `finally` block. The container also self-exits after
15 minutes as a crash backstop. `run-worker.sh <scenario_dir> [command...]` is
a one-shot convenience wrapper used by the proof script.

Each container has a read-only image, a 64 MiB `/work` tmpfs, a 16 MiB `/tmp`
tmpfs, a non-root UID, no Linux capabilities, `no-new-privileges`, a custom
seccomp allowlist, a 64-process limit, 512 MiB memory limit, one CPU, and no
published ports. The scenario stream rejects symlinks, hardlinks, special
files, more than 512 files, 1,024 total entries, 16 path levels, or 32 MiB
of file data. Output still
needs the D6 secret filter in the supervisor before it leaves the application.

## Network policy

`setup-net.sh` creates a dedicated IPv4-only bridge and installs the first
forwarding rule in `DOCKER-USER`: approved pinned IPs on TCP 443 are accepted;
all other forwarding is logged (at a bounded rate) and dropped. A separate
`INPUT` rule blocks the container from host services through the bridge
gateway. IPv6 input and forwarding from this bridge are dropped. During a
policy refresh, a temporary top-level DROP rule keeps traffic blocked until
the new allowlist is installed. The worker's DNS upstream is set to its own
loopback, and approved names are entered in `/etc/hosts` at creation time.
This avoids the external DNS tunnel left open in the PDF's starter script.

The default allowed hosts are `pypi.org`, `files.pythonhosted.org`, and
`registry.npmjs.org`. Change them on the VM and refresh the policy with:

```bash
sudo env CRUCIBLE_ALLOW_HOSTS='pypi.org files.pythonhosted.org' ./infra/setup-net.sh
```

An empty `CRUCIBLE_ALLOW_HOSTS` seals all external egress; the proof's positive
TLS check then has no allowed destination and cannot run. IP pins are resolved
on the host when setup runs. Refresh after the provider rotates addresses.
IP pinning is **not exact hostname enforcement**: a shared CDN IP can serve
other TLS hostnames. D3 must judge the requested host and D6 must inspect
outbound content; production deployments should place a strict TLS-aware
egress proxy in front of shared-IP destinations or use dedicated destination
IPs. No other containers should be attached to `crucible-net`.

The seccomp file is derived from the [Moby `seccomp/v0.2.1` default allowlist](https://github.com/moby/profiles/blob/seccomp/v0.2.1/seccomp/default.json) (Apache-2.0; license in `LICENSE-moby-profiles.txt`); it additionally removes `ptrace`, process-memory access, and `socketcall`. It keeps `SCMP_ACT_ERRNO` as the default, so privileged syscalls require an explicit allow rule and the dropped capabilities still apply. Docker's default AppArmor profile remains active on the `runc` path where AppArmor is available. A seccomp EPERM is not automatically a kernel log entry; the network LOG target supplies the visible containment event.

The wall proof inserts a temporary targetless rule for the probe container's
source IPv4 and `1.1.1.1:443` immediately before the default DROP. Its counter
must increment, and the rule is removed afterward. A targetless rule changes
only counters, as described by the [iptables manual](https://man7.org/linux/man-pages/man8/iptables.8.html).

Docker's [firewall documentation](https://docs.docker.com/engine/network/firewall-iptables/) describes the `DOCKER-USER` ordering, and its [DNS documentation](https://docs.docker.com/engine/network/) explains the embedded resolver and per-container `--dns` behavior.
