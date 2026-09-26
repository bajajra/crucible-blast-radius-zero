# DeepSeek Harness spike

This directory is an executable integration spike against the sibling DeepSeek Harness checkout. The reusable parts are a profile overlay (`worker.patch.yml`) and a native Cordis plugin (`policy_plugin.mjs`). The native plugin intercepts registered DSH tool calls through `tools/pre-execute` and `tools/post-execute`. A pre-exec denial becomes a model-visible tool error. Every broker failure, malformed verdict, or missing broker token causes a denial. A broker-approved tool is still denied when DSH runs on the host; `CRUCIBLE_DSH_CONTAINERIZED=1` is required before DSH delegates to its stock tool body. Text tool output is sent through the broker before the model sees it; non-text tool output is blocked.

The plugin translates DSH `bash`/`pwsh` to CRUCIBLE `shell`, DSH `read`/`read_image` to `file_read`, and DSH `write`/`edit` to `file_write`. It includes the full DSH arguments in `payload` and the episode identifiers in `context`. Other DSH tool names are forwarded as their own `kind` for the broker to decide. The broker must require a per-run token and must not treat an unknown kind as automatically trusted.

## Config validation and focused tests

From the CRUCIBLE directory:

```sh
node --test dsh/test_policy_plugin.mjs
```

From the DeepSeek Harness checkout, this composes the profile without running a worker:

```sh
CRUCIBLE_ROOT="$(cd ../crucible && pwd)"
DSH_HOME=/tmp/crucible-dsh-spike \
CRUCIBLE_BROKER_URL=http://127.0.0.1:8765 \
CRUCIBLE_BROKER_TOKEN=test-broker-token-1234 \
CRUCIBLE_INFERENCE_BASE_URL=http://127.0.0.1:9999/v1 \
CRUCIBLE_INFERENCE_TOKEN=spike \
node --import tsx/esm apps/cli/src/bin.ts --profile headless \
  --patch "$CRUCIBLE_ROOT/dsh/worker.patch.yml" --dump-config
```

The `--dump-config-schema` form also imports `policy_plugin.mjs` successfully. The focused tests passed, and a direct round trip against `python3 -m crucible.broker` returned the expected host-tool denial and redacted the fake canary in post-exec output. These checks passed against the local checkout on September 26, 2026. The keyless mock-worker overlay is `smoke.patch.yml`; its sibling repository fixture requests one `bash` tool call. The runtime attempt was:

```sh
CRUCIBLE_ROOT="$(cd ../crucible && pwd)"
DSH_HOME=/tmp/crucible-dsh-spike \
CRUCIBLE_BROKER_URL=http://127.0.0.1:8765 \
CRUCIBLE_BROKER_TOKEN=test-broker-token-1234 \
CRUCIBLE_INFERENCE_BASE_URL=http://127.0.0.1:9999/v1 \
CRUCIBLE_INFERENCE_TOKEN=spike \
node --import tsx/esm apps/cli/src/bin.ts --profile headless \
  --patch "$CRUCIBLE_ROOT/dsh/worker.patch.yml" \
  --patch "$CRUCIBLE_ROOT/dsh/smoke.patch.yml" \
  --json 'Run the smoke tool once.'
```

It stopped before tool dispatch because the local DSH checkout lacks its compiled macOS addon at `native/system/packages/darwin-arm64/bin/system.node`. The DSH checkout was inspected read-only. A DSH installation or Linux build with its native addon is required for a live round trip.

## Runtime boundary

The stock DSH `bash` tool dispatches on the DSH process host. The native gate therefore denies even broker-approved tool calls unless `CRUCIBLE_DSH_CONTAINERIZED=1` is set. This profile is a seam proof, not a contained worker runtime. CRUCIBLE's Python supervisor dispatches approved actions into fresh Docker containers and is the current execution path. To make DSH the worker runtime, package DSH with its Linux native addon inside each fresh worker container, then route model and broker requests through controlled gateways. The current policy broker listens on host loopback, which a container cannot reach through its own `127.0.0.1`; a scoped gateway would be needed. Keep the real Vultr key on the supervisor side; `CRUCIBLE_INFERENCE_TOKEN` is only a short-lived gateway token in a future container runtime.

The overlay disables DSH's DeepSeek session-log contribution, OTel export, and Web tool so they do not create extra outbound paths during this spike. The DSH plugin manager can install package bundles into a profile, but installing and mounting a generated defense bundle safely in a disposable worker remains unimplemented. The Python registry owns CRUCIBLE's current pull/write defense path.
