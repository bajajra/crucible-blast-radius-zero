# Public static demo

The private dashboard reads the experience bank on the VM. Its action details,
model text, and proof transcripts must not be copied to a public site. Use the
separate exporter in `crucible/public_demo.py` for GitHub Pages. It emits only
numeric rates/counts, fixed action and defense labels, and one of four exact
supervisor-approved report sentences. It can also include a fixed-field wall
summary parsed from the private `infra/prove-wall.sh` transcript. It drops
URLs, payloads, IPs, container/image IDs, free-form reasons, private proof
logs, and unknown attack shapes.

Generate a preview after the Linux wall proof and model-driven Docker run:

```bash
python3 -m crucible.public_demo --db data/experience.sqlite \
  --wall-proof data/wall-proof.txt --wall-runtime runc \
  --output dist/public-demo --require-docker --require-wall-proof
python3 -m http.server 8000 --directory dist/public-demo
```

Use `--wall-runtime runsc-oci` only for a transcript from the optional gVisor
runtime. The parser requires the chosen runtime's explicit Docker check; for
`runsc-oci`, it also requires the host attestation with OCI seccomp and sandbox
networking. For either runtime it requires all container checks, successful
pinned TLS, denied external DNS and `ptrace`, a timed-out direct-IP probe with
a positive counter immediately before the final DROP, container teardown, and
the final completion marker. Failed, partial, conflicting, or duplicate proof
transcripts stop the export. The resulting JSON contains the fixed runtime
label and check summary; it never contains the raw transcript or identifiers.

Visit `http://127.0.0.1:8000` and inspect both generated files. The exporter
requires at least one Docker episode and a complete passing transcript with
both gate flags. A transcript can be copied or forged; this parser checks its
format and outcomes, not its origin. Review the private VM evidence from
`docs/demo.md` separately before presenting a containment claim. The page
explicitly separates Docker results from simulation.

To publish the reviewed snapshot from the repository's `main` branch `/docs`
folder, generate only the two public files there, inspect the staged diff, then
commit and push:

```bash
python3 -m crucible.public_demo --db data/experience.sqlite \
  --wall-proof data/wall-proof.txt --wall-runtime runc \
  --output docs --require-docker --require-wall-proof
git add docs/index.html docs/snapshot.json
git diff --cached -- docs/index.html docs/snapshot.json
git commit -m "Publish reviewed public demo snapshot"
git push origin main
```

These commands run in a trusted checkout with access to the private bank and
transcript. If they exist only on the VM, run the exporter there and transfer
**only** `index.html` and `snapshot.json` into the local `docs/` directory over
SSH. Keep the bank and full transcript in ignored private storage; never stage
them. The transcript parser is a publication gate, and manual review of the
underlying VM evidence remains necessary.

For this repository, enable GitHub Pages with the source `main` and `/docs` in
**Settings → Pages**, or use the [GitHub Pages REST API](https://docs.github.com/en/rest/pages/pages):

```bash
printf '%s' '{"source":{"branch":"main","path":"/docs"}}' |
  gh api --method POST repos/bajajra/crucible-blast-radius-zero/pages --input -
```

If Pages is already enabled, use `--method PUT` with the same body. After its
build completes, check
`https://bajajra.github.io/crucible-blast-radius-zero/` and the served
`snapshot.json`. The [GitHub Pages publishing-source guide](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
confirms that a public repository can publish from `main` `/docs`. The public
site is a static snapshot; rerun and publish after later VM episodes if it
needs fresh metrics.
