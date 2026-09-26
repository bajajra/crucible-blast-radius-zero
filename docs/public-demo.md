# Public static demo

The private dashboard reads the experience bank on the VM. Its action details,
model text, and proof transcripts must not be copied to a public site. Use the
separate exporter in `crucible/public_demo.py` for GitHub Pages. It emits only
numeric rates/counts, fixed action and defense labels, and one of four exact
supervisor-approved report sentences. It drops URLs, payloads, episode IDs,
free-form reasons, private proof logs, and unknown attack shapes.

Generate a preview after the Linux wall proof and model-driven Docker run:

```bash
python3 -m crucible.public_demo --db data/experience.sqlite \
  --output dist/public-demo --require-docker
python3 -m http.server 8000 --directory dist/public-demo
```

Visit `http://127.0.0.1:8000` and inspect both generated files. The exporter
requires at least one Docker episode when `--require-docker` is used, but the
database alone cannot prove a kernel firewall or seccomp block. Review the VM
evidence from `docs/demo.md` separately before presenting a containment claim.
The page explicitly separates Docker results from simulation.

To publish the reviewed snapshot from the repository's `main` branch `/docs`
folder, generate only the two public files there, inspect the staged diff, then
commit and push:

```bash
python3 -m crucible.public_demo --db data/experience.sqlite \
  --output docs --require-docker
git add docs/index.html docs/snapshot.json
git diff --cached -- docs/index.html docs/snapshot.json
git commit -m "Publish reviewed public demo snapshot"
git push origin main
```

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
