# Web docs

Two webs: local `serve` for you, GitHub Pages for the world.

## Local serve

```bash
sentinel report . --out report.html
sentinel serve . --port 8000
```

Open http://127.0.0.1:8000. Same page as `report`, plus `/json` for scripts:

```bash
curl http://127.0.0.1:8000/json | jq .risk
```

No auth, binds loopback only. Do not expose it. Stop with ctrl-c.

## GitHub Pages

Docs live in `docs/` and build with mkdocs material.

Site config is `mkdocs.yml`. Nav points at the md files you already edit. Push to `main` and the pages workflow publishes to https://hahaahhdev.github.io/sentinel/.

### Run docs locally

```bash
pip install -e .[dev]
mkdocs serve
```

Open http://127.0.0.1:8000. Edit md, page reloads.

### Build check

```bash
mkdocs build --strict
ls site/index.html
```

Strict fails on bad links, so fix those before push.

### How deploy works

`.github/workflows/pages.yml` does:

1. checkout
2. setup python
3. `pip install mkdocs mkdocs-material`
4. `mkdocs gh-deploy --force`

Uses `actions/deploy-pages`. No tokens to manage. First run needs Pages turned on in repo settings, source set to GitHub Actions.

### Add a page

1. add `docs/MYTHING.md`
2. add `- My thing: MYTHING.md` to `nav:` in `mkdocs.yml`
3. run `mkdocs serve` and check links
4. push

Keep pages short, start with what and copy paste commands. Match the tone in `QUICKSTART.md`.
