# Actions and CI

Pipes and GitHub.

## The one command

```bash
sentinel check ./data
sentinel check ./data --fail-warn
echo $?
```

Fails on high or drift. Add `--fail-warn` to fail on warn too. Best gate for uploads and golden data.

Json for scripts:

```bash
sentinel check ./uploads --json > check.json
sentinel verify ./uploads --json > verify.json
sentinel scan ./uploads --json > scan.json
```

Sarif for code scanning:

```bash
sentinel scan . --sarif > results.sarif
sentinel check . --sarif > results.sarif
```

Upload with `github/codeql-action/upload-sarif`.

## Verify gate

```bash
sentinel verify ./data --fail
```

Exit 1 on changed or deleted. New files do not fail. Good when baseline is committed.

## Full workflow

See `examples/github-action.yml`. Minimal job:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install -e .
- run: sentinel check . --json > check.json
- uses: actions/upload-artifact@v4
  with:
    name: sentinel-check
    path: check.json
```

Sarif job:

```yaml
- run: sentinel scan . --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Docs build runs in `ci.yml` too via `mkdocs build --strict`.

## HTML artifacts

```bash
sentinel report ./uploads --out report.html
```

One offline file. Upload it, link it in PRs.

## Pre commit

```yaml
- repo: local
  hooks:
    - id: sentinel-check
      name: sentinel check
      entry: sentinel check .
      language: system
      pass_filenames: false
```

## Alerts in prod

```bash
sentinel watch ./uploads --webhook "$WEBHOOK_URL"
```

Body is `{"text": "title\ndetail"}`. Works for Slack and Discord. Add mail via yaml `mail_to` plus local smtp if you run your own box.
