# sentinel

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![version](https://img.shields.io/badge/version-0.3.0-orange)
![docs](https://img.shields.io/badge/docs-github%20pages-blue)
![ci](https://github.com/HahaAhhDev/sentinel/actions/workflows/ci.yml/badge.svg)

Tiny folder watchdog that spots ransomware-like behavior. Baseline it, watch it, get told before it is too late.

Docs site: https://hahaahhdev.github.io/sentinel/

```
pip install sentinel
sentinel init ~/Documents
sentinel watch ~/Documents
```

That is the pitch. No server. No signup. Files stay local.

---

## Why this one

Most integrity tools are built for servers and need setup. Most crypto detectors only scan once and miss live hits.

Sentinel does both, plus two things others skip:

- vault of clean copies, so `protect --restore-clean all` brings back pre hit text, not post hit junk
- one risk number via `check`, so CI and humans read the same line

Live rules plus one shot scan plus real restores. That combo is rare.

## Demo in 30 seconds

```bash
pip install -e .
sentinel demo
sentinel scan ./demo_run
sentinel check ./demo_run
sentinel report ./demo_run --out report.html
```

You get entropy, file scores, and a risk line like `risk warn 55`. Open `report.html` for the pretty page.

## Install

```bash
git clone https://github.com/HahaAhhDev/sentinel
cd sentinel
pip install -e .
```

Needs Python 3.10+. Pulls `watchdog`, `typer`, `rich`, `pyyaml`, `psutil`. Dev extras add `pytest`, `mkdocs`, `mkdocs-material`.

## Quickstart

```bash
sentinel init ~/Documents
sentinel verify ~/Documents
sentinel scan ~/Documents
sentinel check ~/Documents
sentinel watch ~/Documents
```

Full walk is in [docs](https://hahaahhdev.github.io/sentinel/) under Quickstart. Short version: `init` once, `check` often, `watch` when it matters.

## Commands

| Command | What it does |
| --- | --- |
| `init` | Hash all, fill vault |
| `update` | Rehash only changed |
| `status` | Counts, dates, vault size |
| `verify` | Diff vs baseline |
| `diff` | Text diffs via vault |
| `scan` | Score files, json or sarif |
| `why FILE` | Explain one file |
| `check` | Verify plus scan plus risk, for CI |
| `watch` | Live loop, canary, notes, storms |
| `learn` | Watch quiet, suggest burst |
| `protect` | Fill vault or restore clean |
| `events`, `timeline` | Last hits |
| `snaps`, `restore` | Quarantine packs |
| `report`, `serve` | HTML page, local web |
| `config-init`, `doctor` | Scaffold yaml, self test |
| `clean`, `demo` | Wipe, fake hit |

See `docs/CLI.md` or the [web CLI page](https://hahaahhdev.github.io/sentinel/CLI/) for flags and copy paste samples.

## How it spots trouble

Four small rules that stack, plus one risk roll up.

- burst: N events in M secs, stock 25 in 10
- entropy: Shannon on first 1MB, stock line 7.5, zips and pics skipped by magic
- canary: `.sentinel/canary.txt` touched means now
- notes and exts: `.locked`, `READ_ME.txt`, words like `bitcoin` and `decrypt`

`scan` scores 0 to 100 per file. `check` rolls verify plus scan into risk `clean`, `warn`, `high`. Details in [Rules](https://hahaahhdev.github.io/sentinel/RULES/).

Tune with `learn`:

```bash
sentinel learn ~/Documents --secs 60
```

Work like normal for a minute, it tells you a sane burst.

## Config

```bash
sentinel config-init
```

Writes `sentinel.yaml`. Sentinel finds `sentinel.yaml`, `.sentinel.yaml`, `.sentinel/config.yaml` by walking up. Flags beat file.

```yaml
burst: 25
window: 10
cooldown: 30
entropy_line: 7.5
vault_max_mb: 5
risk_warn: 40
risk_high: 70
webhook: ""
notify: false
kill: false
```

Ignores merge from built ins, `.sentinelignore`, and yaml `ignore:`. Full list in [Config](https://hahaahhdev.github.io/sentinel/CONFIG/).

## Alerts and restores

Hits go to terminal, `.sentinel/sentinel.log`, `.sentinel/events.jsonl`. Optional webhook, mail via local smtp, desktop popup.

Two safety nets:

- quarantine in `.sentinel/quarantine/<ts>/`, post hit copies for forensics
- vault in `.sentinel/vault/`, pre hit clean copies for restores

```bash
sentinel snaps .
sentinel protect . --restore-clean all
```

Most tools only do the first. Vault is why restores actually work.

## CI and web

```bash
sentinel check ./uploads --fail-warn
sentinel scan . --sarif > results.sarif
sentinel report . --out report.html
sentinel serve . --port 8000
```

Sarif feeds GitHub code scanning. Html is one offline file. Serve adds `/json` for scripts. Workflow samples in `examples/` and [Actions](https://hahaahhdev.github.io/sentinel/ACTIONS/).

Web docs build with mkdocs material. `mkdocs serve` to preview, push to `main` to publish via Pages. How to in [Web docs](https://hahaahhdev.github.io/sentinel/WEB/).

## Layout

```
sentinel/
  cli.py       # commands
  baseline.py  # hash, sqlite, diff
  detect.py    # entropy, notes, risk
  vault.py     # clean copies
  watcher.py   # live loop
  respond.py   # logs, webhook, mail, sarif
  report.py    # html
  serve.py     # local web
  learn.py     # auto tune
  proc.py      # top writer, kill
  config.py    # yaml
docs/          # pages source
examples/
tests/
```

## Contributing

See `CONTRIBUTING.md`. Fork, `pip install -e .[dev]`, `pytest -q`, PR with a test and what folder you tried it on.

## License

MIT, see `LICENSE`.
