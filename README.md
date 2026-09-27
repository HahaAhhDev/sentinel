# sentinel

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![version](https://img.shields.io/badge/version-0.5.0-orange)
![docs](https://img.shields.io/badge/docs-github%20pages-blue)
![ci](https://github.com/HahaAhhDev/sentinel/actions/workflows/ci.yml/badge.svg)

Tiny folder watchdog that spots ransomware-like behavior and blocks it. Baseline it, watch it, let it kill the bad proc.

Docs site: https://hahaahhdev.github.io/sentinel/

```
pip install sentinel-watch
sentinel init ~/Documents
sentinel watch ~/Documents --response auto
```

That is the pitch. No server. No signup. Files stay local. Works on Linux and Windows.

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
pip install sentinel-watch
```

From source:

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
| `watch` | Live loop. `--response warn/auto/paranoid` |
| `learn` | Watch quiet, suggest burst |
| `harden` | Canaries plus autostart plus net plus drift |
| `netscan` | Live odd connections |
| `persist` | Autostart entries, scored |
| `quar` | Jailed binaries, resume held pids |
| `win-task` | Windows logon task, create or remove |
| `bench` | Hash rate on this box |
| `policy` | Tier, rules, explain one file |
| `prune` | Trim snaps and logs to caps |
| `incident` | Zip case bundle |
| `service` | Install steps per OS |
| `intel` | Local sha blocklist |
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
sentinel config-init --profile server
```

Writes `sentinel.yaml`. Profiles: home, server, uploads, paranoid. Explicit keys beat the profile. Sentinel finds `sentinel.yaml`, `.sentinel.yaml`, `.sentinel/config.yaml` by walking up. Flags beat file. `doctor` lints the file and names bad keys.

```yaml
burst: 25
window: 10
cooldown: 30
entropy_line: 7.5
response: warn
profile: home
vault_max_mb: 5
vault_keep: 3
quar_max_mb: 500
risk_warn: 40
risk_high: 70
webhook: ""
notify: false
kill: false
allow: []
paths: []
```

Ignores merge from built ins, `.sentinelignore`, and yaml `ignore:`. Full list in [Config](https://hahaahhdev.github.io/sentinel/CONFIG/).

## Alerts, restores, cases

Hits go to terminal, `.sentinel/sentinel.log`, `.sentinel/events.jsonl`. Optional webhook, mail via local smtp, desktop popup.

Two safety nets plus one jail:

- quarantine in `.sentinel/quarantine/<ts>/`, post hit copies for forensics
- vault in `.sentinel/vault/`, pre hit clean copies for restores
- binquar in `.sentinel/binquar/`, jailed attacker binaries with sha

```bash
sentinel snaps .
sentinel quar .
sentinel protect . --restore-clean all
```

Most tools only do the first. Vault is why restores actually work, binquar is why repeat offenders get flagged by hash.

```bash
sentinel incident . --out case.zip
sentinel prune . --max-mb 500
```

Bundle zips logs, quar index, and verify state for someone else to read. Prune caps quarantine size and trims events so long hits do not fill the disk.

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
  vault.py     # clean copies plus history
  watcher.py   # live loop
  respond.py   # logs, webhook, mail, sarif, prune, bundle
  report.py    # html
  serve.py     # local web
  learn.py     # auto tune
  health.py    # watcher counters
  policy.py    # tiers
  quar.py      # binary jail
  persist.py   # autostart scan
  net.py       # conn scan
  canary.py    # decoys
  guard.py     # hits into blocks
  rules.py     # string packs
  intel.py     # sha blocklist
  proc.py      # top writer, kill, signed check
  config.py    # yaml, profiles, lint
docs/          # pages source
examples/
tests/
```

## Contributing

See `CONTRIBUTING.md`. Fork, `pip install -e .[dev]`, `pytest -q`, PR with a test and what folder you tried it on.

## License

MIT, see `LICENSE`.
