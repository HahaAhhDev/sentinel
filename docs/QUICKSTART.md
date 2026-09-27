# Quickstart

Five minutes from zero to watching.

## 1. Install

```bash
git clone https://github.com/HahaAhhDev/sentinel
cd sentinel
pip install -e .
sentinel --help
sentinel doctor .
```

`doctor` checks perms, watchdog, config, baseline.

## 2. Baseline

```bash
sentinel init ~/Documents
sentinel status ~/Documents
```

Writes `.sentinel/baseline.db` plus clean copies in `.sentinel/vault`. Skips `.git`, `node_modules`, `.venv` by default.

Scaffold config if you want flags in a file:

```bash
sentinel config-init
```

## 3. Check

```bash
sentinel check ~/Documents
```

One risk line plus diffs plus scan hits. Use this daily. `--json` for scripts, `--sarif` for GitHub, `--html report.html` for humans.

## 4. Verify and diff

```bash
sentinel verify ~/Documents
sentinel diff ~/Documents
```

`verify` lists changed, new, deleted. `diff` shows text diffs via vault.

## 5. Scan and why

```bash
sentinel scan ~/Documents
sentinel why ~/Documents/weird.enc
```

Scores 0 to 100. `why` explains one file.

## 6. Watch

```bash
sentinel watch ~/Documents
```

Leave it running. Touch `.sentinel/canary.txt` in another shell to see it fire. Ctrl-c stops. Add `--daemon` to bg it.

Tune first:

```bash
sentinel learn ~/Documents --secs 60
```

## 7. Fix

```bash
sentinel protect . --restore-clean all
sentinel snaps .
```

Vault brings clean back. Quarantine keeps post hit copies for forensics.

## Next

- read `CONFIG.md` for yaml
- read `RULES.md` to tune burst and entropy
- read `CLI.md` for all flags
- read `WEB.md` for serve and pages
