# Quickstart

Five minutes from zero to watching.

## 1. Install

```bash
pip install sentinel-watch
sentinel --help
sentinel doctor .
```

Or from source:

```bash
git clone https://github.com/HahaAhhDev/sentinel
cd sentinel
pip install -e .
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
sentinel config-init --profile home
```

Profiles: home, server, uploads, paranoid. Server and up block on their own.

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
sentinel watch ~/Documents --response auto
```

warn only yells, auto kills unknown writers and jails them, paranoid freezes the rest. Leave it running. Touch `passwords.txt` in another shell to see a canary fire. Ctrl-c stops. `--daemon` bgs it on unix, `win-task --create` keeps it on Windows.

Tune first:

```bash
sentinel learn ~/Documents --secs 60
```

## 7. Fix

```bash
sentinel protect . --restore-clean all
sentinel quar .
```

Vault brings pre hit copies back, newest version first. Quarantine keeps post hit copies plus jailed binaries for forensics.

## 8. Harden the box

```bash
sentinel harden ~/Documents
```

One pass: canaries, autostart entries, odd connections, drift, tier. Clean what it flags.

## Next

- read `CONFIG.md` for yaml and profiles
- read `RULES.md` to tune burst and entropy
- read `PROTECTION.md` for tiers and rollback
- read `WINDOWS.md` on Windows
- read `CLI.md` for all flags
- read `WEB.md` for serve and pages
