# CLI reference

All commands. `sentinel --help` prints the same.

## init

```bash
sentinel init ~/Documents
sentinel init . --jobs 8 --vault-mb 5
```

Hashes all files to `.sentinel/baseline.db` and fills `.sentinel/vault` with small clean copies. Vault is what `protect` and `diff` use later.

## update

```bash
sentinel update .
```

Rehash only what changed by size or mtime. Fast for big folders.

## status

```bash
sentinel status .
```

Shows count, dates, vault size.

## verify

```bash
sentinel verify .
sentinel verify . --json
sentinel verify . --fail
sentinel verify . --html report.html
```

Diff vs baseline. `--fail` exits 1 on changed or deleted. Good for CI.

## diff

```bash
sentinel diff .
sentinel diff . --n 5
```

Unified diffs for changed text files using vault copies.

## scan

```bash
sentinel scan .
sentinel scan . --json
sentinel scan . --sarif > results.sarif
sentinel scan . --html report.html
```

Score 0 to 100. Prints 40+. Use `--sarif` for GitHub code scanning.

## why

```bash
sentinel why ./weird.enc
```

One file score, entropy, size, reasons.

## check

```bash
sentinel check .
sentinel check . --json
sentinel check . --sarif > results.sarif
sentinel check . --fail-warn
```

Verify plus scan plus one risk number. The one to run in CI. Fails on high or drift by default, on warn with `--fail-warn`.

## watch

```bash
sentinel watch .
sentinel watch . --burst 25 --window 10 --cooldown 30
sentinel watch . --webhook "$URL" --notify --kill
sentinel watch . --daemon
sentinel watch . --response auto
```

Live loop. Order per event: canary, note, rename or delete storm, burst, single scrambled file. Cooldown keeps it to 1 or 2 alerts per hit.

`--response` picks warn, auto, or paranoid. auto kills the writer and jails its binary. paranoid also freezes the rest. `--daemon` forks to bg and writes `.sentinel/watch.pid`. On Windows use `win-task` to run at logon.

## learn

```bash
sentinel learn . --secs 60
```

Sit quiet while you work, then suggests burst and window.

## protect

```bash
sentinel protect .
sentinel protect . --restore-clean all
sentinel protect . --restore-clean a.txt,b.txt
```

Fill vault, or bring clean copies back. This beats plain quarantine because it restores pre hit text, not post hit junk.

## harden, netscan, persist

```bash
sentinel harden .
sentinel harden . --json
sentinel netscan
sentinel persist
```

`harden` does one pass: canaries, autostart scan, odd connections, drift, tier. `netscan` shows live odd connections. `persist` lists autostart entries scored for bad signs. Full story in Protection and Windows pages.

## quar and win-task

```bash
sentinel quar .
sentinel quar . --resume-pid 1234
sentinel win-task "C:\Data" --create
sentinel win-task "C:\Data" --remove
```

`quar` lists jailed binaries with sha. `--resume-pid` unfreezes a held proc. `win-task` prints or makes the logon task on Windows.

## events and timeline

```bash
sentinel events .
sentinel events . --json
sentinel timeline . --n 30
```

Last hits from `.sentinel/events.jsonl`.

## snaps and restore

```bash
sentinel snaps .
sentinel restore .
sentinel restore . 20240101_120000
```

Quarantine packs are post hit copies for forensics. Vault is for real restores. Use both.

## report and serve

```bash
sentinel report . --out report.html
sentinel serve . --port 8000
```

`report` writes one offline html file. `serve` hosts it at `http://127.0.0.1:8000` with json at `/json`.

## config-init and doctor

```bash
sentinel config-init
sentinel config-init my.yaml
sentinel doctor .
```

Scaffold yaml, or self test perms and baseline.

## clean and demo

```bash
sentinel clean .
sentinel demo
sentinel demo ./scratch
```

Wipe state, or build a fake hit to test rules.
