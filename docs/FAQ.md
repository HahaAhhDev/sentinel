# FAQ

## Will this stop real ransomware?

It blocks the noisy kind: fast mass writes, canary trips, note drops. On auto it kills the writer and jails the binary. On paranoid it freezes the rest too. Kernel rootkits and firmware tricks are out of scope for userland Python. Use Secure Boot, updates, real backups, and an EDR next to it on high value boxes.

## Does it phone home?

No. All local. Webhook and mail only fire if you set them.

## Why sqlite plus vault?

Sqlite is one file, no setup, fine to 100k rows. Vault is plain copies of small clean files, so restores work without a backup server. Keep real backups too.

## Big folders?

`init` hashes with 8 threads. 10k small files takes seconds. Over 20MB stores as `skipped-big` and tracks size only. `update` rehashes only what moved. Bump `MAX_HASH_SIZE` in `baseline.py` if you want full hashes.

## Spammy during builds?

Add ignores:

```
dist/
build/
*.map
```

Or raise burst, or run `learn` while you build:

```bash
sentinel learn . --secs 60
```

## Can it fix files?

Yes for small text and code. `protect` fills vault on init. `protect --restore-clean all` brings changed files back. `snaps` and `restore` handle quarantine post hit copies for forensics. Videos and big bins are not vaulted by default, change `vault_max_mb` if you want them.

## Windows?

Yes, same commands. Popups use a plain box, richer toasts with `pip install plyer`. Always on via `sentinel win-task --create` which makes a logon scheduled task. Full notes in Windows page.

## What does auto do that warn does not?

warn only logs, snaps, alerts. auto also kills top writers and jails binaries by sha. paranoid also suspends the rest. Pick with `--response` or yaml `response:`.

## Where is state?

All in `<root>/.sentinel/`:

- `baseline.db`
- `vault/` clean copies
- `binquar/` jailed binaries plus sha index
- `canary.txt` plus five decoy canaries in root
- `sentinel.log`
- `events.jsonl`
- `quarantine/<ts>/`
- `watch.pid` if daemon

`clean` wipes it.

## Docs site?

Source in `docs/`, config in `mkdocs.yml`. `mkdocs serve` to preview. Push to `main` deploys to https://hahaahhdev.github.io/sentinel/ via pages workflow. Details in `WEB.md`.
