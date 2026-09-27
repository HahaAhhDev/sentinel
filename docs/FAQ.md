# FAQ

## Will this catch real ransomware?

It catches the shape: fast mass writes plus unreadable files plus notes. It will not catch slow or deep stuff. Think smoke alarm, not firewall.

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

Watch works via watchdog. Popup tries notify-send, osascript, termux-notification. PRs welcome for native toast.

## Where is state?

All in `<root>/.sentinel/`:

- `baseline.db`
- `vault/` clean copies
- `canary.txt`
- `sentinel.log`
- `events.jsonl`
- `quarantine/<ts>/`
- `watch.pid` if daemon

`clean` wipes it.

## Docs site?

Source in `docs/`, config in `mkdocs.yml`. `mkdocs serve` to preview. Push to `main` deploys to https://hahaahhdev.github.io/sentinel/ via pages workflow. Details in `WEB.md`.
