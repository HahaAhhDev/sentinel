# Config

Almost no setup, here are the knobs.

## Make one

```bash
sentinel config-init
sentinel config-init --profile server
sentinel config-init my.yaml --profile paranoid
```

Writes defaults to yaml. Edit and go. `doctor` lints and names bad keys.

## Profiles

One word presets. Explicit keys beat the profile.

- `home`: quiet watch, warn only
- `server`: auto block, higher burst
- `uploads`: strict entropy, bigger vault
- `paranoid`: low burst, low line, freeze rest

```yaml
profile: server
response: auto
```

## Lookup

Walks up and takes first hit:

1. `sentinel.yaml`
2. `.sentinel.yaml`
3. `.sentinel/config.yaml`

Force one:

```bash
sentinel watch . --config ./examples/sentinel.yaml
```

Flags beat file values.

## Full file

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
serve_port: 8000
webhook: ""
notify: false
kill: false
mail_to: ""
mail_from: "sentinel@localhost"
smtp_host: "localhost"
smtp_port: 25
allow: []
ignore:
  - "*.tmp"
  - "*.log"
paths: []
```

## What each does

- `burst`, `window`: trip after N in M secs. Lower is louder. Run `learn` if unsure.
- `cooldown`: quiet secs after a hit. Stops 500 mails for one strain.
- `entropy_line`: 7.5 stock. 7.2 strict, 7.8 chill.
- `vault_max_mb`: cap per clean copy. 5 covers docs and code, skips videos.
- `risk_warn`, `risk_high`: lines for `check`. 40 and 70 work for most.
- `serve_port`: for `serve`.
- `webhook`: Slack or Discord url. Posts `{"text": ...}`.
- `notify`: desktop popup if `notify-send`, `osascript`, or termux tool exists.
- `response`: warn, auto, paranoid. auto kills unknown writers, paranoid freezes rest too.
- `kill`: old flag for auto. Off by default.
- `allow`: proc name bits never killed. Backup tools built in plus yours.
- `vault_keep`: versions kept per file. 3 is fine.
- `quar_max_mb`: quarantine cap. `prune` trims oldest first.
- `paths`: per prefix tweaks, first match wins:

```yaml
paths:
  - prefix: "media/"
    entropy_line: 7.9
  - prefix: "docs/"
    entropy_line: 7.2
```
- `mail_to`, `smtp_*`: mail via local smtp. Blank `mail_to` means off.
- `ignore`: extra globs. Merged with `.sentinelignore`.

## Ignores

Three layers, all merge:

- built in: `.git`, `__pycache__`, `.sentinel`, `node_modules`, `.venv`, `dist`, `build`
- `.sentinelignore` in root:

```
*.tmp
*.log
scratch/
```

- `ignore:` in yaml

Check count:

```bash
python -c "from sentinel.baseline import list_files; print(len(list_files('.')))"
```

## Per command

- `init`, `update`: use ignores at hash time
- `verify`, `scan`, `check`, `report`: same ignores so diffs stay clean
- `watch`: same plus 0.5s debounce on repeat saves
- `protect`: same, plus size cap
