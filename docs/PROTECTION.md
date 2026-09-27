# Protection model

Sentinel used to only yell. Now it blocks, if you let it.

Honest note first: this is userland Python. It stops noisy ransomware, script rats, and junk autostarts cold. It does not stop kernel rootkits or firmware tricks. Pair it with Secure Boot, updates, real backups, and an EDR on high value boxes.

## Tiers

One knob, three moods. Set in yaml or per run:

```bash
sentinel watch ~/Documents --response auto
```

```yaml
response: auto
```

- `warn`: log, snapshot, alert. Never touches processes. Stock setting.
- `auto`: plus kills the top writer and jails its binary in `.sentinel/binquar` with sha. Good for home and small servers.
- `paranoid`: plus freezes the rest of the writers with suspend so you can look. Resume one with `sentinel quar . --resume-pid 1234`.

Old `--kill` flag still works and means auto.

## What happens on a hit

Order per event stays: canary, note, rename or delete storm, burst, scrambled file. What changes is the tail:

1. snapshot hit files to quarantine
2. on auto and up: kill top writer pids holding files open under root
3. copy each killer binary aside with sha and reason
4. on paranoid: suspend the next writers instead of killing
5. alert as usual: terminal, log, jsonl, webhook, mail, popup

See it with:

```bash
sentinel quar ~/Documents
```

## Vault vs bin quarantine

Two jails, different jobs:

- `.sentinel/vault/` holds pre hit clean copies of your docs. `protect --restore-clean all` brings them back.
- `.sentinel/binquar/` holds post hit copies of attacker binaries with sha index. Forensics, plus `known_bad` blocks repeat offenders by hash.

## Canaries

`init` and `watch` now lay five boring files next to your real ones: `taxes_2022.docx`, `passwords.txt`, and friends. Any touch trips at once. Touch one yourself to test:

```bash
echo x >> ~/Documents/passwords.txt
```

## Harden

One pass over the box:

```bash
sentinel harden ~/Documents
sentinel harden . --json
```

Checks canaries, autostart entries with sus scores, odd connections, baseline drift, and prints the tier. Clean the flagged lines it shows.

## Autostart and network

```bash
sentinel persist
sentinel netscan
```

`persist` reads Windows Run keys plus Startup folder, or Linux autostart, systemd user units, shell rcs, and crontab. Scores lolbin words like `powershell -enc`, `bitsadmin`, `curl ... | sh`.

`netscan` lists live established connections to odd ports or from odd bins like `mshta.exe`. Normal https stays quiet.

## Limits

- kernel rootkits: out of scope, use Secure Boot plus EDR
- slow drip crypto under burst line: caught by `scan` entropy later, not live
- encrypted vault: vault copies are plain, guard `.sentinel` with disk perms
- network block: sentinel kills procs, it does not firewall. Add host firewall rules for that
