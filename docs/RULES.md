# Rules

How each rule works and how to tune it.

## Burst

`Burst` counts events in a sliding window. Stock 25 in 10s. Trips once, then cooldown 30s.

When to change:

- photo import or build: raise to 100/10 or ignore that dir
- tiny notes folder: drop to 10/10

```bash
sentinel watch ~/Notes --burst 10 --window 10
sentinel learn ~/Notes --secs 60
```

`Mix` tracks per kind too. `storm()` fires on rename or delete floods at a third of burst, min 5. Real strains rename a lot, editors do not.

## Entropy

Reads first 1MB, runs Shannon, rounds to 2dp.

Rough scale:

- 3 to 5: text, code, markdown
- 5 to 7: office docs, some media
- 7.5+: random, packed, crypto

Magic skip: zip `PK`, png, jpg, gif, gzip, bmp. Those return clean.

Tune:

```yaml
entropy_line: 7.8
```

Strict labs use 7.2. Media heavy laptops use 7.8. Baseline now stores entropy too, so `check` can spot jumps later.

## Canary

Plain file at `.sentinel/canary.txt`. `watch` makes it if missing. Any hit there alerts at once.

Add your own boring names next to real stuff. Code only auto watches the one in `.sentinel`, but burst still catches mass hits on yours.

## Notes and extensions

Bad exts in `detect.py`: `.enc`, `.locked`, `.crypt`, `.cerber`, `.locky`, plus a few more.

Note names: `READ_ME.txt`, `HOW_TO_DECRYPT.txt`, etc. Exact base match, case blind.

Note words: `decrypt`, `bitcoin`, `monero`, `ransom`, `onion`, `tor`, `recovery key`. Needs 2+ in first 4KB and file under 20KB.

Score in `score_file`:

- 60 sus ext
- 50 note name, 45 note words
- 40 high entropy

Cap 100. `scan` prints 40+. `why FILE` explains one file.

## Risk

`risk()` rolls it up for `check`:

- 50 for 10+ deleted, 10 for any deleted
- 40 for 20+ changed, 10 for any changed
- 40 for top score 70+ or 5+ hits, 15 for any hits

Cap 100. Levels: clean under 40, warn 40 to 69, high 70+. Tune lines with `risk_warn` and `risk_high`.

## Watch order

Per event:

1. canary? alert now
2. note name or words? alert
3. rename or delete storm? alert plus snap plus maybe kill
4. burst? alert plus snap plus maybe kill
5. single scrambled file? alert

Cooldown covers 2 to 5 so one strain makes 1 or 2 alerts, not 500.
