# Windows guide

Same tool, same commands. A few notes.

## Install

```powershell
pip install sentinel-watch
sentinel doctor $HOME
```

Needs Python 3.10+. No compiler, no drivers. `watchdog`, `psutil`, all wheels.

Popups work out of the box with a plain message box. Richer toasts need plyer:

```powershell
pip install plyer
```

## Always on

`--daemon` fork is unix only. Pick per OS:

```bash
sentinel service /home/you/Documents --install
```

Prints systemd steps on Linux, launchd steps on Mac, and points at `win-task --create` on Windows. Units live in `examples/`.

```powershell
sentinel win-task C:\Users\you\Documents --create
```

Shows the exact `schtasks` line first. Creates an ONLOGON task at HIGHEST run level running `sentinel watch --response auto`. Remove with `--remove`. Task name defaults to SentinelWatch, change with yaml `win_task:`.

## What is checked

- Run keys `HKCU\...\Run` and `RunOnce` via `sentinel persist`
- Startup folder lnks and exes
- Odd connections via `sentinel netscan`
- Canaries, burst, entropy, notes via `sentinel watch`

Registry reads need nothing special for HKCU. HIGHEST task level covers protected spots.

## Response tiers

Same as unix: `warn`, `auto`, `paranoid`. On Windows kill uses terminate, hold uses psutil suspend which freezes the proc until `quar --resume-pid`.

```powershell
sentinel watch C:\Data --response auto --notify
```

## Paths

Quote them. Backslashes are fine:

```powershell
sentinel init "C:\Users\you\Documents"
sentinel check "C:\Data" --json
```

Note names match case blind, entropy skips zips and pics by magic bytes same as unix.

## Limits

- No kernel driver, so no boot time or kernel rootkit view
- SmartScreen and Defender stay on, sentinel sits next to them
- Long paths over 260 chars need long path support on in Windows
