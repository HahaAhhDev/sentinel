import os
import sys

# autostart spots, per os

WIN_RUN_KEYS = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
]

LINUX_SPOTS = [
    ".config/autostart",
    ".config/systemd/user",
]


def is_win():
    return sys.platform == "win32"


def win_run_entries():
    # read Run keys, empty on miss
    out = []
    try:
        import winreg
    except ImportError:
        return out
    import winreg as _w

    for sub, hive in WIN_RUN_KEYS:
        for root_const, tag in ((_w.HKEY_CURRENT_USER, "HKCU"),):
            try:
                with _w.OpenKey(root_const, sub) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = _w.EnumValue(k, i)
                            out.append({"where": f"{tag}\\{sub}", "name": name, "cmd": str(val)})
                            i += 1
                        except OSError:
                            break
            except OSError:
                continue
    return out


def win_startup_files():
    # startup folder lnks and exes
    out = []
    base = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
    if not os.path.isdir(base):
        return out
    for name in os.listdir(base):
        out.append({"where": "startup", "name": name, "cmd": os.path.join(base, name)})
    return out


def linux_entries(home=""):
    # cron plus autostart plus systemd user
    home = home or os.path.expanduser("~")
    out = []
    for spot in LINUX_SPOTS:
        d = os.path.join(home, spot)
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            out.append({"where": spot, "name": name, "cmd": os.path.join(d, name)})
    for name in [".bashrc", ".profile", ".bash_profile"]:
        p = os.path.join(home, name)
        if os.path.isfile(p):
            try:
                with open(p, errors="ignore") as f:
                    t = f.read()
                if "curl" in t and ("sh" in t or "bash" in t):
                    out.append({"where": "shell rc", "name": name, "cmd": "pipe to shell found"})
            except OSError:
                pass
    return out


def cron_hits():
    # crontab -l lines, best effort
    import subprocess

    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return []
        return [{"where": "crontab", "name": str(i), "cmd": l} for i, l in enumerate(r.stdout.splitlines()) if l.strip() and not l.startswith("#")]
    except Exception:
        return []


def scan(home=""):
    # all spots for this os
    if is_win():
        return win_run_entries() + win_startup_files()
    return linux_entries(home) + cron_hits()


def sus(entry):
    # rank one entry 0-100
    cmd = (entry.get("cmd", "") + " " + entry.get("name", "")).lower()
    pts = 0
    why = []
    for w in ["powershell -enc", "powershell -e ", "bitsadmin", "certutil", "mshta", "wscript", "cscript", "regsvr32", "rundll32", ".ps1", "temp\\", "/tmp/", "curl", "wget", "appdata\\", ".onion"]:
        if w in cmd:
            pts += 30
            why.append(w.strip())
            if pts >= 60:
                break
    return min(pts, 100), why
