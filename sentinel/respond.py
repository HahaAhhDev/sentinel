import json
import os
import shutil
import smtplib
import subprocess
import urllib.request
from datetime import datetime
from email.message import EmailMessage

from rich import print as rprint

LOG_NAME = "sentinel.log"
JSON_NAME = "events.jsonl"


def root_dir(root):
    d = os.path.join(os.path.abspath(root), ".sentinel")
    os.makedirs(d, exist_ok=True)
    return d


def log_line(root, msg):
    # plain text line
    p = os.path.join(root_dir(root), LOG_NAME)
    ts = datetime.now().isoformat(timespec="seconds")
    with open(p, "a") as f:
        f.write(f"{ts} {msg}\n")


def log_json(root, kind, detail="", paths=None, extra=None):
    # json line for tools
    p = os.path.join(root_dir(root), JSON_NAME)
    row = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "kind": kind,
        "detail": detail,
        "paths": (paths or [])[:20],
    }
    if extra:
        row.update(extra)
    with open(p, "a") as f:
        f.write(json.dumps(row) + "\n")


def read_json_log(root, limit=50):
    p = os.path.join(root_dir(root), JSON_NAME)
    if not os.path.isfile(p):
        return []
    out = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    return out[-limit:]


def show_alert(title, detail):
    # loud red
    rprint(f"[bold red][sentinel] {title}[/bold red]")
    if detail:
        rprint(f"[red]{detail}[/red]")


def snapshot(root, paths):
    # copies of hit files, post hit
    if not paths:
        return ""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(root_dir(root), "quarantine", ts)
    os.makedirs(dest, exist_ok=True)
    for p in paths[:50]:
        full = p if os.path.isabs(p) else os.path.join(root, p)
        if not os.path.isfile(full):
            continue
        try:
            base = os.path.basename(full)
            name = base
            i = 1
            while os.path.exists(os.path.join(dest, name)):
                name = f"{i}_{base}"
                i += 1
            shutil.copy2(full, os.path.join(dest, name))
        except OSError:
            continue
    return dest


def list_snaps(root):
    q = os.path.join(root_dir(root), "quarantine")
    if not os.path.isdir(q):
        return []
    return sorted(os.listdir(q))


def send_webhook(url, title, detail):
    # slack and discord both take this
    if not url:
        return False
    try:
        data = json.dumps({"text": f"*{title}*\n{detail}"}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status < 400
    except Exception:
        return False


def send_mail(cfg, title, detail):
    # dumb smtp, no auth frills
    to = cfg.get("mail_to", "")
    if not to:
        return False
    try:
        m = EmailMessage()
        m["Subject"] = f"[sentinel] {title}"
        m["From"] = cfg.get("mail_from", "sentinel@localhost")
        m["To"] = to
        m.set_content(detail or title)
        host = cfg.get("smtp_host", "localhost")
        port = int(cfg.get("smtp_port", 25))
        with smtplib.SMTP(host, port, timeout=5) as s:
            s.send_message(m)
        return True
    except Exception:
        return False


def win_box(title, detail):
    # plain popup, stdlib only
    try:
        import ctypes

        MB_OK = 0x0
        MB_ICONWARNING = 0x30
        ctypes.windll.user32.MessageBoxW(0, detail[:500] or title, f"sentinel: {title}", MB_OK | MB_ICONWARNING)
        return True
    except Exception:
        return False


def win_toast(title, detail):
    # rich toast if plyer around
    try:
        from plyer import notification

        notification.notify(title=f"sentinel: {title}", message=(detail or "")[:250], timeout=10)
        return True
    except Exception:
        return False


def desktop_note(title, detail):
    # win first, then linux, mac
    import sys

    if sys.platform == "win32":
        if win_toast(title, detail):
            return True
        return win_box(title, detail)
    try:
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", title, detail], timeout=3)
            return True
        if shutil.which("osascript"):
            subprocess.run(
                ["osascript", "-e", f'display notification "{detail}" with title "{title}"'],
                timeout=3,
            )
            return True
        if shutil.which("termux-notification"):
            subprocess.run(["termux-notification", "-t", title, "-c", detail], timeout=3)
            return True
    except Exception:
        pass
    return False


def dir_mb(path):
    # size walk
    total = 0
    for dp, _, fn in os.walk(path):
        for n in fn:
            try:
                total += os.path.getsize(os.path.join(dp, n))
            except OSError:
                pass
    return total / (1024 * 1024)


def prune(root, quar_max_mb=500, keep_events=500):
    # cap disk use, oldest snaps first
    root = os.path.abspath(root)
    did = []
    q = os.path.join(root_dir(root), "quarantine")
    if os.path.isdir(q) and quar_max_mb > 0:
        while dir_mb(q) > quar_max_mb:
            names = sorted(os.listdir(q))
            if not names:
                break
            try:
                shutil.rmtree(os.path.join(q, names[0]))
                did.append(f"dropped snap {names[0]}")
            except OSError:
                break
    jp = os.path.join(root_dir(root), JSON_NAME)
    if os.path.isfile(jp):
        with open(jp) as f:
            lines = f.readlines()
        if len(lines) > keep_events:
            with open(jp, "w") as f:
                f.writelines(lines[-keep_events:])
            did.append(f"trimmed events to {keep_events}")
    return did


def bundle(root, dest=""):
    # one zip for the grown ups
    import zipfile

    from . import baseline as _base

    root = os.path.abspath(root)
    dest = dest or os.path.join(root, f"sentinel-case-{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
    try:
        v = _base.verify(root)
    except FileNotFoundError:
        v = {"changed": [], "new": [], "deleted": [], "meta": {}}
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for name in [LOG_NAME, JSON_NAME, "intel.txt"]:
            p = os.path.join(root_dir(root), name)
            if os.path.isfile(p):
                z.write(p, f".sentinel/{name}")
        qp = os.path.join(root_dir(root), "binquar", "index.jsonl")
        if os.path.isfile(qp):
            z.write(qp, ".sentinel/binquar-index.jsonl")
        z.writestr("verify.json", json.dumps(v, indent=2))
        z.writestr("events.json", json.dumps(read_json_log(root, 500), indent=2))
    return dest


def sarif(scan_rows, root=""):    # github code scan shape
    rules = [
        {"id": "sentinel/encrypted", "name": "PossibleEncrypted", "shortDescription": {"text": "file looks encrypted"}},
        {"id": "sentinel/note", "name": "PossibleNote", "shortDescription": {"text": "possible ransom note"}},
    ]
    res = []
    for r in scan_rows or []:
        why = ", ".join(r.get("why", []))
        rid = "sentinel/note" if "note" in why else "sentinel/encrypted"
        lvl = "error" if r.get("score", 0) >= 70 else "warning"
        res.append(
            {
                "ruleId": rid,
                "level": lvl,
                "message": {"text": f"score {r.get('score')} {why}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": os.path.relpath(r.get('path', ''), root or '.')}}}],
            }
        )
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "sentinel", "rules": rules}}, "results": res}]}


def alert(root, title, detail="", paths=None, webhook="", notify=False, cfg=None):
    show_alert(title, detail)
    log_line(root, f"{title} | {detail}")
    log_json(root, title, detail, paths)
    if paths:
        snapshot(root, paths)
    if webhook:
        send_webhook(webhook, title, detail)
    if cfg and cfg.get("mail_to"):
        send_mail(cfg, title, detail)
    if notify:
        desktop_note(title, detail)
