import hashlib
import json
import os
import shutil
from datetime import datetime

# bin quarantine lives here


def quar_dir(root):
    d = os.path.join(os.path.abspath(root), ".sentinel", "binquar")
    os.makedirs(d, exist_ok=True)
    return d


def meta_path(root):
    return os.path.join(quar_dir(root), "index.jsonl")


def sha_of(path):
    # chunk it
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(8192)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def put(root, exe_path, why=""):
    # copy exe aside, record it
    if not exe_path or not os.path.isfile(exe_path):
        return None
    try:
        digest = sha_of(exe_path)
    except OSError:
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(exe_path)
    dest = os.path.join(quar_dir(root), f"{ts}_{digest[:12]}_{base}")
    try:
        shutil.copy2(exe_path, dest)
    except OSError:
        return None
    row = {"ts": ts, "sha": digest, "from": exe_path, "to": dest, "why": why}
    with open(meta_path(root), "a") as f:
        f.write(json.dumps(row) + "\n")
    return row


def list_all(root):
    p = meta_path(root)
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
    return out


def known_bad(root, digest):
    # check sha against past hits
    for r in list_all(root):
        if r.get("sha") == digest:
            return True
    return False
