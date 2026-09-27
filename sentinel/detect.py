import math
import os
from collections import Counter, deque
from datetime import datetime

# exts i have seen in writeups
SUS_EXTS = {
    ".enc", ".locked", ".crypt", ".cerber", ".locky", ".aaa", ".xyz",
    ".odin", ".zepto", ".micro", ".aes", ".rsa", ".crypted", ".cryptolocker",
    ".rmd", ".r5a", ".Wallet", ".cobra",
}

# note names most crews reuse
NOTE_NAMES = {
    "read_me.txt", "readme_decrypt.txt", "how_to_decrypt.txt",
    "decrypt_instructions.txt", "ransom_note.txt", "recovery_key.txt",
    "how_to_recover.txt", "decrypt_readme.txt", "read_me_to_decrypt.txt",
    "how_to_decrypt_my_files.txt",
}

NOTE_WORDS = ["decrypt", "bitcoin", "monero", "ransom", "pay ", "tor ", "onion", "recovery key", "send $"]

# zip png jpg trip entropy, skip by header
ZIP_MAGIC = [b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"\x1f\x8b", b"BM"]

ENTROPY_LINE = 7.5


def shannon(data):
    # bog standard math
    if not data:
        return 0.0
    n = len(data)
    out = 0.0
    for v in Counter(data).values():
        p = v / n
        out -= p * math.log2(p)
    return out


def file_entropy(path, limit=1024 * 1024):
    # peek at head, good enough
    try:
        with open(path, "rb") as f:
            b = f.read(limit)
        return round(shannon(b), 2)
    except OSError:
        return 0.0


def is_zip_like(path):
    # magic check
    try:
        with open(path, "rb") as f:
            head = f.read(4)
        return any(head.startswith(m) for m in ZIP_MAGIC)
    except OSError:
        return False


def is_note_name(path):
    return os.path.basename(path.lower()) in NOTE_NAMES


def looks_like_note(path):
    # tiny file with pushy words
    try:
        if os.path.getsize(path) > 20 * 1024:
            return False
        with open(path, "r", errors="ignore") as f:
            t = f.read(4000).lower()
        hits = [w for w in NOTE_WORDS if w in t]
        return len(hits) >= 2
    except OSError:
        return False


def looks_encrypted(path, line=ENTROPY_LINE):
    # ext then entropy
    _, ext = os.path.splitext(path.lower())
    if ext in SUS_EXTS:
        return True, "bad extension"
    if not os.path.isfile(path):
        return False, ""
    try:
        if os.path.getsize(path) == 0:
            return False, ""
    except OSError:
        return False, ""
    if is_zip_like(path):
        return False, ""
    e = file_entropy(path)
    if e >= line:
        return True, f"high entropy {e}"
    return False, ""


def score_file(path, line=ENTROPY_LINE, packs=None):
    # 0-100 plus why list
    pts = 0
    why = []
    _, ext = os.path.splitext(path.lower())
    if ext in SUS_EXTS:
        pts += 60
        why.append("sus extension")
    if is_note_name(path):
        pts += 50
        why.append("note name")
    elif looks_like_note(path):
        pts += 45
        why.append("note words")
    bad, msg = looks_encrypted(path, line)
    if bad and "high entropy" in msg:
        pts += 40
        why.append(msg)
    if packs:
        from . import rules as _rules

        rpts, rwhy = _rules.check_file(path, packs)
        if rpts:
            pts += rpts
            why += rwhy
    return min(pts, 100), why


def explain(path, line=ENTROPY_LINE):
    # plain words for one file
    from . import rules as _rules

    s, why = score_file(path, line, _rules.load_all())
    try:
        size = os.path.getsize(path)
    except OSError:
        size = -1
    e = file_entropy(path) if os.path.isfile(path) else 0.0
    lvl = "clean"
    if s >= 70:
        lvl = "high"
    elif s >= 40:
        lvl = "sus"
    return {"path": path, "score": s, "level": lvl, "why": why, "entropy": e, "size": size}


def risk(verify_res, scan_rows):
    # one number for the whole folder
    n_ch = len(verify_res.get("changed", []))
    n_del = len(verify_res.get("deleted", []))
    top = max([r["score"] for r in (scan_rows or [])] or [0])
    n_hit = len(scan_rows or [])
    pts = 0
    bits = []
    if n_del >= 10:
        pts += 50
        bits.append(f"{n_del} deleted")
    elif n_del > 0:
        pts += 10
        bits.append(f"{n_del} deleted")
    if n_ch >= 20:
        pts += 40
        bits.append(f"{n_ch} changed")
    elif n_ch > 0:
        pts += 10
        bits.append(f"{n_ch} changed")
    if top >= 70 or n_hit >= 5:
        pts += 40
        bits.append(f"scan top {top}")
    elif n_hit > 0:
        pts += 15
        bits.append(f"{n_hit} scan hits")
    pts = min(pts, 100)
    lvl = "clean"
    if pts >= 70:
        lvl = "high"
    elif pts >= 40:
        lvl = "warn"
    return {"score": pts, "level": lvl, "bits": bits}


class Burst:
    # count hits in a window
    def __init__(self, max_events=25, window=10):
        self.max_events = max_events
        self.window = window
        self.times = deque()

    def add(self, when=None):
        # push one, drop old
        t = when or datetime.now().timestamp()
        self.times.append(t)
        cut = t - self.window
        while self.times and self.times[0] < cut:
            self.times.popleft()
        return len(self.times)

    def tripped(self):
        return len(self.times) >= self.max_events

    def count(self):
        return len(self.times)

    def reset(self):
        self.times.clear()


class Mix:
    # per kind counts
    def __init__(self, max_events=25, window=10):
        self.max_events = max_events
        self.window = window
        self.by_kind = {}

    def add(self, kind, when=None):
        b = self.by_kind.get(kind)
        if b is None:
            b = Burst(self.max_events, self.window)
            self.by_kind[kind] = b
        return b.add(when)

    def tripped_kind(self):
        for k, b in self.by_kind.items():
            if b.tripped():
                return k
        return ""

    def storm(self):
        # rename or delete floods count double
        for k in ("moved", "deleted"):
            b = self.by_kind.get(k)
            if b and len(b.times) >= max(5, self.max_events // 3):
                return k
        return ""

    def reset(self):
        for b in self.by_kind.values():
            b.reset()
