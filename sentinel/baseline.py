import difflib
import fnmatch
import hashlib
import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

from .detect import file_entropy

# junk we never hash
SKIP_DIRS = {".git", "__pycache__", ".sentinel", "node_modules", ".venv", ".tox", "dist", "build"}

# over this we skip the hash
MAX_HASH_SIZE = 20 * 1024 * 1024


def db_path_for(root):
    return os.path.join(root, ".sentinel", "baseline.db")


def seal_path_for(root):
    return os.path.join(root, ".sentinel", "seal")


def seal(root, db_path):
    # stamp db hash so wipes show
    try:
        h = file_hash(db_path)
        with open(seal_path_for(root), "w") as f:
            f.write(h)
    except OSError:
        pass


def seal_ok(root, db_path):
    # true when db matches stamp
    try:
        with open(seal_path_for(root)) as f:
            want = f.read().strip()
        return file_hash(db_path) == want
    except OSError:
        return True


def file_hash(path):
    # read in bits
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(8192)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def hit_ignore(rel, pats):
    # match full or base
    base = os.path.basename(rel)
    for p in pats or []:
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(base, p):
            return True
    return False


def skip(path, root, pats=None):
    rel = os.path.relpath(path, root)
    for part in rel.split(os.sep):
        if part in SKIP_DIRS:
            return True
    if hit_ignore(rel, pats):
        return True
    # skip links, they cause loops
    if os.path.islink(path):
        return True
    return False


def list_files(root, pats=None):
    out = []
    for dp, dn, fn in os.walk(root, followlinks=False):
        # cut junk early
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for name in fn:
            full = os.path.join(dp, name)
            if skip(full, root, pats):
                continue
            out.append(full)
    return out


def _one(args):
    # one file for the pool
    full, root = args
    rel = os.path.relpath(full, root)
    try:
        st = os.stat(full)
        if st.st_size > MAX_HASH_SIZE:
            return (rel, "skipped-big", st.st_size, st.st_mtime, -1.0)
        h = file_hash(full)
        e = -1.0
        # only entropy small text-ish stuff, keeps init fast
        if st.st_size < 2 * 1024 * 1024:
            try:
                e = file_entropy(full)
            except OSError:
                e = -1.0
        return (rel, h, st.st_size, st.st_mtime, e)
    except OSError:
        return None


def build(root, db_path=None, pats=None, jobs=8):
    # fresh baseline
    root = os.path.abspath(root)
    if db_path is None:
        db_path = db_path_for(root)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    files = list_files(root, pats)
    rows = []
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for r in ex.map(_one, [(f, root) for f in files]):
            if r:
                rows.append(r)

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("drop table if exists files")
    cur.execute("create table files (path text primary key, hash text, size integer, mtime real, entropy real)")
    cur.execute("drop table if exists meta")
    cur.execute("create table meta (k text primary key, v text)")
    cur.executemany("insert into files values (?, ?, ?, ?, ?)", rows)
    cur.execute("insert into meta values (?, ?)", ("created", str(time.time())))
    cur.execute("insert into meta values (?, ?)", ("root", root))
    cur.execute("insert into meta values (?, ?)", ("count", str(len(rows))))
    con.commit()
    con.close()
    seal(root, db_path)
    return len(rows)


def update(root, db_path=None, pats=None, jobs=8):
    # rehash only what moved, keeps old rows
    root = os.path.abspath(root)
    if db_path is None:
        db_path = db_path_for(root)
    if not os.path.exists(db_path):
        return build(root, db_path, pats, jobs)
    old, _ = load_baseline(db_path)
    live = list_files(root, pats)
    live_rels = {os.path.relpath(f, root) for f in live}
    # drop deleted
    for p in list(old):
        if p not in live_rels:
            del old[p]
    # find changed by size/mtime first
    todo = []
    for full in live:
        rel = os.path.relpath(full, root)
        try:
            st = os.stat(full)
        except OSError:
            continue
        o = old.get(rel)
        if o is None or o["size"] != st.st_size or abs(o["mtime"] - st.st_mtime) > 1:
            todo.append(full)
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for r in ex.map(_one, [(f, root) for f in todo]):
            if r:
                rel, h, size, mt, e = r
                old[rel] = {"hash": h, "size": size, "mtime": mt, "entropy": e}
    # write back
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("drop table if exists files")
    cur.execute("create table files (path text primary key, hash text, size integer, mtime real, entropy real)")
    rows = [(k, v["hash"], v["size"], v["mtime"], v.get("entropy", -1.0)) for k, v in old.items()]
    cur.executemany("insert into files values (?, ?, ?, ?, ?)", rows)
    cur.execute("insert or replace into meta values (?, ?)", ("count", str(len(rows))))
    cur.execute("insert or replace into meta values (?, ?)", ("updated", str(time.time())))
    con.commit()
    con.close()
    seal(root, db_path)
    return len(rows)


def load_baseline(db_path):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    # old dbs lack entropy col, cope with both
    cur.execute("pragma table_info(files)")
    cols = [r[1] for r in cur.fetchall()]
    if "entropy" in cols:
        cur.execute("select path, hash, size, mtime, entropy from files")
        rows = {r[0]: {"hash": r[1], "size": r[2], "mtime": r[3], "entropy": r[4]} for r in cur.fetchall()}
    else:
        cur.execute("select path, hash, size, mtime from files")
        rows = {r[0]: {"hash": r[1], "size": r[2], "mtime": r[3], "entropy": -1.0} for r in cur.fetchall()}
    try:
        cur.execute("select k, v from meta")
        meta = dict(cur.fetchall())
    except Exception:
        meta = {}
    con.close()
    return rows, meta


def verify(root, db_path=None, pats=None):
    # diff live vs saved
    root = os.path.abspath(root)
    if db_path is None:
        db_path = db_path_for(root)
    if not os.path.exists(db_path):
        raise FileNotFoundError("no baseline yet, run sentinel init first")

    old, meta = load_baseline(db_path)
    seen = set()
    changed = []
    new = []

    for full in list_files(root, pats):
        rel = os.path.relpath(full, root)
        seen.add(rel)
        try:
            st = os.stat(full)
        except OSError:
            continue
        if rel not in old:
            new.append(rel)
            continue
        if old[rel]["hash"] == "skipped-big":
            if old[rel]["size"] != st.st_size:
                changed.append(rel)
            continue
        try:
            h = file_hash(full)
        except OSError:
            continue
        if h != old[rel]["hash"]:
            changed.append(rel)

    gone = [p for p in old if p not in seen]
    # entropy jumps smell like crypto even under burst line
    jumped = []
    for rel in changed:
        o = old.get(rel, {}).get("entropy", -1.0)
        if o is None or o < 0:
            continue
        try:
            now_e = file_entropy(os.path.join(root, rel))
        except OSError:
            continue
        if now_e - o > 2.0:
            jumped.append(rel)
    return {
        "changed": sorted(changed),
        "new": sorted(new),
        "deleted": sorted(gone),
        "jumped": sorted(jumped),
        "seal_ok": seal_ok(root, db_path),
        "meta": meta,
    }


def diff_text(root, rel, max_lines=60):
    # unified diff for small text files
    from .vault import vault_path_for

    full = os.path.join(root, rel)
    vp = vault_path_for(root, rel)
    if not os.path.isfile(vp) or not os.path.isfile(full):
        return ""
    try:
        if os.path.getsize(vp) > 200 * 1024 or os.path.getsize(full) > 200 * 1024:
            return "too big to diff"
        with open(vp, "r", errors="ignore") as f:
            a = f.read().splitlines()
        with open(full, "r", errors="ignore") as f:
            b = f.read().splitlines()
        out = list(difflib.unified_diff(a, b, fromfile="vault", tofile="live", lineterm=""))
        if not out:
            return ""
        if len(out) > max_lines:
            out = out[:max_lines] + ["... cut ..."]
        return "\n".join(out)
    except OSError:
        return ""
