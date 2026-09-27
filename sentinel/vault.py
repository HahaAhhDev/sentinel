import hashlib
import os
import shutil
import time

# vault holds last clean copies, small files only


def vault_dir(root):
    d = os.path.join(os.path.abspath(root), ".sentinel", "vault")
    os.makedirs(d, exist_ok=True)
    return d


def hist_dir(root, rel):
    # versions live beside, out of the way
    d = os.path.join(vault_dir(root), ".history", rel)
    os.makedirs(os.path.dirname(os.path.join(d, "x")), exist_ok=True)
    os.makedirs(d, exist_ok=True)
    return d


def vault_path_for(root, rel):
    # keep sub path so restores land right
    return os.path.join(vault_dir(root), rel)


def same(a, b):
    # quick content match
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        h1, h2 = hashlib.sha256(), hashlib.sha256()
        with open(a, "rb") as f:
            h1.update(f.read())
        with open(b, "rb") as f:
            h2.update(f.read())
        return h1.digest() == h2.digest()
    except OSError:
        return False


def push_history(root, rel, keep=3):
    # stash current copy before overwrite
    src = vault_path_for(root, rel)
    if not os.path.isfile(src):
        return
    d = hist_dir(root, rel)
    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(d, f"{ts}_{os.path.basename(rel)}")
    try:
        shutil.copy2(src, dest)
    except OSError:
        return
    olds = sorted(os.listdir(d))
    for name in olds[:-keep]:
        try:
            os.unlink(os.path.join(d, name))
        except OSError:
            pass


def newest_history(root, rel):
    d = os.path.join(vault_dir(root), ".history", rel)
    if not os.path.isdir(d):
        return ""
    names = sorted(os.listdir(d))
    return os.path.join(d, names[-1]) if names else ""


def should_keep(full, max_mb=5):
    # tiny text-ish files only
    try:
        if os.path.getsize(full) > max_mb * 1024 * 1024:
            return False
        if os.path.islink(full):
            return False
        return True
    except OSError:
        return False


def fill(root, pats=None, max_mb=5, keep=3):
    # copy live files in as clean set
    from .baseline import list_files

    n = 0
    for full in list_files(root, pats):
        if not should_keep(full, max_mb):
            continue
        rel = os.path.relpath(full, root)
        dest = vault_path_for(root, rel)
        try:
            if os.path.exists(dest):
                if os.path.getmtime(dest) >= os.path.getmtime(full):
                    continue
                if not same(dest, full):
                    push_history(root, rel, keep)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(full, dest)
            n += 1
        except OSError:
            continue
    return n


def refresh_one(root, full, max_mb=5):
    # stash one file after a clean check
    if not should_keep(full, max_mb):
        return False
    rel = os.path.relpath(full, root)
    dest = vault_path_for(root, rel)
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(full, dest)
        return True
    except OSError:
        return False


def restore_one(root, rel):
    # newest history first, vault copy as fallback
    dest = os.path.join(root, rel)
    src = newest_history(root, rel) or vault_path_for(root, rel)
    if not os.path.isfile(src):
        return False
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        return True
    except OSError:
        return False


def restore_many(root, rels):
    # bring a list back
    ok = 0
    for r in rels:
        if restore_one(root, r):
            ok += 1
    return ok


def prune_gone(root, known):
    # drop vault files no longer live
    base = vault_dir(root)
    n = 0
    for dp, _, fn in os.walk(base):
        for name in fn:
            full = os.path.join(dp, name)
            rel = os.path.relpath(full, base)
            if rel not in known:
                try:
                    os.unlink(full)
                    n += 1
                except OSError:
                    pass
    return n
