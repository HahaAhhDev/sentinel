import os
import shutil

# vault holds last clean copies, small files only


def vault_dir(root):
    d = os.path.join(os.path.abspath(root), ".sentinel", "vault")
    os.makedirs(d, exist_ok=True)
    return d


def vault_path_for(root, rel):
    # keep sub path so restores land right
    return os.path.join(vault_dir(root), rel)


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


def fill(root, pats=None, max_mb=5):
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
    # bring one back
    src = vault_path_for(root, rel)
    dest = os.path.join(root, rel)
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
