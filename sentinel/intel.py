import os

# local sha blocklist, feed optional

NAME = "intel.txt"


def path_for(root):
    return os.path.join(os.path.abspath(root), ".sentinel", NAME)


def load(root):
    # shas we already fear
    p = path_for(root)
    out = set()
    if not os.path.isfile(p):
        return out
    with open(p) as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                out.add(line.split()[0])
    return out


def save(root, shas):
    # merge new shas in
    have = load(root)
    have |= {s.strip().lower() for s in shas if s.strip()}
    os.makedirs(os.path.dirname(path_for(root)), exist_ok=True)
    with open(path_for(root), "w") as f:
        for s in sorted(have):
            f.write(s + "\n")
    return len(have)


def check(root, digest):
    return digest.lower() in load(root)


def scan_file(root, full):
    # hash and match, empty when clean
    from .baseline import file_hash

    try:
        h = file_hash(full)
    except OSError:
        return False, ""
    if check(root, h):
        return True, f"known bad sha {h[:12]}"
    return False, ""
