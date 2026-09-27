import os

try:
    import yaml
except ImportError:
    yaml = None

# tiny string rules, yara mood without the dep

PACK_DIR = os.path.join(os.path.dirname(__file__), "packs")


def list_packs():
    # yaml files shipped with us
    if not os.path.isdir(PACK_DIR):
        return []
    return sorted(f for f in os.listdir(PACK_DIR) if f.endswith((".yaml", ".yml")))


def load_pack(name):
    # one pack to dict
    p = os.path.join(PACK_DIR, name)
    if not os.path.isfile(p) or yaml is None:
        return {"name": name, "rules": []}
    with open(p) as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("name", name)
    data.setdefault("rules", [])
    return data


def load_all(names=None):
    # many packs at once
    out = []
    for n in names or list_packs():
        out.append(load_pack(n))
    return out


def check_file(path, packs=None, limit=64 * 1024):
    # score bytes against string lists
    pts = 0
    why = []
    try:
        if os.path.getsize(path) > 5 * 1024 * 1024:
            return 0, []
        with open(path, "rb") as f:
            blob = f.read(limit).lower()
    except OSError:
        return 0, []
    for pack in packs if packs is not None else load_all():
        for rule in pack.get("rules", []):
            hits = 0
            for s in rule.get("strings", []):
                if s.lower().encode() in blob:
                    hits += 1
            need = int(rule.get("need", 2))
            if hits >= need and hits > 0:
                pts += int(rule.get("points", 30))
                why.append(rule.get("name", "rule"))
    return min(pts, 100), why
