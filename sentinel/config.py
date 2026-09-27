import os

try:
    import yaml
except ImportError:
    yaml = None

# files we check, first hit wins
NAMES = ["sentinel.yaml", ".sentinel.yaml", ".sentinel/config.yaml"]

# what you get if no file found
DEFAULTS = {
    "path": ".",
    "burst": 25,
    "window": 10,
    "cooldown": 30,
    "entropy_line": 7.5,
    "webhook": "",
    "ignore": [],
    "kill": False,
    "notify": False,
    # new bits
    "vault_max_mb": 5,
    "risk_warn": 40,
    "risk_high": 70,
    "serve_port": 8000,
    "mail_to": "",
    "mail_from": "sentinel@localhost",
    "smtp_host": "localhost",
    "smtp_port": 25,
}


def find(start="."):
    # walk up til we hit one
    d = os.path.abspath(start)
    while True:
        for n in NAMES:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
        up = os.path.dirname(d)
        if up == d:
            return ""
        d = up


def load(path=""):
    # yaml on top of defaults
    out = dict(DEFAULTS)
    p = path or find()
    if p and yaml and os.path.isfile(p):
        with open(p) as f:
            data = yaml.safe_load(f) or {}
        for k, v in data.items():
            out[k] = v
    out["_file"] = p
    return out


def load_ignore(root, extra=None):
    # file globs plus yaml list
    pats = list(extra or [])
    for name in [".sentinelignore", ".gitignore"]:
        p = os.path.join(root, name)
        if not os.path.isfile(p):
            continue
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pats.append(line)
    return pats


def write_example(dest):
    # dump defaults for people to tweak
    if yaml is None:
        return False
    data = {k: v for k, v in DEFAULTS.items()}
    with open(dest, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    return True
