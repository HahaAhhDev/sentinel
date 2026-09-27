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
    # block tiers: warn, auto, paranoid
    "response": "warn",
    "canaries": 5,
    "win_task": "SentinelWatch",
    # procs we never kill
    "allow": [],
    # per path tweaks, first prefix match wins
    "paths": [],
    # keep N vault versions per file
    "vault_keep": 3,
    # quarantine cap in mb, 0 means no cap
    "quar_max_mb": 500,
}

# one word starters
PROFILES = {
    "home": {"burst": 25, "window": 10, "entropy_line": 7.5, "response": "warn", "vault_max_mb": 5},
    "server": {"burst": 50, "window": 10, "entropy_line": 7.5, "response": "auto", "vault_max_mb": 5},
    "uploads": {"burst": 40, "window": 10, "entropy_line": 7.2, "response": "auto", "vault_max_mb": 10},
    "paranoid": {"burst": 10, "window": 10, "entropy_line": 7.0, "response": "paranoid", "vault_max_mb": 10},
}

KNOWN = set(DEFAULTS) | {"profile"}


def apply_profile(cfg):
    # fold preset under explicit keys
    name = str(cfg.get("profile", "")).lower()
    if name in PROFILES:
        base = dict(PROFILES[name])
        base.update({k: v for k, v in cfg.items() if k in DEFAULTS and v != DEFAULTS.get(k)})
        base.update({k: v for k, v in cfg.items() if k not in DEFAULTS})
        return base
    return cfg


def check(cfg):
    # lint it, return gripes
    gripes = []
    for k in cfg:
        if k.startswith("_"):
            continue
        if k not in KNOWN:
            gripes.append(f"unknown key {k}")
    if str(cfg.get("response", "warn")).lower() not in ("warn", "auto", "paranoid"):
        gripes.append("response must be warn, auto, or paranoid")
    try:
        if not 0 < float(cfg.get("entropy_line", 7.5)) < 8.5:
            gripes.append("entropy_line looks off, 7.0 to 8.0 is sane")
    except (TypeError, ValueError):
        gripes.append("entropy_line must be a number")
    return gripes


def line_for(rel, cfg):
    # per path entropy line
    for rule in cfg.get("paths", []) or []:
        if str(rel).startswith(str(rule.get("prefix", ""))):
            try:
                return float(rule.get("entropy_line", cfg.get("entropy_line", 7.5)))
            except (TypeError, ValueError):
                pass
    return float(cfg.get("entropy_line", 7.5))


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
    out = apply_profile(out)
    out["_file"] = p
    out["_gripes"] = check(out)
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
