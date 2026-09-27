from . import health, policy, proc, quar, respond

# one place where hits turn into blocks


def allowed(name, cfg):
    # allowlisted writers never die
    keep = {a.lower() for a in (cfg or {}).get("allow", [])}
    keep |= {"backup", "rsync", "borg", "restic", "robocopy"}
    n = (name or "").lower()
    return any(k in n for k in keep)


def handle(root, title, detail, paths, cfg, suspects=None):
    # returns what we did
    tier = policy.norm((cfg or {}).get("response", "warn"))
    webhook = (cfg or {}).get("webhook", "")
    notify = bool((cfg or {}).get("notify", False))
    did = ["log", "snapshot", "alert"]

    respond.alert(root, title, detail, paths, webhook, notify, cfg)
    health.bump(root, "hits")

    if not policy.kills(tier):
        return did

    # kill unknown writers, spare known good
    for s in suspects or proc.top_writer(root, 3):
        pid = s.get("pid")
        name = s.get("name", "")
        if allowed(name, cfg):
            did.append(f"spared {name}")
            continue
        exe = proc.exe_of(pid)
        if exe and proc.is_signed(exe):
            did.append(f"spared signed {name}")
            continue
        if pid and proc.kill(pid):
            did.append(f"killed {pid}")
        if exe:
            row = quar.put(root, exe, title)
            if row:
                did.append(f"quarantined {exe}")

    if policy.locks(tier):
        # freeze the rest holding files open
        for s in proc.top_writer(root, 5):
            if allowed(s.get("name", ""), cfg):
                continue
            if proc.suspend(s.get("pid")):
                did.append(f"held {s.get('pid')}")
    return did
