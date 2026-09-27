from . import policy, proc, quar, respond

# one place where hits turn into blocks


def handle(root, title, detail, paths, cfg, suspects=None):
    # returns what we did
    tier = policy.norm((cfg or {}).get("response", "warn"))
    webhook = (cfg or {}).get("webhook", "")
    notify = bool((cfg or {}).get("notify", False))
    did = ["log", "snapshot", "alert"]

    respond.alert(root, title, detail, paths, webhook, notify, cfg)

    if not policy.kills(tier):
        return did

    # kill top writers in watched root
    for s in suspects or proc.top_writer(root, 3):
        pid = s.get("pid")
        exe = proc.exe_of(pid)
        if pid and proc.kill(pid):
            did.append(f"killed {pid}")
        if exe:
            row = quar.put(root, exe, title)
            if row:
                did.append(f"quarantined {exe}")

    if policy.locks(tier):
        # freeze the rest holding files open
        for s in proc.top_writer(root, 5):
            if proc.suspend(s.get("pid")):
                did.append(f"held {s.get('pid')}")
    return did
