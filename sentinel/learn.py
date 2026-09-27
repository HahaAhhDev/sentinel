import time

from .watcher import watch_loop


def learn(root, pats=None, secs=60):
    # sit quiet and count, then suggest burst
    counts = []
    total = {"n": 0}
    start = time.time()

    def on_event(kind, full):
        total["n"] += 1
        counts.append(time.time())

    # run loop in main thread but stop after secs
    import threading

    t = threading.Thread(target=watch_loop, args=(root, on_event, pats), daemon=True)
    t.start()
    time.sleep(secs)
    # cant stop watchdog cleanly here, daemon dies with us
    # keep math simple
    n = total["n"]
    per10 = round(n / max(secs, 1) * 10, 1)
    # suggest 3x normal plus floor
    sug = max(10, int(per10 * 3) + 5)
    return {"secs": secs, "events": n, "per10": per10, "suggest_burst": sug, "suggest_window": 10}
