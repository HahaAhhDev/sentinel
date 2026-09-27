import json
import os
import time

# tiny health counters for the watcher

NAME = "health.json"


def path_for(root):
    d = os.path.join(os.path.abspath(root), ".sentinel")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, NAME)


def load(root):
    p = path_for(root)
    if not os.path.isfile(p):
        return {"events": 0, "errors": 0, "hits": 0, "started": time.time(), "last": time.time()}
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return {"events": 0, "errors": 0, "hits": 0, "started": time.time(), "last": time.time()}


def save(root, h):
    h["last"] = time.time()
    try:
        with open(path_for(root), "w") as f:
            json.dump(h, f)
    except OSError:
        pass


def bump(root, key, n=1):
    # add n to a counter
    h = load(root)
    h[key] = int(h.get(key, 0)) + n
    save(root, h)
    return h


def wrap(root, fn):
    # run fn, count errors instead of dying
    def inner(*a, **k):
        try:
            r = fn(*a, **k)
            bump(root, "events")
            return r
        except Exception:
            bump(root, "errors")
            return None

    return inner
