import os

try:
    import psutil
except ImportError:
    psutil = None


def top_writer(root, limit=5):
    # who holds most files open here
    if psutil is None:
        return []
    root = os.path.abspath(root)
    hits = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            files = p.open_files()
        except Exception:
            continue
        n = sum(1 for f in files if f.path.startswith(root))
        if n:
            hits.append({"pid": p.info["pid"], "name": p.info["name"] or "?", "open": n})
    hits.sort(key=lambda x: x["open"], reverse=True)
    return hits[:limit]


def kill(pid):
    # soft kill, let it flush
    if psutil is None:
        return False
    try:
        p = psutil.Process(pid)
        p.terminate()
        return True
    except Exception:
        return False


def describe(pid):
    # one liner for logs
    if psutil is None:
        return str(pid)
    try:
        p = psutil.Process(pid)
        return f"{p.name()} ({pid}) cwd={p.cwd()}"
    except Exception:
        return str(pid)
