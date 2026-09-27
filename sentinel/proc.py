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


def exe_of(pid):
    # path to the binary or empty
    if psutil is None or not pid:
        return ""
    try:
        return psutil.Process(pid).exe() or ""
    except Exception:
        return ""


def is_signed(exe):
    # windows authenticode check, best effort
    import subprocess
    import sys

    if sys.platform != "win32" or not exe:
        return False
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"(Get-AuthenticodeSignature '{exe}').Status"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return "Valid" in r.stdout
    except Exception:
        return False


def suspend(pid):
    # freeze it, works both os
    if psutil is None or not pid:
        return False
    try:
        psutil.Process(pid).suspend()
        return True
    except Exception:
        return False


def resume(pid):
    # unfreeze it
    if psutil is None or not pid:
        return False
    try:
        psutil.Process(pid).resume()
        return True
    except Exception:
        return False
