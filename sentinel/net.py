import os

try:
    import psutil
except ImportError:
    psutil = None

# ports rats love
ODD_PORTS = {4444, 5555, 6666, 6667, 1337, 31337, 8081, 9001}

# bins that should not phone home
WEIRD_BINS = {"powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe"}


def conns():
    # live conns or empty
    if psutil is None:
        return []
    try:
        return psutil.net_connections(kind="inet")
    except Exception:
        return []


def name_of(pid):
    # pid to name, best effort
    if psutil is None:
        return "?"
    try:
        return psutil.Process(pid).name() or "?"
    except Exception:
        return "?"


def scan(conn_list=None):
    # flag odd remote ends
    rows = []
    for c in conn_list if conn_list is not None else conns():
        try:
            raddr = c.raddr
            status = c.status
            pid = c.pid
        except Exception:
            continue
        if status not in ("ESTABLISHED", "SYN_SENT"):
            continue
        if not raddr:
            continue
        ip = raddr.ip if hasattr(raddr, "ip") else raddr[0]
        port = raddr.port if hasattr(raddr, "port") else raddr[1]
        if str(ip).startswith(("127.", "10.", "192.168.")) and port not in ODD_PORTS:
            continue
        if str(ip).startswith("172."):
            try:
                second = int(str(ip).split(".")[1])
                if 16 <= second <= 31 and port not in ODD_PORTS:
                    continue
            except ValueError:
                pass
        name = name_of(pid)
        pts = 10
        why = [f"{ip}:{port}"]
        if port in ODD_PORTS:
            pts += 50
            why.append("odd port")
        if os.path.basename(name).lower() in WEIRD_BINS:
            pts += 30
            why.append("odd bin")
        if pts < 40:
            continue
        rows.append({"pid": pid, "name": name, "ip": str(ip), "port": port, "score": min(pts, 100), "why": why})
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows
