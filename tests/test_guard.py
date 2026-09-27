import os

from sentinel import canary, guard, net, persist, policy, quar


def test_tiers():
    # warn watches, auto kills, paranoid holds
    assert policy.norm("bogus") == "warn"
    assert not policy.kills("warn")
    assert policy.kills("auto")
    assert policy.locks("paranoid")
    assert "quarantine binary" in policy.what("auto")


def test_quar_put_and_list(tmp_path):
    # jail a fake exe
    d = str(tmp_path)
    exe = os.path.join(d, "evil.exe")
    with open(exe, "wb") as f:
        f.write(b"mz fake binary")
    row = quar.put(d, exe, "test hit")
    assert row and os.path.isfile(row["to"])
    rows = quar.list_all(d)
    assert len(rows) == 1
    assert quar.known_bad(d, row["sha"])


def test_persist_score():
    # lolbin lines rank high
    e = {"where": "HKCU\\Run", "name": "up", "cmd": "powershell -enc aGVsbG8="}
    pts, why = persist.sus(e)
    assert pts >= 30
    clean = {"where": "x", "name": "one", "cmd": "C:\\Windows\\notepad.exe"}
    assert persist.sus(clean)[0] == 0


def test_persist_linux_tmp(tmp_path):
    # fake home with autostart file
    home = str(tmp_path)
    d = os.path.join(home, ".config", "autostart")
    os.makedirs(d)
    with open(os.path.join(d, "x.desktop"), "w") as f:
        f.write("Exec=evil")
    rows = persist.linux_entries(home)
    assert any(r["name"] == "x.desktop" for r in rows)


def test_net_scan_fake():
    # odd port flags, local clean does not
    class C:
        def __init__(self, ip, port, status, pid):
            self.raddr = (ip, port)
            self.status = status
            self.pid = pid

    rows = net.scan([C("8.8.8.8", 4444, "ESTABLISHED", 1)])
    assert rows and rows[0]["score"] >= 40
    assert "odd port" in rows[0]["why"]
    rows2 = net.scan([C("127.0.0.1", 8000, "ESTABLISHED", 1)])
    assert rows2 == []


def test_canary_deploy(tmp_path):
    # lays files, spots them
    d = str(tmp_path)
    n = canary.deploy(d)
    assert n == len(canary.NAMES)
    assert canary.is_canary(d, os.path.join(d, canary.NAMES[0]))
    assert not canary.is_canary(d, os.path.join(d, "real.txt"))


def test_guard_warn_only(tmp_path):
    # warn tier never kills
    d = str(tmp_path)
    with open(os.path.join(d, "a.txt"), "w") as f:
        f.write("hi")
    did = guard.handle(d, "test", "detail", [], {"response": "warn"})
    assert did == ["log", "snapshot", "alert"]


def test_guard_auto_fake_pid(tmp_path):
    # auto tier with dead pid does not blow up
    d = str(tmp_path)
    did = guard.handle(d, "test", "detail", [], {"response": "auto"}, [{"pid": 999999999, "name": "ghost", "open": 1}])
    assert "log" in did
