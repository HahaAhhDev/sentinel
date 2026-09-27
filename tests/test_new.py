import json
import os

from sentinel import baseline, config, detect, respond, vault
from sentinel.report import scan_files


def test_vault_roundtrip(tmp_path):
    # fill then break then bring back
    d = str(tmp_path)
    p = os.path.join(d, "a.txt")
    with open(p, "w") as f:
        f.write("clean here")
    n = vault.fill(d, [], 5)
    assert n >= 1
    with open(p, "w") as f:
        f.write("scrambled!!!")
    ok = vault.restore_many(d, ["a.txt"])
    assert ok == 1
    with open(p) as f:
        assert f.read() == "clean here"


def test_update_keeps_count(tmp_path):
    # update after edit keeps track
    d = str(tmp_path)
    with open(os.path.join(d, "a.txt"), "w") as f:
        f.write("hi")
    baseline.build(d)
    with open(os.path.join(d, "a.txt"), "w") as f:
        f.write("bye now")
    n = baseline.update(d)
    assert n == 1
    r = baseline.verify(d)
    assert r["changed"] == []


def test_risk_levels():
    # clean stays clean
    v = {"changed": [], "new": [], "deleted": [], "meta": {}}
    r = detect.risk(v, [])
    assert r["level"] == "clean"
    # lots deleted goes high
    v2 = {"changed": [], "new": [], "deleted": [str(i) for i in range(12)], "meta": {}}
    r2 = detect.risk(v2, [])
    assert r2["score"] >= 40


def test_explain_one(tmp_path):
    # why gives words
    p = tmp_path / "x.locked"
    p.write_bytes(b"hi")
    e = detect.explain(str(p))
    assert e["score"] >= 60
    assert e["level"] in ("sus", "high")


def test_sarif_shape(tmp_path):
    # sarif has runs
    d = str(tmp_path)
    with open(os.path.join(d, "bad.locked"), "wb") as f:
        f.write(os.urandom(3000))
    rows = scan_files(d)
    s = respond.sarif(rows, d)
    assert s["version"].startswith("2.")
    assert len(s["runs"][0]["results"]) >= 1


def test_config_write(tmp_path):
    # scaffold writes yaml
    dest = os.path.join(str(tmp_path), "s.yaml")
    assert config.write_example(dest)
    assert os.path.isfile(dest)


def test_diff_text(tmp_path):
    # vault diff shows change
    d = str(tmp_path)
    p = os.path.join(d, "a.txt")
    with open(p, "w") as f:
        f.write("line1\nline2\n")
    baseline.build(d)
    vault.fill(d, [], 5)
    with open(p, "w") as f:
        f.write("line1\nlineX\n")
    out = baseline.diff_text(d, "a.txt")
    assert "lineX" in out or "line2" in out


def test_storm(tmp_path):
    # delete flood trips storm
    m = detect.Mix(max_events=9, window=10)
    for _ in range(5):
        m.add("deleted")
    assert m.storm() == "deleted"
