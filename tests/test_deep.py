import os

from sentinel import baseline, config, health, intel, respond, rules, vault
from sentinel.report import scan_files


def test_rules_hit_note(tmp_path):
    # note words trip the pack
    p = tmp_path / "n.txt"
    p.write_text("pay bitcoin to decrypt, see onion link")
    pts, why = rules.check_file(str(p), rules.load_all())
    assert pts > 0


def test_rules_quiet_clean(tmp_path):
    p = tmp_path / "ok.txt"
    p.write_text("hello world, nothing here")
    pts, _ = rules.check_file(str(p), rules.load_all())
    assert pts == 0


def test_intel_block(tmp_path):
    # save a sha, scan flags it
    d = str(tmp_path)
    p = os.path.join(d, "evil.bin")
    with open(p, "wb") as f:
        f.write(b"not random at all, just plain text padding " * 50)
    from sentinel.baseline import file_hash

    h = file_hash(p)
    intel.save(d, [h])
    rows = scan_files(d)
    assert any("known bad" in ",".join(r["why"]) for r in rows)


def test_profiles():
    # presets fold in
    c = config.apply_profile({"profile": "paranoid", "response": "warn"})
    assert c["response"] == "paranoid"
    assert c["burst"] == 10


def test_config_gripes():
    # bad keys get called out
    g = config.check({"response": "nuke", "zzz": 1})
    assert any("response" in x for x in g)
    assert any("zzz" in x for x in g)


def test_per_path_line():
    c = {"entropy_line": 7.5, "paths": [{"prefix": "media/", "entropy_line": 7.9}]}
    assert config.line_for("media/x.mp4", c) == 7.9
    assert config.line_for("docs/a.txt", c) == 7.5


def test_seal_roundtrip(tmp_path):
    # build stamps, verify passes
    d = str(tmp_path)
    with open(os.path.join(d, "a.txt"), "w") as f:
        f.write("hi")
    baseline.build(d)
    r = baseline.verify(d)
    assert r["seal_ok"]


def test_seal_broken(tmp_path):
    # poke the db, seal trips
    d = str(tmp_path)
    with open(os.path.join(d, "a.txt"), "w") as f:
        f.write("hi")
    baseline.build(d)
    with open(baseline.db_path_for(d), "ab") as f:
        f.write(b"junk")
    r = baseline.verify(d)
    assert not r["seal_ok"]


def test_vault_history(tmp_path):
    # second fill keeps old copy
    d = str(tmp_path)
    p = os.path.join(d, "a.txt")
    with open(p, "w") as f:
        f.write("v1 words here")
    vault.fill(d, [], 5, keep=3)
    with open(p, "w") as f:
        f.write("v2 words here!!")
    import time

    os.utime(p, (time.time() + 5, time.time() + 5))
    vault.fill(d, [], 5, keep=3)
    assert vault.newest_history(d, "a.txt") != ""
    n = vault.restore_many(d, ["a.txt"])
    assert n == 1
    with open(p) as f:
        assert f.read() == "v1 words here"


def test_prune(tmp_path):
    # trims events file
    d = str(tmp_path)
    for _ in range(10):
        respond.log_json(d, "x", "y")
    did = respond.prune(d, 500, keep_events=3)
    assert any("trimmed" in x for x in did)
    assert len(respond.read_json_log(d, 100)) == 3


def test_bundle(tmp_path):
    # zip comes out
    d = str(tmp_path)
    with open(os.path.join(d, "a.txt"), "w") as f:
        f.write("hi")
    dest = respond.bundle(d, os.path.join(d, "case.zip"))
    assert os.path.isfile(dest)


def test_health_wrap(tmp_path):
    # errors count, no raise
    d = str(tmp_path)

    def boom():
        raise ValueError("x")

    health.wrap(d, boom)()
    assert health.load(d)["errors"] == 1
