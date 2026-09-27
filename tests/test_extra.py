import os

from sentinel import baseline, config, detect, report, respond


def test_note_name():
    assert detect.is_note_name("READ_ME.txt")
    assert detect.is_note_name("/x/HOW_TO_DECRYPT.txt")
    assert not detect.is_note_name("notes.txt")


def test_note_words():
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
        f.write("pay bitcoin to decrypt, see onion link")
        p = f.name
    try:
        assert detect.looks_like_note(p)
    finally:
        os.unlink(p)


def test_score_locked():
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False, suffix=".locked") as f:
        f.write(b"hi")
        p = f.name
    try:
        s, why = detect.score_file(p)
        assert s >= 60
    finally:
        os.unlink(p)


def test_zip_skipped():
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as f:
        f.write(b"PK\x03\x04" + os.urandom(2000))
        p = f.name
    try:
        bad, _ = detect.looks_encrypted(p)
        assert not bad
    finally:
        os.unlink(p)


def test_ignore_works(tmp_path):
    # .sentinelignore should hide files
    (tmp_path / "a.tmp").write_text("hi")
    (tmp_path / "b.txt").write_text("hi")
    (tmp_path / ".sentinelignore").write_text("*.tmp\n")
    pats = config.load_ignore(str(tmp_path), [])
    files = baseline.list_files(str(tmp_path), pats)
    names = [os.path.basename(p) for p in files]
    assert "b.txt" in names
    assert "a.tmp" not in names


def test_config_defaults():
    c = config.load("")
    assert c["burst"] == 25
    assert "path" in c


def test_scan_and_report(tmp_path):
    d = str(tmp_path)
    with open(os.path.join(d, "ok.txt"), "w") as f:
        f.write("hello " * 100)
    with open(os.path.join(d, "bad.locked"), "wb") as f:
        f.write(os.urandom(4000))
    rows = report.scan_files(d)
    assert any("bad.locked" in r["path"] for r in rows)
    out = os.path.join(d, "r.html")
    report.write_report(d, out, {"changed": [], "new": [], "deleted": [], "meta": {}}, rows, [])
    assert os.path.isfile(out)


def test_mix():
    m = detect.Mix(max_events=2, window=10)
    m.add("created")
    assert m.tripped_kind() == ""
    m.add("created")
    assert m.tripped_kind() == "created"


def test_events_log(tmp_path):
    d = str(tmp_path)
    respond.log_json(d, "test hit", "detail here", ["a.txt"])
    rows = respond.read_json_log(d, 10)
    assert rows[-1]["kind"] == "test hit"
