import os
import tempfile

from sentinel import baseline, detect


def test_entropy_low_for_text():
    # plain text scores low
    with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
        f.write("hello " * 500)
        p = f.name
    try:
        assert detect.file_entropy(p) < 5.0
    finally:
        os.unlink(p)


def test_entropy_high_for_random():
    # random bytes score high
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(os.urandom(5000))
        p = f.name
    try:
        assert detect.file_entropy(p) > 7.0
    finally:
        os.unlink(p)


def test_burst_trips():
    b = detect.Burst(max_events=3, window=10)
    b.add()
    b.add()
    assert not b.tripped()
    b.add()
    assert b.tripped()


def test_baseline_roundtrip():
    # build then verify, should be clean
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a.txt"), "w") as f:
            f.write("hi")
        n = baseline.build(d)
        assert n == 1
        r = baseline.verify(d)
        assert r["changed"] == []
        assert r["deleted"] == []

        # touch a file, should show up
        with open(os.path.join(d, "a.txt"), "w") as f:
            f.write("bye")
        r2 = baseline.verify(d)
        assert r2["changed"] == ["a.txt"]
