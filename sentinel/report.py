import os
from datetime import datetime

from . import baseline, detect, respond

CSS = """
body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#222;line-height:1.5}
.head{background:#111;color:#fff;padding:1.4rem;border-radius:12px}
.pill{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;margin-right:6px}
.ok{background:#e6f4ea;color:#137333}
.bad{background:#fce8e6;color:#a50e0e}
.warn{background:#fef7e0;color:#b06000}
table{width:100%;border-collapse:collapse;margin-top:1rem}
th,td{text-align:left;padding:8px;border-bottom:1px solid #eee;font-size:14px;vertical-align:top}
code{background:#f1f3f4;padding:2px 6px;border-radius:4px;word-break:break-all}
.muted{color:#666;font-size:13px}
"""


def scan_files(root, pats=None, line=7.5, top=200, packs=None, intel_on=True, cfg=None):
    # walk, hash once, score all
    from .baseline import file_hash, list_files

    if packs is None:
        from . import rules as _rules

        packs = _rules.load_all()
    if intel_on:
        from . import intel as _intel
    else:
        _intel = None
    if cfg is not None:
        from .config import line_for as _line_for
    else:
        _line_for = None

    out = []
    for full in list_files(root, pats):
        rel = os.path.relpath(full, root)
        per = _line_for(rel, cfg) if _line_for else line
        try:
            if os.path.getsize(full) > 5 * 1024 * 1024 or os.path.islink(full):
                h = ""
            else:
                h = file_hash(full)
        except OSError:
            continue
        if h and _intel and _intel.check(root, h):
            out.append({"path": full, "score": 100, "why": [f"known bad sha {h[:12]}"]})
            continue
        score, why = detect.score_file(full, per, packs)
        if score >= 40:
            out.append({"path": full, "score": score, "why": why})
    out.sort(key=lambda x: x["score"], reverse=True)
    return out[:top]


def build_html(root, verify_res=None, scan_rows=None, events=None, risk_res=None):
    # one file, works offline
    root = os.path.abspath(root)
    if verify_res is None:
        try:
            verify_res = baseline.verify(root)
        except FileNotFoundError:
            verify_res = {"changed": [], "new": [], "deleted": [], "meta": {}}
    if scan_rows is None:
        scan_rows = []
    if events is None:
        events = respond.read_json_log(root, 100)
    if risk_res is None:
        risk_res = detect.risk(verify_res, scan_rows)

    lvl = risk_res.get("level", "clean")
    cls = {"clean": "ok", "warn": "warn", "high": "bad"}.get(lvl, "warn")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    def rows_for(items, kind):
        if not items:
            return "<tr><td colspan=2 class=muted>none</td></tr>"
        return "".join(f"<tr><td>{kind}</td><td><code>{x}</code></td></tr>" for x in items)

    rows = rows_for(verify_res.get("changed", []), "changed")
    rows += rows_for(verify_res.get("new", []), "new")
    rows += rows_for(verify_res.get("deleted", []), "deleted")

    srows = ""
    for r in (scan_rows or [])[:200]:
        rel = os.path.relpath(r["path"], root)
        srows += f"<tr><td>{r['score']}</td><td><code>{rel}</code></td><td>{', '.join(r['why'])}</td></tr>"
    if not srows:
        srows = "<tr><td colspan=3 class=muted>no hits</td></tr>"

    erows = ""
    for e in reversed(events or []):
        erows += f"<tr><td class=muted>{e.get('ts','')}</td><td>{e.get('kind','')}</td><td>{e.get('detail','')}</td></tr>"
    if not erows:
        erows = "<tr><td colspan=3 class=muted>no events yet</td></tr>"

    bits = ", ".join(risk_res.get("bits", [])) or "nothing odd"
    meta = verify_res.get("meta", {})
    base_info = f"baseline {meta.get('count','?')} files"
    if meta.get("created"):
        try:
            base_info += " from " + datetime.fromtimestamp(float(meta["created"])).strftime("%Y-%m-%d")
        except Exception:
            pass

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>sentinel report</title><style>{CSS}</style></head><body>
<div class="head"><h1 style="margin:0">sentinel report</h1>
<div class="muted" style="color:#ccc">{root} · {ts} · {base_info}</div>
<p><span class="pill {cls}">risk {lvl} {risk_res.get('score',0)}</span>
<span class="pill warn">{len(verify_res.get('changed',[]))} changed</span>
<span class="pill warn">{len(scan_rows or [])} scan hits</span>
<span class="pill warn">{len(events or [])} events</span></p>
<p class="muted" style="color:#ccc">{bits}</p></div>
<h2>diff vs baseline</h2><table><tr><th>kind</th><th>file</th></tr>{rows}</table>
<h2>scan hits</h2><table><tr><th>score</th><th>file</th><th>why</th></tr>{srows}</table>
<h2>recent events</h2><table><tr><th>time</th><th>kind</th><th>detail</th></tr>{erows}</table>
<p class="muted">made by sentinel {ts} · open <code>sentinel timeline</code> for cli view</p></body></html>"""


def write_report(root, dest, verify_res=None, scan_rows=None, events=None, risk_res=None):
    html = build_html(root, verify_res, scan_rows, events, risk_res)
    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    with open(dest, "w") as f:
        f.write(html)
    return dest
