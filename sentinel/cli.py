import json
import os
import shutil
import sys
import time

import typer
from rich import print as rprint
from rich.progress import track
from rich.table import Table

from . import baseline, canary, detect, guard, net, persist, policy, proc, quar, report, respond, vault
from . import config as cfgmod
from .watcher import watch_loop

app = typer.Typer(help="watch a folder and yell if it acts weird", no_args_is_help=True)


def _cfg(config, **over):
    # file plus flags
    c = cfgmod.load(config or "")
    for k, v in over.items():
        if v not in ("", None):
            c[k] = v
    return c


def _pats(root, c):
    return cfgmod.load_ignore(root, c.get("ignore", []))


def _risk_c(c):
    return int(c.get("risk_warn", 40)), int(c.get("risk_high", 70))


@app.command()
def init(
    path: str = typer.Argument(".", help="folder to baseline"),
    config: str = typer.Option("", help="yaml to use"),
    jobs: int = typer.Option(8, help="hash threads"),
    vault_mb: int = typer.Option(5, help="vault cap per file in mb"),
):
    # fresh start
    c = _cfg(config)
    root = os.path.abspath(path)
    pats = _pats(root, c)
    made = canary.deploy(root)
    files = baseline.list_files(root, pats)
    rprint(f"hashing {len(files)} files in {root}")
    n = baseline.build(root, pats=pats, jobs=jobs)
    v = vault.fill(root, pats, vault_mb)
    rprint(f"[green]saved {n} files, vaulted {v}, {made} canaries[/green]")


@app.command()
def update(
    path: str = typer.Argument(".", help="folder"),
    config: str = typer.Option(""),
    jobs: int = typer.Option(8, help="hash threads"),
):
    # quick refresh, keeps history cheap
    c = _cfg(config)
    root = os.path.abspath(path)
    pats = _pats(root, c)
    n = baseline.update(root, pats=pats, jobs=jobs)
    rprint(f"[green]now tracking {n} files[/green]")


@app.command()
def status(path: str = typer.Argument(".", help="folder"), config: str = typer.Option("")):
    # what do we know
    root = os.path.abspath(path)
    db = baseline.db_path_for(root)
    if not os.path.isfile(db):
        rprint("[red]no baseline, run init first[/red]")
        raise typer.Exit(1)
    _, meta = baseline.load_baseline(db)
    t = Table(title=f"status {root}")
    t.add_column("key")
    t.add_column("value")
    for k in ["root", "count", "created", "updated"]:
        if k in meta:
            t.add_row(k, str(meta[k]))
    # vault size
    vd = os.path.join(root, ".sentinel", "vault")
    n_v = sum(len(f) for _, _, f in os.walk(vd)) if os.path.isdir(vd) else 0
    t.add_row("vault files", str(n_v))
    rprint(t)


@app.command()
def verify(
    path: str = typer.Argument(".", help="folder"),
    config: str = typer.Option(""),
    out_json: bool = typer.Option(False, "--json", help="json out"),
    fail: bool = typer.Option(False, "--fail", help="exit 1 on drift"),
    html: str = typer.Option("", help="write page here"),
):
    # diff vs baseline
    c = _cfg(config)
    root = os.path.abspath(path)
    pats = _pats(root, c)
    try:
        r = baseline.verify(root, pats=pats)
    except FileNotFoundError:
        rprint("[red]no baseline, run init first[/red]")
        raise typer.Exit(1)
    if out_json:
        print(json.dumps(r, indent=2))
    elif not r["changed"] and not r["new"] and not r["deleted"]:
        rprint("[green]all clean[/green]")
    else:
        t = Table(title=f"verify {root}")
        t.add_column("kind")
        t.add_column("file")
        for f in r["changed"]:
            t.add_row("changed", f)
        for f in r["new"]:
            t.add_row("new", f)
        for f in r["deleted"]:
            t.add_row("deleted", f)
        rprint(t)
    if html:
        report.write_report(root, html, verify_res=r)
        rprint(f"[green]wrote {html}[/green]")
    if fail and (r["changed"] or r["deleted"]):
        raise typer.Exit(1)


@app.command()
def diff(
    path: str = typer.Argument(".", help="folder"),
    config: str = typer.Option(""),
    n: int = typer.Option(10, help="max files to show"),
):
    # text diffs for changed files
    c = _cfg(config)
    root = os.path.abspath(path)
    pats = _pats(root, c)
    try:
        r = baseline.verify(root, pats=pats)
    except FileNotFoundError:
        rprint("[red]no baseline[/red]")
        raise typer.Exit(1)
    if not r["changed"]:
        rprint("[green]no changed files[/green]")
        return
    for rel in r["changed"][:n]:
        rprint(f"[bold]{rel}[/bold]")
        d = baseline.diff_text(root, rel)
        if d:
            print(d[:4000])
        else:
            rprint("[dim]binary or no vault copy[/dim]")
        print()


@app.command()
def scan(
    path: str = typer.Argument(".", help="folder"),
    config: str = typer.Option(""),
    line: float = typer.Option(7.5, help="entropy line"),
    top: int = typer.Option(200, help="max rows"),
    out_json: bool = typer.Option(False, "--json", help="json out"),
    sarif: bool = typer.Option(False, "--sarif", help="sarif out"),
    html: str = typer.Option("", help="write page here"),
):
    # hunt bad files once
    c = _cfg(config)
    if c.get("entropy_line"):
        line = float(c["entropy_line"])
    root = os.path.abspath(path)
    pats = _pats(root, c)
    rows = report.scan_files(root, pats, line, top)
    if sarif:
        print(json.dumps(respond.sarif(rows, root), indent=2))
        return
    if out_json:
        print(json.dumps(rows, indent=2))
    elif not rows:
        rprint("[green]no hits[/green]")
    else:
        t = Table(title=f"scan {root}")
        t.add_column("score")
        t.add_column("file")
        t.add_column("why")
        for r in rows:
            short = os.path.relpath(r["path"], root)
            t.add_row(str(r["score"]), short, ", ".join(r["why"]))
        rprint(t)
    if html:
        report.write_report(root, html, scan_rows=rows)
        rprint(f"[green]wrote {html}[/green]")


@app.command()
def why(file: str = typer.Argument(..., help="file to explain"), line: float = typer.Option(7.5)):
    # why did this score so
    full = os.path.abspath(file)
    if not os.path.exists(full):
        rprint(f"[red]no such file {full}[/red]")
        raise typer.Exit(1)
    e = detect.explain(full, line)
    t = Table(title=full)
    t.add_column("k")
    t.add_column("v")
    t.add_row("score", str(e["score"]))
    t.add_row("level", e["level"])
    t.add_row("entropy", str(e["entropy"]))
    t.add_row("size", str(e["size"]))
    t.add_row("why", ", ".join(e["why"]) or "nothing odd")
    rprint(t)


@app.command()
def check(
    path: str = typer.Argument(".", help="folder"),
    config: str = typer.Option(""),
    out_json: bool = typer.Option(False, "--json", help="json out"),
    sarif: bool = typer.Option(False, "--sarif", help="sarif out"),
    html: str = typer.Option("", help="write page here"),
    fail_warn: bool = typer.Option(False, help="fail on warn+"),
):
    # verify plus scan plus one risk number
    c = _cfg(config)
    root = os.path.abspath(path)
    pats = _pats(root, c)
    line = float(c.get("entropy_line", 7.5))
    w_warn, _ = _risk_c(c)
    try:
        v = baseline.verify(root, pats=pats)
    except FileNotFoundError:
        v = {"changed": [], "new": [], "deleted": [], "meta": {}}
    rows = report.scan_files(root, pats, line)
    rk = detect.risk(v, rows)
    if sarif:
        print(json.dumps(respond.sarif(rows, root), indent=2))
        return
    if out_json:
        print(json.dumps({"verify": v, "scan": rows, "risk": rk}, indent=2))
    else:
        col = {"clean": "green", "warn": "yellow", "high": "red"}.get(rk["level"], "yellow")
        rprint(f"[{col}]risk {rk['level']} {rk['score']}[/{col}] " + (", ".join(rk["bits"]) or "all quiet"))
        if v["changed"] or v["deleted"]:
            rprint(f"{len(v['changed'])} changed, {len(v['deleted'])} deleted, {len(v['new'])} new")
        if rows:
            rprint(f"{len(rows)} scan hits, top {rows[0]['score']}")
    if html:
        report.write_report(root, html, v, rows, respond.read_json_log(root, 100), rk)
        rprint(f"[green]wrote {html}[/green]")
    bad = rk["score"] >= w_warn if fail_warn else rk["level"] == "high" or bool(v["changed"] or v["deleted"])
    if bad:
        raise typer.Exit(1)


@app.command()
def watch(
    path: str = typer.Argument(".", help="folder"),
    config: str = typer.Option("", help="yaml"),
    burst: int = typer.Option(25, help="events to trip"),
    window: int = typer.Option(10, help="window secs"),
    cooldown: int = typer.Option(30, help="quiet after hit"),
    webhook: str = typer.Option("", help="slack/discord url"),
    kill: bool = typer.Option(False, help="kill top writer"),
    notify: bool = typer.Option(False, help="popup"),
    response: str = typer.Option("", help="warn, auto, or paranoid"),
    daemon: bool = typer.Option(False, help="run in bg"),
    pidfile: str = typer.Option("", help="where to store pid"),
):
    # live loop, blocks real hits per tier
    c = _cfg(config, burst=burst, window=window, webhook=webhook)
    burst = int(c["burst"])
    window = int(c["window"])
    cooldown = int(c.get("cooldown", cooldown))
    line = float(c.get("entropy_line", 7.5))
    if kill or c.get("kill"):
        # old flag means auto at least
        c["response"] = "auto"
    if response:
        c["response"] = policy.norm(response)
    if notify or c.get("notify"):
        notify = True
        c["notify"] = True

    root = os.path.abspath(path)
    pats = _pats(root, c)

    if daemon:
        # fork off, write pid
        if sys.platform == "win32":
            rprint("[red]daemon fork is unix only, use win-task instead[/red]")
            raise typer.Exit(1)
        pf = pidfile or os.path.join(root, ".sentinel", "watch.pid")
        os.makedirs(os.path.dirname(pf), exist_ok=True)
        pid = os.fork() if hasattr(os, "fork") else None
        if pid and pid > 0:
            with open(pf, "w") as f:
                f.write(str(pid))
            rprint(f"[green]bg pid {pid} in {pf}[/green]")
            return

    single = os.path.join(root, ".sentinel", "canary.txt")
    os.makedirs(os.path.dirname(single), exist_ok=True)
    if not os.path.exists(single):
        with open(single, "w") as f:
            f.write("leave me alone")
    canary.deploy(root)

    b = detect.Burst(max_events=burst, window=window)
    mix = detect.Mix(max_events=burst, window=window)
    recent: list[str] = []
    cool_until = 0.0
    tier = policy.norm(c.get("response", "warn"))

    rprint(f"[green]watching {root} (burst {burst}/{window}s, {tier})[/green]")
    rprint("ctrl-c to stop")

    def on_event(kind, full):
        nonlocal cool_until
        now = time.time()
        n = b.add(now)
        mix.add(kind, now)
        recent.append(full)
        if len(recent) > 100:
            recent.pop(0)

        # canary always wins, blocks even on warn tier lore
        if canary.is_canary(root, full):
            guard.handle(root, "canary touched", f"{kind} {full}", [full], c)
            b.reset()
            return

        # note check
        if kind in ("created", "modified"):
            if detect.is_note_name(full) or detect.looks_like_note(full):
                if now > cool_until:
                    cool_until = now + cooldown
                    guard.handle(root, "possible ransom note", full, [full], c)
                return

        # rename or delete flood
        st = mix.storm()
        if st and now > cool_until:
            cool_until = now + cooldown
            guard.handle(root, f"{st} storm", f"{kind} flood, last {os.path.basename(full)}", list(recent), c)
            b.reset()
            mix.reset()
            recent.clear()
            return

        # plain burst
        if b.tripped() and now > cool_until:
            cool_until = now + cooldown
            detail = f"{n} events in {window}s, last: {os.path.basename(full)}"
            guard.handle(root, "burst of file changes", detail, list(recent), c)
            b.reset()
            mix.reset()
            recent.clear()
            return

        # one scrambled file
        if kind in ("created", "modified"):
            bad, why = detect.looks_encrypted(full, line)
            if bad and now > cool_until:
                cool_until = now + cooldown
                guard.handle(root, "file looks encrypted", f"{full} ({why})", [full], c)

    watch_loop(root, on_event, pats=pats)


@app.command()
def harden(
    path: str = typer.Argument(".", help="folder to guard"),
    config: str = typer.Option(""),
    out_json: bool = typer.Option(False, "--json", help="json out"),
):
    # one pass: canaries, persist, net, baseline state
    import sys as _sys

    c = _cfg(config)
    root = os.path.abspath(path)
    made = canary.deploy(root)
    entries = persist.scan()
    flagged = []
    for e in entries:
        pts, why = persist.sus(e)
        if pts >= 30:
            flagged.append({**e, "score": pts, "why": why})
    nets = net.scan()
    try:
        v = baseline.verify(root, pats=_pats(root, c))
        drift = len(v["changed"]) + len(v["deleted"])
    except FileNotFoundError:
        drift = -1
    res = {
        "os": _sys.platform,
        "canaries": made,
        "persist_total": len(entries),
        "persist_flagged": flagged,
        "net_hits": nets,
        "drift": drift,
        "tier": policy.norm(c.get("response", "warn")),
    }
    if out_json:
        print(json.dumps(res, indent=2))
        return
    t = Table(title=f"harden {root} ({res['os']})")
    t.add_column("check")
    t.add_column("result")
    t.add_row("canaries laid", str(made))
    t.add_row("autostart entries", f"{len(entries)} ({len(flagged)} sus)")
    for f in flagged[:5]:
        t.add_row("  sus", f"{f['name']} [{', '.join(f['why'])}]")
    t.add_row("odd connections", str(len(nets)))
    for n in nets[:5]:
        t.add_row("  conn", f"{n['name']} {n['ip']}:{n['port']} ({', '.join(n['why'])})")
    t.add_row("baseline drift", "no baseline" if drift < 0 else str(drift))
    t.add_row("response tier", res["tier"] + f" ({', '.join(policy.what(res['tier']))})")
    rprint(t)
    if flagged or nets or drift and drift > 0:
        rprint("[yellow]look above, clean those first[/yellow]")
    else:
        rprint("[green]looks quiet[/green]")


@app.command()
def netscan(out_json: bool = typer.Option(False, "--json", help="json out")):
    # live odd connections
    rows = net.scan()
    if out_json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        rprint("[green]no odd connections[/green]")
        return
    t = Table(title="odd connections")
    t.add_column("pid")
    t.add_column("proc")
    t.add_column("remote")
    t.add_column("score")
    t.add_column("why")
    for r in rows:
        t.add_row(str(r["pid"]), r["name"], f"{r['ip']}:{r['port']}", str(r["score"]), ", ".join(r["why"]))
    rprint(t)


@app.command(name="persist")
def persist_cmd(out_json: bool = typer.Option(False, "--json", help="json out")):
    # autostart entries on this box
    rows = persist.scan()
    out = []
    for e in rows:
        pts, why = persist.sus(e)
        out.append({**e, "score": pts, "why": why})
    out.sort(key=lambda r: r["score"], reverse=True)
    if out_json:
        print(json.dumps(out, indent=2))
        return
    if not out:
        rprint("[green]no autostart entries found[/green]")
        return
    t = Table(title="autostart")
    t.add_column("score")
    t.add_column("where")
    t.add_column("name")
    t.add_column("cmd")
    for e in out:
        cmd = e["cmd"]
        if len(cmd) > 60:
            cmd = cmd[:60] + "..."
        t.add_row(str(e["score"]), e["where"], e["name"], cmd)
    rprint(t)


@app.command(name="quar")
def quar_cmd(
    path: str = typer.Argument(".", help="folder"),
    resume_pid: int = typer.Option(0, help="resume a held pid"),
):
    # jailed binaries, plus unfreeze
    root = os.path.abspath(path)
    if resume_pid:
        ok = proc.resume(resume_pid)
        rprint("[green]resumed[/green]" if ok else "[red]no such pid[/red]")
        return
    rows = quar.list_all(root)
    if not rows:
        rprint("quarantine empty, nothing jailed yet")
        return
    t = Table(title=f"jailed {root}")
    t.add_column("time")
    t.add_column("sha")
    t.add_column("from")
    t.add_column("why")
    for r in rows:
        t.add_row(r.get("ts", ""), (r.get("sha", "")[:12]), r.get("from", "")[:50], r.get("why", "")[:40])
    rprint(t)


@app.command()
def win_task(
    path: str = typer.Argument(".", help="folder to watch"),
    create: bool = typer.Option(False, help="make scheduled task"),
    remove: bool = typer.Option(False, help="drop scheduled task"),
    task: str = typer.Option("", help="task name"),
    config: str = typer.Option("", help="yaml to use"),
):
    # windows always on watch via task scheduler
    import subprocess as _sp
    import sys as _sys

    c = _cfg(config)
    name = task or c.get("win_task", "SentinelWatch")
    root = os.path.abspath(path)
    if remove:
        if _sys.platform != "win32":
            rprint("remove runs on windows only")
            raise typer.Exit(1)
        _sp.run(["schtasks", "/Delete", "/TN", name, "/F"])
        rprint(f"[green]dropped {name}[/green]")
        return
    cmd = f'schtasks /Create /TN "{name}" /TR "sentinel watch \\"{root}\\" --response auto" /SC ONLOGON /RL HIGHEST /F'
    if create:
        if _sys.platform != "win32":
            rprint("create runs on windows only, command would be:")
            rprint(cmd)
            raise typer.Exit(1)
        _sp.run(cmd, shell=True)
        rprint(f"[green]watch starts at logon ({name})[/green]")
        return
    rprint("run with --create on your windows box:")
    rprint(cmd)


@app.command()
def events(
    path: str = typer.Argument(".", help="folder"),
    n: int = typer.Option(20, help="how many"),
    out_json: bool = typer.Option(False, "--json", help="json out"),
):
    # last hits
    root = os.path.abspath(path)
    rows = respond.read_json_log(root, n)
    if out_json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        rprint("no events yet")
        return
    t = Table(title=f"events {root}")
    t.add_column("time")
    t.add_column("kind")
    t.add_column("detail")
    for e in rows:
        t.add_row(e.get("ts", ""), e.get("kind", ""), e.get("detail", "")[:80])
    rprint(t)


@app.command()
def timeline(path: str = typer.Argument(".", help="folder"), n: int = typer.Option(30)):
    # time sorted view
    root = os.path.abspath(path)
    rows = respond.read_json_log(root, n)
    if not rows:
        rprint("no events yet, run watch first")
        return
    for e in rows:
        rprint(f"[dim]{e.get('ts','')}[/dim] [bold]{e.get('kind','')}[/bold] {e.get('detail','')[:100]}")


@app.command()
def snaps(path: str = typer.Argument(".", help="folder")):
    # quarantine packs
    root = os.path.abspath(path)
    q = os.path.join(root, ".sentinel", "quarantine")
    names = respond.list_snaps(root)
    if not names:
        rprint("no snapshots yet")
        return
    t = Table(title=f"snapshots {root}")
    t.add_column("id")
    t.add_column("files")
    for name in names:
        full = os.path.join(q, name)
        try:
            cnt = len(os.listdir(full))
        except OSError:
            cnt = 0
        t.add_row(name, str(cnt))
    rprint(t)


@app.command()
def restore(path: str = typer.Argument(".", help="folder"), snap: str = typer.Argument("", help="snap id or blank")):
    # bring quarantine back, flat
    root = os.path.abspath(path)
    q = os.path.join(root, ".sentinel", "quarantine")
    names = respond.list_snaps(root)
    if not names:
        rprint("nothing to restore")
        raise typer.Exit(1)
    pick = snap or names[-1]
    src = os.path.join(q, pick)
    if not os.path.isdir(src):
        rprint(f"[red]no snap {pick}[/red]")
        raise typer.Exit(1)
    n = 0
    for name in os.listdir(src):
        try:
            shutil.copy2(os.path.join(src, name), os.path.join(root, name))
            n += 1
        except OSError:
            continue
    rprint(f"[green]restored {n} files from {pick}[/green]")


@app.command()
def protect(
    path: str = typer.Argument(".", help="folder"),
    config: str = typer.Option(""),
    max_mb: int = typer.Option(5, help="cap per file"),
    restore_clean: str = typer.Option("", help="restore these rel paths, comma list, or 'all'"),
):
    # vault of clean copies, this is what saves you
    c = _cfg(config)
    root = os.path.abspath(path)
    pats = _pats(root, c)
    cap = max_mb or int(c.get("vault_max_mb", 5))
    if restore_clean:
        try:
            v = baseline.verify(root, pats=pats)
        except FileNotFoundError:
            rprint("[red]no baseline[/red]")
            raise typer.Exit(1)
        targets = v["changed"] if restore_clean == "all" else [s.strip() for s in restore_clean.split(",")]
        ok = vault.restore_many(root, targets)
        rprint(f"[green]brought back {ok} clean files[/green]")
        return
    n = vault.fill(root, pats, cap)
    rprint(f"[green]vaulted {n} clean files[/green]")


@app.command(name="report")
def report_cmd(path: str = typer.Argument(".", help="folder"), out: str = typer.Option("report.html"), config: str = typer.Option("")):
    # one page html
    c = _cfg(config)
    root = os.path.abspath(path)
    pats = _pats(root, c)
    line = float(c.get("entropy_line", 7.5))
    try:
        v = baseline.verify(root, pats=pats)
    except FileNotFoundError:
        v = {"changed": [], "new": [], "deleted": [], "meta": {}}
    rows = report.scan_files(root, pats, line)
    evts = respond.read_json_log(root, 100)
    rk = detect.risk(v, rows)
    report.write_report(root, out, v, rows, evts, rk)
    rprint(f"[green]wrote {out}[/green]")


@app.command(name="serve")
def serve_cmd(path: str = typer.Argument(".", help="folder"), port: int = typer.Option(8000, help="port")):
    # local web view
    from .serve import serve

    serve(os.path.abspath(path), port)


@app.command()
def learn(path: str = typer.Argument(".", help="folder"), secs: int = typer.Option(60, help="watch secs"), config: str = typer.Option("")):
    # watch quiet and suggest burst
    from .learn import learn as do_learn

    c = _cfg(config)
    root = os.path.abspath(path)
    pats = _pats(root, c)
    rprint(f"listening for {secs}s, work like normal...")
    r = do_learn(root, pats, secs)
    rprint(f"saw {r['events']} events ({r['per10']}/10s)")
    rprint(f"[green]try burst {r['suggest_burst']} window {r['suggest_window']}[/green]")


@app.command()
def config_init(dest: str = typer.Argument("sentinel.yaml", help="where to write")):
    # starter yaml
    if os.path.exists(dest):
        rprint(f"[red]{dest} exists, remove it first[/red]")
        raise typer.Exit(1)
    cfgmod.write_example(dest)
    rprint(f"[green]wrote {dest}, tweak and go[/green]")


@app.command()
def doctor(path: str = typer.Argument(".", help="folder")):
    # quick self test
    root = os.path.abspath(path)
    ok = True
    rprint(f"checking {root}")
    # perms
    if not os.access(root, os.R_OK | os.W_OK):
        rprint("[red]cant read/write folder[/red]")
        ok = False
    else:
        rprint("[green]folder rw ok[/green]")
    # watchdog import
    try:
        import watchdog  # noqa

        rprint("[green]watchdog ok[/green]")
    except Exception:
        rprint("[red]watchdog missing[/red]")
        ok = False
    # config
    c = cfgmod.load()
    rprint(f"config file: {c.get('_file') or 'none, using defaults'}")
    # baseline
    db = baseline.db_path_for(root)
    if os.path.isfile(db):
        _, meta = baseline.load_baseline(db)
        rprint(f"[green]baseline {meta.get('count','?')} files[/green]")
    else:
        rprint("[yellow]no baseline yet[/yellow]")
    # os and tier
    c = cfgmod.load()
    rprint(f"os {sys.platform}, tier {policy.norm(c.get('response', 'warn'))}")
    try:
        n_p = len(persist.scan())
        rprint(f"autostart entries: {n_p} (see persist cmd)")
    except Exception:
        pass
    # python
    rprint(f"python {sys.version.split()[0]}")
    if not ok:
        raise typer.Exit(1)
    rprint("[green]all good[/green]")


@app.command()
def clean(path: str = typer.Argument(".", help="folder")):
    # wipe state
    root = os.path.abspath(path)
    d = os.path.join(root, ".sentinel")
    if os.path.isdir(d):
        shutil.rmtree(d)
        rprint(f"[green]cleaned {d}[/green]")
    else:
        rprint("nothing to clean")


@app.command()
def demo(path: str = typer.Argument("./demo_run", help="scratch dir")):
    # fake hit to see rules
    root = os.path.abspath(path)
    os.makedirs(root, exist_ok=True)
    rprint(f"making fake files in {root}")

    for i in track(range(5), description="setup"):
        with open(os.path.join(root, f"note{i}.txt"), "w") as f:
            f.write("hello " * 200)

    b = detect.Burst(max_events=10, window=5)
    for i in range(12):
        p = os.path.join(root, f"note{i % 5}.txt")
        with open(p, "wb") as f:
            f.write(os.urandom(5000))
        b.add()
        time.sleep(0.05)

    with open(os.path.join(root, "READ_ME.txt"), "w") as f:
        f.write("pay bitcoin to decrypt your files, see onion link")

    e = detect.file_entropy(os.path.join(root, "note0.txt"))
    rprint(f"entropy now: {e}")
    s, why = detect.score_file(os.path.join(root, "note0.txt"))
    rprint(f"score note0: {s} ({', '.join(why)})")
    if b.tripped():
        rprint("[red]demo would trip burst rule[/red]")
    else:
        rprint("demo did not trip, try lower limits")


if __name__ == "__main__":
    app()
