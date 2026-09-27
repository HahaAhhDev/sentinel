import os
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .baseline import hit_ignore


class Handler(FileSystemEventHandler):
    # tiny shim to a callback
    def __init__(self, root, on_event, pats=None):
        super().__init__()
        self.root = os.path.abspath(root)
        self.on_event = on_event
        self.pats = pats or []

    def _pass(self, path):
        rel = os.path.relpath(path, self.root)
        if rel.startswith(".sentinel"):
            return False
        if hit_ignore(rel, self.pats):
            return False
        return True

    def on_created(self, e):
        if not e.is_directory and self._pass(e.src_path):
            self.on_event("created", e.src_path)

    def on_modified(self, e):
        if not e.is_directory and self._pass(e.src_path):
            self.on_event("modified", e.src_path)

    def on_deleted(self, e):
        if not e.is_directory and self._pass(e.src_path):
            self.on_event("deleted", e.src_path)

    def on_moved(self, e):
        if not e.is_directory and self._pass(str(e.src_path)):
            self.on_event("moved", str(e.dest_path))


def watch_loop(root, on_event, pats=None, poll=1.0, debounce=0.5):
    # debounce repeat saves
    ob = Observer()
    last = {}
    orig = on_event

    def wrapped(kind, path):
        now = time.time()
        if last.get(path, 0) + debounce > now and kind == "modified":
            return
        last[path] = now
        orig(kind, path)

    ob.schedule(Handler(root, wrapped, pats), root, recursive=True)
    ob.start()
    try:
        while True:
            time.sleep(poll)
    except KeyboardInterrupt:
        pass
    finally:
        ob.stop()
        ob.join()
