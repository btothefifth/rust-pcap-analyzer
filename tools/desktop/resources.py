"""Local worker lifecycle budgets, separate from capture-time parser semantics."""
from __future__ import annotations
from contextlib import AbstractContextManager
import json
import os
from pathlib import Path
import signal
import threading
import time
import uuid

class WorkerStopped(RuntimeError):
    pass

def publish_state(path, value, *, attempts=25, retry_delay=0.004):
    """Atomic replacement with unique staging, durable file flush, bounded retry.

    Parent directory must be a trusted stable workspace. Directory durability is
    asserted only on POSIX; this is not protection against a hostile local owner.
    """
    path = Path(path)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    if (len(raw) > 65536 or type(attempts) is not int or not 1 <= attempts <= 100
            or type(retry_delay) not in (int, float) or not 0 <= retry_delay <= 1):
        raise ValueError("state publication budget")
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".next")
    try:
        with temp.open("xb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        for attempt in range(attempts):
            try:
                os.replace(temp, path)
                break
            except PermissionError:
                if attempt + 1 == attempts:
                    raise
                time.sleep(retry_delay * (attempt + 1))
        if os.name == "posix":
            fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        temp.unlink(missing_ok=True)

class ResourceGuard(AbstractContextManager):
    """Kill a direct native child on cancellation, timeout, or observed disk excess.

    Disk accounting is a sampled logical budget, not a kernel/filesystem quota.
    Existing bounded log writes and SQLite limits remain independent safeguards.
    No packet expiration, timestamps, or TCP decision uses this wall clock.
    """
    def __init__(self, directory, disk_budget, timeout_seconds=86400):
        if type(disk_budget) is not int or not 65536 <= disk_budget <= 64 * 1024**4:
            raise ValueError("worker disk budget outside 64 KiB..64 TiB")
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 7 * 86400:
            raise ValueError("worker lifetime budget outside (0, 7 days]")
        self.directory = Path(directory)
        self.disk_budget = disk_budget
        self.timeout_seconds = timeout_seconds
        self.started = time.monotonic()
        self.done = threading.Event()
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.reason = None
        self.child = None
        self.peak = 0
        self.handlers = {}
        self.thread = None

    def stop(self, reason="cancelled"):
        with self.lock:
            if self.reason is None:
                self.reason = reason
            self.stopped.set()
            child = self.child
        if child is not None and child.poll() is None:
            try:
                child.kill()
            except OSError:
                pass

    def attach(self, child):
        with self.lock:
            self.child = child
        if self.stopped.is_set():
            self.stop(self.reason)

    def sample(self):
        if (self.directory / "cancel.request").exists():
            self.stop("cancelled")
        if time.monotonic() - self.started > self.timeout_seconds:
            self.stop("worker_lifetime_budget")
        total = 0
        count = 0
        for entry in self.directory.iterdir():
            count += 1
            if count > 256:
                self.stop("workspace_file_count_budget")
                break
            if entry.is_symlink():
                self.stop("workspace_symlink_rejected")
                break
            try:
                stat = entry.stat()
            except FileNotFoundError:
                continue  # Unique state staging file was atomically published.
            if entry.is_file():
                total += stat.st_size
        self.peak = max(self.peak, total)
        if total > self.disk_budget:
            self.stop("observed_workspace_disk_budget")

    def check(self):
        if self.stopped.is_set():
            raise WorkerStopped(self.reason or "cancelled")

    def __enter__(self):
        def watch():
            while not self.done.wait(0.05):
                try:
                    self.sample()
                except OSError as error:
                    self.stop("disk_measurement_" + type(error).__name__)
                if self.stopped.is_set():
                    return
        if threading.current_thread() is threading.main_thread():
            for name in ("SIGTERM", "SIGINT", "SIGBREAK"):
                sig = getattr(signal, name, None)
                if sig is not None:
                    self.handlers[sig] = signal.getsignal(sig)
                    signal.signal(sig, lambda *_: self.stop("cancelled"))
        try:
            self.sample()
            self.thread = threading.Thread(target=watch, name="pcap-worker-budget", daemon=True)
            self.thread.start()
            return self
        except BaseException:
            for sig, handler in self.handlers.items():
                signal.signal(sig, handler)
            raise

    def __exit__(self, *_):
        self.done.set()
        if self.thread is not None:
            self.thread.join(timeout=2)
        for sig, handler in self.handlers.items():
            signal.signal(sig, handler)
        return False
