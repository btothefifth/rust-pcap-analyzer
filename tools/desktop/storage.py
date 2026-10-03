"""One logical admission owner for the trusted, exclusively owned workspace.

Counts retained files (including hardlink names) conservatively, never deletes
retained evidence, and reserves coexistence peaks before writers start. This is
not a filesystem quota: external writers/trusted executables and sampled native
SQLite allocation are outside an exact physical-cap guarantee. The manager's
create-new owner marker prevents restart from reclaiming uncertain live writers.
"""
from __future__ import annotations
from bisect import bisect_right, insort
from dataclasses import dataclass
import os
import re
from pathlib import Path
import stat
import threading

MAX_ENTRIES = 32768
MAX_JOBS = 128
MAX_RESEARCH = 1024
MAX_EXPORTS = 128
MIN_JOB_BUDGET = 512 * 1024

class StorageDenied(ValueError):
    """Retained bytes/cardinality or unresolved writer ownership deny admission."""

@dataclass
class Census:
    files: dict
    entries: int

    @property
    def bytes(self):
        return sum(self.files.values())


def census(directory, max_entries=MAX_ENTRIES):
    """Bounded recursive traversal; reject unsafe or unmeasurable retained state."""
    root = Path(directory)
    files = {}
    entries = 0
    pending = [root]
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as iterator:
            for entry in iterator:
                entries += 1
                if entries > max_entries:
                    raise StorageDenied("workspace entry budget; retain evidence and clean up explicitly")
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue  # Atomic worker state staging may have just moved.
                path = Path(entry.path)
                if stat.S_ISLNK(info.st_mode):
                    raise StorageDenied("workspace symlink rejected")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    files[path] = info.st_size
                else:
                    raise StorageDenied("workspace special file rejected")
    return Census(files, entries)


@dataclass(eq=False)
class Reservation:
    owner: object
    path: Path
    peak: int
    entries: int
    basis: int = 0
    active: bool = True

    def release(self):
        with self.owner.lock:
            if self.active:
                self.owner.reservations.remove(self)
                self.active = False


class WorkspaceBudget:
    def __init__(self, root, limit, *, max_entries=MAX_ENTRIES):
        if type(limit) is not int or not 65536 <= limit < 50_000_000_000:
            raise ValueError("workspace disk budget outside 64 KiB..<50 GB")
        self.root = Path(root)
        self.limit = limit
        self.max_entries = max_entries
        self.lock = threading.RLock()
        self.reservations = []
        self.research = {}
        initial = census(self.root, max_entries)
        # Legacy over-budget evidence stays readable. New writes are denied.
        for path in initial.files:
            if (path.name == "receipt.json" and path.parent.parent.name == "research"
                    and path.parent.parent.parent.parent == self.root / "runs"
                    and re.fullmatch(r"[0-9a-f]{32}",path.parent.name)):
                keys = self.research.setdefault(path.parent.parent.parent.name, [])
                keys.append(path.parent.name)
        for keys in self.research.values():
            keys.sort()

    def _usage(self):
        current = census(self.root, self.max_entries)
        charged = current.bytes
        entries = current.entries
        for claim in self.reservations:
            inside = sum(size for path, size in current.files.items()
                         if path == claim.path or claim.path in path.parents)
            charged += max(0, claim.basis + claim.peak - inside)
            # Conservative: entry reservations remain charged while active.
            entries += claim.entries
        return current, charged, entries

    def available(self):
        with self.lock:
            _, charged, _ = self._usage()
            return max(0, self.limit - charged)

    def reserve(self, path, peak, *, entries=1, kind=None, maximum=None):
        path = Path(path)
        if (type(peak) is not int or peak < 0 or type(entries) is not int or entries < 0
                or self.root not in path.parents):
            raise ValueError("invalid workspace reservation")
        with self.lock:
            current, charged, count = self._usage()
            for claim in self.reservations:
                if (path == claim.path or path in claim.path.parents or claim.path in path.parents):
                    raise StorageDenied("workspace writer still owns this scope")
            if kind is not None:
                parent = path.parent
                existing = 0
                if parent.exists():
                    with os.scandir(parent) as iterator:
                        for item in iterator:
                            existing += 1
                            if existing >= maximum:
                                raise StorageDenied(kind + " retention count budget")
                existing += sum(r.path.parent == parent for r in self.reservations)
                if existing >= maximum:
                    raise StorageDenied(kind + " retention count budget")
            if charged + peak > self.limit:
                raise StorageDenied("workspace retained disk budget; retain evidence and clean up explicitly")
            if count + entries > self.max_entries:
                raise StorageDenied("workspace entry budget")
            basis = sum(size for item, size in current.files.items()
                        if item == path or path in item.parents)
            claim = Reservation(self, path, peak, entries, basis)
            self.reservations.append(claim)
            return claim

    def register_research(self, job, rid):
        with self.lock:
            keys = self.research.setdefault(job, [])
            if rid not in keys:
                insort(keys, rid)

    def research_keys(self, job, after="", limit=100):
        with self.lock:
            keys = self.research.get(job, [])
            offset = bisect_right(keys, after)
            selected = keys[offset:offset + limit]
            return selected, offset + len(selected) < len(keys)

    def status(self):
        with self.lock:
            current, charged, entries = self._usage()
            return {"retained_bytes": str(current.bytes), "admitted_peak_bytes": str(charged),
                    "disk_budget": str(self.limit), "retained_entries": current.entries,
                    "entry_budget": self.max_entries, "active_reservations": len(self.reservations),
                    "accounting": "logical_admission_and_sampled_worker_monitor",
                    "cleanup": "explicit_owner_cleanup_required; evidence_is_never_automatically_deleted"}
