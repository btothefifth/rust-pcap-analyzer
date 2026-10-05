"""Bounded-output subprocess runner used only for explicitly selected trusted tools."""
from __future__ import annotations
from pathlib import Path
import time
from scripts.owned_process import run as run_owned


def run(argv: list[str], directory: Path, name: str, *, timeout: float = 300,
        max_log_bytes: int = 256 * 1024 * 1024, cwd: Path | None = None) -> dict:
    if timeout <= 0 or max_log_bytes < 1:
        raise ValueError("positive process timeout/output budget required")
    directory.mkdir(parents=True, exist_ok=True)
    outpath, errpath = directory / (name + ".stdout"), directory / (name + ".stderr")
    started = time.monotonic()
    with outpath.open("xb") as out, errpath.open("xb") as err:
        try:
            result = run_owned(argv, stdout=out, stderr=err, cwd=cwd,
                               timeout=timeout, max_output_bytes=max_log_bytes)
            size = outpath.stat().st_size + errpath.stat().st_size
            reason = result.reason or ("output_budget" if size > max_log_bytes else None)
            return dict(command=argv, returncode=result.returncode, status="FAIL" if reason or result.returncode else "PASS",
                        reason=reason, elapsed_seconds=round(time.monotonic() - started, 6),
                        stdout=str(outpath), stderr=str(errpath), log_limit_bytes=max_log_bytes)
        except FileNotFoundError as error:
            return dict(command=argv, status="BLOCKED", reason="executable_unavailable", detail=str(error),
                        elapsed_seconds=round(time.monotonic() - started, 6), stdout=str(outpath), stderr=str(errpath))
