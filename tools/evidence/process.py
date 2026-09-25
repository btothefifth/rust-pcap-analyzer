"""Bounded-output subprocess runner used only for explicitly selected trusted tools."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import time


def run(argv: list[str], directory: Path, name: str, *, timeout: float = 300,
        max_log_bytes: int = 256 * 1024 * 1024, cwd: Path | None = None) -> dict:
    if timeout <= 0 or max_log_bytes < 1:
        raise ValueError("positive process timeout/output budget required")
    directory.mkdir(parents=True, exist_ok=True)
    outpath, errpath = directory / (name + ".stdout"), directory / (name + ".stderr")
    started = time.monotonic()
    proc = None
    with outpath.open("xb") as out, errpath.open("xb") as err:
        try:
            proc = subprocess.Popen(argv, stdout=out, stderr=err, cwd=cwd, stdin=subprocess.DEVNULL)
            stop = None
            while proc.poll() is None:
                elapsed = time.monotonic() - started
                if elapsed > timeout:
                    stop = "timeout"
                if outpath.stat().st_size + errpath.stat().st_size > max_log_bytes:
                    stop = "output_budget"
                if stop:
                    proc.kill()
                    proc.wait()
                    break
                time.sleep(0.02)
            return dict(command=argv, returncode=proc.returncode, status="FAIL" if stop or proc.returncode else "PASS",
                        reason=stop, elapsed_seconds=round(time.monotonic() - started, 6),
                        stdout=str(outpath), stderr=str(errpath), log_limit_bytes=max_log_bytes)
        except FileNotFoundError as error:
            return dict(command=argv, status="BLOCKED", reason="executable_unavailable", detail=str(error),
                        elapsed_seconds=round(time.monotonic() - started, 6), stdout=str(outpath), stderr=str(errpath))
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
