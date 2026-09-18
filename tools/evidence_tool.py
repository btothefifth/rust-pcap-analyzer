#!/usr/bin/env python3
"""Offline evidence tooling. No network access occurs except explicit corpus fetch."""
from __future__ import annotations
import sys
import sqlite3
import subprocess
from evidence.common import InvalidEvidence

def main() -> int:
    if len(sys.argv) < 2:
        print("usage: evidence_tool.py index|oracle|corpus|differential|minimize|qualify|benchmark ...", file=sys.stderr)
        return 2
    command, args = sys.argv[1], sys.argv[2:]
    if command == "index":
        from evidence.index import main as run
    elif command == "oracle":
        from evidence.oracles import main as run
    elif command == "corpus":
        from evidence.corpus import main as run
    elif command == "differential":
        from evidence.differential import main as run
    elif command == "minimize":
        from evidence.minimize import main as run
    elif command == "qualify":
        from evidence.qualify import main as run
    elif command == "benchmark":
        from evidence.benchmark import main as run
    else:
        print(f"unknown tool: {command}", file=sys.stderr)
        return 2
    try:
        return run(args)
    except (InvalidEvidence, ValueError, OSError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
