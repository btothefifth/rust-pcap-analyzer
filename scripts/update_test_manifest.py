#!/usr/bin/env python3
"""Explicit development operation; never called automatically by validation."""
import json
import sys
sys.dont_write_bytecode = True
from static_check import ROOT, selectors
path = ROOT / "tests/TEST-MANIFEST.json"
path.write_text(json.dumps({"schema": "pcap-evidence.test-selectors.v1", "selectors": selectors(),
                           "note": "Source inventory, not proof of execution. cfg(unix) tests are conditional."}, indent=2) + "\n")
print(f"wrote {len(selectors())} source selectors")
