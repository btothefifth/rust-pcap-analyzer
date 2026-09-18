#!/usr/bin/env python3
"""Structural preflight only. This is explicitly NOT a Rust compiler/type checker."""
from __future__ import annotations
import ast
import json
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def selectors() -> list[str]:
    result = []
    for file in sorted((ROOT / "tests").glob("*.rs")):
        for name in re.findall(r"#\[test\]\s*fn\s+(\w+)", file.read_text()):
            result.append(f"{file.stem}::{name}")
    return result


def check() -> dict:
    rust = sorted((ROOT / "src").glob("*.rs")) + sorted((ROOT / "tests").rglob("*.rs")) + sorted((ROOT / "examples").glob("*.rs"))
    declared = re.findall(r"pub mod (\w+);", (ROOT / "src/lib.rs").read_text())
    for name in declared:
        assert (ROOT / "src" / f"{name}.rs").is_file(), name
    for file in rust:
        text = file.read_text()
        assert b"\r" not in file.read_bytes(), f"unexpected CRLF/mixed newline: {file}"
        assert not re.search(r"\b(todo!|unimplemented!)\s*\(", text), file
        if file.parent.name == "src":
            assert not re.search(r"\bunsafe\s*\{", text), file
    for file in (ROOT / "scripts").glob("*.py"):
        ast.parse(file.read_text(), filename=str(file))
    for file in (ROOT / "tests").glob("*.rs"):
        for name in re.findall(r'fixture\("([^"]+)"\)', file.read_text()):
            assert (ROOT / "tests/fixtures" / name).is_file(), (file, name)
    expected = json.loads((ROOT / "tests/TEST-MANIFEST.json").read_text())["selectors"]
    actual = selectors()
    assert actual == expected, "test selector drift; explicitly update the manifest after reviewing the changed tests"
    lexical = "NOT_RUN_PYGMENTS_NOT_INSTALLED"
    try:
        from pygments.lexers import RustLexer
        from pygments.token import Token
        import pygments
    except ImportError:
        pass
    else:
        for file in rust:
            stack = []
            for token, value in RustLexer().get_tokens(file.read_text()):
                if token in Token.Punctuation:
                    for c in value:
                        if c in "([{":
                            stack.append(c)
                        elif c in ")]}":
                            assert stack and stack.pop() == {")": "(", "]": "[", "}": "{"}[c], (file, c)
            assert not stack, (file, stack)
        lexical = f"delimiter balance passed with Pygments {pygments.__version__}; not syntax/type checking"
    return {"status": "PASSED_STRUCTURAL_PREFLIGHT_ONLY", "rust_files_inspected": len(rust), "source_test_selectors": len(actual),
            "module_paths_resolved": len(declared), "lexical_check": lexical, "native_rust_executed": False}

if __name__ == "__main__":
    print(json.dumps(check(), indent=2, sort_keys=True))
