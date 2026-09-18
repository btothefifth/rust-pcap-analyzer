from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from typing import Any, BinaryIO, Iterator

class InvalidEvidence(ValueError):
    pass

def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")

def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise InvalidEvidence(f"duplicate JSON member: {key}")
        out[key] = value
    return out

def load_json(data: bytes | str) -> Any:
    def invalid_number(value: str) -> Any:
        raise InvalidEvidence(f"unsupported JSON numeric value: {value}")
    return json.loads(data, object_pairs_hook=no_duplicates, parse_constant=invalid_number,
                      parse_float=invalid_number)

def unsigned(value: Any, bits: int = 64) -> int:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        raise InvalidEvidence("expected canonical decimal string")
    number = int(value)
    if str(number) != value or not 0 <= number < 1 << bits:
        raise InvalidEvidence("noncanonical or out-of-range unsigned number")
    return number

def signed(value: Any, bits: int = 128) -> int:
    if not isinstance(value, str):
        raise InvalidEvidence("expected signed decimal string")
    try:
        number = int(value)
    except (ValueError, TypeError) as error:
        raise InvalidEvidence("invalid signed number") from error
    if str(number) != value or not -(1 << (bits - 1)) <= number < 1 << (bits - 1):
        raise InvalidEvidence("noncanonical or out-of-range signed number")
    return number

def small_int(value: Any, limit: int = (1 << 32) - 1) -> int:
    if type(value) is not int or not 0 <= value <= limit:
        raise InvalidEvidence("invalid bounded integer")
    return value

def time_key(value: str | None) -> str | None:
    return None if value is None else f"{signed(value) + (1 << 127):039d}"

def digest_file(path: Path, block: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as file:
        for data in iter(lambda: file.read(block), b""):
            h.update(data)
    return h.hexdigest()

def digest_hex(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise InvalidEvidence("invalid SHA-256 encoding")
    return bytes.fromhex(value)

def bounded_lines(file: BinaryIO, limit: int) -> Iterator[bytes]:
    if limit < 1:
        raise ValueError("line limit must be positive")
    while True:
        line = file.readline(limit + 1)
        if not line:
            return
        if len(line) > limit or not line.endswith(b"\n"):
            raise InvalidEvidence("oversized or unterminated event line")
        yield line

def publish_new(temp: Path, destination: Path) -> None:
    """No-replace publication. Requires a trusted stable parent and hard links."""
    # Windows rejects fsync on a read-only handle. The temporary file is
    # created by this process, so retain write access while flushing it.
    with temp.open("r+b") as file:
        file.flush()
        os.fsync(file.fileno())
    os.link(temp, destination)
    temp.unlink()
    if os.name == "posix":
        fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
