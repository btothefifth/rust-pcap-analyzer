"""Explicit authorized OPC UA symmetric transform, outside the parser trust root.

Supports Basic256Sha256 MSG/CLO Sign and SignAndEncrypt with already-derived,
caller-scoped symmetric keys. No key discovery, guessing, capture-secret parsing,
certificate trust, asymmetric OPN decryption, or endpoint-authentication claim.

The optional cryptography package is imported ONLY after explicit authorization
and only for AES. It is not a dependency of any shipped Rust parser workspace.
The independently implemented framing/MAC/padding rules are tested separately.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import hmac
import struct

POLICY = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
MAX_CHUNK = 4 * 1024 * 1024

class TransformError(ValueError):
    """Intentionally contains no plaintext, key material, or private paths."""

@dataclass(frozen=True)
class Context:
    source_sha256: str
    source_offset: int
    channel_id: int
    token_id: int
    sequence: int
    direction: int
    key_reference: str
    mode: str = "SignAndEncrypt"
    policy: str = POLICY
    request_id: int | None = None

@dataclass(frozen=True, repr=False)
class Keys:
    signing: bytes = field(repr=False)
    encryption: bytes = field(repr=False)
    iv: bytes = field(repr=False)

@dataclass(frozen=True, repr=False)
class Derived:
    body: bytes = field(repr=False)
    receipt: dict


def transform(chunk: bytes, context: Context, keys: Keys, *, authorized: bool = False) -> Derived:
    if authorized is not True:
        raise TransformError("explicit decryption authorization required")
    if context.policy != POLICY or context.mode not in {"Sign", "SignAndEncrypt"}:
        raise TransformError("unsupported explicit security policy/mode")
    if (not isinstance(chunk, bytes) or not 56 <= len(chunk) <= MAX_CHUNK
            or len(context.source_sha256) != 64
            or any(c not in "0123456789abcdef" for c in context.source_sha256)
            or type(context.source_offset) is not int or not 0 <= context.source_offset < 2**64
            or context.source_offset + len(chunk) >= 2**64
            or context.direction not in (0, 1)
            or not context.key_reference or len(context.key_reference) > 128
            or any(ord(c) < 32 for c in context.key_reference)
            or any(type(n) is not int or not 0 <= n < 2**32 for n in
                   (context.channel_id, context.token_id, context.sequence))
            or context.request_id is not None and not 0 <= context.request_id < 2**32):
        raise TransformError("invalid bounded transform context")
    if any(not isinstance(x, bytes) for x in (keys.signing, keys.encryption, keys.iv)):
        raise TransformError("key material must be explicit immutable bytes")
    if len(keys.signing) != 32 or len(keys.encryption) != 32 or len(keys.iv) != 16:
        raise TransformError("key dimensions do not match policy")
    kind, flag = chunk[:3], chunk[3:4]
    size, channel, token = struct.unpack_from("<III", chunk, 4)
    if (kind not in (b"MSG", b"CLO") or flag not in (b"C", b"F", b"A")
            or kind == b"CLO" and flag != b"F" or size != len(chunk)
            or channel != context.channel_id or token != context.token_id):
        raise TransformError("chunk does not match authorized channel/token scope")
    if context.mode == "SignAndEncrypt":
        encrypted = chunk[16:]
        if len(encrypted) % 16:
            raise TransformError("invalid protected message")
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError as exc:
            raise TransformError("explicit AES provider is unavailable; no fallback") from exc
        decryptor = Cipher(algorithms.AES(keys.encryption), modes.CBC(keys.iv)).decryptor()
        plain = decryptor.update(encrypted) + decryptor.finalize()
    else:
        plain = chunk[16:]
    if len(plain) < 40:
        raise TransformError("invalid protected message")
    signed, signature = plain[:-32], plain[-32:]
    expected = hmac.new(keys.signing, chunk[:16] + signed, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise TransformError("invalid protected message")
    # Padding is examined only after MAC verification; never emit unauthenticated bytes.
    if context.mode == "SignAndEncrypt":
        padding = signed[-1]
        length = padding + 1  # includes the PaddingSize byte
        if length > len(signed) - 8 or signed[-length:] != bytes([padding]) * length:
            raise TransformError("invalid protected message")
        payload = signed[:-length]
    else:
        payload = signed
    if len(payload) < 8:
        raise TransformError("invalid protected message")
    sequence, request = struct.unpack_from("<II", payload)
    if sequence != context.sequence or context.request_id is not None and request != context.request_id:
        raise TransformError("protected sequence/request outside authorized scope")
    body = payload[8:]
    receipt = {
        "schema": "pcap-evidence.authorized-transform.v1",
        "transform": "opcua-basic256sha256-symmetric",
        "source": {"sha256": context.source_sha256, "start": str(context.source_offset),
                   "end": str(context.source_offset + len(chunk)),
                   "chunk_sha256": hashlib.sha256(chunk).hexdigest()},
        "derived": {"sha256": hashlib.sha256(body).hexdigest(), "bytes": str(len(body)),
                    "domain": "derived_plaintext_not_captured_byte_spans"},
        "policy": context.policy, "mode": context.mode, "channel": str(channel),
        "token": str(token), "sequence": str(sequence), "request": str(request),
        "direction": context.direction, "key_reference": context.key_reference,
        "chunk_flag": flag.decode("ascii"), "mac_verified_with_supplied_key": True,
        "certificate_trust_verified": False, "endpoint_identity_verified": False,
        "source_capture_independently_verified": False, "keys_exported": False,
        "provider_boundary": "explicit_optional_crypto_not_parser_semantics",
    }
    return Derived(body=body, receipt=receipt)
