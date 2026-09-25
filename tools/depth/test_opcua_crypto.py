import hashlib
import hmac
import struct
import unittest

from tools.depth.opcua_crypto import Context, Keys, TransformError, transform


class OpcUaCryptoBoundaryTests(unittest.TestCase):
    def context(self, *, mode="Sign"):
        return Context(
            source_sha256=hashlib.sha256(b"capture").hexdigest(),
            source_offset=12,
            channel_id=7,
            token_id=9,
            sequence=3,
            direction=1,
            key_reference="test-key-reference",
            mode=mode,
            request_id=11,
        )

    def signed_chunk(self):
        signing = b"s" * 32
        signed = struct.pack("<II", 3, 11) + b"derived-body"
        header = bytearray(b"MSGF" + b"\0\0\0\0")
        header.extend(struct.pack("<II", 7, 9))
        signature = hmac.new(signing, bytes(header) + signed, hashlib.sha256).digest()
        chunk = bytes(header) + signed + signature
        header[4:8] = struct.pack("<I", len(chunk))
        signature = hmac.new(signing, bytes(header) + signed, hashlib.sha256).digest()
        return bytes(header) + signed + signature, signing

    def test_authorization_is_required_before_processing(self):
        chunk, _ = self.signed_chunk()
        with self.assertRaises(TransformError):
            transform(
                chunk,
                self.context(),
                Keys(b"s" * 32, b"e" * 32, b"i" * 16),
            )

    def test_signed_mode_verifies_and_returns_derived_body(self):
        chunk, signing = self.signed_chunk()
        result = transform(
            chunk,
            self.context(),
            Keys(signing, b"e" * 32, b"i" * 16),
            authorized=True,
        )
        self.assertEqual(result.body, b"derived-body")
        self.assertTrue(result.receipt["mac_verified_with_supplied_key"])
        self.assertFalse(result.receipt["endpoint_identity_verified"])
        self.assertEqual(result.receipt["source"]["start"], "12")

    def test_tampering_is_rejected_without_plaintext_output(self):
        chunk, signing = self.signed_chunk()
        tampered = bytearray(chunk)
        tampered[-1] ^= 1
        with self.assertRaises(TransformError):
            transform(
                bytes(tampered),
                self.context(),
                Keys(signing, b"e" * 32, b"i" * 16),
                authorized=True,
            )


if __name__ == "__main__":
    unittest.main()
