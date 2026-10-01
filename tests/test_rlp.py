"""Strict canonical RLP codec tests."""

import unittest

from app.rlp import RLPError, decode, encode


class RLPRoundTrip(unittest.TestCase):
    def test_scalar_and_strings(self):
        for value in [b"", b"a", b"abc", b"dog", b"0" * 55, b"x" * 56,
                      b"y" * 1024]:
            with self.subTest(value=value[:8]):
                self.assertEqual(decode(encode(value)), value)

    def test_nested_lists(self):
        item = [[b"do", b"g"], [b"cat", [b"x", b"y"]], b"end"]
        self.assertEqual(decode(encode(item)), item)

    def test_empty(self):
        self.assertEqual(decode(encode(b"")), b"")
        self.assertEqual(decode(encode([])), [])


class RLPNonCanonicalRejections(unittest.TestCase):
    def reject(self, raw: bytes, needle: str = ""):
        with self.assertRaises(RLPError):
            decode(raw)

    def test_single_byte_padded(self):
        self.reject(bytes.fromhex("8101"))   # 0x01 as a length-1 string
        self.reject(bytes.fromhex("817f"))   # 0x7f as a length-1 string

    def test_short_string_with_leading_zero(self):
        # 0xb801 + x: long-form header declaring 1 byte (must be 0x81 x)
        self.reject(bytes([0xb8, 0x01, ord("x")]))

    def test_length_of_length_leading_zero(self):
        # 0xb9 0x00 0x38 + 56 bytes -> should use 0xb8 0x38 short form
        self.reject(bytes([0xb9, 0x00, 0x38]) + b"a" * 56)

    def test_length_of_length_leading_zero_list(self):
        self.reject(bytes([0xf9, 0x00, 0x38]) + b"c" * 56)

    def test_truncated_string(self):
        self.reject(bytes.fromhex("8201"))          # declares 2, gives 1
        self.reject(bytes([0xb8, 0x20]) + b"a" * 3)  # declares 32, gives 3

    def test_truncated_list(self):
        self.reject(bytes.fromhex("c3"))            # declares 3, gives 0
        self.reject(bytes.fromhex("c280"))          # declares 2, gives 1

    def test_trailing_bytes(self):
        with self.assertRaises(RLPError):
            decode(encode(b"a") + encode(b"b"))

    def test_empty_input(self):
        with self.assertRaises(RLPError):
            decode(b"")

    def test_canonical_reencode_identity(self):
        # Every accepted item re-encodes to exactly what was supplied.
        canonical = [
            b"\x01",
            encode([b"a", b"b"]),
            encode([[b"deep"]]),
            bytes([0xb8, 0x38]) + b"z" * 56,
        ]
        for raw in canonical:
            self.assertEqual(encode(decode(raw)), raw)


if __name__ == "__main__":
    unittest.main()
