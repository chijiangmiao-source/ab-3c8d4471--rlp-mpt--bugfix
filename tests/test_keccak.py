"""Keccak-256 test vectors (Ethereum padding variant)."""

import unittest

from app.keccak import keccak256


class KeccakVectors(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_abc(self):
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_short(self):
        self.assertEqual(
            keccak256(b"hello").hex(),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")

    def test_exactly_one_rate(self):
        # Message whose padded form spans two rate blocks.
        self.assertEqual(
            keccak256(b"A" * 136).hex(),
            "cfbaa33d0639debd26f425287642acd461b3064b2bae139ea5919adba46f40f1")

    def test_all_bytes(self):
        self.assertEqual(
            keccak256(bytes(range(256))).hex(),
            "dc924469b334aed2a19fac7252e9961aea41f8d91996366029dbe0884229bf36")


if __name__ == "__main__":
    unittest.main()
