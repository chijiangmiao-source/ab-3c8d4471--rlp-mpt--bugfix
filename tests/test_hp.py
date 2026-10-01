"""Hex-prefix compact path tests."""

import unittest

from app import hp


class HPRoundTrip(unittest.TestCase):
    def test_examples(self):
        cases = [
            ([], False),
            ([0], False),
            ([1, 2, 3, 4, 5], True),
            ([0, 1, 2, 3, 4, 5], False),
            ([0xf, 0, 0, 0xf], True),
        ]
        for nibbles, term in cases:
            data = hp.encode(nibbles, term)
            got_nibbles, got_term = hp.decode(data)
            self.assertEqual(got_nibbles, nibbles)
            self.assertEqual(got_term, term)

    def test_known_encodings(self):
        # Odd, terminator: high nibble 3
        self.assertEqual(hp.encode([1, 2, 3], True), bytes.fromhex("3123"))
        # Even, no terminator: high nibble 0, padding nibble zero
        self.assertEqual(hp.encode([1, 2], False), bytes.fromhex("0012"))
        # Odd, no terminator: high nibble 1
        self.assertEqual(hp.encode([1, 2, 3], False), bytes.fromhex("1123"))
        # Even, terminator: high nibble 2
        self.assertEqual(hp.encode([1, 2], True), bytes.fromhex("2012"))


class HPRejections(unittest.TestCase):
    def test_empty(self):
        with self.assertRaises(hp.HPError):
            hp.decode(b"")

    def test_bad_flag_nibble(self):
        for head in range(4, 8):
            with self.assertRaises(hp.HPError):
                hp.decode(bytes([head << 4]))

    def test_even_form_nonzero_padding_nibble(self):
        # 0x1? would be odd form; even form with low nibble set is invalid
        with self.assertRaises(hp.HPError):
            hp.decode(bytes.fromhex("01"))
        with self.assertRaises(hp.HPError):
            hp.decode(bytes.fromhex("23"))


if __name__ == "__main__":
    unittest.main()
