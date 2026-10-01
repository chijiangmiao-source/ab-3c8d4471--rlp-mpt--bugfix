"""Ethereum hex-prefix (HP / compact) encoding of trie nibble paths."""

from __future__ import annotations


class HPError(ValueError):
    """Raised on malformed hex-prefix data."""


def encode(nibbles: list[int], terminator: bool) -> bytes:
    if any(not 0 <= n <= 0xF for n in nibbles):
        raise HPError("nibble out of range")
    flag = 2 if terminator else 0
    if len(nibbles) % 2:
        return bytes([(flag + 1) * 16 + nibbles[0]]) + bytes(
            _pair(nibbles[1:]))
    return bytes([flag * 16]) + bytes(_pair(nibbles))


def _pair(nibbles: list[int]) -> list[int]:
    return [nibbles[i] * 16 + nibbles[i + 1] for i in range(0, len(nibbles), 2)]


def decode(data: bytes) -> tuple[list[int], bool]:
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise HPError("hex-prefix payload must be a non-empty byte string")
    head = data[0] >> 4
    if head > 3:
        raise HPError("invalid hex-prefix flag")
    terminator = head >= 2

    nibbles: list[int] = []
    body = data
    if head in (0, 2):
        # Even form: low nibble of the first byte is required to be zero.
        if data[0] & 0x0F:
            raise HPError("non-canonical even hex-prefix encoding")
        body = data[1:]
    else:
        nibbles.append(data[0] & 0x0F)
        body = data[1:]

    for byte in body:
        nibbles.append(byte >> 4)
        nibbles.append(byte & 0x0F)
    return nibbles, terminator


def nibbles_from_key(key: bytes) -> list[int]:
    out: list[int] = []
    for byte in key:
        out.append(byte >> 4)
        out.append(byte & 0x0F)
    return out
