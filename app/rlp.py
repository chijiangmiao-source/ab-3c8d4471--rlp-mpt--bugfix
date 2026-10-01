"""Canonical Recursive Length Prefix (RLP) encoding/decoding.

The decoder is deliberately strict: it rejects truncated input, trailing
bytes, non-canonical length prefixes and non-canonical integer bytes
(leading zero bytes and 0x00 encoded as more than one byte).
"""

from __future__ import annotations

from typing import Iterable, Union

RLPItem = Union[bytes, list]


class RLPError(ValueError):
    """Raised on any malformed or non-canonical RLP input."""


def encode(item: RLPItem) -> bytes:
    if isinstance(item, bytes):
        return _encode_bytes(item)
    if isinstance(item, (bytearray,)):
        return _encode_bytes(bytes(item))
    if isinstance(item, Iterable):
        body = b"".join(encode(child) for child in item)
        return _encode_with_base(0xC0, len(body)) + body
    raise TypeError(f"cannot RLP-encode {type(item)!r}")


def _encode_bytes(data: bytes) -> bytes:
    if len(data) == 1 and data[0] < 0x80:
        return data
    return _encode_with_base(0x80, len(data)) + data


def _encode_with_base(base: int, length: int) -> bytes:
    if length < 56:
        return bytes((base + length,))
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((base + 55 + len(length_bytes),)) + length_bytes


def decode(data: bytes) -> RLPItem:
    item, consumed = _decode_at(memoryview(data), 0)
    if consumed != len(data):
        raise RLPError("trailing bytes after RLP item")
    return item


def decode_raw(data: bytes) -> tuple[RLPItem, int]:
    """Decode one item, returning it and the number of bytes consumed."""
    view = memoryview(data)
    item, consumed = _decode_at(view, 0)
    return item, consumed


def _decode_at(view: memoryview, start: int) -> tuple[RLPItem, int]:
    if start >= len(view):
        raise RLPError("truncated RLP item")
    prefix = view[start]

    if prefix < 0x80:
        return bytes((prefix,)), start + 1

    if prefix < 0xB8:
        length = prefix - 0x80
        begin = start + 1
        end = begin + length
        if end > len(view):
            raise RLPError("truncated RLP string")
        payload = bytes(view[begin:end])
        # Single-byte values < 0x80 must be encoded as themselves.
        if length == 1 and payload[0] < 0x80:
            raise RLPError("non-canonical RLP string")
        return payload, end

    if prefix < 0xC0:
        return _decode_long_string(view, start, prefix - 0xB7)

    if prefix < 0xF8:
        length = prefix - 0xC0
        return _decode_list(view, start + 1, length)

    return _decode_long_list(view, start, prefix - 0xF7)


def _decode_long_string(view: memoryview, start: int, size: int) -> tuple[bytes, int]:
    begin_len = start + 1
    if begin_len + size > len(view):
        raise RLPError("truncated RLP length-of-length")
    length = _read_canonical_length(view, begin_len, size)
    if length < 56:
        raise RLPError("non-canonical RLP length prefix (should be short form)")
    begin = begin_len + size
    end = begin + length
    if end > len(view):
        raise RLPError("truncated RLP string")
    return bytes(view[begin:end]), end


def _decode_long_list(view: memoryview, start: int, size: int) -> tuple[list, int]:
    begin_len = start + 1
    if begin_len + size > len(view):
        raise RLPError("truncated RLP length-of-length")
    length = _read_canonical_length(view, begin_len, size)
    if length < 56:
        raise RLPError("non-canonical RLP length prefix (should be short form)")
    return _decode_list(view, begin_len + size, length)


def _read_canonical_length(view: memoryview, at: int, size: int) -> int:
    if size == 0:
        raise RLPError("invalid RLP length size 0")
    if view[at] == 0:
        raise RLPError("non-canonical RLP length (leading zero)")
    value = 0
    for i in range(size):
        value = (value << 8) | view[at + i]
    return value


def _decode_list(view: memoryview, begin: int, length: int) -> tuple[list, int]:
    end = begin + length
    if end > len(view):
        raise RLPError("truncated RLP list")
    items: list[RLPItem] = []
    pos = begin
    while pos < end:
        child, pos = _decode_at(view, pos)
        items.append(child)
    if pos != end:
        raise RLPError("truncated RLP list content")
    return items, end
