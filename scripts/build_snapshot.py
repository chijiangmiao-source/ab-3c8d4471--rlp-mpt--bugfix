"""Generate the deterministic offline authorization snapshot fixtures.

Produces data/snapshot.json containing:
  * a Merkle Patricia trie root committing a set of command ids to
    authorization flags (01 = enabled, other values exist but are not
    enabled);
  * valid root-to-leaf proofs for sample commands;
  * a standard short-embedded-node proof: a branch root whose nibble slot
    references the leaf by the leaf's full RLP byte string (length < 32),
    so the proof contains only the root node;
  * a tampered-child proof where one hash-referenced node is replaced so
    the parent/child reference mismatch must be detected;
  * a non-canonical RLP proof (single byte encoded as 0x8101) committed by
    a claimed root, which must be rejected at the first failing layer.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import hp as hexprefix  # noqa: E402
from app.keccak import keccak256  # noqa: E402
from app.rlp import decode, encode  # noqa: E402
from app.trie import MemoryTrie  # noqa: E402

# Fixed command directory: id -> authorization flag.
COMMANDS = {
    "0x417274696c6c65725f4c41554e43485f30303031": True,   # ARTILLER_LAUNCH_0001
    "0x417274696c6c65725f4c41554e43485f30303032": True,
    "0x5245434f4e5f4c41554e43485f30303031": False,         # RECON_LAUNCH_0001
    "0x5245434f4e5f4c41554e43485f30303032": False,
    "0x53515541445f4c4f4f505f30303031": True,             # SQUAD_LOOP_0001
    "0x44524f4e455f535452494b455f30303039": False,        # DRONE_STRIKE_0009
    "0x45564143554154494f4e5f4f524445525f303037": False,  # EVACUATION_ORDER_007
    "0x535550504c595f44524f505f30303034": True,           # SUPPLY_DROP_0004
}


def _proof_hex(trie: MemoryTrie, key: bytes) -> list[str]:
    return ["0x" + raw.hex() for raw in trie.get_proof(key)]


def build_snapshot() -> dict:
    trie = MemoryTrie()
    for key_hex, enabled in COMMANDS.items():
        trie.put(bytes.fromhex(key_hex[2:]), b"\x01" if enabled else b"\x00")

    enabled_key = "0x417274696c6c65725f4c41554e43485f30303031"
    disabled_key = "0x5245434f4e5f4c41554e43485f30303031"

    fixtures = []
    for key_hex, enabled in COMMANDS.items():
        key = bytes.fromhex(key_hex[2:])
        fixtures.append({
            "name": ("enabled" if enabled else "disabled") + "_" +
                    key_hex[2:10],
            "command_id": key_hex,
            "root_hash": "0x" + trie.root_hash.hex(),
            "proof": _proof_hex(trie, key),
            "expect": "AUTHORIZED" if enabled else "UNAUTHORIZED",
        })

    # --- Standard short embedded node (instruction 0x12).  The root is a
    # branch whose nibble-1 slot holds the *full RLP byte string* of the
    # short leaf (RLP < 32 bytes), so the proof provides only the root. -
    embedded_key = "0x12"
    embedded_leaf_raw = encode(
        [hexprefix.encode([2], True), b"\x01"])
    if len(embedded_leaf_raw) >= 32:
        raise RuntimeError("无法构造短内嵌夹具：叶节点 RLP 必须短于 32 字节")
    embedded_branch = [b""] * 17
    embedded_branch[1] = embedded_leaf_raw
    embedded_root_raw = encode(embedded_branch)
    embedded_case = {
        "name": "short_embedded_leaf",
        "command_id": embedded_key,
        "root_hash": "0x" + keccak256(embedded_root_raw).hex(),
        "proof": ["0x" + embedded_root_raw.hex()],
        "expect": "AUTHORIZED",
    }

    # --- Tampered child: parent stays valid, the hashed child is replaced
    # with a *different, still valid* committed node, so its hash mismatches
    # the reference stored in the parent at the first failing layer. -----
    en_key = bytes.fromhex(enabled_key[2:])
    good = trie.get_proof(en_key)
    all_node_raws = [raw for raw in trie.db.values()]
    tampered = list(good)
    replaced = False
    for i in range(1, len(tampered)):
        candidate = next(
            (raw for raw in all_node_raws
             if raw != tampered[i] and len(raw) >= 32
             and keccak256(raw) != keccak256(tampered[i])),
            None)
        if candidate is not None:
            tampered[i] = candidate
            replaced = True
            break
    if not replaced:
        raise RuntimeError("无法构造篡改夹具：缺少可替换的已提交节点")
    tampered_case = {
        "name": "tampered_child_reference",
        "command_id": enabled_key,
        "root_hash": "0x" + trie.root_hash.hex(),
        "proof": ["0x" + raw.hex() for raw in tampered],
        "expect": "INVALID",
    }

    # --- Non-canonical RLP committed by the claimed root (0x8101). ---
    malformed = bytes.fromhex("8101")
    noncanon_case = {
        "name": "noncanonical_rlp",
        "command_id": "0x01",
        "root_hash": "0x" + keccak256(malformed).hex(),
        "proof": ["0x" + malformed.hex()],
        "expect": "INVALID",
    }

    # --- Truncated proof (last hashed node removed). -----------------------
    truncated_case = {
        "name": "truncated_path",
        "command_id": disabled_key,
        "root_hash": "0x" + trie.root_hash.hex(),
        "proof": _proof_hex(trie, bytes.fromhex(disabled_key[2:]))[:-1],
        "expect": "INVALID",
    }

    return {
        "trie_root": "0x" + trie.root_hash.hex(),
        "description": "离线指令授权快照（MPT 承诺：叶值 01 表示启用；支持标准短内嵌节点）",
        "fixtures": fixtures + [embedded_case, tampered_case,
                                noncanon_case, truncated_case],
    }


def main() -> None:
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "snapshot.json")
    snapshot = build_snapshot()
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, ensure_ascii=False, indent=2)
    print(f"wrote {out}")
    print(f"root = {snapshot['trie_root']}")
    print(f"fixtures = {len(snapshot['fixtures'])}")


if __name__ == "__main__":
    main()
