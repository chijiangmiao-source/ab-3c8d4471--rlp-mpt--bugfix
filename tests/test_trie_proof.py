"""MPT proof verification tests: valid proofs and every failure class."""

import json
import os
import unittest

from app.keccak import keccak256
from app.hp import encode as hp_encode
from app.rlp import decode, encode
from app.trie import (AUTHORIZED, INVALID, UNAUTHORIZED, EMPTY_ROOT,
                      MemoryTrie, verify_proof)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_trie() -> tuple[MemoryTrie, list[tuple[bytes, bytes]]]:
    trie = MemoryTrie()
    pairs = [
        (bytes.fromhex("00"), b"\x00"),
        (bytes.fromhex("01"), b"\x01"),
        (bytes.fromhex("12"), b"\x00"),
        (bytes.fromhex("1234"), b"\x01"),
        (bytes.fromhex("1235"), b"\x00"),
        (bytes.fromhex("12ff"), b"\x00"),
        (bytes.fromhex("abcd"), b"\x01"),
        (bytes.fromhex("deadbeef"), b"\x00"),
        (bytes.fromhex("abcdef01"), b"\x00"),
    ]
    for key, value in pairs:
        trie.put(key, value)
    return trie, pairs


class EmptyAndSimpleTrie(unittest.TestCase):
    def test_empty_root_constant(self):
        self.assertEqual(
            EMPTY_ROOT.hex(),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

    def test_single_leaf_authorized(self):
        trie = MemoryTrie()
        key = bytes.fromhex("1234")
        trie.put(key, b"\x01")
        result = verify_proof(trie.root_hash, key, trie.get_proof(key))
        self.assertEqual(result.status, AUTHORIZED)
        self.assertTrue(result.authorized)
        self.assertEqual(result.leaf_value_hex, "0x01")
        self.assertTrue(any(layer.node_kind == "leaf" for layer in result.layers))

    def test_single_leaf_unauthorized(self):
        trie = MemoryTrie()
        key = b"\xaa"
        trie.put(key, b"\x00")
        result = verify_proof(trie.root_hash, key, trie.get_proof(key))
        self.assertEqual(result.status, UNAUTHORIZED)
        self.assertFalse(result.authorized)
        self.assertEqual(result.leaf_value_hex, "0x00")

    def test_nonzero_nonone_value_is_unauthorized(self):
        trie = MemoryTrie()
        trie.put(b"\x01\x02", b"\x02")
        result = verify_proof(trie.root_hash, b"\x01\x02", trie.get_proof(b"\x01\x02"))
        self.assertEqual(result.status, UNAUTHORIZED)
        self.assertEqual(result.leaf_value_hex, "0x02")


class BranchValueSlot(unittest.TestCase):
    def test_prefix_keys(self):
        trie = MemoryTrie()
        trie.put(bytes.fromhex("ab"), b"\x00")
        trie.put(bytes.fromhex("abcd"), b"\x01")
        short = verify_proof(trie.root_hash, bytes.fromhex("ab"),
                             trie.get_proof(bytes.fromhex("ab")))
        long = verify_proof(trie.root_hash, bytes.fromhex("abcd"),
                            trie.get_proof(bytes.fromhex("abcd")))
        self.assertEqual(short.status, UNAUTHORIZED)
        self.assertEqual(long.status, AUTHORIZED)
        self.assertTrue(
            any(layer.note and "叶值 = 0x00" in layer.note
                for layer in short.layers))


class TraceContents(unittest.TestCase):
    def test_root_to_leaf_trace(self):
        trie, _ = build_trie()
        key = bytes.fromhex("1234")
        result = verify_proof(trie.root_hash, key, trie.get_proof(key))
        self.assertEqual(result.status, AUTHORIZED)
        # Consecutive layer numbering.
        layers = result.layers
        self.assertEqual([l.layer for l in layers], list(range(len(layers))))
        # Root reference at layer zero, hash/embedded afterwards.
        self.assertEqual(layers[0].ref_kind, "root")
        for layer in layers[1:]:
            self.assertIn(layer.ref_kind, ("hash", "embedded"))
        # Every layer carries a 32-byte node summary and consumed nibbles
        # accumulate to the full key path.
        for layer in layers:
            self.assertEqual(len(layer.actual_hash), 2 + 64)
        self.assertEqual(layers[-1].cumulative_path, "0x1234")
        self.assertEqual(layers[-1].node_kind, "leaf")
        # Embedded nodes and hash references both appear in this fixture.
        kinds = {layer.ref_kind for layer in layers[1:]}
        self.assertIn("embedded", kinds)
        self.assertTrue(any(layer.next_ref_kind == "hash" for layer in layers))

    def test_embedded_note_present(self):
        trie, _ = build_trie()
        result = verify_proof(trie.root_hash, bytes.fromhex("1234"),
                              trie.get_proof(bytes.fromhex("1234")))
        embedded = [l for l in result.layers if l.ref_kind == "embedded"]
        self.assertTrue(embedded)
        for layer in embedded:
            self.assertIn("内嵌", layer.note)


class ValidProofsAcrossFixture(unittest.TestCase):
    def test_all_keys(self):
        trie, pairs = build_trie()
        for key, value in pairs:
            with self.subTest(key=key.hex()):
                result = verify_proof(trie.root_hash, key, trie.get_proof(key))
                expected = AUTHORIZED if value == b"\x01" else UNAUTHORIZED
                self.assertEqual(result.status, expected)
                self.assertIsNone(result.failure_layer)
                self.assertEqual(
                    result.leaf_value_hex, "0x" + value.hex())

    def test_accepts_decoded_node_lists(self):
        trie, pairs = build_trie()
        key = bytes.fromhex("abcd")
        proof = trie.get_proof(key)
        decoded = [decode(raw) for raw in proof]
        result = verify_proof(trie.root_hash, key, decoded)
        self.assertEqual(result.status, AUTHORIZED)


class ShortInlineEmbeddedNode(unittest.TestCase):
    """Canonical short-byte-string inline references (RLP < 32 bytes)."""

    def _short_inline_proof(self, value=b"\x01"):
        # Command id 0x12 -> nibbles [1,2]; the root branch consumes nibble 1
        # and embeds, as a short byte string carrying the leaf's *full RLP*,
        # the leaf covering remaining nibble [2]. Only the root is supplied.
        leaf_raw = encode([hp_encode([2], True), value])
        assert len(leaf_raw) < 32
        branch = [b""] * 17
        branch[1] = leaf_raw
        root_raw = encode(branch)
        return keccak256(root_raw), bytes.fromhex("12"), [root_raw], leaf_raw

    def test_command_0x12_short_inline_leaf_authorized(self):
        root, key, proof, leaf_raw = self._short_inline_proof()
        result = verify_proof(root, key, proof)
        self.assertEqual(result.status, AUTHORIZED)
        self.assertTrue(result.authorized)
        self.assertEqual(result.leaf_value_hex, "0x01")
        self.assertIsNone(result.failure_reason)

    def test_two_layer_replay_evidence(self):
        root, key, proof, leaf_raw = self._short_inline_proof()
        result = verify_proof(root, key, proof)
        self.assertEqual(len(result.layers), 2)
        root_layer, leaf_layer = result.layers
        # Layer 0: the root branch committed by the 32-byte root hash.
        self.assertEqual(root_layer.layer, 0)
        self.assertEqual(root_layer.node_kind, "branch")
        self.assertEqual(root_layer.ref_kind, "root")
        self.assertEqual(root_layer.actual_hash, "0x" + root.hex())
        self.assertEqual(root_layer.consumed_nibbles, "1")
        self.assertEqual(root_layer.cumulative_path, "0x")
        self.assertEqual(root_layer.next_ref_kind, "embedded")
        self.assertEqual(root_layer.raw_rlp_hex, "0x" + proof[0].hex())
        # Layer 1: the inline leaf carried by the parent as a short string.
        self.assertEqual(leaf_layer.layer, 1)
        self.assertEqual(leaf_layer.node_kind, "leaf")
        self.assertEqual(leaf_layer.ref_kind, "embedded")
        self.assertEqual(leaf_layer.actual_hash,
                         "0x" + keccak256(leaf_raw).hex())
        self.assertEqual(leaf_layer.raw_rlp_hex, "0x" + leaf_raw.hex())
        self.assertEqual(leaf_layer.consumed_nibbles, "0x2")
        self.assertEqual(leaf_layer.cumulative_path, "0x12")
        self.assertIn("内嵌", leaf_layer.note)
        self.assertIn("叶值 = 0x01", leaf_layer.note)

    def test_nested_list_form_still_accepted(self):
        # Same trie, but the embedded child is a nested RLP list (the form
        # produced when tooling decodes proof nodes before verification).
        leaf_raw = encode([hp_encode([2], True), b"\x01"])
        branch = [b""] * 17
        branch[1] = decode(leaf_raw)
        root_raw = encode(branch)
        result = verify_proof(keccak256(root_raw), bytes.fromhex("12"),
                              [root_raw])
        self.assertEqual(result.status, AUTHORIZED)
        self.assertEqual(result.leaf_value_hex, "0x01")
        self.assertEqual(len(result.layers), 2)

    def test_32_byte_hash_reference_still_followed(self):
        # Regression: a child whose RLP reaches 32 bytes is referenced by
        # hash and the next standalone proof entry is consumed.
        trie, _ = build_trie()
        key = bytes.fromhex("1234")
        result = verify_proof(trie.root_hash, key, trie.get_proof(key))
        self.assertEqual(result.status, AUTHORIZED)
        self.assertEqual(result.leaf_value_hex, "0x01")
        self.assertTrue(
            any(layer.ref_kind == "hash" for layer in result.layers))

    def test_embedded_node_separately_provided_still_consumed(self):
        # Compatibility case: an inline node shipped as its own proof entry
        # is consumed (not reported as an unconsumed tail node).
        root, key, proof, leaf_raw = self._short_inline_proof()
        result = verify_proof(root, key, proof + [leaf_raw])
        self.assertEqual(result.status, AUTHORIZED)
        self.assertEqual(result.leaf_value_hex, "0x01")
        leaf_layer = result.layers[1]
        self.assertIn("证明中单独提供", leaf_layer.note)

    def test_duplicate_embedded_node_rejected(self):
        root, key, proof, leaf_raw = self._short_inline_proof()
        result = verify_proof(root, key, proof + [leaf_raw, leaf_raw])
        self.assertEqual(result.status, INVALID)
        self.assertIn("尾节点", result.failure_reason)

    def test_invalid_short_reference_rejected_as_invalid_not_crash(self):
        # A <32-byte child string that is not a valid node list must be an
        # INVALID verdict, never an uncaught exception (exit-code-1 crash).
        branch = [b""] * 17
        branch[1] = b"\x01"                    # bare byte, not an RLP list
        root_raw = encode(branch)
        result = verify_proof(keccak256(root_raw), bytes.fromhex("12"),
                              [root_raw])
        self.assertEqual(result.status, INVALID)
        self.assertEqual(result.failure_layer, 0)
        self.assertIn("内嵌", result.failure_reason)
        self.assertIsNone(result.leaf_value_hex)
        self.assertFalse(result.authorized)

    def test_non_list_truncated_short_reference_rejected(self):
        branch = [b""] * 17
        branch[1] = bytes.fromhex("c380")      # truncated RLP list
        root_raw = encode(branch)
        result = verify_proof(keccak256(root_raw), bytes.fromhex("12"),
                              [root_raw])
        self.assertEqual(result.status, INVALID)
        self.assertIn("内嵌", result.failure_reason)

    def test_wrong_value_in_inline_leaf_is_unauthorized_not_invalid(self):
        root, key, proof, _ = self._short_inline_proof(value=b"\x00")
        result = verify_proof(root, key, proof)
        self.assertEqual(result.status, UNAUTHORIZED)
        self.assertFalse(result.authorized)
        self.assertEqual(result.leaf_value_hex, "0x00")

    def test_extension_inline_short_string(self):
        # Extension node embedding its branch child via a short byte string.
        leaf_a_raw = encode([hp_encode([0], True), b"\x01"])
        leaf_b_raw = encode([hp_encode([0], True), b"\x00"])
        inner_branch = [b""] * 17
        inner_branch[3] = leaf_a_raw
        inner_branch[4] = leaf_b_raw
        inner_raw = encode(inner_branch)
        assert len(inner_raw) < 32
        ext = [hp_encode([1, 2], False), inner_raw]
        root_raw = encode(ext)
        # key 0x1230 nibbles [1,2,3,0]: extension [1,2], branch slot 3,
        # leaf [0].
        result = verify_proof(keccak256(root_raw), bytes.fromhex("1230"),
                              [root_raw])
        self.assertEqual(result.status, AUTHORIZED)
        self.assertEqual(result.leaf_value_hex, "0x01")
        self.assertEqual(
            [l.node_kind for l in result.layers],
            ["extension", "branch", "leaf"])


class TamperedChildReference(unittest.TestCase):
    def test_replaced_hashed_child(self):
        trie, _ = build_trie()
        key = bytes.fromhex("1234")
        proof = trie.get_proof(key)
        # Keep the parent intact; swap the hashed child at index 1 for a
        # different committed node so its hash mismatches the parent ref.
        tampered = [proof[0], proof[2]] + proof[2:]
        result = verify_proof(trie.root_hash, key, tampered)
        self.assertEqual(result.status, INVALID)
        self.assertEqual(result.failure_layer, 1)
        self.assertIn("父子引用不符", result.failure_reason)
        self.assertIsNone(result.leaf_value_hex)
        self.assertFalse(result.authorized)

    def test_wrong_root_hash(self):
        trie, _ = build_trie()
        key = bytes.fromhex("1234")
        result = verify_proof(b"\x00" * 32, key, trie.get_proof(key))
        self.assertEqual(result.status, INVALID)
        self.assertEqual(result.failure_layer, 0)
        self.assertIn("父子引用不符", result.failure_reason)

    def test_root_must_be_32_bytes(self):
        trie, _ = build_trie()
        key = bytes.fromhex("1234")
        result = verify_proof(b"\x00" * 31, key, trie.get_proof(key))
        self.assertEqual(result.status, INVALID)
        self.assertEqual(result.failure_layer, -1)


class NonCanonicalAndTruncatedRLP(unittest.TestCase):
    def test_noncanonical_committed_by_root(self):
        bad = bytes.fromhex("8101")
        result = verify_proof(keccak256(bad), b"\x01", [bad])
        self.assertEqual(result.status, INVALID)
        self.assertEqual(result.failure_layer, 0)
        self.assertIn("RLP非规范", result.failure_reason)

    def test_truncated_list_committed_by_root(self):
        bad = bytes.fromhex("c380")
        result = verify_proof(keccak256(bad), b"\x01", [bad])
        self.assertEqual(result.status, INVALID)
        self.assertIn("截断", result.failure_reason)

    def test_truncated_proof_missing_leaf(self):
        trie, _ = build_trie()
        key = bytes.fromhex("1234")
        proof = trie.get_proof(key)
        result = verify_proof(trie.root_hash, key, proof[:-1])
        self.assertEqual(result.status, INVALID)
        self.assertIn("路径残缺", result.failure_reason)

    def test_length_of_length_leading_zero(self):
        bad = bytes([0xb9, 0x00, 0x38]) + b"a" * 56
        result = verify_proof(keccak256(bad), b"a", [bad])
        self.assertEqual(result.status, INVALID)
        self.assertIn("RLP非规范", result.failure_reason)


class DuplicateAndTail(unittest.TestCase):
    def test_extra_unconsumed_node(self):
        trie, _ = build_trie()
        key = bytes.fromhex("1234")
        proof = trie.get_proof(key)
        result = verify_proof(trie.root_hash, key, proof + [proof[-1]])
        self.assertEqual(result.status, INVALID)
        self.assertIn("尾节点", result.failure_reason)

    def test_repeated_node_in_chain(self):
        trie, _ = build_trie()
        key = bytes.fromhex("1234")
        proof = trie.get_proof(key)
        result = verify_proof(trie.root_hash, key,
                              proof[:2] + [proof[1]] + proof[2:])
        self.assertEqual(result.status, INVALID)

    def test_empty_proof(self):
        trie, _ = build_trie()
        result = verify_proof(trie.root_hash, bytes.fromhex("12"), [])
        self.assertEqual(result.status, INVALID)
        self.assertEqual(result.failure_layer, 0)


class HexPrefixFailure(unittest.TestCase):
    def test_bad_flag_in_committed_leaf(self):
        node = encode([bytes([0x40]), b"\x01"])
        result = verify_proof(keccak256(node), b"", [node])
        self.assertEqual(result.status, INVALID)
        self.assertIn("十六进制前缀", result.failure_reason)

    def test_bad_flag_on_hashed_leaf_layer(self):
        k1 = b"\x00" + bytes(range(1, 32))
        k2 = b"\x01" + bytes(range(1, 32))
        trie = MemoryTrie()
        trie.put(k1, b"\x01")
        trie.put(k2, b"\x00")
        proof = trie.get_proof(k1)
        leaf = decode(proof[-1])
        bad_path = bytes([0x40 | leaf[0][0]]) + leaf[0][1:]
        # The tampered leaf hash differs from the parent commitment.
        result = verify_proof(
            trie.root_hash, k1,
            proof[:-1] + [encode([bad_path, leaf[1]])])
        self.assertEqual(result.status, INVALID)
        self.assertTrue("十六进制前缀" in result.failure_reason or
                        "父子引用不符" in result.failure_reason)


class NonexistentKey(unittest.TestCase):
    def test_path_diverges(self):
        trie, _ = build_trie()
        proof = trie.get_proof(bytes.fromhex("1234"))
        result = verify_proof(trie.root_hash, bytes.fromhex("1234ff"), proof)
        self.assertEqual(result.status, INVALID)


class SnapshotFixtures(unittest.TestCase):
    def test_shipped_snapshot_scenarios(self):
        path = os.path.join(ROOT_DIR, "data", "snapshot.json")
        with open(path, encoding="utf-8") as fh:
            snapshot = json.load(fh)
        for fixture in snapshot["fixtures"]:
            with self.subTest(name=fixture["name"]):
                root = bytes.fromhex(fixture["root_hash"][2:])
                key = bytes.fromhex(fixture["command_id"][2:])
                proof = [bytes.fromhex(n[2:]) for n in fixture["proof"]]
                result = verify_proof(root, key, proof)
                self.assertEqual(result.status, fixture["expect"])


if __name__ == "__main__":
    unittest.main()
