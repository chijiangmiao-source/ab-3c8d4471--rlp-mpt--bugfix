"""Merkle Patricia Trie: proof verification and a small in-memory builder.

Proofs are RLP-encoded trie nodes supplied **from root to leaf**, exactly
as a ground reviewer imports them from an offline authorization snapshot.
The verifier walks the nibble path of a hex command id while checking every
parent/child reference; nodes with RLP length < 32 are embedded inline by
the trie spec, and only 32-byte hash references consume the next proof
entry.  One trace row is recorded per layer so the result page can replay
the whole walk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import hp as hexprefix
from .keccak import keccak256
from .rlp import RLPError, decode, decode_raw, encode

EMPTY_ROOT = keccak256(encode(b""))

AUTHORIZED = "AUTHORIZED"
UNAUTHORIZED = "UNAUTHORIZED"
INVALID = "INVALID"

REF_ROOT = "root"
REF_HASH = "hash"
REF_EMBEDDED = "embedded"

_STATUS_TEXT = {
    AUTHORIZED: "已授权",
    UNAUTHORIZED: "未授权",
    INVALID: "证明无效",
}


@dataclass
class LayerTrace:
    layer: int
    node_kind: str                        # branch / extension / leaf
    ref_kind: str                         # root / hash / embedded
    expected_ref: Optional[str]           # hash the parent promised
    actual_hash: str                      # keccak of this node's canonical RLP
    consumed_nibbles: str                 # nibbles consumed at this layer
    cumulative_path: str                  # nibbles consumed from the root so far
    next_ref_kind: Optional[str] = None
    next_ref: Optional[str] = None
    raw_rlp_hex: str = ""
    note: str = ""


@dataclass
class VerificationResult:
    status: str
    authorized: bool
    root_hex: str
    key_hex: str
    leaf_value_hex: Optional[str] = None
    failure_layer: Optional[int] = None
    failure_reason: Optional[str] = None
    layers: list[LayerTrace] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "authorized": self.authorized,
            "status_text": _STATUS_TEXT[self.status],
            "root": self.root_hex,
            "key": self.key_hex,
            "leaf_value": self.leaf_value_hex,
            "failure_layer": self.failure_layer,
            "failure_reason": self.failure_reason,
            "layers": [layer.__dict__ for layer in self.layers],
        }


class ProofError(Exception):
    def __init__(self, layer: int, reason: str):
        super().__init__(reason)
        self.layer = layer
        self.reason = reason


def _as_hex(nibbles: list[int]) -> str:
    return "0x" + "".join(f"{n:x}" for n in nibbles)


def verify_proof(root_hash: bytes, key: bytes, proof_nodes: list[bytes]) -> VerificationResult:
    """Verify root-first *proof_nodes* commit *key* under *root_hash*."""
    result = VerificationResult(
        status=INVALID, authorized=False,
        root_hex="0x" + root_hash.hex(), key_hex="0x" + key.hex())
    target = hexprefix.nibbles_from_key(key)

    try:
        if len(root_hash) != 32:
            raise ProofError(-1, "根哈希必须为32字节")
        if not proof_nodes:
            raise ProofError(0, "证明为空：缺少根节点")

        # Accept either raw RLP bytes or already-decoded node lists; the
        # latter is what some tooling (e.g. py-trie's get_proof) produces.
        proof_raws: list[bytes] = []
        for supplied in proof_nodes:
            proof_raws.append(
                encode(list(supplied)) if isinstance(supplied, (list, tuple))
                else bytes(supplied))

        idx = 0
        expected_hash: Optional[bytes] = root_hash
        ref_kind = REF_ROOT
        seen_hashes: set[bytes] = set()
        pos = 0
        node_count = 0
        leaf_value: Optional[bytes] = None
        terminated = False

        while not terminated:
            layer = node_count
            raw = proof_raws[idx]

            try:
                _node, consumed = decode_raw(raw)
                if consumed != len(raw):
                    raise RLPError("节点编码后存在多余字节")
                node = decode(raw)
            except RLPError as exc:
                raise ProofError(layer, f"RLP非规范或截断：{exc}") from exc

            actual_hash = keccak256(raw)
            if actual_hash != expected_hash:
                raise ProofError(
                    layer,
                    "父子引用不符：父节点承诺 "
                    f"0x{expected_hash.hex()} ，实际节点散列 0x{actual_hash.hex()}")
            if actual_hash in seen_hashes:
                raise ProofError(layer,
                                 f"重复尾节点：0x{actual_hash.hex()} 重复出现")
            seen_hashes.add(actual_hash)
            idx += 1

            base_trace = LayerTrace(
                layer=node_count, node_kind="", ref_kind=ref_kind,
                expected_ref="0x" + expected_hash.hex(),
                actual_hash="0x" + actual_hash.hex(),
                consumed_nibbles="", cumulative_path=_as_hex(target[:pos]),
                raw_rlp_hex="0x" + raw.hex())

            # Walk any inline-embedded chain; it ends at a leaf or a hash ref.
            leaf_value, terminated, pos, expected_hash, ref_kind, node_count, idx, \
                next_trace = _walk_from(
                    node, target, pos, node_count, layer, base_trace,
                    seen_hashes, proof_raws, idx)
            result.layers.extend(next_trace)
            if terminated:
                break
            if expected_hash is None:
                raise ProofError(layer, "路径残缺：内嵌链未终止且无后续散列引用")
            if idx >= len(proof_raws):
                raise ProofError(
                    node_count, "路径残缺：证明在抵达叶节点前结束，缺少引用节点")

        if idx < len(proof_raws):
            raise ProofError(
                node_count, f"证明存在 {len(proof_raws) - idx} 个未被路径消费的尾节点"
                     "（疑似重复尾节点）")

        result.leaf_value_hex = "0x" + (leaf_value or b"").hex()
        if leaf_value == b"\x01":
            result.status = AUTHORIZED
            result.authorized = True
        else:
            result.status = UNAUTHORIZED
            result.authorized = False
        return result

    except ProofError as fail:
        # Any failure clears any previously derived success conclusion.
        result.status = INVALID
        result.authorized = False
        result.leaf_value_hex = None
        result.failure_layer = fail.layer
        result.failure_reason = fail.reason
        return result


def _walk_from(node, target, pos, node_count, layer, base_trace, seen_hashes,
               proof_raws, idx):
    """Walk one decoded node plus its embedded descendants.

    Returns (leaf_value, terminated, pos, next_hash, next_ref_kind,
    node_count, idx, traces).  *next_hash* / *next_ref_kind* describe the
    reference that requires the next standalone proof entry (None at a
    leaf).  Embedded nodes are normally inlined in their parent; some
    tooling nevertheless ships them as separate proof entries, so an
    embedded child whose canonical bytes equal the next proof entry is
    consumed there as well.
    """
    traces: list[LayerTrace] = []
    current = node
    embedded = False
    inline_raw: Optional[bytes] = None

    def _embedded_note(raw_child: bytes) -> str:
        nonlocal idx
        if idx < len(proof_raws) and proof_raws[idx] == raw_child:
            idx += 1
            return "内嵌节点（RLP < 32 字节，证明中单独提供）"
        return "内嵌节点（RLP < 32 字节，按规范内联）"

    while True:
        trace_layer = node_count
        node_count += 1
        if embedded:
            current_raw_hex = "0x" + inline_raw.hex()
            embedded_hash = keccak256(inline_raw)
        else:
            current_raw_hex = base_trace.raw_rlp_hex
            embedded_hash = None
        trace = LayerTrace(
            layer=trace_layer, node_kind="",
            ref_kind=base_trace.ref_kind if not embedded else REF_EMBEDDED,
            expected_ref=base_trace.expected_ref if not embedded else None,
            actual_hash=base_trace.actual_hash if not embedded else
            "0x" + embedded_hash.hex(),
            consumed_nibbles="", cumulative_path=_as_hex(target[:pos]),
            raw_rlp_hex=current_raw_hex,
            note="" if not embedded else _embedded_note(inline_raw))
        if embedded:
            if embedded_hash in seen_hashes:
                raise ProofError(trace_layer,
                                 f"重复尾节点：0x{embedded_hash.hex()} 重复出现")
            seen_hashes.add(embedded_hash)
        if not isinstance(current, list) or len(current) not in (2, 17):
            raise ProofError(trace_layer, "节点结构无效：既非叶/扩展节点也非分支节点")

        if len(current) == 17:
            trace.node_kind = "branch"
            for slot in range(17):
                if not isinstance(current[slot], (bytes, list)):
                    raise ProofError(trace_layer, "分支节点包含无效引用类型")
            if pos == len(target):
                value = current[16]
                if not isinstance(value, bytes) or value == b"":
                    raise ProofError(trace_layer, "路径残缺：命中分支值槽但为空")
                trace.consumed_nibbles = "(终止于分支值槽)"
                trace.note = (trace.note + " " if trace.note else "") + \
                    f"叶值 = 0x{value.hex()}"
                traces.append(trace)
                return value, True, pos, None, None, node_count, idx, traces
            nib = target[pos]
            child = current[nib]
            if child == b"":
                raise ProofError(trace_layer, f"路径残缺：分支槽 {nib:x} 为空")
            trace.consumed_nibbles = f"{nib:x}"
            pos += 1
            traces.append(trace)
            kind, embedded_node, inline = _classify_ref(trace_layer, child)
            _annotate_next(traces[-1], kind, inline if kind == REF_HASH else None)
            if kind == REF_HASH:
                return None, False, pos, inline, REF_HASH, node_count, idx, traces
            current, inline_raw, embedded = embedded_node, inline, True
            continue

        encoded_path, child_or_value = current
        if not isinstance(encoded_path, bytes) or not isinstance(
                child_or_value, (bytes, list)):
            raise ProofError(trace_layer, "叶/扩展节点字段类型无效")
        try:
            path_nibbles, is_leaf = hexprefix.decode(encoded_path)
        except hexprefix.HPError as exc:
            raise ProofError(trace_layer, f"十六进制前缀错误：{exc}") from exc
        remaining = target[pos:]

        if is_leaf:
            trace.node_kind = "leaf"
            if remaining != path_nibbles:
                raise ProofError(
                    trace_layer,
                    "路径不匹配：叶节点路径 "
                    f"{_as_hex(path_nibbles)} 与剩余路径 {_as_hex(remaining)} 不符")
            if not isinstance(child_or_value, bytes):
                raise ProofError(trace_layer, "叶节点值必须为字节串")
            trace.consumed_nibbles = _as_hex(path_nibbles)
            trace.cumulative_path = _as_hex(target[:pos + len(path_nibbles)])
            trace.note = (trace.note + " " if trace.note else "") + \
                f"叶值 = 0x{child_or_value.hex()}"
            traces.append(trace)
            return child_or_value, True, pos, None, None, node_count, idx, traces

        trace.node_kind = "extension"
        if remaining[:len(path_nibbles)] != path_nibbles:
            raise ProofError(
                trace_layer,
                "路径不匹配：扩展节点路径 "
                f"{_as_hex(path_nibbles)} 与剩余路径前缀不符")
        trace.consumed_nibbles = _as_hex(path_nibbles)
        pos += len(path_nibbles)
        trace.cumulative_path = _as_hex(target[:pos])
        traces.append(trace)
        kind, embedded_node, inline = _classify_ref(trace_layer, child_or_value)
        _annotate_next(traces[-1], kind, inline if kind == REF_HASH else None)
        if kind == REF_HASH:
            return None, False, pos, inline, REF_HASH, node_count, idx, traces
        current, inline_raw, embedded = embedded_node, inline, True


def _classify_ref(layer: int, child) -> tuple[str, Optional[list], Optional[bytes]]:
    """Classify a branch/extension child reference.

    Returns ``(kind, embedded_node, ref_raw)``:

      * ``REF_HASH``     -- a 32-byte hash reference; ``embedded_node`` is
                            None and ``ref_raw`` is the hash bytes.
      * ``REF_EMBEDDED`` -- a node inlined per the trie spec because its RLP
                            is shorter than 32 bytes.  Two encodings are
                            accepted: a nested RLP list (the decoded form some
                            tooling emits) and the canonical short byte string
                            carrying the child's *full RLP*.  For this form
                            ``embedded_node`` is the decoded node list and
                            ``ref_raw`` its canonical raw RLP.
    """
    if isinstance(child, list):
        return REF_EMBEDDED, child, encode(child)
    if isinstance(child, bytes) and len(child) == 32:
        return REF_HASH, None, child
    if isinstance(child, (bytes, bytearray)) and len(child) < 32:
        raw = bytes(child)
        try:
            embedded_node, consumed = decode_raw(raw)
            if consumed != len(raw):
                raise RLPError("内嵌节点编码后存在多余字节")
            if not isinstance(embedded_node, list):
                raise RLPError("内嵌引用不是RLP节点列表")
        except RLPError as exc:
            raise ProofError(layer, f"无效的内嵌节点引用：{exc}") from exc
        return REF_EMBEDDED, embedded_node, raw
    raise ProofError(layer, "无效的子节点引用：既非内嵌节点也非32字节散列")


def _annotate_next(trace: LayerTrace, kind: str, ref: Optional[bytes]) -> None:
    trace.next_ref_kind = kind
    trace.next_ref = ("0x" + ref.hex()) if ref is not None else "（内嵌节点）"


# ---------------------------------------------------------------------------
# Minimal in-memory Merkle Patricia Trie used to build snapshot fixtures.
# ---------------------------------------------------------------------------

class MemoryTrie:
    def __init__(self) -> None:
        self.db: dict[bytes, bytes] = {}
        self.root_hash = EMPTY_ROOT

    def put(self, key: bytes, value: bytes) -> None:
        nibbles = hexprefix.nibbles_from_key(key)
        root_node = self._load(self.root_hash)
        new_node = self._update(root_node, nibbles, value)
        self.root_hash = self._commit(new_node)

    def get_proof(self, key: bytes) -> list[bytes]:
        """Return standalone (hashed) nodes on root->leaf path, root first."""
        proof: list[bytes] = []
        ref = self.root_hash
        nibbles = hexprefix.nibbles_from_key(key)
        pos = 0
        while True:
            raw = self.db[ref]
            node = decode(raw)
            proof.append(raw)
            child, pos = _descend(node, nibbles, pos)
            if child is None:
                return proof
            while isinstance(child, list):
                child, pos = _descend(child, nibbles, pos)
                if child is None:
                    return proof
            ref = child

    def _load(self, ref: bytes):
        if ref == b"" or ref == EMPTY_ROOT:
            return b""
        return decode(self.db[ref])

    def _commit(self, node) -> bytes:
        """Persist a node tree and return its hash reference."""
        raw = encode(node)
        h = keccak256(raw)
        if h not in self.db:
            self.db[h] = raw
            if isinstance(node, list):
                for child in node:
                    if isinstance(child, list):
                        self._commit(child)
        return h

    def _update(self, node, nibbles: list[int], value: bytes):
        if node == b"":
            return [hexprefix.encode(nibbles, True), value]

        if len(node) == 2:
            path_nibbles, is_leaf = hexprefix.decode(node[0])
            if is_leaf:
                if path_nibbles == nibbles:
                    return [node[0], value]
                prefix_len = _common_prefix(path_nibbles, nibbles)
                prefix = path_nibbles[:prefix_len]
                branch = [b""] * 17
                self._attach_leaf(branch, path_nibbles[prefix_len:], node[1])
                self._attach_leaf(branch, nibbles[prefix_len:], value)
                if prefix:
                    return [hexprefix.encode(prefix, False), self._store(branch)]
                return branch

            prefix_len = _common_prefix(path_nibbles, nibbles)
            if prefix_len == len(path_nibbles):
                child_node = self._deref(node[1])
                updated = self._update(child_node, nibbles[prefix_len:], value)
                return [node[0], self._store(updated)]

            prefix = path_nibbles[:prefix_len]
            branch = [b""] * 17
            old_tail = path_nibbles[prefix_len + 1:]
            if old_tail:
                old_continuation = [hexprefix.encode(old_tail, False), node[1]]
                branch[path_nibbles[prefix_len]] = self._store(old_continuation)
            else:
                branch[path_nibbles[prefix_len]] = self._deref_or_ref(node[1])
            self._attach_leaf(branch, nibbles[prefix_len:], value)
            if prefix:
                return [hexprefix.encode(prefix, False), self._store(branch)]
            return branch

        branch = list(node)
        if not nibbles:
            branch[16] = value
            return branch
        nib, rest = nibbles[0], nibbles[1:]
        if branch[nib] == b"":
            leaf = [hexprefix.encode(rest, True), value]
            branch[nib] = self._store(leaf)
        else:
            child_node = self._deref(branch[nib])
            updated = self._update(child_node, rest, value)
            branch[nib] = self._store(updated)
        return branch

    def _attach_leaf(self, branch, nibbles_from_slot, value) -> None:
        if not nibbles_from_slot:
            # Key terminates exactly at this branch: value slot 16.
            branch[16] = value
            return
        nib, rest = nibbles_from_slot[0], nibbles_from_slot[1:]
        leaf = [hexprefix.encode(rest, True), value]
        branch[nib] = self._store(leaf)

    def _deref(self, ref):
        if isinstance(ref, list):
            return ref
        return decode(self.db[ref])

    def _deref_or_ref(self, ref):
        return ref if isinstance(ref, list) else ref

    def _store(self, node):
        """Return the node itself when small (embedded), else hash+persist."""
        raw = encode(node)
        if len(raw) < 32:
            return node
        h = keccak256(raw)
        self.db.setdefault(h, raw)
        if isinstance(node, list):
            for child in node:
                if isinstance(child, list):
                    self._commit(child)
        return h


def _descend(node, nibbles, pos):
    """Return (child_ref_or_node_or_None, new_pos) for one node hop."""
    if len(node) == 17:
        if pos == len(nibbles):
            return None, pos
        child = node[nibbles[pos]]
        return child, pos + 1
    path_nibbles, is_leaf = hexprefix.decode(node[0])
    if is_leaf:
        return None, pos
    return node[1], pos + len(path_nibbles)


def _common_prefix(a: list[int], b: list[int]) -> int:
    i = 0
    while i < len(a) and i < len(b) and a[i] == b[i]:
        i += 1
    return i
