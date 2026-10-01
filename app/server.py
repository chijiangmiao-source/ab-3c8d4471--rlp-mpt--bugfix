"""HTTP entry point for the offline authorization snapshot reviewer.

Stdlib-only.  Serves:
  GET /            static single-page reviewer (webstatic/)
  GET /healthz     liveness probe -> 200 {"status": "ok"}
  GET /api/snapshot   deterministic fixtures (data/snapshot.json)
  POST /api/verify    verify a submitted snapshot object

Configuration via environment:
  HOST=0.0.0.0   PORT=8080   (Compose maps the configurable host port here)
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.trie import verify_proof  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "webstatic")
SNAPSHOT_PATH = os.path.join(BASE_DIR, "data", "snapshot.json")

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}


def _load_snapshot() -> dict:
    with open(SNAPSHOT_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def run_verification(payload: dict) -> dict:
    """Validate request shape and run proof verification."""
    if not isinstance(payload, dict):
        raise ValueError("请求体必须为 JSON 对象")
    root_hex = payload.get("root_hash", "")
    key_hex = payload.get("command_id", "")
    nodes = payload.get("proof")
    if not isinstance(root_hex, str) or not isinstance(key_hex, str):
        raise ValueError("root_hash 与 command_id 必须为十六进制字符串")
    if not isinstance(nodes, list):
        raise ValueError("proof 必须为按根到叶排序的节点数组")

    root = _unhex(root_hex, "根哈希")
    if root is None or len(root) != 32:
        raise ValueError("根哈希必须为32字节的十六进制串")
    key = _unhex(key_hex, "指令标识")
    if key is None or len(key) == 0:
        raise ValueError("指令标识必须为非空十六进制串")
    raws = []
    for i, item in enumerate(nodes):
        raw = _unhex(item if isinstance(item, str) else "", f"第{i}个节点")
        if raw is None:
            raise ValueError(f"第{i}个证明节点不是合法十六进制串")
        raws.append(raw)

    return verify_proof(root, key, raws).to_dict()


def _unhex(value: str, what: str):
    v = value[2:] if value.startswith("0x") or value.startswith("0X") else value
    if v == "":
        return b""
    if len(v) % 2 or any(c not in "0123456789abcdefABCDEF" for c in v):
        return None
    try:
        return bytes.fromhex(v)
    except ValueError:
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "OfflineAuthReviewer/1.0"

    def log_message(self, fmt, *args):  # quieter logs
        sys.stderr.write("[http] " + fmt % args + "\n")

    # -- helpers ----------------------------------------------------------
    def _send_json(self, code: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_static(self, rel: str) -> None:
        rel = rel.lstrip("/")
        if rel == "":
            rel = "index.html"
        path = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not path.startswith(STATIC_DIR) or not os.path.isfile(path):
            self._send_json(404, {"error": "not found"})
            return
        ext = os.path.splitext(path)[1]
        with open(path, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", _CONTENT_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # -- routes -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        if path == "/api/snapshot":
            try:
                self._send_json(200, _load_snapshot())
            except FileNotFoundError:
                self._send_json(503, {"error": "快照尚未生成，请先运行 build_snapshot"})
            return
        self._send_static(path)

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/api/verify":
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "请求体不是合法 JSON"})
            return
        try:
            result = run_verification(payload)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, result)


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    if not os.path.exists(SNAPSHOT_PATH):
        sys.stderr.write("snapshot missing; generating via scripts.build_snapshot\n")
        from scripts.build_snapshot import build_snapshot
        with open(SNAPSHOT_PATH, "w", encoding="utf-8") as fh:
            json.dump(build_snapshot(), fh, ensure_ascii=False, indent=2)
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"offline authorization reviewer listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
