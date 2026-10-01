"""End-to-end HTTP/API smoke tests against the stdlib server.

Boots app.server on an ephemeral port in a background thread and exercises
the health endpoint, static entry, snapshot API and verification API.
"""

import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from app import server as srv

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _request(method: str, path: str, body=None):
    url = f"http://127.0.0.1:{HttpSmoke.port}{path}"
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class HttpSmoke(unittest.TestCase):
    port = 0
    httpd = None
    thread = None

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)

    def test_healthz(self):
        code, body = _request("GET", "/healthz")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"status": "ok"})

    def test_static_entry(self):
        code, body = _request("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn("离线指令授权快照复核台".encode("utf-8"), body)

    def test_assets(self):
        for asset in ("/styles.css", "/app.js"):
            code, body = _request("GET", asset)
            self.assertEqual(code, 200, asset)
            self.assertTrue(body)

    def test_404_for_unknown(self):
        code, _ = _request("GET", "/nope")
        self.assertEqual(code, 404)

    def test_snapshot_fixtures(self):
        code, body = _request("GET", "/api/snapshot")
        self.assertEqual(code, 200)
        snapshot = json.loads(body)
        self.assertGreaterEqual(len(snapshot["fixtures"]), 8)

    def _verify(self, fixture):
        code, body = _request("POST", "/api/verify", fixture)
        self.assertEqual(code, 200)
        return json.loads(body)

    def test_authorized_disabled_tampered_noncanonical_scenarios(self):
        _, body = _request("GET", "/api/snapshot")
        fixtures = json.loads(body)["fixtures"]
        by_name = {f["name"]: f for f in fixtures}

        enabled = self._verify(next(f for f in fixtures if f["expect"] == "AUTHORIZED"))
        self.assertEqual(enabled["status"], "AUTHORIZED")
        self.assertEqual(enabled["status_text"], "已授权")
        self.assertTrue(enabled["authorized"])
        self.assertEqual(enabled["leaf_value"], "0x01")
        self.assertTrue(enabled["layers"])

        disabled = self._verify(next(f for f in fixtures if f["expect"] == "UNAUTHORIZED"))
        self.assertEqual(disabled["status"], "UNAUTHORIZED")
        self.assertEqual(disabled["status_text"], "未授权")
        self.assertFalse(disabled["authorized"])
        self.assertEqual(disabled["leaf_value"], "0x00")

        tampered = self._verify(by_name["tampered_child_reference"])
        self.assertEqual(tampered["status"], "INVALID")
        self.assertEqual(tampered["status_text"], "证明无效")
        self.assertIsNotNone(tampered["failure_layer"])
        self.assertIn("父子引用不符", tampered["failure_reason"])
        self.assertIsNone(tampered["leaf_value"])

        noncanon = self._verify(by_name["noncanonical_rlp"])
        self.assertEqual(noncanon["status"], "INVALID")
        self.assertIn("RLP", noncanon["failure_reason"])
        self.assertEqual(noncanon["failure_layer"], 0)

        truncated = self._verify(by_name["truncated_path"])
        self.assertEqual(truncated["status"], "INVALID")
        self.assertIn("路径残缺", truncated["failure_reason"])

    def test_every_layer_trace_fields(self):
        _, body = _request("GET", "/api/snapshot")
        fx = next(f for f in json.loads(body)["fixtures"]
                  if f["expect"] == "AUTHORIZED")
        result = self._verify(fx)
        for layer in result["layers"]:
            self.assertIn(layer["node_kind"], ("branch", "extension", "leaf"))
            self.assertIn(layer["ref_kind"], ("root", "hash", "embedded"))
            self.assertRegex(layer["actual_hash"], r"^0x[0-9a-f]{64}$")
            self.assertTrue(layer["cumulative_path"].startswith("0x"))
            if layer["node_kind"] != "leaf":
                self.assertIn(layer["next_ref_kind"], ("hash", "embedded"))

    def test_bad_requests_are_400(self):
        code, body = _request("POST", "/api/verify", {"root_hash": "zz"})
        self.assertEqual(code, 400)
        self.assertIn("error", json.loads(body))

        code, _ = _request("POST", "/api/verify",
                           {"root_hash": "0x" + "00" * 32,
                            "command_id": "0xaa", "proof": "not-a-list"})
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
