"""Static page build checks (no browser/node required).

Validates that the single-page reviewer is internally consistent:
  * referenced CSS/JS assets exist;
  * every element id used by app.js exists in index.html;
  * CSS classes produced by app.js are defined in styles.css;
  * JavaScript is syntactically valid when node is available (else the
    static consistency checks below still run).
"""

import os
import re
import shutil
import subprocess
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT_DIR, "webstatic")


def _read(name: str) -> str:
    with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
        return fh.read()


class PageBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("index.html")
        cls.css = _read("styles.css")
        cls.js = _read("app.js")

    def test_assets_referenced_and_present(self):
        for asset in re.findall(r'(?:href|src)="(/[^"]+)"', self.html):
            if not asset.endswith((".css", ".js")):
                continue  # route links such as /healthz are not static files
            local = asset.lstrip("/")
            self.assertTrue(
                os.path.isfile(os.path.join(STATIC, local)),
                f"missing asset {asset}")

    def test_required_element_ids(self):
        ids_used = set(re.findall(r'getElementById\("([^"]+)"\)', self.js))
        ids_defined = set(re.findall(r'id="([^"]+)"', self.html))
        missing = ids_used - ids_defined
        self.assertFalse(missing, f"app.js uses ids absent from html: {missing}")

    def test_css_classes_used_in_js_are_defined(self):
        # renderResult assigns verdict.<STATUS> and ref-/node-kind- classes.
        for status in ("AUTHORIZED", "UNAUTHORIZED", "INVALID"):
            self.assertRegex(self.css, rf"\.verdict\.{status}\b")
        for ref in ("root", "hash", "embedded"):
            self.assertRegex(self.css, rf"\.ref-{ref}\b")
        for kind in ("leaf", "branch", "extension"):
            self.assertRegex(self.css, rf"\.node-kind-{kind}\b")

    def test_status_and_labels_complete(self):
        for label in ("已授权", "未授权", "证明无效"):
            self.assertIn(label, self.js)
        for label in ("根承诺", "32字节散列引用", "内嵌节点引用"):
            self.assertIn(label, self.js)

    def test_html_tag_balance(self):
        for tag in ("html", "head", "body", "table", "thead", "tbody",
                    "section", "header", "footer", "main"):
            opens = len(re.findall(rf"<{tag}[\s>]", self.html))
            closes = len(re.findall(rf"</{tag}>", self.html))
            self.assertEqual(opens, closes, f"<{tag}> unbalanced")

    def test_js_syntax_with_node_if_present(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available; static checks already passed")
        proc = subprocess.run(
            [node, "--check", os.path.join(STATIC, "app.js")],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_page_contains_static_entry_copy(self):
        self.assertIn("离线指令授权快照复核台", self.html)
        self.assertIn("/healthz", self.html)


if __name__ == "__main__":
    unittest.main()
