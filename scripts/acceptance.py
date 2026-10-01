"""Acceptance runner used by the Compose ``verify`` service.

It interleaves, across the three required scenarios (valid authorization,
tampered child reference, non-canonical RLP), three kinds of checks:

  1. proof-verification code tests (unittest modules / classes);
  2. static page build checks (tests.test_page);
  3. live API/HTTP smoke against the running web service
     (health endpoint + page entry + POST /api/verify for the scenario).

The process exits 0 only if every phase passes; otherwise it exits 1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080")

failures: list[str] = []
passed: list[str] = []


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72, flush=True)


def record(name: str, ok: bool, detail: str = "") -> None:
    (passed if ok else failures).append(name)
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail else ""), flush=True)


def run_unittest(name: str, test_ids: list[str]) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", *test_ids],
        cwd=ROOT_DIR, capture_output=True, text=True)
    ok = proc.returncode == 0
    if not ok:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        detail = detail[-1] if detail else "unittest failed"
    else:
        tail = [ln for ln in proc.stdout.splitlines() if ln.startswith("Ran ")]
        detail = tail[-1] if tail else "ok"
    record(name, ok, detail)


def http_get(path: str, timeout: float = 5.0):
    req = urllib.request.Request(BASE_URL + path, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def http_post(path: str, body: dict, timeout: float = 5.0):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        BASE_URL + path, data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def wait_for_health(attempts: int = 30, delay: float = 1.0) -> bool:
    for _ in range(attempts):
        try:
            status, body = http_get("/healthz")
            if status == 200 and json.loads(body).get("status") == "ok":
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(delay)
    return False


def smoke_health_and_page() -> None:
    try:
        status, body = http_get("/healthz")
        record("冒烟/健康端点 /healthz 返回 200 ok",
               status == 200 and json.loads(body).get("status") == "ok")
    except Exception as exc:  # noqa: BLE001
        record("冒烟/健康端点 /healthz", False, str(exc))
    try:
        status, body = http_get("/")
        record("冒烟/页面静态入口 / 可访问且含复核台标题",
               status == 200 and
               "离线指令授权快照复核台".encode("utf-8") in body)
    except Exception as exc:  # noqa: BLE001
        record("冒烟/页面静态入口 /", False, str(exc))
    for asset in ("/styles.css", "/app.js"):
        try:
            status, _ = http_get(asset)
            record(f"冒烟/页面资源 {asset}", status == 200)
        except Exception as exc:  # noqa: BLE001
            record(f"冒烟/页面资源 {asset}", False, str(exc))


def get_fixtures() -> dict[str, dict]:
    _, body = http_get("/api/snapshot")
    fixtures = json.loads(body)["fixtures"]
    return {fx["name"]: fx for fx in fixtures}


def verify_via_api(fixture_name: str, expected: str) -> None:
    fixtures = get_fixtures()
    fixture = next((fx for n, fx in fixtures.items()
                    if n.startswith(fixture_name)), None)
    if fixture is None:
        record(f"冒烟/API 场景 {fixture_name} 夹具存在", False, "missing fixture")
        return
    try:
        status, body = http_post("/api/verify", fixture)
        result = json.loads(body)
        ok = status == 200 and result["status"] == expected
        detail = f"status={result['status']}"
        if result["status"] == "INVALID":
            detail += f" 首个失败层={result['failure_layer']} 原因={result['failure_reason']}"
        else:
            detail += f" 层数={len(result['layers'])} 叶值={result['leaf_value']}"
        record(f"冒烟/API 校验 {fixture['name']} -> {expected}", ok, detail)
    except Exception as exc:  # noqa: BLE001
        record(f"冒烟/API 校验 {fixture_name}", False, str(exc))


PAGE_CHECK = ["tests.test_page"]


def main() -> int:
    banner(f"离线授权快照验收（目标服务：{BASE_URL}）")
    record("前置/等待 web 服务健康检查通过", wait_for_health())

    # ---- 场景一：有效授权 ------------------------------------------------
    banner("场景一：有效授权（证明有效且叶值 01）")
    run_unittest("代码测试/Keccak-256 标准向量",
                 ["tests.test_keccak"])
    run_unittest("代码测试/规范 RLP 编解码", ["tests.test_rlp"])
    run_unittest("代码测试/Hex-Prefix 路径编码", ["tests.test_hp"])
    run_unittest("代码测试/标准短内嵌节点判定为已授权（两层证据）",
                 ["tests.test_trie_proof.ShortEmbeddedNode"])
    run_unittest("代码测试/有效证明判定为已授权（含分支值槽、逐层轨迹）",
                 ["tests.test_trie_proof.EmptyAndSimpleTrie",
                  "tests.test_trie_proof.BranchValueSlot",
                  "tests.test_trie_proof.TraceContents",
                  "tests.test_trie_proof.ValidProofsAcrossFixture",
                  "tests.test_trie_proof.SnapshotFixtures"])
    run_unittest("页面构建检查/静态页面一致性", PAGE_CHECK)
    smoke_health_and_page()
    verify_via_api("enabled", "AUTHORIZED")
    verify_via_api("short_embedded_leaf", "AUTHORIZED")
    verify_via_api("disabled", "UNAUTHORIZED")

    # ---- 场景二：篡改子节点引用 ------------------------------------------
    banner("场景二：篡改子节点引用（父子引用不符）")
    run_unittest("代码测试/篡改引用、错误根哈希与重复尾节点被拒",
                 ["tests.test_trie_proof.TamperedChildReference",
                  "tests.test_trie_proof.DuplicateAndTail",
                  "tests.test_trie_proof.NonexistentKey"])
    run_unittest("页面构建检查/静态页面一致性（复查）", PAGE_CHECK)
    smoke_health_and_page()
    verify_via_api("tampered_child_reference", "INVALID")

    # ---- 场景三：非规范/截断 RLP -----------------------------------------
    banner("场景三：非规范 RLP、截断与十六进制前缀错误")
    run_unittest("代码测试/非规范RLP、截断与HP错误在首个失败层拒绝",
                 ["tests.test_trie_proof.NonCanonicalAndTruncatedRLP",
                  "tests.test_trie_proof.HexPrefixFailure"])
    run_unittest("代码测试/HTTP API 全量冒烟（进程内服务）",
                 ["tests.test_http_api"])
    run_unittest("页面构建检查/静态页面一致性（复查）", PAGE_CHECK)
    smoke_health_and_page()
    verify_via_api("noncanonical_rlp", "INVALID")
    verify_via_api("truncated_path", "INVALID")

    banner("验收汇总")
    print(f"通过 {len(passed)} 项，失败 {len(failures)} 项")
    if failures:
        print("\n失败项：")
        for name in failures:
            print(f"  - {name}")
        print("\n结论：验收未通过")
        return 1
    print("结论：全部验收通过（有效授权 / 篡改引用 / 非规范RLP）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
