#!/usr/bin/env python3
"""Unit/control tests for CONTROL_PY.registry_absent npm 404 body shapes.

Accepts only measured primary-source shapes when HTTP status is exactly 404:
  1) object {"error":"Not found"}  (package metadata URL)
  2) JSON string "Not Found"       (version document URL)

Refuses non-404 statuses, network failure, malformed/non-JSON bodies,
200 with a Not-Found-looking body, and 404 with unrelated object/string.
Does not publish. Does not broaden into arbitrary string matching.
"""
from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path


def load_control():
    yml = Path(__file__).resolve().parents[1] / ".github/workflows/verify-js-first-publish.yml"
    lines = yml.read_text().splitlines(True)
    start = next(i + 1 for i, line in enumerate(lines) if line.startswith("  CONTROL_PY: |"))
    end = start
    while end < len(lines) and (
        lines[end].startswith("    ")
        or (lines[end].strip() == "" and end + 1 < len(lines) and lines[end + 1].startswith("    "))
    ):
        end += 1
    code = "".join(line[4:] if line.startswith("    ") else line for line in lines[start:end])
    idx = code.find("if __name__ == '__main__':")
    ns: dict = {}
    exec(compile(code[:idx], str(yml), "exec"), ns)
    return ns["registry_absent"], ns["Refusal"]


class FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n: int = -1):
        if n < 0:
            data, self._body = self._body, b""
            return data
        data, self._body = self._body[:n], self._body[n:]
        return data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def http_error(code: int, body: bytes, url: str = "https://registry.npmjs.org/x"):
    return urllib.error.HTTPError(url, code, "err", hdrs=None, fp=io.BytesIO(body))


def make_opener(plan: list):
    """plan items: ('http', code, body_bytes) | ('ok', body_bytes) | ('network',) | callable"""
    state = {"i": 0}

    def opener(req, timeout=20):
        i = state["i"]
        state["i"] = i + 1
        if i >= len(plan):
            raise AssertionError(f"unexpected extra request: {req.full_url}")
        item = plan[i]
        if callable(item):
            return item(req, timeout)
        kind = item[0]
        if kind == "network":
            raise urllib.error.URLError("simulated network failure")
        if kind == "ok":
            return FakeResponse(item[1])
        if kind == "http":
            _, code, body = item
            raise http_error(code, body, url=req.full_url)
        raise AssertionError(item)

    return opener


def expect_refusal(fn, code_substr: str):
    registry_absent, Refusal = load_control()
    try:
        fn(registry_absent)
    except Refusal as ex:
        if code_substr not in str(ex):
            raise AssertionError(f"expected Refusal containing {code_substr!r}, got {ex!r}") from ex
        return
    except Exception as ex:
        raise AssertionError(f"expected Refusal({code_substr}), got {type(ex).__name__}: {ex}") from ex
    raise AssertionError(f"expected Refusal({code_substr}), but call succeeded")


def main() -> int:
    registry_absent, Refusal = load_control()
    pkg = b'{"error":"Not found"}'
    ver = b'"Not Found"'
    passed = 0

    # ACCEPT: both measured shapes across the two URLs
    registry_absent(
        "raven-receipt-verifier",
        "0.1.0",
        opener=make_opener([("http", 404, pkg), ("http", 404, ver)]),
    )
    print("PASS accept both measured 404 shapes")
    passed += 1

    # ACCEPT: object shape alone for both URLs (still valid if registry used object everywhere)
    registry_absent(
        "raven-receipt-verifier",
        "0.1.0",
        opener=make_opener([("http", 404, pkg), ("http", 404, pkg)]),
    )
    print("PASS accept object shape on both URLs")
    passed += 1

    # ACCEPT: string shape alone for both URLs
    registry_absent(
        "raven-receipt-verifier",
        "0.1.0",
        opener=make_opener([("http", 404, ver), ("http", 404, ver)]),
    )
    print("PASS accept JSON string shape on both URLs")
    passed += 1

    # REFUSE: non-404 statuses
    for status in (401, 403, 429, 500, 502, 503):
        expect_refusal(
            lambda ra, s=status: ra(
                "pkg", "1.0.0", opener=make_opener([("http", s, pkg)])
            ),
            "REGISTRY_NOT_CONFIRMED_ABSENT",
        )
        print(f"PASS refuse HTTP {status}")
        passed += 1

    # REFUSE: network failure (URLError; __main__ wraps as RELEASE_GUARD_REFUSAL)
    try:
        registry_absent("pkg", "1.0.0", opener=make_opener([("network",)]))
        raise AssertionError("network failure should not pass")
    except urllib.error.URLError:
        print("PASS refuse network failure (URLError)")
        passed += 1
    except Refusal as ex:
        raise AssertionError(f"network should be URLError, got Refusal {ex}") from ex

    # REFUSE: malformed / non-JSON on 404
    expect_refusal(
        lambda ra: ra(
            "pkg",
            "1.0.0",
            opener=make_opener([("http", 404, b"not-json{{{")]),
        ),
        "REGISTRY_INVALID_ABSENCE_RESPONSE",
    )
    print("PASS refuse malformed non-JSON 404 body")
    passed += 1

    # REFUSE: 200 with Not-Found-looking body (treated as exists)
    expect_refusal(
        lambda ra: ra(
            "pkg",
            "1.0.0",
            opener=make_opener([("ok", b'"Not Found"')]),
        ),
        "REGISTRY_PACKAGE_ALREADY_EXISTS",
    )
    print("PASS refuse 200 with Not-Found-looking body")
    passed += 1

    # REFUSE: 404 unrelated object
    expect_refusal(
        lambda ra: ra(
            "pkg",
            "1.0.0",
            opener=make_opener([("http", 404, b'{"error":"teapot"}')]),
        ),
        "REGISTRY_INVALID_ABSENCE_RESPONSE",
    )
    print("PASS refuse 404 unrelated object")
    passed += 1

    # REFUSE: 404 unrelated string
    expect_refusal(
        lambda ra: ra(
            "pkg",
            "1.0.0",
            opener=make_opener([("http", 404, b'"gone"')]),
        ),
        "REGISTRY_INVALID_ABSENCE_RESPONSE",
    )
    print("PASS refuse 404 unrelated string")
    passed += 1

    # REFUSE: 404 wrong casing / detached substring (must not broaden)
    expect_refusal(
        lambda ra: ra(
            "pkg",
            "1.0.0",
            opener=make_opener([("http", 404, b'"not found"')]),
        ),
        "REGISTRY_INVALID_ABSENCE_RESPONSE",
    )
    print("PASS refuse 404 wrong-casing string not found")
    passed += 1

    expect_refusal(
        lambda ra: ra(
            "pkg",
            "1.0.0",
            opener=make_opener([("http", 404, b'{"error":"Not Found"}')]),
        ),
        "REGISTRY_INVALID_ABSENCE_RESPONSE",
    )
    print("PASS refuse 404 object with wrong Not Found casing")
    passed += 1

    # REFUSE: 404 JSON null / number / array
    for body in (b"null", b"1", b"[]"):
        expect_refusal(
            lambda ra, b=body: ra(
                "pkg", "1.0.0", opener=make_opener([("http", 404, b)])
            ),
            "REGISTRY_INVALID_ABSENCE_RESPONSE",
        )
        print(f"PASS refuse 404 JSON {body!r}")
        passed += 1

    print(f"ALL_REGISTRY_ABSENT_SHAPE_CONTROLS_PASSED count={passed}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as ex:
        print(f"REGISTRY_ABSENT_SHAPE_CONTROL_FAILURE: {ex}", file=sys.stderr)
        raise
