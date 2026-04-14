#!/usr/bin/env python3
"""
快速检查爬取结果质量：对比修复前后函数是否不同、是否完整。

用法：
    python scripts/check_result.py                  # 检查 result.json
    python scripts/check_result.py my_result.json   # 检查指定文件
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _resolve(arg: str) -> Path:
    p = Path(arg)
    if p.exists():
        return p.resolve()
    alt = REPO_ROOT / arg
    if alt.exists():
        return alt
    return p.resolve()


def main() -> None:
    input_path = (
        _resolve(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "result.json"
    )
    if not input_path.exists():
        print(f"找不到文件: {input_path}")
        sys.exit(1)

    data = json.loads(input_path.read_text(encoding="utf-8"))
    items = data["items"] if isinstance(data, dict) else data

    total = len(items)
    counts = {"ok": 0, "same": 0, "patch_ctx": 0, "no_vuln": 0, "no_fixed": 0}

    print(f"\n{'CVE':<20} {'Function':<45} {'Status'}")
    print("-" * 90)

    for it in items:
        cve = it.get("cve", "") or it.get("cve_id", "")
        func = (it.get("function_name") or "")[:44]
        vuln = (
            it.get("vulnerable_function") or it.get("vulnerable_code") or ""
        ).strip()
        fixed = (it.get("fixed_function") or it.get("fixed_code") or "").strip()

        patch_ctx = vuln.startswith("/* patch context")

        if not vuln:
            status = "[no vuln func]"
            counts["no_vuln"] += 1
        elif not fixed:
            status = "[no fixed func]"
            counts["no_fixed"] += 1
        elif vuln == fixed:
            status = "[!! SAME !!]"
            counts["same"] += 1
        elif patch_ctx:
            status = "[diff ctx only]"
            counts["patch_ctx"] += 1
        else:
            status = "[OK]"
            counts["ok"] += 1

        print(f"{cve:<20} {func:<45} {status}")

    print("-" * 90)
    print(f"\nTotal {total}:")
    print(f"  OK (complete, different) : {counts['ok']}")
    print(f"  diff context only        : {counts['patch_ctx']}")
    print(f"  SAME (BUG)               : {counts['same']}")
    print(f"  no vuln func             : {counts['no_vuln']}")
    print(f"  no fixed func            : {counts['no_fixed']}")

    if counts["same"] > 0:
        print("\n[!] Version identification bug detected. Please re-crawl.")
    else:
        print("\n[v] No same-before-after issues found.")


if __name__ == "__main__":
    main()
