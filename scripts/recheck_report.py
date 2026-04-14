#!/usr/bin/env python3
"""
对已有爬取结果做最终 LLM 完整性审查，将审查结果写回 JSON，并重新生成报告。

用法（仓库根目录）::

    python scripts/recheck_report.py output/result_2026_03.json output/report_2026_03.md
    python scripts/recheck_report.py output/result_2026_03.json   # 报告路径自动推导
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from autoyara.llm.quality_check import check_quality
from autoyara.llm.sync_client import SyncLLMClient
from autoyara.models import sync_function_line_arrays


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print("用法: python scripts/recheck_report.py <result.json> [report.md]")
        sys.exit(1)

    json_path = Path(args[0])
    if not json_path.is_absolute():
        json_path = REPO_ROOT / json_path
    if not json_path.exists():
        print(f"找不到文件: {json_path}")
        sys.exit(1)

    # 推导报告路径
    if len(args) >= 2:
        report_path = Path(args[1])
        if not report_path.is_absolute():
            report_path = REPO_ROOT / report_path
    else:
        report_path = json_path.with_name(json_path.stem + "_report.md")

    print(f"\n[recheck] 输入: {json_path}")
    print(f"[recheck] 报告: {report_path}")

    data = json.loads(json_path.read_text(encoding="utf-8"))
    items: list[dict] = data["items"] if isinstance(data, dict) else data

    total = len(items)
    print(f"[recheck] 共 {total} 条，开始 LLM 最终审查...\n")

    client = SyncLLMClient()
    ok_count = 0
    fail_count = 0

    try:
        for i, item in enumerate(items, 1):
            cve_id = item.get("cve", item.get("cve_id", ""))
            desc = item.get("vuln_description", item.get("description", ""))
            vuln_func = item.get("vulnerable_function", item.get("vulnerable_code", ""))
            fixed_func = item.get("fixed_function", item.get("fixed_code", ""))
            func_name = item.get("function_name", "")

            print(f"  [{i}/{total}] {cve_id} / {func_name[:50]}")

            qc = check_quality(
                description=desc,
                vulnerable_function=vuln_func or "",
                fixed_function=fixed_func or "",
                cve_id=cve_id,
                client=client,
            )

            # 写回审查结果（覆盖旧值）
            item["quality_ok"] = qc.overall_ok
            item["quality_score"] = qc.score
            item["quality_failed"] = qc.failed_fields()
            item["quality_reason"] = qc.reason

            if qc.overall_ok:
                ok_count += 1
            else:
                fail_count += 1
    finally:
        client.close()

    # 写回 JSON
    if isinstance(data, dict):
        data["items"] = items
        out_data = data
    else:
        out_data = items
    for it in items:
        sync_function_line_arrays(it)
    json_path.write_text(
        json.dumps(out_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"\n[recheck] 审查完成：OK={ok_count}  FAIL={fail_count}  总计={total}")
    print(f"[recheck] 结果已写回: {json_path}")

    # 重新生成报告
    print("\n[recheck] 重新生成报告...")
    import subprocess

    py = sys.executable
    result = subprocess.run(
        [
            py,
            str(REPO_ROOT / "scripts" / "gen_report.py"),
            str(json_path),
            str(report_path),
        ],
        capture_output=True,
        text=True,
    )
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip())

    print(f"\n[recheck] 报告已生成: {report_path}")
    print("\n质量统计：")
    print(f"  [OK] 完整: {ok_count}/{total}")
    print(f"  [FAIL] 不完整: {fail_count}/{total}")

    if fail_count > 0:
        print("\n  不完整条目：")
        for item in items:
            if not item.get("quality_ok", True):
                cve = item.get("cve", item.get("cve_id", ""))
                func = item.get("function_name", "")
                reason = item.get("quality_reason", "")
                failed = ", ".join(item.get("quality_failed") or [])
                print(f"    {cve} / {func[:40]}")
                print(f"      缺失: {failed}")
                if reason:
                    print(f"      原因: {reason}")


if __name__ == "__main__":
    main()
