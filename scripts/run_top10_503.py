#!/usr/bin/env python3
"""
爬取 2026 年 2 月安全公告前 10 个 CVE 的 5.0.3.x 修复链接。

数据来源：在线拉取 2026-02 安全公告 Markdown，按公告顺序提取每个 CVE 的 5.0.3.x 链接。
输出：output/top10_503_2026_02.json + output/top10_503_2026_02.md

用法（仓库根目录）：
    python scripts/run_top10_503.py
    python scripts/run_top10_503.py --no-llm      # 跳过 LLM 审查
    python scripts/run_top10_503.py --limit 5     # 只跑前 5 个
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (REPO_ROOT, REPO_ROOT / "src"):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from autoyara.collectors.oh_crawler.cli import (
    _apply_tokens_from_config_yaml,
)  # noqa: E402
from autoyara.collectors.oh_crawler.discovery import (
    fetch_bulletin,
    parse_all_links,
)  # noqa: E402
from autoyara.collectors.oh_crawler.pipeline import process_item  # noqa: E402
from autoyara.llm.sync_client import (
    SyncLLMClient,
    ensure_llm_api_key_or_exit,
)  # noqa: E402
from autoyara.models import (
    sync_function_line_arrays,
    to_legacy_result_dict,
)  # noqa: E402

_apply_tokens_from_config_yaml()

YEAR, MONTH = 2026, 2
VERSION_FILTER = "5.0.3"
FALLBACK_JSON = REPO_ROOT / "output" / "result_2026_02.json"


def _collect_503_from_bulletin(limit: int) -> list[tuple[str, dict]] | None:
    """从在线安全公告按公告顺序提取每个 CVE 的 5.0.3.x 链接。
    网络不通时返回 None。
    """
    print(f"[1/3] 拉取 {YEAR}-{MONTH:02d} 安全公告 …")
    md = fetch_bulletin(YEAR, MONTH)
    if not md:
        print("  [WARN] 无法获取在线公告，将回退到本地 JSON")
        return None
    print(f"  公告长度: {len(md)} 字节")
    all_links = parse_all_links(md)
    print(f"  公告共含 {len(all_links)} 条修复链接（所有版本）")

    seen: dict[str, dict] = {}
    for lk in all_links:
        cve = (lk.get("cve") or "").upper().strip()
        ver = lk.get("version_label", "")
        if not cve or VERSION_FILTER not in ver:
            continue
        if cve in seen:
            continue
        seen[cve] = {
            "url": lk.get("url", ""),
            "repo": lk.get("repo", ""),
            "severity": lk.get("severity", ""),
            "version": ver,
            "vuln_title": "",
            "vuln_type": lk.get("vuln_type", ""),
            "vuln_impact": lk.get("vuln_impact", ""),
        }
        if len(seen) >= limit:
            break
    return list(seen.items())


def _collect_503_from_local(limit: int) -> list[tuple[str, dict]]:
    """从本地 result_2026_02.json 收集 5.0.3.x 链接（公告不可达时的回退）。

    按 CVE 年份降序（2026 > 2025）排列，使 OpenHarmony 自有漏洞排在三方库前面。
    """
    if not FALLBACK_JSON.exists():
        print(f"  [ERROR] 本地回退文件不存在: {FALLBACK_JSON}")
        sys.exit(1)
    print(f"  [1/3] 从本地回退文件 {FALLBACK_JSON.name} 读取 5.0.3.x 链接 …")
    raw = json.loads(FALLBACK_JSON.read_text(encoding="utf-8"))
    items: list[dict] = raw["items"] if isinstance(raw, dict) else raw

    seen: dict[str, dict] = {}
    for it in items:
        cve = (it.get("cve") or it.get("cve_id") or "").upper().strip()
        ver = it.get("version", "")
        if not cve or VERSION_FILTER not in ver:
            continue
        if cve in seen:
            continue
        url = (it.get("reference_url") or it.get("url") or "").strip()
        if not url:
            continue
        seen[cve] = {
            "url": url,
            "repo": it.get("repo", ""),
            "severity": it.get("severity", ""),
            "version": ver,
            "vuln_title": it.get("vuln_title", ""),
            "vuln_type": it.get("vuln_type", ""),
            "vuln_impact": it.get("vuln_impact", ""),
        }

    # 保持 JSON 中公告原始顺序（已按公告逐行写入，勿再排序）
    return list(seen.items())[:limit]


def _collect_503_links(limit: int) -> list[tuple[str, dict]]:
    result = _collect_503_from_bulletin(limit)
    if result is not None:
        return result
    return _collect_503_from_local(limit)


def _build_item(cve_id: str, meta: dict) -> dict:
    url = re.sub(r"[?#].*$", "", meta["url"])
    common = {
        "cve": cve_id,
        "severity": meta.get("severity", ""),
        "version_label": meta.get("version", ""),
        "vuln_title": meta.get("vuln_title", ""),
        "vuln_type": meta.get("vuln_type", ""),
        "vuln_impact": meta.get("vuln_impact", ""),
    }
    pr_m = re.match(
        r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/(?:pulls|pull|merge_requests)/(\d+)",
        url,
        re.I,
    )
    if pr_m:
        return {
            **common,
            "url": url,
            "repo": meta.get("repo") or pr_m.group(2),
            "url_type": "pr",
        }
    cm = re.match(
        r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
        url,
        re.I,
    )
    if cm:
        return {
            **common,
            "url": url,
            "repo": meta.get("repo") or cm.group(2),
            "url_type": "commit",
            "fix_sha": cm.group(3),
        }
    return {}


def main() -> None:
    ap = argparse.ArgumentParser(
        description="爬取 2026-02 公告前 N 个 CVE 的 5.0.3.x 链接"
    )
    ap.add_argument("--limit", type=int, default=10, help="CVE 数量上限（默认 10）")
    ap.add_argument("--no-llm", action="store_true", help="跳过 LLM 质量审查")
    args = ap.parse_args()

    LIMIT = args.limit
    do_llm = not args.no_llm
    if do_llm:
        ensure_llm_api_key_or_exit()

    print("=" * 60)
    print(f"OpenHarmony 安全公告 {YEAR}-{MONTH:02d}  5.0.3.x  前 {LIMIT} 个 CVE")
    print(f"LLM 质量审查: {'启用' if do_llm else '跳过'}")
    print("=" * 60 + "\n")

    # ── 1. 从公告收集 5.0.3.x 链接（函数内已打印进度）──
    cve_list = _collect_503_links(LIMIT)
    if not cve_list:
        print("  [ERROR] 公告中未找到 5.0.3.x 链接")
        sys.exit(1)
    print(f"\n  按公告顺序取前 {len(cve_list)} 个 CVE（5.0.3.x）：")
    for cve, meta in cve_list:
        print(f"    {cve}  {meta['url'][:80]}")

    # ── 2. 逐个爬取 ──────────────────────────────────────
    print(f"\n[2/3] 开始爬取（共 {len(cve_list)} 个）…\n")
    client = SyncLLMClient() if do_llm else None
    all_results: list[dict] = []

    try:
        for idx, (cve_id, meta) in enumerate(cve_list, 1):
            item = _build_item(cve_id, meta)
            if not item:
                print(f"  [{idx}/{len(cve_list)}] {cve_id}  [SKIP] URL 格式不支持")
                continue

            print(f"  [{idx}/{len(cve_list)}] {cve_id}  ({meta.get('version', '')})")
            print(f"    url: {meta['url']}")

            t0 = time.time()
            try:
                models = process_item(item, quality_check=do_llm, llm_client=client)
            except Exception as e:
                print(f"    [ERROR] {e}")
                models = []

            elapsed = time.time() - t0
            print(f"    耗时: {elapsed:.1f}s  结果: {len(models)} 个函数")

            for m in models:
                row = to_legacy_result_dict(m)
                if m.validation is not None:
                    row["quality_ok"] = m.validation.is_valid
                    row["quality_score"] = m.validation.score
                    row["quality_reason"] = m.validation.details
                sync_function_line_arrays(row)
                all_results.append(row)

                fn = row.get("function_name", "")
                vf = row.get("vulnerable_function", "")
                ff = row.get("fixed_function", "")
                qok = row.get("quality_ok")
                qstr = "OK" if qok else "FAIL" if qok is False else "-"
                print(f"    [{qstr}] {fn}  before={len(vf)}c after={len(ff)}c")
                if row.get("quality_reason"):
                    print(f"       LLM: {row['quality_reason'][:120]}")

            time.sleep(1.0)
    finally:
        if client:
            client.close()

    # ── 3. 写结果 ────────────────────────────────────────
    print("\n[3/3] 保存结果 …")
    out_dir = REPO_ROOT / "output"
    json_path = out_dir / "top10_503_2026_02.json"
    report_path = out_dir / "top10_503_2026_02.md"

    payload = {
        "year": 2026,
        "month": 2,
        "version": "5.0.3.x",
        "total": len(all_results),
        "items": all_results,
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"  JSON → {json_path}  ({len(all_results)} 条)")

    gen = REPO_ROOT / "scripts" / "gen_report.py"
    if gen.is_file():
        r = subprocess.run(
            [sys.executable, str(gen), str(json_path), str(report_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if r.stdout:
            print(r.stdout.strip())
        if r.stderr and r.returncode != 0:
            print(r.stderr.strip())
        print(f"  报告 → {report_path}")

    print(f"\n{'=' * 60}")
    print(
        f"汇总：{len(all_results)} 个函数条目，来自 {len(cve_list)} 个 CVE（5.0.3.x）"
    )
    ok = sum(1 for r in all_results if r.get("quality_ok") is True)
    fail = sum(1 for r in all_results if r.get("quality_ok") is False)
    skip = sum(1 for r in all_results if r.get("quality_ok") is None)
    if do_llm:
        print(f"  LLM 审查: 通过={ok} 未通过={fail} 未审={skip}")
    seen_cves_out = sorted({r.get("cve") or r.get("cve_id", "") for r in all_results})
    print(f"  成功 CVE: {seen_cves_out}")
    print("=" * 60)


if __name__ == "__main__":
    main()
