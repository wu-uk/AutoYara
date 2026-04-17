#!/usr/bin/env python3
"""
爬取 2026 年 2 月安全公告前 10 个 CVE 的完整漏洞函数（含 LLM 质量审查）。

用法（仓库根目录）：
    python scripts/run_top10_feb.py
    python scripts/run_top10_feb.py --no-llm       # 跳过 LLM 审查，更快
    python scripts/run_top10_feb.py --limit 5      # 只跑前 5 个
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (REPO_ROOT, REPO_ROOT / "src"):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

# 确保 UTF-8 输出（-X utf8 或手动重配置）
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# sys.path 修改后的延迟导入（scripts 目录已在 pyproject.toml 中豁免 E402）
from autoyara.collectors.oh_crawler.cli import _apply_tokens_from_config_yaml
from autoyara.collectors.oh_crawler.discovery import fetch_bulletin, parse_all_links
from autoyara.collectors.oh_crawler.pipeline import process_item
from autoyara.llm.sync_client import SyncLLMClient, ensure_llm_api_key_or_exit
from autoyara.models import sync_function_line_arrays, to_legacy_result_dict

_apply_tokens_from_config_yaml()


def build_item(cve_id: str, url: str, meta: dict) -> dict:
    """从公告链接构建 crawler_item，透传 vuln_type/vuln_impact 等公告元数据。"""
    url = re.sub(r"[?#].*$", "", url.strip())
    # 公告表格中的短标签字段
    common = {
        "cve": cve_id,
        "severity": meta.get("severity", ""),
        "version_label": meta.get("version_label", meta.get("version", "")),
        "vuln_title": meta.get("vuln_title", meta.get("title", "")),
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
    ap = argparse.ArgumentParser(description="爬取 2026-02 公告前 N 个 CVE")
    ap.add_argument(
        "--limit", type=int, default=10, help="爬取 CVE 数量上限（默认 10）"
    )
    ap.add_argument("--no-llm", action="store_true", help="跳过 LLM 质量审查")
    ap.add_argument("--log", default="", help="同时写日志到文件")
    args = ap.parse_args()

    YEAR, MONTH = 2026, 2
    LIMIT = args.limit
    do_llm = not args.no_llm
    if do_llm:
        ensure_llm_api_key_or_exit()

    # 双写日志
    import builtins as _builtins

    _real_print = _builtins.print  # 先保存原始 print，再覆盖
    _log_fh = None
    if args.log:
        _log_path = Path(args.log)
        _log_path.parent.mkdir(parents=True, exist_ok=True)
        _log_fh = open(_log_path, "w", encoding="utf-8", buffering=1)

    def _p(*a, **kw):
        _real_print(*a, **kw)
        if _log_fh:
            kw2 = {k: v for k, v in kw.items() if k != "file"}
            _real_print(*a, file=_log_fh, **kw2)

    _builtins.print = _p

    print(f"{'=' * 60}")
    print(f"OpenHarmony 安全公告 {YEAR}-{MONTH:02d}  前 {LIMIT} 个 CVE")
    print(f"LLM 质量审查: {'启用' if do_llm else '跳过'}")
    print(f"{'=' * 60}\n")

    # ── 1. 拉公告 ───────────────────────────────────
    print("[1/4] 拉取安全公告 Markdown …")
    md = fetch_bulletin(YEAR, MONTH)
    if not md:
        print("  [ERROR] 无法获取公告，退出")
        sys.exit(1)
    print(f"  公告长度: {len(md)} 字节")

    # ── 2. 解析链接 ──────────────────────────────────
    print("\n[2/4] 解析 CVE 修复链接 …")
    all_links = parse_all_links(md)  # list of CrawlerItem-like dict
    print(f"  公告共含 {len(all_links)} 条链接")

    # 去重：每个 CVE 只取第一条（通常是 6.0.x 主版本）
    seen_cve: dict[str, dict] = {}
    for lk in all_links:
        cve = (lk.get("cve") or lk.get("cve_id") or "").upper()
        if cve and cve not in seen_cve:
            seen_cve[cve] = lk

    cve_list = list(seen_cve.items())[:LIMIT]
    print(f"  去重后取前 {len(cve_list)} 个 CVE：")
    for cve, lk in cve_list:
        print(f"    {cve}  {lk.get('url', '')[:80]}")

    # ── 3. 逐个爬取 ──────────────────────────────────
    print(f"\n[3/4] 开始爬取（共 {len(cve_list)} 个）…\n")
    client = SyncLLMClient() if do_llm else None
    all_results: list[dict] = []

    try:
        for idx, (cve_id, lk) in enumerate(cve_list, 1):
            url = lk.get("url") or lk.get("reference_url") or ""
            if not url:
                print(f"  [{idx}/{len(cve_list)}] {cve_id} 无 URL，跳过")
                continue

            print(f"  [{idx}/{len(cve_list)}] {cve_id}")
            print(f"    url: {url}")

            item = build_item(cve_id, url, lk)
            if not item:
                print("    [SKIP] URL 格式不识别")
                continue

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
                qstr = "✓" if qok else "✗" if qok is False else "-"
                vtype = row.get("vuln_type", "")
                impact = row.get("vuln_impact", "")
                print(f"    [{qstr}] {fn}  before={len(vf)}c after={len(ff)}c")
                if vtype or impact:
                    print(f"       漏洞描述: {vtype}  漏洞影响: {impact}")
                if row.get("quality_reason"):
                    print(f"       LLM: {row['quality_reason'][:120]}")

            time.sleep(1.0)  # 礼貌间隔
    finally:
        if client:
            client.close()

    # ── 4. 写结果 ────────────────────────────────────
    print("\n[4/4] 保存结果 …")
    out_dir = REPO_ROOT / "output"
    out_dir.mkdir(exist_ok=True)

    json_path = out_dir / "top10_2026_02.json"
    report_path = out_dir / "top10_2026_02.md"

    payload = {
        "year": YEAR,
        "month": MONTH,
        "total": len(all_results),
        "items": all_results,
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"  JSON → {json_path}  ({len(all_results)} 条)")

    # 生成 Markdown 报告
    gen = REPO_ROOT / "scripts" / "gen_report.py"
    if gen.is_file():
        import subprocess

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

    # ── 汇总打印 ─────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"汇总：{len(all_results)} 个函数条目，来自 {len(cve_list)} 个 CVE")
    ok = sum(1 for r in all_results if r.get("quality_ok") is True)
    fail = sum(1 for r in all_results if r.get("quality_ok") is False)
    skip = sum(1 for r in all_results if r.get("quality_ok") is None)
    if do_llm:
        print(f"  LLM 审查: 通过={ok} 未通过={fail} 未审={skip}")
    seen_cves_out = sorted({r.get("cve") or r.get("cve_id", "") for r in all_results})
    print(f"  成功 CVE: {seen_cves_out}")
    print(f"{'=' * 60}")

    # 恢复原始 print
    _builtins.print = _real_print
    if _log_fh:
        _log_fh.close()


if __name__ == "__main__":
    main()
