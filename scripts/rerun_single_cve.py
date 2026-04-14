#!/usr/bin/env python3
"""
重新爬取单条 CVE，并把结果合并回已有的 JSON 文件，最后重新生成报告。

用法（在仓库根目录执行）：
    # 从 JSON 里读取 URL（需要 JSON 里已有 reference_url 字段）
    python scripts/rerun_single_cve.py CVE-2026-22695 output/result_2026_03.json

    # 手动指定 URL（推荐；commit 或 gitcode/gitee PR 均可）
    python scripts/rerun_single_cve.py CVE-2026-22695 output/result_2026_03.json ^
        --url https://gitcode.com/openharmony/third_party_libpng/commit/abc123

    # 多条链接（如多版本 PR）可重复 --url；不写则从 JSON 的 reference_url 或
    # “diff fetch failed - pr: …” 占位行里自动提取

    # 同时指定报告输出路径
    python scripts/rerun_single_cve.py CVE-2026-22695 output/result_2026_03.json ^
        --url https://... --report output/report_2026_03.md
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
# 项目根：加载 configs.config（API Key）；src：加载 autoyara 包
for p in (REPO_ROOT, REPO_ROOT / "src"):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

from autoyara.collectors.oh_crawler.cli import (  # noqa: E402
    _apply_tokens_from_config_yaml,
)
from autoyara.collectors.oh_crawler.pipeline import process_item  # noqa: E402
from autoyara.llm.sync_client import SyncLLMClient  # noqa: E402
from autoyara.models import (
    sync_function_line_arrays,
    to_legacy_result_dict,
)  # noqa: E402

_apply_tokens_from_config_yaml()


def _find_url_from_items(items: list[dict], cve_id: str) -> str:
    """从 JSON 条目里找第一条 reference_url / url。"""
    for it in items:
        if (
            it.get("cve", "").upper() == cve_id
            or it.get("cve_id", "").upper() == cve_id
        ):
            u = it.get("reference_url", "") or it.get("url", "")
            if u:
                return u
    return ""


def _url_from_failed_placeholder(it: dict) -> str:
    """从「diff fetch failed - pr/commit: <url>」类占位字符串里取出链接。"""
    vf = (it.get("vulnerable_function") or "").strip()
    m = re.search(
        r"\(diff fetch failed - (?:pr|commit):\s*(https?://[^)]+)\)",
        vf,
        re.I,
    )
    if m:
        return m.group(1).strip().rstrip(").")
    return ""


def _discover_url_meta_pairs(old_items: list[dict]) -> list[tuple[str, dict]]:
    """每条旧记录对应一个待爬链接，并按 (URL, 版本) 去重，避免重复处理同一 PR/commit。"""
    pairs: list[tuple[str, dict]] = []
    seen: set[tuple[str, str]] = set()
    for it in old_items:
        u = (it.get("reference_url") or it.get("url") or "").strip()
        if not u:
            u = _url_from_failed_placeholder(it)
        if not u:
            continue
        version = (it.get("version") or "").strip()
        key = (u, version)
        if key in seen:
            continue
        seen.add(key)
        pairs.append((u, it))
    return pairs


def _build_crawler_item(
    url: str,
    cve_id: str,
    meta_it: dict,
    *,
    patch_body: str | None,
) -> dict:
    url = re.sub(r"[?#].*$", "", url.strip())
    pr_m = re.match(
        r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/(?:pulls|pull|merge_requests)/(\d+)",
        url,
        re.I,
    )
    if pr_m:
        _, repo, _ = pr_m.group(1), pr_m.group(2), pr_m.group(3)
        item: dict = {
            "url": url,
            "cve": cve_id,
            "repo": meta_it.get("repo") or repo,
            "severity": meta_it.get("severity", ""),
            "version_label": meta_it.get("version", ""),
            "vuln_title": meta_it.get("vuln_title", ""),
            "url_type": "pr",
        }
        if patch_body:
            item["patch_body"] = patch_body
        return item
    cm = re.match(
        r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
        url,
        re.I,
    )
    if not cm:
        raise SystemExit(
            f"  错误：URL 格式不支持（需要 gitee/gitcode 的 commit 或 PR）\n  URL: {url}"
        )
    repo, sha = cm.group(2), cm.group(3)
    item = {
        "url": url,
        "cve": cve_id,
        "repo": meta_it.get("repo", repo),
        "severity": meta_it.get("severity", ""),
        "version_label": meta_it.get("version", ""),
        "vuln_title": meta_it.get("vuln_title", ""),
        "url_type": "commit",
        "fix_sha": sha,
    }
    if patch_body:
        item["patch_body"] = patch_body
    return item


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        description="重新爬取单条 CVE 并更新 JSON + 报告",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("cve_id", help="CVE 编号，如 CVE-2026-22695")
    ap.add_argument(
        "json_path", help="已有 JSON 结果文件路径，如 output/result_2026_03.json"
    )
    ap.add_argument(
        "--url",
        action="append",
        dest="urls",
        metavar="URL",
        default=None,
        help="gitee/gitcode commit 或 PR；可重复；不填则从 JSON 推断",
    )
    ap.add_argument(
        "--patch",
        metavar="FILE",
        help="本地 .diff/.patch 文件（配合 --url 跳过在线拉取）",
    )
    ap.add_argument(
        "--report", metavar="FILE", help="报告输出路径（默认同 JSON 同名 .md）"
    )
    ap.add_argument("--no-quality-check", action="store_true", help="跳过 LLM 质量审查")
    args = ap.parse_args()

    cve_id = args.cve_id.upper()
    json_path = Path(args.json_path)
    if not json_path.is_absolute():
        json_path = REPO_ROOT / json_path

    report_path = Path(args.report) if args.report else json_path.with_suffix(".md")
    if not report_path.is_absolute():
        report_path = REPO_ROOT / report_path

    if not json_path.exists():
        print(f"找不到文件: {json_path}")
        sys.exit(1)

    raw = json.loads(json_path.read_text(encoding="utf-8"))
    items: list[dict] = raw["items"] if isinstance(raw, dict) else raw

    # 找到旧条目
    old_items = [
        it
        for it in items
        if it.get("cve", "").upper() == cve_id or it.get("cve_id", "").upper() == cve_id
    ]
    if not old_items:
        print(f"在 {json_path.name} 中找不到 {cve_id}")
        print(
            "现有 CVE：", sorted({it.get("cve", it.get("cve_id", "")) for it in items})
        )
        sys.exit(1)

    print(f"\n[rerun] CVE: {cve_id}，找到 {len(old_items)} 条旧记录")

    first = old_items[0]
    pairs: list[tuple[str, dict]] = []
    if args.urls:
        for i, u in enumerate(args.urls):
            u = (u or "").strip()
            if not u:
                continue
            meta = old_items[min(i, len(old_items) - 1)]
            pairs.append((u, meta))
    else:
        pairs = _discover_url_meta_pairs(old_items)
        if not pairs:
            u0 = _find_url_from_items(items, cve_id)
            if u0:
                pairs = [(u0, first)]

    if not pairs:
        print(
            f"  错误：找不到 {cve_id} 的可爬链接\n"
            f"  请用 --url 指定，例如：\n"
            f"    python scripts/rerun_single_cve.py {cve_id} {args.json_path} "
            f"--url https://gitcode.com/openharmony/<repo>/commit/<sha>\n"
            f"    或 --url https://gitcode.com/openharmony/<repo>/pulls/<n>"
        )
        sys.exit(1)

    patch_body = None
    patch_file = (args.patch or "").strip()
    if patch_file:
        if len(pairs) != 1:
            print("  错误：--patch 仅支持与单条 --url 同时使用")
            sys.exit(1)
        pf = Path(patch_file)
        if not pf.is_absolute():
            pf = REPO_ROOT / pf
        if not pf.exists():
            print(f"  错误：找不到 patch 文件: {pf}")
            sys.exit(1)
        patch_body = pf.read_text(encoding="utf-8", errors="replace")
        if "diff --git" not in patch_body:
            print(f"  错误：patch 文件不包含 unified diff (diff --git)\n  文件: {pf}")
            sys.exit(1)
        print(f"  本地 patch: {pf.name}  ({len(patch_body)} 字节)")

    do_qc = not args.no_quality_check
    print(f"  质量审查: {'启用' if do_qc else '跳过'}")
    print(f"  待处理链接数: {len(pairs)}")
    for u, meta in pairs:
        print(f"    - {meta.get('version', '')!s}  {u[:88]}")

    client = SyncLLMClient() if do_qc else None
    all_new_models = []
    try:
        for idx, (url, meta_it) in enumerate(pairs):
            pb = patch_body if idx == 0 and patch_body else None
            crawler_item = _build_crawler_item(url, cve_id, meta_it, patch_body=pb)
            print(f"\n  [{idx + 1}/{len(pairs)}] 重新处理…")
            chunk = process_item(crawler_item, quality_check=do_qc, llm_client=client)
            if chunk:
                all_new_models.extend(chunk)
    finally:
        if client:
            client.close()

    if not all_new_models:
        print("[rerun] 处理结果为空，保持原有数据不变")
        sys.exit(1)

    print(f"\n[rerun] 新提取到 {len(all_new_models)} 个函数条目")

    new_dicts = []
    for model in all_new_models:
        row = to_legacy_result_dict(model)
        if model.validation is not None:
            row["quality_ok"] = model.validation.is_valid
            row["quality_score"] = model.validation.score
            row["quality_failed"] = model.validation.failed_checks
            row["quality_reason"] = model.validation.details
        sync_function_line_arrays(row)
        new_dicts.append(row)

    # 打印摘要
    for nd in new_dicts:
        func = nd.get("function_name", "")
        vf = nd.get("vulnerable_function", "")
        ff = nd.get("fixed_function", "")
        qok = nd.get("quality_ok")
        same = vf.strip() == ff.strip()
        qok_str = "OK" if qok else "FAIL" if qok is False else "-"
        same_str = "WARNING same" if same else "OK different"
        print(f"  Function : {func}")
        print(
            f"  Before   : {len(vf)} chars  After: {len(ff)} chars  Quality: {qok_str}"
        )
        print(f"  Diff     : {same_str}")
        if nd.get("quality_reason"):
            print(f"  LLM note : {nd['quality_reason']}")

    # 找到插入位置（替换旧条目）
    insert_pos = next(
        (
            i
            for i, it in enumerate(items)
            if it.get("cve", "").upper() == cve_id
            or it.get("cve_id", "").upper() == cve_id
        ),
        len(items),
    )
    updated_items = (
        list(items[:insert_pos])
        + new_dicts
        + [
            it
            for it in items[insert_pos:]
            if it.get("cve", "").upper() != cve_id
            and it.get("cve_id", "").upper() != cve_id
        ]
    )

    # 写回 JSON
    if isinstance(raw, dict):
        raw["items"] = updated_items
        out_data = raw
    else:
        out_data = updated_items

    json_path.write_text(
        json.dumps(out_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\n[rerun] JSON 已更新: {json_path}")
    print(f"  旧条目 {len(old_items)} 条 → 新条目 {len(new_dicts)} 条")

    # 重新生成报告
    print("\n[rerun] 重新生成报告...")
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "gen_report.py"),
            str(json_path),
            str(report_path),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip())

    print(f"\n[rerun] 完成！报告: {report_path}")


if __name__ == "__main__":
    main()
