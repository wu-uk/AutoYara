import argparse
import io
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from autoyara.llm.sync_client import SyncLLMClient, ensure_llm_api_key_or_exit
from autoyara.models import sync_function_line_arrays, to_legacy_result_dict

from .discovery import fetch_bulletin, parse_all_links
from .pipeline import process_item

# cli.py → …/src/autoyara/collectors/oh_crawler/cli.py → 仓库根为 parents[4]
_REPO_ROOT = Path(__file__).resolve().parents[4]


def _apply_tokens_from_config_yaml() -> None:
    """若环境变量未设置，则从仓库根 ``configs/config.yaml`` 注入 GitCode/GitHub 令牌。"""
    try:
        from configs.config import settings
    except Exception:
        return
    if not (os.environ.get("GITCODE_PRIVATE_TOKEN") or os.environ.get("GITCODE_TOKEN")):
        gc = getattr(settings, "gitcode_private_token", "") or ""
        if gc.strip():
            os.environ["GITCODE_PRIVATE_TOKEN"] = gc.strip()
    if not (os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_API_TOKEN")):
        gh = getattr(settings, "github_token", "") or ""
        if gh.strip():
            os.environ["GITHUB_TOKEN"] = gh.strip()
    if not (os.environ.get("GITEE_ACCESS_TOKEN") or os.environ.get("GITEE_TOKEN")):
        gt = getattr(settings, "gitee_access_token", "") or ""
        if gt.strip():
            os.environ["GITEE_ACCESS_TOKEN"] = gt.strip()


def _run_gen_report(json_file: str, report_file: str) -> None:
    """调用 scripts/gen_report.py 生成 Markdown。"""
    script = _REPO_ROOT / "scripts" / "gen_report.py"
    if not script.is_file():
        print(f"[warn] 未找到 {script}，跳过 --report")
        return
    jp = Path(json_file)
    rp = Path(report_file)
    if not jp.is_absolute():
        jp = Path.cwd() / jp
    if not rp.is_absolute():
        rp = Path.cwd() / rp
    print(f"\n[report] 生成 {rp} …")
    r = subprocess.run(
        [sys.executable, str(script), str(jp), str(rp)],
        cwd=str(_REPO_ROOT),
    )
    if r.returncode != 0:
        print(f"[warn] gen_report 退出码 {r.returncode}")


def print_result(r):
    sep = "=" * 65
    print()
    print(sep)
    print("[3] CVE      : " + r["cve"])
    print("    Repo     : " + r["repo"])
    print("    File     : " + r["file"])
    print("    Function : " + r["function_name"])
    print("    Version  : " + r["version"])
    print("    Severity : " + r["severity"])
    for hdr in r.get("hunk_headers", []):
        print("    Hunk     : " + hdr)
    if r.get("vuln_title"):
        print("    VulnTitle: " + r["vuln_title"])
    if r.get("vuln_cve_hint"):
        print("    CVE(Hint): " + r["vuln_cve_hint"])
    if r.get("vuln_description"):
        print("\n    Vulnerability Description:")
        for ln in r["vuln_description"].splitlines():
            print("      " + ln)
    if r["removed_lines"]:
        print("\n    Key change (removed):")
        for x in r["removed_lines"]:
            if x["code"].strip() not in ("", "-", "- "):
                print(f"      {x['lineno']:4d}-  {x['code']}")
    if r["added_lines"]:
        print("    Key change (added):")
        for x in r["added_lines"]:
            print(f"      {x['lineno']:4d}+  {x['code']}")
    print("\n[1] VULNERABLE FUNCTION (before fix):")
    print(r["vulnerable_function"])
    print("\n[2] FIXED FUNCTION (after fix):")
    print(r["fixed_function"])
    print(sep)


def main(argv=None):
    # 保证能 import configs；项目根须在 sys.path（pip install -e . 或从仓库根运行）
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    _apply_tokens_from_config_yaml()

    print("=" * 60)
    print("  OpenHarmony CVE Crawler v16")
    print("  GitCode：GITCODE_PRIVATE_TOKEN + API 拉取 commit diff / 源码 blob")
    print("  父提交优先 GitHub API；无旧源码时用 new+diff 反向合成父文件")
    print("  @@ hint 函数名解析：取 kill_kprobe 而非 static")
    print("=" * 60)

    ap = argparse.ArgumentParser(
        description="爬取 OpenHarmony 安全公告中的 CVE 链接并提取漏洞/修复函数"
    )
    ap.add_argument("--year", type=int, help="年份，如 2026")
    ap.add_argument("--month", type=int, help="月份 1-12")
    ap.add_argument("--json", metavar="FILE", help="导出 JSON，如 result.json")
    ap.add_argument(
        "--report",
        metavar="FILE",
        help="生成 Markdown 报告（与 --json 联用，调用 scripts/gen_report.py）",
    )
    ap.add_argument("--txt", metavar="FILE", help="导出 TXT 报告（可选）")
    ap.add_argument("--max", type=int, help="最多处理几条链接（默认全部）")
    ap.add_argument(
        "--commit-url",
        metavar="URL",
        help="只处理一条 commit 链接（如 GitCode 某次提交，可配 --patch）",
    )
    ap.add_argument(
        "--patch",
        metavar="FILE",
        help="本地 unified diff（.patch/.diff），与 --commit-url 一起用可跳过在线拉取 patch",
    )
    ap.add_argument(
        "--cve",
        default="MANUAL",
        help="与 --commit-url 联用时的 CVE 标识（默认 MANUAL）",
    )
    ap.add_argument(
        "--quality-check",
        action="store_true",
        help="爬取后调用 LLM 审查每条结果的完整性（需配置 config.yaml）",
    )
    cli = ap.parse_args(argv)
    use_cli = (cli.year is not None and cli.month is not None) or (
        (cli.commit_url or "").strip() != ""
    )

    if use_cli and (cli.commit_url or "").strip():
        year, month = 2026, 1
        json_out = (cli.json or "").strip() or None
        report_out = (cli.report or "").strip() or None
        txt_out = (cli.txt or "").strip() or None
        mx = 1
        cu = (cli.commit_url or "").strip()
        patch_body = None
        pf = (cli.patch or "").strip()
        if pf:
            try:
                with open(pf, encoding="utf-8", errors="replace") as f:
                    patch_body = f.read()
            except Exception as e:
                print("ERROR: cannot read --patch: " + str(e))
                sys.exit(1)
            if "diff --git" not in patch_body:
                print("ERROR: --patch file must contain unified diff (diff --git)")
                sys.exit(1)
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
            re.sub(r"[?#].*$", "", cu),
            re.I,
        )
        if not m:
            print(
                "ERROR: --commit-url must be gitee/gitcode .../owner/repo/commit/<sha>"
            )
            sys.exit(1)
        owner, repo, sha = m.group(1), m.group(2), m.group(3)
        all_links = [
            {
                "cve": (cli.cve or "MANUAL").strip() or "MANUAL",
                "repo": repo,
                "severity": "",
                "version_label": "manual",
                "url": cu,
                "url_type": "commit",
                "fix_sha": sha,
                "patch_body": patch_body,
            }
        ]
        print(
            "\n[CLI] commit-url mode owner={} repo={} sha={} patch_file={}".format(
                owner, repo, sha[:12], pf or "(none)"
            )
        )
    elif use_cli:
        year, month = cli.year, cli.month
        if not (2020 <= year <= 2030):
            print("ERROR: year must be 2020-2030")
            sys.exit(1)
        if not (1 <= month <= 12):
            print("ERROR: month must be 1-12")
            sys.exit(1)
        json_out = (cli.json or "").strip() or None
        report_out = (cli.report or "").strip() or None
        txt_out = (cli.txt or "").strip() or None
        mx = cli.max
        print(
            f"\n[CLI] year={year} month={month} json={json_out} "
            f"report={report_out} txt={txt_out} max={mx}"
        )
    else:
        while True:
            try:
                year = int(input("\nYear (e.g. 2025): "))
                if 2020 <= year <= 2030:
                    break
                print("  Please enter 2020-2030")
            except ValueError:
                print("  Invalid number")

        while True:
            try:
                month = int(input("Month (1-12): "))
                if 1 <= month <= 12:
                    break
                print("  Please enter 1-12")
            except ValueError:
                print("  Invalid number")

        print("\n[Optional] Output files (press Enter to skip)")
        json_out = input("  JSON (e.g. result.json): ").strip() or None
        txt_out = input("  TXT  (e.g. report.txt):  ").strip() or None
        report_out = None
        mx_input = input("\nMax CVE links to process (Enter=all): ").strip()
        mx = int(mx_input) if mx_input.isdigit() else None

    commit_url_mode = use_cli and (cli.commit_url or "").strip() != ""
    do_quality_check = getattr(cli, "quality_check", False)

    if not commit_url_mode:
        md = fetch_bulletin(year, month)
        if not md:
            print("ERROR: cannot fetch bulletin")
            sys.exit(1)

        all_links = parse_all_links(md)
        cve_set = {x["cve"] for x in all_links}
        print(f"\n== Found {len(all_links)} links across {len(cve_set)} CVEs ==")
        for x in all_links:
            print(
                f"  {x['cve']:<20} [{x['url_type']:<7}] {x['version_label'][:8]:<8} -> {x['url'][:60]}"
            )
    else:
        print(f"\n== Single commit mode: {len(all_links)} link(s) ==")
        for x in all_links:
            print(
                f"  {x['cve']:<20} [{x['url_type']:<7}] {x['version_label'][:8]:<8} -> {x['url'][:60]}"
            )

    if mx:
        all_links = all_links[:mx]

    all_results = []
    incomplete_results = []

    if do_quality_check:
        ensure_llm_api_key_or_exit()
        print("\n[质量审查] 已启用 LLM 审查，结果将标注完整性")
    llm_client = SyncLLMClient() if do_quality_check else None

    try:
        for i, item in enumerate(all_links, 1):
            print(
                f"\n[{i}/{len(all_links)}] {item['cve']} [{item['url_type']}] {item['version_label']}"
            )
            funcs = process_item(
                item, quality_check=do_quality_check, llm_client=llm_client
            )
            if funcs:
                for f in funcs:
                    row = to_legacy_result_dict(f)
                    if f.validation is not None:
                        row["quality_ok"] = f.validation.is_valid
                        row["quality_score"] = f.validation.score
                        row["quality_failed"] = f.validation.failed_checks
                        row["quality_reason"] = f.validation.details
                        if not f.validation.is_valid:
                            incomplete_results.append(row)
                    print_result(row)
                    all_results.append(row)
            else:
                placeholder = {
                    "cve": item["cve"],
                    "repo": item["repo"],
                    "severity": item["severity"],
                    "version": item["version_label"],
                    "file": "(unavailable)",
                    "function_name": "(unavailable)",
                    "hunk_headers": [],
                    "removed_lines": [],
                    "added_lines": [],
                    "vuln_title": "",
                    "vuln_description": "",
                    "vuln_cve_hint": "",
                    "vulnerable_function": "(diff fetch failed - {}: {})".format(
                        item["url_type"], item["url"]
                    ),
                    "fixed_function": "(diff fetch failed)",
                }
                sync_function_line_arrays(placeholder)
                print("  [!] no diff - saved as placeholder")
                all_results.append(placeholder)
            if i < len(all_links):
                time.sleep(1.0)
    finally:
        if llm_client is not None:
            llm_client.close()

    if do_quality_check:
        total = len(all_results)
        ok = total - len(incomplete_results)
        print(
            f"\n[质量审查] 完整: {ok}/{total}  不完整: {len(incomplete_results)}/{total}"
        )
        if incomplete_results:
            print("  不完整条目：")
            for r in incomplete_results:
                print(
                    f"    {r['cve']} / {r['function_name']} — {r.get('quality_reason', '')}"
                )

    if txt_out:
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        for r in all_results:
            print_result(r)
        sys.stdout = old
        with open(txt_out, "w", encoding="utf-8") as f:
            f.write(buf.getvalue())
        print("\n[OK] TXT: " + txt_out)

    if json_out:
        for r in all_results:
            sync_function_line_arrays(r)
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "year": year,
                    "month": month,
                    "total": len(all_results),
                    "items": all_results,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        print("[OK] JSON: " + json_out)
        if report_out:
            _run_gen_report(json_out, report_out)
    elif (cli.report or "").strip():
        print("[warn] 已指定 --report 但未指定 --json，跳过 Markdown 生成")

    print(
        f"\nDone. {len(all_results)} functions, {len({r['cve'] for r in all_results})} CVEs."
    )


if __name__ == "__main__":
    main()
