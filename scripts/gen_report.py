#!/usr/bin/env python3
"""
从采集结果 JSON 生成可读的 Markdown 报告。

用法（仓库根目录）::

    python scripts/gen_report.py                          # 默认读 output/bulletin_sample.json
    python scripts/gen_report.py result.json              # 指定输入文件
    python scripts/gen_report.py result.json report.md   # 指定输入和输出
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

_DEFAULT_INPUT = REPO_ROOT / "output" / "bulletin_sample.json"
_DEFAULT_OUTPUT = REPO_ROOT / "output" / "cve_report.md"


def _resolve_input(arg: str) -> Path:
    p = Path(arg)
    if p.is_absolute():
        return p
    if p.exists():
        return p.resolve()
    alt = REPO_ROOT / arg
    if alt.exists():
        return alt
    return p.resolve()


def _code_block(code: str, lang: str = "c") -> str:
    code = (code or "").strip()
    if not code:
        return "_（未提取到代码）_\n"
    return f"```{lang}\n{code}\n```\n"


def _guess_lang(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return {
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".py": "python",
        ".rs": "rust",
        ".go": "go",
        ".java": "java",
        ".patch": "diff",
    }.get(ext, "c")


def _normalize(it: dict) -> dict:
    """兼容新旧两种字段命名。"""

    def _get(*keys: str, default: str = "") -> str:
        for k in keys:
            v = it.get(k)
            if v:
                return str(v)
        return default

    return {
        "cve": _get("cve", "cve_id"),
        "repository": _get("repo", "repository"),
        "severity": _get("severity"),
        "version": _get("version", "affected_version"),
        "file_path": _get("file", "file_path"),
        "function_name": _get("function_name"),
        "hunk_headers": it.get("hunk_headers") or [],
        "removed_lines": it.get("removed_lines") or [],
        "added_lines": it.get("added_lines") or [],
        "title": _get("vuln_title", "title"),
        "description": _get("vuln_description", "description"),
        "vuln_type": _get("vuln_type"),  # 漏洞描述（短标签）
        "vuln_impact": _get("vuln_impact"),  # 漏洞影响
        "reference_url": _get("reference_url"),
        "vulnerable_code": _get("vulnerable_function", "vulnerable_code"),
        "fixed_code": _get("fixed_function", "fixed_code"),
        "quality_ok": it.get("quality_ok"),
        "quality_score": it.get("quality_score"),
        "quality_failed": it.get("quality_failed") or [],
        "quality_reason": _get("quality_reason"),
    }


def dedup(items: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out = []
    for it in items:
        key = (
            it.get("cve", "") or it.get("cve_id", ""),
            it.get("file_path", "") or it.get("file", ""),
            it.get("function_name", ""),
            (it.get("vulnerable_function") or it.get("vulnerable_code") or "")[:64],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def main() -> None:
    args = sys.argv[1:]
    input_path = _resolve_input(args[0]) if args else _DEFAULT_INPUT
    output_path = Path(args[1]).resolve() if len(args) >= 2 else _DEFAULT_OUTPUT

    if not input_path.exists():
        print(f"找不到输入文件：{input_path}")
        print("用法：python scripts/gen_report.py [输入JSON] [输出MD]")
        sys.exit(1)

    data = json.loads(input_path.read_text(encoding="utf-8"))
    raw: list[dict] = data["items"] if isinstance(data, dict) else data
    items = [_normalize(it) for it in dedup(raw)]

    groups: dict[str, list[dict]] = {}
    for it in items:
        cve = it.get("cve") or "UNKNOWN"
        groups.setdefault(cve, []).append(it)

    lines: list[str] = []
    lines.append("# CVE 漏洞采集报告\n")
    lines.append(
        f"> 来源：`{input_path.name}`  共 **{len(items)}** 条（去重后），"
        f"涉及 **{len(groups)}** 个 CVE\n"
    )
    lines.append("---\n")

    lines.append("## 目录\n")
    for cve, its in groups.items():
        repo = its[0].get("repository", "")
        sev = its[0].get("severity", "")
        ver = its[0].get("version", "")
        ver_str = f"  `{ver}`" if ver else ""
        anchor = cve.lower().replace("-", "")
        lines.append(
            f"- [{cve}](#{anchor})  `{repo}` {sev}{ver_str}  （{len(its)} 个函数）"
        )
    lines.append("\n---\n")

    for cve, its in groups.items():
        anchor = cve.lower().replace("-", "")
        repo = its[0].get("repository", "")
        sev = its[0].get("severity", "")
        ref = its[0].get("reference_url", "")
        ver = its[0].get("version", "")
        ver_str = f"  ·  `{ver}`" if ver else ""

        lines.append(f'<a id="{anchor}"></a>\n')
        lines.append(f"## {cve}  ·  {repo}  ·  {sev}{ver_str}\n")
        if ref:
            lines.append(f"**参考链接**：<{ref}>\n")

        title = next((it.get("title", "") for it in its if it.get("title")), "")
        desc = next(
            (it.get("description", "") for it in its if it.get("description")), ""
        )
        vuln_type = next(
            (it.get("vuln_type", "") for it in its if it.get("vuln_type")), ""
        )
        vuln_impact = next(
            (it.get("vuln_impact", "") for it in its if it.get("vuln_impact")), ""
        )

        if title:
            lines.append(f"**标题**：{title}\n")

        # 漏洞描述（短标签）和漏洞影响（公告表格 or LLM 生成）
        if vuln_type or vuln_impact:
            row_parts = []
            if vuln_type:
                row_parts.append(f"漏洞描述：**{vuln_type}**")
            if vuln_impact:
                row_parts.append(f"漏洞影响：**{vuln_impact}**")
            lines.append("  ·  ".join(row_parts) + "\n")

        # 详细描述（NVD 英文描述 or PR 描述）
        if desc:
            lines.append("**详细描述**：\n")
            lines.append(f"> {desc.strip().replace(chr(10), chr(10) + '> ')}\n")
        else:
            lines.append(
                "**详细描述**：_（本条仍无描述：可能 NVD 尚未收录该 CVE、请求失败，"
                "或公告行内无文字说明）_\n"
            )

        lines.append(f"\n共涉及 **{len(its)}** 个函数／代码区域：\n")

        for j, it in enumerate(its, 1):
            func = it.get("function_name") or "（无函数名）"
            fpath = it.get("file_path", "")
            lang = _guess_lang(fpath)
            hunks = it.get("hunk_headers") or []
            added = len(it.get("added_lines") or [])
            removed = len(it.get("removed_lines") or [])

            vuln_code = (it.get("vulnerable_code") or "").strip()
            fixed_code = (it.get("fixed_code") or "").strip()
            is_patch_ctx = vuln_code.startswith("/* patch context")

            q_ok = it.get("quality_ok")
            q_score = it.get("quality_score")
            q_failed = it.get("quality_failed") or []
            q_reason = it.get("quality_reason", "")

            lines.append(f"### {j}. `{func}`\n")
            lines.append(
                f"**文件**：`{fpath}`  |  **变更**：+{added} / -{removed} 行\n"
            )
            if hunks:
                lines.append(
                    "**Hunk 位置**：" + "、".join(f"`{h}`" for h in hunks) + "\n"
                )

            if q_ok is not None:
                if q_score is None and q_ok is False:
                    lines.append(
                        "**质量审查**：[未评定]（LLM 接口未成功，"
                        "不代表描述或函数不合格；请检查 API Key / 网络）"
                    )
                else:
                    badge = "[OK]" if q_ok else "[FAIL]"
                    score_str = (
                        f"  评分 {q_score:.2f}"
                        if isinstance(q_score, int | float)
                        else ""
                    )
                    lines.append(f"**质量审查**：{badge}{score_str}")
                if q_failed:
                    lines.append(f"  不合格字段：{', '.join(q_failed)}")
                if q_reason:
                    lines.append(f"  原因：{q_reason}")
                lines.append("\n")

            if is_patch_ctx:
                lines.append("\n#### 代码变更（diff 上下文，源文件不可用）\n")
                removed_lines = it.get("removed_lines") or []
                added_lines = it.get("added_lines") or []
                if removed_lines or added_lines:
                    lines.append("```diff")
                    for r in removed_lines:
                        lines.append(f"- {r.get('code', '')}")
                    for a in added_lines:
                        lines.append(f"+ {a.get('code', '')}")
                    lines.append("```\n")
                if vuln_code:
                    lines.append(
                        "<details><summary>修复前上下文窗口（展开）</summary>\n"
                    )
                    lines.append(_code_block(vuln_code, lang))
                    lines.append("</details>\n")
                if fixed_code:
                    lines.append(
                        "<details><summary>修复后上下文窗口（展开）</summary>\n"
                    )
                    lines.append(_code_block(fixed_code, lang))
                    lines.append("</details>\n")
                if (
                    not removed_lines
                    and not added_lines
                    and not vuln_code
                    and not fixed_code
                ):
                    lines.append("_（无行级变更记录）_\n")
            else:
                lines.append("\n#### 漏洞函数（修复前）\n")
                lines.append(_code_block(vuln_code, lang))

                lines.append("\n#### 修复函数（修复后）\n")
                lines.append(_code_block(fixed_code, lang))

                lines.append("\n#### 关键变更行\n")
                removed_lines = it.get("removed_lines") or []
                added_lines = it.get("added_lines") or []
                if removed_lines or added_lines:
                    lines.append("```diff")
                    for r in removed_lines:
                        lines.append(f"- {r.get('code', '')}")
                    for a in added_lines:
                        lines.append(f"+ {a.get('code', '')}")
                    lines.append("```\n")
                else:
                    lines.append("_（无行级变更记录）_\n")

            lines.append("\n---\n")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"报告已生成：{output_path}  （共 {len(items)} 条，{len(groups)} 个 CVE）")


if __name__ == "__main__":
    main()
