from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, cast

from autoyara.models import CVEItem

from ..analysis import (
    build_versions_from_diff,
    diff_hunk_lines_embedded,
    extract_function_for_hunks,
    fetch_source,
    fetch_source_upstream,
    get_parent_sha,
    get_parent_sha_upstream,
    get_upstream_commit_from_patch,
    parent_source_from_diff,
    realign_hunks_new_starts,
)
from .context import DiffPipelineContext

# 这些扩展名表示文件本身就是 patch/diff，不含真正的源码函数
_PATCH_EXTENSIONS = {".patch", ".diff"}


def _is_patch_file(filepath: str) -> bool:
    return Path(filepath).suffix.lower() in _PATCH_EXTENSIONS


def process_file_hunks(
    ctx: DiffPipelineContext, filepath: str, fhunks: list[dict[str, Any]]
) -> list[CVEItem]:
    oh_repo = ctx.oh_repo
    fix_sha = ctx.fix_sha
    gh_owner = ctx.gh_owner
    diff = ctx.diff
    item = ctx.item
    url = ctx.url
    vuln_meta = ctx.vuln_meta

    is_patch_file = _is_patch_file(filepath)
    reconstructed: str | None = None
    fh_use: list[dict[str, Any]] = list(fhunks)

    # ── 1. 拉取源文件两个版本 ──────────────────────────────────────────────
    new_src: str | None = None  # 修复后完整源文件
    old_src: str | None = None  # 修复前完整源文件

    if not is_patch_file:
        new_src = fetch_source(oh_repo, filepath, fix_sha, gh_owner)
        parent_sha = get_parent_sha(oh_repo, fix_sha, gh_owner=gh_owner)
        if parent_sha:
            old_src = fetch_source(oh_repo, filepath, parent_sha, gh_owner)

        upstream_sha = get_upstream_commit_from_patch(diff) if diff else None
        if upstream_sha:
            print("  [upstream] commit: " + upstream_sha[:12])
            if not old_src:
                up_parent, up_repo = get_parent_sha_upstream(upstream_sha)
                if up_parent:
                    old_src = fetch_source_upstream(
                        filepath, up_parent, up_repo or "torvalds/linux"
                    )
            if not new_src:
                new_src = fetch_source_upstream(
                    filepath, upstream_sha, "torvalds/linux"
                )

        # old_src 与 new_src 内容相同 → 未能获取修复前，丢弃 old_src
        if old_src and new_src and old_src.strip() == new_src.strip():
            print("  [warn] old_src == new_src，尝试 reconstruct 恢复旧版")
            old_src = None

        # 用 new+diff 恢复父版本（与补丁一致）；先对齐 @@ 与当前 new_src
        if new_src and fhunks:
            fh_use = realign_hunks_new_starts(new_src, fhunks)
            reconstructed = parent_source_from_diff(new_src, fh_use)
        if new_src and not old_src and reconstructed:
            old_src = reconstructed

    old_from_diff = reconstructed

    # ── 2. 按 function_hint 分组 hunk ────────────────────────────────────
    func_hunks: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for h in fh_use:
        func_hunks[h["function_hint"]].append(h)

    # ── 3. 逐函数构造 CVEItem ────────────────────────────────────────────
    results: list[CVEItem] = []
    for func_hint, fh_list in func_hunks.items():
        hint = cast(str, func_hint)
        old_ref = max(cast(int, h["old_start"]) for h in fh_list)
        new_ref = max(cast(int, h["new_start"]) for h in fh_list)
        old_src_eff = old_from_diff if old_from_diff else old_src

        vuln_func: str = ""
        fixed_func: str = ""
        is_complete: bool = False

        if is_patch_file:
            # patch 文件本身：用 diff 窗口，不完整
            vuln_func, fixed_func = build_versions_from_diff(fh_list, full_src=None)
            is_complete = False

        elif old_src_eff and new_src:
            # 最理想：两个版本的完整源文件都有（优先 new+diff 逆向父本）
            old_func = extract_function_for_hunks(
                old_src_eff, hint, old_ref, fh_list, fixed_side=False
            )
            new_func = extract_function_for_hunks(
                new_src, hint, new_ref, fh_list, fixed_side=True
            )
            if old_func and new_func and old_func.strip() != new_func.strip():
                vuln_func = old_func
                fixed_func = new_func
                is_complete = True
            elif new_func:
                # 有修复后函数，用 diff 从修复后版本内精确替换出修复前版本
                vuln_func, fixed_func = build_versions_from_diff(
                    fh_list, full_src=new_func, mode_src="new"
                )
                is_complete = vuln_func.strip() != fixed_func.strip()
            elif old_func:
                # 有修复前函数，用 diff 从修复前版本内精确替换出修复后版本
                vuln_func, fixed_func = build_versions_from_diff(
                    fh_list, full_src=old_func, mode_src="old"
                )
                is_complete = vuln_func.strip() != fixed_func.strip()
            else:
                vuln_func, fixed_func = build_versions_from_diff(fh_list)
                is_complete = False

        elif new_src:
            # 只有修复后源文件：提取函数后用 diff 反推修复前
            new_func = extract_function_for_hunks(
                new_src, hint, new_ref, fh_list, fixed_side=True
            )
            vuln_func, fixed_func = build_versions_from_diff(
                fh_list, full_src=new_func, mode_src="new"
            )
            is_complete = bool(new_func) and vuln_func.strip() != fixed_func.strip()

        elif old_src_eff:
            # 只有修复前源文件：提取函数后用 diff 推出修复后
            old_func = extract_function_for_hunks(
                old_src_eff, hint, old_ref, fh_list, fixed_side=False
            )
            vuln_func, fixed_func = build_versions_from_diff(
                fh_list, full_src=old_func, mode_src="old"
            )
            is_complete = bool(old_func) and vuln_func.strip() != fixed_func.strip()

        else:
            # 无任何源文件：纯 diff 窗口
            vuln_func, fixed_func = build_versions_from_diff(fh_list)
            is_complete = False

        if (
            not is_patch_file
            and new_src
            and vuln_func
            and fixed_func
            and not diff_hunk_lines_embedded(vuln_func, fixed_func, fh_list)
        ):
            v_all, f_all = build_versions_from_diff(
                fh_list, full_src=new_src, mode_src="new"
            )
            if (
                v_all
                and f_all
                and not v_all.lstrip().startswith("/* patch context")
                and diff_hunk_lines_embedded(v_all, f_all, fh_list)
            ):
                v2 = extract_function_for_hunks(
                    v_all, hint, old_ref, fh_list, fixed_side=False
                )
                f2 = extract_function_for_hunks(
                    f_all, hint, new_ref, fh_list, fixed_side=True
                )
                if v2 and f2:
                    vuln_func, fixed_func = v2, f2
                    is_complete = v2.strip() != f2.strip()

        if not is_complete:
            print(f"  [incomplete] {filepath}:{hint or '(no hint)'} — 仅 diff 上下文")

        all_removed = [r for h in fh_list for r in h["removed"]]
        all_added = [a for h in fh_list for a in h["added"]]
        desc = (vuln_meta.get("description", "") or "").strip()
        title = (vuln_meta.get("title", "") or "").strip()
        results.append(
            CVEItem(
                cve_id=item.get("cve", ""),
                repository=oh_repo,
                severity=item.get("severity", ""),
                affected_version=item.get("version_label", ""),
                title=title,
                description=desc if desc else title,
                reference_url=url,
                cve_hint=vuln_meta.get("cve", ""),
                file_path=filepath,
                function_name=hint,
                hunk_headers=[h["hunk_header"] for h in fh_list],
                vulnerable_code=vuln_func,
                fixed_code=fixed_func,
                added_lines=all_added,
                removed_lines=all_removed,
                changed_hunks_count=len(fh_list),
                is_complete=is_complete,
            )
        )
    return results
