"""NVD 兜底补充模块。

在「公告/GitCode 爬取 + LLM 审查」之后，若任一项仍不完整，再从此处补全：

1. NVD REST API（``services.nvd.nist.gov/rest/json/cves/2.0?cveId=...``）与
   ``https://nvd.nist.gov/vuln/detail/<CVE-ID>`` 详情页中的 References 同源；
2. 其中的 GitHub commit（优先带 Patch 标签）→ 拉 ``.diff`` / raw 源码，提取修复前/后完整函数。

同一 CVE 可能列出多个 Patch 提交（如先引入回归、再修复）；会跳过「修复前后函数体相同」的提交，
直到找到真实修复提交。

典型调用::

    from .nvd_fallback import nvd_supplement
    supplement = nvd_supplement(cve_id=..., failed_fields=[...], ...)
"""

from __future__ import annotations

import re

import urllib3

from autoyara.collectors.analysis import (
    extract_function_for_hunks,
    parent_source_from_diff,
    realign_hunks_new_starts,
)

from .analysis import get_parent_sha
from .diff_utils import parse_diff_full
from .http_client import SESSION, H

urllib3.disable_warnings()

_NVD_BASE = "https://nvd.nist.gov/vuln/detail/"
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
_TIMEOUT = 20
# 同一次进程内按 CVE 缓存，避免「预填描述 + 兜底补全」重复打 NVD
_NVD_INFO_CACHE: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# NVD HTML 详情页爬取 Patch 链接（作为 REST API 的补充/备用）
# ---------------------------------------------------------------------------


def _scrape_nvd_html_patches(cve_id: str) -> list[str]:
    """
    从 https://nvd.nist.gov/vuln/detail/{cve_id} HTML 页面的
    「References to Advisories, Solutions, and Tools」章节，
    提取带有 "Patch" 标签的 URL 列表。

    当 REST API 的 Patch 链接为空或 rate-limited 时作为备用。
    """
    url = f"{_NVD_BASE}{cve_id.upper()}"
    print(f"  [nvd-html] 爬取详情页: {url}")
    html = _get(url, allow_html=True)
    if not html:
        print("  [nvd-html] 无法获取页面")
        return []

    # NVD 页面结构：References 区域中每条链接紧跟若干 <span class="badge ...">Patch</span>
    # 用正则提取 <a href="URL">...</a> ... <span>Patch</span> 的配对
    patch_urls: list[str] = []

    # 方法1：找到 hyperlink + 其后紧跟含 "Patch" 的 span
    # 示例片段：<a href="https://github.com/...">...</a> ... <span ...>Patch</span>
    # NVD 每条 reference 大致在同一 <tr> 或 <li> 块中
    blocks = re.split(r"</?(?:tr|li)[^>]*>", html, flags=re.I)
    for block in blocks:
        if "Patch" not in block:
            continue
        hrefs = re.findall(r'href="(https?://[^"]+)"', block, re.I)
        for href in hrefs:
            if href not in patch_urls:
                patch_urls.append(href)

    # 方法2：直接用 JSON-LD 或 data-* 属性（某些 NVD 版本）
    if not patch_urls:
        # 找所有含 "Patch" 标签旁的链接
        patch_spans = [m.start() for m in re.finditer(r"Patch", html)]
        for pos in patch_spans:
            # 向前查 300 字符找 href
            snippet = html[max(0, pos - 300) : pos]
            hrefs = re.findall(r'href="(https?://[^"]+)"', snippet, re.I)
            for href in hrefs:
                if href not in patch_urls:
                    patch_urls.append(href)

    # 去掉 NVD 自身链接
    patch_urls = [u for u in patch_urls if "nvd.nist.gov" not in u]
    print(f"  [nvd-html] 找到 {len(patch_urls)} 条 Patch URL")
    return patch_urls


def _get(url: str, *, allow_html: bool = False) -> str | None:
    """简单 GET，返回文本或 None。"""
    try:
        headers = dict(H)
        if allow_html:
            headers["Accept"] = "text/html,application/xhtml+xml,*/*"
        r = SESSION.get(url, headers=headers, timeout=_TIMEOUT, verify=False)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# NVD API：获取 Description 和 Patch 链接
# ---------------------------------------------------------------------------


def fetch_nvd_info(cve_id: str) -> dict:
    """
    从 NVD REST API 获取 CVE 信息。
    返回 {"description": str, "patch_urls": [str], "references": [str]}
    """
    cache_key = cve_id.upper().strip()
    if cache_key in _NVD_INFO_CACHE:
        return _NVD_INFO_CACHE[cache_key]

    url = _NVD_API.format(cve_id=cve_id.upper())
    print(f"  [nvd-api] {url[:80]}")
    try:
        r = SESSION.get(url, headers=H, timeout=_TIMEOUT, verify=False)
        if r.status_code != 200:
            print(f"  [nvd-api] HTTP {r.status_code}")
            return {}
        data = r.json()
    except Exception as e:
        print(f"  [nvd-api] 请求失败: {e}")
        return {}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print("  [nvd-api] 无结果")
        return {}

    cve_data = vulns[0].get("cve", {})

    # Description（优先 en）
    description = ""
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "").strip()
            break

    # References：Patch 标签 + 所有 GitHub commit（NVD 里常与「Patch」并列，用于上游完整源码）
    patch_urls = []
    all_refs = []
    gh_patch_commits: list[str] = []
    gh_other_commits: list[str] = []

    def _is_github_commit(u: str) -> bool:
        return bool(
            re.match(
                r"https?://github\.com/[^/]+/[^/]+/commit/[0-9a-f]+", u.strip(), re.I
            )
        )

    for ref in cve_data.get("references", []):
        ref_url = (ref.get("url") or "").strip()
        tags = ref.get("tags", [])
        if ref_url:
            all_refs.append(ref_url)
        if "Patch" in tags and ref_url:
            patch_urls.append(ref_url)
        if ref_url and _is_github_commit(ref_url):
            if "Patch" in tags:
                gh_patch_commits.append(ref_url)
            else:
                gh_other_commits.append(ref_url)

    def _dedup(seq: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for u in seq:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    gh_patch_deduped = _dedup(gh_patch_commits)
    gh_patch_set = set(gh_patch_deduped)
    github_commit_urls = gh_patch_deduped + [
        u for u in _dedup(gh_other_commits) if u not in gh_patch_set
    ]

    print(
        f"  [nvd-api] description={len(description)}字符  patch_urls={len(patch_urls)}"
        f"  github_commits={len(github_commit_urls)}"
    )

    # 若 API 未返回任何 GitHub patch commit，尝试从 NVD HTML 详情页补充
    if not github_commit_urls:
        html_patches = _scrape_nvd_html_patches(cve_id)
        for hp in html_patches:
            if _is_github_commit(hp):
                github_commit_urls.append(hp)
            if hp not in patch_urls:
                patch_urls.append(hp)
        if github_commit_urls:
            print(f"  [nvd-html] 补充到 {len(github_commit_urls)} 条 GitHub commit URL")

    out = {
        "description": description,
        "patch_urls": patch_urls,
        "references": all_refs,
        "github_commit_urls": github_commit_urls,
    }
    _NVD_INFO_CACHE[cache_key] = out
    return out


def prefill_description_from_nvd(
    cve_id: str,
    current: str | None,
    *,
    min_len: int = 40,
) -> str:
    """公告/commit 未带足够漏洞说明时，用 NVD 英文描述预填（不依赖 LLM 先判失败）。

    与 GitCode/GitHub 令牌无关；NVD 2.0 API 匿名可访问。
    """
    cur = (current or "").strip()
    if len(cur) >= min_len:
        return current or ""
    if not cve_id or not re.match(r"CVE-\d{4}-\d+", cve_id, re.I):
        return cur
    info = fetch_nvd_info(cve_id)
    nd = (info.get("description") or "").strip()
    if not nd:
        return cur
    if len(nd) > len(cur):
        print(f"  [nvd-prefill] 漏洞描述由 NVD 预填（{len(nd)} 字符）")
        return nd
    return cur


# ---------------------------------------------------------------------------
# 从 GitHub commit URL 提取修复前/后函数
# ---------------------------------------------------------------------------


def _parse_github_commit_url(url: str) -> tuple[str, str, str] | None:
    """解析 github.com/owner/repo/commit/sha，返回 (owner, repo, sha)。"""
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
        url.strip(),
        re.I,
    )
    if m:
        return m.group(1), m.group(2), m.group(3)
    return None


def fetch_github_patch_functions(
    patch_url: str,
) -> dict[str, str | None]:
    """
    从 GitHub commit URL 拉取 diff，提取修复前/后函数体。

    返回 {
        "vulnerable_function": str | None,
        "fixed_function": str | None,
        "description": str,   # commit message（如有）
    }
    """
    result: dict[str, str | None] = {
        "vulnerable_function": None,
        "fixed_function": None,
        "description": "",
    }

    parsed = _parse_github_commit_url(patch_url)
    if not parsed:
        print(f"  [nvd-fallback] 非 GitHub commit URL: {patch_url[:80]}")
        return result

    owner, repo, sha = parsed

    # 拉 .diff
    diff_url = f"https://github.com/{owner}/{repo}/commit/{sha}.diff"
    print(f"  [nvd-fallback] diff: {diff_url[:90]}")
    diff_text = _get(diff_url)
    if not diff_text or "diff --git" not in diff_text:
        diff_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
        print(f"  [nvd-fallback] patch: {diff_url[:90]}")
        diff_text = _get(diff_url)

    if not diff_text or "diff --git" not in diff_text:
        print("  [nvd-fallback] 无法获取 diff")
        return result

    # 提取 commit message 作为描述补充
    msg_m = re.search(
        r"^Subject:\s*(?:\[[^\]]+\]\s*)?(.+?)(?:\n\n|\n---)", diff_text, re.M | re.S
    )
    if msg_m:
        result["description"] = msg_m.group(0).strip()

    # 解析 diff
    hunks = parse_diff_full(diff_text)
    if not hunks:
        print("  [nvd-fallback] diff 解析无 hunk")
        return result

    # 按文件分组；优先 .c/.h 等待改代码文件，避免 AUTHORS 等掩盖主漏洞文件
    from collections import defaultdict

    file_hunks: dict[str, list] = defaultdict(list)
    for h in hunks:
        file_hunks[h["file"]].append(h)

    _code_suffix = (".c", ".h", ".cpp", ".cc", ".hpp", ".cxx", ".java", ".go", ".rs")

    def _pick_main_file(paths: list[str]) -> str:
        lower = [(p, p.lower()) for p in paths]
        code_files = [p for p, pl in lower if pl.endswith(_code_suffix)]
        pool = code_files if code_files else paths
        return max(pool, key=lambda f: len(file_hunks[f]))

    best_file = _pick_main_file(list(file_hunks.keys()))
    fhunks = file_hunks[best_file]
    func_hint = fhunks[0].get("function_hint", "")
    print(f"  [nvd-fallback] file={best_file} func={func_hint[:60]}")

    # 拉 new_src（fix 后，用 sha）
    new_src_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{best_file}"
    print(f"  [nvd-fallback] new_src: {new_src_url[:90]}")
    new_src = _get(new_src_url)
    if new_src and len(new_src) < 200:
        new_src = None

    parent_sha = get_parent_sha(repo, sha, gh_owner=owner)

    old_src = None
    if parent_sha:
        old_src_url = (
            f"https://raw.githubusercontent.com/{owner}/{repo}/{parent_sha}/{best_file}"
        )
        print(f"  [nvd-fallback] old_src: {old_src_url[:90]}")
        old_src = _get(old_src_url)
        if old_src and len(old_src) < 200:
            old_src = None

    if old_src and new_src and old_src.strip() == new_src.strip():
        old_src = None

    fh_use = realign_hunks_new_starts(new_src, fhunks) if new_src else list(fhunks)
    reconstructed = (
        parent_source_from_diff(new_src, fh_use) if new_src and fh_use else None
    )
    old_eff = old_src or reconstructed

    new_ref = max(h["new_start"] for h in fh_use)
    old_ref = max(h["old_start"] for h in fh_use)

    fixed_func = (
        extract_function_for_hunks(new_src, func_hint, new_ref, fh_use, fixed_side=True)
        if new_src
        else None
    )
    vuln_func = (
        extract_function_for_hunks(
            old_eff, func_hint, old_ref, fh_use, fixed_side=False
        )
        if old_eff
        else None
    )

    if fixed_func:
        result["fixed_function"] = fixed_func
        print(f"  [nvd-fallback] fixed_func OK ({len(fixed_func)} chars)")
    if vuln_func:
        result["vulnerable_function"] = vuln_func
        print(f"  [nvd-fallback] vuln_func OK ({len(vuln_func)} chars)")

    return result


# ---------------------------------------------------------------------------
# 主入口：对单条 AutoYaraDataModel 进行 NVD 兜底补充
# ---------------------------------------------------------------------------


def nvd_supplement(
    cve_id: str,
    failed_fields: list[str],
    current_description: str = "",
    current_vuln_func: str = "",  # noqa: ARG001
    current_fixed_func: str = "",  # noqa: ARG001
) -> dict[str, str | None]:
    """
    根据 LLM 判定的不完整字段，从 NVD 和 GitHub 补充信息。

    Args:
        cve_id: CVE 编号，如 "CVE-2026-22695"
        failed_fields: LLM 认为不完整的字段名列表，
                       如 ["description", "vulnerable_function", "fixed_function"]
        current_description: 现有描述（用于判断是否需要替换）
        current_vuln_func: 现有修复前函数
        current_fixed_func: 现有修复后函数

    Returns:
        包含补充后字段的字典，键与 AutoYaraDataModel 字段对应：
        {
            "description": str | None,        # None 表示无需/无法补充
            "vulnerable_function": str | None,
            "fixed_function": str | None,
        }
    """
    supplement: dict[str, str | None] = {
        "description": None,
        "vulnerable_function": None,
        "fixed_function": None,
    }

    if not failed_fields:
        return supplement

    print(f"\n  [nvd-fallback] 启动 NVD 兜底补充 CVE={cve_id} 缺失={failed_fields}")

    nvd_info = fetch_nvd_info(cve_id)
    if not nvd_info:
        print("  [nvd-fallback] NVD API 无数据，放弃")
        return supplement

    # 补充描述
    if "description" in failed_fields:
        nvd_desc = nvd_info.get("description", "").strip()
        if nvd_desc and len(nvd_desc) > len(current_description):
            supplement["description"] = nvd_desc
            print(f"  [nvd-fallback] 描述已补充（{len(nvd_desc)} 字符）")

    # 补充函数（需要 Patch 链接）
    need_funcs = any(
        f in failed_fields for f in ("vulnerable_function", "fixed_function")
    )
    if need_funcs:
        patch_urls = nvd_info.get("patch_urls", [])
        gh_candidates = nvd_info.get("github_commit_urls") or []
        if not gh_candidates:
            gh_candidates = [
                u
                for u in patch_urls
                if re.match(r"https?://github\.com/.+/commit/[0-9a-f]+", u, re.I)
            ]
        print(f"  [nvd-fallback] GitHub commit 候选: {len(gh_candidates)} 条")

        for pu in gh_candidates:
            funcs = fetch_github_patch_functions(pu)
            vu_raw = funcs.get("vulnerable_function") or ""
            fx_raw = funcs.get("fixed_function") or ""
            vu = vu_raw.strip()
            fx = fx_raw.strip()
            if need_funcs:
                if not vu or not fx:
                    continue
                # 跳过「非修复型」提交（如仅引入问题的 commit，提取结果前后相同）
                if vu == fx:
                    print(f"  [nvd-fallback] 跳过（修复前后相同）: {pu[:72]}…")
                    continue
            if "vulnerable_function" in failed_fields and vu_raw:
                supplement["vulnerable_function"] = vu_raw
            if "fixed_function" in failed_fields and fx_raw:
                supplement["fixed_function"] = fx_raw
            if "description" in failed_fields and not supplement["description"]:
                commit_desc = funcs.get("description", "")
                if commit_desc and len(commit_desc) > 30:
                    supplement["description"] = commit_desc

            need_vuln = "vulnerable_function" in failed_fields
            need_fix = "fixed_function" in failed_fields
            have_vuln = not need_vuln or bool(supplement.get("vulnerable_function"))
            have_fix = not need_fix or bool(supplement.get("fixed_function"))
            if need_funcs and have_vuln and have_fix:
                break

    return supplement
