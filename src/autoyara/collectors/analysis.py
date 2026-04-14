import copy
import json
import os
import re
from typing import Any

from .discovery import UPSTREAM
from .gitcode import (
    fetch_gitcode_file_blob,
    get_parent_sha_gitcode,
    gitcode_auth_headers,
    gitcode_private_token,
)
from .http_client import SESSION, H, get
from .internal_types import CrawlerLink

_src_cache = {}
_parent_cache = {}


def _github_api_headers():
    h = dict(H)
    tok = (
        os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_API_TOKEN") or ""
    ).strip()
    if tok:
        h["Authorization"] = "Bearer " + tok
    return h


def fetch_source(oh_repo, filepath, ref, gh_owner="openharmony"):
    if not ref:
        return None
    key = (gh_owner, oh_repo, ref, filepath)
    if key in _src_cache:
        return _src_cache[key]
    for u in [
        f"https://raw.githubusercontent.com/{gh_owner}/{oh_repo}/{ref}/{filepath}",
        f"https://raw.githubusercontent.com/openharmony/{oh_repo}/{ref}/{filepath}",
    ]:
        print("  [src] " + u[:90])
        t = get(u)
        if t and len(t) > 500:
            print(f"  [OK] {len(t)} bytes")
            _src_cache[key] = t
            return t
    if oh_repo in UPSTREAM:
        up_owner, up_repo, up_branch = UPSTREAM[oh_repo]
        for up_ref in [up_branch, "master", "main"]:
            u = f"https://raw.githubusercontent.com/{up_owner}/{up_repo}/{up_ref}/{filepath}"
            print("  [src-upstream] " + u[:90])
            t = get(u)
            if t and len(t) > 500:
                print(f"  [OK] {len(t)} bytes")
                _src_cache[key] = t
                return t
    if gitcode_private_token() and gh_owner:
        print("  [src-gitcode] " + filepath[:60])
        t = fetch_gitcode_file_blob(gh_owner, oh_repo, ref, filepath)
        if t and len(t) > 10:
            _src_cache[key] = t
            return t
    _src_cache[key] = None
    return None


def get_parent_sha(oh_repo, sha, gh_owner=None):
    if not sha:
        return None
    key = (oh_repo, sha, gh_owner or "")
    if key in _parent_cache:
        return _parent_cache[key]
    if gh_owner and gitcode_private_token():
        pg = get_parent_sha_gitcode(gh_owner, oh_repo, sha)
        if pg:
            _parent_cache[key] = pg
            return pg
    for try_owner in ["openharmony", "openharmony-tpc"]:
        try:
            r = SESSION.get(
                f"https://api.github.com/repos/{try_owner}/{oh_repo}/commits/{sha}",
                headers=_github_api_headers(),
                timeout=25,
                verify=False,
            )
            r.raise_for_status()
            t = r.content.decode("utf-8", errors="replace")
        except Exception:
            t = None
        if t and "{" in t:
            try:
                data = json.loads(t)
                if "API rate limit" in data.get("message", ""):
                    print("  [parent] GitHub rate limited")
                    break
                parents = data.get("parents", [])
                if parents:
                    p = parents[0]["sha"]
                    print("  [parent] " + p[:12] + " (github)")
                    _parent_cache[key] = p
                    return p
            except Exception:
                pass
    t = get(f"https://gitee.com/api/v5/repos/openharmony/{oh_repo}/commits/{sha}")
    if t and "{" in t:
        try:
            data = json.loads(t)
            parents = data.get("parents") or []
            if parents:
                p = parents[0].get("sha") or parents[0].get("id", "")
                if p:
                    print("  [parent] " + p[:12] + " (gitee)")
                    _parent_cache[key] = p
                    return p
        except Exception:
            pass
    _parent_cache[key] = None
    return None


def get_upstream_commit_from_patch(diff_text):
    """从 patch 文件的 commit message 里提取上游 mainline commit SHA"""
    m = re.search(r"^\s*commit\s+([0-9a-f]{40})\s*$", diff_text, re.M | re.I)
    if m:
        return m.group(1)
    m = re.search(r"commit\s+([0-9a-f]{40})", diff_text, re.I)
    if m:
        return m.group(1)
    return None


def get_parent_sha_upstream(upstream_sha):
    """从 torvalds/linux 获取上游 commit 的 parent SHA。

    无 GITHUB_TOKEN 时 API 限流严重（匿名 60 次/小时），限流直接跳过而不重试。
    """
    if not upstream_sha:
        return None, None
    try:
        r = SESSION.get(
            f"https://api.github.com/repos/torvalds/linux/commits/{upstream_sha}",
            headers=_github_api_headers(),
            timeout=20,
            verify=False,
        )
        if r.status_code in (403, 429):
            print("  [upstream] GitHub API rate limited, skipping parent lookup")
            return None, None
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict):
            msg = data.get("message", "")
            if "rate limit" in msg.lower():
                print("  [upstream] GitHub rate limited")
                return None, None
            parents = data.get("parents", [])
            if parents:
                p = parents[0]["sha"]
                print("  [upstream parent] " + p[:12])
                return p, "torvalds/linux"
    except Exception:
        pass
    return None, None


def fetch_source_upstream(filepath, ref, repo="torvalds/linux"):
    """从上游仓库（如 torvalds/linux）获取源文件"""
    u = f"https://raw.githubusercontent.com/{repo}/{ref}/{filepath}"
    print("  [src-upstream2] " + u[:90])
    t = get(u)
    if t and len(t) > 500:
        print(f"  [OK] {len(t)} bytes")
        return t
    return None


def strip_html_to_text(html):
    """简单 HTML -> 文本，便于从 commit 页面兜底提取描述。"""
    if not html:
        return ""
    t = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html)
    t = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", t)
    t = re.sub(r"(?is)<[^>]+>", " ", t)
    t = re.sub(r"&nbsp;", " ", t)
    t = re.sub(r"&amp;", "&", t)
    t = re.sub(r"&#39;|&apos;", "'", t)
    t = re.sub(r"&quot;", '"', t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def _clean_desc_line(line):
    s = (line or "").strip()
    if not s:
        return ""
    if s.startswith(("Signed-off-by:", "Reviewed-by:", "Tested-by:", "Acked-by:")):
        return ""
    if s.startswith("Cc:"):
        return ""
    if s.startswith("Fixes:"):
        return ""
    if s.startswith("Link:"):
        return ""
    return s


def parse_vuln_desc_from_patch_text(diff_text):
    if not diff_text or not isinstance(diff_text, str):
        return {"title": "", "description": "", "cve": ""}
    title = ""
    m = re.search(r"(?im)^Subject:\s*(?:\[[^\]]+\]\s*)?(.+)$", diff_text)
    if m:
        title = m.group(1).strip()
    cve = ""
    cve_m = re.search(r"\b(CVE-\d{4}-\d+)\b", diff_text, re.I)
    if cve_m:
        cve = cve_m.group(1).upper()
    desc = ""
    body_m = re.search(
        r"(?is)^Subject:.*?\n\n(.*?)(?:\n---\n|\ndiff --git |\nIndex: )",
        diff_text,
        re.M,
    )
    if body_m:
        body = body_m.group(1)
        lines = []
        for ln in body.splitlines():
            x = _clean_desc_line(ln)
            if x:
                lines.append(x)
        if lines:
            desc = "\n".join(lines[:12]).strip()
    # GitCode 等返回的 unified diff 可能没有 From:/Subject:，仅在 diff --git 前有说明与 CVE 行
    if (not title or not desc) and "diff --git" in diff_text:
        head = diff_text.split("diff --git", 1)[0].strip()
        if len(head) > 15:
            if not cve:
                cm2 = re.search(r"\b(CVE-\d{4}-\d+)\b", head, re.I)
                if cm2:
                    cve = cm2.group(0).upper()
            hlines = []
            for ln in head.splitlines():
                x = _clean_desc_line(ln)
                if x:
                    hlines.append(x)
            if hlines:
                if not title:
                    title = hlines[0][:240]
                if not desc:
                    rest = hlines[1:] if title == hlines[0] else hlines
                    desc = "\n".join(rest).strip()[:8000]
    return {"title": title, "description": desc, "cve": cve}


def _commit_message_from_api_json(data: dict) -> str:
    """解析 GitHub/Gitee/GitCode 等返回的 commit JSON，取出完整提交说明。"""
    if not isinstance(data, dict):
        return ""
    c = data.get("commit")
    if isinstance(c, dict):
        msg = c.get("message")
        if isinstance(msg, str) and msg.strip():
            return msg.strip()
        title = c.get("title")
        body = c.get("body")
        parts = []
        if isinstance(title, str) and title.strip():
            parts.append(title.strip())
        if isinstance(body, str) and body.strip():
            parts.append(body.strip())
        if parts:
            return "\n".join(parts)
    for k in ("message", "title"):
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def fetch_commit_meta_from_api(owner, repo, sha):
    """尝试从 GitHub/Gitee/GitCode API 获取 commit message（GitCode 公开仓可无 token）。"""
    if not (owner and repo and sha):
        return ""
    for try_owner in [owner, "openharmony"]:
        try:
            r = SESSION.get(
                f"https://api.github.com/repos/{try_owner}/{repo}/commits/{sha}",
                headers=_github_api_headers(),
                timeout=25,
                verify=False,
            )
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict):
                msg = _commit_message_from_api_json(data)
                if msg:
                    return msg
        except Exception:
            pass
    try:
        t = get(f"https://gitee.com/api/v5/repos/{owner}/{repo}/commits/{sha}")
        if t:
            data = json.loads(t)
            msg = _commit_message_from_api_json(data)
            if msg:
                return msg
    except Exception:
        pass
    try:
        url = f"https://gitcode.com/api/v5/repos/{owner}/{repo}/commits/{sha}"
        r = SESSION.get(url, headers=gitcode_auth_headers(), timeout=25, verify=False)
        r.raise_for_status()
        data = r.json()
        msg = _commit_message_from_api_json(data)
        if msg:
            return msg
    except Exception:
        pass
    return ""


def fetch_vuln_description(item: CrawlerLink, diff_text):
    """
    聚合漏洞描述来源（优先级）：
    1) patch 头 Subject/正文
    2) commit API message
    3) commit 页面文本兜底
    """
    info = parse_vuln_desc_from_patch_text(diff_text)
    title = info.get("title", "")
    desc = info.get("description", "")
    cve = info.get("cve", "")
    url = item.get("url", "")
    # 支持 commit / patch(blob) / github / gitcode / gitee 等各种 URL 格式
    owner: str = "openharmony"
    repo: str = item.get("repo", "")
    sha: str | None = item.get("fix_sha")
    # gitee/gitcode commit URL
    m = re.match(
        r"https?://(?:gitee|gitcode|github)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
        url,
        re.I,
    )
    if m:
        owner, repo, sha = m.group(1), m.group(2), m.group(3)
    else:
        # gitcode/gitee blob patch URL: .../blob/<sha>/filename.patch
        m2 = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/blob/([0-9a-f]+)/",
            url,
            re.I,
        )
        if m2:
            owner, repo, sha = m2.group(1), m2.group(2), m2.group(3)
        elif not sha:
            # 从 diff_text 里尝试提取 SHA（patch 文件头通常含 From <sha>）
            sha_m = re.search(r"^From ([0-9a-f]{40})\b", diff_text or "", re.M)
            if sha_m:
                sha = sha_m.group(1)
    if not title or not desc or not cve:
        msg = fetch_commit_meta_from_api(owner, repo, sha)
        if msg:
            if not cve:
                cm = re.search(r"\b(CVE-\d{4}-\d+)\b", msg, re.I)
                if cm:
                    cve = cm.group(0).upper()
            lines = [x.strip() for x in msg.splitlines()]
            lines = [x for x in lines if _clean_desc_line(x)]
            if lines:
                first = lines[0]
                if not title:
                    title = first
                if not desc:
                    if title == first:
                        desc = "\n".join(lines[1:]).strip()[:8000]
                    else:
                        desc = "\n".join(lines).strip()[:8000]
            if not desc and msg.strip():
                tail = msg.strip()
                if title and tail.startswith(title):
                    tail = tail[len(title) :].lstrip("\n\r- ")
                desc = tail[:8000].strip()
    if (not title or not desc) and url:
        page = get(url, allow_html=True)
        txt = strip_html_to_text(page or "")
        if txt:
            if not cve:
                c = re.search(r"\b(CVE-\d{4}-\d+)\b", txt, re.I)
                if c:
                    cve = c.group(1).upper()
            if not title:
                tm = re.search(
                    r"(?:commit|提交|修复|fix)\s*[:：]?\s*([^\n.]{10,240})",
                    txt,
                    re.I,
                )
                if tm:
                    title = tm.group(1).strip()
            if not desc:
                dm = re.search(
                    r"CVE\s*[:：]\s*CVE-\d{4}-\d+\s*(.+?)(?=Signed-off-by|---\s*$)",
                    txt,
                    re.I | re.S,
                )
                if dm:
                    desc = re.sub(r"\s+", " ", dm.group(1).strip())[:2000]
                if not desc and len(txt) > 80:
                    cut = txt[:1500]
                    if "Signed-off-by" in cut:
                        cut = cut.split("Signed-off-by")[0]
                    desc = re.sub(r"\s+", " ", cut.strip())[:2000]
    return {"title": title, "description": desc, "cve": cve}


def parse_fname_from_hint(func_hint):
    if not func_hint:
        return ""
    hint = func_hint.strip()
    matches = re.findall(r"([a-zA-Z_]\w*)\s*\(", hint)
    if matches:
        # C hunk 头多为 `func(a, b)`，取首个标识符；C++ `Class::method(` 取最后一个。
        return matches[-1] if "::" in hint else matches[0]
    return re.split(r"[(\s]", hint)[0].strip()


_FN_LINE_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "else",
        "case",
        "default",
        "sizeof",
        "static",
        "inline",
        "extern",
        "const",
        "unsigned",
        "struct",
        "enum",
        "typedef",
    }
)


def _anchor_find_lineno(text: str, code: str) -> int | None:
    """在 text 中定位与 patch 行匹配的 1-based 行号（精确子串优先，其次空白归一后整行匹配）。"""
    c = code.strip()
    if len(c) < 8 or c in ("-", "- -"):
        return None
    idx = text.find(c)
    if idx >= 0:
        return text.count("\n", 0, idx) + 1
    norm = re.sub(r"\s+", " ", c)
    for i, ln in enumerate(text.splitlines(), start=1):
        if re.sub(r"\s+", " ", ln.strip()) == norm:
            return i
    return None


def anchor_lineno_in_source(
    source: str | None, hunk_list: list[dict[str, Any]], *, fixed_side: bool
) -> int | None:
    """用 hunk 中较长的 +/- 行在源码里定位行号（1-based），用于纠正 @@ 函数名或行号漂移。"""
    if not source:
        return None
    text = source.replace("\r\n", "\n")

    for h in hunk_list:
        key = "added" if fixed_side else "removed"
        for it in h.get(key) or []:
            ln = _anchor_find_lineno(text, it.get("code", ""))
            if ln is not None:
                return ln
    return None


def _snippet_contains_hunk_side_lines(
    snippet: str, hunk_list: list[dict[str, Any]], *, fixed_side: bool
) -> bool:
    """片段是否包含任一较长的 +/- 行（用于判断 extract 是否抽对了函数）。"""
    for h in hunk_list:
        key = "added" if fixed_side else "removed"
        for it in h.get(key) or []:
            c = (it.get("code") or "").strip()
            if len(c) < 10:
                continue
            if c in snippet:
                return True
            n = re.sub(r"\s+", " ", c)
            if n and any(
                re.sub(r"\s+", " ", ln.strip()) == n for ln in snippet.splitlines()
            ):
                return True
    return False


def infer_fname_before_line(
    lines: list[str], target_idx: int, max_back: int = 300
) -> str:
    """从 target_idx 向上找最近一行「函数定义名(」形式，避开 if/for 等。"""
    # 同一行内：name( ... ) 且非以 ); 结尾的调用语句
    def_line = re.compile(r"^[\t ]*([a-zA-Z_]\w*)\s*\([^;]*\)\s*$")
    call_stmt = re.compile(r"^[\t ]*[a-zA-Z_]\w*\s*\(.*\)\s*;\s*$")
    for i in range(target_idx, max(-1, target_idx - max_back), -1):
        raw = lines[i]
        st = raw.strip()
        if not st or st.startswith(("#", "/*", "*", "//", "}")):
            continue
        if call_stmt.match(raw):
            continue
        m = def_line.match(raw)
        if not m:
            continue
        name = m.group(1)
        if name in _FN_LINE_KEYWORDS:
            continue
        return name
    return ""


def extract_function_for_hunks(
    source: str | None,
    func_hint: str,
    ref_line: int,
    hunk_list: list[dict[str, Any]],
    *,
    fixed_side: bool,
) -> str | None:
    """结合 @@ 行号与 hunk 锚点行提取函数；修正 @@ 函数名错误时仍能对位。"""
    if not source:
        return None
    text = source.replace("\r\n", "\n")
    anchor = anchor_lineno_in_source(text, hunk_list, fixed_side=fixed_side)
    ref_fb = (
        min(h["new_start"] for h in hunk_list)
        if fixed_side
        else min(h["old_start"] for h in hunk_list)
    )
    line_no = anchor or ref_fb or ref_line
    lines = text.splitlines()
    tidx = min(max(line_no - 1, 0), len(lines) - 1)
    hint_fname = parse_fname_from_hint(func_hint)
    inferred = infer_fname_before_line(lines, tidx)

    def by_name(fname: str | None) -> str | None:
        if not fname:
            return None
        return extract_function(text, f"{fname}(void)", line_no)

    # 优先 @@ 函数名；若片段中根本没有 hunk 关键行，再试反向推断（应对 @@ 写错）
    for fname in (hint_fname, inferred):
        if not fname:
            continue
        out = by_name(fname)
        if out and _snippet_contains_hunk_side_lines(
            out, hunk_list, fixed_side=fixed_side
        ):
            return out
    out = by_name(hint_fname) or extract_function(text, func_hint, line_no)
    if not out and inferred and (not hint_fname or inferred == hint_fname):
        out = by_name(inferred)
    return out


def extend_signature_start(lines, sig_idx):
    while sig_idx > 0:
        prev_raw = lines[sig_idx - 1]
        if not prev_raw.strip():
            sig_idx -= 1
            continue
        if prev_raw[0] in (" ", "\t"):
            break
        pl = prev_raw.lstrip()
        if pl.startswith(("#", "/*", "*", "//")):
            break
        pr = prev_raw.rstrip()
        if pr.endswith("}") or pr.endswith(";"):
            break
        sig_idx -= 1
    return sig_idx


def _match_brace_end(lines: list[str], sig_idx: int, fname: str, n: int) -> int | None:
    depth, found_open, end_idx = 0, False, None
    for i in range(sig_idx, min(sig_idx + 5000, n)):
        if not found_open and i > sig_idx + 8:
            line = lines[i]
            if (
                line
                and line[0] not in (" ", "\t")
                and not line.lstrip().startswith(("/*", "*", "//", "#", "}"))
                and fname not in line
                and "{" not in line
            ):
                break
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                found_open = True
            elif ch == "}":
                depth -= 1
                if found_open and depth == 0:
                    end_idx = i
                    break
        if end_idx is not None:
            break
    return end_idx


def extract_function(
    source: str | None, func_hint: str, target_lineno: int
) -> str | None:
    if not source:
        return None
    lines = source.splitlines()
    n = len(lines)
    target_idx = min(max(target_lineno - 1, 0), n - 1)
    fname = parse_fname_from_hint(func_hint)
    if not fname:
        return None

    spans_seen: set[tuple[int, int]] = set()
    spans: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        if not line or not line.strip():
            continue
        s = line.lstrip()
        if s.startswith(("/*", "*", "//", "#")):
            continue
        if fname not in line:
            continue
        # 缩进行多为调用点；允许「行首空白 + 函数名起头」或 static，以支持 Tab 缩进的定义行
        if (
            line[0] in (" ", "\t")
            and not s.startswith(fname)
            and not s.startswith("static")
        ):
            continue
        sig_i = extend_signature_start(lines, i)
        end_i = _match_brace_end(lines, sig_i, fname, n)
        if end_i is None:
            continue
        key = (sig_i, end_i)
        if key in spans_seen:
            continue
        spans_seen.add(key)
        spans.append(key)

    if not spans:
        return None

    containing = [se for se in spans if se[0] <= target_idx <= se[1]]
    if containing:
        sig_idx, end_idx = min(containing, key=lambda se: se[1] - se[0])
    else:

        def edge_dist(se: tuple[int, int]) -> int:
            s, e = se
            return (target_idx - e) if target_idx > e else (s - target_idx)

        sig_idx, end_idx = min(spans, key=edge_dist)

    return "\n".join(lines[sig_idx : end_idx + 1])


def extract_function_by_lineno(source: str | None, target_lineno: int) -> str | None:
    """在源文件中找包含或紧跟 target_lineno 的函数体，不依赖函数名 hint。

    策略：
    1. 从 target_lineno 向上扫描找函数签名，要求 end_i >= target_idx
    2. 若向上找不到（target 在两个函数之间的空行），再向下找最近函数签名
    """
    if not source:
        return None
    lines = source.splitlines()
    n = len(lines)
    target_idx = min(max(target_lineno - 1, 0), n - 1)

    _FUNC_KEYWORDS = frozenset(
        (
            "if",
            "for",
            "while",
            "switch",
            "return",
            "sizeof",
            "else",
            "case",
            "default",
            "do",
        )
    )
    _FUNC_PREFIXES = (
        "static",
        "inline",
        "void",
        "int",
        "char",
        "bool",
        "BOOL",
        "LITE",
        "SWTMR",
        "STATIC",
        "unsigned",
        "struct",
        "enum",
        "UINT",
        "INT",
        "VOID",
    )

    def _try_find_func_at(sig_i: int) -> str | None:
        """尝试以 sig_i 为签名起点提取函数，要求函数体包含 target_idx 或紧随其后。"""
        line = lines[sig_i]
        if not line or not line.strip():
            return None
        s = line.lstrip()
        if s.startswith(("/*", "*", "//", "#")):
            return None
        if line[0] in (" ", "\t") and not s.startswith(_FUNC_PREFIXES):
            return None
        if "(" not in line:
            return None
        m = re.search(r"\b([a-zA-Z_]\w*)\s*\(", line)
        if not m:
            return None
        fname = m.group(1)
        if fname in _FUNC_KEYWORDS:
            return None
        end_i = _match_brace_end(lines, sig_i, fname, n)
        if end_i is None:
            return None
        # 函数包含 target，或 target 在函数签名之前的紧邻空行内
        if end_i >= target_idx:
            actual_sig = extend_signature_start(lines, sig_i)
            return "\n".join(lines[actual_sig : end_i + 1])
        return None

    # 1) 向上扫描
    for i in range(target_idx, max(target_idx - 200, -1), -1):
        result = _try_find_func_at(i)
        if result:
            return result

    # 2) 向下扫描（target 在两个函数之间的空行或紧贴下一函数签名前）
    for i in range(target_idx + 1, min(target_idx + 20, n)):
        result = _try_find_func_at(i)
        if result:
            return result

    return None


def hunk_sequences_from_body(body):
    old_seq, new_seq = [], []
    for raw in body.splitlines():
        if not raw:
            continue
        kind = raw[0]
        if kind not in " +-":
            continue
        code = raw[1:]
        if kind == " ":
            old_seq.append(code)
            new_seq.append(code)
        elif kind == "+":
            new_seq.append(code)
        elif kind == "-":
            old_seq.append(code)
    return old_seq, new_seq


def _lines_equal_seq(chunk, new_seq):
    if len(chunk) != len(new_seq):
        return False
    for a, b in zip(chunk, new_seq, strict=False):
        if a.rstrip("\r") != b.rstrip("\r"):
            return False
    return True


def _find_seq_in_lines(lines: list[str], seq: list[str], near: int) -> int | None:
    """在 lines 中以 near 为中心，搜索与 seq 完全匹配的起始行索引（允许 ±50 行偏移）。"""
    if not seq:
        return None
    radius = 50
    lo = max(0, near - radius)
    hi = min(len(lines) - len(seq), near + radius)
    best_idx: int | None = None
    best_dist = radius + 1
    for i in range(lo, hi + 1):
        chunk = lines[i : i + len(seq)]
        if _lines_equal_seq(chunk, seq) or _lines_equal_seq(
            [x.rstrip() for x in chunk], [x.rstrip() for x in seq]
        ):
            d = abs(i - near)
            if d < best_dist:
                best_dist = d
                best_idx = i
    return best_idx


def _find_seq_best_in_lines(
    lines: list[str], seq: list[str], near: int | None = None
) -> int | None:
    """在全文件中找与 seq 匹配的起始行；若给定 near（0-based 行索引），优先选距离最近的一处。"""
    if not seq:
        return None
    hi = len(lines) - len(seq)
    if hi < 0:
        return None
    best_idx: int | None = None
    best_dist = 10**9
    for i in range(0, hi + 1):
        chunk = lines[i : i + len(seq)]
        if _lines_equal_seq(chunk, seq) or _lines_equal_seq(
            [x.rstrip() for x in chunk], [x.rstrip() for x in seq]
        ):
            if near is None:
                return i
            d = abs(i - near)
            if d < best_dist:
                best_dist = d
                best_idx = i
    return best_idx


def realign_hunks_new_starts(
    new_src: str, hunk_list: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """按「修复后」全文重定位每个 hunk 的 new_start。

    公告补丁里的 @@ 行号常与 fix_sha 拉到的源文件不一致（差数百行），
    reconstruct 仅在 ±50 行内搜会整段失败，父版本逆向落空后只能误用 git parent
    或其它降级路径，导致抽到错误函数（如 22695 抽到 colormapped）。
    """
    if not new_src or not hunk_list:
        return hunk_list
    text = new_src.replace("\r\n", "\n")
    lines = text.splitlines()
    out = copy.deepcopy(hunk_list)
    adjusted = False
    for h in out:
        body = h.get("body") or ""
        if not body:
            continue
        old_seq, new_seq = hunk_sequences_from_body(body)
        near = max(0, int(h.get("new_start", 1)) - 1)
        found: int | None = None
        if new_seq:
            found = _find_seq_best_in_lines(lines, new_seq, near)
        if found is None:
            candidates: list[str] = []
            for raw in body.splitlines():
                if not raw.startswith(" "):
                    continue
                c = raw[1:].rstrip("\n\r")
                if len(c) < 18:
                    continue
                cs = c.strip()
                if cs.startswith(("/", "*", "//")):
                    continue
                candidates.append(c)
            if candidates:
                anchor = max(candidates, key=len)
                found = _find_seq_best_in_lines(lines, [anchor], near)
        if found is None:
            continue
        nl = found + 1
        old_nl = int(h.get("new_start") or 0)
        if nl != old_nl:
            h["new_start"] = nl
            adjusted = True
    if adjusted:
        print(
            "  [realign] 已按当前源文件对 hunk 的 new_start 重定位（修正 @@ 与 fix 版本错位）"
        )
    return out


def reconstruct_old_from_new(
    new_src: str | None, hunks: list[dict[str, Any]]
) -> str | None:
    """将 new_src + diff hunks 反向推算出旧版本全文。

    - 行号越界或不一致时先尝试在 ±50 行内模糊定位；若仍失败则跳过该 hunk。
    - 所有 hunk 都跳过时返回 None（调用方可降级为 derive_vulnerable）。
    """
    if not new_src or not hunks:
        return None
    lines = list(new_src.splitlines())
    skipped = 0
    for h in sorted(hunks, key=lambda x: x.get("new_start", 0), reverse=True):
        body = h.get("body")
        if not body:
            continue
        old_seq, new_seq = hunk_sequences_from_body(body)
        if not new_seq and not old_seq:
            continue
        start = h["new_start"] - 1
        end = start + len(new_seq)
        # 越界时尝试模糊定位
        if start < 0 or end > len(lines):
            found = _find_seq_in_lines(lines, new_seq, start) if new_seq else None
            if found is not None:
                start, end = found, found + len(new_seq)
            else:
                skipped += 1
                continue
        # 内容不一致时同样尝试模糊定位
        chunk = lines[start:end]
        if not _lines_equal_seq(chunk, new_seq) and not _lines_equal_seq(
            [x.rstrip() for x in chunk], [x.rstrip() for x in new_seq]
        ):
            found = _find_seq_in_lines(lines, new_seq, start) if new_seq else None
            if found is not None:
                start, end = found, found + len(new_seq)
            else:
                skipped += 1
                continue
        lines[start:end] = old_seq
    if skipped == len(hunks):
        return None
    return "\n".join(lines)


def parent_source_from_diff(
    new_src: str, hunk_list: list[dict[str, Any]]
) -> str | None:
    """由修复后全文 + diff 得到修复前全文。

    先按行号逆向应用 hunk（与补丁基准一致）；若失败（行错位、空白不一致等），
    再使用 ``build_versions_from_diff`` 的逐 hunk 子串替换（与多 hunk 非连续逻辑一致）。
    """
    if not new_src or not hunk_list:
        return None
    old = reconstruct_old_from_new(new_src, hunk_list)
    if old and old.strip() and old.strip() != new_src.strip():
        print("  [reconstruct] 行号逆向得到父版本全文")
        return old
    v_fb, f_fb = build_versions_from_diff(hunk_list, full_src=new_src, mode_src="new")
    if (
        v_fb
        and f_fb
        and not v_fb.lstrip().startswith("/* patch context")
        and v_fb.strip() != f_fb.strip()
    ):
        print("  [reconstruct] 逐 hunk 子串替换得到父版本全文")
        return v_fb
    return None


def diff_hunk_lines_embedded(
    vuln_text: str, fixed_text: str, hunk_list: list[dict[str, Any]]
) -> bool:
    """检查 diff 中是否有实质 +/- 行出现在对应版本提取结果里（按行 strip 比较）。

    用于发现「关键变更行」与「整函数提取」错位（多 hunk、父提交与补丁基准不一致等）。
    若仅有上下文行、无 +/-，视为通过。
    """
    vuln_strips = {ln.strip() for ln in vuln_text.splitlines() if ln.strip()}
    fix_strips = {ln.strip() for ln in fixed_text.splitlines() if ln.strip()}
    saw_change = False
    for h in hunk_list:
        body = h.get("body") or ""
        for raw in body.splitlines():
            if not raw or raw[0] not in "+-":
                continue
            code = raw[1:].strip()
            if len(code) < 5:
                continue
            saw_change = True
            if raw[0] == "-" and code in vuln_strips:
                return True
            if raw[0] == "+" and code in fix_strips:
                return True
    return not saw_change


def derive_vulnerable(
    fixed_func: str | None, all_hunks: list[dict[str, Any]]
) -> str | None:
    """从修复后函数反推漏洞函数：将 added 行替换回 removed 行。

    若没有发生任何实质替换（结果与输入完全相同），返回 None 而非相同内容，
    避免 vulnerable_code == fixed_code 的无效爬取。
    """
    if not fixed_func:
        return None
    result = fixed_func
    changed = False
    for hunk in all_hunks:
        added, removed = hunk["added"], hunk["removed"]
        for i, add_item in enumerate(added):
            code = add_item["code"]
            if code in result:
                if i < len(removed):
                    new_result = result.replace(code, removed[i]["code"], 1)
                else:
                    new_result = re.sub(re.escape(code) + r"\n?", "", result, count=1)
                if new_result != result:
                    changed = True
                result = new_result
    if not changed:
        return None
    return result


def _hunk_vuln_fixed_text_windows(h: dict[str, Any]) -> tuple[str, str]:
    """单 hunk 的 (漏洞侧拼接文本, 修复侧拼接文本)，不含 patch 注释。"""
    hl, fl = [], []
    for raw in (h.get("body") or "").splitlines():
        if not raw:
            continue
        k = raw[0]
        c = raw[1:] if k in "+- " else raw
        if k == " ":
            hl.append(c)
            fl.append(c)
        elif k == "-":
            hl.append(c)
        elif k == "+":
            fl.append(c)
    return "\n".join(hl), "\n".join(fl)


def build_versions_from_diff(
    hunk_list: list[dict[str, Any]],
    full_src: str | None = None,
    mode_src: str = "new",
) -> tuple[str, str]:
    """从 diff hunk 直接构造修复前/后两个版本的代码片段。

    逻辑：
    - 修复前（vulnerable）：context 行 + `-` 行，去掉 `+` 行
    - 修复后（fixed）：context 行 + `+` 行，去掉 `-` 行

    当提供了 full_src（完整函数体）时，将 diff 窗口内的变更区域精确替换到函数体中，
    得到完整的两个函数版本。否则仅返回 diff 上下文窗口（带行号注释）。

    Returns:
        (vulnerable_code, fixed_code) — 两者保证不同（若 diff 无变更则均为空串）。
    """
    vuln_lines: list[str] = []
    fixed_lines: list[str] = []

    for h in hunk_list:
        body = h.get("body", "")
        for raw in body.splitlines():
            if not raw:
                continue
            kind = raw[0] if raw else " "
            code = raw[1:] if kind in ("+", "-", " ") else raw
            if kind == " ":
                vuln_lines.append(code)
                fixed_lines.append(code)
            elif kind == "-":
                vuln_lines.append(code)
                # 不加入 fixed
            elif kind == "+":
                # 不加入 vuln
                fixed_lines.append(code)

    vuln_window = "\n".join(vuln_lines)
    fixed_window = "\n".join(fixed_lines)

    if not full_src:
        # 无完整源文件：直接返回 diff 窗口，附行号注释
        vuln_snippet = patch_snippet(hunk_list, "old")
        fixed_snippet = patch_snippet(hunk_list, "new")
        return vuln_snippet, fixed_snippet

    # 有完整源文件：将 diff 窗口替换进函数体
    # 以 mode_src 对应侧的窗口内容在 full_src 中定位并替换
    src_window = fixed_window if mode_src == "new" else vuln_window
    other_window = vuln_window if mode_src == "new" else fixed_window

    if src_window and src_window in full_src:
        if mode_src == "new":
            # full_src 是修复后：替换出修复前
            vuln_full = full_src.replace(src_window, other_window, 1)
            fixed_full = full_src
        else:
            # full_src 是修复前：替换出修复后
            vuln_full = full_src
            fixed_full = full_src.replace(src_window, other_window, 1)
        if vuln_full.strip() != fixed_full.strip():
            return vuln_full, fixed_full

    # 多段 hunk 在源文件中不连续，拼接后的 window 无法一次 in full_src：逐 hunk 替换
    if len(hunk_list) > 1:
        cur = full_src
        ok = True
        sort_key = "old_start" if mode_src == "old" else "new_start"
        for h in sorted(hunk_list, key=lambda x: x.get(sort_key, 0), reverse=True):
            vuln_w, fixed_w = _hunk_vuln_fixed_text_windows(h)
            if mode_src == "new":
                sw, ow = fixed_w, vuln_w
            else:
                sw, ow = vuln_w, fixed_w
            if not sw or sw not in cur:
                ok = False
                break
            cur = cur.replace(sw, ow, 1)
        if ok and cur.strip() != full_src.strip():
            if mode_src == "new":
                return cur, full_src
            return full_src, cur

    # 定位失败（行内空白等原因）：退回 diff 窗口
    vuln_snippet = patch_snippet(hunk_list, "old")
    fixed_snippet = patch_snippet(hunk_list, "new")
    return vuln_snippet, fixed_snippet


def patch_snippet(hunk_list: list[dict[str, Any]], mode: str) -> str:
    lines = ["/* patch context - source file unavailable */"]
    for h in hunk_list:
        start = h["old_start"] if mode == "old" else h["new_start"]
        lines.append(f"/* ... line {start} ... */")
        if mode == "old":
            items = sorted(
                [(c["old"], c["code"]) for c in h["context"]]
                + [(r["lineno"], r["code"]) for r in h["removed"]],
                key=lambda x: x[0],
            )
        else:
            items = sorted(
                [(c["new"], c["code"]) for c in h["context"]]
                + [(a["lineno"], a["code"]) for a in h["added"]],
                key=lambda x: x[0],
            )
        for lineno, code in items:
            lines.append(f"{lineno:5d}  {code}")
    return "\n".join(lines)
