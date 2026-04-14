import json
import os
import re

from .discovery import UPSTREAM
from .gitcode import (
    fetch_gitcode_file_blob,
    get_parent_sha_gitcode,
    gitcode_auth_headers,
    gitcode_private_token,
)
from .http_client import SESSION, H, get

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


def fetch_source(
    oh_repo, filepath, ref, gh_owner="openharmony", *, allow_upstream_fallback=True
):
    """从 OH 镜像仓库获取源文件。

    allow_upstream_fallback=True（默认）：OH 仓库拉不到时，尝试从上游 master 获取
        （适用于 new_src，即 fix 后版本）。
    allow_upstream_fallback=False：禁止 fallback 到上游 master
        （必须用于 old_src，即 fix 前版本，避免新旧版本内容相同）。
    """
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
    if allow_upstream_fallback and oh_repo in UPSTREAM:
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
    """从 torvalds/linux 获取上游 commit 的 parent SHA"""
    if not upstream_sha:
        return None, None
    t = get(f"https://api.github.com/repos/torvalds/linux/commits/{upstream_sha}")
    if t and "{" in t:
        try:
            data = json.loads(t)
            if "API rate limit" in data.get("message", ""):
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
            desc = "\n".join(lines).strip()
    return {"title": title, "description": desc, "cve": cve}


def fetch_commit_meta_from_api(owner, repo, sha):
    """尝试从 GitHub/Gitee/GitCode API 获取 commit message。"""
    msg = ""
    if owner and repo and sha:
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
                    msg = ((data.get("commit") or {}).get("message") or "").strip()
                    if msg:
                        return msg
            except Exception:
                pass
        try:
            t = get(f"https://gitee.com/api/v5/repos/{owner}/{repo}/commits/{sha}")
            if t:
                data = json.loads(t)
                msg = (
                    data.get("commit", {}).get("message")
                    or data.get("message")
                    or data.get("title")
                    or ""
                ).strip()
                if msg:
                    return msg
        except Exception:
            pass
        if gitcode_private_token():
            try:
                url = f"https://gitcode.com/api/v5/repos/{owner}/{repo}/commits/{sha}"
                r = SESSION.get(
                    url, headers=gitcode_auth_headers(), timeout=25, verify=False
                )
                r.raise_for_status()
                data = r.json()
                msg = (
                    data.get("commit", {}).get("message")
                    or data.get("message")
                    or data.get("title")
                    or ""
                ).strip()
                if msg:
                    return msg
            except Exception:
                pass
    return ""


def fetch_vuln_description(item, diff_text):
    """
    聚合漏洞描述来源（优先级）：
    0) PR 讨论页「原因/描述」字段（OpenHarmony PR 模板，最权威）
    1) patch 头 Subject/正文
    2) commit API message
    3) commit 页面文本兜底
    """
    # 0) 优先使用 PR body 中「原因/描述」结构化字段
    pr_parsed = item.get("pr_description_parsed") or {}
    pr_reason = (pr_parsed.get("reason") or "").strip()
    pr_desc_body = (pr_parsed.get("description") or "").strip()
    pr_issue = (pr_parsed.get("issue") or "").strip()
    pr_title = pr_issue or ""
    pr_desc = ""
    if pr_reason and pr_desc_body:
        pr_desc = f"原因：{pr_reason}\n描述：{pr_desc_body}"
    elif pr_reason:
        pr_desc = pr_reason
    elif pr_desc_body:
        pr_desc = pr_desc_body

    info = parse_vuln_desc_from_patch_text(diff_text)
    title = info.get("title", "")
    desc = info.get("description", "")
    cve = info.get("cve", "")
    url = item.get("url", "")

    # 如果 PR body 有更好的来源，直接采用
    if pr_title and not title:
        title = pr_title
    if pr_desc and (not desc or len(pr_desc) > len(desc)):
        desc = pr_desc
        if pr_parsed:
            print(f"  [pr-desc] 使用 PR body 中的「原因/描述」字段 ({len(desc)} 字符)")
    m = re.match(
        r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)", url, re.I
    )
    owner = m.group(1) if m else "openharmony"
    repo = m.group(2) if m else item.get("repo", "")
    sha = m.group(3) if m else item.get("fix_sha")
    if not (title and desc):
        msg = fetch_commit_meta_from_api(owner, repo, sha)
        lines = []
        if msg:
            lines = [x.strip() for x in msg.splitlines()]
            lines = [x for x in lines if _clean_desc_line(x)]
        if lines:
            if not title:
                title = lines[0]
            if not desc:
                desc = "\n".join(lines[1:]).strip()
    if not (title and desc) and url:
        page = get(url, allow_html=True)
        txt = strip_html_to_text(page or "")
        if txt:
            if not cve:
                c = re.search(r"\b(CVE-\d{4}-\d+)\b", txt, re.I)
                if c:
                    cve = c.group(1).upper()
            if not title:
                tm = re.search(
                    r"(?:commit|修复|fix)\s*[:：]?\s*([^.]{20,200})", txt, re.I
                )
                if tm:
                    title = tm.group(1).strip()
            if not desc:
                dm = re.search(
                    r"(?:Upstream commit.*?)(object_err\(\).*?not crash in the process\.)",
                    txt,
                    re.I,
                )
                if dm:
                    desc = dm.group(1).strip()

    # 最后兜底：从 NVD API 补充描述
    cve_id = cve or item.get("cve", "")
    if not desc and cve_id and re.match(r"CVE-\d{4}-\d+", cve_id, re.I):
        try:
            from .nvd_fallback import fetch_nvd_info

            nvd = fetch_nvd_info(cve_id)
            if nvd.get("description"):
                desc = nvd["description"]
                print(f"  [nvd-desc] 从 NVD 补充描述 {len(desc)} 字符")
        except Exception:
            pass

    return {"title": title, "description": desc, "cve": cve}


def parse_fname_from_hint(func_hint):
    if not func_hint:
        return ""
    hint = func_hint.strip()
    matches = re.findall(r"([a-zA-Z_]\w*)\s*\(", hint)
    if matches:
        return matches[-1] if "::" in hint else matches[0]
    return re.split(r"[(\s]", hint)[0].strip()


def extend_signature_start(lines, sig_idx):
    """向上扩展函数签名起始行（处理多行签名如返回类型单独一行）。

    停止条件：
    - 上一行缩进（属于代码块内部）
    - 上一行是注释、预处理指令
    - 上一行以 } 或 ; 结尾（前一函数末尾或语句）
    - 上一行包含 -> 或 = （赋值/成员访问，属于语句而非签名）
    - 上一行包含 ( 且不像是函数签名的一部分
    """
    while sig_idx > 0:
        prev_raw = lines[sig_idx - 1]
        if not prev_raw.strip():
            # 空行：继续往上找，但最多跳过1行空行
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
        # 赋值语句或成员访问（不属于函数签名）
        if "->" in prev_raw or ("=" in prev_raw and "==" not in prev_raw):
            break
        sig_idx -= 1
    return sig_idx


def _match_brace_end(lines, sig_idx, fname, n):
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


def extract_function(source, func_hint, target_lineno):
    if not source:
        return None
    lines = source.splitlines()
    n = len(lines)
    target_idx = min(max(target_lineno - 1, 0), n - 1)
    fname = parse_fname_from_hint(func_hint)
    if not fname:
        return None

    spans_seen = set()
    spans = []
    for i, line in enumerate(lines):
        if not line or not line.strip():
            continue
        s = line.lstrip()
        if s.startswith(("/*", "*", "//", "#")):
            continue
        if fname not in line:
            continue
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

        def edge_dist(se):
            s, e = se
            return (target_idx - e) if target_idx > e else (s - target_idx)

        sig_idx, end_idx = min(spans, key=edge_dist)

    return "\n".join(lines[sig_idx : end_idx + 1])


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


def reconstruct_old_from_new(new_src, hunks):
    """用 new_src + diff hunks 逆向重建旧版本文件。

    倒序处理 hunk（从文件末尾往前），避免行号偏移问题。
    某个 hunk 匹配失败时跳过（不放弃整个重建），
    最后检查是否有 hunk 成功应用，没有则返回 None。
    """
    if not new_src or not hunks:
        return None
    lines = list(new_src.splitlines())
    applied = 0
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
        if start < 0 or end > len(lines):
            print(
                f"  [reconstruct] 行号越界 new_start={h.get('new_start')} "
                f"need [{start},{end}) len={len(lines)}，跳过此 hunk"
            )
            skipped += 1
            continue
        chunk = lines[start:end]
        if not _lines_equal_seq(chunk, new_seq):
            if not _lines_equal_seq(
                [x.rstrip() for x in chunk], [x.rstrip() for x in new_seq]
            ):
                print(
                    "  [reconstruct] 与 diff 中新侧行不一致 new_start={}，跳过此 hunk".format(
                        h.get("new_start")
                    )
                )
                skipped += 1
                continue
        lines[start:end] = old_seq
        applied += 1
    if applied == 0:
        print(f"  [reconstruct] 全部 {skipped} 个 hunk 均跳过，重建失败")
        return None
    if skipped:
        print(f"  [reconstruct] 应用 {applied} 个 hunk，跳过 {skipped} 个")
    return "\n".join(lines)


def _apply_hunk_reverse(result_lines: list, body: str) -> list:
    """将单个 hunk 的 diff body 逆向应用到 result_lines（fixed→vulnerable）。

    策略：
    1. 优先用整块匹配：在 result_lines 中定位连续的 new_seq，整块替换为 old_seq。
    2. 块匹配失败时降级：按 diff body 行序逐组处理连续的 +/- 行段，
       找到 + 行在 result_lines 里的位置，将该位置处的连续 + 行替换为对应的 - 行。
    """
    old_seq, new_seq = hunk_sequences_from_body(body)
    n = len(new_seq)
    if n == 0:
        return result_lines

    # --- 策略1：整块匹配 ---
    for i in range(len(result_lines) - n + 1):
        if all(result_lines[i + j].rstrip() == new_seq[j].rstrip() for j in range(n)):
            return result_lines[:i] + old_seq + result_lines[i + n :]

    # --- 策略2：按 diff 行序逐段处理 ---
    # 把 body 解析为"段"：每段是连续的 +/- 行组（夹在上下文行之间）
    # 段内：+ 行是需要从 result_lines 删除的，- 行是需要插入的
    segments: list[tuple[list[str], list[str]]] = []  # [(added_lines, removed_lines)]
    cur_added: list[str] = []
    cur_removed: list[str] = []

    for raw in body.splitlines():
        if raw.startswith("\\"):
            continue
        if raw.startswith("+"):
            cur_added.append(raw[1:])
        elif raw.startswith("-"):
            cur_removed.append(raw[1:])
        else:
            # 上下文行：flush 当前段
            if cur_added or cur_removed:
                segments.append((cur_added, cur_removed))
                cur_added, cur_removed = [], []
    if cur_added or cur_removed:
        segments.append((cur_added, cur_removed))

    lines = list(result_lines)
    for added_lines, removed_lines in segments:
        if not added_lines:
            # 纯删除段（diff 里只有 - 行，没有 + 行）：旧代码中有这些行，
            # 但在 fixed_func 里它们不存在，需要插入
            # → 找到上下文定位点（跳过，无法精确插入，保持原样）
            continue

        # 找到 added_lines 在 lines 中的起始位置
        na = len(added_lines)
        found = -1
        for i in range(len(lines) - na + 1):
            if all(lines[i + j].rstrip() == added_lines[j].rstrip() for j in range(na)):
                found = i
                break

        if found >= 0:
            # 将 found 位置处的 na 个 added 行替换为 removed 行
            lines = lines[:found] + removed_lines + lines[found + na :]

    return lines


def _extract_adjacent_minus_plus_pairs(body: str) -> list[tuple[str, str]]:
    """从 unified diff body 中提取紧邻的 (- 旧行, + 新行) 对。"""
    pairs: list[tuple[str, str]] = []
    lines = body.splitlines()
    i = 0
    while i < len(lines) - 1:
        a, b = lines[i], lines[i + 1]
        if a.startswith("---") or b.startswith("+++"):
            i += 1
            continue
        if a.startswith("-") and not a.startswith("--"):
            if b.startswith("+") and not b.startswith("++"):
                pairs.append((a[1:], b[1:]))
                i += 2
                continue
        i += 1
    return pairs


_MEMCPY_ROW_RE = re.compile(
    r"^(\s*)memcpy\s*\(\s*output_row\s*,\s*local_row\s*,\s*([^)]+)\)\s*;\s*$",
    re.MULTILINE,
)


def _memcpy_revert_to_old_vulnerable(text: str, old_line: str, new_line: str) -> str:
    """当 patch 的「新侧」与当前源码（如 master）不一致时，仍恢复 diff 里「旧侧」的 memcpy 行。

    典型：patch 把 ``(size_t)row_bytes`` 换成 ``copy_bytes``，但 master 已是 ``row_bytes``
    （无 cast），整块逆向匹配失败，需在函数内把 ``memcpy(..., row_bytes|copy_bytes)``
    写成 diff 里带 ``(size_t)row_bytes`` 的那一行。
    """
    if "(size_t)row_bytes" not in old_line or "memcpy" not in old_line:
        return text
    if "copy_bytes" not in new_line and "row_bytes" not in new_line:
        return text

    m = _MEMCPY_ROW_RE.search(text)
    if not m:
        return text
    inner = m.group(2).strip()
    if inner == "(size_t)row_bytes":
        return text
    if inner not in ("row_bytes", "copy_bytes"):
        return text

    indent = m.group(1)
    stmt = indent + old_line.strip()
    return text[: m.start()] + stmt + text[m.end() :]


def _apply_minus_plus_pair_reversals(text: str, body: str) -> str:
    """按相邻 -/+ 对把「新行」换回「旧行」，并处理 master 与 patch 新侧不完全一致的情况。"""
    if not body.strip():
        return text
    for old_line, new_line in _extract_adjacent_minus_plus_pairs(body):
        if new_line in text:
            text = text.replace(new_line, old_line, 1)
            continue
        nu = new_line.rstrip()
        ou = old_line.rstrip()
        replaced = False
        parts = text.split("\n")
        out: list[str] = []
        for line in parts:
            if not replaced and line.rstrip() == nu:
                indent = line[: len(line) - len(line.lstrip())]
                out.append(indent + ou)
                replaced = True
            else:
                out.append(line)
        text = "\n".join(out)
        if replaced:
            continue
        text = _memcpy_revert_to_old_vulnerable(text, old_line, new_line)
    return text


def derive_vulnerable(fixed_func, all_hunks):
    """从修复后函数逆向重建漏洞版本函数。

    对每个 hunk，用 _apply_hunk_reverse 将 fixed_func 中的 + 行替换回 - 行，
    以恢复漏洞版本代码。

    再按各 hunk 的相邻 -/+ 行做一次补充替换：解决「patch 针对旧版、当前拉取的是
    master」导致 new 侧与源码不完全一致、整块匹配失败而漏掉 ``(size_t)`` 等细节的问题。
    """
    if not fixed_func:
        return None

    result_lines = fixed_func.splitlines()

    for hunk in all_hunks:
        body = hunk.get("body", "")
        if not body:
            # 无 body 时跳过（patch_snippet 模式下不应调用此函数）
            continue
        result_lines = _apply_hunk_reverse(result_lines, body)

    text = "\n".join(result_lines)
    for hunk in all_hunks:
        text = _apply_minus_plus_pair_reversals(text, hunk.get("body", ""))

    return text


def patch_snippet(hunk_list, mode):
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
