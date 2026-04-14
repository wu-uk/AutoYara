"""Gitee Pull Request 辅助：匿名 unified diff 与 Open API access_token。"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import quote

from .http_client import get

_HEAD_SHA_RE = re.compile(r"head_sha=([0-9a-f]{40})")

# OpenHarmony PR 模板中常见的「原因/描述」节标题（Markdown h2 格式）
_OH_REASON_RE = re.compile(
    r"#+\s*原因[（(][^)\n）]*[)）]\s*\n+(.*?)(?=#+\s*|$)",
    re.S,
)
_OH_DESC_RE = re.compile(
    r"#+\s*描述[（(][^)\n）]*[)）]\s*\n+(.*?)(?=#+\s*|$)",
    re.S,
)


def gitee_access_token() -> str:
    return (
        os.environ.get("GITEE_ACCESS_TOKEN") or os.environ.get("GITEE_TOKEN") or ""
    ).strip()


def gitee_pull_api_url(owner: str, repo: str, num: str) -> str:
    """``GET .../pulls/:num``；若配置了 token 则附带 ``access_token``，减轻匿名 403 频控。"""
    base = f"https://gitee.com/api/v5/repos/{owner}/{repo}/pulls/{num}"
    tok = gitee_access_token()
    if tok:
        return f"{base}?access_token={quote(tok)}"
    return base


def try_gitee_pr_unified_diff(owner: str, repo: str, num: str) -> str | None:
    """Gitee 支持 ``/pulls/N.diff`` 匿名 HTTP，不占用 Open API 配额。"""
    for pr_path in (f"pulls/{num}", f"pull/{num}", f"merge_requests/{num}"):
        for suf in (".diff", ".patch"):
            pu = f"https://gitee.com/{owner}/{repo}/{pr_path}{suf}"
            print("  [pr] " + pu[:100])
            t = get(pu)
            if t and "diff --git" in t:
                print(f"  [OK] gitee PR unified diff {len(t)} bytes")
                return t.strip()
    return None


def fetch_gitee_pr_body(owner: str, repo: str, num: str) -> str:
    """通过 Gitee Open API v5 获取 PR body（包含 PR 模板中的「原因/描述」字段）。

    返回 PR body 原文（Markdown），失败时返回空字符串。
    """
    url = gitee_pull_api_url(owner, repo, num)
    t = get(url)
    if not t:
        return ""
    try:
        data = json.loads(t)
        return (data.get("body") or "").strip()
    except Exception:
        return ""


def parse_oh_pr_description(body: str) -> dict[str, str]:
    """从 OpenHarmony PR 模板正文中提取「原因」和「描述」字段。

    返回 ``{"reason": ..., "description": ..., "issue": ...}``。
    """
    result: dict[str, str] = {"reason": "", "description": "", "issue": ""}
    if not body:
        return result

    # 相关 Issue
    iss = re.search(r"#+\s*相关.{0,6}[Ii]ssue[^\n]*\n+(.*?)(?=#+\s*|$)", body, re.S)
    if iss:
        result["issue"] = iss.group(1).strip().splitlines()[0].strip()

    # 原因（目的、解决的问题等）
    reason_m = _OH_REASON_RE.search(body)
    if reason_m:
        result["reason"] = reason_m.group(1).strip()

    # 描述（做了什么，变了什么）
    desc_m = _OH_DESC_RE.search(body)
    if desc_m:
        result["description"] = desc_m.group(1).strip()

    return result


def scrape_gitee_pr_head_sha(owner: str, repo: str, num: str) -> str | None:
    """从 PR 页内嵌 ``gon`` 提取 ``head_sha``，供后续按 commit 拉取完整源文件。"""
    for path in (f"pulls/{num}", f"pull/{num}"):
        url = f"https://gitee.com/{owner}/{repo}/{path}"
        html = get(url, allow_html=True)
        if not html:
            continue
        m = _HEAD_SHA_RE.search(html)
        if m:
            s = m.group(1)
            print(f"  [gitee-pr] head_sha={s[:12]} (from PR page)")
            return s
    return None
