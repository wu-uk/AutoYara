import re

from .http_client import get

UPSTREAM = {
    "third_party_libpng": ("pnggroup", "libpng", "master"),
    "third_party_libexif": ("libexif", "libexif", "master"),
    "third_party_curl": ("curl", "curl", "master"),
    "third_party_zlib": ("madler", "zlib", "master"),
    "third_party_openssl": ("openssl", "openssl", "master"),
    "third_party_expat": ("libexpat", "libexpat", "master"),
    "third_party_libwebp": ("webmproject", "libwebp", "main"),
}


def fetch_bulletin(year, month):
    for url in [
        f"https://gitcode.com/openharmony/security/raw/master/zh/security-disclosure/{year}/{year}-{month:02d}.md",
        f"https://gitee.com/openharmony/security/raw/master/zh/security-disclosure/{year}/{year}-{month:02d}.md",
        f"https://raw.githubusercontent.com/openharmony/security/master/zh/security-disclosure/{year}/{year}-{month:02d}.md",
    ]:
        print("[bulletin] " + url)
        t = get(url)
        if t and len(t) > 200 and ("CVE" in t or "|" in t):
            print(f"[OK] {len(t)} bytes")
            return t
    return None


def classify_url(url):
    if re.search(r"/commit/[0-9a-f]{7,40}", url, re.I):
        return "commit"
    if re.search(r"/(pulls|pull|merge_requests)/\d+", url, re.I):
        return "pr"
    if re.search(r"/blob/[0-9a-f]{7,40}/.*\.patch", url, re.I):
        return "patch"
    return "other"


def _split_cells(line: str) -> list[str]:
    """将 Markdown 表格行按 | 分割为单元格列表（去首尾空格）。"""
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _is_separator_row(cells: list[str]) -> bool:
    """判断是否为表格分隔行（全为 --- / :---: 等）。"""
    return bool(cells) and all(re.match(r"^[-: ]+$", c) for c in cells if c.strip())


def parse_bulletin_meta(md: str) -> dict[str, dict]:
    """
    解析公告 Markdown，返回每个 CVE 的元数据字典（漏洞描述/漏洞影响等）。

    仅解析有 「漏洞描述」 和 「漏洞影响」 列的第一种表格（OpenHarmony 自有仓漏洞）。
    三方库漏洞所在的第二种表格无这两列，对应 CVE 的 vuln_type/vuln_impact 为空。

    返回格式::

        {
            "CVE-2026-0639": {
                "vuln_type":   "LiteOS_a内存泄露漏洞",
                "vuln_impact": "本地攻击者可造成DOS",
            },
            ...
        }
    """
    meta: dict[str, dict] = {}
    col_vuln_type = -1
    col_vuln_impact = -1

    for line in md.splitlines():
        if not line.strip().startswith("|"):
            col_vuln_type = -1
            col_vuln_impact = -1
            continue

        cells = _split_cells(line)

        if _is_separator_row(cells):
            continue

        first = cells[0] if cells else ""

        # 检测表头行：第一格含 "CVE" 但不是实际 CVE ID
        if "CVE" in first and not re.match(r"CVE-\d{4}-\d+", first.strip()):
            col_vuln_type = -1
            col_vuln_impact = -1
            for i, h in enumerate(cells):
                if "漏洞描述" in h:
                    col_vuln_type = i
                elif "漏洞影响" in h:
                    col_vuln_impact = i
            continue

        cve_m = re.match(r"(CVE-[\d-]+)", first.strip())
        if not cve_m:
            continue
        cve = cve_m.group(1)

        vuln_type = (
            cells[col_vuln_type].strip() if 0 <= col_vuln_type < len(cells) else ""
        )
        vuln_impact = (
            cells[col_vuln_impact].strip() if 0 <= col_vuln_impact < len(cells) else ""
        )
        # 过滤占位符"无"
        vuln_type = "" if vuln_type in ("无", "-", "") else vuln_type
        vuln_impact = "" if vuln_impact in ("无", "-", "") else vuln_impact

        meta[cve] = {"vuln_type": vuln_type, "vuln_impact": vuln_impact}

    return meta


def parse_all_links(md: str) -> list[dict]:
    """
    解析公告 Markdown，返回含修复链接的 CVE 条目列表。

    每条记录包含：cve, repo, severity, version_label, url, url_type,
                  vuln_type（漏洞描述），vuln_impact（漏洞影响）。
    """
    # 先整体解析出各 CVE 的元数据
    meta_map = parse_bulletin_meta(md)

    results = []
    for line in md.splitlines():
        if not line.strip().startswith("|"):
            continue
        cve_m = re.search(r"\b(CVE-[\d-]+)\b", line)
        if not cve_m:
            continue
        cve = cve_m.group(1)
        repo_m = re.search(
            r"(third_party_[\w.]+|kernel_[\w.]+|arkcompiler_[\w.]+|security_[\w.]+|communication_[\w.]+)",
            line,
        )
        repo = repo_m.group(1) if repo_m else ""
        sev_m = re.search(r"(严重|高危|中危|低危|无)", line)
        severity = sev_m.group(1) if sev_m else ""

        cve_meta = meta_map.get(cve, {})
        vuln_type = cve_meta.get("vuln_type", "")
        vuln_impact = cve_meta.get("vuln_impact", "")

        for label_raw, url_raw in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", line):
            for url in re.split(r"[;；]", url_raw):
                url = url.strip().rstrip(".,;)")
                if not url.startswith("http"):
                    continue
                t = classify_url(url)
                if t != "other":
                    results.append(
                        {
                            "cve": cve,
                            "repo": repo,
                            "severity": severity,
                            "version_label": label_raw.strip(),
                            "url": url,
                            "url_type": t,
                            "vuln_type": vuln_type,
                            "vuln_impact": vuln_impact,
                        }
                    )
    return results
