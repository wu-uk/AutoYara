"""extract_function：hunk 行号落在邻接函数体内时仍应命中 hunk 头所指函数。"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from autoyara.collectors.analysis import (
    _hunk_vuln_fixed_text_windows,
    build_versions_from_diff,
    diff_hunk_lines_embedded,
    extract_function,
    extract_function_for_hunks,
    parent_source_from_diff,
    parse_fname_from_hint,
)


def test_extract_prefers_span_containing_target():
    src = """static int
png_image_read_colormapped(void* argument)
{
   int x;
   line3268_placeholder();
}

static int
png_image_read_direct_scaled(void* argument)
{
   png_ptr();
   memcpy(a,b,row_bytes);
}
"""
    hint = "png_image_read_direct_scaled(void* argument)"
    out = extract_function(src, hint, 8)
    assert out
    assert "png_image_read_direct_scaled" in out
    assert "colormapped" not in out
    assert "memcpy" in out


def test_parse_fname_c_vs_cpp():
    assert parse_fname_from_hint(
        "png_image_read_direct_scaled(png_voidp argument)"
    ) == ("png_image_read_direct_scaled")
    assert parse_fname_from_hint("ns::Class::method(int x)") == "method"


def test_build_versions_multi_hunk_non_contiguous():
    """两段 hunk 中间有未出现在 diff 里的行时，仍能整文件替换得到漏洞/修复版。"""
    full_new = """void f(void) {
   int a = 1;
   int x = 1;
   int mid = 99;
   int y = 2;
   return;
}
"""
    h1 = {
        "old_start": 2,
        "new_start": 2,
        "body": "   int a = 1;\n-   int x = 0;\n+   int x = 1;\n",
        "context": [],
        "removed": [],
        "added": [],
    }
    h2 = {
        "old_start": 5,
        "new_start": 5,
        "body": "   int mid = 99;\n-   int y = 0;\n+   int y = 2;\n",
        "context": [],
        "removed": [],
        "added": [],
    }
    v, f = build_versions_from_diff([h1, h2], full_src=full_new, mode_src="new")
    assert "int x = 0" in v and "int x = 1" in f
    assert "int y = 0" in v and "int y = 2" in f
    assert "int mid = 99" in v
    assert diff_hunk_lines_embedded(v, f, [h1, h2])


def test_extract_function_for_hunks_wrong_hint_uses_anchor():
    """@@ 函数名错误时，用 +/- 行锚点 + 反向推断仍能抽到真实函数。"""
    src = """static int
png_image_read_colormapped(void* a)
{
   return 0;
}

static int
\tpng_image_read_direct_scaled(png_voidp argument)
{
   png_read_row(png_ptr, local_row, NULL);
          memcpy(output_row, local_row, copy_bytes);
}
"""
    hlist = [
        {
            "old_start": 1,
            "new_start": 1,
            "body": "",
            "added": [
                {
                    "code": "          memcpy(output_row, local_row, copy_bytes);",
                    "lineno": 1,
                }
            ],
            "removed": [],
            "context": [],
        }
    ]
    out = extract_function_for_hunks(
        src, "png_image_read_colormapped(void)", 2, hlist, fixed_side=True
    )
    assert out
    assert "png_image_read_direct_scaled" in out
    assert "memcpy" in out
    assert "png_image_read_colormapped" not in out


def test_parent_source_from_diff_build_versions_fallback():
    """行号 reconstruct 失败时，parent_source_from_diff 用逐 hunk 子串替换得到父本。"""
    from autoyara.collectors.oh_crawler.diff_utils import parse_diff_full

    diff = (
        Path(__file__).resolve().parents[1] / "output" / "cve_2026_22695_v2.diff"
    ).read_text(encoding="utf-8")
    h = [x for x in parse_diff_full(diff) if x["file"] == "pngread.c"]
    f0 = _hunk_vuln_fixed_text_windows(h[0])[1]
    f1 = _hunk_vuln_fixed_text_windows(h[1])[1]
    prefix = """static int
png_image_read_direct_scaled(png_voidp argument)
{
   png_image_read_control *display = png_voidcast(png_image_read_control*,
"""
    new_src = prefix + f0 + "\n   {\n      {\n" + f1 + "\n}\n"
    par = parent_source_from_diff(new_src, h)
    assert par and "(size_t)row_bytes" in par
    assert "copy_bytes" not in par
    hint = h[0]["function_hint"]
    old_ref = max(x["old_start"] for x in h)
    new_ref = max(x["new_start"] for x in h)
    vu = extract_function_for_hunks(par, hint, old_ref, h, fixed_side=False)
    fx = extract_function_for_hunks(new_src, hint, new_ref, h, fixed_side=True)
    assert vu and fx and vu.strip() != fx.strip()
    assert diff_hunk_lines_embedded(vu, fx, h)


def test_cve_22695_no_colormapped_leak_and_memcpy_semantics():
    """CVE-2026-22695：与仓库内 v2 补丁一致的合成场景下，不得抽到 colormapped；memcpy 语义与截图一致。"""
    from autoyara.collectors.oh_crawler.diff_utils import parse_diff_full

    diff = (
        Path(__file__).resolve().parents[1] / "output" / "cve_2026_22695_v2.diff"
    ).read_text(encoding="utf-8")
    h = [x for x in parse_diff_full(diff) if x["file"] == "pngread.c"]
    f0 = _hunk_vuln_fixed_text_windows(h[0])[1]
    f1 = _hunk_vuln_fixed_text_windows(h[1])[1]
    prefix = """static int
png_image_read_direct_scaled(png_voidp argument)
{
   png_image_read_control *display = png_voidcast(png_image_read_control*,
"""
    new_src = prefix + f0 + "\n   {\n      {\n" + f1 + "\n}\n"
    par = parent_source_from_diff(new_src, h)
    assert par is not None
    hint = h[0]["function_hint"]
    assert "direct_scaled" in hint
    old_ref = max(x["old_start"] for x in h)
    new_ref = max(x["new_start"] for x in h)
    vu = extract_function_for_hunks(par, hint, old_ref, h, fixed_side=False)
    fx = extract_function_for_hunks(new_src, hint, new_ref, h, fixed_side=True)
    assert vu and fx
    for blob, label in ((vu, "vuln"), (fx, "fixed")):
        assert "png_image_read_colormapped" not in blob, label
        assert "png_image_read_direct_scaled" in blob, label

    def _n(s: str) -> str:
        return re.sub(r"\s+", "", s)

    assert "memcpy(output_row,local_row,(size_t)row_bytes)" in _n(vu)
    assert "copy_bytes" in fx
    assert "memcpy(output_row,local_row,copy_bytes)" in _n(fx)
    assert "memcpy(output_row,local_row,(size_t)row_bytes)" not in _n(fx)


def test_diff_hunk_lines_embedded_negative():
    h = {
        "body": "-  memcpy(bad);\n+  memcpy(good);\n",
        "context": [],
        "removed": [],
        "added": [],
    }
    assert not diff_hunk_lines_embedded("void x(){ }", "void x(){ }", [h])


if __name__ == "__main__":
    test_extract_prefers_span_containing_target()
    test_parse_fname_c_vs_cpp()
    test_build_versions_multi_hunk_non_contiguous()
    test_extract_function_for_hunks_wrong_hint_uses_anchor()
    test_parent_source_from_diff_build_versions_fallback()
    test_cve_22695_no_colormapped_leak_and_memcpy_semantics()
    test_diff_hunk_lines_embedded_negative()
    print("ok")
