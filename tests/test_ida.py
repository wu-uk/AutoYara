import json
import os
import shutil
from unittest.mock import MagicMock, patch

import pytest

from autoyara.config import settings
from autoyara.ida.server import get_hex_from_ida


@pytest.fixture
def elf_file(tmp_path):
    """创建一个临时的 ELF 文件"""
    elf_path = tmp_path / "test.elf"
    elf_path.write_text("dummy elf content")
    return str(elf_path)


@pytest.fixture
def ida_file(tmp_path):
    ida_path = tmp_path / "ida.exe"
    ida_path.write_text("dummy ida")
    return str(ida_path)

@pytest.fixture(autouse=True)
def clean_tmp_dirs():
    old_dirs = set(os.listdir(settings.tmp_dir))
    yield
    new_dirs = set(os.listdir(settings.tmp_dir)) - old_dirs
    for d in new_dirs:
        dir_path = os.path.join(settings.tmp_dir, d)
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path, ignore_errors=True)

@patch("autoyara.ida.server.subprocess.Popen")
def test_get_hex_from_ida_mock(mock_popen, elf_file, ida_file):
    mock_process = MagicMock()
    mock_process.poll.return_value = 0
    mock_process.pid = 1234
    mock_popen.return_value = mock_process

    def mock_read_text(path, default=""):
        if "output.json" in path:
            return json.dumps(
                {
                    "status": "success",
                    "func_name": "main",
                    "hex": "55 48 89 E5",
                }
            )
        if "done.txt" in path:
            return "ok"
        return default

    real_exists = os.path.exists
    with patch("autoyara.ida.server.IDA_PATH", ida_file), patch(
        "autoyara.ida.server.read_text", side_effect=mock_read_text
    ), patch(
        "autoyara.ida.server.os.path.exists",
        side_effect=lambda p: (
            "output.json" in str(p) or "done.txt" in str(p) or real_exists(p)
        ),
    ):
        result = get_hex_from_ida(elf_file, "main")
        assert "函数 main 的 Hex:" in result
        assert "55 48 89 E5" in result

def test_invalid_file_path():
    result = get_hex_from_ida("non_existent_file.elf", "main")
    assert "Error: 文件不存在" in result
