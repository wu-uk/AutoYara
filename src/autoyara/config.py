from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "config.yaml"


class Settings:
    def __init__(self) -> None:
        self._config = self._load_external_config()

    def _load_external_config(self) -> dict:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                return data
            raise ValueError(f"配置文件格式错误: {CONFIG_PATH}")
        raise FileNotFoundError(
            f"配置文件未找到: {CONFIG_PATH}\n请参考 configs/config.yaml.example 创建配置文件"
        )

    @property
    def python_path(self) -> str:
        return self._config["PYTHON_PATH"]

    @property
    def ida_path(self) -> str:
        return self._config["IDA_PATH"]

    @property
    def log_dir(self) -> str:
        log_dir = PROJECT_ROOT / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        return str(log_dir)

    @property
    def tmp_dir(self) -> str:
        tmp_dir = PROJECT_ROOT / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        return str(tmp_dir)

    @property
    def openai_api_key(self) -> str:
        return self._config.get("OPENAI_API_KEY", "")

    @property
    def server_cmd(self) -> list[str]:
        return [
            self.python_path,
            str(PROJECT_ROOT / "src" / "autoyara" / "ida" / "server.py"),
        ]


settings = Settings()


__all__ = ["Settings", "settings"]
