import os
import sys

from openai import OpenAI

DEFAULT_MODEL = "deepseek/deepseek-v3.2"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


def get_effective_openai_credentials() -> tuple[str, str | None]:
    """合并环境变量与 ``configs/config.yaml`` 中的 OpenAI 凭据。

    优先级：环境变量 > config.yaml > DEFAULT_BASE_URL 兜底。
    """
    env_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    env_base = (os.environ.get("OPENAI_BASE_URL") or "").strip() or None
    cfg_key, cfg_base = "", None
    try:
        from configs.config import settings

        cfg_key = (getattr(settings, "openai_api_key", None) or "").strip()
        cfg_base = (getattr(settings, "openai_base_url", None) or "").strip() or None
    except Exception:
        pass
    api_key = env_key or cfg_key
    base_url = env_base or cfg_base or DEFAULT_BASE_URL
    return api_key, base_url


def ensure_llm_api_key_or_exit(*, script_hint: str = "") -> None:
    """在启用 LLM 的脚本入口调用：未配置 API key 则打印说明并以退出码 2 结束。"""
    key, _ = get_effective_openai_credentials()
    if key:
        return
    lines = [
        "错误：已启用 LLM 审查，但未检测到 OPENAI_API_KEY。",
        "",
        "请任选其一配置：",
        "  1) 环境变量：OPENAI_API_KEY（可选 OPENAI_BASE_URL）",
        "  2) 仓库根目录 configs/config.yaml 中填写 OPENAI_API_KEY",
        "",
        "或使用 --no-llm / --no-quality-check 跳过审查。",
    ]
    if script_hint:
        lines = [lines[0], "", script_hint, ""] + lines[1:]
    sys.stderr.write("\n".join(lines) + "\n")
    raise SystemExit(2)


def _default_openai_credentials() -> tuple[str, str | None]:
    return get_effective_openai_credentials()


class SyncLLMClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        base_url: str | None = None,
        **kwargs,
    ):
        default_api_key, default_base_url = _default_openai_credentials()
        resolved_api_key = (api_key or "").strip() or default_api_key
        resolved_base_url = base_url or default_base_url
        self.client = OpenAI(
            api_key=resolved_api_key,
            base_url=resolved_base_url,
            **kwargs,
        )
        self.model = model

    def chat(self, messages: list[dict]) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
        )
        return response.choices[0].message.content or ""

    def prompt(self, text: str) -> str:
        return self.chat([{"role": "user", "content": text}])

    def close(self) -> None:
        close_method = getattr(self.client, "close", None)
        if callable(close_method):
            close_method()

    def __enter__(self) -> "SyncLLMClient":
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb) -> bool:
        self.close()
        return False


def create_sync_client(
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    base_url: str | None = None,
    **kwargs,
) -> SyncLLMClient:
    return SyncLLMClient(api_key=api_key, model=model, base_url=base_url, **kwargs)
