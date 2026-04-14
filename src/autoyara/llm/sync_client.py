import os

import httpx
from openai import OpenAI

DEFAULT_MODEL = "openai/gpt-4o"


def _default_openai_credentials() -> tuple[str, str | None]:
    """优先环境变量，其次仓库根目录 ``configs/config.yaml``（需已将项目根加入 sys.path）。"""
    key = (
        os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENROUTER_API_KEY") or ""
    ).strip()
    base = (
        os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENROUTER_BASE_URL") or ""
    ).strip() or None
    try:
        from configs.config import settings

        if not key:
            key = settings.openai_api_key.strip()
        if base is None or not base:
            bu = settings.openai_base_url.strip()
            if bu:
                base = bu
    except Exception:
        pass
    return key, base


def _build_http_client() -> httpx.Client | None:
    """从环境变量读取代理配置，构造显式代理的 httpx.Client。"""
    proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    if not proxy:
        return None
    return httpx.Client(proxy=proxy, verify=False)


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
        http_client = _build_http_client()
        if http_client is not None:
            kwargs.setdefault("http_client", http_client)
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
