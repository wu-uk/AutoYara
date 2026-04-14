import inspect
import os

import httpx
from openai import AsyncOpenAI

DEFAULT_MODEL = "openai/gpt-4o"


def _default_openai_credentials() -> tuple[str, str | None]:
    try:
        from configs.config import settings
    except Exception:
        return "", None
    api_key = settings.openai_api_key.strip()
    base_url = settings.openai_base_url.strip() or None
    return api_key, base_url


def _build_async_http_client() -> httpx.AsyncClient | None:
    """从环境变量读取代理配置，构造显式代理的 httpx.AsyncClient。"""
    proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    if not proxy:
        return None
    return httpx.AsyncClient(proxy=proxy, verify=False)


class AsyncLLMClient:
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
        http_client = _build_async_http_client()
        if http_client is not None:
            kwargs.setdefault("http_client", http_client)
        self.client = AsyncOpenAI(
            api_key=resolved_api_key,
            base_url=resolved_base_url,
            **kwargs,
        )
        self.model = model

    async def chat(self, messages: list[dict]) -> str:
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
        )
        return response.choices[0].message.content or ""

    async def prompt(self, text: str) -> str:
        return await self.chat([{"role": "user", "content": text}])

    async def close(self) -> None:
        close_method = getattr(self.client, "close", None)
        if not callable(close_method):
            return
        result = close_method()
        if inspect.isawaitable(result):
            await result

    async def __aenter__(self) -> "AsyncLLMClient":
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb) -> bool:
        await self.close()
        return False


async def create_async_client(
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    base_url: str | None = None,
    **kwargs,
) -> AsyncLLMClient:
    return AsyncLLMClient(api_key=api_key, model=model, base_url=base_url, **kwargs)
