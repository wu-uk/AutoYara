import inspect

from openai import AsyncOpenAI

from autoyara.llm.sync_client import get_effective_openai_credentials

DEFAULT_MODEL = "deepseek/deepseek-v3.2"


class AsyncLLMClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        base_url: str | None = None,
        **kwargs,
    ):
        default_api_key, default_base_url = get_effective_openai_credentials()
        resolved_api_key = (api_key or "").strip() or default_api_key
        resolved_base_url = base_url or default_base_url
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
