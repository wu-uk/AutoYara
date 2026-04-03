from openai import OpenAI

DEFAULT_MODEL = "gpt-5"


class SyncLLMClient:
    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str | None = None,
        **kwargs,
    ):
        self.client = OpenAI(api_key=api_key, base_url=base_url, **kwargs)
        self.model = model

    def chat(self, messages: list[dict]) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
        )
        return response.choices[0].message.content or ""

    def prompt(self, text: str) -> str:
        return self.chat([{"role": "user", "content": text}])


def create_sync_client(
    api_key: str,
    model: str = DEFAULT_MODEL,
    base_url: str | None = None,
    **kwargs,
) -> SyncLLMClient:
    return SyncLLMClient(api_key=api_key, model=model, base_url=base_url, **kwargs)
