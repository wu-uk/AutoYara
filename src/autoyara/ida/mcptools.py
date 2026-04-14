# 标准库
import asyncio  # noqa: I001

# 第三方库
from mcp import stdio_client, StdioServerParameters

# 内部模块
from autoyara.config import settings


def get_hex_from_ida(elf_file_path, function_name):
    server_cmd = settings.server_cmd

    async def _call():
        params = StdioServerParameters(
            command=server_cmd[0],
            args=server_cmd[1:],
            env=None,
        )
        async with stdio_client(params) as (read, write):
            from mcp import ClientSession
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.call_tool(
                    "get_hex_from_ida",
                    {
                        "elf_file_path": elf_file_path,
                        "function_name": function_name,
                    },
                )

    return asyncio.run(_call())
