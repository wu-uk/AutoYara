import os
import sys
from unittest.mock import MagicMock

# 加入 src 路径
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
src_path = os.path.join(project_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from autoyara.ReAct import ReActAgent
from autoyara.models import AgentTask
from autoyara.llm.sync_client import SyncLLMClient

def test_agent_with_mock_llm():
    # 1. 准备 Mock LLM
    mock_llm = MagicMock(spec=SyncLLMClient)
    
    # 模拟 LLM 的两轮对话
    # 第一轮：决定调用 get_hex_from_ida
    # 第二轮：根据 Observation 给出 Final Answer
    mock_llm.prompt.side_effect = [
        """Thought: I need to extract the hex for the main function.
Action: get_hex_from_ida
Action Input: {"elf_file_path": "tmp/hello", "function_name": "main"}
""",
        """Thought: I now have the hex for the main function.
Final Answer: The hex for function "main" is "55 48 89 E5 48 8D 05".
"""
    ]

    # 2. 准备工具 Mock (可选，这里直接用真实的或者 Mock)
    # 为了测试循环，我们 mock 掉 get_hex_from_ida 的调用
    agent = ReActAgent(llm_client=mock_llm)
    agent.tools["get_hex_from_ida"] = MagicMock(return_value="55 48 89 E5 48 8D 05")

    # 3. 运行任务
    task = AgentTask(
        cve_id="CVE-TEST",
        target_binary="tmp/hello",
        function_name="main"
    )
    
    print(f"--- Running Agent Task for {task.cve_id} ---")
    result = agent.run(task)

    # 4. 验证结果
    print(f"Success: {result.success}")
    print(f"Final Answer: {result.output}")
    print("\nSteps taken:")
    for i, step in enumerate(result.steps):
        print(f"Step {i+1}:")
        print(f"  Thought: {step['thought']}")
        print(f"  Action: {step['action']}")
        print(f"  Action Input: {step['action_input']}")
        print(f"  Observation: {step['observation']}")

    assert result.success is True
    assert "55 48 89 E5" in result.output
    print("\n[OK] Agent loop and IDA tool interaction verified with mock LLM.")

if __name__ == "__main__":
    test_agent_with_mock_llm()
