import os
import sys

# 加入 src 路径
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
src_path = os.path.join(project_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from autoyara.ReAct import ReActAgent
from autoyara.models import AgentTask
from autoyara.llm.sync_client import create_sync_client
from autoyara.config import settings

def run_real_agent():
    # 1. 创建真实的 LLM Client（自动读取 settings）
    client = create_sync_client()

    # 2. 初始化 Agent
    agent = ReActAgent(llm_client=client)

    # 3. 准备任务
    # 使用之前测试过的 hello_world.elf
    elf_path = os.path.join(project_root, "tmp", "hello")
    if not os.path.exists(elf_path):
        print(f"Error: 找不到测试二进制文件: {elf_path}")
        return

    task = AgentTask(
        cve_id="CVE-2024-REAL-TEST",
        target_binary=elf_path,
        function_name="main"
    )

    print(f"--- Starting Real Agent Task ---")
    print(f"CVE: {task.cve_id}")
    print(f"Binary: {task.target_binary}")
    print(f"Function: {task.function_name}")
    print("-" * 30)

    # 4. 运行
    try:
        result = agent.run(task)
        
        # 5. 输出结果
        print(f"\nFinal Success: {result.success}")
        print(f"Final Answer: {result.output}")
        
            
    except Exception as e:
        print(f"Execution failed: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    run_real_agent()
