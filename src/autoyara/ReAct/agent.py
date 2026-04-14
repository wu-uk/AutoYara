from __future__ import annotations

import json
import re
from typing import Any, Callable

from autoyara.ida.mcptools import get_hex_from_ida
from autoyara.llm.sync_client import SyncLLMClient
from autoyara.models import AgentResult, AgentTask
from autoyara.runtime_logger import create_runtime_logger

from .internal_types import AgentState, AgentStep


class ReActAgent:
    def __init__(
        self,
        llm_client: SyncLLMClient,
        max_steps: int = 10,
    ):
        self.llm = llm_client
        self.max_steps = max_steps
        self.tools: dict[str, Callable] = {
            "get_hex_from_ida": get_hex_from_ida,
        }

    def _get_prompt(self, task: AgentTask) -> str:
        prompt = f"""
You are a security researcher agent specializing in binary analysis and CVE matching.
Your goal is to extract hex for a specific function using IDA MCP for CVE: {task.cve_id}.

TOOLS:
- get_hex_from_ida(elf_file_path: str, function_name: str) -> str:
  Extracts the hex string for a given function in an ELF file.

GUIDELINES:
1. ALWAYS use the `get_hex_from_ida` tool to get the hex string. 
2. DO NOT guess, hallucinate, or provide any hex strings from your own knowledge.
3. If the tool returns an error, report it.
4. When providing Hex strings in the Final Answer, ALWAYS maintain the original format from the tool (UPPERCASE with spaces, e.g., "55 48 89 E5"). DO NOT remove spaces or convert to lowercase.
5. You must return ONLY valid JSON object, no extra text.

Return schema:
{{
  "thought": "string",
  "action": "get_hex_from_ida" or null,
  "action_input": {{"elf_file_path": "string", "function_name": "string"}} or {{}},
  "final_answer": "string" or null
}}

Begin!

Task: Extract hex for function "{task.function_name}" from binary "{task.target_binary}"
"""
        return prompt

    def _parse_llm_json(self, text: str) -> dict[str, Any] | None:
        raw = (text or "").strip()
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return None
        except json.JSONDecodeError:
            pass
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            return None
        try:
            parsed = json.loads(m.group(0))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
        return None

    def run(self, task: AgentTask) -> AgentResult:
        state = AgentState(max_steps=self.max_steps)
        prompt = self._get_prompt(task)
        history = prompt
        logger = create_runtime_logger(prefix="agent", task_id=task.cve_id)
        logger.info("task", f"Starting task: {task.cve_id}")

        for step_idx in range(self.max_steps):
            logger.info("step", f"--- Step {step_idx + 1} ---")
            response = self.llm.prompt(history)
            logger.debug("llm_response_raw", response)
            payload = self._parse_llm_json(response)
            if payload is None:
                logger.info("error", "Failed to parse LLM JSON response")
                state.finished = True
                state.result = f"Failed to parse LLM JSON response: {response}"
                break

            thought = str(payload.get("thought") or "").strip()
            action = payload.get("action")
            final_answer = payload.get("final_answer")
            action_input = payload.get("action_input")

            logger.info("thought", thought or "(empty)")

            if action:
                action_name = str(action).strip()
                if not isinstance(action_input, dict):
                    observation = f"Error: Invalid action_input, expected object: {action_input}"
                    logger.info("error", observation)
                    history += f"\nTool Observation:\n{observation}\nRespond with JSON only."
                    continue

                logger.info("action", action_name)
                logger.info("action_input", json.dumps(action_input, ensure_ascii=False))

                if action_name in self.tools:
                    try:
                        logger.info("tool_exec", f"Executing {action_name}")
                        observation = self.tools[action_name](**action_input)
                        logger.info("observation", str(observation))
                    except Exception as e:
                        observation = f"Error: Failed to execute {action_name}: {e}"
                        logger.info("error", observation)
                else:
                    observation = f"Error: Unknown tool: {action_name}"
                    logger.info("error", observation)

                step = AgentStep(
                    thought=thought,
                    action=action_name,
                    action_input=action_input,
                    observation=str(observation),
                )
                state.steps.append(step)
                history += f"\nTool Observation:\n{observation}\nRespond with JSON only."
                continue

            if final_answer:
                final_text = str(final_answer).strip()
                logger.info("final_answer", final_text)
                state.steps.append(
                    AgentStep(
                        thought=thought,
                        action="final_answer",
                        action_input={},
                        observation=final_text,
                    )
                )
                state.finished = True
                state.result = final_text
                break

            logger.info("error", "No action and no final_answer in LLM JSON response")
            state.finished = True
            state.result = f"Invalid LLM JSON response: {response}"
            break

        logger.info("task", f"Task finished. Success: {state.finished}")
        return AgentResult(
            success=state.finished and "Error" not in state.result,
            output=state.result,
            steps=[
                {
                    "thought": s.thought,
                    "action": s.action,
                    "action_input": s.action_input,
                    "observation": s.observation
                } for s in state.steps
            ]
        )
