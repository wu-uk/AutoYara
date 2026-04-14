from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AgentStep:
    """ReAct Agent 的单步执行记录"""
    thought: str
    action: str
    action_input: dict[str, Any]
    observation: str


@dataclass(slots=True)
class AgentState:
    """Agent 的运行状态"""
    steps: list[AgentStep] = field(default_factory=list)
    max_steps: int = 10
    finished: bool = False
    result: str = ""
