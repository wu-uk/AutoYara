from __future__ import annotations

import ast
import json
import re
from json import JSONDecodeError


def _strip_code_fence(raw: str) -> str:
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.I)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip())
    return cleaned


def _extract_json_candidate(text: str) -> str:
    starts = [idx for idx in (text.find("{"), text.find("[")) if idx != -1]
    if not starts:
        return text
    start = min(starts)

    stack: list[str] = []
    in_string = False
    quote = ""
    escaped = False
    pairs = {"{": "}", "[": "]"}
    closes = set(pairs.values())

    for i, ch in enumerate(text[start:], start=start):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
            continue

        if ch in ('"', "'"):
            in_string = True
            quote = ch
            continue

        if ch in pairs:
            stack.append(pairs[ch])
            continue

        if ch in closes:
            if not stack or ch != stack[-1]:
                continue
            stack.pop()
            if not stack:
                return text[start : i + 1]

    return text[start:]


def _drop_unmatched_closers(text: str) -> str:
    """Drop unmatched closing brackets/braces while preserving quoted strings."""
    out: list[str] = []
    stack: list[str] = []
    in_string = False
    quote = ""
    escaped = False
    pairs = {"{": "}", "[": "]"}
    closes = set(pairs.values())

    for ch in text:
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
            continue

        if ch in ('"', "'"):
            in_string = True
            quote = ch
            out.append(ch)
            continue

        if ch in pairs:
            stack.append(pairs[ch])
            out.append(ch)
            continue

        if ch in closes:
            if stack and ch == stack[-1]:
                stack.pop()
                out.append(ch)
            # Ignore unmatched closer characters.
            continue

        out.append(ch)

    return "".join(out)


def _loads_json(text: str) -> dict:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("LLM response JSON root must be an object")
    return data


def parse_llm_json(raw: str) -> dict:
    """Parse LLM output into JSON object with lightweight fault tolerance."""
    cleaned = _strip_code_fence(raw)
    candidates = [cleaned]
    extracted = _extract_json_candidate(cleaned)
    if extracted != cleaned:
        candidates.append(extracted)
    repaired = _drop_unmatched_closers(extracted)
    if repaired not in candidates:
        candidates.append(repaired)

    for candidate in candidates:
        try:
            return _loads_json(candidate)
        except (JSONDecodeError, ValueError):
            pass

    # Fallback for Python-literal style outputs, e.g. True/False/None/single quotes.
    for candidate in candidates:
        try:
            data = ast.literal_eval(candidate)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    raise ValueError("Failed to parse LLM response as JSON object")
