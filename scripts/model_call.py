#!/usr/bin/env python3
"""Call an OpenAI-compatible endpoint and validate a small triage schema.

The script also supports an offline fixture, so parsing and validation can run
in CI without a model credential.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class SchemaError(ValueError):
    """Raised when a model response violates the local contract."""


def extract_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        first_newline = cleaned.find("\n")
        cleaned = cleaned[first_newline + 1 :] if first_newline >= 0 else cleaned
        if cleaned.rstrip().endswith("```"):
            cleaned = cleaned.rstrip()[:-3]

    start = cleaned.find("{")
    if start < 0:
        raise SchemaError("response does not contain a JSON object")
    try:
        value, _ = json.JSONDecoder().raw_decode(cleaned[start:])
    except json.JSONDecodeError as exc:
        raise SchemaError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise SchemaError("top-level response must be a JSON object")
    return value


def validate_triage(value: dict[str, Any]) -> dict[str, Any]:
    required = {"summary", "severity", "evidence", "next_checks"}
    missing = required - value.keys()
    if missing:
        raise SchemaError(f"missing fields: {', '.join(sorted(missing))}")
    if not isinstance(value["summary"], str) or not value["summary"].strip():
        raise SchemaError("summary must be a non-empty string")
    if value["severity"] not in {"info", "warning", "critical"}:
        raise SchemaError("severity must be one of: info, warning, critical")
    for field in ("evidence", "next_checks"):
        if not isinstance(value[field], list) or not all(
            isinstance(item, str) and item.strip() for item in value[field]
        ):
            raise SchemaError(f"{field} must be a list of non-empty strings")
    if len(value["next_checks"]) > 3:
        raise SchemaError("next_checks must contain at most 3 items")
    return {key: value[key] for key in ("summary", "severity", "evidence", "next_checks")}


def prompt_for(log_text: str) -> str:
    return f"""任务：分析下列 Linux 应用日志。

限制：
- 只根据提供的日志判断；
- 不生成或执行修改系统状态的命令；
- 证据不足时在 summary 中明确写 unknown；
- 只返回一个 JSON 对象。

输出字段：
- summary: string
- severity: info | warning | critical
- evidence: string[]
- next_checks: string[]，最多 3 项，只允许只读检查

<LOGS>
{log_text}
</LOGS>"""


def request_model(log_text: str, timeout: float = 20.0, attempts: int = 3) -> dict[str, Any]:
    base_url = os.environ.get("CHRONO_AI_BASE_URL", "").rstrip("/")
    api_key = os.environ.get("CHRONO_AI_API_KEY", "")
    model = os.environ.get("CHRONO_AI_MODEL", "")
    if not all((base_url, api_key, model)):
        raise RuntimeError("CHRONO_AI_BASE_URL, CHRONO_AI_API_KEY and CHRONO_AI_MODEL are required")

    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": "你是 Linux 故障分析助手。只返回 JSON，不执行命令，不得补造日志中不存在的事实。",
            },
            {"role": "user", "content": prompt_for(log_text)},
        ],
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    url = f"{base_url}/chat/completions"

    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "linux-ai-lab/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                decoded = json.loads(response.read().decode("utf-8"))
            content = decoded["choices"][0]["message"]["content"]
            return validate_triage(extract_json(content))
        except urllib.error.HTTPError as exc:
            retryable = exc.code == 429 or exc.code in {500, 502, 503, 504}
            if not retryable or attempt == attempts:
                raise RuntimeError(f"model request failed with HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == attempts:
                raise RuntimeError("model request failed after bounded retries") from exc
        delay = (2 ** (attempt - 1)) + random.uniform(0.0, 0.25)
        time.sleep(delay)

    raise RuntimeError("unreachable retry state")


def read_offline(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "choices" in raw:
        raw = extract_json(raw["choices"][0]["message"]["content"])
    if not isinstance(raw, dict):
        raise SchemaError("offline fixture must contain a JSON object")
    return validate_triage(raw)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, help="UTF-8 log fixture for an online request")
    parser.add_argument("--offline", type=Path, help="validate a local response fixture without network")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if bool(args.log) == bool(args.offline):
        print("Choose exactly one of --log or --offline", file=sys.stderr)
        return 2
    try:
        result = (
            read_offline(args.offline)
            if args.offline
            else request_model(args.log.read_text(encoding="utf-8")[-12_000:])
        )
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, KeyError, json.JSONDecodeError, SchemaError, RuntimeError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"Validated triage result written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

