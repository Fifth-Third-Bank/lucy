"""Host adapters: run one agent loop (reader / court / planter) to completion.

A host is anything that can drive a tool-using model conversation. The
OpenAI-compatible host below speaks the Chat Completions function-calling
protocol over plain HTTPS (no SDK dependency) and works with any
OpenAI-compatible endpoint (api.openai.com, Azure, local gateways) via:

  OPENAI_API_KEY     bearer token (required)
  OPENAI_BASE_URL    default https://api.openai.com/v1
  OPENAI_MODEL       e.g. gpt-5.6-cyber (required; never guessed)
  LUCY_OPENAI_USD_PER_MTOKEN  blended $/Mtoken for budget enforcement

Budget is enforced HERE (summed usage x unit price), because API hosts have
no --max-budget flag; exceeding it raises BudgetExceeded and the run ends
honestly.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Any, Protocol
import urllib.error
import urllib.request

from lucy.runtime.localtools import WorkspaceTools, tool_schemas


class LaneError(RuntimeError):
    """A reader/court lane ended abnormally (crash, budget kill, exhaustion)."""


# Per-lane spend cap: runaway-loop protection, never an economy lever (lanes
# bill actuals). The default leaves room for ordinary targeted reading while
# still stopping a genuinely looping lane. Because any killed lane aborts
# recapture fail-closed, operators should raise the cap for known workloads
# rather than treating partial lane output as complete.
LANE_BUDGET_USD_DEFAULT = 25.0


class BudgetExceeded(RuntimeError):
    pass


class AgentHost(Protocol):
    def run_agent(
        self,
        *,
        system: str,
        task: str,
        workspace: Path,
        allow_edit: bool = False,
        max_turns: int = 60,
    ) -> str:
        """Drive one fresh agent conversation; return its final text."""
        ...


class ClaudeAgentHost:
    """Per-lane Claude host: one fresh ``claude --print`` process per agent.

    Used by launcher-owned orchestration (recapture laps, and optionally the
    full orchestrator) so readers/courts run as isolated processes with a
    read-only tool surface — no skill session, no shell, no subagent spawning.
    """

    def __init__(
        self,
        *,
        claude_binary: str = "claude",
        lane_budget_usd: float | None = LANE_BUDGET_USD_DEFAULT,
    ) -> None:
        self.claude_binary = claude_binary
        self.lane_budget_usd = lane_budget_usd

    def run_agent(
        self,
        *,
        system: str,
        task: str,
        workspace: Path,
        allow_edit: bool = False,
        max_turns: int = 60,
    ) -> str:
        import subprocess

        from lucy.runtime.trial import direct_claude_environment

        if allow_edit:
            raise ValueError("ClaudeAgentHost lanes are read-only")
        command = [
            self.claude_binary,
            "--print",
            "--no-session-persistence",
            "--setting-sources",
            "user",
            "--system-prompt",
            system,
            "--allowedTools",
            "Read,Grep,Glob",
            "--output-format",
            "text",
        ]
        if self.lane_budget_usd is not None:
            command.extend(["--max-budget-usd", str(self.lane_budget_usd)])
        command.append(task)
        result = subprocess.run(
            command,
            cwd=workspace,
            env=direct_claude_environment(),
            capture_output=True,
            text=True,
            check=False,
            timeout=3600,
        )
        if result.returncode != 0:
            # A budget-killed or crashed lane is never a clean result, even
            # when it emitted partial output; otherwise quiet convergence can
            # count incomplete work.
            raise LaneError(
                f"claude lane exited {result.returncode}: "
                f"{result.stderr.strip()[:300] or result.stdout.strip()[:300]}"
            )
        return result.stdout


class OpenAIHost:
    def __init__(
        self,
        *,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        max_budget_usd: float | None = None,
    ) -> None:
        self.model = model or os.environ.get("OPENAI_MODEL", "")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if not self.model:
            raise ValueError("OPENAI_MODEL is required (never guessed)")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is required")
        self.max_budget_usd = max_budget_usd
        self.usd_per_mtoken = float(os.environ.get("LUCY_OPENAI_USD_PER_MTOKEN", "10"))
        self.spent_tokens = 0

    # -- transport -----------------------------------------------------
    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=600) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as error:
                if error.code in (429, 500, 502, 503, 529) and attempt < 3:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise RuntimeError(
                    f"OpenAI host HTTP {error.code}: {error.read().decode('utf-8', 'replace')[:400]}"
                ) from error
            except urllib.error.URLError as error:
                if attempt < 3:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise RuntimeError(f"OpenAI host unreachable: {error}") from error
        raise RuntimeError("unreachable")

    def _charge(self, usage: dict[str, Any]) -> None:
        self.spent_tokens += int(usage.get("total_tokens", 0) or 0)
        if self.max_budget_usd is not None:
            spent_usd = self.spent_tokens / 1_000_000 * self.usd_per_mtoken
            if spent_usd > self.max_budget_usd:
                raise BudgetExceeded(
                    f"budget exhausted: ~${spent_usd:.2f} of ${self.max_budget_usd}"
                )

    # -- agent loop ----------------------------------------------------
    def run_agent(
        self,
        *,
        system: str,
        task: str,
        workspace: Path,
        allow_edit: bool = False,
        max_turns: int = 60,
    ) -> str:
        tools = WorkspaceTools(workspace, allow_edit=allow_edit)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": task},
        ]
        for _ in range(max_turns):
            response = self._post(
                {
                    "model": self.model,
                    "messages": messages,
                    "tools": tool_schemas(allow_edit=allow_edit),
                }
            )
            self._charge(response.get("usage", {}))
            choice = response["choices"][0]
            message = choice["message"]
            messages.append(message)
            calls = message.get("tool_calls") or []
            if not calls:
                return str(message.get("content") or "")
            for call in calls:
                function = call.get("function", {})
                try:
                    arguments = json.loads(function.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {}
                result = tools.dispatch(str(function.get("name", "")), arguments)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id", ""),
                        "content": result[:20000],
                    }
                )
        raise LaneError("lane exhausted max turns without a final response")
