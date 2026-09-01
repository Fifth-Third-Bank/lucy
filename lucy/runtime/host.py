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

The Codex host uses ``codex exec`` and the user's saved Codex login. It does
not require an API key. Every invocation is ephemeral and receives a custom
least-privilege permission profile: common runtime files plus the prepared
workspace only, no command network, and no access to the launcher's separate
answer-key custody. Do not replace that profile with the broader legacy
``--sandbox read-only`` mode; read-only prevents writes but is not a
workspace-only read boundary.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
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


class CodexAgentHost:
    """One fresh, ephemeral ``codex exec`` process per lane.

    The CLI reuses the user's saved Codex authentication. User/project
    configuration and optional tool surfaces are disabled so a scanned
    repository cannot widen the lane. A Codex permission profile enforces
    workspace-only reads (or writes for the isolated planter); failure to
    parse or apply the profile is a lane failure, never a silent fallback.
    """

    DEFAULT_MODEL = "gpt-5.6-sol"
    DEFAULT_REASONING_EFFORT = "high"
    PROFILE_NAME = "lucy_lane"
    REASONING_EFFORTS = {"minimal", "low", "medium", "high", "xhigh", "max", "ultra"}

    def __init__(
        self,
        *,
        codex_binary: str = "codex",
        model: str = DEFAULT_MODEL,
        reasoning_effort: str = DEFAULT_REASONING_EFFORT,
        timeout_seconds: int = 3600,
        metrics_path: Path | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("Codex model must not be empty")
        if reasoning_effort not in self.REASONING_EFFORTS:
            raise ValueError("unsupported Codex reasoning effort")
        if timeout_seconds < 1:
            raise ValueError("Codex timeout must be positive")
        self.codex_binary = codex_binary
        self.model = model
        self.reasoning_effort = reasoning_effort
        self.timeout_seconds = timeout_seconds
        self.metrics_path = metrics_path
        self._runner = runner or subprocess.run
        self._metrics_lock = threading.Lock()

    @staticmethod
    def _environment() -> dict[str, str]:
        """Keep saved CLI auth available but never pass API keys to lanes."""
        environment = dict(os.environ)
        for name in ("OPENAI_API_KEY", "CODEX_API_KEY"):
            environment.pop(name, None)
        return environment

    def _permission_profile(self, *, workspace: Path, allow_edit: bool) -> str:
        workspace_access = "write" if allow_edit else "read"
        workspace_key = json.dumps(str(workspace.resolve()))
        runtime_rules = ['\":minimal\"=\"read\"']
        executable = shutil.which(self.codex_binary)
        if executable is not None:
            # Codex may re-exec its own binary while applying a patch. Permit
            # only the PATH entry and resolved executable, never their parent
            # package or home trees.
            executable_path = Path(executable).absolute()
            for path in sorted({executable_path, executable_path.resolve()}, key=str):
                runtime_rules.append(f"{json.dumps(str(path))}=\"read\"")
        filesystem_rules = ",".join(runtime_rules)
        # Register the disposable directory explicitly. ``--cd`` sets cwd,
        # but the permission profile itself remains the capability boundary.
        return (
            f"permissions.{self.PROFILE_NAME}="
            f"{{workspace_roots={{{workspace_key}=true}},"
            f"filesystem={{{filesystem_rules},"
            f"\":workspace_roots\"={{\".\"=\"{workspace_access}\"}}}},"
            "network={enabled=false}}"
        )

    def _command(
        self,
        *,
        system: str,
        task: str,
        workspace: Path,
        allow_edit: bool,
    ) -> list[str]:
        configurations = (
            f'default_permissions="{self.PROFILE_NAME}"',
            self._permission_profile(workspace=workspace, allow_edit=allow_edit),
            f"developer_instructions={json.dumps(system)}",
            f'model_reasoning_effort="{self.reasoning_effort}"',
            'model_verbosity="low"',
            'approval_policy="never"',
            "agents.enabled=false",
            "allow_login_shell=false",
            'shell_environment_policy.inherit="core"',
            "shell_environment_policy.ignore_default_excludes=false",
            "project_doc_max_bytes=0",
            "features.apps=false",
            "features.plugins=false",
            "features.browser_use=false",
            "features.computer_use=false",
            "tools.web_search=false",
        )
        command = [
            self.codex_binary,
            "exec",
            "--strict-config",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--ephemeral",
            "--json",
            "--color",
            "never",
            "--model",
            self.model,
            "--cd",
            str(workspace),
        ]
        for configuration in configurations:
            command.extend(["--config", configuration])
        command.append(task)
        return command

    @staticmethod
    def _lane_kind(task: str, *, allow_edit: bool) -> str:
        if allow_edit:
            return "planter"
        first = task.lstrip().splitlines()[0] if task.strip() else ""
        if first.startswith("LUCY READER"):
            return "reader"
        if first.startswith("LUCY SWEEP"):
            return "sweep"
        if first.startswith("LUCY COURT"):
            return "court"
        return "agent"

    @staticmethod
    def _parse_events(stdout: str) -> tuple[str, dict[str, int]]:
        final_text: str | None = None
        usage = {
            "input_tokens": 0,
            "cached_input_tokens": 0,
            "output_tokens": 0,
            "reasoning_output_tokens": 0,
        }
        for line_number, line in enumerate(stdout.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise LaneError(
                    f"codex emitted invalid JSONL at line {line_number}"
                ) from error
            if event.get("type") == "item.completed":
                item = event.get("item") or {}
                if item.get("type") == "agent_message" and isinstance(item.get("text"), str):
                    final_text = item["text"]
            if event.get("type") == "turn.completed":
                event_usage = event.get("usage") or {}
                for key in usage:
                    usage[key] += int(event_usage.get(key, 0) or 0)
        if final_text is None:
            raise LaneError("codex lane returned no final agent message")
        return final_text, usage

    def _record_metrics(self, record: dict[str, Any]) -> None:
        if self.metrics_path is None:
            return
        payload = json.dumps(record, sort_keys=True) + "\n"
        with self._metrics_lock:
            self.metrics_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(
                self.metrics_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                handle.write(payload)

    def run_agent(
        self,
        *,
        system: str,
        task: str,
        workspace: Path,
        allow_edit: bool = False,
        max_turns: int = 60,
    ) -> str:
        # codex exec owns its internal tool loop. max_turns has no faithful
        # CLI mapping; the hard wall-clock timeout is the fail-closed bound.
        del max_turns
        started_wall = datetime.now(timezone.utc)
        started_mono = time.monotonic()
        kind = self._lane_kind(task, allow_edit=allow_edit)
        command = self._command(
            system=system,
            task=task,
            workspace=workspace.resolve(),
            allow_edit=allow_edit,
        )
        record: dict[str, Any] = {
            "schema": "lucy-codex-invocation/v1",
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "kind": kind,
            "workspace_access": "write" if allow_edit else "read",
            "started_at": started_wall.isoformat(),
        }
        try:
            result = self._runner(
                command,
                cwd=workspace,
                env=self._environment(),
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
            if result.returncode != 0:
                record.update({"status": "error", "exit_code": result.returncode})
                detail = (result.stderr or result.stdout or "no diagnostic").strip()
                raise LaneError(
                    f"codex lane exited {result.returncode}: {detail[:300]}"
                )
            final_text, usage = self._parse_events(result.stdout)
            record.update({"status": "ok", "exit_code": 0, **usage})
            return final_text
        except subprocess.TimeoutExpired as error:
            record.update({"status": "timeout", "exit_code": None})
            raise LaneError(
                f"codex lane exceeded {self.timeout_seconds} seconds"
            ) from error
        except LaneError:
            record.setdefault("status", "error")
            record.setdefault("exit_code", None)
            raise
        except OSError as error:
            record.update({"status": "error", "exit_code": None})
            raise LaneError(f"could not start codex lane: {error}") from error
        finally:
            completed = datetime.now(timezone.utc)
            record["completed_at"] = completed.isoformat()
            record["duration_seconds"] = round(time.monotonic() - started_mono, 3)
            self._record_metrics(record)


def summarize_codex_usage(metrics_path: Path) -> dict[str, Any]:
    """Summarize launcher-recorded Codex JSONL without inventing cost."""
    rows: list[dict[str, Any]] = []
    if metrics_path.is_file():
        for line in metrics_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    successful = [row for row in rows if row.get("status") == "ok"]
    totals = {
        key: sum(int(row.get(key, 0) or 0) for row in successful)
        for key in (
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
        )
    }
    starts = [str(row["started_at"]) for row in rows if row.get("started_at")]
    completions = [str(row["completed_at"]) for row in rows if row.get("completed_at")]
    wall_seconds = 0.0
    if starts and completions:
        first = datetime.fromisoformat(min(starts))
        last = datetime.fromisoformat(max(completions))
        wall_seconds = round((last - first).total_seconds(), 3)
    return {
        "schema": "lucy-codex-usage/v1",
        "models": sorted({str(row.get("model")) for row in rows if row.get("model")}),
        "calls": len(rows),
        "successful_calls": len(successful),
        "failed_calls": len(rows) - len(successful),
        "wall_seconds": wall_seconds,
        **totals,
        "cost": {
            "unit": "tokens",
            "dollar_amount": None,
            "note": (
                "codex exec with saved ChatGPT authentication does not expose "
                "an authoritative per-run dollar charge; apply the current plan "
                "credit/rate card to these token totals"
            ),
        },
    }


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
