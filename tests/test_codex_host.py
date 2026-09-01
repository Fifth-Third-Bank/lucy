"""Saved-login Codex CLI host: confinement, parsing, and usage receipts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lucy.runtime.host import CodexAgentHost, LaneError, summarize_codex_usage
from lucy.runtime.trial import (
    COPY_IGNORE,
    _recorded_custody_home,
    launch_trial,
    parse_args,
    require_host_tools,
)

ROOT = Path(__file__).parents[1]


def successful_events(message: str = '{"path":"a.py"}') -> str:
    return "\n".join(
        (
            json.dumps({"type": "thread.started", "thread_id": "t-test"}),
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": message},
                }
            ),
            json.dumps(
                {
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 100,
                        "cached_input_tokens": 40,
                        "output_tokens": 25,
                        "reasoning_output_tokens": 5,
                    },
                }
            ),
        )
    )


class CodexHostTests(unittest.TestCase):
    def test_estimate_output_renders_unicode_punctuation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [
                    str(ROOT / "lucy" / "bin" / "lucy"),
                    "scan",
                    "--host",
                    "codex",
                    "--target",
                    str(ROOT / "tests" / "fixtures" / "polyglot"),
                    "--results",
                    str(Path(directory) / "results"),
                    "--estimate-only",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertNotIn("\\u2014", completed.stdout)
        self.assertIn("—", completed.stdout)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["cost_estimate"]["host"], "codex")

    def test_cli_defaults_to_claude_and_accepts_both_explicit_hosts(self) -> None:
        base = ["lucy", "scan", "--target", "/tmp/source", "--results", "/tmp/results"]
        with patch("sys.argv", base):
            defaults = parse_args()
        self.assertIsNone(defaults.host)
        self.assertEqual(defaults.planter, "auto")

        with patch("sys.argv", base + ["--host", "claude"]):
            self.assertEqual(parse_args().host, "claude")
        with patch("sys.argv", base + ["--host", "codex"]):
            codex = parse_args()
        self.assertEqual(codex.host, "codex")
        self.assertIsNone(codex.codex_model)
        self.assertIsNone(codex.codex_reasoning)

    def test_prepared_copy_strips_codex_project_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ignored = COPY_IGNORE(
                directory,
                [".codex", ".CODEX", "AGENTS.md", "source.py"],
            )
        self.assertIn(".codex", ignored)
        self.assertIn(".CODEX", ignored)
        self.assertIn("AGENTS.md", ignored)
        self.assertNotIn("source.py", ignored)

    def test_tool_preflight_requires_only_the_selected_cli(self) -> None:
        def available(binary):
            return f"/bin/{binary}" if binary in {"codex", "bwrap"} else None

        with patch("lucy.runtime.trial.shutil.which", side_effect=available):
            require_host_tools("codex", "codex")
            with self.assertRaisesRegex(ValueError, "Claude Code executable"):
                require_host_tools("claude", "claude")

        with tempfile.TemporaryDirectory() as directory:
            not_executable = Path(directory) / "codex"
            not_executable.write_text("not executable\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Codex CLI executable"):
                require_host_tools(
                    "codex", "codex", codex_binary=str(not_executable)
                )

    def test_linux_codex_preflight_requires_bubblewrap(self) -> None:
        def available(binary):
            return "/bin/codex" if binary == "codex" else None

        with (
            patch("lucy.runtime.trial.sys.platform", "linux"),
            patch("lucy.runtime.trial.shutil.which", side_effect=available),
        ):
            with self.assertRaisesRegex(ValueError, "bubblewrap"):
                require_host_tools("codex", "codex")

        # Claude-only operation is independent of the Codex sandbox helper.
        with (
            patch("lucy.runtime.trial.sys.platform", "linux"),
            patch(
                "lucy.runtime.trial.shutil.which",
                side_effect=lambda binary: "/bin/claude" if binary == "claude" else None,
            ),
        ):
            require_host_tools("claude", "claude")

    def test_launch_preflight_happens_before_results_or_workspace_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results"
            with self.assertRaisesRegex(ValueError, "Codex CLI executable"):
                launch_trial(
                    root / "missing-target",
                    results,
                    host="codex",
                    planter="codex",
                    codex_binary=str(root / "missing-codex"),
                )
            self.assertFalse(results.exists())

    def test_custom_custody_locator_requires_matching_private_held_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results"
            run_id = "r-host-parity"
            public_path = results / "runs" / run_id / "trial.json"
            held_root = root / "custody"
            held_path = held_root / "runs" / run_id / "trial.json"
            public_path.parent.mkdir(parents=True)
            held_path.parent.mkdir(parents=True)
            held_root.chmod(0o700)
            record = {
                "run_id": run_id,
                "workspace": str(results / "workspaces" / run_id),
                "results_root": str(results),
                "baseline_sha256": "a" * 64,
                "custody_home": str(held_root),
            }
            public_path.write_text(json.dumps(record), encoding="utf-8")
            held_path.write_text(json.dumps(record), encoding="utf-8")
            held_path.chmod(0o600)
            fallback = root / "default-custody"
            with patch.dict(os.environ, {"LUCY_CUSTODY_HOME": str(fallback)}):
                self.assertEqual(
                    held_root.resolve(), _recorded_custody_home(results, run_id)
                )
                tampered = dict(record, workspace=str(root / "attacker-workspace"))
                public_path.write_text(json.dumps(tampered), encoding="utf-8")
                self.assertEqual(
                    fallback.resolve(), _recorded_custody_home(results, run_id)
                )

    def test_builds_ephemeral_workspace_only_command_and_parses_usage(self) -> None:
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, successful_events(), "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metrics = root / "results" / "CODEX_USAGE.jsonl"
            workspace = root / "workspace"
            workspace.mkdir()
            with patch("lucy.runtime.host.shutil.which", return_value="/usr/local/bin/codex"):
                host = CodexAgentHost(metrics_path=metrics, runner=runner)
                result = host.run_agent(
                    system="fixed reader contract",
                    task="LUCY READER PASS=1 LENS=L1-auth",
                    workspace=workspace,
                )

            self.assertEqual(result, '{"path":"a.py"}')
            command, kwargs = calls[0]
            self.assertEqual(command[:2], ["codex", "exec"])
            for flag in (
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--skip-git-repo-check",
                "--strict-config",
                "--json",
            ):
                self.assertIn(flag, command)
            self.assertNotIn("--sandbox", command)
            self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", command)
            self.assertEqual(command[command.index("--model") + 1], "gpt-5.6-sol")
            configurations = [
                command[index + 1]
                for index, value in enumerate(command)
                if value == "--config"
            ]
            self.assertIn('default_permissions="lucy_lane"', configurations)
            profile = next(value for value in configurations if value.startswith("permissions."))
            self.assertIn(f'{json.dumps(str(workspace.resolve()))}=true', profile)
            self.assertIn('\":workspace_roots\"={\".\"=\"read\"}', profile)
            self.assertIn("network={enabled=false}", profile)
            self.assertNotIn('\":root\"', profile)
            self.assertIn("agents.enabled=false", configurations)
            self.assertIn("features.apps=false", configurations)
            self.assertIn("features.plugins=false", configurations)
            self.assertIn('approval_policy="never"', configurations)
            self.assertTrue(
                any(value.startswith("developer_instructions=") for value in configurations)
            )
            self.assertEqual(kwargs["cwd"], workspace)
            self.assertNotIn("OPENAI_API_KEY", kwargs["env"])
            self.assertNotIn("CODEX_API_KEY", kwargs["env"])

            summary = summarize_codex_usage(metrics)
            self.assertEqual(summary["calls"], 1)
            self.assertEqual(summary["successful_calls"], 1)
            self.assertEqual(summary["input_tokens"], 100)
            self.assertEqual(summary["cached_input_tokens"], 40)
            self.assertEqual(summary["output_tokens"], 25)
            self.assertIsNone(summary["cost"]["dollar_amount"])

    def test_planter_gets_workspace_write_but_no_broader_access(self) -> None:
        captured = []

        def runner(command, **kwargs):
            captured.append(command)
            return subprocess.CompletedProcess(command, 0, successful_events("{}"), "")

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with patch("lucy.runtime.host.shutil.which", return_value=None):
                CodexAgentHost(runner=runner).run_agent(
                    system="planter",
                    task="plant",
                    workspace=workspace,
                    allow_edit=True,
                )
        profile = next(
            captured[0][index + 1]
            for index, value in enumerate(captured[0])
            if value == "--config"
            and captured[0][index + 1].startswith("permissions.")
        )
        self.assertIn('\":workspace_roots\"={\".\"=\"write\"}', profile)
        self.assertNotIn('\":root\"', profile)
        self.assertNotIn('\":tmpdir\"', profile)
        self.assertNotIn('\":slash_tmp\"', profile)

    def test_nonzero_exit_missing_message_and_missing_binary_fail_closed(self) -> None:
        def failed(command, **kwargs):
            return subprocess.CompletedProcess(command, 7, "", "auth failed")

        with tempfile.TemporaryDirectory() as directory:
            host = CodexAgentHost(runner=failed)
            with self.assertRaisesRegex(LaneError, "exited 7"):
                host.run_agent(system="reader", task="read", workspace=Path(directory))

        def no_final(command, **kwargs):
            stdout = json.dumps({"type": "turn.completed", "usage": {}})
            return subprocess.CompletedProcess(command, 0, stdout, "")

        with tempfile.TemporaryDirectory() as directory:
            metrics = Path(directory) / "usage.jsonl"
            host = CodexAgentHost(runner=no_final, metrics_path=metrics)
            with self.assertRaisesRegex(LaneError, "no final agent message"):
                host.run_agent(system="reader", task="read", workspace=Path(directory))
            self.assertEqual(summarize_codex_usage(metrics)["failed_calls"], 1)

        def missing(command, **kwargs):
            raise FileNotFoundError("codex")

        with tempfile.TemporaryDirectory() as directory:
            metrics = Path(directory) / "usage.jsonl"
            host = CodexAgentHost(runner=missing, metrics_path=metrics)
            with self.assertRaisesRegex(LaneError, "could not start codex lane"):
                host.run_agent(system="reader", task="read", workspace=Path(directory))
            self.assertEqual(summarize_codex_usage(metrics)["failed_calls"], 1)

    def test_environment_preserves_saved_login_location_not_api_keys(self) -> None:
        original = {
            name: os.environ.get(name)
            for name in ("CODEX_HOME", "OPENAI_API_KEY", "CODEX_API_KEY")
        }
        try:
            os.environ["CODEX_HOME"] = "/example/codex-home"
            os.environ["OPENAI_API_KEY"] = "api-secret"
            os.environ["CODEX_API_KEY"] = "codex-secret"
            environment = CodexAgentHost._environment()
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        self.assertEqual(environment["CODEX_HOME"], "/example/codex-home")
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("CODEX_API_KEY", environment)


if __name__ == "__main__":
    unittest.main()
