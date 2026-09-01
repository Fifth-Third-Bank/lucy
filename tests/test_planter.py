import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from lucy.runtime.planter import (
    FORBIDDEN_PATH_PARTS,
    forbidden_paths_clause,
    validate_answer_key,
)


class PlanterValidationTests(unittest.TestCase):
    def create_workspace(self, root: Path) -> Path:
        workspace = root / "workspace"
        (workspace / "src").mkdir(parents=True)
        for index in range(8):
            (workspace / "src" / f"file{index}.py").write_text("secure = True\n")
        subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        subprocess.run(["git", "add", "--all"], cwd=workspace, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "baseline",
            ],
            cwd=workspace,
            check=True,
        )
        return workspace

    def test_validates_exact_family_spread_and_mutation_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = self.create_workspace(Path(directory))
            families = ["L1-auth"] * 2 + ["L2-secrets"] * 2 + ["L3-injection"] * 2 + ["L4-infra"] * 2
            canaries = []
            for index, family in enumerate(families):
                line = f"secure = False_{index}"
                path = workspace / "src" / f"file{index}.py"
                path.write_text(line + "\n")
                canaries.append(
                    {
                        "slot": index + 1,
                        "family": family,
                        "path": f"src/file{index}.py",
                        "line": 1,
                        "title": f"Mutation {index}",
                        "reachability": f"invoked by module entrypoint {index} at import time",
                        "mutation_sha256": hashlib.sha256(line.encode()).hexdigest(),
                    }
                )
            answer = {"schema": "lucy-answer-key/v1", "canaries": canaries}
            validated = validate_answer_key(answer, workspace)
            self.assertEqual(8, len(validated["canaries"]))
            self.assertTrue(all(len(row["mutation_sha256"]) == 64 for row in validated["canaries"]))

    def test_rejects_marker_or_unrepresented_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = self.create_workspace(Path(directory))
            (workspace / "src" / "file0.py").write_text("# planted canary\n")
            answer = {
                "schema": "lucy-answer-key/v1",
                "canaries": [
                    {
                        "slot": index + 1,
                        "family": ("L1-auth", "L1-auth", "L2-secrets", "L2-secrets", "L3-injection", "L3-injection", "L4-infra", "L4-infra")[index],
                        "path": f"src/file{index}.py",
                        "line": 1,
                        "title": "x",
                        "reachability": "invoked by module entrypoint at import time",
                        "mutation_sha256": hashlib.sha256(b"# planted canary").hexdigest(),
                    }
                    for index in range(8)
                ],
            }
            with self.assertRaises(ValueError):
                validate_answer_key(answer, workspace)

    def test_rejects_new_files_and_invalid_python(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = self.create_workspace(Path(directory))
            (workspace / "src" / "new.py").write_text("value = 1\n")
            with self.assertRaisesRegex(ValueError, "only modify existing files"):
                validate_answer_key({"schema": "lucy-answer-key/v1", "canaries": []}, workspace)

    def test_rejects_test_fixture_paths(self) -> None:
        # Test fixtures are scanner inputs, not eligible application loci.
        for part in ("tests", "fixtures"):
            self.assertIn(part, FORBIDDEN_PATH_PARTS)
        with tempfile.TemporaryDirectory() as directory:
            workspace = self.create_workspace(Path(directory))
            fixture_dir = workspace / "tests" / "fixtures" / "app"
            fixture_dir.mkdir(parents=True)
            fixture_file = fixture_dir / "handler.py"
            fixture_file.write_text("secure = True\n")
            subprocess.run(["git", "add", "--all"], cwd=workspace, check=True)
            subprocess.run(
                ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "-q", "-m", "fixture"],
                cwd=workspace,
                check=True,
            )
            fixture_file.write_text("secure = False\n")
            answer = {
                "schema": "lucy-answer-key/v1",
                "canaries": [
                    {
                        "slot": index + 1,
                        "family": ("L1-auth", "L1-auth", "L2-secrets", "L2-secrets",
                                   "L3-injection", "L3-injection", "L4-infra", "L4-infra")[index],
                        "path": "tests/fixtures/app/handler.py" if index == 0 else f"src/file{index}.py",
                        "line": 1,
                        "title": "x",
                        "reachability": "invoked by module entrypoint at import time",
                    }
                    for index in range(8)
                ],
            }
            with self.assertRaisesRegex(ValueError, "forbidden path"):
                validate_answer_key(answer, workspace)

    def test_prompt_clause_spells_out_enforced_names(self) -> None:
        clause = forbidden_paths_clause()
        for part in sorted(FORBIDDEN_PATH_PARTS):
            self.assertIn(part, clause)


if __name__ == "__main__":
    unittest.main()
