import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).parents[1] / "tools" / "check_public_metadata.py"
SPEC = importlib.util.spec_from_file_location("check_public_metadata", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def require_jenkins_metadata(test_case: unittest.TestCase, root: Path) -> None:
    """Run publishing-policy assertions only where their source exists.

    Public release archives intentionally omit internal Jenkins configuration.
    Public GitHub clones have Git metadata but still correctly lack these
    internal files, so repository presence cannot distinguish the two forms.
    """
    if (root / ".jenkins").is_dir():
        return
    test_case.skipTest(
        "source-only Jenkins publishing policy is absent from the public archive"
    )


class PublicMetadataTests(unittest.TestCase):
    def test_accepts_generic_lucy_zip_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("Import lucy.zip.\n", encoding="utf-8")
            self.assertEqual([], MODULE.check(root))

    def test_rejects_absolute_home_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "Source: /" + "Users/example/Downloads/lucy.zip\n", encoding="utf-8"
            )
            errors = MODULE.check(root)
            self.assertTrue(any("absolute macOS home path" in error for error in errors))

    def test_rejects_legacy_package_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("Legacy GEN" + "7 kit\n", encoding="utf-8")
            errors = MODULE.check(root)
            self.assertTrue(any("legacy package label" in error for error in errors))

    def test_pinned_toolbox_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            toolbox = root / "lucy" / "toolbox"
            toolbox.mkdir(parents=True)
            (toolbox / "source.py").write_text("legacy GEN" + "7 label\n")
            errors = MODULE.check(root)
            self.assertTrue(any("legacy package label" in error for error in errors))

    def test_allows_legacy_label_only_in_census_compatibility_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            toolbox = root / "lucy" / "toolbox"
            toolbox.mkdir(parents=True)
            (toolbox / "census.py").write_text("legacy GEN" + "7 label\n")
            self.assertEqual([], MODULE.check(root))

    def test_rejects_private_narrative_markers_and_identifiers(self) -> None:
        examples = {
            "narrative": "field" + " basis: incident details\n",
            "application": "app" + "20-final\n",
            "run": "r-" + "5ad1780552d3\n",
            "repository": "lucy" + "-oss\n",
        }
        for name, content in examples.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "README.md").write_text(content, encoding="utf-8")
                self.assertTrue(MODULE.check(root))

    def test_scans_release_source_suffixes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "example.rb").write_text(
                "# " + "field" + " record: incident details\n", encoding="utf-8"
            )
            self.assertTrue(MODULE.check(root))

    def test_organization_identity_is_limited_to_approved_files(self) -> None:
        identity = "Fifth" + " Third"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(identity + " attribution\n", encoding="utf-8")
            (root / "notes.md").write_text(identity + " example\n", encoding="utf-8")
            errors = MODULE.check(root)
            self.assertFalse(any(error.startswith("README.md:") for error in errors))
            self.assertTrue(any(error.startswith("notes.md:") for error in errors))

    def test_rejects_private_company_domain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "notes.md").write_text(
                "Contact owner@" + "53" + ".com\n", encoding="utf-8"
            )
            errors = MODULE.check(root)
            self.assertTrue(any("private email or web domain" in error for error in errors))




class ReleaseIdentityParityTests(unittest.TestCase):
    """The public artifact must describe itself correctly: one version
    everywhere, no private repository branding in emitted output, and no
    fictional source URLs. SARIF keeps scanner and converter provenance in
    their respective fields."""

    ROOT = Path(__file__).parents[1]

    def test_module_version_matches_pyproject(self) -> None:
        import re

        pyproject = (self.ROOT / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
        namespace: dict = {}
        exec((self.ROOT / "lucy" / "__init__.py").read_text(encoding="utf-8"), namespace)
        self.assertEqual(declared, namespace["__version__"])

    def test_release_version_matches_public_metadata(self) -> None:
        import re

        pyproject = (self.ROOT / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
        changelog = (self.ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        readme = (self.ROOT / "README.md").read_text(encoding="utf-8")
        report_template = (
            self.ROOT / "lucy" / "toolbox" / "SCAN_REPORT_TEMPLATE.json"
        ).read_text(encoding="utf-8")

        self.assertIn(f"## {declared} -", changelog)
        self.assertNotIn("## Unreleased", changelog)
        self.assertIn(f"version-{declared}-blue", readme)
        self.assertIn(f"e.g. {declared}", report_template)

    def test_release_deploy_tag_matches_version(self) -> None:
        import re

        require_jenkins_metadata(self, self.ROOT)
        pyproject = (self.ROOT / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
        release = (self.ROOT / ".jenkins" / "release-deploy.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn(f'tagToCreate: "v{declared}"', release)

    def test_runtime_emits_no_internal_repo_brand(self) -> None:
        internal_label = "lucy" + "-oss"
        for module in ("report", "seal", "sarif", "artifacts", "trial"):
            source = (self.ROOT / "lucy" / "runtime" / f"{module}.py").read_text(encoding="utf-8")
            self.assertNotIn(internal_label, source, f"{module}.py brands output as a private repo")

    def test_sarif_uses_release_version_and_run_metadata(self) -> None:
        import sys

        sys.path.insert(0, str(self.ROOT))
        from lucy import __version__
        from lucy.runtime.sarif import to_sarif

        # Provenance: SARIF must report the version of the scan that
        # PRODUCED the report; the installed converter's version is only a
        # clearly-marked fallback for artifacts predating scanner_version.
        current = to_sarif({
            "app": {"scan_run": "lucy r-test", "scanner_version": "0.8.7"},
            "findings": [],
        })
        driver = current["runs"][0]["tool"]["driver"]
        self.assertEqual("0.8.7", driver["version"])
        self.assertEqual("lucy r-test", current["runs"][0]["automationDetails"]["id"])
        self.assertNotIn("informationUri", driver)
        self.assertEqual({"converterVersion": __version__}, driver["properties"])
        # A converter must never claim a scanner version it cannot know:
        # legacy reports get NO driver.version, only the converter property.
        legacy = to_sarif({"app": {"scan_run": "lucy r-old"}, "findings": []})
        legacy_driver = legacy["runs"][0]["tool"]["driver"]
        self.assertNotIn("version", legacy_driver)
        self.assertEqual({"converterVersion": __version__}, legacy_driver["properties"])

    def test_report_contract_carries_scanner_version(self) -> None:
        import json
        import re

        report_source = (self.ROOT / "lucy" / "runtime" / "report.py").read_text(encoding="utf-8")
        self.assertIn('"scanner_version": lucy_version', report_source)
        template = json.loads(
            (self.ROOT / "lucy" / "toolbox" / "SCAN_REPORT_TEMPLATE.json").read_text(encoding="utf-8")
        )
        self.assertIn("scanner_version", template["app"])
        gate_source = (self.ROOT / "lucy" / "toolbox" / "scan_report_gate.py").read_text(encoding="utf-8")
        self.assertIn("'scanner_version'", gate_source)

    def test_asset_manifest_sizes_match_bytes(self) -> None:
        import json

        toolbox = self.ROOT / "lucy" / "toolbox"
        manifest = json.loads((toolbox / "assets.json").read_text(encoding="utf-8"))
        for asset in manifest["assets"]:
            self.assertEqual(
                asset["size"],
                len((toolbox / asset["path"]).read_bytes()),
                f"manifest size drift: {asset['path']}",
            )

    def test_threat_model_carries_no_stale_release_blockers(self) -> None:
        text = (self.ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
        self.assertNotIn("legal/allowlist decision", text)
        self.assertNotIn("not yet wired", text)

    def test_docs_describe_pii_masking_boundary(self) -> None:
        readme = (self.ROOT / "README.md").read_text(encoding="utf-8")
        threat_model = (self.ROOT / "docs" / "threat-model.md").read_text(
            encoding="utf-8"
        )
        certification = (self.ROOT / "docs" / "certification.md").read_text(
            encoding="utf-8"
        )
        contract = (
            self.ROOT / "lucy" / "toolbox" / "SCAN_REPORT_CONTRACT.md"
        ).read_text(encoding="utf-8")

        self.assertNotIn("everything written passes redaction first", readme)
        self.assertNotIn("Mandatory pre-write redaction", threat_model)
        self.assertIn("unredacted working copy", readme)
        self.assertIn("not comprehensive PII anonymization or DLP", readme)
        self.assertIn("not comprehensive PII anonymization or DLP", threat_model)
        self.assertIn("selected credential-pattern checks", certification)
        self.assertRegex(contract, r"operator\s+responsibilities")


class ReleaseArchivePolicyTests(unittest.TestCase):
    ROOT = Path(__file__).parents[1]

    def setUp(self) -> None:
        require_jenkins_metadata(self, self.ROOT)

    def test_build_archives_include_public_github_metadata_without_codeowners(self) -> None:
        for name in ("ci-build.yaml", "dev-build.yaml", "release-build.yaml"):
            config = (self.ROOT / ".jenkins" / name).read_text(encoding="utf-8")
            self.assertIn('directory: "lucy,docs,tests,tools,.github"', config, name)
            for excluded in (
                "BuildInfo.txt",
                ".github/CODEOWNERS",
                "**/__pycache__/",
                "**/__pycache__/**",
                "**/*.pyc",
                "**/*.pyo",
                "**/.pytest_cache/",
                "**/.pytest_cache/**",
                "**/.mypy_cache/",
                "**/.mypy_cache/**",
                "**/.ruff_cache/",
                "**/.ruff_cache/**",
                "**/.DS_Store",
            ):
                self.assertIn(excluded, config, f"{name}: {excluded}")
            self.assertNotIn("filterPatterns:", config, name)

    def test_artifact_coordinates_are_resolved(self) -> None:
        config = (self.ROOT / ".jenkins" / "artifacts.yaml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("TODO(", config)


class JenkinsMetadataBoundaryTests(unittest.TestCase):
    def test_public_archive_without_jenkins_metadata_skips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(unittest.SkipTest):
                require_jenkins_metadata(self, Path(directory))

    def test_source_checkout_with_jenkins_metadata_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".jenkins").mkdir()
            require_jenkins_metadata(self, root)


if __name__ == "__main__":
    unittest.main()
