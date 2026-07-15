"""Golden and mutation tests for the Authority validator."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_authority", REPOSITORY_ROOT / "scripts" / "validate_authority.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ValidateAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name) / "authority"
        shutil.copytree(
            REPOSITORY_ROOT,
            self.root,
            ignore=shutil.ignore_patterns(".git", "__pycache__"),
        )
        self.git("init", "--quiet")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Authority validator test")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "fixture")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def git(self, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )

    def manifest(self) -> dict:
        return json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))

    def write_manifest(self, manifest: dict) -> None:
        (self.root / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )

    def assert_error(self, expected: str) -> None:
        self.assertTrue(
            any(expected in error for error in VALIDATOR.validate_repository(self.root)),
            f"expected {expected!r}",
        )

    def test_golden_repository_passes(self) -> None:
        self.assertEqual(VALIDATOR.validate_repository(self.root), [])

    def test_cca_001_publishes_authorized_azure_catalog(self) -> None:
        manifest = self.manifest()
        cca_001 = next(policy for policy in manifest["policies"] if policy["id"] == "CCA-001")
        policy_text = " ".join(
            (self.root / cca_001["path"]).read_text(encoding="utf-8").split()
        )

        self.assertEqual(cca_001["version"], "1.1.0")
        self.assertIn("Azure Container Apps for compute", policy_text)
        for service in (
            "Azure Cosmos DB serverless",
            "Azure Storage Table",
            "Azure SQL Database serverless",
        ):
            self.assertIn(service, policy_text)
        for region in ("West Europe", "North Europe"):
            self.assertIn(region, policy_text)
        self.assertIn(
            "`assess-cloud-workload` skill supplied by their Control Tower kit or distribution",
            policy_text,
        )
        self.assertNotIn(".github/skills/", policy_text)

    def test_dr_009_distinguishes_active_and_backup_payload_retention(self) -> None:
        manifest = self.manifest()
        dr_009 = next(policy for policy in manifest["policies"] if policy["id"] == "DR-009")
        policy_text = " ".join(
            (self.root / dr_009["path"]).read_text(encoding="utf-8").split()
        )

        self.assertEqual(dr_009["version"], "1.1.0")
        self.assertIn(
            "Retain payloads in active or queryable storage for no more than 30 days.",
            policy_text,
        )
        self.assertIn(
            "Provider-managed backup or PITR copies may contain expired payloads only for the configured technical backup-retention period",
            policy_text,
        )
        self.assertIn(
            "remain within approved EU regions, are inaccessible to normal application or query paths, and are restricted to controlled recovery.",
            policy_text,
        )
        self.assertIn(
            "This is not a waiver and does not permit ordinary access after 30 days.",
            policy_text,
        )
        self.assertIn(
            "Before restored data is exposed to normal service access, re-apply the active 30-day payload retention and the 180-day payload-free audit/receipt retention/deletion rules.",
            policy_text,
        )
        self.assertIn(
            "Record recovery authorization and access, restore processing, and post-restore deletion/reconciliation evidence.",
            policy_text,
        )
        self.assertIn(
            "`classify-data` skill supplied by the Control Tower kit or distribution",
            policy_text,
        )
        self.assertNotIn(".github/skills/", policy_text)

    def test_skill_directory_is_not_required(self) -> None:
        shutil.rmtree(self.root / ".github" / "skills", ignore_errors=True)
        self.assertEqual(VALIDATOR.validate_repository(self.root), [])

    def test_canonical_digest_ignores_line_ending_representation(self) -> None:
        lf_bytes = b"# Demo\n\nA policy line.\n"
        crlf_bytes = b"# Demo\r\n\r\nA policy line.\r\n"
        self.assertEqual(
            VALIDATOR.canonical_policy_digest(lf_bytes),
            VALIDATOR.canonical_policy_digest(crlf_bytes),
        )

    def test_blocks_digest_mismatch(self) -> None:
        path = self.root / "policies" / "cloud" / "CCA-001.md"
        path.write_text(path.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
        self.assert_error("SHA-256 does not match")

    def test_blocks_unsafe_path(self) -> None:
        manifest = self.manifest()
        manifest["policies"][0]["path"] = "../outside.md"
        self.write_manifest(manifest)
        self.assert_error("unsafe policy path")

    def test_blocks_duplicate_property_id(self) -> None:
        manifest = self.manifest()
        manifest["policies"][1]["properties"][0] = manifest["policies"][0]["properties"][0]
        self.write_manifest(manifest)
        self.assert_error("duplicate property id")

    def test_blocks_missing_policy_anchor(self) -> None:
        path = self.root / "policies" / "cloud" / "CCA-001.md"
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace('<a id="cca-001-bicep"></a>\n', ""), encoding="utf-8"
        )
        self.assert_error("missing stable property anchor")

    def test_blocks_unsupported_operator(self) -> None:
        manifest = self.manifest()
        manifest["policies"][0]["applicability"]["rule"] = {"matches": ["platform", "azure"]}
        self.write_manifest(manifest)
        self.assert_error("unsupported operator")


if __name__ == "__main__":
    unittest.main()
