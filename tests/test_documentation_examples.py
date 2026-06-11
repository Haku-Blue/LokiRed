from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from policy import load_policy


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DocumentationExamplesTest(unittest.TestCase):
    def test_policy_template_examples_are_parseable(self) -> None:
        template_paths = sorted((PROJECT_ROOT / "docs" / "examples").glob("policy-*.yml"))

        self.assertEqual(
            {path.name for path in template_paths},
            {
                "policy-high-confidence-enforcement.yml",
                "policy-repository-specific.yml",
                "policy-warn-only.yml",
            },
        )
        for template_path in template_paths:
            with self.subTest(template=template_path.name), tempfile.TemporaryDirectory() as temp_dir:
                policy = load_policy(temp_dir, str(template_path))

                self.assertEqual(policy["schema_version"], "1.0")
                self.assertIn("access", policy)

    def test_policy_template_docs_link_copyable_examples(self) -> None:
        text = (PROJECT_ROOT / "docs" / "policy-templates.md").read_text(encoding="utf-8")

        self.assertIn("examples/policy-warn-only.yml", text)
        self.assertIn("examples/policy-high-confidence-enforcement.yml", text)
        self.assertIn("examples/policy-repository-specific.yml", text)
        self.assertIn("Organization defaults with repository overrides", text)

    def test_coverage_docs_track_required_visibility_classes(self) -> None:
        text = (PROJECT_ROOT / "docs" / "coverage.md").read_text(encoding="utf-8")
        normalized = text.lower()

        for expected in (
            "committed repository artifacts",
            "workspace settings",
            "user-profile settings",
            "SaaS-managed GitHub settings",
            "runtime tool calls",
            "Action coverage",
            "endpoint-only future coverage",
        ):
            self.assertIn(expected.lower(), normalized)


if __name__ == "__main__":
    unittest.main()
