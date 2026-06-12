from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OLD_ACTION_PIN = "HakuBlue/LokiRed@v" + ".".join(["0", "1", "0"])
CURRENT_ACTION_PIN = "HakuBlue/LokiRed@" + "v0.2.0"


class ReleasePreparationTest(unittest.TestCase):
    def test_pyproject_declares_v020_and_pep639_license_metadata(self) -> None:
        pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        project = pyproject["project"]
        self.assertEqual(project["version"], "0.2.0")
        self.assertEqual(project["license"], "Apache-2.0")
        self.assertEqual(project["license-files"], ["LICENSE"])
        self.assertTrue((PROJECT_ROOT / "LICENSE").is_file())
        self.assertNotIn(
            "License :: OSI Approved :: Apache Software License",
            project.get("classifiers", []),
        )
        self.assertIn("setuptools>=77", pyproject["build-system"]["requires"])

    def test_public_action_examples_reference_v020_and_stable_check_names(self) -> None:
        public_examples = [
            PROJECT_ROOT / "README.md",
            PROJECT_ROOT / "docs" / "guide.md",
            PROJECT_ROOT / "docs" / "branch-protection-rollout.md",
            PROJECT_ROOT / "docs" / "examples" / "lokired-pr-warn-only.yml",
            PROJECT_ROOT / "docs" / "examples" / "lokired-pr-policy.yml",
        ]

        for path in public_examples:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(PROJECT_ROOT)):
                self.assertNotIn(OLD_ACTION_PIN, text)
                if "HakuBlue/LokiRed@" in text:
                    self.assertIn(CURRENT_ACTION_PIN, text)

        warn_only = (PROJECT_ROOT / "docs" / "examples" / "lokired-pr-warn-only.yml").read_text(encoding="utf-8")
        enforcing = (PROJECT_ROOT / "docs" / "examples" / "lokired-pr-policy.yml").read_text(encoding="utf-8")
        rollout = (PROJECT_ROOT / "docs" / "branch-protection-rollout.md").read_text(encoding="utf-8")

        self.assertIn("name: LokiRed permission review", warn_only)
        self.assertIn("mode: diff", warn_only)
        self.assertIn("name: LokiRed policy check", enforcing)
        self.assertIn("mode: policy-check", enforcing)
        self.assertIn("before GitHub has seen it pass at least once", rollout)
        self.assertIn("LokiRed PR policy / LokiRed policy check", rollout)

    def test_repository_native_pr_review_workflow_is_warn_only_and_minimal_permission(self) -> None:
        workflow = (PROJECT_ROOT / ".github" / "workflows" / "lokired-pr-review.yml").read_text(encoding="utf-8")

        for expected in (
            "on:\n  pull_request:",
            "permissions:\n  contents: read",
            "name: LokiRed permission review",
            "uses: actions/checkout@v6",
            "fetch-depth: 0",
            "ref: ${{ github.event.pull_request.head.sha }}",
            "uses: actions/setup-python@v6",
            'python-version: "3.12"',
            "uses: ./",
            "mode: diff",
            "output-format: \"markdown\"",
            "json-report-path: \"lokired-pr-report.json\"",
            "append-step-summary: \"true\"",
        ):
            self.assertIn(expected, workflow)

        self.assertNotIn("mode: policy-check", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("security-events: write", workflow)


if __name__ == "__main__":
    unittest.main()
