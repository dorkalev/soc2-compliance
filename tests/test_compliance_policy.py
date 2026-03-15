import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from compliance_models import ComplianceConfig
from compliance_policy import enforce_policy, filter_excluded_paths


def make_config(**overrides) -> ComplianceConfig:
    base = {
        "gemini_api_key": "test-key",
        "linear_api_key": "linear-key",
        "github_token": "gh-token",
        "pr_number": "42",
        "repo": "acme/widgets",
        "pr_body": "Implements PROJ-42 with docs and tests.",
        "pr_title": "PROJ-42: Add widget flow",
        "pr_author": "dor",
        "target_repo": ".",
        "base_branch": "main",
        "ticket_pattern": r"[A-Z]+-\d+",
        "issues_path": "issues",
        "specs_path": "specs",
        "linear_team_id": "",
        "required_reviewers": ["coderabbit"],
        "expected_reviewers": ["coderabbit"],
        "confidence_threshold": 70,
        "test_exclude_paths": ["generated/"],
        "pr_labels": [],
        "exempt": False,
        "review_phase": "final",
        "review_check_pending": False,
        "run_id": "",
        "commit_sha": "",
        "review_gate_recheck_seconds": 180,
    }
    base.update(overrides)
    return ComplianceConfig(**base)


class PolicyTests(unittest.TestCase):
    def test_filter_excluded_paths_skips_configured_prefix(self):
        filtered = filter_excluded_paths(
            ["generated/schema.py", "src/service.py:12", "src/api.py"],
            ["generated/", "src/service.py"],
        )
        self.assertEqual(filtered, ["src/api.py"])

    def test_enforce_policy_caps_score_on_mandatory_failures(self):
        findings = {
            "confidence_percent": 100,
            "tickets_found": [],
            "invalid_tickets": [],
            "unspecced_changes": [],
            "missing_documentation": [],
            "spec_issues": [],
            "untested_files": [],
            "unresolved_reviews": [],
            "dismissed_reviews": [],
            "missing_reviewers": [],
            "summary": "",
        }

        report = enforce_policy(make_config(pr_body="too short"), findings)

        self.assertFalse(report["compliant"])
        self.assertEqual(report["confidence_percent"], 55)
        self.assertIn("MANDATORY: PR description is empty or too brief (min 20 chars)", report["issues"])
        self.assertIn("MANDATORY: No Linear ticket referenced in PR title or description", report["issues"])

    def test_enforce_policy_strips_review_findings_when_review_pending(self):
        findings = {
            "confidence_percent": 95,
            "tickets_found": ["PROJ-42"],
            "invalid_tickets": [],
            "unspecced_changes": [],
            "missing_documentation": [],
            "spec_issues": [],
            "untested_files": ["generated/schema.py", "src/service.py"],
            "unresolved_reviews": ["coderabbit CRITICAL on src/db.py:42: SQL injection"],
            "dismissed_reviews": ["greptile MAJOR on src/auth.py:9: bypass"],
            "missing_reviewers": ["coderabbit"],
            "summary": "",
        }

        report = enforce_policy(
            make_config(
                required_reviewers=[],
                expected_reviewers=["coderabbit"],
                review_phase="pre-review",
                review_check_pending=True,
            ),
            findings,
        )

        self.assertTrue(report["compliant"])
        self.assertEqual(report["confidence_percent"], 95)
        self.assertEqual(report["unresolved_reviews"], [])
        self.assertEqual(report["dismissed_reviews"], [])
        self.assertEqual(report["missing_reviewers"], [])
        self.assertEqual(report["untested_files"], ["src/service.py"])

    def test_enforce_policy_handles_valid_exempt_pr(self):
        findings = {
            "confidence_percent": 100,
            "tickets_found": [],
            "invalid_tickets": [],
            "unspecced_changes": [],
            "missing_documentation": [],
            "spec_issues": [],
            "untested_files": [],
            "unresolved_reviews": [],
            "dismissed_reviews": [],
            "missing_reviewers": [],
            "summary": "Trivial change",
            "exempt_justified": True,
        }

        report = enforce_policy(make_config(exempt=True), findings)

        self.assertTrue(report["compliant"])
        self.assertTrue(report["exempt"])
        self.assertEqual(report["summary"], "Trivial change")


if __name__ == "__main__":
    unittest.main()
