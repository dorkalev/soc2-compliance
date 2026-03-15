import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from compliance_models import ComplianceConfig
from compliance_review_gate import (
    apply_dismissed_review_deductions,
    collect_blocking_review_findings,
    is_real_review,
    reviewer_bypassed,
    reviewer_requirement_satisfied,
    severity_for_bot_comment,
)


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
        "required_reviewers": ["coderabbit", "greptile"],
        "expected_reviewers": [],
        "confidence_threshold": 70,
        "test_exclude_paths": [],
        "pr_labels": [],
        "exempt": False,
        "agent_key": "review-gate",
        "agent_name": "SOC2 Review Gate Agent",
        "blocking_criteria": "required reviewer missing or unresolved major/critical review findings remain open.",
        "review_phase": "final",
        "review_check_pending": False,
        "run_id": "",
        "commit_sha": "",
        "review_gate_recheck_seconds": 180,
    }
    base.update(overrides)
    return ComplianceConfig(**base)


class SeverityTests(unittest.TestCase):
    def test_severity_for_known_bots(self):
        self.assertEqual(severity_for_bot_comment("coderabbit", "Critical bug"), "critical")
        self.assertEqual(severity_for_bot_comment("coderabbit", "Potential issue found"), "major")
        self.assertEqual(severity_for_bot_comment("aikido", "High severity"), "major")
        self.assertEqual(severity_for_bot_comment("greptile", "Any feedback"), "major")
        self.assertIsNone(severity_for_bot_comment("coderabbit", "nit: rename variable"))

    def test_is_real_review_filters_placeholders(self):
        self.assertFalse(is_real_review("review in progress by coderabbit", "coderabbit"))
        self.assertTrue(is_real_review("Reviews paused\nWalkthrough", "coderabbit"))
        self.assertTrue(is_real_review("review in progress by coderabbit\nActions performed\nFull review triggered.", "coderabbit"))
        self.assertTrue(is_real_review("Walkthrough\nLooks good", "coderabbit"))
        self.assertTrue(is_real_review("security review complete", "aikido"))

    def test_reviewer_requirement_satisfied_allows_greptile_bypass(self):
        bypass = "Too many files changed for review. (`153 files found`, `100 file limit`)"
        self.assertTrue(reviewer_bypassed(bypass, "greptile"))
        self.assertTrue(reviewer_requirement_satisfied(bypass, "greptile"))
        self.assertFalse(reviewer_requirement_satisfied("(no comments found)", "greptile"))


class ReviewGateCollectionTests(unittest.TestCase):
    @patch("compliance_review_gate.fetch_review_threads_raw")
    def test_collect_blocking_review_findings_handles_unresolved_and_dismissed(self, mock_fetch):
        mock_fetch.return_value = [
            {
                "isResolved": False,
                "comments": {
                    "nodes": [
                        {
                            "author": {"login": "coderabbitai[bot]"},
                            "body": "Critical SQL injection risk",
                            "path": "src/db.py",
                            "line": 42,
                            "reactions": {"nodes": []},
                        }
                    ]
                },
            },
            {
                "isResolved": True,
                "comments": {
                    "nodes": [
                        {
                            "author": {"login": "greptile-apps[bot]"},
                            "body": "Possible auth bypass",
                            "path": "src/auth.py",
                            "line": 9,
                            "reactions": {"nodes": []},
                        },
                        {
                            "author": {"login": "dor"},
                            "body": "Handled in a follow-up diff",
                            "path": "src/auth.py",
                            "line": 9,
                            "reactions": {"nodes": []},
                        },
                    ]
                },
            },
            {
                "isResolved": False,
                "comments": {
                    "nodes": [
                        {
                            "author": {"login": "coderabbitai[bot]"},
                            "body": "Major issue: null dereference",
                            "path": "src/nulls.py",
                            "line": 3,
                            "reactions": {"nodes": []},
                        },
                        {
                            "author": {"login": "dor"},
                            "body": "Acknowledged",
                            "path": "src/nulls.py",
                            "line": 3,
                            "reactions": {"nodes": []},
                        },
                    ]
                },
            },
        ]

        findings = collect_blocking_review_findings(make_config())

        self.assertEqual(
            findings["unresolved_reviews"],
            ["coderabbit CRITICAL on src/db.py:42: Critical SQL injection risk"],
        )
        self.assertEqual(
            findings["dismissed_reviews"],
            ["greptile MAJOR on src/auth.py:9: Possible auth bypass | Developer: Handled in a follow-up diff"],
        )
        self.assertIsNone(findings["error"])

    def test_apply_dismissed_review_deductions_reduces_score(self):
        report = {
            "confidence_percent": 90,
            "confidence_threshold": 70,
            "dismissed_reviews": [
                "coderabbit CRITICAL on src/db.py:42: SQL injection",
                "greptile MAJOR on src/auth.py:9: bypass",
            ],
            "issues": [],
            "compliant": True,
        }

        apply_dismissed_review_deductions(report, 70)

        self.assertEqual(report["confidence_percent"], 82)
        self.assertTrue(report["compliant"])
        self.assertIn("2 dismissed review finding(s) (resolved without code fix)", report["issues"])


if __name__ == "__main__":
    unittest.main()
