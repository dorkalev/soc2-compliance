import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from compliance_commenting import LiveComment
from compliance_models import ComplianceConfig


def make_config(**overrides) -> ComplianceConfig:
    base = {
        "gemini_api_key": "test-key",
        "linear_api_key": "linear-key",
        "github_token": None,
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
        "expected_reviewers": [],
        "confidence_threshold": 70,
        "test_exclude_paths": [],
        "pr_labels": [],
        "exempt": False,
        "agent_key": "audit",
        "agent_name": "SOC2 Audit Agent",
        "blocking_criteria": "ticket coverage, docs/spec coverage, or test coverage violates policy.",
        "review_phase": "awaiting-review",
        "review_check_pending": True,
        "run_id": "12345",
        "commit_sha": "abcdef0",
        "review_gate_recheck_seconds": 180,
        "review_gate_only": False,
    }
    base.update(overrides)
    return ComplianceConfig(**base)


class CapturingLiveComment(LiveComment):
    def __init__(self, config: ComplianceConfig):
        self.last_body = ""
        super().__init__(config)

    def _upsert(self, body: str):
        self.last_body = f"{self._marker()}\n{body}"


class CommentingTests(unittest.TestCase):
    def test_marker_includes_agent_key_and_replaces_legacy_markers(self):
        comment = CapturingLiveComment(make_config(review_phase="post-review", agent_key="review-gate"))

        self.assertEqual(comment._marker(), "<!-- soc2-compliance-bot:review-gate:post-review -->")
        self.assertIn("<!-- soc2-compliance-bot -->", comment._markers_to_replace())
        self.assertIn("<!-- soc2-compliance-bot:awaiting-review -->", comment._markers_to_replace())
        self.assertIn("<!-- soc2-compliance-bot:review-gate:awaiting-review -->", comment._markers_to_replace())

    def test_finalize_mentions_agent_name_and_blocking_rule(self):
        comment = CapturingLiveComment(make_config())
        report = {
            "compliant": False,
            "confidence_percent": 65,
            "confidence_threshold": 70,
            "exempt": False,
            "review_check_pending": True,
            "expected_reviewers": ["coderabbit"],
            "tickets_found": ["PROJ-42"],
            "invalid_tickets": [],
            "unspecced_changes": [],
            "missing_documentation": [],
            "spec_issues": [],
            "untested_files": ["src/service.py: no test file found"],
            "unresolved_reviews": [],
            "dismissed_reviews": [],
            "missing_reviewers": [],
        }

        comment.finalize(report)

        self.assertIn("## ⏳ SOC2 Audit Agent: waiting for required review", comment.last_body)
        self.assertIn("**Blocks merge now:** Yes", comment.last_body)
        self.assertIn("**Blocks merge when:** ticket coverage, docs/spec coverage, or test coverage violates policy.", comment.last_body)
        self.assertIn("Fix: run `/forge:fix-compliance`", comment.last_body)
        self.assertNotIn("Claude Code", comment.last_body)

    def test_finalize_uses_partial_audit_copy_when_review_already_posted(self):
        comment = CapturingLiveComment(make_config())
        report = {
            "compliant": True,
            "confidence_percent": 100,
            "confidence_threshold": 70,
            "exempt": False,
            "review_check_pending": True,
            "expected_reviewers": [],
            "tickets_found": ["PROJ-42"],
            "invalid_tickets": [],
            "unspecced_changes": [],
            "missing_documentation": [],
            "spec_issues": [],
            "untested_files": [],
            "unresolved_reviews": [],
            "dismissed_reviews": [],
            "missing_reviewers": [],
        }

        comment.finalize(report)

        self.assertIn("## ℹ️ SOC2 Audit Agent: partial audit", comment.last_body)
        self.assertIn("Required review already posted.", comment.last_body)
        self.assertNotIn("Final compliance scoring is blocked until required review posts", comment.last_body)


if __name__ == "__main__":
    unittest.main()
