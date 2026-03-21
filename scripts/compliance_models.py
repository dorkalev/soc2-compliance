from __future__ import annotations

from dataclasses import dataclass


COMMENT_MARKER_PREFIX = "<!-- soc2-compliance-bot"
SUPPORTED_REVIEWERS = ("coderabbit", "aikido", "greptile")


@dataclass(frozen=True)
class ComplianceConfig:
    gemini_api_key: str | None
    linear_api_key: str | None
    github_token: str | None
    pr_number: str
    repo: str
    pr_body: str
    pr_title: str
    pr_author: str
    target_repo: str
    base_branch: str
    ticket_pattern: str
    issues_path: str
    specs_path: str
    linear_team_id: str
    required_reviewers: list[str]
    expected_reviewers: list[str]
    confidence_threshold: int
    test_exclude_paths: list[str]
    pr_labels: list[str]
    exempt: bool
    agent_key: str
    agent_name: str
    blocking_criteria: str
    review_phase: str
    review_check_pending: bool
    run_id: str
    commit_sha: str
    review_gate_recheck_seconds: int
    review_gate_only: bool
