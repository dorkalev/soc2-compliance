from __future__ import annotations

import os

from compliance_models import ComplianceConfig, SUPPORTED_REVIEWERS


def _parse_reviewers(raw: str) -> list[str]:
    reviewers = [r.strip().lower() for r in raw.split(",") if r.strip()]
    if any(r in {"*", "all"} for r in reviewers):
        return list(SUPPORTED_REVIEWERS)

    parsed: list[str] = []
    seen: set[str] = set()
    for reviewer in reviewers:
        if reviewer in SUPPORTED_REVIEWERS and reviewer not in seen:
            parsed.append(reviewer)
            seen.add(reviewer)
    return parsed


def _fetch_pr_metadata(github_token: str | None, repo: str, pr_number: str) -> tuple[str, str, str]:
    """Fetch PR body/title/author from GitHub API if not provided via env."""
    body = os.environ.get("PR_BODY", "")
    title = os.environ.get("PR_TITLE", "")
    author = os.environ.get("PR_AUTHOR", "")
    if (body and title) or not (github_token and repo and pr_number):
        return body, title, author

    try:
        import httpx

        resp = httpx.get(
            f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
            headers={"Authorization": f"token {github_token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            return (
                data.get("body", "") or "",
                data.get("title", "") or "",
                data.get("user", {}).get("login", "") or "",
            )
    except Exception:
        pass

    return body, title, author


def _default_agent_key(review_phase: str) -> str:
    if review_phase in {"awaiting-review", "pre-review"}:
        return "audit"
    if review_phase in {"post-review", "final"}:
        return "review-gate"
    return review_phase or "compliance"


def _default_agent_name(review_phase: str) -> str:
    if review_phase in {"awaiting-review", "pre-review"}:
        return "SOC2 Audit Agent"
    if review_phase in {"post-review", "final"}:
        return "SOC2 Review Gate Agent"
    return "SOC2 Compliance Agent"


def _default_blocking_criteria(review_phase: str) -> str:
    if review_phase in {"awaiting-review", "pre-review"}:
        return (
            "ticket coverage, documentation/spec coverage, or test coverage violates policy. "
            "Review-bot findings are excluded in this phase."
        )
    return (
        "the score is below threshold, a required review bot is missing, or any unresolved "
        "major/critical review finding remains open."
    )


def load_config() -> ComplianceConfig:
    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    linear_api_key = os.environ.get("LINEAR_API_KEY")
    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("REPO_TOKEN")
    pr_number = os.environ.get("PR_NUMBER", "")
    repo = os.environ.get("REPO", "")
    pr_body, pr_title, pr_author = _fetch_pr_metadata(github_token, repo, pr_number)
    pr_labels = [label.strip() for label in os.environ.get("PR_LABELS", "").split(",") if label.strip()]
    exempt = "compliance:exempt" in pr_labels
    required_reviewers = _parse_reviewers(os.environ.get("REQUIRED_REVIEWERS", ""))
    expected_reviewers = _parse_reviewers(os.environ.get("EXPECTED_REVIEWERS", ""))
    review_phase = os.environ.get("REVIEW_PHASE", "final").strip().lower() or "final"
    agent_key = os.environ.get("COMPLIANCE_AGENT_KEY", "").strip() or _default_agent_key(review_phase)
    agent_name = os.environ.get("COMPLIANCE_AGENT_NAME", "").strip() or _default_agent_name(review_phase)
    blocking_criteria = (
        os.environ.get("COMPLIANCE_BLOCKING_CRITERIA", "").strip() or _default_blocking_criteria(review_phase)
    )

    return ComplianceConfig(
        gemini_api_key=gemini_api_key,
        linear_api_key=linear_api_key,
        github_token=github_token,
        pr_number=pr_number,
        repo=repo,
        pr_body=pr_body,
        pr_title=pr_title,
        pr_author=pr_author,
        target_repo=os.environ.get("TARGET_REPO", "."),
        base_branch=os.environ.get("BASE_BRANCH", "main"),
        ticket_pattern=os.environ.get("TICKET_PATTERN", r"[A-Z]+-\d+"),
        issues_path=os.environ.get("ISSUES_PATH", "issues"),
        specs_path=os.environ.get("SPECS_PATH", "specs"),
        linear_team_id=os.environ.get("LINEAR_TEAM_ID", ""),
        required_reviewers=required_reviewers,
        expected_reviewers=expected_reviewers,
        confidence_threshold=int(os.environ.get("CONFIDENCE_THRESHOLD", "70")),
        test_exclude_paths=[
            path.strip() for path in os.environ.get("TEST_EXCLUDE_PATHS", "").split(",") if path.strip()
        ],
        pr_labels=pr_labels,
        exempt=exempt,
        agent_key=agent_key,
        agent_name=agent_name,
        blocking_criteria=blocking_criteria,
        review_phase=review_phase,
        review_check_pending=(
            not exempt
            and review_phase in {"awaiting-review", "pre-review"}
            and bool(expected_reviewers)
            and not bool(required_reviewers)
        ),
        run_id=os.environ.get("GITHUB_RUN_ID", ""),
        commit_sha=os.environ.get("COMMIT_SHA", "")[:7],
        review_gate_recheck_seconds=int(os.environ.get("REVIEW_GATE_RECHECK_SECONDS", "180")),
    )
