from __future__ import annotations

import re

from compliance_models import ComplianceConfig


BOT_LOGINS = {
    "coderabbit": "coderabbitai[bot]",
    "aikido": "aikido-pr-checks[bot]",
    "greptile": "greptile-apps[bot]",
}


def requested_review_bots(config: ComplianceConfig) -> list[str]:
    return list(config.required_reviewers)


def bot_login_for(reviewer: str) -> str:
    return BOT_LOGINS.get(reviewer.lower(), f"{reviewer}[bot]")


def reviewer_bypassed(result: str, reviewer: str) -> bool:
    low = result.lower()
    if "greptile" in reviewer.lower():
        return "too many files changed for review" in low
    return False


def severity_for_bot_comment(bot_short: str, body: str) -> str | None:
    """Classify severity for deterministic early/late review gating."""
    text = (body or "").lower()

    if bot_short == "coderabbit":
        if re.search(r"\bcritical\b", text):
            return "critical"
        if re.search(r"\bmajor\b|\bpotential issue\b", text):
            return "major"
        return None

    if bot_short == "aikido":
        if re.search(r"\bcritical\b", text):
            return "critical"
        if re.search(r"\bmajor\b|\bhigh\b", text):
            return "major"
        return None

    if bot_short == "greptile":
        return "major"

    return None


def short_summary(text: str, limit: int = 100) -> str:
    line = (text or "").strip().split("\n", 1)[0].strip()
    line = re.sub(r"\s+", " ", line)
    if not line:
        return "No summary provided"
    if len(line) <= limit:
        return line
    return line[: limit - 1].rstrip() + "…"


def fetch_review_threads_raw(config: ComplianceConfig) -> list[dict]:
    """Fetch raw review threads for deterministic review gating."""
    if not (config.github_token and config.repo and config.pr_number):
        return []

    owner, repo = config.repo.split("/", 1)
    query = """
    query($owner: String!, $repo: String!, $pr: Int!) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $pr) {
          reviewThreads(first: 100) {
            nodes {
              isResolved
              comments(first: 20) {
                nodes {
                  author { login }
                  body
                  path
                  line
                  reactions(first: 10) {
                    nodes { user { login } }
                  }
                }
              }
            }
          }
        }
      }
    }"""
    import httpx

    resp = httpx.post(
        "https://api.github.com/graphql",
        headers={"Authorization": f"Bearer {config.github_token}", "Content-Type": "application/json"},
        json={"query": query, "variables": {"owner": owner, "repo": repo, "pr": int(config.pr_number)}},
        timeout=20,
    )
    resp.raise_for_status()
    return (
        resp.json()
        .get("data", {}).get("repository", {}).get("pullRequest", {})
        .get("reviewThreads", {}).get("nodes", [])
    )


def _extract_human_response(comments: list[dict], bot_login_set: set[str]) -> str:
    for comment in comments:
        author = (comment.get("author", {}) or {}).get("login", "")
        if author and author not in bot_login_set and not author.endswith("[bot]"):
            return short_summary(comment.get("body", ""), limit=80)
    return ""


def collect_blocking_review_findings(config: ComplianceConfig) -> dict:
    """
    Deterministically collect unresolved major/critical findings from review bots.
    Also collects dismissed findings: resolved threads where a human replied but
    no code fix was made (bot CRITICAL/MAJOR only).
    """
    configured_bots = requested_review_bots(config)
    if not configured_bots or config.exempt:
        return {"unresolved_reviews": [], "dismissed_reviews": [], "error": None}

    login_to_short = {login: short for short, login in BOT_LOGINS.items() if short in configured_bots}

    try:
        threads = fetch_review_threads_raw(config)
    except Exception as exc:
        return {"unresolved_reviews": [], "dismissed_reviews": [], "error": str(exc)}

    bot_login_set = set(login_to_short.keys())

    def thread_acknowledged_by_human(comments: list[dict]) -> bool:
        for comment in comments:
            author = (comment.get("author", {}) or {}).get("login", "")
            if author and author not in bot_login_set and not author.endswith("[bot]"):
                return True
            reactions = comment.get("reactions", {}).get("nodes", [])
            for reaction in reactions:
                user = (reaction.get("user", {}) or {}).get("login", "")
                if user and user not in bot_login_set and not user.endswith("[bot]"):
                    return True
        return False

    unresolved: list[str] = []
    dismissed: list[str] = []
    for thread in threads:
        comments = thread.get("comments", {}).get("nodes", [])
        is_resolved = thread.get("isResolved", False)

        bot_comment = None
        bot_short = None
        for comment in comments:
            login = (comment.get("author", {}) or {}).get("login", "")
            if login in login_to_short:
                bot_comment = comment
                bot_short = login_to_short[login]
                break

        if not bot_comment or not bot_short:
            continue

        severity = severity_for_bot_comment(bot_short, bot_comment.get("body", ""))
        if not severity:
            continue

        path = bot_comment.get("path") or "(unknown file)"
        line = bot_comment.get("line")
        location = f"{path}:{line}" if line else path
        summary = short_summary(bot_comment.get("body", ""))

        if is_resolved:
            if thread_acknowledged_by_human(comments):
                entry = f"{bot_short} {severity.upper()} on {location}: {summary}"
                human_text = _extract_human_response(comments, bot_login_set)
                if human_text:
                    entry += f" | Developer: {human_text}"
                dismissed.append(entry)
            continue

        if thread_acknowledged_by_human(comments):
            continue

        unresolved.append(f"{bot_short} {severity.upper()} on {location}: {summary}")

    return {"unresolved_reviews": unresolved, "dismissed_reviews": dismissed, "error": None}


def build_review_gate_failure_report(
    config: ComplianceConfig,
    unresolved_reviews: list[str],
    phase: str,
    dismissed_reviews: list[str] | None = None,
) -> dict:
    count = len(unresolved_reviews)
    summary = (
        f"Fast-failed at {phase} review gate: {count} unresolved major/critical "
        f"CodeRabbit/Greptile/Aikido finding(s)"
    )
    return {
        "compliant": False,
        "confidence_percent": 0,
        "confidence_threshold": config.confidence_threshold,
        "summary": summary,
        "issues": [f"{count} critical/major review finding(s) unresolved"],
        "tickets_found": [],
        "invalid_tickets": [],
        "unspecced_changes": [],
        "missing_documentation": [],
        "spec_issues": [],
        "untested_files": [],
        "unresolved_reviews": unresolved_reviews,
        "dismissed_reviews": dismissed_reviews or [],
        "missing_reviewers": [],
        "review_gate_phase": phase,
    }


def apply_dismissed_review_deductions(report: dict, confidence_threshold: int) -> None:
    dismissed = report.get("dismissed_reviews", [])
    if not dismissed:
        return

    deduction = 0
    for entry in dismissed:
        if " CRITICAL " in entry:
            deduction += 5
        else:
            deduction += 3

    if deduction <= 0:
        return

    current = report.get("confidence_percent", 100)
    report["confidence_percent"] = max(0, current - deduction)
    report["issues"].append(
        f"{len(dismissed)} dismissed review finding(s) (resolved without code fix)"
    )
    if report["confidence_percent"] < report.get("confidence_threshold", confidence_threshold):
        report["compliant"] = False


def strip_review_findings_for_pending_phase(findings: dict) -> dict:
    sanitized = dict(findings)
    sanitized["unresolved_reviews"] = []
    sanitized["dismissed_reviews"] = []
    sanitized["missing_reviewers"] = []
    return sanitized


def is_real_review(result: str, reviewer: str) -> bool:
    if "(no comments found)" in result:
        return False

    low = result.lower()
    if "coderabbit" in reviewer.lower():
        if "reviews paused" in low:
            return "walkthrough" in low or "actions performed" in low
        is_placeholder = (
            "review in progress by coderabbit" in low
            or "currently processing" in low
        )
        if is_placeholder and "walkthrough" not in low:
            return False
    return True


def reviewer_requirement_satisfied(result: str, reviewer: str) -> bool:
    return reviewer_bypassed(result, reviewer) or is_real_review(result, reviewer)


def run_review_gate(config: ComplianceConfig, comment, phase: str) -> tuple[dict | None, list[str]]:
    configured_bots = requested_review_bots(config)
    if config.exempt or not configured_bots:
        return None, []

    comment.add_step("🔎", f"Review gate ({phase}) — checking unresolved major/critical bot findings")
    gate = collect_blocking_review_findings(config)
    if gate["error"]:
        comment.add_step("⚠️", f"Review gate ({phase}) unavailable: {gate['error']}")
        return None, []

    unresolved = gate["unresolved_reviews"]
    dismissed = gate.get("dismissed_reviews", [])

    if dismissed:
        comment.add_step(
            "⚠️",
            f"Review gate ({phase}) — {len(dismissed)} dismissed review finding(s) (resolved without code fix)",
        )

    if unresolved:
        comment.add_step(
            "❌",
            f"Review gate ({phase}) failed — {len(unresolved)} unresolved major/critical finding(s)",
        )
        return build_review_gate_failure_report(
            config,
            unresolved_reviews=unresolved,
            phase=phase,
            dismissed_reviews=dismissed,
        ), dismissed

    comment.add_step("✅", f"Review gate ({phase}) passed")
    return None, dismissed
