from __future__ import annotations

import sys

from compliance_models import COMMENT_MARKER, ComplianceConfig


class LiveComment:
    """Manages a single PR comment that updates in-place as the agent works."""

    def __init__(self, config: ComplianceConfig):
        self.config = config
        self.comment_id = None
        self.steps: list[str] = []
        self._delete_existing_comments()

    def _api(self, method: str, endpoint: str, body: dict | None = None):
        if not (self.config.github_token and self.config.repo and self.config.pr_number):
            return None

        owner, repo = self.config.repo.split("/", 1)
        url = f"https://api.github.com/repos/{owner}/{repo}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.config.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            import httpx

            fn = {"POST": httpx.post, "PATCH": httpx.patch, "GET": httpx.get, "DELETE": httpx.delete}[method]
            kwargs = {"headers": headers, "timeout": 15}
            if body:
                kwargs["json"] = body
            resp = fn(url, **kwargs)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            print(f"GitHub API ({method} {endpoint}): {exc}", file=sys.stderr)
            return None

    def _delete_existing_comments(self):
        """Delete any existing SOC2 Compliance comments so the new one appears at the bottom."""
        if not (self.config.github_token and self.config.repo and self.config.pr_number):
            return

        page = 1
        while page <= 10:
            result = self._api("GET", f"issues/{self.config.pr_number}/comments?per_page=100&page={page}")
            if not result:
                break
            for comment in result:
                if COMMENT_MARKER in (comment.get("body") or ""):
                    print(f"Deleting old compliance comment #{comment['id']}", file=sys.stderr)
                    self._api("DELETE", f"issues/comments/{comment['id']}")
            if len(result) < 100:
                break
            page += 1

    def _footer(self) -> str:
        parts = ["[soc2-compliance](https://github.com/dorkalev/soc2-compliance)"]
        if self.config.commit_sha:
            parts.append(f"commit {self.config.commit_sha}")
        if self.config.run_id:
            parts.append(
                f"[run {self.config.run_id}](https://github.com/{self.config.repo}/actions/runs/{self.config.run_id})"
            )
        return f"---\n<sub>{' · '.join(parts)}</sub>"

    def add_step(self, icon: str, text: str):
        self.steps.append(f"{icon} {text}")
        self._post_progress()

    def update_last_step(self, icon: str, text: str):
        if self.steps:
            self.steps[-1] = f"{icon} {text}"
        else:
            self.steps.append(f"{icon} {text}")
        self._post_progress()

    def _post_progress(self):
        body = "## 🔍 SOC2 Compliance: Auditing...\n\n"
        for step in self.steps:
            body += f"- {step}\n"
        body += f"\n{self._footer()}"
        self._upsert(body)

    def _upsert(self, body: str):
        body = f"{COMMENT_MARKER}\n{body}"
        if self.comment_id:
            self._api("PATCH", f"issues/comments/{self.comment_id}", {"body": body})
        else:
            result = self._api("POST", f"issues/{self.config.pr_number}/comments", {"body": body})
            if result:
                self.comment_id = result["id"]

    def _scorecard_line(self, items: list[str], pass_label: str, fail_label: str) -> str:
        if not items:
            return f"  :white_check_mark: {pass_label}\n"

        line = f"  :x: {fail_label}\n"
        for item in items:
            line += f"  - {item}\n"
        return line

    def finalize(self, report: dict):
        compliant = report.get("compliant", False)
        confidence = report.get("confidence_percent", 0)
        threshold = report.get("confidence_threshold", self.config.confidence_threshold)
        is_exempt = report.get("exempt", False)
        review_pending = report.get("review_check_pending", False)
        expected_reviewers = report.get("expected_reviewers", [])
        icon = "⏳" if review_pending else ("✅" if compliant else "❌")

        exempt_badge = " (exempt)" if is_exempt else ""
        if review_pending:
            body = "## ⏳ SOC2 Compliance: review pending\n\n"
            if expected_reviewers:
                body += (
                    "Final compliance scoring is blocked until required review posts: "
                    + ", ".join(expected_reviewers)
                    + "\n\n"
                )
            body += "Current findings below exclude review-tool results.\n\n"
        else:
            partial_badge = " · partial (no review check)" if not self.config.required_reviewers and not is_exempt else ""
            body = f"## {icon} SOC2 Compliance: {confidence}%{exempt_badge}{partial_badge}\n\n"

        if is_exempt:
            body += f"Threshold {threshold}% · exempt PR, lightweight audit\n\n"
            if not report.get("exempt_justified", True):
                body += ":x: Change is too large or complex for exemption\n\n"
        else:
            body += f"Threshold {threshold}%\n\n"

            tickets = report.get("tickets_found", [])
            invalid = report.get("invalid_tickets", [])
            unspecced = report.get("unspecced_changes", [])
            missing_docs = report.get("missing_documentation", [])
            spec_issues = report.get("spec_issues", [])
            untested = report.get("untested_files", [])
            unresolved = report.get("unresolved_reviews", [])
            missing_reviewers = report.get("missing_reviewers", [])

            if tickets and not invalid:
                body += f"  :white_check_mark: Tickets: {', '.join(tickets)}\n"
            elif tickets:
                body += f"  :x: Tickets: {', '.join(tickets)}\n"
                for ticket in invalid:
                    body += f"  - {ticket}\n"
            else:
                body += "  :x: No tickets found\n"

            body += self._scorecard_line(unspecced, "All changes covered by tickets", "Untracked changes")
            body += self._scorecard_line(
                missing_docs + spec_issues,
                "Issue & spec files present",
                "Documentation gaps",
            )
            body += self._scorecard_line(untested, "Test coverage", "Missing tests")

            dismissed = report.get("dismissed_reviews", [])
            if dismissed:
                body += f"  :warning: {len(dismissed)} dismissed review finding(s) (resolved without code fix)\n"
                for finding in dismissed:
                    body += f"  - {finding}\n"

            if not review_pending:
                body += self._scorecard_line(
                    unresolved + [f"Missing: {reviewer}" for reviewer in missing_reviewers],
                    "Reviews clean",
                    "Review issues",
                )

            body += "\n"

        if not compliant:
            body += "---\n\n"
            body += "Fix: run `/forge:fix-compliance` in Claude Code\n\n"

        body += self._footer()
        self._upsert(body)
