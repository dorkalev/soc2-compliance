from __future__ import annotations

import sys

from compliance_models import ComplianceConfig
from compliance_review_gate import strip_review_findings_for_pending_phase


def calculate_score(findings: dict) -> int:
    score = 100
    score -= 10 * len(findings.get("invalid_tickets", []))
    score -= 10 * len(findings.get("unspecced_changes", []))
    score -= 10 * len(findings.get("missing_documentation", []))
    score -= 10 * len(findings.get("spec_issues", []))
    score -= 5 * len(findings.get("untested_files", []))
    score -= 5 * len(findings.get("missing_reviewers", []))
    return max(0, min(100, score))


def filter_excluded_paths(files: list[str], exclude_paths: list[str]) -> list[str]:
    if not exclude_paths:
        return files
    return [
        path for path in files
        if not any(path.startswith(excluded) or path.split(":")[0].startswith(excluded) for excluded in exclude_paths)
    ]


def enforce_policy(config: ComplianceConfig, findings: dict) -> dict:
    findings = dict(findings)
    if config.review_check_pending:
        findings = strip_review_findings_for_pending_phase(findings)

    findings["untested_files"] = filter_excluded_paths(
        findings.get("untested_files", []),
        config.test_exclude_paths,
    )

    agent_score = findings.get("confidence_percent", 0)
    confidence = calculate_score(findings)
    if agent_score != confidence:
        print(f"Score override: agent={agent_score}% -> deterministic={confidence}%", file=sys.stderr)

    report = {
        "compliant": confidence >= config.confidence_threshold,
        "confidence_percent": confidence,
        "confidence_threshold": config.confidence_threshold,
        "summary": findings.get("summary", ""),
        "tickets_found": findings.get("tickets_found", []),
        "issues": [],
        "invalid_tickets": findings.get("invalid_tickets", []),
        "unspecced_changes": findings.get("unspecced_changes", []),
        "missing_documentation": findings.get("missing_documentation", []),
        "spec_issues": findings.get("spec_issues", []),
        "untested_files": findings.get("untested_files", []),
        "unresolved_reviews": findings.get("unresolved_reviews", []),
        "dismissed_reviews": findings.get("dismissed_reviews", []),
        "missing_reviewers": findings.get("missing_reviewers", []),
        "review_check_pending": config.review_check_pending,
        "expected_reviewers": config.expected_reviewers,
    }

    if config.exempt:
        report["exempt"] = True
        exempt_justified = findings.get("exempt_justified", True)
        report["exempt_justified"] = exempt_justified
        if not exempt_justified:
            report["compliant"] = False
            report["issues"].append(
                "Change is too large or complex for compliance:exempt — create a ticket"
            )
        else:
            if len((config.pr_body or "").strip()) < 20:
                report["compliant"] = False
                report["issues"].insert(0, "MANDATORY: PR description is empty or too brief (min 20 chars)")
            else:
                report["compliant"] = True
            return report

    if len((config.pr_body or "").strip()) < 20:
        report["compliant"] = False
        report["issues"].insert(0, "MANDATORY: PR description is empty or too brief (min 20 chars)")

    tickets = [ticket for ticket in findings.get("tickets_found", []) if ticket.strip()]
    invalid = findings.get("invalid_tickets", [])
    if not tickets and not invalid:
        report["compliant"] = False
        report["issues"].insert(0, "MANDATORY: No Linear ticket referenced in PR title or description")
    elif not tickets and invalid:
        report["compliant"] = False
        report["issues"].insert(
            0,
            "MANDATORY: All referenced tickets are invalid — no verified authorization in Linear",
        )

    if report.get("unresolved_reviews"):
        report["compliant"] = False
        if not any("critical/major review" in issue.lower() for issue in report["issues"]):
            report["issues"].insert(
                0,
                f"MANDATORY: {len(report['unresolved_reviews'])} unresolved critical/major review finding(s)",
            )

    if report.get("missing_reviewers"):
        report["compliant"] = False
        report["issues"].insert(
            0,
            "MANDATORY: Required reviewer(s) not posted: " + ", ".join(report["missing_reviewers"]),
        )

    if any(issue.startswith("MANDATORY:") for issue in report["issues"]) and confidence > 55:
        confidence = 55
        report["confidence_percent"] = confidence
        report["compliant"] = False

    if report["invalid_tickets"]:
        report["issues"].append(f"{len(report['invalid_tickets'])} ticket(s) not found in Linear")
    if report["unspecced_changes"]:
        report["issues"].append(
            f"{len(report['unspecced_changes'])} file(s) changed without ticket coverage"
        )
    if report["missing_documentation"]:
        report["issues"].append(
            f"{len(report['missing_documentation'])} ticket(s) missing issues/ or specs/ files"
        )
    if report["spec_issues"]:
        report["issues"].append(f"{len(report['spec_issues'])} spec alignment issue(s)")
    if report["untested_files"]:
        report["issues"].append(f"{len(report['untested_files'])} source file(s) with no test coverage")
    if report["missing_reviewers"]:
        report["issues"].append(
            "Required reviewer(s) not posted: " + ", ".join(report["missing_reviewers"])
        )
    if report["unresolved_reviews"]:
        report["issues"].append(
            f"{len(report['unresolved_reviews'])} critical/major review finding(s) unresolved"
        )

    if not report["summary"]:
        report["summary"] = (
            f"Confidence {confidence}% (threshold {config.confidence_threshold}%) — "
            + ("passed" if report["compliant"] else "failed")
        )

    return report
