#!/usr/bin/env python3
"""
SOC2 Compliance Verification Script

Verifies that PR changes align with:
- Issue tracker tickets (Linear)
- Local issue requirement files
- Technical specification files

Uses Gemini API for intelligent alignment checking.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import httpx

# Configuration from environment
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
LINEAR_API_KEY = os.environ.get("LINEAR_API_KEY")
PR_BODY = os.environ.get("PR_BODY", "")
PR_NUMBER = os.environ.get("PR_NUMBER", "")
TARGET_REPO = os.environ.get("TARGET_REPO", ".")
BASE_BRANCH = os.environ.get("BASE_BRANCH", "main")
TICKET_PATTERN = os.environ.get("TICKET_PATTERN", r"[A-Z]+-\d+")
ISSUES_PATH = os.environ.get("ISSUES_PATH", "issues")
SPECS_PATH = os.environ.get("SPECS_PATH", "specs")
LINEAR_TEAM_ID = os.environ.get("LINEAR_TEAM_ID", "")
FAIL_ON_UNSPECCED = os.environ.get("FAIL_ON_UNSPECCED", "true").lower() == "true"
FAIL_ON_MISSING_TICKET = os.environ.get("FAIL_ON_MISSING_TICKET", "true").lower() == "true"

# Token limits (conservative estimates)
MAX_DIFF_CHARS = 400_000  # ~100K tokens
MAX_CONTEXT_CHARS = 800_000  # ~200K tokens for full context


def extract_ticket_ids(text: str) -> list[str]:
    """Extract ticket IDs from text using configured pattern."""
    pattern = re.compile(TICKET_PATTERN)
    matches = pattern.findall(text)
    return list(set(matches))  # Deduplicate


def fetch_linear_ticket(ticket_id: str) -> dict | None:
    """Fetch ticket details from Linear API."""
    if not LINEAR_API_KEY:
        return None

    # Use searchIssues to find by identifier (e.g., "BOL-410")
    query = """
    query SearchIssue($term: String!) {
        searchIssues(term: $term, first: 5) {
            nodes {
                id
                identifier
                title
                description
                state { name }
                labels { nodes { name } }
            }
        }
    }
    """

    try:
        resp = httpx.post(
            "https://api.linear.app/graphql",
            headers={
                "Authorization": LINEAR_API_KEY,
                "Content-Type": "application/json",
            },
            json={"query": query, "variables": {"term": ticket_id}},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        # Check for errors in response
        if "errors" in data:
            print(f"Warning: Linear API error for {ticket_id}: {data['errors']}", file=sys.stderr)
            return None

        nodes = data.get("data", {}).get("searchIssues", {}).get("nodes", [])
        # Find exact match for the identifier
        for node in nodes:
            if node.get("identifier") == ticket_id:
                return node
        # Fallback to first result if no exact match
        if nodes:
            return nodes[0]
    except Exception as e:
        print(f"Warning: Failed to fetch Linear ticket {ticket_id}: {e}", file=sys.stderr)

    return None


def read_local_files(ticket_ids: list[str], repo_path: str) -> dict:
    """Read local issue and spec files."""
    result = {"issues": {}, "specs": {}}
    repo = Path(repo_path)

    # Read issue files
    issues_dir = repo / ISSUES_PATH
    if issues_dir.exists():
        for ticket_id in ticket_ids:
            # Try common naming patterns
            for pattern in [f"{ticket_id}.md", f"{ticket_id.lower()}.md", f"{ticket_id.replace('-', '_')}.md"]:
                issue_file = issues_dir / pattern
                if issue_file.exists():
                    result["issues"][ticket_id] = issue_file.read_text()
                    break

    # Read spec files - include all that might be relevant
    specs_dir = repo / SPECS_PATH
    if specs_dir.exists():
        for spec_file in specs_dir.glob("**/*.md"):
            content = spec_file.read_text()
            # Check if spec mentions any of our tickets
            for ticket_id in ticket_ids:
                if ticket_id.lower() in content.lower():
                    rel_path = spec_file.relative_to(repo)
                    result["specs"][str(rel_path)] = content
                    break

        # Also include specs that match ticket ID patterns in filename
        for ticket_id in ticket_ids:
            for pattern in [f"*{ticket_id}*", f"*{ticket_id.lower()}*"]:
                for spec_file in specs_dir.glob(f"**/{pattern}.md"):
                    rel_path = spec_file.relative_to(repo)
                    if str(rel_path) not in result["specs"]:
                        result["specs"][str(rel_path)] = spec_file.read_text()

    return result


def get_diff(repo_path: str) -> tuple[str, str]:
    """Get git diff from base branch. Returns (diff, stats)."""
    try:
        # Get diff stats
        stats_result = subprocess.run(
            ["git", "diff", f"origin/{BASE_BRANCH}...HEAD", "--stat"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        stats = stats_result.stdout

        # Get full diff
        diff_result = subprocess.run(
            ["git", "diff", f"origin/{BASE_BRANCH}...HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        diff = diff_result.stdout

        return diff, stats
    except subprocess.TimeoutExpired:
        return "", "Error: Diff generation timed out"
    except Exception as e:
        return "", f"Error: {e}"


def get_changed_files(repo_path: str) -> list[str]:
    """Get list of changed files."""
    try:
        result = subprocess.run(
            ["git", "diff", f"origin/{BASE_BRANCH}...HEAD", "--name-only"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return [f for f in result.stdout.strip().split("\n") if f]
    except Exception:
        return []


def summarize_large_diff(diff: str, repo_path: str) -> str:
    """Summarize a large diff by file."""
    changed_files = get_changed_files(repo_path)

    summary_parts = ["# Diff Summary (too large for full analysis)\n"]

    for filepath in changed_files[:50]:  # Limit to 50 files
        try:
            result = subprocess.run(
                ["git", "diff", f"origin/{BASE_BRANCH}...HEAD", "--", filepath],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            file_diff = result.stdout

            # Count changes
            additions = len([l for l in file_diff.split("\n") if l.startswith("+")])
            deletions = len([l for l in file_diff.split("\n") if l.startswith("-")])

            # Include truncated diff
            if len(file_diff) > 5000:
                file_diff = file_diff[:5000] + "\n... (truncated)"

            summary_parts.append(f"\n## {filepath} (+{additions}/-{deletions})\n```\n{file_diff}\n```")
        except Exception:
            summary_parts.append(f"\n## {filepath}\nError reading diff")

    return "\n".join(summary_parts)


def verify_with_gemini(
    tickets_data: dict,
    local_files: dict,
    diff: str,
    diff_stats: str,
    pr_body: str,
) -> dict:
    """Use Gemini to verify alignment between tickets, specs, and code."""
    from google import genai

    client = genai.Client(api_key=GEMINI_API_KEY)

    # Build context sections
    context_parts = []

    # PR Description
    context_parts.append(f"## Pull Request Description\n\n{pr_body}")

    # Linear tickets
    if tickets_data:
        context_parts.append("## Issue Tracker Tickets\n")
        for ticket_id, data in tickets_data.items():
            if data:
                context_parts.append(f"### {ticket_id}: {data.get('title', 'No title')}")
                context_parts.append(f"State: {data.get('state', {}).get('name', 'Unknown')}")
                context_parts.append(f"Description:\n{data.get('description', 'No description')}\n")
            else:
                context_parts.append(f"### {ticket_id}: (Could not fetch from Linear)\n")

    # Local issue files
    if local_files["issues"]:
        context_parts.append("## Local Issue Requirement Files\n")
        for filename, content in local_files["issues"].items():
            context_parts.append(f"### {filename}\n{content}\n")

    # Spec files
    if local_files["specs"]:
        context_parts.append("## Technical Specification Files\n")
        for filename, content in local_files["specs"].items():
            context_parts.append(f"### {filename}\n{content}\n")

    # Diff stats
    context_parts.append(f"## Changed Files Summary\n\n```\n{diff_stats}\n```")

    # Diff content
    context_parts.append(f"## Code Changes (Diff)\n\n```diff\n{diff}\n```")

    full_context = "\n\n".join(context_parts)

    # Truncate if needed
    if len(full_context) > MAX_CONTEXT_CHARS:
        full_context = full_context[:MAX_CONTEXT_CHARS] + "\n\n... (context truncated due to size)"

    prompt = f"""You are a SOC2 compliance auditor reviewing a pull request.

Your task is to verify ALIGNMENT between:
1. Issue tracker tickets (requirements from project management)
2. Local issue files (product requirements documentation)
3. Technical spec files (implementation specifications)
4. The actual code changes in the PR

{full_context}

## Analysis Required

1. **Ticket Coverage**: Are the code changes implementing what's described in the tickets?
2. **Spec Alignment**: Do the changes follow the technical specifications?
3. **Unspecced Changes**: Are there any code changes NOT documented in tickets/specs?
4. **Incomplete Implementation**: Are there spec items NOT implemented in the code?
5. **Scope Creep**: Does the PR include changes beyond the ticket scope?

## Output

Respond with a JSON object (no markdown, just raw JSON):
{{
    "compliant": true/false,
    "summary": "One sentence summary of compliance status",
    "tickets_found": ["list", "of", "ticket", "ids"],
    "issues": ["list of compliance issues found"],
    "unspecced_changes": ["files or features changed without spec coverage"],
    "unimplemented_specs": ["spec items not found in the code"],
    "spec_coverage": "Brief description of how well specs cover the changes",
    "recommendations": ["suggestions for improving compliance"]
}}

Be strict but fair. Minor documentation changes and test files don't need specs.
Config changes and dependency updates should still reference a ticket.
"""

    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )

        # Parse JSON from response
        response_text = response.text.strip()

        # Handle markdown code blocks
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1])

        return json.loads(response_text)
    except json.JSONDecodeError as e:
        return {
            "compliant": False,
            "summary": f"Failed to parse Gemini response: {e}",
            "issues": ["Gemini response was not valid JSON"],
            "raw_response": response.text if "response" in dir() else "No response",
        }
    except Exception as e:
        return {
            "compliant": False,
            "summary": f"Gemini API error: {e}",
            "issues": [str(e)],
        }


def main():
    """Main entry point."""
    report = {
        "compliant": True,
        "summary": "",
        "tickets_found": [],
        "issues": [],
        "unspecced_changes": [],
        "unimplemented_specs": [],
        "spec_coverage": "",
        "recommendations": [],
    }

    # 1. Extract ticket IDs from PR body
    ticket_ids = extract_ticket_ids(PR_BODY)
    report["tickets_found"] = ticket_ids

    if not ticket_ids and FAIL_ON_MISSING_TICKET:
        report["compliant"] = False
        report["summary"] = "No ticket reference found in PR description"
        report["issues"].append(
            f"PR must reference at least one ticket matching pattern: {TICKET_PATTERN}"
        )
        print(json.dumps(report, indent=2))
        return

    # 2. Fetch Linear tickets
    tickets_data = {}
    for ticket_id in ticket_ids:
        tickets_data[ticket_id] = fetch_linear_ticket(ticket_id)

    # 3. Read local issue and spec files
    local_files = read_local_files(ticket_ids, TARGET_REPO)

    # 4. Get diff
    diff, diff_stats = get_diff(TARGET_REPO)

    if not diff:
        report["summary"] = "No changes detected"
        report["issues"].append("Could not generate diff or no changes found")
        print(json.dumps(report, indent=2))
        return

    # 5. Handle large diffs
    if len(diff) > MAX_DIFF_CHARS:
        diff = summarize_large_diff(diff, TARGET_REPO)

    # 6. Verify with Gemini
    if not GEMINI_API_KEY:
        report["compliant"] = False
        report["summary"] = "GEMINI_API_KEY not configured"
        report["issues"].append("Cannot perform AI compliance check without Gemini API key")
        print(json.dumps(report, indent=2))
        return

    gemini_result = verify_with_gemini(
        tickets_data, local_files, diff, diff_stats, PR_BODY
    )

    # 7. Merge results
    report.update(gemini_result)

    # 8. Apply policy rules
    if not report["compliant"]:
        pass  # Already failed
    elif report.get("unspecced_changes") and FAIL_ON_UNSPECCED:
        report["compliant"] = False
        if "Unspecced changes detected" not in report.get("summary", ""):
            report["summary"] = "Unspecced changes detected: " + report.get("summary", "")
    elif not ticket_ids and FAIL_ON_MISSING_TICKET:
        report["compliant"] = False

    # Output
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
