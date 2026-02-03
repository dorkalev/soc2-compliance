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
import time
from pathlib import Path

import httpx

# Retry configuration for API calls
MAX_RETRIES = 5
INITIAL_BACKOFF = 2  # seconds

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


def generate_issue_file_content(ticket_id: str, linear_data: dict | None) -> str:
    """Generate issue file markdown content from Linear ticket data."""
    if not linear_data:
        return f"""# {ticket_id}

## Summary
<!-- Add summary from Linear ticket -->

## Acceptance Criteria
- [ ] <!-- Add acceptance criteria -->

## Out of Scope
- <!-- Items explicitly excluded -->
"""

    title = linear_data.get("title", "")
    description = linear_data.get("description", "") or ""
    state = linear_data.get("state", {}).get("name", "")
    labels = [label.get("name") for label in linear_data.get("labels", {}).get("nodes", [])]

    return f"""# {ticket_id}: {title}

## Summary
{description if description else "<!-- Add summary -->"}

## Acceptance Criteria
- [ ] <!-- Extract from description or add manually -->

## Out of Scope
- <!-- Items explicitly excluded -->

---
*Status: {state}*
*Labels: {", ".join(labels) if labels else "None"}*
"""


def fetch_linear_ticket(ticket_id: str) -> dict | None:
    """Fetch ticket details from Linear API."""
    if not LINEAR_API_KEY:
        return None

    # Use searchIssues to find by identifier (e.g., "PROJ-123")
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
                    try:
                        result["issues"][ticket_id] = issue_file.read_text(errors="replace")
                    except Exception as e:
                        print(f"Warning: Could not read issue file {issue_file}: {e}", file=sys.stderr)
                    break

    # Read spec files - include all that might be relevant
    specs_dir = repo / SPECS_PATH
    if specs_dir.exists():
        for spec_file in specs_dir.glob("**/*.md"):
            try:
                content = spec_file.read_text(errors="replace")
            except Exception as e:
                print(f"Warning: Could not read spec file {spec_file}: {e}", file=sys.stderr)
                continue
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
                        try:
                            result["specs"][str(rel_path)] = spec_file.read_text(errors="replace")
                        except Exception as e:
                            print(f"Warning: Could not read spec file {spec_file}: {e}", file=sys.stderr)

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


def get_branch_commit_tickets(repo_path: str) -> set[str]:
    """
    Extract ticket IDs from non-merge commits on this branch.

    This excludes tickets that came from merge commits (e.g., merging staging
    into the feature branch), ensuring we only track tickets for work actually
    done on this branch.
    """
    try:
        # Get commit messages from non-merge commits only
        # --no-merges excludes merge commits
        # --first-parent follows only the first parent (the branch itself)
        result = subprocess.run(
            [
                "git", "log", f"origin/{BASE_BRANCH}..HEAD",
                "--no-merges",
                "--format=%s%n%b",  # Subject and body
            ],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        commit_text = result.stdout
        return set(extract_ticket_ids(commit_text))
    except Exception as e:
        print(f"Warning: Could not get branch commit tickets: {e}", file=sys.stderr)
        return set()


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


def generate_fix_suggestions(
    unspecced_changes: list[str],
    changed_files: list[str],
    ticket_ids: list[str],
    pr_body: str,
) -> dict:
    """Generate actionable fix suggestions for unspecced changes."""
    if not unspecced_changes:
        return {}

    primary_ticket = ticket_ids[0] if ticket_ids else "TICKET-XXX"

    # Categorize unspecced changes
    file_changes = []
    semantic_changes = []

    for change in unspecced_changes:
        # Check if it looks like a file path
        if "/" in change or change.endswith((".py", ".js", ".ts", ".md", ".yml", ".yaml", ".json", ".html", ".css")):
            file_changes.append(change)
        else:
            semantic_changes.append(change)

    # Match semantic descriptions to actual files if possible
    matched_files = []
    for change in semantic_changes:
        change_lower = change.lower()
        for f in changed_files:
            f_lower = f.lower()
            # Simple keyword matching
            if any(word in f_lower for word in change_lower.split() if len(word) > 3):
                if f not in matched_files and f not in file_changes:
                    matched_files.append(f)
                    break

    all_unspecced_files = file_changes + matched_files

    # Generate PR body table rows
    table_rows = []
    for filepath in all_unspecced_files[:10]:  # Limit to 10
        # Determine change type
        change_type = "Added" if filepath not in pr_body else "Modified"
        # Generate description based on file type
        if filepath.endswith(".md"):
            desc = "Documentation"
        elif filepath.endswith((".jpg", ".png", ".svg", ".gif")):
            desc = "Static assets"
        elif filepath.endswith((".yml", ".yaml")):
            desc = "Configuration/workflow"
        elif "test" in filepath.lower():
            desc = "Test coverage"
        elif "script" in filepath.lower():
            desc = "Utility script"
        else:
            desc = "Implementation"

        table_rows.append(f"| `{filepath}` | {change_type} | {primary_ticket} | {desc} |")

    # For semantic changes without file matches, create generic rows
    for change in semantic_changes:
        if not any(change.lower() in f.lower() for f in matched_files):
            table_rows.append(f"| *(see below)* | Modified | {primary_ticket} | {change} |")

    if not table_rows:
        return {}

    # Build the suggested PR body addition
    suggested_table = "| File | Change | Ticket | Description |\n|------|--------|--------|-------------|\n"
    suggested_table += "\n".join(table_rows)

    # Build concise agent prompt that references Forge command
    files_csv = ",".join(all_unspecced_files[:10])
    agent_prompt = f"""SOC2 compliance check failed. Run this command to fix:

/forge:fix-compliance --files "{files_csv}"

Or for a full compliance rebuild:

/forge:fix-compliance

This will:
1. Add undocumented files to the PR's Key Changes table
2. Map each file to the appropriate Linear ticket ({primary_ticket})
3. Update the PR description with proper audit traceability

Files needing documentation:
{chr(10).join(f"- {f}" for f in all_unspecced_files)}"""

    return {
        "suggested_table_rows": table_rows,
        "suggested_table": suggested_table,
        "agent_prompt": agent_prompt,
        "unspecced_files": all_unspecced_files,
        "semantic_changes": [c for c in semantic_changes if not any(c.lower() in f.lower() for f in matched_files)],
    }


def extract_documented_files(pr_body: str) -> set[str]:
    """Extract file paths mentioned in PR body's Key Changes table."""
    documented = set()

    # Look for markdown table rows with file paths
    # Patterns: | `path/to/file.py` | or | path/to/file.py |
    lines = pr_body.split("\n")
    in_key_changes = False

    for line in lines:
        # Detect "Key Changes" section
        if "key changes" in line.lower() or "### key changes" in line.lower():
            in_key_changes = True
            continue
        # Detect end of section (next header)
        if in_key_changes and line.startswith("##"):
            in_key_changes = False
            continue

        if "|" in line:
            # Extract file paths from table cells
            # Match backtick-wrapped or plain paths
            import re
            # Match: `path/to/file.ext` or path/to/file.ext in table cells
            matches = re.findall(r'`([^`]+)`|(?<=\|)\s*([a-zA-Z0-9_./\-*]+\.[a-zA-Z0-9]+)', line)
            for match in matches:
                path = match[0] or match[1]
                if path and "/" in path:
                    # Handle wildcards like "og-image.*" by extracting base name
                    documented.add(path.strip())
                    # Also add without backticks
                    documented.add(path.strip().replace("`", ""))

    return documented


def verify_with_gemini(
    tickets_data: dict,
    local_files: dict,
    diff: str,
    diff_stats: str,
    pr_body: str,
    changed_files: list[str],
) -> dict:
    """Use Gemini to verify alignment between tickets, specs, and code."""
    from google import genai

    client = genai.Client(api_key=GEMINI_API_KEY)

    # Pre-extract files already documented in PR body
    documented_files = extract_documented_files(pr_body)

    # Build list of files that are ALREADY documented
    already_documented = []
    for f in changed_files:
        for doc in documented_files:
            # Exact match or partial match (for wildcards)
            if f == doc or f in doc or doc in f:
                already_documented.append(f)
                break
            # Handle base name matching (e.g., "og-image.jpg" matches "og-image")
            if "/" in f:
                base = f.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                if base in doc:
                    already_documented.append(f)
                    break

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

    # Build the pre-documented files list for the prompt
    documented_files_str = "\n".join(f"- {f}" for f in already_documented) if already_documented else "None identified"

    prompt = f"""You are a SOC2 compliance auditor. The PR DESCRIPTION is the CENTRAL JUNCTION connecting all audit artifacts.

## AUDIT PHILOSOPHY

The PR description is the **single source of truth** for compliance. It must accurately connect:
- Linear tickets (issue tracker)
- Local issue files (issues/*.md)
- Technical specs (specs/*.md)
- Actual code changes (git diff)

Every claim in the PR must be verifiable. Every change must be documented.

{full_context}

## FILES ALREADY DOCUMENTED IN PR

These files appear in the PR body's Key Changes table - do NOT flag as unspecced:

{documented_files_str}

## VALIDATION CHECKS (PR Description as Junction)

### CHECK 1: PR → Linear (Tickets Exist)
For each ticket in PR's "Linear Tickets" table:
- Verify it exists in the "Issue Tracker Tickets" section above
- If a ticket is listed in PR but NOT found in Linear, flag in "invalid_tickets"

### CHECK 2: PR → Code (Tickets Implemented)
For each ticket in PR's "Linear Tickets" table:
- Verify the code diff contains changes related to that ticket
- Check if the ticket ID appears in Key Changes table's "Ticket" column
- If a ticket is listed but has NO corresponding code changes, flag in "unimplemented_tickets"
- Exception: Tickets marked "merged from staging" or "from PR #X" are OK

### CHECK 3: Code → PR (Changes Documented)
For each file in the code diff:
- Verify it appears in PR body (Key Changes table or description)
- If a changed file is NOT documented anywhere in PR, flag in "unspecced_changes"
- Exception: Files in "FILES ALREADY DOCUMENTED" list above are OK

### CHECK 4: PR → Issues/Specs (Documentation Exists)
For tickets claiming implementation:
- Check if corresponding issues/{{TICKET}}.md file was provided
- Check if specs mention the feature/ticket
- Flag gaps in "missing_documentation"

### CHECK 5: Internal Consistency
- Tickets in Key Changes "Ticket" column should be in Linear Tickets table
- File paths in Key Changes should exist in the diff
- Flag inconsistencies in "issues"

## OUTPUT FORMAT

Respond with JSON only (no markdown):
{{
    "compliant": true/false,
    "summary": "One sentence explaining pass/fail",
    "tickets_found": ["TICKET-1", "TICKET-2"],
    "issues": ["List of compliance violations"],
    "invalid_tickets": ["TICKET-X: not found in Linear"],
    "unimplemented_tickets": ["TICKET-Y: listed in PR but no code changes"],
    "unspecced_changes": ["path/to/file.py: changed but not in PR description"],
    "missing_documentation": ["TICKET-Z: no issues/ or specs/ file found"],
    "unimplemented_specs": ["Spec item X not implemented"],
    "spec_coverage": "How well specs cover the changes",
    "recommendations": ["Suggestions to fix compliance issues"]
}}

## RULES

1. PR description is authoritative - all checks validate against it
2. Empty arrays [] mean check passed
3. Any non-empty violation array means "compliant": false
4. Be strict: false audit trails are worse than strict enforcement
5. Exceptions: test files, minor docs, and config don't need full spec coverage
"""

    # Retry loop with exponential backoff for rate limiting
    last_error = None
    response = None

    for attempt in range(MAX_RETRIES):
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

            result = json.loads(response_text)

            # Generate fix suggestions if there are unspecced changes
            if result.get("unspecced_changes"):
                ticket_ids = result.get("tickets_found", [])
                suggestions = generate_fix_suggestions(
                    result["unspecced_changes"],
                    changed_files,
                    ticket_ids,
                    pr_body,
                )
                result["fix_suggestions"] = suggestions

            return result

        except json.JSONDecodeError as e:
            return {
                "compliant": False,
                "summary": f"Failed to parse Gemini response: {e}",
                "issues": ["Gemini response was not valid JSON"],
                "raw_response": response.text if response else "No response",
            }
        except Exception as e:
            last_error = e
            error_str = str(e).lower()

            # Check for rate limiting (429) or resource exhausted errors
            if "429" in str(e) or "resource_exhausted" in error_str or "rate" in error_str:
                wait_time = INITIAL_BACKOFF ** (attempt + 1)
                # Silently retry - don't print to stderr as workflow captures it
                time.sleep(wait_time)
                continue

            # For other errors, don't retry
            return {
                "compliant": False,
                "summary": f"Gemini API error: {e}",
                "issues": [str(e)],
            }

    # All retries exhausted
    return {
        "compliant": False,
        "summary": f"Gemini API error after {MAX_RETRIES} retries: {last_error}",
        "issues": [f"Rate limited - exceeded {MAX_RETRIES} retry attempts"],
    }


def main():
    """Main entry point."""
    report = {
        "compliant": True,
        "summary": "",
        "tickets_found": [],
        "issues": [],
        "invalid_tickets": [],
        "unimplemented_tickets": [],
        "merge_commit_tickets": [],
        "unspecced_changes": [],
        "missing_documentation": [],
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

    # 3b. Generate suggested issue files for tickets without local files
    missing_issue_files = {}
    for ticket_id in ticket_ids:
        if ticket_id not in local_files["issues"]:
            content = generate_issue_file_content(ticket_id, tickets_data.get(ticket_id))
            missing_issue_files[ticket_id] = content

    if missing_issue_files:
        report["suggested_issue_files"] = missing_issue_files

    # 4. Get diff
    diff, diff_stats = get_diff(TARGET_REPO)

    if not diff:
        report["summary"] = "No changes detected"
        report["issues"].append("Could not generate diff or no changes found")
        print(json.dumps(report, indent=2))
        return

    # 5. Get changed files list
    changed_files = get_changed_files(TARGET_REPO)

    # 5b. Get tickets from actual branch commits (excluding merge commits)
    branch_commit_tickets = get_branch_commit_tickets(TARGET_REPO)

    # 5c. Detect tickets in PR body but not in branch commits
    # This is informational - tickets don't need to be in commit messages
    merge_commit_tickets = [t for t in ticket_ids if t not in branch_commit_tickets]
    if merge_commit_tickets:
        report["merge_commit_tickets"] = merge_commit_tickets
        # Note: Don't print here - workflow captures both stdout and stderr to JSON file

    # 6. Handle large diffs
    if len(diff) > MAX_DIFF_CHARS:
        diff = summarize_large_diff(diff, TARGET_REPO)

    # 7. Verify with Gemini
    if not GEMINI_API_KEY:
        report["compliant"] = False
        report["summary"] = "GEMINI_API_KEY not configured"
        report["issues"].append("Cannot perform AI compliance check without Gemini API key")
        print(json.dumps(report, indent=2))
        return

    gemini_result = verify_with_gemini(
        tickets_data, local_files, diff, diff_stats, PR_BODY, changed_files
    )

    # 8. Merge results
    report.update(gemini_result)

    # 9. Apply policy rules - PR description is the junction, verify all connections
    violations = []

    # Check 1: Invalid tickets (PR → Linear)
    if report.get("invalid_tickets"):
        violations.append("invalid_tickets")
        report["issues"].append(
            "PR references tickets not found in Linear. "
            "Remove invalid ticket IDs or create them in Linear first."
        )

    # Check 2: Unimplemented tickets (PR → Code)
    if report.get("unimplemented_tickets"):
        violations.append("unimplemented_tickets")
        report["issues"].append(
            "PR lists tickets with no corresponding code changes. "
            "Remove these tickets or implement them."
        )

    # Check 3: Unspecced changes (Code → PR)
    if report.get("unspecced_changes") and FAIL_ON_UNSPECCED:
        violations.append("unspecced_changes")
        report["issues"].append(
            "Code changes not documented in PR description. "
            "Add them to the Key Changes table."
        )

    # Check 4: Missing documentation (PR → Issues/Specs)
    if report.get("missing_documentation"):
        # This is a warning, not a blocker by default
        pass

    # Check 5: No tickets at all
    if not ticket_ids and FAIL_ON_MISSING_TICKET:
        violations.append("no_tickets")
        report["issues"].append(
            f"PR must reference at least one ticket matching pattern: {TICKET_PATTERN}"
        )

    # Check 6: Tickets from merge commits (PR lists tickets with no branch commits)
    # NOTE: This is a warning only, not a blocker. Tickets can legitimately be in PR
    # body without being in commit messages (e.g., small fixes, workflow changes).
    # The warning helps identify cases where tickets from merged branches are inherited.
    if report.get("merge_commit_tickets"):
        # Don't add to violations - just a warning
        merge_tickets = report["merge_commit_tickets"]
        report["recommendations"].append(
            f"Note: Tickets {', '.join(merge_tickets)} are in PR body but not in commit messages. "
            "This is OK if these are your primary tickets. If they came from merging another branch, consider removing them."
        )

    # Set compliance status based on violations
    if violations and report.get("compliant", True):
        report["compliant"] = False
        report["summary"] = f"PR description junction validation failed: {', '.join(violations)}"

    # Output
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
