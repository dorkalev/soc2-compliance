#!/usr/bin/env python3
"""
SOC2 Compliance Agent

An AI agent that audits PRs by investigating with tools rather than
receiving a pre-built context dump. Updates a live PR comment as it works.

Checks:
  1. Ticket traceability (Linear → PR → code)
  2. Documentation (issues/ and specs/ files exist and align)
  3. Test coverage (changed source files have tests)
  4. Review tools (CodeRabbit, Aikido, Greptile findings addressed)
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
LINEAR_API_KEY = os.environ.get("LINEAR_API_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("REPO_TOKEN")
PR_BODY = os.environ.get("PR_BODY", "")
PR_TITLE = os.environ.get("PR_TITLE", "")
PR_AUTHOR = os.environ.get("PR_AUTHOR", "")
PR_NUMBER = os.environ.get("PR_NUMBER", "")
REPO = os.environ.get("REPO", "")
TARGET_REPO = os.environ.get("TARGET_REPO", ".")
BASE_BRANCH = os.environ.get("BASE_BRANCH", "main")
TICKET_PATTERN = os.environ.get("TICKET_PATTERN", r"[A-Z]+-\d+")
ISSUES_PATH = os.environ.get("ISSUES_PATH", "issues")
SPECS_PATH = os.environ.get("SPECS_PATH", "specs")
LINEAR_TEAM_ID = os.environ.get("LINEAR_TEAM_ID", "")
REQUIRED_REVIEWERS = [
    r.strip() for r in os.environ.get("REQUIRED_REVIEWERS", "").split(",") if r.strip()
]
CONFIDENCE_THRESHOLD = int(os.environ.get("CONFIDENCE_THRESHOLD", "70"))
RUN_ID = os.environ.get("GITHUB_RUN_ID", "")
COMMIT_SHA = os.environ.get("COMMIT_SHA", "")[:7]

MAX_STEPS = 25
MAX_TOOL_OUTPUT = 50_000  # chars per tool result
MAX_RETRIES = 5
INITIAL_BACKOFF = 2


# ---------------------------------------------------------------------------
# Live PR comment
# ---------------------------------------------------------------------------
class LiveComment:
    """Manages a single PR comment that updates in-place as the agent works."""

    def __init__(self):
        self.comment_id = None
        self.steps: list[str] = []

    # -- GitHub helpers --
    def _api(self, method, endpoint, body=None):
        if not (GITHUB_TOKEN and REPO and PR_NUMBER):
            return None
        owner, repo = REPO.split("/", 1)
        url = f"https://api.github.com/repos/{owner}/{repo}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            fn = {"POST": httpx.post, "PATCH": httpx.patch, "GET": httpx.get}[method]
            kw = {"headers": headers, "timeout": 15}
            if body:
                kw["json"] = body
            resp = fn(url, **kw)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"GitHub API ({method} {endpoint}): {e}", file=sys.stderr)
            return None

    def _footer(self):
        parts = ["[soc2-compliance](https://github.com/dorkalev/soc2-compliance)"]
        if COMMIT_SHA:
            parts.append(f"commit {COMMIT_SHA}")
        if RUN_ID:
            parts.append(f"[run {RUN_ID}](https://github.com/{REPO}/actions/runs/{RUN_ID})")
        return f"---\n<sub>{' · '.join(parts)}</sub>"

    # -- Progress tracking --
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
        if self.comment_id:
            self._api("PATCH", f"issues/comments/{self.comment_id}", {"body": body})
        else:
            result = self._api("POST", f"issues/{PR_NUMBER}/comments", {"body": body})
            if result:
                self.comment_id = result["id"]

    # -- Final report --
    def finalize(self, report: dict):
        compliant = report.get("compliant", False)
        confidence = report.get("confidence_percent", 0)
        threshold = report.get("confidence_threshold", CONFIDENCE_THRESHOLD)
        icon = "✅" if compliant else "❌"

        body = f"## {icon} SOC2 Compliance: {confidence}%\n\n"

        if compliant:
            body += f"Confidence **{confidence}%** (threshold {threshold}%) — all checks look good.\n\n"
        else:
            body += f"Confidence **{confidence}%** (threshold {threshold}%)\n\n"
            body += "### Issues Found\n\n"
            for issue in report.get("issues", []):
                body += f"- {issue}\n"
            body += "\n"

        # Audit trail (always shown)
        if self.steps:
            body += "### Audit Trail\n\n"
            for step in self.steps:
                body += f"- {step}\n"
            body += "\n"

        if report.get("tickets_found"):
            body += f"**Tickets:** {', '.join(report['tickets_found'])}\n\n"

        if not compliant:
            body += "---\n\n"
            body += "## 🔧 How to Fix\n\n"
            body += "Run this command in Claude Code:\n\n"
            body += "```\n/forge:fix-compliance\n```\n\n"

        body += self._footer()
        self._upsert(body)


# ---------------------------------------------------------------------------
# Agent tools
# ---------------------------------------------------------------------------
def tool_git_diff(file: str | None = None) -> str:
    """Get the git diff from the base branch. Optionally filter to one file."""
    cmd = ["git", "diff", f"origin/{BASE_BRANCH}...HEAD"]
    if file:
        cmd += ["--", file]
    try:
        r = subprocess.run(cmd, cwd=TARGET_REPO, capture_output=True, text=True, timeout=60)
        out = r.stdout
        if len(out) > MAX_TOOL_OUTPUT:
            out = out[:MAX_TOOL_OUTPUT] + "\n... (truncated)"
        return out or "(no diff)"
    except Exception as e:
        return f"Error: {e}"


def tool_git_diff_stat() -> str:
    """Get a one-line-per-file summary of changes (files and line counts)."""
    try:
        r = subprocess.run(
            ["git", "diff", f"origin/{BASE_BRANCH}...HEAD", "--stat"],
            cwd=TARGET_REPO, capture_output=True, text=True, timeout=30,
        )
        return r.stdout or "(no changes)"
    except Exception as e:
        return f"Error: {e}"


def tool_git_ls_files(pattern: str | None = None) -> str:
    """List tracked files, optionally filtered by glob pattern (e.g. '*test*', 'tests/**')."""
    from fnmatch import fnmatch

    try:
        r = subprocess.run(
            ["git", "ls-files"], cwd=TARGET_REPO, capture_output=True, text=True, timeout=30,
        )
        files = [f for f in r.stdout.strip().split("\n") if f]
        if pattern:
            # Match against full path AND basename so "*test*" finds "src/tests/test_auth.py"
            files = [
                f for f in files
                if fnmatch(f, pattern) or fnmatch(f.rsplit("/", 1)[-1], pattern)
            ]
        out = "\n".join(files)
        if len(out) > MAX_TOOL_OUTPUT:
            out = "\n".join(files[:500]) + f"\n... ({len(files)} files total)"
        return out or "(no matching files)"
    except Exception as e:
        return f"Error: {e}"


def tool_read_file(path: str) -> str:
    """Read a file from the repository."""
    try:
        content = (Path(TARGET_REPO) / path).read_text(errors="replace")
        if len(content) > MAX_TOOL_OUTPUT:
            content = content[:MAX_TOOL_OUTPUT] + "\n... (truncated)"
        return content
    except FileNotFoundError:
        return f"File not found: {path}"
    except Exception as e:
        return f"Error reading {path}: {e}"


def tool_list_directory(path: str = ".") -> str:
    """List files and subdirectories at a path."""
    try:
        entries = sorted((Path(TARGET_REPO) / path).iterdir())
        lines = []
        for e in entries:
            prefix = "dir  " if e.is_dir() else "file "
            lines.append(f"{prefix} {e.name}")
        return "\n".join(lines) or "(empty)"
    except FileNotFoundError:
        return f"Directory not found: {path}"
    except Exception as e:
        return f"Error: {e}"


def tool_linear_ticket(ticket_id: str) -> str:
    """Fetch a ticket from Linear by identifier (e.g. 'PROJ-123')."""
    if not LINEAR_API_KEY:
        return "Linear API key not configured"
    query = """
    query($term: String!) {
        searchIssues(term: $term, first: 5) {
            nodes { id identifier title description state { name } labels { nodes { name } } }
        }
    }"""
    try:
        resp = httpx.post(
            "https://api.linear.app/graphql",
            headers={"Authorization": LINEAR_API_KEY, "Content-Type": "application/json"},
            json={"query": query, "variables": {"term": ticket_id}},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data:
            return f"Linear error: {json.dumps(data['errors'])}"
        nodes = data.get("data", {}).get("searchIssues", {}).get("nodes", [])
        for n in nodes:
            if n.get("identifier") == ticket_id:
                return json.dumps(n, indent=2)
        if nodes:
            return json.dumps(nodes[0], indent=2) + "\n(closest match — exact ID not found)"
        return f"NOT FOUND: {ticket_id} does not exist in Linear"
    except Exception as e:
        return f"Error fetching {ticket_id}: {e}"


def tool_pr_comments(author_filter: str | None = None) -> str:
    """Fetch PR comments. Use author_filter for a specific bot (e.g. 'coderabbitai[bot]')."""
    if not (GITHUB_TOKEN and REPO and PR_NUMBER):
        return "GitHub config missing"
    owner, repo = REPO.split("/", 1)
    all_comments = []
    page = 1
    while page <= 10:
        try:
            resp = httpx.get(
                f"https://api.github.com/repos/{owner}/{repo}/issues/{PR_NUMBER}/comments",
                headers={"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"},
                params={"per_page": 100, "page": page},
                timeout=15,
            )
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break
            all_comments.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        except Exception as e:
            return f"Error: {e}"

    if author_filter:
        all_comments = [
            c for c in all_comments
            if author_filter.lower() in c.get("user", {}).get("login", "").lower()
        ]

    results = []
    for c in all_comments:
        user = c.get("user", {}).get("login", "unknown")
        body = c.get("body", "")
        if len(body) > 3000:
            body = body[:3000] + "... (truncated)"
        results.append(f"--- @{user} ---\n{body}")

    return "\n\n".join(results) if results else "(no comments found)"


def tool_pr_review_threads(state_filter: str | None = None) -> str:
    """Fetch inline review threads. state_filter: 'resolved', 'unresolved', or omit for all."""
    if not (GITHUB_TOKEN and REPO and PR_NUMBER):
        return "GitHub config missing"
    owner, repo = REPO.split("/", 1)
    query = """
    query($owner: String!, $repo: String!, $pr: Int!) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $pr) {
          reviewThreads(first: 100) {
            nodes {
              isResolved
              comments(first: 10) {
                nodes { author { login } body path line }
              }
            }
          }
        }
      }
    }"""
    try:
        resp = httpx.post(
            "https://api.github.com/graphql",
            headers={"Authorization": f"Bearer {GITHUB_TOKEN}", "Content-Type": "application/json"},
            json={"query": query, "variables": {"owner": owner, "repo": repo, "pr": int(PR_NUMBER)}},
            timeout=15,
        )
        resp.raise_for_status()
        threads = (
            resp.json()
            .get("data", {}).get("repository", {}).get("pullRequest", {})
            .get("reviewThreads", {}).get("nodes", [])
        )
    except Exception as e:
        return f"Error: {e}"

    results = []
    for t in threads:
        resolved = t.get("isResolved", False)
        if state_filter == "resolved" and not resolved:
            continue
        if state_filter == "unresolved" and resolved:
            continue
        comments = t.get("comments", {}).get("nodes", [])
        if not comments:
            continue
        first = comments[0]
        author = first.get("author", {}).get("login", "unknown")
        path = first.get("path", "")
        line = first.get("line", "")
        body = first.get("body", "")[:1000]
        status = "RESOLVED" if resolved else "UNRESOLVED"
        replies = len(comments) - 1
        reply_info = f" ({replies} replies)" if replies else ""
        results.append(f"[{status}] @{author} on {path}:{line}{reply_info}\n{body}")

    return "\n\n".join(results) if results else "(no review threads found)"


BOT_LOGINS = {
    "coderabbit": "coderabbitai[bot]",
    "aikido": "aikido-security[bot]",
    "greptile": "greptile[bot]",
}


def tool_wait_for_reviewer(reviewer: str, max_wait: int = 120) -> str:
    """Wait for a review bot to post, polling every 30s. Returns its comments or timeout."""
    author = BOT_LOGINS.get(reviewer.lower(), f"{reviewer}[bot]")
    interval = 30
    elapsed = 0

    while True:
        result = tool_pr_comments(author_filter=author)
        if "(no comments found)" not in result:
            return f"POSTED (found after {elapsed}s):\n{result}"
        elapsed += interval
        if elapsed > max_wait:
            break
        time.sleep(interval)

    return f"NOT POSTED: {reviewer} did not post within {max_wait}s"


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------
TOOL_FUNCTIONS = {
    "git_diff": tool_git_diff,
    "git_diff_stat": tool_git_diff_stat,
    "git_ls_files": tool_git_ls_files,
    "read_file": tool_read_file,
    "list_directory": tool_list_directory,
    "linear_ticket": tool_linear_ticket,
    "pr_comments": tool_pr_comments,
    "pr_review_threads": tool_pr_review_threads,
    "wait_for_reviewer": tool_wait_for_reviewer,
    "submit_report": lambda **kw: "SUBMITTED",  # handled specially in the loop
}


def _build_tool_declarations():
    """Build Gemini function declarations."""
    from google.genai import types

    decls = [
        types.FunctionDeclaration(
            name="git_diff",
            description="Get git diff from base branch. Shows added/removed lines. Use without file param for full diff, or specify a file path.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "file": types.Schema(type="STRING", description="Optional file path to diff"),
                },
            ),
        ),
        types.FunctionDeclaration(
            name="git_diff_stat",
            description="Get a summary of all changed files with insertion/deletion counts. Good starting point to understand the PR scope.",
            parameters=types.Schema(type="OBJECT", properties={}),
        ),
        types.FunctionDeclaration(
            name="git_ls_files",
            description="List tracked files, optionally filtered by glob. Use to find test files (e.g. '*test*', 'tests/**/*.py').",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "pattern": types.Schema(type="STRING", description="Glob pattern to filter files"),
                },
            ),
        ),
        types.FunctionDeclaration(
            name="read_file",
            description="Read a file's contents. Use for issues/*.md, specs/*.md, or source files.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "path": types.Schema(type="STRING", description="File path relative to repo root"),
                },
                required=["path"],
            ),
        ),
        types.FunctionDeclaration(
            name="list_directory",
            description="List files and subdirectories at a path. Use to explore issues/, specs/, tests/ directories.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "path": types.Schema(type="STRING", description="Directory path (default: repo root)"),
                },
            ),
        ),
        types.FunctionDeclaration(
            name="linear_ticket",
            description="Fetch a ticket from Linear to verify it exists and get its details.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "ticket_id": types.Schema(type="STRING", description="Ticket identifier, e.g. 'PROJ-123'"),
                },
                required=["ticket_id"],
            ),
        ),
        types.FunctionDeclaration(
            name="pr_comments",
            description="Fetch PR comments. Filter by bot name to check if a review tool has posted (e.g. 'coderabbitai[bot]', 'aikido-security[bot]', 'greptile[bot]').",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "author_filter": types.Schema(type="STRING", description="Filter by comment author login"),
                },
            ),
        ),
        types.FunctionDeclaration(
            name="wait_for_reviewer",
            description="Wait for a review bot to post its review, polling every 30s. Use when a reviewer hasn't posted yet. Pass the short name: 'coderabbit', 'aikido', or 'greptile'.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "reviewer": types.Schema(type="STRING", description="Reviewer short name: 'coderabbit', 'aikido', or 'greptile'"),
                    "max_wait": types.Schema(type="INTEGER", description="Max seconds to wait (default: 120)"),
                },
                required=["reviewer"],
            ),
        ),
        types.FunctionDeclaration(
            name="pr_review_threads",
            description="Fetch inline review comment threads with resolution status. Use state_filter='unresolved' to find open issues.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "state_filter": types.Schema(
                        type="STRING",
                        description="Filter: 'resolved', 'unresolved', or omit for all",
                    ),
                },
            ),
        ),
        types.FunctionDeclaration(
            name="submit_report",
            description="Submit your final compliance findings with a confidence score. Call this when your investigation is complete.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "findings_json": types.Schema(
                        type="STRING",
                        description='JSON string with findings. Required keys: confidence_percent (integer 0-100), tickets_found (list), invalid_tickets (list), unspecced_changes (list), missing_documentation (list), untested_files (list), unresolved_reviews (list), spec_issues (list), missing_reviewers (list), summary (string)',
                    ),
                },
                required=["findings_json"],
            ),
        ),
    ]
    return types.Tool(function_declarations=decls)


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------
def build_system_prompt() -> str:
    reviewers_block = ""
    if REQUIRED_REVIEWERS:
        names = ", ".join(REQUIRED_REVIEWERS)
        reviewers_block = f"""
### 5. Review Tools ({names})
For each reviewer:
- First use pr_comments with author_filter to check if they already posted
  (bot logins: coderabbit → "coderabbitai[bot]", aikido → "aikido-security[bot]", greptile → "greptile[bot]")
- If they HAVEN'T posted yet, use wait_for_reviewer to wait for them (up to 2 minutes each).
  The PR might have just been opened and the bots need time to run.
- Once they've posted, scan for CRITICAL or MAJOR severity findings
- Use pr_review_threads with state_filter="unresolved" to find open threads
- A critical/major finding is unresolved if: the thread is unresolved AND the
  original author is a review bot AND no human replied acknowledging it

**Confidence impact:**
- Bot posted, all findings resolved → no penalty. Good signal.
- Bot posted, unresolved CRITICAL finding → major penalty (~25-30%). This is a real risk.
- Bot posted, unresolved MAJOR finding → moderate penalty (~10-15%).
- Bot posted, only minor/info findings unresolved → no penalty. These are suggestions.
- Bot didn't post even after waiting → minor penalty (~5%). It may be down or not configured.

Report: which reviewers posted, which are missing, and any unresolved critical/major findings.
"""
    else:
        reviewers_block = """
### 5. Review Tools
No required reviewers configured. Skip this check.
"""

    pr_title_line = f"- Title: {PR_TITLE}" if PR_TITLE else ""
    pr_author_line = f"- Author: @{PR_AUTHOR}" if PR_AUTHOR else ""

    return f"""You are a SOC2 compliance auditor. Investigate this pull request methodically using the tools provided.

## Context
- PR #{PR_NUMBER} in {REPO}
{pr_title_line}
{pr_author_line}
- Base branch: {BASE_BRANCH}
- Ticket pattern: {TICKET_PATTERN}
- Issues path: {ISSUES_PATH}/
- Specs path: {SPECS_PATH}/

## PR Title
{PR_TITLE or "(no title)"}

## PR Description
{PR_BODY}

## Investigation Checklist

Work through these checks in order. Use tools to gather evidence — don't guess.

### 1. Ticket Traceability
- Extract ticket IDs from the PR title AND description (pattern: {TICKET_PATTERN})
- Verify each ticket exists in Linear (use linear_ticket)
- Use git_diff_stat to see all changed files
- Verify each ticket has corresponding code changes in the diff

### 2. Change Documentation
- Check that all changed files are covered by a ticket in the PR description
- Flag any code changes that aren't traceable to a listed ticket
- Minor files (config, lock files, formatting-only) can share a ticket

### 3. Issue & Spec Files
- Use list_directory to check {ISSUES_PATH}/ and {SPECS_PATH}/ directories
- For each ticket, verify {{ISSUES_PATH}}/{{TICKET}}.md exists (use read_file)
- Check that at least one spec file describes the feature being built (use read_file)
- Verify the spec content actually describes what the code implements (compare with git_diff)
- Flag: missing files, empty/placeholder content, spec that doesn't match implementation

### 4. Test Coverage
- Use git_diff_stat to identify changed source files
- For each changed source file, check if a corresponding test file exists or was modified
  Common patterns: test_foo.py, foo_test.py, foo.test.ts, foo.spec.ts, __tests__/foo.ts
- Use git_ls_files with patterns like "*test*", "tests/**" to find test files
- Exclude from this check: config files, docs, migrations, type definitions, static assets
- Flag source files that have no corresponding test file AND no test changes in the diff
{reviewers_block}
## Output

When done, call submit_report with a JSON string containing:
{{
  "confidence_percent": 85,
  "tickets_found": ["TICKET-1"],
  "invalid_tickets": ["TICKET-X: reason"],
  "unspecced_changes": ["path/file.py: not covered by any ticket"],
  "missing_documentation": ["TICKET-1: no issues/TICKET-1.md found"],
  "spec_issues": ["specs/foo.md describes X but code implements Y"],
  "untested_files": ["src/auth.py: no test file found"],
  "unresolved_reviews": ["CodeRabbit CRITICAL on src/db.py:42: SQL injection (unresolved)"],
  "missing_reviewers": ["greptile"],
  "summary": "Brief summary of findings"
}}

## Confidence Scoring

Set confidence_percent (0–100) based on your holistic assessment:

- **90–100**: Full traceability. Tickets verified, specs describe what was built, tests exist, reviews clean.
- **70–89**: Minor gaps. Maybe a config file without a dedicated test, or a spec that's slightly stale. Overall the audit trail is solid.
- **50–69**: Significant gaps. Missing specs, several untested source files, but tickets exist and most things are traceable.
- **30–49**: Major issues. Missing tickets for substantial code, no tests, unresolved critical review findings.
- **0–29**: No traceability. No tickets, no docs, no tests.

Use judgment. A PR that changes 1 source file + 3 config files with tests for the source file is 90%+, even if the config files don't have dedicated tests. A PR with perfect docs but an unresolved SQL injection finding from CodeRabbit is 30%.

The threshold for passing is {CONFIDENCE_THRESHOLD}%.

## Rules
- Be thorough but efficient. Start with git_diff_stat to understand scope, then drill into specifics.
- Don't read every file — focus on what matters for compliance.
- Empty arrays mean the check passed.
- A test file doesn't need to be modified in this PR if it already exists and covers the changed code.
- For specs, check substance — a file containing only a ticket ID is not a real spec.
- Call submit_report exactly once when you're done.
"""


# ---------------------------------------------------------------------------
# Agent progress annotations
# ---------------------------------------------------------------------------
def annotate_tool_call(comment: LiveComment, name: str, args: dict, result: str):
    """Add a progress step based on what tool was called and what it returned."""
    if name == "git_diff_stat":
        file_count = len([l for l in result.strip().split("\n") if l.strip() and "|" in l])
        comment.add_step("📊", f"Scoped PR — {file_count} files changed")

    elif name == "linear_ticket":
        tid = args.get("ticket_id", "?")
        if "NOT FOUND" in result or "does not exist" in result:
            comment.add_step("❌", f"**{tid}** — not found in Linear")
        elif "Error" in result:
            comment.add_step("⚠️", f"**{tid}** — could not reach Linear")
        else:
            title = ""
            try:
                data = json.loads(result.split("\n(closest")[0])
                title = data.get("title", "")
            except Exception:
                pass
            label = f"**{tid}** — {title}" if title else f"**{tid}** verified"
            comment.add_step("✅", label)

    elif name == "list_directory":
        path = args.get("path", ".")
        if ISSUES_PATH in path or SPECS_PATH in path:
            found = result.count("file ")
            comment.add_step("📁", f"`{path}/` — {found} files")

    elif name == "read_file":
        path = args.get("path", "")
        if "File not found" in result:
            comment.add_step("❌", f"`{path}` — not found")
        elif ISSUES_PATH in path or SPECS_PATH in path:
            comment.add_step("📄", f"`{path}` — read")

    elif name == "git_ls_files":
        pattern = args.get("pattern", "")
        if "test" in pattern.lower():
            count = len([l for l in result.strip().split("\n") if l.strip()]) if result.strip() != "(no matching files)" else 0
            comment.add_step("🧪", f"Found {count} test files matching `{pattern}`")

    elif name == "pr_comments":
        author = args.get("author_filter", "")
        if author:
            bot_name = author.replace("[bot]", "")
            has = "(no comments found)" not in result
            if has:
                comment.add_step("✅", f"**{bot_name}** — review found")
            else:
                comment.add_step("⏳", f"**{bot_name}** — no review posted")

    elif name == "pr_review_threads":
        sf = args.get("state_filter", "")
        if sf == "unresolved":
            count = result.count("[UNRESOLVED]")
            if count:
                comment.add_step("⚠️", f"{count} unresolved review thread(s)")
            else:
                comment.add_step("✅", "All review threads resolved")

    elif name == "wait_for_reviewer":
        reviewer = args.get("reviewer", "")
        if "POSTED" in result:
            wait_time = result.split("after ")[1].split("s)")[0] if "after " in result else "0"
            comment.update_last_step("✅", f"**{reviewer}** — review found (waited {wait_time}s)")
        else:
            comment.update_last_step("⏳", f"**{reviewer}** — not posted after waiting")

    elif name == "submit_report":
        comment.add_step("📋", "Investigation complete — applying policy")


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------
def run_agent(comment: LiveComment) -> dict:
    """Run the Gemini-powered compliance agent. Returns raw findings dict."""
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=GEMINI_API_KEY)
    tool_declarations = _build_tool_declarations()
    system_prompt = build_system_prompt()

    contents = [
        types.Content(
            role="user",
            parts=[types.Part(text="Begin your compliance audit. Work through each check methodically.")],
        )
    ]

    config = types.GenerateContentConfig(
        system_instruction=system_prompt,
        tools=[tool_declarations],
        temperature=0,
    )

    for step in range(MAX_STEPS):
        # Call Gemini with retry
        response = None
        for attempt in range(MAX_RETRIES):
            try:
                response = client.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=contents,
                    config=config,
                )
                break
            except Exception as e:
                err = str(e).lower()
                if "429" in str(e) or "rate" in err or "resource_exhausted" in err:
                    time.sleep(INITIAL_BACKOFF ** (attempt + 1))
                    continue
                print(f"Gemini error (step {step}): {e}", file=sys.stderr)
                return {"summary": f"Gemini API error: {e}", "tickets_found": []}

        if response is None:
            return {"summary": "Gemini rate limited after retries", "tickets_found": []}

        # Get the response content
        if not response.candidates:
            print(f"Gemini returned no candidates at step {step}", file=sys.stderr)
            return {"summary": "Gemini returned empty response", "tickets_found": []}
        candidate = response.candidates[0]
        parts = candidate.content.parts if candidate.content else []

        # Collect function calls from response
        function_calls = [p for p in parts if getattr(p, "function_call", None)]

        if not function_calls:
            # Agent responded with text instead of calling submit_report
            text = "".join(getattr(p, "text", "") or "" for p in parts)
            # Try to extract JSON findings from the text
            try:
                # Look for JSON block in the text
                start = text.index("{")
                end = text.rindex("}") + 1
                findings = json.loads(text[start:end])
                if "tickets_found" in findings or "summary" in findings:
                    print(f"Extracted findings from text at step {step}", file=sys.stderr)
                    return findings
            except (ValueError, json.JSONDecodeError):
                pass
            print(f"Agent finished without submit_report at step {step}: {text[:500]}", file=sys.stderr)
            return {"summary": "Agent completed without submitting findings", "tickets_found": []}

        # Add assistant message to conversation
        contents.append(candidate.content)

        # Execute each tool call
        function_responses = []
        for part in function_calls:
            fc = part.function_call
            name = fc.name
            args = dict(fc.args) if fc.args else {}

            # Handle submit_report specially
            if name == "submit_report":
                annotate_tool_call(comment, name, args, "")
                try:
                    findings = json.loads(args.get("findings_json", "{}"))
                    return findings
                except json.JSONDecodeError as e:
                    print(f"Bad JSON in submit_report: {e}", file=sys.stderr)
                    return {"summary": "Agent submitted malformed findings", "tickets_found": []}

            # Pre-annotate long-running tools
            if name == "wait_for_reviewer":
                reviewer = args.get("reviewer", "")
                comment.add_step("⏳", f"Waiting for **{reviewer}**...")

            # Execute tool
            fn = TOOL_FUNCTIONS.get(name)
            if not fn:
                result = f"Unknown tool: {name}"
            else:
                try:
                    result = fn(**args)
                except Exception as e:
                    result = f"Tool error: {e}"

            # Annotate progress
            annotate_tool_call(comment, name, args, result)

            function_responses.append(
                types.Part.from_function_response(name=name, response={"result": result})
            )

        # Add tool results to conversation
        contents.append(types.Content(role="user", parts=function_responses))

    return {"summary": f"Agent did not complete within {MAX_STEPS} steps", "tickets_found": []}


# ---------------------------------------------------------------------------
# Policy enforcement (deterministic — not up to the LLM)
# ---------------------------------------------------------------------------
def enforce_policy(findings: dict) -> dict:
    """Apply confidence threshold to agent findings. Returns the final report."""
    confidence = findings.get("confidence_percent", 0)

    # Clamp to 0-100
    if not isinstance(confidence, (int, float)):
        try:
            confidence = int(confidence)
        except (ValueError, TypeError):
            confidence = 0
    confidence = max(0, min(100, int(confidence)))

    report = {
        "compliant": confidence >= CONFIDENCE_THRESHOLD,
        "confidence_percent": confidence,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "summary": findings.get("summary", ""),
        "tickets_found": findings.get("tickets_found", []),
        "issues": [],
        "invalid_tickets": findings.get("invalid_tickets", []),
        "unspecced_changes": findings.get("unspecced_changes", []),
        "missing_documentation": findings.get("missing_documentation", []),
        "spec_issues": findings.get("spec_issues", []),
        "untested_files": findings.get("untested_files", []),
        "unresolved_reviews": findings.get("unresolved_reviews", []),
        "missing_reviewers": findings.get("missing_reviewers", []),
    }

    # Build human-readable issues list from findings (for the comment)
    if report["invalid_tickets"]:
        report["issues"].append(
            f"{len(report['invalid_tickets'])} ticket(s) not found in Linear"
        )
    if report["unspecced_changes"]:
        report["issues"].append(
            f"{len(report['unspecced_changes'])} file(s) changed without ticket coverage"
        )
    if report["missing_documentation"]:
        report["issues"].append(
            f"{len(report['missing_documentation'])} ticket(s) missing issues/ or specs/ files"
        )
    if report["spec_issues"]:
        report["issues"].append(
            f"{len(report['spec_issues'])} spec alignment issue(s)"
        )
    if report["untested_files"]:
        report["issues"].append(
            f"{len(report['untested_files'])} source file(s) with no test coverage"
        )
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
            f"Confidence {confidence}% (threshold {CONFIDENCE_THRESHOLD}%) — "
            + ("passed" if report["compliant"] else "failed")
        )

    return report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not GEMINI_API_KEY:
        print(json.dumps({"compliant": False, "summary": "GEMINI_API_KEY not set", "issues": ["Missing API key"]}))
        return

    comment = LiveComment()
    comment.add_step("🔄", "Starting compliance audit...")

    try:
        findings = run_agent(comment)
        report = enforce_policy(findings)
    except Exception as e:
        print(f"Agent crashed: {e}", file=sys.stderr)
        report = {
            "compliant": False,
            "summary": f"Compliance agent error: {e}",
            "issues": [str(e)],
            "tickets_found": [],
        }

    comment.finalize(report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
