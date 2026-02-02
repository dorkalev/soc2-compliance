# SOC2 Compliance Checker

AI-powered compliance verification for pull requests. Ensures code changes align with issue tracker tickets and technical specifications.

## Features

- Verifies PR changes match referenced tickets (Linear integration)
- Checks alignment with local issue requirement files
- Validates implementation against technical specs
- Detects unspecced/undocumented changes
- Posts detailed compliance reports to PRs
- Handles large diffs via intelligent summarization
- Fully configurable patterns and paths

## How It Works

```
PR Opened/Updated
       │
       ▼
Extract ticket IDs from PR body (configurable pattern)
       │
       ├──► Fetch from Linear API (optional)
       │
       ├──► Read issues/*.md files
       │
       ├──► Read specs/*.md files
       │
       ▼
Generate diff from base branch
       │
       ▼
Send to Gemini for alignment analysis
       │
       ▼
Post compliance report to PR
       │
       ▼
Pass/Fail the check
```

## Usage

### 1. Add secrets to your repository

| Secret | Required | Description |
|--------|----------|-------------|
| `GEMINI_API_KEY` | Yes | Google Gemini API key |
| `LINEAR_API_KEY` | No | Linear API key for ticket fetching |

### 2. Create workflow in your repository

```yaml
# .github/workflows/compliance.yml
name: SOC2 Compliance

on:
  pull_request:
    branches: [main, staging]

jobs:
  compliance-check:
    uses: dorkalev/soc2-compliance/.github/workflows/compliance-check.yml@main
    with:
      pr_body: ${{ github.event.pull_request.body }}
      pr_number: ${{ github.event.pull_request.number }}
      repo: ${{ github.repository }}
      ticket_pattern: "PROJ-[0-9]+"  # Your ticket pattern
      base_branch: main
      issues_path: issues
      specs_path: specs
    secrets:
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      LINEAR_API_KEY: ${{ secrets.LINEAR_API_KEY }}
      REPO_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 3. Configure branch protection

Add `compliance-check` as a required status check on your protected branches.

## Configuration

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `pr_body` | Yes | - | PR description text |
| `pr_number` | Yes | - | PR number for commenting |
| `repo` | Yes | - | Repository (owner/name) |
| `ticket_pattern` | Yes | - | Regex for ticket IDs (e.g., `PROJ-[0-9]+`) |
| `base_branch` | No | `main` | Branch to diff against |
| `issues_path` | No | `issues` | Path to issue requirement files |
| `specs_path` | No | `specs` | Path to technical spec files |
| `linear_team_id` | No | - | Linear team ID for filtering |
| `fail_on_unspecced` | No | `true` | Fail if changes aren't in specs |
| `fail_on_missing_ticket` | No | `true` | Fail if no ticket in PR body |

## Expected File Structure

```
your-repo/
├── issues/
│   ├── PROJ-123.md      # Product requirements
│   ├── PROJ-456.md
│   └── ...
├── specs/
│   ├── feature-auth.md  # Technical specifications
│   ├── proj-123.md      # Can match ticket IDs
│   └── ...
└── .github/
    └── workflows/
        └── compliance.yml
```

### Issue Files (issues/*.md)

Product requirements documents. Should contain:
- User stories
- Acceptance criteria
- Business logic requirements
- UX requirements

Naming: `{TICKET-ID}.md` (e.g., `PROJ-123.md`)

### Spec Files (specs/*.md)

Technical specifications. Should contain:
- Architecture decisions
- Implementation approach
- API contracts / data models
- Edge cases and error handling

Can reference tickets in content or filename.

## PR Description Format

Reference tickets in your PR body:

```markdown
## Summary
Implements user authentication flow.

## Linear Tickets
- PROJ-123: Add login page
- PROJ-124: Add OAuth integration

## Changes
- Added login component
- Integrated Google OAuth
```

## Compliance Report

The checker posts a comment on your PR:

```markdown
## ✅ SOC2 Compliance Check: Passed

**Summary:** Changes align with PROJ-123 and PROJ-124 specifications.

### Tickets Referenced
- PROJ-123
- PROJ-124

### Spec Coverage
All changes are documented in specs/auth-flow.md
```

Or if it fails:

```markdown
## ❌ SOC2 Compliance Check: Failed

**Summary:** Unspecced changes detected in authentication module.

### Issues Found
- ⚠️ New rate limiting logic not documented in any spec
- ⚠️ PROJ-124 mentions OAuth but code implements SAML

### Unspecced Changes
- `src/auth/rate_limiter.py`
- `src/auth/saml.py`
```

## Large PRs

For PRs with large diffs (>100K tokens), the checker:
1. Summarizes changes by file
2. Includes truncated per-file diffs
3. Focuses analysis on high-level alignment

## Security

This checker runs in a separate repository with restricted access:
- Developers cannot modify the compliance logic in the same PR
- Changes to this repo require separate review
- Audit trail of compliance rule changes

## Development

### Local Testing

```bash
export GEMINI_API_KEY=your-key
export LINEAR_API_KEY=your-key
export PR_BODY="Implements PROJ-123"
export TARGET_REPO=/path/to/repo
export TICKET_PATTERN="PROJ-[0-9]+"
export BASE_BRANCH=main

python scripts/verify_compliance.py
```

### Requirements

- Python 3.12+
- `httpx` - HTTP client
- `google-genai` - Gemini API client

## License

MIT
